//! Negative-exemplar archive for `/mati-enrich`'s closed feedback loop
//! (Proposal D, Phase D3 foundation).
//!
//! When a developer tombstones a gotcha (via `mati gotcha delete` or
//! `mem_set action="delete"`), this module captures the rule + reason +
//! severity into `analytics:negative_exemplar:<dirname>:<slug>` so future
//! `/mati-enrich` runs on the same directory can show the LLM "do NOT
//! extract rules that look like this" — the only mechanism that lets the
//! extractor compound quality over time.
//!
//! Reference: `ENRICH_QUALITY.md` Section 8 (Feedback loop) and the
//! `gotcha_ops::apply_gotcha_tombstone` integration point.
//!
//! Write semantics:
//! - One record per (dirname, gotcha_key) — keyed by slug, so re-tombstoning
//!   (rare) just overwrites the latest snapshot.
//! - When a gotcha has multiple `affected_files`, one record is written per
//!   *unique dirname* (multiple files in the same directory dedup).
//! - Eventual durability — losing a few exemplars on crash is acceptable;
//!   the feedback signal is statistical, not exact.
//!
//! Read semantics:
//! - `scan_recent_for_dirname(dirname, since_secs, limit)` returns the
//!   most-recent tombstoned exemplars for a directory, newest first.
//! - Used by `mati ls tombstoned --recent --dir --json` (D2-β) which feeds
//!   the Deep-tier prompt in `/mati-enrich`.

use std::collections::HashSet;
use std::path::Path;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use super::record::{
    Category, ConfidenceScore, Priority, QualityScore, Record, RecordLifecycle, RecordSource,
    RecordVersion, StalenessScore,
};
use super::session::now_secs;
use super::Store;

/// Key prefix for the negative-exemplar archive.
///
/// Full key shape: `analytics:negative_exemplar:<dirname>:<slug>` where
/// `slug` is the trailing segment of the original `gotcha:<slug>` key.
pub const NEG_EXEMPLAR_PREFIX: &str = "analytics:negative_exemplar:";

/// Snapshot of a tombstoned gotcha, retained as a calibration signal for
/// future `/mati-enrich` extractions in the same directory.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NegativeExemplar {
    /// Original `gotcha:<slug>` key — for traceability and dedup.
    pub gotcha_key: String,
    /// Directory the affected file lived in (no leading/trailing slash).
    /// Multiple files in the same dirname collapse to a single exemplar.
    pub dirname: String,
    /// The tombstoned rule, verbatim.
    pub rule: String,
    /// The tombstoned reason, verbatim.
    pub reason: String,
    /// Severity at the time of tombstone (Priority enum maps to severity
    /// in `GotchaRecord`).
    pub severity: Priority,
    /// Unix seconds when the tombstone fired.
    pub tombstoned_at: u64,
}

/// Compute the storage key for a single (dirname, slug) pair.
///
/// The slug is the trailing path segment of `gotcha:<slug>` — for
/// `gotcha:foo:bar`, slug = `foo:bar`. Colons inside the slug are
/// preserved (mati's key parser handles arbitrary trailing content).
pub fn make_key(dirname: &str, gotcha_slug: &str) -> String {
    format!("{NEG_EXEMPLAR_PREFIX}{dirname}:{gotcha_slug}")
}

/// Extract the `<slug>` portion from a `gotcha:<slug>` key.
/// Returns the input unchanged if the prefix is absent.
fn slug_of(gotcha_key: &str) -> &str {
    gotcha_key.strip_prefix("gotcha:").unwrap_or(gotcha_key)
}

/// Collapse a list of file paths into the unique dirnames they cover.
/// Files with no parent (e.g. top-level `main.rs`) contribute `""` —
/// callers can skip empty dirnames if they want to.
pub fn dirnames_of(affected_files: &[String]) -> Vec<String> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut out: Vec<String> = Vec::new();
    for path in affected_files {
        let dirname = Path::new(path)
            .parent()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();
        if seen.insert(dirname.clone()) {
            out.push(dirname);
        }
    }
    out
}

/// Write one negative-exemplar record per unique dirname in `affected_files`.
///
/// Called from `gotcha_ops::apply_gotcha_tombstone` after the gotcha record
/// itself is tombstoned. Failure is best-effort — the tombstone proceeds
/// even if the exemplar write fails (logged via `tracing::warn`).
///
/// Returns the count of records actually written.
pub async fn write_on_tombstone(
    store: &Store,
    gotcha_key: &str,
    rule: &str,
    reason: &str,
    severity: &Priority,
    affected_files: &[String],
) -> Result<usize> {
    let slug = slug_of(gotcha_key);
    let dirnames = dirnames_of(affected_files);
    let ts = now_secs();

    let mut written = 0;
    for dirname in &dirnames {
        let exemplar = NegativeExemplar {
            gotcha_key: gotcha_key.to_string(),
            dirname: dirname.clone(),
            rule: rule.to_string(),
            reason: reason.to_string(),
            severity: severity.clone(),
            tombstoned_at: ts,
        };
        let record = analytics_record_with_payload(
            &make_key(dirname, slug),
            format!(
                "tombstoned: {} (in {})",
                truncate(rule, 60),
                if dirname.is_empty() {
                    "<root>"
                } else {
                    dirname
                }
            ),
            serde_json::to_value(&exemplar).ok(),
            ts,
        );
        match store.put(&record.key, &record).await {
            Ok(()) => written += 1,
            Err(e) => {
                tracing::warn!("negative_exemplar write failed for {gotcha_key} in {dirname}: {e}")
            }
        }
    }
    Ok(written)
}

/// Scan recent negative exemplars for a directory.
///
/// `since_secs` is a unix-timestamp lower bound; pass `0` for "all time".
/// Results are sorted newest-first. The `limit` caps the returned count
/// AFTER sorting (so you always get the most recent, not the alphabetically
/// first).
pub async fn scan_recent_for_dirname(
    store: &Store,
    dirname: &str,
    since_secs: u64,
    limit: usize,
) -> Result<Vec<NegativeExemplar>> {
    let prefix = format!("{NEG_EXEMPLAR_PREFIX}{dirname}:");
    let records = store.scan_prefix(&prefix).await.unwrap_or_default();
    let mut exemplars: Vec<NegativeExemplar> = records
        .into_iter()
        .filter_map(|r| r.payload.and_then(|p| serde_json::from_value(p).ok()))
        .filter(|e: &NegativeExemplar| e.tombstoned_at >= since_secs)
        .collect();
    exemplars.sort_by_key(|e| std::cmp::Reverse(e.tombstoned_at));
    exemplars.truncate(limit);
    Ok(exemplars)
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max).collect();
        out.push('…');
        out
    }
}

fn analytics_record_with_payload(
    key: &str,
    value: String,
    payload: Option<serde_json::Value>,
    now_ts: u64,
) -> Record {
    Record {
        key: key.to_string(),
        value,
        payload,
        category: Category::Analytics,
        priority: Priority::Normal,
        tags: vec![],
        created_at: now_ts,
        updated_at: now_ts,
        ref_url: None,
        staleness: StalenessScore::fresh(),
        lifecycle: RecordLifecycle::Active,
        version: RecordVersion {
            device_id: uuid::Uuid::new_v4(),
            logical_clock: 1,
            wall_clock: now_ts,
        },
        quality: QualityScore::layer0_default(),
        access_count: 0,
        last_accessed: 0,
        source: RecordSource::StaticAnalysis,
        confidence: ConfidenceScore::for_new_record(&RecordSource::StaticAnalysis),
        gap_analysis_score: 0.0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    async fn fresh_store() -> Store {
        let dir = TempDir::new().unwrap();
        // Leak the dir so it outlives the test (otherwise Drop wipes the store).
        let path = Box::leak(Box::new(dir)).path().to_path_buf();
        Store::open(&path).await.unwrap()
    }

    #[test]
    fn dirnames_dedup_and_strip_basename() {
        let files = vec![
            "src/cli/repair.rs".to_string(),
            "src/cli/init.rs".to_string(), // same dir → dedup
            "src/store/db.rs".to_string(),
            "main.rs".to_string(), // root → empty dirname
        ];
        let dirs = dirnames_of(&files);
        assert_eq!(dirs.len(), 3);
        assert!(dirs.contains(&"src/cli".to_string()));
        assert!(dirs.contains(&"src/store".to_string()));
        assert!(dirs.contains(&"".to_string()));
    }

    #[test]
    fn make_key_format_is_stable() {
        assert_eq!(
            make_key("src/cli", "vague-rule"),
            "analytics:negative_exemplar:src/cli:vague-rule"
        );
        // Empty dirname (root files) — preserved
        assert_eq!(make_key("", "x"), "analytics:negative_exemplar::x");
    }

    #[test]
    fn slug_of_strips_gotcha_prefix() {
        assert_eq!(slug_of("gotcha:foo"), "foo");
        assert_eq!(slug_of("gotcha:foo:bar"), "foo:bar");
        // No prefix → returned as-is.
        assert_eq!(slug_of("foo"), "foo");
    }

    #[tokio::test]
    async fn write_on_tombstone_emits_one_record_per_unique_dirname() {
        let store = fresh_store().await;
        let count = write_on_tombstone(
            &store,
            "gotcha:vague-rule",
            "Be careful with X",
            "It's complex",
            &Priority::Normal,
            &[
                "src/cli/repair.rs".to_string(),
                "src/cli/init.rs".to_string(), // same dirname → dedup
                "src/store/db.rs".to_string(),
            ],
        )
        .await
        .unwrap();
        assert_eq!(count, 2, "src/cli and src/store → 2 unique dirnames");

        // Verify the records are there at the expected keys.
        assert!(store
            .get("analytics:negative_exemplar:src/cli:vague-rule")
            .await
            .unwrap()
            .is_some());
        assert!(store
            .get("analytics:negative_exemplar:src/store:vague-rule")
            .await
            .unwrap()
            .is_some());
    }

    #[tokio::test]
    async fn write_on_tombstone_payload_roundtrips() {
        let store = fresh_store().await;
        write_on_tombstone(
            &store,
            "gotcha:test-rule",
            "Test rule",
            "test reason",
            &Priority::High,
            &["src/foo/bar.rs".to_string()],
        )
        .await
        .unwrap();

        let rec = store
            .get("analytics:negative_exemplar:src/foo:test-rule")
            .await
            .unwrap()
            .expect("record present");
        let payload = rec.payload.expect("payload present");
        let exemplar: NegativeExemplar = serde_json::from_value(payload).unwrap();

        assert_eq!(exemplar.gotcha_key, "gotcha:test-rule");
        assert_eq!(exemplar.dirname, "src/foo");
        assert_eq!(exemplar.rule, "Test rule");
        assert_eq!(exemplar.reason, "test reason");
        assert_eq!(exemplar.severity, Priority::High);
        assert!(exemplar.tombstoned_at > 0);
    }

    #[tokio::test]
    async fn scan_returns_newest_first_within_limit() {
        let store = fresh_store().await;

        // Write 3 exemplars in the same dirname with explicit timestamps.
        // Use direct `store.put` to control tombstoned_at since
        // write_on_tombstone uses now_secs().
        for (slug, ts) in [("r1", 100u64), ("r2", 300), ("r3", 200)] {
            let exemplar = NegativeExemplar {
                gotcha_key: format!("gotcha:{slug}"),
                dirname: "src/cli".to_string(),
                rule: format!("rule {slug}"),
                reason: "reason".to_string(),
                severity: Priority::Normal,
                tombstoned_at: ts,
            };
            let rec = analytics_record_with_payload(
                &make_key("src/cli", slug),
                format!("test {slug}"),
                serde_json::to_value(&exemplar).ok(),
                ts,
            );
            store.put(&rec.key, &rec).await.unwrap();
        }

        // limit=2 should return r2 (ts=300) and r3 (ts=200), in that order.
        let recent = scan_recent_for_dirname(&store, "src/cli", 0, 2)
            .await
            .unwrap();
        assert_eq!(recent.len(), 2);
        assert_eq!(recent[0].gotcha_key, "gotcha:r2");
        assert_eq!(recent[1].gotcha_key, "gotcha:r3");
    }

    #[tokio::test]
    async fn scan_respects_since_secs_window() {
        let store = fresh_store().await;
        for (slug, ts) in [("old", 100u64), ("new", 500)] {
            let exemplar = NegativeExemplar {
                gotcha_key: format!("gotcha:{slug}"),
                dirname: "src".to_string(),
                rule: "r".to_string(),
                reason: "x".to_string(),
                severity: Priority::Normal,
                tombstoned_at: ts,
            };
            let rec = analytics_record_with_payload(
                &make_key("src", slug),
                "t".to_string(),
                serde_json::to_value(&exemplar).ok(),
                ts,
            );
            store.put(&rec.key, &rec).await.unwrap();
        }

        let recent = scan_recent_for_dirname(&store, "src", 200, 10)
            .await
            .unwrap();
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].gotcha_key, "gotcha:new");
    }

    #[tokio::test]
    async fn scan_empty_when_no_dirname_match() {
        let store = fresh_store().await;
        write_on_tombstone(
            &store,
            "gotcha:r",
            "rule",
            "reason",
            &Priority::Normal,
            &["src/cli/foo.rs".to_string()],
        )
        .await
        .unwrap();

        // Different dirname → no match.
        let recent = scan_recent_for_dirname(&store, "src/store", 0, 10)
            .await
            .unwrap();
        assert!(recent.is_empty());
    }
}
