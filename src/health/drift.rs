//! Gotcha content drift — "the code this rule describes changed since a human
//! last confirmed the rule".
//!
//! Staleness already answers *how old* a record is: elapsed time, commits
//! since the last baseline, cascade from a linked file. That says a rule is
//! dusty. It does not say the rule may now be **wrong**. Drift does: a gotcha
//! is drifted when a file it names hashes differently today than it did at the
//! moment someone signed off on the rule against it.
//!
//! ## Why this is derived, not scored
//!
//! Nothing here writes. Drift is a pure comparison between
//! [`GotchaRecord::confirmed_content`] (written once, by the confirm paths in
//! [`crate::store::gotcha_ops`]) and the `content_hash` `mati init` already
//! stores on each `file:*` record. Both values exist before this module runs,
//! so detection costs one map lookup per affected file and adds nothing to
//! `mati init`.
//!
//! It deliberately stays out of the staleness composite. Two reasons:
//!
//! 1. A gotcha's own staleness feeds `cascade_factor` on every file that
//!    links it (ARCHITECTURE.md section 17). Weight added here would raise
//!    that factor and could push a linked file's tier into `Liability` or
//!    `Tombstone`, which degrades what `hooks::decide::evaluate` injects for
//!    it — `Liability` shows a bare warning, `Tombstone` suppresses the
//!    record entirely (section 10.1). Enforcement itself would be unaffected
//!    (the gotcha loop runs ahead of the tier checks), but the linked files'
//!    context would go dark for a fact that says nothing about them.
//! 2. `StalenessAnalyzer::compute_staleness` rebuilds `staleness.signals` from
//!    scratch on every pass, so a drift signal parked there would be erased by
//!    the next `mati init` — a fact that silently decays is worse than no
//!    fact.
//!
//! Drift is therefore reported (`mati stale`, `mati doctor`) and never
//! enforced. A drifted gotcha keeps denying reads, which is the point: the
//! rule is more likely to matter, not less, once the code moved.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::store::record::{GotchaRecord, Record, RecordLifecycle};

/// One confirmed gotcha whose code has changed since confirmation.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct DriftedGotcha {
    /// `gotcha:<slug>` key.
    pub key: String,
    /// The rule text, for display.
    pub rule: String,
    /// The affected files whose current digest differs from the stamped one.
    /// Never empty — a gotcha with no differing file is not reported.
    pub drifted_files: Vec<String>,
}

/// Build the `path → content_hash` map drift compares against, from `file:*`
/// records the caller has already scanned.
///
/// Files with no stored digest are omitted, which makes them unknown rather
/// than drifted.
pub fn current_content_hashes(file_records: &[Record]) -> HashMap<String, String> {
    let mut out = HashMap::with_capacity(file_records.len());
    for record in file_records {
        let Some(path) = record.key.strip_prefix("file:") else {
            continue;
        };
        if let Some(hash) = crate::store::gotcha_ops::content_hash_of(record) {
            out.insert(path.to_string(), hash);
        }
    }
    out
}

/// Find the confirmed gotchas whose affected files have changed since they
/// were confirmed.
///
/// Pure — no I/O, no mutation. Both inputs come from scans the caller already
/// performs.
///
/// A file is drifted only when *both* digests are known and they differ. That
/// makes every "unknown" case a non-report:
///
/// - a record confirmed before the stamp existed (`confirmed_content` empty),
/// - a glob entry such as `src/payments/**`, which has no `file:*` record,
/// - a path re-keyed by the rename migration, whose stamp is under the old
///   spelling (a rename is not a content change),
/// - a file `mati init` could not parse, which carries no `content_hash`.
///
/// Unconfirmed gotchas are skipped outright: they are Layer 0 candidates that
/// nobody vouched for, so there is no sign-off for the code to have drifted
/// away from.
pub fn detect_drift(
    gotcha_records: &[Record],
    current_hashes: &HashMap<String, String>,
) -> Vec<DriftedGotcha> {
    let mut out: Vec<DriftedGotcha> = Vec::new();

    for record in gotcha_records {
        if !matches!(record.lifecycle, RecordLifecycle::Active) {
            continue;
        }
        let Some(gotcha) = record.payload_as::<GotchaRecord>() else {
            continue;
        };
        if !gotcha.confirmed || gotcha.confirmed_content.is_empty() {
            continue;
        }

        let drifted_files: Vec<String> = gotcha
            .affected_files
            .iter()
            .filter(|path| {
                match (
                    gotcha.confirmed_content.get(*path),
                    current_hashes.get(*path),
                ) {
                    (Some(stamped), Some(current)) => stamped != current,
                    _ => false,
                }
            })
            .cloned()
            .collect();

        if !drifted_files.is_empty() {
            out.push(DriftedGotcha {
                key: record.key.clone(),
                rule: gotcha.rule.clone(),
                drifted_files,
            });
        }
    }

    out.sort_by(|a, b| a.key.cmp(&b.key));
    out
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::record::{
        Category, ConfidenceScore, Priority, QualityScore, RecordSource, RecordVersion,
        StalenessScore, TombstoneReason,
    };
    use std::collections::BTreeMap;

    fn stamp(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn hashes(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn gotcha(
        key: &str,
        files: &[&str],
        confirmed: bool,
        confirmed_content: BTreeMap<String, String>,
    ) -> Record {
        let payload = GotchaRecord {
            rule: "Call close() before drop".into(),
            reason: "because the lock leaks otherwise".into(),
            severity: Priority::High,
            affected_files: files.iter().map(|s| s.to_string()).collect(),
            ref_url: None,
            discovered_session: 1_000_000,
            confirmed,
            confirmed_content,
        };
        Record {
            key: key.to_string(),
            value: payload.rule.clone(),
            payload: serde_json::to_value(&payload).ok(),
            category: Category::Gotcha,
            priority: Priority::High,
            tags: vec![],
            created_at: 1_000_000,
            updated_at: 1_000_000,
            ref_url: None,
            staleness: StalenessScore::fresh(),
            lifecycle: RecordLifecycle::Active,
            version: RecordVersion {
                device_id: uuid::Uuid::new_v4(),
                logical_clock: 1,
                wall_clock: 1_000_000,
            },
            quality: QualityScore::layer0_default(),
            access_count: 0,
            last_accessed: 0,
            source: RecordSource::DeveloperManual,
            confidence: ConfidenceScore::for_new_record(&RecordSource::DeveloperManual),
            gap_analysis_score: 0.0,
        }
    }

    #[test]
    fn unchanged_file_is_not_drift() {
        let g = gotcha(
            "gotcha:a",
            &["src/a.rs"],
            true,
            stamp(&[("src/a.rs", "h1")]),
        );
        let found = detect_drift(&[g], &hashes(&[("src/a.rs", "h1")]));
        assert!(found.is_empty(), "identical digests must not report drift");
    }

    #[test]
    fn changed_file_is_drift() {
        let g = gotcha(
            "gotcha:a",
            &["src/a.rs"],
            true,
            stamp(&[("src/a.rs", "h1")]),
        );
        let found = detect_drift(&[g], &hashes(&[("src/a.rs", "h2")]));
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].key, "gotcha:a");
        assert_eq!(found[0].drifted_files, vec!["src/a.rs".to_string()]);
    }

    /// Pre-upgrade records carry no stamp. They must read as "unknown", not as
    /// drifted — otherwise every existing store would light up on first run.
    #[test]
    fn missing_stamp_is_never_drift() {
        let g = gotcha("gotcha:legacy", &["src/a.rs"], true, BTreeMap::new());
        assert!(detect_drift(&[g], &hashes(&[("src/a.rs", "h2")])).is_empty());
    }

    /// A stamped path whose file record has no digest (unparsed file, glob,
    /// file dropped from the index) is unknown, not drifted.
    #[test]
    fn missing_current_hash_is_never_drift() {
        let g = gotcha(
            "gotcha:a",
            &["src/a.rs", "src/payments/**"],
            true,
            stamp(&[("src/a.rs", "h1")]),
        );
        assert!(detect_drift(&[g], &hashes(&[])).is_empty());
    }

    #[test]
    fn unconfirmed_gotcha_is_never_drift() {
        let g = gotcha(
            "gotcha:a",
            &["src/a.rs"],
            false,
            stamp(&[("src/a.rs", "h1")]),
        );
        assert!(detect_drift(&[g], &hashes(&[("src/a.rs", "h2")])).is_empty());
    }

    #[test]
    fn tombstoned_gotcha_is_never_drift() {
        let mut g = gotcha(
            "gotcha:a",
            &["src/a.rs"],
            true,
            stamp(&[("src/a.rs", "h1")]),
        );
        g.lifecycle = RecordLifecycle::Tombstoned {
            reason: TombstoneReason::ManualDeletion,
            at: 1_000_100,
        };
        assert!(detect_drift(&[g], &hashes(&[("src/a.rs", "h2")])).is_empty());
    }

    /// Multi-file: only the files that actually moved are named, and a gotcha
    /// whose other files are unchanged still reports.
    #[test]
    fn multi_file_reports_only_the_changed_paths() {
        let g = gotcha(
            "gotcha:multi",
            &["src/a.rs", "src/b.rs", "src/c.rs"],
            true,
            stamp(&[("src/a.rs", "h1"), ("src/b.rs", "h2"), ("src/c.rs", "h3")]),
        );
        let found = detect_drift(
            &[g],
            &hashes(&[
                ("src/a.rs", "h1"),
                ("src/b.rs", "CHANGED"),
                ("src/c.rs", "h3"),
            ]),
        );
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].drifted_files, vec!["src/b.rs".to_string()]);
    }

    /// A stamp entry for a path the gotcha no longer names is ignored — the
    /// rename migration rewrites `affected_files` without touching the stamp.
    #[test]
    fn stamp_entry_outside_affected_files_is_ignored() {
        let g = gotcha(
            "gotcha:renamed",
            &["src/new.rs"],
            true,
            stamp(&[("src/old.rs", "h1")]),
        );
        assert!(detect_drift(&[g], &hashes(&[("src/old.rs", "CHANGED")])).is_empty());
    }

    #[test]
    fn current_content_hashes_reads_file_records() {
        let mut file = gotcha("file:src/a.rs", &[], true, BTreeMap::new());
        file.category = Category::File;
        file.payload = Some(serde_json::json!({ "path": "src/a.rs", "content_hash": "h9" }));
        let mut unparsed = file.clone();
        unparsed.key = "file:src/b.bin".into();
        unparsed.payload = Some(serde_json::json!({ "path": "src/b.bin" }));

        let map = current_content_hashes(&[file, unparsed]);
        assert_eq!(map.get("src/a.rs"), Some(&"h9".to_string()));
        assert!(
            !map.contains_key("src/b.bin"),
            "a file with no digest must stay unknown"
        );
    }
}
