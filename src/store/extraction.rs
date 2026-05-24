//! Extraction-outcome tracking for `/mati-enrich`'s closed feedback loop
//! (Proposal D, Phase D3).
//!
//! When the slash flow writes a candidate gotcha during enrichment, this
//! module captures provenance (depth tier, source file, timestamp) into
//! `analytics:extraction:<gotcha_slug>` with `outcome = Pending`. When the
//! developer later confirms or tombstones the gotcha,
//! [`mark_outcome`] flips the outcome and records when. `mati doctor` reads
//! these records to surface per-tier accuracy ("Deep tier: 14 extractions,
//! 50% confirmed → worth investigating"), the metric that lets us prove
//! the adaptive triage is doing real work.
//!
//! Detection rule: a gotcha write is treated as an extraction iff its
//! record tags contain `"enriched"`. Optional `"depth:<tier>"` tag carries
//! the tier the agent extracted at. Both come from the D2-γ prompt updates.
//! Records without `"enriched"` (manual `mati gotcha add`, MCP `mem_set`
//! without enrichment context) are NOT tracked — keeps the analytics
//! clean to the enrichment pipeline.
//!
//! Reference: `ENRICH_QUALITY.md` Section 8 (Feedback loop).

use anyhow::Result;
use serde::{Deserialize, Serialize};

use super::record::{
    Category, ConfidenceScore, Priority, QualityScore, Record, RecordLifecycle, RecordSource,
    RecordVersion, StalenessScore,
};
use super::session::now_secs;
use super::Store;
use crate::health::enrichment::EnrichmentDepth;

/// Key prefix for extraction tracking records.
pub const EXTRACTION_PREFIX: &str = "analytics:extraction:";

/// Tag that signals "this gotcha was written by `/mati-enrich`".
pub const ENRICHED_TAG: &str = "enriched";

/// Tag-prefix that carries the depth tier (e.g. `"depth:deep"`).
pub const DEPTH_TAG_PREFIX: &str = "depth:";

/// Tag-prefix carrying the signal source used to enumerate candidates
/// in Stage 1/2: `"signal-source:ast"` (SOTA-α/β tree-sitter pipeline)
/// or `"signal-source:llm"` (D2-γ prompt-driven scanning). Absent on
/// older records — treated as `Llm` for compatibility.
pub const SIGNAL_SOURCE_TAG_PREFIX: &str = "signal-source:";

/// Tag flag set when the Deep-tier prompt actually included negative
/// exemplars in Stage 2. Present = true; absent = false.
pub const NEG_EXEMPLAR_TAG: &str = "with-neg-exemplars";

/// Lifecycle outcome for an enrichment-produced candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtractionOutcome {
    /// Written but not yet confirmed or tombstoned.
    Pending,
    /// Developer confirmed via `mati gotcha confirm` (or MCP equivalent).
    Confirmed,
    /// Developer tombstoned via `mati gotcha delete` (or MCP equivalent).
    Tombstoned,
}

/// Source of Stage-1/2 signal enumeration. SOTA-α moved signal extraction
/// from LLM-driven scanning to deterministic tree-sitter; this enum lets
/// `mati doctor` A/B the two and prove the SOTA pipeline is actually
/// producing higher-quality candidates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalSource {
    /// Tree-sitter-driven signal extraction via `mati extract-signals`
    /// (SOTA-α/β path).
    Ast,
    /// LLM-driven file scanning (D2-γ / pre-SOTA path).
    Llm,
}

impl SignalSource {
    pub fn as_str(self) -> &'static str {
        match self {
            SignalSource::Ast => "ast",
            SignalSource::Llm => "llm",
        }
    }
}

/// Per-extraction configuration parsed from gotcha tags. Powers the
/// per-config breakdown in `mati doctor`'s extraction-quality section.
///
/// Backward-compat defaults: `signal_source = Llm`, `with_negative_exemplars
/// = false` — matches pre-SOTA behavior so older records bucket sensibly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtractionConfig {
    pub signal_source: SignalSource,
    pub with_negative_exemplars: bool,
}

impl Default for ExtractionConfig {
    fn default() -> Self {
        Self {
            signal_source: SignalSource::Llm,
            with_negative_exemplars: false,
        }
    }
}

impl ExtractionConfig {
    /// Stable label for grouping (`"llm+no_neg"`, `"ast+neg"`, etc.).
    /// Used as the HashMap key in PerConfigStats so reports are
    /// reproducible across runs.
    pub fn label(&self) -> String {
        format!(
            "{}+{}",
            self.signal_source.as_str(),
            if self.with_negative_exemplars {
                "neg"
            } else {
                "no_neg"
            }
        )
    }
}

/// Per-extraction provenance + outcome. One record per enrichment-produced
/// gotcha, keyed by `analytics:extraction:<slug>` (slug = the part after
/// `gotcha:`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExtractionRecord {
    pub gotcha_key: String,
    /// Depth tier the agent used during extraction. `None` when the agent
    /// didn't tag a depth (e.g. older pre-D2 prompt, or a third-party flow).
    pub depth: Option<EnrichmentDepth>,
    /// First affected file (used for directory-scoped aggregation in
    /// `mati doctor`). Empty when the gotcha had no affected_files.
    pub file_path: String,
    pub created_at: u64,
    pub outcome: ExtractionOutcome,
    /// Unix secs when outcome transitioned from Pending. `None` while Pending.
    pub outcome_at: Option<u64>,
    /// SOTA-γ: which pipeline configuration produced this candidate.
    /// `Default::default()` (= llm + no_neg) for backward compat with
    /// records written before this field was added.
    #[serde(default)]
    pub config: ExtractionConfig,
}

impl ExtractionRecord {
    /// Days between creation and outcome. `None` while Pending.
    pub fn days_to_outcome(&self) -> Option<i64> {
        self.outcome_at.map(|t| {
            let delta = t.saturating_sub(self.created_at);
            (delta / 86_400) as i64
        })
    }
}

/// Compute the storage key for a gotcha's extraction record.
pub fn key_for(gotcha_key: &str) -> String {
    let slug = gotcha_key.strip_prefix("gotcha:").unwrap_or(gotcha_key);
    format!("{EXTRACTION_PREFIX}{slug}")
}

/// Parsed classification of a gotcha's enrichment tags.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TagClassification {
    pub is_enriched: bool,
    pub depth: Option<EnrichmentDepth>,
    pub config: ExtractionConfig,
}

/// Inspect a gotcha record's tags and return the full parsed
/// classification:
/// - `is_enriched`: true iff the `enriched` tag is present
/// - `depth`: Some(tier) if a `depth:<tier>` tag is present and valid
/// - `config`: parsed [`ExtractionConfig`] — defaults to `(Llm, false)`
///   when the corresponding tags aren't present, preserving pre-SOTA-γ
///   behavior for records that don't carry the new tags.
pub fn classify_tags(tags: &[String]) -> TagClassification {
    let mut is_enriched = false;
    let mut depth = None;
    let mut config = ExtractionConfig::default();
    for tag in tags {
        if tag == ENRICHED_TAG {
            is_enriched = true;
        } else if tag == NEG_EXEMPLAR_TAG {
            config.with_negative_exemplars = true;
        } else if let Some(rest) = tag.strip_prefix(DEPTH_TAG_PREFIX) {
            depth = match rest {
                "fast" => Some(EnrichmentDepth::Fast),
                "standard" => Some(EnrichmentDepth::Standard),
                "deep" => Some(EnrichmentDepth::Deep),
                _ => None,
            };
        } else if let Some(rest) = tag.strip_prefix(SIGNAL_SOURCE_TAG_PREFIX) {
            config.signal_source = match rest {
                "ast" => SignalSource::Ast,
                "llm" => SignalSource::Llm,
                _ => config.signal_source,
            };
        }
    }
    TagClassification {
        is_enriched,
        depth,
        config,
    }
}

/// Write an ExtractionRecord on gotcha creation (only if the `enriched`
/// tag is present). Best-effort — failure is logged via `tracing::warn`
/// and does not block the gotcha write.
///
/// `affected_files` may be empty; we record `""` in that case so the
/// record still exists for outcome tracking.
pub async fn write_on_extraction(
    store: &Store,
    gotcha_key: &str,
    tags: &[String],
    affected_files: &[String],
) -> Result<bool> {
    let TagClassification {
        is_enriched,
        depth,
        config,
    } = classify_tags(tags);
    if !is_enriched {
        return Ok(false);
    }
    let file_path = affected_files.first().cloned().unwrap_or_default();
    let ts = now_secs();
    let extraction = ExtractionRecord {
        gotcha_key: gotcha_key.to_string(),
        depth,
        file_path,
        created_at: ts,
        outcome: ExtractionOutcome::Pending,
        outcome_at: None,
        config,
    };
    let key = key_for(gotcha_key);
    let record = analytics_record(&key, &extraction, ts);
    match store.put(&key, &record).await {
        Ok(()) => Ok(true),
        Err(e) => {
            tracing::warn!("extraction: write failed for {gotcha_key}: {e}");
            Ok(false)
        }
    }
}

/// Mark an existing ExtractionRecord with the given outcome. No-op if the
/// record doesn't exist (e.g. the gotcha was written by a non-enrichment
/// path, or by an older binary before D3 shipped).
///
/// Best-effort — failure is logged but never propagated.
pub async fn mark_outcome(
    store: &Store,
    gotcha_key: &str,
    outcome: ExtractionOutcome,
) -> Result<bool> {
    let key = key_for(gotcha_key);
    let Some(existing) = store.get(&key).await? else {
        return Ok(false);
    };
    let Some(payload) = existing.payload.clone() else {
        return Ok(false);
    };
    let Ok(mut extraction) = serde_json::from_value::<ExtractionRecord>(payload) else {
        tracing::warn!("extraction: payload deserialize failed for {gotcha_key}");
        return Ok(false);
    };
    // Idempotent — if the outcome is already set, only update the timestamp
    // when the new outcome differs (terminal-state transitions).
    if extraction.outcome == outcome {
        return Ok(false);
    }
    extraction.outcome = outcome;
    extraction.outcome_at = Some(now_secs());
    let record = analytics_record(&key, &extraction, extraction.created_at);
    match store.put(&key, &record).await {
        Ok(()) => Ok(true),
        Err(e) => {
            tracing::warn!("extraction: outcome write failed for {gotcha_key}: {e}");
            Ok(false)
        }
    }
}

/// Aggregate counts for `mati doctor`'s extraction-accuracy section.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExtractionStats {
    pub total: u64,
    pub confirmed: u64,
    pub tombstoned: u64,
    pub pending: u64,
    /// Pending records older than 90 days. Computed dynamically; not a
    /// persisted lifecycle state.
    pub expired: u64,
    pub per_tier: PerTierStats,
    /// SOTA-δ: per-config A/B breakdown. Each entry keyed by
    /// `ExtractionConfig::label()` (`"ast+neg"`, `"llm+no_neg"`, …).
    /// Lets reviewers prove the SOTA pipeline produces better-quality
    /// candidates than the legacy LLM-driven scan.
    #[serde(default)]
    pub per_config: std::collections::BTreeMap<String, TierStats>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PerTierStats {
    pub fast: TierStats,
    pub standard: TierStats,
    pub deep: TierStats,
    /// Records whose tags didn't include a `depth:<tier>` entry.
    pub unknown: TierStats,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TierStats {
    pub total: u64,
    pub confirmed: u64,
    pub tombstoned: u64,
    pub pending: u64,
}

impl TierStats {
    /// Confirmed rate (0.0–1.0), or `None` when total is 0.
    pub fn confirmed_rate(&self) -> Option<f64> {
        if self.total == 0 {
            None
        } else {
            Some(self.confirmed as f64 / self.total as f64)
        }
    }
}

/// Walk all extraction records via direct `Store` and compute aggregate
/// stats. Convenience wrapper around [`aggregate_stats`] for callers that
/// hold a `&Store`. Callers using `StoreProxy` should scan_prefix
/// themselves and call `aggregate_stats` directly.
///
/// `since_secs` filters to extractions created at or after the given
/// unix timestamp. Pass `0` for "all time".
pub async fn compute_stats(store: &Store, since_secs: u64) -> Result<ExtractionStats> {
    let records = store
        .scan_prefix(EXTRACTION_PREFIX)
        .await
        .unwrap_or_default();
    let extractions: Vec<ExtractionRecord> = records
        .into_iter()
        .filter_map(|r| r.payload.and_then(|p| serde_json::from_value(p).ok()))
        .collect();
    Ok(aggregate_stats(&extractions, since_secs, now_secs()))
}

/// Pure aggregator — no I/O. Takes a slice of already-deserialized
/// ExtractionRecord-s and computes the stats.
///
/// `since_secs` filters by `created_at`; `now` is the wall clock used to
/// compute the 90-day expiry cutoff. Splitting I/O from aggregation lets
/// callers reuse the math from either `&Store` (compute_stats) or
/// `&StoreProxy` (which has its own scan_prefix path).
pub fn aggregate_stats(
    extractions: &[ExtractionRecord],
    since_secs: u64,
    now: u64,
) -> ExtractionStats {
    let expiry_cutoff = now.saturating_sub(90 * 86_400);

    let mut stats = ExtractionStats::default();
    for e in extractions {
        if e.created_at < since_secs {
            continue;
        }
        stats.total += 1;
        let tier_stats: &mut TierStats = match e.depth {
            Some(EnrichmentDepth::Fast) => &mut stats.per_tier.fast,
            Some(EnrichmentDepth::Standard) => &mut stats.per_tier.standard,
            Some(EnrichmentDepth::Deep) => &mut stats.per_tier.deep,
            None => &mut stats.per_tier.unknown,
        };
        tier_stats.total += 1;
        // Per-config bucket lookup. Use BTreeMap::entry to lazy-initialize
        // so missing configs don't appear with 0/0/0 noise.
        let config_label = e.config.label();
        let config_stats: &mut TierStats = stats.per_config.entry(config_label).or_default();
        config_stats.total += 1;

        match e.outcome {
            ExtractionOutcome::Confirmed => {
                stats.confirmed += 1;
                tier_stats.confirmed += 1;
                config_stats.confirmed += 1;
            }
            ExtractionOutcome::Tombstoned => {
                stats.tombstoned += 1;
                tier_stats.tombstoned += 1;
                config_stats.tombstoned += 1;
            }
            ExtractionOutcome::Pending => {
                if e.created_at < expiry_cutoff {
                    stats.expired += 1;
                } else {
                    stats.pending += 1;
                    tier_stats.pending += 1;
                    config_stats.pending += 1;
                }
            }
        }
    }
    stats
}

fn analytics_record(key: &str, payload: &ExtractionRecord, created_at: u64) -> Record {
    let value = format!(
        "{:?} ({})",
        payload.outcome,
        payload.depth.map(|d| d.as_str()).unwrap_or("unknown")
    );
    Record {
        key: key.to_string(),
        value,
        payload: serde_json::to_value(payload).ok(),
        category: Category::Analytics,
        priority: Priority::Normal,
        tags: vec![],
        created_at,
        updated_at: now_secs(),
        ref_url: None,
        staleness: StalenessScore::fresh(),
        lifecycle: RecordLifecycle::Active,
        version: RecordVersion {
            device_id: uuid::Uuid::new_v4(),
            logical_clock: 1,
            wall_clock: now_secs(),
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
        let path = Box::leak(Box::new(dir)).path().to_path_buf();
        Store::open(&path).await.unwrap()
    }

    #[test]
    fn classify_tags_detects_enriched_and_depth() {
        let c = classify_tags(&["enriched".into(), "depth:deep".into()]);
        assert!(c.is_enriched);
        assert_eq!(c.depth, Some(EnrichmentDepth::Deep));
        // No signal-source / neg-exemplars tag → defaults to Llm + false.
        assert_eq!(c.config.signal_source, SignalSource::Llm);
        assert!(!c.config.with_negative_exemplars);
    }

    #[test]
    fn classify_tags_no_enriched_is_skipped() {
        let c = classify_tags(&["test".into(), "depth:fast".into()]);
        assert!(!c.is_enriched);
        assert_eq!(c.depth, Some(EnrichmentDepth::Fast));
    }

    #[test]
    fn classify_tags_unknown_depth_value_yields_none() {
        let c = classify_tags(&["enriched".into(), "depth:bogus".into()]);
        assert!(c.is_enriched);
        assert!(c.depth.is_none());
    }

    #[test]
    fn classify_tags_no_depth_tag_yields_none() {
        let c = classify_tags(&["enriched".into(), "other".into()]);
        assert!(c.is_enriched);
        assert!(c.depth.is_none());
    }

    #[test]
    fn classify_tags_picks_up_signal_source_ast_and_neg_exemplars() {
        let c = classify_tags(&[
            "enriched".into(),
            "depth:deep".into(),
            "signal-source:ast".into(),
            "with-neg-exemplars".into(),
        ]);
        assert!(c.is_enriched);
        assert_eq!(c.depth, Some(EnrichmentDepth::Deep));
        assert_eq!(c.config.signal_source, SignalSource::Ast);
        assert!(c.config.with_negative_exemplars);
    }

    #[test]
    fn classify_tags_invalid_signal_source_keeps_default() {
        let c = classify_tags(&["enriched".into(), "signal-source:bogus".into()]);
        assert_eq!(c.config.signal_source, SignalSource::Llm);
    }

    #[test]
    fn extraction_config_label_stable_for_all_combos() {
        let combos = [
            (SignalSource::Llm, false, "llm+no_neg"),
            (SignalSource::Llm, true, "llm+neg"),
            (SignalSource::Ast, false, "ast+no_neg"),
            (SignalSource::Ast, true, "ast+neg"),
        ];
        for (src, neg, expected) in combos {
            let cfg = ExtractionConfig {
                signal_source: src,
                with_negative_exemplars: neg,
            };
            assert_eq!(cfg.label(), expected, "{cfg:?}");
        }
    }

    #[test]
    fn key_for_strips_gotcha_prefix() {
        assert_eq!(key_for("gotcha:foo"), "analytics:extraction:foo");
        assert_eq!(key_for("gotcha:foo:bar"), "analytics:extraction:foo:bar");
        assert_eq!(key_for("foo"), "analytics:extraction:foo");
    }

    #[tokio::test]
    async fn write_on_extraction_skips_when_not_enriched() {
        let store = fresh_store().await;
        let written = write_on_extraction(
            &store,
            "gotcha:manual-add",
            &["test".into()], // no "enriched"
            &["src/foo.rs".into()],
        )
        .await
        .unwrap();
        assert!(!written);
        // Verify nothing was persisted.
        assert!(store
            .get("analytics:extraction:manual-add")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn write_on_extraction_writes_pending_with_depth() {
        let store = fresh_store().await;
        let written = write_on_extraction(
            &store,
            "gotcha:r1",
            &["enriched".into(), "depth:deep".into()],
            &["src/cli/repair.rs".into()],
        )
        .await
        .unwrap();
        assert!(written);

        let rec = store
            .get("analytics:extraction:r1")
            .await
            .unwrap()
            .expect("written");
        let extraction: ExtractionRecord =
            serde_json::from_value(rec.payload.expect("payload")).unwrap();
        assert_eq!(extraction.gotcha_key, "gotcha:r1");
        assert_eq!(extraction.depth, Some(EnrichmentDepth::Deep));
        assert_eq!(extraction.file_path, "src/cli/repair.rs");
        assert_eq!(extraction.outcome, ExtractionOutcome::Pending);
        assert!(extraction.outcome_at.is_none());
    }

    #[tokio::test]
    async fn mark_outcome_flips_pending_to_confirmed() {
        let store = fresh_store().await;
        write_on_extraction(
            &store,
            "gotcha:r2",
            &["enriched".into(), "depth:fast".into()],
            &["src/foo.rs".into()],
        )
        .await
        .unwrap();

        let updated = mark_outcome(&store, "gotcha:r2", ExtractionOutcome::Confirmed)
            .await
            .unwrap();
        assert!(updated);

        let rec = store
            .get("analytics:extraction:r2")
            .await
            .unwrap()
            .expect("present");
        let extraction: ExtractionRecord =
            serde_json::from_value(rec.payload.expect("payload")).unwrap();
        assert_eq!(extraction.outcome, ExtractionOutcome::Confirmed);
        assert!(extraction.outcome_at.is_some());
    }

    #[tokio::test]
    async fn mark_outcome_is_idempotent() {
        let store = fresh_store().await;
        write_on_extraction(
            &store,
            "gotcha:r3",
            &["enriched".into()],
            &["src/x.rs".into()],
        )
        .await
        .unwrap();
        mark_outcome(&store, "gotcha:r3", ExtractionOutcome::Tombstoned)
            .await
            .unwrap();
        // Second call with the same outcome → no-op (returns false).
        let updated = mark_outcome(&store, "gotcha:r3", ExtractionOutcome::Tombstoned)
            .await
            .unwrap();
        assert!(
            !updated,
            "second mark_outcome with same outcome must be no-op"
        );
    }

    #[tokio::test]
    async fn mark_outcome_missing_record_returns_false() {
        let store = fresh_store().await;
        let updated = mark_outcome(&store, "gotcha:nonexistent", ExtractionOutcome::Confirmed)
            .await
            .unwrap();
        assert!(!updated);
    }

    #[tokio::test]
    async fn compute_stats_per_tier_breakdown() {
        let store = fresh_store().await;

        // Write 4 enrichment records across tiers, then mark outcomes.
        let cases = [
            ("gotcha:f1", "fast", ExtractionOutcome::Confirmed),
            ("gotcha:f2", "fast", ExtractionOutcome::Tombstoned),
            ("gotcha:s1", "standard", ExtractionOutcome::Confirmed),
            ("gotcha:d1", "deep", ExtractionOutcome::Confirmed),
        ];
        for (gk, depth, outcome) in &cases {
            write_on_extraction(
                &store,
                gk,
                &["enriched".into(), format!("depth:{depth}")],
                &["src/x.rs".into()],
            )
            .await
            .unwrap();
            mark_outcome(&store, gk, *outcome).await.unwrap();
        }

        let stats = compute_stats(&store, 0).await.unwrap();
        assert_eq!(stats.total, 4);
        assert_eq!(stats.confirmed, 3);
        assert_eq!(stats.tombstoned, 1);
        assert_eq!(stats.per_tier.fast.total, 2);
        assert_eq!(stats.per_tier.fast.confirmed, 1);
        assert_eq!(stats.per_tier.fast.tombstoned, 1);
        assert_eq!(stats.per_tier.standard.total, 1);
        assert_eq!(stats.per_tier.standard.confirmed, 1);
        assert_eq!(stats.per_tier.deep.total, 1);
        assert_eq!(stats.per_tier.deep.confirmed, 1);

        // Rate calculations.
        assert_eq!(stats.per_tier.fast.confirmed_rate(), Some(0.5));
        assert_eq!(stats.per_tier.standard.confirmed_rate(), Some(1.0));
        assert_eq!(stats.per_tier.unknown.confirmed_rate(), None);
    }

    #[tokio::test]
    async fn compute_stats_respects_since_secs() {
        let store = fresh_store().await;
        write_on_extraction(
            &store,
            "gotcha:r",
            &["enriched".into()],
            &["src/x.rs".into()],
        )
        .await
        .unwrap();
        // since_secs in the future → no records.
        let stats = compute_stats(&store, u64::MAX).await.unwrap();
        assert_eq!(stats.total, 0);
    }

    #[test]
    fn days_to_outcome_computed_from_timestamps() {
        let extraction = ExtractionRecord {
            gotcha_key: "gotcha:t".into(),
            depth: None,
            file_path: String::new(),
            created_at: 1_000_000,
            outcome: ExtractionOutcome::Confirmed,
            outcome_at: Some(1_000_000 + 2 * 86_400),
            config: ExtractionConfig::default(),
        };
        assert_eq!(extraction.days_to_outcome(), Some(2));

        let pending = ExtractionRecord {
            gotcha_key: "gotcha:p".into(),
            depth: None,
            file_path: String::new(),
            created_at: 1_000_000,
            outcome: ExtractionOutcome::Pending,
            outcome_at: None,
            config: ExtractionConfig::default(),
        };
        assert_eq!(pending.days_to_outcome(), None);
    }

    #[tokio::test]
    async fn per_config_breakdown_aggregates_correctly() {
        let store = fresh_store().await;

        // Write 4 records across the 4 (signal_source × neg_exemplars)
        // configs. Three confirmed, one tombstoned — proves per-config
        // accuracy aggregation works.
        let cases = [
            (
                "gotcha:a",
                vec!["enriched", "signal-source:ast", "with-neg-exemplars"],
                ExtractionOutcome::Confirmed,
            ),
            (
                "gotcha:b",
                vec!["enriched", "signal-source:ast"],
                ExtractionOutcome::Confirmed,
            ),
            (
                "gotcha:c",
                vec!["enriched", "signal-source:llm", "with-neg-exemplars"],
                ExtractionOutcome::Tombstoned,
            ),
            ("gotcha:d", vec!["enriched"], ExtractionOutcome::Confirmed),
        ];
        for (key, tags, outcome) in &cases {
            let owned: Vec<String> = tags.iter().map(|s| s.to_string()).collect();
            write_on_extraction(&store, key, &owned, &["src/x.rs".into()])
                .await
                .unwrap();
            mark_outcome(&store, key, *outcome).await.unwrap();
        }

        let stats = compute_stats(&store, 0).await.unwrap();
        assert_eq!(stats.total, 4);
        assert_eq!(stats.confirmed, 3);
        assert_eq!(stats.tombstoned, 1);

        // Per-config buckets exist for each combination written.
        assert_eq!(stats.per_config.get("ast+neg").unwrap().total, 1);
        assert_eq!(stats.per_config.get("ast+no_neg").unwrap().total, 1);
        assert_eq!(stats.per_config.get("llm+neg").unwrap().total, 1);
        assert_eq!(stats.per_config.get("llm+no_neg").unwrap().total, 1);

        // ast+* configs both confirmed.
        assert_eq!(stats.per_config.get("ast+neg").unwrap().confirmed, 1);
        assert_eq!(stats.per_config.get("ast+no_neg").unwrap().confirmed, 1);
        // llm+neg got tombstoned.
        assert_eq!(stats.per_config.get("llm+neg").unwrap().tombstoned, 1);
        // llm+no_neg confirmed.
        assert_eq!(stats.per_config.get("llm+no_neg").unwrap().confirmed, 1);
    }
}
