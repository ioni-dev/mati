//! Incremental staleness from reparse diffs (M-12-C).
//!
//! When `mati reparse` detects structural changes in a file, this module
//! updates the staleness score on the file record and cascades staleness
//! to linked gotcha records.

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;

use crate::store::record::{FileRecord, Record, StalenessScore, StalenessSignal};
use crate::store::Store;

/// Maximum staleness increment from a single reparse pass.
const MAX_REPARSE_INCREMENT: f32 = 0.4;

/// Staleness increment per entry point change.
const ENTRY_POINT_WEIGHT: f32 = 0.15;

/// Staleness increment per import change.
const IMPORT_WEIGHT: f32 = 0.10;

/// Staleness increment when TODOs change.
const TODOS_WEIGHT: f32 = 0.05;

/// Staleness increment per unsafe block change.
const UNSAFE_WEIGHT: f32 = 0.10;

/// Staleness increment per unwrap change.
const UNWRAP_WEIGHT: f32 = 0.05;

/// Staleness increment cascaded to linked gotchas.
const CASCADE_WEIGHT: f32 = 0.10;

/// Diff between old and new file analysis — drives staleness signals.
#[derive(Debug, Clone)]
pub struct ReparseDiff {
    pub entry_points_added: Vec<String>,
    pub entry_points_removed: Vec<String>,
    pub imports_added: Vec<String>,
    pub imports_removed: Vec<String>,
    pub todos_changed: bool,
    pub unsafe_delta: i32,
    pub unwrap_delta: i32,
}

impl ReparseDiff {
    /// True when no structural changes were detected.
    pub fn is_empty(&self) -> bool {
        self.entry_points_added.is_empty()
            && self.entry_points_removed.is_empty()
            && self.imports_added.is_empty()
            && self.imports_removed.is_empty()
            && !self.todos_changed
            && self.unsafe_delta == 0
            && self.unwrap_delta == 0
    }
}

/// Apply reparse-derived staleness signals to a record's `StalenessScore`.
///
/// Returns the new signals added (empty if diff is empty). The record's
/// staleness value/tier/signals/computed_at are updated in place.
pub fn apply_reparse_staleness(
    record: &mut Record,
    diff: &ReparseDiff,
) -> Vec<StalenessSignal> {
    if diff.is_empty() {
        return vec![];
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut new_signals = Vec::new();
    let mut increment: f32 = 0.0;

    let ep_changes =
        (diff.entry_points_added.len() + diff.entry_points_removed.len()) as u32;
    if ep_changes > 0 {
        let signal = StalenessSignal::EntryPointsChanged(ep_changes);
        new_signals.push(signal);
        increment += ep_changes as f32 * ENTRY_POINT_WEIGHT;
    }

    let import_changes =
        (diff.imports_added.len() + diff.imports_removed.len()) as u32;
    if import_changes > 0 {
        let signal = StalenessSignal::ImportsChanged(import_changes);
        new_signals.push(signal);
        increment += import_changes as f32 * IMPORT_WEIGHT;
    }

    if diff.todos_changed {
        new_signals.push(StalenessSignal::TodosChanged);
        increment += TODOS_WEIGHT;
    }

    if diff.unsafe_delta != 0 {
        new_signals.push(StalenessSignal::UnsafeCountChanged(diff.unsafe_delta));
        increment += diff.unsafe_delta.unsigned_abs() as f32 * UNSAFE_WEIGHT;
    }

    if diff.unwrap_delta != 0 {
        new_signals.push(StalenessSignal::UnwrapCountChanged(diff.unwrap_delta));
        increment += diff.unwrap_delta.unsigned_abs() as f32 * UNWRAP_WEIGHT;
    }

    // Cap increment
    increment = increment.min(MAX_REPARSE_INCREMENT);

    // Update score
    let new_value = (record.staleness.value + increment).min(1.0);
    record.staleness.value = new_value;
    record.staleness.tier = StalenessScore::tier_from_value(new_value);
    record.staleness.computed_at = now;
    record.staleness.signals.extend(new_signals.clone());

    // Cap signal history to prevent unbounded growth
    const MAX_SIGNALS: usize = 20;
    if record.staleness.signals.len() > MAX_SIGNALS {
        let drain_count = record.staleness.signals.len() - MAX_SIGNALS;
        record.staleness.signals.drain(..drain_count);
    }

    new_signals
}

/// Cascade staleness to gotcha records linked from this file record.
///
/// For each `gotcha_keys` entry: add `LinkedFileChanged`, bump staleness by 0.10.
pub async fn cascade_staleness_to_gotchas(
    store: &Store,
    file_record: &FileRecord,
) -> Result<u32> {
    if file_record.gotcha_keys.is_empty() {
        return Ok(0);
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut cascaded = 0u32;

    for gotcha_key in &file_record.gotcha_keys {
        if let Some(mut gotcha_record) = store.get(gotcha_key).await? {
            let signal = StalenessSignal::LinkedFileChanged {
                path: file_record.path.clone(),
            };

            let new_value = (gotcha_record.staleness.value + CASCADE_WEIGHT).min(1.0);
            gotcha_record.staleness.value = new_value;
            gotcha_record.staleness.tier = StalenessScore::tier_from_value(new_value);
            gotcha_record.staleness.computed_at = now;
            gotcha_record.staleness.signals.push(signal);

            const MAX_SIGNALS: usize = 20;
            if gotcha_record.staleness.signals.len() > MAX_SIGNALS {
                let drain_count = gotcha_record.staleness.signals.len() - MAX_SIGNALS;
                gotcha_record.staleness.signals.drain(..drain_count);
            }

            gotcha_record.updated_at = now;
            gotcha_record.version.logical_clock += 1;
            gotcha_record.version.wall_clock = now;

            store.put(gotcha_key, &gotcha_record).await?;
            cascaded += 1;
        }
    }

    Ok(cascaded)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::record::*;
    use tempfile::TempDir;

    fn make_file_record_with_staleness(value: f32) -> Record {
        Record {
            key: "file:src/main.rs".to_string(),
            value: String::new(),
            category: Category::File,
            priority: Priority::Normal,
            tags: vec![],
            created_at: 1_000_000,
            updated_at: 1_000_000,
            ref_url: None,
            staleness: StalenessScore {
                value,
                tier: StalenessScore::tier_from_value(value),
                signals: vec![],
                computed_at: 0,
                last_record_sha: String::new(),
            },
            lifecycle: RecordLifecycle::Active,
            version: RecordVersion {
                device_id: uuid::Uuid::new_v4(),
                logical_clock: 1,
                wall_clock: 1_000_000,
            },
            quality: QualityScore::layer0_default(),
            access_count: 0,
            last_accessed: 0,
            source: RecordSource::StaticAnalysis,
            confidence: ConfidenceScore::for_new_record(&RecordSource::StaticAnalysis),
            gap_analysis_score: 0.0,
        }
    }

    fn make_gotcha_record(key: &str) -> Record {
        let gotcha = GotchaRecord {
            rule: "test rule".into(),
            reason: "test reason".into(),
            severity: Priority::High,
            affected_files: vec!["src/main.rs".into()],
            ref_url: None,
            discovered_session: 0,
            confirmed: true,
        };
        Record {
            key: key.to_string(),
            value: serde_json::to_string(&gotcha).unwrap(),
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

    fn empty_diff() -> ReparseDiff {
        ReparseDiff {
            entry_points_added: vec![],
            entry_points_removed: vec![],
            imports_added: vec![],
            imports_removed: vec![],
            todos_changed: false,
            unsafe_delta: 0,
            unwrap_delta: 0,
        }
    }

    #[test]
    fn empty_diff_produces_no_signals() {
        let mut record = make_file_record_with_staleness(0.0);
        let signals = apply_reparse_staleness(&mut record, &empty_diff());
        assert!(signals.is_empty());
        assert!(record.staleness.value < 0.01);
    }

    #[test]
    fn entry_point_changes_bump_staleness() {
        let mut record = make_file_record_with_staleness(0.0);
        let diff = ReparseDiff {
            entry_points_added: vec!["new_fn".into()],
            entry_points_removed: vec!["old_fn".into()],
            ..empty_diff()
        };
        let signals = apply_reparse_staleness(&mut record, &diff);
        assert_eq!(signals.len(), 1);
        assert!((record.staleness.value - 0.30).abs() < 0.01);
        assert_eq!(record.staleness.tier, StalenessTier::Aging);
    }

    #[test]
    fn import_changes_bump_staleness() {
        let mut record = make_file_record_with_staleness(0.0);
        let diff = ReparseDiff {
            imports_added: vec!["new_dep".into()],
            ..empty_diff()
        };
        let signals = apply_reparse_staleness(&mut record, &diff);
        assert_eq!(signals.len(), 1);
        assert!((record.staleness.value - 0.10).abs() < 0.01);
    }

    #[test]
    fn increment_capped_at_max() {
        let mut record = make_file_record_with_staleness(0.0);
        let diff = ReparseDiff {
            entry_points_added: vec!["a".into(), "b".into(), "c".into(), "d".into()],
            imports_added: vec!["x".into(), "y".into(), "z".into()],
            ..empty_diff()
        };
        let _signals = apply_reparse_staleness(&mut record, &diff);
        // 4*0.15 + 3*0.10 = 0.90, capped at 0.40
        assert!((record.staleness.value - 0.40).abs() < 0.01);
    }

    #[test]
    fn staleness_does_not_exceed_one() {
        let mut record = make_file_record_with_staleness(0.85);
        let diff = ReparseDiff {
            entry_points_added: vec!["a".into(), "b".into()],
            ..empty_diff()
        };
        let _signals = apply_reparse_staleness(&mut record, &diff);
        assert!(record.staleness.value <= 1.0);
    }

    #[test]
    fn tier_updates_correctly_after_increment() {
        let mut record = make_file_record_with_staleness(0.35);
        let diff = ReparseDiff {
            entry_points_removed: vec!["removed_fn".into()],
            ..empty_diff()
        };
        let _signals = apply_reparse_staleness(&mut record, &diff);
        // 0.35 + 0.15 = 0.50 → Stale
        assert_eq!(record.staleness.tier, StalenessTier::Stale);
    }

    #[tokio::test]
    async fn cascade_staleness_bumps_linked_gotchas() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();

        let gotcha = make_gotcha_record("gotcha:test-rule");
        store.put("gotcha:test-rule", &gotcha).await.unwrap();

        let file_record = FileRecord {
            path: "src/main.rs".into(),
            purpose: String::new(),
            entry_points: vec![],
            imports: vec![],
            gotcha_keys: vec!["gotcha:test-rule".into()],
            decision_keys: vec![],
            todos: vec![],
            unsafe_count: 0,
            unwrap_count: 0,
            change_frequency: 0,
            last_author: None,
            is_hotspot: false,
            token_cost_estimate: 0,
            last_modified_session: 0,
        };

        let cascaded = cascade_staleness_to_gotchas(&store, &file_record)
            .await
            .unwrap();

        assert_eq!(cascaded, 1);

        let updated = store.get("gotcha:test-rule").await.unwrap().unwrap();
        assert!((updated.staleness.value - 0.10).abs() < 0.01);
        assert!(updated.staleness.signals.iter().any(|s| {
            matches!(s, StalenessSignal::LinkedFileChanged { path } if path == "src/main.rs")
        }));

        store.close().await.unwrap();
    }

    #[tokio::test]
    async fn cascade_noop_when_no_gotcha_keys() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();

        let file_record = FileRecord {
            path: "src/main.rs".into(),
            purpose: String::new(),
            entry_points: vec![],
            imports: vec![],
            gotcha_keys: vec![],
            decision_keys: vec![],
            todos: vec![],
            unsafe_count: 0,
            unwrap_count: 0,
            change_frequency: 0,
            last_author: None,
            is_hotspot: false,
            token_cost_estimate: 0,
            last_modified_session: 0,
        };

        let cascaded = cascade_staleness_to_gotchas(&store, &file_record)
            .await
            .unwrap();
        assert_eq!(cascaded, 0);

        store.close().await.unwrap();
    }

    #[tokio::test]
    async fn cascade_skips_missing_gotcha_records() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();

        let file_record = FileRecord {
            path: "src/main.rs".into(),
            purpose: String::new(),
            entry_points: vec![],
            imports: vec![],
            gotcha_keys: vec!["gotcha:nonexistent".into()],
            decision_keys: vec![],
            todos: vec![],
            unsafe_count: 0,
            unwrap_count: 0,
            change_frequency: 0,
            last_author: None,
            is_hotspot: false,
            token_cost_estimate: 0,
            last_modified_session: 0,
        };

        let cascaded = cascade_staleness_to_gotchas(&store, &file_record)
            .await
            .unwrap();
        assert_eq!(cascaded, 0);

        store.close().await.unwrap();
    }
}
