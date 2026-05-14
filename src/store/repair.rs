//! Gotcha index reconciliation engine.
//!
//! # Consistency model
//!
//! Gotcha mutations write to three locations:
//!
//! | Location | Role | Example key |
//! |----------|------|-------------|
//! | `gotcha:*` record | **Canonical truth** | `gotcha:never-unwrap` |
//! | `file:*` payload `.gotcha_keys` | Derived index | `file:src/main.rs` |
//! | `graph:edge:file:…:has_gotcha:gotcha:…` | Derived index | `graph:edge:file:src/main.rs:has_gotcha:gotcha:never-unwrap` |
//!
//! The canonical gotcha record is always written first and fails hard. The
//! derived indexes (file links and graph edges) are best-effort: if they fail,
//! the gotcha record still persists and a dirty marker is set so the drift is
//! visible and repairable.
//!
//! This means **links and edges are never authoritative**. They are
//! materialized views that can be rebuilt entirely from `gotcha:*` records.
//!
//! # Dirty markers
//!
//! When a best-effort secondary write fails in [`super::gotcha_ops`], the
//! affected gotcha key is enqueued in a dirty marker record at
//! `analytics:integrity:gotcha_links`. This marker is:
//! - read by `mati status` to surface "index drift detected" warnings
//! - drained by `mati repair --fast` for targeted reconciliation
//! - cleared by `mati repair` after full reconciliation + verification
//!
//! # Repair modes
//!
//! - **Full** (`mati repair`): scans all gotcha and file records, diffs
//!   against desired state, applies repairs, then verifies by re-running the
//!   diff. Clears the dirty marker only after verification passes. This is the
//!   only mode that provides a complete integrity guarantee.
//!
//! - **Fast** (`mati repair --fast`): drains the dirty-marker queue only.
//!   Repairs the specific gotcha keys that were flagged. This is an
//!   optimization, not an integrity proof — it cannot detect drift that wasn't
//!   caused by a tracked failure (e.g., manual store edits, bugs in other
//!   write paths).
//!
//! - **Check** (`mati repair --check`): read-only diff, no writes. Exits
//!   non-zero if drift exists. CI-ready.
//!
//! # Usage
//!
//! ```text
//! mati repair          # full reconcile + verify
//! mati repair --check  # detect drift, exit 1 if found (CI)
//! mati repair --fast   # drain dirty queue only (opportunistic)
//! mati repair --json   # machine-readable output
//! ```

use std::collections::{BTreeSet, HashMap};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::graph::edges::{Edge, EdgeKind};
use crate::store::db::Store;
use crate::store::record::{
    Category, GotchaRecord, Priority, Record, RecordLifecycle, RecordSource, RecordVersion,
    StalenessScore,
};

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Dirty marker key — written when a best-effort secondary write fails.
pub const DIRTY_MARKER_KEY: &str = "analytics:integrity:gotcha_links";

// ── Report ───────────────────────────────────────────────────────────────────

/// Result of a check or repair operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepairReport {
    pub scanned_gotchas: usize,
    pub scanned_files: usize,
    pub missing_file_links: Vec<DriftEntry>,
    pub stale_file_links: Vec<DriftEntry>,
    pub missing_edges: Vec<DriftEntry>,
    pub stale_edges: Vec<DriftEntry>,
    pub repaired_count: usize,
    pub verification_passed: bool,
    pub dirty_marker_cleared: bool,
}

impl RepairReport {
    pub fn has_drift(&self) -> bool {
        !self.missing_file_links.is_empty()
            || !self.stale_file_links.is_empty()
            || !self.missing_edges.is_empty()
            || !self.stale_edges.is_empty()
    }

    pub fn total_drift(&self) -> usize {
        self.missing_file_links.len()
            + self.stale_file_links.len()
            + self.missing_edges.len()
            + self.stale_edges.len()
    }
}

/// A single drift item — identifies what's wrong and where.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftEntry {
    pub gotcha_key: String,
    pub file_path: String,
}

/// Dirty marker payload — persisted at `DIRTY_MARKER_KEY`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirtyMarker {
    pub dirty: bool,
    pub dirty_since: u64,
    pub cause: String,
    pub affected_keys: Vec<String>,
    pub last_checked_at: u64,
    pub last_repaired_at: u64,
}

impl DirtyMarker {
    pub fn clean() -> Self {
        Self {
            dirty: false,
            dirty_since: 0,
            cause: String::new(),
            affected_keys: vec![],
            last_checked_at: 0,
            last_repaired_at: 0,
        }
    }
}

// ── Dirty marker operations ──────────────────────────────────────────────────

/// Mark the gotcha index as dirty after a partial-write failure.
pub async fn mark_dirty(store: &Store, gotcha_key: &str, cause: &str) {
    let now = now_secs();

    // Try to read existing marker to preserve history
    let mut marker = read_dirty_marker(store)
        .await
        .unwrap_or_else(DirtyMarker::clean);
    marker.dirty = true;
    if marker.dirty_since == 0 {
        marker.dirty_since = now;
    }
    marker.cause = cause.to_string();
    if !marker.affected_keys.contains(&gotcha_key.to_string()) {
        marker.affected_keys.push(gotcha_key.to_string());
    }

    let record = Record {
        key: DIRTY_MARKER_KEY.to_string(),
        value: cause.to_string(),
        payload: serde_json::to_value(&marker).ok(),
        category: Category::Analytics,
        priority: Priority::Normal,
        tags: vec![],
        created_at: now,
        updated_at: now,
        ref_url: None,
        staleness: StalenessScore::fresh(),
        lifecycle: RecordLifecycle::Active,
        version: RecordVersion {
            device_id: uuid::Uuid::new_v4(),
            logical_clock: 1,
            wall_clock: now,
        },
        quality: crate::store::record::QualityScore::layer0_default(),
        access_count: 0,
        last_accessed: 0,
        source: RecordSource::StaticAnalysis,
        confidence: crate::store::record::ConfidenceScore::for_new_record(
            &RecordSource::StaticAnalysis,
        ),
        gap_analysis_score: 0.0,
    };

    // Best-effort — don't fail the caller if marker write fails
    let _ = store.put(DIRTY_MARKER_KEY, &record).await;
}

/// Read the current dirty marker, if any.
pub async fn read_dirty_marker(store: &Store) -> Option<DirtyMarker> {
    store
        .get(DIRTY_MARKER_KEY)
        .await
        .ok()
        .flatten()
        .and_then(|r| r.payload_as::<DirtyMarker>())
}

/// Check whether the gotcha index is currently marked dirty.
pub async fn is_dirty(store: &Store) -> bool {
    read_dirty_marker(store)
        .await
        .map(|m| m.dirty)
        .unwrap_or(false)
}

// ── Check ────────────────────────────────────────────────────────────────────

/// Compute the diff between canonical gotcha state and derived indexes.
/// Does not write anything.
pub async fn check_gotcha_indexes(store: &Store) -> Result<RepairReport> {
    // Phase 1: derive desired state from canonical gotcha records
    let (desired_file_links, desired_edges, scanned_gotchas) = derive_desired_state(store).await?;

    // Phase 2: diff against actual state
    let (actual_file_links, scanned_files) = read_actual_file_links(store).await?;
    let actual_edges = read_actual_edges(store).await?;

    let (missing_file_links, stale_file_links) =
        diff_file_links(&desired_file_links, &actual_file_links);
    let (missing_edges, stale_edges) = diff_edges(&desired_edges, &actual_edges);

    Ok(RepairReport {
        scanned_gotchas,
        scanned_files,
        missing_file_links,
        stale_file_links,
        missing_edges,
        stale_edges,
        repaired_count: 0,
        verification_passed: true, // check-only: no repair to verify
        dirty_marker_cleared: false,
    })
}

// ── Repair ───────────────────────────────────────────────────────────────────

/// Repair mode controls what gets fixed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepairMode {
    /// Full scan and reconcile.
    Full,
    /// Only drain queued dirty items (fast path).
    Fast,
}

/// Reconcile derived indexes to match canonical gotcha state.
pub async fn repair_gotcha_indexes(store: &Store, mode: RepairMode) -> Result<RepairReport> {
    let now = now_secs();

    // For fast mode, only repair keys from the dirty marker queue
    if mode == RepairMode::Fast {
        return repair_fast(store, now).await;
    }

    // Phase 1: derive desired state
    let (desired_file_links, desired_edges, scanned_gotchas) = derive_desired_state(store).await?;

    // Phase 2: diff
    let (actual_file_links, scanned_files) = read_actual_file_links(store).await?;
    let actual_edges = read_actual_edges(store).await?;

    let (missing_file_links, stale_file_links) =
        diff_file_links(&desired_file_links, &actual_file_links);
    let (missing_edges, stale_edges) = diff_edges(&desired_edges, &actual_edges);

    let total_drift =
        missing_file_links.len() + stale_file_links.len() + missing_edges.len() + stale_edges.len();

    if total_drift == 0 {
        // Already clean — clear dirty marker if set
        clear_dirty_marker(store, now).await;
        return Ok(RepairReport {
            scanned_gotchas,
            scanned_files,
            missing_file_links: vec![],
            stale_file_links: vec![],
            missing_edges: vec![],
            stale_edges: vec![],
            repaired_count: 0,
            verification_passed: true,
            dirty_marker_cleared: true,
        });
    }

    // Phase 3: apply repairs

    // 3a. Rebuild file-record gotcha_keys from desired state
    let mut repaired = 0usize;
    for (file_path, desired_keys) in &desired_file_links {
        let file_key = format!("file:{file_path}");
        if let Ok(Some(mut record)) = store.get(&file_key).await {
            let current_keys = extract_gotcha_keys(&record);
            let desired_sorted: Vec<&String> = desired_keys.iter().collect();
            let current_sorted: Vec<&String> = current_keys.iter().collect();

            if desired_sorted != current_sorted {
                set_gotcha_keys(&mut record, desired_keys.iter().cloned().collect());
                record.updated_at = now;
                record.version.logical_clock += 1;
                record.version.wall_clock = now;
                if store.put(&file_key, &record).await.is_ok() {
                    repaired += 1;
                }
            }
        }
    }

    // Also clear gotcha_keys from files that should have none
    let (actual_file_links_2, _) = read_actual_file_links(store).await?;
    for (file_path, actual_keys) in &actual_file_links_2 {
        if !desired_file_links.contains_key(file_path.as_str()) && !actual_keys.is_empty() {
            let file_key = format!("file:{file_path}");
            if let Ok(Some(mut record)) = store.get(&file_key).await {
                set_gotcha_keys(&mut record, vec![]);
                record.updated_at = now;
                record.version.logical_clock += 1;
                record.version.wall_clock = now;
                if store.put(&file_key, &record).await.is_ok() {
                    repaired += 1;
                }
            }
        }
    }

    // 3b. Rebuild graph edges
    let ts = now.to_le_bytes();
    for entry in &missing_edges {
        let file_key = format!("file:{}", entry.file_path);
        let edge_key = Edge::new(&file_key, EdgeKind::HasGotcha, &entry.gotcha_key).to_key();
        if store.put_raw(&edge_key, &ts).await.is_ok() {
            repaired += 1;
        }
    }
    for entry in &stale_edges {
        let file_key = format!("file:{}", entry.file_path);
        let edge_key = Edge::new(&file_key, EdgeKind::HasGotcha, &entry.gotcha_key).to_key();
        if store.delete(&edge_key).await.is_ok() {
            repaired += 1;
        }
    }

    // Phase 4: verify by recomputing diff
    let verify = check_gotcha_indexes(store).await?;
    let verification_passed = !verify.has_drift();

    if verification_passed {
        clear_dirty_marker(store, now).await;
    }

    Ok(RepairReport {
        scanned_gotchas,
        scanned_files,
        missing_file_links,
        stale_file_links,
        missing_edges,
        stale_edges,
        repaired_count: repaired,
        verification_passed,
        dirty_marker_cleared: verification_passed,
    })
}

// ── Fast repair ──────────────────────────────────────────────────────────────

async fn repair_fast(store: &Store, now: u64) -> Result<RepairReport> {
    let marker = match read_dirty_marker(store).await {
        Some(m) if m.dirty => m,
        _ => {
            return Ok(RepairReport {
                scanned_gotchas: 0,
                scanned_files: 0,
                missing_file_links: vec![],
                stale_file_links: vec![],
                missing_edges: vec![],
                stale_edges: vec![],
                repaired_count: 0,
                verification_passed: true,
                dirty_marker_cleared: false,
            });
        }
    };

    let mut repaired = 0usize;
    let ts = now.to_le_bytes();

    for gotcha_key in &marker.affected_keys {
        // Read canonical state for this gotcha
        let desired_files: Vec<String> = match store.get(gotcha_key).await? {
            Some(record) if matches!(record.lifecycle, RecordLifecycle::Active) => record
                .payload_as::<GotchaRecord>()
                .map(|g| g.affected_files)
                .unwrap_or_default(),
            // Tombstoned or missing — desired state is empty
            _ => vec![],
        };

        // Repair file links
        for file_path in &desired_files {
            let file_key = format!("file:{file_path}");
            if let Ok(Some(mut record)) = store.get(&file_key).await {
                let keys = extract_gotcha_keys(&record);
                if !keys.contains(gotcha_key) {
                    let mut new_keys = keys;
                    new_keys.push(gotcha_key.clone());
                    set_gotcha_keys(&mut record, new_keys);
                    record.updated_at = now;
                    record.version.logical_clock += 1;
                    record.version.wall_clock = now;
                    if store.put(&file_key, &record).await.is_ok() {
                        repaired += 1;
                    }
                }
            }

            // Repair edge
            let file_key = format!("file:{file_path}");
            let edge_key = Edge::new(&file_key, EdgeKind::HasGotcha, gotcha_key.as_str()).to_key();
            if store.put_raw(&edge_key, &ts).await.is_ok() {
                repaired += 1;
            }
        }

        // Remove stale links from files that reference this gotcha but are NOT
        // in the current desired_files. This handles both:
        // - tombstoned/missing gotchas (desired_files is empty → all refs removed)
        // - moved gotchas (e.g. affected_files changed from [A,B] to [B,C] → A cleaned)
        //
        // Previously, this scan only ran for the tombstoned case, leaving stale
        // links behind when a gotcha's affected_files changed.
        {
            let desired_set: std::collections::HashSet<&str> =
                desired_files.iter().map(String::as_str).collect();
            let files = store.scan_prefix("file:").await?;
            for mut file_record in files {
                let file_path = file_record
                    .key
                    .strip_prefix("file:")
                    .unwrap_or(&file_record.key);
                // Skip files that are correctly in desired_files
                if desired_set.contains(file_path) {
                    continue;
                }
                let keys = extract_gotcha_keys(&file_record);
                if keys.contains(gotcha_key) {
                    let new_keys: Vec<String> =
                        keys.into_iter().filter(|k| k != gotcha_key).collect();
                    set_gotcha_keys(&mut file_record, new_keys);
                    file_record.updated_at = now;
                    file_record.version.logical_clock += 1;
                    file_record.version.wall_clock = now;
                    if store.put(&file_record.key, &file_record).await.is_ok() {
                        repaired += 1;
                    }
                }
                // Also remove stale HasGotcha edge
                let edge_key =
                    Edge::new(&file_record.key, EdgeKind::HasGotcha, gotcha_key.as_str()).to_key();
                let _ = store.delete(&edge_key).await;
            }
        }
    }

    if repaired > 0 {
        clear_dirty_marker(store, now).await;
    }

    Ok(RepairReport {
        scanned_gotchas: marker.affected_keys.len(),
        scanned_files: 0,
        missing_file_links: vec![],
        stale_file_links: vec![],
        missing_edges: vec![],
        stale_edges: vec![],
        repaired_count: repaired,
        verification_passed: true,
        dirty_marker_cleared: repaired > 0,
    })
}

// ── Internal helpers ─────────────────────────────────────────────────────────

/// Phase 1: build desired state from canonical gotcha records.
async fn derive_desired_state(
    store: &Store,
) -> Result<(
    HashMap<String, BTreeSet<String>>,
    BTreeSet<(String, String)>,
    usize,
)> {
    let gotchas = store.scan_prefix("gotcha:").await?;
    let scanned = gotchas.len();

    let mut desired_file_links: HashMap<String, BTreeSet<String>> = HashMap::new();
    let mut desired_edges: BTreeSet<(String, String)> = BTreeSet::new();

    for record in &gotchas {
        if !matches!(record.lifecycle, RecordLifecycle::Active) {
            continue;
        }
        let Some(gotcha) = record.payload_as::<GotchaRecord>() else {
            continue;
        };

        for file_path in &gotcha.affected_files {
            desired_file_links
                .entry(file_path.clone())
                .or_default()
                .insert(record.key.clone());
            desired_edges.insert((file_path.clone(), record.key.clone()));
        }
    }

    Ok((desired_file_links, desired_edges, scanned))
}

/// Read actual gotcha_keys from all file records.
async fn read_actual_file_links(store: &Store) -> Result<(HashMap<String, Vec<String>>, usize)> {
    let files = store.scan_prefix("file:").await?;
    let count = files.len();
    let mut actual: HashMap<String, Vec<String>> = HashMap::new();

    for record in &files {
        let path = record
            .key
            .strip_prefix("file:")
            .unwrap_or(&record.key)
            .to_string();
        let keys = extract_gotcha_keys(record);
        if !keys.is_empty() {
            actual.insert(path, keys);
        }
    }

    Ok((actual, count))
}

/// Read actual HasGotcha edges from the graph edge store.
async fn read_actual_edges(store: &Store) -> Result<BTreeSet<(String, String)>> {
    let edge_keys = store.scan_keys("graph:edge:").await?;
    let mut actual = BTreeSet::new();

    for key in &edge_keys {
        if let Some(edge) = Edge::from_key(key) {
            if edge.kind == EdgeKind::HasGotcha {
                let file_path = edge
                    .from
                    .strip_prefix("file:")
                    .unwrap_or(&edge.from)
                    .to_string();
                actual.insert((file_path, edge.to));
            }
        }
    }

    Ok(actual)
}

/// Diff file links: compare desired vs actual.
fn diff_file_links(
    desired: &HashMap<String, BTreeSet<String>>,
    actual: &HashMap<String, Vec<String>>,
) -> (Vec<DriftEntry>, Vec<DriftEntry>) {
    let mut missing = Vec::new();
    let mut stale = Vec::new();

    // Find missing links (in desired but not in actual)
    for (file_path, desired_keys) in desired {
        let actual_keys: BTreeSet<String> = actual
            .get(file_path)
            .map(|v| v.iter().cloned().collect())
            .unwrap_or_default();

        for key in desired_keys {
            if !actual_keys.contains(key) {
                missing.push(DriftEntry {
                    gotcha_key: key.clone(),
                    file_path: file_path.clone(),
                });
            }
        }
    }

    // Find stale links (in actual but not in desired)
    for (file_path, actual_keys) in actual {
        let desired_keys = desired.get(file_path);
        for key in actual_keys {
            let is_desired = desired_keys.map(|d| d.contains(key)).unwrap_or(false);
            if !is_desired {
                stale.push(DriftEntry {
                    gotcha_key: key.clone(),
                    file_path: file_path.clone(),
                });
            }
        }
    }

    (missing, stale)
}

/// Diff edges: compare desired vs actual.
fn diff_edges(
    desired: &BTreeSet<(String, String)>,
    actual: &BTreeSet<(String, String)>,
) -> (Vec<DriftEntry>, Vec<DriftEntry>) {
    let missing: Vec<DriftEntry> = desired
        .difference(actual)
        .map(|(file_path, gotcha_key)| DriftEntry {
            gotcha_key: gotcha_key.clone(),
            file_path: file_path.clone(),
        })
        .collect();

    let stale: Vec<DriftEntry> = actual
        .difference(desired)
        .map(|(file_path, gotcha_key)| DriftEntry {
            gotcha_key: gotcha_key.clone(),
            file_path: file_path.clone(),
        })
        .collect();

    (missing, stale)
}

fn extract_gotcha_keys(record: &Record) -> Vec<String> {
    record
        .payload
        .as_ref()
        .and_then(|p| p.get("gotcha_keys"))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

fn set_gotcha_keys(record: &mut Record, keys: Vec<String>) {
    if let Some(payload) = record.payload.as_mut() {
        if let Some(obj) = payload.as_object_mut() {
            obj.insert(
                "gotcha_keys".into(),
                serde_json::Value::Array(keys.into_iter().map(serde_json::Value::String).collect()),
            );
        }
    }
}

/// Remove a single gotcha key from the dirty marker if it is the only key
/// currently flagged.
///
/// Used by [`super::gotcha_ops`] as the "disarm" half of its cancellation
/// guard: after a successful all-secondary-writes path, the caller pre-armed
/// `mark_dirty(key)` upfront and now wants to release it. If another caller
/// has flagged a different key concurrently (or a previous failure left a
/// key behind), we leave the marker alone — `repair_fast` on the next boot
/// will reconcile both. This is best-effort and never blocks the caller.
pub async fn clear_dirty_key_if_solo(store: &Store, gotcha_key: &str) {
    let Some(mut marker) = read_dirty_marker(store).await else {
        return;
    };
    if !marker.dirty {
        return;
    }
    // Only clear if our key is the *only* dirty one. If other keys are
    // present, leaving the marker intact is the safe choice — repair will
    // reconcile our successfully-written derived state as a no-op.
    let only_ours = marker.affected_keys.len() == 1 && marker.affected_keys[0] == gotcha_key;
    if !only_ours {
        return;
    }

    let now = now_secs();
    marker.dirty = false;
    marker.affected_keys.clear();
    marker.last_repaired_at = now;

    let record = Record {
        key: DIRTY_MARKER_KEY.to_string(),
        value: String::new(),
        payload: serde_json::to_value(&marker).ok(),
        category: Category::Analytics,
        priority: Priority::Normal,
        tags: vec![],
        created_at: now,
        updated_at: now,
        ref_url: None,
        staleness: StalenessScore::fresh(),
        lifecycle: RecordLifecycle::Active,
        version: RecordVersion {
            device_id: uuid::Uuid::new_v4(),
            logical_clock: 1,
            wall_clock: now,
        },
        quality: crate::store::record::QualityScore::layer0_default(),
        access_count: 0,
        last_accessed: 0,
        source: RecordSource::StaticAnalysis,
        confidence: crate::store::record::ConfidenceScore::for_new_record(
            &RecordSource::StaticAnalysis,
        ),
        gap_analysis_score: 0.0,
    };
    let _ = store.put(DIRTY_MARKER_KEY, &record).await;
}

async fn clear_dirty_marker(store: &Store, now: u64) {
    if let Some(mut marker) = read_dirty_marker(store).await {
        marker.dirty = false;
        marker.affected_keys.clear();
        marker.last_repaired_at = now;

        let record = Record {
            key: DIRTY_MARKER_KEY.to_string(),
            value: String::new(),
            payload: serde_json::to_value(&marker).ok(),
            category: Category::Analytics,
            priority: Priority::Normal,
            tags: vec![],
            created_at: now,
            updated_at: now,
            ref_url: None,
            staleness: StalenessScore::fresh(),
            lifecycle: RecordLifecycle::Active,
            version: RecordVersion {
                device_id: uuid::Uuid::new_v4(),
                logical_clock: 1,
                wall_clock: now,
            },
            quality: crate::store::record::QualityScore::layer0_default(),
            access_count: 0,
            last_accessed: 0,
            source: RecordSource::StaticAnalysis,
            confidence: crate::store::record::ConfidenceScore::for_new_record(
                &RecordSource::StaticAnalysis,
            ),
            gap_analysis_score: 0.0,
        };
        let _ = store.put(DIRTY_MARKER_KEY, &record).await;
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::record::FileRecord;

    fn make_gotcha(key: &str, files: &[&str]) -> Record {
        let gotcha = GotchaRecord {
            rule: "test".into(),
            reason: "test".into(),
            severity: Priority::High,
            affected_files: files.iter().map(|s| s.to_string()).collect(),
            ref_url: None,
            discovered_session: 1_000_000,
            confirmed: true,
        };
        Record {
            key: key.to_string(),
            value: "test".into(),
            payload: serde_json::to_value(&gotcha).ok(),
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
            quality: crate::store::record::QualityScore::layer0_default(),
            access_count: 0,
            last_accessed: 0,
            source: RecordSource::DeveloperManual,
            confidence: crate::store::record::ConfidenceScore::for_new_record(
                &RecordSource::DeveloperManual,
            ),
            gap_analysis_score: 0.0,
        }
    }

    fn make_file(path: &str, gotcha_keys: &[&str]) -> Record {
        let file = FileRecord {
            path: path.to_string(),
            purpose: String::new(),
            entry_points: vec![],
            imports: vec![],
            gotcha_keys: gotcha_keys.iter().map(|s| s.to_string()).collect(),
            decision_keys: vec![],
            todos: vec![],
            unsafe_count: 0,
            unwrap_count: 0,
            change_frequency: 0,
            last_author: None,
            is_hotspot: false,
            token_cost_estimate: 0,
            last_modified_session: 0,
            content_hash: None,
            line_count: 0,
            blast_radius: None,
            propagated_staleness: None,
        };
        Record {
            key: format!("file:{path}"),
            value: String::new(),
            payload: serde_json::to_value(&file).ok(),
            category: Category::File,
            priority: Priority::Normal,
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
            quality: crate::store::record::QualityScore::layer0_default(),
            access_count: 0,
            last_accessed: 0,
            source: RecordSource::StaticAnalysis,
            confidence: crate::store::record::ConfidenceScore::for_new_record(
                &RecordSource::StaticAnalysis,
            ),
            gap_analysis_score: 0.0,
        }
    }

    #[tokio::test]
    async fn check_detects_no_drift_when_consistent() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();

        store
            .put("gotcha:g1", &make_gotcha("gotcha:g1", &["src/a.rs"]))
            .await
            .unwrap();
        store
            .put("file:src/a.rs", &make_file("src/a.rs", &["gotcha:g1"]))
            .await
            .unwrap();

        let edge = Edge::new("file:src/a.rs", EdgeKind::HasGotcha, "gotcha:g1");
        store
            .put_raw(&edge.to_key(), &now_secs().to_le_bytes())
            .await
            .unwrap();

        let report = check_gotcha_indexes(&store).await.unwrap();
        assert!(!report.has_drift());
        assert_eq!(report.scanned_gotchas, 1);
        assert_eq!(report.scanned_files, 1);

        store.close().await.unwrap();
    }

    #[tokio::test]
    async fn check_detects_missing_file_link() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();

        store
            .put("gotcha:g1", &make_gotcha("gotcha:g1", &["src/a.rs"]))
            .await
            .unwrap();
        // File exists but has no gotcha_keys
        store
            .put("file:src/a.rs", &make_file("src/a.rs", &[]))
            .await
            .unwrap();

        let report = check_gotcha_indexes(&store).await.unwrap();
        assert!(report.has_drift());
        assert_eq!(report.missing_file_links.len(), 1);
        assert_eq!(report.missing_file_links[0].gotcha_key, "gotcha:g1");
        assert_eq!(report.missing_file_links[0].file_path, "src/a.rs");

        store.close().await.unwrap();
    }

    #[tokio::test]
    async fn check_detects_stale_file_link() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();

        // No active gotcha, but file still references one
        store
            .put("file:src/a.rs", &make_file("src/a.rs", &["gotcha:deleted"]))
            .await
            .unwrap();

        let report = check_gotcha_indexes(&store).await.unwrap();
        assert!(report.has_drift());
        assert_eq!(report.stale_file_links.len(), 1);
        assert_eq!(report.stale_file_links[0].gotcha_key, "gotcha:deleted");

        store.close().await.unwrap();
    }

    #[tokio::test]
    async fn repair_fixes_missing_links_and_verifies() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();

        store
            .put(
                "gotcha:g1",
                &make_gotcha("gotcha:g1", &["src/a.rs", "src/b.rs"]),
            )
            .await
            .unwrap();
        store
            .put("file:src/a.rs", &make_file("src/a.rs", &[]))
            .await
            .unwrap();
        store
            .put("file:src/b.rs", &make_file("src/b.rs", &[]))
            .await
            .unwrap();

        let report = repair_gotcha_indexes(&store, RepairMode::Full)
            .await
            .unwrap();
        assert!(report.verification_passed);
        assert!(report.repaired_count > 0);
        assert!(report.dirty_marker_cleared);

        // Verify file records now have the right keys
        let a = store.get("file:src/a.rs").await.unwrap().unwrap();
        let b = store.get("file:src/b.rs").await.unwrap().unwrap();
        assert!(extract_gotcha_keys(&a).contains(&"gotcha:g1".to_string()));
        assert!(extract_gotcha_keys(&b).contains(&"gotcha:g1".to_string()));

        // Verify edges exist
        let edges = store.scan_keys("graph:edge:").await.unwrap();
        let edge_a = Edge::new("file:src/a.rs", EdgeKind::HasGotcha, "gotcha:g1").to_key();
        let edge_b = Edge::new("file:src/b.rs", EdgeKind::HasGotcha, "gotcha:g1").to_key();
        assert!(edges.contains(&edge_a));
        assert!(edges.contains(&edge_b));

        store.close().await.unwrap();
    }

    #[tokio::test]
    async fn repair_removes_stale_links() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();

        // File references a gotcha that doesn't exist
        store
            .put("file:src/a.rs", &make_file("src/a.rs", &["gotcha:ghost"]))
            .await
            .unwrap();

        let report = repair_gotcha_indexes(&store, RepairMode::Full)
            .await
            .unwrap();
        assert!(report.verification_passed);

        let a = store.get("file:src/a.rs").await.unwrap().unwrap();
        assert!(extract_gotcha_keys(&a).is_empty());

        store.close().await.unwrap();
    }

    #[tokio::test]
    async fn dirty_marker_lifecycle() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();

        assert!(!is_dirty(&store).await);

        mark_dirty(&store, "gotcha:test", "link sync failed").await;
        assert!(is_dirty(&store).await);

        let marker = read_dirty_marker(&store).await.unwrap();
        assert!(marker.dirty);
        assert_eq!(marker.affected_keys, vec!["gotcha:test"]);

        clear_dirty_marker(&store, now_secs()).await;
        assert!(!is_dirty(&store).await);

        store.close().await.unwrap();
    }

    /// Simulates a partial-write failure and verifies the full recovery contract:
    /// 1. Canonical gotcha record persists
    /// 2. File links are missing (secondary write "failed")
    /// 3. Dirty marker is set
    /// 4. Repair restores derived state from canonical truth
    /// 5. Dirty marker is cleared after verified repair
    #[tokio::test]
    async fn partial_failure_recovery_contract() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();

        // Seed file records
        store
            .put("file:src/a.rs", &make_file("src/a.rs", &[]))
            .await
            .unwrap();
        store
            .put("file:src/b.rs", &make_file("src/b.rs", &[]))
            .await
            .unwrap();

        // Simulate step 2 succeeding: write the canonical gotcha record directly
        let gotcha = make_gotcha("gotcha:partial", &["src/a.rs", "src/b.rs"]);
        store.put("gotcha:partial", &gotcha).await.unwrap();

        // Simulate step 3 failing: do NOT write file links or edges
        // (this is what happens when sync_gotcha_file_links errors out)

        // Simulate the failure handler: set dirty marker
        mark_dirty(&store, "gotcha:partial", "link sync failed").await;

        // ── Verify partial-failure state ──────────────────────────────────

        // Canonical record exists
        let canonical = store.get("gotcha:partial").await.unwrap();
        assert!(canonical.is_some(), "canonical gotcha record must persist");

        // File links are missing
        let a = store.get("file:src/a.rs").await.unwrap().unwrap();
        let b = store.get("file:src/b.rs").await.unwrap().unwrap();
        assert!(
            extract_gotcha_keys(&a).is_empty(),
            "file link should be missing (secondary write failed)"
        );
        assert!(
            extract_gotcha_keys(&b).is_empty(),
            "file link should be missing (secondary write failed)"
        );

        // Dirty marker is set
        assert!(is_dirty(&store).await, "dirty marker must be set");
        let marker = read_dirty_marker(&store).await.unwrap();
        assert!(marker.affected_keys.contains(&"gotcha:partial".to_string()));

        // Check detects the drift
        let pre = check_gotcha_indexes(&store).await.unwrap();
        assert!(pre.has_drift());
        assert_eq!(pre.missing_file_links.len(), 2);
        assert_eq!(pre.missing_edges.len(), 2);

        // ── Repair restores consistency ───────────────────────────────────

        let report = repair_gotcha_indexes(&store, RepairMode::Full)
            .await
            .unwrap();
        assert!(report.repaired_count > 0, "repair should fix something");
        assert!(
            report.verification_passed,
            "post-repair verification must pass"
        );
        assert!(
            report.dirty_marker_cleared,
            "dirty marker must be cleared after verified repair"
        );

        // File links now correct
        let a2 = store.get("file:src/a.rs").await.unwrap().unwrap();
        let b2 = store.get("file:src/b.rs").await.unwrap().unwrap();
        assert!(extract_gotcha_keys(&a2).contains(&"gotcha:partial".to_string()));
        assert!(extract_gotcha_keys(&b2).contains(&"gotcha:partial".to_string()));

        // Edges now exist
        let edges = store.scan_keys("graph:edge:").await.unwrap();
        let edge_a = Edge::new("file:src/a.rs", EdgeKind::HasGotcha, "gotcha:partial").to_key();
        let edge_b = Edge::new("file:src/b.rs", EdgeKind::HasGotcha, "gotcha:partial").to_key();
        assert!(edges.contains(&edge_a));
        assert!(edges.contains(&edge_b));

        // Dirty marker cleared
        assert!(!is_dirty(&store).await);

        // Re-check confirms no drift remains
        let post = check_gotcha_indexes(&store).await.unwrap();
        assert!(!post.has_drift());

        store.close().await.unwrap();
    }

    /// Verifies that repair_fast removes stale file links when a gotcha's
    /// affected_files changed (e.g. from [A,B] to [B,C]). Previously,
    /// repair_fast only cleaned stale links for tombstoned/missing gotchas,
    /// leaving file A with a stale reference after a move.
    #[tokio::test]
    async fn fast_repair_removes_stale_links_on_move() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();

        // Seed file records for A, B, and C
        store
            .put("file:src/a.rs", &make_file("src/a.rs", &["gotcha:moved"]))
            .await
            .unwrap();
        store
            .put("file:src/b.rs", &make_file("src/b.rs", &["gotcha:moved"]))
            .await
            .unwrap();
        store
            .put("file:src/c.rs", &make_file("src/c.rs", &[]))
            .await
            .unwrap();

        // Gotcha now targets [B, C] — A is stale
        store
            .put(
                "gotcha:moved",
                &make_gotcha("gotcha:moved", &["src/b.rs", "src/c.rs"]),
            )
            .await
            .unwrap();

        // Also add a stale edge for A
        let stale_edge = Edge::new("file:src/a.rs", EdgeKind::HasGotcha, "gotcha:moved");
        store
            .put_raw(&stale_edge.to_key(), &now_secs().to_le_bytes())
            .await
            .unwrap();

        // Mark dirty so repair_fast picks it up
        mark_dirty(&store, "gotcha:moved", "affected_files changed").await;

        // Run fast repair
        let report = repair_fast(&store, now_secs()).await.unwrap();
        assert!(
            report.repaired_count > 0,
            "fast repair should fix something"
        );
        assert!(report.dirty_marker_cleared);

        // A should no longer reference the gotcha
        let a = store.get("file:src/a.rs").await.unwrap().unwrap();
        assert!(
            !extract_gotcha_keys(&a).contains(&"gotcha:moved".to_string()),
            "stale link on file A should be removed"
        );

        // B should still reference the gotcha
        let b = store.get("file:src/b.rs").await.unwrap().unwrap();
        assert!(extract_gotcha_keys(&b).contains(&"gotcha:moved".to_string()));

        // C should now reference the gotcha
        let c = store.get("file:src/c.rs").await.unwrap().unwrap();
        assert!(extract_gotcha_keys(&c).contains(&"gotcha:moved".to_string()));

        // Full check should confirm consistency
        let check = check_gotcha_indexes(&store).await.unwrap();
        assert!(
            !check.has_drift(),
            "no drift should remain after fast repair: missing_file_links={}, stale_file_links={}, missing_edges={}, stale_edges={}",
            check.missing_file_links.len(),
            check.stale_file_links.len(),
            check.missing_edges.len(),
            check.stale_edges.len(),
        );

        store.close().await.unwrap();
    }

    /// Fault-injection test for the `mati serve` boot-time auto-drain.
    ///
    /// Simulates an unclean shutdown that left real drift AND a dirty marker.
    /// On reopen, the same `is_dirty + repair_gotcha_indexes(Fast)` sequence
    /// that `mcp::server::serve()` runs must clear both. Locks down the
    /// contract for the boot-time recovery added alongside the panic hook
    /// and explicit shutdown flush.
    #[tokio::test]
    async fn auto_drain_on_reopen_clears_dirty_marker_and_drift() {
        let dir = tempfile::TempDir::new().unwrap();

        // Session 1: introduce drift (gotcha now targets [B,C], but file A still
        // references it from before, file C has not yet been linked, plus a
        // stale edge to A). Mark dirty as if a partial-write recorded the
        // failure. Close to simulate the daemon process exiting.
        {
            let store = Store::open(dir.path()).await.unwrap();
            store
                .put("file:src/a.rs", &make_file("src/a.rs", &["gotcha:moved"]))
                .await
                .unwrap();
            store
                .put("file:src/b.rs", &make_file("src/b.rs", &["gotcha:moved"]))
                .await
                .unwrap();
            store
                .put("file:src/c.rs", &make_file("src/c.rs", &[]))
                .await
                .unwrap();
            store
                .put(
                    "gotcha:moved",
                    &make_gotcha("gotcha:moved", &["src/b.rs", "src/c.rs"]),
                )
                .await
                .unwrap();
            let stale_edge = Edge::new("file:src/a.rs", EdgeKind::HasGotcha, "gotcha:moved");
            store
                .put_raw(&stale_edge.to_key(), &now_secs().to_le_bytes())
                .await
                .unwrap();
            mark_dirty(&store, "gotcha:moved", "simulated partial-write").await;

            // Sanity: pre-shutdown state really is broken.
            let pre = check_gotcha_indexes(&store).await.unwrap();
            assert!(pre.has_drift(), "drift must exist before shutdown");
            assert!(is_dirty(&store).await, "marker must be set before shutdown");

            store.close().await.unwrap();
        }

        // Session 2: reopen and run the exact sequence `serve()` runs at
        // startup. The dirty marker must survive the reopen (it's persisted
        // in the knowledge tree), and the Fast drain must clear both the
        // marker and the drift.
        {
            let store = Store::open(dir.path()).await.unwrap();
            assert!(
                is_dirty(&store).await,
                "dirty marker should survive reopen across sessions"
            );

            let report = repair_gotcha_indexes(&store, RepairMode::Fast)
                .await
                .unwrap();
            assert!(report.repaired_count > 0, "Fast drain must apply repairs");
            assert!(
                report.dirty_marker_cleared,
                "Fast drain must clear the dirty marker on success"
            );

            assert!(
                !is_dirty(&store).await,
                "auto-drain should leave no dirty marker behind"
            );

            let post = check_gotcha_indexes(&store).await.unwrap();
            assert!(
                !post.has_drift(),
                "no drift after auto-drain: missing_file={}, stale_file={}, missing_edge={}, stale_edge={}",
                post.missing_file_links.len(),
                post.stale_file_links.len(),
                post.missing_edges.len(),
                post.stale_edges.len(),
            );

            store.close().await.unwrap();
        }
    }
}
