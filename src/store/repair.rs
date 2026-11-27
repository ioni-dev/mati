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
//! # Unnormalized paths
//!
//! Rebuilding from the canonical record only works if the record's
//! `affected_files` are spelled the way the read gate spells them. Writes
//! before `gotcha_ops` normalized them could store `./src/a.rs` or an absolute
//! path, which joins to no `file:*` record at all — the gotcha is silently
//! inert. This is drift in the canonical record itself, not in a derived index,
//! so it gets its own class ([`RepairReport::unnormalized_paths`]) and is
//! repaired first, before any index reconciliation.
//!
//! # Orphaned file records
//!
//! A `file:*` record whose path is no longer in the repo is not drift — the
//! derived indexes agree with the canonical records, the file is simply gone.
//! It still inflates every coverage denominator, so [`find_orphaned_files`]
//! reports it, split into [`OrphanKind::OutsideRepo`] (another tree's paths)
//! and [`OrphanKind::DeletedInRepo`] (this project's own history), plus
//! [`OrphanKind::Scaffold`] (files `mati init` wrote, indexed before the walker
//! skipped them).
//! [`purge_orphaned_files`] tombstones them behind `--purge-orphans`, and
//! refuses above [`ORPHAN_PURGE_MAX_SHARE`].
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
//! mati repair                  # full reconcile + verify
//! mati repair --check          # detect drift, exit 1 if found (CI)
//! mati repair --fast           # drain dirty queue only (opportunistic)
//! mati repair --purge-orphans  # also tombstone file records whose path is gone
//! mati repair --json           # machine-readable output
//! ```

use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::{Component, Path};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::graph::edges::{Edge, EdgeKind};
use crate::store::db::Store;
use crate::store::record::{
    Category, GotchaRecord, Priority, Record, RecordLifecycle, RecordSource, RecordVersion,
    StalenessScore, TombstoneReason,
};

/// Read-only store access used by the integrity *check* paths, so they can run
/// against either a direct [`Store`] or a daemon-routed proxy (e.g. the CLI's
/// `StoreProxy`, which routes reads through the daemon socket). Only the three
/// read primitives the checks need — all writes stay on `&Store`.
#[allow(async_fn_in_trait)]
pub trait RepairReader {
    async fn get(&self, key: &str) -> Result<Option<Record>>;
    async fn scan_prefix(&self, prefix: &str) -> Result<Vec<Record>>;
    async fn scan_keys(&self, prefix: &str) -> Result<Vec<String>>;
}

impl RepairReader for Store {
    async fn get(&self, key: &str) -> Result<Option<Record>> {
        Store::get(self, key).await
    }
    async fn scan_prefix(&self, prefix: &str) -> Result<Vec<Record>> {
        Store::scan_prefix(self, prefix).await
    }
    async fn scan_keys(&self, prefix: &str) -> Result<Vec<String>> {
        Store::scan_keys(self, prefix).await
    }
}

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
    /// `affected_files` entries stored in a spelling the read gate never
    /// produces (`./src/a.rs`, an absolute path, `src//a.rs`). `file_path`
    /// holds the offending entry as stored. `#[serde(default)]` so reports
    /// serialized before this field existed still deserialize.
    #[serde(default)]
    pub unnormalized_paths: Vec<DriftEntry>,
    /// `file:*` records whose path no longer resolves under the repo root.
    /// Not drift: the derived indexes agree with the canonical records, the
    /// records are just about files that are gone. Only `mati repair`'s full
    /// scan and `--check` fill this in — both have a repo root to resolve
    /// against. `#[serde(default)]` for reports written before it existed.
    #[serde(default)]
    pub orphaned_files: Vec<OrphanEntry>,
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
            || !self.unnormalized_paths.is_empty()
    }

    pub fn total_drift(&self) -> usize {
        self.missing_file_links.len()
            + self.stale_file_links.len()
            + self.missing_edges.len()
            + self.stale_edges.len()
            + self.unnormalized_paths.len()
    }
}

/// A single drift item — identifies what's wrong and where.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftEntry {
    pub gotcha_key: String,
    pub file_path: String,
}

/// Why a `file:*` record's path does not resolve in the repo. The two mean
/// different things to whoever is deciding whether to purge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrphanKind {
    /// Absolute, or under a top-level directory this repo does not have —
    /// another checkout's tree, indexed by a benchmark or a stray `mati init`.
    OutsideRepo,
    /// Repo-relative and plausible, but gone from the working tree. Real
    /// project history: a file a refactor removed.
    DeletedInRepo,
    /// A file `mati init` wrote. The walker skips these now; stores indexed
    /// before that still hold records for them, whether or not they exist.
    Scaffold,
}

/// A `file:*` record naming a path that is not in the repo any more.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrphanEntry {
    pub key: String,
    pub kind: OrphanKind,
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
            device_id: crate::store::stable_device_id(),
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
pub async fn read_dirty_marker<R: RepairReader>(reader: &R) -> Option<DirtyMarker> {
    reader
        .get(DIRTY_MARKER_KEY)
        .await
        .ok()
        .flatten()
        .and_then(|r| r.payload_as::<DirtyMarker>())
}

/// Check whether the gotcha index is currently marked dirty.
pub async fn is_dirty<R: RepairReader>(reader: &R) -> bool {
    read_dirty_marker(reader)
        .await
        .map(|m| m.dirty)
        .unwrap_or(false)
}

// ── Check ────────────────────────────────────────────────────────────────────

/// Compute the diff between canonical gotcha state and derived indexes.
/// Does not write anything.
///
/// `repo_root` must be [`crate::store::slug_root`] — the root an absolute
/// `affected_files` entry has to be stripped of before it can be recognized as
/// unnormalized.
pub async fn check_gotcha_indexes<R: RepairReader>(
    reader: &R,
    repo_root: &Path,
) -> Result<RepairReport> {
    // Phase 1: derive desired state from canonical gotcha records
    let mut desired = derive_desired_state(reader, repo_root).await?;

    // Phase 2: diff against actual state
    let actual = read_actual_file_links(reader).await?;
    let actual_edges = read_actual_edges(reader).await?;
    desired.drop_tombstoned(&actual.tombstoned);

    let (missing_file_links, stale_file_links) =
        diff_file_links(&desired.file_links, &actual.links);
    let (missing_edges, stale_edges) = diff_edges(&desired.edges, &actual_edges);

    Ok(RepairReport {
        scanned_gotchas: desired.scanned,
        scanned_files: actual.scanned,
        missing_file_links,
        stale_file_links,
        missing_edges,
        stale_edges,
        unnormalized_paths: desired.unnormalized,
        // Needs a repo root, which a `RepairReader` does not carry — the CLI
        // fills this in from `slug_root`.
        orphaned_files: vec![],
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
///
/// `repo_root` must be [`crate::store::slug_root`], for the same reason
/// [`check_gotcha_indexes`] needs it. Fast mode never reads it — it drains
/// the dirty queue against paths the canonical records already carry.
pub async fn repair_gotcha_indexes(
    store: &Store,
    repo_root: &Path,
    mode: RepairMode,
) -> Result<RepairReport> {
    let now = now_secs();

    // For fast mode, only repair keys from the dirty marker queue
    if mode == RepairMode::Fast {
        return repair_fast(store, now).await;
    }

    // Phase 0: re-key gotchas whose affected_files were stored in a spelling
    // the read gate never produces. This has to run BEFORE the desired state is
    // derived — desired state comes from the canonical paths, so reconciling
    // first would rebuild links for the wrong spelling and undo itself.
    let (unnormalized_paths, path_repairs) =
        repair_unnormalized_paths(store, repo_root, now).await?;

    // Phase 1: derive desired state
    let mut desired = derive_desired_state(store, repo_root).await?;
    let scanned_gotchas = desired.scanned;

    // Phase 2: diff
    let actual = read_actual_file_links(store).await?;
    let actual_edges = read_actual_edges(store).await?;
    desired.drop_tombstoned(&actual.tombstoned);
    let scanned_files = actual.scanned;

    let (missing_file_links, stale_file_links) =
        diff_file_links(&desired.file_links, &actual.links);
    let (missing_edges, stale_edges) = diff_edges(&desired.edges, &actual_edges);

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
            unnormalized_paths,
            orphaned_files: vec![],
            repaired_count: path_repairs,
            verification_passed: true,
            dirty_marker_cleared: true,
        });
    }

    // Phase 3: apply repairs

    // 3a. Rebuild file-record gotcha_keys from desired state
    let mut repaired = path_repairs;
    for (file_path, desired_keys) in &desired.file_links {
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
    let actual_file_links_2 = read_actual_file_links(store).await?.links;
    for (file_path, actual_keys) in &actual_file_links_2 {
        if !desired.file_links.contains_key(file_path.as_str()) && !actual_keys.is_empty() {
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
    let verify = check_gotcha_indexes(store, repo_root).await?;
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
        unnormalized_paths,
        orphaned_files: vec![],
        repaired_count: repaired,
        verification_passed,
        dirty_marker_cleared: verification_passed,
    })
}

// ── Path normalization repair ────────────────────────────────────────────────

/// Rewrite every active gotcha whose `affected_files` are not in normalized
/// form, and re-point its file links at the corrected paths.
///
/// Detection and repair share one scan. Link maintenance goes through
/// [`crate::store::gotcha_ops::sync_gotcha_file_links`], which diffs old
/// against new, handles the MVCC retry, and creates a Layer 0 `file:*` stub
/// when the corrected path has no record yet — so the gate starts enforcing
/// without waiting for a re-index. Graph edges are left to the main diff phase,
/// which runs afterwards against the rewritten canonical records.
///
/// Returns the drift that was found (for the report) and the number of records
/// rewritten. The record write fails hard, matching the canonical-record rule
/// in the module docs; the link sync is best-effort.
async fn repair_unnormalized_paths(
    store: &Store,
    repo_root: &Path,
    now: u64,
) -> Result<(Vec<DriftEntry>, usize)> {
    let mut drift: Vec<DriftEntry> = Vec::new();
    let mut repaired = 0usize;

    for mut record in store.scan_prefix("gotcha:").await? {
        if !matches!(record.lifecycle, RecordLifecycle::Active) {
            continue;
        }
        let Some(gotcha) = record.payload_as::<GotchaRecord>() else {
            continue;
        };

        let normalized =
            crate::store::gotcha_ops::normalize_affected_files(&gotcha.affected_files, repo_root);
        if normalized == gotcha.affected_files {
            continue;
        }
        drift.extend(unnormalized_entries(
            &record.key,
            &gotcha.affected_files,
            repo_root,
        ));

        // Patch the array in place rather than re-serializing a GotchaRecord:
        // MCP `mem_set` merges caller payloads, so a gotcha payload can carry
        // fields beyond the struct and re-serializing would drop them.
        let Some(obj) = record.payload.as_mut().and_then(|p| p.as_object_mut()) else {
            continue;
        };
        obj.insert(
            "affected_files".into(),
            serde_json::Value::Array(
                normalized
                    .iter()
                    .cloned()
                    .map(serde_json::Value::String)
                    .collect(),
            ),
        );
        record.updated_at = now;
        record.version.logical_clock += 1;
        record.version.wall_clock = now;
        store.put(&record.key, &record).await?;
        repaired += 1;

        if let Err(e) = crate::store::gotcha_ops::sync_gotcha_file_links(
            store,
            &record.key,
            &gotcha.affected_files,
            &normalized,
        )
        .await
        {
            tracing::warn!("repair: file link re-point failed for {}: {e}", record.key);
        }
    }

    Ok((drift, repaired))
}

// ── Orphaned file records ────────────────────────────────────────────────────

/// Refuse to purge when orphans are this share of the active `file:*` records.
///
/// The failure this guards against is a root that names the wrong tree, which
/// fails *every* path — its signature is ~100%. The worst rate measured on a
/// real store is 48% (a benchmark that indexed a second repo into it). 90%
/// sits between the two.
pub const ORPHAN_PURGE_MAX_SHARE: f64 = 0.9;

/// One orphan scan: what was found, and what it was found among.
pub struct OrphanScan {
    pub orphans: Vec<OrphanEntry>,
    /// Active `file:*` records scanned — the denominator the purge guard uses.
    pub active_files: usize,
}

impl OrphanScan {
    /// True when the orphan share says the root is wrong. Scaffold orphans are
    /// matched by name, not by resolving against the root, so they don't count.
    pub fn looks_like_wrong_root(&self) -> bool {
        let unresolved = self
            .orphans
            .iter()
            .filter(|o| o.kind != OrphanKind::Scaffold)
            .count();
        unresolved as f64 > self.active_files as f64 * ORPHAN_PURGE_MAX_SHARE
    }
}

/// Result of [`purge_orphaned_files`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PurgeOutcome {
    Purged {
        tombstoned: usize,
        unlinked: usize,
    },
    /// Too many orphans to be believable — see [`ORPHAN_PURGE_MAX_SHARE`].
    Refused {
        orphans: usize,
        active_files: usize,
    },
}

/// Find active `file:*` records whose path is no longer in the repo.
///
/// `root` must be [`crate::store::slug_root`] — the working tree the store's
/// slug was keyed on, which is what record paths are relative to. The process
/// cwd is not it (a command runs from subdirectories) and neither is git's
/// discovery from an arbitrary path (a gitlink child resolves to its parent).
pub async fn find_orphaned_files<R: RepairReader>(reader: &R, root: &Path) -> Result<OrphanScan> {
    let mut orphans = Vec::new();
    let mut active_files = 0usize;

    for record in reader.scan_prefix("file:").await? {
        if !matches!(record.lifecycle, RecordLifecycle::Active) {
            continue;
        }
        active_files += 1;

        let path = record.key.strip_prefix("file:").unwrap_or_default();
        let kind = if crate::scaffold::is_generated_file(path) {
            OrphanKind::Scaffold
        } else if path.is_empty() || root.join(path).exists() {
            continue;
        } else {
            classify_orphan(root, path)
        };
        orphans.push(OrphanEntry {
            key: record.key.clone(),
            kind,
        });
    }

    Ok(OrphanScan {
        orphans,
        active_files,
    })
}

/// A path that leaves the repo, or sits under a top-level directory the repo
/// does not have, came from another tree. Anything else is plausibly ours.
///
/// A missing file directly at the repo root has no directory to judge it by,
/// so it reads as deleted-in-repo — the conservative side of the split.
fn classify_orphan(root: &Path, path: &str) -> OrphanKind {
    let path = Path::new(path);
    if path.is_absolute() {
        return OrphanKind::OutsideRepo;
    }
    let mut components = path.components();
    match (components.next(), components.next()) {
        (Some(Component::ParentDir), _) => OrphanKind::OutsideRepo,
        (Some(Component::Normal(top)), Some(_)) if !root.join(top).is_dir() => {
            OrphanKind::OutsideRepo
        }
        _ => OrphanKind::DeletedInRepo,
    }
}

/// Tombstone every orphan in `scan` and drop the derived links pointing at it.
///
/// Soft delete, the way gotcha deletion works: the record stays readable by
/// key and the gotchas that named it are untouched — only the record's
/// `gotcha_keys` entries and its `HasGotcha` edges go. `derive_desired_state`
/// stops wanting links to a tombstoned file record, so the run verifies clean.
pub async fn purge_orphaned_files(store: &Store, scan: &OrphanScan) -> Result<PurgeOutcome> {
    if scan.looks_like_wrong_root() {
        return Ok(PurgeOutcome::Refused {
            orphans: scan.orphans.len(),
            active_files: scan.active_files,
        });
    }

    let now = now_secs();
    let mut tombstoned = 0usize;
    let mut unlinked = 0usize;

    for orphan in &scan.orphans {
        let Some(mut record) = store.get(&orphan.key).await? else {
            continue;
        };
        for gotcha_key in extract_gotcha_keys(&record) {
            let edge = Edge::new(&record.key, EdgeKind::HasGotcha, &gotcha_key).to_key();
            let _ = store.delete(&edge).await;
            unlinked += 1;
        }
        set_gotcha_keys(&mut record, vec![]);
        let reason = match orphan.kind {
            OrphanKind::Scaffold => TombstoneReason::MigrationRepair,
            _ => TombstoneReason::FileDeleted,
        };
        let dead = crate::store::gotcha_ops::tombstoned_copy(&record, reason, now);
        store.put(&dead.key, &dead).await?;
        tombstoned += 1;
    }

    Ok(PurgeOutcome::Purged {
        tombstoned,
        unlinked,
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
                unnormalized_paths: vec![],
                orphaned_files: vec![],
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
        // Fast mode never scans for unnormalized paths — that needs the full
        // `gotcha:*` walk, which is exactly what this mode exists to skip.
        unnormalized_paths: vec![],
        orphaned_files: vec![],
        repaired_count: repaired,
        verification_passed: true,
        dirty_marker_cleared: repaired > 0,
    })
}

// ── Internal helpers ─────────────────────────────────────────────────────────

/// Phase 1 output: what the derived indexes should contain, plus the canonical
/// records that are themselves malformed.
struct DesiredState {
    file_links: HashMap<String, BTreeSet<String>>,
    edges: BTreeSet<(String, String)>,
    scanned: usize,
    /// `affected_files` entries that are not in normalized form. Reported as
    /// drift in its own right — the desired state derived above still uses the
    /// stored spelling, since that is what the indexes were built from.
    unnormalized: Vec<DriftEntry>,
}

impl DesiredState {
    /// A tombstoned `file:*` record is not a link target, the same way a
    /// tombstoned gotcha is not a link source. Without this, purging an orphan
    /// that carried gotcha links would read as missing-link drift forever.
    fn drop_tombstoned(&mut self, tombstoned: &HashSet<String>) {
        self.file_links.retain(|path, _| !tombstoned.contains(path));
        self.edges.retain(|(path, _)| !tombstoned.contains(path));
    }
}

/// Phase 1: build desired state from canonical gotcha records.
async fn derive_desired_state<R: RepairReader>(
    reader: &R,
    repo_root: &Path,
) -> Result<DesiredState> {
    let gotchas = reader.scan_prefix("gotcha:").await?;
    let scanned = gotchas.len();

    let mut file_links: HashMap<String, BTreeSet<String>> = HashMap::new();
    let mut edges: BTreeSet<(String, String)> = BTreeSet::new();
    let mut unnormalized: Vec<DriftEntry> = Vec::new();

    for record in &gotchas {
        if !matches!(record.lifecycle, RecordLifecycle::Active) {
            continue;
        }
        let Some(gotcha) = record.payload_as::<GotchaRecord>() else {
            continue;
        };

        unnormalized.extend(unnormalized_entries(
            &record.key,
            &gotcha.affected_files,
            repo_root,
        ));

        for file_path in &gotcha.affected_files {
            file_links
                .entry(file_path.clone())
                .or_default()
                .insert(record.key.clone());
            edges.insert((file_path.clone(), record.key.clone()));
        }
    }

    Ok(DesiredState {
        file_links,
        edges,
        scanned,
        unnormalized,
    })
}

/// Which of `affected_files` are not in the form the read gate produces.
///
/// An entry is drift when it does not survive
/// [`crate::store::gotcha_ops::normalize_affected_files`] verbatim — either it
/// normalized to something else (`./src/a.rs` → `src/a.rs`) or it collapsed
/// into a duplicate of another entry.
fn unnormalized_entries(
    gotcha_key: &str,
    affected_files: &[String],
    repo_root: &Path,
) -> Vec<DriftEntry> {
    let normalized = crate::store::gotcha_ops::normalize_affected_files(affected_files, repo_root);
    if normalized == affected_files {
        return Vec::new();
    }
    affected_files
        .iter()
        .filter(|path| !normalized.contains(*path))
        .map(|path| DriftEntry {
            gotcha_key: gotcha_key.to_string(),
            file_path: path.clone(),
        })
        .collect()
}

/// Actual state of the file-link index: the `gotcha_keys` each file record
/// carries, how many records were scanned, and which of their paths belong to
/// a tombstoned record.
struct ActualFileLinks {
    links: HashMap<String, Vec<String>>,
    scanned: usize,
    tombstoned: HashSet<String>,
}

/// Read actual gotcha_keys from all file records.
async fn read_actual_file_links<R: RepairReader>(reader: &R) -> Result<ActualFileLinks> {
    let files = reader.scan_prefix("file:").await?;
    let scanned = files.len();
    let mut links: HashMap<String, Vec<String>> = HashMap::new();
    let mut tombstoned: HashSet<String> = HashSet::new();

    for record in &files {
        let path = record
            .key
            .strip_prefix("file:")
            .unwrap_or(&record.key)
            .to_string();
        if !matches!(record.lifecycle, RecordLifecycle::Active) {
            tombstoned.insert(path.clone());
        }
        let keys = extract_gotcha_keys(record);
        if !keys.is_empty() {
            links.insert(path, keys);
        }
    }

    Ok(ActualFileLinks {
        links,
        scanned,
        tombstoned,
    })
}

/// Read actual HasGotcha edges from the graph edge store.
async fn read_actual_edges<R: RepairReader>(reader: &R) -> Result<BTreeSet<(String, String)>> {
    let edge_keys = reader.scan_keys("graph:edge:").await?;
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
            device_id: crate::store::stable_device_id(),
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
                device_id: crate::store::stable_device_id(),
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
            confirmed_content: Default::default(),
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

        let report = check_gotcha_indexes(&store, dir.path()).await.unwrap();
        assert!(!report.has_drift());
        assert_eq!(report.scanned_gotchas, 1);
        assert_eq!(report.scanned_files, 1);

        store.close().await.unwrap();
    }

    #[tokio::test]
    async fn codeowners_candidate_write_has_no_index_drift() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();
        for path in ["src/payments/card.rs", "src/payments/wallet.rs"] {
            store
                .put(&format!("file:{path}"), &make_file(path, &[]))
                .await
                .unwrap();
        }

        let rules = crate::analysis::onboarding::parse_codeowners("src/payments/** @team\n");
        let repo_files = vec![
            "src/payments/card.rs".to_string(),
            "src/payments/wallet.rs".to_string(),
        ];
        let candidate = crate::analysis::onboarding::codeowners_candidates(
            &rules,
            &repo_files,
            uuid::Uuid::nil(),
            1,
            1_000_000,
        )
        .pop()
        .unwrap();
        let gotcha = candidate
            .payload_as::<GotchaRecord>()
            .expect("candidate must carry a GotchaRecord");

        crate::store::gotcha_ops::apply_gotcha_write(
            &store,
            dir.path(),
            &candidate,
            &[],
            &gotcha.affected_files,
            true,
        )
        .await
        .unwrap();

        let report = check_gotcha_indexes(&store, dir.path()).await.unwrap();
        assert!(!report.has_drift());
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

        let report = check_gotcha_indexes(&store, dir.path()).await.unwrap();
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

        let report = check_gotcha_indexes(&store, dir.path()).await.unwrap();
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

        let report = repair_gotcha_indexes(&store, dir.path(), RepairMode::Full)
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

        let report = repair_gotcha_indexes(&store, dir.path(), RepairMode::Full)
            .await
            .unwrap();
        assert!(report.verification_passed);

        let a = store.get("file:src/a.rs").await.unwrap().unwrap();
        assert!(extract_gotcha_keys(&a).is_empty());

        store.close().await.unwrap();
    }

    // ── Unnormalized affected_files ──────────────────────────────────────
    //
    // Records written before `gotcha_ops` normalized paths carry spellings the
    // read gate never produces, so they join to no `file:*` record and the
    // gotcha is silently inert. `--check` has to surface that (it gates CI) and
    // a normal run has to fix it.

    #[tokio::test]
    async fn check_detects_unnormalized_affected_files() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();

        store
            .put("gotcha:g1", &make_gotcha("gotcha:g1", &["./src/a.rs"]))
            .await
            .unwrap();

        let report = check_gotcha_indexes(&store, dir.path()).await.unwrap();
        assert!(report.has_drift(), "--check must exit non-zero on this");
        assert_eq!(report.unnormalized_paths.len(), 1);
        assert_eq!(report.unnormalized_paths[0].gotcha_key, "gotcha:g1");
        assert_eq!(report.unnormalized_paths[0].file_path, "./src/a.rs");
        // Check is read-only: nothing was rewritten.
        let stored = store.get("gotcha:g1").await.unwrap().unwrap();
        let gotcha = stored.payload_as::<GotchaRecord>().unwrap();
        assert_eq!(gotcha.affected_files, vec!["./src/a.rs".to_string()]);

        store.close().await.unwrap();
    }

    #[tokio::test]
    async fn check_reports_no_unnormalized_drift_for_clean_paths_and_globs() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();

        store
            .put(
                "gotcha:g1",
                &make_gotcha("gotcha:g1", &["src/a.rs", "src/payments/**"]),
            )
            .await
            .unwrap();
        store
            .put("file:src/a.rs", &make_file("src/a.rs", &["gotcha:g1"]))
            .await
            .unwrap();

        let report = check_gotcha_indexes(&store, dir.path()).await.unwrap();
        assert!(report.unnormalized_paths.is_empty());

        store.close().await.unwrap();
    }

    /// Full repair re-keys the record, links the corrected path (creating a
    /// Layer 0 stub because `mati init` never indexed it), and drops the link
    /// at the raw spelling. Verification must pass on the same run.
    #[tokio::test]
    async fn repair_rewrites_unnormalized_paths_and_repoints_links() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();

        store
            .put("gotcha:g1", &make_gotcha("gotcha:g1", &["./src/a.rs"]))
            .await
            .unwrap();
        // A file record left over at the raw spelling, as a pre-fix write to an
        // existing `file:./src/a.rs` stub would have produced.
        store
            .put("file:./src/a.rs", &make_file("./src/a.rs", &["gotcha:g1"]))
            .await
            .unwrap();

        let report = repair_gotcha_indexes(&store, dir.path(), RepairMode::Full)
            .await
            .unwrap();
        assert_eq!(report.unnormalized_paths.len(), 1);
        assert!(report.repaired_count > 0);
        assert!(report.verification_passed);

        let stored = store.get("gotcha:g1").await.unwrap().unwrap();
        let gotcha = stored.payload_as::<GotchaRecord>().unwrap();
        assert_eq!(gotcha.affected_files, vec!["src/a.rs".to_string()]);

        let good = store
            .get("file:src/a.rs")
            .await
            .unwrap()
            .expect("corrected path must be linked, stubbed if it had no record");
        assert_eq!(extract_gotcha_keys(&good), vec!["gotcha:g1".to_string()]);

        let raw = store.get("file:./src/a.rs").await.unwrap().unwrap();
        assert!(
            extract_gotcha_keys(&raw).is_empty(),
            "link at the raw spelling must be dropped"
        );

        // Idempotent: a second run finds nothing left to do.
        let again = check_gotcha_indexes(&store, dir.path()).await.unwrap();
        assert!(!again.has_drift());

        store.close().await.unwrap();
    }

    /// Tombstoned records are excluded from every other drift class; the path
    /// check must not resurrect them into the report either.
    #[tokio::test]
    async fn repair_skips_unnormalized_paths_on_tombstoned_gotchas() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();

        let mut record = make_gotcha("gotcha:dead", &["./src/a.rs"]);
        record.lifecycle = RecordLifecycle::Tombstoned {
            reason: crate::store::record::TombstoneReason::ManualDeletion,
            at: 1_000_000,
        };
        store.put("gotcha:dead", &record).await.unwrap();

        let report = check_gotcha_indexes(&store, dir.path()).await.unwrap();
        assert!(report.unnormalized_paths.is_empty());

        store.close().await.unwrap();
    }

    // ── Orphaned file records ────────────────────────────────────────────

    /// A repo root holding one real file under `src/`, so the classifier has
    /// a top-level directory that exists and one that does not.
    fn seed_repo(dir: &Path) {
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(dir.join("src/a.rs"), "fn main() {}").unwrap();
    }

    #[tokio::test]
    async fn orphan_scan_separates_outside_repo_from_deleted_in_repo() {
        let dir = tempfile::TempDir::new().unwrap();
        seed_repo(dir.path());
        let store = Store::open(dir.path()).await.unwrap();

        std::fs::create_dir_all(dir.path().join(".claude/hooks")).unwrap();
        std::fs::write(dir.path().join(".claude/hooks/pre-read.sh"), "").unwrap();
        std::fs::write(dir.path().join(".claude/hooks/mine.sh"), "").unwrap();

        for path in [
            "src/a.rs",
            "src/gone.rs",
            "hclsyntax/parser.go",
            "/tmp/scratchpad/notes.md",
            ".claude/hooks/pre-read.sh",
            ".claude/hooks/mine.sh",
        ] {
            store
                .put(&format!("file:{path}"), &make_file(path, &[]))
                .await
                .unwrap();
        }

        let scan = find_orphaned_files(&store, dir.path()).await.unwrap();
        assert_eq!(scan.active_files, 6);

        let kind = |key: &str| scan.orphans.iter().find(|o| o.key == key).map(|o| o.kind);
        assert_eq!(kind("file:src/a.rs"), None, "the file is right there");
        assert_eq!(kind("file:src/gone.rs"), Some(OrphanKind::DeletedInRepo));
        assert_eq!(
            kind("file:hclsyntax/parser.go"),
            Some(OrphanKind::OutsideRepo),
            "a top-level directory this repo does not have"
        );
        assert_eq!(
            kind("file:/tmp/scratchpad/notes.md"),
            Some(OrphanKind::OutsideRepo)
        );
        assert_eq!(
            kind("file:.claude/hooks/pre-read.sh"),
            Some(OrphanKind::Scaffold),
            "mati wrote it, so it is not project code even though it exists"
        );
        assert_eq!(
            kind("file:.claude/hooks/mine.sh"),
            None,
            "the user's own hook"
        );

        // The scan is read-only.
        let gone = store.get("file:src/gone.rs").await.unwrap().unwrap();
        assert!(matches!(gone.lifecycle, RecordLifecycle::Active));

        store.close().await.unwrap();
    }

    #[tokio::test]
    async fn purge_tombstones_orphans_and_unlinks_their_gotchas() {
        let dir = tempfile::TempDir::new().unwrap();
        seed_repo(dir.path());
        let store = Store::open(dir.path()).await.unwrap();

        store
            .put(
                "gotcha:g1",
                &make_gotcha("gotcha:g1", &["src/a.rs", "src/gone.rs"]),
            )
            .await
            .unwrap();
        store
            .put("file:src/a.rs", &make_file("src/a.rs", &["gotcha:g1"]))
            .await
            .unwrap();
        store
            .put(
                "file:src/gone.rs",
                &make_file("src/gone.rs", &["gotcha:g1"]),
            )
            .await
            .unwrap();
        for path in ["file:src/a.rs", "file:src/gone.rs"] {
            let edge = Edge::new(path, EdgeKind::HasGotcha, "gotcha:g1");
            store
                .put_raw(&edge.to_key(), &now_secs().to_le_bytes())
                .await
                .unwrap();
        }

        let scan = find_orphaned_files(&store, dir.path()).await.unwrap();
        let outcome = purge_orphaned_files(&store, &scan).await.unwrap();
        assert_eq!(
            outcome,
            PurgeOutcome::Purged {
                tombstoned: 1,
                unlinked: 1
            }
        );

        let gone = store.get("file:src/gone.rs").await.unwrap().unwrap();
        assert!(matches!(gone.lifecycle, RecordLifecycle::Tombstoned { .. }));
        assert!(extract_gotcha_keys(&gone).is_empty());

        let edges = store.scan_keys("graph:edge:").await.unwrap();
        let dead_edge = Edge::new("file:src/gone.rs", EdgeKind::HasGotcha, "gotcha:g1").to_key();
        assert!(!edges.contains(&dead_edge));

        // The gotcha still names the purged path, and the surviving file keeps
        // its link. The purge must not read as drift on the next check.
        let live = store.get("file:src/a.rs").await.unwrap().unwrap();
        assert_eq!(extract_gotcha_keys(&live), vec!["gotcha:g1".to_string()]);
        let report = check_gotcha_indexes(&store, dir.path()).await.unwrap();
        assert!(
            !report.has_drift(),
            "purged orphans must not read as missing links: missing_file={:?}, missing_edges={:?}",
            report.missing_file_links.len(),
            report.missing_edges.len(),
        );

        store.close().await.unwrap();
    }

    #[tokio::test]
    async fn purge_refuses_when_orphans_are_most_of_the_store() {
        let dir = tempfile::TempDir::new().unwrap();
        seed_repo(dir.path());
        let store = Store::open(dir.path()).await.unwrap();

        // 1 real file, 19 orphans — 95%, above ORPHAN_PURGE_MAX_SHARE.
        store
            .put("file:src/a.rs", &make_file("src/a.rs", &[]))
            .await
            .unwrap();
        for i in 0..19 {
            let path = format!("src/gone{i}.rs");
            store
                .put(&format!("file:{path}"), &make_file(&path, &[]))
                .await
                .unwrap();
        }

        let scan = find_orphaned_files(&store, dir.path()).await.unwrap();
        assert_eq!(
            purge_orphaned_files(&store, &scan).await.unwrap(),
            PurgeOutcome::Refused {
                orphans: 19,
                active_files: 20
            }
        );

        let untouched = store.get("file:src/gone0.rs").await.unwrap().unwrap();
        assert!(matches!(untouched.lifecycle, RecordLifecycle::Active));

        store.close().await.unwrap();
    }

    #[tokio::test]
    async fn purge_removes_scaffold_records_even_when_they_are_most_of_the_store() {
        let dir = tempfile::TempDir::new().unwrap();
        seed_repo(dir.path());
        let store = Store::open(dir.path()).await.unwrap();

        store
            .put("file:src/a.rs", &make_file("src/a.rs", &[]))
            .await
            .unwrap();
        let scaffold: Vec<String> = crate::scaffold::settings::HOOK_SCRIPTS
            .iter()
            .map(|(name, _)| format!(".claude/hooks/{name}"))
            .collect();
        for path in &scaffold {
            store
                .put(&format!("file:{path}"), &make_file(path, &[]))
                .await
                .unwrap();
        }

        let scan = find_orphaned_files(&store, dir.path()).await.unwrap();
        assert_eq!(
            purge_orphaned_files(&store, &scan).await.unwrap(),
            PurgeOutcome::Purged {
                tombstoned: scaffold.len(),
                unlinked: 0
            }
        );
        let real = store.get("file:src/a.rs").await.unwrap().unwrap();
        assert!(matches!(real.lifecycle, RecordLifecycle::Active));

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
        let pre = check_gotcha_indexes(&store, dir.path()).await.unwrap();
        assert!(pre.has_drift());
        assert_eq!(pre.missing_file_links.len(), 2);
        assert_eq!(pre.missing_edges.len(), 2);

        // ── Repair restores consistency ───────────────────────────────────

        let report = repair_gotcha_indexes(&store, dir.path(), RepairMode::Full)
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
        let post = check_gotcha_indexes(&store, dir.path()).await.unwrap();
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
        let check = check_gotcha_indexes(&store, dir.path()).await.unwrap();
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
            let pre = check_gotcha_indexes(&store, dir.path()).await.unwrap();
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

            let report = repair_gotcha_indexes(&store, dir.path(), RepairMode::Fast)
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

            let post = check_gotcha_indexes(&store, dir.path()).await.unwrap();
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
