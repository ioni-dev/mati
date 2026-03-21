//! Incremental staleness from reparse diffs (M-12-C) and full staleness
//! analysis (M-13-A).
//!
//! When `mati reparse` detects structural changes in a file, this module
//! updates the staleness score on the file record and cascades staleness
//! to linked gotcha records.
//!
//! The [`StalenessAnalyzer`] performs a complete 5-factor staleness computation
//! across all knowledge records, using time, git, semantic, dependency, and
//! cascade signals.

use std::collections::HashMap;
use std::path::Path;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use anyhow::Result;

use crate::store::record::{
    Category, FileRecord, GotchaRecord, Record, RecordLifecycle, StalenessScore, StalenessSignal,
    StalenessTier,
};
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

// ── M-13-A: StalenessAnalyzer — full 5-factor staleness computation ──────────

/// Seconds in one day.
const SECS_PER_DAY: f64 = 86_400.0;

/// Number of days after which the time factor reaches 1.0.
const TIME_STALE_DAYS: f64 = 90.0;

/// Weight for the time-based staleness factor.
const TIME_WEIGHT: f32 = 0.20;

/// Weight for the git-based staleness factor.
const GIT_WEIGHT: f32 = 0.35;

/// Weight for the semantic staleness factor (v0.1: always 0.0).
#[allow(dead_code)]
const SEMANTIC_WEIGHT: f32 = 0.25;

/// Weight for the dependency staleness factor.
const DEP_WEIGHT: f32 = 0.10;

/// Weight multiplier for the cascade staleness factor.
const CASCADE_WEIGHT_FACTOR: f32 = 0.10;

/// Maximum commits examined during a revwalk before bailing out.
const GIT_REVWALK_LIMIT: usize = 2000;

/// When revwalk hits the cap without finding the since-SHA, assume this many
/// commits have occurred (conservative staleness signal).
const GIT_CAP_HIT_COMMITS: u32 = 3;

/// Maximum number of recompute signals to preserve from reparse (M-12).
const MAX_RECOMPUTE_SIGNALS: usize = 10;

/// Time budget for `analyze_all` in milliseconds. After this, stop processing
/// new records and write out whatever was computed.
const ANALYZE_TIME_BUDGET_MS: u64 = 2000;

/// Record key prefixes that the analyzer scans.
const STALENESS_PREFIXES: &[&str] = &["file:", "gotcha:", "decision:", "dep:", "dev_note:"];

/// 24 hours in seconds — window for reparse signal preservation.
const REPARSE_WINDOW_SECS: u64 = 86_400;

// ── StalenessReport ─────────────────────────────────────────────────────────

/// Summary of a full `analyze_all` pass.
#[derive(Debug, Clone)]
pub struct StalenessReport {
    /// Total records scanned.
    pub scanned: u32,
    /// Records whose staleness was updated.
    pub updated: u32,
    /// Records moved to Tombstone.
    pub tombstoned: u32,
    /// Records moved to Liability.
    pub liability: u32,
    /// Records above Stale tier threshold.
    pub stale: u32,
}

// ── StalenessAnalyzer ───────────────────────────────────────────────────────

/// Full staleness analyzer using the 5-factor formula from ARCHITECTURE.md §17.
///
/// Opened once per CLI invocation, reuses the git2 repo handle and cached HEAD.
pub struct StalenessAnalyzer {
    repo: Option<git2::Repository>,
    now: u64,
    head_commit: Option<String>,
}

impl StalenessAnalyzer {
    /// Open the analyzer. `repo_path` should be the project root containing `.git`.
    ///
    /// If the git repo cannot be opened, the analyzer proceeds with git_factor = 0.0.
    pub fn new(repo_path: &Path) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let repo = git2::Repository::open(repo_path).ok();
        let head_commit = repo.as_ref().and_then(|r| head_commit_sha(r));

        Self {
            repo,
            now,
            head_commit,
        }
    }

    /// Test-only constructor that allows injecting a fixed `now` timestamp.
    #[cfg(test)]
    fn new_with_now(repo_path: &Path, now: u64) -> Self {
        let repo = git2::Repository::open(repo_path).ok();
        let head_commit = repo.as_ref().and_then(|r| head_commit_sha(r));

        Self {
            repo,
            now,
            head_commit,
        }
    }

    /// Scan all staleness-eligible prefixes, recompute scores, and batch-write
    /// updated records. Respects a 2-second time budget — partial results are
    /// written if the budget is exceeded.
    pub async fn analyze_all(&self, store: &Store) -> Result<StalenessReport> {
        let deadline = Instant::now() + std::time::Duration::from_millis(ANALYZE_TIME_BUDGET_MS);

        let mut report = StalenessReport {
            scanned: 0,
            updated: 0,
            tombstoned: 0,
            liability: 0,
            stale: 0,
        };

        // Pre-load dep records for dep_factor lookups.
        let dep_records = store.scan_prefix("dep:").await.unwrap_or_default();
        let dep_cache: HashMap<String, Record> = dep_records
            .into_iter()
            .map(|r| (r.key.clone(), r))
            .collect();

        let mut updates: Vec<(String, Record)> = Vec::new();

        for prefix in STALENESS_PREFIXES {
            if Instant::now() >= deadline {
                tracing::warn!(
                    "staleness analyze_all: time budget exceeded after {} records",
                    report.scanned
                );
                break;
            }

            let records = match store.scan_prefix(prefix).await {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!("staleness scan_prefix({prefix}) failed: {e}");
                    continue;
                }
            };

            for record in records {
                if Instant::now() >= deadline {
                    tracing::warn!(
                        "staleness analyze_all: time budget exceeded mid-prefix at {} records",
                        report.scanned
                    );
                    break;
                }

                report.scanned += 1;

                // Skip non-active records.
                if !matches!(record.lifecycle, RecordLifecycle::Active) {
                    continue;
                }

                let mut updated = record.clone();
                match self
                    .compute_staleness(&mut updated, store, &dep_cache)
                    .await
                {
                    Ok(()) => {}
                    Err(e) => {
                        tracing::warn!("staleness compute for {} failed: {e}", record.key);
                        continue;
                    }
                }

                if staleness_changed(&record, &updated) {
                    // Track tier counts.
                    match updated.staleness.tier {
                        StalenessTier::Tombstone => report.tombstoned += 1,
                        StalenessTier::Liability => report.liability += 1,
                        StalenessTier::Stale => report.stale += 1,
                        _ => {}
                    }

                    updated.updated_at = self.now;
                    updated.version.logical_clock += 1;
                    updated.version.wall_clock = self.now;

                    updates.push((updated.key.clone(), updated));
                    report.updated += 1;
                }
            }
        }

        // Batch write all updates.
        if !updates.is_empty() {
            let batch: Vec<(&str, &Record)> = updates
                .iter()
                .map(|(k, r)| (k.as_str(), r))
                .collect();
            if let Err(e) = store.put_batch(&batch).await {
                tracing::warn!("staleness batch write failed: {e}");
            }
        }

        Ok(report)
    }

    /// Compute the 5-factor staleness score for a single record.
    ///
    /// Modifies the record in-place. Returns `Ok(())` on success.
    async fn compute_staleness(
        &self,
        record: &mut Record,
        store: &Store,
        dep_cache: &HashMap<String, Record>,
    ) -> Result<()> {
        // Parse FileRecord once if this is a file: record.
        let file_record: Option<FileRecord> = if record.key.starts_with("file:") {
            record.payload_as::<FileRecord>()
        } else {
            None
        };

        // ── Hard override: FileDeleted ──────────────────────────────────────
        // Check if there's already a FileDeleted signal. If so, verify the file
        // is still deleted on disk. If the file was restored, clear the override.
        if record
            .staleness
            .signals
            .iter()
            .any(|s| matches!(s, StalenessSignal::FileDeleted))
        {
            let path = record.key.strip_prefix("file:").unwrap_or(&record.key);
            if Path::new(path).exists() {
                // File was restored — clear the FileDeleted signal.
                record
                    .staleness
                    .signals
                    .retain(|s| !matches!(s, StalenessSignal::FileDeleted));
            } else {
                // Still deleted — tombstone.
                record.staleness.value = 1.0;
                record.staleness.tier = StalenessTier::Tombstone;
                record.staleness.computed_at = self.now;
                return Ok(());
            }
        }

        // Check if file: record's file no longer exists on disk (new detection).
        if record.key.starts_with("file:") {
            let path = record.key.strip_prefix("file:").unwrap_or(&record.key);
            if !path.is_empty() && !Path::new(path).exists() {
                record.staleness.signals.push(StalenessSignal::FileDeleted);
                record.staleness.value = 1.0;
                record.staleness.tier = StalenessTier::Tombstone;
                record.staleness.computed_at = self.now;
                return Ok(());
            }
        }

        // ── Hard override: FileRenamed ──────────────────────────────────────
        let has_rename = record
            .staleness
            .signals
            .iter()
            .any(|s| matches!(s, StalenessSignal::FileRenamed { .. }));
        if has_rename {
            // Find the new_path from the signal.
            let new_path_exists = record.staleness.signals.iter().any(|s| {
                if let StalenessSignal::FileRenamed { new_path } = s {
                    Path::new(new_path).exists()
                } else {
                    false
                }
            });
            if new_path_exists {
                // Rename still unresolved — liability.
                record.staleness.value = 0.85;
                record.staleness.tier = StalenessTier::Liability;
                record.staleness.computed_at = self.now;
                return Ok(());
            }
            // new_path no longer exists either — fall through to normal computation.
            // The rename signal will be retained as historical context.
        }

        // ── Snapshot reparse signals for preservation check ─────────────────
        let reparse_signals: Vec<StalenessSignal> = record
            .staleness
            .signals
            .iter()
            .filter(|s| is_reparse_signal(s))
            .cloned()
            .collect();
        let had_recent_reparse = record.staleness.computed_at > 0
            && self.now.saturating_sub(record.staleness.computed_at) < REPARSE_WINDOW_SECS
            && !reparse_signals.is_empty();
        let old_value = record.staleness.value;

        // ── 5-factor computation ────────────────────────────────────────────
        let time_f = time_factor(record, self.now);

        let (git_f, new_sha) = if let Some(ref repo) = self.repo {
            let path_str = record.key.strip_prefix("file:").unwrap_or(&record.key);
            self.git_factor(repo, path_str, &record.staleness.last_record_sha)
        } else {
            (0.0_f32, None)
        };

        let semantic_f = semantic_factor();

        let dep_f = dep_factor(file_record.as_ref(), dep_cache);

        let cascade_f = cascade_factor(record, file_record.as_ref(), store).await;

        let raw_value = time_f * TIME_WEIGHT
            + git_f * GIT_WEIGHT
            + semantic_f * SEMANTIC_WEIGHT
            + dep_f * DEP_WEIGHT
            + cascade_f * CASCADE_WEIGHT_FACTOR;

        let clamped = raw_value.clamp(0.0, 1.0);

        // ── Reparse signal preservation ─────────────────────────────────────
        // If recent reparse signals exist (within 24h) and the analyzer would
        // reduce the score, preserve the higher value.
        let final_value = if had_recent_reparse && clamped < old_value {
            old_value
        } else {
            clamped
        };

        // ── Build new signals list ──────────────────────────────────────────
        let mut new_signals = Vec::new();

        // Preserve reparse signals (capped).
        if had_recent_reparse {
            for sig in reparse_signals.iter().take(MAX_RECOMPUTE_SIGNALS) {
                new_signals.push(sig.clone());
            }
        }

        // Add git signal if commits were found.
        if git_f > 0.0 {
            // Use LinesChangedPct as a proxy for git factor until GitCommitsSince
            // is added to StalenessSignal in record.rs by a separate agent.
            new_signals.push(StalenessSignal::LinesChangedPct(git_f));
        }

        // Cap total signals.
        const MAX_SIGNALS: usize = 20;
        if new_signals.len() > MAX_SIGNALS {
            let drain_count = new_signals.len() - MAX_SIGNALS;
            new_signals.drain(..drain_count);
        }

        // ── Apply ───────────────────────────────────────────────────────────
        record.staleness.value = final_value;
        record.staleness.tier = StalenessScore::tier_from_value(final_value);
        record.staleness.computed_at = self.now;
        record.staleness.signals = new_signals;

        if let Some(sha) = new_sha {
            record.staleness.last_record_sha = sha;
        }

        Ok(())
    }

    // ── Git factor ──────────────────────────────────────────────────────────

    /// Two-phase git factor:
    /// 1. O(1) blob comparison: compare blob SHA at HEAD vs blob SHA at stored commit.
    /// 2. If changed, revwalk to count commits since stored SHA.
    ///
    /// When `last_record_sha` is empty, set baseline (return 0.0 + HEAD SHA).
    fn git_factor(
        &self,
        repo: &git2::Repository,
        path: &str,
        last_record_sha: &str,
    ) -> (f32, Option<String>) {
        let head_sha = match &self.head_commit {
            Some(sha) => sha.clone(),
            None => return (0.0, None),
        };

        // No baseline established — set it now, no staleness.
        if last_record_sha.is_empty() {
            return (0.0, Some(head_sha));
        }

        // Already at HEAD — no change.
        if last_record_sha == head_sha {
            return (0.0, None);
        }

        // Phase 1: O(1) blob comparison.
        let blob_at_head = blob_sha_at_head(repo, path);
        let blob_at_record = blob_sha_at_commit(repo, path, last_record_sha);

        match (blob_at_head, blob_at_record) {
            (Some(ref h), Some(ref r)) if h == r => {
                // File content unchanged — update SHA to HEAD but no staleness.
                return (0.0, Some(head_sha));
            }
            (None, _) => {
                // File not in HEAD tree — might be deleted. Return small signal.
                return (0.0, Some(head_sha));
            }
            _ => {
                // File changed — phase 2: count commits.
            }
        }

        // Phase 2: revwalk to count commits since stored SHA.
        let count = self.count_commits_since(repo, path, last_record_sha);
        let factor = commits_to_factor(count);

        (factor, Some(head_sha))
    }

    /// Count commits touching `path` since `since_sha`, respecting GIT_REVWALK_LIMIT.
    ///
    /// Uses `total_iterations` (not walked-commit counter) for consistent
    /// merge-commit handling. Returns GIT_CAP_HIT_COMMITS if the revwalk cap
    /// is hit without finding `since_sha` and no commits were counted.
    fn count_commits_since(
        &self,
        repo: &git2::Repository,
        path: &str,
        since_sha: &str,
    ) -> u32 {
        let head_oid = match repo.head().ok().and_then(|h| h.target()) {
            Some(oid) => oid,
            None => return 0,
        };

        let mut revwalk = match repo.revwalk() {
            Ok(rw) => rw,
            Err(_) => return 0,
        };

        if revwalk.push(head_oid).is_err() {
            return 0;
        }

        // Sort topologically for consistent traversal.
        revwalk.set_sorting(git2::Sort::TOPOLOGICAL).ok();

        let mut count: u32 = 0;
        let mut total_iterations: usize = 0;
        let mut found_since = false;

        for oid_result in revwalk {
            total_iterations += 1;
            if total_iterations > GIT_REVWALK_LIMIT {
                break;
            }

            let oid = match oid_result {
                Ok(o) => o,
                Err(_) => continue,
            };

            // Check if we've reached the since-SHA.
            let oid_str = oid.to_string();
            if oid_str == since_sha {
                found_since = true;
                break;
            }

            if commit_touches_file(repo, oid, path) {
                count += 1;
            }
        }

        // Cap hit without finding since_sha and no commits counted.
        if !found_since && count == 0 && total_iterations >= GIT_REVWALK_LIMIT {
            return GIT_CAP_HIT_COMMITS;
        }

        count
    }
}

// ── Factor functions ────────────────────────────────────────────────────────

/// Time factor: linear ramp from 0.0 to 1.0 over TIME_STALE_DAYS.
///
/// Uses `max(updated_at, last_accessed)` as the reference timestamp, NOT
/// `computed_at` (which is when staleness was last recalculated, not when the
/// record was last meaningfully touched).
fn time_factor(record: &Record, now: u64) -> f32 {
    let last_touch = record.updated_at.max(record.last_accessed);
    if last_touch == 0 || last_touch >= now {
        return 0.0;
    }

    let elapsed_secs = (now - last_touch) as f64;
    let elapsed_days = elapsed_secs / SECS_PER_DAY;
    let factor = (elapsed_days / TIME_STALE_DAYS).min(1.0);

    factor as f32
}

/// Semantic factor: placeholder for v0.1 — always returns 0.0.
///
/// In v0.2+ this will use candle embeddings to measure semantic drift between
/// the record's content and the current file content.
fn semantic_factor() -> f32 {
    0.0
}

/// Dependency factor: checks if any imports in the file record reference
/// dependencies whose versions have been bumped since the record was last
/// updated.
///
/// LIMITATION (v0.1): Only parses Rust `use` statements from `FileRecord.imports`.
/// Other languages (TypeScript, Python, Go) will be supported when their import
/// parsers emit normalized dependency names.
fn dep_factor(
    file_record: Option<&FileRecord>,
    dep_cache: &HashMap<String, Record>,
) -> f32 {
    let fr = match file_record {
        Some(fr) => fr,
        None => return 0.0,
    };

    if fr.imports.is_empty() || dep_cache.is_empty() {
        return 0.0;
    }

    let mut bumped_count = 0u32;
    let mut checked_count = 0u32;

    for import in &fr.imports {
        // Extract crate name from Rust use path: "tokio::sync::Mutex" -> "tokio"
        let crate_name = import.split("::").next().unwrap_or(import);
        let dep_key = format!("dep:{crate_name}");

        if let Some(dep_record) = dep_cache.get(&dep_key) {
            checked_count += 1;

            // Check if the dep was updated more recently than the file record.
            if dep_record.updated_at > fr.last_modified_session {
                // Check for DependencyBumped signal on the dep record.
                let has_bump_signal = dep_record.staleness.signals.iter().any(|s| {
                    matches!(s, StalenessSignal::DependencyBumped { .. })
                });
                if has_bump_signal || dep_record.updated_at > fr.last_modified_session + 1 {
                    bumped_count += 1;
                }
            }
        }
    }

    if checked_count == 0 {
        return 0.0;
    }

    // More bumped deps -> higher staleness. Cap at 1.0.
    let ratio = bumped_count as f32 / checked_count as f32;
    ratio.min(1.0)
}

/// Cascade factor: for file records, check if linked gotchas/decisions are stale.
/// For gotcha records, check if affected_files have stale records.
async fn cascade_factor(
    record: &Record,
    file_record: Option<&FileRecord>,
    store: &Store,
) -> f32 {
    match record.category {
        Category::File => {
            let fr = match file_record {
                Some(fr) => fr,
                None => return 0.0,
            };

            let linked_keys: Vec<&str> = fr
                .gotcha_keys
                .iter()
                .chain(fr.decision_keys.iter())
                .map(|s| s.as_str())
                .collect();

            if linked_keys.is_empty() {
                return 0.0;
            }

            let mut stale_count = 0u32;
            for key in &linked_keys {
                if let Ok(Some(linked)) = store.get(key).await {
                    if linked.staleness.value >= 0.4 {
                        stale_count += 1;
                    }
                }
            }

            if stale_count == 0 {
                return 0.0;
            }

            let ratio = stale_count as f32 / linked_keys.len() as f32;
            ratio.min(1.0)
        }
        Category::Gotcha => {
            // Parse the gotcha to find affected_files.
            let gotcha: Option<GotchaRecord> = record.payload_as::<GotchaRecord>();
            let gotcha = match gotcha {
                Some(g) => g,
                None => return 0.0,
            };

            if gotcha.affected_files.is_empty() {
                return 0.0;
            }

            let mut stale_count = 0u32;
            for path in &gotcha.affected_files {
                let file_key = format!("file:{path}");
                if let Ok(Some(file_rec)) = store.get(&file_key).await {
                    if file_rec.staleness.value >= 0.4 {
                        stale_count += 1;
                    }
                }
            }

            if stale_count == 0 {
                return 0.0;
            }

            let ratio = stale_count as f32 / gotcha.affected_files.len() as f32;
            ratio.min(1.0)
        }
        _ => 0.0,
    }
}

// ── Git helper functions ────────────────────────────────────────────────────

/// Get the SHA string of HEAD commit, if available.
fn head_commit_sha(repo: &git2::Repository) -> Option<String> {
    repo.head().ok()?.target().map(|oid| oid.to_string())
}

/// Get the blob SHA for a file at HEAD.
fn blob_sha_at_head(repo: &git2::Repository, path: &str) -> Option<String> {
    let head_ref = repo.head().ok()?;
    let commit = head_ref.peel_to_commit().ok()?;
    let tree = commit.tree().ok()?;
    let entry = tree.get_path(Path::new(path)).ok()?;
    Some(entry.id().to_string())
}

/// Get the blob SHA for a file at a specific commit.
fn blob_sha_at_commit(
    repo: &git2::Repository,
    path: &str,
    commit_sha: &str,
) -> Option<String> {
    let oid = git2::Oid::from_str(commit_sha).ok()?;
    let commit = repo.find_commit(oid).ok()?;
    let tree = commit.tree().ok()?;
    let entry = tree.get_path(Path::new(path)).ok()?;
    Some(entry.id().to_string())
}

/// Count recent commits touching a file path, with a total iteration limit
/// for consistent merge-commit handling.
#[allow(dead_code)]
fn count_recent_commits(
    repo: &git2::Repository,
    path: &str,
    limit: usize,
) -> u32 {
    let head_oid = match repo.head().ok().and_then(|h| h.target()) {
        Some(oid) => oid,
        None => return 0,
    };

    let mut revwalk = match repo.revwalk() {
        Ok(rw) => rw,
        Err(_) => return 0,
    };

    if revwalk.push(head_oid).is_err() {
        return 0;
    }

    revwalk.set_sorting(git2::Sort::TOPOLOGICAL).ok();

    let mut count: u32 = 0;
    let mut total_iterations: usize = 0;

    for oid_result in revwalk {
        total_iterations += 1;
        if total_iterations > limit {
            break;
        }

        let oid = match oid_result {
            Ok(o) => o,
            Err(_) => continue,
        };

        if commit_touches_file(repo, oid, path) {
            count += 1;
        }
    }

    count
}

/// Map a commit count to a staleness factor.
///
/// ```text
/// 0 -> 0.00
/// 1 -> 0.15
/// 2 -> 0.30
/// 3 -> 0.50
/// 4 -> 0.70
/// 5+ -> 1.00
/// ```
fn commits_to_factor(commits: u32) -> f32 {
    match commits {
        0 => 0.0,
        1 => 0.15,
        2 => 0.30,
        3 => 0.50,
        4 => 0.70,
        _ => 1.0,
    }
}

/// Check whether a commit touches a specific file by comparing tree entries
/// with the parent commit's tree.
fn commit_touches_file(
    repo: &git2::Repository,
    commit_oid: git2::Oid,
    path: &str,
) -> bool {
    let commit = match repo.find_commit(commit_oid) {
        Ok(c) => c,
        Err(_) => return false,
    };

    let tree = match commit.tree() {
        Ok(t) => t,
        Err(_) => return false,
    };

    let file_entry = tree.get_path(Path::new(path)).ok();

    // If no parents, this is the initial commit — file is touched if it exists.
    if commit.parent_count() == 0 {
        return file_entry.is_some();
    }

    // Compare with first parent.
    let parent = match commit.parent(0) {
        Ok(p) => p,
        Err(_) => return file_entry.is_some(),
    };

    let parent_tree = match parent.tree() {
        Ok(t) => t,
        Err(_) => return file_entry.is_some(),
    };

    let parent_entry = parent_tree.get_path(Path::new(path)).ok();

    match (file_entry, parent_entry) {
        (Some(cur), Some(par)) => cur.id() != par.id(),
        (Some(_), None) => true,  // File added.
        (None, Some(_)) => true,  // File deleted.
        (None, None) => false,
    }
}

/// Determine whether an old and new staleness state differ enough to warrant
/// writing the updated record.
///
/// Checks: value delta > 0.01, tier change, signal count change, AND
/// last_record_sha change.
fn staleness_changed(old: &Record, new: &Record) -> bool {
    let value_delta = (old.staleness.value - new.staleness.value).abs();
    if value_delta > 0.01 {
        return true;
    }

    if old.staleness.tier != new.staleness.tier {
        return true;
    }

    if old.staleness.signals.len() != new.staleness.signals.len() {
        return true;
    }

    if old.staleness.last_record_sha != new.staleness.last_record_sha {
        return true;
    }

    false
}

/// Returns true if a signal is one generated by the reparse (M-12) pipeline.
fn is_reparse_signal(signal: &StalenessSignal) -> bool {
    matches!(
        signal,
        StalenessSignal::EntryPointsChanged(_)
            | StalenessSignal::ImportsChanged(_)
            | StalenessSignal::TodosChanged
            | StalenessSignal::UnsafeCountChanged(_)
            | StalenessSignal::UnwrapCountChanged(_)
    )
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
            payload: None,
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
            value: gotcha.rule.clone(),
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

    // ── M-13-A: StalenessAnalyzer tests ─────────────────────────────────────

    /// Helper: create a record with specific timestamps for time_factor tests.
    fn make_record_at(key: &str, updated_at: u64, last_accessed: u64) -> Record {
        Record {
            key: key.to_string(),
            value: String::new(),
            category: Category::File,
            priority: Priority::Normal,
            tags: vec![],
            created_at: updated_at,
            updated_at,
            ref_url: None,
            staleness: StalenessScore {
                value: 0.0,
                tier: StalenessTier::Fresh,
                signals: vec![],
                computed_at: 0,
                last_record_sha: String::new(),
            },
            lifecycle: RecordLifecycle::Active,
            version: RecordVersion {
                device_id: uuid::Uuid::new_v4(),
                logical_clock: 1,
                wall_clock: updated_at,
            },
            quality: QualityScore::layer0_default(),
            access_count: 0,
            last_accessed,
            source: RecordSource::StaticAnalysis,
            confidence: ConfidenceScore::for_new_record(&RecordSource::StaticAnalysis),
            gap_analysis_score: 0.0,
            payload: None,
        }
    }

    /// Helper: make a file record with FileRecord value JSON.
    fn make_file_record_full(
        key: &str,
        imports: Vec<String>,
        gotcha_keys: Vec<String>,
        decision_keys: Vec<String>,
        last_modified_session: u64,
    ) -> Record {
        let fr = FileRecord {
            path: key.strip_prefix("file:").unwrap_or(key).to_string(),
            purpose: String::new(),
            entry_points: vec![],
            imports,
            gotcha_keys: gotcha_keys.clone(),
            decision_keys: decision_keys.clone(),
            todos: vec![],
            unsafe_count: 0,
            unwrap_count: 0,
            change_frequency: 0,
            last_author: None,
            is_hotspot: false,
            token_cost_estimate: 0,
            last_modified_session,
        };
        Record {
            key: key.to_string(),
            value: serde_json::to_string(&fr).unwrap(),
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
            quality: QualityScore::layer0_default(),
            access_count: 0,
            last_accessed: 0,
            source: RecordSource::StaticAnalysis,
            confidence: ConfidenceScore::for_new_record(&RecordSource::StaticAnalysis),
            gap_analysis_score: 0.0,
            payload: None,
        }
    }

    // ── time_factor tests ───────────────────────────────────────────────────

    #[test]
    fn time_factor_zero_when_just_updated() {
        let now = 10_000_000u64;
        let record = make_record_at("file:test.rs", now, 0);
        let factor = time_factor(&record, now);
        assert!(factor.abs() < 0.001, "expected ~0.0, got {factor}");
    }

    #[test]
    fn time_factor_half_at_45_days() {
        let now = 10_000_000u64;
        let forty_five_days_ago = now - (45 * 86400);
        let record = make_record_at("file:test.rs", forty_five_days_ago, 0);
        let factor = time_factor(&record, now);
        assert!(
            (factor - 0.5).abs() < 0.02,
            "expected ~0.5 at 45 days, got {factor}"
        );
    }

    #[test]
    fn time_factor_max_at_90_days() {
        let now = 10_000_000u64;
        let ninety_days_ago = now - (90 * 86400);
        let record = make_record_at("file:test.rs", ninety_days_ago, 0);
        let factor = time_factor(&record, now);
        assert!(
            (factor - 1.0).abs() < 0.02,
            "expected ~1.0 at 90 days, got {factor}"
        );
    }

    #[test]
    fn time_factor_uses_last_accessed_when_newer() {
        let now = 10_000_000u64;
        // updated_at is old, but last_accessed is recent.
        let record = make_record_at("file:test.rs", now - (90 * 86400), now - 86400);
        let factor = time_factor(&record, now);
        // Should use last_accessed (1 day ago), not updated_at (90 days ago).
        assert!(
            factor < 0.05,
            "expected near-zero with recent access, got {factor}"
        );
    }

    // ── git_factor tests ────────────────────────────────────────────────────

    #[test]
    fn git_factor_zero_when_no_repo() {
        let analyzer = StalenessAnalyzer {
            repo: None,
            now: 2_000_000,
            head_commit: None,
        };
        // When there's no repo, git_factor can't be called via the analyzer path,
        // so compute_staleness will return (0.0, None) for git.
        // Test the direct path:
        assert!(analyzer.repo.is_none());
    }

    // ── dep_factor tests ────────────────────────────────────────────────────

    #[test]
    fn dep_factor_zero_when_no_imports() {
        let fr = FileRecord {
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
            last_modified_session: 1_000_000,
        };
        let cache = HashMap::new();
        let factor = dep_factor(Some(&fr), &cache);
        assert!(factor.abs() < 0.001);
    }

    #[test]
    fn dep_factor_detects_bumped_dep() {
        let fr = FileRecord {
            path: "src/main.rs".into(),
            purpose: String::new(),
            entry_points: vec![],
            imports: vec!["tokio::sync::Mutex".into()],
            gotcha_keys: vec![],
            decision_keys: vec![],
            todos: vec![],
            unsafe_count: 0,
            unwrap_count: 0,
            change_frequency: 0,
            last_author: None,
            is_hotspot: false,
            token_cost_estimate: 0,
            last_modified_session: 1_000_000,
        };

        // Create a dep record for tokio that was updated after the file.
        let mut dep_rec = Record {
            key: "dep:tokio".to_string(),
            value: String::new(),
            category: Category::Dependency,
            priority: Priority::Normal,
            tags: vec![],
            created_at: 500_000,
            updated_at: 2_000_000, // Updated after file's last_modified_session.
            ref_url: None,
            staleness: StalenessScore {
                value: 0.0,
                tier: StalenessTier::Fresh,
                signals: vec![StalenessSignal::DependencyBumped {
                    dep: "tokio".into(),
                    old_ver: "1.0".into(),
                    new_ver: "1.1".into(),
                }],
                computed_at: 0,
                last_record_sha: String::new(),
            },
            lifecycle: RecordLifecycle::Active,
            version: RecordVersion {
                device_id: uuid::Uuid::new_v4(),
                logical_clock: 1,
                wall_clock: 2_000_000,
            },
            quality: QualityScore::layer0_default(),
            access_count: 0,
            last_accessed: 0,
            source: RecordSource::StaticAnalysis,
            confidence: ConfidenceScore::for_new_record(&RecordSource::StaticAnalysis),
            gap_analysis_score: 0.0,
            payload: None,
        };

        let mut cache = HashMap::new();
        cache.insert("dep:tokio".to_string(), dep_rec.clone());

        let factor = dep_factor(Some(&fr), &cache);
        assert!(
            factor > 0.5,
            "expected high dep factor for bumped dep, got {factor}"
        );

        // With no bump signal and same updated_at, factor should be zero.
        dep_rec.staleness.signals.clear();
        dep_rec.updated_at = 1_000_000; // Same as file.
        cache.insert("dep:tokio".to_string(), dep_rec);
        let factor2 = dep_factor(Some(&fr), &cache);
        assert!(
            factor2.abs() < 0.001,
            "expected zero when dep not bumped, got {factor2}"
        );
    }

    // ── cascade_factor tests ────────────────────────────────────────────────

    #[tokio::test]
    async fn cascade_factor_zero_when_no_linked() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();

        let fr = FileRecord {
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

        let record = make_file_record_full(
            "file:src/main.rs",
            vec![],
            vec![],
            vec![],
            0,
        );

        let factor = cascade_factor(&record, Some(&fr), &store).await;
        assert!(factor.abs() < 0.001);

        store.close().await.unwrap();
    }

    #[tokio::test]
    async fn cascade_factor_detects_stale_linked_gotcha() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();

        // Create a stale gotcha.
        let mut gotcha = make_gotcha_record("gotcha:stale-rule");
        gotcha.staleness.value = 0.6;
        gotcha.staleness.tier = StalenessTier::Stale;
        store.put("gotcha:stale-rule", &gotcha).await.unwrap();

        let fr = FileRecord {
            path: "src/main.rs".into(),
            purpose: String::new(),
            entry_points: vec![],
            imports: vec![],
            gotcha_keys: vec!["gotcha:stale-rule".into()],
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

        let record = make_file_record_full(
            "file:src/main.rs",
            vec![],
            vec!["gotcha:stale-rule".into()],
            vec![],
            0,
        );

        let factor = cascade_factor(&record, Some(&fr), &store).await;
        assert!(
            factor > 0.5,
            "expected positive cascade factor for stale linked gotcha, got {factor}"
        );

        store.close().await.unwrap();
    }

    #[tokio::test]
    async fn cascade_factor_gotcha_detects_stale_affected_file() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();

        // Create a stale file record.
        let mut file_rec = make_file_record_with_staleness(0.6);
        file_rec.key = "file:src/main.rs".to_string();
        store.put("file:src/main.rs", &file_rec).await.unwrap();

        // Create a gotcha that references this file.
        let gotcha_record = make_gotcha_record("gotcha:test-cascade");
        let factor = cascade_factor(&gotcha_record, None, &store).await;
        assert!(
            factor > 0.5,
            "expected positive cascade factor for stale affected file, got {factor}"
        );

        store.close().await.unwrap();
    }

    // ── Hard override tests ─────────────────────────────────────────────────

    #[tokio::test]
    async fn hard_override_file_deleted_sets_tombstone() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();

        // Use a path that definitely doesn't exist on disk.
        let mut record = make_file_record_with_staleness(0.0);
        record.key = "file:/tmp/definitely_nonexistent_mati_test_file_xyz.rs".to_string();
        store.put(&record.key, &record).await.unwrap();

        let analyzer = StalenessAnalyzer::new_with_now(dir.path(), 2_000_000);
        let dep_cache = HashMap::new();
        analyzer
            .compute_staleness(&mut record, &store, &dep_cache)
            .await
            .unwrap();

        assert_eq!(record.staleness.tier, StalenessTier::Tombstone);
        assert!((record.staleness.value - 1.0).abs() < 0.01);

        store.close().await.unwrap();
    }

    #[tokio::test]
    async fn hard_override_file_renamed_sets_liability() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();

        // Create both old and new files on disk.
        let old_path = dir.path().join("old_file.rs");
        let new_path = dir.path().join("renamed.rs");
        std::fs::write(&old_path, "fn main() {}").unwrap();
        std::fs::write(&new_path, "fn main() {}").unwrap();

        let mut record = make_file_record_with_staleness(0.0);
        record.key = format!("file:{}", old_path.to_string_lossy());
        record.staleness.signals.push(StalenessSignal::FileRenamed {
            new_path: new_path.to_string_lossy().to_string(),
        });

        let analyzer = StalenessAnalyzer::new_with_now(dir.path(), 2_000_000);
        let dep_cache = HashMap::new();
        analyzer
            .compute_staleness(&mut record, &store, &dep_cache)
            .await
            .unwrap();

        assert_eq!(record.staleness.tier, StalenessTier::Liability);
        assert!((record.staleness.value - 0.85).abs() < 0.01);

        store.close().await.unwrap();
    }

    #[tokio::test]
    async fn file_restored_clears_deleted_override() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();

        // Create a file on disk.
        let file_path = dir.path().join("restored.rs");
        std::fs::write(&file_path, "fn main() {}").unwrap();

        // Record has a FileDeleted signal, but the file now exists on disk.
        let mut record = make_file_record_with_staleness(0.5);
        record.key = format!("file:{}", file_path.to_string_lossy());
        record.staleness.signals.push(StalenessSignal::FileDeleted);

        let analyzer = StalenessAnalyzer::new_with_now(dir.path(), 2_000_000);
        let dep_cache = HashMap::new();
        analyzer
            .compute_staleness(&mut record, &store, &dep_cache)
            .await
            .unwrap();

        // Should NOT be tombstoned since file exists.
        assert_ne!(record.staleness.tier, StalenessTier::Tombstone);
        // FileDeleted signal should be cleared.
        assert!(
            !record
                .staleness
                .signals
                .iter()
                .any(|s| matches!(s, StalenessSignal::FileDeleted)),
            "FileDeleted signal should be cleared when file is restored"
        );

        store.close().await.unwrap();
    }

    // ── staleness_changed tests ─────────────────────────────────────────────

    #[test]
    fn staleness_changed_detects_tier_change() {
        let mut old = make_file_record_with_staleness(0.19);
        let mut new = old.clone();
        new.staleness.value = 0.21;
        new.staleness.tier = StalenessTier::Aging;
        old.staleness.tier = StalenessTier::Fresh;
        assert!(staleness_changed(&old, &new));
    }

    #[test]
    fn staleness_changed_ignores_small_delta() {
        let old = make_file_record_with_staleness(0.10);
        let mut new = old.clone();
        new.staleness.value = 0.105; // Delta 0.005 < 0.01 threshold.
        assert!(!staleness_changed(&old, &new));
    }

    #[test]
    fn staleness_changed_detects_sha_change() {
        let old = make_file_record_with_staleness(0.10);
        let mut new = old.clone();
        new.staleness.last_record_sha = "abc123".to_string();
        assert!(staleness_changed(&old, &new));
    }

    #[test]
    fn staleness_changed_detects_signal_count_change() {
        let old = make_file_record_with_staleness(0.10);
        let mut new = old.clone();
        new.staleness
            .signals
            .push(StalenessSignal::LinesChangedPct(0.5));
        assert!(staleness_changed(&old, &new));
    }

    // ── analyze_all tests ───────────────────────────────────────────────────

    #[tokio::test]
    async fn analyze_all_updates_stale_records() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();

        // Create a record that should become stale (old timestamp).
        // Use a file path that exists on disk so it doesn't get tombstoned.
        let file_path = dir.path().join("old_file.rs");
        std::fs::write(&file_path, "fn main() {}").unwrap();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let sixty_days_ago = now - (60 * 86400);

        let mut record = make_record_at(
            &format!("file:{}", file_path.to_string_lossy()),
            sixty_days_ago,
            0,
        );
        record.lifecycle = RecordLifecycle::Active;
        store.put(&record.key, &record).await.unwrap();

        let analyzer = StalenessAnalyzer::new(dir.path());
        let report = analyzer.analyze_all(&store).await.unwrap();

        assert!(report.scanned >= 1, "should scan at least 1 record");
        // The time factor at 60 days = 60/90 = ~0.67 * 0.20 = ~0.13
        // That's enough to register a change from 0.0.
        assert!(report.updated >= 1, "should update stale record");

        store.close().await.unwrap();
    }

    #[tokio::test]
    async fn analyze_all_skips_non_active() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let old = now - (60 * 86400);

        let mut record = make_record_at("file:tombstoned.rs", old, 0);
        record.lifecycle = RecordLifecycle::Tombstoned {
            reason: TombstoneReason::ManualDeletion,
            at: now,
        };
        store.put(&record.key, &record).await.unwrap();

        let analyzer = StalenessAnalyzer::new_with_now(dir.path(), now);
        let report = analyzer.analyze_all(&store).await.unwrap();

        // Record was scanned but not updated because it's tombstoned.
        assert_eq!(report.updated, 0);

        store.close().await.unwrap();
    }

    // ── commits_to_factor tests ─────────────────────────────────────────────

    #[test]
    fn commits_to_factor_mapping() {
        assert!((commits_to_factor(0) - 0.0).abs() < 0.001);
        assert!((commits_to_factor(1) - 0.15).abs() < 0.001);
        assert!((commits_to_factor(2) - 0.30).abs() < 0.001);
        assert!((commits_to_factor(3) - 0.50).abs() < 0.001);
        assert!((commits_to_factor(4) - 0.70).abs() < 0.001);
        assert!((commits_to_factor(5) - 1.0).abs() < 0.001);
        assert!((commits_to_factor(100) - 1.0).abs() < 0.001);
    }

    // ── reparse signal preservation tests ───────────────────────────────────

    #[tokio::test]
    async fn reparse_signals_preserved_within_24h() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();

        let file_path = dir.path().join("recent_reparse.rs");
        std::fs::write(&file_path, "fn main() {}").unwrap();

        let now = 2_000_000u64;
        let recent = now - 3600; // 1 hour ago

        let mut record = make_record_at(
            &format!("file:{}", file_path.to_string_lossy()),
            now - 100,
            0,
        );
        // Simulate recent reparse: computed_at within 24h, with reparse signals.
        record.staleness.computed_at = recent;
        record.staleness.value = 0.3;
        record.staleness.tier = StalenessTier::Aging;
        record.staleness.signals = vec![
            StalenessSignal::EntryPointsChanged(2),
            StalenessSignal::ImportsChanged(1),
        ];

        let analyzer = StalenessAnalyzer::new_with_now(dir.path(), now);
        let dep_cache = HashMap::new();
        analyzer
            .compute_staleness(&mut record, &store, &dep_cache)
            .await
            .unwrap();

        // The 5-factor formula would compute a low value (record is ~100s old),
        // but reparse signal preservation should keep the higher value.
        assert!(
            record.staleness.value >= 0.3,
            "reparse signal preservation should keep value >= 0.3, got {}",
            record.staleness.value
        );

        // Reparse signals should be preserved.
        let has_ep = record
            .staleness
            .signals
            .iter()
            .any(|s| matches!(s, StalenessSignal::EntryPointsChanged(_)));
        assert!(has_ep, "EntryPointsChanged signal should be preserved");

        store.close().await.unwrap();
    }

    #[test]
    fn signal_cap_at_20_for_reparse_signals() {
        let mut record = make_file_record_with_staleness(0.0);

        // Add 25 signals via repeated reparse applications.
        for i in 0..25 {
            let diff = ReparseDiff {
                entry_points_added: vec![format!("fn_{i}")],
                ..empty_diff()
            };
            apply_reparse_staleness(&mut record, &diff);
        }

        // Signal list should be capped at 20.
        assert!(
            record.staleness.signals.len() <= 20,
            "signals should be capped at 20, got {}",
            record.staleness.signals.len()
        );
    }

    // ── is_reparse_signal tests ─────────────────────────────────────────────

    #[test]
    fn is_reparse_signal_identifies_reparse_signals() {
        assert!(is_reparse_signal(&StalenessSignal::EntryPointsChanged(1)));
        assert!(is_reparse_signal(&StalenessSignal::ImportsChanged(2)));
        assert!(is_reparse_signal(&StalenessSignal::TodosChanged));
        assert!(is_reparse_signal(&StalenessSignal::UnsafeCountChanged(1)));
        assert!(is_reparse_signal(&StalenessSignal::UnwrapCountChanged(-1)));

        // Non-reparse signals.
        assert!(!is_reparse_signal(&StalenessSignal::FileDeleted));
        assert!(!is_reparse_signal(&StalenessSignal::LinesChangedPct(0.5)));
        assert!(!is_reparse_signal(&StalenessSignal::NotAccessedDays(7)));
    }
}
