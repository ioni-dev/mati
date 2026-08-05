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
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};

use crate::store::record::{
    Category, FileRecord, GotchaRecord, Record, RecordLifecycle, StalenessScore, StalenessSignal,
    StalenessTier,
};
use crate::store::Store;

/// Maximum staleness increment from a single reparse pass.
const MAX_REPARSE_INCREMENT: f32 = 0.4;

/// Ceiling on the staleness a record can hold from reparse alone.
///
/// Sits below the 0.7 `Liability` floor on purpose. `Liability` and
/// `Tombstone` no longer gate gotcha enforcement (`hooks::decide::evaluate`
/// runs the gotcha loop before it checks the tier), but they still gate
/// injection — `Liability` degrades the cached blurb to a warning,
/// `Tombstone` suppresses it. An increment that accumulates per edit would
/// let a few edits in one session mark a file's blurb untrustworthy, when
/// the file was only being actively worked on, not abandoned.
///
/// That harm is smaller now than when this constant was written: a degraded
/// blurb precedes a file read that was about to happen anyway, not a
/// disabled deny. It is still real — Liability also drops any blast-radius
/// warning from the same pass, per `hooks::decide::evaluate` — and the
/// margin under 0.7 is about maximizing signal while staying clear of the
/// floor, not about which harm sits past it. The value does not need to
/// change because of the reorder. Git, time, dep and cascade factors still
/// reach those tiers through [`StalenessAnalyzer::compute_staleness`].
const MAX_REPARSE_STALENESS: f32 = 0.69;

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
pub fn apply_reparse_staleness(record: &mut Record, diff: &ReparseDiff) -> Vec<StalenessSignal> {
    if diff.is_empty() {
        return vec![];
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut new_signals = Vec::new();
    let mut increment: f32 = 0.0;

    let ep_changes = (diff.entry_points_added.len() + diff.entry_points_removed.len()) as u32;
    if ep_changes > 0 {
        let signal = StalenessSignal::EntryPointsChanged(ep_changes);
        new_signals.push(signal);
        increment += ep_changes as f32 * ENTRY_POINT_WEIGHT;
    }

    let import_changes = (diff.imports_added.len() + diff.imports_removed.len()) as u32;
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

    // Saturating add: never past the reparse ceiling, never below a value some
    // other factor (or a hard override) already set.
    let new_value = (record.staleness.value + increment)
        .min(MAX_REPARSE_STALENESS)
        .max(record.staleness.value);
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
pub async fn cascade_staleness_to_gotchas(store: &Store, file_record: &FileRecord) -> Result<u32> {
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

            let new_value = (gotcha_record.staleness.value + CASCADE_WEIGHT)
                .min(MAX_REPARSE_STALENESS)
                .max(gotcha_record.staleness.value);
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
pub const ANALYZE_TIME_BUDGET_MS: u64 = 2000;

/// Record key prefixes that the analyzer scans.
const STALENESS_PREFIXES: &[&str] = &["file:", "gotcha:", "decision:", "dep:", "dev_note:"];

/// Where a budget-truncated scan stopped, so the next one resumes there.
///
/// `health:*` is Eventual durability (`store::durability`): the cursor is
/// derived scheduling state, not knowledge. Losing it to a crash restarts the
/// sweep at the first prefix, which costs one redundant pass and nothing else.
const STALENESS_CURSOR_KEY: &str = "health:staleness_cursor";

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

/// Full staleness analyzer using the 5-factor formula from ARCHITECTURE.md section 17.
///
/// Opened once per harvest, reuses the git2 repo handle and cached HEAD.
pub struct StalenessAnalyzer {
    /// `git2::Repository` is `Send` but not `Sync`, and [`Self::analyze_all`]
    /// takes `&self` across `await` points. Without the `Mutex` the resulting
    /// future is `!Send` and cannot run inside the daemon's spawned socket task.
    /// The guard is never held across an `await` — see [`Self::git_factor_for`].
    repo: Option<Mutex<git2::Repository>>,
    /// Directory that relative `file:` record paths resolve against. Never the
    /// process CWD: the daemon inherits its CWD from whichever hook spawned it,
    /// and a wrong root would report every tracked file as deleted.
    root: PathBuf,
    /// True when [`Self::root`] is a git worktree root. `FileDeleted` — the only
    /// signal that reaches Tombstone, which switches enforcement off for a file —
    /// is never asserted without it.
    root_from_git: bool,
    now: u64,
    head_commit: Option<String>,
}

impl StalenessAnalyzer {
    /// Open the analyzer. `repo_path` is the project root, or any directory
    /// inside it — the git root is discovered upward from there.
    ///
    /// If no git repo is found, the analyzer proceeds with git_factor = 0.0 and
    /// asserts no deletions.
    pub fn new(repo_path: &Path) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self::open_at(repo_path, now)
    }

    fn open_at(repo_path: &Path, now: u64) -> Self {
        let repo = git2::Repository::discover(repo_path).ok();
        let head_commit = repo.as_ref().and_then(head_commit_sha);
        let workdir = repo
            .as_ref()
            .and_then(|r| r.workdir().map(Path::to_path_buf));

        Self {
            repo: repo.map(Mutex::new),
            root_from_git: workdir.is_some(),
            root: workdir.unwrap_or_else(|| repo_path.to_path_buf()),
            now,
            head_commit,
        }
    }

    /// Test-only constructor that allows injecting a fixed `now` timestamp.
    #[cfg(test)]
    fn new_with_now(repo_path: &Path, now: u64) -> Self {
        Self::open_at(repo_path, now)
    }

    /// Resolve a record path against [`Self::root`] and test it on disk.
    fn path_exists(&self, path: &str) -> bool {
        self.root.join(path).exists()
    }

    /// Scan all staleness-eligible prefixes, recompute scores, and batch-write
    /// updated records. Respects a 2-second time budget — partial results are
    /// written if the budget is exceeded, and the next call resumes where this
    /// one stopped.
    pub async fn analyze_all(&self, store: &Store) -> Result<StalenessReport> {
        let deadline = Instant::now() + std::time::Duration::from_millis(ANALYZE_TIME_BUDGET_MS);
        self.analyze_until(store, deadline).await
    }

    /// [`Self::analyze_all`] with the deadline supplied, so a test can prove the
    /// budget gates the scan without racing a wall clock.
    ///
    /// The scan walks `STALENESS_PREFIXES` in order and each prefix in key
    /// order, so a budget that expires always expires in the same place: inside
    /// `file:`, the largest prefix and the only one paying git cost. Without a
    /// resume cursor the next pass starts over at `file:`, and the four prefixes
    /// behind it recompute only on a pass that happens to finish `file:` — luck,
    /// not a bound. The cursor carries the position over, so coverage advances
    /// every harvest whatever the budget reached.
    async fn analyze_until(&self, store: &Store, deadline: Instant) -> Result<StalenessReport> {
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

        // A cursor naming a prefix the sweep no longer covers is not a position.
        // Restart rather than skip: `record.key <= cursor` against an unrelated
        // key would silently starve whatever sorts below it.
        let stored_cursor = read_cursor(store).await;
        let resume = stored_cursor.as_deref().and_then(|key| {
            STALENESS_PREFIXES
                .iter()
                .position(|p| key.starts_with(p))
                .map(|idx| (idx, key))
        });
        let (resume_prefix, resume_after) = match resume {
            Some((idx, key)) => (idx, Some(key)),
            None => (0, None),
        };

        let mut updates: Vec<(String, Record)> = Vec::new();
        let mut last_visited: Option<String> = None;
        let mut truncated = false;

        'prefixes: for (idx, prefix) in STALENESS_PREFIXES.iter().enumerate().skip(resume_prefix) {
            if Instant::now() >= deadline {
                truncated = true;
                tracing::warn!(
                    "staleness analyze_all: time budget exceeded after {} records",
                    report.scanned
                );
                break;
            }

            // `scan_prefix` does not promise an order. The cursor is a key, so
            // the sweep needs one: sort, or a resumed pass skips whatever
            // happens to sort low this time and revisits the rest.
            let mut records = match store.scan_prefix(prefix).await {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!("staleness scan_prefix({prefix}) failed: {e}");
                    continue;
                }
            };
            records.sort_by(|a, b| a.key.cmp(&b.key));

            for record in records {
                // Already covered by the pass that set the cursor. Checked
                // before the deadline so a resumed pass spends its budget on
                // new records, not on re-deciding to skip old ones.
                if idx == resume_prefix {
                    if let Some(after) = resume_after {
                        if record.key.as_str() <= after {
                            continue;
                        }
                    }
                }

                if Instant::now() >= deadline {
                    truncated = true;
                    tracing::warn!(
                        "staleness analyze_all: time budget exceeded mid-prefix at {} records",
                        report.scanned
                    );
                    break 'prefixes;
                }

                report.scanned += 1;
                last_visited = Some(record.key.clone());

                // Skip non-active records.
                if !matches!(record.lifecycle, RecordLifecycle::Active) {
                    continue;
                }

                let mut updated = record.clone();
                match self
                    .compute_staleness(&mut updated, store, &dep_cache, deadline)
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
        // Reporting must reflect persisted reality, not attempted computation.
        // If the batch write fails, surface that failure so callers do not log a
        // successful analysis based on in-memory-only updates.
        if !updates.is_empty() {
            let batch: Vec<(&str, &Record)> =
                updates.iter().map(|(k, r)| (k.as_str(), r)).collect();
            store.put_batch(&batch).await.with_context(|| {
                format!("staleness batch write failed for {} records", batch.len())
            })?;
        }

        // Cursor last: it must only ever claim work the batch above persisted.
        // A truncated pass that visited nothing leaves the cursor alone rather
        // than rewinding it.
        match (truncated, last_visited) {
            (true, Some(key)) => write_cursor(store, &key, self.now).await,
            (true, None) => {}
            // Only when one exists: a store with a budget it never exhausts
            // must not pay a tantivy delete every harvest to clear nothing.
            (false, _) if stored_cursor.is_some() => clear_cursor(store).await,
            (false, _) => {}
        }

        Ok(report)
    }

    /// Compute the 5-factor staleness score for a single record.
    ///
    /// Modifies the record in-place. Returns `Ok(())` on success.
    ///
    /// `deadline` is the pass deadline, not a per-record one. Only the git
    /// factor consults it: its revwalk is the sole unbounded-by-wall-clock step
    /// here, and it stops mid-walk rather than letting one record run the pass
    /// past its budget. See [`Self::count_commits_since`].
    async fn compute_staleness(
        &self,
        record: &mut Record,
        store: &Store,
        dep_cache: &HashMap<String, Record>,
        deadline: Instant,
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
            if self.path_exists(path) {
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
        // Gated on `root_from_git`: asserting a deletion tombstones the record,
        // and a tombstoned file record makes `hooks::decide::evaluate` pass every
        // read through before it reaches the gotcha loop. An unproven root must
        // not be able to switch enforcement off.
        if record.key.starts_with("file:") && self.root_from_git {
            let path = record.key.strip_prefix("file:").unwrap_or(&record.key);
            if !path.is_empty() && !self.path_exists(path) {
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
                    self.path_exists(new_path)
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

        let (git_f, new_sha) =
            self.git_factor_for(&record.key, &record.staleness.last_record_sha, deadline);

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
        // Recent reparse signals (within 24h) hold the score up against a lower
        // recompute, but only as far as reparse is itself allowed to raise it.
        // Without that bound a record over-accumulated before the ceiling
        // existed stays pinned at its old tier instead of recovering, and every
        // further edit renews the window.
        let final_value = if had_recent_reparse {
            clamped.max(old_value.min(MAX_REPARSE_STALENESS))
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

    /// Take the repo lock, compute the git factor, drop the lock.
    ///
    /// Synchronous on purpose: the `MutexGuard` must not survive into
    /// [`Self::compute_staleness`], which awaits after this returns.
    /// A poisoned lock yields no git signal rather than a panic.
    fn git_factor_for(
        &self,
        key: &str,
        last_record_sha: &str,
        deadline: Instant,
    ) -> (f32, Option<String>) {
        let Some(mutex) = self.repo.as_ref() else {
            return (0.0, None);
        };
        let Ok(repo) = mutex.lock() else {
            return (0.0, None);
        };
        let path = key.strip_prefix("file:").unwrap_or(key);
        self.git_factor(&repo, path, last_record_sha, deadline)
    }

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
        deadline: Instant,
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
        let count = self.count_commits_since(repo, path, last_record_sha, deadline);
        let factor = commits_to_factor(count);

        (factor, Some(head_sha))
    }

    /// Count commits touching `path` since `since_sha`, respecting
    /// GIT_REVWALK_LIMIT and the pass deadline.
    ///
    /// Uses `total_iterations` (not walked-commit counter) for consistent
    /// merge-commit handling. Returns GIT_CAP_HIT_COMMITS if the walk stops
    /// early — cap or deadline — without finding `since_sha` and no commits
    /// were counted.
    ///
    /// The deadline check is per iteration because each one runs
    /// [`commit_touches_file`], two tree lookups against the object database.
    /// `GIT_REVWALK_LIMIT` alone bounds the walk at 2000 of those, which on a
    /// deep history costs seconds — longer than the whole pass budget, inside a
    /// single record. The outer loop only gates when a record *starts*, so
    /// without this the pass overshoots by however long the walk takes.
    fn count_commits_since(
        &self,
        repo: &git2::Repository,
        path: &str,
        since_sha: &str,
        deadline: Instant,
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
        let mut stopped_early = false;

        for oid_result in revwalk {
            total_iterations += 1;
            if total_iterations > GIT_REVWALK_LIMIT {
                stopped_early = true;
                break;
            }
            if Instant::now() >= deadline {
                stopped_early = true;
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

        // Stopped early without finding since_sha and nothing counted: the
        // history is known to have moved, so report the conservative floor
        // rather than 0, which reads as "unchanged".
        if !found_since && count == 0 && stopped_early {
            return GIT_CAP_HIT_COMMITS;
        }

        count
    }
}

/// The daemon serves each socket connection from a `tokio::spawn`ed task, so
/// everything the harvest awaits must be `Send`. This was false for two
/// releases — `&StalenessAnalyzer` is `Send` only while the analyzer is `Sync`,
/// and `git2::Repository` is not — and the harvest silently dropped staleness
/// rather than failing to compile. Keep the assertion; it is the whole reason
/// the `Mutex` is there.
const _: fn() = || {
    fn assert_send<T: Send>(_: T) {}
    fn probe(analyzer: &StalenessAnalyzer, store: &Store) {
        assert_send(analyzer.analyze_all(store));
    }
    let _ = probe;
};

// ── Resume cursor ───────────────────────────────────────────────────────────
//
// Every cursor operation is best-effort. Staleness runs on the SessionEnd hook
// path, so a store fault here must cost a fair sweep and nothing more: a lost
// cursor restarts at `file:`, exactly the behaviour that existed before it.

/// Payload field holding the resume position.
///
/// The position lives in `payload`, not `value`: `Store::put` indexes `value`
/// into tantivy, and the position is a record key — a `mem_query` for a path
/// would match the cursor as if it were knowledge about that path.
const CURSOR_FIELD: &str = "after";

/// The key the last truncated scan stopped on, or `None` to start at the top.
async fn read_cursor(store: &Store) -> Option<String> {
    let record = match store.get(STALENESS_CURSOR_KEY).await {
        Ok(record) => record?,
        Err(e) => {
            tracing::warn!("staleness cursor read failed: {e}");
            return None;
        }
    };
    record
        .payload
        .as_ref()
        .and_then(|p| p.get(CURSOR_FIELD))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

async fn write_cursor(store: &Store, key: &str, now: u64) {
    let mut record = Record::layer0_file_stub(
        STALENESS_CURSOR_KEY,
        crate::store::stable_device_id(),
        1,
        now,
    );
    record.category = Category::Analytics;
    record.payload = Some(serde_json::json!({ CURSOR_FIELD: key }));
    if let Err(e) = store.put(STALENESS_CURSOR_KEY, &record).await {
        tracing::warn!("staleness cursor write failed: {e}");
    }
}

async fn clear_cursor(store: &Store) {
    if let Err(e) = store.delete(STALENESS_CURSOR_KEY).await {
        tracing::warn!("staleness cursor clear failed: {e}");
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
fn dep_factor(file_record: Option<&FileRecord>, dep_cache: &HashMap<String, Record>) -> f32 {
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
        let dep_record = dep_lookup_keys(import)
            .into_iter()
            .find_map(|key| dep_cache.get(&key));

        if let Some(dep_record) = dep_record {
            checked_count += 1;

            // Check if the dep was updated more recently than the file record.
            if dep_record.updated_at > fr.last_modified_session {
                // Check for DependencyBumped signal on the dep record.
                let has_bump_signal = dep_record
                    .staleness
                    .signals
                    .iter()
                    .any(|s| matches!(s, StalenessSignal::DependencyBumped { .. }));
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

fn dep_lookup_keys(import: &str) -> Vec<String> {
    let mut keys = Vec::new();

    if let Some(crate_name) = import
        .split("::")
        .next()
        .filter(|name| *name != import || import.contains("::"))
    {
        push_dep_key(&mut keys, "cargo", crate_name);
        keys.push(format!("dep:{crate_name}"));
    }

    if let Some(package_name) = npm_package_name(import) {
        push_dep_key(&mut keys, "npm", package_name);
        keys.push(format!("dep:{package_name}"));
    }

    for module_name in go_module_candidates(import) {
        push_dep_key(&mut keys, "go", &module_name);
        keys.push(format!("dep:{module_name}"));
    }

    keys
}

fn push_dep_key(keys: &mut Vec<String>, ecosystem: &str, name: &str) {
    let key = format!("dep:{ecosystem}:{name}");
    if !keys.contains(&key) {
        keys.push(key);
    }
}

fn npm_package_name(import: &str) -> Option<&str> {
    if import.is_empty()
        || import.starts_with('.')
        || import.starts_with('/')
        || import.contains("::")
        || first_path_segment(import).is_some_and(|seg| seg.contains('.'))
    {
        return None;
    }

    if import.starts_with('@') {
        let mut segments = import.split('/');
        let scope = segments.next()?;
        let package = segments.next()?;
        let len = scope.len() + 1 + package.len();
        Some(&import[..len])
    } else {
        first_path_segment(import)
    }
}

fn go_module_candidates(import: &str) -> Vec<String> {
    if import.is_empty()
        || import.starts_with('.')
        || import.starts_with('/')
        || import.contains("::")
        || !first_path_segment(import).is_some_and(|seg| seg.contains('.'))
    {
        return Vec::new();
    }

    let segments: Vec<&str> = import.split('/').collect();
    let mut modules = Vec::new();
    for len in (2..=segments.len()).rev() {
        let module = segments[..len].join("/");
        if !modules.contains(&module) {
            modules.push(module);
        }
    }
    modules
}

fn first_path_segment(import: &str) -> Option<&str> {
    import
        .split('/')
        .next()
        .filter(|segment| !segment.is_empty())
}

/// Cascade factor: for file records, check if linked gotchas/decisions are stale.
/// For gotcha records, check if affected_files have stale records.
async fn cascade_factor(record: &Record, file_record: Option<&FileRecord>, store: &Store) -> f32 {
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
fn blob_sha_at_commit(repo: &git2::Repository, path: &str, commit_sha: &str) -> Option<String> {
    let oid = git2::Oid::from_str(commit_sha).ok()?;
    let commit = repo.find_commit(oid).ok()?;
    let tree = commit.tree().ok()?;
    let entry = tree.get_path(Path::new(path)).ok()?;
    Some(entry.id().to_string())
}

/// Count recent commits touching a file path, with a total iteration limit
/// for consistent merge-commit handling.
#[allow(dead_code)]
fn count_recent_commits(repo: &git2::Repository, path: &str, limit: usize) -> u32 {
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
fn commit_touches_file(repo: &git2::Repository, commit_oid: git2::Oid, path: &str) -> bool {
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
        (Some(_), None) => true, // File added.
        (None, Some(_)) => true, // File deleted.
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

    /// A deadline no test will reach — for call sites not testing the budget.
    fn far_deadline() -> Instant {
        Instant::now() + std::time::Duration::from_secs(3600)
    }

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
            confirmed_content: Default::default(),
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

    fn make_linked_file_record() -> FileRecord {
        FileRecord {
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
            content_hash: None,
            line_count: 0,
            blast_radius: None,
            propagated_staleness: None,
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
            content_hash: None,
            line_count: 0,
            blast_radius: None,
            propagated_staleness: None,
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
            content_hash: None,
            line_count: 0,
            blast_radius: None,
            propagated_staleness: None,
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
            content_hash: None,
            line_count: 0,
            blast_radius: None,
            propagated_staleness: None,
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
            content_hash: None,
            line_count: 0,
            blast_radius: None,
            propagated_staleness: None,
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
            root: PathBuf::from("/nonexistent"),
            root_from_git: false,
            now: 2_000_000,
            head_commit: None,
        };
        assert_eq!(
            analyzer.git_factor_for("file:src/main.rs", "deadbeef", far_deadline()),
            (0.0, None)
        );
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
            content_hash: None,
            line_count: 0,
            blast_radius: None,
            propagated_staleness: None,
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
            content_hash: None,
            line_count: 0,
            blast_radius: None,
            propagated_staleness: None,
        };

        // Create a dep record for tokio that was updated after the file.
        let mut dep_rec = Record {
            key: "dep:cargo:tokio".to_string(),
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
        cache.insert("dep:cargo:tokio".to_string(), dep_rec.clone());

        let factor = dep_factor(Some(&fr), &cache);
        assert!(
            factor > 0.5,
            "expected high dep factor for bumped dep, got {factor}"
        );

        // With no bump signal and same updated_at, factor should be zero.
        dep_rec.staleness.signals.clear();
        dep_rec.updated_at = 1_000_000; // Same as file.
        cache.insert("dep:cargo:tokio".to_string(), dep_rec);
        let factor2 = dep_factor(Some(&fr), &cache);
        assert!(
            factor2.abs() < 0.001,
            "expected zero when dep not bumped, got {factor2}"
        );
    }

    #[test]
    fn dep_factor_detects_bumped_npm_dep_from_subpath_import() {
        let fr = FileRecord {
            path: "src/app.ts".into(),
            purpose: String::new(),
            entry_points: vec![],
            imports: vec!["@types/node/fs".into()],
            gotcha_keys: vec![],
            decision_keys: vec![],
            todos: vec![],
            unsafe_count: 0,
            unwrap_count: 0,
            change_frequency: 0,
            last_author: None,
            is_hotspot: false,
            token_cost_estimate: 0,
            line_count: 0,
            blast_radius: None,
            propagated_staleness: None,
            last_modified_session: 1_000_000,
            content_hash: None,
        };

        let dep_rec = Record {
            key: "dep:npm:@types/node".to_string(),
            value: String::new(),
            category: Category::Dependency,
            priority: Priority::Normal,
            tags: vec![],
            created_at: 500_000,
            updated_at: 2_000_000,
            ref_url: None,
            staleness: StalenessScore {
                value: 0.0,
                tier: StalenessTier::Fresh,
                signals: vec![StalenessSignal::DependencyBumped {
                    dep: "@types/node".into(),
                    old_ver: "20.0.0".into(),
                    new_ver: "20.1.0".into(),
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
        cache.insert(dep_rec.key.clone(), dep_rec);

        let factor = dep_factor(Some(&fr), &cache);
        assert!(
            factor > 0.5,
            "expected high dep factor for bumped npm dep, got {factor}"
        );
    }

    #[test]
    fn dep_factor_detects_bumped_go_dep_from_subpackage_import() {
        let fr = FileRecord {
            path: "internal/server.go".into(),
            purpose: String::new(),
            entry_points: vec![],
            imports: vec!["github.com/gin-gonic/gin/render".into()],
            gotcha_keys: vec![],
            decision_keys: vec![],
            todos: vec![],
            unsafe_count: 0,
            unwrap_count: 0,
            change_frequency: 0,
            last_author: None,
            is_hotspot: false,
            token_cost_estimate: 0,
            line_count: 0,
            blast_radius: None,
            propagated_staleness: None,
            last_modified_session: 1_000_000,
            content_hash: None,
        };

        let dep_rec = Record {
            key: "dep:go:github.com/gin-gonic/gin".to_string(),
            value: String::new(),
            category: Category::Dependency,
            priority: Priority::Normal,
            tags: vec![],
            created_at: 500_000,
            updated_at: 2_000_000,
            ref_url: None,
            staleness: StalenessScore {
                value: 0.0,
                tier: StalenessTier::Fresh,
                signals: vec![StalenessSignal::DependencyBumped {
                    dep: "github.com/gin-gonic/gin".into(),
                    old_ver: "1.9.0".into(),
                    new_ver: "1.9.1".into(),
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
        cache.insert(dep_rec.key.clone(), dep_rec);

        let factor = dep_factor(Some(&fr), &cache);
        assert!(
            factor > 0.5,
            "expected high dep factor for bumped go dep, got {factor}"
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
            content_hash: None,
            line_count: 0,
            blast_radius: None,
            propagated_staleness: None,
        };

        let record = make_file_record_full("file:src/main.rs", vec![], vec![], vec![], 0);

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
            content_hash: None,
            line_count: 0,
            blast_radius: None,
            propagated_staleness: None,
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
        // Deletion is only asserted from a git-proven root — establish one.
        git2::Repository::init(dir.path()).unwrap();

        // Use a path that definitely doesn't exist on disk.
        let mut record = make_file_record_with_staleness(0.0);
        record.key = "file:/tmp/definitely_nonexistent_mati_test_file_xyz.rs".to_string();
        store.put(&record.key, &record).await.unwrap();

        let analyzer = StalenessAnalyzer::new_with_now(dir.path(), 2_000_000);
        let dep_cache = HashMap::new();
        analyzer
            .compute_staleness(&mut record, &store, &dep_cache, far_deadline())
            .await
            .unwrap();

        assert_eq!(record.staleness.tier, StalenessTier::Tombstone);
        assert!((record.staleness.value - 1.0).abs() < 0.01);

        store.close().await.unwrap();
    }

    /// The tombstone override is the only path that reaches `Tombstone`, and a
    /// tombstoned file record makes `hooks::decide::evaluate` pass every read
    /// through before it reaches the gotcha loop. Without a git-proven root the
    /// analyzer cannot tell "deleted" from "wrong working directory", so it must
    /// assert nothing — otherwise a daemon started outside the repo would switch
    /// enforcement off for the whole project.
    #[tokio::test]
    async fn missing_file_is_not_tombstoned_without_a_git_root() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();

        let mut record = make_file_record_with_staleness(0.0);
        record.key = "file:src/definitely_nonexistent_mati_xyz.rs".to_string();

        // No `Repository::init` — `root_from_git` is false.
        let analyzer = StalenessAnalyzer::new_with_now(dir.path(), 2_000_000);
        assert!(!analyzer.root_from_git);

        analyzer
            .compute_staleness(&mut record, &store, &HashMap::new(), far_deadline())
            .await
            .unwrap();

        assert_ne!(record.staleness.tier, StalenessTier::Tombstone);
        assert!(!record
            .staleness
            .signals
            .iter()
            .any(|s| matches!(s, StalenessSignal::FileDeleted)));

        store.close().await.unwrap();
    }

    /// Relative record paths resolve against the analyzer's root, not the
    /// process CWD. The daemon inherits its CWD from whichever hook spawned it.
    #[tokio::test]
    async fn relative_paths_resolve_against_the_repo_root_not_the_cwd() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();
        git2::Repository::init(dir.path()).unwrap();
        std::fs::create_dir_all(dir.path().join("src")).unwrap();
        std::fs::write(dir.path().join("src/present.rs"), "fn main() {}").unwrap();

        let analyzer = StalenessAnalyzer::new_with_now(dir.path(), 2_000_000);

        // `src/present.rs` does not exist relative to the test process CWD.
        assert!(!Path::new("src/present.rs").exists());

        let mut record = make_file_record_with_staleness(0.0);
        record.key = "file:src/present.rs".to_string();
        analyzer
            .compute_staleness(&mut record, &store, &HashMap::new(), far_deadline())
            .await
            .unwrap();

        assert_ne!(record.staleness.tier, StalenessTier::Tombstone);

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
            .compute_staleness(&mut record, &store, &dep_cache, far_deadline())
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
            .compute_staleness(&mut record, &store, &dep_cache, far_deadline())
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

    /// The scan checks the deadline before every prefix and every record, so an
    /// already-expired budget must stop it before it touches anything.
    #[tokio::test]
    async fn expired_time_budget_stops_the_scan_before_any_write() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();
        let file_path = dir.path().join("old_file.rs");
        std::fs::write(&file_path, "fn main() {}").unwrap();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut record = make_record_at(
            &format!("file:{}", file_path.to_string_lossy()),
            now - (60 * 86400),
            0,
        );
        record.lifecycle = RecordLifecycle::Active;
        store.put(&record.key, &record).await.unwrap();
        let before = store.get(&record.key).await.unwrap().unwrap();

        let analyzer = StalenessAnalyzer::new(dir.path());
        let expired = Instant::now() - std::time::Duration::from_millis(1);
        let report = analyzer.analyze_until(&store, expired).await.unwrap();

        assert_eq!(report.scanned, 0);
        assert_eq!(report.updated, 0);
        let after = store.get(&record.key).await.unwrap().unwrap();
        assert_eq!(after.version.logical_clock, before.version.logical_clock);

        // Same store, same analyzer, real budget — proves the assertion above is
        // the deadline talking and not an empty scan.
        let report = analyzer.analyze_all(&store).await.unwrap();
        assert!(report.scanned >= 1);
        assert!(report.updated >= 1);

        store.close().await.unwrap();
    }

    /// The budget bounds the SessionEnd hook, whose scaffold timeout is 4s.
    #[test]
    fn time_budget_is_unchanged() {
        assert_eq!(ANALYZE_TIME_BUDGET_MS, 2000);
    }

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

    // ── resume cursor tests ─────────────────────────────────────────────────

    /// Every prefix, seeded old enough that the first computation changes the
    /// score and therefore persists `computed_at`.
    async fn seed_one_record_per_prefix(store: &Store, now: u64) -> Vec<String> {
        let old = now - (60 * 86_400);
        let keys = [
            "file:zzz_last.rs",
            "gotcha:g1",
            "decision:d1",
            "dep:cargo:serde",
            "dev_note:n1",
        ];
        for key in keys {
            let mut record = make_record_at(key, old, 0);
            record.category = match key.split(':').next().unwrap() {
                "gotcha" => Category::Gotcha,
                "decision" => Category::Decision,
                "dep" => Category::Dependency,
                "dev_note" => Category::DevNote,
                _ => Category::File,
            };
            store.put(key, &record).await.unwrap();
        }
        keys.iter().map(|k| k.to_string()).collect()
    }

    /// A `file:` record that costs a whole budget to score: `cascade_factor`
    /// issues one store read per linked key, and none of these exist.
    fn make_budget_eating_record(key: &str, now: u64, links: usize) -> Record {
        let mut record = make_record_at(key, now - (60 * 86_400), 0);
        let gotcha_keys: Vec<String> = (0..links).map(|i| format!("gotcha:absent-{i}")).collect();
        let fr = make_file_record_full(key, vec![], gotcha_keys, vec![], 0);
        record.payload = serde_json::from_str(&fr.value).ok();
        record
    }

    /// The scan order is fixed, so a budget that expires always expires inside
    /// `file:`, and the four prefixes behind it would never recompute. The
    /// cursor is what bounds coverage: pass 2 must start where pass 1 stopped
    /// and finish the store, not restart at `file:` and starve the tail again.
    #[tokio::test]
    async fn a_truncated_pass_parks_a_cursor_and_the_next_pass_finishes_the_store() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();
        let now = 20_000_000u64;

        let mut keys = seed_one_record_per_prefix(&store, now).await;
        // Sorts first inside `file:`, so it is what a truncated pass spends
        // its whole budget on.
        let hog = "file:aaa_expensive.rs";
        let record = make_budget_eating_record(hog, now, 20_000);
        store.put(hog, &record).await.unwrap();
        keys.push(hog.to_string());

        let analyzer = StalenessAnalyzer::new_with_now(dir.path(), now);

        let deadline = Instant::now() + std::time::Duration::from_millis(5);
        let first = analyzer.analyze_until(&store, deadline).await.unwrap();
        assert!(first.scanned >= 1, "a pass must make progress");
        assert!(
            first.scanned < keys.len() as u32,
            "the budget did not truncate: scanned {} of {}",
            first.scanned,
            keys.len()
        );
        assert_eq!(
            read_cursor(&store).await.as_deref(),
            Some(hog),
            "a truncated pass parks the cursor on the last record it finished"
        );

        let second = analyzer.analyze_all(&store).await.unwrap();
        assert_eq!(
            second.scanned,
            keys.len() as u32 - first.scanned,
            "the resumed pass must not re-scan what the cursor already covered"
        );
        assert!(
            read_cursor(&store).await.is_none(),
            "a pass that reaches the end clears the cursor"
        );

        for key in &keys {
            let record = store.get(key).await.unwrap().unwrap();
            assert_eq!(
                record.staleness.computed_at, now,
                "{key} was never recomputed across the sweep"
            );
        }

        store.close().await.unwrap();
    }

    /// The cursor is scheduling state on the Eventual path, so it can be lost,
    /// stale, or left behind by a prefix list that has since changed. Anything
    /// the sweep cannot place must restart it, never skip.
    #[tokio::test]
    async fn an_unplaceable_cursor_restarts_the_sweep() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();
        let now = 20_000_000u64;

        let keys = seed_one_record_per_prefix(&store, now).await;
        write_cursor(&store, "retired_namespace:zzz", now).await;

        let analyzer = StalenessAnalyzer::new_with_now(dir.path(), now);
        let report = analyzer.analyze_all(&store).await.unwrap();

        assert_eq!(
            report.scanned,
            keys.len() as u32,
            "an unplaceable cursor must not skip any record"
        );
        assert!(read_cursor(&store).await.is_none());

        store.close().await.unwrap();
    }

    /// An empty position is absence, not position zero.
    #[tokio::test]
    async fn an_empty_cursor_position_reads_as_no_cursor() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();

        write_cursor(&store, "", 20_000_000).await;
        assert!(read_cursor(&store).await.is_none());

        store.close().await.unwrap();
    }

    /// The position must not reach the search index: it is a record key, and a
    /// `mem_query` for that path would otherwise match the cursor.
    #[tokio::test]
    async fn the_cursor_position_is_not_searchable() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();

        write_cursor(&store, "file:src/distinctive_marker.rs", 20_000_000).await;
        let hits = store.search("distinctive_marker", 10).await.unwrap();

        assert!(
            !hits.iter().any(|r| r.key == STALENESS_CURSOR_KEY),
            "cursor leaked into the search index: {hits:?}"
        );

        store.close().await.unwrap();
    }

    /// The budget still stops the scan. An expired one writes no cursor either:
    /// a pass that visited nothing has no position to record, and rewinding to
    /// one it did not reach would re-run work the previous pass already did.
    #[tokio::test]
    async fn an_expired_budget_leaves_the_cursor_untouched() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();
        let now = 20_000_000u64;

        seed_one_record_per_prefix(&store, now).await;
        write_cursor(&store, "file:zzz_last.rs", now).await;

        let analyzer = StalenessAnalyzer::new_with_now(dir.path(), now);
        let expired = Instant::now() - std::time::Duration::from_millis(1);
        let report = analyzer.analyze_until(&store, expired).await.unwrap();

        assert_eq!(report.scanned, 0);
        assert_eq!(
            read_cursor(&store).await.as_deref(),
            Some("file:zzz_last.rs")
        );

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
            .compute_staleness(&mut record, &store, &dep_cache, far_deadline())
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

    // ── Reparse accumulation cannot disable enforcement ─────────────────────

    /// `hooks::decide::evaluate` runs the gotcha loop before it looks at the
    /// file's staleness tier — pinned by `decide::tests::gate_never_silently_
    /// disables`. So `Liability`/`Tombstone` no longer disable enforcement of
    /// a confirmed gotcha. They still gate *injection*: `Liability` degrades
    /// the file's cached purpose blurb to a bare warning, and `Tombstone`
    /// (absent a `FileDeleted` signal) suppresses it entirely. Reparse
    /// staleness is applied per edit, so without a ceiling across passes,
    /// editing one file a handful of times in a session would cross that
    /// boundary and mark its cached blurb untrustworthy — a false signal,
    /// since the file wasn't abandoned, just actively edited.
    ///
    /// These tests bound the reparse contribution. They do not touch the tier
    /// thresholds or what the tiers mean.
    mod reparse_cannot_disable_enforcement {
        use super::*;
        use crate::hooks::decide::{evaluate, Decision, EnforcementInput};

        /// A diff big enough to saturate a single pass at
        /// [`MAX_REPARSE_INCREMENT`].
        fn saturating_diff() -> ReparseDiff {
            ReparseDiff {
                entry_points_added: vec!["a".into(), "b".into(), "c".into(), "d".into()],
                imports_added: vec!["x".into(), "y".into(), "z".into()],
                ..empty_diff()
            }
        }

        /// A file record carrying one maximally-valid confirmed gotcha, plus
        /// that gotcha, in the JSON shape `evaluate` reads.
        fn enforcement_input_for(record: &Record) -> EnforcementInput {
            let mut gotcha = make_gotcha_record("gotcha:test");
            gotcha.confidence.value = 1.0;
            gotcha.quality.value = 1.0;

            let mut file = record.clone();
            file.confidence.value = 0.7;
            file.quality.value = 0.5;
            file.payload = serde_json::json!({ "gotcha_keys": ["gotcha:test"] }).into();

            let mut gotchas = HashMap::new();
            gotchas.insert(
                "gotcha:test".to_string(),
                serde_json::to_value(&gotcha).unwrap(),
            );
            EnforcementInput {
                rel_path: "src/main.rs".into(),
                file_record: Some(serde_json::to_value(&file).unwrap()),
                gotcha_records: gotchas,
                already_consulted: false,
                file_exists: None,
            }
        }

        /// The anchor: no number of reparse passes reaches a tier that
        /// degrades injection, and a confirmed gotcha keeps denying
        /// regardless — the second assertion holds even without the ceiling
        /// now, but stays here as a regression guard.
        #[test]
        fn repeated_reparse_never_reaches_a_tier_that_degrades_injection() {
            let mut record = make_file_record_with_staleness(0.0);

            for pass in 1..=50 {
                apply_reparse_staleness(&mut record, &saturating_diff());
                assert!(
                    !matches!(
                        record.staleness.tier,
                        StalenessTier::Liability | StalenessTier::Tombstone
                    ),
                    "INJECTION DEGRADED: {} reparse passes reached tier {:?} \
                     (value {}). Liability and Tombstone still gate what gets \
                     injected for this file, even though they no longer gate \
                     gotcha enforcement",
                    pass,
                    record.staleness.tier,
                    record.staleness.value
                );

                let decision = evaluate(&enforcement_input_for(&record)).decision;
                assert!(
                    matches!(decision, Decision::Deny { .. }),
                    "ENFORCEMENT DISABLED: after {pass} reparse passes a confirmed \
                     gotcha produced {decision:?} instead of Deny"
                );
            }

            assert!(record.staleness.value <= MAX_REPARSE_STALENESS + f32::EPSILON);
        }

        /// The ceiling is only meaningful while it stays inside `Stale`.
        #[test]
        fn ceiling_sits_below_the_liability_floor() {
            assert_eq!(
                StalenessScore::tier_from_value(MAX_REPARSE_STALENESS),
                StalenessTier::Stale,
                "MAX_REPARSE_STALENESS must stay below the 0.7 Liability floor"
            );
        }

        /// The signal is not neutered: one pass still moves the score, and the
        /// score keeps climbing until it saturates.
        #[test]
        fn a_single_reparse_still_raises_staleness() {
            let mut record = make_file_record_with_staleness(0.0);
            let signals = apply_reparse_staleness(&mut record, &saturating_diff());

            assert!(!signals.is_empty(), "a non-empty diff must emit signals");
            assert!(
                (record.staleness.value - MAX_REPARSE_INCREMENT).abs() < 0.01,
                "one saturating pass must still add the full increment, got {}",
                record.staleness.value
            );
            assert_eq!(record.staleness.tier, StalenessTier::Stale);

            let after_first = record.staleness.value;
            apply_reparse_staleness(&mut record, &saturating_diff());
            assert!(
                record.staleness.value > after_first,
                "a second pass must still raise the score below the ceiling"
            );
        }

        /// Another factor may legitimately hold a record above the ceiling.
        /// Reparse must not drag it back down.
        #[test]
        fn reparse_never_lowers_a_score_set_by_another_factor() {
            let mut record = make_file_record_with_staleness(0.95);
            apply_reparse_staleness(&mut record, &saturating_diff());
            assert!((record.staleness.value - 0.95).abs() < f32::EPSILON);
            assert_eq!(record.staleness.tier, StalenessTier::Tombstone);
        }

        /// The cascade to linked gotchas accumulates the same way. A tombstoned
        /// gotcha is dropped by `mcp::tools::is_injectable_gotcha`.
        #[tokio::test]
        async fn cascade_to_gotchas_saturates_below_liability() {
            let dir = TempDir::new().unwrap();
            let store = Store::open(dir.path()).await.unwrap();
            store
                .put("gotcha:test-rule", &make_gotcha_record("gotcha:test-rule"))
                .await
                .unwrap();

            let mut file_record = make_linked_file_record();
            file_record.gotcha_keys = vec!["gotcha:test-rule".into()];

            for _ in 0..30 {
                cascade_staleness_to_gotchas(&store, &file_record)
                    .await
                    .unwrap();
            }

            let updated = store.get("gotcha:test-rule").await.unwrap().unwrap();
            assert!(
                updated.staleness.value <= MAX_REPARSE_STALENESS + f32::EPSILON,
                "cascade accumulated to {}",
                updated.staleness.value
            );
            assert_eq!(updated.staleness.tier, StalenessTier::Stale);

            store.close().await.unwrap();
        }

        /// `compute_staleness` preserves a recent reparse score against a lower
        /// recompute. A record already over the ceiling — accumulated before it
        /// existed — must recompute down instead of staying pinned.
        #[tokio::test]
        async fn analyze_recomputes_an_over_accumulated_record_down() {
            let dir = TempDir::new().unwrap();
            let store = Store::open(dir.path()).await.unwrap();

            let file_path = dir.path().join("hot.rs");
            std::fs::write(&file_path, "fn main() {}").unwrap();

            let now = 2_000_000u64;
            let key = format!("file:{}", file_path.to_string_lossy());
            let mut record = make_record_at(&key, now - 100, 0);
            record.staleness.value = 0.95;
            record.staleness.tier = StalenessTier::Tombstone;
            record.staleness.computed_at = now - 3600;
            record.staleness.signals = vec![
                StalenessSignal::ImportsChanged(2),
                StalenessSignal::UnwrapCountChanged(12),
            ];

            let analyzer = StalenessAnalyzer::new_with_now(dir.path(), now);
            analyzer
                .compute_staleness(&mut record, &store, &HashMap::new(), far_deadline())
                .await
                .unwrap();

            assert!(
                record.staleness.value <= MAX_REPARSE_STALENESS + f32::EPSILON,
                "the 24h preservation window pinned the record at {}",
                record.staleness.value
            );
            assert!(!matches!(
                record.staleness.tier,
                StalenessTier::Liability | StalenessTier::Tombstone
            ));
            assert!(
                record
                    .staleness
                    .signals
                    .iter()
                    .any(|s| matches!(s, StalenessSignal::ImportsChanged(_))),
                "recomputing down must not erase the reparse signals"
            );

            store.close().await.unwrap();
        }
    }

    // ── revwalk deadline ────────────────────────────────────────────────────

    /// Commit `content` to `name` and return the commit SHA.
    fn commit_file(repo: &git2::Repository, name: &str, content: &str) -> String {
        let workdir = repo.workdir().expect("bare repo").to_path_buf();
        std::fs::write(workdir.join(name), content).unwrap();
        let mut index = repo.index().unwrap();
        index.add_path(Path::new(name)).unwrap();
        index.write().unwrap();
        let tree = repo.find_tree(index.write_tree().unwrap()).unwrap();
        let sig = git2::Signature::now("t", "t@example.com").unwrap();
        let parent = repo.head().ok().and_then(|h| h.peel_to_commit().ok());
        let parents: Vec<&git2::Commit> = parent.iter().collect();
        repo.commit(Some("HEAD"), &sig, &sig, "c", &tree, &parents)
            .unwrap()
            .to_string()
    }

    /// The revwalk stops at the pass deadline instead of running to
    /// `GIT_REVWALK_LIMIT`.
    ///
    /// `analyze_until` gates only when a record *starts*, so before the
    /// deadline reached here one record could walk 2000 commits — seconds —
    /// after the pass had already spent its budget, and the SessionEnd hook
    /// overshot by that much.
    #[test]
    fn count_commits_since_stops_at_the_deadline() {
        let dir = TempDir::new().unwrap();
        let repo = git2::Repository::init(dir.path()).unwrap();
        let mut shas = Vec::new();
        for i in 0..12 {
            shas.push(commit_file(&repo, "a.txt", &format!("v{i}\n")));
        }
        let analyzer = StalenessAnalyzer::new(dir.path());
        let root_sha = &shas[0];

        assert_eq!(
            analyzer.count_commits_since(&repo, "a.txt", root_sha, far_deadline()),
            11,
            "an unbounded walk reaches the root commit and counts the rest"
        );

        assert_eq!(
            analyzer.count_commits_since(&repo, "a.txt", root_sha, Instant::now()),
            GIT_CAP_HIT_COMMITS,
            "an expired deadline stops the walk and reports the conservative floor"
        );
    }

    /// A record whose walk cannot finish inside the budget still gets a
    /// staleness signal — undercounting keeps enforcement on, silence would
    /// read as "unchanged".
    #[test]
    fn deadline_truncated_walk_reports_a_nonzero_git_factor() {
        let dir = TempDir::new().unwrap();
        let repo = git2::Repository::init(dir.path()).unwrap();
        let root_sha = commit_file(&repo, "a.txt", "v0\n");
        commit_file(&repo, "a.txt", "v1\n");
        let analyzer = StalenessAnalyzer::new(dir.path());

        let (factor, sha) = analyzer.git_factor(&repo, "a.txt", &root_sha, Instant::now());
        assert!(factor > 0.0, "truncated walk must not report 'unchanged'");
        assert!(sha.is_some(), "baseline still advances to HEAD");
    }
}
