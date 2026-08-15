use super::*;

// ── M-13-A: StalenessAnalyzer — full 5-factor staleness computation ──────────

/// Seconds in one day.
pub(crate) const SECS_PER_DAY: f64 = 86_400.0;

/// Number of days after which the time factor reaches 1.0.
pub(crate) const TIME_STALE_DAYS: f64 = 90.0;

/// Weight for the time-based staleness factor.
pub(super) const TIME_WEIGHT: f32 = 0.20;

/// Weight for the git-based staleness factor.
pub(super) const GIT_WEIGHT: f32 = 0.35;

/// Weight for the semantic staleness factor (v0.1: always 0.0).
#[allow(dead_code)]
pub(super) const SEMANTIC_WEIGHT: f32 = 0.25;

/// Weight for the dependency staleness factor.
pub(super) const DEP_WEIGHT: f32 = 0.10;

/// Weight multiplier for the cascade staleness factor.
pub(super) const CASCADE_WEIGHT_FACTOR: f32 = 0.10;

/// Maximum commits examined during a revwalk before bailing out.
pub(super) const GIT_REVWALK_LIMIT: usize = 2000;

/// When revwalk hits the cap without finding the since-SHA, assume this many
/// commits have occurred (conservative staleness signal).
pub(crate) const GIT_CAP_HIT_COMMITS: u32 = 3;

/// Maximum number of recompute signals to preserve from reparse (M-12).
pub(super) const MAX_RECOMPUTE_SIGNALS: usize = 10;

/// Time budget for `analyze_all` in milliseconds. After this, stop processing
/// new records and write out whatever was computed.
pub const ANALYZE_TIME_BUDGET_MS: u64 = 2000;

/// Share of a pass's scanned records that may newly reach Tombstone before the
/// pass is discarded rather than written.
pub(super) const MAX_TOMBSTONE_RATIO: f32 = 0.5;

/// Smallest pass the ratio check applies to. Below this a genuine deletion
/// sweep and a broken pass are the same shape.
pub(super) const MIN_TOMBSTONE_SAMPLE: u32 = 20;

/// Record key prefixes that the analyzer scans.
pub(super) const STALENESS_PREFIXES: &[&str] =
    &["file:", "gotcha:", "decision:", "dep:", "dev_note:"];

/// 24 hours in seconds — window for reparse signal preservation.
pub(super) const REPARSE_WINDOW_SECS: u64 = 86_400;

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
    pub(super) repo: Option<Mutex<git2::Repository>>,
    /// Directory that relative `file:` record paths resolve against. Never the
    /// process CWD: the daemon inherits its CWD from whichever hook spawned it,
    /// and a wrong root would report every tracked file as deleted.
    pub(super) root: PathBuf,
    /// True when [`Self::root`] is a git worktree root. `FileDeleted` — the only
    /// signal that reaches Tombstone, which switches enforcement off for a file —
    /// is never asserted without it.
    pub(super) root_from_git: bool,
    pub(super) now: u64,
    pub(super) head_commit: Option<String>,
}

impl StalenessAnalyzer {
    /// Open the analyzer. `repo_path` is the project root, or any directory
    /// inside it — the git root is discovered upward from there.
    ///
    /// If no git repo is found there, or the one found is bare (no working
    /// tree), the analyzer proceeds with git_factor = 0.0 and asserts no
    /// deletions.
    pub fn new(repo_path: &Path) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self::open_at(repo_path, now)
    }

    fn open_at(repo_path: &Path, now: u64) -> Self {
        // One discover call for both the identity (root) and the live repo
        // handle this analyzer holds for git operations — see
        // `RepoIdent::discover_with_repo`.
        let (ident, discovered) = RepoIdent::discover_with_repo(repo_path);

        // The root the store's slug was keyed on. Records were written
        // relative to this, so this is what they must resolve against.
        // `slug_root` is `ident.workdir` — the same value the daemon's own
        // slug derivation falls back to — so a submodule or linked worktree
        // can no longer name a different repo than the one `ident` just
        // discovered: they are the same discovery. Grounded means "a real
        // working tree was found here", not "two independent computations
        // happened to agree".
        let root = ident.slug_root(repo_path);
        let grounded = ident.workdir.is_some();

        let repo = grounded.then_some(discovered).flatten();
        let head_commit = repo.as_ref().and_then(head_commit_sha);

        Self {
            repo: repo.map(Mutex::new),
            root_from_git: grounded,
            root,
            now,
            head_commit,
        }
    }

    /// Test-only constructor that allows injecting a fixed `now` timestamp.
    #[cfg(test)]
    pub(super) fn new_with_now(repo_path: &Path, now: u64) -> Self {
        Self::open_at(repo_path, now)
    }

    /// Resolve a record path against [`Self::root`] and test it on disk.
    fn path_exists(&self, path: &str) -> bool {
        self.root.join(path).exists()
    }

    /// True when `record` is a Layer 0 stub whose every affected file is gone.
    ///
    /// Confirmed stubs are excluded: confirming one makes it the developer's
    /// rule, and a rule with a dead address is theirs to re-point, not ours to
    /// discard. A stub naming no file at all is never dead by this test.
    fn is_dead_stub(&self, record: &Record) -> bool {
        if !crate::store::gotcha_ops::is_auto_gotcha(&record.key) {
            return false;
        }
        let Some(gotcha) = record.payload_as::<GotchaRecord>() else {
            return false;
        };
        !gotcha.confirmed
            && !gotcha.affected_files.is_empty()
            && gotcha.affected_files.iter().all(|p| !self.path_exists(p))
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
    pub(super) async fn analyze_until(
        &self,
        store: &Store,
        deadline: Instant,
    ) -> Result<StalenessReport> {
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

        // Most of the store tombstoned means a broken root, not a repo. Discard
        // the whole pass — that root is not trustworthy for the git factor either.
        if report.scanned >= MIN_TOMBSTONE_SAMPLE
            && report.tombstoned as f32 > report.scanned as f32 * MAX_TOMBSTONE_RATIO
        {
            tracing::error!(
                scanned = report.scanned,
                tombstoned = report.tombstoned,
                root = %self.root.display(),
                root_from_git = self.root_from_git,
                "staleness analyze_all: tombstone ratio above {MAX_TOMBSTONE_RATIO}, pass discarded"
            );
            return Ok(StalenessReport {
                scanned: report.scanned,
                updated: 0,
                tombstoned: 0,
                liability: 0,
                stale: 0,
            });
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
    pub(super) async fn compute_staleness(
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
                // File was restored — clear the FileDeleted signal. Seeing the
                // file proves it is there whatever the root, so this direction
                // needs no grounding.
                record
                    .staleness
                    .signals
                    .retain(|s| !matches!(s, StalenessSignal::FileDeleted));
            } else {
                // Not seeing it proves nothing without a grounded root, which
                // cannot tell "deleted" from "wrong tree". Refresh only from
                // one; otherwise leave the record exactly as it stands.
                if self.root_from_git {
                    record.staleness.value = 1.0;
                    record.staleness.tier = StalenessTier::Tombstone;
                    record.staleness.computed_at = self.now;
                }
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

        // ── Hard override: dead Layer 0 stub ────────────────────────────────
        // A stub outlives the file it is about: `mem_bootstrap` injects the
        // auto-derived ones unconfirmed, so one left behind by a deletion keeps
        // advising about a path nobody can open. Gated on `root_from_git` for
        // the reason `FileDeleted` is, and self-reversing the same way — a
        // restored path fails the check and the score recomputes normally.
        if self.root_from_git && self.is_dead_stub(record) {
            record.staleness.value = 1.0;
            record.staleness.tier = StalenessTier::Tombstone;
            record.staleness.computed_at = self.now;
            return Ok(());
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
    pub(super) fn git_factor_for(
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
    pub(super) fn git_factor(
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
    pub(super) fn count_commits_since(
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
