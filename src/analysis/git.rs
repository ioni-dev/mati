//! Git history mining — Layer 0 signal extraction via git2.
//!
//! Single-pass revwalk over full history (capped at [`MAX_COMMITS`] non-merge
//! commits) to extract per-file change frequency, last author, hotspot
//! detection, rename tracking, and co-change pairs.
//!
//! # Performance
//!
//! - Commit cap keeps large repos predictable: O(5k) not O(all history).
//! - Merge commits skipped (no signal) and don't count toward the cap.
//! - Bulk commits (>50 files) skipped for co-change pairs (O(n²) avoidance).
//! - `context_lines(0)` + no hunk/line callbacks: git2 skips content diffing.
//! - `walked_files` HashSet: O(1) per-delta membership check.
//!
//! # Graceful degradation (P9)
//!
//! All errors return `Ok(GitSignals::empty())` — never fatal.
//! No `.git` directory, unborn HEAD, shallow clones — all handled silently.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use anyhow::Result;
use git2::{DiffFindOptions, DiffOptions, Repository, Sort};
use tracing::{debug, warn};

// ── Constants ────────────────────────────────────────────────────────────────

/// Maximum non-merge commits to process. Full history is walked but capped
/// here to keep performance predictable on large repos. 5,000 commits covers
/// months to years of history on most projects.
const MAX_COMMITS: usize = 5_000;

/// Top 10% of files by change frequency are flagged as hotspots.
const HOTSPOT_PERCENTILE: f64 = 0.10;

/// Minimum co-occurrence ratio for a pair to be considered co-changing.
/// ratio = pair_count / min(freq_a, freq_b).
const CO_CHANGE_THRESHOLD: f64 = 0.70;

/// Commits touching more than this many files are skipped for co-change
/// pair generation (prevents O(n²) explosion from bulk refactors).
/// Frequency counting still applies.
const MAX_COMMIT_FILES: usize = 50;

// ── Output type ──────────────────────────────────────────────────────────────

/// Git-derived signals for an entire repository, keyed by repo-relative path.
#[derive(Debug, Clone)]
pub struct GitSignals {
    /// path → total commits touching the file (capped at MAX_COMMITS window).
    pub change_frequency: HashMap<String, u32>,
    /// path → most recent committer name.
    pub last_authors: HashMap<String, String>,
    /// Top 10% of files by frequency, sorted descending.
    pub hotspot_files: Vec<String>,
    /// Renames detected via `git2::DiffFindOptions`: (old_path, new_path).
    pub recent_renames: Vec<(String, String)>,
    /// Co-change pairs where ratio >= CO_CHANGE_THRESHOLD: (a, b, count) with a < b.
    pub co_change_pairs: Vec<(String, String, u32)>,
    /// path → number of revert commits that touched the file (conventional "Revert " prefix).
    pub revert_counts: HashMap<String, u32>,
    /// path → (author_name → commit_count). Used to detect ownership concentration.
    pub author_commit_counts: HashMap<String, HashMap<String, u32>>,
}

impl GitSignals {
    /// Returns an empty set of signals — used when git is unavailable.
    pub fn empty() -> Self {
        Self {
            change_frequency: HashMap::new(),
            last_authors: HashMap::new(),
            hotspot_files: Vec::new(),
            recent_renames: Vec::new(),
            co_change_pairs: Vec::new(),
            revert_counts: HashMap::new(),
            author_commit_counts: HashMap::new(),
        }
    }
}

// ── Public API ───────────────────────────────────────────────────────────────

/// Single-pass revwalk over full history (capped at MAX_COMMITS non-merge commits).
///
/// Sync — git2 is blocking. Returns `GitSignals::empty()` if no `.git` or
/// no commits (P9 graceful degradation).
///
/// `walked_files` constrains output to files the walker discovered —
/// git deltas for files outside this set are ignored.
pub fn mine_git_history(repo_path: &Path, walked_files: &HashSet<String>) -> Result<GitSignals> {
    // Phase 1: Open + setup
    let repo = match Repository::open(repo_path) {
        Ok(r) => r,
        Err(e) => {
            debug!("no git repo at {}: {e}", repo_path.display());
            return Ok(GitSignals::empty());
        }
    };

    let mut revwalk = match repo.revwalk() {
        Ok(rw) => rw,
        Err(e) => {
            debug!("revwalk failed (unborn HEAD?): {e}");
            return Ok(GitSignals::empty());
        }
    };

    if let Err(e) = revwalk.push_head() {
        debug!("push_head failed (unborn HEAD?): {e}");
        return Ok(GitSignals::empty());
    }
    if let Err(e) = revwalk.set_sorting(Sort::TIME) {
        debug!("set_sorting failed: {e}");
        return Ok(GitSignals::empty());
    }

    // Path interning: map path strings → u32 indices to avoid cloning in hot loops.
    // Paths are stored once in `intern_vec`, and all per-commit tracking uses indices.
    let mut intern_map: HashMap<String, u32> = HashMap::new();
    let mut intern_vec: Vec<String> = Vec::new();

    let mut change_frequency: HashMap<u32, u32> = HashMap::new();
    let mut last_authors: HashMap<u32, String> = HashMap::new();
    let mut pair_counts: HashMap<(u32, u32), u32> = HashMap::new();
    let mut revert_counts_intern: HashMap<u32, u32> = HashMap::new();
    let mut author_counts_intern: HashMap<u32, HashMap<String, u32>> = HashMap::new();
    let mut recent_renames: Vec<(String, String)> = Vec::new();
    let mut commit_files: Vec<u32> = Vec::with_capacity(64);
    let mut commits_processed: usize = 0;

    // Hoist diff config out of the loop — stateless, reusable
    let mut diff_opts = DiffOptions::new();
    diff_opts.context_lines(0);
    diff_opts.ignore_submodules(true);

    let mut find_opts = DiffFindOptions::new();
    find_opts.renames(true);

    // Intern a path string, returning its stable u32 index.
    let mut intern = |path: String| -> u32 {
        if let Some(&idx) = intern_map.get(&path) {
            return idx;
        }
        let idx = intern_vec.len() as u32;
        intern_vec.push(path.clone());
        intern_map.insert(path, idx);
        idx
    };

    // Phase 2: Walk commits
    for oid_result in revwalk {
        if commits_processed >= MAX_COMMITS {
            break;
        }

        let oid = match oid_result {
            Ok(o) => o,
            Err(e) => {
                warn!("revwalk yielded bad oid: {e}");
                continue;
            }
        };

        let commit = match repo.find_commit(oid) {
            Ok(c) => c,
            Err(e) => {
                warn!("corrupt commit {oid}: {e}");
                continue;
            }
        };

        // Skip merge commits — no meaningful co-change signal, don't count toward cap
        if commit.parent_count() > 1 {
            continue;
        }

        let commit_tree = match commit.tree() {
            Ok(t) => t,
            Err(e) => {
                warn!("missing tree for {oid}: {e}");
                continue;
            }
        };

        let parent_tree = if commit.parent_count() == 1 {
            match commit.parent(0).and_then(|p| p.tree()) {
                Ok(t) => Some(t),
                Err(e) => {
                    warn!("missing parent tree for {oid}: {e}");
                    continue;
                }
            }
        } else {
            // Initial commit — diff against empty tree
            None
        };

        let mut diff = match repo.diff_tree_to_tree(
            parent_tree.as_ref(),
            Some(&commit_tree),
            Some(&mut diff_opts),
        ) {
            Ok(d) => d,
            Err(e) => {
                warn!("diff failed for {oid}: {e}");
                continue;
            }
        };

        if let Err(e) = diff.find_similar(Some(&mut find_opts)) {
            warn!("find_similar failed for {oid}: {e}");
            // Continue without rename detection — diff is still valid
        }

        // Collect changed files
        commit_files.clear();

        let deltas = diff.deltas();
        for delta in deltas {
            let status = delta.status();

            // Track renames
            if status == git2::Delta::Renamed {
                if let (Some(old), Some(new)) = (
                    normalize_git_path(delta.old_file().path()),
                    normalize_git_path(delta.new_file().path()),
                ) {
                    if walked_files.contains(&new) {
                        recent_renames.push((old, new));
                    }
                }
            }

            // For deletions use old_file (new_file path is technically valid but
            // semantically the delete targets the old path). For everything else
            // use new_file (post-rename).
            let path = if status == git2::Delta::Deleted {
                match normalize_git_path(delta.old_file().path()) {
                    Some(p) => p,
                    None => continue,
                }
            } else {
                match normalize_git_path(delta.new_file().path()) {
                    Some(p) => p,
                    None => continue,
                }
            };

            // Filter to walked files only
            if !walked_files.contains(&path) {
                continue;
            }

            commit_files.push(intern(path));
        }

        // Update frequency for all files (even in bulk commits)
        let committer_name = commit.committer().name().unwrap_or("unknown").to_string();
        for &idx in &commit_files {
            *change_frequency.entry(idx).or_insert(0) += 1;
            last_authors
                .entry(idx)
                .or_insert_with(|| committer_name.clone());
            *author_counts_intern
                .entry(idx)
                .or_default()
                .entry(committer_name.clone())
                .or_insert(0) += 1;
        }

        // Generate co-change pairs — skip bulk commits
        if commit_files.len() > 1 && commit_files.len() <= MAX_COMMIT_FILES {
            commit_files.sort_unstable();
            for i in 0..commit_files.len() {
                for j in (i + 1)..commit_files.len() {
                    let key = (commit_files[i], commit_files[j]);
                    *pair_counts.entry(key).or_insert(0) += 1;
                }
            }
        }

        // Detect revert commits by conventional "Revert " subject prefix.
        if commit
            .message()
            .map(|m| m.starts_with("Revert "))
            .unwrap_or(false)
        {
            for &idx in &commit_files {
                *revert_counts_intern.entry(idx).or_insert(0) += 1;
            }
        }

        commits_processed += 1;
    }

    // Phase 3: Post-process — convert interned indices back to path strings

    let str_frequency: HashMap<String, u32> = change_frequency
        .iter()
        .map(|(&idx, &count)| (intern_vec[idx as usize].clone(), count))
        .collect();

    let str_authors: HashMap<String, String> = last_authors
        .into_iter()
        .map(|(idx, name)| (intern_vec[idx as usize].clone(), name))
        .collect();

    // Hotspots: top 10% by frequency
    let hotspot_files = compute_hotspots(&str_frequency);

    // Co-change filter: ratio >= threshold
    let mut co_change_pairs: Vec<(String, String, u32)> = pair_counts
        .into_iter()
        .filter(|((a, b), count)| {
            let freq_a = change_frequency.get(a).copied().unwrap_or(0);
            let freq_b = change_frequency.get(b).copied().unwrap_or(0);
            let min_freq = freq_a.min(freq_b);
            if min_freq == 0 {
                return false;
            }
            let ratio = *count as f64 / min_freq as f64;
            ratio >= CO_CHANGE_THRESHOLD
        })
        .map(|((a, b), count)| {
            (
                intern_vec[a as usize].clone(),
                intern_vec[b as usize].clone(),
                count,
            )
        })
        .collect();

    co_change_pairs.sort_by(|a, b| {
        b.2.cmp(&a.2)
            .then_with(|| a.0.cmp(&b.0))
            .then_with(|| a.1.cmp(&b.1))
    });

    let revert_counts: HashMap<String, u32> = revert_counts_intern
        .into_iter()
        .map(|(idx, count)| (intern_vec[idx as usize].clone(), count))
        .collect();

    let author_commit_counts: HashMap<String, HashMap<String, u32>> = author_counts_intern
        .into_iter()
        .map(|(idx, counts)| (intern_vec[idx as usize].clone(), counts))
        .collect();

    Ok(GitSignals {
        change_frequency: str_frequency,
        last_authors: str_authors,
        hotspot_files,
        recent_renames,
        co_change_pairs,
        revert_counts,
        author_commit_counts,
    })
}

// ── Internal helpers ─────────────────────────────────────────────────────────

/// Convert a git2 `Path` to a forward-slash `String`. Returns `None` for non-UTF-8 paths.
fn normalize_git_path(path: Option<&Path>) -> Option<String> {
    path.and_then(|p| p.to_str()).map(|s| s.replace('\\', "/"))
}

/// Compute hotspot files: top `ceil(n * HOTSPOT_PERCENTILE)` by frequency (min 1).
fn compute_hotspots(change_frequency: &HashMap<String, u32>) -> Vec<String> {
    if change_frequency.is_empty() {
        return Vec::new();
    }

    let mut files: Vec<(&String, &u32)> = change_frequency.iter().collect();
    files.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));

    let cutoff = hotspot_cutoff(files.len());
    files
        .into_iter()
        .take(cutoff)
        .map(|(path, _)| path.clone())
        .collect()
}

/// Number of files in the hotspot tier: `ceil(total * HOTSPOT_PERCENTILE)`, min 1.
fn hotspot_cutoff(total_files: usize) -> usize {
    let raw = (total_files as f64 * HOTSPOT_PERCENTILE).ceil() as usize;
    raw.max(1)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use git2::{Oid, Signature, Time};
    use std::fs;
    use tempfile::TempDir;

    /// Create a commit in the given repo touching the specified files.
    /// Files are created/overwritten with dummy content.
    fn make_commit(
        repo: &Repository,
        files: &[&str],
        message: &str,
        author_name: &str,
        time_epoch: i64,
    ) -> Oid {
        let workdir = repo.workdir().expect("bare repo not supported in tests");
        let mut index = repo.index().expect("failed to get index");

        for file in files {
            let file_path = workdir.join(file);
            if let Some(parent) = file_path.parent() {
                fs::create_dir_all(parent).expect("failed to create parent dirs");
            }
            // Write unique content to trigger a real diff
            fs::write(&file_path, format!("{message}: {file}")).expect("failed to write file");
            index
                .add_path(Path::new(file))
                .expect("failed to add to index");
        }

        let tree_oid = index.write_tree().expect("failed to write tree");
        index.write().expect("failed to write index");
        let tree = repo.find_tree(tree_oid).expect("failed to find tree");

        let sig = Signature::new(
            author_name,
            &format!("{author_name}@test.com"),
            &Time::new(time_epoch, 0),
        )
        .expect("failed to create signature");

        let parent_commit = repo.head().ok().and_then(|h| h.peel_to_commit().ok());
        let parents: Vec<&git2::Commit> = parent_commit.iter().collect();

        repo.commit(Some("HEAD"), &sig, &sig, message, &tree, &parents)
            .expect("failed to create commit")
    }

    /// Create a merge commit (2 parents) in the repo.
    fn make_merge_commit(
        repo: &Repository,
        files: &[&str],
        message: &str,
        branch_tip: Oid,
        time_epoch: i64,
    ) -> Oid {
        let workdir = repo.workdir().expect("bare repo");
        let mut index = repo.index().expect("index");

        for file in files {
            let file_path = workdir.join(file);
            if let Some(parent) = file_path.parent() {
                fs::create_dir_all(parent).expect("dirs");
            }
            fs::write(&file_path, format!("{message}: {file}")).expect("write");
            index.add_path(Path::new(file)).expect("add");
        }

        let tree_oid = index.write_tree().expect("write tree");
        index.write().expect("write index");
        let tree = repo.find_tree(tree_oid).expect("find tree");

        let sig =
            Signature::new("merger", "merger@test.com", &Time::new(time_epoch, 0)).expect("sig");

        let head_commit = repo.head().unwrap().peel_to_commit().unwrap();
        let branch_commit = repo.find_commit(branch_tip).unwrap();

        repo.commit(
            Some("HEAD"),
            &sig,
            &sig,
            message,
            &tree,
            &[&head_commit, &branch_commit],
        )
        .expect("merge commit")
    }

    fn walked(files: &[&str]) -> HashSet<String> {
        files.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn empty_repo_returns_empty() {
        let tmp = TempDir::new().unwrap();
        let _repo = Repository::init(tmp.path()).unwrap();
        let signals = mine_git_history(tmp.path(), &walked(&[])).unwrap();
        assert!(signals.change_frequency.is_empty());
        assert!(signals.last_authors.is_empty());
        assert!(signals.hotspot_files.is_empty());
        assert!(signals.co_change_pairs.is_empty());
    }

    #[test]
    fn no_git_dir_returns_empty() {
        let tmp = TempDir::new().unwrap();
        let signals = mine_git_history(tmp.path(), &walked(&[])).unwrap();
        assert!(signals.change_frequency.is_empty());
    }

    #[test]
    fn single_commit_single_file() {
        let tmp = TempDir::new().unwrap();
        let repo = Repository::init(tmp.path()).unwrap();
        make_commit(&repo, &["src/main.rs"], "initial", "alice", 1000);

        let signals = mine_git_history(tmp.path(), &walked(&["src/main.rs"])).unwrap();

        assert_eq!(signals.change_frequency.get("src/main.rs"), Some(&1));
        assert_eq!(
            signals.last_authors.get("src/main.rs"),
            Some(&"alice".to_string())
        );
        assert!(signals.co_change_pairs.is_empty());
    }

    #[test]
    fn multiple_commits_same_file() {
        let tmp = TempDir::new().unwrap();
        let repo = Repository::init(tmp.path()).unwrap();
        make_commit(&repo, &["lib.rs"], "first", "alice", 1000);
        make_commit(&repo, &["lib.rs"], "second", "bob", 2000);
        make_commit(&repo, &["lib.rs"], "third", "carol", 3000);

        let signals = mine_git_history(tmp.path(), &walked(&["lib.rs"])).unwrap();
        assert_eq!(signals.change_frequency.get("lib.rs"), Some(&3));
    }

    #[test]
    fn last_author_is_most_recent() {
        let tmp = TempDir::new().unwrap();
        let repo = Repository::init(tmp.path()).unwrap();
        make_commit(&repo, &["f.rs"], "old", "alice", 1000);
        make_commit(&repo, &["f.rs"], "new", "bob", 2000);

        let signals = mine_git_history(tmp.path(), &walked(&["f.rs"])).unwrap();
        assert_eq!(
            signals.last_authors.get("f.rs"),
            Some(&"bob".to_string()),
            "last author should be the most recent committer"
        );
    }

    #[test]
    fn hotspot_top_10_percent() {
        let tmp = TempDir::new().unwrap();
        let repo = Repository::init(tmp.path()).unwrap();

        // Create 10 files, make one "hot" with many commits
        let all_files: Vec<String> = (0..10).map(|i| format!("f{i}.rs")).collect();
        let all_refs: Vec<&str> = all_files.iter().map(|s| s.as_str()).collect();

        // Initial commit with all files
        make_commit(&repo, &all_refs, "init", "alice", 1000);

        // Make f0.rs hot: 9 more commits
        for i in 1..=9 {
            make_commit(&repo, &["f0.rs"], &format!("hot-{i}"), "alice", 1000 + i);
        }

        let signals = mine_git_history(tmp.path(), &walked(&all_refs)).unwrap();

        // Top 10% of 10 files = 1 file
        assert_eq!(signals.hotspot_files.len(), 1);
        assert_eq!(signals.hotspot_files[0], "f0.rs");
    }

    #[test]
    fn merge_commits_skipped() {
        let tmp = TempDir::new().unwrap();
        let repo = Repository::init(tmp.path()).unwrap();

        // Create main commit
        make_commit(&repo, &["a.rs"], "main work", "alice", 1000);

        // Create a branch commit (detached, we'll use its OID as second parent)
        let branch_oid = make_commit(&repo, &["b.rs"], "branch work", "bob", 2000);

        // Create merge commit touching c.rs
        make_merge_commit(&repo, &["c.rs"], "merge", branch_oid, 3000);

        let signals = mine_git_history(tmp.path(), &walked(&["a.rs", "b.rs", "c.rs"])).unwrap();

        // Merge commit's files should NOT appear in frequency from the merge itself
        // a.rs: 1 (main), b.rs: 1 (branch), c.rs: 0 (merge skipped)
        // Note: b.rs shows 1 from the branch commit (non-merge, counted)
        assert_eq!(signals.change_frequency.get("a.rs"), Some(&1));
        assert!(
            !signals.change_frequency.contains_key("c.rs")
                || signals.change_frequency.get("c.rs") == Some(&0),
            "merge commit files should not be counted"
        );
    }

    #[test]
    fn bulk_commits_skipped_for_pairs() {
        let tmp = TempDir::new().unwrap();
        let repo = Repository::init(tmp.path()).unwrap();

        // Create a commit with >50 files
        let files: Vec<String> = (0..51).map(|i| format!("f{i}.rs")).collect();
        let file_refs: Vec<&str> = files.iter().map(|s| s.as_str()).collect();
        make_commit(&repo, &file_refs, "bulk", "alice", 1000);

        let signals = mine_git_history(tmp.path(), &walked(&file_refs)).unwrap();

        // Frequency should still be counted
        assert_eq!(signals.change_frequency.get("f0.rs"), Some(&1));

        // But no co-change pairs from this bulk commit
        assert!(
            signals.co_change_pairs.is_empty(),
            "bulk commits should not generate co-change pairs"
        );
    }

    #[test]
    fn co_change_above_threshold() {
        let tmp = TempDir::new().unwrap();
        let repo = Repository::init(tmp.path()).unwrap();

        // a.rs and b.rs always committed together (5 times)
        for i in 0..5 {
            make_commit(
                &repo,
                &["a.rs", "b.rs"],
                &format!("pair-{i}"),
                "alice",
                1000 + i,
            );
        }

        let signals = mine_git_history(tmp.path(), &walked(&["a.rs", "b.rs"])).unwrap();

        assert_eq!(signals.co_change_pairs.len(), 1);
        let (a, b, count) = &signals.co_change_pairs[0];
        assert_eq!(a, "a.rs");
        assert_eq!(b, "b.rs");
        assert_eq!(*count, 5);
    }

    #[test]
    fn co_change_asymmetric_frequency_still_included() {
        // a=10 commits, b=2 commits, pair=2.
        // ratio = 2/min(10,2) = 1.0 >= 0.70 → included (from b's perspective they always co-change).
        let tmp = TempDir::new().unwrap();
        let repo = Repository::init(tmp.path()).unwrap();

        for i in 0..10 {
            if i < 2 {
                make_commit(
                    &repo,
                    &["a.rs", "b.rs"],
                    &format!("both-{i}"),
                    "alice",
                    1000 + i,
                );
            } else {
                make_commit(&repo, &["a.rs"], &format!("solo-{i}"), "alice", 1000 + i);
            }
        }

        let signals = mine_git_history(tmp.path(), &walked(&["a.rs", "b.rs"])).unwrap();
        // ratio = 2/min(10,2) = 1.0 — this IS above threshold, which is correct
        assert_eq!(signals.co_change_pairs.len(), 1);
    }

    #[test]
    fn co_change_below_threshold_real() {
        let tmp = TempDir::new().unwrap();
        let repo = Repository::init(tmp.path()).unwrap();

        // a.rs: 10 commits, b.rs: 10 commits, only 2 co-changes
        // ratio = 2/10 = 0.20 < 0.70
        for i in 0..10 {
            if i < 2 {
                make_commit(
                    &repo,
                    &["a.rs", "b.rs"],
                    &format!("both-{i}"),
                    "alice",
                    1000 + i,
                );
            } else if i % 2 == 0 {
                make_commit(&repo, &["a.rs"], &format!("a-solo-{i}"), "alice", 1000 + i);
            } else {
                make_commit(&repo, &["b.rs"], &format!("b-solo-{i}"), "alice", 1000 + i);
            }
        }

        let signals = mine_git_history(tmp.path(), &walked(&["a.rs", "b.rs"])).unwrap();

        assert!(
            signals.co_change_pairs.is_empty(),
            "pair with ratio < 0.70 should be excluded"
        );
    }

    #[test]
    fn rename_detected() {
        let tmp = TempDir::new().unwrap();
        let repo = Repository::init(tmp.path()).unwrap();

        // Create initial file
        make_commit(&repo, &["old.rs"], "initial", "alice", 1000);

        // Rename via git: remove old, add new with same content
        let workdir = repo.workdir().unwrap();
        let old_content = fs::read_to_string(workdir.join("old.rs")).unwrap();
        fs::remove_file(workdir.join("old.rs")).unwrap();
        fs::write(workdir.join("new.rs"), &old_content).unwrap();

        let mut index = repo.index().unwrap();
        index.remove_path(Path::new("old.rs")).unwrap();
        index.add_path(Path::new("new.rs")).unwrap();
        let tree_oid = index.write_tree().unwrap();
        index.write().unwrap();
        let tree = repo.find_tree(tree_oid).unwrap();
        let sig = Signature::new("alice", "alice@test.com", &Time::new(2000, 0)).unwrap();
        let parent = repo.head().unwrap().peel_to_commit().unwrap();
        repo.commit(Some("HEAD"), &sig, &sig, "rename", &tree, &[&parent])
            .unwrap();

        let signals = mine_git_history(tmp.path(), &walked(&["old.rs", "new.rs"])).unwrap();

        assert!(
            signals
                .recent_renames
                .contains(&("old.rs".to_string(), "new.rs".to_string())),
            "rename should be detected: {:?}",
            signals.recent_renames
        );
    }

    #[test]
    fn walked_files_filter() {
        let tmp = TempDir::new().unwrap();
        let repo = Repository::init(tmp.path()).unwrap();
        make_commit(&repo, &["tracked.rs", "ignored.rs"], "init", "alice", 1000);

        // Only "tracked.rs" in walked set
        let signals = mine_git_history(tmp.path(), &walked(&["tracked.rs"])).unwrap();

        assert!(signals.change_frequency.contains_key("tracked.rs"));
        assert!(
            !signals.change_frequency.contains_key("ignored.rs"),
            "files not in walked_files should be excluded"
        );
    }

    #[test]
    #[ignore] // ~130s — creates 5,100 real git commits. Run with: cargo test -- --ignored
    fn commit_cap_respected() {
        let tmp = TempDir::new().unwrap();
        let repo = Repository::init(tmp.path()).unwrap();

        // Create MAX_COMMITS + 100 commits
        let total = MAX_COMMITS + 100;
        for i in 0..total {
            make_commit(
                &repo,
                &["f.rs"],
                &format!("commit-{i}"),
                "alice",
                1000 + i as i64,
            );
        }

        let signals = mine_git_history(tmp.path(), &walked(&["f.rs"])).unwrap();

        // Frequency should be capped at MAX_COMMITS
        assert_eq!(
            signals.change_frequency.get("f.rs"),
            Some(&(MAX_COMMITS as u32)),
            "should process exactly MAX_COMMITS commits"
        );
    }

    #[test]
    fn forward_slash_paths() {
        let tmp = TempDir::new().unwrap();
        let repo = Repository::init(tmp.path()).unwrap();
        make_commit(&repo, &["src/lib/mod.rs"], "init", "alice", 1000);

        let signals = mine_git_history(tmp.path(), &walked(&["src/lib/mod.rs"])).unwrap();

        for key in signals.change_frequency.keys() {
            assert!(
                !key.contains('\\'),
                "paths should use forward slashes: {key}"
            );
        }
    }

    #[test]
    fn deterministic_output() {
        let tmp = TempDir::new().unwrap();
        let repo = Repository::init(tmp.path()).unwrap();

        make_commit(&repo, &["a.rs", "b.rs"], "first", "alice", 1000);
        make_commit(&repo, &["a.rs", "b.rs", "c.rs"], "second", "bob", 2000);

        let w = walked(&["a.rs", "b.rs", "c.rs"]);
        let s1 = mine_git_history(tmp.path(), &w).unwrap();
        let s2 = mine_git_history(tmp.path(), &w).unwrap();

        assert_eq!(s1.change_frequency, s2.change_frequency);
        assert_eq!(s1.last_authors, s2.last_authors);
        assert_eq!(s1.hotspot_files, s2.hotspot_files);
        assert_eq!(s1.co_change_pairs, s2.co_change_pairs);
    }

    #[test]
    fn hotspot_cutoff_math() {
        assert_eq!(hotspot_cutoff(10), 1); // ceil(10 * 0.10) = 1
        assert_eq!(hotspot_cutoff(15), 2); // ceil(15 * 0.10) = 2
        assert_eq!(hotspot_cutoff(1), 1); // min 1
        assert_eq!(hotspot_cutoff(100), 10); // ceil(100 * 0.10) = 10
    }
}
