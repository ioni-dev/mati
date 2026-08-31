use std::collections::BTreeSet;
use std::path::Path;

use anyhow::Result;

use mati_core::mcp::protocol::Command;
use mati_core::seal::{manifest_path, read_manifest};
use mati_core::store::{GotchaRecord, RecordLifecycle};

use super::hook_decide::{discover_repo_root, HookRunOutcome};
use super::hooks::{hook_fire_v2, run_with_deadline};
use super::proxy::StoreProxy;

/// Watching a file costs a descriptor, and every event costs a `mati`
/// subprocess. A store with more gotcha'd files than this is pathological;
/// truncating loudly beats exhausting the watcher.
const MAX_WATCH_PATHS: usize = 512;

/// `mati watch-paths` — emit SessionStart hook JSON registering the files whose
/// changes mati wants to hear about.
///
/// Claude Code starts no file watcher until a SessionStart hook returns
/// `hookSpecificOutput.watchPaths`, so this call is what makes every later
/// `FileChanged` event exist. Fail-open: on any failure it prints nothing, the
/// watcher never starts, and freshness stays at today's `mati init` behaviour.
pub async fn run_watch_paths() -> Result<HookRunOutcome> {
    // Same budget as `subagent-context`: bounds the daemon ping/scan path for a
    // non-enforcing session-lifecycle hook. The timer starts after startup, and
    // the scaffold's 4s ceiling leaves room for a cold binary (~1050ms).
    const WATCH_PATHS_DEADLINE_MS: u64 = 3000;

    run_with_deadline(
        "session-start",
        "<watch-paths>",
        WATCH_PATHS_DEADLINE_MS,
        "watch path collection exceeded internal deadline",
        run_watch_paths_inner(),
    )
    .await
}

async fn run_watch_paths_inner() -> Result<()> {
    let cwd = match std::env::current_dir() {
        Ok(d) => d,
        Err(_) => return Ok(()),
    };
    let repo_root = discover_repo_root(&cwd).unwrap_or_else(|| cwd.clone());

    rearm_sealed_files(&repo_root).await;

    let store = match StoreProxy::open(&cwd).await {
        Ok(s) => s,
        Err(_) => return Ok(()),
    };
    let gotchas = match store.scan_prefix("gotcha:").await {
        Ok(g) => g,
        Err(_) => return Ok(()),
    };

    let paths = watch_paths_for(&gotchas, &repo_root);
    if paths.is_empty() {
        return Ok(());
    }

    let out = serde_json::json!({
        "hookSpecificOutput": {
            "hookEventName": "SessionStart",
            "watchPaths": paths,
        }
    });
    println!("{}", serde_json::to_string(&out)?);
    Ok(())
}

/// Tier 2: a new session must not inherit the previous one's lifted files.
///
/// Fires the existing receipt clear, which re-arms the manifest daemon-side,
/// so the floor and the gate move together. Re-arming alone would leave a
/// sealed file behind a receipt that is still live in this worktree — the gate
/// would allow the read, the kernel would refuse it, and nothing would tell
/// the agent to consult.
///
/// Gated on a non-empty manifest, read store-free: a repo that seals nothing
/// keeps its receipts across a session boundary exactly as before.
async fn rearm_sealed_files(repo_root: &Path) {
    let sealed = manifest_path(repo_root)
        .map(|p| !read_manifest(&p).files.is_empty())
        .unwrap_or(false);
    if sealed {
        let _ = hook_fire_v2(Command::SessionClearConsults).await;
    }
}

/// The watch set: every existing file named by an Active gotcha.
///
/// Scoped to gotcha'd files rather than the whole index because those are the
/// files whose content can invalidate a rule that denies a read — the drift
/// question `confirmed_content` exists to answer. A `file:*` record with no
/// gotcha attached keeps its `mati init` freshness.
///
/// Unconfirmed gotchas count: a Layer 0 stub gets its `confirmed_content` stamp
/// at confirm time, and the staleness cascade reaches it either way.
///
/// Paths are absolute and built by joining `repo_root`, so the `file_path`
/// Claude Code echoes back has a prefix the FileChanged adapter can strip.
/// Glob entries (`src/payments/**`) and paths outside the repo drop out on the
/// existence check.
/// A `file:*` key is repo-relative, so a path that is absolute or climbs out
/// with `..` can never match a record — watching it would spend events on
/// reparses that always miss.
fn is_repo_relative(rel: &str) -> bool {
    use std::path::Component;
    let path = Path::new(rel);
    path.is_relative()
        && !path
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::Prefix(_)))
}

fn watch_paths_for(gotcha_records: &[mati_core::store::Record], repo_root: &Path) -> Vec<String> {
    let mut paths: BTreeSet<String> = BTreeSet::new();

    for record in gotcha_records {
        if !matches!(record.lifecycle, RecordLifecycle::Active) {
            continue;
        }
        let Some(gotcha) = record.payload_as::<GotchaRecord>() else {
            continue;
        };
        for rel in &gotcha.affected_files {
            if !is_repo_relative(rel) {
                continue;
            }
            let abs = repo_root.join(rel);
            if !abs.is_file() {
                continue;
            }
            if let Some(s) = abs.to_str() {
                paths.insert(s.to_string());
            }
        }
    }

    let total = paths.len();
    let mut paths: Vec<String> = paths.into_iter().collect();
    if total > MAX_WATCH_PATHS {
        paths.truncate(MAX_WATCH_PATHS);
        tracing::warn!(
            "watch-paths: {total} gotcha'd files exceeds the {MAX_WATCH_PATHS} watch cap — \
             {} file(s) will not report changes",
            total - MAX_WATCH_PATHS
        );
    }
    paths
}

#[cfg(test)]
mod tests {
    use super::*;
    use mati_core::store::{
        Category, ConfidenceScore, Priority, QualityScore, Record, RecordSource, RecordVersion,
        StalenessScore, TombstoneReason,
    };

    fn gotcha(key: &str, files: &[&str]) -> Record {
        let payload = GotchaRecord {
            rule: "Call close() before drop".into(),
            reason: "because the lock leaks otherwise".into(),
            severity: Priority::High,
            affected_files: files.iter().map(|s| s.to_string()).collect(),
            ref_url: None,
            discovered_session: 1_000_000,
            confirmed: true,
            confirmed_content: Default::default(),
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

    fn repo_with(files: &[&str]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        for f in files {
            let p = dir.path().join(f);
            std::fs::create_dir_all(p.parent().expect("parent")).expect("mkdir");
            std::fs::write(&p, "content").expect("write");
        }
        dir
    }

    #[test]
    fn emits_absolute_paths_for_existing_gotcha_files() {
        let dir = repo_with(&["src/a.rs"]);
        let paths = watch_paths_for(&[gotcha("gotcha:a", &["src/a.rs"])], dir.path());
        assert_eq!(paths, vec![format!("{}/src/a.rs", dir.path().display())]);
    }

    /// A glob entry has no file behind it, and a stale path may have been
    /// deleted. Neither may reach chokidar.
    #[test]
    fn skips_globs_and_missing_files() {
        let dir = repo_with(&["src/a.rs"]);
        let paths = watch_paths_for(
            &[gotcha(
                "gotcha:a",
                &["src/a.rs", "src/payments/**", "src/gone.rs"],
            )],
            dir.path(),
        );
        assert_eq!(paths.len(), 1);
        assert!(paths[0].ends_with("/src/a.rs"));
    }

    #[test]
    fn deduplicates_files_named_by_several_gotchas() {
        let dir = repo_with(&["src/a.rs", "src/b.rs"]);
        let paths = watch_paths_for(
            &[
                gotcha("gotcha:a", &["src/a.rs"]),
                gotcha("gotcha:b", &["src/a.rs", "src/b.rs"]),
            ],
            dir.path(),
        );
        assert_eq!(paths.len(), 2);
    }

    #[test]
    fn tombstoned_gotchas_contribute_nothing() {
        let dir = repo_with(&["src/a.rs"]);
        let mut g = gotcha("gotcha:a", &["src/a.rs"]);
        g.lifecycle = RecordLifecycle::Tombstoned {
            reason: TombstoneReason::ManualDeletion,
            at: 1_000_100,
        };
        assert!(watch_paths_for(&[g], dir.path()).is_empty());
    }

    /// A path escaping the repo root cannot be a `file:*` key, so watching it
    /// would only spend events on reparses that can never match a record.
    #[test]
    fn skips_paths_that_escape_the_repo() {
        let dir = repo_with(&["src/a.rs", "outside.rs"]);
        let paths = watch_paths_for(
            &[gotcha("gotcha:a", &["../outside.rs"])],
            &dir.path().join("src"),
        );
        assert!(
            paths.is_empty(),
            "an out-of-repo path must not be watched, got {paths:?}"
        );
    }

    #[test]
    fn skips_absolute_affected_files() {
        let dir = repo_with(&["src/a.rs"]);
        let abs = dir.path().join("src/a.rs").display().to_string();
        assert!(watch_paths_for(&[gotcha("gotcha:a", &[&abs])], dir.path()).is_empty());
    }
}
