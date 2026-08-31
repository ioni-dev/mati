//! Consultation gate for mati's own content-emitting commands.
//!
//! `mati extract-signals` and `mati verify-evidence` print source text from the
//! working tree, but they are not shell commands, so `classify_command` never
//! sees them and the PreToolUse read gate never fires. Measured 2026-08-30:
//! `sed` on a file with an unconsulted confirmed gotcha was denied, and
//! `mati extract-signals --file <same path>` in the same session returned an
//! exact source line. `/mati-enrich` names both commands, so the channel is not
//! obscure to an agent.
//!
//! The line this draws: a command that emits source text without producing a
//! record is a raw read channel and is gated here. Records that quote source —
//! a gotcha's `reason`, a file record's `purpose` — are the product and are
//! not gated.
//!
//! That is disclosure the design accepts, not consultation. `mati show` prints
//! record content and mints NO receipt: verified 2026-08-31, a `cat` on the
//! same file denies identically before and after. So a file record's
//! `purpose` — the module doc comment `mati init` extracted — is readable for
//! a file the gate is denying. Accepted, because the hook already injects that
//! same field as `additionalContext` without a receipt, and because it is
//! developer-written prose rather than the implementation.
//!
//! What is NOT accepted is minting such a record from ungated bytes on demand.
//! `mati suggest` would quote a `SECURITY:` line out of a denied file into a
//! new record that `mati show` then prints (reproduced 2026-08-31), so it
//! skips files that already carry a confirmed gotcha.
//!
//! **Fails closed**, unlike the hook path. `FAILURE_MODES.md` section 1 puts
//! fail-open where correctness depends on a live daemon *and* blocking would
//! wedge the agent's own tools. Here mati is the reader: refusing one hidden
//! subcommand stops enrichment, which needs the daemon anyway, and leaves every
//! other tool untouched. Failing open would hand out a one-line bypass — stop
//! the daemon, then read. `ensure_daemon` runs first so a cold start is a
//! spawn, not a refusal.

use std::path::Path;

use anyhow::{bail, Result};

use crate::cli::daemon::{daemon_result, mati_root_for_ident, DaemonResult};

/// Refuse to emit `file`'s contents unless this actor holds a consultation
/// receipt for it, matching what the read gate would decide for a `cat`.
///
/// The store is discovered from the TARGET FILE, never from the process cwd:
/// `cd /tmp && mati extract-signals --file /abs/path/in/repo.rs` otherwise
/// resolves to no store and prints the file (observed while building this).
/// The path is canonicalized first, so a symlink pointing into the repo is
/// gated as its target.
pub async fn require_consultation(file: &Path) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let raw_abs = if file.is_absolute() {
        file.to_path_buf()
    } else {
        cwd.join(file)
    };
    let abs = std::fs::canonicalize(&raw_abs).unwrap_or(raw_abs);
    let anchor = abs.parent().unwrap_or(cwd.as_path());

    let ident = mati_core::store::RepoIdent::discover(anchor);
    let repo_root = ident
        .workdir
        .as_ref()
        .map(|w| std::fs::canonicalize(w).unwrap_or_else(|_| w.clone()));
    let rel = mati_core::hooks::decide::normalize_path(
        &abs.to_string_lossy(),
        repo_root.as_ref().and_then(|p| p.to_str()),
    );
    let file_key = format!("file:{rel}");
    let root = mati_root_for_ident(&ident, anchor)?;

    // No store here means nothing to gate — a file outside any mati repo has
    // no gotchas. Checked before `ensure_daemon` so this never scaffolds one.
    if !root.join("knowledge.db").exists() {
        return Ok(());
    }

    mati_core::mcp::daemon_lifecycle::ensure_daemon(&root).await;

    let worktree = mati_core::store::session::worktree_scope_tag(anchor);
    let actor = mati_core::store::session::combined_actor_scope(worktree.as_deref(), None);

    let DaemonResult::Ok(resp) = daemon_result(
        &root,
        "hook_evaluate",
        serde_json::json!({ "file_key": &file_key, "include_recent": false, "actor": actor }),
    )
    .await
    else {
        bail!(unknown(&rel, "the mati daemon did not answer"));
    };

    if resp.get("ok").and_then(|v| v.as_bool()) != Some(true) {
        bail!(unknown(&rel, "the mati daemon returned an error"));
    }
    let Some(data) = resp.get("data").filter(|v| v.is_object()) else {
        bail!(unknown(&rel, "the mati daemon returned no evaluation"));
    };

    // A store or gotcha fault leaves consultation state unknown. The hook path
    // fails open here; this one cannot, for the reason in the module doc.
    let flag = |name: &str| data.get(name).and_then(|v| v.as_bool()).unwrap_or(false);
    if flag("gotcha_error") || (flag("store_error") && data.get("file_record").is_none()) {
        bail!(unknown(&rel, "mati could not read its own store"));
    }

    if mati_core::hooks::decide::read_needs_receipt(data) {
        bail!(
            "{rel} has a confirmed gotcha this session has not consulted.\n\
             Call mem_get(\"file:{rel}\") and read the record, then retry."
        );
    }
    Ok(())
}

fn unknown(rel: &str, why: &str) -> String {
    format!(
        "cannot tell whether {rel} has been consulted: {why}.\n\
         This command prints source text, so it refuses rather than guess. \
         Retry, or run `mati daemon start`."
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    use tempfile::TempDir;

    /// A file inside `dir` with a parent that exists, so `abs.parent()` is a
    /// real anchor rather than the cwd fallback.
    fn source_file(dir: &TempDir) -> std::path::PathBuf {
        let file = dir.path().join("src/lib.rs");
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(&file, "fn main() {}\n").unwrap();
        file
    }

    /// Put a store where the gate will look for `file`'s, so it gets past the
    /// "no store, nothing to gate" branch. An empty file is enough — that
    /// branch only calls `exists`.
    fn seed_store_for(file: &Path) {
        let anchor = file.parent().unwrap();
        let ident = mati_core::store::RepoIdent::discover(anchor);
        let root = mati_root_for_ident(&ident, anchor).unwrap();
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("knowledge.db"), b"").unwrap();
    }

    /// `ensure_daemon` skips its spawn phase on `cfg!(test)` OR this variable.
    /// A bin test links the lib without `--test`, so `cfg!(test)` is false
    /// there and the variable is what keeps these tests from spawning a real
    /// daemon. Unset on drop, so a failing assert does not leak it.
    struct NoDaemonSpawn;

    impl NoDaemonSpawn {
        fn on() -> Self {
            std::env::set_var("MATI_DISABLE_AUTO_SPAWN", "1");
            Self
        }
    }

    impl Drop for NoDaemonSpawn {
        fn drop(&mut self) {
            std::env::remove_var("MATI_DISABLE_AUTO_SPAWN");
        }
    }

    /// A file outside any mati store has no gotchas, so gating it would refuse
    /// reads nothing can ever authorize. Checked before `ensure_daemon`, so
    /// this must not scaffold a store either.
    #[tokio::test]
    async fn a_file_with_no_store_is_not_gated() {
        crate::cli::ensure_test_home();
        let dir = TempDir::new().unwrap();
        let file = source_file(&dir);

        require_consultation(&file)
            .await
            .expect("no store, no gate");

        let anchor = file.parent().unwrap();
        let ident = mati_core::store::RepoIdent::discover(anchor);
        let root = mati_root_for_ident(&ident, anchor).unwrap();
        assert!(
            !root.join("knowledge.db").exists(),
            "the gate must not create a store it only meant to look for"
        );
    }

    /// The bypass this exists to close: stop the daemon, then read. Failing
    /// open here would hand it out in one line, so an unreachable daemon is an
    /// error, not an allow — the opposite of the hook path's P9.
    #[tokio::test]
    async fn an_unreachable_daemon_refuses_rather_than_printing() {
        crate::cli::ensure_test_home();
        let dir = TempDir::new().unwrap();
        let file = source_file(&dir);
        seed_store_for(&file);

        let _no_spawn = NoDaemonSpawn::on();
        let err = require_consultation(&file)
            .await
            .expect_err("an unreachable daemon must not allow the read");

        let msg = err.to_string();
        assert!(msg.contains("lib.rs"), "must name the file: {msg}");
        assert!(msg.contains("the mati daemon did not answer"), "{msg}");
        assert!(msg.contains("refuses rather than guess"), "{msg}");
    }

    /// The store is discovered from the target file, never the process cwd:
    /// `cd /tmp && mati extract-signals --file /abs/path/in/repo.rs` otherwise
    /// resolves to no store and prints the file. The cwd here is the mati repo,
    /// whose per-process test home holds no store, so reaching the refusal at
    /// all proves the anchor came from the file.
    #[tokio::test]
    async fn the_store_is_found_from_the_file_not_the_cwd() {
        crate::cli::ensure_test_home();
        let cwd = std::env::current_dir().unwrap();
        let cwd_ident = mati_core::store::RepoIdent::discover(&cwd);
        let cwd_root = mati_root_for_ident(&cwd_ident, &cwd).unwrap();
        assert!(
            !cwd_root.join("knowledge.db").exists(),
            "the control is void if the cwd already has a store"
        );

        let dir = TempDir::new().unwrap();
        let file = source_file(&dir);
        seed_store_for(&file);

        let _no_spawn = NoDaemonSpawn::on();
        let err = require_consultation(&file)
            .await
            .expect_err("the file's own store must be the one consulted");
        assert!(err.to_string().contains("cannot tell whether"), "{err}");
    }

    /// A symlink from outside the repo is gated as its target. Without the
    /// canonicalize the anchor would be the link's parent, which has no store,
    /// and the gate would wave the read through.
    #[tokio::test]
    async fn a_symlink_is_gated_as_its_target() {
        crate::cli::ensure_test_home();
        let target_dir = TempDir::new().unwrap();
        let target = source_file(&target_dir);
        seed_store_for(&target);

        let link_dir = TempDir::new().unwrap();
        let link = link_dir.path().join("shortcut.rs");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let _no_spawn = NoDaemonSpawn::on();
        let err = require_consultation(&link)
            .await
            .expect_err("a symlink must resolve to its target's store");
        assert!(err.to_string().contains("cannot tell whether"), "{err}");
    }
}
