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
//! a gotcha's `reason`, a file record's `purpose` — are the product, and
//! reading one is the consultation itself, so nothing about them is gated.
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
