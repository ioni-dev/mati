use anyhow::Result;

use mati_core::store::RecordLifecycle;

use super::proxy::StoreProxy;
use super::stats::gotcha_health;

/// `mati subagent-context` — emit SubagentStart hook JSON for Claude Code.
///
/// Reads the confirmed-gotcha count from the store (same path as `mati stats`)
/// and prints the hookSpecificOutput JSON that Claude Code expects for a
/// SubagentStart hook.  Fail-open: if the store cannot be opened, prints
/// nothing and exits 0 so the subagent always spawns.
pub async fn run_subagent_context() -> Result<()> {
    let cwd = match std::env::current_dir() {
        Ok(d) => d,
        Err(_) => return Ok(()),
    };

    let store = match StoreProxy::open(&cwd).await {
        Ok(s) => s,
        Err(_) => return Ok(()),
    };

    let mut gotchas = match store.scan_prefix("gotcha:").await {
        Ok(g) => g,
        Err(_) => return Ok(()),
    };
    gotchas.retain(|r| matches!(r.lifecycle, RecordLifecycle::Active));
    let health = gotcha_health(&gotchas);
    let n = health.confirmed;

    let ctx = if n > 0 {
        format!(
            "[mati] This repo uses mati, a codebase-memory layer: {n} confirmed gotcha(s) — \
             recorded constraints that aren't obvious from the code. \
             mem_bootstrap loads them; mem_get(\"file:<path>\") returns a file's recorded \
             gotchas before you read or edit it."
        )
    } else {
        "[mati] This repo uses mati, a codebase-memory layer. \
         mem_bootstrap loads any recorded gotchas; \
         mem_get(\"file:<path>\") returns a file's recorded gotchas before you read or edit it."
            .to_string()
    };

    let out = serde_json::json!({
        "hookSpecificOutput": {
            "hookEventName": "SubagentStart",
            "additionalContext": ctx
        }
    });

    println!("{}", serde_json::to_string(&out)?);
    Ok(())
}
