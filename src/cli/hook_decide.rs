//! CLI adapter for `mati hook-decide <variant>`.
//!
//! Owns daemon readiness, stdin parsing, and platform-specific output.
//! Delegates the pure enforcement decision to `hooks::decide::evaluate()`.

use anyhow::Result;
use clap::{Args, ValueEnum};
use std::collections::HashMap;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use crate::cli::daemon::{daemon_result, mati_root_for, read_pid_file, DaemonResult};
use mati_core::hooks::decide::{self, Decision, EnforcementInput, HookEvent};

// ── Public types ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum HookVariant {
    ClaudePreRead,
    ClaudePreBash,
    CodexPreBash,
    CodexPostBash,
}

#[derive(Args, Debug)]
pub struct HookDecideArgs {
    /// Which hook variant to execute.
    #[arg(value_enum)]
    pub variant: HookVariant,
}

// ── Entry point ─────────────────────────────────────────────────────────────

pub async fn run(args: HookDecideArgs) -> Result<()> {
    // 1. Read stdin (tool input JSON from hook protocol).
    let mut input_str = String::new();
    std::io::stdin().read_to_string(&mut input_str)?;
    let input: serde_json::Value =
        serde_json::from_str(&input_str).unwrap_or(serde_json::Value::Null);

    // 2. Extract file path (variant-specific).
    let raw_path = match extract_path(&input, args.variant) {
        Some(p) => p,
        None => {
            emit_allow(args.variant);
            return Ok(());
        }
    };

    // 3. Resolve repo root via git2 (no subprocess).
    let cwd = std::env::current_dir()?;
    let repo_root = discover_repo_root(&cwd);
    let repo_root_str = repo_root.as_ref().and_then(|p| p.to_str());
    // Platform limitation: bare relative paths in shell commands (e.g. `cat foo.rs`)
    // resolve against the hook process cwd, which is the repo root when set by
    // Claude Code / Codex. If the platform changes cwd semantics, relative paths
    // may need a tool_input.workdir field to resolve correctly.
    let rel_path = decide::normalize_path(&raw_path, repo_root_str);

    // 4. Resolve mati root (for daemon socket). Use repo_root for consistent slug.
    let root_for_slug = repo_root.as_deref().unwrap_or(&cwd);
    let mati_root = match mati_root_for(root_for_slug) {
        Ok(r) => r,
        Err(_) => {
            log_fail_open(&rel_path, "cannot determine mati root");
            emit_allow(args.variant);
            return Ok(());
        }
    };

    // 5. Ensure daemon is reachable (auto-start if needed).
    if !ensure_daemon(&mati_root).await {
        log_fail_open(&rel_path, "daemon not running after auto-start");
        emit_allow(args.variant);
        return Ok(());
    }

    // 6. codex-post-bash: separate flow — no evaluate(), just compliance logging.
    if args.variant == HookVariant::CodexPostBash {
        return run_post_bash(&mati_root, &rel_path).await;
    }

    // 7. Single hook_evaluate round-trip.
    let file_key = format!("file:{rel_path}");
    let include_recent = matches!(args.variant, HookVariant::CodexPreBash);

    let eval_data = match daemon_result(
        &mati_root,
        "hook_evaluate",
        serde_json::json!({
            "file_key": &file_key,
            "include_recent": include_recent,
        }),
    )
    .await
    {
        DaemonResult::Ok(resp) => resp.get("data").cloned().unwrap_or(serde_json::Value::Null),
        _ => {
            log_fail_open(&rel_path, "hook_evaluate failed");
            emit_allow(args.variant);
            return Ok(());
        }
    };

    // 8–11. Process eval response through the adapter pipeline.
    let adapter = process_eval_response(args.variant, &rel_path, &eval_data);

    // Fire events (non-blocking).
    fire_events(&mati_root, &adapter.events).await;

    // Fail-open telemetry for store/gotcha errors.
    if let EvalDataCheck::FailOpen(reason) = check_eval_data(args.variant, &rel_path, &eval_data) {
        log_fail_open(&rel_path, &reason);
    }

    // Platform-specific output.
    if !adapter.stdout.is_empty() {
        println!("{}", adapter.stdout);
    }
    if !adapter.stderr.is_empty() {
        eprintln!("{}", adapter.stderr);
    }
    if adapter.exit_code != 0 {
        let _ = std::io::Write::flush(&mut std::io::stderr());
        std::process::exit(adapter.exit_code);
    }

    Ok(())
}

// ── Path extraction ─────────────────────────────────────────────────────────

fn extract_path(input: &serde_json::Value, variant: HookVariant) -> Option<String> {
    match variant {
        HookVariant::ClaudePreRead => {
            // Structured file_path from Claude Code.
            input
                .pointer("/tool_input/file_path")
                .or_else(|| input.pointer("/tool_input/path"))
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
        }
        HookVariant::ClaudePreBash | HookVariant::CodexPreBash | HookVariant::CodexPostBash => {
            // Raw command string — classify then extract.
            let cmd = input
                .pointer("/tool_input/command")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())?;
            let class = decide::classify_command(cmd)?;
            decide::extract_file_path(cmd, class)
        }
    }
}

// ── Repo root ───────────────────────────────────────────────────────────────

/// Discover the git repo root via git2. Returns `None` for bare repos or
/// when not inside a git repository. No subprocess spawned.
///
/// Note: `repo.workdir()` may return a path with a trailing separator
/// (e.g. `/path/to/repo/`). We strip it so that `derive_slug()` produces
/// the same hash as `std::env::current_dir()` (which omits it). Without
/// this, repos without a remote URL get different slugs from `hook-decide`
/// vs `mati init`/`mati daemon`, causing daemon socket discovery to fail.
fn discover_repo_root(cwd: &Path) -> Option<PathBuf> {
    git2::Repository::discover(cwd).ok().and_then(|repo| {
        repo.workdir().map(|p| {
            // Strip trailing separator that git2's workdir() sometimes adds.
            let s = p.to_string_lossy();
            let trimmed = s.trim_end_matches('/');
            PathBuf::from(trimmed)
        })
    })
}

// ── Daemon readiness ────────────────────────────────────────────────────────

/// Ensure the daemon is reachable. Auto-starts if needed.
///
/// Recovery strategy:
/// - `Ok` → daemon is healthy, return immediately.
/// - `NotRunning` / `StaleSocket` → spawn daemon, poll for readiness.
/// - `Unresponsive` → socket exists + PID alive but can't connect.
///   Most common after MCP server crash, PID recycling, or a stale
///   daemon running an old protocol version (version mismatch returns
///   `Unresponsive`). Wait 300ms (covers the PID-write→socket-bind
///   race), then SIGTERM the old PID + force-cleanup and spawn fresh
///   if still unresponsive. The SIGTERM is critical: without it the old
///   process holds the exclusive SurrealKV Store lock and the new spawn
///   deadlocks on `Store::open()`.
///
/// Readiness poll uses exponential backoff: 50+100+150+200+300 = 800ms.
/// Total worst-case latency including Unresponsive recovery: ~1.6s.
/// Well within the 3000ms hook timeout.
async fn ensure_daemon(mati_root: &Path) -> bool {
    use std::time::Duration;

    // Phase 1: probe current state.
    match daemon_result(mati_root, "ping", serde_json::json!({})).await {
        DaemonResult::Ok(_) => return true,
        DaemonResult::NotRunning | DaemonResult::StaleSocket => {}
        DaemonResult::Unresponsive => {
            // Socket exists + PID alive, but can't connect. Could be:
            //   (a) daemon mid-startup (PID written, socket not yet bound)
            //   (b) recycled PID after MCP crash — stale, safe to clean up
            //   (c) genuinely hung process
            // Wait 300ms to cover (a), then re-probe.
            tokio::time::sleep(Duration::from_millis(300)).await;
            match daemon_result(mati_root, "ping", serde_json::json!({})).await {
                DaemonResult::Ok(_) => return true,
                DaemonResult::NotRunning | DaemonResult::StaleSocket => {
                    // daemon_result cleaned up stale files — fall through to spawn.
                }
                DaemonResult::Unresponsive => {
                    // Still unresponsive after 300ms. The PID is alive but not
                    // serving our socket — most likely a stale daemon running
                    // an old protocol version, or a recycled PID.
                    //
                    // Read the PID before removing the files so we can SIGTERM
                    // the old process. Without this, the old daemon keeps the
                    // exclusive SurrealKV Store lock and our new spawn blocks
                    // on Store::open() indefinitely — a deadlock.
                    let stale_pid = read_pid_file(mati_root).map(|(pid, _)| pid);
                    let _ = std::fs::remove_file(mati_root.join("mati.sock"));
                    let _ = std::fs::remove_file(mati_root.join("mati.pid"));
                    if let Some(pid) = stale_pid {
                        let _ = std::process::Command::new("kill")
                            .args(["-TERM", &pid.to_string()])
                            .stdin(std::process::Stdio::null())
                            .stdout(std::process::Stdio::null())
                            .stderr(std::process::Stdio::null())
                            .status();
                        // Give the old process time to release the Store lock.
                        tokio::time::sleep(Duration::from_millis(200)).await;
                    }
                }
            }
        }
    }

    // Phase 2: check if another process is already starting the daemon.
    // The daemon writes `mati.starting` before acquiring the Store lock.
    // If another hook already spawned a daemon within the last 5 seconds,
    // wait for it instead of spawning a competing instance (which would
    // block on the exclusive Store lock and waste time).
    let starting = mati_root.join("mati.starting");
    if starting.exists() {
        if let Ok(meta) = starting.metadata() {
            if let Ok(modified) = meta.modified() {
                if modified.elapsed().unwrap_or_default() < Duration::from_secs(5) {
                    // Another process is starting — poll for readiness.
                    for ms in [100, 150, 200, 250, 300] {
                        tokio::time::sleep(Duration::from_millis(ms)).await;
                        if matches!(
                            daemon_result(mati_root, "ping", serde_json::json!({})).await,
                            DaemonResult::Ok(_)
                        ) {
                            return true;
                        }
                    }
                    // Other spawn failed or is too slow — fall through to our own spawn.
                }
            }
        }
    }

    // Phase 3: spawn daemon.
    let exe = match std::env::current_exe() {
        Ok(e) => e,
        Err(_) => return false,
    };

    // Capture stderr to a log file so startup failures are diagnosable.
    let stderr_target = dirs::home_dir()
        .map(|h| h.join(".mati").join("daemon_start.log"))
        .and_then(|p| {
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&p)
                .ok()
        })
        .map(std::process::Stdio::from)
        .unwrap_or_else(std::process::Stdio::null);

    let _ = std::process::Command::new(&exe)
        .args(["daemon", "start"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(stderr_target)
        .spawn();

    // Phase 4: readiness poll with exponential backoff.
    // Budget: 50+100+150+200+300 = 800ms.
    for ms in [50, 100, 150, 200, 300] {
        tokio::time::sleep(Duration::from_millis(ms)).await;
        if matches!(
            daemon_result(mati_root, "ping", serde_json::json!({})).await,
            DaemonResult::Ok(_)
        ) {
            return true;
        }
    }

    false
}

// ── codex-post-bash flow ────────────────────────────────────────────────────

/// Compliance logging only — no `evaluate()`, no gotcha fetching.
async fn run_post_bash(mati_root: &Path, rel_path: &str) -> Result<()> {
    let file_key = format!("file:{rel_path}");

    // Reuse existing session_check_consulted_recent command.
    let consulted = match daemon_result(
        mati_root,
        "session_check_consulted_recent",
        serde_json::json!({ "key": &file_key, "ttl_secs": 900 }),
    )
    .await
    {
        DaemonResult::Ok(resp) => resp.get("data").and_then(|v| v.as_bool()).unwrap_or(false),
        _ => false,
    };

    // Fire the appropriate compliance event via typed v2 command.
    let event = if consulted {
        mati_core::mcp::protocol::SessionEvent::ComplianceHit
    } else {
        mati_core::mcp::protocol::SessionEvent::CodexShellMiss
    };
    let cmd = mati_core::mcp::protocol::Command::SessionLog(
        mati_core::mcp::protocol::SessionLogInput {
            event,
            key: file_key.clone(),
        },
    );
    let _ = super::daemon::daemon_v2(mati_root, cmd).await;

    // Post-hook: no output, always exit 0.
    Ok(())
}

// ── Fail-open telemetry ─────────────────────────────────────────────────────

fn log_fail_open(rel_path: &str, reason: &str) {
    eprintln!("[mati] WARNING: enforcement bypassed for {rel_path} — {reason}");
    if let Some(home) = dirs::home_dir() {
        let log_dir = home.join(".mati");
        let _ = std::fs::create_dir_all(&log_dir);
        let log_path = log_dir.join("fail_open.log");
        let now = chrono_lite_utc();
        let entry = format!("{now} FAIL_OPEN hook=hook-decide file={rel_path} reason={reason}\n");
        let _ = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_path)
            .and_then(|mut f| std::io::Write::write_all(&mut f, entry.as_bytes()));
    }
}

/// UTC timestamp without pulling in chrono.
fn chrono_lite_utc() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // Good enough for log lines — not worth a dependency.
    format!("{secs}")
}

// ── Platform-aware event mapping ────────────────────────────────────────────

/// Filter and translate events based on platform semantics.
///
/// Codex pre-bash:
///   - Deny → CodexShellBlocked (not generic BlockedUnconsultedRead)
///   - Advisory/Liability/AlreadyConsulted are silent → suppress Hit (no receipt)
///   - NoRecord → Miss (keep)
///
/// Claude pre-read/pre-bash: keep all events as-is.
fn platform_events(
    variant: HookVariant,
    decision: &Decision,
    events: Vec<HookEvent>,
) -> Vec<HookEvent> {
    match variant {
        HookVariant::CodexPreBash => events
            .into_iter()
            .filter_map(|e| match e {
                HookEvent::Miss { .. } => Some(e),
                HookEvent::BlockedUnconsultedRead { key } => {
                    Some(HookEvent::CodexShellBlocked { key })
                }
                HookEvent::Hit { .. } => {
                    // Suppress Hit for outcomes where Codex receives no context.
                    // Minting a consultation receipt without delivering context
                    // would incorrectly downgrade future deny decisions.
                    match decision {
                        Decision::AlreadyConsulted { .. }
                        | Decision::Advisory { .. }
                        | Decision::Liability { .. } => None,
                        _ => Some(e),
                    }
                }
                _ => Some(e),
            })
            .collect(),
        HookVariant::CodexPostBash => {
            // Post-bash uses its own flow — should not reach here.
            events
        }
        HookVariant::ClaudePreRead | HookVariant::ClaudePreBash => {
            // Claude delivers context for all non-silent outcomes.
            events
        }
    }
}

// ── Event firing ────────────────────────────────────────────────────────────

async fn fire_events(mati_root: &Path, events: &[HookEvent]) {
    use mati_core::mcp::protocol as p;
    for event in events {
        let cmd = match event {
            HookEvent::Hit { key } => p::Command::ConsultationHit(p::ConsultationHitInput {
                key: key.clone(),
            }),
            HookEvent::Miss { key } => p::Command::SessionLog(p::SessionLogInput {
                event: p::SessionEvent::Miss,
                key: key.clone(),
            }),
            HookEvent::BlockedUnconsultedRead { key } => {
                p::Command::SessionLog(p::SessionLogInput {
                    event: p::SessionEvent::ComplianceMiss,
                    key: key.clone(),
                })
            }
            HookEvent::CodexShellBlocked { key } => {
                p::Command::SessionLog(p::SessionLogInput {
                    event: p::SessionEvent::CodexShellMiss,
                    key: key.clone(),
                })
            }
            HookEvent::ComplianceHit { key } => p::Command::SessionLog(p::SessionLogInput {
                event: p::SessionEvent::ComplianceHit,
                key: key.clone(),
            }),
        };
        // Fire-and-forget — drop silently on failure (P9).
        let _ = super::daemon::daemon_v2(mati_root, cmd).await;
    }
}

// ── Platform output ─────────────────────────────────────────────────────────

fn emit_allow(variant: HookVariant) {
    match variant {
        HookVariant::ClaudePreRead | HookVariant::ClaudePreBash => {
            println!(
                r#"{{"hookSpecificOutput":{{"hookEventName":"PreToolUse","permissionDecision":"allow"}}}}"#
            );
        }
        HookVariant::CodexPreBash | HookVariant::CodexPostBash => {
            // Silent exit 0.
        }
    }
}

// emit_decision, emit_claude_decision, and emit_codex_pre_bash_decision
// have been replaced by format_decision() + format_claude_output() in the
// testable adapter core above. The run() function now uses process_eval_response().

// ── Helpers ─────────────────────────────────────────────────────────────────

fn extract_gotcha_map(eval_data: &serde_json::Value) -> HashMap<String, serde_json::Value> {
    eval_data
        .get("gotcha_records")
        .and_then(|v| v.as_object())
        .map(|obj| obj.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
        .unwrap_or_default()
}

/// Escape a string for inclusion inside a JSON string value.
fn escape_json_string(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

// ── Testable adapter core ───────────────────────────────────────────────────

/// Result of processing a hook_evaluate response through the full adapter
/// pipeline: eval_data → EnforcementInput → evaluate → platform_events →
/// format output. Captures everything a test needs to verify without I/O.
#[derive(Debug)]
struct AdapterResult {
    /// Platform-specific stdout (JSON for Claude, empty for Codex allow).
    stdout: String,
    /// Platform-specific stderr (only Codex deny).
    stderr: String,
    /// Exit code (2 for Codex deny, 0 otherwise).
    exit_code: i32,
    /// Events to fire (already platform-filtered).
    events: Vec<HookEvent>,
    /// The semantic decision (used by tests via Debug).
    #[allow(dead_code)]
    decision: Decision,
}

/// Special adapter outcome when the eval_data contains errors.
enum EvalDataCheck {
    /// Proceed with enforcement evaluation.
    Ok(EnforcementInput),
    /// Fail-open due to store/gotcha error.
    FailOpen(String),
}

/// Check eval_data for store/gotcha errors and build EnforcementInput.
fn check_eval_data(
    variant: HookVariant,
    rel_path: &str,
    eval_data: &serde_json::Value,
) -> EvalDataCheck {
    let include_recent = matches!(
        variant,
        HookVariant::CodexPreBash | HookVariant::CodexPostBash
    );
    let already_consulted = if include_recent {
        eval_data
            .get("consulted_recent")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    } else {
        eval_data
            .get("consulted")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    };

    let input = EnforcementInput {
        rel_path: rel_path.to_string(),
        file_record: eval_data
            .get("file_record")
            .cloned()
            .filter(|v| !v.is_null()),
        gotcha_records: extract_gotcha_map(eval_data),
        already_consulted,
    };

    let store_error = eval_data
        .get("store_error")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if store_error && input.file_record.is_none() {
        return EvalDataCheck::FailOpen("store error during hook_evaluate".into());
    }

    let gotcha_error = eval_data
        .get("gotcha_error")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if gotcha_error {
        return EvalDataCheck::FailOpen("gotcha fetch error during hook_evaluate".into());
    }

    EvalDataCheck::Ok(input)
}

/// Process a hook_evaluate response through the full adapter pipeline.
/// No I/O — returns a result struct for testing.
fn process_eval_response(
    variant: HookVariant,
    rel_path: &str,
    eval_data: &serde_json::Value,
) -> AdapterResult {
    let enforcement_input = match check_eval_data(variant, rel_path, eval_data) {
        EvalDataCheck::Ok(input) => input,
        EvalDataCheck::FailOpen(_reason) => {
            let stdout = match variant {
                HookVariant::ClaudePreRead | HookVariant::ClaudePreBash => {
                    r#"{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}"#.to_string()
                }
                _ => String::new(),
            };
            return AdapterResult {
                stdout,
                stderr: String::new(),
                exit_code: 0,
                events: vec![],
                decision: Decision::Allow,
            };
        }
    };

    let result = decide::evaluate(&enforcement_input);
    let events = platform_events(variant, &result.decision, result.events);

    let (stdout, stderr, exit_code) = format_decision(variant, &result.decision, rel_path);

    AdapterResult {
        stdout,
        stderr,
        exit_code,
        events,
        decision: result.decision,
    }
}

/// Format the decision as platform output strings + exit code.
/// Does NOT call process::exit — returns the values for the caller to act on.
fn format_decision(
    variant: HookVariant,
    decision: &Decision,
    _rel_path: &str,
) -> (String, String, i32) {
    match variant {
        HookVariant::ClaudePreRead | HookVariant::ClaudePreBash => {
            let stdout = format_claude_output(decision);
            (stdout, String::new(), 0)
        }
        HookVariant::CodexPreBash => match decision {
            Decision::Deny { file_key, .. } => {
                let stderr = format!("mati: call mem_get(\"{file_key}\") first");
                (String::new(), stderr, 2)
            }
            _ => (String::new(), String::new(), 0),
        },
        HookVariant::CodexPostBash => (String::new(), String::new(), 0),
    }
}

fn format_claude_output(decision: &Decision) -> String {
    match decision {
        Decision::Deny { reason, .. } => {
            let escaped = escape_json_string(reason);
            format!(
                r#"{{"hookSpecificOutput":{{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"{escaped}"}}}}"#
            )
        }
        Decision::AlreadyConsulted { context } => {
            let escaped =
                escape_json_string(&format!("[mati] Record already consulted. {context}"));
            format!(
                r#"{{"hookSpecificOutput":{{"hookEventName":"PreToolUse","permissionDecision":"allow","additionalContext":"{escaped}"}}}}"#
            )
        }
        Decision::Advisory { context } => {
            let escaped = escape_json_string(&format!("[mati] {context}"));
            format!(
                r#"{{"hookSpecificOutput":{{"hookEventName":"PreToolUse","permissionDecision":"allow","additionalContext":"{escaped}"}}}}"#
            )
        }
        Decision::Liability { context, .. } => {
            let escaped = escape_json_string(&format!("[mati] {context}"));
            format!(
                r#"{{"hookSpecificOutput":{{"hookEventName":"PreToolUse","permissionDecision":"allow","additionalContext":"{escaped}"}}}}"#
            )
        }
        _ => {
            r#"{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}"#
                .to_string()
        }
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── extract_path ────────────────────────────────────────────────────

    #[test]
    fn extract_path_claude_pre_read_file_path() {
        let input = json!({"tool_input": {"file_path": "/home/user/project/src/main.rs"}});
        assert_eq!(
            extract_path(&input, HookVariant::ClaudePreRead),
            Some("/home/user/project/src/main.rs".into())
        );
    }

    #[test]
    fn extract_path_claude_pre_read_path_fallback() {
        let input = json!({"tool_input": {"path": "src/main.rs"}});
        assert_eq!(
            extract_path(&input, HookVariant::ClaudePreRead),
            Some("src/main.rs".into())
        );
    }

    #[test]
    fn extract_path_claude_pre_read_empty() {
        let input = json!({"tool_input": {"file_path": ""}});
        assert_eq!(extract_path(&input, HookVariant::ClaudePreRead), None);
    }

    #[test]
    fn extract_path_codex_pre_bash_cat() {
        let input = json!({"tool_input": {"command": "cat src/main.rs"}});
        assert_eq!(
            extract_path(&input, HookVariant::CodexPreBash),
            Some("src/main.rs".into())
        );
    }

    #[test]
    fn extract_path_codex_pre_bash_non_file_command() {
        let input = json!({"tool_input": {"command": "ls -la"}});
        assert_eq!(extract_path(&input, HookVariant::CodexPreBash), None);
    }

    #[test]
    fn extract_path_codex_pre_bash_empty_command() {
        let input = json!({"tool_input": {"command": ""}});
        assert_eq!(extract_path(&input, HookVariant::CodexPreBash), None);
    }

    #[test]
    fn extract_path_codex_fixture_tool_input_command() {
        // The supported Codex input fixture — proves no regression.
        let input = json!({"tool_input": {"command": "cat src/main.rs"}});
        assert_eq!(
            extract_path(&input, HookVariant::CodexPreBash),
            Some("src/main.rs".into())
        );
    }

    // ── platform_events ─────────────────────────────────────────────────

    #[test]
    fn codex_deny_translates_to_shell_blocked() {
        let events = vec![HookEvent::BlockedUnconsultedRead {
            key: "file:src/main.rs".into(),
        }];
        let decision = Decision::Deny {
            file_key: "file:src/main.rs".into(),
            reason: "test".into(),
        };
        let result = platform_events(HookVariant::CodexPreBash, &decision, events);
        assert_eq!(result.len(), 1);
        assert!(matches!(
            &result[0],
            HookEvent::CodexShellBlocked { key } if key == "file:src/main.rs"
        ));
    }

    #[test]
    fn codex_advisory_suppresses_hit() {
        let events = vec![HookEvent::Hit {
            key: "file:src/main.rs".into(),
        }];
        let decision = Decision::Advisory {
            context: "test".into(),
        };
        let result = platform_events(HookVariant::CodexPreBash, &decision, events);
        assert!(
            result.is_empty(),
            "Codex should not mint receipts for silent outcomes"
        );
    }

    #[test]
    fn codex_liability_suppresses_hit() {
        let events = vec![HookEvent::Hit {
            key: "file:src/main.rs".into(),
        }];
        let decision = Decision::Liability {
            staleness: 0.85,
            context: "test".into(),
        };
        let result = platform_events(HookVariant::CodexPreBash, &decision, events);
        assert!(result.is_empty());
    }

    #[test]
    fn codex_already_consulted_suppresses_hit() {
        let events = vec![HookEvent::Hit {
            key: "file:src/main.rs".into(),
        }];
        let decision = Decision::AlreadyConsulted {
            context: "test".into(),
        };
        let result = platform_events(HookVariant::CodexPreBash, &decision, events);
        assert!(result.is_empty());
    }

    #[test]
    fn codex_no_record_keeps_miss() {
        let events = vec![HookEvent::Miss {
            key: "file:src/main.rs".into(),
        }];
        let decision = Decision::NoRecord;
        let result = platform_events(HookVariant::CodexPreBash, &decision, events);
        assert_eq!(result.len(), 1);
        assert!(matches!(&result[0], HookEvent::Miss { .. }));
    }

    #[test]
    fn claude_keeps_all_events() {
        let events = vec![HookEvent::Hit {
            key: "file:src/main.rs".into(),
        }];
        let decision = Decision::Advisory {
            context: "test".into(),
        };
        let result = platform_events(HookVariant::ClaudePreRead, &decision, events);
        assert_eq!(
            result.len(),
            1,
            "Claude should keep Hit for advisory outcomes"
        );
    }

    #[test]
    fn claude_deny_keeps_blocked_event() {
        let events = vec![HookEvent::BlockedUnconsultedRead {
            key: "file:src/main.rs".into(),
        }];
        let decision = Decision::Deny {
            file_key: "file:src/main.rs".into(),
            reason: "test".into(),
        };
        let result = platform_events(HookVariant::ClaudePreBash, &decision, events);
        assert_eq!(result.len(), 1);
        assert!(matches!(
            &result[0],
            HookEvent::BlockedUnconsultedRead { .. }
        ));
    }

    // ── End-to-end adapter tests ────────────────────────────────────────
    //
    // These test the full adapter pipeline: mock hook_evaluate response →
    // EnforcementInput → evaluate → platform_events → format output.
    // Exercises the same code path as run() without daemon I/O.

    fn deny_eligible_eval_data() -> serde_json::Value {
        json!({
            "file_key": "file:src/main.rs",
            "file_record": {
                "value": "Entry point",
                "confidence": { "value": 0.7 },
                "quality": { "value": 0.5 },
                "staleness": { "value": 0.1, "tier": "fresh" },
                "payload": { "gotcha_keys": ["gotcha:test-rule"] }
            },
            "gotcha_records": {
                "gotcha:test-rule": {
                    "value": "Never call unwrap in this file",
                    "confidence": { "value": 0.8 },
                    "quality": { "value": 0.6 },
                    "payload": { "confirmed": true }
                }
            },
            "consulted": false,
            "consulted_recent": false,
            "store_error": false,
            "gotcha_error": false
        })
    }

    #[test]
    fn e2e_codex_deny_exit2_stderr_and_shell_blocked_event() {
        let data = deny_eligible_eval_data();
        let result = process_eval_response(HookVariant::CodexPreBash, "src/main.rs", &data);

        assert_eq!(result.exit_code, 2, "Codex deny must exit 2");
        assert!(
            result.stderr.contains("mem_get"),
            "stderr must instruct agent to call mem_get, got: {}",
            result.stderr
        );
        assert!(result.stdout.is_empty(), "Codex deny should have no stdout");
        assert_eq!(result.events.len(), 1);
        assert!(
            matches!(&result.events[0], HookEvent::CodexShellBlocked { key } if key == "file:src/main.rs"),
            "Codex deny must emit CodexShellBlocked, got: {:?}",
            result.events
        );
        assert!(matches!(result.decision, Decision::Deny { .. }));
    }

    #[test]
    fn e2e_claude_deny_json_output_and_blocked_event() {
        let data = deny_eligible_eval_data();
        let result = process_eval_response(HookVariant::ClaudePreBash, "src/main.rs", &data);

        assert_eq!(result.exit_code, 0, "Claude always exits 0");
        let json: serde_json::Value =
            serde_json::from_str(&result.stdout).expect("stdout must be valid JSON");
        assert_eq!(
            json.pointer("/hookSpecificOutput/permissionDecision")
                .and_then(|v| v.as_str()),
            Some("deny")
        );
        assert!(
            json.pointer("/hookSpecificOutput/permissionDecisionReason")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .contains("mem_get"),
            "deny reason must mention mem_get"
        );
        assert_eq!(result.events.len(), 1);
        assert!(matches!(
            &result.events[0],
            HookEvent::BlockedUnconsultedRead { .. }
        ));
    }

    #[test]
    fn e2e_codex_advisory_silent_no_hit() {
        let data = json!({
            "file_key": "file:src/lib.rs",
            "file_record": {
                "value": "Library root",
                "confidence": { "value": 0.45 },
                "quality": { "value": 0.5 },
                "staleness": { "value": 0.1, "tier": "fresh" },
                "payload": { "gotcha_keys": [] }
            },
            "gotcha_records": {},
            "consulted": false,
            "consulted_recent": false,
            "store_error": false,
            "gotcha_error": false
        });
        let result = process_eval_response(HookVariant::CodexPreBash, "src/lib.rs", &data);

        assert_eq!(result.exit_code, 0);
        assert!(result.stdout.is_empty(), "Codex advisory must be silent");
        assert!(result.stderr.is_empty());
        // Advisory emits Hit in the core, but Codex suppresses it.
        assert!(
            result.events.is_empty(),
            "Codex must NOT mint consultation receipt for advisory, got: {:?}",
            result.events
        );
        assert!(matches!(result.decision, Decision::Advisory { .. }));
    }

    #[test]
    fn e2e_claude_advisory_injects_context() {
        let data = json!({
            "file_key": "file:src/lib.rs",
            "file_record": {
                "value": "Library root",
                "confidence": { "value": 0.45 },
                "quality": { "value": 0.5 },
                "staleness": { "value": 0.1, "tier": "fresh" },
                "payload": { "gotcha_keys": [] }
            },
            "gotcha_records": {},
            "consulted": false,
            "consulted_recent": false,
            "store_error": false,
            "gotcha_error": false
        });
        let result = process_eval_response(HookVariant::ClaudePreRead, "src/lib.rs", &data);

        assert_eq!(result.exit_code, 0);
        let json: serde_json::Value =
            serde_json::from_str(&result.stdout).expect("stdout must be valid JSON");
        assert_eq!(
            json.pointer("/hookSpecificOutput/permissionDecision")
                .and_then(|v| v.as_str()),
            Some("allow")
        );
        assert!(
            json.pointer("/hookSpecificOutput/additionalContext")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .contains("[mati]"),
            "Claude advisory must inject context"
        );
        // Claude DOES fire Hit for advisory.
        assert_eq!(result.events.len(), 1);
        assert!(matches!(&result.events[0], HookEvent::Hit { .. }));
    }

    #[test]
    fn e2e_codex_consulted_allows_silently() {
        let mut data = deny_eligible_eval_data();
        data["consulted_recent"] = json!(true);
        let result = process_eval_response(HookVariant::CodexPreBash, "src/main.rs", &data);

        assert_eq!(result.exit_code, 0, "consulted file must not be blocked");
        assert!(result.stdout.is_empty());
        assert!(result.stderr.is_empty());
        // AlreadyConsulted is silent for Codex → Hit suppressed.
        assert!(result.events.is_empty());
    }

    #[test]
    fn e2e_store_error_fails_open() {
        let data = json!({
            "file_key": "file:src/main.rs",
            "file_record": null,
            "gotcha_records": {},
            "consulted": false,
            "consulted_recent": false,
            "store_error": true,
            "gotcha_error": false
        });
        let result = process_eval_response(HookVariant::CodexPreBash, "src/main.rs", &data);

        assert_eq!(result.exit_code, 0, "store error must fail open");
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn e2e_gotcha_error_fails_open() {
        let data = json!({
            "file_key": "file:src/main.rs",
            "file_record": {
                "value": "test",
                "confidence": { "value": 0.7 },
                "quality": { "value": 0.5 },
                "staleness": { "value": 0.1, "tier": "fresh" },
                "payload": { "gotcha_keys": ["gotcha:broken"] }
            },
            "gotcha_records": {},
            "consulted": false,
            "consulted_recent": false,
            "store_error": false,
            "gotcha_error": true
        });
        let result = process_eval_response(HookVariant::ClaudePreBash, "src/main.rs", &data);

        assert_eq!(result.exit_code, 0, "gotcha error must fail open");
        let json: serde_json::Value =
            serde_json::from_str(&result.stdout).expect("stdout must be valid JSON");
        assert_eq!(
            json.pointer("/hookSpecificOutput/permissionDecision")
                .and_then(|v| v.as_str()),
            Some("allow"),
            "gotcha error must produce allow"
        );
    }

    #[test]
    fn e2e_no_record_allows() {
        let data = json!({
            "file_key": "file:src/new.rs",
            "file_record": null,
            "gotcha_records": {},
            "consulted": false,
            "consulted_recent": false,
            "store_error": false,
            "gotcha_error": false
        });
        let result = process_eval_response(HookVariant::ClaudePreRead, "src/new.rs", &data);

        assert_eq!(result.exit_code, 0);
        assert!(matches!(result.decision, Decision::NoRecord));
        assert_eq!(result.events.len(), 1);
        assert!(matches!(&result.events[0], HookEvent::Miss { .. }));
    }
}
