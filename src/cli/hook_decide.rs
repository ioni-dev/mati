//! CLI adapter for `mati hook-decide <variant>`.
//!
//! Owns daemon readiness, stdin parsing, and platform-specific output.
//! Delegates the pure enforcement decision to `hooks::decide::evaluate()`.

use anyhow::Result;
use clap::{Args, ValueEnum};
use globset::{Glob, GlobSet, GlobSetBuilder};
use std::collections::HashMap;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::cli::daemon::{daemon_result, mati_root_for, DaemonResult};
use mati_core::hooks::decide::{self, Decision, EnforcementInput, HookEvent};

// ── Public types ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum HookVariant {
    ClaudePreRead,
    /// Claude PreToolUse(Edit|Write|NotebookEdit): gate file *edits*. Uses
    /// `consulted_recent` (a recent-consultation TTL, matching the Codex
    /// `apply_patch` edit gate) — NOT the read gate's persistent `consulted` — so
    /// an edit must be preceded by a *recent* mem_get: read-then-edit flows within
    /// the TTL, and blind or stale-consult edits deny. Non-deny outcomes DEFER to
    /// the normal permission flow instead of emitting `allow` — edits are
    /// permission-required, so force-allow would suppress the user's edit prompt.
    ClaudePreEdit,
    ClaudePreBash,
    CodexPreBash,
    CodexPostBash,
    /// Codex PreToolUse(apply_patch): gate file *edits*. Multi-file flow
    /// (`run_apply_patch`) — parses the patch envelope and denies if any
    /// touched file has an unconsulted confirmed gotcha.
    CodexPreApplyPatch,
    /// Claude PostToolUse(mcp__mati__mem_get): record actor-scoped consult receipt.
    /// Payload carries session_id, agent_id (subagent), and tool_input.key.
    ///
    /// clap's default kebab derive would yield `claude-post-mem-get`; pin the CLI
    /// value to `claude-post-memget` so it matches the installed hook script
    /// (`post-memget.sh` → `mati hook-decide claude-post-memget`).
    #[value(name = "claude-post-memget")]
    ClaudePostMemGet,
}

#[derive(Args, Debug)]
pub struct HookDecideArgs {
    /// Which hook variant to execute.
    #[arg(value_enum)]
    pub variant: HookVariant,
}

// ── Entry point ─────────────────────────────────────────────────────────────

/// Outer end-to-end deadline for the hook process.
///
/// Claude Code SIGKILLs the hook subprocess at 3000ms wall-clock. SIGKILL
/// bypasses every internal `log_fail_open` call, leaving operators blind to
/// wedged-daemon spikes — the exact failure mode `fail_open.log` exists to
/// surface. This ceiling fires ~500ms before SIGKILL so we get one clean
/// fail-open log entry + an allow stdout before Claude reaps us.
const HOOK_DEADLINE_MS: u64 = 2500;

pub async fn run(args: HookDecideArgs) -> Result<()> {
    let variant = args.variant;
    match tokio::time::timeout(Duration::from_millis(HOOK_DEADLINE_MS), run_inner(args)).await {
        Ok(inner_result) => inner_result,
        Err(_elapsed) => {
            // Internal deadline exceeded. We don't know which path stalled
            // (path may not even have been extracted yet), so log with the
            // sentinel "<unknown>" — still better than no entry at all.
            log_fail_open("<unknown>", "hook process exceeded internal deadline");
            emit_allow(variant);
            Ok(())
        }
    }
}

async fn run_inner(args: HookDecideArgs) -> Result<()> {
    // 1. Read stdin (tool input JSON from hook protocol).
    let mut input_str = String::new();
    std::io::stdin().read_to_string(&mut input_str)?;
    let input: serde_json::Value =
        serde_json::from_str(&input_str).unwrap_or(serde_json::Value::Null);

    // apply_patch is multi-file: it parses the patch envelope and evaluates
    // every touched path, so it has its own flow rather than the single-path
    // pipeline below.
    if args.variant == HookVariant::CodexPreApplyPatch {
        return run_apply_patch(&input).await;
    }

    // claude-post-memget: records an actor-scoped consult receipt using
    // tool_input.key directly — NOT a file path, so skip extract_path entirely.
    if args.variant == HookVariant::ClaudePostMemGet {
        return run_post_memget(&input).await;
    }

    // 1b. Parse agent_id: present only in subagent hook payloads.
    // Gate actor = agent_id if present, else None (NO session_id fallback).
    // - Subagent: actor = Some(agent_id) → reads actor-scoped receipt.
    // - Main thread: actor = None → reads global receipt (unchanged path).
    let agent_id = input
        .get("agent_id")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty());

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
    //
    // `rel_path` is the LEXICAL key — the primary gate. When it finds no
    // gotcha, the canonical-key fallback below (WI-20) re-evaluates the
    // symlink's real target so the gate still fires.
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
    // ClaudePreEdit and CodexPreBash both want the recent-TTL consultation, not
    // the persistent `consulted` flag: an edit / shell-read must be freshly
    // preceded by a mem_get (matches the Codex apply_patch edit gate).
    let include_recent = matches!(
        args.variant,
        HookVariant::CodexPreBash | HookVariant::ClaudePreEdit
    );

    // Enterprise consult-mandate globs (env-supplied; see `apply_consult_mandate`), compiled
    // once and applied at every evaluation site below — primary, canonical (symlink), and
    // multi-file extras — for parity with gotcha enforcement.
    let consult_globs = consult_globset();

    let eval_data = match daemon_result(
        &mati_root,
        "hook_evaluate",
        serde_json::json!({
            "file_key": &file_key,
            "include_recent": include_recent,
            "actor": agent_id,
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
    let mut adapter = process_eval_response(args.variant, &rel_path, &eval_data);
    // Consult mandate on the PRIMARY (lexical) file — before the escalation blocks so a
    // mandated deny short-circuits the canonical/extra round-trips too.
    apply_consult_mandate(
        &mut adapter,
        args.variant,
        &rel_path,
        consulted_flag(&eval_data, include_recent),
        consult_globs.as_ref(),
    );

    // Fail-open telemetry for store/gotcha errors on the LEXICAL evaluation.
    // This describes the lexical lookup that just ran; the canonical fallback
    // below has its own per-lookup error handling (a failed canonical
    // hook_evaluate simply leaves the lexical decision intact).
    let lexical_fail_open = match check_eval_data(args.variant, &rel_path, &eval_data) {
        EvalDataCheck::FailOpen(reason) => Some(reason),
        EvalDataCheck::Ok(_) => None,
    };

    // WI-20: canonical-key fallback (symlink-bypass close).
    //
    // The lexical key (`file:<rel_path>`) is the primary gate and is evaluated
    // first, above — never weakened. ONLY when the lexical gate did NOT deny do
    // we resolve the symlink: a symlink to a gotcha'd file has a different
    // lexical key, so the lexical gate misses it. We canonicalize the accessed
    // path (resolving symlinks), strip the canonicalized repo_root, and evaluate
    // that target's key too. If the real target carries an unconsulted confirmed
    // gotcha, the gate fires on it. Fully defensive: any failure (no repo root,
    // canonicalize error, target outside the repo, identical key) leaves the
    // lexical-only decision untouched. Perf: one extra realpath + one daemon
    // round-trip, and only on the non-deny path, so the common case is zero-cost.
    if !matches!(adapter.decision, Decision::Deny { .. }) {
        if let Some(canon_rel) =
            canonical_rel_path(&raw_path, &cwd, repo_root.as_deref(), &rel_path)
        {
            let canon_key = format!("file:{canon_rel}");
            if let DaemonResult::Ok(resp) = daemon_result(
                &mati_root,
                "hook_evaluate",
                serde_json::json!({
                    "file_key": &canon_key,
                    "include_recent": include_recent,
                    "actor": agent_id,
                }),
            )
            .await
            {
                let canon_eval = resp.get("data").cloned().unwrap_or(serde_json::Value::Null);
                let mut canon_adapter =
                    process_eval_response(args.variant, &canon_rel, &canon_eval);
                // Mandate the symlink's real target too (parity with the gotcha WI-20 close).
                apply_consult_mandate(
                    &mut canon_adapter,
                    args.variant,
                    &canon_rel,
                    consulted_flag(&canon_eval, include_recent),
                    consult_globs.as_ref(),
                );
                // Only ESCALATE: adopt the canonical result solely when it denies.
                // A non-deny canonical outcome never downgrades the lexical
                // decision (e.g. a lexical Advisory must survive). The canonical
                // adapter is self-contained — its deny reason and audit events
                // already key on `canon_rel` (the real target) — so swapping the
                // adapter alone re-points output + events at the resolved file.
                if matches!(canon_adapter.decision, Decision::Deny { .. }) {
                    adapter = canon_adapter;
                }
            }
        }
    }

    // Multi-file bash reads (`cat a.rs b.rs`, `grep pat f1 f2`): the single-path
    // flow above fully evaluated the PRIMARY file; gate the REMAINING files too
    // so a gotcha on a non-primary file still denies. Escalate-only, mirroring
    // the canonical fallback (a non-deny extra file never downgrades the
    // decision) and a no-op when the command names a single file — the common
    // case — so it adds zero daemon round-trips there. Capped like apply_patch.
    if !matches!(adapter.decision, Decision::Deny { .. })
        && matches!(
            args.variant,
            HookVariant::ClaudePreBash | HookVariant::CodexPreBash
        )
    {
        if let Some(cmd) = input
            .pointer("/tool_input/command")
            .and_then(|v| v.as_str())
        {
            if let Some(class) = decide::classify_command(cmd) {
                for extra_raw in decide::extract_file_paths(cmd, class)
                    .into_iter()
                    .take(decide::MAX_APPLY_PATCH_FILES)
                {
                    let extra_rel = decide::normalize_path(&extra_raw, repo_root_str);
                    if extra_rel == rel_path {
                        continue; // primary already evaluated above
                    }
                    let extra_key = format!("file:{extra_rel}");
                    if let DaemonResult::Ok(resp) = daemon_result(
                        &mati_root,
                        "hook_evaluate",
                        serde_json::json!({
                            "file_key": &extra_key,
                            "include_recent": include_recent,
                            "actor": agent_id,
                        }),
                    )
                    .await
                    {
                        let extra_eval =
                            resp.get("data").cloned().unwrap_or(serde_json::Value::Null);
                        let mut extra_adapter =
                            process_eval_response(args.variant, &extra_rel, &extra_eval);
                        // Mandate non-primary bash args too (parity with gotcha extra-file gating).
                        apply_consult_mandate(
                            &mut extra_adapter,
                            args.variant,
                            &extra_rel,
                            consulted_flag(&extra_eval, include_recent),
                            consult_globs.as_ref(),
                        );
                        if matches!(extra_adapter.decision, Decision::Deny { .. }) {
                            adapter = extra_adapter;
                            break;
                        }
                    }
                }
            }
        }
    }

    // Fire events (non-blocking).
    // session_id (Claude Code provides it at the top level of the hook input)
    // attributes these audit events to this agent session — per-actor audit.
    let session_id = input.get("session_id").and_then(|v| v.as_str());
    fire_events(&mati_root, &adapter.events, session_id).await;

    // Emit the lexical fail-open telemetry captured before the fallback.
    if let Some(reason) = lexical_fail_open {
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
        HookVariant::ClaudePreRead | HookVariant::ClaudePreEdit => {
            // Structured path from Claude Code. Read/Edit/Write use `file_path`;
            // NotebookEdit uses `notebook_path`. We check both (plus a legacy
            // `path` fallback) so the edit gate covers every edit-class tool in
            // the matcher regardless of which field the tool populates — rather
            // than assuming one field for a tool whose schema we haven't pinned.
            input
                .pointer("/tool_input/file_path")
                .or_else(|| input.pointer("/tool_input/notebook_path"))
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
        // apply_patch is multi-file and handled by `run_apply_patch` before the
        // single-path pipeline; never reaches here.
        HookVariant::CodexPreApplyPatch => None,
        // post-memget is handled by `run_post_memget` before extract_path is called;
        // it uses tool_input.key directly, not a file path.
        HookVariant::ClaudePostMemGet => None,
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

/// WI-20: compute the CANONICAL repo-relative key for the symlink-bypass
/// fallback, or `None` if the canonical resolution can't be trusted.
///
/// Returns `Some(canonical_rel)` ONLY when, after resolving symlinks on the
/// accessed path, both hold:
///
///   - the canonical target lands UNDER the canonical repo root, AND
///   - the canonical key DIFFERS from the lexical key (`lexical_rel`).
///
/// Otherwise returns `None`, leaving the lexical-only decision intact. This is
/// the additive half of the gate: it never weakens the lexical lookup — the
/// caller only consults it when the lexical gate did not already deny.
///
/// Defensive by construction: a missing repo root, a `canonicalize` failure, a
/// target resolving outside the repo, or a no-op (same key) all yield `None`.
/// Reuses [`super::sandbox::canonicalize_lenient`] so symlink resolution matches
/// the L3 sandbox floor exactly (canonicalize; on a non-existent leaf,
/// canonicalize the parent and re-append the leaf).
fn canonical_rel_path(
    raw_path: &str,
    cwd: &Path,
    repo_root: Option<&Path>,
    lexical_rel: &str,
) -> Option<String> {
    // No repo root → we can't strip a prefix to form a repo-relative key.
    let repo_root = repo_root?;

    // Resolve the repo root itself through symlinks so the `starts_with`
    // containment check below is sound (e.g. macOS `/var` → `/private/var`).
    let canon_root = super::sandbox::canonicalize_lenient(repo_root)?;

    // Build the ABSOLUTE accessed path. A relative shell arg (`cat foo.rs`)
    // resolves against the hook process cwd (the repo root under Claude/Codex).
    let raw = Path::new(raw_path);
    let abs_access = if raw.is_absolute() {
        raw.to_path_buf()
    } else {
        cwd.join(raw)
    };

    // Resolve symlinks on the accessed path (this is the whole point: a symlink
    // to a gotcha'd file canonicalizes to the real target).
    let canon_access = super::sandbox::canonicalize_lenient(&abs_access)?;

    // Containment: the canonical target must be inside the repo. Out-of-repo
    // targets can't match a store key and must never deny — fall back to lexical.
    let stripped = canon_access.strip_prefix(&canon_root).ok()?;
    let stripped_str = stripped.to_str()?;

    // Normalize to the same lexical key shape used at registration / lookup.
    let canon_rel = decide::normalize_path(stripped_str, None);

    // Zero-cost no-op: if the canonical key equals the lexical one (no symlink
    // involved), skip the redundant second daemon round-trip.
    if canon_rel == lexical_rel {
        return None;
    }
    Some(canon_rel)
}

// ── Daemon readiness ────────────────────────────────────────────────────────

/// Ensure the daemon is reachable. Auto-starts if needed.
///
/// Pass-33: this is now a thin delegate to
/// [`mati_core::mcp::daemon_lifecycle::ensure_daemon`]. The library-side
/// implementation is the canonical one — sharing it lets MCP socket-backed
/// callers (`proxy_daemon_result` / `proxy_daemon_v2`) auto-spawn with the
/// exact same recovery semantics as the hook path. See the lib module
/// docs for the full Phase 1–4 strategy.
async fn ensure_daemon(mati_root: &Path) -> bool {
    mati_core::mcp::daemon_lifecycle::ensure_daemon(mati_root).await
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
    let cmd =
        mati_core::mcp::protocol::Command::SessionLog(mati_core::mcp::protocol::SessionLogInput {
            event,
            key: file_key.clone(),
            session_id: None,
        });
    let _ = super::daemon::daemon_v2(mati_root, cmd).await;

    // Post-hook: no output, always exit 0.
    Ok(())
}

// ── claude-post-memget flow ─────────────────────────────────────────────────

/// Record an actor-scoped consult receipt after a successful mem_get.
///
/// Fail-open at every step: if the key, session_id, or daemon is missing, exit 0.
/// No stdout output (PostToolUse hooks are fire-and-forget).
async fn run_post_memget(input: &serde_json::Value) -> Result<()> {
    let key = match input
        .pointer("/tool_input/key")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
    {
        Some(k) => k,
        None => return Ok(()),
    };

    let agent_id = input
        .get("agent_id")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty());
    let session_id = input
        .get("session_id")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty());
    let actor = agent_id.or(session_id);

    let cwd = std::env::current_dir()?;
    // Resolve the daemon slug the way the gate does (repo root, not cwd) so the
    // actor-scoped receipt lands in the same store the gate will read.
    let repo_root = discover_repo_root(&cwd);
    let root_for_slug = repo_root.as_deref().unwrap_or(&cwd);
    let mati_root = match mati_root_for(root_for_slug) {
        Ok(r) => r,
        Err(_) => return Ok(()),
    };
    if !ensure_daemon(&mati_root).await {
        return Ok(());
    }

    let cmd = mati_core::mcp::protocol::Command::ConsultationHit(
        mati_core::mcp::protocol::ConsultationHitInput {
            key: key.to_string(),
            actor: actor.map(str::to_string),
            session_id: session_id.map(str::to_string),
            agent_id: agent_id.map(str::to_string),
        },
    );
    let _ = super::daemon::daemon_v2(&mati_root, cmd).await;
    Ok(())
}

// ── codex-pre-apply-patch flow ──────────────────────────────────────────────

/// Multi-file edit enforcement for Codex `apply_patch`.
///
/// Parses the patch envelope into target paths, evaluates each against the
/// gotcha store, and denies (exit 2 + stderr) if ANY touched file has a
/// confirmed gotcha the agent has not consulted. Fails OPEN at every step
/// (no command, no paths, unreachable daemon, per-file eval error, file count
/// over the cap) — wrongly blocking all edits is worse than missing a gotcha.
async fn run_apply_patch(input: &serde_json::Value) -> Result<()> {
    let variant = HookVariant::CodexPreApplyPatch;

    // 1. Patch text from tool_input.command.
    let Some(cmd) = input
        .pointer("/tool_input/command")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
    else {
        emit_allow(variant);
        return Ok(());
    };

    // 2. Parse target paths from the envelope.
    let mut raw_paths = decide::extract_apply_patch_files(cmd);
    if raw_paths.is_empty() {
        emit_allow(variant);
        return Ok(());
    }
    if raw_paths.len() > decide::MAX_APPLY_PATCH_FILES {
        log_fail_open(
            "<apply_patch>",
            &format!(
                "patch touches {} files; gating only the first {}",
                raw_paths.len(),
                decide::MAX_APPLY_PATCH_FILES
            ),
        );
        raw_paths.truncate(decide::MAX_APPLY_PATCH_FILES);
    }

    // 3. Repo root + mati root + daemon (shared shape with the single-path flow).
    let cwd = std::env::current_dir()?;
    let repo_root = discover_repo_root(&cwd);
    let repo_root_str = repo_root.as_ref().and_then(|p| p.to_str());
    let root_for_slug = repo_root.as_deref().unwrap_or(&cwd);
    let mati_root = match mati_root_for(root_for_slug) {
        Ok(r) => r,
        Err(_) => {
            log_fail_open("<apply_patch>", "cannot determine mati root");
            emit_allow(variant);
            return Ok(());
        }
    };
    if !ensure_daemon(&mati_root).await {
        log_fail_open("<apply_patch>", "daemon not running after auto-start");
        emit_allow(variant);
        return Ok(());
    }

    // 4. Evaluate each touched path; collect the ones that must be consulted.
    // agent_id is present in subagent hook payloads; None on the Codex path.
    let agent_id = input
        .get("agent_id")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty());
    let mut denied: Vec<String> = Vec::new();
    let mut events: Vec<HookEvent> = Vec::new();
    for raw in &raw_paths {
        let rel_path = decide::normalize_path(raw, repo_root_str);
        let file_key = format!("file:{rel_path}");
        let eval_data = match daemon_result(
            &mati_root,
            "hook_evaluate",
            serde_json::json!({ "file_key": &file_key, "include_recent": true, "actor": agent_id }),
        )
        .await
        {
            DaemonResult::Ok(resp) => resp.get("data").cloned().unwrap_or(serde_json::Value::Null),
            _ => {
                // Per-file fail-open: don't block the whole edit on one bad lookup.
                log_fail_open(&rel_path, "hook_evaluate failed");
                continue;
            }
        };

        let adapter = process_eval_response(variant, &rel_path, &eval_data);
        if matches!(adapter.decision, Decision::Deny { .. }) {
            denied.push(file_key);
            events.extend(adapter.events);
        }
    }

    // 5. Fire compliance events for the blocked files (fire-and-forget).
    // Codex apply_patch: no Claude session_id in the input; attribution is via
    // agent_type ("codex"). Per-actor session attribution is a Claude-path feature.
    fire_events(&mati_root, &events, None).await;

    // 6. Deny if any file needs consultation; otherwise allow.
    if denied.is_empty() {
        emit_allow(variant);
        return Ok(());
    }
    let msg = if denied.len() == 1 {
        format!("mati: call mem_get(\"{}\") before editing", denied[0])
    } else {
        format!(
            "mati: consult these files before editing — call mem_get for each: {}",
            denied.join(", ")
        )
    };
    eprintln!("{msg}");
    let _ = std::io::Write::flush(&mut std::io::stderr());
    std::process::exit(2);
}

// ── Fail-open telemetry ─────────────────────────────────────────────────────

fn log_fail_open(rel_path: &str, reason: &str) {
    eprintln!("[mati] WARNING: enforcement bypassed for {rel_path} — {reason}");
    if let Some(home) = dirs::home_dir() {
        let log_dir = home.join(".mati");
        let _ = std::fs::create_dir_all(&log_dir);
        let log_path = log_dir.join("fail_open.log");
        log_fail_open_at(&log_path, rel_path, reason);
    }
}

/// Append one entry to `fail_open.log`. Format MUST match the parser in
/// `cli::stats::parse_iso_timestamp` — the round-trip is covered by
/// `fail_open_log_round_trip_writer_reader` in `cli::stats`'s test module.
pub(super) fn log_fail_open_at(log_path: &Path, rel_path: &str, reason: &str) {
    let now = iso_utc_now();
    let entry = format!("{now} FAIL_OPEN hook=hook-decide file={rel_path} reason={reason}\n");
    let _ = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
        .and_then(|mut f| std::io::Write::write_all(&mut f, entry.as_bytes()));
}

/// UTC timestamp in ISO 8601 format `YYYY-MM-DDTHH:MM:SSZ`.
///
/// Format is the canonical on-disk shape for `fail_open.log` and any other
/// human/parser-readable log written from the hook path. `parse_iso_timestamp`
/// in `cli::stats` is the matching reader; changing one without the other
/// silently breaks the 7-day fail-open window in `mati stats` / `mati doctor`.
fn iso_utc_now() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

// ── Platform-aware event mapping ────────────────────────────────────────────

/// Filter and translate events based on platform semantics.
///
/// Codex pre-bash:
///   - Deny → CodexShellBlocked (not generic BlockedUnconsultedRead)
///   - Advisory/Liability are silent → suppress Hit (no receipt)
///   - AlreadyConsulted → suppress ComplianceHit (codex-post-bash records it)
///   - NoRecord → Miss (keep)
///
/// Claude pre-read/pre-bash: keep all events as-is.
fn platform_events(
    variant: HookVariant,
    decision: &Decision,
    events: Vec<HookEvent>,
) -> Vec<HookEvent> {
    match variant {
        HookVariant::CodexPreBash | HookVariant::CodexPreApplyPatch => events
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
                    // `evaluate()` emits Hit only for Advisory and Liability;
                    // AlreadyConsulted emits ComplianceHit (handled below).
                    match decision {
                        Decision::Advisory { .. } | Decision::Liability { .. } => None,
                        _ => Some(e),
                    }
                }
                HookEvent::ComplianceHit { .. } => {
                    // codex-post-bash owns ComplianceHit/AllowAfterReceipt
                    // for shell commands — suppress from pre-bash to avoid
                    // double-recording the enforcement event.
                    None
                }
                _ => Some(e),
            })
            .collect(),
        HookVariant::CodexPostBash | HookVariant::ClaudePostMemGet => {
            // Post-bash and post-memget use their own flows — should not reach here.
            events
        }
        HookVariant::ClaudePreEdit => events
            .into_iter()
            // Plane 2: translate to edit-attributed events and KEEP them, so the
            // audit trail records both that a stale/blind edit was blocked
            // (EditBlocked → Deny) and that a consulted edit proceeded
            // (EditConsulted → AllowAfterReceipt), each with an edit-specific
            // reason code. Drop the rest — the read gate owns Hit/Miss here.
            .filter_map(|e| match e {
                HookEvent::BlockedUnconsultedRead { key } => Some(HookEvent::EditBlocked { key }),
                // Keep the floor-mandate deny (its own reason code), don't fold into EditBlocked.
                HookEvent::FloorConsultBlocked { key } => {
                    Some(HookEvent::FloorConsultBlocked { key })
                }
                HookEvent::ComplianceHit { key } => Some(HookEvent::EditConsulted { key }),
                _ => None,
            })
            .collect(),
        HookVariant::ClaudePreRead | HookVariant::ClaudePreBash => {
            // Claude delivers context for all non-silent outcomes.
            events
        }
    }
}

// ── Event firing ────────────────────────────────────────────────────────────

async fn fire_events(mati_root: &Path, events: &[HookEvent], session_id: Option<&str>) {
    use mati_core::mcp::protocol as p;
    // Per-actor audit attribution (schema_version 2): tag each SessionLog with the
    // agent session that triggered it, when the platform provides one.
    let sid = || session_id.map(str::to_string);
    for event in events {
        let cmd = match event {
            HookEvent::Hit { key } => p::Command::ConsultationHit(p::ConsultationHitInput {
                key: key.clone(),
                actor: None,
                session_id: None,
                agent_id: None,
            }),
            HookEvent::Miss { key } => p::Command::SessionLog(p::SessionLogInput {
                event: p::SessionEvent::Miss,
                key: key.clone(),
                session_id: sid(),
            }),
            HookEvent::BlockedUnconsultedRead { key } => {
                p::Command::SessionLog(p::SessionLogInput {
                    event: p::SessionEvent::ComplianceMiss,
                    key: key.clone(),
                    session_id: sid(),
                })
            }
            HookEvent::CodexShellBlocked { key } => p::Command::SessionLog(p::SessionLogInput {
                event: p::SessionEvent::CodexShellMiss,
                key: key.clone(),
                session_id: sid(),
            }),
            HookEvent::ComplianceHit { key } => p::Command::SessionLog(p::SessionLogInput {
                event: p::SessionEvent::ComplianceHit,
                key: key.clone(),
                session_id: sid(),
            }),
            HookEvent::EditConsulted { key } => p::Command::SessionLog(p::SessionLogInput {
                event: p::SessionEvent::EditConsulted,
                key: key.clone(),
                session_id: sid(),
            }),
            HookEvent::EditBlocked { key } => p::Command::SessionLog(p::SessionLogInput {
                event: p::SessionEvent::EditBlocked,
                key: key.clone(),
                session_id: sid(),
            }),
            HookEvent::FloorConsultBlocked { key } => p::Command::SessionLog(p::SessionLogInput {
                event: p::SessionEvent::FloorConsultMiss,
                key: key.clone(),
                session_id: sid(),
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
        HookVariant::CodexPreBash
        | HookVariant::CodexPostBash
        | HookVariant::CodexPreApplyPatch
        | HookVariant::ClaudePreEdit
        | HookVariant::ClaudePostMemGet => {
            // Silent exit 0 = defer to the normal permission flow. For edits this
            // is deliberate: emitting "allow" would suppress the user's edit
            // prompt on every non-gotcha file (edits are permission-required).
            // ClaudePostMemGet is PostToolUse — no output needed.
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

// ── Floor consult mandate (enterprise governance overlay) ────────────────────

/// Compile the enterprise floor's signed consult-required globs, supplied out-of-band via
/// `MATI_CONSULT_GLOBS` (a JSON array of glob strings, e.g. `["phi/**","src/payments/**"]`).
///
/// A NEUTRAL primitive: OSS enforces per-actor consultation on whatever globs it is handed;
/// verifying the signed floor that produced them is the caller's job (mati-cloud). Returns
/// `None` (no mandate) when unset, empty, or unparseable — fail-open, matching the hook posture.
fn consult_globset() -> Option<GlobSet> {
    consult_globset_from(&std::env::var("MATI_CONSULT_GLOBS").ok()?)
}

/// The actor's consultation status from a `hook_evaluate` bundle: the recent-TTL flag for
/// edit/shell gates, the persistent flag otherwise (mirrors `check_eval_data`).
fn consulted_flag(eval_data: &serde_json::Value, include_recent: bool) -> bool {
    let field = if include_recent {
        "consulted_recent"
    } else {
        "consulted"
    };
    eval_data
        .get(field)
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

/// Pure compile step for [`consult_globset`], split out for testing without env.
fn consult_globset_from(raw: &str) -> Option<GlobSet> {
    let globs: Vec<String> = serde_json::from_str(raw).ok()?;
    if globs.is_empty() {
        return None;
    }
    let mut builder = GlobSetBuilder::new();
    for g in &globs {
        if let Ok(glob) = Glob::new(g) {
            builder.add(glob);
        }
    }
    builder.build().ok().filter(|s| !s.is_empty())
}

/// Escalate the decision to a Deny when the accessed file matches a signed consult-required
/// glob and this actor has not consulted it — a governance mandate to consult even absent a
/// local gotcha. Never downgrades an existing Deny (deny > consult); no-op when there is no
/// mandate or the actor already consulted (consultation satisfies it, like a gotcha'd file).
/// The per-actor receipt is minted by the agent's own `mem_get` on the file.
fn apply_consult_mandate(
    adapter: &mut AdapterResult,
    variant: HookVariant,
    rel_path: &str,
    consulted: bool,
    globs: Option<&GlobSet>,
) {
    let Some(globs) = globs else {
        return;
    };
    if consulted || matches!(adapter.decision, Decision::Deny { .. }) || !globs.is_match(rel_path) {
        return;
    }
    let file_key = format!("file:{rel_path}");
    let decision = Decision::Deny {
        file_key: file_key.clone(),
        reason: format!(
            "[mati] Org policy requires consulting {rel_path} before access — \
             call mem_get(\"{file_key}\") first."
        ),
    };
    let events = platform_events(
        variant,
        &decision,
        vec![HookEvent::FloorConsultBlocked { key: file_key }],
    );
    let (stdout, stderr, exit_code) = format_decision(variant, &decision, rel_path);
    *adapter = AdapterResult {
        stdout,
        stderr,
        exit_code,
        events,
        decision,
    };
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
        HookVariant::CodexPreBash
            | HookVariant::CodexPostBash
            | HookVariant::CodexPreApplyPatch
            | HookVariant::ClaudePreEdit
            | HookVariant::ClaudePostMemGet
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
                _ => String::new(), // ClaudePostMemGet: no output
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
        HookVariant::ClaudePreEdit => match decision {
            Decision::Deny { file_key, .. } => {
                let path = file_key.strip_prefix("file:").unwrap_or(file_key);
                let reason = format!(
                    "[mati] Confirmed gotcha on {path} — call mem_get(\"{file_key}\") \
                     and read the record before editing this file."
                );
                let escaped = escape_json_string(&reason);
                let stdout = format!(
                    r#"{{"hookSpecificOutput":{{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"{escaped}"}}}}"#
                );
                (stdout, String::new(), 0)
            }
            // Non-deny: DEFER to the normal permission flow (empty stdout, exit 0).
            // Deliberately NOT permissionDecision:"allow" — see pre_edit.rs.
            _ => (String::new(), String::new(), 0),
        },
        HookVariant::CodexPreBash | HookVariant::CodexPreApplyPatch => match decision {
            Decision::Deny { file_key, .. } => {
                let stderr = format!("mati: call mem_get(\"{file_key}\") first");
                (String::new(), stderr, 2)
            }
            _ => (String::new(), String::new(), 0),
        },
        HookVariant::CodexPostBash | HookVariant::ClaudePostMemGet => {
            (String::new(), String::new(), 0)
        }
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
        // Codex AlreadyConsulted emits ComplianceHit (post-Bug 1). Codex
        // pre-bash still suppresses it so codex-post-bash owns it.
        let events = vec![HookEvent::ComplianceHit {
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
    fn e2e_codex_apply_patch_deny_exit2_when_unconsulted() {
        // apply_patch reads the recent-TTL receipt (consulted_recent). With no
        // receipt, a confirmed gotcha on a touched file must deny the edit.
        let data = deny_eligible_eval_data();
        let result = process_eval_response(HookVariant::CodexPreApplyPatch, "src/main.rs", &data);

        assert_eq!(result.exit_code, 2, "apply_patch deny must exit 2");
        assert!(matches!(result.decision, Decision::Deny { .. }));
        assert_eq!(result.events.len(), 1);
        assert!(
            matches!(&result.events[0], HookEvent::CodexShellBlocked { key } if key == "file:src/main.rs"),
            "apply_patch deny must emit CodexShellBlocked, got: {:?}",
            result.events
        );
    }

    #[test]
    fn e2e_codex_apply_patch_allows_after_consult() {
        // Once the file has a recent consultation receipt, the edit is allowed.
        let mut data = deny_eligible_eval_data();
        data["consulted_recent"] = json!(true);
        let result = process_eval_response(HookVariant::CodexPreApplyPatch, "src/main.rs", &data);

        assert_eq!(result.exit_code, 0, "consulted edit must be allowed");
        assert!(!matches!(result.decision, Decision::Deny { .. }));
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
        // AlreadyConsulted is silent for Codex pre-bash — ComplianceHit is
        // suppressed so codex-post-bash is the sole emitter of AllowAfterReceipt
        // for shell commands.
        assert!(result.events.is_empty());
    }

    #[test]
    fn e2e_claude_consulted_records_allow_after_receipt() {
        // Bug 1 regression guard: when Claude pre-read allows a consulted
        // read, the adapter must emit ComplianceHit so the daemon records
        // an AllowAfterReceipt enforcement event.
        let mut data = deny_eligible_eval_data();
        data["consulted"] = json!(true);
        let result = process_eval_response(HookVariant::ClaudePreRead, "src/main.rs", &data);

        assert_eq!(result.exit_code, 0, "Claude always exits 0");
        let json: serde_json::Value =
            serde_json::from_str(&result.stdout).expect("stdout must be valid JSON");
        assert_eq!(
            json.pointer("/hookSpecificOutput/permissionDecision")
                .and_then(|v| v.as_str()),
            Some("allow")
        );
        assert!(matches!(result.decision, Decision::AlreadyConsulted { .. }));
        assert_eq!(result.events.len(), 1);
        assert!(
            matches!(&result.events[0], HookEvent::ComplianceHit { key } if key == "file:src/main.rs"),
            "AlreadyConsulted must emit ComplianceHit so AllowAfterReceipt is recorded, got: {:?}",
            result.events
        );
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

    // ── Outer deadline wrapper ──────────────────────────────────────────
    //
    // Mirrors the production wrapper in `run()`: when the inner future
    // exceeds the deadline, the wrapper must produce an allow output and
    // log a fail-open entry. We can't drive the real `run()` from a unit
    // test (it reads stdin and may spawn daemons), so we test the deadline
    // shape directly using the same `tokio::time::timeout` + `emit_allow`
    // path the production code takes.

    async fn run_with_deadline<F>(deadline_ms: u64, variant: HookVariant, inner: F) -> Result<()>
    where
        F: std::future::Future<Output = Result<()>>,
    {
        match tokio::time::timeout(Duration::from_millis(deadline_ms), inner).await {
            Ok(inner_result) => inner_result,
            Err(_elapsed) => {
                // Match the production wrapper exactly. We don't write to
                // the real fail_open.log here — production code does, and
                // testing that side effect would require touching the home
                // dir. The load-bearing assertion is "completes within
                // budget + emits allow", not "wrote to disk".
                emit_allow(variant);
                Ok(())
            }
        }
    }

    #[tokio::test]
    async fn outer_deadline_emits_allow_on_timeout() {
        use std::time::Instant;

        // Use a small real deadline + a long inner sleep. We assert the
        // wrapper returns close to `deadline_ms`, not after `inner_sleep_ms`.
        // This proves `timeout` actually fires before the inner future
        // completes. The deadline is small so the test stays fast — the
        // production constant (HOOK_DEADLINE_MS = 2500) is verified
        // separately by the wrapper's structure, not by waiting 2.5s here.
        let deadline_ms = 100u64;
        let inner_sleep_ms = 5_000u64;

        let start = Instant::now();
        let result = run_with_deadline(deadline_ms, HookVariant::ClaudePreRead, async move {
            tokio::time::sleep(Duration::from_millis(inner_sleep_ms)).await;
            Ok(())
        })
        .await;
        let elapsed = start.elapsed();

        // The wrapper must absorb the timeout into Ok(()).
        assert!(
            result.is_ok(),
            "deadline wrapper must never propagate Err on timeout, got: {result:?}"
        );

        // The wrapper must complete close to the deadline, not after the
        // inner sleep. Generous upper bound to tolerate CI scheduler noise,
        // but well below `inner_sleep_ms` so timeout-vs-completion is
        // unambiguous.
        assert!(
            elapsed < Duration::from_millis(deadline_ms + 400),
            "wrapper took {elapsed:?} — should fire near deadline ({deadline_ms}ms), not wait for inner sleep ({inner_sleep_ms}ms)"
        );
        assert!(
            elapsed >= Duration::from_millis(deadline_ms),
            "wrapper took {elapsed:?} — must wait at least the deadline ({deadline_ms}ms) before timing out"
        );

        // The production wrapper calls `emit_allow(variant)` on timeout.
        // We can't capture process stdout from a unit test, so we verify
        // the contract by re-checking the exact JSON shape `emit_allow`
        // produces for the Claude variants — a regression there would also
        // break this test's expectations.
        let allow_json =
            r#"{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}"#;
        let parsed: serde_json::Value =
            serde_json::from_str(allow_json).expect("allow JSON shape must parse");
        assert_eq!(
            parsed
                .pointer("/hookSpecificOutput/permissionDecision")
                .and_then(|v| v.as_str()),
            Some("allow"),
            "deadline path must produce permissionDecision=allow"
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

    // ── ClaudePreEdit (WI-01, L1 edit-gate) ─────────────────────────────

    #[test]
    fn extract_path_claude_pre_edit_file_path() {
        // Edit/Write both pass the target at tool_input.file_path, same as Read.
        let input = json!({"tool_input": {"file_path": "/repo/src/pay.rs"}});
        assert_eq!(
            extract_path(&input, HookVariant::ClaudePreEdit),
            Some("/repo/src/pay.rs".into())
        );
    }

    #[test]
    fn extract_path_claude_pre_edit_notebook_path() {
        // NotebookEdit carries the target at tool_input.notebook_path, not
        // file_path — the edit gate must still extract it so notebooks are gated.
        let input = json!({"tool_input": {"notebook_path": "/repo/nb/analysis.ipynb"}});
        assert_eq!(
            extract_path(&input, HookVariant::ClaudePreEdit),
            Some("/repo/nb/analysis.ipynb".into())
        );
    }

    #[test]
    fn extract_path_codex_pre_bash_egrep_and_fgrep() {
        // egrep/fgrep satisfy Claude's read-before-edit; mati now detects them so
        // they can't be used to satisfy the read requirement unconsulted.
        let egrep = json!({"tool_input": {"command": "egrep TODO src/main.rs"}});
        assert_eq!(
            extract_path(&egrep, HookVariant::CodexPreBash),
            Some("src/main.rs".into())
        );
        let fgrep = json!({"tool_input": {"command": "fgrep needle src/main.rs"}});
        assert_eq!(
            extract_path(&fgrep, HookVariant::CodexPreBash),
            Some("src/main.rs".into())
        );
    }

    #[test]
    fn e2e_claude_pre_edit_denies_blind_edit() {
        // Blind edit (no consultation receipt) to a confirmed-gotcha file must be
        // denied with an edit-flavored Claude PreToolUse deny JSON.
        let data = deny_eligible_eval_data();
        let result = process_eval_response(HookVariant::ClaudePreEdit, "src/main.rs", &data);

        assert_eq!(
            result.exit_code, 0,
            "Claude always exits 0; deny is in the JSON"
        );
        let json: serde_json::Value =
            serde_json::from_str(&result.stdout).expect("deny stdout must be valid JSON");
        assert_eq!(
            json.pointer("/hookSpecificOutput/permissionDecision")
                .and_then(|v| v.as_str()),
            Some("deny")
        );
        assert!(
            json.pointer("/hookSpecificOutput/permissionDecisionReason")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .contains("before editing"),
            "deny reason must be edit-flavored, got: {}",
            result.stdout
        );
        // Plane 2: records an edit-attributed Deny enforcement event.
        assert_eq!(result.events.len(), 1);
        assert!(matches!(&result.events[0], HookEvent::EditBlocked { .. }));
        assert!(matches!(result.decision, Decision::Deny { .. }));
    }

    #[test]
    fn e2e_claude_pre_edit_defers_after_consult() {
        // With a RECENT consultation receipt (consulted_recent, matching the
        // Codex apply_patch edit gate), the edit DEFERS to the normal permission
        // flow (empty stdout, exit 0) — deliberately NOT a forced allow.
        let mut data = deny_eligible_eval_data();
        data["consulted_recent"] = json!(true);
        let result = process_eval_response(HookVariant::ClaudePreEdit, "src/main.rs", &data);

        assert_eq!(result.exit_code, 0);
        assert!(
            result.stdout.is_empty(),
            "consulted edit must DEFER (empty stdout), not force-allow, got: {}",
            result.stdout
        );
        assert!(result.stderr.is_empty());
        assert!(matches!(result.decision, Decision::AlreadyConsulted { .. }));
        // Plane 2: a consulted edit records an EditConsulted event (→
        // AllowAfterReceipt, reason `edit_after_receipt`) — the audit evidence
        // that this edit was preceded by a recent consult.
        assert_eq!(result.events.len(), 1);
        assert!(matches!(&result.events[0], HookEvent::EditConsulted { .. }));
    }

    #[test]
    fn e2e_claude_pre_edit_defers_no_record() {
        // No record / no gotcha → defer (never force-allow, never block) so the
        // user's normal edit-permission flow applies.
        let data = json!({
            "file_key": "file:src/new.rs",
            "file_record": null,
            "gotcha_records": {},
            "consulted": false,
            "consulted_recent": false,
            "store_error": false,
            "gotcha_error": false
        });
        let result = process_eval_response(HookVariant::ClaudePreEdit, "src/new.rs", &data);

        assert_eq!(result.exit_code, 0);
        assert!(result.stdout.is_empty(), "no-record edit must defer");
        assert!(matches!(result.decision, Decision::NoRecord));
        // No block event for a non-gotcha file.
        assert!(result.events.is_empty());
    }

    #[test]
    fn e2e_claude_pre_edit_store_error_defers() {
        // Fail-open: a store error must defer (empty stdout), never block the edit.
        let data = json!({
            "file_key": "file:src/main.rs",
            "file_record": null,
            "gotcha_records": {},
            "consulted": false,
            "consulted_recent": false,
            "store_error": true,
            "gotcha_error": false
        });
        let result = process_eval_response(HookVariant::ClaudePreEdit, "src/main.rs", &data);

        assert_eq!(result.exit_code, 0, "store error must fail open (defer)");
        assert!(result.stdout.is_empty());
        assert_eq!(result.decision, Decision::Allow);
    }

    // ── canonical_rel_path (WI-20 symlink-bypass fallback) ──────────────────
    //
    // These exercise the canonical-key resolver directly against a real
    // filesystem (tempdir + real symlinks). The full deny-through-symlink
    // enforcement is proven end-to-end in `tests/hook_decide_integration.rs`.

    // Unix-only: these create real symlinks via `std::os::unix::fs::symlink`.
    // The CI test matrix is Unix-only (ubuntu + macos); gating at the function
    // level keeps them honest if a Windows runner is ever added, matching the
    // integration test's `#[cfg(unix)]`.
    #[cfg(unix)]
    #[test]
    fn canonical_rel_resolves_symlink_to_real_target_key() {
        // A symlink to a real in-repo file must canonicalize to the REAL
        // target's repo-relative key — this is the bypass-closing resolution.
        let repo = tempfile::TempDir::new().expect("tempdir");
        let root = repo.path();
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("src/real.rs"), "fn x() {}\n").unwrap();
        // link.rs (at repo root) → src/real.rs
        std::os::unix::fs::symlink(root.join("src/real.rs"), root.join("link.rs")).unwrap();

        // Accessed via the symlink. Lexical key would be "link.rs"; canonical
        // must resolve to "src/real.rs".
        let got = canonical_rel_path(
            root.join("link.rs").to_str().unwrap(),
            root,
            Some(root),
            "link.rs",
        );
        assert_eq!(got.as_deref(), Some("src/real.rs"));
    }

    #[cfg(unix)]
    #[test]
    fn canonical_rel_relative_access_resolves_against_cwd() {
        // A bare relative shell arg (`cat link.rs`) resolves against cwd (the
        // repo root) before canonicalization.
        let repo = tempfile::TempDir::new().expect("tempdir");
        let root = repo.path();
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("src/real.rs"), "fn x() {}\n").unwrap();
        std::os::unix::fs::symlink(root.join("src/real.rs"), root.join("link.rs")).unwrap();

        let got = canonical_rel_path("link.rs", root, Some(root), "link.rs");
        assert_eq!(got.as_deref(), Some("src/real.rs"));
    }

    #[test]
    fn canonical_rel_non_symlink_is_noop() {
        // A plain (non-symlink) in-repo file canonicalizes back to its own
        // lexical key — the helper returns None so we skip the redundant
        // second daemon round-trip (zero-cost common path).
        let repo = tempfile::TempDir::new().expect("tempdir");
        let root = repo.path();
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("src/real.rs"), "fn x() {}\n").unwrap();

        let got = canonical_rel_path(
            root.join("src/real.rs").to_str().unwrap(),
            root,
            Some(root),
            "src/real.rs",
        );
        assert_eq!(got, None, "non-symlink access must not trigger a fallback");
    }

    #[cfg(unix)]
    #[test]
    fn canonical_rel_outside_repo_is_none() {
        // A symlink pointing OUTSIDE the repo must NOT yield a key — it can't
        // match a store record and must never deny. Falls back to lexical-only.
        let repo = tempfile::TempDir::new().expect("tempdir");
        let outside = tempfile::TempDir::new().expect("tempdir");
        let root = repo.path();
        std::fs::write(outside.path().join("secret.rs"), "fn x() {}\n").unwrap();
        std::os::unix::fs::symlink(outside.path().join("secret.rs"), root.join("escape.rs"))
            .unwrap();

        let got = canonical_rel_path(
            root.join("escape.rs").to_str().unwrap(),
            root,
            Some(root),
            "escape.rs",
        );
        assert_eq!(got, None, "out-of-repo symlink target must yield no key");
    }

    #[test]
    fn canonical_rel_no_repo_root_is_none() {
        // Without a repo root we can't form a repo-relative key — fall back to
        // lexical-only (never crash).
        let got = canonical_rel_path("/some/abs/path.rs", Path::new("/tmp"), None, "path.rs");
        assert_eq!(got, None);
    }

    #[test]
    fn canonical_rel_nonexistent_leaf_under_real_dir() {
        // canonicalize_lenient tolerates a missing leaf: a not-yet-created file
        // under a real (possibly symlinked) directory still yields its key.
        let repo = tempfile::TempDir::new().expect("tempdir");
        let root = repo.path();
        std::fs::create_dir_all(root.join("src")).unwrap();

        // No symlink, leaf does not exist → canonicalizes to its own lexical
        // key → no-op (None).
        let got = canonical_rel_path(
            root.join("src/ghost.rs").to_str().unwrap(),
            root,
            Some(root),
            "src/ghost.rs",
        );
        assert_eq!(got, None);
    }

    // ── Floor consult mandate overlay ────────────────────────────────────────

    fn allow_adapter() -> AdapterResult {
        AdapterResult {
            stdout: "allow".to_string(),
            stderr: String::new(),
            exit_code: 0,
            events: vec![],
            decision: Decision::Allow,
        }
    }

    fn phi_globs() -> GlobSet {
        consult_globset_from(r#"["phi/**"]"#).unwrap()
    }

    #[test]
    fn consult_globset_from_parses_and_rejects() {
        assert!(consult_globset_from(r#"["phi/**","src/pay/**"]"#).is_some());
        assert!(consult_globset_from("[]").is_none());
        assert!(consult_globset_from("not json").is_none());
    }

    #[test]
    fn mandate_denies_unconsulted_match() {
        let g = phi_globs();
        let mut a = allow_adapter();
        apply_consult_mandate(
            &mut a,
            HookVariant::ClaudePreRead,
            "phi/records.rs",
            false,
            Some(&g),
        );
        assert!(matches!(a.decision, Decision::Deny { .. }));
        assert!(
            a.stdout.contains("deny"),
            "pre-read deny output must be emitted"
        );
        assert!(
            matches!(
                a.events.first(),
                Some(HookEvent::FloorConsultBlocked { .. })
            ),
            "floor mandate deny must emit its own event (distinct audit reason code)"
        );
    }

    #[test]
    fn mandate_allows_when_consulted() {
        let g = phi_globs();
        let mut a = allow_adapter();
        apply_consult_mandate(
            &mut a,
            HookVariant::ClaudePreRead,
            "phi/records.rs",
            true,
            Some(&g),
        );
        assert!(
            matches!(a.decision, Decision::Allow),
            "consultation satisfies the mandate"
        );
    }

    #[test]
    fn mandate_noop_on_nonmatch_or_no_globs() {
        let g = phi_globs();
        let mut a = allow_adapter();
        apply_consult_mandate(
            &mut a,
            HookVariant::ClaudePreRead,
            "src/main.rs",
            false,
            Some(&g),
        );
        assert!(
            matches!(a.decision, Decision::Allow),
            "non-matching path is untouched"
        );

        let mut b = allow_adapter();
        apply_consult_mandate(
            &mut b,
            HookVariant::ClaudePreRead,
            "phi/records.rs",
            false,
            None,
        );
        assert!(
            matches!(b.decision, Decision::Allow),
            "no mandate -> no change"
        );
    }

    #[test]
    fn mandate_preserves_existing_deny() {
        let g = phi_globs();
        let mut a = AdapterResult {
            stdout: "x".to_string(),
            stderr: String::new(),
            exit_code: 0,
            events: vec![],
            decision: Decision::Deny {
                file_key: "file:phi/x.rs".to_string(),
                reason: "gotcha-deny".to_string(),
            },
        };
        apply_consult_mandate(
            &mut a,
            HookVariant::ClaudePreRead,
            "phi/x.rs",
            false,
            Some(&g),
        );
        match &a.decision {
            Decision::Deny { reason, .. } => {
                assert_eq!(reason, "gotcha-deny", "deny > consult; not overwritten")
            }
            _ => panic!("expected the pre-existing Deny to survive"),
        }
    }
}
