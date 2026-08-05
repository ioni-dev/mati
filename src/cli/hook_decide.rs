//! CLI adapter for `mati hook-decide <variant>`.
//!
//! Owns daemon readiness, stdin parsing, and platform-specific output.
//! Delegates the pure enforcement decision to `hooks::decide::evaluate()`.

use anyhow::Result;
use clap::{Args, ValueEnum};
use globset::{Glob, GlobSet, GlobSetBuilder};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::cli::daemon::{daemon_result, daemon_v2, mati_root_for, DaemonResult};
use mati_core::hooks::decide::{self, Decision, EnforcementInput, HookEvent};

// ── Public types ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum HookVariant {
    ClaudePreRead,
    /// Claude PreToolUse(Edit|Write|NotebookEdit): gate file *edits*. Uses
    /// `consulted_recent` (a recent-consultation TTL, matching the Codex
    /// `apply_patch` edit gate) — NOT the read gate's persistent `consulted` — so
    /// an edit must be preceded by a *recent* mem_get: read-then-edit flows within
    /// the TTL, and blind or stale-consult edits deny. Context-bearing non-deny
    /// outcomes inject context into the normal permission flow; edits never
    /// emit `allow` because they are permission-required.
    ClaudePreEdit,
    ClaudePreBash,
    CodexPreBash,
    CodexPostBash,
    /// Codex PreToolUse(apply_patch): gate file *edits*. Multi-file flow
    /// (`run_apply_patch`) — parses the patch envelope and denies if any
    /// touched file has an unconsulted confirmed gotcha.
    CodexPreApplyPatch,
    /// Claude PostToolUse(mcp__mati__mem_get): record a consult receipt.
    /// Payload carries session_id, agent_id (subagent), and tool_input.key.
    ///
    /// clap's default kebab derive would yield `claude-post-mem-get`; pin the CLI
    /// value to `claude-post-memget` so it matches the installed hook script
    /// (`post-memget.sh` → `mati hook-decide claude-post-memget`).
    #[value(name = "claude-post-memget")]
    ClaudePostMemGet,
    /// Claude PostToolUse(Bash): mint schema consultation receipts after a
    /// successful allowlisted database introspection.
    #[value(name = "claude-post-bash")]
    ClaudePostBash,
}

#[derive(Args, Debug)]
pub struct HookDecideArgs {
    /// Which hook variant to execute.
    #[arg(value_enum)]
    pub variant: HookVariant,
}

/// The result of running a hook inside the async runtime.
///
/// A timeout must terminate the process before Tokio waits for the blocking
/// stdin reader to finish, but returning this outcome keeps the decision path
/// testable. The binary entry point turns `Terminate` into the actual process
/// exit after this future has returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookRunOutcome {
    Continue,
    Terminate(i32),
}

// ── Entry point ─────────────────────────────────────────────────────────────

/// Outer end-to-end deadline for the hook process.
///
/// The scaffold registers these hooks with `"timeout": 4` (seconds — see
/// `scaffold::settings`), and the host kills the subprocess at that ceiling.
/// That kill bypasses every internal `log_fail_open` call, leaving operators
/// blind to wedged-daemon spikes — the exact failure mode `fail_open.log`
/// exists to surface. This deadline fires first so we get one clean fail-open
/// log entry + an allow stdout before the host reaps us.
///
/// It must clear the ceiling *including* startup, which happens before this
/// timer begins: ~115ms warm, ~1050ms on a cold binary. 2500 + 1050 = ~3.5s
/// against a 4s ceiling.
const HOOK_DEADLINE_MS: u64 = 2500;

pub async fn run(args: HookDecideArgs) -> Result<HookRunOutcome> {
    let variant = args.variant;
    match tokio::time::timeout(Duration::from_millis(HOOK_DEADLINE_MS), run_inner(args)).await {
        Ok(inner_result) => inner_result.map(|()| HookRunOutcome::Continue),
        Err(_elapsed) => {
            // Internal deadline exceeded. We don't know which path stalled
            // (path may not even have been extracted yet), so log with the
            // sentinel "<unknown>" — still better than no entry at all.
            log_fail_open("<unknown>", "hook process exceeded internal deadline");
            emit_allow(variant);
            Ok(HookRunOutcome::Terminate(0))
        }
    }
}

async fn run_inner(args: HookDecideArgs) -> Result<()> {
    // 1. Read stdin (tool input JSON from hook protocol) asynchronously so
    // the outer HOOK_DEADLINE_MS timeout can observe a still-open pipe. Tokio
    // may keep the underlying blocking reader alive after cancellation; the
    // timeout path therefore exits the process explicitly after flushing its
    // fail-open log and allow response.
    let mut input_str = String::new();
    tokio::io::AsyncReadExt::read_to_string(&mut tokio::io::stdin(), &mut input_str).await?;
    let input: serde_json::Value =
        serde_json::from_str(&input_str).unwrap_or(serde_json::Value::Null);

    // apply_patch is multi-file: it parses the patch envelope and evaluates
    // every touched path, so it has its own flow rather than the single-path
    // pipeline below.
    if args.variant == HookVariant::CodexPreApplyPatch {
        return run_apply_patch(&input).await;
    }

    // claude-post-memget: records a consult receipt using
    // tool_input.key directly — NOT a file path, so skip extract_path entirely.
    if args.variant == HookVariant::ClaudePostMemGet {
        return run_post_memget(&input).await;
    }

    if args.variant == HookVariant::ClaudePostBash {
        return run_post_bash_introspection(&input).await;
    }

    // 1b. Parse agent_id: present only in subagent hook payloads.
    // Gate actor = agent_id if present, else None (NO session_id fallback).
    // - Subagent: actor = Some(agent_id) → reads actor-scoped receipt.
    // - Main thread: actor = None → reads global receipt (unchanged path).
    let agent_id = input
        .get("agent_id")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty());

    // Normalize Bash once so the same governed action drives both the
    // fileless policy path and the file-gate composition path.
    let bash_action = if matches!(
        args.variant,
        HookVariant::ClaudePreBash | HookVariant::CodexPreBash
    ) {
        input
            .pointer("/tool_input/command")
            .and_then(|v| v.as_str())
            .map(|command| decide::normalize_action(Some(command), None))
    } else {
        None
    };
    let raw_command = input
        .pointer("/tool_input/command")
        .and_then(|value| value.as_str());

    // 2. Extract file path (variant-specific).
    let raw_path = match extract_path(&input, args.variant) {
        Some(p) => p,
        None => {
            if let Some(action) = bash_action
                .as_ref()
                .filter(|action| action.tool == "db_client" || action.tool == "unknown")
            {
                return run_fileless_policy(&input, args.variant, action, agent_id).await;
            }
            emit_allow(args.variant);
            return Ok(());
        }
    };

    // 3. Resolve repo root via git2 (no subprocess).
    let Ok(cwd) = std::env::current_dir() else {
        return Ok(());
    };
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
        // `daemon_data` rejects `{"ok": false}` envelopes — a daemon-side
        // error must take the fail-open-and-record path below, not evaluate
        // a Null bundle as "no record" (which would log a false Miss).
        DaemonResult::Ok(resp) => match daemon_data(&resp) {
            Some(d) => d,
            None => {
                log_fail_open(&rel_path, "hook_evaluate returned error");
                emit_allow(args.variant);
                return Ok(());
            }
        },
        _ => {
            log_fail_open(&rel_path, "hook_evaluate failed");
            emit_allow(args.variant);
            return Ok(());
        }
    };

    // 8–11. Process eval response through the adapter pipeline.
    let file_exists = file_exists_for_deleted_signal(&eval_data, &raw_path, &cwd);
    let mut adapter = process_eval_response(args.variant, &rel_path, &eval_data, file_exists);
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
    // `file_exists` is irrelevant here — this call only classifies
    // store/gotcha errors, and its `Ok` branch's EnforcementInput is
    // discarded (the real one, with `file_exists` populated, is built by
    // `process_eval_response` above).
    let lexical_fail_open = match check_eval_data(args.variant, &rel_path, &eval_data, None) {
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
    // Resolved once and shared by both gates below. A gate that knows about
    // symlinks alongside one that does not is the defect; which glob missed is
    // only the symptom. `canonical_rel_path` returns None for a non-symlink.
    let canon_rel = canonical_rel_path(&raw_path, &cwd, repo_root.as_deref(), &rel_path);
    if !matches!(adapter.decision, Decision::Deny { .. }) {
        if let Some(canon_rel) = canon_rel.as_deref() {
            let canon_key = format!("file:{canon_rel}");
            if let Some(canon_eval) = match daemon_result(
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
                DaemonResult::Ok(resp) => {
                    let d = daemon_data(&resp);
                    if d.is_none() {
                        // Escalate-only path: the lexical decision stands, but
                        // record the gap — the real target went ungated.
                        log_fail_open(canon_rel, "hook_evaluate returned error (canonical)");
                    }
                    d
                }
                _ => None,
            } {
                let canon_file_exists =
                    file_exists_for_deleted_signal(&canon_eval, canon_rel, &cwd);
                let mut canon_adapter =
                    process_eval_response(args.variant, canon_rel, &canon_eval, canon_file_exists);
                // Mandate the symlink's real target too (parity with the gotcha WI-20 close).
                apply_consult_mandate(
                    &mut canon_adapter,
                    args.variant,
                    canon_rel,
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
                    match daemon_result(
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
                        DaemonResult::Ok(resp) => {
                            let Some(extra_eval) = daemon_data(&resp) else {
                                log_fail_open(
                                    &extra_rel,
                                    "hook_evaluate returned error (extra file)",
                                );
                                continue;
                            };
                            let extra_file_exists =
                                file_exists_for_deleted_signal(&extra_eval, &extra_raw, &cwd);
                            let mut extra_adapter = process_eval_response(
                                args.variant,
                                &extra_rel,
                                &extra_eval,
                                extra_file_exists,
                            );
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
                        // Per-file fail-open, but RECORDED (gap-aware doctrine —
                        // matches the apply_patch loop): the extra file simply
                        // isn't gated this round, and the log says so.
                        _ => log_fail_open(&extra_rel, "hook_evaluate failed (extra file)"),
                    }
                }
            }
        }
    }

    // A file-bearing governed DB command gets the policy decision after the
    // existing file gate. A file-gate Deny is already final, so skip the
    // policy round-trip and its possible second event on that path.
    if matches!(
        args.variant,
        HookVariant::ClaudePreBash | HookVariant::CodexPreBash | HookVariant::ClaudePreEdit
    ) && !matches!(adapter.decision, Decision::Deny { .. })
    {
        // A bash file argument has the same second identity as an edit target:
        // `psql -f link.sql` can read through to the real in-repo target. Keep
        // one db_client action so host/tool matching survives the governed_tool
        // filter; unlike edits, add canonical paths to action.files rather than
        // building a separate path action. action.files is cloned into
        // PolicyShadowObserved, so shadow observations now record resolved paths
        // alongside lexical ones, showing what the command actually touched.
        let policy_actions: Vec<decide::Action> = match args.variant {
            HookVariant::ClaudePreBash | HookVariant::CodexPreBash => bash_action
                .as_ref()
                .cloned()
                .map(|mut action| {
                    let lexical_files: Vec<String> = action
                        .files
                        .iter()
                        .take(decide::MAX_APPLY_PATCH_FILES)
                        .cloned()
                        .collect();
                    for lexical in lexical_files {
                        if let Some(canonical) =
                            canonical_rel_path(&lexical, &cwd, repo_root.as_deref(), &lexical)
                        {
                            if !action.files.iter().any(|path| path == &canonical) {
                                action.files.push(canonical);
                            }
                        }
                    }
                    action
                })
                .into_iter()
                .collect(),
            HookVariant::ClaudePreEdit => std::iter::once(rel_path.as_str())
                .chain(canon_rel.as_deref())
                .map(|path| decide::normalize_action(None, Some(path)))
                .collect(),
            _ => Vec::new(),
        };
        let governed_tool = if args.variant == HookVariant::ClaudePreEdit {
            "path"
        } else {
            "db_client"
        };
        for action in &policy_actions {
            // Escalate-only: stop at the first deny, and never lower an
            // existing decision. Edits already make one hook_evaluate round
            // trip; a future optimization could piggyback policy verdicts onto
            // that response.
            if matches!(adapter.decision, Decision::Deny { .. }) {
                break;
            }
            if let Some((policy_decision, policy_events)) = evaluate_governed_policy(
                Some(&mati_root),
                action,
                governed_tool,
                agent_id,
                "<policy>",
                policy_block_exempt(args.variant, &input),
                raw_command,
            )
            .await
            {
                merge_policy_result(&mut adapter, args.variant, policy_decision, policy_events);
            }
        }
    }

    // Platform-specific output FIRST, audit events second: the outer deadline
    // can cancel this future between the two. A decision that was delivered
    // but not recorded is an honest gap (fail-open doctrine); an event
    // recorded for a decision that was never delivered would be a phantom
    // entry in the hash-chained audit log. Missing beats false.
    if !adapter.stdout.is_empty() {
        println!("{}", adapter.stdout);
    }
    if !adapter.stderr.is_empty() {
        eprintln!("{}", adapter.stderr);
    }

    // Fire audit events (sequential daemon round-trips, bounded by the outer
    // deadline). session_id (Claude Code provides it at the top level of the
    // hook input) and agent_id (present in subagent payloads) attribute these
    // events to the agent session / actor — per-actor audit.
    let session_id = input.get("session_id").and_then(|v| v.as_str());
    fire_events(
        &mati_root,
        &adapter.events,
        session_id,
        agent_id,
        adapter.basis_hash.as_deref(),
    )
    .await;

    // Emit the lexical fail-open telemetry captured before the fallback.
    if let Some(reason) = lexical_fail_open {
        log_fail_open(&rel_path, &reason);
    }

    if adapter.exit_code != 0 {
        let _ = std::io::Write::flush(&mut std::io::stderr());
        std::process::exit(adapter.exit_code);
    }

    Ok(())
}

/// Evaluate local policies for a governed, fileless Bash command.
///
/// This is deliberately separate from the file-gate path: file-bearing DB
/// commands continue through the existing gotcha flow until policy/file-gate
/// composition is specified.
async fn run_fileless_policy(
    input: &serde_json::Value,
    variant: HookVariant,
    action: &decide::Action,
    agent_id: Option<&str>,
) -> Result<()> {
    let Ok(cwd) = std::env::current_dir() else {
        return Ok(());
    };
    let repo_root = discover_repo_root(&cwd);
    let root_for_slug = repo_root.as_deref().unwrap_or(&cwd);
    let mati_root = match mati_root_for(root_for_slug) {
        Ok(root) => root,
        Err(_) => {
            log_fail_open("<fileless-bash>", "cannot determine mati root");
            emit_allow(variant);
            return Ok(());
        }
    };
    let Some((decision, events)) = evaluate_governed_policy(
        Some(&mati_root),
        action,
        "db_client",
        agent_id,
        "<fileless-bash>",
        policy_block_exempt(variant, input),
        input
            .pointer("/tool_input/command")
            .and_then(|value| value.as_str()),
    )
    .await
    else {
        emit_allow(variant);
        return Ok(());
    };
    let (stdout, stderr, exit_code) = format_decision(variant, &decision, "<policy>");
    if !stdout.is_empty() {
        println!("{stdout}");
    }
    if !stderr.is_empty() {
        eprintln!("{stderr}");
    }
    let session_id = input.get("session_id").and_then(|v| v.as_str());
    fire_events(&mati_root, &events, session_id, agent_id, None).await;
    if exit_code != 0 {
        let _ = std::io::Write::flush(&mut std::io::stderr());
        std::process::exit(exit_code);
    }
    Ok(())
}

/// Evaluate a governed local policy without producing platform output.
///
/// `None` is both the non-governed result and the fail-open result. Callers
/// must preserve their existing decision when it is returned for composition.
async fn evaluate_governed_policy(
    mati_root: Option<&Path>,
    action: &decide::Action,
    governed_tool: &str,
    agent_id: Option<&str>,
    failure_path: &str,
    introspection_exemption: bool,
    raw_command: Option<&str>,
) -> Option<(Decision, Vec<HookEvent>)> {
    if action.tool != governed_tool && action.tool != "unknown" {
        return None;
    }
    let Some(mati_root) = mati_root else {
        log_fail_open(failure_path, "cannot determine mati root");
        return None;
    };
    if !ensure_daemon(mati_root).await {
        log_fail_open(failure_path, "daemon not running after auto-start");
        return None;
    }
    let evaluation =
        policy_verdicts_for_action(mati_root, action, agent_id, failure_path, raw_command).await?;
    let strict = evaluation.verdicts.iter().any(|verdict| verdict.strict);
    let core_verdicts = policy_core_verdicts(&evaluation.verdicts, introspection_exemption);
    let result = decide::evaluate_policy_verdicts(&core_verdicts, strict);
    let mut events: Vec<HookEvent> = result
        .events
        .into_iter()
        .map(|event| match event {
            HookEvent::PolicyShadowObserved { key, would, .. } => HookEvent::PolicyShadowObserved {
                key,
                would,
                action: Some(action.clone()),
            },
            event => event,
        })
        .collect();
    if let Some(key) = evaluation.bypass_key {
        events.push(HookEvent::UnclassifiedPolicyLiteralBypass { key });
    }
    Some((result.decision, events))
}

fn policy_core_verdicts(
    verdicts: &[mati_core::mcp::protocol::PolicyVerdict],
    introspection_exemption: bool,
) -> Vec<decide::PolicyVerdict> {
    verdicts
        .iter()
        .filter_map(|verdict| {
            if introspection_exemption
                && matches!(verdict.stage, mati_core::store::PolicyStage::Shadow)
                && matches!(verdict.mode, mati_core::store::PolicyMode::Block)
            {
                return None;
            }
            Some(decide::PolicyVerdict {
                key: verdict.key.clone(),
                rule: verdict.rule.clone(),
                requires_key: verdict.requires_key.clone(),
                block: matches!(verdict.mode, mati_core::store::PolicyMode::Block)
                    && (!introspection_exemption || verdict.satisfied),
                satisfied: verdict.satisfied,
                stage: verdict.stage,
            })
        })
        .collect()
}

async fn policy_verdicts_for_action(
    mati_root: &Path,
    action: &decide::Action,
    agent_id: Option<&str>,
    failure_path: &str,
    raw_command: Option<&str>,
) -> Option<mati_core::mcp::protocol::PolicyEvaluateResult> {
    let response = daemon_v2(
        mati_root,
        mati_core::mcp::protocol::Command::PolicyEvaluate(
            mati_core::mcp::protocol::PolicyEvaluateInput {
                action: action.clone(),
                actor: agent_id.map(str::to_string),
                raw_command: raw_command.map(str::to_string),
            },
        ),
    )
    .await;
    let data = match response {
        DaemonResult::Ok(resp) => match daemon_data(&resp) {
            Some(data) => data,
            None => {
                log_fail_open(failure_path, "policy_evaluate returned error");
                return None;
            }
        },
        _ => {
            log_fail_open(failure_path, "policy_evaluate failed");
            return None;
        }
    };
    match serde_json::from_value(data) {
        Ok(verdicts) => Some(verdicts),
        Err(_) => {
            log_fail_open(failure_path, "policy_evaluate returned invalid data");
            None
        }
    }
}

/// A successful schema inspection is the remedy for a DB policy, so the
/// pre-Bash gate may steer it but must not block it.
fn policy_block_exempt(variant: HookVariant, input: &serde_json::Value) -> bool {
    matches!(
        variant,
        HookVariant::ClaudePreBash | HookVariant::CodexPreBash
    ) && input
        .pointer("/tool_input/command")
        .and_then(|value| value.as_str())
        .is_some_and(decide::is_schema_introspection)
}

/// Merge a policy result into the existing file-gate result without lowering it.
fn merge_policy_result(
    adapter: &mut AdapterResult,
    variant: HookVariant,
    policy_decision: Decision,
    policy_events: Vec<HookEvent>,
) {
    let merged_decision = match policy_decision {
        Decision::Deny { .. } => policy_decision,
        Decision::Advisory {
            context: policy_context,
        } => match &adapter.decision {
            Decision::Deny { .. } => adapter.decision.clone(),
            Decision::Advisory { context } => Decision::Advisory {
                context: format!("{context}\n{policy_context}"),
            },
            Decision::AlreadyConsulted { .. } if variant == HookVariant::ClaudePreEdit => {
                Decision::Advisory {
                    context: policy_context,
                }
            }
            Decision::AlreadyConsulted { context } => Decision::AlreadyConsulted {
                context: format!("{context}\n{policy_context}"),
            },
            Decision::Liability { staleness, context } => Decision::Liability {
                staleness: *staleness,
                context: format!("{context}\n{policy_context}"),
            },
            _ => Decision::Advisory {
                context: policy_context,
            },
        },
        Decision::Allow => adapter.decision.clone(),
        _ => adapter.decision.clone(),
    };
    adapter.decision = merged_decision;
    adapter.events.extend(policy_events);
    let (stdout, stderr, exit_code) = format_decision(variant, &adapter.decision, "<policy>");
    adapter.stdout = stdout;
    adapter.stderr = stderr;
    adapter.exit_code = exit_code;
}

// ── Path extraction ─────────────────────────────────────────────────────────

/// Reject `extract_file_path` results that cannot be a file path: shell
/// redirection fragments (`2>/dev/null`, `>>`, `2>&1`) or a multi-line blob
/// (the classifier grabbed an entire quoted command, not one argument).
/// These pollute the `analytics:miss_*` aggregate that feeds `mati status`'s
/// hit rate. Only rejects; never widens what counts as a real path.
fn looks_like_file_path(s: &str) -> bool {
    if s.is_empty() || s.contains('\n') || s.contains('\r') {
        return false;
    }
    let trimmed = s.trim_start_matches(|c: char| c.is_ascii_digit());
    !trimmed.starts_with('>') && !trimmed.starts_with('<') && !trimmed.starts_with('|')
}

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
            decide::extract_file_path(cmd, class).filter(|p| looks_like_file_path(p))
        }
        // apply_patch is multi-file and handled by `run_apply_patch` before the
        // single-path pipeline; never reaches here.
        HookVariant::CodexPreApplyPatch => None,
        // post-memget is handled by `run_post_memget` before extract_path is called;
        // it uses tool_input.key directly, not a file path.
        HookVariant::ClaudePostMemGet => None,
        HookVariant::ClaudePostBash => None,
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
        // Strip the trailing separator that git2's workdir() sometimes adds.
        // `to_str` (NOT `to_string_lossy`): a non-UTF-8 root would be
        // silently rewritten with U+FFFD — a valid-looking but WRONG path,
        // producing a wrong slug and wrong store keys (a permanent, silent
        // gate miss). Returning None instead falls back to cwd-based
        // resolution, which is at least honest about not knowing the root.
        let root = repo.workdir()?.to_str()?.trim_end_matches('/');
        Some(PathBuf::from(root))
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

/// Resolve `accessed_path` to an absolute path against `cwd`, the way the
/// hook process resolves a bare relative shell argument. Same rule
/// `canonical_rel_path` uses for `abs_access`, without the symlink
/// resolution — an existence check doesn't need it.
fn resolve_access_path(accessed_path: &str, cwd: &Path) -> PathBuf {
    let raw = Path::new(accessed_path);
    if raw.is_absolute() {
        raw.to_path_buf()
    } else {
        cwd.join(raw)
    }
}

/// Populate [`EnforcementInput::file_exists`] — but ONLY when `eval_data`'s
/// file record actually carries the `FileDeleted` staleness signal. The
/// common, non-deleted-file path must pay nothing for this: `None` short-
/// circuits before any stat runs.
///
/// `Path::try_exists()` distinguishes "confirmed absent" (`Ok(false)`) from
/// "can't tell" (`Err`, e.g. a permission-denied parent directory) — the
/// latter stays `None` so an ambiguous stat fails open into today's
/// behavior (the signal alone decides) rather than inventing a new one.
fn file_exists_for_deleted_signal(
    eval_data: &serde_json::Value,
    accessed_path: &str,
    cwd: &Path,
) -> Option<bool> {
    let file_record = eval_data.get("file_record")?;
    if !decide::has_file_deleted_signal(file_record) {
        return None;
    }
    resolve_access_path(accessed_path, cwd).try_exists().ok()
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
        serde_json::json!({
            "key": &file_key,
            "ttl_secs": mati_core::store::session::CONSULTED_RECENT_TTL_SECS,
        }),
    )
    .await
    {
        DaemonResult::Ok(resp) => match daemon_data(&resp) {
            Some(d) => d.as_bool().unwrap_or(false),
            // Daemon-side error: the consultation state is UNKNOWN. Recording
            // a CodexShellMiss here would be a false "bypass detected" audit
            // event (the daemon is reachable, so it WOULD be recorded).
            None => return Ok(()),
        },
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
            actor: None,
            decision_basis_hash: None,
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
    // A failed mem_get delivered no context — minting a receipt for it would
    // wrongly downgrade a future deny (a receipt is proof the record was
    // READ). MCP tool errors surface as `tool_response.isError: true`; an
    // absent field means success, so this guard is a no-op on the happy path.
    if input
        .pointer("/tool_response/isError")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        return Ok(());
    }

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
    let actor = receipt_actor(agent_id, session_id);

    let cwd = std::env::current_dir()?;
    // Resolve the daemon slug the way the gate does (repo root, not cwd) so the
    // receipt lands in the store the gate will read. The actor scope matches the
    // gate too: agent receipts are scoped, while the main thread (no agent_id)
    // uses the global receipt.
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
            capture_fingerprint: true,
            actor: actor.map(str::to_string),
            session_id: session_id.map(str::to_string),
            agent_id: agent_id.map(str::to_string),
            decision_basis_hash: None,
            source: Some(mati_core::store::ReceiptSource::MemGet),
        },
    );
    let _ = super::daemon::daemon_v2(&mati_root, cmd).await;
    Ok(())
}

/// Best-effort PostToolUse adapter for schema introspection. The policy
/// evaluation and receipt minting are deliberately fire-and-forget: a
/// PostToolUse hook must never disrupt the agent session.
async fn run_post_bash_introspection(input: &serde_json::Value) -> Result<()> {
    if !post_bash_succeeded(input) {
        return Ok(());
    }
    let Some(command) = input
        .pointer("/tool_input/command")
        .and_then(|value| value.as_str())
        .filter(|command| decide::is_schema_introspection(command))
    else {
        return Ok(());
    };
    let action = decide::normalize_action(Some(command), None);
    if action.tool != "db_client" {
        // `command` passed `is_schema_introspection` above but its leading
        // word didn't classify — an upstream PreToolUse hook rewrote it
        // (observed live: `rtk psql …`). The receipt this command should
        // mint never mints, so a `db_client` policy stays permanently
        // denied. Record the signature; do not attempt to mint or recover.
        record_wrapped_client_miss(input, &action).await;
        return Ok(());
    }

    let Ok(cwd) = std::env::current_dir() else {
        return Ok(());
    };
    let repo_root = discover_repo_root(&cwd);
    let root_for_slug = repo_root.as_deref().unwrap_or(&cwd);
    let mati_root = match mati_root_for(root_for_slug) {
        Ok(root) => root,
        Err(_) => return Ok(()),
    };
    if !ensure_daemon(&mati_root).await {
        return Ok(());
    }

    let Some(evaluation) = policy_verdicts_for_action(
        &mati_root,
        &action,
        input.get("agent_id").and_then(|value| value.as_str()),
        "<post-bash>",
        Some(command),
    )
    .await
    else {
        return Ok(());
    };
    let agent_id = input
        .get("agent_id")
        .and_then(|value| value.as_str())
        .filter(|value| !value.is_empty());
    let session_id = input
        .get("session_id")
        .and_then(|value| value.as_str())
        .filter(|value| !value.is_empty());
    for verdict in evaluation.verdicts {
        if !accepts_db_introspection(&verdict.via) {
            continue;
        }
        let _ = daemon_v2(
            &mati_root,
            mati_core::mcp::protocol::Command::ConsultationHit(
                mati_core::mcp::protocol::ConsultationHitInput {
                    key: verdict.requires_key,
                    capture_fingerprint: false,
                    actor: receipt_actor(agent_id, session_id).map(str::to_string),
                    session_id: session_id.map(str::to_string),
                    agent_id: agent_id.map(str::to_string),
                    decision_basis_hash: None,
                    source: Some(mati_core::store::ReceiptSource::DbIntrospection),
                },
            ),
        )
        .await;
    }
    Ok(())
}

/// Record the wrapped-db-client deadlock signature: `is_schema_introspection`
/// was true but `normalize_action` did not classify the same command as
/// `db_client`. Diagnostic only — best-effort and fail-open like the rest of
/// this module, and never touches any allow/deny decision (this hook variant
/// emits no `permissionDecision` at all; see `allow_output`).
async fn record_wrapped_client_miss(input: &serde_json::Value, action: &decide::Action) {
    let Ok(cwd) = std::env::current_dir() else {
        return;
    };
    let repo_root = discover_repo_root(&cwd);
    let root_for_slug = repo_root.as_deref().unwrap_or(&cwd);
    let Ok(mati_root) = mati_root_for(root_for_slug) else {
        return;
    };
    if !ensure_daemon(&mati_root).await {
        return;
    }

    let session_id = input
        .get("session_id")
        .and_then(|value| value.as_str())
        .filter(|value| !value.is_empty());
    // The leading token survives env-assignment and PREFIX_WORDS stripping in
    // `normalize_action`, so it names the wrapper (e.g. "rtk") without ever
    // carrying the full command text (which may embed a DSN password).
    let wrapper = action.argv.first().map(String::as_str).unwrap_or("unknown");
    tracing::warn!(
        "post-bash: schema-introspection command led by '{wrapper}' did not \
         classify as db_client — likely rewritten by another PreToolUse hook; \
         its consultation receipt cannot mint (deadlock signature)"
    );

    let cmd =
        mati_core::mcp::protocol::Command::SessionLog(mati_core::mcp::protocol::SessionLogInput {
            event: mati_core::mcp::protocol::SessionEvent::WrappedDbClientMiss,
            key: format!("enforcement:wrapped_client:{wrapper}"),
            session_id: session_id.map(str::to_string),
            actor: None,
            decision_basis_hash: None,
        });
    let _ = daemon_v2(&mati_root, cmd).await;
}

/// Select the receipt scope shared by the gate and both post-tool mint paths.
/// Session IDs remain consultation metadata, not receipt scope.
fn receipt_actor<'a>(agent_id: Option<&'a str>, _session_id: Option<&str>) -> Option<&'a str> {
    agent_id
}

/// Claude's PostToolUse payloads have used both camelCase and snake_case
/// spellings. An unrecognized payload shape is not success: minting must stop
/// until the hook understands the new shape.
fn post_bash_succeeded(input: &serde_json::Value) -> bool {
    let Some(response) = input.pointer("/tool_response") else {
        tracing::warn!("Claude PostToolUse Bash payload is missing tool_response");
        return false;
    };
    // Claude Code omits `isError` entirely on a successful Bash command. A
    // captured payload carries exactly `{stdout, stderr, interrupted, isImage,
    // noOutputExpected}` and no exit status at all, so requiring the field made
    // every introspection look like a failure and `DbIntrospection` could never
    // mint. Absent means success, matching `run_post_memget`; only an explicit
    // `true` is a failure.
    //
    // Observed alongside that: a Bash call that exits non-zero fires no
    // PostToolUse event at all, so this function never runs for a failed
    // command and cannot mint for one. That is what makes the absent-means-
    // success default safe rather than merely convenient. Confirmed in both
    // `default` and `acceptEdits` permission modes; `bypassPermissions` is
    // untested. The checks below stay as defense in depth, because the absence
    // of an event is Claude Code's behavior to change, not a contract mati
    // controls: if a failing command ever did reach this function it would
    // carry no `isError` either, and the shape alone could not distinguish it
    // from a success.
    if response
        .get("isError")
        .or_else(|| response.get("is_error"))
        .and_then(|value| value.as_bool())
        .unwrap_or(false)
    {
        return false;
    }
    // A cancelled command taught the agent nothing, so it must not mint.
    if response
        .get("interrupted")
        .and_then(|value| value.as_bool())
        .unwrap_or(false)
    {
        return false;
    }
    for key in ["exit_code", "exitCode"] {
        let Some(value) = response.get(key) else {
            continue;
        };
        let Some(code) = value.as_i64() else {
            tracing::warn!("Claude PostToolUse Bash payload has non-numeric {key}");
            return false;
        };
        if code != 0 {
            return false;
        }
    }
    true
}

fn accepts_db_introspection(via: &[mati_core::store::ReceiptSource]) -> bool {
    via.contains(&mati_core::store::ReceiptSource::DbIntrospection)
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
    // Enterprise consult-mandate globs — parity with the single-path flow.
    let consult_globs = consult_globset();
    // (deny key, deny reason, origin). The origin selects the message shape: a
    // policy deny's key is the policy, not something the agent can consult.
    let mut denied: Vec<(String, String, decide::DenyOrigin)> = Vec::new();
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
            DaemonResult::Ok(resp) => match daemon_data(&resp) {
                Some(d) => d,
                None => {
                    // Per-file fail-open on a daemon-side error — recorded,
                    // not evaluated as a false "no record".
                    log_fail_open(&rel_path, "hook_evaluate returned error");
                    continue;
                }
            },
            _ => {
                // Per-file fail-open: don't block the whole edit on one bad lookup.
                log_fail_open(&rel_path, "hook_evaluate failed");
                continue;
            }
        };

        let file_exists = file_exists_for_deleted_signal(&eval_data, raw, &cwd);
        let mut adapter = process_eval_response(variant, &rel_path, &eval_data, file_exists);
        // Consult mandate on the patch target — parity with the read/edit
        // gates (this path uses include_recent semantics, hence `true`).
        apply_consult_mandate(
            &mut adapter,
            variant,
            &rel_path,
            consulted_flag(&eval_data, true),
            consult_globs.as_ref(),
        );
        // Resolve the symlink target ONCE, before any gate runs. Both the
        // gotcha gate and the policy gate need it: one gate knowing about
        // symlinks while its sibling does not was the actual defect, and a
        // path policy that misses a symlinked target is only the symptom.
        // `canonical_rel_path` returns None for a non-symlink, so the common
        // case costs nothing.
        let canon_rel = canonical_rel_path(raw, &cwd, repo_root.as_deref(), &rel_path);

        // Codex apply_patch has the exact target path, so apply the same
        // target_path_glob policy gate used by Claude edits, over the lexical
        // key and the canonical one. Escalate-only: the loop stops at the first
        // deny and a non-deny outcome never lowers an existing decision.
        for policy_path in std::iter::once(rel_path.as_str()).chain(canon_rel.as_deref()) {
            if matches!(adapter.decision, Decision::Deny { .. }) {
                break;
            }
            let action = decide::normalize_action(None, Some(policy_path));
            if let Some((policy_decision, policy_events)) = evaluate_governed_policy(
                Some(&mati_root),
                &action,
                "path",
                agent_id,
                "<apply-patch-policy>",
                policy_block_exempt(variant, input),
                None,
            )
            .await
            {
                merge_policy_result(&mut adapter, variant, policy_decision, policy_events);
            }
        }
        // WI-20 parity: a patch targeting an in-repo symlink would otherwise
        // evaluate only the lexical key and write through to the real target
        // ungated. Escalate-only, like the read/edit path: a non-deny
        // canonical result never downgrades the lexical decision, and
        // `canonical_rel_path` returns None (zero cost) for non-symlinks.
        if !matches!(adapter.decision, Decision::Deny { .. }) {
            if let Some(canon_rel) = canon_rel.as_deref() {
                let canon_key = format!("file:{canon_rel}");
                if let Some(canon_eval) = match daemon_result(
                    &mati_root,
                    "hook_evaluate",
                    serde_json::json!({ "file_key": &canon_key, "include_recent": true, "actor": agent_id }),
                )
                .await
                {
                    DaemonResult::Ok(resp) => {
                        let d = daemon_data(&resp);
                        if d.is_none() {
                            log_fail_open(
                                canon_rel,
                                "hook_evaluate returned error (canonical)",
                            );
                        }
                        d
                    }
                    _ => None,
                } {
                    let canon_file_exists =
                        file_exists_for_deleted_signal(&canon_eval, canon_rel, &cwd);
                    let mut canon_adapter =
                        process_eval_response(variant, canon_rel, &canon_eval, canon_file_exists);
                    apply_consult_mandate(
                        &mut canon_adapter,
                        variant,
                        canon_rel,
                        consulted_flag(&canon_eval, true),
                        consult_globs.as_ref(),
                    );
                    if matches!(canon_adapter.decision, Decision::Deny { .. }) {
                        adapter = canon_adapter;
                    }
                }
            }
        }
        // The Deny carries its own file_key — the lexical key, the canonical
        // (real-target) key, or the mandate key, whichever actually denied.
        if let Decision::Deny {
            file_key: denied_key,
            reason,
            origin,
        } = &adapter.decision
        {
            denied.push((denied_key.clone(), reason.clone(), *origin));
        }
        // Unconditionally: a non-denying policy still produces events. A shadow
        // observation and a satisfied block's receipt must both be recorded, or
        // `mati policy observations` reports zero matches for a policy that
        // matched every time, and this adapter's audit trail diverges from the
        // Claude edit gate's for the same action.
        events.extend(adapter.events);
    }

    // 5. Deny if any file needs consultation; otherwise allow. Output FIRST,
    // audit events second (missing beats false — see run_inner).
    if denied.is_empty() {
        // Output first, events second, matching the deny path below: a decision
        // delivered but unrecorded is an honest gap, the reverse is a lie.
        emit_allow(variant);
        // Firing here is what makes a non-denying policy observable at all. A
        // shadow-stage match and a satisfied block both land on this path, and
        // returning early dropped every one of them.
        fire_events(&mati_root, &events, None, agent_id, None).await;
        return Ok(());
    }
    // Policy denies carry their own actionable instruction; file denies keep the
    // established consult-the-file shape. A patch can trip both at once, so both
    // are reported rather than one shadowing the other.
    let (policy_denies, file_denies): (Vec<_>, Vec<_>) = denied
        .iter()
        .partition(|(_, _, origin)| matches!(origin, decide::DenyOrigin::Policy));
    let mut lines: Vec<String> = policy_denies
        .iter()
        .map(|(_, reason, _)| reason.clone())
        .collect();
    if file_denies.len() == 1 {
        lines.push(format!(
            "mati: call mem_get(\"{}\") before editing",
            file_denies[0].0
        ));
    } else if file_denies.len() > 1 {
        lines.push(format!(
            "mati: consult these files before editing — call mem_get for each: {}",
            file_denies
                .iter()
                .map(|(key, _, _)| key.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    let msg = lines.join("\n");
    eprintln!("{msg}");
    let _ = std::io::Write::flush(&mut std::io::stderr());

    // 6. Fire compliance events for the blocked files (fire-and-forget).
    // Codex apply_patch: no Claude session_id in the input; agent_id is
    // present only in subagent payloads.
    fire_events(&mati_root, &events, None, agent_id, None).await;
    std::process::exit(2);
}

// ── Fail-open telemetry ─────────────────────────────────────────────────────

fn log_fail_open(rel_path: &str, reason: &str) {
    log_fail_open_named("hook-decide", rel_path, reason);
}

/// Record a fail-open event for a hook that uses the shared hook lifecycle.
pub(crate) fn log_fail_open_named(hook: &str, rel_path: &str, reason: &str) {
    eprintln!("[mati] WARNING: enforcement bypassed for {rel_path} — {reason}");
    if let Some(log_dir) = mati_core::store::mati_home_opt() {
        let _ = std::fs::create_dir_all(&log_dir);
        let log_path = log_dir.join("fail_open.log");
        log_fail_open_at_named(&log_path, hook, rel_path, reason);
    }
}

/// Append one entry to `fail_open.log`. Format MUST match the parser in
/// `cli::stats::parse_iso_timestamp` — the round-trip is covered by
/// `fail_open_log_round_trip_writer_reader` in `cli::stats`'s test module.
#[allow(dead_code)] // The direct writer is exercised by the stats round-trip test.
pub(super) fn log_fail_open_at(log_path: &Path, rel_path: &str, reason: &str) {
    log_fail_open_at_named(log_path, "hook-decide", rel_path, reason);
}

fn log_fail_open_at_named(log_path: &Path, hook: &str, rel_path: &str, reason: &str) {
    let now = iso_utc_now();
    let entry = format!("{now} FAIL_OPEN hook={hook} file={rel_path} reason={reason}\n");
    let _ = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
        .and_then(|mut f| {
            std::io::Write::write_all(&mut f, entry.as_bytes())?;
            std::io::Write::flush(&mut f)
        });
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
        HookVariant::CodexPostBash
        | HookVariant::ClaudePostMemGet
        | HookVariant::ClaudePostBash => {
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
                HookEvent::PolicyConsultBlocked { key } => {
                    Some(HookEvent::PolicyConsultBlocked { key })
                }
                HookEvent::PolicyConsulted { key } => Some(HookEvent::PolicyConsulted { key }),
                HookEvent::PolicySteered { key } => Some(HookEvent::PolicySteered { key }),
                HookEvent::PolicyShadowObserved { key, would, action } => {
                    Some(HookEvent::PolicyShadowObserved { key, would, action })
                }
                HookEvent::ComplianceHit { key } => Some(HookEvent::EditConsulted { key }),
                // Not a Hit/Miss the read gate owns — a real deny was
                // suppressed on this edit's target, so the edit path must
                // keep it too, not drop it like the plain Miss below.
                HookEvent::TombstoneBypassedDeny { key } => {
                    Some(HookEvent::TombstoneBypassedDeny { key })
                }
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

async fn fire_events(
    mati_root: &Path,
    events: &[HookEvent],
    session_id: Option<&str>,
    agent_id: Option<&str>,
    basis_hash: Option<&str>,
) {
    for event in events {
        let Some(cmd) = session_command(event, session_id, agent_id, basis_hash) else {
            continue;
        };
        // Fire-and-forget — drop silently on failure (P9).
        let _ = super::daemon::daemon_v2(mati_root, cmd).await;
    }
}

/// Translate one semantic [`HookEvent`] into the daemon command that records it.
///
/// Pure, so the mapping is testable: it decides which enforcement event type
/// each outcome lands as, and it is where a Codex pre-hook BLOCK was recorded
/// as the post-bash hook's after-the-fact bypass.
fn session_command(
    event: &HookEvent,
    session_id: Option<&str>,
    agent_id: Option<&str>,
    basis_hash: Option<&str>,
) -> Option<mati_core::mcp::protocol::Command> {
    use mati_core::mcp::protocol as p;
    // Per-actor audit attribution (schema_version 2): tag each SessionLog with the
    // agent session that triggered it, when the platform provides one.
    let sid = || session_id.map(str::to_string);
    // Receipt scope, so the daemon can find the receipt that authorized an allow,
    // and the digest of the gotcha state this decision was made on.
    let scope = || agent_id.map(str::to_string);
    let basis = || basis_hash.map(str::to_string);
    Some(match event {
        // Receipt scope must match the evaluation scope: the gate was
        // queried with `actor = agent_id`, so the receipt minted here is
        // scoped the same way. A subagent's Advisory hit must NOT mint a
        // global receipt — receipts are strictly key-scoped in the store
        // (no actor↔global fallback), and a global receipt would satisfy
        // the main thread's gate for context only the subagent received.
        HookEvent::Hit { key } => p::Command::ConsultationHit(p::ConsultationHitInput {
            key: key.clone(),
            capture_fingerprint: true,
            actor: agent_id.map(str::to_string),
            session_id: sid(),
            agent_id: agent_id.map(str::to_string),
            decision_basis_hash: basis(),
            // Hook context injection is neither variant. Left unset rather
            // than guessed; see ConsultationReceipt::source.
            source: None,
        }),
        HookEvent::Miss { key } => p::Command::SessionLog(p::SessionLogInput {
            event: p::SessionEvent::Miss,
            key: key.clone(),
            session_id: sid(),
            actor: scope(),
            decision_basis_hash: basis(),
        }),
        HookEvent::BlockedUnconsultedRead { key } => p::Command::SessionLog(p::SessionLogInput {
            event: p::SessionEvent::ComplianceMiss,
            key: key.clone(),
            session_id: sid(),
            actor: scope(),
            decision_basis_hash: basis(),
        }),
        HookEvent::CodexShellBlocked { key } => p::Command::SessionLog(p::SessionLogInput {
            event: p::SessionEvent::CodexShellBlocked,
            key: key.clone(),
            session_id: sid(),
            actor: scope(),
            decision_basis_hash: basis(),
        }),
        HookEvent::UnclassifiedPolicyLiteralBypass { key } => {
            p::Command::SessionLog(p::SessionLogInput {
                event: p::SessionEvent::UnclassifiedPolicyLiteralBypass,
                key: key.clone(),
                session_id: sid(),
                actor: scope(),
                decision_basis_hash: None,
            })
        }
        HookEvent::ComplianceHit { key } => p::Command::SessionLog(p::SessionLogInput {
            event: p::SessionEvent::ComplianceHit,
            key: key.clone(),
            session_id: sid(),
            actor: scope(),
            decision_basis_hash: basis(),
        }),
        HookEvent::EditConsulted { key } => p::Command::SessionLog(p::SessionLogInput {
            event: p::SessionEvent::EditConsulted,
            key: key.clone(),
            session_id: sid(),
            actor: scope(),
            decision_basis_hash: basis(),
        }),
        HookEvent::EditBlocked { key } => p::Command::SessionLog(p::SessionLogInput {
            event: p::SessionEvent::EditBlocked,
            key: key.clone(),
            session_id: sid(),
            actor: scope(),
            decision_basis_hash: basis(),
        }),
        HookEvent::FloorConsultBlocked { key } => p::Command::SessionLog(p::SessionLogInput {
            event: p::SessionEvent::FloorConsultMiss,
            key: key.clone(),
            session_id: sid(),
            actor: scope(),
            decision_basis_hash: basis(),
        }),
        HookEvent::PolicyConsultBlocked { key } => p::Command::SessionLog(p::SessionLogInput {
            event: p::SessionEvent::PolicyConsultMiss,
            key: key.clone(),
            session_id: sid(),
            actor: scope(),
            // Policy decisions are made on the policy record, not on the
            // file's gotchas — the gotcha digest is not their basis.
            decision_basis_hash: None,
        }),
        HookEvent::PolicyConsulted { key } => p::Command::SessionLog(p::SessionLogInput {
            event: p::SessionEvent::PolicyConsultHit,
            key: key.clone(),
            session_id: sid(),
            actor: scope(),
            // Policy decisions are made on the policy record, not on the
            // file's gotchas — the gotcha digest is not their basis.
            decision_basis_hash: None,
        }),
        HookEvent::PolicySteered { key } => p::Command::SessionLog(p::SessionLogInput {
            event: p::SessionEvent::PolicySteered,
            key: key.clone(),
            session_id: sid(),
            actor: scope(),
            // Policy decisions are made on the policy record, not on the
            // file's gotchas — the gotcha digest is not their basis.
            decision_basis_hash: None,
        }),
        HookEvent::PolicyShadowObserved {
            key,
            would,
            action: Some(action),
        } => p::Command::PolicyShadowObserve(p::PolicyShadowObserveInput {
            policy_key: key.clone(),
            action: action.clone(),
            would: *would,
        }),
        HookEvent::PolicyShadowObserved { .. } => return None,
        HookEvent::TombstoneBypassedDeny { key } => p::Command::SessionLog(p::SessionLogInput {
            event: p::SessionEvent::TombstoneBypassedDeny,
            key: key.clone(),
            session_id: sid(),
            actor: scope(),
            decision_basis_hash: basis(),
        }),
    })
}

// ── Platform output ─────────────────────────────────────────────────────────

/// The force-allow JSON, emitted ONLY for the Claude read gate.
///
/// INVARIANT (do not widen): `permissionDecision:"allow"` bypasses Claude
/// Code's permission system entirely. Read/Glob/Grep are no-permission tools,
/// so the read gate's allow is a harmless no-op. Bash and Edit/Write are
/// permission-REQUIRED tools — force-allowing them would silently suppress the
/// user's permission prompt for every command/edit mati doesn't deny (i.e.
/// installing mati would auto-approve arbitrary shell commands). Every variant
/// other than `ClaudePreRead` must not force-allow; Bash and Edit may still
/// emit context-only output. Covered by `only_pre_read_force_allows` and the
/// ClaudePreEdit output tests.
fn allow_output(variant: HookVariant) -> Option<&'static str> {
    match variant {
        HookVariant::ClaudePreRead => Some(
            r#"{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}"#,
        ),
        HookVariant::ClaudePreBash
        | HookVariant::CodexPreBash
        | HookVariant::CodexPostBash
        | HookVariant::CodexPreApplyPatch
        | HookVariant::ClaudePreEdit
        | HookVariant::ClaudePostMemGet
        | HookVariant::ClaudePostBash => None,
    }
}

fn emit_allow(variant: HookVariant) {
    if let Some(json) = allow_output(variant) {
        println!("{json}");
    }
    let _ = std::io::Write::flush(&mut std::io::stdout());
}

// emit_decision, emit_claude_decision, and emit_codex_pre_bash_decision
// have been replaced by format_decision() + format_claude_output() in the
// testable adapter core above. The run() function now uses process_eval_response().

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Unwrap a daemon response envelope, treating `{"ok": false}` as a failure.
///
/// `send_v2_raw` maps a daemon-side ERROR (backpressure, session mismatch,
/// handler failure) to `DaemonResult::Ok({"ok": false, ...})` — the transport
/// succeeded, the command didn't. Reading `data` without checking `ok` would
/// hand the gate a `Null` bundle that evaluates as NoRecord: the access is
/// allowed (correct, fail-open) but the audit trail records a false Miss
/// ("no knowledge about this file") instead of a gap, and `fail_open.log`
/// stays silent. Returns `None` on `ok: false` so callers take their
/// fail-open-and-record path instead.
fn daemon_data(resp: &serde_json::Value) -> Option<serde_json::Value> {
    if resp.get("ok").and_then(|v| v.as_bool()).unwrap_or(false) {
        Some(resp.get("data").cloned().unwrap_or(serde_json::Value::Null))
    } else {
        None
    }
}

fn extract_gotcha_map(eval_data: &serde_json::Value) -> HashMap<String, serde_json::Value> {
    eval_data
        .get("gotcha_records")
        .and_then(|v| v.as_object())
        .map(|obj| obj.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
        .unwrap_or_default()
}

/// Escape a string for inclusion inside a JSON string value.
///
/// Delegates to serde_json so ALL control characters (U+0000–U+001F) are
/// escaped, not just `\n`/`\r`/`\t` — an unescaped control char anywhere in a
/// deny reason would make the whole hook output unparseable, and an
/// unparseable deny is a lost deny.
fn escape_json_string(s: &str) -> String {
    let mut quoted =
        serde_json::to_string(s).expect("serializing a &str to a JSON string cannot fail");
    // Strip the surrounding quotes serde adds.
    quoted.pop();
    quoted.remove(0);
    quoted
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
    /// Digest of the gotcha state this decision was made on, stamped onto the
    /// enforcement events as `decision_basis_hash`. `None` when the file has
    /// no gotchas — there is no rule state to prove.
    basis_hash: Option<String>,
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
        match Glob::new(g) {
            Ok(glob) => {
                builder.add(glob);
            }
            // Fail-open, but RECORDED: a typo'd org glob silently
            // un-enforcing a path class would be an unrecorded blind spot.
            Err(e) => log_fail_open(
                g,
                &format!("invalid consult-mandate glob, not enforced: {e}"),
            ),
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
        origin: decide::DenyOrigin::ConsultMandate,
    };
    let events = platform_events(
        variant,
        &decision,
        vec![decide::DenyOrigin::ConsultMandate.deny_event(file_key)],
    );
    let (stdout, stderr, exit_code) = format_decision(variant, &decision, rel_path);
    *adapter = AdapterResult {
        stdout,
        stderr,
        exit_code,
        events,
        // A glob mandate is not decided on gotcha state, so the file's gotchas
        // are not this deny's basis.
        basis_hash: None,
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
///
/// `file_exists` is the caller's own on-disk observation — see
/// [`EnforcementInput::file_exists`]. Passed through unchanged; this
/// function does no I/O itself.
fn check_eval_data(
    variant: HookVariant,
    rel_path: &str,
    eval_data: &serde_json::Value,
    file_exists: Option<bool>,
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
        file_exists,
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
/// No I/O itself — `file_exists` is a value the caller already observed (or
/// `None`); this function only threads it through. Returns a result struct
/// for testing.
fn process_eval_response(
    variant: HookVariant,
    rel_path: &str,
    eval_data: &serde_json::Value,
    file_exists: Option<bool>,
) -> AdapterResult {
    let enforcement_input = match check_eval_data(variant, rel_path, eval_data, file_exists) {
        EvalDataCheck::Ok(input) => input,
        EvalDataCheck::FailOpen(_reason) => {
            // Same rule as `allow_output`: only the read gate force-allows;
            // every other variant defers on fail-open (empty stdout).
            let stdout = allow_output(variant)
                .map(str::to_string)
                .unwrap_or_default();
            return AdapterResult {
                stdout,
                stderr: String::new(),
                exit_code: 0,
                events: vec![],
                basis_hash: None,
                decision: Decision::Allow,
            };
        }
    };

    let basis_hash = decision_basis_hash(&enforcement_input.gotcha_records);
    let result = decide::evaluate(&enforcement_input);
    let events = platform_events(variant, &result.decision, result.events);

    let (stdout, stderr, exit_code) = format_decision(variant, &result.decision, rel_path);

    AdapterResult {
        stdout,
        stderr,
        exit_code,
        events,
        basis_hash,
        decision: result.decision,
    }
}

/// Digest of the gotcha state the gate decided on, for the enforcement event's
/// `decision_basis_hash`. Proves which rule text and confidence values were in
/// force. `None` when the file carries no gotchas — a digest of nothing proves
/// nothing, and a constant in the chain would read as a real basis.
fn decision_basis_hash(records: &HashMap<String, serde_json::Value>) -> Option<String> {
    if records.is_empty() {
        return None;
    }
    let pairs: Vec<(&str, &serde_json::Value)> =
        records.iter().map(|(k, v)| (k.as_str(), v)).collect();
    Some(mati_core::store::enforcement::compute_decision_basis_hash(
        &pairs,
    ))
}

/// Format the decision as platform output strings + exit code.
/// Does NOT call process::exit — returns the values for the caller to act on.
fn format_decision(
    variant: HookVariant,
    decision: &Decision,
    _rel_path: &str,
) -> (String, String, i32) {
    match variant {
        HookVariant::ClaudePreRead => {
            let stdout = format_claude_output(decision);
            (stdout, String::new(), 0)
        }
        HookVariant::ClaudePreBash => {
            // Bash is a permission-REQUIRED tool: a deny is a deny, but every
            // non-deny outcome must DEFER to the normal permission flow —
            // never `permissionDecision:"allow"`, which would suppress the
            // user's prompt for the command (see `allow_output`). Context for
            // advisory/consulted outcomes is injected via `additionalContext`
            // WITHOUT a permissionDecision, which Claude Code treats as
            // "inject context, permission flow proceeds normally".
            let stdout = match decision {
                Decision::Deny { reason, .. } => format_deny(reason),
                Decision::AlreadyConsulted { context } => {
                    format_context_only(&format!("[mati] Record already consulted. {context}"))
                }
                Decision::Advisory { context } | Decision::Liability { context, .. } => {
                    format_context_only(&format!("[mati] {context}"))
                }
                _ => String::new(),
            };
            (stdout, String::new(), 0)
        }
        HookVariant::ClaudePreEdit => match decision {
            // Use the decision's own reason (like the read gate) so the message reflects the
            // actual cause — a local gotcha OR an org consultation mandate — instead of always
            // claiming "Confirmed gotcha".
            Decision::Deny { reason, .. } => (format_deny(reason), String::new(), 0),
            Decision::Advisory { context } | Decision::Liability { context, .. } => (
                format_context_only(&format!("[mati] {context}")),
                String::new(),
                0,
            ),
            // All other non-deny outcomes defer with empty stdout; never force-allow an edit.
            _ => (String::new(), String::new(), 0),
        },
        HookVariant::CodexPreBash | HookVariant::CodexPreApplyPatch => match decision {
            Decision::Deny {
                file_key,
                reason,
                origin,
            } => {
                // A policy deny keys on the policy, which is not a consultable
                // record: its `reason` names the key that actually clears it.
                // Printing file_key there would tell the agent to mem_get the
                // policy itself, minting a receipt that never matches
                // requires.key. Matched exhaustively so a new origin has to
                // choose a shape rather than inherit one.
                let stderr = match origin {
                    decide::DenyOrigin::Policy => reason.clone(),
                    decide::DenyOrigin::Gotcha | decide::DenyOrigin::ConsultMandate => {
                        format!("mati: call mem_get(\"{file_key}\") first")
                    }
                };
                (String::new(), stderr, 2)
            }
            _ => (String::new(), String::new(), 0),
        },
        HookVariant::CodexPostBash
        | HookVariant::ClaudePostMemGet
        | HookVariant::ClaudePostBash => (String::new(), String::new(), 0),
    }
}

/// PreToolUse deny JSON — shared by the read, bash, and edit gates.
fn format_deny(reason: &str) -> String {
    let escaped = escape_json_string(reason);
    format!(
        r#"{{"hookSpecificOutput":{{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"{escaped}"}}}}"#
    )
}

/// PreToolUse output that injects context WITHOUT a permissionDecision: the
/// permission flow proceeds normally. Used by permission-required tool gates
/// (Bash) for non-deny outcomes, where a force-allow would suppress the
/// user's prompt.
fn format_context_only(msg: &str) -> String {
    let escaped = escape_json_string(msg);
    format!(
        r#"{{"hookSpecificOutput":{{"hookEventName":"PreToolUse","additionalContext":"{escaped}"}}}}"#
    )
}

fn format_claude_output(decision: &Decision) -> String {
    match decision {
        Decision::Deny { reason, .. } => format_deny(reason),
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

    #[test]
    fn schema_introspection_exempts_matching_strict_block() {
        let input = json!({
            "tool_input": {"command": "psql -h db.prod.internal -c \"\\d orders\""}
        });
        assert!(policy_block_exempt(HookVariant::ClaudePreBash, &input));
        assert!(policy_block_exempt(HookVariant::CodexPreBash, &input));

        let result = decide::evaluate_policy_verdicts(
            &[decide::PolicyVerdict {
                key: "policy:prod-query".into(),
                rule: "Inspect production schema first.".into(),
                requires_key: "schema:orders".into(),
                block: false,
                satisfied: false,
                stage: mati_core::store::PolicyStage::Enforce,
            }],
            true,
        );
        assert!(matches!(result.decision, Decision::Advisory { .. }));
    }

    #[test]
    fn schema_introspection_exemption_produces_no_shadow_observation() {
        let input = json!({
            "tool_input": {"command": "psql -h db.prod.internal -c \"\\d orders\""}
        });
        assert!(policy_block_exempt(HookVariant::ClaudePreBash, &input));
        assert!(policy_block_exempt(HookVariant::CodexPreBash, &input));
        let verdicts = policy_core_verdicts(
            &[mati_core::mcp::protocol::PolicyVerdict {
                key: "policy:prod-query".into(),
                stage: mati_core::store::PolicyStage::Shadow,
                mode: mati_core::store::PolicyMode::Block,
                rule: "Inspect production schema first.".into(),
                reason: "Schema drift matters.".into(),
                severity: mati_core::store::Priority::High,
                requires_key: "schema:orders".into(),
                satisfied: false,
                via: vec![],
                strict: true,
            }],
            true,
        );
        let result = decide::evaluate_policy_verdicts(&verdicts, true);
        assert_eq!(result.decision, Decision::Allow);
        assert!(!result
            .events
            .iter()
            .any(|event| matches!(event, HookEvent::PolicyShadowObserved { .. })));
        assert!(!result
            .events
            .iter()
            .any(|event| matches!(event, HookEvent::PolicyConsulted { .. })));
    }

    #[test]
    fn schema_introspection_exemption_preserves_satisfied_block() {
        let result = decide::evaluate_policy_verdicts(
            &[decide::PolicyVerdict {
                key: "policy:prod-query".into(),
                rule: "Inspect production schema first.".into(),
                requires_key: "schema:orders".into(),
                block: true,
                satisfied: true,
                stage: mati_core::store::PolicyStage::Enforce,
            }],
            true,
        );
        assert_eq!(result.decision, Decision::Allow);
        assert_eq!(
            result.events,
            vec![HookEvent::PolicyConsulted {
                key: "policy:prod-query".into()
            }]
        );
    }

    #[test]
    fn post_bash_success_gating_rejects_failures() {
        let command = "psql -c \"\\d orders\"";
        assert!(post_bash_succeeded(&json!({
            "tool_input": {"command": command},
            "tool_response": {"isError": false, "exit_code": 0}
        })));
        // The real Claude Code shape: no isError, no exit status.
        assert!(post_bash_succeeded(&json!({
            "tool_input": {"command": command},
            "tool_response": {
                "stdout": "Table \"public.inventory\"", "stderr": "",
                "interrupted": false, "isImage": false, "noOutputExpected": false
            }
        })));
        // exit_code alone is still honored when a payload carries it.
        assert!(post_bash_succeeded(&json!({
            "tool_input": {"command": command},
            "tool_response": {"exit_code": 0}
        })));
        for response in [
            json!({"isError": true}),
            json!({"is_error": true}),
            json!({"exit_code": 1}),
            json!({"exitCode": 2}),
            json!({"interrupted": true}),
            json!({"stdout": "x", "interrupted": true, "isImage": false}),
        ] {
            assert!(!post_bash_succeeded(&json!({
                "tool_input": {"command": command},
                "tool_response": response
            })));
        }
        assert!(!post_bash_succeeded(&json!({
            "tool_input": {"command": command}
        })));
    }

    #[test]
    fn post_bash_receipts_ignore_memget_only_policies() {
        assert!(!accepts_db_introspection(&[
            mati_core::store::ReceiptSource::MemGet
        ]));
        assert!(accepts_db_introspection(&[
            mati_core::store::ReceiptSource::DbIntrospection
        ]));
        assert!(accepts_db_introspection(&[
            mati_core::store::ReceiptSource::MemGet,
            mati_core::store::ReceiptSource::DbIntrospection,
        ]));
    }

    async fn assert_main_thread_receipt_is_global(key: &str) {
        crate::cli::ensure_test_home();
        let dir = tempfile::tempdir().unwrap();
        let store = mati_core::store::Store::open(dir.path()).await.unwrap();
        let actor = receipt_actor(None, Some("session-main"));
        let staged = mati_core::store::session::consultation_receipt_staged_for_store(
            &store, key, actor, false, None,
        )
        .await
        .unwrap();
        let (receipt_key, bytes) = (staged.key, staged.bytes);
        let receipt: mati_core::store::Record = rmp_serde::from_slice(&bytes).unwrap();
        store.put(&receipt_key, &receipt).await.unwrap();
        assert_eq!(receipt_key, format!("session:consulted:{key}"));
        assert!(
            mati_core::store::session::check_consulted_recent(&store, key, 900, None)
                .await
                .unwrap()
        );
        assert!(!mati_core::store::session::check_consulted_recent(
            &store,
            key,
            900,
            Some("session-main")
        )
        .await
        .unwrap());
    }

    /// Both mint paths derive their actor identically, so one test covers
    /// them. A session_id must not become receipt scope: the gate reads the
    /// global receipt for the main thread, so scoping by session would mint a
    /// receipt nothing ever checks and the policy would never unlock.
    #[tokio::test]
    async fn main_thread_receipt_uses_global_gate_scope() {
        assert_main_thread_receipt_is_global("schema:orders").await;
    }

    /// The other half: an agent_id is real scope, and its receipt must not
    /// satisfy the gate for anyone else.
    #[tokio::test]
    async fn subagent_receipt_stays_actor_scoped() {
        crate::cli::ensure_test_home();
        let dir = tempfile::tempdir().unwrap();
        let store = mati_core::store::Store::open(dir.path()).await.unwrap();
        let key = "schema:orders";
        let actor = receipt_actor(Some("agent-a"), Some("session-main"));
        assert_eq!(actor, Some("agent-a"));

        let staged = mati_core::store::session::consultation_receipt_staged_for_store(
            &store, key, actor, false, None,
        )
        .await
        .unwrap();
        let (receipt_key, bytes) = (staged.key, staged.bytes);
        let receipt: mati_core::store::Record = rmp_serde::from_slice(&bytes).unwrap();
        store.put(&receipt_key, &receipt).await.unwrap();
        assert_eq!(receipt_key, format!("session:consulted:agent-a:{key}"));

        assert!(mati_core::store::session::check_consulted_recent(
            &store,
            key,
            900,
            Some("agent-a")
        )
        .await
        .unwrap());
        assert!(!mati_core::store::session::check_consulted_recent(
            &store,
            key,
            900,
            Some("agent-b")
        )
        .await
        .unwrap());
        assert!(
            !mati_core::store::session::check_consulted_recent(&store, key, 900, None)
                .await
                .unwrap()
        );
    }

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

    // ── Event mapping ───────────────────────────────────────────────────
    //
    /// A Codex pre-hook block must be recorded as a BLOCK. The mapping sent it
    /// to `CodexShellMiss`, the post-bash hook's after-the-fact bypass event, so
    /// every Codex deny was logged as `bypass_detected` and Codex showed zero
    /// denials in `mati stats` and in the audit built on the chain.
    #[test]
    fn codex_pre_hook_block_maps_to_a_block_not_a_bypass() {
        use mati_core::mcp::protocol as p;
        let cmd = session_command(
            &HookEvent::CodexShellBlocked {
                key: "file:src/main.rs".into(),
            },
            None,
            None,
            None,
        )
        .expect("a block must be recorded");
        match cmd {
            p::Command::SessionLog(input) => assert_eq!(
                input.event,
                p::SessionEvent::CodexShellBlocked,
                "a pre-hook block is not the post-bash miss"
            ),
            other => panic!("expected SessionLog, got {other:?}"),
        }
    }

    /// The post-bash miss keeps its own event: nothing was denied there.
    #[test]
    fn codex_post_bash_miss_stays_a_miss() {
        use mati_core::mcp::protocol as p;
        // `run_post_bash` builds this event directly; pin the two apart.
        assert_ne!(
            p::SessionEvent::CodexShellMiss,
            p::SessionEvent::CodexShellBlocked
        );
    }

    /// The gate's decision basis and receipt scope must reach the daemon, or the
    /// chained event has nothing to record them from.
    #[test]
    fn gate_events_carry_the_basis_hash_and_receipt_scope() {
        use mati_core::mcp::protocol as p;
        let cmd = session_command(
            &HookEvent::BlockedUnconsultedRead {
                key: "file:src/main.rs".into(),
            },
            Some("sess-1"),
            Some("agent-a"),
            Some("deadbeef"),
        )
        .unwrap();
        match cmd {
            p::Command::SessionLog(input) => {
                assert_eq!(input.session_id.as_deref(), Some("sess-1"));
                assert_eq!(input.actor.as_deref(), Some("agent-a"));
                assert_eq!(input.decision_basis_hash.as_deref(), Some("deadbeef"));
            }
            other => panic!("expected SessionLog, got {other:?}"),
        }
    }

    #[test]
    fn decision_basis_hash_is_none_without_gotchas() {
        assert_eq!(decision_basis_hash(&HashMap::new()), None);
        let mut records = HashMap::new();
        records.insert(
            "gotcha:x".to_string(),
            json!({"value": "rule", "confidence": {"value": 0.8}}),
        );
        assert!(decision_basis_hash(&records).is_some());
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

    // ── extract_path: reject non-path shell tokens (miss aggregate pollution) ──
    //
    // Regression for live `analytics:miss_*` entries like
    // `"file:2>/dev/null": 7` and `"file:>>": 3` — the GrepLike extractor
    // took the last non-flag token, which can be a redirect fragment rather
    // than a real path. These must now be rejected as "not a file read op",
    // matching section 10.2's fallthrough for non-file commands.

    #[test]
    fn extract_path_rejects_stderr_redirect() {
        let input = json!({"tool_input": {"command": "grep pattern file.rs 2>/dev/null"}});
        assert_eq!(extract_path(&input, HookVariant::CodexPreBash), None);
    }

    #[test]
    fn extract_path_rejects_bare_append_redirect() {
        let input = json!({"tool_input": {"command": "grep pattern file.txt >>"}});
        assert_eq!(extract_path(&input, HookVariant::CodexPreBash), None);
    }

    #[test]
    fn extract_path_rejects_multiline_quoted_blob() {
        let input = json!({"tool_input": {"command": "grep -n \"pattern\nacross lines\""}});
        assert_eq!(extract_path(&input, HookVariant::CodexPreBash), None);
    }

    #[test]
    fn extract_path_still_accepts_real_path_with_digits() {
        // Guard against over-rejection: a real filename that starts with a
        // digit must not be caught by the redirect-fragment filter.
        let input = json!({"tool_input": {"command": "cat 2024-report.txt"}});
        assert_eq!(
            extract_path(&input, HookVariant::CodexPreBash),
            Some("2024-report.txt".into())
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
            origin: decide::DenyOrigin::Gotcha,
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
            origin: decide::DenyOrigin::Gotcha,
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
        let result = process_eval_response(HookVariant::CodexPreBash, "src/main.rs", &data, None);

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
        let result =
            process_eval_response(HookVariant::CodexPreApplyPatch, "src/main.rs", &data, None);

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
        let result =
            process_eval_response(HookVariant::CodexPreApplyPatch, "src/main.rs", &data, None);

        assert_eq!(result.exit_code, 0, "consulted edit must be allowed");
        assert!(!matches!(result.decision, Decision::Deny { .. }));
    }

    #[test]
    fn e2e_claude_deny_json_output_and_blocked_event() {
        let data = deny_eligible_eval_data();
        let result = process_eval_response(HookVariant::ClaudePreBash, "src/main.rs", &data, None);

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
        let result = process_eval_response(HookVariant::CodexPreBash, "src/lib.rs", &data, None);

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
        let result = process_eval_response(HookVariant::ClaudePreRead, "src/lib.rs", &data, None);

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
        let result = process_eval_response(HookVariant::CodexPreBash, "src/main.rs", &data, None);

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
        let result = process_eval_response(HookVariant::ClaudePreRead, "src/main.rs", &data, None);

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
        let result = process_eval_response(HookVariant::CodexPreBash, "src/main.rs", &data, None);

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
        let result = process_eval_response(HookVariant::ClaudePreBash, "src/main.rs", &data, None);

        assert_eq!(result.exit_code, 0, "gotcha error must fail open");
        assert!(
            result.stdout.is_empty(),
            "Bash fail-open must DEFER (empty stdout), never force-allow — \
             Bash is permission-required; got: {}",
            result.stdout
        );
        assert_eq!(result.decision, Decision::Allow);
    }

    // ── Outer deadline wrapper ──────────────────────────────────────────
    //
    // Mirrors the production wrapper in `run()`: when the inner future
    // exceeds the deadline, the wrapper must produce an allow output and
    // return an explicit termination outcome. We can't drive the real `run()`
    // from a unit test (it reads stdin and may spawn daemons), so we test the
    // deadline shape directly using the same `tokio::time::timeout` +
    // `emit_allow` path the production code takes.

    async fn run_with_deadline<F>(
        deadline_ms: u64,
        variant: HookVariant,
        inner: F,
    ) -> Result<HookRunOutcome>
    where
        F: std::future::Future<Output = Result<()>>,
    {
        match tokio::time::timeout(Duration::from_millis(deadline_ms), inner).await {
            Ok(inner_result) => inner_result.map(|()| HookRunOutcome::Continue),
            Err(_elapsed) => {
                // Match the production wrapper exactly. We don't write to
                // the real fail_open.log here — production code does, and
                // testing that side effect would require touching the home
                // dir. The load-bearing assertion is "completes within
                // budget + emits allow + requests termination", not "wrote
                // to disk".
                emit_allow(variant);
                Ok(HookRunOutcome::Terminate(0))
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

        // The wrapper must absorb the timeout into an explicit allow-and-exit
        // outcome without exiting the unit-test process.
        assert!(
            matches!(result, Ok(HookRunOutcome::Terminate(0))),
            "deadline wrapper must request allow exit on timeout, got: {result:?}"
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

        // The production wrapper calls `emit_allow(variant)` on timeout and
        // uses exit code 0, which is allow for both hook protocols.
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
    fn daemon_data_rejects_error_envelope() {
        // The client wraps daemon-side errors (backpressure, session
        // mismatch, handler failure) as DaemonResult::Ok({"ok": false}).
        // The gate must treat those as eval failures — evaluating the
        // missing `data` as Null would record a false Miss.
        let ok = json!({"ok": true, "v": 2, "data": {"consulted": true}});
        assert_eq!(
            daemon_data(&ok),
            Some(json!({"consulted": true})),
            "ok envelope must yield its data"
        );
        let err = json!({"ok": false, "v": 2, "error": "backpressure", "code": "backpressure"});
        assert!(
            daemon_data(&err).is_none(),
            "error envelope must not evaluate as data"
        );
        assert!(daemon_data(&json!({"v": 2})).is_none());
    }

    // ── Coverage-widening guard ─────────────────────────────────────────
    //
    // `permissionDecision:"allow"` bypasses Claude Code's permission system.
    // Only the read gate (Read/Glob/Grep — no-permission tools) may ever emit
    // it. If this test fails, a change has reintroduced the Bash/edit
    // permission-prompt bypass.

    #[test]
    fn only_pre_read_force_allows() {
        use HookVariant::*;
        for variant in [
            ClaudePreRead,
            ClaudePreEdit,
            ClaudePreBash,
            CodexPreBash,
            CodexPostBash,
            CodexPreApplyPatch,
            ClaudePostMemGet,
            ClaudePostBash,
        ] {
            // 1. The fail-open / no-path allow output.
            match variant {
                ClaudePreRead => assert!(
                    allow_output(variant).is_some(),
                    "read gate keeps its no-op allow"
                ),
                _ => assert!(
                    allow_output(variant).is_none(),
                    "{variant:?} must DEFER on allow — force-allow would bypass \
                     the user's permission prompt"
                ),
            }
            // 2. Every non-deny decision outcome.
            let non_deny_decisions = [
                Decision::Allow,
                Decision::NoRecord,
                Decision::Tombstone,
                Decision::AlreadyConsulted {
                    context: "ctx".into(),
                },
                Decision::Advisory {
                    context: "ctx".into(),
                },
                Decision::Liability {
                    staleness: 0.9,
                    context: "ctx".into(),
                },
            ];
            for decision in &non_deny_decisions {
                let (stdout, _, _) = format_decision(variant, decision, "src/x.rs");
                if variant != ClaudePreRead {
                    assert!(
                        !stdout.contains(r#""permissionDecision":"allow""#),
                        "{variant:?} emitted a force-allow for {decision:?}: {stdout}"
                    );
                }
            }
        }
    }

    #[test]
    fn policy_bash_output_denies_or_injects_without_force_allow() {
        let deny = Decision::Deny {
            file_key: "policy:prod-query".into(),
            reason: "mati: policy policy:prod-query blocked this action. Consult first: mem_get(\"schema:orders\")".into(),
            origin: decide::DenyOrigin::Policy,
        };
        let (stdout, _, _) = format_decision(HookVariant::ClaudePreBash, &deny, "<policy>");
        assert!(stdout.contains(r#""permissionDecision":"deny""#));
        assert!(stdout.contains("policy:prod-query"));
        assert!(stdout.contains("schema:orders"));

        let steer = Decision::Advisory {
            context: "Consult the schema first.".into(),
        };
        let (stdout, _, _) = format_decision(HookVariant::ClaudePreBash, &steer, "<policy>");
        assert!(stdout.contains("additionalContext"));
        assert!(!stdout.contains("permissionDecision"));
    }

    #[test]
    fn codex_db_client_policy_gates_cover_fileless_file_bearing_and_introspection() {
        let deny_verdict = decide::PolicyVerdict {
            key: "policy:prod-query".into(),
            rule: "Consult the schema first.".into(),
            requires_key: "schema:orders".into(),
            block: true,
            satisfied: false,
            stage: mati_core::store::PolicyStage::Enforce,
        };

        let fileless =
            decide::normalize_action(Some("psql -h db.prod.internal -c \"select 1\""), None);
        let file_bearing = decide::normalize_action(
            Some("psql -h db.prod.internal -f migrations/prod.sql"),
            None,
        );
        assert_eq!(fileless.tool, "db_client");
        assert!(fileless.files.is_empty());
        assert_eq!(file_bearing.tool, "db_client");
        assert_eq!(file_bearing.files, vec!["migrations/prod.sql"]);

        for action in [fileless, file_bearing] {
            assert_eq!(action.host.as_deref(), Some("db.prod.internal"));
            let result =
                decide::evaluate_policy_verdicts(std::slice::from_ref(&deny_verdict), true);
            let (stdout, stderr, exit_code) =
                format_decision(HookVariant::CodexPreBash, &result.decision, "<policy>");
            assert!(stdout.is_empty());
            assert!(stderr.starts_with("mati:"));
            assert_eq!(exit_code, 2);
        }

        let introspection_input = json!({
            "tool_input": {"command": "psql -h db.prod.internal -c \"\\d orders\""}
        });
        assert!(policy_block_exempt(
            HookVariant::CodexPreBash,
            &introspection_input
        ));
        let mut exempt_verdict = deny_verdict;
        exempt_verdict.block = false;
        let steered = decide::evaluate_policy_verdicts(std::slice::from_ref(&exempt_verdict), true);
        let (stdout, stderr, exit_code) =
            format_decision(HookVariant::CodexPreBash, &steered.decision, "<policy>");
        assert!(stdout.is_empty());
        assert!(stderr.is_empty());
        assert_eq!(exit_code, 0);
    }

    #[test]
    fn claude_pre_edit_context_never_force_allows() {
        let outcomes = [
            Decision::AlreadyConsulted {
                context: "Already consulted.".into(),
            },
            Decision::Advisory {
                context: "Consult the schema first.".into(),
            },
            Decision::Liability {
                staleness: 0.8,
                context: "This record is stale.".into(),
            },
            Decision::Allow,
            Decision::NoRecord,
            Decision::Tombstone,
            Decision::NotFileRead,
        ];
        for decision in outcomes {
            let (stdout, _, _) = format_decision(HookVariant::ClaudePreEdit, &decision, "x.sql");
            assert!(!stdout.contains(r#""permissionDecision":"allow""#));
        }

        let (stdout, _, _) = format_decision(
            HookVariant::ClaudePreEdit,
            &Decision::Advisory {
                context: "Consult first.".into(),
            },
            "x.sql",
        );
        assert!(stdout.contains("additionalContext"));
        assert!(!stdout.contains("permissionDecision"));
    }

    #[test]
    fn file_gate_and_policy_merge_escalate_only() {
        let mut adapter = AdapterResult {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: 0,
            events: vec![HookEvent::Hit {
                key: "file:prod.sql".into(),
            }],
            decision: Decision::Advisory {
                context: "File guidance.".into(),
            },
            basis_hash: None,
        };
        merge_policy_result(
            &mut adapter,
            HookVariant::ClaudePreBash,
            Decision::Advisory {
                context: "Consult the schema first.".into(),
            },
            vec![HookEvent::PolicyConsulted {
                key: "policy:prod-query".into(),
            }],
        );
        assert_eq!(
            adapter.decision,
            Decision::Advisory {
                context: "File guidance.\nConsult the schema first.".into(),
            }
        );
        assert_eq!(adapter.events.len(), 2);
        assert!(adapter.stdout.contains("additionalContext"));
        assert!(!adapter.stdout.contains("permissionDecision"));

        merge_policy_result(
            &mut adapter,
            HookVariant::ClaudePreBash,
            Decision::Deny {
                file_key: "policy:prod-query".into(),
                reason: "policy denied".into(),
                origin: decide::DenyOrigin::Policy,
            },
            vec![HookEvent::PolicyConsultBlocked {
                key: "policy:prod-query".into(),
            }],
        );
        assert!(matches!(adapter.decision, Decision::Deny { .. }));
        assert!(adapter.stdout.contains(r#""permissionDecision":"deny""#));

        let mut edit_adapter = AdapterResult {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: 0,
            events: vec![],
            decision: Decision::NoRecord,
            basis_hash: None,
        };
        merge_policy_result(
            &mut edit_adapter,
            HookVariant::ClaudePreEdit,
            Decision::Advisory {
                context: "Edit policy guidance.".into(),
            },
            vec![],
        );
        assert!(edit_adapter.stdout.contains("additionalContext"));
        assert!(!edit_adapter.stdout.contains("permissionDecision"));

        edit_adapter.decision = Decision::Deny {
            file_key: "file:x.sql".into(),
            reason: "gotcha denied".into(),
            origin: decide::DenyOrigin::Gotcha,
        };
        merge_policy_result(
            &mut edit_adapter,
            HookVariant::ClaudePreEdit,
            Decision::Advisory {
                context: "Must not lower the edit deny.".into(),
            },
            vec![],
        );
        assert!(matches!(edit_adapter.decision, Decision::Deny { .. }));
        assert!(edit_adapter
            .stdout
            .contains(r#""permissionDecision":"deny""#));

        let mut edit_consulted = AdapterResult {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: 0,
            events: vec![],
            decision: Decision::AlreadyConsulted {
                context: "Record already consulted. Gotcha guidance.".into(),
            },
            basis_hash: None,
        };
        merge_policy_result(
            &mut edit_consulted,
            HookVariant::ClaudePreEdit,
            Decision::Advisory {
                context: "Policy rule for this edit.".into(),
            },
            vec![],
        );
        assert!(matches!(edit_consulted.decision, Decision::Advisory { .. }));
        assert!(edit_consulted.stdout.contains("Policy rule for this edit."));
        assert!(edit_consulted.stdout.contains("additionalContext"));
        assert!(!edit_consulted.stdout.contains("permissionDecision"));
        assert!(!edit_consulted.stdout.contains("Record already consulted"));

        let mut bash_consulted = AdapterResult {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: 0,
            events: vec![],
            decision: Decision::AlreadyConsulted {
                context: "Record already consulted. Gotcha guidance.".into(),
            },
            basis_hash: None,
        };
        merge_policy_result(
            &mut bash_consulted,
            HookVariant::ClaudePreBash,
            Decision::Advisory {
                context: "Policy rule for this command.".into(),
            },
            vec![],
        );
        assert!(matches!(
            bash_consulted.decision,
            Decision::AlreadyConsulted { ref context }
                if context.contains("Record already consulted")
                    && context.contains("Policy rule for this command.")
        ));
        assert!(bash_consulted
            .stdout
            .contains("Record already consulted. Gotcha guidance."));
        assert!(bash_consulted
            .stdout
            .contains("Policy rule for this command."));
    }

    #[test]
    fn e2e_claude_pre_bash_defers_no_record() {
        // A bash command touching a file with no record must DEFER — empty
        // stdout, so the user's Bash permission prompt is preserved.
        let data = json!({
            "file_key": "file:src/new.rs",
            "file_record": null,
            "gotcha_records": {},
            "consulted": false,
            "consulted_recent": false,
            "store_error": false,
            "gotcha_error": false
        });
        let result = process_eval_response(HookVariant::ClaudePreBash, "src/new.rs", &data, None);

        assert_eq!(result.exit_code, 0);
        assert!(
            result.stdout.is_empty(),
            "no-record bash read must defer, got: {}",
            result.stdout
        );
        assert!(matches!(result.decision, Decision::NoRecord));
    }

    #[test]
    fn e2e_claude_pre_bash_advisory_injects_context_without_permission_decision() {
        // Advisory on the bash path: context is injected via additionalContext
        // ONLY — no permissionDecision field at all, so the permission flow
        // proceeds normally.
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
        let result = process_eval_response(HookVariant::ClaudePreBash, "src/lib.rs", &data, None);

        assert_eq!(result.exit_code, 0);
        let json: serde_json::Value =
            serde_json::from_str(&result.stdout).expect("stdout must be valid JSON");
        assert!(
            json.pointer("/hookSpecificOutput/permissionDecision")
                .is_none(),
            "bash advisory must NOT carry a permissionDecision, got: {}",
            result.stdout
        );
        assert!(
            json.pointer("/hookSpecificOutput/additionalContext")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .contains("[mati]"),
            "bash advisory must inject context, got: {}",
            result.stdout
        );
        assert!(matches!(result.decision, Decision::Advisory { .. }));
    }

    #[test]
    fn e2e_claude_pre_bash_deny_still_denies() {
        // The defer change must not weaken the deny: a confirmed unconsulted
        // gotcha on the bash path still emits permissionDecision:"deny".
        let data = deny_eligible_eval_data();
        let result = process_eval_response(HookVariant::ClaudePreBash, "src/main.rs", &data, None);

        let json: serde_json::Value =
            serde_json::from_str(&result.stdout).expect("stdout must be valid JSON");
        assert_eq!(
            json.pointer("/hookSpecificOutput/permissionDecision")
                .and_then(|v| v.as_str()),
            Some("deny")
        );
    }

    #[test]
    fn escape_json_string_escapes_control_chars() {
        // All of U+0000–U+001F must be escaped, not just \n \r \t — an
        // unescaped control char makes the deny JSON unparseable (lost deny).
        let hostile = "a\u{08}b\u{0C}c\u{1B}d\"e\\f\ng";
        let escaped = escape_json_string(hostile);
        let wrapped = format!("{{\"v\":\"{escaped}\"}}");
        let parsed: serde_json::Value =
            serde_json::from_str(&wrapped).expect("escaped output must be valid inside JSON");
        assert_eq!(parsed.pointer("/v").and_then(|v| v.as_str()), Some(hostile));
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
        let result = process_eval_response(HookVariant::ClaudePreRead, "src/new.rs", &data, None);

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
    fn edit_policy_actions_use_the_path_category_and_target() {
        let action = decide::normalize_action(None, Some("migrations/prod.sql"));
        assert_eq!(action.tool, "path");
        assert_eq!(action.target_path.as_deref(), Some("migrations/prod.sql"));
        assert_eq!(action.files, vec!["migrations/prod.sql"]);
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
        let result = process_eval_response(HookVariant::ClaudePreEdit, "src/main.rs", &data, None);

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
        // The message now comes from the decision's own reason (like the read gate), so it
        // instructs the agent to consult; the edit-vs-read distinction lives in the event below
        // (EditBlocked → `edit_blocked_unconsulted`), not the message wording.
        assert!(
            json.pointer("/hookSpecificOutput/permissionDecisionReason")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .contains("mem_get"),
            "deny reason must instruct the agent to consult, got: {}",
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
        // Codex apply_patch edit gate), the edit keeps its normal permission
        // flow and defers silently — deliberately NOT a forced allow.
        let mut data = deny_eligible_eval_data();
        data["consulted_recent"] = json!(true);
        let result = process_eval_response(HookVariant::ClaudePreEdit, "src/main.rs", &data, None);

        assert_eq!(result.exit_code, 0);
        assert!(result.stdout.is_empty());
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
        let result = process_eval_response(HookVariant::ClaudePreEdit, "src/new.rs", &data, None);

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
        let result = process_eval_response(HookVariant::ClaudePreEdit, "src/main.rs", &data, None);

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
            basis_hash: None,
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
    fn mandate_pre_edit_deny_uses_org_policy_message() {
        let g = phi_globs();
        let mut a = allow_adapter();
        apply_consult_mandate(
            &mut a,
            HookVariant::ClaudePreEdit,
            "phi/records.rs",
            false,
            Some(&g),
        );
        assert!(matches!(a.decision, Decision::Deny { .. }));
        assert!(
            a.stdout.contains("deny") && a.stdout.contains("Org policy"),
            "pre-edit mandate deny must show the org-policy reason, not 'Confirmed gotcha'; got {}",
            a.stdout
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
    fn mandate_applies_to_apply_patch_variant() {
        // Parity: the enterprise consult mandate gates Codex apply_patch edits
        // exactly like reads/edits — deny with exit 2 + mem_get instruction.
        let g = phi_globs();
        let mut a = allow_adapter();
        apply_consult_mandate(
            &mut a,
            HookVariant::CodexPreApplyPatch,
            "phi/records.rs",
            false,
            Some(&g),
        );
        assert!(matches!(a.decision, Decision::Deny { .. }));
        assert_eq!(a.exit_code, 2, "apply_patch mandate deny must exit 2");
        assert!(
            a.stderr.contains("mem_get"),
            "apply_patch mandate deny must instruct consultation, got: {}",
            a.stderr
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
                origin: decide::DenyOrigin::Gotcha,
            },
            basis_hash: None,
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
