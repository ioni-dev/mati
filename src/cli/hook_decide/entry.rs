use super::*;

// ── Public types ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum HookVariant {
    /// Claude Code `ConfigChange`: verify mati's registrations in the new
    /// settings content and use the platform's top-level decision object.
    #[value(name = "claude-config-change")]
    ClaudeConfigChange,
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

    if args.variant == HookVariant::ClaudeConfigChange {
        return run_config_change(&input).await;
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
                raw_command,
                PolicyEvaluationOptions {
                    introspection_exemption: policy_block_exempt(args.variant, &input),
                    codex_agent: matches!(
                        args.variant,
                        HookVariant::CodexPreBash | HookVariant::CodexPreApplyPatch
                    ),
                },
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
