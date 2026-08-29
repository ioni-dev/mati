use super::*;

// ── Fail-open telemetry ─────────────────────────────────────────────────────

pub(crate) fn log_fail_open(rel_path: &str, reason: &str) {
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
pub(crate) fn log_fail_open_at(log_path: &Path, rel_path: &str, reason: &str) {
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
pub(crate) fn platform_events(
    variant: HookVariant,
    decision: &Decision,
    events: Vec<HookEvent>,
) -> Vec<HookEvent> {
    match variant {
        HookVariant::ClaudeConfigChange => Vec::new(),
        HookVariant::CodexPreBash | HookVariant::CodexPreApplyPatch => events
            .into_iter()
            .filter_map(|e| match e {
                HookEvent::Miss { .. } => Some(e),
                HookEvent::BlockedUnconsultedRead { key } => {
                    Some(HookEvent::CodexShellBlocked { key })
                }
                // Same translation, for the same reason: the audit chain
                // attributes the deny to `codex`, and only SessionEvent tells
                // it which platform blocked. The lockdown's own reason code is
                // the cost; mis-attributing the agent would be the worse one.
                HookEvent::LockdownBlocked { key } => Some(HookEvent::CodexShellBlocked { key }),
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
        | HookVariant::ClaudePostBash
        | HookVariant::ClaudePostTask
        | HookVariant::ClaudeInstructionsLoaded
        | HookVariant::ClaudeFileChanged => {
            // Post-bash, post-memget, and post-task use their own flows — should
            // not reach here.
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
                HookEvent::PolicyContentBlocked { key } => {
                    Some(HookEvent::PolicyContentBlocked { key })
                }
                HookEvent::PolicyRequirementBlocked { key } => {
                    Some(HookEvent::PolicyRequirementBlocked { key })
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

pub(crate) async fn fire_events(
    mati_root: &Path,
    events: &[HookEvent],
    session_id: Option<&str>,
    agent_id: Option<&str>,
    actor_scope: Option<&str>,
    basis_hash: Option<&str>,
) {
    for event in events {
        let Some(cmd) = session_command(event, session_id, agent_id, actor_scope, basis_hash)
        else {
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
///
/// `agent_id` and `actor_scope` diverge on purpose: `agent_id` is bare
/// subagent attribution (who), `actor_scope` is the worktree-combined
/// receipt/gate scope (where the evaluation looked). Conflating them would
/// stamp a worktree hash into the audit trail's human-readable agent field.
pub(crate) fn session_command(
    event: &HookEvent,
    session_id: Option<&str>,
    agent_id: Option<&str>,
    actor_scope: Option<&str>,
    basis_hash: Option<&str>,
) -> Option<mati_core::mcp::protocol::Command> {
    use mati_core::mcp::protocol as p;
    // Per-actor audit attribution (schema_version 2): tag each SessionLog with the
    // agent session that triggered it, when the platform provides one.
    let sid = || session_id.map(str::to_string);
    // Receipt scope, so the daemon can find the receipt that authorized an allow,
    // and the digest of the gotcha state this decision was made on.
    let scope = || actor_scope.map(str::to_string);
    let basis = || basis_hash.map(str::to_string);
    Some(match event {
        // Receipt scope must match the evaluation scope: the gate was
        // queried with `actor = actor_scope`, so the receipt minted here is
        // scoped the same way. A subagent's Advisory hit must NOT mint a
        // global receipt — receipts are strictly key-scoped in the store
        // (no actor↔global fallback), and a global receipt would satisfy
        // the main thread's gate for context only the subagent received.
        HookEvent::Hit { key } => p::Command::ConsultationHit(p::ConsultationHitInput {
            key: key.clone(),
            capture_fingerprint: true,
            actor: scope(),
            session_id: sid(),
            agent_id: agent_id.map(str::to_string),
            decision_basis_hash: basis(),
            // The hook pushed the record into the agent's context. Preserve
            // that provenance so policies can distinguish it from mem_get.
            source: Some(mati_core::store::ReceiptSource::HookContext),
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
        HookEvent::LockdownBlocked { key } => p::Command::SessionLog(p::SessionLogInput {
            event: p::SessionEvent::LockdownBlocked,
            key: key.clone(),
            session_id: sid(),
            actor: scope(),
            // The lockdown decides on session state, not on the file's gotchas.
            decision_basis_hash: None,
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
        HookEvent::PolicyContentBlocked { key } => p::Command::SessionLog(p::SessionLogInput {
            event: p::SessionEvent::PolicyContentMiss,
            key: key.clone(),
            session_id: sid(),
            actor: scope(),
            decision_basis_hash: None,
        }),
        HookEvent::PolicyRequirementBlocked { key } => p::Command::SessionLog(p::SessionLogInput {
            event: p::SessionEvent::PolicyRequirementMiss,
            key: key.clone(),
            session_id: sid(),
            actor: scope(),
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

/// The no-op allow JSON for the Claude read gate and ConfigChange's separate
/// top-level allow shape. Only the read gate uses the permissionDecision
/// wrapper below.
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
pub(crate) fn allow_output(variant: HookVariant) -> Option<&'static str> {
    match variant {
        HookVariant::ClaudeConfigChange => Some(r#"{"decision":"allow"}"#),
        HookVariant::ClaudePreRead => Some(
            r#"{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}"#,
        ),
        HookVariant::ClaudePreBash
        | HookVariant::CodexPreBash
        | HookVariant::CodexPostBash
        | HookVariant::CodexPreApplyPatch
        | HookVariant::ClaudePreEdit
        | HookVariant::ClaudePostMemGet
        | HookVariant::ClaudePostBash
        | HookVariant::ClaudePostTask
        | HookVariant::ClaudeInstructionsLoaded
        | HookVariant::ClaudeFileChanged => None,
    }
}

pub(crate) fn emit_allow(variant: HookVariant) {
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
pub(crate) fn daemon_data(resp: &serde_json::Value) -> Option<serde_json::Value> {
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
pub(crate) fn escape_json_string(s: &str) -> String {
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
pub(crate) struct AdapterResult {
    /// Platform-specific stdout (JSON for Claude, empty for Codex allow).
    pub(super) stdout: String,
    /// Platform-specific stderr (only Codex deny).
    pub(super) stderr: String,
    /// Exit code (2 for Codex deny, 0 otherwise).
    pub(super) exit_code: i32,
    /// Events to fire (already platform-filtered).
    pub(super) events: Vec<HookEvent>,
    /// Digest of the gotcha state this decision was made on, stamped onto the
    /// enforcement events as `decision_basis_hash`. `None` when the file has
    /// no gotchas — there is no rule state to prove.
    pub(super) basis_hash: Option<String>,
    /// The semantic decision (used by tests via Debug).
    #[allow(dead_code)]
    pub(super) decision: Decision,
}

// ── Floor consult mandate (enterprise governance overlay) ────────────────────

/// Compile the enterprise floor's signed consult-required globs, supplied out-of-band via
/// `MATI_CONSULT_GLOBS` (a JSON array of glob strings, e.g. `["phi/**","src/payments/**"]`).
///
/// A NEUTRAL primitive: OSS enforces per-actor consultation on whatever globs it is handed;
/// verifying the signed floor that produced them is the caller's job (mati-cloud). Returns
/// `None` (no mandate) when unset, empty, or unparseable — fail-open, matching the hook posture.
pub(crate) fn consult_globset() -> Option<GlobSet> {
    consult_globset_from(&std::env::var("MATI_CONSULT_GLOBS").ok()?)
}

/// The actor's consultation status from a `hook_evaluate` bundle: the recent-TTL flag for
/// edit/shell gates, the persistent flag otherwise (mirrors `check_eval_data`).
pub(crate) fn consulted_flag(eval_data: &serde_json::Value, include_recent: bool) -> bool {
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
pub(crate) fn consult_globset_from(raw: &str) -> Option<GlobSet> {
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
pub(crate) fn apply_consult_mandate(
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
pub(crate) enum EvalDataCheck {
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
pub(crate) fn check_eval_data(
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
pub(crate) fn process_eval_response(
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
pub(crate) fn decision_basis_hash(records: &HashMap<String, serde_json::Value>) -> Option<String> {
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
pub(crate) fn format_decision(
    variant: HookVariant,
    decision: &Decision,
    _rel_path: &str,
) -> (String, String, i32) {
    match variant {
        HookVariant::ClaudeConfigChange => (String::new(), String::new(), 0),
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
                    // The lockdown reason names both the owed file and the
                    // `mem_get` that lifts it; the bare form would lose why a
                    // command that touched nothing governed was denied.
                    decide::DenyOrigin::Policy
                    | decide::DenyOrigin::PolicyContentDenied
                    | decide::DenyOrigin::PolicyRequirementUnmet
                    | decide::DenyOrigin::SessionLockdown => reason.clone(),
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
        | HookVariant::ClaudePostBash
        | HookVariant::ClaudePostTask
        | HookVariant::ClaudeInstructionsLoaded
        | HookVariant::ClaudeFileChanged => (String::new(), String::new(), 0),
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
