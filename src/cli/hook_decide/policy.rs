use super::*;

/// Evaluate local policies for a governed, fileless Bash command.
///
/// This is deliberately separate from the file-gate path: file-bearing DB
/// commands continue through the existing gotcha flow until policy/file-gate
/// composition is specified.
pub(crate) async fn run_fileless_policy(
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
    let worktree = mati_core::store::session::worktree_scope_tag(&cwd);
    let actor_scope =
        mati_core::store::session::combined_actor_scope(worktree.as_deref(), agent_id);
    let Some((decision, events)) = evaluate_governed_policy(
        Some(&mati_root),
        action,
        "db_client",
        actor_scope.as_deref(),
        "<fileless-bash>",
        input
            .pointer("/tool_input/command")
            .and_then(|value| value.as_str()),
        PolicyEvaluationOptions {
            introspection_exemption: policy_block_exempt(variant, input),
            codex_agent: matches!(
                variant,
                HookVariant::CodexPreBash | HookVariant::CodexPreApplyPatch
            ),
        },
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
    fire_events(
        &mati_root,
        &events,
        session_id,
        agent_id,
        actor_scope.as_deref(),
        None,
    )
    .await;
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
#[derive(Clone, Copy)]
pub(crate) struct PolicyEvaluationOptions {
    pub(super) introspection_exemption: bool,
    pub(super) codex_agent: bool,
}

pub(crate) async fn evaluate_governed_policy(
    mati_root: Option<&Path>,
    action: &decide::Action,
    governed_tool: &str,
    actor_scope: Option<&str>,
    failure_path: &str,
    raw_command: Option<&str>,
    options: PolicyEvaluationOptions,
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
        policy_verdicts_for_action(mati_root, action, actor_scope, failure_path, raw_command)
            .await?;
    let strict = evaluation.verdicts.iter().any(|verdict| verdict.strict);
    let core_verdicts = policy_core_verdicts(
        &evaluation.verdicts,
        options.introspection_exemption,
        options.codex_agent,
    );
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

pub(crate) fn policy_core_verdicts(
    verdicts: &[mati_core::mcp::protocol::PolicyVerdict],
    introspection_exemption: bool,
    codex_agent: bool,
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
            let no_accepted_sources = verdict.via.is_empty();
            let codex_unfulfillable = codex_agent
                && !verdict
                    .via
                    .iter()
                    .any(|source| mati_core::store::CODEX_PRODUCIBLE_SOURCES.contains(source));
            let unfulfillable = matches!(verdict.stage, mati_core::store::PolicyStage::Enforce)
                && matches!(verdict.mode, mati_core::store::PolicyMode::Block)
                && (no_accepted_sources || codex_unfulfillable);
            Some(decide::PolicyVerdict {
                key: verdict.key.clone(),
                rule: if unfulfillable {
                    let accepted = if no_accepted_sources {
                        "no sources".to_string()
                    } else {
                        verdict
                            .via
                            .iter()
                            .map(|source| format!("{source:?}"))
                            .collect::<Vec<_>>()
                            .join(", ")
                    };
                    if no_accepted_sources {
                        format!(
                            concat!(
                                "mati: policy {} cannot be satisfied because requires.via accepts {}; ",
                                "this policy is steering only here"
                            ),
                            verdict.key, accepted
                        )
                    } else {
                        format!(
                            concat!(
                                "mati: policy {} cannot be satisfied in Codex because it accepts only {}; ",
                                "Codex can mint mem_get and hook_context receipts but cannot attest ",
                                "to those sources, so this policy is steering only here"
                            ),
                            verdict.key, accepted
                        )
                    }
                } else {
                    verdict.rule.clone()
                },
                requires_key: verdict.requires_key.clone(),
                block: matches!(verdict.mode, mati_core::store::PolicyMode::Block)
                    && !unfulfillable
                    && (!introspection_exemption || verdict.satisfied),
                satisfied: verdict.satisfied,
                stage: verdict.stage,
                // H1: the content outcome is carried verbatim and is deliberately
                // NOT gated by `introspection_exemption` — the exemption is the
                // remedy for a consult gate, meaningless for a content
                // restriction. Block vs steer was already folded in by the
                // daemon (Deny vs Warn).
                content: verdict.content,
                // Allowlist mirror, same H1 reasoning — carried verbatim, not
                // gated by the introspection exemption.
                require_content: verdict.require_content,
            })
        })
        .collect()
}

pub(crate) async fn policy_verdicts_for_action(
    mati_root: &Path,
    action: &decide::Action,
    actor_scope: Option<&str>,
    failure_path: &str,
    raw_command: Option<&str>,
) -> Option<mati_core::mcp::protocol::PolicyEvaluateResult> {
    let response = daemon_v2(
        mati_root,
        mati_core::mcp::protocol::Command::PolicyEvaluate(
            mati_core::mcp::protocol::PolicyEvaluateInput {
                action: action.clone(),
                actor: actor_scope.map(str::to_string),
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
pub(crate) fn policy_block_exempt(variant: HookVariant, input: &serde_json::Value) -> bool {
    matches!(
        variant,
        HookVariant::ClaudePreBash | HookVariant::CodexPreBash
    ) && input
        .pointer("/tool_input/command")
        .and_then(|value| value.as_str())
        .is_some_and(decide::is_schema_introspection)
}

/// Merge a policy result into the existing file-gate result without lowering it.
pub(crate) fn merge_policy_result(
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
