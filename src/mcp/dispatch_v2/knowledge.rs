//! Knowledge-side native mutation handlers (gotcha/decision/dev_note + policy write/evaluate).

use super::*;

// ── Knowledge-side native handlers ──────────────────────────────────────────
//
// These handlers use typed DTOs, validate input, and commit mutation+audit
// atomically in a single transact_knowledge call.

pub(super) async fn dispatch_knowledge_mutation(
    graph: &Arc<tokio::sync::RwLock<Graph>>,
    ctx: &RequestContext,
    req: &Request,
) -> Response {
    use crate::mcp::handlers;

    let g = graph.read().await;
    let store = g.store();
    let request_id = req.id;

    let result = match &req.cmd {
        Command::GotchaUpsert(input) => {
            handlers::handle_gotcha_upsert(store, ctx, request_id, input).await
        }
        Command::GotchaConfirm(input) => {
            handlers::handle_gotcha_confirm(store, ctx, request_id, input).await
        }
        Command::GotchaTombstone(input) => {
            handlers::handle_gotcha_tombstone(store, ctx, request_id, input).await
        }
        Command::PolicyWrite(_) => {
            unreachable!("PolicyWrite uses the policy_ops dispatcher")
        }
        Command::FileEnrich(input) => {
            handlers::handle_file_enrich(store, ctx, request_id, input).await
        }
        Command::FileReparse(input) => {
            handlers::handle_file_reparse(store, ctx, request_id, input, &ctx.repo_root).await
        }
        Command::DocCapture(input) => {
            handlers::handle_doc_capture(store, ctx, request_id, input, &ctx.repo_root).await
        }
        Command::DecisionUpsert(input) => {
            handlers::handle_decision_upsert(store, ctx, request_id, input).await
        }
        Command::DevNoteUpsert(input) => {
            handlers::handle_dev_note_upsert(store, ctx, request_id, input).await
        }
        Command::RecordImport(input) => {
            handlers::handle_record_import(store, ctx, request_id, input).await
        }
        _ => {
            unreachable!("is_knowledge_mutation guard ensures only knowledge mutations reach here")
        }
    };

    match result {
        Ok(data) => Response::ok(request_id, data),
        Err((code, message)) => {
            // Write rejected-mutation audit (still atomic — rejection means
            // no mutation record, so audit is a standalone knowledge write).
            if let Some((audit_key, audit_bytes)) = handlers::make_audit(
                ctx,
                request_id,
                req.cmd.kind(),
                req.cmd.target_key(),
                false,
                Some(code.clone()),
            ) {
                let _ = store.put_raw(&audit_key, &audit_bytes).await;
            }
            Response::err(request_id, code, message)
        }
    }
}

pub(super) async fn dispatch_policy_write(
    graph: &Arc<tokio::sync::RwLock<Graph>>,
    ctx: &RequestContext,
    req: &Request,
) -> Response {
    let Command::PolicyWrite(input) = &req.cmd else {
        unreachable!("dispatch_policy_write only accepts PolicyWrite")
    };
    let g = graph.read().await;
    let store = g.store();
    let result = match input.op {
        protocol::PolicyWriteOp::Create => match input.policy.as_ref() {
            Some(policy) => crate::store::policy_ops::create(store, &input.key, policy).await,
            None => {
                return Response::err(
                    req.id,
                    ErrorCode::ValidationFailed,
                    "policy is required for create".to_string(),
                );
            }
        },
        protocol::PolicyWriteOp::Edit => match input.policy.as_ref() {
            Some(policy) => crate::store::policy_ops::edit(store, &input.key, policy).await,
            None => {
                return Response::err(
                    req.id,
                    ErrorCode::ValidationFailed,
                    "policy is required for edit".to_string(),
                );
            }
        },
        protocol::PolicyWriteOp::Enable => {
            crate::store::policy_ops::set_stage(
                store,
                &input.key,
                crate::store::PolicyStage::Enforce,
            )
            .await
        }
        protocol::PolicyWriteOp::Disable => {
            crate::store::policy_ops::set_stage(store, &input.key, crate::store::PolicyStage::Off)
                .await
        }
        protocol::PolicyWriteOp::Stage => {
            let Some(stage) = input.stage else {
                return Response::err(
                    req.id,
                    ErrorCode::ValidationFailed,
                    "stage is required".to_string(),
                );
            };
            crate::store::policy_ops::set_stage(store, &input.key, stage).await
        }
        protocol::PolicyWriteOp::Delete => {
            crate::store::policy_ops::delete(store, &input.key).await
        }
    };
    match result {
        Ok(()) => {
            let records = store.scan_prefix("policy:").await;
            match records {
                Ok(records) => {
                    let refreshed = PolicyMatcherSet::from_records_lenient(&records);
                    *ctx.policy_matcher.write().await = refreshed;
                }
                Err(error) => tracing::warn!(
                    error = %error,
                    "daemon: policy matcher refresh failed; retaining previous set"
                ),
            }
            let warnings = if matches!(
                input.op,
                protocol::PolicyWriteOp::Create | protocol::PolicyWriteOp::Edit
            ) {
                input.policy.as_ref().map(|policy| async {
                    let has_backing = store
                        .get(&policy.requires.key)
                        .await
                        .ok()
                        .flatten()
                        .is_some_and(|record| {
                            !matches!(
                                record.lifecycle,
                                crate::store::RecordLifecycle::Tombstoned { .. }
                            )
                        });
                    crate::store::policy_ops::author_warnings(policy, has_backing)
                })
            } else {
                None
            };
            let warnings = match warnings {
                Some(future) => future.await,
                None => Vec::new(),
            };
            let stage = if let Some(policy) = input.policy.as_ref() {
                policy.stage
            } else {
                store
                    .get(&input.key)
                    .await
                    .ok()
                    .flatten()
                    .and_then(|record| record.payload_as::<crate::store::PolicyRecord>())
                    .map(|policy| policy.stage)
                    .unwrap_or(crate::store::PolicyStage::Off)
            };
            Response::ok(
                req.id,
                serde_json::json!({
                    "ok": true,
                    "key": input.key,
                    "stage": stage,
                    "warnings": warnings
                }),
            )
        }
        Err(error) => {
            use crate::store::policy_ops::PolicyOpError;
            // Map typed policy errors to protocol codes; unknown errors (e.g. a
            // raw store failure) fall through to StoreError.
            let code = match error.downcast_ref::<PolicyOpError>() {
                Some(PolicyOpError::NotFound { .. }) => ErrorCode::NotFound,
                Some(PolicyOpError::AlreadyExists { .. }) => ErrorCode::Conflict,
                Some(PolicyOpError::NotActive { .. }) => ErrorCode::InvalidStateTransition,
                Some(
                    PolicyOpError::InvalidKey { .. }
                    | PolicyOpError::NotAPolicy { .. }
                    | PolicyOpError::InvalidGlob { .. }
                    | PolicyOpError::EmptyTrigger { .. },
                ) => ErrorCode::ValidationFailed,
                Some(PolicyOpError::InvalidPayload { .. }) | None => ErrorCode::StoreError,
            };
            Response::err(req.id, code, error.to_string())
        }
    }
}

pub(super) async fn dispatch_policy_evaluate(
    graph: &Arc<tokio::sync::RwLock<Graph>>,
    ctx: &RequestContext,
    req: &Request,
) -> Response {
    let Command::PolicyEvaluate(input) = &req.cmd else {
        unreachable!("dispatch_policy_evaluate only accepts PolicyEvaluate")
    };

    let (matched, bypass_key) = {
        let matcher = ctx.policy_matcher.read().await;
        let matched = matcher
            .matches(&input.action)
            .into_iter()
            .map(|matched| {
                (
                    matched.key.to_string(),
                    matched.policy.stage,
                    matched.policy.mode,
                    matched.policy.rule.clone(),
                    matched.policy.reason.clone(),
                    matched.policy.severity.clone(),
                    matched.policy.requires.key.clone(),
                    matched.policy.requires.via.clone(),
                    matched.policy.requires.freshness.fingerprint,
                    matched.policy.requires.freshness.ttl_secs,
                )
            })
            .collect::<Vec<_>>();
        let bypass_key = input.raw_command.as_deref().and_then(|raw| {
            matcher
                .detect_unclassified_literal_bypass(&input.action, raw)
                .map(str::to_string)
        });
        (matched, bypass_key)
    };

    let g = graph.read().await;
    let store = g.store();
    let strict = matches!(
        crate::store::enforcement::get_policy_mode(store).await,
        crate::store::enforcement::EnforcementMode::Strict
    );
    let mut verdicts = Vec::with_capacity(matched.len());
    for (key, stage, mode, rule, reason, severity, requires_key, via, fingerprint, ttl_secs) in
        matched
    {
        let satisfied = match mode {
            crate::store::PolicyMode::Steer => true,
            crate::store::PolicyMode::Block => {
                let check = if fingerprint {
                    sess::check_consulted_recent_fingerprinted(
                        store,
                        &requires_key,
                        ttl_secs,
                        input.actor.as_deref(),
                    )
                    .await
                } else {
                    sess::check_consulted_recent(
                        store,
                        &requires_key,
                        ttl_secs,
                        input.actor.as_deref(),
                    )
                    .await
                };
                match check {
                    Ok(value) => value,
                    Err(error) => {
                        return Response::err(req.id, ErrorCode::StoreError, error.to_string())
                    }
                }
            }
        };
        verdicts.push(protocol::PolicyVerdict {
            key,
            stage,
            mode,
            rule,
            reason,
            severity,
            requires_key,
            via,
            satisfied,
            strict,
        });
    }

    Response::ok(
        req.id,
        serde_json::to_value(protocol::PolicyEvaluateResult {
            verdicts,
            bypass_key,
        })
        .unwrap_or_else(|_| serde_json::json!({"verdicts": [], "bypass_key": null})),
    )
}
