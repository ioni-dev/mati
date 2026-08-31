//! Session-side native mutation handlers.

use super::*;

// ── Session-side native handlers ────────────────────────────────────────────
//
// These handlers write mutation + audit atomically in the sessions tree
// using `transact_sessions_raw`.

pub(super) async fn dispatch_session_side(
    graph: &Arc<tokio::sync::RwLock<Graph>>,
    ctx: &RequestContext,
    req: &Request,
) -> Response {
    let g = graph.read().await;
    let store = g.store();
    let request_id = req.id;
    let command_kind = req.cmd.kind().to_string();
    let target_key = req.cmd.target_key().to_string();

    match &req.cmd {
        Command::InstructionsLoaded(input) => {
            match sess::record_instructions_loaded(store, &input.payload).await {
                Ok(_) => Response::ok(request_id, serde_json::Value::Null),
                Err(error) => Response::err(request_id, ErrorCode::StoreError, error.to_string()),
            }
        }
        Command::PolicyShadowObserve(input) => {
            match sess::record_shadow_observation(
                store,
                &input.policy_key,
                &input.action,
                input.would,
            )
            .await
            {
                Ok(()) => Response::ok(request_id, serde_json::json!({"ok": true})),
                Err(error) => Response::err(request_id, ErrorCode::StoreError, error.to_string()),
            }
        }
        Command::SessionLog(input) => {
            let agg_prefix = match input.event {
                protocol::SessionEvent::Miss => "analytics:miss_",
                protocol::SessionEvent::ComplianceMiss => "compliance:miss_",
                protocol::SessionEvent::ComplianceHit => "compliance:allow_after_receipt_",
                protocol::SessionEvent::CodexShellMiss => "compliance:codex_shell_miss_",
                // A pre-hook block IS a deny, so it shares the deny aggregate.
                // Only the post-bash miss stays in codex_shell_miss_, which is
                // what `mati stats` counts as a bypass.
                protocol::SessionEvent::CodexShellBlocked => "compliance:miss_",
                protocol::SessionEvent::UnclassifiedPolicyLiteralBypass => {
                    "compliance:unclassified_policy_literal_bypass_"
                }
                protocol::SessionEvent::Bootstrap => "analytics:bootstrap_",
                protocol::SessionEvent::PromptNudge => "analytics:codex_prompt_nudge_",
                // Edit-gate events share the read aggregates (coarse counts); the
                // edit-vs-read distinction lives in the hash-chained event's
                // decision_reason_code, not the daily aggregate.
                protocol::SessionEvent::EditConsulted => "compliance:allow_after_receipt_",
                protocol::SessionEvent::EditBlocked => "compliance:miss_",
                // Floor-mandate deny shares the miss aggregate; the distinction lives in the
                // event's decision_reason_code (floor_consult_required).
                protocol::SessionEvent::FloorConsultMiss => "compliance:miss_",
                protocol::SessionEvent::PolicyConsultMiss => "compliance:miss_",
                protocol::SessionEvent::PolicyContentMiss => "compliance:miss_",
                protocol::SessionEvent::PolicyRequirementMiss => "compliance:miss_",
                protocol::SessionEvent::PolicyConsultHit => "compliance:allow_after_receipt_",
                protocol::SessionEvent::PolicySteered => "analytics:policy_steer_",
                protocol::SessionEvent::WrappedDbClientMiss => "compliance:wrapped_db_client_miss_",
                protocol::SessionEvent::TombstoneBypassedDeny => "compliance:tombstone_bypass_",
                // A lockdown deny IS a deny; the distinction lives in the
                // event's decision_reason_code (session_lockdown).
                protocol::SessionEvent::LockdownBlocked => "compliance:miss_",
                // Same for the Tier 2 floor deny (seal_floor_restore).
                protocol::SessionEvent::SealFloorBlocked => "compliance:miss_",
                protocol::SessionEvent::SealBypassDetected => "compliance:seal_bypass_",
                // Not a compliance outcome — nothing was denied and nothing
                // was consulted. `analytics:` keeps it out of the hit/miss
                // rate, whose denominator is accesses a gate actually saw.
                protocol::SessionEvent::PathlessAllow => "analytics:pathless_allow_",
            };
            let agg_key = sess::today_key(agg_prefix);

            // Stage agg record + audit for one atomic commit.
            let staged_agg = match sess::upsert_daily_agg_staged(store, &agg_key, &input.key).await
            {
                Ok(s) => s,
                Err(e) => {
                    let entry = build_audit_entry(
                        ctx,
                        request_id,
                        &command_kind,
                        &target_key,
                        false,
                        Some(ErrorCode::StoreError),
                    );
                    write_session_audit(store, &entry).await;
                    return Response::err(request_id, ErrorCode::StoreError, e.to_string());
                }
            };
            let audit_entry =
                build_audit_entry(ctx, request_id, &command_kind, &target_key, true, None);
            // Audit is required — fail closed if serialization fails.
            let audit_bytes = match serialize_audit(&audit_entry) {
                Some(b) => b,
                None => {
                    return Response::err(
                        request_id,
                        ErrorCode::Internal,
                        "audit serialization failed".to_string(),
                    );
                }
            };
            let audit_key = audit_nanos_key("audit:session:");

            // One atomic transaction: agg mutation + audit.
            let writes: Vec<(&str, &[u8])> =
                vec![(&staged_agg.0, &staged_agg.1), (&audit_key, &audit_bytes)];
            if let Err(e) = store.transact_sessions_raw(&writes).await {
                // Transaction failed — accepted audit inside was lost.
                let entry = build_audit_entry(
                    ctx,
                    request_id,
                    &command_kind,
                    &target_key,
                    false,
                    Some(ErrorCode::StoreError),
                );
                write_session_audit(store, &entry).await;
                return Response::err(request_id, ErrorCode::StoreError, e.to_string());
            }

            // Best-effort enforcement event recording (post-transaction).
            match input.event {
                protocol::SessionEvent::ComplianceMiss => {
                    let _ = crate::store::enforcement::record_event_with_session(
                        store,
                        crate::store::enforcement::EnforcementEventType::Deny,
                        crate::store::enforcement::SubjectKind::File,
                        input.key.clone(),
                        "claude".to_string(),
                        None,
                        "gotcha_above_threshold".to_string(),
                        input.decision_basis_hash.clone(),
                        input.session_id.clone(),
                    )
                    .await;
                }
                protocol::SessionEvent::ComplianceHit => {
                    let _ = crate::store::enforcement::record_event_with_session(
                        store,
                        crate::store::enforcement::EnforcementEventType::AllowAfterReceipt,
                        crate::store::enforcement::SubjectKind::File,
                        input.key.clone(),
                        "claude".to_string(),
                        sess::receipt_id_in_force(store, &input.key, input.actor.as_deref()).await,
                        "receipt_valid".to_string(),
                        input.decision_basis_hash.clone(),
                        input.session_id.clone(),
                    )
                    .await;
                }
                // Codex's post-bash hook runs AFTER a shell command finished;
                // by the time we observe "no consultation receipt", the
                // bypass already happened. Record it as `BypassDetected`
                // (label "bypass") rather than `Deny` — nothing was actually
                // denied. Without this arm the event landed only in the
                // daily `compliance:codex_shell_miss_<date>` aggregate and
                // was invisible to `mati history --enforcement`
                // (smoke finding step 128).
                protocol::SessionEvent::CodexShellMiss => {
                    let _ = crate::store::enforcement::record_event(
                        store,
                        crate::store::enforcement::EnforcementEventType::BypassDetected,
                        crate::store::enforcement::SubjectKind::File,
                        input.key.clone(),
                        "codex".to_string(),
                        None,
                        "codex_shell_pre_consult_miss".to_string(),
                        input.decision_basis_hash.clone(),
                    )
                    .await;
                }
                // The Codex PRE hooks exit 2: the read or patch was BLOCKED,
                // not observed after the fact. Recording it as `BypassDetected`
                // alongside the post-bash miss above reported every Codex block
                // as a bypass and left Codex with zero denials in `mati stats`
                // and in the signed audit built on this chain.
                protocol::SessionEvent::CodexShellBlocked => {
                    let _ = crate::store::enforcement::record_event(
                        store,
                        crate::store::enforcement::EnforcementEventType::Deny,
                        crate::store::enforcement::SubjectKind::File,
                        input.key.clone(),
                        "codex".to_string(),
                        None,
                        "codex_pre_consult_blocked".to_string(),
                        input.decision_basis_hash.clone(),
                    )
                    .await;
                }
                // Plane 2: edit-time audit evidence. Same frozen event TYPES as
                // reads (AllowAfterReceipt / Deny) — only the decision_reason_code
                // differs, so the trail attributes the edit gate without touching
                // the frozen hash contract.
                protocol::SessionEvent::EditConsulted => {
                    let _ = crate::store::enforcement::record_event_with_session(
                        store,
                        crate::store::enforcement::EnforcementEventType::AllowAfterReceipt,
                        crate::store::enforcement::SubjectKind::File,
                        input.key.clone(),
                        "claude".to_string(),
                        sess::receipt_id_in_force(store, &input.key, input.actor.as_deref()).await,
                        "edit_after_receipt".to_string(),
                        input.decision_basis_hash.clone(),
                        input.session_id.clone(),
                    )
                    .await;
                }
                protocol::SessionEvent::EditBlocked => {
                    let _ = crate::store::enforcement::record_event_with_session(
                        store,
                        crate::store::enforcement::EnforcementEventType::Deny,
                        crate::store::enforcement::SubjectKind::File,
                        input.key.clone(),
                        "claude".to_string(),
                        None,
                        "edit_blocked_unconsulted".to_string(),
                        input.decision_basis_hash.clone(),
                        input.session_id.clone(),
                    )
                    .await;
                }
                // Enterprise floor mandate deny — distinct reason code so the audit/report can
                // separate an org consultation mandate from a local gotcha.
                protocol::SessionEvent::FloorConsultMiss => {
                    let _ = crate::store::enforcement::record_event_with_session(
                        store,
                        crate::store::enforcement::EnforcementEventType::Deny,
                        crate::store::enforcement::SubjectKind::File,
                        input.key.clone(),
                        "claude".to_string(),
                        None,
                        "floor_consult_required".to_string(),
                        input.decision_basis_hash.clone(),
                        input.session_id.clone(),
                    )
                    .await;
                }
                protocol::SessionEvent::PolicyConsultMiss => {
                    let _ = crate::store::enforcement::record_event_with_session(
                        store,
                        crate::store::enforcement::EnforcementEventType::Deny,
                        crate::store::enforcement::SubjectKind::Control,
                        input.key.clone(),
                        "claude".to_string(),
                        None,
                        "policy_consult_required".to_string(),
                        input.decision_basis_hash.clone(),
                        input.session_id.clone(),
                    )
                    .await;
                }
                protocol::SessionEvent::PolicyContentMiss => {
                    let _ = crate::store::enforcement::record_event_with_session(
                        store,
                        crate::store::enforcement::EnforcementEventType::Deny,
                        crate::store::enforcement::SubjectKind::Control,
                        input.key.clone(),
                        "claude".to_string(),
                        None,
                        "policy_content_denied".to_string(),
                        input.decision_basis_hash.clone(),
                        input.session_id.clone(),
                    )
                    .await;
                }
                protocol::SessionEvent::PolicyRequirementMiss => {
                    let _ = crate::store::enforcement::record_event_with_session(
                        store,
                        crate::store::enforcement::EnforcementEventType::Deny,
                        crate::store::enforcement::SubjectKind::Control,
                        input.key.clone(),
                        "claude".to_string(),
                        None,
                        "policy_requirement_unmet".to_string(),
                        input.decision_basis_hash.clone(),
                        input.session_id.clone(),
                    )
                    .await;
                }
                protocol::SessionEvent::PolicyConsultHit => {
                    let _ = crate::store::enforcement::record_event_with_session(
                        store,
                        crate::store::enforcement::EnforcementEventType::AllowAfterReceipt,
                        crate::store::enforcement::SubjectKind::Control,
                        input.key.clone(),
                        "claude".to_string(),
                        sess::receipt_id_in_force(store, &input.key, input.actor.as_deref()).await,
                        "policy_receipt_valid".to_string(),
                        input.decision_basis_hash.clone(),
                        input.session_id.clone(),
                    )
                    .await;
                }
                // Steering is context injection, not enforcement. Its trace
                // belongs only in the eventual analytics tree.
                protocol::SessionEvent::PolicySteered => {}
                // Post-bash saw a wrapped, unclassifiable introspection command:
                // the receipt it should mint never mints, so a db_client policy
                // stays permanently denied. Nothing was bypassed — record as
                // BypassDetected anyway (same "detected after the fact, no
                // decision changes" shape as CodexShellMiss) rather than adding
                // a new event type to the frozen hash contract.
                protocol::SessionEvent::WrappedDbClientMiss => {
                    let _ = crate::store::enforcement::record_event(
                        store,
                        crate::store::enforcement::EnforcementEventType::BypassDetected,
                        crate::store::enforcement::SubjectKind::System,
                        input.key.clone(),
                        "claude".to_string(),
                        None,
                        "wrapped_client_unclassifiable".to_string(),
                        input.decision_basis_hash.clone(),
                    )
                    .await;
                }
                // The `FileDeleted` bypass already decided `Tombstone` (allow)
                // before this event fires — nothing here changes that. This
                // only records that the bypass suppressed a deny a qualifying
                // confirmed gotcha would otherwise have produced, same
                // "detected after the fact, no decision changes" shape as
                // `CodexShellMiss`.
                protocol::SessionEvent::TombstoneBypassedDeny => {
                    let _ = crate::store::enforcement::record_event_with_session(
                        store,
                        crate::store::enforcement::EnforcementEventType::BypassDetected,
                        crate::store::enforcement::SubjectKind::File,
                        input.key.clone(),
                        "claude".to_string(),
                        None,
                        "tombstone_file_deleted".to_string(),
                        input.decision_basis_hash.clone(),
                        input.session_id.clone(),
                    )
                    .await;
                }
                protocol::SessionEvent::LockdownBlocked => {
                    let _ = crate::store::enforcement::record_event_with_session(
                        store,
                        crate::store::enforcement::EnforcementEventType::Deny,
                        crate::store::enforcement::SubjectKind::File,
                        input.key.clone(),
                        "claude".to_string(),
                        None,
                        "session_lockdown".to_string(),
                        input.decision_basis_hash.clone(),
                        input.session_id.clone(),
                    )
                    .await;
                }
                protocol::SessionEvent::SealFloorBlocked => {
                    let _ = crate::store::enforcement::record_event_with_session(
                        store,
                        crate::store::enforcement::EnforcementEventType::Deny,
                        crate::store::enforcement::SubjectKind::File,
                        input.key.clone(),
                        "claude".to_string(),
                        None,
                        "seal_floor_restore".to_string(),
                        input.decision_basis_hash.clone(),
                        input.session_id.clone(),
                    )
                    .await;
                }
                protocol::SessionEvent::SealBypassDetected => {
                    let _ = crate::store::enforcement::record_event_with_session(
                        store,
                        crate::store::enforcement::EnforcementEventType::BypassDetected,
                        crate::store::enforcement::SubjectKind::File,
                        input.key.clone(),
                        "claude".to_string(),
                        None,
                        "seal_bypass".to_string(),
                        input.decision_basis_hash.clone(),
                        input.session_id.clone(),
                    )
                    .await;
                }
                // Record-only signal; reuse BypassDetected so the frozen hash
                // contract needs no new EnforcementEventType or schema bump.
                protocol::SessionEvent::UnclassifiedPolicyLiteralBypass => {
                    let _ = crate::store::enforcement::record_event_with_session(
                        store,
                        crate::store::enforcement::EnforcementEventType::BypassDetected,
                        crate::store::enforcement::SubjectKind::Control,
                        input.key.clone(),
                        "hook".to_string(),
                        None,
                        "unclassified_policy_literal".to_string(),
                        input.decision_basis_hash.clone(),
                        input.session_id.clone(),
                    )
                    .await;
                }
                _ => {}
            }

            // Tier 1: arm the session lockdown. Every event here is a deny a
            // consultation clears, so the marker names a key `mem_get` can
            // settle. Best-effort, like the enforcement event above — a
            // missing marker costs the lockdown, never the deny itself.
            if matches!(
                input.event,
                protocol::SessionEvent::ComplianceMiss
                    | protocol::SessionEvent::CodexShellBlocked
                    | protocol::SessionEvent::EditBlocked
                    | protocol::SessionEvent::FloorConsultMiss
                    | protocol::SessionEvent::SealFloorBlocked
                    // A detected bypass is stronger evidence than a deny: the
                    // floor was actually crossed. The key it names is a file
                    // key, so `mem_get` still clears the lockdown it arms.
                    | protocol::SessionEvent::SealBypassDetected
            ) {
                let _ = sess::record_owed_receipt(store, &input.key, input.actor.as_deref()).await;
            }

            Response::ok(request_id, serde_json::Value::Null)
        }

        Command::ConsultationHit(input) => {
            // Stage all sessions-tree writes: daily agg + consultation receipt + audit.
            let agg_key = sess::today_key("analytics:hit_");
            let staged_agg = match sess::upsert_daily_agg_staged(store, &agg_key, &input.key).await
            {
                Ok(s) => s,
                Err(e) => {
                    let entry = build_audit_entry(
                        ctx,
                        request_id,
                        &command_kind,
                        &target_key,
                        false,
                        Some(ErrorCode::StoreError),
                    );
                    write_session_audit(store, &entry).await;
                    return Response::err(request_id, ErrorCode::StoreError, e.to_string());
                }
            };
            let staged_receipt = match sess::consultation_receipt_staged_for_store(
                store,
                &input.key,
                input.actor.as_deref(),
                input.capture_fingerprint,
                input.source,
            )
            .await
            {
                Ok(s) => s,
                Err(e) => {
                    let entry = build_audit_entry(
                        ctx,
                        request_id,
                        &command_kind,
                        &target_key,
                        false,
                        Some(ErrorCode::StoreError),
                    );
                    write_session_audit(store, &entry).await;
                    return Response::err(request_id, ErrorCode::StoreError, e.to_string());
                }
            };
            let audit_entry =
                build_audit_entry(ctx, request_id, &command_kind, &target_key, true, None);
            // Audit is required — fail closed if serialization fails.
            let audit_bytes = match serialize_audit(&audit_entry) {
                Some(b) => b,
                None => {
                    return Response::err(
                        request_id,
                        ErrorCode::Internal,
                        "audit serialization failed".to_string(),
                    );
                }
            };
            let audit_key = audit_nanos_key("audit:session:");

            // One atomic transaction: agg + receipt + audit (all sessions tree).
            let writes: Vec<(&str, &[u8])> = vec![
                (&staged_agg.0, &staged_agg.1),
                (&staged_receipt.key, &staged_receipt.bytes),
                (&audit_key, &audit_bytes),
            ];
            if let Err(e) = store.transact_sessions_raw(&writes).await {
                // Transaction failed — accepted audit inside was lost.
                let entry = build_audit_entry(
                    ctx,
                    request_id,
                    &command_kind,
                    &target_key,
                    false,
                    Some(ErrorCode::StoreError),
                );
                write_session_audit(store, &entry).await;
                return Response::err(request_id, ErrorCode::StoreError, e.to_string());
            }

            // Cross-tree substep: access_count bump on target record (knowledge tree).
            // Best-effort — does not block the response.
            if let Ok(Some(mut target_record)) = store.get(&input.key).await {
                target_record.access_count += 1;
                target_record.last_accessed = now_secs();
                let _ = store.put(&input.key, &target_record).await;
            }

            // Best-effort enforcement event: ReceiptMinted — attributed with
            // one-level agent lineage. `session_id` is the spawning session,
            // `agent_id` the subagent actor that consulted under it (empty on the
            // main thread → None). This is the only emitter that receives both,
            // via the `post-memget` hook payload.
            let _ = crate::store::enforcement::record_event_with_lineage(
                store,
                crate::store::enforcement::EnforcementEventType::ReceiptMinted,
                crate::store::enforcement::SubjectKind::File,
                input.key.clone(),
                "claude".to_string(),
                Some(staged_receipt.id.clone()),
                "consultation_requested".to_string(),
                input.decision_basis_hash.clone(),
                input.session_id.clone(),
                input.agent_id.clone().filter(|s| !s.is_empty()),
            )
            .await;

            Response::ok(request_id, serde_json::Value::Null)
        }

        Command::SessionFlush => {
            // Stage session:current record + audit for one atomic commit.
            let staged_flush = match sess::session_flush_staged(store).await {
                Ok(Some(s)) => s,
                Ok(None) => {
                    // No consulted keys — nothing to flush. Still audit.
                    let audit_entry =
                        build_audit_entry(ctx, request_id, &command_kind, &target_key, true, None);
                    write_session_audit(store, &audit_entry).await;
                    return Response::ok(request_id, serde_json::Value::Null);
                }
                Err(e) => {
                    let entry = build_audit_entry(
                        ctx,
                        request_id,
                        &command_kind,
                        &target_key,
                        false,
                        Some(ErrorCode::StoreError),
                    );
                    write_session_audit(store, &entry).await;
                    return Response::err(request_id, ErrorCode::StoreError, e.to_string());
                }
            };
            let audit_entry =
                build_audit_entry(ctx, request_id, &command_kind, &target_key, true, None);
            // Audit is required — fail closed if serialization fails.
            let audit_bytes = match serialize_audit(&audit_entry) {
                Some(b) => b,
                None => {
                    return Response::err(
                        request_id,
                        ErrorCode::Internal,
                        "audit serialization failed".to_string(),
                    );
                }
            };
            let audit_key = audit_nanos_key("audit:session:");

            let writes: Vec<(&str, &[u8])> = vec![
                (&staged_flush.0, &staged_flush.1),
                (&audit_key, &audit_bytes),
            ];
            if let Err(e) = store.transact_sessions_raw(&writes).await {
                let entry = build_audit_entry(
                    ctx,
                    request_id,
                    &command_kind,
                    &target_key,
                    false,
                    Some(ErrorCode::StoreError),
                );
                write_session_audit(store, &entry).await;
                return Response::err(request_id, ErrorCode::StoreError, e.to_string());
            }
            Response::ok(request_id, serde_json::Value::Null)
        }

        Command::SessionHarvest => {
            // SessionHarvest is inherently cross-tree (promotes gotchas in
            // knowledge, archives sessions). Delegate to existing logic which
            // commits its own per-step transactions, then write session-side audit.
            let result = sess::session_harvest(store, &ctx.repo_root).await;
            let (accepted, error_code) = match &result {
                Ok(()) => (true, None),
                Err(_) => (false, Some(ErrorCode::StoreError)),
            };
            // Audit is session-side, written after harvest completes.
            // Harvest itself is multi-step with internal commits — cannot be
            // made atomic end-to-end (cross-tree). Audit records the outcome.
            let entry = build_audit_entry(
                ctx,
                request_id,
                &command_kind,
                &target_key,
                accepted,
                error_code,
            );
            write_session_audit(store, &entry).await;

            match result {
                Ok(()) => Response::ok(request_id, serde_json::Value::Null),
                Err(e) => Response::err(request_id, ErrorCode::StoreError, e.to_string()),
            }
        }

        Command::SessionClearConsults => {
            // Silent scan+delete — no audit entry by design. Compaction wipes the
            // agent's memory, so clearing receipts is a maintenance action, not a
            // semantic mutation worth auditing. Fail-open on error (log, not crash).
            //
            // Tier 2 re-arms first, never after: a crash between the two must
            // leave the file sealed with a live receipt, not open with none.
            // This is also the session-boundary re-arm — `mati watch-paths`
            // fires this command when the manifest is non-empty.
            let rearmed = crate::seal::rearm_all(&store.root);
            if !rearmed.is_empty() {
                tracing::info!("re-armed {} sealed file(s) on receipt clear", rearmed.len());
            }
            match sess::session_clear_consults(store).await {
                Ok(()) => Response::ok(request_id, serde_json::Value::Null),
                Err(e) => {
                    tracing::warn!(error = %e, "session_clear_consults failed; post-compaction re-block window not restored");
                    Response::err(request_id, ErrorCode::StoreError, e.to_string())
                }
            }
        }

        Command::SubagentHarvest(input) => {
            let result = sess::write_subagent_summary(
                store,
                &input.summary,
                input.agent_id.as_deref(),
                input.agent_type.as_deref(),
                input.session_id.as_deref(),
                input.transcript_path.as_deref(),
            )
            .await;
            let (accepted, error_code) = match &result {
                Ok(()) => (true, None),
                Err(_) => (false, Some(ErrorCode::StoreError)),
            };
            let entry = build_audit_entry(
                ctx,
                request_id,
                &command_kind,
                &target_key,
                accepted,
                error_code,
            );
            write_session_audit(store, &entry).await;
            match result {
                Ok(()) => Response::ok(request_id, serde_json::Value::Null),
                Err(e) => Response::err(request_id, ErrorCode::StoreError, e.to_string()),
            }
        }

        Command::SubagentSpawned(input) => {
            // Presence is meaningless without the subagent's identity — no-op if
            // absent, mirroring the empty-summary guard in SubagentHarvest.
            let Some(agent_id) = input.agent_id.clone().filter(|a| !a.is_empty()) else {
                return Response::ok(request_id, serde_json::Value::Null);
            };
            let reason = match input.agent_type.as_deref().filter(|t| !t.is_empty()) {
                Some(t) => format!("subagent_spawned:{t}"),
                None => "subagent_spawned".to_string(),
            };
            let _ = crate::store::enforcement::record_event_with_lineage(
                store,
                crate::store::enforcement::EnforcementEventType::SubagentSpawned,
                crate::store::enforcement::SubjectKind::System,
                agent_id.clone(),
                "claude".to_string(),
                None,
                reason,
                None,
                input.session_id.clone(),
                Some(agent_id),
            )
            .await;
            Response::ok(request_id, serde_json::Value::Null)
        }

        Command::SubagentEdge(input) => {
            // A nested edge needs BOTH ends. The child is the actor; the parent
            // is the spawner. Either absent means this is not a nested spawn (a
            // root spawn has no parent and is already recorded by SubagentSpawned)
            // — no-op, matching the SubagentSpawned identity guard.
            let (Some(child), Some(parent)) = (
                input.child_agent_id.clone().filter(|a| !a.is_empty()),
                input.parent_agent_id.clone().filter(|a| !a.is_empty()),
            ) else {
                return Response::ok(request_id, serde_json::Value::Null);
            };
            let reason = match input.agent_type.as_deref().filter(|t| !t.is_empty()) {
                Some(t) => format!("subagent_edge:{t}"),
                None => "subagent_edge".to_string(),
            };
            let _ = crate::store::enforcement::record_event_with_nested_lineage(
                store,
                crate::store::enforcement::EnforcementEventType::SubagentEdge,
                crate::store::enforcement::SubjectKind::System,
                child.clone(),
                "claude".to_string(),
                None,
                reason,
                None,
                input.session_id.clone(),
                Some(child),
                Some(parent),
            )
            .await;
            Response::ok(request_id, serde_json::Value::Null)
        }

        _ => unreachable!("is_session_side guard ensures only session commands reach here"),
    }
}
