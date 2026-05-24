//! Protocol v2 dispatch — typed semantic commands with audit trail.
//!
//! This module is the ONLY entry point for commands received on the daemon
//! socket. The wire layer (`socket_handle_connection`) accepts only v2
//! `protocol::Request` messages — v1 raw-string commands are not accepted
//! from the wire.
//!
//! ## Command routing
//!
//! - **Knowledge-side mutations** (8 commands): native handlers in
//!   `mcp::handlers`. Mutation + file-link updates + audit committed
//!   atomically in one `transact_knowledge` call.
//! - **Session-side mutations** (4 commands): native handlers here.
//!   Mutation + audit committed atomically in one `transact_sessions_raw`.
//! - **Side-effecting reads** (MemGet, MemBootstrap): native handlers in
//!   `mcp::handlers`. Consultation receipts + audit committed atomically
//!   in sessions tree. Cross-tree access_count bumps are deferred best-effort.
//! - **Compound** (FileEditHook): per-tree atomic batches with substep audit.
//! - **MemQuery**: native pure-read handler via `dispatch_mem_query`
//!   (γ-C1.5). Centralizes mode dispatch so v1 (rmcp tool wrapper) and
//!   v2 (typed Command::MemQuery) produce byte-identical responses.
//! - **Pure reads** (8 commands): v1 bridge for read-only dispatch. No
//!   mutations, no audit, no side effects. The v1 bridge CANNOT reach
//!   `put` or `delete` — no `Command` variant maps to those strings.
//!
//! ## Audit routing
//!
//! - Knowledge-side: `audit:knowledge:<nanos>` in the knowledge tree
//!   (Immediate durability, co-located with mutation).
//! - Session-side + side-effecting reads: `audit:session:<nanos>` in the
//!   sessions tree (Eventual durability, co-located with mutation).
//!
//! ## Transaction model
//!
//! SurrealKV supports multi-key atomic transactions within a single tree.
//! The real constraint is mati's two-tree architecture: no single
//! transaction can span both the knowledge and sessions trees.
//!
//! - Same-tree commands: mutation + audit in one transaction.
//! - Cross-tree commands (FileEditHook, SessionHarvest): per-tree atomic
//!   batches with explicit substep audit.
//! - Best-effort secondary effects (graph edges, access_count bumps):
//!   outside the main transaction, failures logged but not propagated.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use uuid::Uuid;

use crate::graph::Graph;
use crate::mcp::metadata::PeerContext;
use crate::mcp::metrics;
use crate::mcp::protocol::{self, AuditEntry, Command, ErrorCode, Request, Response};
use crate::store::session as sess;

// ── Request context ─────────────────────────────────────────────────────────

/// Ambient context for a single v2 request. Constructed once in
/// `socket_handle_connection`, consumed by `dispatch_v2`.
///
/// Not Clone by design — each request gets exactly one context.
pub(crate) struct RequestContext {
    /// Peer identity from Unix socket credentials.
    pub peer: PeerContext,
    /// Daemon session UUID (from DaemonMetadata, established at startup).
    pub daemon_session: Uuid,
    /// Repository root path (for commands needing filesystem access).
    pub repo_root: PathBuf,
}

// ── V2 dispatch entry point ─────────────────────────────────────────────────

/// Dispatch a v2 protocol request. Returns a v2 `Response`.
///
/// Flow:
/// 1. Validate protocol version (fail-closed before any side effect)
/// 2. Classify command as knowledge-side, session-side, or pure-read
/// 3. Dispatch to appropriate handler path
/// 4. Write audit entry transactionally where possible
pub(crate) async fn dispatch_v2(
    graph: &Arc<tokio::sync::RwLock<Graph>>,
    ctx: &RequestContext,
    req: Request,
) -> Response {
    // Capture command kind before dispatch so it survives any `req` move into
    // a handler. The metrics layer is a process-global no-op when not
    // initialized (tests, etc), so this is safe regardless of daemon state.
    let command_kind = req.cmd.kind();
    let start = Instant::now();

    // Funnel every return path through a single block expression so the
    // metric recorder below captures version-mismatch and session-mismatch
    // rejections the same way it captures successful dispatches.
    let resp: Response = 'dispatch: {
        // 1. Version check — enforced before any dispatch or side effect.
        if req.v != protocol::PROTOCOL_VERSION {
            let resp = Response::err(
                req.id,
                ErrorCode::VersionMismatch,
                format!(
                    "protocol version mismatch: client={} server={}",
                    req.v,
                    protocol::PROTOCOL_VERSION
                ),
            );
            // Audit version mismatch for mutating commands (best-effort since
            // the version itself is wrong — we don't know which tree to target).
            if req.cmd.is_mutation() {
                best_effort_audit(graph, ctx, &req, false, Some(ErrorCode::VersionMismatch)).await;
            }
            break 'dispatch resp;
        }

        // 1b. Session fence — reject requests from stale clients whose cached
        // daemon metadata predates a daemon restart. The client should re-read
        // DaemonMetadata and retry once. Nil session on the request is tolerated
        // only when the daemon itself has a nil session (test / legacy fallback).
        if req.session != ctx.daemon_session {
            let resp = Response::err(
                req.id,
                ErrorCode::SessionMismatch,
                format!(
                    "session mismatch: request={} daemon={}; re-read daemon metadata and retry",
                    req.session, ctx.daemon_session
                ),
            );
            if req.cmd.is_mutation() {
                best_effort_audit(graph, ctx, &req, false, Some(ErrorCode::SessionMismatch)).await;
            }
            break 'dispatch resp;
        }

        // 2. Dispatch based on command classification.
        //
        // All mutations and side-effecting reads have native handlers.
        // Only pure reads (8 commands) use the v1 bridge, which cannot
        // reach any mutation path.
        if is_side_effecting_read(&req.cmd) {
            // MemGet / MemBootstrap: native handler with sessions-tree
            // transactional audit + deferred cross-tree best-effort writes.
            dispatch_side_effecting_read(graph, ctx, &req).await
        } else if matches!(&req.cmd, Command::MemQuery(_)) {
            // γ-C1.5: mem_query is a pure read (no audit, no side effects)
            // but still has rich business logic — route natively to the
            // canonical `handle_mem_query` so v1 and v2 dispatch can never
            // drift. Pre-γ, this fell through to the v1 bridge which
            // serialized back to a string and re-entered `MatiServer::mem_query`.
            dispatch_mem_query(graph, &req).await
        } else if is_session_side(&req.cmd) {
            // Session-side mutations: native handler with audit in sessions tree.
            dispatch_session_side(graph, ctx, &req).await
        } else if is_knowledge_mutation(&req.cmd) {
            // Knowledge-side mutations: native handler with atomic mutation+audit
            // in one transact_knowledge commit.
            dispatch_knowledge_mutation(graph, ctx, &req).await
        } else if is_compound(&req.cmd) {
            // FileEditHook: compound (consultation hit in sessions + reparse in knowledge).
            // Each substep has its own audit in its respective tree.
            dispatch_file_edit_hook(graph, ctx, &req).await
        } else if is_config_command(&req.cmd) {
            // Runtime config get/set — talks to enforcement helpers that use
            // raw bytes outside the transact_knowledge audit path. ConfigSet
            // already emits an EnforcementConfigChanged event via the helper,
            // which is the human-facing audit signal for config changes.
            dispatch_config(graph, &req).await
        } else {
            // Pure reads only — no mutations, no side effects, no audit.
            dispatch_via_v1(graph, ctx, &req).await
        }
    };

    // Saturating cast: per-request latencies above u32::MAX µs (~71 minutes)
    // are pegged rather than wrapping to a tiny value.
    let elapsed_us = start.elapsed().as_micros().min(u128::from(u32::MAX)) as u32;
    let is_error = matches!(resp, Response::Err { .. });
    metrics::record(command_kind, elapsed_us, is_error);

    resp
}

/// Returns true for side-effecting read commands (Category B).
/// These have native handlers with sessions-tree transactional audit.
fn is_side_effecting_read(cmd: &Command) -> bool {
    matches!(cmd, Command::MemGet(_) | Command::MemBootstrap(_))
}

/// Returns true for commands whose mutations target the sessions tree.
fn is_session_side(cmd: &Command) -> bool {
    matches!(
        cmd,
        Command::SessionLog(_)
            | Command::ConsultationHit(_)
            | Command::SessionFlush
            | Command::SessionHarvest
    )
}

/// Returns true for mutation commands whose primary writes target the
/// knowledge tree. These use native handlers with atomic mutation+audit.
fn is_knowledge_mutation(cmd: &Command) -> bool {
    matches!(
        cmd,
        Command::GotchaUpsert(_)
            | Command::GotchaConfirm(_)
            | Command::GotchaTombstone(_)
            | Command::FileEnrich(_)
            | Command::FileReparse(_)
            | Command::DocCapture(_)
            | Command::DecisionUpsert(_)
            | Command::DevNoteUpsert(_)
            | Command::RecordImport(_)
    )
}

/// FileEditHook is a compound: ConsultationHit (session) + FileReparse (knowledge).
/// Handled by dispatching to both paths — not a single-tree transaction.
fn is_compound(cmd: &Command) -> bool {
    matches!(cmd, Command::FileEditHook(_))
}

/// Returns true for runtime configuration commands. These touch raw key/value
/// pairs (`enforcement:mode`, `enforcement:retention_days`) and are routed
/// through a dedicated dispatcher rather than the v1 bridge or the typical
/// knowledge-mutation transactional audit path.
fn is_config_command(cmd: &Command) -> bool {
    matches!(cmd, Command::ConfigGet(_) | Command::ConfigSet(_))
}

/// Dispatch ConfigGet / ConfigSet against the daemon's store.
///
/// ConfigGet is a pure read with no audit entry. ConfigSet calls the
/// enforcement helpers, which already write an `EnforcementConfigChanged`
/// event whenever the value actually changes — that event is the durable
/// audit trail for config mutations.
async fn dispatch_config(graph: &Arc<tokio::sync::RwLock<Graph>>, req: &Request) -> Response {
    use crate::store::enforcement::{
        get_enforcement_mode, get_retention_days, set_enforcement_mode, set_retention_days,
        EnforcementMode,
    };

    let request_id = req.id;
    let g = graph.read().await;
    let store = g.store();

    match &req.cmd {
        Command::ConfigGet(input) => {
            let value = match input.key.as_str() {
                "enforcement.mode" => {
                    let mode = get_enforcement_mode(store).await;
                    match mode {
                        EnforcementMode::Advisory => "advisory".to_string(),
                        EnforcementMode::Strict => "strict".to_string(),
                    }
                }
                "enforcement.retention" => get_retention_days(store).await.to_string(),
                other => {
                    return Response::err(
                        request_id,
                        ErrorCode::ValidationFailed,
                        format!(
                            "unknown config key: {other}; valid keys: enforcement.mode, enforcement.retention"
                        ),
                    );
                }
            };
            Response::ok(request_id, serde_json::Value::String(value))
        }
        Command::ConfigSet(input) => match input.key.as_str() {
            "enforcement.mode" => {
                let mode = match input.value.as_str() {
                    "advisory" => EnforcementMode::Advisory,
                    "strict" => EnforcementMode::Strict,
                    other => {
                        return Response::err(
                            request_id,
                            ErrorCode::ValidationFailed,
                            format!(
                                "invalid enforcement mode: {other}; valid values: advisory, strict"
                            ),
                        );
                    }
                };
                match set_enforcement_mode(store, mode).await {
                    Ok(old) => {
                        let old_label = match old {
                            EnforcementMode::Advisory => "advisory",
                            EnforcementMode::Strict => "strict",
                        };
                        Response::ok(request_id, serde_json::json!({ "old": old_label }))
                    }
                    Err(e) => Response::err(request_id, ErrorCode::StoreError, e.to_string()),
                }
            }
            "enforcement.retention" => {
                let days: u64 = match input.value.parse() {
                    Ok(d) if d > 0 => d,
                    Ok(_) => {
                        return Response::err(
                            request_id,
                            ErrorCode::ValidationFailed,
                            "retention must be at least 1 day".to_string(),
                        );
                    }
                    Err(_) => {
                        return Response::err(
                            request_id,
                            ErrorCode::ValidationFailed,
                            format!(
                                "invalid retention value: {} (expected integer days)",
                                input.value
                            ),
                        );
                    }
                };
                match set_retention_days(store, days).await {
                    Ok(()) => Response::ok(request_id, serde_json::Value::Null),
                    Err(e) => Response::err(request_id, ErrorCode::StoreError, e.to_string()),
                }
            }
            other => Response::err(
                request_id,
                ErrorCode::ValidationFailed,
                format!(
                    "unknown config key: {other}; valid keys: enforcement.mode, enforcement.retention"
                ),
            ),
        },
        _ => unreachable!("is_config_command guard"),
    }
}

// ── Side-effecting read handlers ────────────────────────────────────────────

/// Pure-read native dispatch for `Command::MemQuery`. Calls
/// `handle_mem_query` directly — no audit, no consultation receipt, no
/// deferred writes. γ-C1.5 contract: v1-string and v2-typed paths produce
/// byte-identical responses for the same MemQueryInput.
async fn dispatch_mem_query(graph: &Arc<tokio::sync::RwLock<Graph>>, req: &Request) -> Response {
    use super::handlers;
    let request_id = req.id;
    let input = match &req.cmd {
        Command::MemQuery(i) => i,
        _ => unreachable!("dispatch_mem_query guard"),
    };
    let g = graph.read().await;
    match handlers::handle_mem_query(g.store(), &g, input).await {
        Ok(data) => Response::ok(request_id, data),
        Err((code, msg)) => Response::err(request_id, code, msg),
    }
}

async fn dispatch_side_effecting_read(
    graph: &Arc<tokio::sync::RwLock<Graph>>,
    ctx: &RequestContext,
    req: &Request,
) -> Response {
    use super::handlers;
    let request_id = req.id;

    match &req.cmd {
        Command::MemGet(input) => {
            let g = graph.read().await;
            match handlers::handle_mem_get(g.store(), graph, ctx, request_id, input).await {
                Ok(data) => Response::ok(request_id, data),
                Err((code, msg)) => {
                    // Handler error paths skip audit — write rejection audit
                    // to sessions tree before returning.
                    let entry = build_audit_entry(
                        ctx,
                        request_id,
                        "mem_get",
                        &input.key,
                        false,
                        Some(code.clone()),
                    );
                    write_session_audit(g.store(), &entry).await;
                    Response::err(request_id, code, msg)
                }
            }
        }
        Command::MemBootstrap(input) => {
            let g = graph.read().await;
            match handlers::handle_mem_bootstrap(g.store(), &g, graph, ctx, request_id, input).await
            {
                Ok(injection) => Response::ok(request_id, serde_json::Value::String(injection)),
                Err((code, msg)) => {
                    // Handler already wrote rejection audit to sessions tree.
                    Response::err(request_id, code, msg)
                }
            }
        }
        _ => unreachable!("is_side_effecting_read guard"),
    }
}

// ── Knowledge-side native handlers ──────────────────────────────────────────
//
// These handlers use typed DTOs, validate input, and commit mutation+audit
// atomically in a single transact_knowledge call.

async fn dispatch_knowledge_mutation(
    graph: &Arc<tokio::sync::RwLock<Graph>>,
    ctx: &RequestContext,
    req: &Request,
) -> Response {
    use super::handlers;

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

// ── FileEditHook — compound command ─────────────────────────────────────────
//
// Substep 1: ConsultationHit (sessions tree) — best-effort.
// Substep 2: FileReparse (knowledge tree) — native handler with audit.
// Each substep writes its own audit in its respective tree.

async fn dispatch_file_edit_hook(
    graph: &Arc<tokio::sync::RwLock<Graph>>,
    ctx: &RequestContext,
    req: &Request,
) -> Response {
    let input = match &req.cmd {
        Command::FileEditHook(i) => i,
        _ => unreachable!(),
    };
    let request_id = req.id;

    // Substep 1: consultation hit (sessions tree, best-effort).
    //
    // Same staged transactional model as ConsultationHit: daily agg +
    // consultation receipt + audit committed atomically in one
    // sessions-tree transaction. Cross-tree access_count bump is a
    // separate best-effort write. The whole substep is non-blocking —
    // staging or transaction failures are logged, never propagated.
    {
        let g = graph.read().await;
        let store = g.store();
        let file_key = format!("file:{}", input.path);

        // Stage session-tree writes.
        let agg_key = sess::today_key("analytics:hit_");
        let staged_agg = sess::upsert_daily_agg_staged(store, &agg_key, &file_key).await;
        let staged_receipt = sess::consultation_receipt_staged(&file_key);
        let audit_entry = build_audit_entry(
            ctx,
            request_id,
            "file_edit_hook:consultation",
            &file_key,
            true,
            None,
        );
        let audit_key = audit_nanos_key("audit:session:");
        let audit_bytes = serialize_audit(&audit_entry);

        // Atomic commit: agg + receipt + audit (all sessions tree).
        let mut writes: Vec<(&str, &[u8])> = Vec::new();
        if let Ok(ref agg) = staged_agg {
            writes.push((&agg.0, &agg.1));
        }
        if let Ok(ref receipt) = staged_receipt {
            writes.push((&receipt.0, &receipt.1));
        }
        if let Some(ref ab) = audit_bytes {
            writes.push((&audit_key, ab));
        }

        if let Err(e) = store.transact_sessions_raw(&writes).await {
            tracing::warn!(
                request_id = %request_id,
                "file_edit_hook: consultation substep sessions transaction failed: {e}"
            );
        }

        // Cross-tree best-effort: access_count bump on knowledge record.
        if let Ok(Some(mut record)) = store.get(&file_key).await {
            record.access_count += 1;
            record.last_accessed = now_secs();
            let _ = store.put(&file_key, &record).await;
        }
    }

    // Substep 2: reparse (knowledge tree, native handler with audit).
    {
        let g = graph.read().await;
        let store = g.store();
        let reparse_input = protocol::FileReparseInput {
            path: input.path.clone(),
        };
        match super::handlers::handle_file_reparse(
            store,
            ctx,
            request_id,
            &reparse_input,
            &ctx.repo_root,
        )
        .await
        {
            Ok(_) => {}
            Err((_code, msg)) => {
                tracing::warn!("file_edit_hook: reparse substep failed: {msg}");
                // Non-fatal — post-edit hook must not block the agent.
            }
        }
    }

    Response::ok(request_id, serde_json::Value::Null)
}

// ── Session-side native handlers ────────────────────────────────────────────
//
// These handlers write mutation + audit atomically in the sessions tree
// using `transact_sessions_raw`.

async fn dispatch_session_side(
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
        Command::SessionLog(input) => {
            let agg_prefix = match input.event {
                protocol::SessionEvent::Miss => "analytics:miss_",
                protocol::SessionEvent::ComplianceMiss => "compliance:miss_",
                protocol::SessionEvent::ComplianceHit => "compliance:allow_after_receipt_",
                protocol::SessionEvent::CodexShellMiss => "compliance:codex_shell_miss_",
                protocol::SessionEvent::Bootstrap => "analytics:bootstrap_",
                protocol::SessionEvent::PromptNudge => "analytics:codex_prompt_nudge_",
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
                    let _ = crate::store::enforcement::record_event(
                        store,
                        crate::store::enforcement::EnforcementEventType::Deny,
                        crate::store::enforcement::SubjectKind::File,
                        input.key.clone(),
                        "claude".to_string(),
                        None,
                        "gotcha_above_threshold".to_string(),
                        None,
                    )
                    .await;
                }
                protocol::SessionEvent::ComplianceHit => {
                    let _ = crate::store::enforcement::record_event(
                        store,
                        crate::store::enforcement::EnforcementEventType::AllowAfterReceipt,
                        crate::store::enforcement::SubjectKind::File,
                        input.key.clone(),
                        "claude".to_string(),
                        None,
                        "receipt_valid".to_string(),
                        None,
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
                        None,
                    )
                    .await;
                }
                _ => {}
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
            let staged_receipt = match sess::consultation_receipt_staged(&input.key) {
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
                (&staged_receipt.0, &staged_receipt.1),
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

            // Best-effort enforcement event: ReceiptMinted
            let _ = crate::store::enforcement::record_event(
                store,
                crate::store::enforcement::EnforcementEventType::ReceiptMinted,
                crate::store::enforcement::SubjectKind::File,
                input.key.clone(),
                "claude".to_string(),
                None,
                "consultation_requested".to_string(),
                None,
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
            let result = sess::session_harvest_no_staleness(store).await;
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

        _ => unreachable!("is_session_side guard ensures only session commands reach here"),
    }
}

// ── V1 bridge (internal adapter) ────────────────────────────────────────────
//
// Converts v2 Command variants into v1 SocketRequest format and delegates to
// the existing socket_dispatch. This is an INTERNAL adapter — not reachable
// from the wire. The raw `put` and `delete` arms in socket_dispatch are
// unreachable because no Command variant maps to "put" or "delete".

async fn dispatch_via_v1(
    graph: &Arc<tokio::sync::RwLock<Graph>>,
    ctx: &RequestContext,
    req: &Request,
) -> Response {
    use super::server::{socket_dispatch, SocketRequest};

    let (cmd, args) = command_to_v1(&req.cmd);

    // Safety guard: the v1 bridge must NEVER produce "put" or "delete".
    // Primary guard is unreachable!() in command_to_v1; this is defense-in-depth.
    if cmd == "put" || cmd == "delete" {
        return Response::err(
            req.id,
            ErrorCode::Internal,
            format!("v1 bridge produced forbidden mutation command: {cmd}"),
        );
    }

    let v1_req = SocketRequest {
        cmd,
        version: Some(1),
        args,
    };

    let v1_resp = socket_dispatch(graph, &ctx.repo_root, &v1_req).await;

    // Convert v1 SocketResponse to v2 Response.
    if v1_resp.ok {
        Response::ok(req.id, v1_resp.data.unwrap_or(serde_json::Value::Null))
    } else {
        let message = v1_resp.error.unwrap_or_else(|| "unknown error".to_string());
        let code = classify_v1_error(&message);
        Response::err(req.id, code, message)
    }
}

/// Map v1 error message strings to v2 structured error codes.
fn classify_v1_error(message: &str) -> ErrorCode {
    if message.contains("not found") {
        ErrorCode::NotFound
    } else if message.contains("already exists") {
        ErrorCode::Conflict
    } else if message.contains("tombstoned") || message.contains("cannot confirm") {
        ErrorCode::InvalidStateTransition
    } else if message.contains("store") {
        ErrorCode::StoreError
    } else {
        ErrorCode::Internal
    }
}

/// Map a v2 Command variant to v1 (cmd string, args JSON).
///
/// This function NEVER returns "put" or "delete" — those raw mutation
/// commands have no corresponding Command variant.
fn command_to_v1(cmd: &Command) -> (String, serde_json::Value) {
    use serde_json::json;

    match cmd {
        // A. Pure reads
        Command::Ping => ("ping".into(), json!({})),
        Command::Metrics => ("metrics".into(), json!({})),
        Command::Get(i) => ("get".into(), json!({ "key": i.key })),
        Command::HookEvaluate(i) => (
            "hook_evaluate".into(),
            json!({ "file_key": i.file_key, "include_recent": i.include_recent }),
        ),
        Command::ScanPrefix(i) => ("scan_prefix".into(), json!({ "prefix": i.prefix })),
        Command::History(i) => ("history".into(), json!({ "key": i.key, "limit": i.limit })),
        Command::HistorySince(i) => (
            "history_since".into(),
            json!({ "key": i.key, "since_ts": i.since_ts, "limit": i.limit }),
        ),
        Command::SessionCheckConsulted(i) => {
            ("session_check_consulted".into(), json!({ "key": i.key }))
        }
        Command::SessionCheckConsultedRecent(i) => (
            "session_check_consulted_recent".into(),
            json!({ "key": i.key, "ttl_secs": i.ttl_secs }),
        ),
        // MemQuery is now handled natively via `dispatch_mem_query`
        // (γ-C1.5). It must not reach this bridge.
        Command::MemQuery(_) => {
            unreachable!("MemQuery is handled natively, not via v1 bridge")
        }
        Command::ScanEnforcementEvents(i) => (
            "scan_enforcement_events".into(),
            json!({ "since_seq": i.since_seq, "until_seq": i.until_seq }),
        ),

        // B. Reads with side effects — handled natively, not via v1 bridge.
        Command::MemGet(_) | Command::MemBootstrap(_) => {
            unreachable!("side-effecting reads are handled natively, not via v1 bridge")
        }

        // Knowledge-side mutations are handled by native handlers — not via v1 bridge.
        Command::GotchaUpsert(_)
        | Command::GotchaConfirm(_)
        | Command::GotchaTombstone(_)
        | Command::FileEnrich(_)
        | Command::FileReparse(_)
        | Command::FileEditHook(_)
        | Command::DocCapture(_)
        | Command::DecisionUpsert(_)
        | Command::DevNoteUpsert(_)
        | Command::RecordImport(_) => {
            unreachable!("knowledge-side mutations are handled natively, not via v1 bridge")
        }

        // Session-side commands are handled natively — should not reach here.
        Command::SessionLog(_)
        | Command::ConsultationHit(_)
        | Command::SessionFlush
        | Command::SessionHarvest => {
            unreachable!("session-side commands are handled natively, not via v1 bridge")
        }

        // Config commands are handled natively — should not reach here.
        Command::ConfigGet(_) | Command::ConfigSet(_) => {
            unreachable!("config commands are handled natively, not via v1 bridge")
        }
    }
}

// ── Audit helpers ───────────────────────────────────────────────────────────

fn build_audit_entry(
    ctx: &RequestContext,
    request_id: Uuid,
    command_kind: &str,
    target_key: &str,
    accepted: bool,
    error_code: Option<ErrorCode>,
) -> AuditEntry {
    AuditEntry {
        ts: now_secs(),
        peer_uid: ctx.peer.uid,
        peer_pid: ctx.peer.pid,
        daemon_session: ctx.daemon_session,
        request_id,
        command_kind: command_kind.to_string(),
        target_key: target_key.to_string(),
        accepted,
        error_code,
    }
}

fn serialize_audit(entry: &AuditEntry) -> Option<Vec<u8>> {
    match rmp_serde::to_vec_named(entry) {
        Ok(b) => Some(b),
        Err(e) => {
            tracing::warn!("audit: serialize failed: {e}");
            None
        }
    }
}

fn audit_nanos_key(prefix: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{prefix}{nanos}")
}

/// Write audit to sessions tree. Used for session-side mutations.
/// Best-effort — never blocks the response.
async fn write_session_audit(store: &crate::store::Store, entry: &AuditEntry) {
    let Some(bytes) = serialize_audit(entry) else {
        return;
    };
    let key = audit_nanos_key("audit:session:");
    if let Err(e) = store.put_raw(&key, &bytes).await {
        tracing::warn!("audit: session write failed for {key}: {e}");
    }
}

/// Best-effort audit for protocol-level errors (version mismatch) where
/// the correct tree is ambiguous. Writes to sessions tree.
async fn best_effort_audit(
    graph: &Arc<tokio::sync::RwLock<Graph>>,
    ctx: &RequestContext,
    req: &Request,
    accepted: bool,
    error_code: Option<ErrorCode>,
) {
    let entry = build_audit_entry(
        ctx,
        req.id,
        req.cmd.kind(),
        req.cmd.target_key(),
        accepted,
        error_code,
    );
    let g = graph.read().await;
    write_session_audit(g.store(), &entry).await;
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::Graph;
    use crate::mcp::metadata::PeerContext;
    use crate::mcp::protocol::*;
    use crate::store::Store;

    /// Explicit test PeerContext — makes it obvious that auth is bypassed
    /// for handler isolation testing.
    fn test_peer() -> PeerContext {
        PeerContext {
            uid: 501,
            pid: Some(99999),
        }
    }

    /// Stable session UUID shared by test_ctx and make_request so the
    /// session fence passes. Tests that need a mismatch construct their
    /// own Request/RequestContext.
    fn test_session() -> Uuid {
        // Deterministic but non-nil so it exercises the real comparison path.
        Uuid::from_bytes([0xAA; 16])
    }

    fn test_ctx(repo_root: &std::path::Path) -> RequestContext {
        RequestContext {
            peer: test_peer(),
            daemon_session: test_session(),
            repo_root: repo_root.to_path_buf(),
        }
    }

    fn make_request(cmd: Command) -> Request {
        Request {
            v: PROTOCOL_VERSION,
            id: Uuid::new_v4(),
            session: test_session(),
            agent: None,
            cmd,
        }
    }

    #[tokio::test]
    async fn v2_ping_dispatches() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).await.unwrap();
        let graph = Graph::load(store).await.unwrap();
        let graph = Arc::new(tokio::sync::RwLock::new(graph));
        let ctx = test_ctx(dir.path());

        let req = make_request(Command::Ping);
        let resp = dispatch_v2(&graph, &ctx, req).await;

        match resp {
            Response::Ok { data, .. } => {
                assert_eq!(data, serde_json::json!("pong"));
            }
            Response::Err { message, .. } => panic!("expected Ok, got Err: {message}"),
        }
    }

    #[tokio::test]
    async fn v2_version_mismatch_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).await.unwrap();
        let graph = Graph::load(store).await.unwrap();
        let graph = Arc::new(tokio::sync::RwLock::new(graph));
        let ctx = test_ctx(dir.path());

        let req = Request {
            v: 99,
            id: Uuid::new_v4(),
            session: Uuid::new_v4(),
            agent: None,
            cmd: Command::Ping,
        };
        let resp = dispatch_v2(&graph, &ctx, req).await;

        match resp {
            Response::Err { code, .. } => {
                assert_eq!(code, ErrorCode::VersionMismatch);
            }
            Response::Ok { .. } => panic!("expected VersionMismatch error"),
        }
    }

    #[tokio::test]
    async fn v2_get_returns_null_for_missing_key() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).await.unwrap();
        let graph = Graph::load(store).await.unwrap();
        let graph = Arc::new(tokio::sync::RwLock::new(graph));
        let ctx = test_ctx(dir.path());

        let req = make_request(Command::Get(GetInput {
            key: "file:nonexistent".into(),
        }));
        let resp = dispatch_v2(&graph, &ctx, req).await;

        match resp {
            Response::Ok { data, .. } => {
                assert!(data.is_null(), "missing key should return null");
            }
            Response::Err { message, .. } => panic!("expected Ok(null), got Err: {message}"),
        }
    }

    #[tokio::test]
    async fn v2_session_log_writes_audit_to_sessions_tree() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).await.unwrap();
        let graph = Graph::load(store).await.unwrap();
        let graph = Arc::new(tokio::sync::RwLock::new(graph));
        let ctx = test_ctx(dir.path());

        let req = make_request(Command::SessionLog(SessionLogInput {
            event: SessionEvent::Miss,
            key: "file:test".into(),
        }));
        let resp = dispatch_v2(&graph, &ctx, req).await;
        assert!(matches!(resp, Response::Ok { .. }));

        // Audit should be in sessions tree (audit:session:* prefix).
        let g = graph.read().await;
        let session_audit_keys = g.store().scan_keys("audit:session:").await.unwrap();
        assert!(
            !session_audit_keys.is_empty(),
            "session-side mutation should produce audit:session:* entry"
        );
        // And NOT in knowledge tree.
        let knowledge_audit_keys = g.store().scan_keys("audit:knowledge:").await.unwrap();
        assert!(
            knowledge_audit_keys.is_empty(),
            "session-side mutation should not produce audit:knowledge:* entry"
        );
    }

    #[tokio::test]
    async fn v2_pure_read_does_not_write_audit() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).await.unwrap();
        let graph = Graph::load(store).await.unwrap();
        let graph = Arc::new(tokio::sync::RwLock::new(graph));
        let ctx = test_ctx(dir.path());

        let req = make_request(Command::Ping);
        let _ = dispatch_v2(&graph, &ctx, req).await;

        let g = graph.read().await;
        let session_keys = g.store().scan_keys("audit:session:").await.unwrap();
        let knowledge_keys = g.store().scan_keys("audit:knowledge:").await.unwrap();
        assert!(session_keys.is_empty() && knowledge_keys.is_empty());
    }

    #[tokio::test]
    async fn v2_audit_entry_contains_peer_identity() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).await.unwrap();
        let graph = Graph::load(store).await.unwrap();
        let graph = Arc::new(tokio::sync::RwLock::new(graph));

        let peer = PeerContext {
            uid: 12345,
            pid: Some(67890),
        };
        let daemon_session = test_session();
        let ctx = RequestContext {
            peer,
            daemon_session,
            repo_root: dir.path().to_path_buf(),
        };

        let req = make_request(Command::ConsultationHit(ConsultationHitInput {
            key: "file:test".into(),
        }));
        let request_id = req.id;
        let _ = dispatch_v2(&graph, &ctx, req).await;

        // Read back the audit entry from sessions tree.
        let g = graph.read().await;
        let audit_keys = g.store().scan_keys("audit:session:").await.unwrap();
        assert_eq!(audit_keys.len(), 1);

        let txn = g
            .store()
            .sessions_tree()
            .begin_with_mode(surrealkv::Mode::ReadOnly)
            .unwrap();
        let raw = txn.get(audit_keys[0].as_bytes()).unwrap().unwrap();
        let entry: AuditEntry = rmp_serde::from_slice(&raw).unwrap();

        assert_eq!(entry.peer_uid, 12345);
        assert_eq!(entry.peer_pid, Some(67890));
        assert_eq!(entry.daemon_session, daemon_session);
        assert_eq!(entry.request_id, request_id);
        assert_eq!(entry.command_kind, "consultation_hit");
        assert_eq!(entry.target_key, "file:test");
        assert!(entry.accepted);
        assert!(entry.error_code.is_none());
    }

    #[tokio::test]
    async fn v1_bridge_only_handles_pure_reads() {
        // The v1 bridge handles ONLY pure reads that have no native dispatch
        // arm. Mutations, side-effecting reads, AND `Command::MemQuery`
        // (γ-C1.5) are all handled natively. Verify the remaining v1 bridge
        // commands never produce "put" or "delete".
        //
        // Pre-γ-C1.5 this list contained 9 entries; MemQuery was the 9th.
        // It now lives in `dispatch_mem_query` — see the byte-identical
        // parity tests in `handlers::tests::mem_query_*`.
        let pure_read_commands: Vec<Command> = vec![
            Command::Ping,
            Command::Get(GetInput { key: "k".into() }),
            Command::HookEvaluate(HookEvaluateInput {
                file_key: "file:k".into(),
                include_recent: false,
            }),
            Command::ScanPrefix(ScanPrefixInput { prefix: "p".into() }),
            Command::History(HistoryInput {
                key: "k".into(),
                limit: 10,
            }),
            Command::HistorySince(HistorySinceInput {
                key: "k".into(),
                since_ts: 0,
                limit: 10,
            }),
            Command::SessionCheckConsulted(SessionCheckConsultedInput { key: "k".into() }),
            Command::SessionCheckConsultedRecent(SessionCheckConsultedRecentInput {
                key: "k".into(),
                ttl_secs: 900,
            }),
        ];

        assert_eq!(
            pure_read_commands.len(),
            8,
            "must cover all 8 pure read commands still routed via v1 bridge \
             (was 9 before γ-C1.5 moved MemQuery to a native arm)"
        );
        for cmd in pure_read_commands {
            assert!(!cmd.is_mutation(), "{} must not be a mutation", cmd.kind());
            assert!(
                !is_side_effecting_read(&cmd),
                "{} must not be a side-effecting read",
                cmd.kind()
            );
            let (v1_cmd, _) = command_to_v1(&cmd);
            assert_ne!(
                v1_cmd,
                "put",
                "v1 bridge must never produce 'put': got it for {}",
                cmd.kind()
            );
            assert_ne!(
                v1_cmd,
                "delete",
                "v1 bridge must never produce 'delete': got it for {}",
                cmd.kind()
            );
        }
    }

    #[test]
    fn no_mutation_or_side_effecting_read_reaches_v1_bridge() {
        // All 8 knowledge-side mutations + 4 session-side mutations + 1 compound
        // + 2 side-effecting reads are handled natively. Only pure reads go
        // through the v1 bridge.
        let all_mutations: Vec<Command> = vec![
            Command::GotchaUpsert(GotchaDraftInput {
                key: "gotcha:t".into(),
                rule: "r".into(),
                reason: "r".into(),
                severity: Severity::Normal,
                affected_files: vec![],
                ref_url: None,
                tags: vec![],
                priority: Priority::Normal,
                source: None,
            }),
            Command::GotchaConfirm(GotchaConfirmInput {
                key: "gotcha:t".into(),
            }),
            Command::GotchaTombstone(GotchaTombstoneInput {
                key: "gotcha:t".into(),
            }),
            Command::FileEnrich(FileEnrichInput {
                path: "p".into(),
                purpose: "p".into(),
                entry_points: vec![],
                decision_keys: vec![],
                todos: vec![],
                tags: vec![],
                priority: Priority::Normal,
            }),
            Command::FileReparse(FileReparseInput { path: "p".into() }),
            Command::FileEditHook(FileEditHookInput { path: "p".into() }),
            Command::DocCapture(DocCaptureInput { path: "p".into() }),
            Command::DecisionUpsert(DecisionUpsertInput {
                slug: "s".into(),
                value: "v".into(),
                summary: "s".into(),
                rationale: "r".into(),
                tags: vec![],
                priority: Priority::Normal,
            }),
            Command::DevNoteUpsert(DevNoteUpsertInput {
                key: None,
                text: "t".into(),
                tags: vec![],
                priority: Priority::Normal,
            }),
            Command::SessionLog(SessionLogInput {
                event: SessionEvent::Miss,
                key: "k".into(),
            }),
            Command::ConsultationHit(ConsultationHitInput { key: "k".into() }),
            Command::SessionFlush,
            Command::SessionHarvest,
            // Side-effecting reads.
            Command::MemGet(MemGetInput { key: "k".into() }),
            Command::MemBootstrap(MemBootstrapInput {
                context_files: vec![],
            }),
        ];
        for cmd in &all_mutations {
            assert!(
                is_knowledge_mutation(cmd)
                    || is_session_side(cmd)
                    || is_compound(cmd)
                    || is_side_effecting_read(cmd),
                "{} must be handled natively, not via v1 bridge",
                cmd.kind()
            );
        }
    }

    #[tokio::test]
    async fn knowledge_side_mutation_audit_goes_to_knowledge_tree() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).await.unwrap();
        let graph = Graph::load(store).await.unwrap();
        let graph = Arc::new(tokio::sync::RwLock::new(graph));
        let ctx = test_ctx(dir.path());

        // GotchaConfirm is knowledge-side. It will fail (no record), but
        // should still produce a knowledge-tree audit entry.
        let req = make_request(Command::GotchaConfirm(GotchaConfirmInput {
            key: "gotcha:nonexistent".into(),
        }));
        let resp = dispatch_v2(&graph, &ctx, req).await;
        assert!(matches!(resp, Response::Err { .. }));

        let g = graph.read().await;
        let knowledge_audit = g.store().scan_keys("audit:knowledge:").await.unwrap();
        assert!(
            !knowledge_audit.is_empty(),
            "knowledge-side mutation should produce audit:knowledge:* entry"
        );
        let session_audit = g.store().scan_keys("audit:session:").await.unwrap();
        assert!(
            session_audit.is_empty(),
            "knowledge-side mutation should NOT produce audit:session:* entry"
        );
    }

    // ── Native MemGet / MemBootstrap tests ──────────────────────────────

    #[tokio::test]
    async fn native_mem_get_empty_key_returns_error_with_rejection_audit() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).await.unwrap();
        let graph = Graph::load(store).await.unwrap();
        let graph = Arc::new(tokio::sync::RwLock::new(graph));
        let ctx = test_ctx(dir.path());

        let req = make_request(Command::MemGet(MemGetInput { key: "".into() }));
        let resp = dispatch_v2(&graph, &ctx, req).await;

        // Must return Response::Err, not Response::Ok with error payload.
        match resp {
            Response::Err { code, .. } => {
                assert_eq!(code, ErrorCode::ValidationFailed);
            }
            Response::Ok { data, .. } => {
                panic!("empty key must return Response::Err, got Ok with: {data}")
            }
        }

        // Rejection audit must exist in sessions tree with accepted=false.
        let g = graph.read().await;
        let audit_keys = g.store().scan_keys("audit:session:").await.unwrap();
        assert!(
            !audit_keys.is_empty(),
            "empty-key rejection must produce session audit"
        );
        let txn = g
            .store()
            .sessions_tree()
            .begin_with_mode(surrealkv::Mode::ReadOnly)
            .unwrap();
        let raw = txn.get(audit_keys[0].as_bytes()).unwrap().unwrap();
        let entry: AuditEntry = rmp_serde::from_slice(&raw).unwrap();
        assert!(!entry.accepted, "rejection audit must have accepted=false");
        assert_eq!(entry.error_code, Some(ErrorCode::ValidationFailed));
    }

    #[tokio::test]
    async fn native_mem_get_returns_null_for_missing_key() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).await.unwrap();
        let graph = Graph::load(store).await.unwrap();
        let graph = Arc::new(tokio::sync::RwLock::new(graph));
        let ctx = test_ctx(dir.path());

        let req = make_request(Command::MemGet(MemGetInput {
            key: "file:nonexistent".into(),
        }));
        let resp = dispatch_v2(&graph, &ctx, req).await;

        match resp {
            Response::Ok { data, .. } => assert!(data.is_null()),
            Response::Err { message, .. } => panic!("expected Ok(null): {message}"),
        }
    }

    #[tokio::test]
    async fn native_mem_get_writes_session_audit_and_consultation_receipt() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).await.unwrap();
        let graph = Graph::load(store).await.unwrap();
        let graph = Arc::new(tokio::sync::RwLock::new(graph));
        let ctx = test_ctx(dir.path());

        let req = make_request(Command::MemGet(MemGetInput {
            key: "file:src/main.rs".into(),
        }));
        let _ = dispatch_v2(&graph, &ctx, req).await;

        let g = graph.read().await;
        // Audit should be in sessions tree.
        let audit_keys = g.store().scan_keys("audit:session:").await.unwrap();
        assert!(
            !audit_keys.is_empty(),
            "MemGet should produce session-side audit"
        );

        // Consultation receipt should exist.
        let consulted = g
            .store()
            .get("session:consulted:file:src/main.rs")
            .await
            .unwrap();
        assert!(
            consulted.is_some(),
            "MemGet should write consultation receipt"
        );

        // No knowledge-side audit.
        let k_audit = g.store().scan_keys("audit:knowledge:").await.unwrap();
        assert!(
            k_audit.is_empty(),
            "MemGet should NOT produce knowledge-side audit"
        );
    }

    #[tokio::test]
    async fn native_mem_bootstrap_writes_session_audit() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).await.unwrap();
        let graph = Graph::load(store).await.unwrap();
        let graph = Arc::new(tokio::sync::RwLock::new(graph));
        let ctx = test_ctx(dir.path());

        let req = make_request(Command::MemBootstrap(MemBootstrapInput {
            context_files: vec![],
        }));
        let resp = dispatch_v2(&graph, &ctx, req).await;

        // Should return an injection string.
        match resp {
            Response::Ok { data, .. } => {
                assert!(data.is_string(), "MemBootstrap should return a string");
            }
            Response::Err { message, .. } => panic!("expected Ok: {message}"),
        }

        let g = graph.read().await;
        let audit_keys = g.store().scan_keys("audit:session:").await.unwrap();
        assert!(
            !audit_keys.is_empty(),
            "MemBootstrap should produce session-side audit"
        );
    }

    #[tokio::test]
    async fn version_mismatch_cannot_reach_side_effecting_read() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).await.unwrap();
        let graph = Graph::load(store).await.unwrap();
        let graph = Arc::new(tokio::sync::RwLock::new(graph));
        let ctx = test_ctx(dir.path());

        // Version 99 + MemGet: version check must reject before any side effect.
        let req = Request {
            v: 99,
            id: Uuid::new_v4(),
            session: Uuid::new_v4(),
            agent: None,
            cmd: Command::MemGet(MemGetInput {
                key: "file:test".into(),
            }),
        };
        let resp = dispatch_v2(&graph, &ctx, req).await;
        assert!(matches!(
            resp,
            Response::Err {
                code: ErrorCode::VersionMismatch,
                ..
            }
        ));

        // No consultation receipt should exist.
        let g = graph.read().await;
        let consulted = g.store().get("session:consulted:file:test").await.unwrap();
        assert!(
            consulted.is_none(),
            "version mismatch must not write consultation receipt"
        );
    }

    #[tokio::test]
    async fn session_log_mutation_and_audit_are_both_in_sessions_tree() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).await.unwrap();
        let graph = Graph::load(store).await.unwrap();
        let graph = Arc::new(tokio::sync::RwLock::new(graph));
        let ctx = test_ctx(dir.path());

        let req = make_request(Command::SessionLog(SessionLogInput {
            event: SessionEvent::ComplianceMiss,
            key: "file:src/auth.rs".into(),
        }));
        let resp = dispatch_v2(&graph, &ctx, req).await;
        assert!(matches!(resp, Response::Ok { .. }));

        let g = graph.read().await;
        // Both the compliance agg and audit should be in sessions tree.
        let compliance_keys = g.store().scan_keys("compliance:miss_").await.unwrap();
        assert!(
            !compliance_keys.is_empty(),
            "SessionLog should write compliance agg"
        );
        let audit_keys = g.store().scan_keys("audit:session:").await.unwrap();
        assert!(
            !audit_keys.is_empty(),
            "SessionLog should write session-side audit"
        );
        // Nothing in knowledge tree.
        let k_audit = g.store().scan_keys("audit:knowledge:").await.unwrap();
        assert!(k_audit.is_empty());
    }

    /// Regression: SessionLog with CodexShellMiss must produce a
    /// `BypassDetected` enforcement event in the hash-chained log, not just
    /// a daily aggregate. Smoke finding #128 — pre-fix, the event was
    /// invisible to `mati history --enforcement`.
    #[tokio::test]
    async fn session_log_codex_shell_miss_records_bypass_enforcement_event() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).await.unwrap();
        let graph = Graph::load(store).await.unwrap();
        let graph = Arc::new(tokio::sync::RwLock::new(graph));
        let ctx = test_ctx(dir.path());

        let req = make_request(Command::SessionLog(SessionLogInput {
            event: SessionEvent::CodexShellMiss,
            key: "file:src/cli/repair.rs".into(),
        }));
        let resp = dispatch_v2(&graph, &ctx, req).await;
        assert!(matches!(resp, Response::Ok { .. }));

        let g = graph.read().await;

        // Daily aggregate (unchanged from pre-fix behavior).
        let agg = g
            .store()
            .scan_keys("compliance:codex_shell_miss_")
            .await
            .unwrap();
        assert!(!agg.is_empty(), "codex_shell_miss daily agg must be written");

        // NEW: enforcement event in the hash-chained log so `mati history`
        // surfaces it. Pre-fix the scan returned empty.
        let events = crate::store::enforcement::scan_events_since(g.store(), 0)
            .await
            .expect("scan enforcement events");
        assert!(
            !events.is_empty(),
            "CodexShellMiss must record a hash-chained enforcement event \
             (label='bypass') — regression for smoke finding #128"
        );

        let evt = &events[0];
        assert_eq!(
            evt.agent_type, "codex",
            "codex-post-bash event must attribute agent=codex, got: {evt:?}"
        );
        assert_eq!(
            evt.subject_key, "file:src/cli/repair.rs",
            "subject_key must match input.key"
        );
        assert!(
            matches!(
                evt.event_type,
                crate::store::enforcement::EnforcementEventType::BypassDetected
            ),
            "event_type must be BypassDetected, got: {:?}",
            evt.event_type
        );

        // Sanity: the CLI label that `mati history --enforcement` would show
        // for this event is "bypass" (per src/store/enforcement.rs:1000).
        assert_eq!(
            crate::store::enforcement::event_type_label(&evt.event_type),
            "bypass"
        );
    }

    #[tokio::test]
    async fn v2_session_mismatch_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).await.unwrap();
        let graph = Graph::load(store).await.unwrap();
        let graph = Arc::new(tokio::sync::RwLock::new(graph));
        let ctx = test_ctx(dir.path());

        // Construct a request with a different session UUID.
        let req = Request {
            v: PROTOCOL_VERSION,
            id: Uuid::new_v4(),
            session: Uuid::new_v4(), // does NOT match test_session()
            agent: None,
            cmd: Command::Ping,
        };
        let resp = dispatch_v2(&graph, &ctx, req).await;

        match resp {
            Response::Err { code, message, .. } => {
                assert_eq!(code, ErrorCode::SessionMismatch);
                assert!(
                    message.contains("re-read daemon metadata"),
                    "error should guide the client to retry: {message}"
                );
            }
            Response::Ok { .. } => panic!("expected SessionMismatch error"),
        }
    }

    #[tokio::test]
    async fn v2_matching_session_passes_fence() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).await.unwrap();
        let graph = Graph::load(store).await.unwrap();
        let graph = Arc::new(tokio::sync::RwLock::new(graph));
        let ctx = test_ctx(dir.path());

        // make_request uses test_session() which matches ctx.daemon_session.
        let req = make_request(Command::Ping);
        let resp = dispatch_v2(&graph, &ctx, req).await;

        match resp {
            Response::Ok { data, .. } => {
                assert_eq!(data, serde_json::json!("pong"));
            }
            Response::Err { message, .. } => panic!("expected Ok, got Err: {message}"),
        }
    }

    #[tokio::test]
    async fn file_edit_hook_consultation_substep_writes_receipt_and_audit_atomically() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).await.unwrap();
        let graph = Graph::load(store).await.unwrap();
        let graph = Arc::new(tokio::sync::RwLock::new(graph));
        let ctx = test_ctx(dir.path());

        // Create a dummy file so reparse doesn't need real filesystem.
        let test_path = dir.path().join("test.rs");
        std::fs::write(&test_path, "fn main() {}").unwrap();

        let req = make_request(Command::FileEditHook(FileEditHookInput {
            path: "test.rs".into(),
        }));
        let resp = dispatch_v2(&graph, &ctx, req).await;
        assert!(matches!(resp, Response::Ok { .. }));

        let g = graph.read().await;

        // Session-side audit must exist (from consultation substep).
        let audit_keys = g.store().scan_keys("audit:session:").await.unwrap();
        assert!(
            !audit_keys.is_empty(),
            "FileEditHook consultation substep must produce session-side audit"
        );

        // Consultation receipt must exist (staged + committed atomically with audit).
        let consulted = g
            .store()
            .get("session:consulted:file:test.rs")
            .await
            .unwrap();
        assert!(
            consulted.is_some(),
            "FileEditHook consultation substep must write consultation receipt"
        );

        // Daily hit agg must exist (staged + committed atomically with audit).
        let hit_keys = g.store().scan_keys("analytics:hit_").await.unwrap();
        assert!(
            !hit_keys.is_empty(),
            "FileEditHook consultation substep must write daily hit agg"
        );

        // Verify the audit entry is for the consultation substep.
        let txn = g
            .store()
            .sessions_tree()
            .begin_with_mode(surrealkv::Mode::ReadOnly)
            .unwrap();
        let raw = txn.get(audit_keys[0].as_bytes()).unwrap().unwrap();
        let entry: AuditEntry = rmp_serde::from_slice(&raw).unwrap();
        assert_eq!(entry.command_kind, "file_edit_hook:consultation");
        assert!(entry.accepted);
    }

    /// ConfigGet routes through the dedicated native dispatcher and returns
    /// the default value (`advisory`) when nothing has been written yet.
    #[tokio::test]
    async fn config_get_returns_default_enforcement_mode() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).await.unwrap();
        let graph = Graph::load(store).await.unwrap();
        let graph = Arc::new(tokio::sync::RwLock::new(graph));
        let ctx = test_ctx(dir.path());

        let req = make_request(Command::ConfigGet(ConfigGetInput {
            key: "enforcement.mode".into(),
        }));
        let resp = dispatch_v2(&graph, &ctx, req).await;

        match resp {
            Response::Ok { data, .. } => assert_eq!(data, serde_json::json!("advisory")),
            Response::Err { message, .. } => panic!("expected Ok, got Err: {message}"),
        }
    }

    /// ConfigSet writes the value via the daemon path; the next ConfigGet
    /// reflects the new value end-to-end through dispatch_v2.
    #[tokio::test]
    async fn config_set_then_get_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).await.unwrap();
        let graph = Graph::load(store).await.unwrap();
        let graph = Arc::new(tokio::sync::RwLock::new(graph));
        let ctx = test_ctx(dir.path());

        let set_req = make_request(Command::ConfigSet(ConfigSetInput {
            key: "enforcement.mode".into(),
            value: "strict".into(),
        }));
        let set_resp = dispatch_v2(&graph, &ctx, set_req).await;
        match set_resp {
            Response::Ok { data, .. } => {
                assert_eq!(data, serde_json::json!({ "old": "advisory" }));
            }
            Response::Err { message, .. } => panic!("expected Ok, got Err: {message}"),
        }

        let get_req = make_request(Command::ConfigGet(ConfigGetInput {
            key: "enforcement.mode".into(),
        }));
        let get_resp = dispatch_v2(&graph, &ctx, get_req).await;
        match get_resp {
            Response::Ok { data, .. } => assert_eq!(data, serde_json::json!("strict")),
            Response::Err { message, .. } => panic!("expected Ok, got Err: {message}"),
        }
    }

    /// Invalid enforcement mode value is rejected with ValidationFailed —
    /// the daemon never persists garbage values.
    #[tokio::test]
    async fn config_set_rejects_invalid_enforcement_mode() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).await.unwrap();
        let graph = Graph::load(store).await.unwrap();
        let graph = Arc::new(tokio::sync::RwLock::new(graph));
        let ctx = test_ctx(dir.path());

        let req = make_request(Command::ConfigSet(ConfigSetInput {
            key: "enforcement.mode".into(),
            value: "paranoid".into(),
        }));
        let resp = dispatch_v2(&graph, &ctx, req).await;
        match resp {
            Response::Err { code, .. } => assert_eq!(code, ErrorCode::ValidationFailed),
            Response::Ok { .. } => panic!("expected Err, got Ok"),
        }
    }

    /// Unknown config key surfaces ValidationFailed on both get and set.
    #[tokio::test]
    async fn config_unknown_key_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).await.unwrap();
        let graph = Graph::load(store).await.unwrap();
        let graph = Arc::new(tokio::sync::RwLock::new(graph));
        let ctx = test_ctx(dir.path());

        let get_req = make_request(Command::ConfigGet(ConfigGetInput {
            key: "nope.nope".into(),
        }));
        match dispatch_v2(&graph, &ctx, get_req).await {
            Response::Err { code, .. } => assert_eq!(code, ErrorCode::ValidationFailed),
            Response::Ok { .. } => panic!("expected ValidationFailed for unknown get key"),
        }

        let set_req = make_request(Command::ConfigSet(ConfigSetInput {
            key: "nope.nope".into(),
            value: "x".into(),
        }));
        match dispatch_v2(&graph, &ctx, set_req).await {
            Response::Err { code, .. } => assert_eq!(code, ErrorCode::ValidationFailed),
            Response::Ok { .. } => panic!("expected ValidationFailed for unknown set key"),
        }
    }
}
