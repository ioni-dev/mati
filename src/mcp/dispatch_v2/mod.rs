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
//! - **Pure reads** (9 commands): v1 bridge for read-only dispatch. No
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

mod compound;
mod knowledge;
mod reads;
mod session;

#[cfg(test)]
mod tests;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use uuid::Uuid;

use crate::graph::Graph;
use crate::hooks::policy_match::PolicyMatcherSet;
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
    /// Daemon-resident compiled local policies.
    pub policy_matcher: Arc<tokio::sync::RwLock<PolicyMatcherSet>>,
}

/// Load the daemon's compiled policy set from the canonical policy records.
pub async fn load_policy_matcher(store: &crate::store::Store) -> PolicyMatcherSet {
    match store.scan_prefix("policy:").await {
        Ok(records) => PolicyMatcherSet::from_records_lenient(&records),
        Err(error) => {
            tracing::warn!(error = %error, "daemon: policy matcher boot scan failed");
            PolicyMatcherSet::empty()
        }
    }
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
        // DaemonMetadata and retry once.
        //
        // A nil request session is not a stale client. It means the client
        // connected in the window after the socket was bound but before the
        // daemon published its session (cold start binds first, publishes
        // metadata next), so `read_metadata` found nothing and the client sent
        // `Uuid::nil`. Serve it: it holds no opinion about which instance it
        // reached, and rejecting it both forces a client retry and records a
        // phantom error in the metrics ring. A genuinely stale client after a
        // restart sends its OLD non-nil session, which still mismatches here.
        if !req.session.is_nil() && req.session != ctx.daemon_session {
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
        // Only pure reads (9 commands) use the v1 bridge, which cannot
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
        } else if matches!(&req.cmd, Command::PolicyEvaluate(_)) {
            dispatch_policy_evaluate(graph, ctx, &req).await
        } else if matches!(&req.cmd, Command::SessionOwedReceipt(_)) {
            dispatch_owed_receipt(graph, &req).await
        } else if is_session_side(&req.cmd) {
            // Session-side mutations: native handler with audit in sessions tree.
            dispatch_session_side(graph, ctx, &req).await
        } else if is_knowledge_mutation(&req.cmd) {
            // Knowledge-side mutations: native handler with atomic mutation+audit
            // in one transact_knowledge commit.
            if matches!(&req.cmd, Command::PolicyWrite(_)) {
                dispatch_policy_write(graph, ctx, &req).await
            } else {
                dispatch_knowledge_mutation(graph, ctx, &req).await
            }
        } else if is_compound(&req.cmd) {
            // FileEditHook: compound (edit activity in sessions + reparse in knowledge).
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
            | Command::InstructionsLoaded(_)
            | Command::ConsultationHit(_)
            | Command::PolicyShadowObserve(_)
            | Command::SessionFlush
            | Command::SessionHarvest(_)
            | Command::SessionClearConsults
            | Command::SubagentHarvest(_)
            | Command::SubagentSpawned(_)
            | Command::SubagentEdge(_)
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
            | Command::PolicyWrite(_)
            | Command::FileEnrich(_)
            | Command::FileReparse(_)
            | Command::DocCapture(_)
            | Command::DecisionUpsert(_)
            | Command::DevNoteUpsert(_)
            | Command::RecordImport(_)
    )
}

/// FileEditHook is a compound: edit-activity tracking (session) + FileReparse
/// (knowledge). Handled by dispatching to both paths — not a single-tree
/// transaction.
fn is_compound(cmd: &Command) -> bool {
    matches!(cmd, Command::FileEditHook(_))
}

/// Returns true for runtime configuration commands. These touch raw key/value
/// pairs (`enforcement:mode`, `enforcement:retention_days`, `enforcement:policy_mode`) and are routed
/// through a dedicated dispatcher rather than the v1 bridge or the typical
/// knowledge-mutation transactional audit path.
fn is_config_command(cmd: &Command) -> bool {
    matches!(
        cmd,
        Command::ConfigGet(_) | Command::ConfigSet(_) | Command::SandboxAudit(_)
    )
}

/// Dispatch ConfigGet / ConfigSet against the daemon's store.
///
/// ConfigGet is a pure read with no audit entry. ConfigSet calls the
/// enforcement helpers, which already write an `EnforcementConfigChanged`
/// event whenever the value actually changes — that event is the durable
/// audit trail for config mutations.
async fn dispatch_config(graph: &Arc<tokio::sync::RwLock<Graph>>, req: &Request) -> Response {
    use crate::store::enforcement::{
        get_enforcement_mode, get_lockdown, get_policy_mode, get_retention_days,
        set_enforcement_mode, set_lockdown, set_policy_mode, set_retention_days, EnforcementMode,
    };

    let request_id = req.id;
    let g = graph.read().await;
    let store = g.store();

    match &req.cmd {
        Command::ConfigGet(input) => {
            let value = match input.key.as_str() {
                "audit.write_durability" => {
                    let mode = get_enforcement_mode(store).await;
                    match mode {
                        EnforcementMode::Advisory => "best_effort".to_string(),
                        EnforcementMode::Strict => "strict".to_string(),
                    }
                }
                "enforcement.retention" => get_retention_days(store).await.to_string(),
                "policy.mode" => match get_policy_mode(store).await {
                    EnforcementMode::Advisory => "advisory".to_string(),
                    EnforcementMode::Strict => "strict".to_string(),
                },
                "enforcement.lockdown" => if get_lockdown(store).await {
                    "on".to_string()
                } else {
                    "off".to_string()
                },
                other => {
                    return Response::err(
                        request_id,
                        ErrorCode::ValidationFailed,
                        format!(
                            "unknown config key: {other}; valid keys: audit.write_durability, enforcement.retention, policy.mode, enforcement.lockdown"
                        ),
                    );
                }
            };
            Response::ok(request_id, serde_json::Value::String(value))
        }
        Command::ConfigSet(input) => match input.key.as_str() {
            "audit.write_durability" => {
                let mode = match input.value.as_str() {
                    "best_effort" => EnforcementMode::Advisory,
                    "strict" => EnforcementMode::Strict,
                    other => {
                        return Response::err(
                            request_id,
                            ErrorCode::ValidationFailed,
                            format!(
                                "invalid audit.write_durability: {other}; valid values: best_effort, strict"
                            ),
                        );
                    }
                };
                match set_enforcement_mode(store, mode).await {
                    Ok(old) => {
                        let old_label = match old {
                            EnforcementMode::Advisory => "best_effort",
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
            "policy.mode" => {
                let mode = match input.value.as_str() {
                    "advisory" => EnforcementMode::Advisory,
                    "strict" => EnforcementMode::Strict,
                    other => {
                        return Response::err(
                            request_id,
                            ErrorCode::ValidationFailed,
                            format!(
                                "invalid policy.mode: {other}; valid values: advisory, strict"
                            ),
                        );
                    }
                };
                match set_policy_mode(store, mode).await {
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
            "enforcement.lockdown" => {
                let on = match input.value.as_str() {
                    "on" => true,
                    "off" => false,
                    other => {
                        return Response::err(
                            request_id,
                            ErrorCode::ValidationFailed,
                            format!(
                                "invalid enforcement.lockdown: {other}; valid values: on, off"
                            ),
                        );
                    }
                };
                match set_lockdown(store, on).await {
                    Ok(old) => {
                        let old_label = if old { "on" } else { "off" };
                        Response::ok(request_id, serde_json::json!({ "old": old_label }))
                    }
                    Err(e) => Response::err(request_id, ErrorCode::StoreError, e.to_string()),
                }
            }
            other => Response::err(
                request_id,
                ErrorCode::ValidationFailed,
                format!(
                    "unknown config key: {other}; valid keys: audit.write_durability, enforcement.retention, policy.mode, enforcement.lockdown"
                ),
            ),
        },
        Command::SandboxAudit(input) => {
            // Best-effort: record the L3 sandbox-floor change as an
            // EnforcementConfigChanged event in the hash-chained log (socket-mode
            // counterpart of the CLI's direct-mode recording).
            let _ = crate::store::enforcement::record_event(
                store,
                crate::store::enforcement::EnforcementEventType::EnforcementConfigChanged {
                    setting: input.setting.clone(),
                    old_value: input.old_value.clone(),
                    new_value: input.new_value.clone(),
                },
                crate::store::enforcement::SubjectKind::Config,
                input.setting.clone(),
                "cli".to_string(),
                None,
                input.reason.clone(),
                None,
            )
            .await;
            Response::ok(request_id, serde_json::Value::Null)
        }
        _ => unreachable!("is_config_command guard"),
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

use compound::dispatch_file_edit_hook;
use knowledge::{dispatch_knowledge_mutation, dispatch_policy_evaluate, dispatch_policy_write};
#[cfg(test)]
use reads::command_to_v1;
use reads::{
    dispatch_mem_query, dispatch_owed_receipt, dispatch_side_effecting_read, dispatch_via_v1,
};
use session::dispatch_session_side;
