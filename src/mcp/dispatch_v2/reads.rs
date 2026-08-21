//! Pure-read and side-effecting-read dispatch.

use super::*;

// ── Side-effecting read handlers ────────────────────────────────────────────

/// Pure-read native dispatch for `Command::MemQuery`. Calls
/// `handle_mem_query` directly — no audit, no consultation receipt, no
/// deferred writes. γ-C1.5 contract: v1-string and v2-typed paths produce
/// byte-identical responses for the same MemQueryInput.
pub(super) async fn dispatch_mem_query(
    graph: &Arc<tokio::sync::RwLock<Graph>>,
    req: &Request,
) -> Response {
    use crate::mcp::handlers;
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

pub(super) async fn dispatch_side_effecting_read(
    graph: &Arc<tokio::sync::RwLock<Graph>>,
    ctx: &RequestContext,
    req: &Request,
) -> Response {
    use crate::mcp::handlers;
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

// ── V1 bridge (internal adapter) ────────────────────────────────────────────
//
// Converts v2 Command variants into v1 SocketRequest format and delegates to
// the existing socket_dispatch. This is an INTERNAL adapter — not reachable
// from the wire. The raw `put` and `delete` arms in socket_dispatch are
// unreachable because no Command variant maps to "put" or "delete".

pub(super) async fn dispatch_via_v1(
    graph: &Arc<tokio::sync::RwLock<Graph>>,
    ctx: &RequestContext,
    req: &Request,
) -> Response {
    use crate::mcp::server::{socket_dispatch, SocketRequest};

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
pub(super) fn command_to_v1(cmd: &Command) -> (String, serde_json::Value) {
    use serde_json::json;

    match cmd {
        // A. Pure reads
        Command::Ping => ("ping".into(), json!({})),
        Command::Metrics => ("metrics".into(), json!({})),
        Command::Get(i) => ("get".into(), json!({ "key": i.key })),
        Command::HookEvaluate(i) => (
            "hook_evaluate".into(),
            json!({ "file_key": i.file_key, "include_recent": i.include_recent, "actor": i.actor }),
        ),
        Command::PolicyEvaluate(_) => {
            unreachable!("PolicyEvaluate is handled natively, not via v1 bridge")
        }
        Command::ScanPrefix(i) => ("scan_prefix".into(), json!({ "prefix": i.prefix })),
        Command::ScanKeys(i) => ("scan_keys".into(), json!({ "prefix": i.prefix })),
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
        Command::ScanEnforcementEventsWithSkips(i) => (
            "scan_enforcement_events_with_skips".into(),
            json!({ "since_seq": i.since_seq, "until_seq": i.until_seq }),
        ),
        Command::ScanEnforcementEventsSinceMs(i) => (
            "scan_enforcement_events_since_ms".into(),
            json!({ "since_ms": i.since_ms, "until_ms": i.until_ms }),
        ),

        // B. Reads with side effects — handled natively, not via v1 bridge.
        Command::MemGet(_) | Command::MemBootstrap(_) => {
            unreachable!("side-effecting reads are handled natively, not via v1 bridge")
        }

        // Knowledge-side mutations are handled by native handlers — not via v1 bridge.
        Command::GotchaUpsert(_)
        | Command::GotchaConfirm(_)
        | Command::GotchaTombstone(_)
        | Command::PolicyWrite(_)
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
        | Command::InstructionsLoaded(_)
        | Command::ConsultationHit(_)
        | Command::PolicyShadowObserve(_)
        | Command::SessionFlush
        | Command::SessionHarvest
        | Command::SessionClearConsults
        | Command::SubagentHarvest(_) => {
            unreachable!("session-side commands are handled natively, not via v1 bridge")
        }

        // Config commands are handled natively — should not reach here.
        Command::ConfigGet(_) | Command::ConfigSet(_) | Command::SandboxAudit(_) => {
            unreachable!("config commands are handled natively, not via v1 bridge")
        }
    }
}
