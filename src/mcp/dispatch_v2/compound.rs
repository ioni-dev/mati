//! FileEditHook — the one compound (multi-tree) command.

use super::*;

// ── FileEditHook — compound command ─────────────────────────────────────────
//
// Substep 1: edit-activity tracking (sessions tree) — best-effort.
// Substep 2: FileReparse (knowledge tree) — native handler with audit.
// Each substep writes its own audit in its respective tree.

pub(super) async fn dispatch_file_edit_hook(
    graph: &Arc<tokio::sync::RwLock<Graph>>,
    ctx: &RequestContext,
    req: &Request,
) -> Response {
    let input = match &req.cmd {
        Command::FileEditHook(i) => i,
        _ => unreachable!(),
    };
    let request_id = req.id;

    // Substep 1: edit-activity tracking (sessions tree, best-effort).
    //
    // Daily `analytics:hit_` aggregate + audit committed atomically in one
    // sessions-tree transaction. Cross-tree access_count bump is a separate
    // best-effort write. The whole substep is non-blocking — staging or
    // transaction failures are logged, never propagated.
    //
    // Deliberately mints NO consultation receipt. A receipt is proof the agent
    // READ the record (`run_post_memget`), and an edit is not a consultation:
    // minting here let an edit that slipped through a fail-open suppress every
    // later deny on that file, and refreshed the `consulted_recent` TTL the
    // `claude-pre-edit` backstop is keyed on so that gate could never fire.
    // The receipt was incidental to the `mati log-hit` this hook replaced,
    // whose stated job was edit-activity tracking; the tracking stays.
    {
        let g = graph.read().await;
        let store = g.store();
        let file_key = format!("file:{}", input.path);

        // Stage session-tree writes.
        let agg_key = sess::today_key("analytics:hit_");
        let staged_agg = sess::upsert_daily_agg_staged(store, &agg_key, &file_key).await;
        let audit_entry = build_audit_entry(
            ctx,
            request_id,
            "file_edit_hook:activity",
            &file_key,
            true,
            None,
        );
        let audit_key = audit_nanos_key("audit:session:");
        let audit_bytes = serialize_audit(&audit_entry);

        // Atomic commit: agg + audit (all sessions tree).
        let mut writes: Vec<(&str, &[u8])> = Vec::new();
        if let Ok(ref agg) = staged_agg {
            writes.push((&agg.0, &agg.1));
        }
        if let Some(ref ab) = audit_bytes {
            writes.push((&audit_key, ab));
        }

        if let Err(e) = store.transact_sessions_raw(&writes).await {
            tracing::warn!(
                request_id = %request_id,
                "file_edit_hook: activity substep sessions transaction failed: {e}"
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
        match crate::mcp::handlers::handle_file_reparse(
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
