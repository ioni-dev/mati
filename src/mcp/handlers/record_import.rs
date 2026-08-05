//! RecordImport handler.

use super::*;

// ── RecordImport ────────────────────────────────────────────────────────────

/// Bulk-import knowledge-tree records verbatim. Splits the input into chunks
/// and commits each chunk in one `transact_knowledge` call so an entire
/// `mati export` round-trip completes in O(chunks) socket round-trips instead
/// of O(records).
///
/// Records are partitioned by key prefix: any record whose `Durability::for_key`
/// classifies as `Eventual` (session/analytics/audit/etc.) is skipped with a
/// per-record skipped count returned to the client — those are daemon-owned
/// runtime state, not user-authored knowledge, and have no place in an
/// import payload.
///
/// Each chunk gets one audit row (target_key: count) so the audit log records
/// the import without ballooning by 1500× entries.
pub(crate) async fn handle_record_import(
    store: &Store,
    ctx: &RequestContext,
    request_id: Uuid,
    input: &protocol::RecordImportInput,
) -> HandlerResult {
    // Chunk size: bigger = fewer round-trips but more per-transaction memory.
    // 200 records per transaction balances throughput against the SurrealKV
    // transaction-size sweet spot.
    const CHUNK: usize = 200;

    let mut imported: u64 = 0;
    let mut skipped: u64 = 0;
    let mut chunk_buf: Vec<&Record> = Vec::with_capacity(CHUNK);

    let valid_prefixes = [
        "gotcha:",
        "decision:",
        "dev_note:",
        "file:",
        "stage:",
        "dep:",
        // Policies are user-authored source of truth and belong in a
        // backup. show::deactivate_imported_policies lands them at stage
        // off, so a restore never silently starts enforcing.
        "policy:",
    ];

    // First pass: filter records into knowledge-tree-only buckets and skip
    // anything that would route to the sessions tree or fails the prefix
    // allowlist. This mirrors `transact_knowledge`'s precondition check;
    // doing it upfront avoids aborting a 200-record transaction over a
    // single stray record.
    let mut accepted_refs: Vec<&Record> = Vec::with_capacity(input.records.len());
    for r in &input.records {
        let key_str = r.key.as_str();
        if !valid_prefixes.iter().any(|p| key_str.starts_with(p)) {
            skipped += 1;
            continue;
        }
        if crate::store::Durability::for_key(key_str) != crate::store::Durability::Immediate {
            skipped += 1;
            continue;
        }
        accepted_refs.push(r);
    }

    for chunk in accepted_refs.chunks(CHUNK) {
        chunk_buf.clear();
        chunk_buf.extend(chunk.iter().copied());

        // One audit row per chunk. target_key encodes the chunk size so
        // operators can correlate audit entries with import progress.
        let chunk_target = format!("record_import:{}records", chunk_buf.len());
        let audit = make_audit(ctx, request_id, "record_import", &chunk_target, true, None)
            .ok_or_else(|| (ErrorCode::Internal, "audit serialization failed".into()))?;

        let mut ops: Vec<KnowledgeWriteOp<'_>> = Vec::with_capacity(chunk_buf.len() + 1);
        for r in &chunk_buf {
            ops.push(KnowledgeWriteOp::PutRecord {
                key: r.key.as_str(),
                record: r,
            });
        }
        ops.push(KnowledgeWriteOp::PutRaw {
            key: &audit.0,
            value: &audit.1,
        });

        store.transact_knowledge(&ops).await.map_err(|e| {
            (
                ErrorCode::StoreError,
                format!("import transact failed: {e}"),
            )
        })?;

        imported += chunk_buf.len() as u64;
    }

    Ok(serde_json::json!({
        "ok": true,
        "imported": imported,
        "skipped": skipped,
    }))
}
