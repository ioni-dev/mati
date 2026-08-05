//! FileEnrich / FileReparse / DocCapture handlers.

use super::*;

// ── FileEnrich ──────────────────────────────────────────────────────────────

pub(crate) async fn handle_file_enrich(
    store: &Store,
    ctx: &RequestContext,
    request_id: Uuid,
    input: &protocol::FileEnrichInput,
) -> HandlerResult {
    let now = now_secs();
    let file_key = format!("file:{}", input.path);

    let mut record = store
        .get(&file_key)
        .await
        .map_err(|e| (ErrorCode::StoreError, format!("store read: {e}")))?
        .ok_or_else(|| {
            (
                ErrorCode::NotFound,
                format!("file record not found: {file_key} (must be created by init/reparse)"),
            )
        })?;

    // Require purpose on first enrichment, but allow empty on updates
    // (e.g. propagate_confirmation only bumps confirmation_count).
    if input.purpose.is_empty() && record.value.is_empty() {
        return Err((
            ErrorCode::ValidationFailed,
            "purpose must not be empty".into(),
        ));
    }

    if !matches!(record.lifecycle, RecordLifecycle::Active) {
        return Err((
            ErrorCode::InvalidStateTransition,
            format!("{file_key} is tombstoned"),
        ));
    }

    // Merge enrichment with existing structural data.
    let was_confirmed =
        record.source == RecordSource::DeveloperManual || record.confidence.value >= 0.80;

    if let Some(ref mut payload) = record.payload {
        if let Some(obj) = payload.as_object_mut() {
            if !input.purpose.is_empty() {
                obj.insert(
                    "purpose".to_string(),
                    serde_json::Value::String(input.purpose.clone()),
                );
            }
            if !input.entry_points.is_empty() {
                obj.insert(
                    "entry_points".to_string(),
                    serde_json::json!(input.entry_points),
                );
            }
            if !input.decision_keys.is_empty() {
                obj.insert(
                    "decision_keys".to_string(),
                    serde_json::json!(input.decision_keys),
                );
            }
            if !input.todos.is_empty() {
                obj.insert("todos".to_string(), serde_json::json!(input.todos));
            }
            // gotcha_keys and imports are NOT touched — daemon-managed.
        }
    }

    if !input.purpose.is_empty() {
        record.value = input.purpose.clone();
    }
    record.updated_at = now;
    record.version.logical_clock += 1;
    record.version.wall_clock = now;
    record.priority = map_priority(&input.priority);
    if !was_confirmed {
        record.source = RecordSource::ClaudeEnrich;
        record.confidence = ConfidenceScore::for_new_record(&RecordSource::ClaudeEnrich);
    }
    if !input.tags.is_empty() {
        record.tags = input.tags.clone();
    }
    record.quality = quality::analyze(&record);

    let confidence_val = record.confidence.value;
    let quality_val = record.quality.value;
    let tier_label = format!("{:?}", record.quality.tier);

    // Atomic: file record + audit.
    // Audit is required — fail closed if serialization fails.
    let (audit_key, audit_bytes) =
        make_audit(ctx, request_id, "file_enrich", &file_key, true, None)
            .ok_or_else(|| (ErrorCode::Internal, "audit serialization failed".into()))?;
    let ops = vec![
        KnowledgeWriteOp::PutRecord {
            key: &file_key,
            record: &record,
        },
        KnowledgeWriteOp::PutRaw {
            key: &audit_key,
            value: &audit_bytes,
        },
    ];
    store
        .transact_knowledge(&ops)
        .await
        .map_err(|e| (ErrorCode::StoreError, format!("transact failed: {e}")))?;

    Ok(serde_json::json!({
        "ok": true,
        "key": file_key,
        "confidence": confidence_val,
        "quality": quality_val,
        "tier": tier_label,
    }))
}

// ── FileReparse ─────────────────────────────────────────────────────────────

pub(crate) async fn handle_file_reparse(
    store: &Store,
    ctx: &RequestContext,
    request_id: Uuid,
    input: &protocol::FileReparseInput,
    repo_root: &std::path::Path,
) -> HandlerResult {
    if input.path.is_empty() {
        return Err((ErrorCode::ValidationFailed, "path must not be empty".into()));
    }

    // Compute the reparse result without persisting — returns the record to write.
    let staged = crate::analysis::reparse::reparse_staged(store, repo_root, &input.path)
        .await
        .map_err(|e| (ErrorCode::StoreError, format!("reparse failed: {e}")))?;

    let Some((file_key, record)) = staged else {
        // No write needed (no changes, parse failure, or missing file with no record).
        // No record change, but audit is still required for provenance.
        let (audit_key, audit_bytes) =
            make_audit(ctx, request_id, "file_reparse", &input.path, true, None)
                .ok_or_else(|| (ErrorCode::Internal, "audit serialization failed".into()))?;
        let ops = vec![KnowledgeWriteOp::PutRaw {
            key: &audit_key,
            value: &audit_bytes,
        }];
        store
            .transact_knowledge(&ops)
            .await
            .map_err(|e| (ErrorCode::StoreError, format!("audit write failed: {e}")))?;
        return Ok(serde_json::json!({"ok": true}));
    };

    // Atomic: file record + audit in one transaction.
    // Audit is required — fail closed if serialization fails.
    let (audit_key, audit_bytes) =
        make_audit(ctx, request_id, "file_reparse", &input.path, true, None)
            .ok_or_else(|| (ErrorCode::Internal, "audit serialization failed".into()))?;
    let ops = vec![
        KnowledgeWriteOp::PutRecord {
            key: &file_key,
            record: &record,
        },
        KnowledgeWriteOp::PutRaw {
            key: &audit_key,
            value: &audit_bytes,
        },
    ];
    store
        .transact_knowledge(&ops)
        .await
        .map_err(|e| (ErrorCode::StoreError, format!("transact failed: {e}")))?;

    // Best-effort substep: staleness cascade to linked gotchas (separate puts).
    if let Some(fr) = record.payload_as::<FileRecord>() {
        if let Err(e) = crate::health::staleness::cascade_staleness_to_gotchas(store, &fr).await {
            tracing::warn!(
                "file_reparse: staleness cascade failed for {}: {e}",
                input.path
            );
        }
    }

    Ok(serde_json::json!({"ok": true}))
}

// ── DocCapture ──────────────────────────────────────────────────────────────

pub(crate) async fn handle_doc_capture(
    store: &Store,
    ctx: &RequestContext,
    request_id: Uuid,
    input: &protocol::DocCaptureInput,
    repo_root: &std::path::Path,
) -> HandlerResult {
    if input.path.is_empty() {
        return Err((ErrorCode::ValidationFailed, "path must not be empty".into()));
    }

    // Path-only ingestion: daemon reads the file from disk.
    let abs_path = repo_root.join(&input.path);
    let content = std::fs::read_to_string(&abs_path).unwrap_or_default();
    let purpose = crate::store::session::extract_doc_comment(&input.path, &content);

    if purpose.is_empty() {
        // No doc comment found — no-op, but still audit.
        if let Some((ak, ab)) = make_audit(ctx, request_id, "doc_capture", &input.path, true, None)
        {
            let _ = store.put_raw(&ak, &ab).await;
        }
        return Ok(serde_json::json!({"ok": true}));
    }

    let file_key = format!("file:{}", input.path);
    let mut record = match store.get(&file_key).await {
        Ok(Some(r)) => r,
        _ => {
            if let Some((ak, ab)) =
                make_audit(ctx, request_id, "doc_capture", &input.path, true, None)
            {
                let _ = store.put_raw(&ak, &ab).await;
            }
            return Ok(serde_json::json!({"ok": true}));
        }
    };

    // Update only records nobody has manually curated (Layer 0 stub, or a
    // prior doc-capture pass) — see session::doc_capture for why SessionHook
    // must stay eligible here too.
    if !matches!(
        record.source,
        RecordSource::StaticAnalysis | RecordSource::SessionHook
    ) {
        if let Some((ak, ab)) = make_audit(ctx, request_id, "doc_capture", &input.path, true, None)
        {
            let _ = store.put_raw(&ak, &ab).await;
        }
        return Ok(serde_json::json!({"ok": true}));
    }

    if let Some(mut fr) = record.payload_as::<FileRecord>() {
        fr.purpose = purpose.clone();
        record.payload = serde_json::to_value(&fr).ok();
    }

    let now = now_secs();
    record.value = purpose;
    record.source = RecordSource::SessionHook;
    record.confidence.value = 0.65;
    record.quality = QualityScore::doc_comment_default();
    record.updated_at = now;
    record.version.logical_clock += 1;
    record.version.wall_clock = now;

    // Atomic: file record + audit.
    // Audit is required — fail closed if serialization fails.
    let (audit_key, audit_bytes) =
        make_audit(ctx, request_id, "doc_capture", &input.path, true, None)
            .ok_or_else(|| (ErrorCode::Internal, "audit serialization failed".into()))?;
    let ops = vec![
        KnowledgeWriteOp::PutRecord {
            key: &file_key,
            record: &record,
        },
        KnowledgeWriteOp::PutRaw {
            key: &audit_key,
            value: &audit_bytes,
        },
    ];
    store
        .transact_knowledge(&ops)
        .await
        .map_err(|e| (ErrorCode::StoreError, format!("transact failed: {e}")))?;

    Ok(serde_json::json!({"ok": true}))
}
