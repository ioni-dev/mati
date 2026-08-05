//! GotchaUpsert / GotchaConfirm / GotchaTombstone handlers.

use super::*;

// ── GotchaUpsert ────────────────────────────────────────────────────────────

pub(crate) async fn handle_gotcha_upsert(
    store: &Store,
    ctx: &RequestContext,
    request_id: Uuid,
    input: &protocol::GotchaDraftInput,
) -> HandlerResult {
    let now = now_secs();
    let key = &input.key;

    // Validate key prefix.
    if !key.starts_with("gotcha:") {
        return Err((
            ErrorCode::ValidationFailed,
            "key must start with gotcha:".into(),
        ));
    }
    if input.rule.is_empty() {
        return Err((ErrorCode::ValidationFailed, "rule must not be empty".into()));
    }

    // Normalize `affected_files` to the repo-relative form the read gate keys
    // on. This handler has its own atomic transaction loop and does NOT go
    // through `gotcha_ops::apply_gotcha_write`, so the normalization there does
    // not cover it — same reason the extraction-tracking hook below is
    // duplicated. Everything downstream uses this list, never `input`'s.
    let affected_files = crate::store::gotcha_ops::normalize_affected_files(&input.affected_files);

    // Read-modify-commit under bounded write-conflict retry. The daemon serves
    // writes concurrently, so a sibling enforcement-event / receipt write can
    // collide with this commit (see `retry_on_write_conflict`).
    let (record, is_new, old_affected_files) = retry_on_write_conflict(|| {
        upsert_commit_once(store, ctx, request_id, input, &affected_files, now)
    })
    .await?;

    let quality_val = record.quality.value;
    let tier_label = format!("{:?}", record.quality.tier);

    // Best-effort: sync HasGotcha graph edges (cross-tree, outside transaction).
    // Pre-arm the dirty marker before the edge sync and clear it only on
    // success — `upsert_commit_once`'s record + file-link write is already
    // atomic via `transact_knowledge`, so edges are the only derived write
    // left that a cancellation between here and the edge loop's end could
    // leave unrecorded. See `gotcha_ops`'s "Cancellation safety" doc.
    crate::store::repair::mark_dirty(store, key, "gotcha_upsert: pre-arm cancellation guard").await;
    if crate::store::gotcha_ops::sync_has_gotcha_edges(
        store,
        key,
        &old_affected_files,
        &affected_files,
    )
    .await
    {
        crate::store::repair::clear_dirty_key_if_solo(store, key).await;
    }

    // Best-effort: record ControlChanged enforcement event.
    let change_kind = if is_new {
        crate::store::enforcement::ControlChangeKind::Created
    } else {
        crate::store::enforcement::ControlChangeKind::Updated
    };
    let reason_code = if is_new {
        "control_created"
    } else {
        "control_updated"
    };
    if let Err(e) = crate::store::enforcement::record_event(
        store,
        crate::store::enforcement::EnforcementEventType::ControlChanged { change_kind },
        crate::store::enforcement::SubjectKind::Control,
        key.clone(),
        "developer".to_string(),
        None,
        reason_code.to_string(),
        None,
    )
    .await
    {
        tracing::warn!("gotcha_upsert: enforcement event recording failed for {key}: {e}");
    }

    // SOTA-γ telemetry hook (D3): if the input tags mark this as an
    // enrichment-produced gotcha ("enriched"), persist an ExtractionRecord
    // capturing depth + config so `mati doctor`'s per-tier and per-config
    // A/B sections have data to aggregate. Mirror of the
    // `gotcha_ops::apply_gotcha_write` hook — the MCP path has its own
    // atomic transaction loop and doesn't go through that function, so
    // the hook is duplicated here. Best-effort; failure logs but doesn't
    // propagate (analytics, not correctness).
    if is_new {
        let _ =
            crate::store::extraction::write_on_extraction(store, key, &input.tags, &affected_files)
                .await;
    }

    Ok(serde_json::json!({
        "ok": true,
        "key": key,
        "confidence": record.confidence.value,
        "quality": quality_val,
        "tier": tier_label,
    }))
}

/// One read-modify-commit attempt for `handle_gotcha_upsert`. Re-invoked by
/// `retry_on_write_conflict`; re-reads `existing` each call so a retry rebuilds
/// `is_new` / `old_affected_files` / file-link updates against fresh state.
/// Returns the committed record plus the post-commit inputs the caller needs.
///
/// `affected_files` is the caller's already-normalized list; `input`'s own
/// `affected_files` must not be used past this point.
async fn upsert_commit_once(
    store: &Store,
    ctx: &RequestContext,
    request_id: Uuid,
    input: &protocol::GotchaDraftInput,
    affected_files: &[String],
    now: u64,
) -> Result<(Record, bool, Vec<String>), (ErrorCode, String)> {
    let key = &input.key;

    let existing = store
        .get(key)
        .await
        .map_err(|e| (ErrorCode::StoreError, format!("store read failed: {e}")))?;

    let is_tombstoned = existing
        .as_ref()
        .map(|r| matches!(r.lifecycle, RecordLifecycle::Tombstoned { .. }))
        .unwrap_or(false);

    let is_new = existing.is_none() || is_tombstoned;

    // Extract old affected_files BEFORE consuming existing into the record builder.
    let old_affected_files: Vec<String> = existing
        .as_ref()
        .filter(|_| !is_tombstoned)
        .and_then(|r| r.payload_as::<GotchaRecord>())
        .map(|g| g.affected_files)
        .unwrap_or_default();

    let source = match input.source.as_deref() {
        Some("developer_manual") => RecordSource::DeveloperManual,
        Some("import") => RecordSource::Import,
        _ => RecordSource::ClaudeEnrich,
    };

    // Only a developer-originated write may assert confirmation. `mem_set`
    // sends neither field, so an agent still has to use the `confirm` action —
    // P4, memory reflects developer intent. Everything else resets, as before.
    let confirmed = input.confirmed && matches!(source, RecordSource::DeveloperManual);

    // Carry the existing drift baseline through an edit that stays confirmed.
    // Rebuilding it from scratch would erase the stamp a `mati gotcha confirm`
    // wrote, and re-stamping here would clear real drift on a rule whose text
    // was tweaked without anyone re-reading the code.
    let previous = existing
        .as_ref()
        .and_then(|r| r.payload_as::<GotchaRecord>());
    let confirmed_content = match (confirmed, is_new) {
        (true, false) => previous
            .as_ref()
            .map(|g| g.confirmed_content.clone())
            .unwrap_or_default(),
        _ => Default::default(),
    };

    // Build gotcha payload.
    let mut gotcha = GotchaRecord {
        rule: input.rule.clone(),
        reason: input.reason.clone(),
        severity: map_severity(&input.severity),
        affected_files: affected_files.to_vec(),
        ref_url: input.ref_url.clone(),
        discovered_session: if is_new {
            now
        } else {
            previous
                .as_ref()
                .map(|g| g.discovered_session)
                .unwrap_or(now)
        },
        confirmed,
        confirmed_content,
    };

    // Mirror of the `gotcha_ops::apply_gotcha_write` stamp: a new record that
    // arrives already confirmed is a developer vouching for it right now, so it
    // earns the drift baseline `mati gotcha confirm` would have written.
    if confirmed && is_new {
        gotcha.confirmed_content =
            crate::store::gotcha_ops::confirm_content_stamp(store, affected_files).await;
    }

    let mut record = match existing {
        Some(mut r) if !is_tombstoned => {
            r.updated_at = now;
            r.version.logical_clock += 1;
            r.version.wall_clock = now;
            r
        }
        _ => Record {
            key: key.clone(),
            value: String::new(),
            category: Category::Gotcha,
            priority: StorePriority::Normal,
            tags: vec![],
            created_at: now,
            updated_at: now,
            ref_url: None,
            staleness: StalenessScore::fresh(),
            lifecycle: RecordLifecycle::Active,
            version: RecordVersion {
                device_id: crate::store::stable_device_id(),
                logical_clock: 1,
                wall_clock: now,
            },
            quality: QualityScore::layer0_default(),
            access_count: 0,
            last_accessed: 0,
            source: RecordSource::StaticAnalysis,
            confidence: ConfidenceScore::for_new_record(&RecordSource::StaticAnalysis),
            gap_analysis_score: 0.0,
            payload: None,
        },
    };

    // Apply fields.
    record.value = format!("{} because {}", input.rule, input.reason);
    record.category = Category::Gotcha;
    record.lifecycle = RecordLifecycle::Active;
    record.priority = map_priority(&input.priority);
    record.tags = input.tags.clone();
    record.source = source.clone();
    record.confidence = ConfidenceScore::for_new_record(&source);
    if is_tombstoned {
        record.confidence.confirmation_count = 0;
    }
    // A confirmed record carries one explicit developer assertion, matching
    // what `cli::gotcha::finish_gotcha_add` stores on the direct path. The
    // count feeds `log2(count + 2)` in the confidence formula.
    if confirmed {
        record.confidence.confirmation_count = 1;
    }
    record.payload = serde_json::to_value(&gotcha).ok();
    record.quality = quality::analyze(&record);

    // Compute file-link updates for the same transaction.
    let file_link_updates =
        compute_file_link_updates(store, key, &old_affected_files, affected_files).await;

    // Build atomic write: gotcha record + file-link updates + audit.
    // Audit is required — fail closed if serialization fails.
    let (audit_key, audit_bytes) = make_audit(ctx, request_id, "gotcha_upsert", key, true, None)
        .ok_or_else(|| (ErrorCode::Internal, "audit serialization failed".into()))?;
    let mut ops: Vec<KnowledgeWriteOp<'_>> = Vec::new();
    ops.push(KnowledgeWriteOp::PutRecord {
        key,
        record: &record,
    });
    for (fkey, frec) in &file_link_updates {
        ops.push(KnowledgeWriteOp::PutRecord {
            key: fkey.as_str(),
            record: frec,
        });
    }
    ops.push(KnowledgeWriteOp::PutRaw {
        key: &audit_key,
        value: &audit_bytes,
    });
    store
        .transact_knowledge(&ops)
        .await
        .map_err(|e| (ErrorCode::StoreError, format!("transact failed: {e}")))?;

    Ok((record, is_new, old_affected_files))
}

// ── GotchaConfirm ───────────────────────────────────────────────────────────

pub(crate) async fn handle_gotcha_confirm(
    store: &Store,
    ctx: &RequestContext,
    request_id: Uuid,
    input: &protocol::GotchaConfirmInput,
) -> HandlerResult {
    let now = now_secs();
    let key = &input.key;

    if !key.starts_with("gotcha:") {
        return Err((
            ErrorCode::ValidationFailed,
            "confirm only applies to gotcha: keys".into(),
        ));
    }

    // Read-modify-commit under bounded write-conflict retry (see
    // `retry_on_write_conflict`).
    let (record, affected_files) =
        retry_on_write_conflict(|| confirm_commit_once(store, ctx, request_id, key, now)).await?;

    let confidence_val = record.confidence.value;
    let quality_val = record.quality.value;

    // Best-effort: ensure HasGotcha edges exist for all affected files.
    // Pre-arm the dirty marker before the edge sync and clear it only on
    // success — `confirm_commit_once`'s record + file-link write is already
    // atomic via `transact_knowledge`, so edges are the only derived write
    // left that a cancellation between here and the edge loop's end could
    // leave unrecorded. See `gotcha_ops`'s "Cancellation safety" doc.
    crate::store::repair::mark_dirty(store, key, "gotcha_confirm: pre-arm cancellation guard")
        .await;
    if crate::store::gotcha_ops::sync_has_gotcha_edges(store, key, &[], &affected_files).await {
        crate::store::repair::clear_dirty_key_if_solo(store, key).await;
    }

    // Best-effort: invalidate consultation receipts on every affected file.
    //
    // A newly-confirmed gotcha is information the agent has not seen. Any
    // prior `session:consulted:file:<path>` receipt was minted before this
    // gotcha existed (or before it was confirmed), so granting the agent a
    // bypass on that stale receipt would let it edit a file under a
    // confirmed gotcha without ever surfacing the rule. Drop the receipt
    // so the next pre-read / pre-bash hook returns DENY and forces a fresh
    // consultation.
    crate::store::gotcha_ops::invalidate_consultation_receipts(store, &affected_files).await;

    // Best-effort: record ControlChanged::Confirmed enforcement event.
    if let Err(e) = crate::store::enforcement::record_event(
        store,
        crate::store::enforcement::EnforcementEventType::ControlChanged {
            change_kind: crate::store::enforcement::ControlChangeKind::Confirmed,
        },
        crate::store::enforcement::SubjectKind::Control,
        key.clone(),
        "developer".to_string(),
        None,
        "control_confirmed".to_string(),
        None,
    )
    .await
    {
        tracing::warn!("gotcha_confirm: enforcement event recording failed for {key}: {e}");
    }

    // SOTA-γ telemetry hook (D3): flip the matching ExtractionRecord's
    // outcome to Confirmed. No-op when the gotcha wasn't from
    // `/mati-enrich` (no analytics:extraction:* record exists).
    // Mirror of the `gotcha_ops::apply_gotcha_confirm` hook.
    let _ = crate::store::extraction::mark_outcome(
        store,
        key,
        crate::store::extraction::ExtractionOutcome::Confirmed,
    )
    .await;

    Ok(serde_json::json!({
        "ok": true,
        "key": key,
        "confirmed": true,
        "confidence": confidence_val,
        "quality": quality_val,
    }))
}

/// One read-modify-commit attempt for `handle_gotcha_confirm`. Re-invoked by
/// `retry_on_write_conflict`; re-reads the gotcha each call so a retry confirms
/// against fresh state. Returns the confirmed record plus its affected files
/// for the caller's post-commit steps. Validation errors (not-found, not a
/// gotcha, tombstoned) are non-write-conflict errors and so are not retried.
async fn confirm_commit_once(
    store: &Store,
    ctx: &RequestContext,
    request_id: Uuid,
    key: &str,
    now: u64,
) -> Result<(Record, Vec<String>), (ErrorCode, String)> {
    let mut record = store
        .get(key)
        .await
        .map_err(|e| (ErrorCode::StoreError, format!("store read: {e}")))?
        .ok_or_else(|| (ErrorCode::NotFound, format!("record not found: {key}")))?;

    if record.category != Category::Gotcha {
        return Err((
            ErrorCode::ValidationFailed,
            format!("{key} is not a gotcha record"),
        ));
    }
    if !matches!(record.lifecycle, RecordLifecycle::Active) {
        return Err((
            ErrorCode::InvalidStateTransition,
            format!("{key} is tombstoned — cannot confirm"),
        ));
    }

    // Set confirmed + normalize severity.
    if let Some(ref mut payload) = record.payload {
        if let Some(obj) = payload.as_object_mut() {
            if let Some(sev) = obj
                .get("severity")
                .and_then(|v| v.as_str())
                .map(|s| s.to_lowercase())
            {
                obj.insert("severity".to_string(), serde_json::Value::String(sev));
            }
            obj.insert("confirmed".to_string(), serde_json::Value::Bool(true));
        }
    }

    record.source = RecordSource::DeveloperManual;
    record.confidence.value = ConfidenceScore::base_for_source(&RecordSource::DeveloperManual);
    record.confidence.confirmation_count += 1;
    record.quality = quality::analyze(&record);
    record.updated_at = now;
    record.version.logical_clock += 1;
    record.version.wall_clock = now;

    // Re-key `affected_files` into the form the read gate looks up, and write
    // the normalized list back into the payload. `apply_gotcha_confirm` does
    // this on the direct path; without it here, confirming a record stored as
    // `./src/a.rs` leaves `file:src/a.rs.gotcha_keys` empty and the HasGotcha
    // edge pointing at a key nothing reads — confirmed and inert
    // (ARCHITECTURE.md section 22, "Path normalization").
    let affected_files = crate::store::gotcha_ops::normalize_affected_files(
        &record
            .payload_as::<GotchaRecord>()
            .map(|g| g.affected_files)
            .unwrap_or_default(),
    );
    if let Some(rekeyed) =
        crate::store::gotcha_ops::with_normalized_affected_files(&record, &affected_files)
    {
        record = rekeyed;
    }

    // Compute file-link updates + confirmation propagation for same transaction.
    let mut file_updates = compute_file_link_updates(store, key, &[], &affected_files).await;
    apply_confirmation_propagation(store, &affected_files, &mut file_updates).await;

    // Stamp the content digest each affected file currently carries, so a later
    // change to that file is reportable as content drift. The direct-store path
    // does this inside `gotcha_ops::apply_gotcha_confirm`; this handler commits
    // its own `transact_knowledge` and never calls it, so it carries the stamp
    // itself — same as the `affected_files` normalization split. Recomputed from
    // records already read above, so no file is opened and nothing is re-hashed.
    // Must run before the record is staged below.
    let stamp = crate::store::gotcha_ops::confirm_content_stamp(store, &affected_files).await;
    crate::store::gotcha_ops::set_confirm_stamp(&mut record, &stamp);

    // Atomic: gotcha record + file-link updates + confirmation propagation + audit.
    // Audit is required — fail closed if serialization fails.
    let (audit_key, audit_bytes) =
        make_audit(ctx, request_id, "gotcha_confirm", key, true, None)
            .ok_or_else(|| (ErrorCode::Internal, "audit serialization failed".into()))?;
    let mut ops: Vec<KnowledgeWriteOp<'_>> = Vec::new();
    ops.push(KnowledgeWriteOp::PutRecord {
        key,
        record: &record,
    });
    for (fkey, frec) in &file_updates {
        ops.push(KnowledgeWriteOp::PutRecord {
            key: fkey.as_str(),
            record: frec,
        });
    }
    ops.push(KnowledgeWriteOp::PutRaw {
        key: &audit_key,
        value: &audit_bytes,
    });
    store
        .transact_knowledge(&ops)
        .await
        .map_err(|e| (ErrorCode::StoreError, format!("transact failed: {e}")))?;

    Ok((record, affected_files))
}

// ── GotchaTombstone ─────────────────────────────────────────────────────────

pub(crate) async fn handle_gotcha_tombstone(
    store: &Store,
    ctx: &RequestContext,
    request_id: Uuid,
    input: &protocol::GotchaTombstoneInput,
) -> HandlerResult {
    let now = now_secs();
    let key = &input.key;

    if !key.starts_with("gotcha:") {
        return Err((
            ErrorCode::ValidationFailed,
            "tombstone only applies to gotcha: keys".into(),
        ));
    }

    // Read-modify-commit under bounded write-conflict retry (see
    // `retry_on_write_conflict`).
    let (affected_files, neg_exemplar_data) =
        retry_on_write_conflict(|| tombstone_commit_once(store, ctx, request_id, key, now)).await?;

    // Best-effort: remove HasGotcha edges for all affected files.
    // Pre-arm the dirty marker before the edge sync and clear it only on
    // success — `tombstone_commit_once`'s record + file-link write is
    // already atomic via `transact_knowledge`, so edges are the only
    // derived write left that a cancellation between here and the edge
    // loop's end could leave unrecorded. See `gotcha_ops`'s "Cancellation
    // safety" doc.
    crate::store::repair::mark_dirty(store, key, "gotcha_tombstone: pre-arm cancellation guard")
        .await;
    if crate::store::gotcha_ops::sync_has_gotcha_edges(store, key, &affected_files, &[]).await {
        crate::store::repair::clear_dirty_key_if_solo(store, key).await;
    }

    // Best-effort: record ControlChanged::Deleted enforcement event.
    if let Err(e) = crate::store::enforcement::record_event(
        store,
        crate::store::enforcement::EnforcementEventType::ControlChanged {
            change_kind: crate::store::enforcement::ControlChangeKind::Deleted,
        },
        crate::store::enforcement::SubjectKind::Control,
        key.clone(),
        "developer".to_string(),
        None,
        "control_deleted".to_string(),
        None,
    )
    .await
    {
        tracing::warn!("gotcha_tombstone: enforcement event recording failed for {key}: {e}");
    }

    // D3 hooks: write the negative-exemplar archive (for future
    // `/mati-enrich` runs in this directory to learn from) AND flip the
    // matching ExtractionRecord's outcome to Tombstoned (closes the
    // SOTA-γ A/B telemetry loop). Both best-effort; failure logs but
    // never blocks the tombstone path since the gotcha is already
    // tombstoned at this point. Mirror of the gotcha_ops hooks.
    if let Some((rule, reason, severity)) = neg_exemplar_data.as_ref() {
        match crate::store::negative_exemplar::write_on_tombstone(
            store,
            key,
            rule,
            reason,
            severity,
            &affected_files,
        )
        .await
        {
            Ok(n) => tracing::debug!(
                "gotcha_tombstone (mcp): negative_exemplar archived for {key} across {n} dirname(s)"
            ),
            Err(e) => tracing::warn!(
                "gotcha_tombstone (mcp): negative_exemplar write failed for {key}: {e}"
            ),
        }
    }
    let _ = crate::store::extraction::mark_outcome(
        store,
        key,
        crate::store::extraction::ExtractionOutcome::Tombstoned,
    )
    .await;

    Ok(serde_json::json!({"ok": true, "key": key, "tombstoned": true}))
}

/// One read-modify-commit attempt for `handle_gotcha_tombstone`. Re-invoked by
/// `retry_on_write_conflict`; re-reads the gotcha each call. Returns the
/// affected files and the negative-exemplar snapshot for the caller's
/// post-commit steps.
async fn tombstone_commit_once(
    store: &Store,
    ctx: &RequestContext,
    request_id: Uuid,
    key: &str,
    now: u64,
) -> Result<
    (
        Vec<String>,
        Option<(String, String, crate::store::Priority)>,
    ),
    (ErrorCode, String),
> {
    let mut record = store
        .get(key)
        .await
        .map_err(|e| (ErrorCode::StoreError, format!("store read: {e}")))?
        .ok_or_else(|| (ErrorCode::NotFound, format!("record not found: {key}")))?;

    let gotcha_snapshot = record.payload_as::<GotchaRecord>();
    let affected_files: Vec<String> = gotcha_snapshot
        .as_ref()
        .map(|g| g.affected_files.clone())
        .unwrap_or_default();
    // D3 hook: snapshot rule/reason/severity BEFORE lifecycle flips to
    // Tombstoned (the payload survives the flip, but doing it here mirrors
    // the gotcha_ops path and makes the snapshot order obvious to readers).
    let neg_exemplar_data: Option<(String, String, crate::store::Priority)> = gotcha_snapshot
        .as_ref()
        .map(|g| (g.rule.clone(), g.reason.clone(), g.severity.clone()));

    record.lifecycle = RecordLifecycle::Tombstoned {
        reason: TombstoneReason::ManualDeletion,
        at: now,
    };
    record.updated_at = now;
    record.version.logical_clock += 1;
    record.version.wall_clock = now;

    // Compute file-link cleanup for same transaction.
    let file_link_updates = compute_file_link_updates(store, key, &affected_files, &[]).await;

    // Atomic: tombstoned record + file-link cleanup + audit.
    // Audit is required — fail closed if serialization fails.
    let (audit_key, audit_bytes) = make_audit(ctx, request_id, "gotcha_tombstone", key, true, None)
        .ok_or_else(|| (ErrorCode::Internal, "audit serialization failed".into()))?;
    let mut ops: Vec<KnowledgeWriteOp<'_>> = Vec::new();
    ops.push(KnowledgeWriteOp::PutRecord {
        key,
        record: &record,
    });
    for (fkey, frec) in &file_link_updates {
        ops.push(KnowledgeWriteOp::PutRecord {
            key: fkey.as_str(),
            record: frec,
        });
    }
    ops.push(KnowledgeWriteOp::PutRaw {
        key: &audit_key,
        value: &audit_bytes,
    });
    store
        .transact_knowledge(&ops)
        .await
        .map_err(|e| (ErrorCode::StoreError, format!("transact failed: {e}")))?;

    Ok((affected_files, neg_exemplar_data))
}
