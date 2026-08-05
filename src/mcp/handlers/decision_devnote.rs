//! DecisionUpsert / DevNoteUpsert handlers.

use super::*;

// ── DecisionUpsert ──────────────────────────────────────────────────────────

pub(crate) async fn handle_decision_upsert(
    store: &Store,
    ctx: &RequestContext,
    request_id: Uuid,
    input: &protocol::DecisionUpsertInput,
) -> HandlerResult {
    let now = now_secs();
    let key = format!("decision:{}", input.slug);

    if input.slug.is_empty() {
        return Err((ErrorCode::ValidationFailed, "slug must not be empty".into()));
    }
    if input.value.is_empty() {
        return Err((
            ErrorCode::ValidationFailed,
            "value must not be empty".into(),
        ));
    }

    let existing = store
        .get(&key)
        .await
        .map_err(|e| (ErrorCode::StoreError, format!("store read: {e}")))?;

    let was_confirmed = existing
        .as_ref()
        .map(|r| r.source == RecordSource::DeveloperManual || r.confidence.value >= 0.80)
        .unwrap_or(false);

    let mut record = match existing {
        Some(mut r) => {
            r.updated_at = now;
            r.version.logical_clock += 1;
            r.version.wall_clock = now;
            r
        }
        None => Record {
            key: key.clone(),
            value: String::new(),
            category: Category::Decision,
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

    record.value = input.value.clone();
    record.category = Category::Decision;
    record.lifecycle = RecordLifecycle::Active;
    record.priority = map_priority(&input.priority);
    record.tags = input.tags.clone();
    record.payload = Some(serde_json::json!({
        "summary": input.summary,
        "rationale": input.rationale,
    }));
    if !was_confirmed {
        record.source = RecordSource::ClaudeEnrich;
        record.confidence = ConfidenceScore::for_new_record(&RecordSource::ClaudeEnrich);
    }
    record.quality = quality::analyze(&record);

    let confidence_val = record.confidence.value;
    let quality_val = record.quality.value;
    let tier_label = format!("{:?}", record.quality.tier);

    // Audit is required — fail closed if serialization fails.
    let (audit_key, audit_bytes) = make_audit(ctx, request_id, "decision_upsert", &key, true, None)
        .ok_or_else(|| (ErrorCode::Internal, "audit serialization failed".into()))?;
    let ops = vec![
        KnowledgeWriteOp::PutRecord {
            key: &key,
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
        "key": key,
        "confidence": confidence_val,
        "quality": quality_val,
        "tier": tier_label,
    }))
}

// ── DevNoteUpsert ───────────────────────────────────────────────────────────

pub(crate) async fn handle_dev_note_upsert(
    store: &Store,
    ctx: &RequestContext,
    request_id: Uuid,
    input: &protocol::DevNoteUpsertInput,
) -> HandlerResult {
    let now = now_secs();

    if input.text.is_empty() {
        return Err((ErrorCode::ValidationFailed, "text must not be empty".into()));
    }

    let key = match &input.key {
        Some(k) => {
            if !k.starts_with("dev_note:") {
                return Err((
                    ErrorCode::ValidationFailed,
                    "key must start with dev_note:".into(),
                ));
            }
            k.clone()
        }
        None => {
            let slug: String = input
                .text
                .chars()
                .take(30)
                .collect::<String>()
                .to_lowercase()
                .replace(|c: char| !c.is_alphanumeric(), "-");
            format!("dev_note:{slug}-{now}")
        }
    };

    let existing = store
        .get(&key)
        .await
        .map_err(|e| (ErrorCode::StoreError, format!("store read: {e}")))?;

    let mut record = match existing {
        Some(mut r) => {
            r.updated_at = now;
            r.version.logical_clock += 1;
            r.version.wall_clock = now;
            r
        }
        None => Record {
            key: key.clone(),
            value: String::new(),
            category: Category::DevNote,
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
            source: RecordSource::DeveloperManual,
            confidence: ConfidenceScore::for_new_record(&RecordSource::DeveloperManual),
            gap_analysis_score: 0.0,
            payload: None,
        },
    };

    record.value = input.text.clone();
    record.category = Category::DevNote;
    record.lifecycle = RecordLifecycle::Active;
    record.priority = map_priority(&input.priority);
    if !input.tags.is_empty() {
        record.tags = input.tags.clone();
    }
    record.quality = quality::analyze(&record);

    let quality_val = record.quality.value;
    let tier_label = format!("{:?}", record.quality.tier);

    // Audit is required — fail closed if serialization fails.
    let (audit_key, audit_bytes) = make_audit(ctx, request_id, "dev_note_upsert", &key, true, None)
        .ok_or_else(|| (ErrorCode::Internal, "audit serialization failed".into()))?;
    let ops = vec![
        KnowledgeWriteOp::PutRecord {
            key: &key,
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
        "key": key,
        "quality": quality_val,
        "tier": tier_label,
    }))
}
