//! Native v2 handlers for semantic commands.
//!
//! Knowledge-side mutation handlers:
//! 1. Validate the typed input DTO
//! 2. Read existing state via `store.get()`
//! 3. Compute the mutation (new/updated Record)
//! 4. Stage mutation Record(s) + audit raw bytes into `Vec<KnowledgeWriteOp>`
//! 5. Commit atomically via `store.transact_knowledge()`
//!
//! Side-effecting read handlers (MemGet, MemBootstrap):
//! 1. Read primary data
//! 2. Stage session-side writes (consultation receipts, aggs) + audit
//! 3. Commit sessions-tree writes atomically via `transact_sessions_raw`
//! 4. Defer cross-tree best-effort writes (access_count bumps)
//!
//! Cross-tree secondary effects (graph edges, access_count bumps) are explicit
//! substeps OUTSIDE the main transaction, with failure logged but not
//! propagated.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use uuid::Uuid;

use crate::graph::edges::{Edge, EdgeKind};
use crate::health::quality;
use crate::mcp::protocol::{self, AuditEntry, ErrorCode};
use crate::store::db::KnowledgeWriteOp;
use crate::store::record::{
    Category, ConfidenceScore, FileRecord, GotchaRecord, Priority as StorePriority, QualityScore,
    Record, RecordLifecycle, RecordSource, RecordVersion, StalenessScore, TombstoneReason,
};
use crate::store::Store;

use super::dispatch_v2::RequestContext;

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn audit_nanos_key(prefix: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{prefix}{nanos}")
}

/// Audit key prefix for knowledge-tree commands.
const AUDIT_KNOWLEDGE_PREFIX: &str = "audit:knowledge:";
/// Audit key prefix for session-tree commands.
pub(crate) const AUDIT_SESSION_PREFIX: &str = "audit:session:";

fn map_priority(p: &protocol::Priority) -> StorePriority {
    match p {
        protocol::Priority::Critical => StorePriority::Critical,
        protocol::Priority::High => StorePriority::High,
        protocol::Priority::Normal => StorePriority::Normal,
        protocol::Priority::Low => StorePriority::Low,
    }
}

fn map_severity(s: &protocol::Severity) -> StorePriority {
    match s {
        protocol::Severity::Critical => StorePriority::Critical,
        protocol::Severity::High => StorePriority::High,
        protocol::Severity::Normal => StorePriority::Normal,
        protocol::Severity::Low => StorePriority::Low,
    }
}

/// Build and serialize an audit entry. Returns `(key, bytes)` for inclusion
/// in a `KnowledgeWriteOp::PutRaw`.
/// Build and serialize an audit entry with a specified key prefix.
///
/// Use `AUDIT_KNOWLEDGE_PREFIX` for knowledge-tree commands,
/// `AUDIT_SESSION_PREFIX` for session-tree commands.
pub(crate) fn make_audit_with_prefix(
    ctx: &RequestContext,
    request_id: Uuid,
    command_kind: &str,
    target_key: &str,
    accepted: bool,
    error_code: Option<ErrorCode>,
    prefix: &str,
) -> Option<(String, Vec<u8>)> {
    let entry = AuditEntry {
        ts: now_secs(),
        peer_uid: ctx.peer.uid,
        peer_pid: ctx.peer.pid,
        daemon_session: ctx.daemon_session,
        request_id,
        command_kind: command_kind.to_string(),
        target_key: target_key.to_string(),
        accepted,
        error_code,
    };
    match rmp_serde::to_vec_named(&entry) {
        Ok(bytes) => Some((audit_nanos_key(prefix), bytes)),
        Err(e) => {
            tracing::error!("audit serialization failed — this is a bug, audit entry skipped: {e}");
            None
        }
    }
}

/// Convenience: knowledge-tree audit.
pub(crate) fn make_audit(
    ctx: &RequestContext,
    request_id: Uuid,
    command_kind: &str,
    target_key: &str,
    accepted: bool,
    error_code: Option<ErrorCode>,
) -> Option<(String, Vec<u8>)> {
    make_audit_with_prefix(
        ctx,
        request_id,
        command_kind,
        target_key,
        accepted,
        error_code,
        AUDIT_KNOWLEDGE_PREFIX,
    )
}

/// Convenience: session-tree audit.
pub(crate) fn make_session_audit(
    ctx: &RequestContext,
    request_id: Uuid,
    command_kind: &str,
    target_key: &str,
    accepted: bool,
    error_code: Option<ErrorCode>,
) -> Option<(String, Vec<u8>)> {
    make_audit_with_prefix(
        ctx,
        request_id,
        command_kind,
        target_key,
        accepted,
        error_code,
        AUDIT_SESSION_PREFIX,
    )
}

/// Result type for handlers: Ok data or (ErrorCode, message).
type HandlerResult = std::result::Result<serde_json::Value, (ErrorCode, String)>;

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

    // Build gotcha payload.
    let gotcha = GotchaRecord {
        rule: input.rule.clone(),
        reason: input.reason.clone(),
        severity: map_severity(&input.severity),
        affected_files: input.affected_files.clone(),
        ref_url: input.ref_url.clone(),
        discovered_session: if is_new {
            now
        } else {
            existing
                .as_ref()
                .and_then(|r| r.payload_as::<GotchaRecord>())
                .map(|g| g.discovered_session)
                .unwrap_or(now)
        },
        confirmed: false, // Always reset on upsert.
    };

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
                device_id: Uuid::new_v4(),
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
    let source = match input.source.as_deref() {
        Some("developer_manual") => RecordSource::DeveloperManual,
        Some("import") => RecordSource::Import,
        _ => RecordSource::ClaudeEnrich,
    };
    record.source = source.clone();
    record.confidence = ConfidenceScore::for_new_record(&source);
    if is_tombstoned {
        record.confidence.confirmation_count = 0;
    }
    record.payload = serde_json::to_value(&gotcha).ok();
    record.quality = quality::analyze(&record);

    let quality_val = record.quality.value;
    let tier_label = format!("{:?}", record.quality.tier);

    // Compute file-link updates for the same transaction.
    let file_link_updates =
        compute_file_link_updates(store, key, &old_affected_files, &input.affected_files).await;

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

    // Best-effort: sync HasGotcha graph edges (cross-tree, outside transaction).
    sync_has_gotcha_edges(store, key, &old_affected_files, &input.affected_files).await;

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

    Ok(serde_json::json!({
        "ok": true,
        "key": key,
        "confidence": record.confidence.value,
        "quality": quality_val,
        "tier": tier_label,
    }))
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

    let confidence_val = record.confidence.value;
    let quality_val = record.quality.value;

    // Compute file-link updates + confirmation propagation for same transaction.
    let affected_files: Vec<String> = record
        .payload_as::<GotchaRecord>()
        .map(|g| g.affected_files)
        .unwrap_or_default();
    let file_link_updates = compute_file_link_updates(store, key, &[], &affected_files).await;
    let confirmation_updates = compute_confirmation_propagation(store, &affected_files).await;

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
    for (fkey, frec) in &file_link_updates {
        ops.push(KnowledgeWriteOp::PutRecord {
            key: fkey.as_str(),
            record: frec,
        });
    }
    for (fkey, frec) in &confirmation_updates {
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

    // Best-effort: ensure HasGotcha edges exist for all affected files.
    sync_has_gotcha_edges(store, key, &[], &affected_files).await;

    // Best-effort: invalidate consultation receipts on every affected file.
    //
    // A newly-confirmed gotcha is information the agent has not seen. Any
    // prior `session:consulted:file:<path>` receipt was minted before this
    // gotcha existed (or before it was confirmed), so granting the agent a
    // bypass on that stale receipt would let it edit a file under a
    // confirmed gotcha without ever surfacing the rule. Drop the receipt
    // so the next pre-read / pre-bash hook returns DENY and forces a fresh
    // consultation.
    for file_path in &affected_files {
        let consulted_key = format!("session:consulted:file:{file_path}");
        let _ = store.delete(&consulted_key).await;
    }

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

    Ok(serde_json::json!({
        "ok": true,
        "key": key,
        "confirmed": true,
        "confidence": confidence_val,
        "quality": quality_val,
    }))
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

    let mut record = store
        .get(key)
        .await
        .map_err(|e| (ErrorCode::StoreError, format!("store read: {e}")))?
        .ok_or_else(|| (ErrorCode::NotFound, format!("record not found: {key}")))?;

    let affected_files: Vec<String> = record
        .payload_as::<GotchaRecord>()
        .map(|g| g.affected_files)
        .unwrap_or_default();

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

    // Best-effort: remove HasGotcha edges for all affected files.
    sync_has_gotcha_edges(store, key, &affected_files, &[]).await;

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

    Ok(serde_json::json!({"ok": true, "key": key, "tombstoned": true}))
}

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

    // Only update StaticAnalysis-sourced records.
    if record.source != RecordSource::StaticAnalysis {
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
                device_id: Uuid::new_v4(),
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
                device_id: Uuid::new_v4(),
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

// ── Side-effecting reads ────────────────────────────────────────────────────

/// Native MemGet handler.
///
/// Primary: read record, return agent-facing JSON.
/// Sessions-tree transaction: consultation receipt + audit.
/// Deferred best-effort: access_count bump (knowledge, cross-tree) + daily agg (sessions).
pub(crate) async fn handle_mem_get(
    store: &Store,
    graph: &Arc<tokio::sync::RwLock<crate::graph::Graph>>,
    ctx: &RequestContext,
    request_id: Uuid,
    input: &protocol::MemGetInput,
) -> HandlerResult {
    if input.key.is_empty() {
        return Err((ErrorCode::ValidationFailed, "key must not be empty".into()));
    }

    // 1. Read record (pure read — no lock contention with sessions writes).
    let record = match store.get(&input.key).await {
        Ok(Some(r)) => {
            if matches!(r.lifecycle, RecordLifecycle::Tombstoned { .. }) {
                None
            } else {
                Some(r)
            }
        }
        Ok(None) => None,
        Err(e) => return Err((ErrorCode::StoreError, format!("store read: {e}"))),
    };

    // 2. Build response FIRST (must return before client timeout).
    //
    // Includes blast-radius warning injection for high-impact files. This
    // logic used to live in `tools::MatiServer::mem_get` (Direct branch only)
    // — meaning v1-dispatched mem_get calls saw the warning but v2-dispatched
    // ones did not. Centralizing here closes that divergence so both
    // protocol paths return identical responses (see
    // `mem_get_v1_and_v2_responses_are_byte_identical` test).
    let response = match &record {
        Some(r) => {
            let mut agent_json = super::tools::record_to_agent_json(r);
            if r.category == Category::File {
                if let Some(payload) = &r.payload {
                    if let Ok(fr) = serde_json::from_value::<
                        crate::store::record::FileRecord,
                    >(payload.clone())
                    {
                        if let Some(ref br) = fr.blast_radius {
                            use crate::analysis::blast_radius::BlastTier;
                            if matches!(br.tier, BlastTier::High | BlastTier::Critical) {
                                let warning = format!(
                                    "HIGH IMPACT FILE: {} files directly depend on this. Modify with extra care.",
                                    br.direct
                                );
                                if let Some(obj) = agent_json.as_object_mut() {
                                    obj.insert(
                                        "warnings".into(),
                                        serde_json::json!([warning]),
                                    );
                                }
                            }
                        }
                    }
                }
            }
            agent_json
        }
        None => serde_json::Value::Null,
    };

    // 3. Sessions-tree transaction: consultation receipt + audit.
    let receipt = match crate::store::session::consultation_receipt_staged(&input.key) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(
                request_id = %request_id,
                key = %input.key,
                "mem_get: consultation receipt staging failed: {e}"
            );
            // Fail-open: return success but write accepted audit standalone.
            if let Some((ak, ab)) =
                make_session_audit(ctx, request_id, "mem_get", &input.key, true, None)
            {
                let _ = store.transact_sessions_raw(&[(&ak, &ab)]).await;
            }
            return Ok(response);
        }
    };
    // Audit is required alongside the consultation receipt.
    let (audit_key, audit_bytes) =
        make_session_audit(ctx, request_id, "mem_get", &input.key, true, None)
            .ok_or_else(|| (ErrorCode::Internal, "audit serialization failed".into()))?;
    let writes: Vec<(&str, &[u8])> = vec![(&receipt.0, &receipt.1), (&audit_key, &audit_bytes)];
    if let Err(e) = store.transact_sessions_raw(&writes).await {
        tracing::warn!(
            request_id = %request_id,
            key = %input.key,
            "mem_get: sessions transaction failed (fail-open): {e}"
        );
    }

    // 3b. Best-effort enforcement event: ReceiptMinted.
    //
    // Mirrors the dispatch in `Command::ConsultationHit` (dispatch_v2.rs:720)
    // so the `mati history --enforcement` log contains a `receipt_minted`
    // row whether the receipt was minted by an MCP `mem_get` or a CLI
    // `mati explain` / `proxy.log_hit`. Without this, `mem_get`-only
    // workflows produce a silent receipt with no audit-grade evidence
    // that consultation happened, breaking the deny → consult → allow
    // enforcement audit chain.
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

    // 4. Deferred best-effort: access_count bump + daily agg.
    if let Some(mut r) = record {
        r.access_count += 1;
        let key_owned = input.key.clone();
        let graph_clone = Arc::clone(graph);
        tokio::task::spawn(async move {
            let g = graph_clone.read().await;
            let s = g.store();
            let _ = s.put(&key_owned, &r).await;
            let agg_key = crate::store::session::today_key("analytics:hit_");
            let _ = crate::store::session::upsert_daily_agg(s, &agg_key, &key_owned).await;
        });
    }

    Ok(response)
}

/// Native mem_query handler.
///
/// Centralizes the four mem_query modes (`text`, `tag`, `graph`,
/// `semantic`) so both v1 dispatch (`server.rs::socket_dispatch`'s
/// `"mem_query"` arm) and v2 dispatch (`Command::MemQuery`) produce
/// byte-identical responses. Before γ-C1.5, the logic lived only in
/// `tools::MatiServer::mem_query`'s Direct branch — meaning the v2
/// path went through the v1 string bridge and could silently drift if
/// the bridge's serialization assumptions diverged. See
/// `mem_query_handler_text_mode_matches_v1_path` for the byte-equality
/// pin.
///
/// Returns a JSON `Value` (text/tag → array, graph → grouped object).
/// Callers that need a String wrap with `serde_json::to_string_pretty`.
pub(crate) async fn handle_mem_query(
    store: &Store,
    graph_ref: &crate::graph::Graph,
    input: &protocol::MemQueryInput,
) -> HandlerResult {
    use crate::graph::EdgeKind;
    use crate::store::record::Category;

    const MAX_QUERY_LIMIT: usize = 50;
    let limit = (input.limit as usize).min(MAX_QUERY_LIMIT);

    match input.mode {
        protocol::QueryMode::Text => {
            // BM25 search across knowledge tree. Filter out session/analytics
            // and any non-Active records so agents never see internal state.
            let scored = match store.search_scored(&input.query, limit).await {
                Ok(r) => r,
                Err(e) => return Err((ErrorCode::StoreError, format!("search: {e}"))),
            };
            let arr: Vec<serde_json::Value> = scored
                .iter()
                .filter(|(_, r)| {
                    matches!(r.lifecycle, RecordLifecycle::Active)
                        && !matches!(r.category, Category::Session | Category::Analytics)
                })
                .map(|(score, r)| {
                    let mut obj = super::tools::record_to_agent_json(r);
                    if let serde_json::Value::Object(ref mut map) = obj {
                        map.insert(
                            "relevance".into(),
                            serde_json::json!((*score * 1000.0).round() / 1000.0),
                        );
                    }
                    obj
                })
                .collect();
            Ok(serde_json::Value::Array(arr))
        }
        protocol::QueryMode::Tag => {
            // Substring tag match across the agent-visible namespaces.
            // Bounded scan: stop after `limit` matches across all prefixes.
            let query_lower = input.query.to_lowercase();
            let mut matched: Vec<serde_json::Value> = Vec::new();
            for ns in &["gotcha:", "decision:", "file:", "stage:", "dev_note:", "dep:"] {
                if matched.len() >= limit {
                    break;
                }
                let records = match store.scan_prefix(ns).await {
                    Ok(rs) => rs,
                    Err(e) => return Err((ErrorCode::StoreError, format!("scan {ns}: {e}"))),
                };
                for record in records {
                    if matched.len() >= limit {
                        break;
                    }
                    if !matches!(record.lifecycle, RecordLifecycle::Active) {
                        continue;
                    }
                    if record
                        .tags
                        .iter()
                        .any(|t| t.to_lowercase().contains(&query_lower))
                    {
                        matched.push(super::tools::record_to_agent_json(&record));
                    }
                }
            }
            Ok(serde_json::Value::Array(matched))
        }
        protocol::QueryMode::Graph => {
            // 1-hop traversal from a seed key. Per-kind round-robin
            // allocation ensures every non-empty kind surfaces at least one
            // record before any kind gets a second slot. Without this, a
            // hot file with 10+ gotchas would starve imports / co_changes /
            // decisions / notes.
            const GOTCHA_LIMIT: usize = 10;
            const COCHANGE_LIMIT: usize = 5;
            const IMPORT_LIMIT: usize = 5;
            const DECISION_LIMIT: usize = 3;
            const NOTE_LIMIT: usize = 3;

            let edge_groups: &[(EdgeKind, &str, usize)] = &[
                (EdgeKind::HasGotcha, "gotchas", GOTCHA_LIMIT),
                (EdgeKind::CoChanges, "co_changes", COCHANGE_LIMIT),
                (EdgeKind::Imports, "imports", IMPORT_LIMIT),
                (EdgeKind::AffectedBy, "decisions", DECISION_LIMIT),
                (EdgeKind::HasNote, "notes", NOTE_LIMIT),
            ];

            let mut result = serde_json::Map::new();
            result.insert(
                "seed".to_string(),
                serde_json::Value::String(input.query.clone()),
            );
            let mut summary_parts: Vec<String> = Vec::new();

            let mut available: Vec<Vec<String>> = edge_groups
                .iter()
                .map(|(kind, _, cap)| {
                    graph_ref
                        .neighbors(&input.query, kind)
                        .into_iter()
                        .take(*cap)
                        .collect()
                })
                .collect();

            let mut quotas: Vec<usize> = vec![0; edge_groups.len()];
            let mut remaining = limit;
            loop {
                if remaining == 0 {
                    break;
                }
                let mut handed_out = 0usize;
                for (i, slot_keys) in available.iter().enumerate() {
                    if remaining == 0 {
                        break;
                    }
                    if quotas[i] < slot_keys.len() {
                        quotas[i] += 1;
                        remaining -= 1;
                        handed_out += 1;
                    }
                }
                if handed_out == 0 {
                    break;
                }
            }

            for (i, (kind, group_name, _)) in edge_groups.iter().enumerate() {
                let keys = std::mem::take(&mut available[i]);
                let mut group_records: Vec<serde_json::Value> = Vec::new();
                for key in keys.iter().take(quotas[i]) {
                    if let Ok(Some(record)) = store.get(key).await {
                        if matches!(record.lifecycle, RecordLifecycle::Active) {
                            let mut entry = serde_json::Map::new();
                            entry.insert("key".into(), serde_json::Value::String(record.key.clone()));
                            entry.insert(
                                "relationship".into(),
                                serde_json::Value::String(format!("{kind:?}")),
                            );
                            entry.insert(
                                "value".into(),
                                serde_json::Value::String(record.value.clone()),
                            );
                            entry.insert(
                                "confidence".into(),
                                serde_json::json!(record.confidence.value),
                            );
                            entry.insert(
                                "quality".into(),
                                serde_json::json!(record.quality.value),
                            );
                            if let Some(payload) = &record.payload {
                                if let Some(confirmed) = payload.get("confirmed") {
                                    entry.insert("confirmed".into(), confirmed.clone());
                                }
                            }
                            group_records.push(serde_json::Value::Object(entry));
                        }
                    }
                }
                if !group_records.is_empty() {
                    summary_parts.push(format!("{} {}", group_records.len(), group_name));
                }
                result.insert(
                    group_name.to_string(),
                    serde_json::Value::Array(group_records),
                );
            }

            // DependencyAffects overflow — appended to decisions group, still
            // honoring the global `limit` ceiling.
            if remaining > 0 {
                let dep_keys = graph_ref.neighbors(&input.query, &EdgeKind::DependencyAffects);
                let mut dep_added = 0usize;
                for key in dep_keys.iter().take(DECISION_LIMIT.min(remaining)) {
                    if let Ok(Some(record)) = store.get(key).await {
                        if matches!(record.lifecycle, RecordLifecycle::Active) {
                            let mut entry = serde_json::Map::new();
                            entry.insert("key".into(), serde_json::Value::String(record.key.clone()));
                            entry.insert(
                                "relationship".into(),
                                serde_json::Value::String("DependencyAffects".to_string()),
                            );
                            entry.insert(
                                "value".into(),
                                serde_json::Value::String(record.value.clone()),
                            );
                            entry.insert(
                                "confidence".into(),
                                serde_json::json!(record.confidence.value),
                            );
                            entry.insert(
                                "quality".into(),
                                serde_json::json!(record.quality.value),
                            );
                            if let Some(decisions) = result.get_mut("decisions") {
                                if let Some(arr) = decisions.as_array_mut() {
                                    arr.push(serde_json::Value::Object(entry));
                                    dep_added += 1;
                                }
                            }
                        }
                    }
                }
                let _ = dep_added; // remaining is only useful for diagnostic logs
            }

            let summary = if summary_parts.is_empty() {
                "No related records found".to_string()
            } else {
                summary_parts.join(", ")
            };
            result.insert("summary".to_string(), serde_json::Value::String(summary));
            Ok(serde_json::Value::Object(result))
        }
        protocol::QueryMode::Semantic => Err((
            ErrorCode::ValidationFailed,
            "semantic search requires --features semantic (not enabled)".into(),
        )),
    }
}

/// Native MemBootstrap handler.
///
/// Primary: assemble context packet (pure read computation).
/// Sessions-tree transaction: bootstrap agg + consultation receipts for all context files + audit.
/// Deferred best-effort: access_count bumps on context file records (knowledge, cross-tree).
pub(crate) async fn handle_mem_bootstrap(
    store: &Store,
    graph_ref: &crate::graph::Graph,
    graph_arc: &Arc<tokio::sync::RwLock<crate::graph::Graph>>,
    ctx: &RequestContext,
    request_id: Uuid,
    input: &protocol::MemBootstrapInput,
) -> Result<String, (ErrorCode, String)> {
    let context_files = &input.context_files;

    // 1. Assemble context packet (pure read computation) — determines outcome.
    let assembly = super::tools::assemble_context_packet(store, graph_ref, context_files).await;
    let (accepted, error_code) = match &assembly {
        Ok(_) => (true, None),
        Err(_) => (false, Some(ErrorCode::Internal)),
    };

    // 2. Stage all sessions-tree writes: bootstrap agg + per-file consultation receipts + audit.
    let mut session_writes: Vec<(String, Vec<u8>)> = Vec::new();

    // Bootstrap aggregation.
    let bootstrap_agg_key = crate::store::session::today_key("analytics:bootstrap_");
    if let Ok(staged) =
        crate::store::session::upsert_daily_agg_staged(store, &bootstrap_agg_key, "__bootstrap__")
            .await
    {
        session_writes.push(staged);
    }

    // Per-file consultation receipts.
    for file in context_files {
        let file_key = if file.starts_with("file:") {
            file.clone()
        } else {
            format!("file:{file}")
        };
        if let Ok(receipt) = crate::store::session::consultation_receipt_staged(&file_key) {
            session_writes.push(receipt);
        }
        // Per-file daily hit agg.
        let hit_agg_key = crate::store::session::today_key("analytics:hit_");
        if let Ok(staged) =
            crate::store::session::upsert_daily_agg_staged(store, &hit_agg_key, &file_key).await
        {
            session_writes.push(staged);
        }
    }

    // Audit entry — reflects actual assembly outcome.
    // Audit is required — fail closed if serialization fails.
    let audit = make_session_audit(ctx, request_id, "mem_bootstrap", "", accepted, error_code)
        .ok_or_else(|| (ErrorCode::Internal, "audit serialization failed".into()))?;
    session_writes.push(audit);

    // 3. Commit all sessions-tree writes atomically.
    let write_refs: Vec<(&str, &[u8])> = session_writes
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_slice()))
        .collect();
    if let Err(e) = store.transact_sessions_raw(&write_refs).await {
        tracing::warn!(
            request_id = %request_id,
            "mem_bootstrap: sessions transaction failed: {e}"
        );
    }

    // 4. Deferred best-effort: access_count bumps on context file records (only on success).
    if assembly.is_ok() && !context_files.is_empty() {
        let files_owned: Vec<String> = context_files.clone();
        let graph_clone = Arc::clone(graph_arc);
        tokio::task::spawn(async move {
            let g = graph_clone.read().await;
            let s = g.store();
            for file in &files_owned {
                let file_key = if file.starts_with("file:") {
                    file.clone()
                } else {
                    format!("file:{file}")
                };
                if let Ok(Some(mut record)) = s.get(&file_key).await {
                    record.access_count += 1;
                    record.last_accessed = now_secs();
                    let _ = s.put(&file_key, &record).await;
                }
            }
        });
    }

    match assembly {
        Ok(packet) => Ok(packet.injection_string),
        Err(e) => Err((ErrorCode::Internal, format!("bootstrap assembly: {e}"))),
    }
}

// ── File-link staged computation ────────────────────────────────────────────
//
// These helpers read file records, compute the gotcha_keys diff, and return
// updated Records WITHOUT persisting them. The caller stages them into the
// same transact_knowledge call as the gotcha mutation + audit.

use std::collections::HashSet;

/// Compute file-record updates for gotcha_keys link sync.
///
/// Returns a vec of `(file_key, updated_record)` for files that need their
/// `gotcha_keys` array modified. Records that don't exist or don't need
/// changes are excluded.
async fn compute_file_link_updates(
    store: &Store,
    gotcha_key: &str,
    old_files: &[String],
    new_files: &[String],
) -> Vec<(String, Record)> {
    let old_set: HashSet<&str> = old_files.iter().map(String::as_str).collect();
    let new_set: HashSet<&str> = new_files.iter().map(String::as_str).collect();
    let now = now_secs();
    let mut updates = Vec::new();

    // Add gotcha_key to newly-associated files.
    for file_path in new_set.difference(&old_set) {
        let file_key = format!("file:{file_path}");
        if let Ok(Some(mut record)) = store.get(&file_key).await {
            if add_gotcha_key_to_record(&mut record, gotcha_key) {
                record.updated_at = now;
                record.version.logical_clock += 1;
                record.version.wall_clock = now;
                updates.push((file_key, record));
            }
        }
    }

    // Remove gotcha_key from disassociated files.
    for file_path in old_set.difference(&new_set) {
        let file_key = format!("file:{file_path}");
        if let Ok(Some(mut record)) = store.get(&file_key).await {
            if remove_gotcha_key_from_record(&mut record, gotcha_key) {
                record.updated_at = now;
                record.version.logical_clock += 1;
                record.version.wall_clock = now;
                updates.push((file_key, record));
            }
        }
    }

    updates
}

/// Best-effort HasGotcha graph edge sync (cross-tree, outside transaction).
///
/// Adds edges for files in `new_files` that aren't in `old_files`, and removes
/// edges for files in `old_files` that aren't in `new_files`. Failures are
/// logged but not propagated — `mati repair` reconciles on drift.
async fn sync_has_gotcha_edges(
    store: &Store,
    gotcha_key: &str,
    old_files: &[String],
    new_files: &[String],
) {
    use std::collections::HashSet;

    let old_set: HashSet<&str> = old_files.iter().map(String::as_str).collect();
    let new_set: HashSet<&str> = new_files.iter().map(String::as_str).collect();
    let ts = now_secs().to_le_bytes();

    // Add edges for newly-affected files.
    for file_path in &new_set {
        if !old_set.contains(*file_path) {
            let file_key = format!("file:{file_path}");
            let edge_key = Edge::new(&file_key, EdgeKind::HasGotcha, gotcha_key).to_key();
            if let Err(e) = store.put_raw(&edge_key, &ts).await {
                tracing::warn!("sync_has_gotcha_edges: add failed {file_key} → {gotcha_key}: {e}");
            }
        }
    }

    // Remove edges for files no longer affected.
    for file_path in &old_set {
        if !new_set.contains(*file_path) {
            let file_key = format!("file:{file_path}");
            let edge_key = Edge::new(&file_key, EdgeKind::HasGotcha, gotcha_key).to_key();
            if let Err(e) = store.delete(&edge_key).await {
                tracing::warn!(
                    "sync_has_gotcha_edges: remove failed {file_key} → {gotcha_key}: {e}"
                );
            }
        }
    }
}

/// Compute confirmation_count propagation updates for file records.
///
/// Returns updated file records with incremented confirmation_count.
async fn compute_confirmation_propagation(
    store: &Store,
    affected_files: &[String],
) -> Vec<(String, Record)> {
    let now = now_secs();
    let mut updates = Vec::new();
    for file_path in affected_files {
        let file_key = format!("file:{file_path}");
        if let Ok(Some(mut record)) = store.get(&file_key).await {
            record.confidence.confirmation_count += 1;
            record.updated_at = now;
            record.version.logical_clock += 1;
            record.version.wall_clock = now;
            updates.push((file_key, record));
        }
    }
    updates
}

fn add_gotcha_key_to_record(record: &mut Record, gotcha_key: &str) -> bool {
    let Some(payload) = record.payload.as_mut() else {
        record.payload = Some(serde_json::json!({ "gotcha_keys": [gotcha_key] }));
        return true;
    };
    let Some(obj) = payload.as_object_mut() else {
        record.payload = Some(serde_json::json!({ "gotcha_keys": [gotcha_key] }));
        return true;
    };
    match obj.get_mut("gotcha_keys") {
        Some(existing) => {
            if let Some(arr) = existing.as_array_mut() {
                if arr.iter().any(|v| v.as_str() == Some(gotcha_key)) {
                    return false; // Already linked.
                }
                arr.push(serde_json::Value::String(gotcha_key.to_string()));
                true
            } else {
                *existing = serde_json::json!([gotcha_key]);
                true
            }
        }
        None => {
            obj.insert("gotcha_keys".into(), serde_json::json!([gotcha_key]));
            true
        }
    }
}

fn remove_gotcha_key_from_record(record: &mut Record, gotcha_key: &str) -> bool {
    let Some(payload) = record.payload.as_mut() else {
        return false;
    };
    let Some(obj) = payload.as_object_mut() else {
        return false;
    };
    let Some(existing) = obj.get_mut("gotcha_keys") else {
        return false;
    };
    let Some(arr) = existing.as_array_mut() else {
        return false;
    };
    let before = arr.len();
    arr.retain(|v| v.as_str() != Some(gotcha_key));
    arr.len() != before
}

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

    let valid_prefixes = ["gotcha:", "decision:", "dev_note:", "file:", "stage:", "dep:"];

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

        store
            .transact_knowledge(&ops)
            .await
            .map_err(|e| (ErrorCode::StoreError, format!("import transact failed: {e}")))?;

        imported += chunk_buf.len() as u64;
    }

    Ok(serde_json::json!({
        "ok": true,
        "imported": imported,
        "skipped": skipped,
    }))
}

// ─── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::Graph;
    use crate::mcp::metadata::PeerContext;
    use crate::store::record::Record;
    use crate::store::Store;

    fn test_peer() -> PeerContext {
        PeerContext {
            uid: 501,
            pid: Some(99999),
        }
    }

    fn test_ctx(repo_root: &std::path::Path) -> RequestContext {
        RequestContext {
            peer: test_peer(),
            daemon_session: Uuid::from_bytes([0xAA; 16]),
            repo_root: repo_root.to_path_buf(),
        }
    }

    /// Build a File record whose payload encodes a High-tier blast radius.
    ///
    /// The payload is constructed as raw JSON rather than typed `FileRecord`
    /// so this helper survives unrelated field additions to `FileRecord`
    /// (it has 20+ fields, many tagged `#[serde(default)]`). The minimum
    /// required surface is `path` + `blast_radius`.
    fn high_impact_file_record(key: &str, tier: &str, direct: u32) -> Record {
        let path = key.strip_prefix("file:").unwrap_or(key).to_string();
        let payload = serde_json::json!({
            "path": path,
            "purpose": "Storage layer",
            "entry_points": [],
            "imports": [],
            "gotcha_keys": [],
            "decision_keys": [],
            "todos": [],
            "unsafe_count": 0,
            "unwrap_count": 0,
            "change_frequency": 0,
            "last_author": null,
            "is_hotspot": false,
            "token_cost_estimate": 0,
            "last_modified_session": 0,
            "blast_radius": {
                "direct": direct,
                "transitive": direct * 5,
                "score": direct as f32,
                "tier": tier,
            }
        });
        let mut record = Record::layer0_file_stub(
            key.to_string(),
            uuid::Uuid::nil(),
            1,
            0,
        );
        record.payload = Some(payload);
        record
    }

    /// γ-C1 load-bearing test: the v2-native `handle_mem_get` and the
    /// rmcp tool wrapper `MatiServer::mem_get` must produce semantically
    /// identical agent-facing JSON for the same input.
    ///
    /// Before γ-C1, the rmcp tool's Direct branch in `tools.rs` injected a
    /// blast-radius `warnings` field that `handle_mem_get` did not — meaning
    /// v1-dispatched (`mati_root/socket → server.mem_get`) calls saw the
    /// warning, but v2-dispatched (`Command::MemGet → handle_mem_get`)
    /// calls did not. That divergence is a latent correctness bug. This
    /// test pins parity so the two protocol paths can never drift again.
    #[tokio::test]
    async fn mem_get_v1_and_v2_responses_agree_on_blast_radius_warning() {
        use crate::mcp::tools::MatiServer;
        use crate::mcp::types::MemGetParams;
        use rmcp::handler::server::wrapper::Parameters;

        let dir = tempfile::TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();

        // BlastTier serde uses snake_case — "high" not "High".
        let key = "file:src/hotspot.rs";
        let record = high_impact_file_record(key, "high", 22);
        store.put(key, &record).await.unwrap();

        let graph = Graph::load(store).await.unwrap();
        let graph_arc = Arc::new(tokio::sync::RwLock::new(graph));

        // Path A: v2 native handler (after γ-C1 centralization).
        let ctx = test_ctx(dir.path());
        let input = crate::mcp::protocol::MemGetInput { key: key.into() };
        let v2_value = {
            let g = graph_arc.read().await;
            handle_mem_get(g.store(), &graph_arc, &ctx, Uuid::new_v4(), &input)
                .await
                .expect("handle_mem_get must succeed for a known key")
        };

        // Path B: rmcp tool wrapper (v1 dispatch route). Returns a String;
        // parse it back to a Value so we can compare structurally rather
        // than relying on byte-identical formatting (the rmcp path uses
        // `to_string_pretty`, the handler path uses raw values).
        let server = MatiServer::with_graph_arc(Arc::clone(&graph_arc));
        let v1_string = server
            .mem_get(Parameters(MemGetParams {
                key: key.into(),
            }))
            .await;
        let v1_value: serde_json::Value =
            serde_json::from_str(&v1_string).expect("v1 mem_get must return valid JSON");

        // The critical claim: both paths emit the blast-radius warning. If
        // either side drifts in the future, this assertion catches it.
        let v2_warnings = v2_value.get("warnings").cloned();
        let v1_warnings = v1_value.get("warnings").cloned();
        assert_eq!(
            v2_warnings, v1_warnings,
            "v1 and v2 mem_get must emit identical `warnings` field; \
             v1={v1_warnings:?} v2={v2_warnings:?}"
        );
        assert!(
            v2_warnings.is_some(),
            "high-impact file must produce a warnings field, got v2={v2_value:?}"
        );
        // Belt-and-suspenders: the warning text must mention the impact.
        let warnings_text = serde_json::to_string(&v2_warnings.unwrap()).unwrap();
        assert!(
            warnings_text.contains("HIGH IMPACT FILE") && warnings_text.contains("22"),
            "warning content drift, got {warnings_text}"
        );
    }

    /// Negative case: a low-impact file must produce NO `warnings` field on
    /// either path. Pins the lower bound — the warning injection must be
    /// gated on `BlastTier::High | Critical`, not unconditional.
    #[tokio::test]
    async fn mem_get_low_impact_file_emits_no_warnings_on_either_path() {
        use crate::mcp::tools::MatiServer;
        use crate::mcp::types::MemGetParams;
        use rmcp::handler::server::wrapper::Parameters;

        let dir = tempfile::TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();

        let key = "file:src/cold.rs";
        let record = high_impact_file_record(key, "low", 1);
        store.put(key, &record).await.unwrap();

        let graph = Graph::load(store).await.unwrap();
        let graph_arc = Arc::new(tokio::sync::RwLock::new(graph));

        let ctx = test_ctx(dir.path());
        let input = crate::mcp::protocol::MemGetInput { key: key.into() };
        let v2_value = {
            let g = graph_arc.read().await;
            handle_mem_get(g.store(), &graph_arc, &ctx, Uuid::new_v4(), &input)
                .await
                .expect("handle_mem_get must succeed")
        };

        let server = MatiServer::with_graph_arc(Arc::clone(&graph_arc));
        let v1_string = server
            .mem_get(Parameters(MemGetParams {
                key: key.into(),
            }))
            .await;
        let v1_value: serde_json::Value = serde_json::from_str(&v1_string).unwrap();

        assert!(
            v2_value.get("warnings").is_none(),
            "Low-tier file must not produce warnings on v2 path, got {v2_value:?}"
        );
        assert!(
            v1_value.get("warnings").is_none(),
            "Low-tier file must not produce warnings on v1 path, got {v1_value:?}"
        );
    }

    // ── γ-C1.5: mem_query parity ──────────────────────────────────────────

    /// Build a small fixture of records covering the namespaces searched in
    /// tag mode plus a text-searchable value, so all three mem_query modes
    /// have something to find.
    async fn populate_query_fixture(store: &Store) {
        // Gotcha with tag "production-grade" and searchable value.
        let mut g = Record::layer0_file_stub(
            "gotcha:exemplar".to_string(),
            uuid::Uuid::nil(),
            1,
            0,
        );
        g.category = crate::store::record::Category::Gotcha;
        g.value = "Always validate input at boundaries".into();
        g.tags = vec!["production-grade".into(), "security".into()];
        store.put(&g.key, &g).await.unwrap();

        // Decision with the same tag — exercises multi-namespace tag walk.
        let mut d = Record::layer0_file_stub(
            "decision:auth-strategy".to_string(),
            uuid::Uuid::nil(),
            1,
            0,
        );
        d.category = crate::store::record::Category::Decision;
        d.value = "Use JWT for stateless API authentication".into();
        d.tags = vec!["production-grade".into()];
        store.put(&d.key, &d).await.unwrap();

        // A second gotcha with a different tag — must NOT match a
        // "production-grade" tag query, but WILL match a "validate" text query.
        let mut g2 = Record::layer0_file_stub(
            "gotcha:other".to_string(),
            uuid::Uuid::nil(),
            1,
            0,
        );
        g2.category = crate::store::record::Category::Gotcha;
        g2.value = "Validate cache keys for collisions".into();
        g2.tags = vec!["cache".into()];
        store.put(&g2.key, &g2).await.unwrap();
    }

    /// γ-C1.5 load-bearing test: text-mode `mem_query` via v2 native handler
    /// and via the v1 rmcp tool wrapper must produce byte-identical results
    /// after canonicalization. Pins the centralization so both protocol
    /// paths can never silently drift.
    #[tokio::test]
    async fn mem_query_text_mode_v1_and_v2_agree() {
        use crate::mcp::tools::MatiServer;
        use crate::mcp::types::MemQueryParams;
        use rmcp::handler::server::wrapper::Parameters;

        let dir = tempfile::TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();
        populate_query_fixture(&store).await;

        let graph = Graph::load(store).await.unwrap();
        let graph_arc = Arc::new(tokio::sync::RwLock::new(graph));

        // Path A: v2 native handler.
        let input = crate::mcp::protocol::MemQueryInput {
            query: "validate".into(),
            mode: crate::mcp::protocol::QueryMode::Text,
            limit: 10,
        };
        let v2_value = {
            let g = graph_arc.read().await;
            handle_mem_query(g.store(), &g, &input)
                .await
                .expect("handle_mem_query text mode must succeed")
        };

        // Path B: v1 rmcp tool wrapper.
        let server = MatiServer::with_graph_arc(Arc::clone(&graph_arc));
        let v1_string = server
            .mem_query(Parameters(MemQueryParams {
                query: "validate".into(),
                mode: "text".into(),
                limit: 10,
            }))
            .await;
        let v1_value: serde_json::Value = serde_json::from_str(&v1_string).unwrap();

        // Both must be arrays of the same length. The relevance score is
        // BM25-dependent and may vary by floating-point noise, so we compare
        // structure (sorted keys + value fields) rather than raw equality
        // on the `relevance` field.
        let v2_arr = v2_value.as_array().expect("v2 must be array");
        let v1_arr = v1_value.as_array().expect("v1 must be array");
        assert_eq!(
            v2_arr.len(),
            v1_arr.len(),
            "v1/v2 text-mode result lengths differ; v2={v2_arr:?} v1={v1_arr:?}"
        );
        let v2_keys: Vec<_> = v2_arr.iter().filter_map(|r| r.get("key").cloned()).collect();
        let v1_keys: Vec<_> = v1_arr.iter().filter_map(|r| r.get("key").cloned()).collect();
        assert_eq!(
            v2_keys, v1_keys,
            "v1/v2 text-mode key sets differ; v2={v2_keys:?} v1={v1_keys:?}"
        );
    }

    #[tokio::test]
    async fn mem_query_tag_mode_v1_and_v2_agree() {
        use crate::mcp::tools::MatiServer;
        use crate::mcp::types::MemQueryParams;
        use rmcp::handler::server::wrapper::Parameters;

        let dir = tempfile::TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();
        populate_query_fixture(&store).await;

        let graph = Graph::load(store).await.unwrap();
        let graph_arc = Arc::new(tokio::sync::RwLock::new(graph));

        let input = crate::mcp::protocol::MemQueryInput {
            query: "production-grade".into(),
            mode: crate::mcp::protocol::QueryMode::Tag,
            limit: 10,
        };
        let v2_value = {
            let g = graph_arc.read().await;
            handle_mem_query(g.store(), &g, &input).await.unwrap()
        };

        let server = MatiServer::with_graph_arc(Arc::clone(&graph_arc));
        let v1_string = server
            .mem_query(Parameters(MemQueryParams {
                query: "production-grade".into(),
                mode: "tag".into(),
                limit: 10,
            }))
            .await;
        let v1_value: serde_json::Value = serde_json::from_str(&v1_string).unwrap();

        // Tag mode is deterministic (no scoring), so byte-equality at the
        // structural level is achievable. Compare as raw JSON values.
        assert_eq!(
            v2_value, v1_value,
            "v1/v2 tag-mode responses must be byte-equal"
        );

        // And sanity: at least one of the fixture records was tagged
        // "production-grade".
        let arr = v2_value.as_array().expect("array");
        assert!(
            !arr.is_empty(),
            "fixture must produce at least one tag match"
        );
    }

    #[tokio::test]
    async fn mem_query_semantic_mode_returns_error_on_both_paths() {
        use crate::mcp::tools::MatiServer;
        use crate::mcp::types::MemQueryParams;
        use rmcp::handler::server::wrapper::Parameters;

        let dir = tempfile::TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();
        let graph = Graph::load(store).await.unwrap();
        let graph_arc = Arc::new(tokio::sync::RwLock::new(graph));

        // v2 path: HandlerResult Err.
        let input = crate::mcp::protocol::MemQueryInput {
            query: "anything".into(),
            mode: crate::mcp::protocol::QueryMode::Semantic,
            limit: 10,
        };
        let v2_err = {
            let g = graph_arc.read().await;
            handle_mem_query(g.store(), &g, &input).await
        };
        assert!(
            v2_err.is_err(),
            "semantic mode must surface as Err on v2 path"
        );

        // v1 path: error JSON string.
        let server = MatiServer::with_graph_arc(Arc::clone(&graph_arc));
        let v1_string = server
            .mem_query(Parameters(MemQueryParams {
                query: "anything".into(),
                mode: "semantic".into(),
                limit: 10,
            }))
            .await;
        let v1_value: serde_json::Value = serde_json::from_str(&v1_string).unwrap();
        assert!(
            v1_value.get("error").is_some(),
            "semantic mode must surface as `error` field on v1 path, got {v1_value:?}"
        );
        let msg = v1_value
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        assert!(
            msg.contains("semantic search requires"),
            "v1 error message must explain semantic feature requirement, got {msg:?}"
        );
    }
}
