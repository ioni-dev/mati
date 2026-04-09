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
) -> (String, Vec<u8>) {
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
    let bytes = rmp_serde::to_vec_named(&entry).unwrap_or_default();
    (audit_nanos_key(prefix), bytes)
}

/// Convenience: knowledge-tree audit.
pub(crate) fn make_audit(
    ctx: &RequestContext,
    request_id: Uuid,
    command_kind: &str,
    target_key: &str,
    accepted: bool,
    error_code: Option<ErrorCode>,
) -> (String, Vec<u8>) {
    make_audit_with_prefix(ctx, request_id, command_kind, target_key, accepted, error_code, AUDIT_KNOWLEDGE_PREFIX)
}

/// Convenience: session-tree audit.
pub(crate) fn make_session_audit(
    ctx: &RequestContext,
    request_id: Uuid,
    command_kind: &str,
    target_key: &str,
    accepted: bool,
    error_code: Option<ErrorCode>,
) -> (String, Vec<u8>) {
    make_audit_with_prefix(ctx, request_id, command_kind, target_key, accepted, error_code, AUDIT_SESSION_PREFIX)
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

    let existing = store.get(key).await.map_err(|e| {
        (ErrorCode::StoreError, format!("store read failed: {e}"))
    })?;

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
    record.source = RecordSource::ClaudeEnrich;
    record.confidence = ConfidenceScore::for_new_record(&RecordSource::ClaudeEnrich);
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
    let (audit_key, audit_bytes) =
        make_audit(ctx, request_id, "gotcha_upsert", key, true, None);
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
    store.transact_knowledge(&ops).await.map_err(|e| {
        (ErrorCode::StoreError, format!("transact failed: {e}"))
    })?;

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
    let file_link_updates =
        compute_file_link_updates(store, key, &[], &affected_files).await;
    let confirmation_updates =
        compute_confirmation_propagation(store, &affected_files).await;

    // Atomic: gotcha record + file-link updates + confirmation propagation + audit.
    let (audit_key, audit_bytes) =
        make_audit(ctx, request_id, "gotcha_confirm", key, true, None);
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
    store.transact_knowledge(&ops).await.map_err(|e| {
        (ErrorCode::StoreError, format!("transact failed: {e}"))
    })?;

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
    let file_link_updates =
        compute_file_link_updates(store, key, &affected_files, &[]).await;

    // Atomic: tombstoned record + file-link cleanup + audit.
    let (audit_key, audit_bytes) =
        make_audit(ctx, request_id, "gotcha_tombstone", key, true, None);
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
    store.transact_knowledge(&ops).await.map_err(|e| {
        (ErrorCode::StoreError, format!("transact failed: {e}"))
    })?;

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

    if input.purpose.is_empty() {
        return Err((
            ErrorCode::ValidationFailed,
            "purpose must not be empty".into(),
        ));
    }

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

    if !matches!(record.lifecycle, RecordLifecycle::Active) {
        return Err((
            ErrorCode::InvalidStateTransition,
            format!("{file_key} is tombstoned"),
        ));
    }

    // Merge enrichment with existing structural data.
    let was_confirmed = record.source == RecordSource::DeveloperManual
        || record.confidence.value >= 0.80;

    if let Some(ref mut payload) = record.payload {
        if let Some(obj) = payload.as_object_mut() {
            obj.insert(
                "purpose".to_string(),
                serde_json::Value::String(input.purpose.clone()),
            );
            if !input.entry_points.is_empty() {
                obj.insert("entry_points".to_string(), serde_json::json!(input.entry_points));
            }
            if !input.decision_keys.is_empty() {
                obj.insert("decision_keys".to_string(), serde_json::json!(input.decision_keys));
            }
            if !input.todos.is_empty() {
                obj.insert("todos".to_string(), serde_json::json!(input.todos));
            }
            // gotcha_keys and imports are NOT touched — daemon-managed.
        }
    }

    record.value = input.purpose.clone();
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
    let (audit_key, audit_bytes) =
        make_audit(ctx, request_id, "file_enrich", &file_key, true, None);
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
    store.transact_knowledge(&ops).await.map_err(|e| {
        (ErrorCode::StoreError, format!("transact failed: {e}"))
    })?;

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
        let (audit_key, audit_bytes) =
            make_audit(ctx, request_id, "file_reparse", &input.path, true, None);
        let ops = vec![KnowledgeWriteOp::PutRaw {
            key: &audit_key,
            value: &audit_bytes,
        }];
        store.transact_knowledge(&ops).await.map_err(|e| {
            (ErrorCode::StoreError, format!("audit write failed: {e}"))
        })?;
        return Ok(serde_json::json!({"ok": true}));
    };

    // Atomic: file record + audit in one transaction.
    let (audit_key, audit_bytes) =
        make_audit(ctx, request_id, "file_reparse", &input.path, true, None);
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
    store.transact_knowledge(&ops).await.map_err(|e| {
        (ErrorCode::StoreError, format!("transact failed: {e}"))
    })?;

    // Best-effort substep: staleness cascade to linked gotchas (separate puts).
    if let Some(fr) = record.payload_as::<FileRecord>() {
        if let Err(e) =
            crate::health::staleness::cascade_staleness_to_gotchas(store, &fr).await
        {
            tracing::warn!("file_reparse: staleness cascade failed for {}: {e}", input.path);
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
        let (audit_key, audit_bytes) =
            make_audit(ctx, request_id, "doc_capture", &input.path, true, None);
        let _ = store.put_raw(&audit_key, &audit_bytes).await;
        return Ok(serde_json::json!({"ok": true}));
    }

    let file_key = format!("file:{}", input.path);
    let mut record = match store.get(&file_key).await {
        Ok(Some(r)) => r,
        _ => {
            let (audit_key, audit_bytes) =
                make_audit(ctx, request_id, "doc_capture", &input.path, true, None);
            let _ = store.put_raw(&audit_key, &audit_bytes).await;
            return Ok(serde_json::json!({"ok": true}));
        }
    };

    // Only update StaticAnalysis-sourced records.
    if record.source != RecordSource::StaticAnalysis {
        let (audit_key, audit_bytes) =
            make_audit(ctx, request_id, "doc_capture", &input.path, true, None);
        let _ = store.put_raw(&audit_key, &audit_bytes).await;
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
    let (audit_key, audit_bytes) =
        make_audit(ctx, request_id, "doc_capture", &input.path, true, None);
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
    store.transact_knowledge(&ops).await.map_err(|e| {
        (ErrorCode::StoreError, format!("transact failed: {e}"))
    })?;

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

    let existing = store.get(&key).await.map_err(|e| {
        (ErrorCode::StoreError, format!("store read: {e}"))
    })?;

    let was_confirmed = existing
        .as_ref()
        .map(|r| {
            r.source == RecordSource::DeveloperManual || r.confidence.value >= 0.80
        })
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

    let (audit_key, audit_bytes) =
        make_audit(ctx, request_id, "decision_upsert", &key, true, None);
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
    store.transact_knowledge(&ops).await.map_err(|e| {
        (ErrorCode::StoreError, format!("transact failed: {e}"))
    })?;

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
            // Verify exists for update mode.
            if store.get(k).await.map_err(|e| {
                (ErrorCode::StoreError, format!("store read: {e}"))
            })?.is_none()
            {
                return Err((ErrorCode::NotFound, format!("record not found: {k}")));
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

    let existing = store.get(&key).await.map_err(|e| {
        (ErrorCode::StoreError, format!("store read: {e}"))
    })?;

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
    record.quality = quality::analyze(&record);

    let quality_val = record.quality.value;
    let tier_label = format!("{:?}", record.quality.tier);

    let (audit_key, audit_bytes) =
        make_audit(ctx, request_id, "dev_note_upsert", &key, true, None);
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
    store.transact_knowledge(&ops).await.map_err(|e| {
        (ErrorCode::StoreError, format!("transact failed: {e}"))
    })?;

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
) -> serde_json::Value {
    if input.key.is_empty() {
        return serde_json::json!({"error": "key must not be empty"});
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
        Err(e) => return serde_json::json!({"error": format!("store read: {e}")}),
    };

    // 2. Build response FIRST (must return before client timeout).
    let response = match &record {
        Some(r) => super::tools::record_to_agent_json(r),
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
            // Fail-open: return the read result even if receipt fails.
            return response;
        }
    };
    let (audit_key, audit_bytes) = make_session_audit(
        ctx, request_id, "mem_get", &input.key, true, None,
    );
    let writes: Vec<(&str, &[u8])> = vec![
        (&receipt.0, &receipt.1),
        (&audit_key, &audit_bytes),
    ];
    if let Err(e) = store.transact_sessions_raw(&writes).await {
        tracing::warn!(
            request_id = %request_id,
            key = %input.key,
            "mem_get: sessions transaction failed (fail-open): {e}"
        );
    }

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

    response
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
) -> String {
    use super::tools::VECTOR_B;

    let context_files = &input.context_files;

    // 1. Stage all sessions-tree writes: bootstrap agg + per-file consultation receipts + audit.
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

    // Audit entry (sessions-tree).
    let (audit_key, audit_bytes) = make_session_audit(
        ctx,
        request_id,
        "mem_bootstrap",
        "",
        true,
        None,
    );
    session_writes.push((audit_key, audit_bytes));

    // 2. Commit all sessions-tree writes atomically.
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

    // 3. Assemble context packet (pure read computation).
    let result = super::tools::assemble_context_packet(store, graph_ref, context_files).await;

    // 4. Deferred best-effort: access_count bumps on context file records.
    if !context_files.is_empty() {
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

    match result {
        Ok(packet) => packet.injection_string,
        Err(e) => format!("[mati] bootstrap error: {e}{VECTOR_B}"),
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
            obj.insert(
                "gotcha_keys".into(),
                serde_json::json!([gotcha_key]),
            );
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
