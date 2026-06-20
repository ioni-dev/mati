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

/// Max attempts for `retry_on_write_conflict` (initial try + 3 retries).
const WRITE_CONFLICT_RETRIES: usize = 4;

/// Bounded retry for daemon write handlers that commit via `transact_knowledge`.
///
/// SurrealKV uses optimistic MVCC and the daemon serves connections
/// concurrently (dispatch holds only a shared graph read-lock, not a global
/// write lock), so a concurrent knowledge-tree write — most often
/// enforcement-event recording / consultation-receipt minting bumping the hot
/// `enforcement:seq` key — can collide with a gotcha confirm/upsert/tombstone
/// commit and surface `TransactionWriteConflict`. The `op` closure MUST
/// re-read and rebuild its write set on each call: a conflict means the
/// snapshot it built ops against is stale, so replaying the same ops could
/// clobber a concurrent writer. Backoff is 5/10/20ms; any error whose message
/// is not a write conflict (validation, not-found, …) returns immediately
/// without retry.
async fn retry_on_write_conflict<T, F, Fut>(mut op: F) -> Result<T, (ErrorCode, String)>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, (ErrorCode, String)>>,
{
    for attempt in 0..WRITE_CONFLICT_RETRIES {
        match op().await {
            Ok(value) => return Ok(value),
            Err((_, ref msg))
                if attempt + 1 < WRITE_CONFLICT_RETRIES
                    && msg.to_lowercase().contains("write conflict") =>
            {
                // Another knowledge-tree writer committed inside our
                // read→commit window. Back off briefly and retry against a
                // fresh read.
                tokio::time::sleep(std::time::Duration::from_millis(5u64 << attempt)).await;
            }
            Err(e) => return Err(e),
        }
    }
    // The final attempt's retry guard is false, so the loop always returns via
    // the catch-all `Err` arm above before reaching here.
    unreachable!("retry_on_write_conflict loop always returns within the body")
}

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

    // Read-modify-commit under bounded write-conflict retry. The daemon serves
    // writes concurrently, so a sibling enforcement-event / receipt write can
    // collide with this commit (see `retry_on_write_conflict`).
    let (record, is_new, old_affected_files) =
        retry_on_write_conflict(|| upsert_commit_once(store, ctx, request_id, input, now)).await?;

    let quality_val = record.quality.value;
    let tier_label = format!("{:?}", record.quality.tier);

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

    // SOTA-γ telemetry hook (D3): if the input tags mark this as an
    // enrichment-produced gotcha ("enriched"), persist an ExtractionRecord
    // capturing depth + config so `mati doctor`'s per-tier and per-config
    // A/B sections have data to aggregate. Mirror of the
    // `gotcha_ops::apply_gotcha_write` hook — the MCP path has its own
    // atomic transaction loop and doesn't go through that function, so
    // the hook is duplicated here. Best-effort; failure logs but doesn't
    // propagate (analytics, not correctness).
    if is_new {
        let _ = crate::store::extraction::write_on_extraction(
            store,
            key,
            &input.tags,
            &input.affected_files,
        )
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
async fn upsert_commit_once(
    store: &Store,
    ctx: &RequestContext,
    request_id: Uuid,
    input: &protocol::GotchaDraftInput,
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
                    if let Ok(fr) =
                        serde_json::from_value::<crate::store::record::FileRecord>(payload.clone())
                    {
                        use crate::analysis::blast_radius::BlastTier;

                        // Existing: blast-warning injection for high-impact
                        // files. Centralized here so both v1 and v2 dispatch
                        // return identical responses.
                        if let Some(ref br) = fr.blast_radius {
                            if matches!(br.tier, BlastTier::High | BlastTier::Critical) {
                                let warning = format!(
                                    "HIGH IMPACT FILE: {} files directly depend on this. Modify with extra care.",
                                    br.direct
                                );
                                if let Some(obj) = agent_json.as_object_mut() {
                                    obj.insert("warnings".into(), serde_json::json!([warning]));
                                }
                            }
                        }

                        // D2-α: adaptive enrichment depth hint. Pure
                        // additive — older clients ignore the new field.
                        // Cluster size requires a `cluster:index` lookup;
                        // tolerate absence (cold init, repair in progress)
                        // by treating the file as cluster-less.
                        let blast_tier = fr
                            .blast_radius
                            .as_ref()
                            .map(|b| b.tier)
                            .unwrap_or(BlastTier::Isolated);
                        let cluster_size = {
                            let path = input.key.strip_prefix("file:").unwrap_or(&input.key);
                            let mut size = 0u32;
                            if let Ok(Some(idx_rec)) = store.get("cluster:index").await {
                                if let Some(payload) = idx_rec.payload {
                                    if let Ok(idx) = serde_json::from_value::<
                                        crate::analysis::clusters::ClusterIndex,
                                    >(payload)
                                    {
                                        for cluster in &idx.clusters {
                                            if cluster.members.iter().any(|m| m == path) {
                                                size = cluster.size;
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                            size
                        };
                        let depth = crate::health::enrichment::enrichment_depth(
                            fr.line_count,
                            blast_tier,
                            cluster_size,
                            fr.gotcha_keys.len(),
                            None, // comment_density not stored
                        );
                        if let Some(obj) = agent_json.as_object_mut() {
                            obj.insert(
                                "enrichment_depth_hint".into(),
                                serde_json::json!(depth.as_str()),
                            );
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
            for ns in &[
                "gotcha:",
                "decision:",
                "file:",
                "stage:",
                "dev_note:",
                "dep:",
            ] {
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
                            entry.insert(
                                "key".into(),
                                serde_json::Value::String(record.key.clone()),
                            );
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
                            entry.insert("quality".into(), serde_json::json!(record.quality.value));
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
                            entry.insert(
                                "key".into(),
                                serde_json::Value::String(record.key.clone()),
                            );
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
                            entry.insert("quality".into(), serde_json::json!(record.quality.value));
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
        match store.get(&file_key).await {
            Ok(Some(mut record)) => {
                if add_gotcha_key_to_record(&mut record, gotcha_key) {
                    record.updated_at = now;
                    record.version.logical_clock += 1;
                    record.version.wall_clock = now;
                    updates.push((file_key, record));
                }
            }
            Ok(None) => {
                // No file record yet — a file `init` never indexed. Stage a
                // minimal layer-0 file stub carrying this gotcha key so the read
                // gate enforces immediately, instead of leaving the gotcha inert
                // until the next `mati init`. Mirrors the create-on-write
                // fix in gotcha_ops::update_file_gotcha_key. init/reparse later
                // merge real analysis and preserve gotcha_keys.
                let mut stub =
                    Record::layer0_file_stub(file_key.clone(), uuid::Uuid::new_v4(), 1, now);
                let mut fr = FileRecord::layer0_stub(
                    *file_path,
                    vec![],
                    vec![],
                    vec![],
                    0,
                    0,
                    0,
                    None,
                    false,
                    0,
                    now,
                );
                fr.gotcha_keys = vec![gotcha_key.to_string()];
                stub.payload = serde_json::to_value(&fr).ok();
                updates.push((file_key, stub));
            }
            Err(_) => {}
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

    let valid_prefixes = [
        "gotcha:",
        "decision:",
        "dev_note:",
        "file:",
        "stage:",
        "dep:",
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

// ── MemSet (γ-C1.85) ────────────────────────────────────────────────────────
//
// Native handler port of `tools::MatiServer::mem_set`'s Direct branch plus
// the four `&self` helpers (`mem_set_confirm`, `try_confirm_once`,
// `finalize_confirm`, `mem_set_delete`). The bytes here are intentionally
// near-identical to the originals — γ-C1.85 is pure code motion to ensure
// v1 (rmcp tool wrapper) and v2 (Socket → typed Commands) dispatch paths
// converge on a single implementation. After γ-C4 removes the Direct
// backend, this is the only entry point.

/// γ-C1.85 entry point: route `mem_set` to the appropriate write / confirm
/// / delete helper. Returns the JSON string the v1 rmcp tool used to return
/// from its Direct branch — same envelope shape, same error strings.
pub(crate) async fn handle_mem_set(
    graph_arc: &Arc<tokio::sync::RwLock<crate::graph::Graph>>,
    _ctx: &RequestContext,
    _request_id: Uuid,
    params: &crate::mcp::types::MemSetParams,
) -> String {
    match params.action.as_str() {
        "confirm" => apply_mem_set_confirm(graph_arc, &params.key).await,
        "delete" => apply_mem_set_delete(graph_arc, &params.key).await,
        "write" | "" => apply_mem_set_write(graph_arc, params).await,
        other => serde_json::json!({
            "error": format!("unknown action: {other}. Valid: write, confirm, delete")
        })
        .to_string(),
    }
}

async fn apply_mem_set_write(
    graph_arc: &Arc<tokio::sync::RwLock<crate::graph::Graph>>,
    params: &crate::mcp::types::MemSetParams,
) -> String {
    let graph = graph_arc.read().await;
    let store = graph.store();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Validate key namespace. `file:*` writes are intentionally
    // excluded — file records are owned by the static-analysis
    // pipeline (`mati init` Layer 0 + the `file_enrich` /
    // `file_reparse` typed Commands), never by direct mem_set.
    // The Socket path enforces the same restriction in
    // `build_mem_set_command`; both backends now accept and
    // reject identical key prefixes.
    let valid_prefix = ["gotcha:", "decision:", "dev_note:"]
        .iter()
        .any(|p| params.key.starts_with(p));
    if !valid_prefix {
        return serde_json::json!({
            "error": "key must start with gotcha:, decision:, or dev_note:"
        })
        .to_string();
    }

    // Parse category. `File` is intentionally absent — file
    // records are owned by the static-analysis pipeline (see the
    // key-namespace check above for the full justification).
    let category = match params.category.as_str() {
        "Gotcha" => Category::Gotcha,
        "Decision" => Category::Decision,
        "DevNote" => Category::DevNote,
        other => {
            return serde_json::json!({
                "error": format!("unknown category: {other}. Valid: Gotcha, Decision, DevNote")
            })
            .to_string();
        }
    };

    // Parse priority
    let priority = match params.priority.as_str() {
        "Critical" => StorePriority::Critical,
        "High" => StorePriority::High,
        "Low" => StorePriority::Low,
        _ => StorePriority::Normal,
    };

    // Fetch existing record to preserve Layer 0 structural data
    let existing_record =
        match super::tools::resolve_existing_for_write(store.get(&params.key).await) {
            Ok(record) => record,
            Err(error_json) => return error_json,
        };

    // A tombstoned record must not bleed its prior confirmation state
    // into a resurrection — treat it as an unconfirmed write.
    let is_tombstoned = existing_record
        .as_ref()
        .map(|r| matches!(r.lifecycle, RecordLifecycle::Tombstoned { .. }))
        .unwrap_or(false);

    // ── Semantic validation ──────────────────────────────────
    // Key-category consistency: key prefix must match category.
    // This prevents miscategorized records (e.g., gotcha: key
    // with Category::File) that would corrupt the knowledge store.
    let expected_category = match params.key.split(':').next().unwrap_or("") {
        "gotcha" => Category::Gotcha,
        "decision" => Category::Decision,
        "dev_note" => Category::DevNote,
        _ => unreachable!("key prefix already validated"),
    };
    if category != expected_category {
        return serde_json::json!({
            "error": format!(
                "key prefix requires category {expected_category:?}, got {category:?}"
            )
        })
        .to_string();
    }

    // Payload structural validation for new records. Updates to
    // existing records use merge semantics (existing fields are
    // preserved), so partial payloads are valid on update.
    let is_new_record = existing_record.is_none() || is_tombstoned;
    if is_new_record {
        // Normalize for validation (Codex sends JSON-encoded strings).
        let check_payload = match &params.payload {
            serde_json::Value::String(s) => serde_json::from_str::<serde_json::Value>(s)
                .unwrap_or_else(|_| params.payload.clone()),
            _ => params.payload.clone(),
        };
        let obj = check_payload.as_object();
        if let Err(msg) = match &category {
            Category::Gotcha => {
                let valid = obj.is_some_and(|o| {
                    let rule = o.get("rule").and_then(|v| v.as_str()).unwrap_or("");
                    let reason = o.get("reason").and_then(|v| v.as_str()).unwrap_or("");
                    !rule.is_empty() && !reason.is_empty()
                });
                if valid {
                    Ok(())
                } else {
                    Err("gotcha requires payload with non-empty 'rule' and 'reason'")
                }
            }
            Category::Decision => {
                let valid = obj.is_some_and(|o| {
                    let summary = o.get("summary").and_then(|v| v.as_str()).unwrap_or("");
                    let rationale = o.get("rationale").and_then(|v| v.as_str()).unwrap_or("");
                    !summary.is_empty() && !rationale.is_empty()
                });
                if valid {
                    Ok(())
                } else {
                    Err("decision requires payload with non-empty 'summary' and 'rationale'")
                }
            }
            Category::DevNote => {
                if params.value.is_empty() {
                    Err("dev_note requires non-empty value")
                } else {
                    Ok(())
                }
            }
            _ => Ok(()),
        } {
            return serde_json::json!({"error": msg}).to_string();
        }
    }

    let was_confirmed = existing_record
        .as_ref()
        .map(|r| {
            !is_tombstoned
                && (r.source == RecordSource::DeveloperManual || r.confidence.value >= 0.80)
        })
        .unwrap_or(false);

    // Capture old affected_files before mutation (for file-link sync)
    let old_affected_files: Vec<String> = existing_record
        .as_ref()
        .filter(|r| r.key.starts_with("gotcha:"))
        .and_then(|r| r.payload_as::<GotchaRecord>())
        .map(|g| g.affected_files)
        .unwrap_or_default();

    let mut record = match existing_record {
        Some(existing) => existing,
        _ => Record {
            key: params.key.clone(),
            value: String::new(),
            category: category.clone(),
            priority: StorePriority::Normal,
            tags: vec![],
            created_at: now,
            updated_at: now,
            ref_url: None,
            staleness: StalenessScore::fresh(),
            lifecycle: RecordLifecycle::Active,
            version: RecordVersion {
                device_id: uuid::Uuid::new_v4(),
                logical_clock: 0,
                wall_clock: now,
            },
            quality: QualityScore::layer0_default(),
            access_count: 0,
            last_accessed: 0,
            source: RecordSource::StaticAnalysis,
            confidence: ConfidenceScore::for_new_record(&RecordSource::StaticAnalysis),
            gap_analysis_score: 0.0,
            payload: Some(serde_json::json!({})),
        },
    };

    // A write to a tombstoned record revives it; reset
    // confirmation counters so the new write starts fresh.
    if is_tombstoned {
        record.confidence.confirmation_count = 0;
    }
    record.lifecycle = RecordLifecycle::Active;

    // Apply enrichment fields
    record.value = params.value.clone();
    record.category = category;
    record.updated_at = now;
    record.version.logical_clock += 1;
    record.version.wall_clock = now;
    record.priority = priority;

    // Preserve confirmation state: if the existing record was previously confirmed
    // (source=DeveloperManual or confidence>=0.80), keep source/confidence/tags.
    // Otherwise set to ClaudeEnrich defaults.
    if was_confirmed {
        // Only update tags if the caller explicitly provided non-empty tags.
        if !params.tags.is_empty() {
            record.tags = params.tags.clone();
        }
    } else {
        record.source = RecordSource::ClaudeEnrich;
        record.confidence = ConfidenceScore::for_new_record(&RecordSource::ClaudeEnrich);
        record.tags = params.tags.clone();
    }

    // Merge payload: for existing records, preserve structural fields from
    // Layer 0 (entry_points, imports, etc.) while overlaying enrichment.
    // Some MCP clients (Codex) send the payload as a JSON-encoded string
    // rather than a raw object. Parse it if so.
    let new_payload = match &params.payload {
        serde_json::Value::String(s) => {
            serde_json::from_str::<serde_json::Value>(s).unwrap_or_else(|_| params.payload.clone())
        }
        other => other.clone(),
    };
    if new_payload.is_object() && !new_payload.as_object().is_none_or(|o| o.is_empty()) {
        if let Some(existing_payload) = &record.payload {
            // Merge: new values override, existing keys preserved
            let mut merged = existing_payload.clone();
            if let (Some(base), Some(overlay)) = (merged.as_object_mut(), new_payload.as_object()) {
                for (k, v) in overlay {
                    // gotcha_keys is a derived index maintained by the
                    // gotcha confirm/tombstone paths. Overwriting it on
                    // file-record re-enrichment silently drops edges that
                    // were added by gotcha confirm. Union-merge instead.
                    if k == "gotcha_keys" {
                        if let (Some(existing_arr), Some(new_arr)) = (
                            base.get(k).and_then(|e| e.as_array()).cloned(),
                            v.as_array(),
                        ) {
                            let mut union = existing_arr;
                            for item in new_arr {
                                if !union.contains(item) {
                                    union.push(item.clone());
                                }
                            }
                            base.insert(k.clone(), serde_json::Value::Array(union));
                            continue;
                        }
                    }
                    base.insert(k.clone(), v.clone());
                }
                record.payload = Some(serde_json::Value::Object(base.clone()));
            } else {
                record.payload = Some(new_payload);
            }
        } else {
            record.payload = Some(new_payload);
        }
    }

    // Normalize gotcha payload: severity must be snake_case for GotchaRecord deserialization.
    // Claude sends "Critical"/"High"/"Normal"/"Low" but serde expects "critical"/"high"/etc.
    if record.key.starts_with("gotcha:") {
        if let Some(ref mut payload) = record.payload {
            if let Some(obj) = payload.as_object_mut() {
                if let Some(sev) = obj
                    .get("severity")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_lowercase())
                {
                    obj.insert("severity".to_string(), serde_json::Value::String(sev));
                }
            }
        }
    }

    // Recompute quality. Only reset confidence for non-confirmed records —
    // confirmed records keep their DeveloperManual confidence (0.80).
    if !was_confirmed {
        record.confidence = ConfidenceScore::for_new_record(&RecordSource::ClaudeEnrich);
    }
    record.quality = quality::analyze(&record);

    // Write record
    let tier_label = format!("{:?}", record.quality.tier);
    let record_key = record.key.clone();
    if let Err(e) = store.put(&record.key, &record).await {
        return serde_json::json!({"error": e.to_string()}).to_string();
    }

    // Extract affected_files for edge creation and file-link sync (gotchas only)
    let affected_files: Vec<String> = if record_key.starts_with("gotcha:") {
        record
            .payload
            .as_ref()
            .and_then(|p| p.get("affected_files"))
            .and_then(|v| serde_json::from_value::<Vec<String>>(v.clone()).ok())
            .unwrap_or_default()
    } else {
        vec![]
    };

    // Sync file:*.gotcha_keys — the derived index that diff and pre-read hooks use.
    // This was previously skipped, leaving MCP-created gotchas invisible to
    // enforcement surfaces even after confirmation.
    if record_key.starts_with("gotcha:") {
        if let Err(e) = crate::store::gotcha_ops::sync_gotcha_file_links(
            store,
            &record_key,
            &old_affected_files,
            &affected_files,
        )
        .await
        {
            tracing::warn!("mem_set: file link sync failed for {record_key}: {e}");
            crate::store::repair::mark_dirty(
                store,
                &record_key,
                &format!("mem_set link sync failed: {e}"),
            )
            .await;
        }
    }

    let old_affected_set: HashSet<&str> = old_affected_files.iter().map(String::as_str).collect();
    let new_affected_set: HashSet<&str> = affected_files.iter().map(String::as_str).collect();

    drop(graph); // release read lock before taking write lock

    // Keep the in-memory graph in sync with the persisted edge state.
    // mem_set already updated file links above; here we remove stale
    // HasGotcha edges for moved gotchas and add edges for newly-affected files.
    if record_key.starts_with("gotcha:") {
        let mut graph = graph_arc.write().await;

        for file_path in old_affected_set.difference(&new_affected_set) {
            let file_key = format!("file:{file_path}");
            if let Err(e) = graph
                .remove_edge(&file_key, &EdgeKind::HasGotcha, &record_key)
                .await
            {
                tracing::warn!(
                    "mem_set: stale edge removal failed for {file_key} → {record_key}: {e}"
                );
                crate::store::repair::mark_dirty(
                    graph.store(),
                    &record_key,
                    &format!("mem_set edge remove failed: {e}"),
                )
                .await;
            }
        }

        for file_path in new_affected_set.difference(&old_affected_set) {
            let file_key = format!("file:{file_path}");
            if let Err(e) = graph
                .add_edge(&file_key, EdgeKind::HasGotcha, &record_key)
                .await
            {
                tracing::warn!("mem_set: edge add failed for {file_key} → {record_key}: {e}");
                crate::store::repair::mark_dirty(
                    graph.store(),
                    &record_key,
                    &format!("mem_set edge add failed: {e}"),
                )
                .await;
            }
        }
    }

    serde_json::json!({
        "ok": true,
        "key": record_key,
        "confidence": record.confidence.value,
        "quality": record.quality.value,
        "tier": tier_label,
    })
    .to_string()
}

/// Confirm a gotcha record — sets confirmed=true, bumps confidence to 0.80,
/// syncs file-record gotcha_keys. This is the MCP-native equivalent of
/// `mati gotcha confirm`, needed because Codex Bash commands cannot access
/// the daemon socket from the sandbox.
async fn apply_mem_set_confirm(
    graph_arc: &Arc<tokio::sync::RwLock<crate::graph::Graph>>,
    key: &str,
) -> String {
    if !key.starts_with("gotcha:") {
        return serde_json::json!({"error": "confirm action only applies to gotcha: keys"})
            .to_string();
    }

    // Retry loop: SurrealKV MVCC can return a transient write conflict
    // when the confirm races with the preceding write on the same key.
    // Each attempt acquires and releases the read lock to get a fresh snapshot.
    const MAX_RETRIES: usize = 3;
    let mut last_err: Option<String> = None;

    for attempt in 0..MAX_RETRIES {
        // Scope the read lock so it is dropped before finalize_confirm,
        // which needs a write lock for graph edge updates.
        let result = {
            let graph = graph_arc.read().await;
            let store = graph.store();
            try_confirm_once(store, key).await
        };

        match result {
            Ok((rec, files)) => {
                return finalize_confirm(graph_arc, key, &rec, &files).await;
            }
            Err(e) => {
                let msg = format!("{e}");
                if msg.contains("write conflict") && attempt + 1 < MAX_RETRIES {
                    tracing::debug!(
                        "confirm {key}: write conflict (attempt {}), retrying",
                        attempt + 1
                    );
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                    last_err = Some(msg);
                    continue;
                }
                return serde_json::json!({"error": msg}).to_string();
            }
        }
    }
    serde_json::json!({"error": format!("store put: {}", last_err.unwrap_or_default())}).to_string()
}

/// Single attempt at the confirm get-mutate-put cycle.
async fn try_confirm_once(store: &Store, key: &str) -> anyhow::Result<(Record, Vec<String>)> {
    let mut record = store
        .get(key)
        .await?
        .ok_or_else(|| anyhow::anyhow!("record not found: {key}"))?;

    if record.category != Category::Gotcha {
        anyhow::bail!("{key} is not a gotcha record");
    }
    if !matches!(record.lifecycle, RecordLifecycle::Active) {
        anyhow::bail!("{key} is tombstoned — cannot confirm a deleted record");
    }

    // Set confirmed + normalize severity
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

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    record.updated_at = now;
    record.version.logical_clock += 1;
    record.version.wall_clock = now;

    let affected_files: Vec<String> = record
        .payload_as::<GotchaRecord>()
        .map(|g| g.affected_files)
        .unwrap_or_default();

    store.put(key, &record).await?;

    // Record ControlChanged::Confirmed enforcement event — best-effort
    if let Err(e) = crate::store::enforcement::record_event(
        store,
        crate::store::enforcement::EnforcementEventType::ControlChanged {
            change_kind: crate::store::enforcement::ControlChangeKind::Confirmed,
        },
        crate::store::enforcement::SubjectKind::Control,
        key.to_string(),
        "developer".to_string(),
        None,
        "control_confirmed".to_string(),
        None,
    )
    .await
    {
        tracing::warn!("confirm: enforcement event recording failed for {key}: {e}");
    }

    Ok((record, affected_files))
}

/// Post-put work: sync file links, graph edges, consultation receipt.
async fn finalize_confirm(
    graph_arc: &Arc<tokio::sync::RwLock<crate::graph::Graph>>,
    key: &str,
    record: &Record,
    affected_files: &[String],
) -> String {
    // Acquire a fresh read lock for file-link sync.
    let graph = graph_arc.read().await;
    let store = graph.store();

    // Sync file:*.gotcha_keys — best-effort
    for file_path in affected_files {
        let file_key = format!("file:{file_path}");
        if let Ok(Some(mut file_record)) = store.get(&file_key).await {
            let needs_link = file_record
                .payload
                .as_ref()
                .and_then(|p| p.get("gotcha_keys"))
                .and_then(|v| v.as_array())
                .map(|arr| !arr.iter().any(|v| v.as_str() == Some(key)))
                .unwrap_or(true);
            if needs_link {
                if let Some(ref mut payload) = file_record.payload {
                    if let Some(obj) = payload.as_object_mut() {
                        let arr = obj.entry("gotcha_keys").or_insert(serde_json::json!([]));
                        if let Some(arr) = arr.as_array_mut() {
                            arr.push(serde_json::Value::String(key.to_string()));
                        }
                    }
                }
                let _ = store.put(&file_key, &file_record).await;
            }
        }
        // Invalidate any prior consultation receipt on this file —
        // a newly-confirmed gotcha changes what the agent must know
        // about the file, so the bypass token from a pre-confirmation
        // mem_get / explain must not carry over. Mirrors the
        // socket-mode `handle_gotcha_confirm` cleanup so both backends
        // share identical enforcement behavior. (Pre-fix the codex
        // pre-bash hook silently allowed reads on files whose prior
        // bootstrap `mem_get` had minted a still-valid receipt.)
        let consulted_key = format!("session:consulted:{file_key}");
        let _ = store.delete(&consulted_key).await;
    }

    // Propagate confirmation_count to linked file records
    crate::store::gotcha_ops::propagate_confirmation_to_files(store, affected_files).await;

    // Mint consultation receipt so hooks know this file was reviewed
    let _ = crate::store::session::log_hit(store, key).await;

    let confidence_value = record.confidence.value;
    let quality_value = record.quality.value;

    // Release the read lock before taking a write lock for graph edge updates.
    drop(graph);

    // Ensure HasGotcha edges exist in the in-memory graph for all affected files.
    // This is idempotent (add_edge is a no-op if the edge already exists) and guards
    // against gotchas that were written via the CLI path, whose graph edges landed in
    // the persistent store but were never loaded into the running graph.
    if !affected_files.is_empty() {
        let mut g = graph_arc.write().await;
        for file_path in affected_files {
            let file_key = format!("file:{file_path}");
            let _ = g.add_edge(&file_key, EdgeKind::HasGotcha, key).await;
        }
    }

    serde_json::json!({
        "ok": true,
        "key": key,
        "confirmed": true,
        "confidence": confidence_value,
        "quality": quality_value,
    })
    .to_string()
}

/// Tombstone a gotcha record — marks it as deleted, removes file-record
/// links and graph edges. MCP-native equivalent of `mati gotcha delete`.
async fn apply_mem_set_delete(
    graph_arc: &Arc<tokio::sync::RwLock<crate::graph::Graph>>,
    key: &str,
) -> String {
    // Phase 1: read lock — validate and tombstone the record.
    let affected_files = {
        let graph = graph_arc.read().await;
        let store = graph.store();

        if !key.starts_with("gotcha:") {
            return serde_json::json!({"error": "delete action only applies to gotcha: keys"})
                .to_string();
        }

        let record = match store.get(key).await {
            Ok(Some(r)) => r,
            Ok(None) => {
                return serde_json::json!({"error": format!("record not found: {key}")}).to_string()
            }
            Err(e) => return serde_json::json!({"error": format!("store get: {e}")}).to_string(),
        };

        let affected: Vec<String> = record
            .payload_as::<GotchaRecord>()
            .map(|g| g.affected_files)
            .unwrap_or_default();

        if let Err(e) =
            crate::store::gotcha_ops::apply_gotcha_tombstone(store, key, &affected).await
        {
            return serde_json::json!({"error": format!("tombstone failed: {e}")}).to_string();
        }

        affected
    }; // read lock dropped here

    // Phase 2: write lock — clean up in-memory graph edges.
    {
        let mut graph = graph_arc.write().await;
        for file_path in &affected_files {
            let file_key = format!("file:{file_path}");
            // remove_edge is idempotent — the persisted edge is already gone
            // from apply_gotcha_tombstone; this cleans up the in-memory cache.
            if let Err(e) = graph
                .remove_edge(&file_key, &EdgeKind::HasGotcha, key)
                .await
            {
                tracing::warn!(
                    "mem_set_delete: in-memory edge cleanup failed for {file_key} → {key}: {e}"
                );
            }
        }
    }

    serde_json::json!({"ok": true, "key": key, "tombstoned": true}).to_string()
}

// ─── Tests ────────────────────────────────────────────────────────────────

// γ-C4: the v1↔v2 parity tests that lived here (γ-C1, C1.5, C1.75, C1.85)
// were one-time migration gates pinning `MatiServer::mem_*` (v1 in-process
// path) against `handle_mem_*` (v2 native path). After γ-C4 the v1 path
// became a thin Socket-only proxy that forwards to the same handlers, so
// the parity claim is now structural rather than behavioral — there is no
// in-process Direct branch left to drift. The tests were retired along
// with the Direct backend. Handler-level coverage (input → output for each
// mem_* handler) lives in `src/mcp/tools.rs::tests` via the `call_mem_*`
// helpers that drive the handlers directly.

#[cfg(test)]
mod link_sync_tests {
    use super::*;
    use crate::store::record::{Category, FileRecord, RecordLifecycle};
    use crate::store::Store;

    /// The MCP staged link-sync (`compute_file_link_updates`, used by the
    /// typed mem_set/confirm handlers) must create a file stub carrying the
    /// gotcha key when the file was never indexed — mirroring the
    /// `gotcha_ops::update_file_gotcha_key` create-on-write fix — so an
    /// agent-created gotcha on an un-indexed file enforces immediately.
    #[tokio::test]
    async fn compute_file_link_updates_creates_stub_for_unindexed_file() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let store = Store::open(dir.path()).await.expect("open store");

        // No file record exists for this path (init never indexed it).
        let updates =
            compute_file_link_updates(&store, "gotcha:x", &[], &["src/new.rs".to_string()]).await;

        assert_eq!(updates.len(), 1, "one file-record update staged");
        let (key, rec) = &updates[0];
        assert_eq!(key, "file:src/new.rs");
        let fr: FileRecord = rec.payload_as().expect("stub payload is a FileRecord");
        assert!(
            fr.gotcha_keys.contains(&"gotcha:x".to_string()),
            "staged stub must carry the gotcha key (got {:?})",
            fr.gotcha_keys
        );
        assert!(matches!(rec.category, Category::File));
        assert!(matches!(rec.lifecycle, RecordLifecycle::Active));

        store.close().await.expect("close");
    }

    /// Guard: when the file record already exists, no duplicate stub is created
    /// and the existing record simply gains the key (regression on the match arm).
    #[tokio::test]
    async fn compute_file_link_updates_updates_existing_record() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let store = Store::open(dir.path()).await.expect("open store");

        let mut seed = Record::layer0_file_stub("file:src/exists.rs", uuid::Uuid::new_v4(), 1, 1);
        let fr0 = FileRecord::layer0_stub(
            "src/exists.rs",
            vec![],
            vec![],
            vec![],
            0,
            0,
            0,
            None,
            false,
            0,
            1,
        );
        seed.payload = serde_json::to_value(&fr0).ok();
        store.put("file:src/exists.rs", &seed).await.expect("seed");

        let updates =
            compute_file_link_updates(&store, "gotcha:y", &[], &["src/exists.rs".to_string()])
                .await;

        assert_eq!(updates.len(), 1);
        let fr: FileRecord = updates[0].1.payload_as().expect("payload");
        assert!(fr.gotcha_keys.contains(&"gotcha:y".to_string()));

        store.close().await.expect("close");
    }
}
