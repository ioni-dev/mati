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

mod decision_devnote;
mod file;
mod file_link;
mod gotcha;
mod reads;
mod record_import;

// γ-C4: the v1↔v2 parity tests that lived here (γ-C1, C1.5, C1.75, C1.85)
// were one-time migration gates pinning `MatiServer::mem_*` (v1 in-process
// path) against `handle_mem_*` (v2 native path). After γ-C4 the v1 path
// became a thin Socket-only proxy that forwards to the same handlers, so
// the parity claim is now structural rather than behavioral — there is no
// in-process Direct branch left to drift. The tests were retired along
// with the Direct backend. Handler-level coverage (input → output for each
// mem_* handler) lives in `src/mcp/tools/tests.rs` via the `call_mem_*`
// helpers that drive the handlers directly.
#[cfg(test)]
mod link_sync_tests;

pub(crate) use decision_devnote::{handle_decision_upsert, handle_dev_note_upsert};
pub(crate) use file::{handle_doc_capture, handle_file_enrich, handle_file_reparse};
pub(crate) use gotcha::{handle_gotcha_confirm, handle_gotcha_tombstone, handle_gotcha_upsert};
pub(crate) use reads::{handle_mem_bootstrap, handle_mem_get, handle_mem_query};
pub(crate) use record_import::handle_record_import;

use file_link::{apply_confirmation_propagation, compute_file_link_updates};

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
