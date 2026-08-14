//! Centralized gotcha mutation operations.
//!
//! Every path that creates, edits, or tombstones a gotcha record — CLI direct,
//! daemon socket, MCP server — must go through these functions. They enforce
//! the full invariant: key collision check, record write, file-record link sync,
//! and graph edge management.
//!
//! Keeping this in the library crate (`mati_core::store`) ensures the binary
//! crate (`cli/`) and the MCP server (`mcp/server.rs`) share the same logic.
//!
//! ## Partial-failure behaviour
//!
//! SurrealKV supports multi-key atomic transactions within a single tree.
//! However, gotcha mutations span both the knowledge tree (gotcha records,
//! file-record links) and the sessions tree (graph edges). No single
//! transaction can span both trees — this is mati's two-tree architecture
//! constraint, not a SurrealKV limitation.
//!
//! The v2 protocol handlers in `mcp::handlers` stage knowledge-tree writes
//! (gotcha record + file-link updates + audit) in a single atomic
//! `transact_knowledge` call. Graph edge writes remain best-effort — both
//! paths call [`sync_has_gotcha_edges`] for the edge diff itself, but each
//! caller owns the dirty-marker guard around it (see "Cancellation safety"
//! below), so a failed edge write is equally visible to `mati repair --fast`
//! regardless of transport.
//!
//! The functions below are retained for the CLI direct-store path and as
//! building blocks — `stage_file_link_update`, [`sync_has_gotcha_edges`]
//! and [`invalidate_consultation_receipts`] are also called directly by
//! `mcp::handlers`, so the file-link mutation, edge sync and receipt
//! invalidation logic itself is not duplicated even though each transport
//! stages and commits it differently. Their ordering is chosen to minimize
//! damage from a mid-operation failure:
//!
//! 1. **Record write first** — the gotcha record is the source of truth. If
//!    later steps fail, the record exists and a future mutation or manual
//!    `mati review` can reconcile the stale links.
//! 2. **File-record links second** — these are the primary consumer-visible
//!    state. A missing link causes a false-negative (gotcha not shown for a
//!    file); a stale link causes a false-positive. Both are visible in `mati
//!    status` and correctable by re-running `mati gotcha edit`.
//! 3. **Graph edges last** — edges are rebuilt from KV on every `Graph::load`,
//!    so a missing edge is corrected at next graph load as long as the
//!    file-record link is correct.
//!
//! Link-sync and edge-write failures are logged and set a dirty marker via
//! [`super::repair::mark_dirty`]. This makes drift visible in `mati status`
//! and repairable via `mati repair`. The record write is never rolled back,
//! since a partially-linked gotcha is recoverable but a silently lost one
//! is not.
//!
//! ## Cancellation safety
//!
//! These functions run inside cancellable contexts (socket-handler tasks
//! aborted on shutdown drain timeout, `tokio::select!` losing branches in
//! parent code). A future dropped between the canonical record commit and
//! the end of the derived-index loop would leave the gotcha record persisted
//! but file-link / graph-edge state partially updated, with **no dirty
//! marker set** — cancellation is not an explicit failure branch, so the
//! `mark_dirty` calls inside `if let Err(...)` arms never run.
//!
//! Without protection, `repair_fast` on the next startup would skip these
//! orphaned gotchas (`is_dirty()` returns false), and silent drift would
//! persist until a manual `mati repair` ran. To close that hole, we use a
//! `DirtyOnDrop` guard installed *after* the canonical write succeeds and
//! disarmed only when the derived-index work returns normally. If the
//! containing future is dropped mid-loop, the guard's `Drop` impl marks the
//! gotcha key dirty via a synchronous SurrealKV write, ensuring
//! `repair_fast` picks it up on the next start.
//!
//! The guard uses synchronous KV writes (`Tree::insert`/equivalent) rather
//! than async ones because `Drop` can't `.await`. This is safe because
//! SurrealKV transactions are single-writer in their commit path, and the
//! drop-time write is best-effort — drift remains repairable even if the
//! marker write fails.
//!
//! See [`super::repair`] for the full consistency model.

use std::collections::{BTreeMap, HashSet};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;

use crate::graph::edges::{Edge, EdgeKind};
use crate::store::db::Store;
use crate::store::enforcement::{
    record_event, ControlChangeKind, EnforcementEventType, SubjectKind,
};
use crate::store::record::{FileRecord, Record, RecordLifecycle, TombstoneReason};

/// Wall-clock seconds since the UNIX epoch, used to stamp graph edges
/// written by the gotcha mutation pipeline.
///
/// **Storage-class:** the returned value is persisted into SurrealKV (see
/// `apply_gotcha_write` line ~181, where it becomes the edge value). A
/// silent zero would mint an edge timestamped 1970-01-01 that survives
/// forever in the versioned store and breaks any "edges newer than X"
/// query downstream.
///
/// We refuse to fabricate a value when the system clock is before the
/// UNIX epoch (clock-backward / unset RTC / VM resume to 1969). Panicking
/// is preferable to silently corrupting the store: the daemon panic hook
/// installed in `mcp::metadata` cleans up the socket + pid file and writes
/// a "panic" entry to the lifecycle log, so the operator sees the failure
/// and can fix the clock before retrying.
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before UNIX epoch — refusing to write a corrupt timestamp into the gotcha store")
        .as_secs()
}

mod edges;
mod links;
mod mutation;
mod normalization;
mod stamping;

#[cfg(test)]
mod tests;

pub use edges::{
    invalidate_consultation_receipts, propagate_confirmation_to_files, sync_has_gotcha_edges,
};
pub(crate) use links::stage_file_link_update;
pub use links::sync_gotcha_file_links;
pub use mutation::{
    apply_gotcha_confirm, apply_gotcha_tombstone, apply_gotcha_write, ensure_gotcha_key_available,
};
#[cfg(test)]
use normalization::resolve_lenient;
pub use normalization::{
    normalize_affected_file, normalize_affected_files, normalize_affected_files_with_root,
};
pub(crate) use normalization::{tombstoned_copy, with_normalized_affected_files};
use stamping::payload_is_confirmed;
pub use stamping::{confirm_content_stamp, disk_content_hash, set_confirm_stamp};

// ── Tests ────────────────────────────────────────────────────────────────────
