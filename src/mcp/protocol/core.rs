use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::store::AgentKind;

use super::*;
// ── Protocol constants ──────────────────────────────────────────────────────

/// Protocol version. Bump on incompatible wire format changes.
/// v1: newline-delimited JSON, flat cmd/args
/// v2: newline-delimited JSON, typed Command enum, session UUID required,
///     request size capped at [`MAX_FRAME_SIZE`]
pub const PROTOCOL_VERSION: u16 = 2;

/// Maximum request size in bytes (including the trailing newline).
/// Enforced by `socket_handle_connection` via `AsyncReadExt::take` before
/// any JSON parsing occurs. Oversized requests receive
/// [`ErrorCode::FrameTooLarge`] without triggering handler side effects.
///
/// Chosen to comfortably fit the largest normal request (FileEnrich ~2-4 KiB)
/// with headroom, while rejecting pathological payloads.
pub const MAX_FRAME_SIZE: usize = 65_536;

// ── Request ─────────────────────────────────────────────────────────────────

/// Daemon IPC request. Deserialized from a bounded frame.
///
/// Unknown top-level fields are rejected. The `cmd` field is internally tagged
/// by `type`, and each command's input DTO independently rejects unknown fields.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    /// Protocol version — validated at the wire layer before dispatch.
    pub v: u16,
    /// Correlation ID — used to match responses to requests. Not idempotency.
    pub id: Uuid,
    /// Session UUID — required on every request. This is a session marker for
    /// audit/provenance, NOT an authentication token. Peer identity is
    /// established via Unix peer credentials (`peer_cred()`).
    pub session: Uuid,
    /// Client-declared agent identity for attribution (ADR-018).
    /// Optional and additive: pre-multi-agent clients omit this field;
    /// the daemon stamps `Unknown` server-side when absent. NOT verified —
    /// same-UID processes are trusted (THREAT_MODEL.md section 3.I).
    #[serde(default)]
    pub agent: Option<AgentKind>,
    /// The command to execute.
    pub cmd: Command,
}

// ── Response ────────────────────────────────────────────────────────────────

/// Daemon IPC response. Serialized into a bounded frame.
#[derive(Debug, Serialize)]
#[serde(tag = "status")]
pub enum Response {
    /// Command succeeded. `data` contains the command-specific result.
    #[serde(rename = "ok")]
    Ok { id: Uuid, data: serde_json::Value },
    /// Command failed. `code` is a structured error code for programmatic
    /// handling; `message` is a human-readable description.
    #[serde(rename = "err")]
    Err {
        id: Uuid,
        code: ErrorCode,
        message: String,
    },
}

impl Response {
    /// Construct a success response.
    pub fn ok(id: Uuid, data: serde_json::Value) -> Self {
        Self::Ok { id, data }
    }

    /// Construct an error response.
    pub fn err(id: Uuid, code: ErrorCode, message: impl Into<String>) -> Self {
        Self::Err {
            id,
            code,
            message: message.into(),
        }
    }
}

// ── Error codes ─────────────────────────────────────────────────────────────

/// Structured error codes for programmatic handling by the CLI proxy.
///
/// Protocol-level errors (before dispatch):
/// - `VersionMismatch`, `FrameTooLarge`, `MalformedRequest`, `SessionMismatch`
///
/// Command-level errors (during dispatch):
/// - `ValidationFailed`, `NotFound`, `Conflict`, `InvalidStateTransition`,
///   `StoreError`, `Internal`
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// Request protocol version does not match daemon's PROTOCOL_VERSION.
    VersionMismatch,
    /// Request exceeds [`MAX_FRAME_SIZE`] bytes. Rejected before JSON parsing.
    FrameTooLarge,
    /// JSON parse error, unknown fields, or type mismatch.
    MalformedRequest,
    /// Request session UUID does not match daemon's current session.
    /// Client should re-read daemon metadata and retry once.
    SessionMismatch,
    /// Input validation failed (e.g., empty key, invalid slug, bad enum value).
    ValidationFailed,
    /// Referenced record does not exist.
    NotFound,
    /// Key collision (e.g., creating a gotcha that already exists).
    Conflict,
    /// State transition not allowed (e.g., confirming a tombstoned record).
    InvalidStateTransition,
    /// Underlying SurrealKV or tantivy error.
    StoreError,
    /// Unexpected internal error.
    Internal,
}

// ── Command enum ────────────────────────────────────────────────────────────

/// All commands available over the daemon IPC protocol.
///
/// Internally tagged by `"type"`. Each variant either has no arguments (unit)
/// or wraps a typed input DTO with `#[serde(deny_unknown_fields)]`.
///
/// There is no public `put` or `delete` command. All mutations are semantic.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Command {
    // ── A. Pure reads ───────────────────────────────────────────────────
    /// Health check. No arguments.
    #[serde(rename = "ping")]
    Ping,

    /// Snapshot of live daemon metrics — per-command counters and latency
    /// percentiles. Pure read, no audit, no side effects.
    #[serde(rename = "metrics")]
    Metrics,

    /// Single record lookup by key.
    #[serde(rename = "get")]
    Get(GetInput),

    /// Bulk lookup for hook decision: file record + linked gotchas + consultation status.
    #[serde(rename = "hook_evaluate")]
    HookEvaluate(HookEvaluateInput),

    /// Evaluate a normalized action against the daemon-resident local policies.
    #[serde(rename = "policy_evaluate")]
    PolicyEvaluate(PolicyEvaluateInput),

    /// Scan all records whose key starts with a prefix.
    #[serde(rename = "scan_prefix")]
    ScanPrefix(ScanPrefixInput),

    /// Scan raw keys under a prefix, without deserializing values.
    /// Unlike `scan_prefix`, this also returns keys whose values are not
    /// serialized `Record`s (e.g. `graph:edge:*` raw timestamps).
    #[serde(rename = "scan_keys")]
    ScanKeys(ScanKeysInput),

    /// Version history for a single key.
    #[serde(rename = "history")]
    History(HistoryInput),

    /// Version history for a single key since a timestamp.
    #[serde(rename = "history_since")]
    HistorySince(HistorySinceInput),

    /// Check whether a consultation receipt exists for a key.
    #[serde(rename = "session_check_consulted")]
    SessionCheckConsulted(SessionCheckConsultedInput),

    /// Check whether a recent consultation receipt exists (within TTL).
    #[serde(rename = "session_check_consulted_recent")]
    SessionCheckConsultedRecent(SessionCheckConsultedRecentInput),

    /// BM25 text search or graph traversal.
    #[serde(rename = "mem_query")]
    MemQuery(MemQueryInput),

    /// Scan enforcement events stored as raw JSON in the knowledge tree.
    #[serde(rename = "scan_enforcement_events")]
    ScanEnforcementEvents(ScanEnforcementEventsInput),

    /// Time-bounded enforcement scan used by policy activity reporting.
    #[serde(rename = "scan_enforcement_events_since_ms")]
    ScanEnforcementEventsSinceMs(ScanEnforcementEventsSinceMsInput),

    /// Read a runtime configuration value (e.g. audit.write_durability).
    /// Pure read — no audit, no side effects.
    #[serde(rename = "config_get")]
    ConfigGet(ConfigGetInput),

    // ── B. Reads with audited side effects ──────────────────────────────
    /// Single record lookup with consultation receipt side effect.
    #[serde(rename = "mem_get")]
    MemGet(MemGetInput),

    /// Assemble a token-budgeted context packet for session startup.
    #[serde(rename = "mem_bootstrap")]
    MemBootstrap(MemBootstrapInput),

    // ── C. Semantic mutations ───────────────────────────────────────────
    /// Create or update a gotcha record. Always sets confirmed=false.
    #[serde(rename = "gotcha_upsert")]
    GotchaUpsert(GotchaDraftInput),

    /// Confirm a gotcha for hook enforcement. Sets confirmed=true.
    #[serde(rename = "gotcha_confirm")]
    GotchaConfirm(GotchaConfirmInput),

    /// Tombstone a gotcha and clean up file links + graph edges.
    #[serde(rename = "gotcha_tombstone")]
    GotchaTombstone(GotchaTombstoneInput),

    /// Create, enable, disable, or tombstone a local policy.
    #[serde(rename = "policy_write")]
    PolicyWrite(PolicyWriteInput),

    /// Enrich a file record with LLM-derived purpose, entry points, etc.
    /// File record must already exist (created by init/reparse).
    #[serde(rename = "file_enrich")]
    FileEnrich(FileEnrichInput),

    /// Re-analyze a file from disk and update structural fields.
    #[serde(rename = "file_reparse")]
    FileReparse(FileReparseInput),

    /// Post-edit hook compound: consultation hit + file reparse.
    #[serde(rename = "file_edit_hook")]
    FileEditHook(FileEditHookInput),

    /// Extract doc comment from file on disk and update file record purpose.
    #[serde(rename = "doc_capture")]
    DocCapture(DocCaptureInput),

    /// Create or update a decision record.
    #[serde(rename = "decision_upsert")]
    DecisionUpsert(DecisionUpsertInput),

    /// Create or update a dev note.
    #[serde(rename = "dev_note_upsert")]
    DevNoteUpsert(DevNoteUpsertInput),

    /// Write a runtime configuration value. Records an
    /// `EnforcementConfigChanged` event when the value actually changes.
    #[serde(rename = "config_set")]
    ConfigSet(ConfigSetInput),

    /// Record an `EnforcementConfigChanged` audit event for an L3 sandbox-floor
    /// change (`mati sandbox` apply/clear/protect/unprotect). Lets the CLI log
    /// the change even when a daemon holds the store (socket mode).
    #[serde(rename = "sandbox_audit")]
    SandboxAudit(SandboxAuditInput),

    /// Append a session analytics event (6 homogeneous event types).
    #[serde(rename = "session_log")]
    SessionLog(SessionLogInput),

    /// Record a consultation hit: receipt + access metrics + daily agg.
    #[serde(rename = "consultation_hit")]
    ConsultationHit(ConsultationHitInput),

    /// Record a policy shadow observation in the eventual session store.
    #[serde(rename = "policy_shadow_observe")]
    PolicyShadowObserve(PolicyShadowObserveInput),

    /// Flush session data (collect consulted markers into session:current).
    #[serde(rename = "session_flush")]
    SessionFlush,

    /// Archive session, run promotions, collect stale reviews.
    #[serde(rename = "session_harvest")]
    SessionHarvest,

    /// Clear all consult receipts (PostCompact: force re-block after compaction).
    #[serde(rename = "session_clear_consults")]
    SessionClearConsults,

    /// Bulk-import a batch of pre-built `Record`s into the knowledge tree.
    /// Bypasses the semantic upsert handlers — records are written verbatim
    /// so an `export → import` round-trip preserves every field
    /// (`confirmed`, `source`, `confidence`, `lifecycle`, etc.) without
    /// the destructive resets the typed upsert commands apply.
    ///
    /// Only `gotcha:*`, `decision:*`, `dev_note:*`, `file:*`, `stage:*`,
    /// and `dep:*` keys are accepted (the knowledge-tree namespaces).
    /// Session-tree keys (`session:*`, `analytics:*`, `compliance:*`,
    /// `audit:*`) are rejected at the boundary — those are daemon-owned
    /// telemetry that an `export` should never round-trip.
    #[serde(rename = "record_import")]
    RecordImport(RecordImportInput),
}

// ── Input DTOs ──────────────────────────────────────────────────────────────
//
// Each DTO uses `deny_unknown_fields` so extra fields from a malicious or
// misconfigured client are rejected at decode time, not silently dropped.

// ── A. Pure read inputs ─────────────────────────────────────────────────────
