//! Daemon IPC protocol v2 — wire types for the Unix socket boundary.
//!
//! All mutation commands are semantic (no raw `put`/`delete`). Trust-sensitive
//! fields (timestamps, confidence, quality, lifecycle) are daemon-controlled
//! and never cross the wire as client input.
//!
//! ## Wire format
//!
//! Framing: newline-delimited JSON. One JSON object per line, terminated by `\n`.
//! Request size is capped at [`MAX_FRAME_SIZE`] bytes (enforced by the server
//! before full buffering). Oversized requests receive [`ErrorCode::FrameTooLarge`].
//!
//! ## Security properties
//!
//! - All input DTOs use `#[serde(deny_unknown_fields)]`
//! - `Command` is a closed enum — unknown commands are rejected at decode
//! - Session UUID is required on every request (session marker, not auth)
//! - Request ID is correlation only, not idempotency
//!
//! ## Transaction model
//!
//! SurrealKV supports multi-key atomic transactions within a single tree.
//! The real constraint is mati's two-tree architecture: no single transaction
//! can span both the `knowledge` tree and the `sessions` tree.
//!
//! - Same-tree commands: mutation + audit committed in one transaction
//! - Mixed-tree commands: per-tree atomic batches with explicit substep audit

use serde::{Deserialize, Serialize};
use uuid::Uuid;

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

    /// Single record lookup by key.
    #[serde(rename = "get")]
    Get(GetInput),

    /// Bulk lookup for hook decision: file record + linked gotchas + consultation status.
    #[serde(rename = "hook_evaluate")]
    HookEvaluate(HookEvaluateInput),

    /// Scan all records whose key starts with a prefix.
    #[serde(rename = "scan_prefix")]
    ScanPrefix(ScanPrefixInput),

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

    /// Append a session analytics event (6 homogeneous event types).
    #[serde(rename = "session_log")]
    SessionLog(SessionLogInput),

    /// Record a consultation hit: receipt + access metrics + daily agg.
    #[serde(rename = "consultation_hit")]
    ConsultationHit(ConsultationHitInput),

    /// Flush session data (collect consulted markers into session:current).
    #[serde(rename = "session_flush")]
    SessionFlush,

    /// Archive session, run promotions, collect stale reviews.
    #[serde(rename = "session_harvest")]
    SessionHarvest,
}

// ── Input DTOs ──────────────────────────────────────────────────────────────
//
// Each DTO uses `deny_unknown_fields` so extra fields from a malicious or
// misconfigured client are rejected at decode time, not silently dropped.

// ── A. Pure read inputs ─────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GetInput {
    pub key: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HookEvaluateInput {
    pub file_key: String,
    #[serde(default)]
    pub include_recent: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScanPrefixInput {
    pub prefix: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScanEnforcementEventsInput {
    #[serde(default)]
    pub since_seq: u64,
    #[serde(default = "default_until_seq")]
    pub until_seq: u64,
}

fn default_until_seq() -> u64 {
    u64::MAX
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryInput {
    pub key: String,
    #[serde(default = "default_history_limit")]
    pub limit: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistorySinceInput {
    pub key: String,
    pub since_ts: u64,
    #[serde(default = "default_history_limit")]
    pub limit: u64,
}

fn default_history_limit() -> u64 {
    50
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionCheckConsultedInput {
    pub key: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionCheckConsultedRecentInput {
    pub key: String,
    #[serde(default = "default_ttl_secs")]
    pub ttl_secs: u64,
}

fn default_ttl_secs() -> u64 {
    900
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemQueryInput {
    pub query: String,
    #[serde(default = "default_query_mode")]
    pub mode: QueryMode,
    #[serde(default = "default_query_limit")]
    pub limit: u32,
}

fn default_query_mode() -> QueryMode {
    QueryMode::Text
}

fn default_query_limit() -> u32 {
    20
}

/// Search mode for mem_query.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum QueryMode {
    /// BM25 full-text search over record keys, values, and tags.
    Text,
    /// Filter records by tag (substring, case-insensitive).
    Tag,
    /// 1-hop graph traversal from a seed key.
    Graph,
    /// Semantic search (requires --features semantic).
    Semantic,
}

// ── B. Read-with-side-effect inputs ─────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemGetInput {
    pub key: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemBootstrapInput {
    #[serde(default)]
    pub context_files: Vec<String>,
}

// ── C. Semantic mutation inputs ─────────────────────────────────────────────

/// Gotcha creation/update input. The client expresses intent only — the daemon
/// derives confirmation state, confidence, quality, timestamps, and version.
///
/// Confirmation is ALWAYS reset to `false` on upsert. Use `GotchaConfirm`
/// to re-confirm after editing.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GotchaDraftInput {
    /// Gotcha key, must match `gotcha:<slug>`.
    pub key: String,
    /// Actionable rule text (imperative verb).
    pub rule: String,
    /// Causality sentence explaining why this rule exists.
    pub reason: String,
    /// Severity level.
    pub severity: Severity,
    /// File paths this gotcha applies to.
    #[serde(default)]
    pub affected_files: Vec<String>,
    /// Optional external reference URL.
    #[serde(default)]
    pub ref_url: Option<String>,
    /// Optional tags.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Record-level priority.
    #[serde(default)]
    pub priority: Priority,
    /// Record source — when set, the handler uses this instead of defaulting
    /// to `ClaudeEnrich`. CLI `gotcha add` sends `DeveloperManual` here.
    #[serde(default)]
    pub source: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GotchaConfirmInput {
    pub key: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GotchaTombstoneInput {
    pub key: String,
}

/// File enrichment input from LLM analysis (e.g., /mati-enrich workflow).
/// The file record must already exist (created by init/reparse).
///
/// Fields that are daemon-managed and MUST NOT appear:
/// - `gotcha_keys` (managed by gotcha lifecycle commands)
/// - `imports` (derived from tree-sitter)
/// - All structural/internal fields (unsafe_count, unwrap_count, etc.)
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileEnrichInput {
    /// File path (maps to `file:<path>`).
    pub path: String,
    /// Purpose sentence (verb-led).
    pub purpose: String,
    /// Function/method entry points identified by enrichment.
    #[serde(default)]
    pub entry_points: Vec<String>,
    /// Decision records that affect this file.
    #[serde(default)]
    pub decision_keys: Vec<String>,
    /// TODO items found during enrichment.
    #[serde(default)]
    pub todos: Vec<String>,
    /// Optional tags.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Record-level priority.
    #[serde(default)]
    pub priority: Priority,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileReparseInput {
    pub path: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileEditHookInput {
    pub path: String,
}

/// Path-only doc capture. The daemon reads the file from disk and extracts
/// the doc comment — no content crosses the wire.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocCaptureInput {
    pub path: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionUpsertInput {
    /// Key slug (daemon prepends `decision:`).
    pub slug: String,
    /// Human-readable summary ("We use X because Y").
    pub value: String,
    /// Concise decision summary (payload field).
    pub summary: String,
    /// Rationale text (payload field).
    pub rationale: String,
    /// Optional tags.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Record-level priority.
    #[serde(default)]
    pub priority: Priority,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevNoteUpsertInput {
    /// If absent, daemon auto-generates `dev_note:<slug>-<timestamp>`.
    /// If present, must match an existing `dev_note:*` key (update mode).
    #[serde(default)]
    pub key: Option<String>,
    /// Freeform note text.
    pub text: String,
    /// Optional tags.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Record-level priority.
    #[serde(default)]
    pub priority: Priority,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionLogInput {
    /// The event type (closed enum, 6 variants).
    pub event: SessionEvent,
    /// The record key this event pertains to.
    pub key: String,
}

/// Session analytics event types. Each maps to a daily aggregation key prefix.
///
/// `Hit` is NOT included — it has richer side effects and uses the separate
/// `ConsultationHit` command.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SessionEvent {
    Miss,
    ComplianceMiss,
    ComplianceHit,
    CodexShellMiss,
    Bootstrap,
    PromptNudge,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsultationHitInput {
    pub key: String,
}

// ── Shared enums ────────────────────────────────────────────────────────────

/// Severity level for gotcha records. Closed enum.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Critical,
    High,
    #[default]
    Normal,
    Low,
}

/// Record-level priority. Closed enum.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Priority {
    Critical,
    High,
    #[default]
    Normal,
    Low,
}

// ── Conversions from store types ────────────────────────────────────────────

impl From<crate::store::Priority> for Severity {
    fn from(p: crate::store::Priority) -> Self {
        match p {
            crate::store::Priority::Low => Severity::Low,
            crate::store::Priority::Normal => Severity::Normal,
            crate::store::Priority::High => Severity::High,
            crate::store::Priority::Critical => Severity::Critical,
        }
    }
}

impl From<crate::store::Priority> for Priority {
    fn from(p: crate::store::Priority) -> Self {
        match p {
            crate::store::Priority::Low => Priority::Low,
            crate::store::Priority::Normal => Priority::Normal,
            crate::store::Priority::High => Priority::High,
            crate::store::Priority::Critical => Priority::Critical,
        }
    }
}

// ── Command helpers ──────────────────────────────────────────────────────────

impl Command {
    /// Returns the serde rename string for this command variant.
    /// Used for audit logging and tracing spans.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Ping => "ping",
            Self::Get(_) => "get",
            Self::HookEvaluate(_) => "hook_evaluate",
            Self::ScanPrefix(_) => "scan_prefix",
            Self::History(_) => "history",
            Self::HistorySince(_) => "history_since",
            Self::SessionCheckConsulted(_) => "session_check_consulted",
            Self::SessionCheckConsultedRecent(_) => "session_check_consulted_recent",
            Self::MemQuery(_) => "mem_query",
            Self::ScanEnforcementEvents(_) => "scan_enforcement_events",
            Self::MemGet(_) => "mem_get",
            Self::MemBootstrap(_) => "mem_bootstrap",
            Self::GotchaUpsert(_) => "gotcha_upsert",
            Self::GotchaConfirm(_) => "gotcha_confirm",
            Self::GotchaTombstone(_) => "gotcha_tombstone",
            Self::FileEnrich(_) => "file_enrich",
            Self::FileReparse(_) => "file_reparse",
            Self::FileEditHook(_) => "file_edit_hook",
            Self::DocCapture(_) => "doc_capture",
            Self::DecisionUpsert(_) => "decision_upsert",
            Self::DevNoteUpsert(_) => "dev_note_upsert",
            Self::SessionLog(_) => "session_log",
            Self::ConsultationHit(_) => "consultation_hit",
            Self::SessionFlush => "session_flush",
            Self::SessionHarvest => "session_harvest",
        }
    }

    /// Returns the primary target key for this command, if applicable.
    /// Used for audit trail correlation.
    pub fn target_key(&self) -> &str {
        match self {
            Self::Get(i) => &i.key,
            Self::HookEvaluate(i) => &i.file_key,
            Self::ScanPrefix(i) => &i.prefix,
            Self::History(i) => &i.key,
            Self::HistorySince(i) => &i.key,
            Self::SessionCheckConsulted(i) => &i.key,
            Self::SessionCheckConsultedRecent(i) => &i.key,
            Self::MemQuery(i) => &i.query,
            Self::MemGet(i) => &i.key,
            Self::GotchaUpsert(i) => &i.key,
            Self::GotchaConfirm(i) => &i.key,
            Self::GotchaTombstone(i) => &i.key,
            Self::FileEnrich(i) => &i.path,
            Self::FileReparse(i) => &i.path,
            Self::FileEditHook(i) => &i.path,
            Self::DocCapture(i) => &i.path,
            Self::DecisionUpsert(i) => &i.slug,
            Self::DevNoteUpsert(i) => i.key.as_deref().unwrap_or(""),
            Self::SessionLog(i) => &i.key,
            Self::ConsultationHit(i) => &i.key,
            Self::Ping
            | Self::MemBootstrap(_)
            | Self::ScanEnforcementEvents(_)
            | Self::SessionFlush
            | Self::SessionHarvest => "",
        }
    }

    /// Returns true for commands that mutate state (categories B and C).
    ///
    /// Category B (reads with audited side effects): MemGet, MemBootstrap
    /// Category C (semantic mutations): all 13 mutation commands
    ///
    /// Audit entries are written for all of these.
    pub fn is_mutation(&self) -> bool {
        matches!(
            self,
            // B. Reads with audited side effects
            Self::MemGet(_)
            | Self::MemBootstrap(_)
            // C. Semantic mutations
            | Self::GotchaUpsert(_)
            | Self::GotchaConfirm(_)
            | Self::GotchaTombstone(_)
            | Self::FileEnrich(_)
            | Self::FileReparse(_)
            | Self::FileEditHook(_)
            | Self::DocCapture(_)
            | Self::DecisionUpsert(_)
            | Self::DevNoteUpsert(_)
            | Self::SessionLog(_)
            | Self::ConsultationHit(_)
            | Self::SessionFlush
            | Self::SessionHarvest
        )
    }
}

// ── Audit ───────────────────────────────────────────────────────────────────

/// Audit trail entry for commands dispatched through the v2 protocol.
///
/// Written to the sessions tree under `session:audit:<timestamp_ns>`.
/// Lightweight struct — not a full `Record` — to keep audit writes cheap.
///
/// Every mutating command (categories B and C) produces an audit entry.
/// Rejected commands (validation failure, version mismatch) also produce
/// an entry with `accepted = false`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Wall-clock timestamp (seconds since epoch).
    pub ts: u64,
    /// Effective UID of the peer that sent the command.
    pub peer_uid: u32,
    /// PID of the peer process (None on platforms that don't expose it).
    pub peer_pid: Option<u32>,
    /// Daemon session UUID — correlates entries within one daemon lifetime.
    pub daemon_session: Uuid,
    /// Request correlation ID from the v2 protocol.
    pub request_id: Uuid,
    /// Command kind string (e.g., "gotcha_upsert", "file_enrich").
    pub command_kind: String,
    /// Primary key affected by this command (empty for unit commands).
    pub target_key: String,
    /// Whether the command was accepted (dispatched to handler) or rejected.
    pub accepted: bool,
    /// Error code if rejected, None if accepted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<ErrorCode>,
}

// ── V1→V2 command mapping ───────────────────────────────────────────────────
//
// Used by the CLI proxy and MCP proxy to convert legacy v1-style (cmd, args)
// calls into v2 Command JSON. This is a transitional bridge — callers that
// are updated to construct typed Commands directly do not need this.

/// Map a v1-style `(cmd_str, args_json)` pair to a v2 Command JSON object.
///
/// **Pure reads only.** All mutation and side-effecting-read callers have been
/// migrated to construct typed `protocol::Command` values directly via
/// `daemon_v2()`. This function is retained only for pure-read commands used
/// by `daemon_result()` and `proxy_daemon_result()`.
///
/// Panics in debug builds if called with a mutation or side-effecting command.
pub fn v1_to_v2_command(cmd: &str, args: &serde_json::Value) -> serde_json::Value {
    use serde_json::json;

    match cmd {
        // Pure reads — the only commands that still use this mapping.
        "ping" => json!({"type": "ping"}),
        "get" => json!({"type": "get", "key": args["key"]}),
        "hook_evaluate" => json!({
            "type": "hook_evaluate",
            "file_key": args["file_key"],
            "include_recent": args.get("include_recent").and_then(|v| v.as_bool()).unwrap_or(false),
        }),
        "scan_prefix" => json!({"type": "scan_prefix", "prefix": args["prefix"]}),
        "history" => {
            json!({"type": "history", "key": args["key"], "limit": args.get("limit").and_then(|v| v.as_u64()).unwrap_or(50)})
        }
        "history_since" => json!({
            "type": "history_since",
            "key": args["key"],
            "since_ts": args.get("since_ts").and_then(|v| v.as_u64()).unwrap_or(0),
            "limit": args.get("limit").and_then(|v| v.as_u64()).unwrap_or(50),
        }),
        "session_check_consulted" => json!({"type": "session_check_consulted", "key": args["key"]}),
        "session_check_consulted_recent" => json!({
            "type": "session_check_consulted_recent",
            "key": args["key"],
            "ttl_secs": args.get("ttl_secs").and_then(|v| v.as_u64()).unwrap_or(900),
        }),
        "mem_query" => json!({
            "type": "mem_query",
            "query": args["query"],
            "mode": args.get("mode").and_then(|v| v.as_str()).unwrap_or("text"),
            "limit": args.get("limit").and_then(|v| v.as_u64()).unwrap_or(20),
        }),
        "scan_enforcement_events" => json!({
            "type": "scan_enforcement_events",
            "since_seq": args.get("since_seq").and_then(|v| v.as_u64()).unwrap_or(0),
            "until_seq": args.get("until_seq").and_then(|v| v.as_u64()).unwrap_or(u64::MAX),
        }),
        other => {
            panic!(
                "v1_to_v2_command called with unsupported command '{other}' — \
                 only pure reads are supported; mutation/side-effecting callers \
                 must use daemon_v2() with typed Command"
            );
        }
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Wire / protocol ─────────────────────────────────────────────────

    #[test]
    fn valid_v2_ping_request_decodes() {
        let json = serde_json::json!({
            "v": 2,
            "id": "550e8400-e29b-41d4-a716-446655440000",
            "session": "660e8400-e29b-41d4-a716-446655440000",
            "cmd": { "type": "ping" }
        });
        let req: Request = serde_json::from_value(json).unwrap();
        assert_eq!(req.v, PROTOCOL_VERSION);
        assert!(matches!(req.cmd, Command::Ping));
    }

    #[test]
    fn valid_v2_get_request_decodes() {
        let json = serde_json::json!({
            "v": 2,
            "id": "550e8400-e29b-41d4-a716-446655440000",
            "session": "660e8400-e29b-41d4-a716-446655440000",
            "cmd": { "type": "get", "key": "file:src/main.rs" }
        });
        let req: Request = serde_json::from_value(json).unwrap();
        match req.cmd {
            Command::Get(input) => assert_eq!(input.key, "file:src/main.rs"),
            _ => panic!("expected Get"),
        }
    }

    #[test]
    fn valid_gotcha_upsert_decodes() {
        let json = serde_json::json!({
            "v": 2,
            "id": "550e8400-e29b-41d4-a716-446655440000",
            "session": "660e8400-e29b-41d4-a716-446655440000",
            "cmd": {
                "type": "gotcha_upsert",
                "key": "gotcha:stripe-idempotency",
                "rule": "Always include an idempotency key",
                "reason": "Stripe retries without it cause double charges",
                "severity": "high",
                "affected_files": ["src/payments/stripe.rs"],
                "tags": ["payments", "stripe"]
            }
        });
        let req: Request = serde_json::from_value(json).unwrap();
        match req.cmd {
            Command::GotchaUpsert(input) => {
                assert_eq!(input.key, "gotcha:stripe-idempotency");
                assert_eq!(input.severity, Severity::High);
                assert_eq!(input.affected_files, vec!["src/payments/stripe.rs"]);
                assert_eq!(input.priority, Priority::Normal); // default
            }
            _ => panic!("expected GotchaUpsert"),
        }
    }

    #[test]
    fn valid_decision_upsert_decodes() {
        let json = serde_json::json!({
            "v": 2,
            "id": "550e8400-e29b-41d4-a716-446655440000",
            "session": "660e8400-e29b-41d4-a716-446655440000",
            "cmd": {
                "type": "decision_upsert",
                "slug": "unified-retry-strategy",
                "value": "We use exponential backoff because linear retry overloads downstream",
                "summary": "Exponential backoff for all retries",
                "rationale": "Linear retry caused cascading failures in prod 2024-01"
            }
        });
        let req: Request = serde_json::from_value(json).unwrap();
        match req.cmd {
            Command::DecisionUpsert(input) => {
                assert_eq!(input.slug, "unified-retry-strategy");
                assert!(!input.rationale.is_empty());
            }
            _ => panic!("expected DecisionUpsert"),
        }
    }

    #[test]
    fn valid_session_log_decodes() {
        let json = serde_json::json!({
            "v": 2,
            "id": "550e8400-e29b-41d4-a716-446655440000",
            "session": "660e8400-e29b-41d4-a716-446655440000",
            "cmd": {
                "type": "session_log",
                "event": "compliance_miss",
                "key": "file:src/main.rs"
            }
        });
        let req: Request = serde_json::from_value(json).unwrap();
        match req.cmd {
            Command::SessionLog(input) => {
                assert_eq!(input.event, SessionEvent::ComplianceMiss);
                assert_eq!(input.key, "file:src/main.rs");
            }
            _ => panic!("expected SessionLog"),
        }
    }

    #[test]
    fn valid_file_enrich_decodes() {
        let json = serde_json::json!({
            "v": 2,
            "id": "550e8400-e29b-41d4-a716-446655440000",
            "session": "660e8400-e29b-41d4-a716-446655440000",
            "cmd": {
                "type": "file_enrich",
                "path": "src/store/db.rs",
                "purpose": "Own the storage boundary for all SurrealKV operations",
                "entry_points": ["open", "put", "get"],
                "decision_keys": ["decision:storage-engine"]
            }
        });
        let req: Request = serde_json::from_value(json).unwrap();
        match req.cmd {
            Command::FileEnrich(input) => {
                assert_eq!(input.path, "src/store/db.rs");
                assert_eq!(input.entry_points.len(), 3);
                assert!(input.todos.is_empty()); // default
            }
            _ => panic!("expected FileEnrich"),
        }
    }

    // ── Rejection tests ─────────────────────────────────────────────────

    #[test]
    fn bad_version_still_decodes_for_error_handling() {
        // v=99 is parseable but the handler must reject it after decode.
        let json = serde_json::json!({
            "v": 99,
            "id": "550e8400-e29b-41d4-a716-446655440000",
            "session": "660e8400-e29b-41d4-a716-446655440000",
            "cmd": { "type": "ping" }
        });
        let req: Request = serde_json::from_value(json).unwrap();
        assert_ne!(req.v, PROTOCOL_VERSION);
    }

    #[test]
    fn unknown_field_in_request_rejected() {
        let json = serde_json::json!({
            "v": 2,
            "id": "550e8400-e29b-41d4-a716-446655440000",
            "session": "660e8400-e29b-41d4-a716-446655440000",
            "cmd": { "type": "ping" },
            "extra_field": true
        });
        let result = serde_json::from_value::<Request>(json);
        assert!(result.is_err(), "unknown top-level field must be rejected");
    }

    #[test]
    fn unknown_field_in_command_args_rejected() {
        let json = serde_json::json!({
            "v": 2,
            "id": "550e8400-e29b-41d4-a716-446655440000",
            "session": "660e8400-e29b-41d4-a716-446655440000",
            "cmd": { "type": "get", "key": "file:foo", "smuggled": true }
        });
        let result = serde_json::from_value::<Request>(json);
        assert!(
            result.is_err(),
            "unknown field in command args must be rejected"
        );
    }

    #[test]
    fn unknown_command_type_rejected() {
        let json = serde_json::json!({
            "v": 2,
            "id": "550e8400-e29b-41d4-a716-446655440000",
            "session": "660e8400-e29b-41d4-a716-446655440000",
            "cmd": { "type": "raw_put", "key": "gotcha:x", "value": "hacked" }
        });
        let result = serde_json::from_value::<Request>(json);
        assert!(result.is_err(), "unknown command type must be rejected");
    }

    #[test]
    fn malformed_uuid_rejected() {
        let json = serde_json::json!({
            "v": 2,
            "id": "not-a-uuid",
            "session": "660e8400-e29b-41d4-a716-446655440000",
            "cmd": { "type": "ping" }
        });
        let result = serde_json::from_value::<Request>(json);
        assert!(result.is_err(), "malformed UUID must be rejected");
    }

    #[test]
    fn missing_session_rejected() {
        let json = serde_json::json!({
            "v": 2,
            "id": "550e8400-e29b-41d4-a716-446655440000",
            "cmd": { "type": "ping" }
        });
        let result = serde_json::from_value::<Request>(json);
        assert!(result.is_err(), "missing session UUID must be rejected");
    }

    #[test]
    fn gotcha_upsert_rejects_server_owned_fields() {
        // Attempt to smuggle `confirmed` through the wire
        let json = serde_json::json!({
            "v": 2,
            "id": "550e8400-e29b-41d4-a716-446655440000",
            "session": "660e8400-e29b-41d4-a716-446655440000",
            "cmd": {
                "type": "gotcha_upsert",
                "key": "gotcha:test",
                "rule": "test rule",
                "reason": "test reason",
                "severity": "normal",
                "confirmed": true
            }
        });
        let result = serde_json::from_value::<Request>(json);
        assert!(
            result.is_err(),
            "server-owned field `confirmed` must be rejected"
        );
    }

    #[test]
    fn file_enrich_rejects_gotcha_keys() {
        // gotcha_keys is daemon-managed, must not cross the wire
        let json = serde_json::json!({
            "v": 2,
            "id": "550e8400-e29b-41d4-a716-446655440000",
            "session": "660e8400-e29b-41d4-a716-446655440000",
            "cmd": {
                "type": "file_enrich",
                "path": "src/main.rs",
                "purpose": "entry point",
                "gotcha_keys": ["gotcha:smuggled"]
            }
        });
        let result = serde_json::from_value::<Request>(json);
        assert!(
            result.is_err(),
            "daemon-managed field `gotcha_keys` must be rejected"
        );
    }

    #[test]
    fn file_enrich_rejects_imports() {
        // imports is daemon-derived from tree-sitter
        let json = serde_json::json!({
            "v": 2,
            "id": "550e8400-e29b-41d4-a716-446655440000",
            "session": "660e8400-e29b-41d4-a716-446655440000",
            "cmd": {
                "type": "file_enrich",
                "path": "src/main.rs",
                "purpose": "entry point",
                "imports": ["std::io"]
            }
        });
        let result = serde_json::from_value::<Request>(json);
        assert!(
            result.is_err(),
            "daemon-derived field `imports` must be rejected"
        );
    }

    #[test]
    fn invalid_severity_rejected() {
        let json = serde_json::json!({
            "v": 2,
            "id": "550e8400-e29b-41d4-a716-446655440000",
            "session": "660e8400-e29b-41d4-a716-446655440000",
            "cmd": {
                "type": "gotcha_upsert",
                "key": "gotcha:test",
                "rule": "test",
                "reason": "test",
                "severity": "EXTREME"
            }
        });
        let result = serde_json::from_value::<Request>(json);
        assert!(
            result.is_err(),
            "invalid severity enum value must be rejected"
        );
    }

    #[test]
    fn invalid_session_event_rejected() {
        let json = serde_json::json!({
            "v": 2,
            "id": "550e8400-e29b-41d4-a716-446655440000",
            "session": "660e8400-e29b-41d4-a716-446655440000",
            "cmd": {
                "type": "session_log",
                "event": "hit",
                "key": "file:foo"
            }
        });
        let result = serde_json::from_value::<Request>(json);
        assert!(
            result.is_err(),
            "hit is not a SessionEvent variant — must use consultation_hit command"
        );
    }

    // ── Response serialization ──────────────────────────────────────────

    #[test]
    fn ok_response_serializes() {
        let id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let resp = Response::ok(id, serde_json::json!({"pong": true}));
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["status"], "ok");
        assert_eq!(json["data"]["pong"], true);
    }

    #[test]
    fn err_response_serializes_with_code() {
        let id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let resp = Response::err(id, ErrorCode::ValidationFailed, "key must not be empty");
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["status"], "err");
        assert_eq!(json["code"], "validation_failed");
        assert_eq!(json["message"], "key must not be empty");
    }

    #[test]
    fn error_code_roundtrips() {
        let codes = vec![
            ErrorCode::VersionMismatch,
            ErrorCode::FrameTooLarge,
            ErrorCode::MalformedRequest,
            ErrorCode::SessionMismatch,
            ErrorCode::ValidationFailed,
            ErrorCode::NotFound,
            ErrorCode::Conflict,
            ErrorCode::InvalidStateTransition,
            ErrorCode::StoreError,
            ErrorCode::Internal,
        ];
        for code in codes {
            let json = serde_json::to_value(&code).unwrap();
            let back: ErrorCode = serde_json::from_value(json).unwrap();
            assert_eq!(back, code);
        }
    }

    // ── Unit variant commands ───────────────────────────────────────────

    #[test]
    fn session_flush_decodes() {
        let json = serde_json::json!({
            "v": 2,
            "id": "550e8400-e29b-41d4-a716-446655440000",
            "session": "660e8400-e29b-41d4-a716-446655440000",
            "cmd": { "type": "session_flush" }
        });
        let req: Request = serde_json::from_value(json).unwrap();
        assert!(matches!(req.cmd, Command::SessionFlush));
    }

    #[test]
    fn session_harvest_decodes() {
        let json = serde_json::json!({
            "v": 2,
            "id": "550e8400-e29b-41d4-a716-446655440000",
            "session": "660e8400-e29b-41d4-a716-446655440000",
            "cmd": { "type": "session_harvest" }
        });
        let req: Request = serde_json::from_value(json).unwrap();
        assert!(matches!(req.cmd, Command::SessionHarvest));
    }

    #[test]
    fn dev_note_upsert_create_mode() {
        let json = serde_json::json!({
            "v": 2,
            "id": "550e8400-e29b-41d4-a716-446655440000",
            "session": "660e8400-e29b-41d4-a716-446655440000",
            "cmd": {
                "type": "dev_note_upsert",
                "text": "Remember to update the changelog"
            }
        });
        let req: Request = serde_json::from_value(json).unwrap();
        match req.cmd {
            Command::DevNoteUpsert(input) => {
                assert!(input.key.is_none()); // create mode
                assert_eq!(input.text, "Remember to update the changelog");
            }
            _ => panic!("expected DevNoteUpsert"),
        }
    }

    #[test]
    fn dev_note_upsert_update_mode() {
        let json = serde_json::json!({
            "v": 2,
            "id": "550e8400-e29b-41d4-a716-446655440000",
            "session": "660e8400-e29b-41d4-a716-446655440000",
            "cmd": {
                "type": "dev_note_upsert",
                "key": "dev_note:changelog-reminder-1712345678",
                "text": "Updated: remember to update changelog AND version"
            }
        });
        let req: Request = serde_json::from_value(json).unwrap();
        match req.cmd {
            Command::DevNoteUpsert(input) => {
                assert_eq!(
                    input.key.as_deref(),
                    Some("dev_note:changelog-reminder-1712345678")
                );
            }
            _ => panic!("expected DevNoteUpsert"),
        }
    }

    // ── Command helper tests ────────────────────────────────────────────

    #[test]
    fn command_kind_covers_all_variants() {
        // Build one instance of each variant and verify kind() matches serde rename.
        let cases: Vec<(&str, Command)> = vec![
            ("ping", Command::Ping),
            ("get", Command::Get(GetInput { key: "k".into() })),
            (
                "hook_evaluate",
                Command::HookEvaluate(HookEvaluateInput {
                    file_key: "f".into(),
                    include_recent: false,
                }),
            ),
            (
                "scan_prefix",
                Command::ScanPrefix(ScanPrefixInput { prefix: "p".into() }),
            ),
            (
                "history",
                Command::History(HistoryInput {
                    key: "k".into(),
                    limit: 10,
                }),
            ),
            (
                "history_since",
                Command::HistorySince(HistorySinceInput {
                    key: "k".into(),
                    since_ts: 0,
                    limit: 10,
                }),
            ),
            (
                "session_check_consulted",
                Command::SessionCheckConsulted(SessionCheckConsultedInput { key: "k".into() }),
            ),
            (
                "session_check_consulted_recent",
                Command::SessionCheckConsultedRecent(SessionCheckConsultedRecentInput {
                    key: "k".into(),
                    ttl_secs: 900,
                }),
            ),
            (
                "mem_query",
                Command::MemQuery(MemQueryInput {
                    query: "q".into(),
                    mode: QueryMode::Text,
                    limit: 20,
                }),
            ),
            ("mem_get", Command::MemGet(MemGetInput { key: "k".into() })),
            (
                "mem_bootstrap",
                Command::MemBootstrap(MemBootstrapInput {
                    context_files: vec![],
                }),
            ),
            (
                "gotcha_upsert",
                Command::GotchaUpsert(GotchaDraftInput {
                    key: "gotcha:t".into(),
                    rule: "r".into(),
                    reason: "r".into(),
                    severity: Severity::Normal,
                    affected_files: vec![],
                    ref_url: None,
                    tags: vec![],
                    priority: Priority::Normal,
                    source: None,
                }),
            ),
            (
                "gotcha_confirm",
                Command::GotchaConfirm(GotchaConfirmInput {
                    key: "gotcha:t".into(),
                }),
            ),
            (
                "gotcha_tombstone",
                Command::GotchaTombstone(GotchaTombstoneInput {
                    key: "gotcha:t".into(),
                }),
            ),
            (
                "file_enrich",
                Command::FileEnrich(FileEnrichInput {
                    path: "p".into(),
                    purpose: "p".into(),
                    entry_points: vec![],
                    decision_keys: vec![],
                    todos: vec![],
                    tags: vec![],
                    priority: Priority::Normal,
                }),
            ),
            (
                "file_reparse",
                Command::FileReparse(FileReparseInput { path: "p".into() }),
            ),
            (
                "file_edit_hook",
                Command::FileEditHook(FileEditHookInput { path: "p".into() }),
            ),
            (
                "doc_capture",
                Command::DocCapture(DocCaptureInput { path: "p".into() }),
            ),
            (
                "decision_upsert",
                Command::DecisionUpsert(DecisionUpsertInput {
                    slug: "s".into(),
                    value: "v".into(),
                    summary: "s".into(),
                    rationale: "r".into(),
                    tags: vec![],
                    priority: Priority::Normal,
                }),
            ),
            (
                "dev_note_upsert",
                Command::DevNoteUpsert(DevNoteUpsertInput {
                    key: None,
                    text: "t".into(),
                    tags: vec![],
                    priority: Priority::Normal,
                }),
            ),
            (
                "session_log",
                Command::SessionLog(SessionLogInput {
                    event: SessionEvent::Miss,
                    key: "k".into(),
                }),
            ),
            (
                "consultation_hit",
                Command::ConsultationHit(ConsultationHitInput { key: "k".into() }),
            ),
            ("session_flush", Command::SessionFlush),
            ("session_harvest", Command::SessionHarvest),
        ];

        assert_eq!(cases.len(), 24, "must cover all 24 command variants");
        for (expected_kind, cmd) in &cases {
            assert_eq!(
                cmd.kind(),
                *expected_kind,
                "kind() mismatch for {:?}",
                expected_kind
            );
        }
    }

    #[test]
    fn command_is_mutation_classification() {
        // Pure reads — must NOT be mutations
        assert!(!Command::Ping.is_mutation());
        assert!(!Command::Get(GetInput { key: "k".into() }).is_mutation());
        assert!(!Command::MemQuery(MemQueryInput {
            query: "q".into(),
            mode: QueryMode::Text,
            limit: 20,
        })
        .is_mutation());

        // Reads with side effects — ARE mutations (audited)
        assert!(Command::MemGet(MemGetInput { key: "k".into() }).is_mutation());
        assert!(Command::MemBootstrap(MemBootstrapInput {
            context_files: vec![]
        })
        .is_mutation());

        // Semantic mutations — ARE mutations
        assert!(Command::GotchaConfirm(GotchaConfirmInput {
            key: "gotcha:t".into()
        })
        .is_mutation());
        assert!(Command::SessionLog(SessionLogInput {
            event: SessionEvent::Miss,
            key: "k".into(),
        })
        .is_mutation());
        assert!(Command::SessionFlush.is_mutation());
        assert!(Command::SessionHarvest.is_mutation());
    }

    #[test]
    fn command_target_key_returns_expected_values() {
        assert_eq!(Command::Ping.target_key(), "");
        assert_eq!(
            Command::Get(GetInput {
                key: "file:src/main.rs".into()
            })
            .target_key(),
            "file:src/main.rs"
        );
        assert_eq!(
            Command::GotchaUpsert(GotchaDraftInput {
                key: "gotcha:test".into(),
                rule: "r".into(),
                reason: "r".into(),
                severity: Severity::Normal,
                affected_files: vec![],
                ref_url: None,
                tags: vec![],
                priority: Priority::Normal,
                source: None,
            })
            .target_key(),
            "gotcha:test"
        );
        assert_eq!(
            Command::DecisionUpsert(DecisionUpsertInput {
                slug: "my-decision".into(),
                value: "v".into(),
                summary: "s".into(),
                rationale: "r".into(),
                tags: vec![],
                priority: Priority::Normal,
            })
            .target_key(),
            "my-decision"
        );
        // DevNoteUpsert in create mode — no key
        assert_eq!(
            Command::DevNoteUpsert(DevNoteUpsertInput {
                key: None,
                text: "t".into(),
                tags: vec![],
                priority: Priority::Normal,
            })
            .target_key(),
            ""
        );
        assert_eq!(Command::SessionFlush.target_key(), "");
    }

    #[test]
    fn audit_entry_serializes() {
        let entry = AuditEntry {
            ts: 1700000000,
            peer_uid: 501,
            peer_pid: Some(1234),
            daemon_session: Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap(),
            request_id: Uuid::parse_str("660e8400-e29b-41d4-a716-446655440000").unwrap(),
            command_kind: "gotcha_upsert".into(),
            target_key: "gotcha:test".into(),
            accepted: true,
            error_code: None,
        };
        let json = serde_json::to_value(&entry).unwrap();
        assert_eq!(json["peer_uid"], 501);
        assert_eq!(json["command_kind"], "gotcha_upsert");
        assert_eq!(json["accepted"], true);
        // error_code should be absent (skip_serializing_if)
        assert!(json.get("error_code").is_none());
    }

    #[test]
    fn audit_entry_rejected_includes_error_code() {
        let entry = AuditEntry {
            ts: 1700000000,
            peer_uid: 501,
            peer_pid: None,
            daemon_session: Uuid::nil(),
            request_id: Uuid::nil(),
            command_kind: "gotcha_confirm".into(),
            target_key: "gotcha:missing".into(),
            accepted: false,
            error_code: Some(ErrorCode::NotFound),
        };
        let json = serde_json::to_value(&entry).unwrap();
        assert_eq!(json["accepted"], false);
        assert_eq!(json["error_code"], "not_found");
        assert!(json["peer_pid"].is_null());
    }

    // ── store::Priority → protocol type conversions ────────────────────

    #[test]
    fn store_priority_to_protocol_severity_preserves_all_variants() {
        use crate::store::Priority as SP;
        assert_eq!(Severity::from(SP::Low), Severity::Low);
        assert_eq!(Severity::from(SP::Normal), Severity::Normal);
        assert_eq!(Severity::from(SP::High), Severity::High);
        assert_eq!(Severity::from(SP::Critical), Severity::Critical);
    }

    #[test]
    fn store_priority_to_protocol_priority_preserves_all_variants() {
        use crate::store::Priority as SP;
        assert_eq!(Priority::from(SP::Low), Priority::Low);
        assert_eq!(Priority::from(SP::Normal), Priority::Normal);
        assert_eq!(Priority::from(SP::High), Priority::High);
        assert_eq!(Priority::from(SP::Critical), Priority::Critical);
    }
}
