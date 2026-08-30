use serde::{Deserialize, Serialize};

use crate::hooks::decide::Action;
use crate::store::{
    PolicyMode as StorePolicyMode, PolicyRecord, PolicyStage as StorePolicyStage,
    Priority as StorePriority, ReceiptSource as StoreReceiptSource,
};

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
    /// Actor scope for the consult-receipt lookup: `agent_id` for a subagent,
    /// `None` (global) for the main thread. Drives per-actor enforcement.
    #[serde(default)]
    pub actor: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyEvaluateInput {
    pub action: Action,
    #[serde(default)]
    pub actor: Option<String>,
    /// Original command text used only for record-only bypass detection.
    #[serde(default)]
    pub raw_command: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PolicyVerdict {
    pub key: String,
    pub stage: StorePolicyStage,
    pub mode: StorePolicyMode,
    pub rule: String,
    pub reason: String,
    pub severity: StorePriority,
    pub requires_key: String,
    #[serde(default)]
    pub via: Vec<StoreReceiptSource>,
    pub satisfied: bool,
    /// Snapshot of the global enforcement mode used for block degradation.
    #[serde(default)]
    pub strict: bool,
    /// Outcome of the policy's `deny_if` predicate against this action,
    /// independent of `satisfied`/`requires` and never lowered by the
    /// schema-introspection exemption. Defaults to `None` for older daemons.
    #[serde(default)]
    pub content: crate::store::ContentOutcome,
    /// Outcome of the policy's `require` predicate (allowlist mirror of
    /// `content`): `Deny`/`Warn` means the requirement was missed. Defaults to
    /// `None` for older daemons.
    #[serde(default)]
    pub require_content: crate::store::ContentOutcome,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PolicyEvaluateResult {
    pub verdicts: Vec<PolicyVerdict>,
    /// Policy key whose literal was found in an otherwise unclassified command.
    #[serde(default)]
    pub bypass_key: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScanPrefixInput {
    pub prefix: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScanKeysInput {
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

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScanEnforcementEventsSinceMsInput {
    #[serde(default)]
    pub since_ms: u64,
    #[serde(default = "default_until_ms")]
    pub until_ms: u64,
}

fn default_until_ms() -> u64 {
    u64::MAX
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
    /// Receipt scope to check at. Receipts are minted actor-scoped and have no
    /// actor-to-global fallback, so a check that omits this asks about a key
    /// the gate never writes and always answers "not consulted".
    #[serde(default)]
    pub actor: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionCheckConsultedRecentInput {
    pub key: String,
    #[serde(default = "default_ttl_secs")]
    pub ttl_secs: u64,
    /// Receipt scope to check at — see [`SessionCheckConsultedInput::actor`].
    #[serde(default)]
    pub actor: Option<String>,
}

/// Ask whether an actor still owes a consultation receipt for a file it was
/// denied — the Tier 1 session lockdown's only input.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionOwedReceiptInput {
    /// Receipt scope of the caller, exactly as the gate evaluates it.
    #[serde(default)]
    pub actor: Option<String>,
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
    /// Look-back window in days for time-scoped modes (`policy_activity`).
    /// Ignored by other modes; `None` or `0` falls back to the mode's own
    /// default, and values above the retention horizon are capped.
    #[serde(default)]
    pub since: Option<u64>,
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
    /// Confirmed gotchas whose `affected_files` fall under a path prefix.
    /// `query` is a repo-relative directory or file path; empty returns nothing.
    /// Resolves against the canonical `gotcha:*` records, not the search index.
    DirGotchas,
    /// Semantic search (requires --features semantic).
    Semantic,
    /// Shadow observations for local policies (`analytics:policy_shadow_*`).
    /// `query` selects one policy slug; empty means all.
    PolicyObservations,
    /// Activity report for active local policies over a look-back window.
    /// `query` selects one policy slug (empty = all); `since` sets the days.
    PolicyActivity,
    /// Raw local analytics records (`analytics:*`). `query` names the aggregate
    /// by key substring (e.g. `miss_`) and is required — an empty query returns
    /// nothing rather than dumping every record. Bounded by `limit`.
    Analytics,
}

// ── B. Read-with-side-effect inputs ─────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemGetInput {
    pub key: String,
    /// Worktree (and, when a subagent, subagent) scope for the consultation
    /// receipt this call mints. Server-populated by `mati serve` from its own
    /// process cwd — never client-supplied through the public tool schema,
    /// which exposes only `key`.
    #[serde(default)]
    pub actor: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemBootstrapInput {
    #[serde(default)]
    pub context_files: Vec<String>,
}

// ── C. Semantic mutation inputs ─────────────────────────────────────────────

/// Gotcha creation/update input. The client expresses intent only — the daemon
/// derives confidence, quality, timestamps, and version.
///
/// `confirmed` is the one exception, and it is honoured only for a
/// developer-originated write (`source: "developer_manual"`). Everything else,
/// including every `mem_set` from an agent, is forced to `false` and must go
/// through `GotchaConfirm`.
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
    /// Developer-asserted confirmation, honoured only alongside
    /// `source: "developer_manual"`. `mem_set` never sets either field, so an
    /// agent cannot mint an enforcing gotcha without the `confirm` action.
    #[serde(default)]
    pub confirmed: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GotchaConfirmInput {
    pub key: String,
    /// True when the confirm came from an in-session elicitation accept (the
    /// developer approved a prompt showing the rule), false for a CLI or
    /// direct-mode confirm. Drives the enforcement event's reason code so the
    /// audit chain records the strongest confirm channel distinctly. Defaults
    /// to false so an older client that omits it deserializes cleanly.
    #[serde(default)]
    pub via_elicitation: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GotchaTombstoneInput {
    pub key: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyWriteOp {
    Create,
    Edit,
    Enable,
    Disable,
    Stage,
    Delete,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyWriteInput {
    pub op: PolicyWriteOp,
    pub key: String,
    #[serde(default)]
    pub policy: Option<PolicyRecord>,
    #[serde(default)]
    pub stage: Option<StorePolicyStage>,
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
    /// The event type (closed enum, 15 variants).
    pub event: SessionEvent,
    /// The record key this event pertains to.
    pub key: String,
    /// The AI agent session (Claude Code `session_id`) that triggered this event,
    /// for per-actor audit attribution (schema_version 2). Optional — absent for
    /// older clients and agents that provide no session.
    #[serde(default)]
    pub session_id: Option<String>,
    /// Receipt scope this event was decided at — the subagent `agent_id`, or
    /// absent for the main thread. The daemon needs it to look up the receipt
    /// that authorized an allow, since receipts are actor-scoped.
    #[serde(default)]
    pub actor: Option<String>,
    /// SHA-256 of the gotcha state the hook decided on, for the enforcement
    /// event's `decision_basis_hash`. Computed hook-side because that is where
    /// the decision was made; a digest, never raw tool input.
    #[serde(default)]
    pub decision_basis_hash: Option<String>,
}

/// Exact payload received from Claude Code's InstructionsLoaded hook.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstructionsLoadedInput {
    pub payload: crate::hooks::decide::InstructionsLoadedPayload,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyShadowObserveInput {
    pub policy_key: String,
    pub action: Action,
    pub would: crate::hooks::decide::ShadowOutcome,
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
    /// Claude edit gate: an edit DEFERRED because a recent consultation receipt
    /// exists. Records `AllowAfterReceipt` with an edit-specific reason code, so
    /// the audit trail proves the edit (not just the read) was preceded by a
    /// consult (Plane 2 evidence).
    EditConsulted,
    /// Claude edit gate: an edit was DENIED (stale or shell-evaded — no recent
    /// consult). Records `Deny` with an edit-specific reason code.
    EditBlocked,
    /// Enterprise floor mandate: an unconsulted access to a consult-required path was DENIED.
    /// Records `Deny` with reason `floor_consult_required` (distinct from gotcha denies).
    FloorConsultMiss,
    /// Local policy denied an unconsulted governed action.
    PolicyConsultMiss,
    /// Local policy `deny_if` denied a governed action on its content. Records a
    /// `Deny` with reason `policy_content_denied`, distinct from the consult
    /// deny so the audit chain can tell a content restriction from a missed
    /// consult.
    PolicyContentMiss,
    /// Local policy `require` denied a governed action that fell outside its
    /// allowlist / missed a required-content predicate. Records a `Deny` with
    /// reason `policy_requirement_unmet`, distinct from a `deny_if` content
    /// deny so the audit chain can tell "did a forbidden thing" from "failed to
    /// do a required thing."
    PolicyRequirementMiss,
    /// Local policy allowed an action after its receipt was present.
    PolicyConsultHit,
    /// Local policy injected steering context without changing the decision.
    PolicySteered,
    CodexShellMiss,
    /// Codex PRE-hook (`codex-pre-bash` / `codex-pre-apply-patch`) BLOCKED an
    /// unconsulted access — the shell command or patch never ran. Records
    /// `Deny`, unlike [`SessionEvent::CodexShellMiss`], which the POST-bash
    /// hook fires after the fact when nothing was denied.
    CodexShellBlocked,
    /// An unclassified command mentioned a meaningful literal from an active
    /// policy trigger; records a bypass signal without changing the decision.
    UnclassifiedPolicyLiteralBypass,
    /// Tier 1 session lockdown DENIED a Bash command because the session still
    /// owes a receipt on the keyed file. Records `Deny` with reason
    /// `session_lockdown`, distinct from the gotcha deny that armed it.
    LockdownBlocked,
    Bootstrap,
    PromptNudge,
    /// Post-bash observed a command that passed `is_schema_introspection` but
    /// whose leading word did not classify as `db_client` — an upstream
    /// PreToolUse hook rewrote it (observed live: `rtk psql …`). The
    /// consultation receipt this command should mint never mints, so a
    /// `db_client` policy stays permanently unsatisfiable: a deadlock, not a
    /// bypass. Diagnostic only; does not change any decision.
    WrappedDbClientMiss,
    /// The `FileDeleted` tombstone bypass fired on a caller-confirmed
    /// deletion, suppressing a deny a qualifying confirmed gotcha would
    /// otherwise have produced. Records `BypassDetected` — the decision
    /// stayed `Tombstone` (allow), but the suppression is enforcement-
    /// relevant and must reach the hash-chained log.
    TombstoneBypassedDeny,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsultationHitInput {
    pub key: String,
    /// Capture a content fingerprint when the target record exists.
    #[serde(default = "default_capture_fingerprint")]
    pub capture_fingerprint: bool,
    #[serde(default)]
    pub actor: Option<String>,
    /// Claude session_id (the session) — for ReceiptMinted audit attribution.
    #[serde(default)]
    pub session_id: Option<String>,
    /// Subagent agent_id when present (fallback attribution).
    #[serde(default)]
    pub agent_id: Option<String>,
    /// How the consultation happened, recorded onto the receipt. `None` when
    /// the caller's path is unattributed — see
    /// `store::session::ConsultationReceipt::source`. Defaulted so an older
    /// hook binary talking to a newer daemon still mints.
    #[serde(default)]
    pub source: Option<crate::store::ReceiptSource>,
    /// SHA-256 of the gotcha state in force when the receipt was minted.
    #[serde(default)]
    pub decision_basis_hash: Option<String>,
}

fn default_capture_fingerprint() -> bool {
    true
}

/// Input for `Command::SubagentHarvest`. Written by the `SubagentStop` hook
/// when a Task subagent finishes: its `last_assistant_message` is the subagent's
/// own prose summary, captured into `session:summary:latest` so `mem_bootstrap`
/// can surface it as `recent_session`. All fields but `summary` default, so an
/// older hook binary talking to a newer daemon still writes.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubagentHarvestInput {
    /// The subagent's final assistant message — its own summary of the work.
    pub summary: String,
    /// Claude session_id the subagent ran under (the spawning session).
    #[serde(default)]
    pub session_id: Option<String>,
    /// The subagent's own agent_id.
    #[serde(default)]
    pub agent_id: Option<String>,
    /// Subagent type (e.g. "general-purpose").
    #[serde(default)]
    pub agent_type: Option<String>,
    /// Path to the subagent's transcript, for later retrieval.
    #[serde(default)]
    pub transcript_path: Option<String>,
}

/// Input for `Command::SubagentSpawned`. Written by the `SubagentStart` hook:
/// records a subagent's presence as a hash-chained enforcement event so the audit
/// can attribute a subagent that spawned and never consulted. `agent_id` is
/// required in practice (the presence is meaningless without it); the recorder
/// no-ops when it is absent. All fields default for hook/daemon version skew.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubagentSpawnedInput {
    /// The spawned subagent's own agent_id.
    #[serde(default)]
    pub agent_id: Option<String>,
    /// The spawning session_id.
    #[serde(default)]
    pub session_id: Option<String>,
    /// Subagent type (e.g. "general-purpose"), preserved for audit scoring.
    #[serde(default)]
    pub agent_type: Option<String>,
}

/// Input for `Command::SubagentEdge`. Written by the `Agent`-tool `PostToolUse`
/// hook when one subagent spawns another: records the parent→child spawn edge as
/// a hash-chained enforcement event so the audit can walk the tree past the leaf.
/// `child_agent_id` (the spawned subagent) and `parent_agent_id` (its spawner)
/// are both required in practice; the recorder no-ops when either is absent —
/// a root-session spawn (no parent) is already covered by `SubagentSpawned`. All
/// fields default for hook/daemon version skew.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubagentEdgeInput {
    /// The spawned child subagent's own agent_id (`tool_response.agentId`).
    #[serde(default)]
    pub child_agent_id: Option<String>,
    /// The spawning parent subagent's agent_id (top-level `agent_id`).
    #[serde(default)]
    pub parent_agent_id: Option<String>,
    /// The shared session_id.
    #[serde(default)]
    pub session_id: Option<String>,
    /// Child subagent type (e.g. "general-purpose"), preserved for audit scoring.
    #[serde(default)]
    pub agent_type: Option<String>,
}

/// Input for `Command::RecordImport`. Records are written verbatim into the
/// knowledge tree, preserving every field. The daemon validates each record's
/// key prefix against the knowledge-namespace allowlist before writing.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordImportInput {
    pub records: Vec<crate::store::Record>,
}

/// Input for `Command::ConfigGet`. `key` is the dotted config name
/// (e.g. `audit.write_durability`, `enforcement.retention`).
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigGetInput {
    pub key: String,
}

/// Input for `Command::ConfigSet`. Values are always sent as strings on the
/// wire and parsed/validated by the dispatcher.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigSetInput {
    pub key: String,
    pub value: String,
}

/// Input for `Command::SandboxAudit`. The dispatcher records an
/// `EnforcementConfigChanged` event verbatim from these fields.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxAuditInput {
    pub setting: String,
    /// Value mati expected before the observed configuration change. Older
    /// clients may omit this because sandbox audits historically had no
    /// before-value; the guard supplies it for ConfigChange events.
    #[serde(default)]
    pub old_value: String,
    pub new_value: String,
    pub reason: String,
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
