use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::*;
impl Command {
    /// Returns the serde rename string for this command variant.
    /// Used for audit logging and tracing spans.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Ping => "ping",
            Self::Metrics => "metrics",
            Self::Get(_) => "get",
            Self::HookEvaluate(_) => "hook_evaluate",
            Self::PolicyEvaluate(_) => "policy_evaluate",
            Self::ScanPrefix(_) => "scan_prefix",
            Self::ScanKeys(_) => "scan_keys",
            Self::History(_) => "history",
            Self::HistorySince(_) => "history_since",
            Self::SessionCheckConsulted(_) => "session_check_consulted",
            Self::SessionCheckConsultedRecent(_) => "session_check_consulted_recent",
            Self::MemQuery(_) => "mem_query",
            Self::ScanEnforcementEvents(_) => "scan_enforcement_events",
            Self::ScanEnforcementEventsSinceMs(_) => "scan_enforcement_events_since_ms",
            Self::ConfigGet(_) => "config_get",
            Self::ConfigSet(_) => "config_set",
            Self::SandboxAudit(_) => "sandbox_audit",
            Self::MemGet(_) => "mem_get",
            Self::MemBootstrap(_) => "mem_bootstrap",
            Self::GotchaUpsert(_) => "gotcha_upsert",
            Self::GotchaConfirm(_) => "gotcha_confirm",
            Self::GotchaTombstone(_) => "gotcha_tombstone",
            Self::PolicyWrite(_) => "policy_write",
            Self::FileEnrich(_) => "file_enrich",
            Self::FileReparse(_) => "file_reparse",
            Self::FileEditHook(_) => "file_edit_hook",
            Self::DocCapture(_) => "doc_capture",
            Self::DecisionUpsert(_) => "decision_upsert",
            Self::DevNoteUpsert(_) => "dev_note_upsert",
            Self::SessionLog(_) => "session_log",
            Self::ConsultationHit(_) => "consultation_hit",
            Self::PolicyShadowObserve(_) => "policy_shadow_observe",
            Self::SessionFlush => "session_flush",
            Self::SessionHarvest => "session_harvest",
            Self::SessionClearConsults => "session_clear_consults",
            Self::RecordImport(_) => "record_import",
        }
    }

    /// Returns the primary target key for this command, if applicable.
    /// Used for audit trail correlation.
    pub fn target_key(&self) -> &str {
        match self {
            Self::Get(i) => &i.key,
            Self::HookEvaluate(i) => &i.file_key,
            Self::PolicyEvaluate(_) => "",
            Self::ScanPrefix(i) => &i.prefix,
            Self::ScanKeys(i) => &i.prefix,
            Self::History(i) => &i.key,
            Self::HistorySince(i) => &i.key,
            Self::SessionCheckConsulted(i) => &i.key,
            Self::SessionCheckConsultedRecent(i) => &i.key,
            Self::MemQuery(i) => &i.query,
            Self::MemGet(i) => &i.key,
            Self::GotchaUpsert(i) => &i.key,
            Self::GotchaConfirm(i) => &i.key,
            Self::GotchaTombstone(i) => &i.key,
            Self::PolicyWrite(i) => &i.key,
            Self::FileEnrich(i) => &i.path,
            Self::FileReparse(i) => &i.path,
            Self::FileEditHook(i) => &i.path,
            Self::DocCapture(i) => &i.path,
            Self::DecisionUpsert(i) => &i.slug,
            Self::DevNoteUpsert(i) => i.key.as_deref().unwrap_or(""),
            Self::SessionLog(i) => &i.key,
            Self::ConsultationHit(i) => &i.key,
            Self::PolicyShadowObserve(i) => &i.policy_key,
            Self::ConfigGet(i) => &i.key,
            Self::ConfigSet(i) => &i.key,
            Self::SandboxAudit(i) => &i.setting,
            Self::Ping
            | Self::Metrics
            | Self::MemBootstrap(_)
            | Self::ScanEnforcementEvents(_)
            | Self::ScanEnforcementEventsSinceMs(_)
            | Self::SessionFlush
            | Self::SessionHarvest
            | Self::SessionClearConsults
            | Self::RecordImport(_) => "",
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
            | Self::PolicyWrite(_)
            | Self::FileEnrich(_)
            | Self::FileReparse(_)
            | Self::FileEditHook(_)
            | Self::DocCapture(_)
            | Self::DecisionUpsert(_)
            | Self::DevNoteUpsert(_)
            | Self::SessionLog(_)
            | Self::ConsultationHit(_)
            | Self::PolicyShadowObserve(_)
            | Self::ConfigSet(_)
            | Self::SandboxAudit(_)
            | Self::SessionFlush
            | Self::SessionHarvest
            | Self::SessionClearConsults
            | Self::RecordImport(_)
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
        "metrics" => json!({"type": "metrics"}),
        "get" => json!({"type": "get", "key": args["key"]}),
        "hook_evaluate" => json!({
            "type": "hook_evaluate",
            "file_key": args["file_key"],
            "include_recent": args.get("include_recent").and_then(|v| v.as_bool()).unwrap_or(false),
            "actor": args["actor"],
        }),
        "scan_prefix" => json!({"type": "scan_prefix", "prefix": args["prefix"]}),
        "scan_keys" => json!({"type": "scan_keys", "prefix": args["prefix"]}),
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
            "since": args.get("since").and_then(|v| v.as_u64()),
        }),
        "scan_enforcement_events" => json!({
            "type": "scan_enforcement_events",
            "since_seq": args.get("since_seq").and_then(|v| v.as_u64()).unwrap_or(0),
            "until_seq": args.get("until_seq").and_then(|v| v.as_u64()).unwrap_or(u64::MAX),
        }),
        "scan_enforcement_events_since_ms" => json!({
            "type": "scan_enforcement_events_since_ms",
            "since_ms": args.get("since_ms").and_then(|v| v.as_u64()).unwrap_or(0),
            "until_ms": args.get("until_ms").and_then(|v| v.as_u64()).unwrap_or(u64::MAX),
        }),
        // Side-effecting reads — pure read shape on the wire, sessions-tree
        // side effects (consultation receipt, audit) live entirely on the
        // daemon side. Routing these through the typed Command enum is
        // strictly preferable, but the MCP Socket-backend tools.rs paths
        // call into this mapper today; without these arms every mem_get /
        // mem_bootstrap call against a Socket-mode `mati serve` panics the
        // rmcp task and surfaces as `Transport closed` to the client.
        "mem_get" => json!({"type": "mem_get", "key": args["key"]}),
        "mem_bootstrap" => json!({
            "type": "mem_bootstrap",
            "context_files": args.get("context_files").cloned().unwrap_or_else(|| serde_json::json!([])),
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
