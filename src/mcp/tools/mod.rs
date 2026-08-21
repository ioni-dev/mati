//! MCP tool implementations (M-07, M-11).
//!
//! Public MCP surface:
//! - `mem_get`       — direct key lookup
//! - `mem_query`     — BM25 text search or graph traversal
//! - `mem_bootstrap` — session context assembly within a token budget
//! - `mem_set`       — knowledge record writes

use std::collections::HashSet;
use std::path::PathBuf;

use rmcp::handler::server::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::service::{ElicitationError, ElicitationMode};
use rmcp::{tool_router, Peer, RoleServer};
use serde_json::json;

use crate::graph::edges::EdgeKind;
use crate::graph::Graph;
use crate::hooks::decide::{self, Decision, EnforcementInput};
use crate::store::record::{
    Category, ContextPacket, FileRecord, GotchaRecord, Priority, QualityTier, Record,
    RecordLifecycle, StaleReviewPayload, StalenessTier,
};

use super::protocol::{
    self as proto, Command, DecisionUpsertInput, DevNoteUpsertInput, GotchaConfirmInput,
    GotchaDraftInput, GotchaTombstoneInput,
};
use super::server::{proxy_daemon_result, proxy_daemon_v2, ProxyDaemonResult};
use super::types::{MemBootstrapParams, MemGetParams, MemQueryParams, MemSetParams};

mod context_packet;
mod mem_set_command;

#[cfg(test)]
mod tests;

pub use context_packet::assemble_context_packet;
#[cfg(test)]
pub(crate) use context_packet::is_injectable_gotcha;
pub(crate) use context_packet::record_to_agent_json;

#[cfg(test)]
use context_packet::{estimate_tokens, TOKEN_BUDGET};
use mem_set_command::build_mem_set_command;

/// Developer's in-session answer to a gotcha-confirm elicitation. The MCP
/// client renders `confirm` as an accept/decline control; the accept action
/// alone is not enough — the developer must set `confirm=true` to vouch for
/// the rule (P4). Any other outcome leaves the gotcha an unconfirmed draft.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct GotchaConfirmDecision {
    /// Set true to confirm this gotcha and activate hook enforcement.
    confirm: bool,
}
rmcp::elicit_safe!(GotchaConfirmDecision);

/// Whether a gotcha-confirm elicitation resulted in a confirm or a rejection.
#[derive(Debug)]
enum ConfirmOutcome {
    Confirm,
    Rejected(String),
}

/// Result of looking up a gotcha before confirming it.
#[derive(Debug)]
enum GotchaLookup {
    Missing,
    Present { rule: Option<String> },
}

/// Map an elicitation outcome to a confirm-or-reject decision. Only an explicit
/// `confirm=true` accept confirms; decline, cancel, empty content, and any
/// transport/parse failure all reject (fail closed, P4). Pure so the branch that
/// guards enforcement activation is testable without a live client peer.
fn classify_confirm_elicitation(
    key: &str,
    outcome: Result<Option<GotchaConfirmDecision>, ElicitationError>,
) -> ConfirmOutcome {
    match outcome {
        Ok(Some(decision)) if decision.confirm => ConfirmOutcome::Confirm,
        Ok(Some(_))
        | Ok(None)
        | Err(ElicitationError::UserDeclined)
        | Err(ElicitationError::UserCancelled) => ConfirmOutcome::Rejected(format!(
            "confirmation declined; `{key}` stays an unconfirmed draft"
        )),
        Err(err) => ConfirmOutcome::Rejected(format!(
            "confirmation failed: {err}; `{key}` stays an unconfirmed draft"
        )),
    }
}

/// The MCP server struct. After γ-C4, `mati serve` is always a thin
/// MCP-stdio ↔ UDS proxy that forwards every tool call to a separate
/// daemon process (spawned by `mati daemon start` or auto-spawned via
/// `daemon_lifecycle::ensure_daemon`). The daemon owns the store; this
/// struct only carries the path to the daemon root so we know where to
/// open the Unix socket.
#[derive(Clone)]
pub struct MatiServer {
    root: PathBuf,
    /// This process's worktree scope, computed once from `mati serve`'s own
    /// launch cwd (see `worktree_scope_tag`). `None` outside a git repo.
    worktree_tag: Option<String>,
    pub(crate) tool_router: ToolRouter<Self>,
}

impl MatiServer {
    /// Construct a socket-backed proxy rooted at `~/.mati/<slug>/`.
    pub fn with_socket_root(root: PathBuf, worktree_tag: Option<String>) -> Self {
        Self {
            root,
            worktree_tag,
            tool_router: Self::tool_router(),
        }
    }

    fn socket_error(op: &str, result: ProxyDaemonResult) -> String {
        let message = match result {
            ProxyDaemonResult::NotRunning => format!("{op}: daemon not running"),
            ProxyDaemonResult::StaleSocket => format!("{op}: daemon socket stale"),
            ProxyDaemonResult::Unresponsive => format!("{op}: daemon unresponsive"),
            ProxyDaemonResult::Ok(v) => format!("{op}: malformed daemon response: {v}"),
        };
        json!({ "error": message }).to_string()
    }

    async fn socket_call(&self, op: &str, args: serde_json::Value) -> Result<String, String> {
        match proxy_daemon_result(&self.root, op, args).await {
            ProxyDaemonResult::Ok(v) => Self::format_envelope(op, v),
            other => Err(Self::socket_error(op, other)),
        }
    }

    /// Send a typed v2 [`Command`] over the daemon socket and format the
    /// response the same way [`Self::socket_call`] does.
    ///
    /// Use this for mutating commands (gotcha_upsert/confirm/tombstone,
    /// decision_upsert, dev_note_upsert) which have no entry in the legacy
    /// v1→v2 mapper and would panic the rmcp task if routed through
    /// [`Self::socket_call`].
    async fn socket_call_typed(&self, cmd: Command) -> Result<String, String> {
        let op = cmd.kind();
        match proxy_daemon_v2(&self.root, cmd).await {
            ProxyDaemonResult::Ok(v) => Self::format_envelope(op, v),
            other => Err(Self::socket_error(op, other)),
        }
    }

    /// Gate a gotcha confirmation behind an in-session developer accept.
    ///
    /// The confirm reaches the daemon only if the developer sets `confirm=true`
    /// in the elicitation form. A decline, a cancel, an empty response, or any
    /// transport/parse failure leaves the gotcha an unconfirmed draft — the gate
    /// fails closed. A client that cannot elicit is told to run the CLI instead,
    /// so confirmation is never silently granted without a human (P4).
    async fn confirm_gotcha_via_elicitation(
        &self,
        key: &str,
        peer: Peer<RoleServer>,
    ) -> Result<String, String> {
        // Don't ask the developer to vouch for a gotcha that isn't there:
        // reject a missing key before prompting, same as the daemon would.
        let rule = match self.gotcha_lookup(key).await {
            GotchaLookup::Missing => {
                return Err(json!({ "error": format!("gotcha `{key}` not found") }).to_string());
            }
            GotchaLookup::Present { rule } => rule,
        };

        if !peer
            .supported_elicitation_modes()
            .contains(&ElicitationMode::Form)
        {
            return Err(json!({
                "error": format!(
                    "this MCP client cannot prompt for confirmation in-session; run `mati gotcha confirm {key}` to confirm"
                )
            })
            .to_string());
        }

        let message = match rule {
            Some(rule) => {
                format!("Confirm gotcha `{key}` and activate hook enforcement?\n\nRule: {rule}")
            }
            None => format!("Confirm gotcha `{key}` and activate hook enforcement?"),
        };

        match classify_confirm_elicitation(key, peer.elicit::<GotchaConfirmDecision>(message).await)
        {
            ConfirmOutcome::Confirm => {
                self.socket_call_typed(Command::GotchaConfirm(GotchaConfirmInput {
                    key: key.to_string(),
                }))
                .await
            }
            ConfirmOutcome::Rejected(error) => Err(json!({ "error": error }).to_string()),
        }
    }

    /// Look up a gotcha for the confirm gate: whether it exists and, if so, its
    /// rule text for the prompt. A lookup or parse failure counts as `Missing` —
    /// the gate then rejects rather than prompting for a record it can't read.
    async fn gotcha_lookup(&self, key: &str) -> GotchaLookup {
        let Ok(raw) = self.socket_call("get", json!({ "key": key })).await else {
            return GotchaLookup::Missing;
        };
        if raw == "null" {
            return GotchaLookup::Missing;
        }
        match serde_json::from_str::<crate::store::Record>(&raw) {
            Ok(record) => GotchaLookup::Present {
                rule: record
                    .payload_as::<GotchaRecord>()
                    .map(|gotcha| gotcha.rule)
                    .filter(|rule| !rule.is_empty()),
            },
            Err(_) => GotchaLookup::Missing,
        }
    }

    /// Render a daemon envelope `{ok,data}` / `{ok:false,error}`. `Err`
    /// propagates to the rmcp tool result as `isError: true`; `Ok` carries
    /// the plain data string, unmodified from today's behaviour.
    fn format_envelope(op: &str, v: serde_json::Value) -> Result<String, String> {
        if v.get("ok") != Some(&serde_json::Value::Bool(true)) {
            let err = v
                .get("error")
                .and_then(|e| e.as_str())
                .unwrap_or("daemon request failed");
            // Surface the structured error code if present so callers can
            // distinguish validation failures from store errors.
            let code = v.get("code").and_then(|c| c.as_str()).unwrap_or("");
            if code.is_empty() {
                return Err(json!({ "error": err, "op": op }).to_string());
            }
            return Err(json!({ "error": err, "op": op, "code": code }).to_string());
        }
        Ok(match v.get("data") {
            Some(serde_json::Value::String(s)) => s.clone(),
            Some(other) => other.to_string(),
            None => return Err(json!({ "error": "daemon response missing data" }).to_string()),
        })
    }

    /// Actor scope for a `decision:true` hook_evaluate call, matching the
    /// shell hook's `receipt_actor(worktree, agent_id)` (src/cli/hook_decide/
    /// flows.rs) exactly. `${agent_id}` interpolates to `""` on the main
    /// thread (verified live), never absent, so an empty string is treated
    /// the same as no agent — not as a literal empty-string actor.
    fn decision_actor(&self, agent_id: Option<&str>) -> Option<String> {
        let agent_id = agent_id.filter(|s| !s.is_empty());
        crate::store::session::combined_actor_scope(self.worktree_tag.as_deref(), agent_id)
    }

    fn hook_allow() -> String {
        json!({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "allow"
            }
        })
        .to_string()
    }

    fn hook_decision_body(eval: serde_json::Value) -> String {
        let file_key = eval
            .get("file_key")
            .and_then(|v| v.as_str())
            .unwrap_or("file:unknown");
        let rel_path = file_key.strip_prefix("file:").unwrap_or(file_key);
        let gotcha_records = eval
            .get("gotcha_records")
            .and_then(|v| v.as_object())
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .collect();
        let input = EnforcementInput {
            rel_path: rel_path.to_string(),
            file_record: eval.get("file_record").filter(|v| !v.is_null()).cloned(),
            gotcha_records,
            already_consulted: eval
                .get("consulted")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            file_exists: None,
        };
        let reason = match decide::evaluate(&input).decision {
            Decision::Deny { reason, .. } => Some(reason),
            _ => None,
        };
        match reason {
            Some(reason) => json!({
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": reason
                }
            })
            .to_string(),
            None => Self::hook_allow(),
        }
    }
}

#[tool_router]
impl MatiServer {
    /// Retrieve a single record by its namespaced key.
    ///
    /// Returns the JSON-serialised record, or "null" if not found.
    ///
    /// Not read-only: every call mints a `session:consulted:*` receipt
    /// synchronously, and a later hook reads that receipt to allow an edit it
    /// would otherwise deny. A client that prefetched this tool because it
    /// looked read-only would unlock the edit gate on every file it touched.
    /// `destructive_hint` must be stated, not omitted — an omitted
    /// `destructiveHint` defaults to true, and these writes only append.
    #[rmcp::tool(
        name = "mem_get",
        description = "Look up one mati knowledge record by key. Before reading a file directly, call this with \"file:<path>\" and use the record instead when it is confirmed and high-confidence.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = false,
            open_world_hint = false
        )
    )]
    pub(crate) async fn mem_get(
        &self,
        Parameters(params): Parameters<MemGetParams>,
    ) -> Result<String, String> {
        if params.decision {
            let actor = self.decision_actor(params.agent_id.as_deref());
            let eval = self
                .socket_call(
                    "hook_evaluate",
                    json!({
                        "file_key": params.key,
                        "include_recent": false,
                        "actor": actor,
                    }),
                )
                .await;
            return Ok(
                match eval.and_then(|body| serde_json::from_str(&body).map_err(|e| e.to_string())) {
                    Ok(data) => Self::hook_decision_body(data),
                    Err(_) => Self::hook_allow(),
                },
            );
        }
        self.socket_call(
            "mem_get",
            json!({ "key": params.key, "actor": self.worktree_tag }),
        )
        .await
    }

    /// Search the knowledge store using BM25 text search or graph traversal.
    ///
    /// Modes: "text" (default) for full-text BM25, "graph" for 1-hop traversal.
    /// Text mode returns a JSON array. Graph mode returns a grouped JSON object.
    ///
    /// The only tool here that writes nothing at all. `destructive_hint` and
    /// `idempotent_hint` are deliberately unset — the spec says both are
    /// meaningful only when `read_only_hint` is false.
    #[rmcp::tool(
        name = "mem_query",
        description = "Search the mati knowledge store, or read local enforcement telemetry. Knowledge modes: \"text\" (BM25 full-text), \"tag\" (filter by tag), \"graph\" (1-hop traversal from a seed key), \"dir_gotchas\" (confirmed gotchas whose affected_files sit under a directory path). Telemetry modes (read-only): \"policy_observations\", \"policy_activity\" (optional `since` in days), \"analytics\". `limit` is clamped to 50 in every mode; a larger value returns 50 results, not an error.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    pub(crate) async fn mem_query(
        &self,
        Parameters(params): Parameters<MemQueryParams>,
    ) -> Result<String, String> {
        self.socket_call(
            "mem_query",
            json!({ "query": params.query, "mode": params.mode, "limit": params.limit, "since": params.since }),
        )
        .await
    }

    /// Assemble a context packet for the current session.
    ///
    /// Gathers stage, gotchas, file records, and decisions within a 2,000-token budget.
    /// Returns a markdown injection string for Claude.
    ///
    /// Not read-only: each call writes an audit record and a daily aggregate,
    /// and bumps `last_accessed` on every context file. `last_accessed` feeds
    /// `staleness::time_factor`, so the next SessionEnd sweep scores those
    /// records fresher — and the staleness tier gates injection. It never mints
    /// a consultation receipt; see `handle_mem_bootstrap` for why.
    #[rmcp::tool(
        name = "mem_bootstrap",
        description = "Assemble a compact context packet for the current coding session from relevant gotchas, file records, and decisions. Call this at session start.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = false,
            open_world_hint = false
        )
    )]
    pub(crate) async fn mem_bootstrap(
        &self,
        Parameters(params): Parameters<MemBootstrapParams>,
    ) -> Result<String, String> {
        self.socket_call(
            "mem_bootstrap",
            json!({ "context_files": params.context_files }),
        )
        .await
    }

    /// Write an enriched knowledge record to the mati store.
    ///
    /// Used during `/mati-enrich` sessions. Source is always `ClaudeEnrich`.
    /// Gotcha records land with `confirmed=false` — developer runs `mati review`
    /// to confirm and activate hook enforcement.
    #[rmcp::tool(
        name = "mem_set",
        description = "Write, confirm, or delete a knowledge record. Actions: \"write\" (default) creates/updates a record, \"confirm\" activates a gotcha for hook enforcement, \"delete\" tombstones a gotcha.",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = false
        )
    )]
    pub(crate) async fn mem_set(
        &self,
        Parameters(params): Parameters<MemSetParams>,
        peer: Peer<RoleServer>,
    ) -> Result<String, String> {
        if params.key.starts_with("policy:") {
            let slug = params.key.strip_prefix("policy:").unwrap_or(&params.key);
            if params.action == "confirm" {
                return Err(json!({"error": format!("policies are activated with `mati policy enable {slug}`")}).to_string());
            }
            let existing_lookup = self.socket_call("get", json!({"key": params.key})).await?;
            let existing = match existing_lookup.as_str() {
                "null" => None,
                value => match serde_json::from_str::<crate::store::Record>(value) {
                    Ok(record) => Some(record),
                    Err(_) => return Ok(value.to_string()),
                },
            };
            if params.action == "delete" {
                if existing
                    .as_ref()
                    .and_then(|record| record.payload_as::<crate::store::PolicyRecord>())
                    .map(|policy| policy.stage)
                    .is_some_and(|stage| !matches!(stage, crate::store::PolicyStage::Off))
                {
                    let stage = existing
                        .as_ref()
                        .and_then(|record| record.payload_as::<crate::store::PolicyRecord>())
                        .map(|policy| format!("{:?}", policy.stage).to_ascii_lowercase())
                        .unwrap_or_else(|| "non-off".into());
                    return Err(json!({"error": format!("policy {} is {stage}; an agent cannot delete developer-controlled policies. Run `mati policy stage {slug} off` to hand it back to the agent.", params.key)}).to_string());
                }
                return self
                    .socket_call_typed(Command::PolicyWrite(
                        crate::mcp::protocol::PolicyWriteInput {
                            op: crate::mcp::protocol::PolicyWriteOp::Delete,
                            key: params.key.clone(),
                            policy: None,
                            stage: None,
                        },
                    ))
                    .await;
            }
            if matches!(params.action.as_str(), "write" | "") {
                if existing
                    .as_ref()
                    .and_then(|record| record.payload_as::<crate::store::PolicyRecord>())
                    .map(|policy| policy.stage)
                    .is_some_and(|stage| !matches!(stage, crate::store::PolicyStage::Off))
                {
                    let stage = existing
                        .as_ref()
                        .and_then(|record| record.payload_as::<crate::store::PolicyRecord>())
                        .map(|policy| format!("{:?}", policy.stage).to_ascii_lowercase())
                        .unwrap_or_else(|| "non-off".into());
                    return Err(json!({"error": format!("policy {} is {stage}; an agent cannot edit developer-controlled policies. Run `mati policy stage {slug} off` to hand it back to the agent.", params.key)}).to_string());
                }
                let payload = match &params.payload {
                    serde_json::Value::String(value) => {
                        serde_json::from_str(value).unwrap_or_else(|_| params.payload.clone())
                    }
                    value => value.clone(),
                };
                let mut policy: crate::store::PolicyRecord = match serde_json::from_value(payload) {
                    Ok(policy) => policy,
                    Err(error) => return Err(json!({"error": format!("policy payload must deserialize into PolicyRecord: {error}")}).to_string()),
                };
                // Agents may create or edit only off policies. Shadow and
                // enforce are developer-controlled and agent-immutable.
                if !matches!(policy.stage, crate::store::PolicyStage::Off) {
                    policy.stage = crate::store::PolicyStage::Off;
                }
                return self
                    .socket_call_typed(Command::PolicyWrite(
                        crate::mcp::protocol::PolicyWriteInput {
                            op: if existing.is_some() {
                                crate::mcp::protocol::PolicyWriteOp::Edit
                            } else {
                                crate::mcp::protocol::PolicyWriteOp::Create
                            },
                            key: params.key.clone(),
                            policy: Some(policy),
                            stage: None,
                        },
                    ))
                    .await;
            }
        }
        // Confirming a gotcha activates hook enforcement, so it must reflect
        // developer intent, not the agent's (P4). The confirm handler stamps
        // actor "developer" unconditionally, so the human gate lives here:
        // elicit an in-session accept/decline before dispatching the confirm.
        if params.action == "confirm" && params.key.starts_with("gotcha:") {
            return self.confirm_gotcha_via_elicitation(&params.key, peer).await;
        }

        // Route mem_set through typed Commands via proxy_daemon_v2. The
        // legacy v1 mapper has no arms for gotcha_upsert / gotcha_confirm /
        // gotcha_tombstone / decision_upsert / dev_note_upsert / the bogus
        // literal "mem_set" — every prior call panicked the rmcp task and
        // surfaced as `Transport closed` to the client.
        match build_mem_set_command(&params) {
            Ok(cmd) => self.socket_call_typed(cmd).await,
            Err(error) => Err(json!({ "error": error }).to_string()),
        }
    }
}
