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
use rmcp::tool_router;
use serde_json::json;

use crate::graph::edges::EdgeKind;
use crate::graph::Graph;
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
pub(crate) use context_packet::record_to_agent_json;

#[cfg(test)]
use context_packet::{estimate_tokens, TOKEN_BUDGET};
use mem_set_command::build_mem_set_command;

/// The MCP server struct. After γ-C4, `mati serve` is always a thin
/// MCP-stdio ↔ UDS proxy that forwards every tool call to a separate
/// daemon process (spawned by `mati daemon start` or auto-spawned via
/// `daemon_lifecycle::ensure_daemon`). The daemon owns the store; this
/// struct only carries the path to the daemon root so we know where to
/// open the Unix socket.
#[derive(Clone)]
pub struct MatiServer {
    root: PathBuf,
    pub(crate) tool_router: ToolRouter<Self>,
}

impl MatiServer {
    /// Construct a socket-backed proxy rooted at `~/.mati/<slug>/`.
    pub fn with_socket_root(root: PathBuf) -> Self {
        Self {
            root,
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
}

#[tool_router]
impl MatiServer {
    /// Retrieve a single record by its namespaced key.
    ///
    /// Returns the JSON-serialised record, or "null" if not found.
    ///
    /// Note: `read_only_hint = true` is set because mem_get does not modify
    /// knowledge content. However, it does write consultation receipts
    /// (session:consulted:*) synchronously — these are critical for hook
    /// enforcement (deny → mem_get → allow cycle) — and defers access_count
    /// and analytics writes to a background task.
    #[rmcp::tool(
        name = "mem_get",
        description = "Look up one mati knowledge record by key. Before reading a file directly, call this with \"file:<path>\" and use the record instead when it is confirmed and high-confidence.",
        annotations(read_only_hint = true)
    )]
    pub(crate) async fn mem_get(
        &self,
        Parameters(params): Parameters<MemGetParams>,
    ) -> Result<String, String> {
        self.socket_call("mem_get", json!({ "key": params.key }))
            .await
    }

    /// Search the knowledge store using BM25 text search or graph traversal.
    ///
    /// Modes: "text" (default) for full-text BM25, "graph" for 1-hop traversal.
    /// Text mode returns a JSON array. Graph mode returns a grouped JSON object.
    #[rmcp::tool(
        name = "mem_query",
        description = "Search the mati knowledge store, or read local enforcement telemetry. Knowledge modes: \"text\" (BM25 full-text), \"tag\" (filter by tag), \"graph\" (1-hop traversal from a seed key), \"dir_gotchas\" (confirmed gotchas whose affected_files sit under a directory path). Telemetry modes (read-only): \"policy_observations\", \"policy_activity\" (optional `since` in days), \"analytics\". `limit` is clamped to 50 in every mode; a larger value returns 50 results, not an error.",
        annotations(read_only_hint = true)
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
    #[rmcp::tool(
        name = "mem_bootstrap",
        description = "Assemble a compact context packet for the current coding session from relevant gotchas, file records, and decisions. Call this at session start.",
        annotations(read_only_hint = true)
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
            idempotent_hint = false
        )
    )]
    pub(crate) async fn mem_set(
        &self,
        Parameters(params): Parameters<MemSetParams>,
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
