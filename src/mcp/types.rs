//! MCP tool parameter types (M-07).
//!
//! Each struct derives `Deserialize` + `JsonSchema` as required by rmcp's
//! `Parameters<T>` extractor. Descriptions flow into the MCP tool schema
//! and are visible to Claude — keep them concise and actionable.

use schemars::JsonSchema;
use serde::Deserialize;

/// Parameters for the `mem_get` tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct MemGetParams {
    /// Namespaced record key (e.g. "file:src/main.rs", "gotcha:inference-async").
    pub key: String,
}

/// Parameters for the `mem_query` tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct MemQueryParams {
    /// Search query string — matched against record keys, values, and tags.
    pub query: String,
    /// Search mode: "text" (default, BM25 full-text) or "graph" (1-hop traversal from query as seed key).
    #[serde(default = "default_mode")]
    pub mode: String,
    /// Maximum number of results to return (default: 20).
    #[serde(default = "default_limit")]
    pub limit: usize,
}

fn default_mode() -> String {
    "text".to_string()
}

fn default_limit() -> usize {
    20
}

/// Parameters for the `mem_bootstrap` tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct MemBootstrapParams {
    /// File paths currently open or relevant to the task. Used to resolve
    /// graph-connected gotchas and decisions.
    #[serde(default)]
    pub context_files: Vec<String>,
}

fn default_payload() -> serde_json::Value {
    serde_json::Value::Object(serde_json::Map::new())
}

fn default_priority() -> String {
    "Normal".to_string()
}

fn default_action() -> String {
    "write".to_string()
}

/// Parameters for the `mem_set` tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct MemSetParams {
    #[schemars(description = "\
        Action to perform: \"write\" (default, create or update a record), \
        \"confirm\" (confirm a gotcha for hook enforcement), \
        \"delete\" (tombstone a gotcha record).")]
    #[serde(default = "default_action")]
    pub action: String,

    #[schemars(description = "\
        Namespaced key. Patterns: \
        file:src/payments/stripe.go | \
        gotcha:stripe-idempotency-key-required | \
        decision:unified-retry-strategy | \
        dev_note:deployment-checklist")]
    pub key: String,

    #[schemars(description = "\
        Human-readable text (tantivy-indexed). \
        Gotcha: '{rule} because {reason}'. \
        File: purpose sentence starting with a verb. \
        Decision: 'We use X because Y'. \
        DevNote: freeform observation. \
        Not required for confirm or delete actions.")]
    #[serde(default)]
    pub value: String,

    #[schemars(description = "\
        Exactly one of: File | Gotcha | Decision | DevNote. \
        Not required for confirm or delete actions.")]
    #[serde(default)]
    pub category: String,

    #[schemars(description = "\
        Structured payload as a JSON object. \
        Gotcha: {rule:string, reason:string, severity:Critical|High|Normal|Low, \
                affected_files:[string], ref_url:null, discovered_session:0, confirmed:false}. \
        File: {path:string, purpose:string, entry_points:[string], imports:[string], \
               gotcha_keys:[string], decision_keys:[string], todos:[], \
               unsafe_count:0, unwrap_count:0, change_frequency:0, \
               last_author:null, is_hotspot:false, content_hash:null, line_count:0}. \
        Decision: {summary:string, rationale:string}. \
        DevNote or confirm/delete: empty object {}.")]
    #[serde(default = "default_payload")]
    pub payload: serde_json::Value,

    #[schemars(description = "Optional list of lowercase tag strings. Empty array is fine.")]
    #[serde(default)]
    pub tags: Vec<String>,

    #[schemars(description = "Exactly one of: Normal | High | Critical | Low. Default: Normal.")]
    #[serde(default = "default_priority")]
    pub priority: String,
}
