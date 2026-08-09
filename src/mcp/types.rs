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
    /// Prototype mode for Claude's `mcp_tool` hook: return hook JSON instead
    /// of the record body. Normal callers leave this false.
    #[serde(default)]
    pub decision: bool,
}

/// Parameters for the `mem_query` tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct MemQueryParams {
    /// Search query string. For text mode: matched against record keys, values, and tags.
    /// For tag mode: matched against record tags (substring, case-insensitive).
    /// For graph mode: must be a full namespaced record key (e.g. "file:src/main.rs" or "gotcha:my-rule").
    /// For dir_gotchas mode: a repo-relative directory or file path (e.g. "src/store");
    /// an empty query returns nothing.
    /// For policy_observations / policy_activity: a policy slug (empty = all policies).
    /// For analytics: a key substring naming the aggregate (e.g. "miss_"); required —
    /// an empty query returns nothing (it will not dump every analytics record).
    pub query: String,
    /// Search mode. Knowledge search: "text" (default, BM25 full-text),
    /// "tag" (filter by tag), "graph" (1-hop traversal from an exact seed key),
    /// "dir_gotchas" (confirmed gotchas whose affected_files sit under a
    /// directory path, ranked by confidence then quality).
    /// Enforcement telemetry (read-only, local): "policy_observations" (shadow
    /// observations), "policy_activity" (activity report, honors `since`),
    /// "analytics" (raw analytics:* records).
    #[serde(default = "default_mode")]
    pub mode: String,
    /// Maximum number of results to return (default: 20, clamped to 50 — a
    /// larger value silently returns 50, it is not an error). Bounds the
    /// "analytics" result set; "policy_observations" and "policy_activity"
    /// return the full aggregate regardless.
    #[serde(default = "default_limit")]
    pub limit: usize,
    /// Look-back window in days for the "policy_activity" mode (default: 30).
    /// 0 is treated as unset (uses the default); values above the 365-day
    /// retention horizon are capped. Ignored by other modes.
    #[serde(default)]
    pub since: Option<u64>,
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
        gotcha:stripe-idempotency-key-required | \
        decision:unified-retry-strategy | \
        dev_note:deployment-checklist | \
        policy:<slug>. \
        file:* keys are read-only via mem_get — mem_set write rejects them \
        (file records are owned by the static-analysis pipeline, not agents).")]
    pub key: String,

    #[schemars(description = "\
        Human-readable text (tantivy-indexed). \
        Gotcha: '{rule} because {reason}'. \
        Decision: 'We use X because Y'. \
        DevNote: freeform observation. \
        Not required for confirm or delete actions.")]
    #[serde(default)]
    pub value: String,

    #[schemars(description = "\
        Ignored. Record routing is determined entirely by the key prefix \
        (gotcha:/decision:/dev_note:/policy:) — this field has no effect on \
        the write and is accepted only for backward compatibility.")]
    #[serde(default)]
    pub category: String,

    #[schemars(description = "\
        Structured payload as a JSON object. \
        Gotcha: {rule:string, reason:string, severity:Critical|High|Normal|Low, \
                affected_files:[string], ref_url:null, discovered_session:0, confirmed:false}. \
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

#[cfg(test)]
mod tests {
    use super::{MemGetParams, MemSetParams};

    /// `decision` carries `#[serde(default)]` so every existing `mem_get`
    /// caller — which never sends it — keeps deserializing. Losing that
    /// attribute would break every caller at once; pin it.
    #[test]
    fn mem_get_params_decision_defaults_false_when_absent() {
        let params: MemGetParams = serde_json::from_str(r#"{"key":"file:src/main.rs"}"#).unwrap();
        assert_eq!(params.key, "file:src/main.rs");
        assert!(!params.decision);
    }

    #[test]
    fn mem_get_params_decision_true_when_present() {
        let params: MemGetParams =
            serde_json::from_str(r#"{"key":"file:src/main.rs","decision":true}"#).unwrap();
        assert!(params.decision);
    }

    /// Regression: the `mem_set` tool schema previously advertised `file:*`
    /// as a writable key pattern and `File` as a valid category, with a full
    /// `FileRecord` payload shape documented — none of which
    /// `build_mem_set_command` (src/mcp/tools/mem_set_command.rs) has ever accepted; every
    /// `file:` write is rejected. The schema must not promise what the
    /// implementation refuses.
    #[test]
    fn mem_set_schema_does_not_advertise_file_writes() {
        let schema = schemars::schema_for!(MemSetParams);
        let value = serde_json::to_value(&schema).expect("schema serializes");
        let properties = value
            .get("properties")
            .expect("schema has a properties object");

        let key_desc = properties["key"]["description"]
            .as_str()
            .expect("key has a description");
        assert!(
            !key_desc.contains("file:src"),
            "key description should not offer a file: write example, got: {key_desc}"
        );

        let value_desc = properties["value"]["description"]
            .as_str()
            .expect("value has a description");
        assert!(
            !value_desc.contains("File:"),
            "value description should not document a File case, got: {value_desc}"
        );

        let category_desc = properties["category"]["description"]
            .as_str()
            .expect("category has a description");
        assert!(
            !category_desc.contains("File"),
            "category description should not list File as valid, got: {category_desc}"
        );

        let payload_desc = properties["payload"]["description"]
            .as_str()
            .expect("payload has a description");
        assert!(
            !payload_desc.contains("File:"),
            "payload description should not document a File shape, got: {payload_desc}"
        );
    }
}
