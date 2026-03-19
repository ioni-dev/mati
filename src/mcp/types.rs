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
    pub mode: Option<String>,
    /// Maximum number of results to return (default: 20).
    #[serde(default)]
    pub limit: Option<usize>,
}

fn default_mode() -> Option<String> {
    None
}

/// Parameters for the `mem_bootstrap` tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct MemBootstrapParams {
    /// File paths currently open or relevant to the task. Used to resolve
    /// graph-connected gotchas and decisions.
    #[serde(default)]
    pub context_files: Option<Vec<String>>,
}
