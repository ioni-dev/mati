//! MCP tool implementations (M-07, M-11).
//!
//! Public MCP surface:
//! - `mem_get`       — direct key lookup
//! - `mem_query`     — BM25 text search or graph traversal
//! - `mem_bootstrap` — session context assembly within a token budget
//! - `mem_set`       — knowledge record writes

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use rmcp::handler::server::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::tool_router;
use serde_json::json;

use crate::graph::edges::EdgeKind;
use crate::graph::Graph;
use crate::health::quality;
use crate::store::record::{
    Category, ConfidenceScore, ContextPacket, FileRecord, GotchaRecord, Priority, QualityScore,
    QualityTier, Record, RecordLifecycle, RecordSource, RecordVersion, StaleReviewPayload,
    StalenessScore, StalenessTier,
};

use super::server::{proxy_daemon_result, ProxyDaemonResult};
use super::types::{MemBootstrapParams, MemGetParams, MemQueryParams, MemSetParams};

/// Vector B — appended to every mem_bootstrap result (64 tokens, budget 77).
pub(crate) const VECTOR_B: &str =
    "\n\n[mati] Before reading any file: call mem_get(\"file:<path>\").\n\
    confidence>=0.6 + confirmed=true \u{2192} use record, skip file read.\n\
    confidence<0.3 \u{2192} read file, consider mem_set to improve.\n\
    \"add gotcha\" \u{2192} mem_set(Gotcha) then mati gotcha confirm <key>.";

/// Token budget for mem_bootstrap output (ARCHITECTURE.md §6).
const TOKEN_BUDGET: usize = 2_000;

/// Reserved tokens for Vector B suffix.
const VECTOR_B_TOKENS: usize = 77;

/// Estimate token count as text.len() / 4 (consistent with analysis/mod.rs).
fn estimate_tokens(text: &str) -> usize {
    text.len() / 4
}

/// Priority weight for sorting gotchas: confidence × priority_weight.
fn priority_weight(priority: &Priority) -> f32 {
    match priority {
        Priority::Low => 0.25,
        Priority::Normal => 0.50,
        Priority::High => 0.75,
        Priority::Critical => 1.00,
    }
}

/// Strip a Record to its agent-facing shape. Removes internal metadata
/// (device_id, clocks, gap_analysis_score, computed_at, sha, counters)
/// that agents never use. Cuts ~40% of response size.
pub(crate) fn record_to_agent_json(record: &Record) -> serde_json::Value {
    let mut obj = serde_json::Map::new();
    obj.insert("key".into(), serde_json::json!(record.key));
    obj.insert("value".into(), serde_json::json!(record.value));
    obj.insert("category".into(), serde_json::json!(record.category));
    obj.insert("priority".into(), serde_json::json!(record.priority));
    if !record.tags.is_empty() {
        obj.insert("tags".into(), serde_json::json!(record.tags));
    }
    obj.insert(
        "confidence".into(),
        serde_json::json!(record.confidence.value),
    );
    obj.insert(
        "confirmation_count".into(),
        serde_json::json!(record.confidence.confirmation_count),
    );
    obj.insert("quality".into(), serde_json::json!(record.quality.value));
    obj.insert(
        "quality_tier".into(),
        serde_json::json!(record.quality.tier),
    );
    if !record.quality.signals.is_empty() {
        obj.insert(
            "quality_signals".into(),
            serde_json::json!(record.quality.signals),
        );
    }
    obj.insert("source".into(), serde_json::json!(record.source));
    obj.insert(
        "staleness_tier".into(),
        serde_json::json!(record.staleness.tier),
    );
    if let Some(ref url) = record.ref_url {
        obj.insert("ref_url".into(), serde_json::json!(url));
    }
    if let Some(ref payload) = record.payload {
        obj.insert("payload".into(), strip_payload(payload, &record.category));
    }
    serde_json::Value::Object(obj)
}

/// Strip internal-only fields from the payload based on record category.
fn strip_payload(payload: &serde_json::Value, category: &Category) -> serde_json::Value {
    let Some(obj) = payload.as_object() else {
        return payload.clone();
    };

    // Fields to remove per category
    let internal_fields: &[&str] = match category {
        Category::File => &[
            "token_cost_estimate",
            "last_modified_session",
            "content_hash",
        ],
        Category::Gotcha => &["discovered_session"],
        _ => &[],
    };

    if internal_fields.is_empty() {
        return payload.clone();
    }

    let mut stripped = obj.clone();
    for field in internal_fields {
        stripped.remove(*field);
    }

    // Remove empty arrays from file payloads to save space
    if matches!(category, Category::File) {
        stripped.retain(|_, v| !matches!(v, serde_json::Value::Array(a) if a.is_empty()));
    }

    serde_json::Value::Object(stripped)
}

/// The MCP server struct. Holds an `Arc<tokio::sync::RwLock<Graph>>` which
/// owns the Store internally.
#[derive(Clone)]
pub struct MatiServer {
    backend: MatiBackend,
    pub(crate) tool_router: ToolRouter<Self>,
}

#[derive(Clone)]
enum MatiBackend {
    Direct(Arc<tokio::sync::RwLock<Graph>>),
    Socket { root: PathBuf },
}

impl MatiServer {
    pub fn new(graph: Graph) -> Self {
        Self {
            backend: MatiBackend::Direct(Arc::new(tokio::sync::RwLock::new(graph))),
            tool_router: Self::tool_router(),
        }
    }

    /// Construct from an already-wrapped Arc so callers can clone and share it
    /// (e.g. to also start the daemon socket listener in the same process).
    pub fn with_graph_arc(graph: Arc<tokio::sync::RwLock<Graph>>) -> Self {
        Self {
            backend: MatiBackend::Direct(graph),
            tool_router: Self::tool_router(),
        }
    }

    /// Construct a socket-backed proxy for cases where another mati process
    /// already owns the store lock.
    pub fn with_socket_root(root: PathBuf) -> Self {
        Self {
            backend: MatiBackend::Socket { root },
            tool_router: Self::tool_router(),
        }
    }

    /// Expose the inner Arc so the caller can share the graph with other tasks
    /// (e.g. the daemon socket listener spawned alongside `mati serve`).
    pub fn graph_arc(&self) -> Arc<tokio::sync::RwLock<Graph>> {
        match &self.backend {
            MatiBackend::Direct(graph) => Arc::clone(graph),
            MatiBackend::Socket { .. } => {
                panic!("graph_arc is unavailable for a socket-backed MatiServer")
            }
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

    async fn socket_call(&self, op: &str, args: serde_json::Value) -> String {
        let MatiBackend::Socket { root } = &self.backend else {
            unreachable!("socket_call only valid for socket backend");
        };

        match proxy_daemon_result(root, op, args).await {
            ProxyDaemonResult::Ok(v) => {
                if v.get("ok") != Some(&serde_json::Value::Bool(true)) {
                    let err = v
                        .get("error")
                        .and_then(|e| e.as_str())
                        .unwrap_or("daemon request failed");
                    return json!({ "error": err }).to_string();
                }
                match v.get("data") {
                    Some(serde_json::Value::String(s)) => s.clone(),
                    Some(other) => other.to_string(),
                    None => json!({ "error": "daemon response missing data" }).to_string(),
                }
            }
            other => Self::socket_error(op, other),
        }
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
    pub(crate) async fn mem_get(&self, Parameters(params): Parameters<MemGetParams>) -> String {
        match &self.backend {
            MatiBackend::Direct(graph_arc) => {
                let graph = graph_arc.read().await;
                let store = graph.store();
                match store.get(&params.key).await {
                    Ok(Some(mut record)) => {
                        if matches!(record.lifecycle, RecordLifecycle::Tombstoned { .. }) {
                            return "null".to_string();
                        }
                        record.access_count += 1;

                        // Build the response FIRST — must return before the MCP
                        // client's response timeout. Codex closes the stdio pipe
                        // within ~100ms of sending a request if no response arrives.
                        let mut agent_json = record_to_agent_json(&record);

                        // Inject blast radius warning for high-impact files.
                        if record.category == Category::File {
                            if let Some(payload) = &record.payload {
                                if let Some(fr) = serde_json::from_value::<crate::store::record::FileRecord>(payload.clone()).ok() {
                                    if let Some(ref br) = fr.blast_radius {
                                        use crate::analysis::blast_radius::BlastTier;
                                        if matches!(br.tier, BlastTier::High | BlastTier::Critical) {
                                            let warning = format!(
                                                "HIGH IMPACT FILE: {} files directly depend on this. Modify with extra care.",
                                                br.direct
                                            );
                                            if let Some(obj) = agent_json.as_object_mut() {
                                                obj.insert("warnings".into(), json!([warning]));
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        let response = serde_json::to_string_pretty(&agent_json)
                            .unwrap_or_else(|e| {
                                format!("{{\"error\": \"serialization failed: {e}\"}}")
                            });

                        // Write ONLY the consultation receipt synchronously — it is
                        // critical for hook enforcement (deny → mem_get → allow) and
                        // is fast (~1ms, sessions tree, no tantivy index).
                        let consulted_key = format!("session:consulted:{}", params.key);
                        let _ = store
                            .put(
                                &consulted_key,
                                &crate::store::session::session_record(
                                    &consulted_key,
                                    String::new(),
                                ),
                            )
                            .await;

                        // Defer the slow writes (access_count to knowledge tree +
                        // daily hit aggregation) to a background task. These go through
                        // tantivy indexing (~100-300ms) and would cause Codex to close
                        // the stdio pipe before the response is sent if done inline.
                        let key_owned = params.key.clone();
                        let graph_clone = Arc::clone(graph_arc);
                        tokio::task::spawn(async move {
                            let g = graph_clone.read().await;
                            let s = g.store();
                            let _ = s.put(&key_owned, &record).await;
                            let agg_key = crate::store::session::today_key("analytics:hit_");
                            let _ =
                                crate::store::session::upsert_daily_agg(s, &agg_key, &key_owned)
                                    .await;
                        });

                        response
                    }
                    Ok(None) => "null".to_string(),
                    Err(e) => format!("{{\"error\": \"{e}\"}}"),
                }
            }
            MatiBackend::Socket { .. } => {
                self.socket_call("mem_get", json!({ "key": params.key }))
                    .await
            }
        }
    }

    /// Search the knowledge store using BM25 text search or graph traversal.
    ///
    /// Modes: "text" (default) for full-text BM25, "graph" for 1-hop traversal.
    /// Text mode returns a JSON array. Graph mode returns a grouped JSON object.
    #[rmcp::tool(
        name = "mem_query",
        description = "Search the mati knowledge store. Use mode \"text\" for BM25 full-text search, mode \"tag\" to filter by tag, or mode \"graph\" for a 1-hop traversal from a seed key.",
        annotations(read_only_hint = true)
    )]
    pub(crate) async fn mem_query(&self, Parameters(params): Parameters<MemQueryParams>) -> String {
        match &self.backend {
            MatiBackend::Direct(graph_arc) => {
                let mode = params.mode.as_str();
                const MAX_QUERY_LIMIT: usize = 50;
                let limit = params.limit.min(MAX_QUERY_LIMIT);

                match mode {
                    "text" => {
                        let graph = graph_arc.read().await;
                        let store = graph.store();
                        match store.search_scored(&params.query, limit).await {
                    Ok(scored_records) => {
                        let stripped: Vec<serde_json::Value> = scored_records
                            .iter()
                            .filter(|(_, r)| {
                                matches!(r.lifecycle, RecordLifecycle::Active)
                                    && !matches!(r.category, Category::Session | Category::Analytics)
                            })
                            .map(|(score, r)| {
                                let mut obj = record_to_agent_json(r);
                                if let serde_json::Value::Object(ref mut map) = obj {
                                    map.insert(
                                        "relevance".into(),
                                        serde_json::json!((*score * 1000.0).round() / 1000.0),
                                    );
                                }
                                obj
                            })
                            .collect();
                        serde_json::to_string_pretty(&stripped).unwrap_or_else(|e| {
                            format!("{{\"error\": \"serialization failed: {e}\"}}")
                        })
                    }
                    Err(e) => format!("{{\"error\": \"{e}\"}}"),
                }
            }
                    "graph" => {
                        let graph = graph_arc.read().await;
                        let store = graph.store();

                // Per-kind limits ensure gotchas always surface
                const GOTCHA_LIMIT: usize = 10;
                const COCHANGE_LIMIT: usize = 5;
                const IMPORT_LIMIT: usize = 5;
                const DECISION_LIMIT: usize = 3;
                const NOTE_LIMIT: usize = 3;

                let edge_groups: &[(EdgeKind, &str, usize)] = &[
                    (EdgeKind::HasGotcha, "gotchas", GOTCHA_LIMIT),
                    (EdgeKind::CoChanges, "co_changes", COCHANGE_LIMIT),
                    (EdgeKind::Imports, "imports", IMPORT_LIMIT),
                    (EdgeKind::AffectedBy, "decisions", DECISION_LIMIT),
                    (EdgeKind::HasNote, "notes", NOTE_LIMIT),
                ];

                let mut result = serde_json::Map::new();
                result.insert(
                    "seed".to_string(),
                    serde_json::Value::String(params.query.clone()),
                );

                let mut summary_parts = Vec::new();
                let mut remaining = limit;

                for (kind, group_name, group_limit) in edge_groups {
                    let keys = graph.neighbors(&params.query, kind);
                    let mut group_records = Vec::new();

                    for key in keys.iter().take((*group_limit).min(remaining)) {
                        if let Ok(Some(record)) = store.get(key).await {
                            if matches!(record.lifecycle, RecordLifecycle::Active) {
                                let mut entry = serde_json::Map::new();
                                entry.insert(
                                    "key".to_string(),
                                    serde_json::Value::String(record.key.clone()),
                                );
                                entry.insert(
                                    "relationship".to_string(),
                                    serde_json::Value::String(format!("{kind:?}")),
                                );
                                entry.insert(
                                    "value".to_string(),
                                    serde_json::Value::String(record.value.clone()),
                                );
                                entry.insert(
                                    "confidence".to_string(),
                                    serde_json::json!(record.confidence.value),
                                );
                                entry.insert(
                                    "quality".to_string(),
                                    serde_json::json!(record.quality.value),
                                );
                                if let Some(payload) = &record.payload {
                                    if let Some(confirmed) = payload.get("confirmed") {
                                        entry.insert("confirmed".to_string(), confirmed.clone());
                                    }
                                }
                                group_records.push(serde_json::Value::Object(entry));
                            }
                        }
                    }

                    if !group_records.is_empty() {
                        summary_parts.push(format!("{} {}", group_records.len(), group_name));
                    }
                    remaining = remaining.saturating_sub(group_records.len());
                    result.insert(
                        group_name.to_string(),
                        serde_json::Value::Array(group_records),
                    );
                }

                // DependencyAffects — add to decisions group
                if remaining > 0 {
                    let dep_keys = graph.neighbors(&params.query, &EdgeKind::DependencyAffects);
                    let mut dep_added = 0usize;
                    for key in dep_keys.iter().take(DECISION_LIMIT.min(remaining)) {
                        if let Ok(Some(record)) = store.get(key).await {
                            if matches!(record.lifecycle, RecordLifecycle::Active) {
                                let mut entry = serde_json::Map::new();
                                entry.insert(
                                    "key".to_string(),
                                    serde_json::Value::String(record.key.clone()),
                                );
                                entry.insert(
                                    "relationship".to_string(),
                                    serde_json::Value::String("DependencyAffects".to_string()),
                                );
                                entry.insert(
                                    "value".to_string(),
                                    serde_json::Value::String(record.value.clone()),
                                );
                                entry.insert(
                                    "confidence".to_string(),
                                    serde_json::json!(record.confidence.value),
                                );
                                entry.insert(
                                    "quality".to_string(),
                                    serde_json::json!(record.quality.value),
                                );
                                if let Some(decisions) = result.get_mut("decisions") {
                                    if let Some(arr) = decisions.as_array_mut() {
                                        arr.push(serde_json::Value::Object(entry));
                                        dep_added += 1;
                                    }
                                }
                            }
                        }
                    }
                    remaining -= dep_added;
                    let _ = remaining; // suppress unused warning
                }

                let summary = if summary_parts.is_empty() {
                    "No related records found".to_string()
                } else {
                    summary_parts.join(", ")
                };
                result.insert("summary".to_string(), serde_json::Value::String(summary));

                serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|e| format!("{{\"error\": \"serialization failed: {e}\"}}"))
            }
                    "tag" => {
                        let graph = graph_arc.read().await;
                        let store = graph.store();
                        let query_lower = params.query.to_lowercase();
                        let mut matched: Vec<serde_json::Value> = Vec::new();
                        for ns in &["gotcha:", "decision:", "file:", "stage:", "dev_note:", "dep:"] {
                            if let Ok(records) = store.scan_prefix(ns).await {
                                for record in records {
                                    if !matches!(record.lifecycle, RecordLifecycle::Active) {
                                        continue;
                                    }
                                    if record.tags.iter().any(|t| t.to_lowercase().contains(&query_lower)) {
                                        matched.push(record_to_agent_json(&record));
                                        if matched.len() >= limit {
                                            break;
                                        }
                                    }
                                }
                            }
                            if matched.len() >= limit {
                                break;
                            }
                        }
                        serde_json::to_string_pretty(&matched).unwrap_or_else(|e| {
                            format!("{{\"error\": \"serialization failed: {e}\"}}")
                        })
                    }
                    "semantic" => {
                        "{\"error\": \"semantic search requires --features semantic (not enabled)\"}"
                            .to_string()
                    }
                    _ => {
                        format!(
                            "{{\"error\": \"unknown mode: {mode}. Valid modes: text, tag, graph, semantic\"}}"
                        )
                    }
                }
            }
            MatiBackend::Socket { .. } => {
                self.socket_call(
                    "mem_query",
                    json!({ "query": params.query, "mode": params.mode, "limit": params.limit }),
                )
                .await
            }
        }
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
    ) -> String {
        match &self.backend {
            MatiBackend::Direct(graph_arc) => {
                let graph = graph_arc.read().await;
                let store = graph.store();

                let context_files = params.context_files;
                let _ = crate::store::session::log_bootstrap(store, "__bootstrap__").await;
                for file in &context_files {
                    let file_key = if file.starts_with("file:") {
                        file.clone()
                    } else {
                        format!("file:{file}")
                    };
                    let _ = crate::store::session::log_hit(store, &file_key).await;
                }
                match assemble_context_packet(store, &graph, &context_files).await {
                    Ok(packet) => packet.injection_string,
                    Err(e) => format!("[mati] bootstrap error: {e}{VECTOR_B}"),
                }
            }
            MatiBackend::Socket { .. } => {
                self.socket_call(
                    "mem_bootstrap",
                    json!({ "context_files": params.context_files }),
                )
                .await
            }
        }
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
    pub(crate) async fn mem_set(&self, Parameters(params): Parameters<MemSetParams>) -> String {
        match &self.backend {
            MatiBackend::Direct(graph_arc) => {
                // Dispatch on action before the default write path.
                match params.action.as_str() {
                    "confirm" => {
                        return self.mem_set_confirm(graph_arc, &params.key).await;
                    }
                    "delete" => {
                        return self.mem_set_delete(graph_arc, &params.key).await;
                    }
                    "write" | "" => {} // fall through to write path below
                    other => {
                        return serde_json::json!({
                            "error": format!("unknown action: {other}. Valid: write, confirm, delete")
                        })
                        .to_string();
                    }
                }

                let graph = graph_arc.read().await;
                let store = graph.store();
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                // Validate key namespace
                let valid_prefix = ["file:", "gotcha:", "decision:", "dev_note:"]
                    .iter()
                    .any(|p| params.key.starts_with(p));
                if !valid_prefix {
                    return serde_json::json!({
                        "error": "key must start with file:, gotcha:, decision:, or dev_note:"
                    })
                    .to_string();
                }

                // Parse category
                let category = match params.category.as_str() {
                    "File" => Category::File,
                    "Gotcha" => Category::Gotcha,
                    "Decision" => Category::Decision,
                    "DevNote" => Category::DevNote,
                    other => {
                        return serde_json::json!({
                    "error": format!("unknown category: {other}. Valid: File, Gotcha, Decision, DevNote")
                })
                .to_string();
                    }
                };

                // Parse priority
                let priority = match params.priority.as_str() {
                    "Critical" => Priority::Critical,
                    "High" => Priority::High,
                    "Low" => Priority::Low,
                    _ => Priority::Normal,
                };

                // Fetch existing record to preserve Layer 0 structural data
                let existing_record = match resolve_existing_for_write(store.get(&params.key).await)
                {
                    Ok(record) => record,
                    Err(error_json) => return error_json,
                };

                // A tombstoned record must not bleed its prior confirmation state
                // into a resurrection — treat it as an unconfirmed write.
                let is_tombstoned = existing_record
                    .as_ref()
                    .map(|r| matches!(r.lifecycle, RecordLifecycle::Tombstoned { .. }))
                    .unwrap_or(false);

                // ── Semantic validation ──────────────────────────────────
                // Key-category consistency: key prefix must match category.
                // This prevents miscategorized records (e.g., gotcha: key
                // with Category::File) that would corrupt the knowledge store.
                let expected_category = match params.key.split(':').next().unwrap_or("") {
                    "file" => Category::File,
                    "gotcha" => Category::Gotcha,
                    "decision" => Category::Decision,
                    "dev_note" => Category::DevNote,
                    _ => unreachable!("key prefix already validated"),
                };
                if category != expected_category {
                    return serde_json::json!({
                        "error": format!(
                            "key prefix requires category {expected_category:?}, got {category:?}"
                        )
                    })
                    .to_string();
                }

                // Payload structural validation for new records. Updates to
                // existing records use merge semantics (existing fields are
                // preserved), so partial payloads are valid on update.
                let is_new_record = existing_record.is_none() || is_tombstoned;
                if is_new_record {
                    // Normalize for validation (Codex sends JSON-encoded strings).
                    let check_payload = match &params.payload {
                        serde_json::Value::String(s) => {
                            serde_json::from_str::<serde_json::Value>(s)
                                .unwrap_or_else(|_| params.payload.clone())
                        }
                        _ => params.payload.clone(),
                    };
                    let obj = check_payload.as_object();
                    if let Err(msg) = match &category {
                        Category::Gotcha => {
                            let valid = obj.is_some_and(|o| {
                                let rule = o.get("rule").and_then(|v| v.as_str()).unwrap_or("");
                                let reason = o.get("reason").and_then(|v| v.as_str()).unwrap_or("");
                                !rule.is_empty() && !reason.is_empty()
                            });
                            if valid {
                                Ok(())
                            } else {
                                Err("gotcha requires payload with non-empty 'rule' and 'reason'")
                            }
                        }
                        Category::File => {
                            let has_purpose = !params.value.is_empty()
                                || obj
                                    .and_then(|o| o.get("purpose"))
                                    .and_then(|v| v.as_str())
                                    .is_some_and(|s| !s.is_empty());
                            if has_purpose {
                                Ok(())
                            } else {
                                Err("file record requires non-empty value or payload.purpose")
                            }
                        }
                        Category::Decision => {
                            let valid = obj.is_some_and(|o| {
                                let summary =
                                    o.get("summary").and_then(|v| v.as_str()).unwrap_or("");
                                let rationale =
                                    o.get("rationale").and_then(|v| v.as_str()).unwrap_or("");
                                !summary.is_empty() && !rationale.is_empty()
                            });
                            if valid {
                                Ok(())
                            } else {
                                Err("decision requires payload with non-empty 'summary' and 'rationale'")
                            }
                        }
                        Category::DevNote => {
                            if params.value.is_empty() {
                                Err("dev_note requires non-empty value")
                            } else {
                                Ok(())
                            }
                        }
                        _ => Ok(()),
                    } {
                        return serde_json::json!({"error": msg}).to_string();
                    }
                }

                let was_confirmed = existing_record
                    .as_ref()
                    .map(|r| {
                        !is_tombstoned
                            && (r.source == RecordSource::DeveloperManual
                                || r.confidence.value >= 0.80)
                    })
                    .unwrap_or(false);

                // Capture old affected_files before mutation (for file-link sync)
                let old_affected_files: Vec<String> = existing_record
                    .as_ref()
                    .filter(|r| r.key.starts_with("gotcha:"))
                    .and_then(|r| r.payload_as::<GotchaRecord>())
                    .map(|g| g.affected_files)
                    .unwrap_or_default();

                let mut record = match existing_record {
                    Some(existing) => existing,
                    _ => Record {
                        key: params.key.clone(),
                        value: String::new(),
                        category: category.clone(),
                        priority: Priority::Normal,
                        tags: vec![],
                        created_at: now,
                        updated_at: now,
                        ref_url: None,
                        staleness: StalenessScore::fresh(),
                        lifecycle: RecordLifecycle::Active,
                        version: RecordVersion {
                            device_id: uuid::Uuid::new_v4(),
                            logical_clock: 0,
                            wall_clock: now,
                        },
                        quality: QualityScore::layer0_default(),
                        access_count: 0,
                        last_accessed: 0,
                        source: RecordSource::StaticAnalysis,
                        confidence: ConfidenceScore::for_new_record(&RecordSource::StaticAnalysis),
                        gap_analysis_score: 0.0,
                        payload: Some(serde_json::json!({})),
                    },
                };

                // A write to a tombstoned record revives it; reset
                // confirmation counters so the new write starts fresh.
                if is_tombstoned {
                    record.confidence.confirmation_count = 0;
                }
                record.lifecycle = RecordLifecycle::Active;

                // Apply enrichment fields
                record.value = params.value;
                record.category = category;
                record.updated_at = now;
                record.version.logical_clock += 1;
                record.version.wall_clock = now;
                record.priority = priority;

                // Preserve confirmation state: if the existing record was previously confirmed
                // (source=DeveloperManual or confidence>=0.80), keep source/confidence/tags.
                // Otherwise set to ClaudeEnrich defaults.
                if was_confirmed {
                    // Only update tags if the caller explicitly provided non-empty tags.
                    if !params.tags.is_empty() {
                        record.tags = params.tags;
                    }
                } else {
                    record.source = RecordSource::ClaudeEnrich;
                    record.confidence =
                        ConfidenceScore::for_new_record(&RecordSource::ClaudeEnrich);
                    record.tags = params.tags;
                }

                // Merge payload: for existing records, preserve structural fields from
                // Layer 0 (entry_points, imports, etc.) while overlaying enrichment.
                // Some MCP clients (Codex) send the payload as a JSON-encoded string
                // rather than a raw object. Parse it if so.
                let new_payload = match &params.payload {
                    serde_json::Value::String(s) => {
                        serde_json::from_str::<serde_json::Value>(s).unwrap_or(params.payload)
                    }
                    _ => params.payload,
                };
                if new_payload.is_object() && !new_payload.as_object().is_none_or(|o| o.is_empty())
                {
                    if let Some(existing_payload) = &record.payload {
                        // Merge: new values override, existing keys preserved
                        let mut merged = existing_payload.clone();
                        if let (Some(base), Some(overlay)) =
                            (merged.as_object_mut(), new_payload.as_object())
                        {
                            for (k, v) in overlay {
                                // gotcha_keys is a derived index maintained by the
                                // gotcha confirm/tombstone paths. Overwriting it on
                                // file-record re-enrichment silently drops edges that
                                // were added by gotcha confirm. Union-merge instead.
                                if k == "gotcha_keys" {
                                    if let (Some(existing_arr), Some(new_arr)) = (
                                        base.get(k).and_then(|e| e.as_array()).cloned(),
                                        v.as_array(),
                                    ) {
                                        let mut union = existing_arr;
                                        for item in new_arr {
                                            if !union.contains(item) {
                                                union.push(item.clone());
                                            }
                                        }
                                        base.insert(k.clone(), serde_json::Value::Array(union));
                                        continue;
                                    }
                                }
                                base.insert(k.clone(), v.clone());
                            }
                            record.payload = Some(serde_json::Value::Object(base.clone()));
                        } else {
                            record.payload = Some(new_payload);
                        }
                    } else {
                        record.payload = Some(new_payload);
                    }
                }

                // Normalize gotcha payload: severity must be snake_case for GotchaRecord deserialization.
                // Claude sends "Critical"/"High"/"Normal"/"Low" but serde expects "critical"/"high"/etc.
                if record.key.starts_with("gotcha:") {
                    if let Some(ref mut payload) = record.payload {
                        if let Some(obj) = payload.as_object_mut() {
                            if let Some(sev) = obj
                                .get("severity")
                                .and_then(|v| v.as_str())
                                .map(|s| s.to_lowercase())
                            {
                                obj.insert("severity".to_string(), serde_json::Value::String(sev));
                            }
                        }
                    }
                }

                // Recompute quality. Only reset confidence for non-confirmed records —
                // confirmed records keep their DeveloperManual confidence (0.80).
                if !was_confirmed {
                    record.confidence =
                        ConfidenceScore::for_new_record(&RecordSource::ClaudeEnrich);
                }
                record.quality = quality::analyze(&record);

                // Write record
                let tier_label = format!("{:?}", record.quality.tier);
                let record_key = record.key.clone();
                if let Err(e) = store.put(&record.key, &record).await {
                    return serde_json::json!({"error": e.to_string()}).to_string();
                }

                // Extract affected_files for edge creation and file-link sync (gotchas only)
                let affected_files: Vec<String> = if record_key.starts_with("gotcha:") {
                    record
                        .payload
                        .as_ref()
                        .and_then(|p| p.get("affected_files"))
                        .and_then(|v| serde_json::from_value::<Vec<String>>(v.clone()).ok())
                        .unwrap_or_default()
                } else {
                    vec![]
                };

                // Sync file:*.gotcha_keys — the derived index that diff and pre-read hooks use.
                // This was previously skipped, leaving MCP-created gotchas invisible to
                // enforcement surfaces even after confirmation.
                if record_key.starts_with("gotcha:") {
                    if let Err(e) = crate::store::gotcha_ops::sync_gotcha_file_links(
                        store,
                        &record_key,
                        &old_affected_files,
                        &affected_files,
                    )
                    .await
                    {
                        tracing::warn!("mem_set: file link sync failed for {record_key}: {e}");
                        crate::store::repair::mark_dirty(
                            store,
                            &record_key,
                            &format!("mem_set link sync failed: {e}"),
                        )
                        .await;
                    }
                }

                let old_affected_set: HashSet<&str> =
                    old_affected_files.iter().map(String::as_str).collect();
                let new_affected_set: HashSet<&str> =
                    affected_files.iter().map(String::as_str).collect();

                drop(graph); // release read lock before taking write lock

                // Keep the in-memory graph in sync with the persisted edge state.
                // mem_set already updated file links above; here we remove stale
                // HasGotcha edges for moved gotchas and add edges for newly-affected files.
                if record_key.starts_with("gotcha:") {
                    let mut graph = graph_arc.write().await;

                    for file_path in old_affected_set.difference(&new_affected_set) {
                        let file_key = format!("file:{file_path}");
                        if let Err(e) = graph
                            .remove_edge(&file_key, &EdgeKind::HasGotcha, &record_key)
                            .await
                        {
                            tracing::warn!(
                        "mem_set: stale edge removal failed for {file_key} → {record_key}: {e}"
                    );
                            crate::store::repair::mark_dirty(
                                graph.store(),
                                &record_key,
                                &format!("mem_set edge remove failed: {e}"),
                            )
                            .await;
                        }
                    }

                    for file_path in new_affected_set.difference(&old_affected_set) {
                        let file_key = format!("file:{file_path}");
                        if let Err(e) = graph
                            .add_edge(&file_key, EdgeKind::HasGotcha, &record_key)
                            .await
                        {
                            tracing::warn!(
                                "mem_set: edge add failed for {file_key} → {record_key}: {e}"
                            );
                            crate::store::repair::mark_dirty(
                                graph.store(),
                                &record_key,
                                &format!("mem_set edge add failed: {e}"),
                            )
                            .await;
                        }
                    }
                }

                serde_json::json!({
                    "ok": true,
                    "key": record_key,
                    "confidence": record.confidence.value,
                    "quality": record.quality.value,
                    "tier": tier_label,
                })
                .to_string()
            }
            MatiBackend::Socket { .. } => {
                let cmd = match params.action.as_str() {
                    "confirm" => "gotcha_confirm",
                    "delete" => "gotcha_tombstone",
                    _ => "mem_set",
                };
                self.socket_call(
                    cmd,
                    json!({
                        "key": params.key,
                        "value": params.value,
                        "category": params.category,
                        "payload": params.payload,
                        "tags": params.tags,
                        "priority": params.priority,
                    }),
                )
                .await
            }
        }
    }
}

// ── mem_set action helpers ──────────────────────────────────────────────────

impl MatiServer {
    /// Confirm a gotcha record — sets confirmed=true, bumps confidence to 0.80,
    /// syncs file-record gotcha_keys. This is the MCP-native equivalent of
    /// `mati gotcha confirm`, needed because Codex Bash commands cannot access
    /// the daemon socket from the sandbox.
    async fn mem_set_confirm(
        &self,
        graph_arc: &Arc<tokio::sync::RwLock<Graph>>,
        key: &str,
    ) -> String {
        if !key.starts_with("gotcha:") {
            return json!({"error": "confirm action only applies to gotcha: keys"}).to_string();
        }

        // Retry loop: SurrealKV MVCC can return a transient write conflict
        // when the confirm races with the preceding write on the same key.
        // Each attempt acquires and releases the read lock to get a fresh snapshot.
        const MAX_RETRIES: usize = 3;
        let mut last_err: Option<String> = None;

        for attempt in 0..MAX_RETRIES {
            // Scope the read lock so it is dropped before finalize_confirm,
            // which needs a write lock for graph edge updates.
            let result = {
                let graph = graph_arc.read().await;
                let store = graph.store();
                self.try_confirm_once(store, key).await
            };

            match result {
                Ok((rec, files)) => {
                    return self.finalize_confirm(graph_arc, key, &rec, &files).await;
                }
                Err(e) => {
                    let msg = format!("{e}");
                    if msg.contains("write conflict") && attempt + 1 < MAX_RETRIES {
                        tracing::debug!(
                            "confirm {key}: write conflict (attempt {}), retrying",
                            attempt + 1
                        );
                        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                        last_err = Some(msg);
                        continue;
                    }
                    return json!({"error": msg}).to_string();
                }
            }
        }
        json!({"error": format!("store put: {}", last_err.unwrap_or_default())}).to_string()
    }

    /// Single attempt at the confirm get-mutate-put cycle.
    async fn try_confirm_once(
        &self,
        store: &crate::store::Store,
        key: &str,
    ) -> anyhow::Result<(Record, Vec<String>)> {
        let mut record = store
            .get(key)
            .await?
            .ok_or_else(|| anyhow::anyhow!("record not found: {key}"))?;

        if record.category != Category::Gotcha {
            anyhow::bail!("{key} is not a gotcha record");
        }
        if !matches!(record.lifecycle, RecordLifecycle::Active) {
            anyhow::bail!("{key} is tombstoned — cannot confirm a deleted record");
        }

        // Set confirmed + normalize severity
        if let Some(ref mut payload) = record.payload {
            if let Some(obj) = payload.as_object_mut() {
                if let Some(sev) = obj
                    .get("severity")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_lowercase())
                {
                    obj.insert("severity".to_string(), serde_json::Value::String(sev));
                }
                obj.insert("confirmed".to_string(), serde_json::Value::Bool(true));
            }
        }

        record.source = RecordSource::DeveloperManual;
        record.confidence.value = ConfidenceScore::base_for_source(&RecordSource::DeveloperManual);
        record.confidence.confirmation_count += 1;
        record.quality = quality::analyze(&record);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        record.updated_at = now;
        record.version.logical_clock += 1;
        record.version.wall_clock = now;

        let affected_files: Vec<String> = record
            .payload_as::<GotchaRecord>()
            .map(|g| g.affected_files)
            .unwrap_or_default();

        store.put(key, &record).await?;
        Ok((record, affected_files))
    }

    /// Post-put work: sync file links, graph edges, consultation receipt.
    async fn finalize_confirm(
        &self,
        graph_arc: &Arc<tokio::sync::RwLock<Graph>>,
        key: &str,
        record: &Record,
        affected_files: &[String],
    ) -> String {
        // Acquire a fresh read lock for file-link sync.
        let graph = graph_arc.read().await;
        let store = graph.store();

        // Sync file:*.gotcha_keys — best-effort
        for file_path in affected_files {
            let file_key = format!("file:{file_path}");
            if let Ok(Some(mut file_record)) = store.get(&file_key).await {
                let needs_link = file_record
                    .payload
                    .as_ref()
                    .and_then(|p| p.get("gotcha_keys"))
                    .and_then(|v| v.as_array())
                    .map(|arr| !arr.iter().any(|v| v.as_str() == Some(key)))
                    .unwrap_or(true);
                if needs_link {
                    if let Some(ref mut payload) = file_record.payload {
                        if let Some(obj) = payload.as_object_mut() {
                            let arr = obj.entry("gotcha_keys").or_insert(serde_json::json!([]));
                            if let Some(arr) = arr.as_array_mut() {
                                arr.push(serde_json::Value::String(key.to_string()));
                            }
                        }
                    }
                    let _ = store.put(&file_key, &file_record).await;
                }
            }
        }

        // Propagate confirmation_count to linked file records
        crate::store::gotcha_ops::propagate_confirmation_to_files(store, affected_files).await;

        // Mint consultation receipt so hooks know this file was reviewed
        let _ = crate::store::session::log_hit(store, key).await;

        let confidence_value = record.confidence.value;
        let quality_value = record.quality.value;

        // Release the read lock before taking a write lock for graph edge updates.
        drop(graph);

        // Ensure HasGotcha edges exist in the in-memory graph for all affected files.
        // This is idempotent (add_edge is a no-op if the edge already exists) and guards
        // against gotchas that were written via the CLI path, whose graph edges landed in
        // the persistent store but were never loaded into the running graph.
        if !affected_files.is_empty() {
            let mut g = graph_arc.write().await;
            for file_path in affected_files {
                let file_key = format!("file:{file_path}");
                let _ = g.add_edge(&file_key, EdgeKind::HasGotcha, key).await;
            }
        }

        json!({
            "ok": true,
            "key": key,
            "confirmed": true,
            "confidence": confidence_value,
            "quality": quality_value,
        })
        .to_string()
    }

    /// Tombstone a gotcha record — marks it as deleted, removes file-record
    /// links and graph edges. MCP-native equivalent of `mati gotcha delete`.
    async fn mem_set_delete(
        &self,
        graph_arc: &Arc<tokio::sync::RwLock<Graph>>,
        key: &str,
    ) -> String {
        // Phase 1: read lock — validate and tombstone the record.
        let affected_files = {
            let graph = graph_arc.read().await;
            let store = graph.store();

            if !key.starts_with("gotcha:") {
                return json!({"error": "delete action only applies to gotcha: keys"}).to_string();
            }

            let record = match store.get(key).await {
                Ok(Some(r)) => r,
                Ok(None) => {
                    return json!({"error": format!("record not found: {key}")}).to_string()
                }
                Err(e) => return json!({"error": format!("store get: {e}")}).to_string(),
            };

            let affected: Vec<String> = record
                .payload_as::<GotchaRecord>()
                .map(|g| g.affected_files)
                .unwrap_or_default();

            if let Err(e) =
                crate::store::gotcha_ops::apply_gotcha_tombstone(store, key, &affected).await
            {
                return json!({"error": format!("tombstone failed: {e}")}).to_string();
            }

            affected
        }; // read lock dropped here

        // Phase 2: write lock — clean up in-memory graph edges.
        {
            let mut graph = graph_arc.write().await;
            for file_path in &affected_files {
                let file_key = format!("file:{file_path}");
                // remove_edge is idempotent — the persisted edge is already gone
                // from apply_gotcha_tombstone; this cleans up the in-memory cache.
                if let Err(e) = graph
                    .remove_edge(&file_key, &EdgeKind::HasGotcha, key)
                    .await
                {
                    tracing::warn!(
                        "mem_set_delete: in-memory edge cleanup failed for {file_key} → {key}: {e}"
                    );
                }
            }
        }

        json!({"ok": true, "key": key, "tombstoned": true}).to_string()
    }
}

/// Returns true if a gotcha record is eligible for injection into a context packet.
fn is_injectable_gotcha(r: &Record) -> bool {
    if !matches!(r.lifecycle, RecordLifecycle::Active) {
        return false;
    }
    if r.staleness.tier == StalenessTier::Tombstone {
        return false;
    }
    if let Some(gotcha) = r.payload_as::<GotchaRecord>() {
        gotcha.confirmed && r.quality.value >= 0.4
    } else {
        false
    }
}

/// Resolve the existing record for a mem_set write path.
///
/// Returns `Ok(Option<Record>)` on success, or an error JSON string
/// if the store read failed — callers must abort the write.
/// Extracted for testability: the `Err` branch was previously untestable
/// because it required a real store failure.
fn resolve_existing_for_write(
    store_result: anyhow::Result<Option<Record>>,
) -> Result<Option<Record>, String> {
    match store_result {
        Ok(record) => Ok(record),
        Err(e) => Err(serde_json::json!({
            "error": format!("store read failed \u{2014} refusing to write: {e}")
        })
        .to_string()),
    }
}

/// Assemble a [`ContextPacket`] from the store and graph.
///
/// Steps:
/// 1. Fetch `stage:current`
/// 2. Collect confirmed gotchas (deferred until after step 3):
///    - For non-empty `context_files`: fetch only linked gotchas by key
///    - For empty `context_files` (global bootstrap): scan all `gotcha:*`
/// 3. For each context_file: get FileRecord, traverse HasGotcha (1-hop),
///    traverse Imports→HasGotcha (2-hop), traverse AffectedBy for decisions
/// 4. Dedup + sort gotchas by confidence × priority_weight
/// 5. Quality filter: exclude Suppressed, caveat Poor
/// 6. Build markdown injection string within 2,000-token budget
/// 7. Append Vector B suffix
pub async fn assemble_context_packet(
    store: &crate::store::Store,
    graph: &Graph,
    context_files: &[String],
) -> anyhow::Result<ContextPacket> {
    // 1. Stage
    let stage = store.get("stage:current").await?;

    // 2. Gotcha collection — deferred until after context-file traversal
    //    so we can optimize non-empty context_files to fetch only linked gotchas.

    // 3. Context-file traversal
    let mut file_records = Vec::new();
    let mut context_gotcha_keys = HashSet::new();
    let mut decision_keys = HashSet::new();
    // Collect nudge candidates during this pass to avoid N+1 re-lookups later.
    let mut unconfirmed_candidates = Vec::new();
    // M-13-B: collect stale warnings
    let mut stale_warnings: Vec<String> = Vec::new();
    let mut seen_stale_keys: HashSet<String> = HashSet::new();

    for file_path in context_files {
        let file_key = if file_path.starts_with("file:") {
            file_path.clone()
        } else {
            format!("file:{file_path}")
        };

        // Get file record first to check lifecycle/staleness before traversal
        if let Ok(Some(record)) = store.get(&file_key).await {
            // M-13-B: exclude tombstone files from traversal entirely
            if record.staleness.tier == StalenessTier::Tombstone
                || !matches!(record.lifecycle, RecordLifecycle::Active)
            {
                continue;
            }

            // M-13-B: stale/liability file records generate warnings
            match record.staleness.tier {
                StalenessTier::Stale => {
                    let path = file_key.strip_prefix("file:").unwrap_or(&file_key);
                    if seen_stale_keys.insert(file_key.clone()) {
                        stale_warnings.push(format!(
                            "`{path}` record is stale (staleness {:.2}) — verify before trusting",
                            record.staleness.value
                        ));
                    }
                }
                StalenessTier::Liability => {
                    let path = file_key.strip_prefix("file:").unwrap_or(&file_key);
                    if seen_stale_keys.insert(file_key.clone()) {
                        stale_warnings.push(format!(
                            "`{path}` record is a liability (staleness {:.2}) — do not trust, read the file",
                            record.staleness.value
                        ));
                    }
                }
                _ => {}
            }

            if let Some(fr) = record.payload_as::<FileRecord>() {
                // Supplement graph traversal with the record-level gotcha_keys list.
                // FileRecord.gotcha_keys is the authoritative persistent source; the
                // in-memory graph edges are a cache that can lag after CLI gotcha writes
                // (apply_gotcha_write persists to disk but historically skipped the
                // in-memory graph update). Including these keys here ensures bootstrap
                // surfaces confirmed gotchas even when graph edges are stale or missing.
                for key in &fr.gotcha_keys {
                    context_gotcha_keys.insert(key.clone());
                }
                // Nudge detection: hot file (access_count >= 3) with no gotchas
                let is_nudge_candidate = record.access_count >= 3 && fr.gotcha_keys.is_empty();
                file_records.push(fr);
                if is_nudge_candidate {
                    unconfirmed_candidates.push(file_key.clone());
                }
            }
        }

        // 1-hop: direct gotchas
        for key in graph.neighbors(&file_key, &EdgeKind::HasGotcha) {
            context_gotcha_keys.insert(key);
        }

        // 2-hop: imports → their gotchas
        for imported in graph.neighbors(&file_key, &EdgeKind::Imports) {
            for key in graph.neighbors(&imported, &EdgeKind::HasGotcha) {
                context_gotcha_keys.insert(key);
            }
        }

        // Decisions via AffectedBy
        for key in graph.neighbors(&file_key, &EdgeKind::AffectedBy) {
            decision_keys.insert(key);
        }
    }

    // 2. (deferred) Collect confirmed gotchas — scope depends on context_files.
    let mut confirmed_gotchas: Vec<Record> = if context_files.is_empty() {
        // Global bootstrap: scan all gotchas (no context filter).
        let all_gotchas = store.scan_prefix("gotcha:").await?;
        all_gotchas
            .into_iter()
            .filter(is_injectable_gotcha)
            .collect()
    } else {
        // Targeted bootstrap: fetch only gotchas linked to context files.
        let mut gotchas = Vec::with_capacity(context_gotcha_keys.len());
        for key in &context_gotcha_keys {
            if let Ok(Some(record)) = store.get(key).await {
                if is_injectable_gotcha(&record) {
                    gotchas.push(record);
                }
            }
        }
        gotchas
    };

    // M-13-B: surface stale reviews from last 2 days
    {
        let now = chrono::Utc::now();
        for days_ago in 0..2 {
            let date = (now - chrono::Duration::days(days_ago)).format("%Y-%m-%d");
            let review_key = format!("analytics:stale_review_{date}");
            if let Ok(Some(record)) = store.get(&review_key).await {
                if let Some(payload) = record.payload_as::<StaleReviewPayload>() {
                    for entry in &payload.entries {
                        if seen_stale_keys.insert(entry.key.clone()) {
                            let path = entry.key.strip_prefix("file:").unwrap_or(&entry.key);
                            stale_warnings.push(format!(
                                "`{path}` staleness {:.2} ({:?}) — review recommended",
                                entry.staleness_value, entry.tier
                            ));
                        }
                    }
                }
            }
        }
    }

    // Fetch decision records — graph-linked first, fallback to scan
    let mut related_decisions = Vec::new();
    for key in &decision_keys {
        if let Ok(Some(record)) = store.get(key).await {
            related_decisions.push(record);
        }
    }
    // Fallback: when graph traversal found no decisions, scan decision:*
    // prefix so decisions always surface in bootstrap when they exist.
    if related_decisions.is_empty() {
        if let Ok(mut all_decisions) = store.scan_prefix("decision:").await {
            all_decisions.retain(|r| matches!(r.lifecycle, RecordLifecycle::Active));
            all_decisions.sort_by(|a, b| {
                b.confidence
                    .value
                    .partial_cmp(&a.confidence.value)
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
            const DECISION_FALLBACK_LIMIT: usize = 5;
            related_decisions = all_decisions
                .into_iter()
                .take(DECISION_FALLBACK_LIMIT)
                .collect();
        }
    }

    // 4. Sort gotchas by confidence × priority_weight (descending)
    confirmed_gotchas.sort_by(|a, b| {
        let score_a = a.confidence.value * priority_weight(&a.priority);
        let score_b = b.confidence.value * priority_weight(&b.priority);
        score_b
            .partial_cmp(&score_a)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    // 5. Quality filter: exclude Suppressed (<0.2), caveat Poor (0.2–0.4)
    //    Context scoping is already handled in step 2: targeted fetch for non-empty
    //    context_files, full scan for global bootstrap.
    let critical_gotchas: Vec<Record> = confirmed_gotchas
        .into_iter()
        .filter(|r| r.quality.tier != QualityTier::Suppressed)
        .collect();

    // 6. Build markdown injection string within token budget
    let available_tokens = TOKEN_BUDGET - VECTOR_B_TOKENS;
    let mut sections = Vec::new();
    let mut used_tokens = 0;

    // Stage section
    if let Some(ref stage_record) = stage {
        let section = format!("## Current Stage\n{}\n", stage_record.value);
        let tokens = estimate_tokens(&section);
        if used_tokens + tokens <= available_tokens {
            sections.push(section);
            used_tokens += tokens;
        }
    }

    // Gotchas section — separate co-change gotchas (grouped) from regular gotchas (individual)
    if !critical_gotchas.is_empty() {
        let mut gotcha_section = String::from("## Gotchas\n");

        // Regular gotchas (non-co-change) — listed individually
        for record in &critical_gotchas {
            if record.key.starts_with("gotcha:cochange:") {
                continue;
            }
            let caveat = if record.staleness.tier == StalenessTier::Liability {
                " [STALE — verify]"
            } else if record.quality.tier == QualityTier::Poor {
                " [LOW QUALITY — verify]"
            } else {
                ""
            };
            let line = format!("- **{}**{}: {}\n", record.key, caveat, record.value);
            let tokens = estimate_tokens(&line);
            if used_tokens + tokens > available_tokens {
                break;
            }
            gotcha_section.push_str(&line);
            used_tokens += tokens;
        }

        // Co-change gotchas — grouped by source file into one-liners
        let mut cochange_map: std::collections::BTreeMap<String, Vec<(String, String)>> =
            std::collections::BTreeMap::new();
        for record in &critical_gotchas {
            if !record.key.starts_with("gotcha:cochange:") {
                continue;
            }
            // key format: gotcha:cochange:file_a|file_b
            if let Some(pair) = record.key.strip_prefix("gotcha:cochange:") {
                if let Some((src, tgt)) = pair.split_once('|') {
                    // Extract percentage: "... (78%)." → "78%"
                    // Robust: find last '(' then take until '%' or ')'
                    let pct = record
                        .value
                        .rfind('(')
                        .and_then(|i| {
                            record.value[i + 1..]
                                .find(')')
                                .map(|j| &record.value[i + 1..i + 1 + j])
                        })
                        .unwrap_or("?");
                    cochange_map
                        .entry(src.to_string())
                        .or_default()
                        .push((tgt.to_string(), pct.to_string()));
                }
            }
        }
        if !cochange_map.is_empty() {
            let all_pairs: Vec<String> = cochange_map
                .iter()
                .flat_map(|(src, targets)| {
                    targets
                        .iter()
                        .map(move |(tgt, pct)| format!("{src}\u{2194}{tgt} ({pct})"))
                })
                .collect();
            let total = all_pairs.len();
            // Show up to 10 pairs, truncate with count
            let display: Vec<&str> = all_pairs.iter().take(10).map(|s| s.as_str()).collect();
            let suffix = if total > 10 {
                format!(", +{} more", total - 10)
            } else {
                String::new()
            };
            let line = format!("- **Co-change partners**: {}{suffix}\n", display.join(", "));
            let tokens = estimate_tokens(&line);
            if used_tokens + tokens <= available_tokens {
                gotcha_section.push_str(&line);
                used_tokens += tokens;
            }
        }

        if gotcha_section.len() > "## Gotchas\n".len() {
            sections.push(gotcha_section);
        }
    }

    // File records section
    if !file_records.is_empty() {
        let mut file_section = String::from("## Context Files\n");
        for fr in &file_records {
            if fr.purpose.is_empty() {
                continue;
            }
            let line = format!("- **{}**: {}\n", fr.path, fr.purpose);
            let tokens = estimate_tokens(&line);
            if used_tokens + tokens > available_tokens {
                break;
            }
            file_section.push_str(&line);
            used_tokens += tokens;
        }
        if file_section.len() > "## Context Files\n".len() {
            sections.push(file_section);
        }
    }

    // Highest-impact files in context — sorted by blast radius score descending.
    // Only shown when at least one file has a non-isolated blast radius.
    {
        use crate::analysis::blast_radius::BlastTier;
        let mut impact_files: Vec<(&FileRecord, f32)> = file_records
            .iter()
            .filter_map(|fr| {
                fr.blast_radius.as_ref().and_then(|br| {
                    if br.tier == BlastTier::Isolated {
                        None
                    } else {
                        Some((fr, br.score))
                    }
                })
            })
            .collect();
        impact_files.sort_by(|a, b| {
            b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal)
        });

        if !impact_files.is_empty() {
            let mut impact_section = String::from("## Highest Impact Files\n");
            for (fr, _score) in impact_files.iter().take(3) {
                let br = fr.blast_radius.as_ref().unwrap();
                let line = format!(
                    "- `{}`: {} direct importers ({})\n",
                    fr.path,
                    br.direct,
                    br.tier.label(),
                );
                let tokens = estimate_tokens(&line);
                if used_tokens + tokens > available_tokens {
                    break;
                }
                impact_section.push_str(&line);
                used_tokens += tokens;
            }
            if impact_section.len() > "## Highest Impact Files\n".len() {
                sections.push(impact_section);
            }
        }
    }

    // M-13-B: Stale Warnings section — BEFORE Decisions
    if !stale_warnings.is_empty() {
        let mut stale_section = String::from("## Stale Warnings\n");
        for warning in &stale_warnings {
            let line = format!("- {warning}\n");
            let tokens = estimate_tokens(&line);
            if used_tokens + tokens > available_tokens {
                break;
            }
            stale_section.push_str(&line);
            used_tokens += tokens;
        }
        if stale_section.len() > "## Stale Warnings\n".len() {
            sections.push(stale_section);
        }
    }

    // Decisions section
    if !related_decisions.is_empty() {
        let mut dec_section = String::from("## Decisions\n");
        for record in &related_decisions {
            let line = format!("- **{}**: {}\n", record.key, record.value);
            let tokens = estimate_tokens(&line);
            if used_tokens + tokens > available_tokens {
                break;
            }
            dec_section.push_str(&line);
            used_tokens += tokens;
        }
        if dec_section.len() > "## Decisions\n".len() {
            sections.push(dec_section);
        }
    }

    // M-12-E: Passive nudge — detect hot files with no gotchas.
    // NOTE: This is a deliberate exception to P2 ("inject nothing by default").
    // Nudges are advisory suggestions, not knowledge injection, and are only
    // emitted when token budget allows after all knowledge sections.
    // unconfirmed_candidates were collected during the context-file traversal
    // above (step 3), so no additional store lookups are needed here.
    if !unconfirmed_candidates.is_empty() {
        let mut nudge_section = String::from("## Suggested Actions\n");
        for key in &unconfirmed_candidates {
            let path = key.strip_prefix("file:").unwrap_or(key);
            let line = format!(
                "- `{path}` is read frequently but has no recorded gotchas. The developer may want to run `mati gotcha add {path}`.\n"
            );
            let tokens = estimate_tokens(&line);
            if used_tokens + tokens > available_tokens {
                break;
            }
            nudge_section.push_str(&line);
            used_tokens += tokens;
        }
        if nudge_section.len() > "## Suggested Actions\n".len() {
            sections.push(nudge_section);
        }
    }

    let mut injection_string = sections.join("\n");
    injection_string.push_str(VECTOR_B);

    let token_estimate = estimate_tokens(&injection_string) as u32;

    Ok(ContextPacket {
        stage,
        critical_gotchas,
        file_records,
        related_decisions,
        recent_session: None,
        token_estimate,
        stale_warnings,
        unconfirmed_candidates,
        knowledge_gaps: vec![],
        compliance_rate: None,
        injection_string,
    })
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::record::*;
    use crate::store::Store;
    use tempfile::TempDir;

    fn device_id() -> uuid::Uuid {
        uuid::Uuid::nil()
    }

    fn now() -> u64 {
        1_700_000_000
    }

    fn make_record(key: &str, value: &str, category: Category, quality_value: f32) -> Record {
        Record {
            key: key.to_string(),
            value: value.to_string(),
            category,
            priority: Priority::Normal,
            tags: vec![],
            created_at: now(),
            updated_at: now(),
            ref_url: None,
            staleness: StalenessScore::fresh(),
            lifecycle: RecordLifecycle::Active,
            version: RecordVersion {
                device_id: device_id(),
                logical_clock: 1,
                wall_clock: now(),
            },
            quality: QualityScore {
                value: quality_value,
                tier: QualityScore::tier_from_value(quality_value),
                signals: vec![],
                computed_at: now(),
            },
            access_count: 0,
            last_accessed: 0,
            source: RecordSource::DeveloperManual,
            confidence: ConfidenceScore {
                value: 0.8,
                confirmation_count: 1,
                contributor_count: 1,
                last_challenged: None,
                challenge_count: 0,
            },
            gap_analysis_score: 0.0,
            payload: Some(serde_json::json!({})),
        }
    }

    fn make_gotcha_record(key: &str, rule: &str, confirmed: bool, quality_value: f32) -> Record {
        let gotcha = GotchaRecord {
            rule: rule.to_string(),
            reason: "test reason".to_string(),
            severity: Priority::High,
            affected_files: vec![],
            ref_url: None,
            discovered_session: now(),
            confirmed,
        };
        let mut record = make_record(key, rule, Category::Gotcha, quality_value);
        record.payload = serde_json::to_value(&gotcha).ok();
        record
    }

    // ── mem_get tests ────────────────────────────────────────────────────────

    #[tokio::test]
    async fn mem_get_returns_null_for_nonexistent_key() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();
        let graph = Graph::load(store).await.unwrap();
        let server = MatiServer::new(graph);

        let result = server
            .mem_get(Parameters(MemGetParams {
                key: "file:nonexistent.rs".to_string(),
            }))
            .await;
        assert_eq!(result, "null");
    }

    #[tokio::test]
    async fn mem_get_returns_record_for_existing_key() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();
        let record = make_record("gotcha:test", "test value", Category::Gotcha, 0.8);
        store.put("gotcha:test", &record).await.unwrap();

        let graph = Graph::load(store).await.unwrap();
        let server = MatiServer::new(graph);

        let result = server
            .mem_get(Parameters(MemGetParams {
                key: "gotcha:test".to_string(),
            }))
            .await;
        assert!(result.contains("gotcha:test"));
        assert!(result.contains("test value"));
    }

    #[tokio::test]
    async fn mem_get_blast_radius_warning_for_critical_file() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();

        let fr = FileRecord {
            path: "src/core.rs".to_string(),
            purpose: "Core module".to_string(),
            entry_points: vec![],
            imports: vec![],
            gotcha_keys: vec![],
            decision_keys: vec![],
            todos: vec![],
            unsafe_count: 0,
            unwrap_count: 0,
            change_frequency: 0,
            last_author: None,
            is_hotspot: false,
            token_cost_estimate: 100,
            last_modified_session: 0,
            content_hash: None,
            line_count: 0,
            blast_radius: Some(crate::analysis::blast_radius::BlastRadius {
                direct: 45,
                transitive: 10,
                score: 48.0,
                tier: crate::analysis::blast_radius::BlastTier::Critical,
            }),
        };
        let mut record = make_record("file:src/core.rs", "Core module", Category::File, 0.5);
        record.payload = serde_json::to_value(&fr).ok();
        store.put("file:src/core.rs", &record).await.unwrap();

        let graph = Graph::load(store).await.unwrap();
        let server = MatiServer::new(graph);

        let result = server
            .mem_get(Parameters(MemGetParams {
                key: "file:src/core.rs".to_string(),
            }))
            .await;

        assert!(
            result.contains("HIGH IMPACT FILE"),
            "response must contain blast radius warning for critical file, got: {result}"
        );
        assert!(
            result.contains("45"),
            "warning must include direct count"
        );
    }

    #[tokio::test]
    async fn mem_get_no_blast_warning_for_low_file() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();

        let fr = FileRecord {
            path: "src/leaf.rs".to_string(),
            purpose: "Leaf module".to_string(),
            entry_points: vec![],
            imports: vec![],
            gotcha_keys: vec![],
            decision_keys: vec![],
            todos: vec![],
            unsafe_count: 0,
            unwrap_count: 0,
            change_frequency: 0,
            last_author: None,
            is_hotspot: false,
            token_cost_estimate: 100,
            last_modified_session: 0,
            content_hash: None,
            line_count: 0,
            blast_radius: Some(crate::analysis::blast_radius::BlastRadius {
                direct: 2,
                transitive: 0,
                score: 2.0,
                tier: crate::analysis::blast_radius::BlastTier::Low,
            }),
        };
        let mut record = make_record("file:src/leaf.rs", "Leaf module", Category::File, 0.5);
        record.payload = serde_json::to_value(&fr).ok();
        store.put("file:src/leaf.rs", &record).await.unwrap();

        let graph = Graph::load(store).await.unwrap();
        let server = MatiServer::new(graph);

        let result = server
            .mem_get(Parameters(MemGetParams {
                key: "file:src/leaf.rs".to_string(),
            }))
            .await;

        assert!(
            !result.contains("HIGH IMPACT FILE"),
            "low blast radius file should NOT have warning"
        );
    }

    // ── mem_query tests ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn mem_query_text_mode_returns_results() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();
        let record = make_record(
            "gotcha:async-race",
            "never use inference in async context",
            Category::Gotcha,
            0.8,
        );
        store.put("gotcha:async-race", &record).await.unwrap();

        let graph = Graph::load(store).await.unwrap();
        let server = MatiServer::new(graph);

        let result = server
            .mem_query(Parameters(MemQueryParams {
                query: "inference".to_string(),
                mode: "text".to_string(),
                limit: 10,
            }))
            .await;
        assert!(result.contains("gotcha:async-race"));
    }

    #[tokio::test]
    async fn mem_query_unknown_mode_returns_error() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();
        let graph = Graph::load(store).await.unwrap();
        let server = MatiServer::new(graph);

        let result = server
            .mem_query(Parameters(MemQueryParams {
                query: "test".to_string(),
                mode: "invalid".to_string(),
                limit: 20,
            }))
            .await;
        assert!(result.contains("unknown mode"));
    }

    #[tokio::test]
    async fn mem_query_semantic_returns_feature_gate_error() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();
        let graph = Graph::load(store).await.unwrap();
        let server = MatiServer::new(graph);

        let result = server
            .mem_query(Parameters(MemQueryParams {
                query: "test".to_string(),
                mode: "semantic".to_string(),
                limit: 20,
            }))
            .await;
        assert!(result.contains("--features semantic"));
    }

    // ── mem_bootstrap tests ──────────────────────────────────────────────────

    #[tokio::test]
    async fn mem_bootstrap_empty_store_returns_vector_b() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();
        let graph = Graph::load(store).await.unwrap();
        let server = MatiServer::new(graph);

        let result = server
            .mem_bootstrap(Parameters(MemBootstrapParams {
                context_files: vec![],
            }))
            .await;
        assert!(result.contains("[mati] Before reading any file"));
        assert!(result.contains("mem_get"));
    }

    #[tokio::test]
    async fn mem_bootstrap_token_budget_never_exceeds_2000() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();

        // Insert many gotchas to try to exceed the budget
        for i in 0..100 {
            let record = make_gotcha_record(
                &format!("gotcha:test-{i:03}"),
                &format!("This is a very long gotcha rule number {i} with lots of text to fill up the token budget and ensure we test the truncation logic properly"),
                true,
                0.8,
            );
            store.put(&record.key, &record).await.unwrap();
        }

        let graph = Graph::load(store).await.unwrap();

        let packet = assemble_context_packet(graph.store(), &graph, &[])
            .await
            .unwrap();
        let tokens = estimate_tokens(&packet.injection_string);
        assert!(
            tokens <= TOKEN_BUDGET,
            "token estimate {tokens} exceeds budget {TOKEN_BUDGET}"
        );
    }

    #[tokio::test]
    async fn quality_filter_suppressed_excluded() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();

        // Suppressed quality (< 0.2) — should be excluded
        let suppressed = make_gotcha_record("gotcha:suppressed", "bad rule", true, 0.10);
        store.put("gotcha:suppressed", &suppressed).await.unwrap();

        // Good quality — should be included
        let good = make_gotcha_record("gotcha:good", "good rule", true, 0.80);
        store.put("gotcha:good", &good).await.unwrap();

        let graph = Graph::load(store).await.unwrap();
        let packet = assemble_context_packet(graph.store(), &graph, &[])
            .await
            .unwrap();

        assert!(
            !packet.injection_string.contains("gotcha:suppressed"),
            "suppressed gotcha must not appear in injection"
        );
    }

    #[tokio::test]
    async fn quality_filter_poor_caveated() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();

        // Poor quality (0.2–0.4) — should be caveated but included
        let poor = make_gotcha_record("gotcha:poor", "poor rule", true, 0.30);
        store.put("gotcha:poor", &poor).await.unwrap();

        let graph = Graph::load(store).await.unwrap();
        let packet = assemble_context_packet(graph.store(), &graph, &[])
            .await
            .unwrap();

        // Poor records should appear with a caveat
        if packet.injection_string.contains("gotcha:poor") {
            assert!(
                packet.injection_string.contains("LOW QUALITY"),
                "poor quality gotcha must be caveated"
            );
        }
    }

    #[tokio::test]
    async fn assemble_context_packet_with_context_files_does_graph_traversal() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();

        // Create a gotcha record
        let gotcha = make_gotcha_record("gotcha:important", "do not use unwrap", true, 0.80);
        store.put("gotcha:important", &gotcha).await.unwrap();

        // Create a file record
        let file_record = make_record("file:src/main.rs", "{}", Category::File, 0.5);
        store.put("file:src/main.rs", &file_record).await.unwrap();

        // Build graph with HasGotcha edge
        let mut graph = Graph::load(store).await.unwrap();
        graph
            .add_edge("file:src/main.rs", EdgeKind::HasGotcha, "gotcha:important")
            .await
            .unwrap();

        let packet = assemble_context_packet(graph.store(), &graph, &["src/main.rs".to_string()])
            .await
            .unwrap();

        // The gotcha should be in the context packet
        assert!(
            packet.injection_string.contains("gotcha:important")
                || packet
                    .critical_gotchas
                    .iter()
                    .any(|g| g.key == "gotcha:important"),
            "graph-connected gotcha must appear in context packet"
        );
    }

    #[tokio::test]
    async fn assemble_context_packet_excludes_unrelated_gotchas_for_context_files() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();

        let relevant = make_gotcha_record("gotcha:relevant", "do not use unwrap", true, 0.80);
        let unrelated = make_gotcha_record("gotcha:unrelated", "keep retries bounded", true, 0.80);
        store.put("gotcha:relevant", &relevant).await.unwrap();
        store.put("gotcha:unrelated", &unrelated).await.unwrap();

        let file_record = make_record("file:src/main.rs", "{}", Category::File, 0.5);
        store.put("file:src/main.rs", &file_record).await.unwrap();

        let mut graph = Graph::load(store).await.unwrap();
        graph
            .add_edge("file:src/main.rs", EdgeKind::HasGotcha, "gotcha:relevant")
            .await
            .unwrap();

        let packet = assemble_context_packet(graph.store(), &graph, &["src/main.rs".to_string()])
            .await
            .unwrap();

        assert!(
            packet
                .critical_gotchas
                .iter()
                .any(|g| g.key == "gotcha:relevant"),
            "graph-connected gotcha must remain in context packet"
        );
        assert!(
            !packet
                .critical_gotchas
                .iter()
                .any(|g| g.key == "gotcha:unrelated"),
            "unrelated gotcha must not be injected for scoped bootstrap"
        );
        assert!(
            !packet.injection_string.contains("gotcha:unrelated"),
            "injection string must not mention unrelated gotchas"
        );
    }

    /// Regression test for the bootstrap low-confidence file bug.
    ///
    /// Scenario: file record has confidence 0.10 (Layer 0 stub from mati init),
    /// a confirmed gotcha with confidence 0.80 is linked via FileRecord.gotcha_keys,
    /// but NO HasGotcha graph edge exists (simulating CLI gotcha_write that wrote to
    /// the store but never updated the in-memory graph).
    ///
    /// Bootstrap must still surface the confirmed gotcha by falling back to
    /// FileRecord.gotcha_keys when graph edges are absent.
    #[tokio::test]
    async fn bootstrap_surfaces_confirmed_gotcha_when_graph_edge_missing() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();

        // Confirmed gotcha with high confidence/quality
        let gotcha = make_gotcha_record(
            "gotcha:never-remove-rate-limit",
            "Never remove the rate limit check on incoming pipeline events because \
             removing it caused a cascade failure in staging",
            true,
            0.80,
        );
        store
            .put("gotcha:never-remove-rate-limit", &gotcha)
            .await
            .unwrap();

        // File record: low-confidence stub (confidence 0.10), but gotcha_keys populated
        let file_record = {
            let fr = FileRecord {
                path: "src/pipeline/prefilter.rs".to_string(),
                purpose: String::new(), // no purpose — Layer 0 stub
                entry_points: vec![],
                imports: vec![],
                gotcha_keys: vec!["gotcha:never-remove-rate-limit".to_string()],
                decision_keys: vec![],
                todos: vec![],
                unsafe_count: 0,
                unwrap_count: 0,
                change_frequency: 18,
                last_author: Some("dev".to_string()),
                is_hotspot: true,
                token_cost_estimate: 0,
                last_modified_session: now(),
                content_hash: None,
                line_count: 0,
                blast_radius: None,
            };
            let mut r = make_record(
                "file:src/pipeline/prefilter.rs",
                "",
                Category::File,
                0.10, // low confidence — stub
            );
            r.payload = serde_json::to_value(&fr).ok();
            r
        };
        store
            .put("file:src/pipeline/prefilter.rs", &file_record)
            .await
            .unwrap();

        // Intentionally do NOT add a HasGotcha graph edge — simulates the CLI
        // gotcha_write bug where the persistent store edge was written but the
        // in-memory graph was never updated.
        let graph = Graph::load(store).await.unwrap();
        assert_eq!(
            graph.neighbors("file:src/pipeline/prefilter.rs", &EdgeKind::HasGotcha),
            Vec::<String>::new(),
            "test setup: graph must have no HasGotcha edge"
        );

        let packet = assemble_context_packet(
            graph.store(),
            &graph,
            &["src/pipeline/prefilter.rs".to_string()],
        )
        .await
        .unwrap();

        assert!(
            packet
                .critical_gotchas
                .iter()
                .any(|g| g.key == "gotcha:never-remove-rate-limit"),
            "bootstrap must surface confirmed gotcha even when graph edge is missing"
        );
        assert!(
            packet
                .injection_string
                .contains("gotcha:never-remove-rate-limit"),
            "injection string must include the gotcha"
        );
    }

    /// Negative case: file with confidence 0.10 and NO confirmed gotchas should
    /// produce minimal bootstrap output — no purpose text, no gotchas, no receipt.
    #[tokio::test]
    async fn bootstrap_low_confidence_file_with_no_gotchas_returns_minimal_packet() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();

        let file_record = {
            let fr = FileRecord {
                path: "src/empty.rs".to_string(),
                purpose: String::new(),
                entry_points: vec![],
                imports: vec![],
                gotcha_keys: vec![],
                decision_keys: vec![],
                todos: vec![],
                unsafe_count: 0,
                unwrap_count: 0,
                change_frequency: 1,
                last_author: None,
                is_hotspot: false,
                token_cost_estimate: 0,
                last_modified_session: now(),
                content_hash: None,
                line_count: 0,
                blast_radius: None,
            };
            let mut r = make_record("file:src/empty.rs", "", Category::File, 0.10);
            r.payload = serde_json::to_value(&fr).ok();
            r
        };
        store.put("file:src/empty.rs", &file_record).await.unwrap();

        let graph = Graph::load(store).await.unwrap();
        let packet = assemble_context_packet(graph.store(), &graph, &["src/empty.rs".to_string()])
            .await
            .unwrap();

        assert!(
            packet.critical_gotchas.is_empty(),
            "no gotchas should be surfaced for a file with no linked gotchas"
        );
        assert!(
            !packet.injection_string.contains("gotcha:"),
            "injection string must not mention any gotcha keys"
        );
    }

    // ── M-12-E: nudge detection ─────────────────────────────────────────────

    #[tokio::test]
    async fn nudge_shown_for_hot_file_with_no_gotchas() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();

        let fr = FileRecord {
            path: "src/hot.rs".to_string(),
            purpose: "Hot module".to_string(),
            entry_points: vec!["run".to_string()],
            imports: vec![],
            gotcha_keys: vec![], // no gotchas
            decision_keys: vec![],
            todos: vec![],
            unsafe_count: 0,
            unwrap_count: 0,
            change_frequency: 10,
            last_author: None,
            is_hotspot: true,
            token_cost_estimate: 100,
            last_modified_session: now(),
            content_hash: None,
            line_count: 0,
            blast_radius: None,
        };
        let mut file_record = make_record("file:src/hot.rs", &fr.purpose, Category::File, 0.5);
        file_record.payload = serde_json::to_value(&fr).ok();
        file_record.access_count = 5; // >= 3 threshold
        store.put("file:src/hot.rs", &file_record).await.unwrap();

        let graph = Graph::load(store).await.unwrap();
        let packet = assemble_context_packet(graph.store(), &graph, &["src/hot.rs".to_string()])
            .await
            .unwrap();

        assert!(
            packet
                .unconfirmed_candidates
                .contains(&"file:src/hot.rs".to_string()),
            "hot file with no gotchas should be in unconfirmed_candidates"
        );
        assert!(
            packet.injection_string.contains("Suggested Actions"),
            "nudge section should appear in injection string"
        );
        assert!(
            packet.injection_string.contains("mati gotcha add"),
            "nudge should suggest gotcha add command"
        );
    }

    #[tokio::test]
    async fn no_nudge_for_file_with_low_access_count() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();

        let fr = FileRecord {
            path: "src/cold.rs".to_string(),
            purpose: "Cold module".to_string(),
            entry_points: vec![],
            imports: vec![],
            gotcha_keys: vec![],
            decision_keys: vec![],
            todos: vec![],
            unsafe_count: 0,
            unwrap_count: 0,
            change_frequency: 0,
            last_author: None,
            is_hotspot: false,
            token_cost_estimate: 50,
            last_modified_session: now(),
            content_hash: None,
            line_count: 0,
            blast_radius: None,
        };
        let mut file_record = make_record("file:src/cold.rs", &fr.purpose, Category::File, 0.5);
        file_record.payload = serde_json::to_value(&fr).ok();
        file_record.access_count = 1; // < 3 threshold
        store.put("file:src/cold.rs", &file_record).await.unwrap();

        let graph = Graph::load(store).await.unwrap();
        let packet = assemble_context_packet(graph.store(), &graph, &["src/cold.rs".to_string()])
            .await
            .unwrap();

        assert!(
            packet.unconfirmed_candidates.is_empty(),
            "low-access file should not trigger nudge"
        );
    }

    #[tokio::test]
    async fn no_nudge_for_file_with_gotchas() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();

        let fr = FileRecord {
            path: "src/covered.rs".to_string(),
            purpose: "Covered module".to_string(),
            entry_points: vec![],
            imports: vec![],
            gotcha_keys: vec!["gotcha:existing".to_string()],
            decision_keys: vec![],
            todos: vec![],
            unsafe_count: 0,
            unwrap_count: 0,
            change_frequency: 10,
            last_author: None,
            is_hotspot: true,
            token_cost_estimate: 100,
            last_modified_session: now(),
            content_hash: None,
            line_count: 0,
            blast_radius: None,
        };
        let mut file_record = make_record(
            "file:src/covered.rs",
            &serde_json::to_string(&fr).unwrap(),
            Category::File,
            0.5,
        );
        file_record.access_count = 10;
        store
            .put("file:src/covered.rs", &file_record)
            .await
            .unwrap();

        let graph = Graph::load(store).await.unwrap();
        let packet =
            assemble_context_packet(graph.store(), &graph, &["src/covered.rs".to_string()])
                .await
                .unwrap();

        assert!(
            packet.unconfirmed_candidates.is_empty(),
            "file with gotchas should not trigger nudge"
        );
    }

    // ── M-13-B: stale warning tests ─────────────────────────────────────────

    #[tokio::test]
    async fn tombstone_gotcha_excluded_from_bootstrap() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();

        // Create a tombstone-tier gotcha
        let mut gotcha = make_gotcha_record("gotcha:tombstone", "tombstone rule", true, 0.80);
        gotcha.staleness = StalenessScore {
            value: 0.95,
            tier: StalenessTier::Tombstone,
            signals: vec![],
            computed_at: now(),
            last_record_sha: String::new(),
        };
        store.put("gotcha:tombstone", &gotcha).await.unwrap();

        // Create a normal gotcha
        let good = make_gotcha_record("gotcha:good", "good rule", true, 0.80);
        store.put("gotcha:good", &good).await.unwrap();

        let graph = Graph::load(store).await.unwrap();
        let packet = assemble_context_packet(graph.store(), &graph, &[])
            .await
            .unwrap();

        assert!(
            !packet.injection_string.contains("gotcha:tombstone"),
            "tombstone gotcha must not appear in injection"
        );
        assert!(
            packet.injection_string.contains("gotcha:good"),
            "normal gotcha should appear"
        );
    }

    #[tokio::test]
    async fn liability_gotcha_gets_stale_caveat() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();

        let mut gotcha = make_gotcha_record("gotcha:liability", "liability rule", true, 0.80);
        gotcha.staleness = StalenessScore {
            value: 0.75,
            tier: StalenessTier::Liability,
            signals: vec![],
            computed_at: now(),
            last_record_sha: String::new(),
        };
        store.put("gotcha:liability", &gotcha).await.unwrap();

        let graph = Graph::load(store).await.unwrap();
        let packet = assemble_context_packet(graph.store(), &graph, &[])
            .await
            .unwrap();

        if packet.injection_string.contains("gotcha:liability") {
            assert!(
                packet.injection_string.contains("STALE"),
                "liability gotcha must have STALE caveat"
            );
        }
    }

    #[tokio::test]
    async fn stale_file_generates_warning() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();

        let fr = FileRecord {
            path: "src/stale.rs".to_string(),
            purpose: "Stale module".to_string(),
            entry_points: vec![],
            imports: vec![],
            gotcha_keys: vec![],
            decision_keys: vec![],
            todos: vec![],
            unsafe_count: 0,
            unwrap_count: 0,
            change_frequency: 0,
            last_author: None,
            is_hotspot: false,
            token_cost_estimate: 50,
            last_modified_session: now(),
            content_hash: None,
            line_count: 0,
            blast_radius: None,
        };
        let mut file_record = make_record(
            "file:src/stale.rs",
            &serde_json::to_string(&fr).unwrap(),
            Category::File,
            0.5,
        );
        file_record.staleness = StalenessScore {
            value: 0.55,
            tier: StalenessTier::Stale,
            signals: vec![],
            computed_at: now(),
            last_record_sha: String::new(),
        };
        store.put("file:src/stale.rs", &file_record).await.unwrap();

        let graph = Graph::load(store).await.unwrap();
        let packet = assemble_context_packet(graph.store(), &graph, &["src/stale.rs".to_string()])
            .await
            .unwrap();

        assert!(
            !packet.stale_warnings.is_empty(),
            "stale file should generate a warning"
        );
        assert!(
            packet.stale_warnings.iter().any(|w| w.contains("stale.rs")),
            "warning should mention the stale file"
        );
    }

    #[tokio::test]
    async fn tombstone_file_excluded_from_traversal() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();

        let fr = FileRecord {
            path: "src/dead.rs".to_string(),
            purpose: "Dead module".to_string(),
            entry_points: vec![],
            imports: vec![],
            gotcha_keys: vec![],
            decision_keys: vec![],
            todos: vec![],
            unsafe_count: 0,
            unwrap_count: 0,
            change_frequency: 0,
            last_author: None,
            is_hotspot: false,
            token_cost_estimate: 50,
            last_modified_session: now(),
            content_hash: None,
            line_count: 0,
            blast_radius: None,
        };
        let mut file_record = make_record(
            "file:src/dead.rs",
            &serde_json::to_string(&fr).unwrap(),
            Category::File,
            0.5,
        );
        file_record.staleness = StalenessScore {
            value: 0.95,
            tier: StalenessTier::Tombstone,
            signals: vec![],
            computed_at: now(),
            last_record_sha: String::new(),
        };
        store.put("file:src/dead.rs", &file_record).await.unwrap();

        let graph = Graph::load(store).await.unwrap();
        let packet = assemble_context_packet(graph.store(), &graph, &["src/dead.rs".to_string()])
            .await
            .unwrap();

        assert!(
            packet.file_records.is_empty(),
            "tombstone file should not appear in file_records"
        );
    }

    #[tokio::test]
    async fn stale_warnings_deduplicated() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();

        let fr = FileRecord {
            path: "src/dup.rs".to_string(),
            purpose: "Dup module".to_string(),
            entry_points: vec![],
            imports: vec![],
            gotcha_keys: vec![],
            decision_keys: vec![],
            todos: vec![],
            unsafe_count: 0,
            unwrap_count: 0,
            change_frequency: 0,
            last_author: None,
            is_hotspot: false,
            token_cost_estimate: 50,
            last_modified_session: now(),
            content_hash: None,
            line_count: 0,
            blast_radius: None,
        };
        let mut file_record = make_record(
            "file:src/dup.rs",
            &serde_json::to_string(&fr).unwrap(),
            Category::File,
            0.5,
        );
        file_record.staleness = StalenessScore {
            value: 0.55,
            tier: StalenessTier::Stale,
            signals: vec![],
            computed_at: now(),
            last_record_sha: String::new(),
        };
        store.put("file:src/dup.rs", &file_record).await.unwrap();

        // Also create a stale review entry for the same key
        let review_payload = StaleReviewPayload {
            session_timestamp: now(),
            entries: vec![StaleReviewEntry {
                key: "file:src/dup.rs".to_string(),
                staleness_value: 0.55,
                tier: StalenessTier::Stale,
                last_updated: now(),
                signals: vec!["stale".to_string()],
            }],
        };
        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let review_key = format!("analytics:stale_review_{today}");
        let review_record = make_record(
            &review_key,
            &serde_json::to_string(&review_payload).unwrap(),
            Category::Analytics,
            0.5,
        );
        store.put(&review_key, &review_record).await.unwrap();

        let graph = Graph::load(store).await.unwrap();
        let packet = assemble_context_packet(graph.store(), &graph, &["src/dup.rs".to_string()])
            .await
            .unwrap();

        // Should have exactly 1 warning, not 2 (dedup by key)
        let dup_count = packet
            .stale_warnings
            .iter()
            .filter(|w| w.contains("dup.rs"))
            .count();
        assert_eq!(
            dup_count, 1,
            "same key should not produce duplicate warnings"
        );
    }

    #[tokio::test]
    async fn stale_warnings_section_before_decisions() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();

        // Create a stale file
        let fr = FileRecord {
            path: "src/stale.rs".to_string(),
            purpose: "Stale".to_string(),
            entry_points: vec![],
            imports: vec![],
            gotcha_keys: vec![],
            decision_keys: vec![],
            todos: vec![],
            unsafe_count: 0,
            unwrap_count: 0,
            change_frequency: 0,
            last_author: None,
            is_hotspot: false,
            token_cost_estimate: 50,
            last_modified_session: now(),
            content_hash: None,
            line_count: 0,
            blast_radius: None,
        };
        let mut file_record = make_record(
            "file:src/stale.rs",
            &serde_json::to_string(&fr).unwrap(),
            Category::File,
            0.5,
        );
        file_record.staleness = StalenessScore {
            value: 0.55,
            tier: StalenessTier::Stale,
            signals: vec![],
            computed_at: now(),
            last_record_sha: String::new(),
        };
        store.put("file:src/stale.rs", &file_record).await.unwrap();

        // Create a decision record reachable via graph edge
        let decision = make_record("decision:arch", "Use SurrealKV", Category::Decision, 0.8);
        store.put("decision:arch", &decision).await.unwrap();

        let mut graph = Graph::load(store).await.unwrap();
        graph
            .add_edge("file:src/stale.rs", EdgeKind::AffectedBy, "decision:arch")
            .await
            .unwrap();

        let packet = assemble_context_packet(graph.store(), &graph, &["src/stale.rs".to_string()])
            .await
            .unwrap();

        let stale_pos = packet.injection_string.find("## Stale Warnings");
        let dec_pos = packet.injection_string.find("## Decisions");

        if let (Some(s), Some(d)) = (stale_pos, dec_pos) {
            assert!(s < d, "Stale Warnings section must appear before Decisions");
        }
    }

    #[tokio::test]
    async fn unconfirmed_gotcha_never_injected() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();

        // Create an unconfirmed gotcha
        let unconfirmed = make_gotcha_record("gotcha:unconfirmed", "unconfirmed rule", false, 0.80);
        store.put("gotcha:unconfirmed", &unconfirmed).await.unwrap();

        let graph = Graph::load(store).await.unwrap();
        let packet = assemble_context_packet(graph.store(), &graph, &[])
            .await
            .unwrap();

        assert!(
            !packet.injection_string.contains("gotcha:unconfirmed"),
            "unconfirmed gotcha must never be injected"
        );
    }

    #[tokio::test]
    async fn empty_store_returns_only_vector_b() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();
        let graph = Graph::load(store).await.unwrap();

        let packet = assemble_context_packet(graph.store(), &graph, &[])
            .await
            .unwrap();

        assert!(packet.injection_string.contains("[mati] Before reading"));
        assert!(packet.critical_gotchas.is_empty());
        assert!(packet.file_records.is_empty());
        assert!(packet.stale_warnings.is_empty());
        assert!(packet.related_decisions.is_empty());
    }

    // ── mem_set tests ────────────────────────────────────────────────────────

    #[tokio::test]
    async fn mem_set_writes_new_file_record() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();
        let graph = Graph::load(store).await.unwrap();
        let server = MatiServer::new(graph);

        let result = server
            .mem_set(Parameters(MemSetParams {
                action: "write".to_string(),
                key: "file:src/main.rs".to_string(),
                value: "Handles CLI dispatch and binary entry point".to_string(),
                category: "File".to_string(),
                payload: serde_json::json!({
                    "path": "src/main.rs",
                    "purpose": "Handles CLI dispatch and binary entry point"
                }),
                tags: vec!["entry-point".to_string()],
                priority: "Normal".to_string(),
            }))
            .await;

        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed["ok"], true);
        assert_eq!(parsed["key"], "file:src/main.rs");
        assert!((parsed["confidence"].as_f64().unwrap() - 0.60).abs() < 0.01);

        // Read back and verify
        let graph_arc = server.graph_arc();
        let graph = graph_arc.read().await;
        let record = graph
            .store()
            .get("file:src/main.rs")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(record.value, "Handles CLI dispatch and binary entry point");
        assert_eq!(record.source, RecordSource::ClaudeEnrich);
        assert!(record.payload.is_some());
    }

    #[tokio::test]
    async fn mem_set_writes_gotcha_with_quality_score() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();
        let graph = Graph::load(store).await.unwrap();
        let server = MatiServer::new(graph);

        let result = server
            .mem_set(Parameters(MemSetParams { action: "write".to_string(),
                key: "gotcha:always-use-idempotency-keys".to_string(),
                value: "Always pass idempotency_key to Stripe charge creation because duplicate charges cause customer refund disputes".to_string(),
                category: "Gotcha".to_string(),
                payload: serde_json::json!({
                    "rule": "Always pass idempotency_key to Stripe charge creation",
                    "reason": "duplicate charges cause customer refund disputes",
                    "severity": "Critical",
                    "affected_files": ["src/payments/stripe.go"],
                    "ref_url": null,
                    "discovered_session": 0,
                    "confirmed": false
                }),
                tags: vec![],
                priority: "Critical".to_string(),
            }))
            .await;

        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed["ok"], true);
        // Quality should be > 0.2 (passes gate) since rule has imperative verb + reason has causality
        assert!(parsed["quality"].as_f64().unwrap() > 0.2);

        // Read back
        let graph_arc = server.graph_arc();
        let graph = graph_arc.read().await;
        let record = graph
            .store()
            .get("gotcha:always-use-idempotency-keys")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(record.priority, Priority::Critical);
        assert_eq!(record.source, RecordSource::ClaudeEnrich);
    }

    #[tokio::test]
    async fn mem_set_preserves_existing_layer0_data() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();

        // Pre-populate a Layer 0 file record
        let mut layer0 = Record::layer0_file_stub("file:src/db.rs", device_id(), 1, now());
        layer0.payload = Some(serde_json::json!({
            "path": "src/db.rs",
            "purpose": "",
            "entry_points": ["fn connect", "fn query"],
            "imports": ["tokio", "sqlx"],
            "gotcha_keys": [],
            "decision_keys": [],
            "todos": [],
            "unsafe_count": 0,
            "unwrap_count": 2,
            "change_frequency": 45,
            "last_author": "alice",
            "is_hotspot": true,
            "token_cost_estimate": 120,
            "last_modified_session": 0
        }));
        store.put("file:src/db.rs", &layer0).await.unwrap();

        let graph = Graph::load(store).await.unwrap();
        let server = MatiServer::new(graph);

        // Enrich — only send purpose and updated gotcha_keys
        let result = server
            .mem_set(Parameters(MemSetParams {
                action: "write".to_string(),
                key: "file:src/db.rs".to_string(),
                value: "Manages database connection pooling and query execution".to_string(),
                category: "File".to_string(),
                payload: serde_json::json!({
                    "purpose": "Manages database connection pooling and query execution",
                    "gotcha_keys": ["gotcha:always-close-connections"]
                }),
                tags: vec![],
                priority: "Normal".to_string(),
            }))
            .await;

        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed["ok"], true);

        // Verify Layer 0 fields preserved via merge
        let graph_arc = server.graph_arc();
        let graph = graph_arc.read().await;
        let record = graph.store().get("file:src/db.rs").await.unwrap().unwrap();
        let payload = record.payload.unwrap();

        // Enrichment fields updated
        assert_eq!(
            payload["purpose"],
            "Manages database connection pooling and query execution"
        );
        assert_eq!(payload["gotcha_keys"][0], "gotcha:always-close-connections");

        // Layer 0 structural fields preserved
        assert_eq!(payload["entry_points"][0], "fn connect");
        assert_eq!(payload["imports"][0], "tokio");
        assert_eq!(payload["change_frequency"], 45);
        assert_eq!(payload["is_hotspot"], true);

        // Source upgraded to ClaudeEnrich
        assert_eq!(record.source, RecordSource::ClaudeEnrich);
    }

    #[tokio::test]
    async fn mem_set_rejects_invalid_key_prefix() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();
        let graph = Graph::load(store).await.unwrap();
        let server = MatiServer::new(graph);

        let result = server
            .mem_set(Parameters(MemSetParams {
                action: "write".to_string(),
                key: "session:12345".to_string(),
                value: "test".to_string(),
                category: "File".to_string(),
                payload: serde_json::json!({}),
                tags: vec![],
                priority: "Normal".to_string(),
            }))
            .await;

        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert!(parsed["error"]
            .as_str()
            .unwrap()
            .contains("must start with"));
    }

    #[tokio::test]
    async fn mem_set_rejects_invalid_category() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();
        let graph = Graph::load(store).await.unwrap();
        let server = MatiServer::new(graph);

        let result = server
            .mem_set(Parameters(MemSetParams {
                action: "write".to_string(),
                key: "file:test.rs".to_string(),
                value: "test".to_string(),
                category: "Unknown".to_string(),
                payload: serde_json::json!({}),
                tags: vec![],
                priority: "Normal".to_string(),
            }))
            .await;

        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert!(parsed["error"]
            .as_str()
            .unwrap()
            .contains("unknown category"));
    }

    #[tokio::test]
    async fn mem_set_rejects_key_category_mismatch() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();
        let graph = Graph::load(store).await.unwrap();
        let server = MatiServer::new(graph);

        // gotcha: key with File category — must be rejected.
        let result = server
            .mem_set(Parameters(MemSetParams {
                action: "write".to_string(),
                key: "gotcha:should-fail".to_string(),
                value: "test".to_string(),
                category: "File".to_string(),
                payload: serde_json::json!({"purpose": "test"}),
                tags: vec![],
                priority: "Normal".to_string(),
            }))
            .await;

        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert!(
            parsed["error"]
                .as_str()
                .unwrap()
                .contains("requires category"),
            "key-category mismatch must be rejected: {result}"
        );
    }

    #[tokio::test]
    async fn mem_set_rejects_new_gotcha_without_rule_and_reason() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();
        let graph = Graph::load(store).await.unwrap();
        let server = MatiServer::new(graph);

        let result = server
            .mem_set(Parameters(MemSetParams {
                action: "write".to_string(),
                key: "gotcha:missing-fields".to_string(),
                value: "test".to_string(),
                category: "Gotcha".to_string(),
                payload: serde_json::json!({"severity": "Normal"}),
                tags: vec![],
                priority: "Normal".to_string(),
            }))
            .await;

        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert!(
            parsed["error"]
                .as_str()
                .unwrap()
                .contains("'rule' and 'reason'"),
            "new gotcha without rule/reason must be rejected: {result}"
        );
    }

    #[tokio::test]
    async fn mem_set_rejects_new_decision_without_summary_rationale() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();
        let graph = Graph::load(store).await.unwrap();
        let server = MatiServer::new(graph);

        let result = server
            .mem_set(Parameters(MemSetParams {
                action: "write".to_string(),
                key: "decision:incomplete".to_string(),
                value: "test".to_string(),
                category: "Decision".to_string(),
                payload: serde_json::json!({}),
                tags: vec![],
                priority: "Normal".to_string(),
            }))
            .await;

        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert!(
            parsed["error"]
                .as_str()
                .unwrap()
                .contains("'summary' and 'rationale'"),
            "new decision without summary/rationale must be rejected: {result}"
        );
    }

    #[tokio::test]
    async fn mem_set_rejects_new_dev_note_with_empty_value() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();
        let graph = Graph::load(store).await.unwrap();
        let server = MatiServer::new(graph);

        let result = server
            .mem_set(Parameters(MemSetParams {
                action: "write".to_string(),
                key: "dev_note:empty".to_string(),
                value: "".to_string(),
                category: "DevNote".to_string(),
                payload: serde_json::json!({}),
                tags: vec![],
                priority: "Normal".to_string(),
            }))
            .await;

        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert!(
            parsed["error"]
                .as_str()
                .unwrap()
                .contains("non-empty value"),
            "new dev_note with empty value must be rejected: {result}"
        );
    }

    #[tokio::test]
    async fn mem_set_allows_partial_payload_on_update() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();
        let graph = Graph::load(store).await.unwrap();
        let server = MatiServer::new(graph);

        // First write: full payload (new record).
        let result = server
            .mem_set(Parameters(MemSetParams {
                action: "write".to_string(),
                key: "gotcha:partial-update".to_string(),
                value: "test rule because test reason".to_string(),
                category: "Gotcha".to_string(),
                payload: serde_json::json!({
                    "rule": "test rule",
                    "reason": "test reason",
                    "severity": "Normal",
                    "affected_files": [],
                }),
                tags: vec![],
                priority: "Normal".to_string(),
            }))
            .await;
        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed["ok"], true, "initial write must succeed");

        // Second write: partial payload (update) — must succeed because
        // payload validation is skipped for existing records (merge fills fields).
        let result = server
            .mem_set(Parameters(MemSetParams {
                action: "write".to_string(),
                key: "gotcha:partial-update".to_string(),
                value: "updated rule because updated reason".to_string(),
                category: "Gotcha".to_string(),
                payload: serde_json::json!({"reason": "updated reason"}),
                tags: vec![],
                priority: "Normal".to_string(),
            }))
            .await;
        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(
            parsed["ok"], true,
            "partial-payload update must succeed: {result}"
        );
    }

    #[tokio::test]
    async fn mem_set_preserves_confirmation_state_on_update() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();

        // Create a confirmed gotcha (simulates post-mati gotcha confirm state)
        let mut record = make_gotcha_record(
            "gotcha:confirmed-edit-test",
            "Always test first",
            true,
            0.70,
        );
        record.source = RecordSource::DeveloperManual;
        record.confidence = ConfidenceScore {
            value: 0.80,
            confirmation_count: 1,
            contributor_count: 1,
            last_challenged: None,
            challenge_count: 0,
        };
        record.tags = vec!["important".to_string()];
        store
            .put("gotcha:confirmed-edit-test", &record)
            .await
            .unwrap();

        let graph = Graph::load(store).await.unwrap();
        let server = MatiServer::new(graph);

        // Update the gotcha's value via mem_set (simulates Claude editing the reason)
        let result = server
            .mem_set(Parameters(MemSetParams {
                action: "write".to_string(),
                key: "gotcha:confirmed-edit-test".to_string(),
                value: "Always test first because untested changes cause regressions".to_string(),
                category: "Gotcha".to_string(),
                payload: serde_json::json!({
                    "rule": "Always test first",
                    "reason": "untested changes cause regressions",
                    "severity": "High",
                    "affected_files": ["src/main.rs"],
                    "ref_url": null,
                    "discovered_session": 0,
                    "confirmed": true
                }),
                tags: vec![], // empty — should NOT clear existing tags
                priority: "High".to_string(),
            }))
            .await;

        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed["ok"], true);

        // Verify confirmation state preserved
        let graph_arc = server.graph_arc();
        let graph = graph_arc.read().await;
        let updated = graph
            .store()
            .get("gotcha:confirmed-edit-test")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(updated.source, RecordSource::DeveloperManual);
        assert!(
            (updated.confidence.value - 0.80).abs() < 0.01,
            "confidence should stay 0.80, got {}",
            updated.confidence.value
        );
        assert_eq!(updated.confidence.confirmation_count, 1);
        assert_eq!(
            updated.tags,
            vec!["important".to_string()],
            "tags should be preserved when caller sends empty"
        );
    }

    #[tokio::test]
    async fn mem_set_moves_gotcha_links_and_edges_on_edit() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();

        // Seed file records for both old and new affected files.
        let old_file = Record::layer0_file_stub("file:src/old.rs", device_id(), 1, now());
        let new_file = Record::layer0_file_stub("file:src/new.rs", device_id(), 1, now());
        store.put("file:src/old.rs", &old_file).await.unwrap();
        store.put("file:src/new.rs", &new_file).await.unwrap();

        let graph = Graph::load(store).await.unwrap();
        let server = MatiServer::new(graph);

        server
            .mem_set(Parameters(MemSetParams {
                action: "write".to_string(),
                key: "gotcha:test-move".to_string(),
                value: "Always update the paired file because drift breaks the feature".to_string(),
                category: "Gotcha".to_string(),
                payload: serde_json::json!({
                    "rule": "Always update the paired file",
                    "reason": "drift breaks the feature",
                    "severity": "High",
                    "affected_files": ["src/old.rs"],
                    "ref_url": null,
                    "discovered_session": 0,
                    "confirmed": false
                }),
                tags: vec![],
                priority: "High".to_string(),
            }))
            .await;

        server
            .mem_set(Parameters(MemSetParams {
                action: "write".to_string(),
                key: "gotcha:test-move".to_string(),
                value: "Always update the paired file because drift breaks the feature".to_string(),
                category: "Gotcha".to_string(),
                payload: serde_json::json!({
                    "rule": "Always update the paired file",
                    "reason": "drift breaks the feature",
                    "severity": "High",
                    "affected_files": ["src/new.rs"],
                    "ref_url": null,
                    "discovered_session": 0,
                    "confirmed": false
                }),
                tags: vec![],
                priority: "High".to_string(),
            }))
            .await;

        let graph_arc = server.graph_arc();
        let graph = graph_arc.read().await;

        let old_file = graph.store().get("file:src/old.rs").await.unwrap().unwrap();
        let new_file = graph.store().get("file:src/new.rs").await.unwrap().unwrap();
        let old_payload = old_file.payload.unwrap();
        let new_payload = new_file.payload.unwrap();

        assert!(
            old_payload["gotcha_keys"]
                .as_array()
                .map(|arr| arr.is_empty())
                .unwrap_or(true),
            "old file should no longer reference moved gotcha"
        );
        assert_eq!(new_payload["gotcha_keys"][0], "gotcha:test-move");

        assert!(
            !graph
                .neighbors("file:src/old.rs", &EdgeKind::HasGotcha)
                .contains(&"gotcha:test-move".to_string()),
            "old file should not keep stale HasGotcha edge"
        );
        assert!(
            graph
                .neighbors("file:src/new.rs", &EdgeKind::HasGotcha)
                .contains(&"gotcha:test-move".to_string()),
            "new file should gain HasGotcha edge"
        );
    }

    // ── Regression: query limit clamp ───────────────────────────────────────

    /// Regression test: mem_query must clamp the limit to MAX_QUERY_LIMIT (50)
    /// even when the caller passes a larger value. Passing limit=100 must not
    /// error and must return at most 50 results.
    #[tokio::test]
    async fn test_query_limit_clamped_to_max() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();

        // Insert 60 records — more than MAX_QUERY_LIMIT (50).
        for i in 0..60 {
            let record = make_record(
                &format!("gotcha:clamp-test-{i:03}"),
                &format!("clamp test rule number {i}"),
                Category::Gotcha,
                0.8,
            );
            store
                .put(&format!("gotcha:clamp-test-{i:03}"), &record)
                .await
                .unwrap();
        }

        let graph = Graph::load(store).await.unwrap();
        let server = MatiServer::new(graph);

        let result = server
            .mem_query(Parameters(MemQueryParams {
                query: "clamp test rule".to_string(),
                mode: "text".to_string(),
                limit: 100, // exceeds MAX_QUERY_LIMIT (50)
            }))
            .await;

        // Must not error
        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert!(
            parsed.get("error").is_none(),
            "query with limit > 50 must not error"
        );

        // Must return at most 50 results (the clamped limit)
        let results = parsed.as_array().expect("result should be a JSON array");
        assert!(
            results.len() <= 50,
            "result count {} exceeds MAX_QUERY_LIMIT (50)",
            results.len()
        );
    }

    // ── Regression: store-read-error refusal on mem_set write ───────────────

    /// Regression test: mem_set write to a new key must succeed (proving the
    /// Ok(None) arm of the store read works). The Err(e) arm returns
    /// {"error": "store read failed — refusing to write: ..."} but cannot be
    /// triggered without injecting a store fault, which the test harness does
    /// not support. This test validates the happy path; the error format is
    /// documented here for grep-ability.
    #[tokio::test]
    async fn test_mem_set_write_new_key_succeeds() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();
        let graph = Graph::load(store).await.unwrap();
        let server = MatiServer::new(graph);

        let result = server
            .mem_set(Parameters(MemSetParams {
                action: "write".to_string(),
                key: "file:src/brand_new.rs".to_string(),
                value: "Brand new module for regression test".to_string(),
                category: "File".to_string(),
                payload: serde_json::json!({
                    "path": "src/brand_new.rs",
                    "purpose": "Brand new module for regression test"
                }),
                tags: vec![],
                priority: "Normal".to_string(),
            }))
            .await;

        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(
            parsed["ok"], true,
            "writing a new key must succeed (Ok(None) arm)"
        );
        assert_eq!(parsed["key"], "file:src/brand_new.rs");

        // Verify record persisted
        let graph_arc = server.graph_arc();
        let graph = graph_arc.read().await;
        let record = graph
            .store()
            .get("file:src/brand_new.rs")
            .await
            .unwrap()
            .expect("record must exist after write");
        assert_eq!(record.value, "Brand new module for regression test");

        // Note: the Err(e) path (store read failure) returns:
        //   {"error": "store read failed — refusing to write: <details>"}
        // This cannot be exercised without a store-fault injection mechanism.
        // The guard exists at tools.rs line ~605 to prevent blind overwrites
        // when the store is in a degraded state.
    }

    // ── Regression: in-memory graph cleanup after tombstone ─────────────────

    /// Regression test: after deleting a gotcha via mem_set action="delete",
    /// the in-memory graph must no longer contain HasGotcha edges pointing to
    /// the deleted gotcha. Previously, only the store was cleaned up but the
    /// in-memory petgraph retained stale edges until process restart.
    #[tokio::test]
    async fn test_tombstone_removes_in_memory_graph_edges() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();

        // Seed file record
        let file_record = Record::layer0_file_stub("file:src/target.rs", device_id(), 1, now());
        store.put("file:src/target.rs", &file_record).await.unwrap();

        let graph = Graph::load(store).await.unwrap();
        let server = MatiServer::new(graph);

        // Step 1: Write a gotcha linked to the file via affected_files.
        let write_result = server
            .mem_set(Parameters(MemSetParams {
                action: "write".to_string(),
                key: "gotcha:graph-cleanup-test".to_string(),
                value: "Never skip validation because it causes silent data corruption".to_string(),
                category: "Gotcha".to_string(),
                payload: serde_json::json!({
                    "rule": "Never skip validation",
                    "reason": "causes silent data corruption",
                    "severity": "High",
                    "affected_files": ["src/target.rs"],
                    "ref_url": null,
                    "discovered_session": 0,
                    "confirmed": false
                }),
                tags: vec![],
                priority: "High".to_string(),
            }))
            .await;
        let parsed: serde_json::Value = serde_json::from_str(&write_result).unwrap();
        assert_eq!(parsed["ok"], true, "gotcha write must succeed");

        // Step 2: Verify the in-memory graph has the HasGotcha edge.
        {
            let graph_arc = server.graph_arc();
            let graph = graph_arc.read().await;
            let neighbors = graph.neighbors("file:src/target.rs", &EdgeKind::HasGotcha);
            assert!(
                neighbors.contains(&"gotcha:graph-cleanup-test".to_string()),
                "HasGotcha edge must exist after write; neighbors: {neighbors:?}"
            );
        }

        // Step 3: Delete the gotcha.
        let delete_result = server
            .mem_set(Parameters(MemSetParams {
                action: "delete".to_string(),
                key: "gotcha:graph-cleanup-test".to_string(),
                value: String::new(),
                category: String::new(),
                payload: serde_json::json!({}),
                tags: vec![],
                priority: "Normal".to_string(),
            }))
            .await;
        let parsed: serde_json::Value = serde_json::from_str(&delete_result).unwrap();
        assert_eq!(parsed["ok"], true, "gotcha delete must succeed");
        assert_eq!(parsed["tombstoned"], true);

        // Step 4: Verify the in-memory graph no longer has the HasGotcha edge.
        {
            let graph_arc = server.graph_arc();
            let graph = graph_arc.read().await;
            let neighbors = graph.neighbors("file:src/target.rs", &EdgeKind::HasGotcha);
            assert!(
                !neighbors.contains(&"gotcha:graph-cleanup-test".to_string()),
                "HasGotcha edge must be removed after delete; neighbors: {neighbors:?}"
            );
        }

        // Also verify via graph query mode that the gotcha no longer appears.
        let graph_query_result = server
            .mem_query(Parameters(MemQueryParams {
                query: "file:src/target.rs".to_string(),
                mode: "graph".to_string(),
                limit: 20,
            }))
            .await;
        let parsed: serde_json::Value = serde_json::from_str(&graph_query_result).unwrap();
        let gotchas = parsed["gotchas"]
            .as_array()
            .expect("gotchas group must be an array");
        assert!(
            !gotchas
                .iter()
                .any(|g| g["key"] == "gotcha:graph-cleanup-test"),
            "deleted gotcha must not appear in graph query results"
        );
    }

    // ── Regression: graph mode respects global limit ──────────────────────

    /// Graph mode must respect the caller's `limit` as a global cap across all
    /// edge groups. With limit=3 and records in multiple groups, total results
    /// must not exceed 3.
    #[tokio::test]
    async fn test_graph_mode_respects_global_limit() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();

        // Seed file record
        let file_record =
            Record::layer0_file_stub("file:src/graph_limit.rs", device_id(), 1, now());
        store
            .put("file:src/graph_limit.rs", &file_record)
            .await
            .unwrap();

        let graph = Graph::load(store).await.unwrap();
        let server = MatiServer::new(graph);

        // Write 5 gotchas linked to the file
        for i in 0..5 {
            let result = server
                .mem_set(Parameters(MemSetParams {
                    action: "write".to_string(),
                    key: format!("gotcha:limit-test-{i}"),
                    value: format!("Limit test gotcha {i}"),
                    category: "Gotcha".to_string(),
                    payload: serde_json::json!({
                        "rule": format!("Limit rule {i}"),
                        "reason": "testing",
                        "severity": "Normal",
                        "affected_files": ["src/graph_limit.rs"],
                        "ref_url": null,
                        "discovered_session": 0,
                        "confirmed": false
                    }),
                    tags: vec![],
                    priority: "Normal".to_string(),
                }))
                .await;
            let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
            assert_eq!(parsed["ok"], true, "gotcha write {i} must succeed");
        }

        // Query with limit=3 — must get at most 3 total records across all groups.
        let result = server
            .mem_query(Parameters(MemQueryParams {
                query: "file:src/graph_limit.rs".to_string(),
                mode: "graph".to_string(),
                limit: 3,
            }))
            .await;
        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert!(parsed.get("error").is_none(), "graph query must not error");

        // Count total records across all groups.
        let mut total = 0;
        for group in &["gotchas", "co_changes", "imports", "decisions", "notes"] {
            if let Some(arr) = parsed[group].as_array() {
                total += arr.len();
            }
        }
        assert!(
            total <= 3,
            "graph mode with limit=3 must return at most 3 total records, got {total}"
        );
    }

    /// Graph mode with limit=0 must return zero records in all groups.
    #[tokio::test]
    async fn test_graph_mode_limit_zero_returns_empty() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();

        let file_record = Record::layer0_file_stub("file:src/zero.rs", device_id(), 1, now());
        store.put("file:src/zero.rs", &file_record).await.unwrap();

        let graph = Graph::load(store).await.unwrap();
        let server = MatiServer::new(graph);

        // Write one gotcha so there's something to return if limit is ignored.
        let _ = server
            .mem_set(Parameters(MemSetParams {
                action: "write".to_string(),
                key: "gotcha:zero-limit-test".to_string(),
                value: "Should not appear".to_string(),
                category: "Gotcha".to_string(),
                payload: serde_json::json!({
                    "rule": "Zero limit test",
                    "reason": "testing",
                    "severity": "Normal",
                    "affected_files": ["src/zero.rs"],
                    "ref_url": null,
                    "discovered_session": 0,
                    "confirmed": false
                }),
                tags: vec![],
                priority: "Normal".to_string(),
            }))
            .await;

        let result = server
            .mem_query(Parameters(MemQueryParams {
                query: "file:src/zero.rs".to_string(),
                mode: "graph".to_string(),
                limit: 0,
            }))
            .await;
        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();

        let mut total = 0;
        for group in &["gotchas", "co_changes", "imports", "decisions", "notes"] {
            if let Some(arr) = parsed[group].as_array() {
                total += arr.len();
            }
        }
        assert_eq!(total, 0, "limit=0 must return zero records, got {total}");
    }

    // ── Regression: mem_set preserves existing data on overwrite ──────────

    /// When overwriting an existing record, mem_set must read and preserve
    /// Layer 0 structural data from the prior record. This is the exact
    /// scenario that `.ok().flatten()` would have broken: a store error would
    /// have made mem_set treat the record as new, losing preservation behavior.
    #[tokio::test]
    async fn test_mem_set_overwrite_preserves_existing_data() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();

        // Seed a DeveloperManual record with high confidence.
        let mut original = make_record(
            "file:src/preserve.rs",
            "Original purpose from Layer 0",
            Category::File,
            0.7,
        );
        original.source = RecordSource::DeveloperManual;
        original.confidence.value = 0.85;
        original.confidence.confirmation_count = 3;
        store.put("file:src/preserve.rs", &original).await.unwrap();

        let graph = Graph::load(store).await.unwrap();
        let server = MatiServer::new(graph);

        // Overwrite with mem_set — should preserve confirmation state.
        let result = server
            .mem_set(Parameters(MemSetParams {
                action: "write".to_string(),
                key: "file:src/preserve.rs".to_string(),
                value: "Updated purpose from enrichment".to_string(),
                category: "File".to_string(),
                payload: serde_json::json!({"path": "src/preserve.rs"}),
                tags: vec![],
                priority: "Normal".to_string(),
            }))
            .await;
        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed["ok"], true, "overwrite must succeed");

        // Verify the record was updated but preserved confirmation state.
        let graph_arc = server.graph_arc();
        let graph = graph_arc.read().await;
        let record = graph
            .store()
            .get("file:src/preserve.rs")
            .await
            .unwrap()
            .expect("record must exist");
        assert_eq!(
            record.value, "Updated purpose from enrichment",
            "value must be updated"
        );
        // DeveloperManual source + high confidence should be preserved
        // because the write path detects was_confirmed=true.
        assert!(
            record.confidence.value >= 0.80,
            "confirmed record confidence must be preserved, got {}",
            record.confidence.value
        );
    }

    // ── Regression: tombstone multi-file gotcha cleans all edges ──────────

    /// When a gotcha affects multiple files, tombstone must remove in-memory
    /// HasGotcha edges from ALL affected files, not just the first.
    #[tokio::test]
    async fn test_tombstone_multi_file_removes_all_edges() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();

        // Seed two file records
        let f1 = Record::layer0_file_stub("file:src/a.rs", device_id(), 1, now());
        let f2 = Record::layer0_file_stub("file:src/b.rs", device_id(), 1, now());
        store.put("file:src/a.rs", &f1).await.unwrap();
        store.put("file:src/b.rs", &f2).await.unwrap();

        let graph = Graph::load(store).await.unwrap();
        let server = MatiServer::new(graph);

        // Write a gotcha affecting both files
        let result = server
            .mem_set(Parameters(MemSetParams {
                action: "write".to_string(),
                key: "gotcha:multi-file-tombstone".to_string(),
                value: "Cross-file gotcha".to_string(),
                category: "Gotcha".to_string(),
                payload: serde_json::json!({
                    "rule": "Cross-file rule",
                    "reason": "testing multi-file cleanup",
                    "severity": "Normal",
                    "affected_files": ["src/a.rs", "src/b.rs"],
                    "ref_url": null,
                    "discovered_session": 0,
                    "confirmed": false
                }),
                tags: vec![],
                priority: "Normal".to_string(),
            }))
            .await;
        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed["ok"], true);

        // Verify both files have the edge
        {
            let g = server.graph_arc();
            let graph = g.read().await;
            assert!(
                graph
                    .neighbors("file:src/a.rs", &EdgeKind::HasGotcha)
                    .contains(&"gotcha:multi-file-tombstone".to_string()),
                "file:src/a.rs must have HasGotcha edge before delete"
            );
            assert!(
                graph
                    .neighbors("file:src/b.rs", &EdgeKind::HasGotcha)
                    .contains(&"gotcha:multi-file-tombstone".to_string()),
                "file:src/b.rs must have HasGotcha edge before delete"
            );
        }

        // Delete the gotcha
        let result = server
            .mem_set(Parameters(MemSetParams {
                action: "delete".to_string(),
                key: "gotcha:multi-file-tombstone".to_string(),
                value: String::new(),
                category: String::new(),
                payload: serde_json::json!({}),
                tags: vec![],
                priority: "Normal".to_string(),
            }))
            .await;
        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed["ok"], true);

        // Verify BOTH files lost the edge
        {
            let g = server.graph_arc();
            let graph = g.read().await;
            assert!(
                !graph
                    .neighbors("file:src/a.rs", &EdgeKind::HasGotcha)
                    .contains(&"gotcha:multi-file-tombstone".to_string()),
                "file:src/a.rs must NOT have HasGotcha edge after delete"
            );
            assert!(
                !graph
                    .neighbors("file:src/b.rs", &EdgeKind::HasGotcha)
                    .contains(&"gotcha:multi-file-tombstone".to_string()),
                "file:src/b.rs must NOT have HasGotcha edge after delete"
            );
        }
    }

    // ── Regression: confirm is non-idempotent ────────────────────────────

    /// Calling confirm twice must increment confirmation_count each time,
    /// proving `idempotent_hint = false` is correct for mem_set.
    #[tokio::test]
    async fn test_confirm_is_non_idempotent() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();

        let file_record = Record::layer0_file_stub("file:src/idem.rs", device_id(), 1, now());
        store.put("file:src/idem.rs", &file_record).await.unwrap();

        let graph = Graph::load(store).await.unwrap();
        let server = MatiServer::new(graph);

        // Write an unconfirmed gotcha
        let _ = server
            .mem_set(Parameters(MemSetParams {
                action: "write".to_string(),
                key: "gotcha:idem-test".to_string(),
                value: "Idempotency test rule".to_string(),
                category: "Gotcha".to_string(),
                payload: serde_json::json!({
                    "rule": "Idempotency test",
                    "reason": "testing",
                    "severity": "Normal",
                    "affected_files": ["src/idem.rs"],
                    "ref_url": null,
                    "discovered_session": 0,
                    "confirmed": false
                }),
                tags: vec![],
                priority: "Normal".to_string(),
            }))
            .await;

        // First confirm
        let r1 = server
            .mem_set(Parameters(MemSetParams {
                action: "confirm".to_string(),
                key: "gotcha:idem-test".to_string(),
                value: String::new(),
                category: String::new(),
                payload: serde_json::json!({}),
                tags: vec![],
                priority: "Normal".to_string(),
            }))
            .await;
        let p1: serde_json::Value = serde_json::from_str(&r1).unwrap();
        assert_eq!(p1["ok"], true, "first confirm must succeed");
        assert_eq!(p1["confirmed"], true);

        // Read confirmation_count after first confirm
        let count_after_first = {
            let g = server.graph_arc();
            let graph = g.read().await;
            let record = graph
                .store()
                .get("gotcha:idem-test")
                .await
                .unwrap()
                .unwrap();
            record.confidence.confirmation_count
        };

        // Second confirm
        let r2 = server
            .mem_set(Parameters(MemSetParams {
                action: "confirm".to_string(),
                key: "gotcha:idem-test".to_string(),
                value: String::new(),
                category: String::new(),
                payload: serde_json::json!({}),
                tags: vec![],
                priority: "Normal".to_string(),
            }))
            .await;
        let p2: serde_json::Value = serde_json::from_str(&r2).unwrap();
        assert_eq!(p2["ok"], true, "second confirm must succeed");

        // Read confirmation_count after second confirm
        let count_after_second = {
            let g = server.graph_arc();
            let graph = g.read().await;
            let record = graph
                .store()
                .get("gotcha:idem-test")
                .await
                .unwrap()
                .unwrap();
            record.confidence.confirmation_count
        };

        assert!(
            count_after_second > count_after_first,
            "confirmation_count must increase on each confirm: first={count_after_first}, second={count_after_second}"
        );
    }

    // ── Regression: store-read-error refusal (extracted helper) ───────────

    /// The Err(e) branch must return a structured JSON error and refuse to write.
    /// Previously untestable because it required a real store failure.
    #[test]
    fn test_store_read_error_refuses_write() {
        let result = resolve_existing_for_write(Err(anyhow::anyhow!("simulated disk I/O timeout")));
        assert!(result.is_err(), "store error must refuse write");
        let err = result.unwrap_err();
        let parsed: serde_json::Value = serde_json::from_str(&err).unwrap();
        assert!(
            parsed["error"]
                .as_str()
                .unwrap()
                .contains("store read failed"),
            "error must mention store read failure"
        );
        assert!(
            parsed["error"]
                .as_str()
                .unwrap()
                .contains("simulated disk I/O timeout"),
            "error must include the underlying cause"
        );
    }

    /// Ok(None) must pass through — new record, no existing data to preserve.
    #[test]
    fn test_store_read_ok_none_passes_through() {
        let result = resolve_existing_for_write(Ok(None));
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    /// Ok(Some(record)) must pass through — existing record for preservation.
    #[test]
    fn test_store_read_ok_some_passes_through() {
        let record = make_record("file:test.rs", "test", Category::File, 0.5);
        let result = resolve_existing_for_write(Ok(Some(record.clone())));
        assert!(result.is_ok());
        let resolved = result.unwrap();
        assert!(resolved.is_some());
        assert_eq!(resolved.unwrap().key, "file:test.rs");
    }

    #[tokio::test]
    async fn bootstrap_highest_impact_section_appears() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();

        // Create a critical-blast-radius file record
        let fr_critical = FileRecord {
            path: "src/core.rs".to_string(),
            purpose: "Core module".to_string(),
            entry_points: vec![],
            imports: vec![],
            gotcha_keys: vec![],
            decision_keys: vec![],
            todos: vec![],
            unsafe_count: 0,
            unwrap_count: 0,
            change_frequency: 0,
            last_author: None,
            is_hotspot: false,
            token_cost_estimate: 100,
            last_modified_session: 0,
            content_hash: None,
            line_count: 0,
            blast_radius: Some(crate::analysis::blast_radius::BlastRadius {
                direct: 45,
                transitive: 10,
                score: 48.0,
                tier: crate::analysis::blast_radius::BlastTier::Critical,
            }),
        };
        let mut rec = make_record("file:src/core.rs", "Core module", Category::File, 0.5);
        rec.payload = serde_json::to_value(&fr_critical).ok();
        store.put("file:src/core.rs", &rec).await.unwrap();

        // Create a low-blast-radius file record
        let fr_low = FileRecord {
            path: "src/leaf.rs".to_string(),
            purpose: "Leaf module".to_string(),
            entry_points: vec![],
            imports: vec![],
            gotcha_keys: vec![],
            decision_keys: vec![],
            todos: vec![],
            unsafe_count: 0,
            unwrap_count: 0,
            change_frequency: 0,
            last_author: None,
            is_hotspot: false,
            token_cost_estimate: 100,
            last_modified_session: 0,
            content_hash: None,
            line_count: 0,
            blast_radius: Some(crate::analysis::blast_radius::BlastRadius {
                direct: 3,
                transitive: 0,
                score: 3.0,
                tier: crate::analysis::blast_radius::BlastTier::Low,
            }),
        };
        let mut rec2 = make_record("file:src/leaf.rs", "Leaf module", Category::File, 0.5);
        rec2.payload = serde_json::to_value(&fr_low).ok();
        store.put("file:src/leaf.rs", &rec2).await.unwrap();

        let graph = Graph::load(store).await.unwrap();
        let packet = assemble_context_packet(
            graph.store(),
            &graph,
            &["src/core.rs".to_string(), "src/leaf.rs".to_string()],
        )
        .await
        .unwrap();

        assert!(
            packet.injection_string.contains("Highest Impact"),
            "bootstrap must include highest impact section, got: {}",
            packet.injection_string
        );
        assert!(
            packet.injection_string.contains("src/core.rs"),
            "critical file must appear in impact section"
        );
        // core.rs (score 48) should appear before leaf.rs (score 3)
        let core_pos = packet.injection_string.find("src/core.rs").unwrap();
        let leaf_pos = packet.injection_string.find("src/leaf.rs").unwrap_or(usize::MAX);
        assert!(
            core_pos < leaf_pos,
            "core.rs should appear before leaf.rs in impact section"
        );
    }
}
