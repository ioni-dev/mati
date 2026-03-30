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
const VECTOR_B: &str = "\n\n[mati] Before reading any file: call mem_get(\"file:<path>\").\n\
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
fn record_to_agent_json(record: &Record) -> serde_json::Value {
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
                        // Tombstoned records should appear as "not found" to agents.
                        if matches!(record.lifecycle, RecordLifecycle::Tombstoned { .. }) {
                            return "null".to_string();
                        }
                        // M-12-B: bump access_count on every MCP hit (mirrors mati log-hit hook path).
                        record.access_count += 1;
                        // Do NOT recompute confidence here. Confidence recomputation belongs in
                        // the health pipeline (mati stats / mati stale), not on every read.
                        // Writing back a formula-derived value would override confidence values
                        // intentionally bumped by mati init (e.g. co-change quality bump sets
                        // confidence=0.45 so pre-read hooks surface additionalContext).
                        // Best-effort write-back; don't fail the read on write error.
                        let _ = store.put(&params.key, &record).await;
                        // Write session:consulted marker so pre-read/pre-bash hooks know this key
                        // was looked up via MCP and can downgrade deny → allow+context on next access.
                        let _ = crate::store::session::log_hit(store, &params.key).await;
                        serde_json::to_string_pretty(&record_to_agent_json(&record))
                            .unwrap_or_else(|e| {
                                format!("{{\"error\": \"serialization failed: {e}\"}}")
                            })
                    }
                    Ok(None) => "null".to_string(),
                    Err(e) => format!("{{\"error\": \"{e}\"}}"),
                }
            }
            MatiBackend::Socket { .. } => self.socket_call("mem_get", json!({ "key": params.key })).await,
        }
    }

    /// Search the knowledge store using BM25 text search or graph traversal.
    ///
    /// Modes: "text" (default) for full-text BM25, "graph" for 1-hop traversal.
    /// Text mode returns a JSON array. Graph mode returns a grouped JSON object.
    #[rmcp::tool(
        name = "mem_query",
        description = "Search the mati knowledge store. Use mode \"text\" for BM25 full-text search or mode \"graph\" for a 1-hop traversal from a seed key.",
        annotations(read_only_hint = true)
    )]
    pub(crate) async fn mem_query(
        &self,
        Parameters(params): Parameters<MemQueryParams>,
    ) -> String {
        match &self.backend {
            MatiBackend::Direct(graph_arc) => {
                let mode = params.mode.as_str();
                let limit = params.limit;

                match mode {
                    "text" => {
                        let graph = graph_arc.read().await;
                        let store = graph.store();
                        match store.search(&params.query, limit).await {
                    Ok(mut records) => {
                        records.retain(|r| matches!(r.lifecycle, RecordLifecycle::Active));
                        let stripped: Vec<serde_json::Value> =
                            records.iter().map(record_to_agent_json).collect();
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

                for (kind, group_name, group_limit) in edge_groups {
                    let keys = graph.neighbors(&params.query, kind);
                    let mut group_records = Vec::new();

                    for key in keys.iter().take(*group_limit) {
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
                    result.insert(
                        group_name.to_string(),
                        serde_json::Value::Array(group_records),
                    );
                }

                // DependencyAffects — add to decisions group
                let dep_keys = graph.neighbors(&params.query, &EdgeKind::DependencyAffects);
                for key in dep_keys.iter().take(DECISION_LIMIT) {
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
                                }
                            }
                        }
                    }
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
                    "semantic" => {
                        "{\"error\": \"semantic search requires --features semantic (not enabled)\"}"
                            .to_string()
                    }
                    _ => {
                        format!(
                            "{{\"error\": \"unknown mode: {mode}. Valid modes: text, graph, semantic\"}}"
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
                self.socket_call("mem_bootstrap", json!({ "context_files": params.context_files }))
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
        annotations(read_only_hint = false, destructive_hint = false, idempotent_hint = true)
    )]
    pub(crate) async fn mem_set(&self, Parameters(params): Parameters<MemSetParams>) -> String {
        match &self.backend {
            MatiBackend::Direct(graph_arc) => {
                // Dispatch on action before the default write path.
                match params.action.as_str() {
                    "confirm" => {
                        return self
                            .mem_set_confirm(graph_arc, &params.key)
                            .await;
                    }
                    "delete" => {
                        return self
                            .mem_set_delete(graph_arc, &params.key)
                            .await;
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
        let existing_record = store.get(&params.key).await.ok().flatten();

        let was_confirmed = existing_record
            .as_ref()
            .map(|r| r.source == RecordSource::DeveloperManual || r.confidence.value >= 0.80)
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
            record.confidence = ConfidenceScore::for_new_record(&RecordSource::ClaudeEnrich);
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
        if new_payload.is_object() && !new_payload.as_object().map_or(true, |o| o.is_empty()) {
            if let Some(existing_payload) = &record.payload {
                // Merge: new values override, existing keys preserved
                let mut merged = existing_payload.clone();
                if let (Some(base), Some(overlay)) =
                    (merged.as_object_mut(), new_payload.as_object())
                {
                    for (k, v) in overlay {
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
            record.confidence = ConfidenceScore::for_new_record(&RecordSource::ClaudeEnrich);
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
        let new_affected_set: HashSet<&str> = affected_files.iter().map(String::as_str).collect();

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
                    tracing::warn!("mem_set: edge add failed for {file_key} → {record_key}: {e}");
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
        let graph = graph_arc.read().await;
        let store = graph.store();

        if !key.starts_with("gotcha:") {
            return json!({"error": "confirm action only applies to gotcha: keys"}).to_string();
        }

        let mut record = match store.get(key).await {
            Ok(Some(r)) => r,
            Ok(None) => return json!({"error": format!("record not found: {key}")}).to_string(),
            Err(e) => return json!({"error": format!("store get: {e}")}).to_string(),
        };

        if record.category != Category::Gotcha {
            return json!({"error": format!("{key} is not a gotcha record")}).to_string();
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
                obj.insert(
                    "confirmed".to_string(),
                    serde_json::Value::Bool(true),
                );
            }
        }

        record.source = RecordSource::DeveloperManual;
        record.confidence.value =
            ConfidenceScore::base_for_source(&RecordSource::DeveloperManual);
        record.confidence.confirmation_count += 1;
        record.quality = quality::analyze(&record);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        record.updated_at = now;
        record.version.logical_clock += 1;
        record.version.wall_clock = now;

        // Extract affected_files for file-link sync
        let affected_files: Vec<String> = record
            .payload_as::<GotchaRecord>()
            .map(|g| g.affected_files)
            .unwrap_or_default();

        if let Err(e) = store.put(key, &record).await {
            return json!({"error": format!("store put: {e}")}).to_string();
        }

        // Sync file:*.gotcha_keys — best-effort
        for file_path in &affected_files {
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
                            let arr = obj
                                .entry("gotcha_keys")
                                .or_insert(serde_json::json!([]));
                            if let Some(arr) = arr.as_array_mut() {
                                arr.push(serde_json::Value::String(key.to_string()));
                            }
                        }
                    }
                    let _ = store.put(&file_key, &file_record).await;
                }
            }
        }

        // Mint consultation receipt so hooks know this file was reviewed
        let _ = crate::store::session::log_hit(store, key).await;

        json!({
            "ok": true,
            "key": key,
            "confirmed": true,
            "confidence": record.confidence.value,
            "quality": record.quality.value,
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
        let graph = graph_arc.read().await;
        let store = graph.store();

        if !key.starts_with("gotcha:") {
            return json!({"error": "delete action only applies to gotcha: keys"}).to_string();
        }

        let record = match store.get(key).await {
            Ok(Some(r)) => r,
            Ok(None) => return json!({"error": format!("record not found: {key}")}).to_string(),
            Err(e) => return json!({"error": format!("store get: {e}")}).to_string(),
        };

        let affected_files: Vec<String> = record
            .payload_as::<GotchaRecord>()
            .map(|g| g.affected_files)
            .unwrap_or_default();

        match crate::store::gotcha_ops::apply_gotcha_tombstone(store, key, &affected_files).await {
            Ok(()) => json!({"ok": true, "key": key, "tombstoned": true}).to_string(),
            Err(e) => json!({"error": format!("tombstone failed: {e}")}).to_string(),
        }
    }
}

/// Assemble a [`ContextPacket`] from the store and graph.
///
/// Steps:
/// 1. Fetch `stage:current`
/// 2. Scan `gotcha:*`, filter confirmed + quality >= 0.4
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

    // 2. Scan all gotchas, filter confirmed + quality >= 0.4, exclude tombstones
    let all_gotchas = store.scan_prefix("gotcha:").await?;
    let mut confirmed_gotchas: Vec<Record> = all_gotchas
        .into_iter()
        .filter(|r| {
            // Exclude tombstoned records
            if !matches!(r.lifecycle, RecordLifecycle::Active) {
                return false;
            }
            // Exclude tombstone-tier staleness
            if r.staleness.tier == StalenessTier::Tombstone {
                return false;
            }
            // Check confirmed flag from structured payload
            if let Some(gotcha) = r.payload_as::<GotchaRecord>() {
                gotcha.confirmed && r.quality.value >= 0.4
            } else {
                // No payload or unparseable — exclude
                false
            }
        })
        .collect();

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

    // Fetch decision records
    let mut related_decisions = Vec::new();
    for key in &decision_keys {
        if let Ok(Some(record)) = store.get(key).await {
            related_decisions.push(record);
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

    // 5. Context filter + quality filter:
    //    - when context_files are provided, only inject graph-reachable gotchas
    //    - when context_files are empty, preserve the global bootstrap behavior
    //    - always exclude Suppressed (<0.2), caveat Poor (0.2–0.4)
    let critical_gotchas: Vec<Record> = confirmed_gotchas
        .into_iter()
        .filter(|r| context_files.is_empty() || context_gotcha_keys.contains(&r.key))
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
            .mem_set(Parameters(MemSetParams { action: "write".to_string(),
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
            .mem_set(Parameters(MemSetParams { action: "write".to_string(),
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
            .mem_set(Parameters(MemSetParams { action: "write".to_string(),
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
            .mem_set(Parameters(MemSetParams { action: "write".to_string(),
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
            .mem_set(Parameters(MemSetParams { action: "write".to_string(),
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
            .mem_set(Parameters(MemSetParams { action: "write".to_string(),
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
            .mem_set(Parameters(MemSetParams { action: "write".to_string(),
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
}
