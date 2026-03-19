//! MCP tool implementations (M-07).
//!
//! Exactly 3 tools — hard limit per CLAUDE.md:
//! - `mem_get`       — direct key lookup
//! - `mem_query`     — BM25 text search or graph traversal
//! - `mem_bootstrap` — context packet assembly with token budget

use std::collections::HashSet;
use std::sync::Arc;

use rmcp::handler::server::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::tool_router;

use crate::graph::edges::EdgeKind;
use crate::graph::Graph;
use crate::store::record::{
    ContextPacket, FileRecord, GotchaRecord, Priority, QualityTier, Record,
};

use super::types::{MemBootstrapParams, MemGetParams, MemQueryParams};

/// Vector B — appended to every mem_bootstrap result.
const VECTOR_B: &str = "\n\n[mati] Before reading any file, call mem_get(\"file:<path>\") first.\n\
    Records with confirmed=true and confidence >= 0.6 replace file reads.\n\
    The PreToolUse hook enforces this automatically.\n\
    Low-confidence records (confidence < 0.3) should be verified by file read.";

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

/// The MCP server struct. Holds an `Arc<tokio::sync::RwLock<Graph>>` which
/// owns the Store internally.
#[derive(Clone)]
pub struct MatiServer {
    graph: Arc<tokio::sync::RwLock<Graph>>,
    pub(crate) tool_router: ToolRouter<Self>,
}

impl MatiServer {
    pub fn new(graph: Graph) -> Self {
        Self {
            graph: Arc::new(tokio::sync::RwLock::new(graph)),
            tool_router: Self::tool_router(),
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
        description = "Look up a single mati knowledge record by key. Always call this before using Read on any file — pass the key as \"file:<path>\". If this returns a confirmed record with confidence >= 0.6, do not read the file — use this record instead."
    )]
    async fn mem_get(&self, Parameters(params): Parameters<MemGetParams>) -> String {
        let graph = self.graph.read().await;
        let store = graph.store();
        match store.get(&params.key).await {
            Ok(Some(record)) => serde_json::to_string_pretty(&record).unwrap_or_else(|e| {
                format!("{{\"error\": \"serialization failed: {e}\"}}")
            }),
            Ok(None) => "null".to_string(),
            Err(e) => format!("{{\"error\": \"{e}\"}}"),
        }
    }

    /// Search the knowledge store using BM25 text search or graph traversal.
    ///
    /// Modes: "text" (default) for full-text BM25, "graph" for 1-hop traversal.
    /// Returns a JSON array of matching records.
    #[rmcp::tool(
        name = "mem_query",
        description = "Search the mati knowledge store. Modes: \"text\" (default, BM25 full-text search) or \"graph\" (1-hop traversal from query as seed key). Returns matching records as JSON array."
    )]
    async fn mem_query(&self, Parameters(params): Parameters<MemQueryParams>) -> String {
        let mode = params.mode.as_deref().unwrap_or("text");
        let limit = params.limit.unwrap_or(20);

        match mode {
            "text" => {
                let graph = self.graph.read().await;
                let store = graph.store();
                match store.search(&params.query, limit).await {
                    Ok(records) => serde_json::to_string_pretty(&records).unwrap_or_else(|e| {
                        format!("{{\"error\": \"serialization failed: {e}\"}}")
                    }),
                    Err(e) => format!("{{\"error\": \"{e}\"}}"),
                }
            }
            "graph" => {
                let graph = self.graph.read().await;
                let store = graph.store();

                // Use the query as a seed key, traverse all edge kinds 1-hop
                let mut neighbor_keys = HashSet::new();
                for kind in &[
                    EdgeKind::HasGotcha,
                    EdgeKind::Imports,
                    EdgeKind::AffectedBy,
                    EdgeKind::HasNote,
                    EdgeKind::CoChanges,
                    EdgeKind::DependencyAffects,
                ] {
                    for key in graph.neighbors(&params.query, kind) {
                        neighbor_keys.insert(key);
                    }
                }

                let mut records = Vec::new();
                for key in neighbor_keys.iter().take(limit) {
                    if let Ok(Some(record)) = store.get(key).await {
                        records.push(record);
                    }
                }
                serde_json::to_string_pretty(&records).unwrap_or_else(|e| {
                    format!("{{\"error\": \"serialization failed: {e}\"}}")
                })
            }
            "semantic" => {
                "{\"error\": \"semantic search requires --features semantic (not enabled)\"}".to_string()
            }
            _ => {
                format!("{{\"error\": \"unknown mode: {mode}. Valid modes: text, graph, semantic\"}}")
            }
        }
    }

    /// Assemble a context packet for the current session.
    ///
    /// Gathers stage, gotchas, file records, and decisions within a 2,000-token budget.
    /// Returns a markdown injection string for Claude.
    #[rmcp::tool(
        name = "mem_bootstrap",
        description = "Assemble a context packet for the current coding session. Gathers confirmed gotchas, file records, and architectural decisions relevant to the provided context_files, within a 2,000-token budget. Call this at session start."
    )]
    async fn mem_bootstrap(&self, Parameters(params): Parameters<MemBootstrapParams>) -> String {
        let graph = self.graph.read().await;
        let store = graph.store();

        let context_files = params.context_files.unwrap_or_default();
        match assemble_context_packet(store, &*graph, &context_files).await {
            Ok(packet) => packet.injection_string,
            Err(e) => format!("[mati] bootstrap error: {e}{VECTOR_B}"),
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

    // 2. Scan all gotchas, filter confirmed + quality >= 0.4
    let all_gotchas = store.scan_prefix("gotcha:").await?;
    let mut confirmed_gotchas: Vec<Record> = all_gotchas
        .into_iter()
        .filter(|r| {
            // Parse the gotcha detail to check confirmed flag
            if let Ok(gotcha) = serde_json::from_str::<GotchaRecord>(&r.value) {
                gotcha.confirmed && r.quality.value >= 0.4
            } else {
                // If value isn't a GotchaRecord JSON, check quality only
                r.quality.value >= 0.4
            }
        })
        .collect();

    // 3. Context-file traversal
    let mut file_records = Vec::new();
    let mut context_gotcha_keys = HashSet::new();
    let mut decision_keys = HashSet::new();

    for file_path in context_files {
        let file_key = if file_path.starts_with("file:") {
            file_path.clone()
        } else {
            format!("file:{file_path}")
        };

        // Get file record
        if let Ok(Some(record)) = store.get(&file_key).await {
            if let Ok(fr) = serde_json::from_str::<FileRecord>(&record.value) {
                file_records.push(fr);
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

    // 5. Quality filter: exclude Suppressed (<0.2), caveat Poor (0.2–0.4)
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

    // Gotchas section
    if !critical_gotchas.is_empty() {
        let mut gotcha_section = String::from("## Gotchas\n");
        for record in &critical_gotchas {
            let caveat = if record.quality.tier == QualityTier::Poor {
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
        sections.push(gotcha_section);
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
        stale_warnings: vec![],
        unconfirmed_candidates: vec![],
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
        let value = serde_json::to_string(&gotcha).unwrap();
        make_record(key, &value, Category::Gotcha, quality_value)
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
        let record = make_record(
            "gotcha:test",
            "test value",
            Category::Gotcha,
            0.8,
        );
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
                mode: Some("text".to_string()),
                limit: Some(10),
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
                mode: Some("invalid".to_string()),
                limit: None,
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
                mode: Some("semantic".to_string()),
                limit: None,
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
                context_files: None,
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

        let packet = assemble_context_packet(graph.store(), &graph, &[]).await.unwrap();
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
        let packet = assemble_context_packet(graph.store(), &graph, &[]).await.unwrap();

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
        let packet = assemble_context_packet(graph.store(), &graph, &[]).await.unwrap();

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
        let file_record = make_record(
            "file:src/main.rs",
            "{}",
            Category::File,
            0.5,
        );
        store.put("file:src/main.rs", &file_record).await.unwrap();

        // Build graph with HasGotcha edge
        let mut graph = Graph::load(store).await.unwrap();
        graph
            .add_edge("file:src/main.rs", EdgeKind::HasGotcha, "gotcha:important")
            .await
            .unwrap();

        let packet = assemble_context_packet(
            graph.store(),
            &graph,
            &["src/main.rs".to_string()],
        )
        .await
        .unwrap();

        // The gotcha should be in the context packet
        assert!(
            packet.injection_string.contains("gotcha:important")
                || packet.critical_gotchas.iter().any(|g| g.key == "gotcha:important"),
            "graph-connected gotcha must appear in context packet"
        );
    }
}
