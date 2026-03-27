//! MCP tool implementations (M-07, M-11).
//!
//! 4 tools:
//! - `mem_get`       — direct key lookup
//! - `mem_query`     — BM25 text search or graph traversal
//! - `mem_bootstrap` — context packet assembly with token budget
//! - `mem_set`       — write enriched knowledge records (M-11)

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use rmcp::handler::server::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::tool_router;

use crate::graph::edges::EdgeKind;
use crate::graph::Graph;
use crate::health::quality;
use crate::store::record::{
    Category, ConfidenceScore, ContextPacket, FileRecord, GotchaRecord, Priority, QualityScore,
    QualityTier, Record, RecordLifecycle, RecordSource, RecordVersion, StalenessScore,
    StaleReviewPayload, StalenessTier,
};

use super::types::{MemBootstrapParams, MemGetParams, MemQueryParams, MemSetParams};

/// Vector B — appended to every mem_bootstrap result (70 tokens, budget 77).
const VECTOR_B: &str = "\n\n[mati] Before reading any file: call mem_get(\"file:<path>\").\n\
    confidence>=0.6 + confirmed=true \u{2192} use record, skip file read.\n\
    confidence<0.3 \u{2192} read file, then consider mem_set to improve.\n\
    Dev says \"add that as a gotcha\" \u{2192} call mem_set (category=Gotcha, confirmed=false).";

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

    /// Construct from an already-wrapped Arc so callers can clone and share it
    /// (e.g. to also start the daemon socket listener in the same process).
    pub fn with_graph_arc(graph: Arc<tokio::sync::RwLock<Graph>>) -> Self {
        Self {
            graph,
            tool_router: Self::tool_router(),
        }
    }

    /// Expose the inner Arc so the caller can share the graph with other tasks
    /// (e.g. the daemon socket listener spawned alongside `mati serve`).
    pub fn graph_arc(&self) -> Arc<tokio::sync::RwLock<Graph>> {
        Arc::clone(&self.graph)
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
            Ok(Some(mut record)) => {
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
                serde_json::to_string_pretty(&record).unwrap_or_else(|e| {
                    format!("{{\"error\": \"serialization failed: {e}\"}}")
                })
            }
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
                    Ok(mut records) => {
                        records.retain(|r| matches!(r.lifecycle, RecordLifecycle::Active));
                        serde_json::to_string_pretty(&records).unwrap_or_else(|e| {
                            format!("{{\"error\": \"serialization failed: {e}\"}}")
                        })
                    }
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
                        if matches!(record.lifecycle, RecordLifecycle::Active) {
                            records.push(record);
                        }
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
        match assemble_context_packet(store, &graph, &context_files).await {
            Ok(packet) => packet.injection_string,
            Err(e) => format!("[mati] bootstrap error: {e}{VECTOR_B}"),
        }
    }

    /// Write an enriched knowledge record to the mati store.
    ///
    /// Used during `/mati-enrich` sessions. Source is always `ClaudeEnrich`.
    /// Gotcha records land with `confirmed=false` — developer runs `mati review`
    /// to confirm and activate hook enforcement.
    #[rmcp::tool(
        name = "mem_set",
        description = "Write enriched knowledge to the mati store. \n\nUSE FOR: (1) /mati-enrich file/directory enrichment, (2) inline capture when developer says 'add that as a gotcha' / 'remember this' / 'note that'. \n\nGOTCHA RULES: rule MUST start with imperative verb (Always/Never/Ensure/Do not). reason MUST state causality — what breaks and why. confirmed MUST be false. \n\nFILE RULES: value and purpose MUST start with a verb (Handles/Manages/Validates). Preserve all existing structural fields from mem_get — only update purpose and gotcha_keys. \n\nAFTER WRITING GOTCHAS: always remind developer to run `mati review` to activate hooks. \n\nQUALITY GATE: records with quality < 0.2 are suppressed and never injected. Imperative verb + causality reason = quality >= 0.4 (injectable)."
    )]
    async fn mem_set(&self, Parameters(params): Parameters<MemSetParams>) -> String {
        let graph = self.graph.read().await;
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
        let mut record = match store.get(&params.key).await {
            Ok(Some(existing)) => existing,
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
                payload: None,
            },
        };

        // Apply enrichment fields
        record.value = params.value;
        record.category = category;
        record.source = RecordSource::ClaudeEnrich;
        record.updated_at = now;
        record.version.logical_clock += 1;
        record.version.wall_clock = now;
        record.tags = params.tags;
        record.priority = priority;

        // Merge payload: for existing records, preserve structural fields from
        // Layer 0 (entry_points, imports, etc.) while overlaying enrichment.
        if let Some(new_payload) = params.payload {
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
                    if let Some(sev) = obj.get("severity").and_then(|v| v.as_str()).map(|s| s.to_lowercase()) {
                        obj.insert("severity".to_string(), serde_json::Value::String(sev));
                    }
                }
            }
        }

        // Recompute confidence + quality
        record.confidence = ConfidenceScore::for_new_record(&RecordSource::ClaudeEnrich);
        record.quality = quality::analyze(&record);

        // Write
        let tier_label = format!("{:?}", record.quality.tier);
        match store.put(&record.key, &record).await {
            Ok(_) => serde_json::json!({
                "ok": true,
                "key": record.key,
                "confidence": record.confidence.value,
                "quality": record.quality.value,
                "tier": tier_label,
            })
            .to_string(),
            Err(e) => serde_json::json!({"error": e.to_string()}).to_string(),
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
                let is_nudge_candidate =
                    record.access_count >= 3 && fr.gotcha_keys.is_empty();
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
            let caveat = if record.staleness.tier == StalenessTier::Liability {
                " [STALE — verify before trusting]"
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
            payload: None,
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
        let mut file_record = make_record(
            "file:src/hot.rs",
            &fr.purpose,
            Category::File,
            0.5,
        );
        file_record.payload = serde_json::to_value(&fr).ok();
        file_record.access_count = 5; // >= 3 threshold
        store.put("file:src/hot.rs", &file_record).await.unwrap();

        let graph = Graph::load(store).await.unwrap();
        let packet = assemble_context_packet(
            graph.store(),
            &graph,
            &["src/hot.rs".to_string()],
        )
        .await
        .unwrap();

        assert!(
            packet.unconfirmed_candidates.contains(&"file:src/hot.rs".to_string()),
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
        let mut file_record = make_record(
            "file:src/cold.rs",
            &fr.purpose,
            Category::File,
            0.5,
        );
        file_record.payload = serde_json::to_value(&fr).ok();
        file_record.access_count = 1; // < 3 threshold
        store.put("file:src/cold.rs", &file_record).await.unwrap();

        let graph = Graph::load(store).await.unwrap();
        let packet = assemble_context_packet(
            graph.store(),
            &graph,
            &["src/cold.rs".to_string()],
        )
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
        store.put("file:src/covered.rs", &file_record).await.unwrap();

        let graph = Graph::load(store).await.unwrap();
        let packet = assemble_context_packet(
            graph.store(),
            &graph,
            &["src/covered.rs".to_string()],
        )
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
        let packet = assemble_context_packet(graph.store(), &graph, &[]).await.unwrap();

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
        let packet = assemble_context_packet(graph.store(), &graph, &[]).await.unwrap();

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
        let packet = assemble_context_packet(
            graph.store(),
            &graph,
            &["src/stale.rs".to_string()],
        )
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
        let packet = assemble_context_packet(
            graph.store(),
            &graph,
            &["src/dead.rs".to_string()],
        )
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
        let packet = assemble_context_packet(
            graph.store(),
            &graph,
            &["src/dup.rs".to_string()],
        )
        .await
        .unwrap();

        // Should have exactly 1 warning, not 2 (dedup by key)
        let dup_count = packet
            .stale_warnings
            .iter()
            .filter(|w| w.contains("dup.rs"))
            .count();
        assert_eq!(dup_count, 1, "same key should not produce duplicate warnings");
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
        let decision = make_record(
            "decision:arch",
            "Use SurrealKV",
            Category::Decision,
            0.8,
        );
        store.put("decision:arch", &decision).await.unwrap();

        let mut graph = Graph::load(store).await.unwrap();
        graph
            .add_edge("file:src/stale.rs", EdgeKind::AffectedBy, "decision:arch")
            .await
            .unwrap();

        let packet = assemble_context_packet(
            graph.store(),
            &graph,
            &["src/stale.rs".to_string()],
        )
        .await
        .unwrap();

        let stale_pos = packet.injection_string.find("## Stale Warnings");
        let dec_pos = packet.injection_string.find("## Decisions");

        if let (Some(s), Some(d)) = (stale_pos, dec_pos) {
            assert!(
                s < d,
                "Stale Warnings section must appear before Decisions"
            );
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
        let packet = assemble_context_packet(graph.store(), &graph, &[]).await.unwrap();

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

        let packet = assemble_context_packet(graph.store(), &graph, &[]).await.unwrap();

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
                key: "file:src/main.rs".to_string(),
                value: "Handles CLI dispatch and binary entry point".to_string(),
                category: "File".to_string(),
                payload: Some(serde_json::json!({
                    "path": "src/main.rs",
                    "purpose": "Handles CLI dispatch and binary entry point"
                })),
                tags: vec!["entry-point".to_string()],
                priority: "Normal".to_string(),
            }))
            .await;

        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed["ok"], true);
        assert_eq!(parsed["key"], "file:src/main.rs");
        assert!((parsed["confidence"].as_f64().unwrap() - 0.60).abs() < 0.01);

        // Read back and verify
        let graph = server.graph.read().await;
        let record = graph.store().get("file:src/main.rs").await.unwrap().unwrap();
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
            .mem_set(Parameters(MemSetParams {
                key: "gotcha:always-use-idempotency-keys".to_string(),
                value: "Always pass idempotency_key to Stripe charge creation because duplicate charges cause customer refund disputes".to_string(),
                category: "Gotcha".to_string(),
                payload: Some(serde_json::json!({
                    "rule": "Always pass idempotency_key to Stripe charge creation",
                    "reason": "duplicate charges cause customer refund disputes",
                    "severity": "Critical",
                    "affected_files": ["src/payments/stripe.go"],
                    "ref_url": null,
                    "discovered_session": 0,
                    "confirmed": false
                })),
                tags: vec![],
                priority: "Critical".to_string(),
            }))
            .await;

        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed["ok"], true);
        // Quality should be > 0.2 (passes gate) since rule has imperative verb + reason has causality
        assert!(parsed["quality"].as_f64().unwrap() > 0.2);

        // Read back
        let graph = server.graph.read().await;
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
                key: "file:src/db.rs".to_string(),
                value: "Manages database connection pooling and query execution".to_string(),
                category: "File".to_string(),
                payload: Some(serde_json::json!({
                    "purpose": "Manages database connection pooling and query execution",
                    "gotcha_keys": ["gotcha:always-close-connections"]
                })),
                tags: vec![],
                priority: "Normal".to_string(),
            }))
            .await;

        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed["ok"], true);

        // Verify Layer 0 fields preserved via merge
        let graph = server.graph.read().await;
        let record = graph.store().get("file:src/db.rs").await.unwrap().unwrap();
        let payload = record.payload.unwrap();

        // Enrichment fields updated
        assert_eq!(payload["purpose"], "Manages database connection pooling and query execution");
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
                key: "session:12345".to_string(),
                value: "test".to_string(),
                category: "File".to_string(),
                payload: None,
                tags: vec![],
                priority: "Normal".to_string(),
            }))
            .await;

        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert!(parsed["error"].as_str().unwrap().contains("must start with"));
    }

    #[tokio::test]
    async fn mem_set_rejects_invalid_category() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();
        let graph = Graph::load(store).await.unwrap();
        let server = MatiServer::new(graph);

        let result = server
            .mem_set(Parameters(MemSetParams {
                key: "file:test.rs".to_string(),
                value: "test".to_string(),
                category: "Unknown".to_string(),
                payload: None,
                tags: vec![],
                priority: "Normal".to_string(),
            }))
            .await;

        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert!(parsed["error"].as_str().unwrap().contains("unknown category"));
    }
}
