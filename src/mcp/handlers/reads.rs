//! Side-effecting read handlers: MemGet, MemQuery, MemBootstrap.

use super::*;

// ── Side-effecting reads ────────────────────────────────────────────────────

/// Native MemGet handler.
///
/// Primary: read record, return agent-facing JSON.
/// Sessions-tree transaction: consultation receipt + audit.
/// Deferred best-effort: access_count bump (knowledge, cross-tree) + daily agg (sessions).
pub(crate) async fn handle_mem_get(
    store: &Store,
    graph: &Arc<tokio::sync::RwLock<crate::graph::Graph>>,
    ctx: &RequestContext,
    request_id: Uuid,
    input: &protocol::MemGetInput,
) -> HandlerResult {
    if input.key.is_empty() {
        return Err((ErrorCode::ValidationFailed, "key must not be empty".into()));
    }

    // 1. Read record (pure read — no lock contention with sessions writes).
    let record = match store.get(&input.key).await {
        Ok(Some(r)) => {
            if matches!(r.lifecycle, RecordLifecycle::Tombstoned { .. }) {
                None
            } else {
                Some(r)
            }
        }
        Ok(None) => None,
        Err(e) => return Err((ErrorCode::StoreError, format!("store read: {e}"))),
    };

    // 2. Build response FIRST (must return before client timeout).
    //
    // Includes blast-radius warning injection for high-impact files. This
    // logic used to live in `tools::MatiServer::mem_get` (Direct branch only)
    // — meaning v1-dispatched mem_get calls saw the warning but v2-dispatched
    // ones did not. Centralizing here closes that divergence so both
    // protocol paths return identical responses (see
    // `mem_get_v1_and_v2_responses_are_byte_identical` test).
    let response = match &record {
        Some(r) => {
            let mut agent_json = crate::mcp::tools::record_to_agent_json(r);
            if r.category == Category::File {
                if let Some(payload) = &r.payload {
                    if let Ok(fr) =
                        serde_json::from_value::<crate::store::record::FileRecord>(payload.clone())
                    {
                        use crate::analysis::blast_radius::BlastTier;

                        // Existing: blast-warning injection for high-impact
                        // files. Centralized here so both v1 and v2 dispatch
                        // return identical responses.
                        if let Some(ref br) = fr.blast_radius {
                            if matches!(br.tier, BlastTier::High | BlastTier::Critical) {
                                let warning = format!(
                                    "HIGH IMPACT FILE: {} files directly depend on this. Modify with extra care.",
                                    br.direct
                                );
                                if let Some(obj) = agent_json.as_object_mut() {
                                    obj.insert("warnings".into(), serde_json::json!([warning]));
                                }
                            }
                        }

                        // D2-α: adaptive enrichment depth hint. Pure
                        // additive — older clients ignore the new field.
                        // Cluster size requires a `cluster:index` lookup;
                        // tolerate absence (cold init, repair in progress)
                        // by treating the file as cluster-less.
                        let blast_tier = fr
                            .blast_radius
                            .as_ref()
                            .map(|b| b.tier)
                            .unwrap_or(BlastTier::Isolated);
                        let cluster_size = {
                            let path = input.key.strip_prefix("file:").unwrap_or(&input.key);
                            let mut size = 0u32;
                            if let Ok(Some(idx_rec)) = store.get("cluster:index").await {
                                if let Some(payload) = idx_rec.payload {
                                    if let Ok(idx) = serde_json::from_value::<
                                        crate::analysis::clusters::ClusterIndex,
                                    >(payload)
                                    {
                                        for cluster in &idx.clusters {
                                            if cluster.members.iter().any(|m| m == path) {
                                                size = cluster.size;
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                            size
                        };
                        let depth = crate::health::enrichment::enrichment_depth(
                            fr.line_count,
                            blast_tier,
                            cluster_size,
                            fr.gotcha_keys.len(),
                            None, // comment_density not stored
                        );
                        if let Some(obj) = agent_json.as_object_mut() {
                            obj.insert(
                                "enrichment_depth_hint".into(),
                                serde_json::json!(depth.as_str()),
                            );
                        }
                    }
                }
            }
            agent_json
        }
        None => serde_json::Value::Null,
    };

    // 3. Sessions-tree transaction: consultation receipt + audit.
    let receipt = match crate::store::session::consultation_receipt_staged_with_fingerprint(
        &input.key,
        None,
        record
            .as_ref()
            .and_then(crate::store::session::record_content_fingerprint),
    ) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(
                request_id = %request_id,
                key = %input.key,
                "mem_get: consultation receipt staging failed: {e}"
            );
            // Fail-open: return success but write accepted audit standalone.
            if let Some((ak, ab)) =
                make_session_audit(ctx, request_id, "mem_get", &input.key, true, None)
            {
                let _ = store.transact_sessions_raw(&[(&ak, &ab)]).await;
            }
            return Ok(response);
        }
    };
    // Audit is required alongside the consultation receipt.
    let (audit_key, audit_bytes) =
        make_session_audit(ctx, request_id, "mem_get", &input.key, true, None)
            .ok_or_else(|| (ErrorCode::Internal, "audit serialization failed".into()))?;
    let writes: Vec<(&str, &[u8])> =
        vec![(&receipt.key, &receipt.bytes), (&audit_key, &audit_bytes)];
    if let Err(e) = store.transact_sessions_raw(&writes).await {
        tracing::warn!(
            request_id = %request_id,
            key = %input.key,
            "mem_get: sessions transaction failed (fail-open): {e}"
        );
    }

    // 3b. Best-effort enforcement event: ReceiptMinted.
    //
    // Mirrors the dispatch in `Command::ConsultationHit` (dispatch_v2.rs:720)
    // so the `mati history --enforcement` log contains a `receipt_minted`
    // row whether the receipt was minted by an MCP `mem_get` or a CLI
    // `mati explain` / `proxy.log_hit`. Without this, `mem_get`-only
    // workflows produce a silent receipt with no audit-grade evidence
    // that consultation happened, breaking the deny → consult → allow
    // enforcement audit chain.
    let _ = crate::store::enforcement::record_event(
        store,
        crate::store::enforcement::EnforcementEventType::ReceiptMinted,
        crate::store::enforcement::SubjectKind::File,
        input.key.clone(),
        "claude".to_string(),
        Some(receipt.id),
        "consultation_requested".to_string(),
        // No gotcha state is loaded on this path, so there is no decision basis
        // to hash — mem_get returns one record, it does not run the gate.
        None,
    )
    .await;

    // 4. Deferred best-effort: access_count bump + daily agg.
    if let Some(mut r) = record {
        r.access_count += 1;
        let key_owned = input.key.clone();
        let graph_clone = Arc::clone(graph);
        tokio::task::spawn(async move {
            let g = graph_clone.read().await;
            let s = g.store();
            let _ = s.put(&key_owned, &r).await;
            let agg_key = crate::store::session::today_key("analytics:hit_");
            let _ = crate::store::session::upsert_daily_agg(s, &agg_key, &key_owned).await;
        });
    }

    Ok(response)
}

/// Native mem_query handler.
///
/// Centralizes the four mem_query modes (`text`, `tag`, `graph`,
/// `semantic`) so both v1 dispatch (`server.rs::socket_dispatch`'s
/// `"mem_query"` arm) and v2 dispatch (`Command::MemQuery`) produce
/// byte-identical responses. Before γ-C1.5, the logic lived only in
/// `tools::MatiServer::mem_query`'s Direct branch — meaning the v2
/// path went through the v1 string bridge and could silently drift if
/// the bridge's serialization assumptions diverged. See
/// `mem_query_handler_text_mode_matches_v1_path` for the byte-equality
/// pin.
///
/// Returns a JSON `Value` (text/tag → array, graph → grouped object).
/// Callers that need a String wrap with `serde_json::to_string_pretty`.
/// Trim a caller-supplied directory query into a comparable repo-relative prefix.
fn normalize_path_prefix(query: &str) -> &str {
    query.trim().trim_start_matches("./").trim_matches('/')
}

/// Segment-aware prefix test — `src/st` must not match `src/store/db.rs`.
fn path_under_prefix(path: &str, prefix: &str) -> bool {
    let path = normalize_path_prefix(path);
    path == prefix
        || path
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.starts_with('/'))
}

pub(crate) async fn handle_mem_query(
    store: &Store,
    graph_ref: &crate::graph::Graph,
    input: &protocol::MemQueryInput,
) -> HandlerResult {
    use crate::graph::EdgeKind;
    use crate::store::record::Category;

    const MAX_QUERY_LIMIT: usize = 50;
    let limit = (input.limit as usize).min(MAX_QUERY_LIMIT);

    match input.mode {
        protocol::QueryMode::Text => {
            // BM25 search across knowledge tree. Filter out session/analytics
            // and any non-Active records so agents never see internal state.
            let scored = match store.search_scored(&input.query, limit).await {
                Ok(r) => r,
                Err(e) => return Err((ErrorCode::StoreError, format!("search: {e}"))),
            };
            let arr: Vec<serde_json::Value> = scored
                .iter()
                .filter(|(_, r)| {
                    matches!(r.lifecycle, RecordLifecycle::Active)
                        && !matches!(r.category, Category::Session | Category::Analytics)
                })
                .map(|(score, r)| {
                    let mut obj = crate::mcp::tools::record_to_agent_json(r);
                    if let serde_json::Value::Object(ref mut map) = obj {
                        map.insert(
                            "relevance".into(),
                            serde_json::json!((*score * 1000.0).round() / 1000.0),
                        );
                    }
                    obj
                })
                .collect();
            Ok(serde_json::Value::Array(arr))
        }
        protocol::QueryMode::Tag => {
            // Substring tag match across the agent-visible namespaces.
            // Bounded scan: stop after `limit` matches across all prefixes.
            let query_lower = input.query.to_lowercase();
            let mut matched: Vec<serde_json::Value> = Vec::new();
            for ns in &[
                "gotcha:",
                "decision:",
                "file:",
                "stage:",
                "dev_note:",
                "dep:",
            ] {
                if matched.len() >= limit {
                    break;
                }
                let records = match store.scan_prefix(ns).await {
                    Ok(rs) => rs,
                    Err(e) => return Err((ErrorCode::StoreError, format!("scan {ns}: {e}"))),
                };
                for record in records {
                    if matched.len() >= limit {
                        break;
                    }
                    if !matches!(record.lifecycle, RecordLifecycle::Active) {
                        continue;
                    }
                    if record
                        .tags
                        .iter()
                        .any(|t| t.to_lowercase().contains(&query_lower))
                    {
                        matched.push(crate::mcp::tools::record_to_agent_json(&record));
                    }
                }
            }
            Ok(serde_json::Value::Array(matched))
        }
        protocol::QueryMode::Graph => {
            // 1-hop traversal from a seed key. Per-kind round-robin
            // allocation ensures every non-empty kind surfaces at least one
            // record before any kind gets a second slot. Without this, a
            // hot file with 10+ gotchas would starve imports / co_changes /
            // decisions / notes.
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
                serde_json::Value::String(input.query.clone()),
            );
            let mut summary_parts: Vec<String> = Vec::new();

            // HasGotcha / AffectedBy / HasNote edges are written file -> X
            // only (see gotcha_ops::apply_gotcha_write). A file seed's
            // outgoing traversal already finds them; a gotcha:/decision:/
            // dev_note: seed needs the reverse (incoming) lookup instead,
            // or it silently returns nothing for a pair the file-side query
            // surfaces. Imports and CoChanges are unaffected: CoChanges
            // edges are written in both directions at creation time, and
            // Imports is intentionally forward-only ("what I import" is a
            // different question from "who imports me").
            let mut available: Vec<Vec<String>> = edge_groups
                .iter()
                .map(|(kind, _, cap)| {
                    let mut keys = graph_ref.neighbors(&input.query, kind);
                    if matches!(
                        kind,
                        EdgeKind::HasGotcha | EdgeKind::AffectedBy | EdgeKind::HasNote
                    ) {
                        let mut seen: std::collections::HashSet<String> =
                            keys.iter().cloned().collect();
                        for key in graph_ref.neighbors_incoming(&input.query, kind) {
                            if seen.insert(key.clone()) {
                                keys.push(key);
                            }
                        }
                    }
                    keys.truncate(*cap);
                    keys
                })
                .collect();

            let mut quotas: Vec<usize> = vec![0; edge_groups.len()];
            let mut remaining = limit;
            loop {
                if remaining == 0 {
                    break;
                }
                let mut handed_out = 0usize;
                for (i, slot_keys) in available.iter().enumerate() {
                    if remaining == 0 {
                        break;
                    }
                    if quotas[i] < slot_keys.len() {
                        quotas[i] += 1;
                        remaining -= 1;
                        handed_out += 1;
                    }
                }
                if handed_out == 0 {
                    break;
                }
            }

            for (i, (kind, group_name, _)) in edge_groups.iter().enumerate() {
                let keys = std::mem::take(&mut available[i]);
                let mut group_records: Vec<serde_json::Value> = Vec::new();
                for key in keys.iter().take(quotas[i]) {
                    if let Ok(Some(record)) = store.get(key).await {
                        if matches!(record.lifecycle, RecordLifecycle::Active) {
                            let mut entry = serde_json::Map::new();
                            entry.insert(
                                "key".into(),
                                serde_json::Value::String(record.key.clone()),
                            );
                            entry.insert(
                                "relationship".into(),
                                serde_json::Value::String(format!("{kind:?}")),
                            );
                            entry.insert(
                                "value".into(),
                                serde_json::Value::String(record.value.clone()),
                            );
                            entry.insert(
                                "confidence".into(),
                                serde_json::json!(record.confidence.value),
                            );
                            entry.insert("quality".into(), serde_json::json!(record.quality.value));
                            if let Some(payload) = &record.payload {
                                if let Some(confirmed) = payload.get("confirmed") {
                                    entry.insert("confirmed".into(), confirmed.clone());
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

            // DependencyAffects overflow — appended to decisions group, still
            // honoring the global `limit` ceiling.
            if remaining > 0 {
                let dep_keys = graph_ref.neighbors(&input.query, &EdgeKind::DependencyAffects);
                let mut dep_added = 0usize;
                for key in dep_keys.iter().take(DECISION_LIMIT.min(remaining)) {
                    if let Ok(Some(record)) = store.get(key).await {
                        if matches!(record.lifecycle, RecordLifecycle::Active) {
                            let mut entry = serde_json::Map::new();
                            entry.insert(
                                "key".into(),
                                serde_json::Value::String(record.key.clone()),
                            );
                            entry.insert(
                                "relationship".into(),
                                serde_json::Value::String("DependencyAffects".to_string()),
                            );
                            entry.insert(
                                "value".into(),
                                serde_json::Value::String(record.value.clone()),
                            );
                            entry.insert(
                                "confidence".into(),
                                serde_json::json!(record.confidence.value),
                            );
                            entry.insert("quality".into(), serde_json::json!(record.quality.value));
                            if let Some(decisions) = result.get_mut("decisions") {
                                if let Some(arr) = decisions.as_array_mut() {
                                    arr.push(serde_json::Value::Object(entry));
                                    dep_added += 1;
                                }
                            }
                        }
                    }
                }
                let _ = dep_added; // remaining is only useful for diagnostic logs
            }

            let summary = if summary_parts.is_empty() {
                "No related records found".to_string()
            } else {
                summary_parts.join(", ")
            };
            result.insert("summary".to_string(), serde_json::Value::String(summary));
            Ok(serde_json::Value::Object(result))
        }
        protocol::QueryMode::DirGotchas => {
            // The tantivy index stores no `affected_files`, so a text query for a
            // directory can only match file records. This mode resolves the
            // canonical `gotcha:*` records instead — no index, no ranking.
            let prefix = normalize_path_prefix(&input.query);
            if prefix.is_empty() {
                return Ok(serde_json::Value::Array(Vec::new()));
            }
            let records = store
                .scan_prefix("gotcha:")
                .await
                .map_err(|e| (ErrorCode::StoreError, format!("scan gotcha: {e}")))?;
            let mut matched: Vec<&Record> = records
                .iter()
                .filter(|r| matches!(r.lifecycle, RecordLifecycle::Active))
                .filter(|r| {
                    r.payload_as::<GotchaRecord>().is_some_and(|g| {
                        g.confirmed
                            && g.affected_files
                                .iter()
                                .any(|f| path_under_prefix(f, prefix))
                    })
                })
                .collect();
            matched.sort_by(|a, b| {
                b.confidence
                    .value
                    .total_cmp(&a.confidence.value)
                    .then(b.quality.value.total_cmp(&a.quality.value))
                    .then_with(|| a.key.cmp(&b.key))
            });
            let arr: Vec<serde_json::Value> = matched
                .into_iter()
                .take(limit)
                .map(crate::mcp::tools::record_to_agent_json)
                .collect();
            Ok(serde_json::Value::Array(arr))
        }
        protocol::QueryMode::Semantic => Err((
            ErrorCode::ValidationFailed,
            "semantic search requires --features semantic (not enabled)".into(),
        )),
        protocol::QueryMode::PolicyObservations => {
            // Shadow observations — bounded daily aggregates of what a
            // not-yet-live policy would have denied. `query` selects one slug.
            let slug = (!input.query.is_empty()).then_some(input.query.as_str());
            let shadow = store
                .scan_prefix("analytics:policy_shadow_")
                .await
                .map_err(|e| (ErrorCode::StoreError, format!("scan shadow: {e}")))?;
            let observations =
                crate::store::observability::assemble_shadow_observations(&shadow, slug);
            serde_json::to_value(observations)
                .map_err(|e| (ErrorCode::StoreError, format!("serialize: {e}")))
        }
        protocol::QueryMode::PolicyActivity => {
            use crate::store::{enforcement, observability};
            // Treat since:0 as unset (a zero-width window reports every policy
            // as NoActivity, which an agent could misread as "these rules are
            // dead"), and cap at the retention horizon so an absurd `since`
            // can't yield a nonsensical window or force a full-history rescan.
            let days = input
                .since
                .filter(|&d| d > 0)
                .unwrap_or(observability::POLICY_ACTIVITY_DEFAULT_DAYS)
                .min(observability::POLICY_ACTIVITY_RETENTION_DAYS);
            let slug = (!input.query.is_empty()).then_some(input.query.as_str());
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let window_start = observability::window_start_secs(now, days);
            let enforcement = enforcement::scan_enforcement_events_since_ms(
                store,
                window_start.saturating_mul(1000),
                now.saturating_mul(1000),
            )
            .await
            .map_err(|e| (ErrorCode::StoreError, format!("scan enforcement: {e}")))?;
            let policy_records = store
                .scan_prefix("policy:")
                .await
                .map_err(|e| (ErrorCode::StoreError, format!("scan policy: {e}")))?;
            let shadow_records = store
                .scan_prefix("analytics:policy_shadow_")
                .await
                .map_err(|e| (ErrorCode::StoreError, format!("scan shadow: {e}")))?;
            let steer_records = store
                .scan_prefix("analytics:policy_steer_")
                .await
                .map_err(|e| (ErrorCode::StoreError, format!("scan steer: {e}")))?;
            let report = observability::assemble_activity_report(
                now,
                days,
                &policy_records,
                &enforcement,
                &shadow_records,
                &steer_records,
                slug,
            );
            serde_json::to_value(report)
                .map_err(|e| (ErrorCode::StoreError, format!("serialize: {e}")))
        }
        protocol::QueryMode::Analytics => {
            // Raw analytics records. Text mode deliberately excludes this
            // category; this mode is the explicit opt-in for reading it.
            // Require a query that names the aggregate (e.g. "miss_"): an empty
            // query would otherwise dump every analytics record — daily
            // telemetry aggregates AND internal caches (gaps/stale caches,
            // negative exemplars) — at the agent. Empty → nothing, consistent
            // with text/tag modes.
            let needle = input.query.trim().to_lowercase();
            if needle.is_empty() {
                Ok(serde_json::Value::Array(Vec::new()))
            } else {
                let records = store
                    .scan_prefix("analytics:")
                    .await
                    .map_err(|e| (ErrorCode::StoreError, format!("scan analytics: {e}")))?;
                let arr: Vec<serde_json::Value> = records
                    .iter()
                    .filter(|r| matches!(r.lifecycle, RecordLifecycle::Active))
                    .filter(|r| r.key.to_lowercase().contains(&needle))
                    .take(limit)
                    .map(crate::mcp::tools::record_to_agent_json)
                    .collect();
                Ok(serde_json::Value::Array(arr))
            }
        }
    }
}

/// Native MemBootstrap handler.
///
/// Primary: assemble context packet (pure read computation).
/// Sessions-tree transaction: bootstrap aggregate + audit.
/// Deferred best-effort: access_count bumps on context file records (knowledge, cross-tree).
pub(crate) async fn handle_mem_bootstrap(
    store: &Store,
    graph_ref: &crate::graph::Graph,
    graph_arc: &Arc<tokio::sync::RwLock<crate::graph::Graph>>,
    ctx: &RequestContext,
    request_id: Uuid,
    input: &protocol::MemBootstrapInput,
) -> Result<String, (ErrorCode, String)> {
    let context_files = &input.context_files;

    // 1. Assemble context packet (pure read computation) — determines outcome.
    let assembly =
        crate::mcp::tools::assemble_context_packet(store, graph_ref, context_files).await;
    let (accepted, error_code) = match &assembly {
        Ok(_) => (true, None),
        Err(_) => (false, Some(ErrorCode::Internal)),
    };

    // 2. Stage the bootstrap aggregate and audit only.
    //
    // Bootstrap surfaces context, but it is not a consultation of each file's
    // record. Only an actual read (`mem_get`, or an allowlisted schema
    // introspection) may mint a receipt; otherwise bootstrap silently unlocks
    // later reads/edits and has no ReceiptMinted event to anchor that receipt.
    let mut session_writes: Vec<(String, Vec<u8>)> = Vec::new();

    // Bootstrap aggregation. `analytics:hit_` stays out on purpose: it pairs
    // 1:1 with `HookEvent::Hit`/`Miss` from a real per-file gate decision
    // (decide::evaluate), and bootstrap has no per-file miss to pair against —
    // counting it would only inflate `mati stats` hit rate.
    let bootstrap_agg_key = crate::store::session::today_key("analytics:bootstrap_");
    if let Ok(staged) =
        crate::store::session::upsert_daily_agg_staged(store, &bootstrap_agg_key, "__bootstrap__")
            .await
    {
        session_writes.push(staged);
    }

    // Audit entry — reflects actual assembly outcome.
    // Audit is required — fail closed if serialization fails.
    let audit = make_session_audit(ctx, request_id, "mem_bootstrap", "", accepted, error_code)
        .ok_or_else(|| (ErrorCode::Internal, "audit serialization failed".into()))?;
    session_writes.push(audit);

    // 3. Commit all sessions-tree writes atomically.
    let write_refs: Vec<(&str, &[u8])> = session_writes
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_slice()))
        .collect();
    if let Err(e) = store.transact_sessions_raw(&write_refs).await {
        tracing::warn!(
            request_id = %request_id,
            "mem_bootstrap: sessions transaction failed: {e}"
        );
    }

    // 4. Deferred best-effort: access_count bumps on context file records (only on success).
    if assembly.is_ok() && !context_files.is_empty() {
        let files_owned: Vec<String> = context_files.clone();
        let graph_clone = Arc::clone(graph_arc);
        tokio::task::spawn(async move {
            let g = graph_clone.read().await;
            let s = g.store();
            for file in &files_owned {
                let file_key = if file.starts_with("file:") {
                    file.clone()
                } else {
                    format!("file:{file}")
                };
                if let Ok(Some(mut record)) = s.get(&file_key).await {
                    record.access_count += 1;
                    record.last_accessed = now_secs();
                    let _ = s.put(&file_key, &record).await;
                }
            }
        });
    }

    match assembly {
        Ok(packet) => Ok(packet.injection_string),
        Err(e) => Err((ErrorCode::Internal, format!("bootstrap assembly: {e}"))),
    }
}
