//! Context-packet assembly for mem_bootstrap — shared by the rmcp
//! wrapper in mod.rs and the native daemon handler in mcp::handlers.

use super::*;

/// Vector B — appended to every mem_bootstrap result (64 tokens, budget 77).
pub(crate) const VECTOR_B: &str =
    "\n\n[mati] Before reading any file: call mem_get(\"file:<path>\").\n\
    confidence>=0.6 + confirmed=true \u{2192} use record, skip file read.\n\
    confidence<0.3 \u{2192} read file, consider mem_set to improve.\n\
    \"add gotcha\" \u{2192} mem_set(Gotcha) then mati gotcha confirm <key>.";

/// Token budget for mem_bootstrap output (ARCHITECTURE.md section 6).
pub(super) const TOKEN_BUDGET: usize = 2_000;

/// Reserved tokens for Vector B suffix.
const VECTOR_B_TOKENS: usize = 77;

/// Estimate token count as text.len() / 4 (consistent with analysis/mod.rs).
pub(super) fn estimate_tokens(text: &str) -> usize {
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

/// Returns true if a gotcha record is eligible for injection into a context packet.
///
/// Two classes of gotchas surface in bootstrap:
///
/// 1. **Developer-confirmed gotchas** (`payload.confirmed = true`) — these are
///    intentional captures and always inject when quality is acceptable.
/// 2. **Auto-derived Layer 0 stubs with intrinsic signal value** —
///    `gotcha:cochange:*`, `gotcha:revert:*`, `gotcha:ownership:*` records
///    are minted by `mati init` from git history. They are NOT
///    developer-confirmed (so they never trigger hook enforcement / file-read
///    DENY), but their content is high-signal information the agent should
///    see in bootstrap. Pre-fix these were marked `confirmed=true` at init
///    which violated the "confirmed ⇒ developer-authoritative ⇒ confidence
///    ≥ 0.80" schema invariant. Now we keep them `confirmed=false` and
///    explicitly allowlist them here so bootstrap still surfaces them.
fn is_injectable_gotcha(r: &Record) -> bool {
    if !matches!(r.lifecycle, RecordLifecycle::Active) {
        return false;
    }
    if r.staleness.tier == StalenessTier::Tombstone {
        return false;
    }
    if r.quality.value < 0.4 {
        return false;
    }
    if let Some(gotcha) = r.payload_as::<GotchaRecord>() {
        if gotcha.confirmed {
            return true;
        }
    }
    // Auto-derived Layer 0 stubs: include advisory signals even unconfirmed.
    r.key.starts_with("gotcha:cochange:")
        || r.key.starts_with("gotcha:revert:")
        || r.key.starts_with("gotcha:ownership:")
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
        impact_files.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        if !impact_files.is_empty() {
            let mut impact_section = String::from("## Highest Impact Files\n");
            for (fr, _score) in impact_files.iter().take(3) {
                let br = fr
                    .blast_radius
                    .as_ref()
                    .expect("filter_map above kept only files with Some(blast_radius)");
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
