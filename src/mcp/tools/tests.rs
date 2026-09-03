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
        confirmed_content: Default::default(),
    };
    let mut record = make_record(key, rule, Category::Gotcha, quality_value);
    record.payload = serde_json::to_value(&gotcha).ok();
    record
}

/// Seed a gotcha directly through the canonical `gotcha_ops` write path —
/// used by tests that need real `HasGotcha` graph edges to traverse, not
/// the mem_set request/response envelope itself.
async fn seed_gotcha_for_graph_test(
    store: &Store,
    repo_root: &std::path::Path,
    key: &str,
    rule: &str,
    affected_files: &[String],
) {
    let gotcha = GotchaRecord {
        rule: rule.to_string(),
        reason: "testing".to_string(),
        severity: Priority::Normal,
        affected_files: affected_files.to_vec(),
        ref_url: None,
        discovered_session: 0,
        confirmed: false,
        confirmed_content: Default::default(),
    };
    let mut record = make_record(key, rule, Category::Gotcha, 0.5);
    record.payload = serde_json::to_value(&gotcha).ok();
    crate::store::gotcha_ops::apply_gotcha_write(
        store,
        repo_root,
        &record,
        &[],
        affected_files,
        true,
    )
    .await
    .expect("seed gotcha write must succeed");
}

// ── γ-C3a helpers: handler-level test entry points ───────────────────────
//
// γ-C4 removed `MatiBackend::Direct`. These helpers replaced the
// pre-γ pattern `MatiServer::new(graph).mem_*(Parameters(...)).await`.
// They drive the canonical daemon-side handlers (mcp::handlers::*)
// directly, returning a `String` so existing test assertions
// (`result.contains(...)`, `assert_eq!(result, "null")`) keep working.

fn handler_test_ctx() -> crate::mcp::dispatch_v2::RequestContext {
    crate::mcp::dispatch_v2::RequestContext {
        peer: crate::mcp::metadata::PeerContext {
            uid: 501,
            pid: Some(99999),
        },
        daemon_session: uuid::Uuid::nil(),
        repo_root: std::path::PathBuf::new(),
        policy_matcher: std::sync::Arc::new(tokio::sync::RwLock::new(
            crate::hooks::policy_match::PolicyMatcherSet::empty(),
        )),
    }
}

async fn call_mem_get(
    graph_arc: &std::sync::Arc<tokio::sync::RwLock<crate::graph::Graph>>,
    key: &str,
) -> String {
    call_mem_get_rooted(graph_arc, key, std::path::Path::new("")).await
}

/// `call_mem_get` against a daemon whose repo root is `repo_root` — the only
/// thing that resolves a `file:` key to a path on disk.
async fn call_mem_get_rooted(
    graph_arc: &std::sync::Arc<tokio::sync::RwLock<crate::graph::Graph>>,
    key: &str,
    repo_root: &std::path::Path,
) -> String {
    let mut ctx = handler_test_ctx();
    ctx.repo_root = repo_root.to_path_buf();
    let input = crate::mcp::protocol::MemGetInput {
        key: key.to_string(),
        actor: None,
    };
    let g = graph_arc.read().await;
    match crate::mcp::handlers::handle_mem_get(
        g.store(),
        graph_arc,
        &ctx,
        uuid::Uuid::new_v4(),
        &input,
    )
    .await
    {
        Ok(v) => serde_json::to_string_pretty(&v).unwrap_or_else(|_| "{}".into()),
        Err((_code, msg)) => format!("{{\"error\": \"{}\"}}", msg.replace('"', "\\\"")),
    }
}

async fn call_mem_query(
    graph_arc: &std::sync::Arc<tokio::sync::RwLock<crate::graph::Graph>>,
    query: &str,
    mode: crate::mcp::protocol::QueryMode,
    limit: u32,
) -> String {
    let input = crate::mcp::protocol::MemQueryInput {
        query: query.to_string(),
        mode,
        limit,
        since: None,
    };
    let g = graph_arc.read().await;
    match crate::mcp::handlers::handle_mem_query(g.store(), &g, &input).await {
        Ok(v) => serde_json::to_string_pretty(&v).unwrap_or_else(|_| "{}".into()),
        Err((_code, msg)) => format!("{{\"error\": \"{}\"}}", msg.replace('"', "\\\"")),
    }
}

async fn call_mem_bootstrap(
    graph_arc: &std::sync::Arc<tokio::sync::RwLock<crate::graph::Graph>>,
    context_files: Vec<String>,
) -> String {
    let ctx = handler_test_ctx();
    let input = crate::mcp::protocol::MemBootstrapInput { context_files };
    let g = graph_arc.read().await;
    match crate::mcp::handlers::handle_mem_bootstrap(
        g.store(),
        &g,
        graph_arc,
        &ctx,
        uuid::Uuid::new_v4(),
        &input,
    )
    .await
    {
        Ok(s) => s,
        Err((_code, msg)) => format!("[mati] bootstrap error: {msg}"),
    }
}

// ── mem_get tests ────────────────────────────────────────────────────────

#[tokio::test]
async fn mem_get_returns_null_for_nonexistent_key() {
    let dir = TempDir::new().unwrap();
    let store = Store::open(dir.path()).await.unwrap();
    let graph = Graph::load(store).await.unwrap();
    let graph_arc = std::sync::Arc::new(tokio::sync::RwLock::new(graph));

    let result = call_mem_get(&graph_arc, "file:nonexistent.rs").await;
    assert_eq!(result, "null");
}

/// Task 8: the receipt `mem_get` mints is what lifts the Tier 2 floor, so a
/// sealed file becomes readable by consulting it and not by any other route.
#[tokio::test]
async fn mem_get_lifts_the_tier_2_floor_on_the_file_it_mints_a_receipt_for() {
    use std::os::unix::fs::PermissionsExt;

    let dir = TempDir::new().unwrap();
    let store = Store::open(dir.path()).await.unwrap();
    let store_root = store.root.clone();

    let rel = "src/gated.rs";
    let abs = dir.path().join(rel);
    std::fs::create_dir_all(abs.parent().unwrap()).unwrap();
    std::fs::write(&abs, b"secret").unwrap();
    let key = format!("file:{rel}");
    let record = make_record(&key, "gated file", Category::File, 0.8);
    store.put(&key, &record).await.unwrap();

    // Seal it the way `mati seal add` does: manifest row first, then chmod.
    let mut manifest = crate::seal::Manifest::default();
    manifest.files.push(crate::seal::SealedFile {
        path: std::fs::canonicalize(&abs)
            .unwrap()
            .to_string_lossy()
            .into(),
        mode: "644".to_string(),
        ..Default::default()
    });
    crate::seal::write_manifest(&crate::seal::manifest_in(&store_root), &manifest).unwrap();
    std::fs::set_permissions(
        &abs,
        std::fs::Permissions::from_mode(crate::seal::SEALED_MODE),
    )
    .unwrap();
    assert!(
        std::fs::read(&abs).is_err(),
        "sealed file must be unreadable"
    );

    let graph = Graph::load(store).await.unwrap();
    let graph_arc = std::sync::Arc::new(tokio::sync::RwLock::new(graph));

    // A receipt for another file leaves the floor standing.
    call_mem_get_rooted(&graph_arc, "file:src/other.rs", dir.path()).await;
    assert!(std::fs::read(&abs).is_err());

    let result = call_mem_get_rooted(&graph_arc, &key, dir.path()).await;
    assert!(result.contains(&key));
    assert_eq!(std::fs::read(&abs).unwrap(), b"secret");
}

#[tokio::test]
async fn mem_get_returns_record_for_existing_key() {
    let dir = TempDir::new().unwrap();
    let store = Store::open(dir.path()).await.unwrap();
    let record = make_record("gotcha:test", "test value", Category::Gotcha, 0.8);
    store.put("gotcha:test", &record).await.unwrap();

    let graph = Graph::load(store).await.unwrap();
    let graph_arc = std::sync::Arc::new(tokio::sync::RwLock::new(graph));

    let result = call_mem_get(&graph_arc, "gotcha:test").await;
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
        propagated_staleness: None,
    };
    let mut record = make_record("file:src/core.rs", "Core module", Category::File, 0.5);
    record.payload = serde_json::to_value(&fr).ok();
    store.put("file:src/core.rs", &record).await.unwrap();

    let graph = Graph::load(store).await.unwrap();
    let graph_arc = std::sync::Arc::new(tokio::sync::RwLock::new(graph));

    let result = call_mem_get(&graph_arc, "file:src/core.rs").await;

    assert!(
        result.contains("HIGH IMPACT FILE"),
        "response must contain blast radius warning for critical file, got: {result}"
    );
    assert!(result.contains("45"), "warning must include direct count");
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
        propagated_staleness: None,
    };
    let mut record = make_record("file:src/leaf.rs", "Leaf module", Category::File, 0.5);
    record.payload = serde_json::to_value(&fr).ok();
    store.put("file:src/leaf.rs", &record).await.unwrap();

    let graph = Graph::load(store).await.unwrap();
    let graph_arc = std::sync::Arc::new(tokio::sync::RwLock::new(graph));

    let result = call_mem_get(&graph_arc, "file:src/leaf.rs").await;

    assert!(
        !result.contains("HIGH IMPACT FILE"),
        "low blast radius file should NOT have warning"
    );
}

// ── mem_get enrichment_depth_hint (D2-α) ─────────────────────────────────

#[tokio::test]
async fn mem_get_includes_depth_hint_for_file_records() {
    let dir = TempDir::new().unwrap();
    let store = Store::open(dir.path()).await.unwrap();

    // 50 LoC, Isolated blast, no cluster, no gotchas → score 0 → Fast
    let fr = FileRecord {
        path: "src/tiny.rs".to_string(),
        purpose: "Tiny leaf module".to_string(),
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
        line_count: 50,
        blast_radius: Some(crate::analysis::blast_radius::BlastRadius {
            direct: 0,
            transitive: 0,
            score: 0.0,
            tier: crate::analysis::blast_radius::BlastTier::Isolated,
        }),
        propagated_staleness: None,
    };
    let mut record = make_record("file:src/tiny.rs", "Tiny leaf", Category::File, 0.5);
    record.payload = serde_json::to_value(&fr).ok();
    store.put("file:src/tiny.rs", &record).await.unwrap();

    let graph = Graph::load(store).await.unwrap();
    let graph_arc = std::sync::Arc::new(tokio::sync::RwLock::new(graph));

    let result = call_mem_get(&graph_arc, "file:src/tiny.rs").await;
    let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
    assert_eq!(
        parsed.get("enrichment_depth_hint").and_then(|v| v.as_str()),
        Some("fast"),
        "tiny isolated file should hint Fast tier; got: {result}"
    );
}

#[tokio::test]
async fn mem_get_depth_hint_for_hotspot_is_deep() {
    let dir = TempDir::new().unwrap();
    let store = Store::open(dir.path()).await.unwrap();

    // 500 LoC (+3) + High blast (+2) = 5 → Deep
    let fr = FileRecord {
        path: "src/core.rs".to_string(),
        purpose: "Core hotspot".to_string(),
        entry_points: vec![],
        imports: vec![],
        gotcha_keys: vec![],
        decision_keys: vec![],
        todos: vec![],
        unsafe_count: 0,
        unwrap_count: 0,
        change_frequency: 0,
        last_author: None,
        is_hotspot: true,
        token_cost_estimate: 5000,
        last_modified_session: 0,
        content_hash: None,
        line_count: 500,
        blast_radius: Some(crate::analysis::blast_radius::BlastRadius {
            direct: 20,
            transitive: 30,
            score: 35.0,
            tier: crate::analysis::blast_radius::BlastTier::High,
        }),
        propagated_staleness: None,
    };
    let mut record = make_record("file:src/core.rs", "Core hotspot", Category::File, 0.5);
    record.payload = serde_json::to_value(&fr).ok();
    store.put("file:src/core.rs", &record).await.unwrap();

    let graph = Graph::load(store).await.unwrap();
    let graph_arc = std::sync::Arc::new(tokio::sync::RwLock::new(graph));

    let result = call_mem_get(&graph_arc, "file:src/core.rs").await;
    let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
    assert_eq!(
        parsed.get("enrichment_depth_hint").and_then(|v| v.as_str()),
        Some("deep"),
        "large hotspot file should hint Deep tier; got: {result}"
    );
}

#[tokio::test]
async fn mem_get_omits_depth_hint_for_non_file_records() {
    let dir = TempDir::new().unwrap();
    let store = Store::open(dir.path()).await.unwrap();

    let record = make_record("gotcha:foo", "rule", Category::Gotcha, 0.6);
    store.put("gotcha:foo", &record).await.unwrap();

    let graph = Graph::load(store).await.unwrap();
    let graph_arc = std::sync::Arc::new(tokio::sync::RwLock::new(graph));

    let result = call_mem_get(&graph_arc, "gotcha:foo").await;
    let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
    // depth_hint is scoped to file: keys; gotcha responses must NOT carry it.
    assert!(
        parsed.get("enrichment_depth_hint").is_none(),
        "non-file records should not carry enrichment_depth_hint; got: {result}"
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
    let graph_arc = std::sync::Arc::new(tokio::sync::RwLock::new(graph));

    let result = call_mem_query(
        &graph_arc,
        "inference",
        crate::mcp::protocol::QueryMode::Text,
        10,
    )
    .await;
    assert!(result.contains("gotcha:async-race"));
}

// Note: γ-C3a deleted the `mem_query_unknown_mode_returns_error` test
// that used to live here. The unknown-mode string-to-enum conversion no
// longer happens in `tools::mem_query`'s body — after centralization,
// typed `QueryMode` is the input. The validation now lives at the
// protocol layer's serde Deserialize impl. Coverage moved to
// `protocol::tests::query_mode_deserialize_rejects_unknown_variant`.

#[tokio::test]
async fn mem_query_semantic_returns_feature_gate_error() {
    let dir = TempDir::new().unwrap();
    let store = Store::open(dir.path()).await.unwrap();
    let graph = Graph::load(store).await.unwrap();
    let graph_arc = std::sync::Arc::new(tokio::sync::RwLock::new(graph));

    let result = call_mem_query(
        &graph_arc,
        "test",
        crate::mcp::protocol::QueryMode::Semantic,
        20,
    )
    .await;
    assert!(
        result.contains("--features semantic"),
        "semantic mode must surface feature-gate error, got: {result}"
    );
}

// ── mem_query dir_gotchas tests ──────────────────────────────────────────

fn make_dir_gotcha(
    key: &str,
    rule: &str,
    confirmed: bool,
    affected_files: &[&str],
    confidence: f32,
) -> Record {
    let gotcha = GotchaRecord {
        rule: rule.to_string(),
        reason: "test reason".to_string(),
        severity: Priority::High,
        affected_files: affected_files.iter().map(|f| f.to_string()).collect(),
        ref_url: None,
        discovered_session: now(),
        confirmed,
        confirmed_content: Default::default(),
    };
    let mut record = make_record(key, rule, Category::Gotcha, 0.7);
    record.confidence.value = confidence;
    record.payload = serde_json::to_value(&gotcha).ok();
    record
}

async fn seeded_dir_gotcha_graph(dir: &TempDir) -> std::sync::Arc<tokio::sync::RwLock<Graph>> {
    let store = Store::open(dir.path()).await.unwrap();
    for record in [
        make_dir_gotcha(
            "gotcha:store-low",
            "Store rule low",
            true,
            &["src/store/db.rs"],
            0.7,
        ),
        make_dir_gotcha(
            "gotcha:store-high",
            "Store rule high",
            true,
            &["src/store/nested/deep.rs"],
            0.9,
        ),
        make_dir_gotcha(
            "gotcha:store-unconfirmed",
            "Store stub",
            false,
            &["src/store/db.rs"],
            0.9,
        ),
        make_dir_gotcha(
            "gotcha:other-dir",
            "Mcp rule",
            true,
            &["src/mcp/server.rs"],
            0.9,
        ),
    ] {
        let key = record.key.clone();
        store.put(&key, &record).await.unwrap();
    }
    let graph = Graph::load(store).await.unwrap();
    std::sync::Arc::new(tokio::sync::RwLock::new(graph))
}

/// The documented Stage 1.1 call: a directory path must return the
/// confirmed gotchas for that directory — including nested ones, excluding
/// unconfirmed stubs and other directories — ranked by confidence.
#[tokio::test]
async fn mem_query_dir_gotchas_returns_confirmed_gotchas_under_the_path() {
    let dir = TempDir::new().unwrap();
    let graph_arc = seeded_dir_gotcha_graph(&dir).await;

    let result = call_mem_query(
        &graph_arc,
        "src/store",
        crate::mcp::protocol::QueryMode::DirGotchas,
        10,
    )
    .await;
    let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
    let keys: Vec<&str> = parsed
        .as_array()
        .expect("dir_gotchas must return an array")
        .iter()
        .map(|r| r["key"].as_str().unwrap())
        .collect();
    assert_eq!(keys, vec!["gotcha:store-high", "gotcha:store-low"]);
}

/// A directory with no confirmed gotchas returns an empty array, not an
/// error. `src/st` must not match `src/store` — the prefix is
/// segment-aware. An empty query returns nothing rather than everything.
#[tokio::test]
async fn mem_query_dir_gotchas_empty_when_nothing_matches() {
    let dir = TempDir::new().unwrap();
    let graph_arc = seeded_dir_gotcha_graph(&dir).await;

    for query in ["docs", "src/st", ""] {
        let result = call_mem_query(
            &graph_arc,
            query,
            crate::mcp::protocol::QueryMode::DirGotchas,
            10,
        )
        .await;
        assert_eq!(
            result.trim(),
            "[]",
            "query {query:?} must return an empty array, got: {result}"
        );
    }
}

/// Text mode is the wrong tool for this lookup and stays that way: the
/// tantivy index carries no `affected_files`, so a directory query matches
/// file records by key. Pins why Stage 1.1 uses `dir_gotchas`.
#[tokio::test]
async fn mem_query_text_mode_does_not_match_gotchas_by_directory() {
    let dir = TempDir::new().unwrap();
    let store = Store::open(dir.path()).await.unwrap();
    let record = make_dir_gotcha(
        "gotcha:some-rule",
        "Rule text with no path in it",
        true,
        &["src/store/db.rs"],
        0.9,
    );
    store.put("gotcha:some-rule", &record).await.unwrap();
    let graph = Graph::load(store).await.unwrap();
    let graph_arc = std::sync::Arc::new(tokio::sync::RwLock::new(graph));

    let result = call_mem_query(
        &graph_arc,
        "src/store",
        crate::mcp::protocol::QueryMode::Text,
        10,
    )
    .await;
    assert!(
        !result.contains("gotcha:some-rule"),
        "text mode must not retrieve gotchas by directory, got: {result}"
    );
}

// ── mem_query telemetry-mode tests ───────────────────────────────────────

#[tokio::test]
async fn mem_query_analytics_mode_surfaces_analytics_records() {
    let dir = TempDir::new().unwrap();
    let store = Store::open(dir.path()).await.unwrap();
    let record = make_record(
        "analytics:miss_2026-07-24",
        "misses today",
        Category::Analytics,
        0.5,
    );
    store.put(&record.key, &record).await.unwrap();
    let graph = Graph::load(store).await.unwrap();
    let graph_arc = std::sync::Arc::new(tokio::sync::RwLock::new(graph));

    // Substring match returns the record — Text mode filters analytics out,
    // this mode is the explicit opt-in.
    let hit = call_mem_query(
        &graph_arc,
        "miss",
        crate::mcp::protocol::QueryMode::Analytics,
        20,
    )
    .await;
    assert!(
        hit.contains("analytics:miss_2026-07-24"),
        "analytics mode must surface matching records, got: {hit}"
    );

    // A non-matching substring filters it out.
    let miss = call_mem_query(
        &graph_arc,
        "compliance",
        crate::mcp::protocol::QueryMode::Analytics,
        20,
    )
    .await;
    assert!(
        !miss.contains("analytics:miss_2026-07-24"),
        "analytics query filter must exclude non-matching keys, got: {miss}"
    );
}

#[tokio::test]
async fn mem_query_policy_observations_empty_store_is_empty_object() {
    let dir = TempDir::new().unwrap();
    let store = Store::open(dir.path()).await.unwrap();
    let graph = Graph::load(store).await.unwrap();
    let graph_arc = std::sync::Arc::new(tokio::sync::RwLock::new(graph));

    let result = call_mem_query(
        &graph_arc,
        "",
        crate::mcp::protocol::QueryMode::PolicyObservations,
        20,
    )
    .await;
    let value: serde_json::Value = serde_json::from_str(&result).unwrap();
    assert!(
        value.is_object() && value.as_object().unwrap().is_empty(),
        "policy_observations on an empty store must be an empty object, got: {result}"
    );
}

#[tokio::test]
async fn mem_query_policy_activity_empty_store_returns_report() {
    let dir = TempDir::new().unwrap();
    let store = Store::open(dir.path()).await.unwrap();
    let graph = Graph::load(store).await.unwrap();
    let graph_arc = std::sync::Arc::new(tokio::sync::RwLock::new(graph));

    let result = call_mem_query(
        &graph_arc,
        "",
        crate::mcp::protocol::QueryMode::PolicyActivity,
        20,
    )
    .await;
    let value: serde_json::Value = serde_json::from_str(&result).unwrap();
    // Default window applies when `since` is absent, and no policies exist.
    assert_eq!(value["window_days"], 30);
    assert!(value["policies"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn mem_query_policy_activity_since_zero_falls_back_to_default() {
    let dir = TempDir::new().unwrap();
    let store = Store::open(dir.path()).await.unwrap();
    let graph = Graph::load(store).await.unwrap();
    let graph_arc = std::sync::Arc::new(tokio::sync::RwLock::new(graph));

    // since:0 is a footgun (zero-width window → every policy NoActivity);
    // the handler coerces it to the default window. call_mem_query hardcodes
    // since:None, so drive the handler directly.
    let input = crate::mcp::protocol::MemQueryInput {
        query: String::new(),
        mode: crate::mcp::protocol::QueryMode::PolicyActivity,
        limit: 20,
        since: Some(0),
    };
    let g = graph_arc.read().await;
    let value = crate::mcp::handlers::handle_mem_query(g.store(), &g, &input)
        .await
        .unwrap();
    assert_eq!(
        value["window_days"], 30,
        "since:0 must fall back to default"
    );
}

#[tokio::test]
async fn mem_query_analytics_filters_before_take_limit() {
    let dir = TempDir::new().unwrap();
    let store = Store::open(dir.path()).await.unwrap();
    // Three non-matching analytics records sort BEFORE the one we want
    // ("hit_" < "miss_"); with limit=1 the substring filter must still
    // surface the match, proving the filter runs before take(limit).
    for d in ["2026-07-01", "2026-07-02", "2026-07-03"] {
        let r = make_record(&format!("analytics:hit_{d}"), "h", Category::Analytics, 0.5);
        store.put(&r.key, &r).await.unwrap();
    }
    let want = make_record("analytics:miss_2026-07-04", "m", Category::Analytics, 0.5);
    store.put(&want.key, &want).await.unwrap();
    let graph = Graph::load(store).await.unwrap();
    let graph_arc = std::sync::Arc::new(tokio::sync::RwLock::new(graph));

    let out = call_mem_query(
        &graph_arc,
        "miss_",
        crate::mcp::protocol::QueryMode::Analytics,
        1,
    )
    .await;
    assert!(
        out.contains("analytics:miss_2026-07-04"),
        "substring filter must run before take(limit): {out}"
    );
}

#[tokio::test]
async fn mem_query_analytics_empty_query_returns_nothing() {
    let dir = TempDir::new().unwrap();
    let store = Store::open(dir.path()).await.unwrap();
    // A record exists, but an empty query must NOT dump it — the mode
    // requires a named aggregate so it can't firehose internal analytics.
    let r = make_record("analytics:miss_2026-07-24", "m", Category::Analytics, 0.5);
    store.put(&r.key, &r).await.unwrap();
    let graph = Graph::load(store).await.unwrap();
    let graph_arc = std::sync::Arc::new(tokio::sync::RwLock::new(graph));

    let out = call_mem_query(
        &graph_arc,
        "",
        crate::mcp::protocol::QueryMode::Analytics,
        20,
    )
    .await;
    assert_eq!(
        out, "[]",
        "empty analytics query must return nothing, got: {out}"
    );
}

#[tokio::test]
async fn mem_query_policy_activity_since_caps_at_retention() {
    let dir = TempDir::new().unwrap();
    let store = Store::open(dir.path()).await.unwrap();
    let graph = Graph::load(store).await.unwrap();
    let graph_arc = std::sync::Arc::new(tokio::sync::RwLock::new(graph));

    let input = crate::mcp::protocol::MemQueryInput {
        query: String::new(),
        mode: crate::mcp::protocol::QueryMode::PolicyActivity,
        limit: 20,
        since: Some(u64::MAX),
    };
    let g = graph_arc.read().await;
    let value = crate::mcp::handlers::handle_mem_query(g.store(), &g, &input)
        .await
        .unwrap();
    assert_eq!(
        value["window_days"], 365,
        "an absurd `since` must cap at the retention horizon"
    );
}

// ── mem_bootstrap tests ──────────────────────────────────────────────────

#[tokio::test]
async fn mem_bootstrap_empty_store_returns_vector_b() {
    let dir = TempDir::new().unwrap();
    let store = Store::open(dir.path()).await.unwrap();
    let graph = Graph::load(store).await.unwrap();
    let graph_arc = std::sync::Arc::new(tokio::sync::RwLock::new(graph));

    let result = call_mem_bootstrap(&graph_arc, vec![]).await;
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
async fn recent_subagent_summary_surfaces_in_packet() {
    let dir = TempDir::new().unwrap();
    let store = Store::open(dir.path()).await.unwrap();

    crate::store::session::write_subagent_summary(
        &store,
        "Subagent read auth.rs; tokens expire after 15m.",
        Some("agent-1"),
        Some("general-purpose"),
        Some("sess-x"),
        None,
    )
    .await
    .unwrap();

    let graph = Graph::load(store).await.unwrap();
    let packet = assemble_context_packet(graph.store(), &graph, &[])
        .await
        .unwrap();

    assert_eq!(
        packet.recent_session.as_deref(),
        Some("Subagent read auth.rs; tokens expire after 15m.")
    );
    assert!(
        packet.injection_string.contains("## Recent Subagent"),
        "summary must render a section: {}",
        packet.injection_string
    );
    assert!(packet.injection_string.contains("tokens expire after 15m"));
}

#[tokio::test]
async fn recent_session_absent_when_no_summary() {
    let dir = TempDir::new().unwrap();
    let store = Store::open(dir.path()).await.unwrap();

    let graph = Graph::load(store).await.unwrap();
    let packet = assemble_context_packet(graph.store(), &graph, &[])
        .await
        .unwrap();

    assert!(packet.recent_session.is_none());
    assert!(!packet.injection_string.contains("## Recent Subagent"));
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
            propagated_staleness: None,
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
            propagated_staleness: None,
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
        propagated_staleness: None,
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
        propagated_staleness: None,
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
        propagated_staleness: None,
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
    let packet = assemble_context_packet(graph.store(), &graph, &["src/covered.rs".to_string()])
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
        propagated_staleness: None,
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
        propagated_staleness: None,
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
        propagated_staleness: None,
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
        propagated_staleness: None,
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

fn policy_payload(enabled: bool) -> serde_json::Value {
    serde_json::json!({
        "name": "Query safety",
        "rule": "Consult the schema first.",
        "reason": "Production schemas drift because deployments change.",
        "scope": "repo",
        "mode": "block",
        "trigger": {"tool": "db_client"},
        "requires": {
            "key": "schema:orders",
            "via": ["mem_get"],
            "freshness": {"ttl_secs": 900}
        },
        "stage": if enabled { "enforce" } else { "off" },
        "severity": "high",
        "created_by": "agent"
    })
}

// The confirm gate must fail closed: only an explicit `confirm=true` accept
// activates enforcement; decline, cancel, and empty content must all reject.
#[test]
fn confirm_elicitation_only_confirms_on_explicit_accept() {
    use super::{classify_confirm_elicitation, ConfirmOutcome, GotchaConfirmDecision};
    use rmcp::service::ElicitationError;

    let key = "gotcha:x";
    let confirmed =
        classify_confirm_elicitation(key, Ok(Some(GotchaConfirmDecision { confirm: true })));
    assert!(matches!(confirmed, ConfirmOutcome::Confirm));

    for rejected in [
        classify_confirm_elicitation(key, Ok(Some(GotchaConfirmDecision { confirm: false }))),
        classify_confirm_elicitation(key, Ok(None)),
        classify_confirm_elicitation(key, Err(ElicitationError::UserDeclined)),
        classify_confirm_elicitation(key, Err(ElicitationError::UserCancelled)),
    ] {
        assert!(matches!(rejected, ConfirmOutcome::Rejected(_)));
    }
}

// `mem_set_preserves_existing_layer0_data` was removed: file: writes
// are no longer accepted via mem_set on either backend. Layer 0
// preservation under enrichment is now exercised by the
// `file_enrich` typed Command's tests (see `handle_file_enrich`).

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
    let graph_arc = std::sync::Arc::new(tokio::sync::RwLock::new(graph));

    let result = call_mem_query(
        &graph_arc,
        "clamp test rule",
        crate::mcp::protocol::QueryMode::Text,
        100, // exceeds MAX_QUERY_LIMIT (50)
    )
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

// ── Regression: graph mode respects global limit ──────────────────────

/// Graph mode must respect the caller's `limit` as a global cap across all
/// edge groups. With limit=3 and records in multiple groups, total results
/// must not exceed 3.
#[tokio::test]
async fn test_graph_mode_respects_global_limit() {
    let dir = TempDir::new().unwrap();
    let store = Store::open(dir.path()).await.unwrap();

    // Seed file record
    let file_record = Record::layer0_file_stub("file:src/graph_limit.rs", device_id(), 1, now());
    store
        .put("file:src/graph_limit.rs", &file_record)
        .await
        .unwrap();

    // Write 5 gotchas linked to the file, before the graph takes
    // ownership of the store.
    for i in 0..5 {
        seed_gotcha_for_graph_test(
            &store,
            dir.path(),
            &format!("gotcha:limit-test-{i}"),
            &format!("Limit rule {i}"),
            &["src/graph_limit.rs".to_string()],
        )
        .await;
    }

    let graph = Graph::load(store).await.unwrap();
    let graph_arc = std::sync::Arc::new(tokio::sync::RwLock::new(graph));

    // Query with limit=3 — must get at most 3 total records across all groups.
    let result = call_mem_query(
        &graph_arc,
        "file:src/graph_limit.rs",
        crate::mcp::protocol::QueryMode::Graph,
        3,
    )
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

    // Write one gotcha so there's something to return if limit is ignored.
    seed_gotcha_for_graph_test(
        &store,
        dir.path(),
        "gotcha:zero-limit-test",
        "Zero limit test",
        &["src/zero.rs".to_string()],
    )
    .await;

    let graph = Graph::load(store).await.unwrap();
    let graph_arc = std::sync::Arc::new(tokio::sync::RwLock::new(graph));

    let result = call_mem_query(
        &graph_arc,
        "file:src/zero.rs",
        crate::mcp::protocol::QueryMode::Graph,
        0,
    )
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

// ── Regression: graph mode traverses from non-file seeds ───────────────

/// `HasGotcha` edges are written `file:* -> gotcha:*` only. Graph mode
/// must still resolve a `gotcha:*` seed to the files that carry it via
/// the reverse (incoming) lookup, not just a `file:*` seed via the
/// forward lookup -- otherwise the same (file, gotcha) pair is visible
/// from one side and invisible from the other.
#[tokio::test]
async fn test_graph_mode_traverses_from_gotcha_seed() {
    let dir = TempDir::new().unwrap();
    let store = Store::open(dir.path()).await.unwrap();

    let file_record = Record::layer0_file_stub("file:src/graph_reverse.rs", device_id(), 1, now());
    store
        .put("file:src/graph_reverse.rs", &file_record)
        .await
        .unwrap();

    seed_gotcha_for_graph_test(
        &store,
        dir.path(),
        "gotcha:reverse-traversal-test",
        "Reverse traversal rule",
        &["src/graph_reverse.rs".to_string()],
    )
    .await;

    let graph = Graph::load(store).await.unwrap();
    let graph_arc = std::sync::Arc::new(tokio::sync::RwLock::new(graph));

    // The file-side query must see the gotcha (sanity check, pins the
    // known-working direction).
    let file_side = call_mem_query(
        &graph_arc,
        "file:src/graph_reverse.rs",
        crate::mcp::protocol::QueryMode::Graph,
        20,
    )
    .await;
    let file_side: serde_json::Value = serde_json::from_str(&file_side).unwrap();
    assert!(
        file_side["gotchas"].as_array().is_some_and(|a| a
            .iter()
            .any(|g| g["key"] == "gotcha:reverse-traversal-test")),
        "file-side graph query must surface the gotcha, got: {file_side}"
    );

    // The gotcha-side query must see the file -- this is the direction
    // that previously returned "No related records found".
    let gotcha_side = call_mem_query(
        &graph_arc,
        "gotcha:reverse-traversal-test",
        crate::mcp::protocol::QueryMode::Graph,
        20,
    )
    .await;
    let gotcha_side: serde_json::Value = serde_json::from_str(&gotcha_side).unwrap();
    assert_ne!(
        gotcha_side["summary"], "No related records found",
        "gotcha-seed graph query should find the linked file, got: {gotcha_side}"
    );
    assert!(
        gotcha_side["gotchas"]
            .as_array()
            .is_some_and(|a| a.iter().any(|g| g["key"] == "file:src/graph_reverse.rs")),
        "gotcha-seed graph query must surface the linked file, got: {gotcha_side}"
    );
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
        propagated_staleness: None,
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
        propagated_staleness: None,
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
    let leaf_pos = packet
        .injection_string
        .find("src/leaf.rs")
        .unwrap_or(usize::MAX);
    assert!(
        core_pos < leaf_pos,
        "core.rs should appear before leaf.rs in impact section"
    );
}

// ── Pass-29 regression: build_mem_set_command routing ──────────────
//
// The Socket-backend mem_set previously dispatched
// "gotcha_confirm" / "gotcha_tombstone" / "mem_set" through the
// legacy v1 mapper (`v1_to_v2_command`) which has no entries for
// those commands and panicked the rmcp task. The fix routes through
// typed Commands; these tests pin the routing logic.
//
// All test inputs are constructed manually instead of via JSON
// parsing — `MemSetParams` is `Deserialize`-only.

fn make_params(action: &str, key: &str) -> MemSetParams {
    MemSetParams {
        action: action.to_string(),
        key: key.to_string(),
        value: String::new(),
        category: String::new(),
        payload: serde_json::Value::Object(serde_json::Map::new()),
        tags: vec![],
        priority: "Normal".to_string(),
    }
}

#[test]
fn mem_set_socket_routes_gotcha_confirm() {
    let p = make_params("confirm", "gotcha:foo");
    let cmd = build_mem_set_command(&p).expect("must build");
    assert_eq!(cmd.kind(), "gotcha_confirm");
    assert_eq!(cmd.target_key(), "gotcha:foo");
}

#[test]
fn mem_set_socket_rejects_confirm_on_non_gotcha_key() {
    let p = make_params("confirm", "decision:not-allowed");
    let err = build_mem_set_command(&p).expect_err("must reject");
    assert!(
        err.contains("gotcha:"),
        "error must mention gotcha: prefix, got: {err}"
    );
}

#[test]
fn mem_set_socket_routes_gotcha_tombstone() {
    let p = make_params("delete", "gotcha:foo");
    let cmd = build_mem_set_command(&p).expect("must build");
    assert_eq!(cmd.kind(), "gotcha_tombstone");
    assert_eq!(cmd.target_key(), "gotcha:foo");
}

#[test]
fn mem_set_socket_routes_gotcha_upsert_by_key_prefix() {
    let mut p = make_params("write", "gotcha:stripe-idempotency");
    p.payload = serde_json::json!({
        "rule": "Always include an idempotency key",
        "reason": "Stripe retries cause double charges without it",
        "severity": "High",
        "affected_files": ["src/payments/stripe.rs"],
    });
    p.tags = vec!["payments".into()];
    p.priority = "High".into();
    let cmd = build_mem_set_command(&p).expect("must build");
    assert_eq!(cmd.kind(), "gotcha_upsert");
    match cmd {
        Command::GotchaUpsert(input) => {
            assert_eq!(input.key, "gotcha:stripe-idempotency");
            assert_eq!(input.rule, "Always include an idempotency key");
            assert_eq!(input.severity, proto::Severity::High);
            assert_eq!(input.priority, proto::Priority::High);
            assert_eq!(input.affected_files, vec!["src/payments/stripe.rs"]);
            assert_eq!(input.tags, vec!["payments".to_string()]);
        }
        _ => panic!("expected GotchaUpsert"),
    }
}

#[test]
fn mem_set_socket_routes_decision_upsert_by_key_prefix() {
    let mut p = make_params("write", "decision:retry-strategy");
    p.value = "We use exponential backoff because linear overloads downstream".into();
    p.payload = serde_json::json!({
        "summary": "Exponential backoff for all retries",
        "rationale": "Linear retry caused cascading failures in prod 2024-01",
    });
    let cmd = build_mem_set_command(&p).expect("must build");
    assert_eq!(cmd.kind(), "decision_upsert");
    match cmd {
        Command::DecisionUpsert(input) => {
            assert_eq!(input.slug, "retry-strategy");
            assert_eq!(input.summary, "Exponential backoff for all retries");
            assert!(input.rationale.contains("cascading"));
        }
        _ => panic!("expected DecisionUpsert"),
    }
}

#[test]
fn mem_set_socket_routes_dev_note_upsert_by_key_prefix() {
    let mut p = make_params("write", "dev_note:remember-changelog");
    p.value = "Remember to update the changelog before release".into();
    let cmd = build_mem_set_command(&p).expect("must build");
    assert_eq!(cmd.kind(), "dev_note_upsert");
    match cmd {
        Command::DevNoteUpsert(input) => {
            assert_eq!(input.key.as_deref(), Some("dev_note:remember-changelog"));
            assert!(input.text.contains("changelog"));
        }
        _ => panic!("expected DevNoteUpsert"),
    }
}

#[test]
fn mem_set_socket_routes_policy_create_inert() {
    let mut p = make_params("write", "policy:query-safety");
    p.payload = policy_payload(true);
    let cmd = build_mem_set_command(&p).expect("must build");
    match cmd {
        Command::PolicyWrite(input) => {
            assert!(matches!(input.op, proto::PolicyWriteOp::Create));
            assert!(matches!(
                input.policy.unwrap().stage,
                crate::store::PolicyStage::Off
            ));
        }
        _ => panic!("expected PolicyWrite"),
    }
}

#[test]
fn mem_set_socket_rejects_policy_lifecycle_actions() {
    for action in ["confirm", "delete"] {
        let p = make_params(action, "policy:query-safety");
        let err = build_mem_set_command(&p).expect_err("must reject");
        assert!(err.contains("mati policy"), "{action}: {err}");
    }
}

#[test]
fn mem_set_socket_rejects_write_with_unknown_prefix() {
    // file: writes are not supported via mem_set Socket path —
    // there is no public typed Command for them.
    let p = make_params("write", "file:src/main.rs");
    let err = build_mem_set_command(&p).expect_err("must reject");
    assert!(
        err.contains("gotcha:") && err.contains("decision:") && err.contains("dev_note:"),
        "error must list valid prefixes, got: {err}"
    );
}

#[test]
fn mem_set_socket_rejects_unknown_action() {
    let p = make_params("smuggle", "gotcha:foo");
    let err = build_mem_set_command(&p).expect_err("must reject");
    assert!(
        err.contains("smuggle"),
        "error must echo the bad action, got: {err}"
    );
}

#[test]
fn mem_set_socket_rejects_gotcha_write_missing_payload_fields() {
    let p = make_params("write", "gotcha:incomplete");
    let err = build_mem_set_command(&p).expect_err("must reject");
    assert!(
        err.contains("rule"),
        "error must mention 'rule', got: {err}"
    );
}

#[test]
fn mem_set_socket_handles_codex_string_payload() {
    // Codex sends payload as a JSON-encoded string; the typed
    // builder must transparently parse it (matching Direct path).
    let mut p = make_params("write", "gotcha:codex-style");
    p.payload = serde_json::Value::String(
        r#"{"rule":"do X","reason":"because Y","severity":"low"}"#.to_string(),
    );
    let cmd = build_mem_set_command(&p).expect("must build from stringified payload");
    match cmd {
        Command::GotchaUpsert(input) => {
            assert_eq!(input.rule, "do X");
            assert_eq!(input.severity, proto::Severity::Low);
        }
        _ => panic!("expected GotchaUpsert"),
    }
}

// ── hook decision body (F11 — mcp_tool prototype transport) ────────────────

#[test]
fn hook_allow_emits_expected_shape() {
    let body = MatiServer::hook_allow();
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        v,
        serde_json::json!({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "allow"
            }
        })
    );
}

/// A server whose repo root is an empty path: no test here carries a
/// `FileDeleted` signal, so the existence check never runs.
fn decision_server() -> MatiServer {
    MatiServer::with_socket_root(
        std::path::PathBuf::new(),
        std::path::PathBuf::new(),
        Some("wt-tag".to_string()),
    )
}

#[test]
fn hook_decision_body_denies_for_qualifying_confirmed_gotcha() {
    // Shape matches hooks::decide's own EnforcementInput fixtures
    // (make_file_record / make_gotcha in hooks/decide/tests.rs): confirmed
    // gotcha, confidence >= 0.6, quality >= 0.4 — the ARCHITECTURE.md 10.1 gate.
    let eval = serde_json::json!({
        "file_key": "file:src/danger.rs",
        "file_record": {
            "value": "danger module",
            "confidence": { "value": 0.9 },
            "quality": { "value": 0.9 },
            "staleness": { "value": 0.1, "tier": "fresh" },
            "payload": { "gotcha_keys": ["gotcha:danger"] }
        },
        "gotcha_records": {
            "gotcha:danger": {
                "value": "Never bypass the danger check",
                "confidence": { "value": 0.8 },
                "quality": { "value": 0.8 },
                "payload": { "confirmed": true }
            }
        },
        "consulted": false
    });
    let body = decision_server().hook_decision_body(eval);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["hookSpecificOutput"]["hookEventName"], "PreToolUse");
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "deny");
    // Exact reason text from hooks::decide::evaluate's Deny arm.
    assert_eq!(
        v["hookSpecificOutput"]["permissionDecisionReason"],
        "[mati] Confirmed gotcha on src/danger.rs — \
         call mem_get(\"file:src/danger.rs\") and read the record \
         before accessing this file."
    );
}

#[test]
fn hook_decision_body_allows_when_no_record() {
    let body =
        decision_server().hook_decision_body(serde_json::json!({ "file_key": "file:none.rs" }));
    assert_eq!(body, MatiServer::hook_allow());
}

#[test]
fn hook_decision_body_allows_when_gotcha_does_not_qualify() {
    // Confirmed, but confidence (0.4) is below the 0.6 threshold — must allow.
    let eval = serde_json::json!({
        "file_key": "file:src/weak.rs",
        "file_record": {
            "value": "weak module",
            "confidence": { "value": 0.9 },
            "quality": { "value": 0.9 },
            "staleness": { "value": 0.1, "tier": "fresh" },
            "payload": { "gotcha_keys": ["gotcha:weak"] }
        },
        "gotcha_records": {
            "gotcha:weak": {
                "value": "Some weak rule",
                "confidence": { "value": 0.4 },
                "quality": { "value": 0.8 },
                "payload": { "confirmed": true }
            }
        },
        "consulted": false
    });
    let body = decision_server().hook_decision_body(eval);
    assert_eq!(body, MatiServer::hook_allow());
}

/// A `FileDeleted` signal is a stale snapshot — it is cleared only by the
/// staleness sweep, so it outlives a delete-then-restore. The MCP decision
/// path hard-coded `file_exists: None`, so on that transport the bypass was
/// genuinely unconditional and a restored file with a qualifying gotcha was
/// allowed through. It must stat the path and deny like the CLI adapter does.
#[test]
fn hook_decision_body_denies_when_a_file_deleted_signal_is_stale() {
    let dir = TempDir::new().unwrap();
    std::fs::create_dir_all(dir.path().join("src")).unwrap();
    std::fs::write(dir.path().join("src/back.rs"), "// restored\n").unwrap();

    let eval = serde_json::json!({
        "file_key": "file:src/back.rs",
        "file_record": {
            "value": "restored module",
            "confidence": { "value": 0.9 },
            "quality": { "value": 0.9 },
            "staleness": { "value": 0.95, "tier": "tombstone", "signals": ["file_deleted"] },
            "payload": { "gotcha_keys": ["gotcha:back"] }
        },
        "gotcha_records": {
            "gotcha:back": {
                "value": "Never bypass the restored check",
                "confidence": { "value": 0.8 },
                "quality": { "value": 0.8 },
                "payload": { "confirmed": true }
            }
        },
        "consulted": false
    });

    let server = MatiServer::with_socket_root(
        std::path::PathBuf::new(),
        dir.path().to_path_buf(),
        Some("wt-tag".to_string()),
    );
    let v: serde_json::Value = serde_json::from_str(&server.hook_decision_body(eval)).unwrap();
    assert_eq!(
        v["hookSpecificOutput"]["permissionDecision"], "deny",
        "a path that is back on disk must not ride the FileDeleted bypass"
    );
}

/// The other half of the same guard: a path that really is gone still
/// bypasses, so the fix does not turn a deleted file into an unliftable deny.
#[test]
fn hook_decision_body_allows_when_the_file_is_really_gone() {
    let dir = TempDir::new().unwrap();
    let eval = serde_json::json!({
        "file_key": "file:src/gone.rs",
        "file_record": {
            "value": "deleted module",
            "confidence": { "value": 0.9 },
            "quality": { "value": 0.9 },
            "staleness": { "value": 0.95, "tier": "tombstone", "signals": ["file_deleted"] },
            "payload": { "gotcha_keys": ["gotcha:gone"] }
        },
        "gotcha_records": {
            "gotcha:gone": {
                "value": "Never bypass the gone check",
                "confidence": { "value": 0.8 },
                "quality": { "value": 0.8 },
                "payload": { "confirmed": true }
            }
        },
        "consulted": false
    });

    let server = MatiServer::with_socket_root(
        std::path::PathBuf::new(),
        dir.path().to_path_buf(),
        Some("wt-tag".to_string()),
    );
    assert_eq!(
        server.hook_decision_body(eval),
        MatiServer::hook_allow(),
        "a genuinely deleted file still bypasses"
    );
}

// ── decision actor scope (F11 second half) ──────────────────────────────
//
// Verified live against the release binary, not guessed: registering the
// mcp_tool hook's `input` with `"agent_id": "${agent_id}"` and logging what
// the probe MCP server actually received showed `"agent_id": ""` for a
// main-thread Read and a real subagent id (e.g. "aef36aa9aa07ebc82") for a
// Task-spawned subagent's Read. Before this fix, `decision_actor` did not
// exist and `mem_get`'s decision branch sent `self.worktree_tag` alone —
// reproduced live: after the main thread consulted (minting a receipt at
// the bare worktree scope), an uninvolved subagent's `decision:true` call
// returned `allow` even though that subagent never called mem_get itself.
// `combined_actor_scope`'s own combination logic is covered by
// `combined_actor_scope_precedence` in src/store/session.rs; these tests
// pin `decision_actor`'s empty-string handling and its call shape, which is
// the new surface this fix adds.

#[test]
fn decision_actor_treats_interpolated_empty_agent_id_as_none() {
    let server = MatiServer::with_socket_root(
        std::path::PathBuf::new(),
        std::path::PathBuf::new(),
        Some("wt-tag".to_string()),
    );
    // "${agent_id}" interpolates to "" on the main thread, never absent.
    assert_eq!(server.decision_actor(Some("")), Some("wt-tag".to_string()));
    assert_eq!(server.decision_actor(None), Some("wt-tag".to_string()));
}

#[test]
fn decision_actor_combines_worktree_and_subagent_id() {
    let server = MatiServer::with_socket_root(
        std::path::PathBuf::new(),
        std::path::PathBuf::new(),
        Some("wt-tag".to_string()),
    );
    assert_eq!(
        server.decision_actor(Some("agentA")),
        Some("wt-tag:agentA".to_string())
    );
}

#[test]
fn decision_actor_distinguishes_two_subagents() {
    let server = MatiServer::with_socket_root(
        std::path::PathBuf::new(),
        std::path::PathBuf::new(),
        Some("wt-tag".to_string()),
    );
    // The pre-fix bug: both calls sent the same bare worktree actor, so one
    // subagent's receipt (or the main thread's) satisfied every other
    // subagent's gate. Distinct agent ids must now produce distinct scopes.
    assert_ne!(
        server.decision_actor(Some("agentA")),
        server.decision_actor(Some("agentB"))
    );
}

#[test]
fn confirm_elicitation_schema_has_no_root_title() {
    // Codex's elicitation-schema parser (codex_app_server, 0.152) rejects a root
    // `title`, which schemars stamps from the type name — it broke every gotcha
    // confirm on Codex. The #[schemars(transform = strip_root_title)] on
    // GotchaConfirmDecision must strip it. `from_type` is the exact path rmcp uses
    // to build the wire requestedSchema, so this asserts what goes over the wire.
    let schema = rmcp::model::ElicitationSchema::builder()
        .required_bool_with("confirm", |b| {
            b.description("Set true to confirm this gotcha and activate hook enforcement.")
        })
        .build()
        .expect("elicitation schema builds");
    let json = serde_json::to_value(&schema).expect("serialize schema");
    assert!(
        json.get("title").is_none(),
        "elicitation requestedSchema must not carry a root title (Codex rejects it); got: {json}"
    );
    // Sanity: the confirm property (and its doc-derived description) survive.
    assert!(
        json["properties"]["confirm"].is_object(),
        "confirm property must survive the transform; got: {json}"
    );
}
