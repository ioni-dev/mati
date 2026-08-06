use super::*;
use crate::store::record::*;
use tempfile::TempDir;

/// A deadline no test will reach — for call sites not testing the budget.
fn far_deadline() -> Instant {
    Instant::now() + std::time::Duration::from_secs(3600)
}

fn make_file_record_with_staleness(value: f32) -> Record {
    Record {
        key: "file:src/main.rs".to_string(),
        value: String::new(),
        category: Category::File,
        priority: Priority::Normal,
        tags: vec![],
        created_at: 1_000_000,
        updated_at: 1_000_000,
        ref_url: None,
        staleness: StalenessScore {
            value,
            tier: StalenessScore::tier_from_value(value),
            signals: vec![],
            computed_at: 0,
            last_record_sha: String::new(),
        },
        lifecycle: RecordLifecycle::Active,
        version: RecordVersion {
            device_id: uuid::Uuid::new_v4(),
            logical_clock: 1,
            wall_clock: 1_000_000,
        },
        quality: QualityScore::layer0_default(),
        access_count: 0,
        last_accessed: 0,
        source: RecordSource::StaticAnalysis,
        confidence: ConfidenceScore::for_new_record(&RecordSource::StaticAnalysis),
        gap_analysis_score: 0.0,
        payload: None,
    }
}

fn make_gotcha_record(key: &str) -> Record {
    let gotcha = GotchaRecord {
        rule: "test rule".into(),
        reason: "test reason".into(),
        severity: Priority::High,
        affected_files: vec!["src/main.rs".into()],
        ref_url: None,
        discovered_session: 0,
        confirmed: true,
        confirmed_content: Default::default(),
    };
    Record {
        key: key.to_string(),
        value: gotcha.rule.clone(),
        payload: serde_json::to_value(&gotcha).ok(),
        category: Category::Gotcha,
        priority: Priority::High,
        tags: vec![],
        created_at: 1_000_000,
        updated_at: 1_000_000,
        ref_url: None,
        staleness: StalenessScore::fresh(),
        lifecycle: RecordLifecycle::Active,
        version: RecordVersion {
            device_id: uuid::Uuid::new_v4(),
            logical_clock: 1,
            wall_clock: 1_000_000,
        },
        quality: QualityScore::layer0_default(),
        access_count: 0,
        last_accessed: 0,
        source: RecordSource::DeveloperManual,
        confidence: ConfidenceScore::for_new_record(&RecordSource::DeveloperManual),
        gap_analysis_score: 0.0,
    }
}

fn make_linked_file_record() -> FileRecord {
    FileRecord {
        path: "src/main.rs".into(),
        purpose: String::new(),
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
        token_cost_estimate: 0,
        last_modified_session: 0,
        content_hash: None,
        line_count: 0,
        blast_radius: None,
        propagated_staleness: None,
    }
}

fn empty_diff() -> ReparseDiff {
    ReparseDiff {
        entry_points_added: vec![],
        entry_points_removed: vec![],
        imports_added: vec![],
        imports_removed: vec![],
        todos_changed: false,
        unsafe_delta: 0,
        unwrap_delta: 0,
    }
}

#[test]
fn empty_diff_produces_no_signals() {
    let mut record = make_file_record_with_staleness(0.0);
    let signals = apply_reparse_staleness(&mut record, &empty_diff());
    assert!(signals.is_empty());
    assert!(record.staleness.value < 0.01);
}

#[test]
fn entry_point_changes_bump_staleness() {
    let mut record = make_file_record_with_staleness(0.0);
    let diff = ReparseDiff {
        entry_points_added: vec!["new_fn".into()],
        entry_points_removed: vec!["old_fn".into()],
        ..empty_diff()
    };
    let signals = apply_reparse_staleness(&mut record, &diff);
    assert_eq!(signals.len(), 1);
    assert!((record.staleness.value - 0.30).abs() < 0.01);
    assert_eq!(record.staleness.tier, StalenessTier::Aging);
}

#[test]
fn import_changes_bump_staleness() {
    let mut record = make_file_record_with_staleness(0.0);
    let diff = ReparseDiff {
        imports_added: vec!["new_dep".into()],
        ..empty_diff()
    };
    let signals = apply_reparse_staleness(&mut record, &diff);
    assert_eq!(signals.len(), 1);
    assert!((record.staleness.value - 0.10).abs() < 0.01);
}

#[test]
fn increment_capped_at_max() {
    let mut record = make_file_record_with_staleness(0.0);
    let diff = ReparseDiff {
        entry_points_added: vec!["a".into(), "b".into(), "c".into(), "d".into()],
        imports_added: vec!["x".into(), "y".into(), "z".into()],
        ..empty_diff()
    };
    let _signals = apply_reparse_staleness(&mut record, &diff);
    // 4*0.15 + 3*0.10 = 0.90, capped at 0.40
    assert!((record.staleness.value - 0.40).abs() < 0.01);
}

#[test]
fn staleness_does_not_exceed_one() {
    let mut record = make_file_record_with_staleness(0.85);
    let diff = ReparseDiff {
        entry_points_added: vec!["a".into(), "b".into()],
        ..empty_diff()
    };
    let _signals = apply_reparse_staleness(&mut record, &diff);
    assert!(record.staleness.value <= 1.0);
}

#[test]
fn tier_updates_correctly_after_increment() {
    let mut record = make_file_record_with_staleness(0.35);
    let diff = ReparseDiff {
        entry_points_removed: vec!["removed_fn".into()],
        ..empty_diff()
    };
    let _signals = apply_reparse_staleness(&mut record, &diff);
    // 0.35 + 0.15 = 0.50 → Stale
    assert_eq!(record.staleness.tier, StalenessTier::Stale);
}

#[tokio::test]
async fn cascade_staleness_bumps_linked_gotchas() {
    let dir = TempDir::new().unwrap();
    let store = Store::open(dir.path()).await.unwrap();

    let gotcha = make_gotcha_record("gotcha:test-rule");
    store.put("gotcha:test-rule", &gotcha).await.unwrap();

    let file_record = FileRecord {
        path: "src/main.rs".into(),
        purpose: String::new(),
        entry_points: vec![],
        imports: vec![],
        gotcha_keys: vec!["gotcha:test-rule".into()],
        decision_keys: vec![],
        todos: vec![],
        unsafe_count: 0,
        unwrap_count: 0,
        change_frequency: 0,
        last_author: None,
        is_hotspot: false,
        token_cost_estimate: 0,
        last_modified_session: 0,
        content_hash: None,
        line_count: 0,
        blast_radius: None,
        propagated_staleness: None,
    };

    let cascaded = cascade_staleness_to_gotchas(&store, &file_record)
        .await
        .unwrap();

    assert_eq!(cascaded, 1);

    let updated = store.get("gotcha:test-rule").await.unwrap().unwrap();
    assert!((updated.staleness.value - 0.10).abs() < 0.01);
    assert!(updated.staleness.signals.iter().any(|s| {
        matches!(s, StalenessSignal::LinkedFileChanged { path } if path == "src/main.rs")
    }));

    store.close().await.unwrap();
}

#[tokio::test]
async fn cascade_noop_when_no_gotcha_keys() {
    let dir = TempDir::new().unwrap();
    let store = Store::open(dir.path()).await.unwrap();

    let file_record = FileRecord {
        path: "src/main.rs".into(),
        purpose: String::new(),
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
        token_cost_estimate: 0,
        last_modified_session: 0,
        content_hash: None,
        line_count: 0,
        blast_radius: None,
        propagated_staleness: None,
    };

    let cascaded = cascade_staleness_to_gotchas(&store, &file_record)
        .await
        .unwrap();
    assert_eq!(cascaded, 0);

    store.close().await.unwrap();
}

#[tokio::test]
async fn cascade_skips_missing_gotcha_records() {
    let dir = TempDir::new().unwrap();
    let store = Store::open(dir.path()).await.unwrap();

    let file_record = FileRecord {
        path: "src/main.rs".into(),
        purpose: String::new(),
        entry_points: vec![],
        imports: vec![],
        gotcha_keys: vec!["gotcha:nonexistent".into()],
        decision_keys: vec![],
        todos: vec![],
        unsafe_count: 0,
        unwrap_count: 0,
        change_frequency: 0,
        last_author: None,
        is_hotspot: false,
        token_cost_estimate: 0,
        last_modified_session: 0,
        content_hash: None,
        line_count: 0,
        blast_radius: None,
        propagated_staleness: None,
    };

    let cascaded = cascade_staleness_to_gotchas(&store, &file_record)
        .await
        .unwrap();
    assert_eq!(cascaded, 0);

    store.close().await.unwrap();
}

// ── M-13-A: StalenessAnalyzer tests ─────────────────────────────────────

/// Helper: create a record with specific timestamps for time_factor tests.
fn make_record_at(key: &str, updated_at: u64, last_accessed: u64) -> Record {
    Record {
        key: key.to_string(),
        value: String::new(),
        category: Category::File,
        priority: Priority::Normal,
        tags: vec![],
        created_at: updated_at,
        updated_at,
        ref_url: None,
        staleness: StalenessScore {
            value: 0.0,
            tier: StalenessTier::Fresh,
            signals: vec![],
            computed_at: 0,
            last_record_sha: String::new(),
        },
        lifecycle: RecordLifecycle::Active,
        version: RecordVersion {
            device_id: uuid::Uuid::new_v4(),
            logical_clock: 1,
            wall_clock: updated_at,
        },
        quality: QualityScore::layer0_default(),
        access_count: 0,
        last_accessed,
        source: RecordSource::StaticAnalysis,
        confidence: ConfidenceScore::for_new_record(&RecordSource::StaticAnalysis),
        gap_analysis_score: 0.0,
        payload: None,
    }
}

/// Helper: make a file record with FileRecord value JSON.
fn make_file_record_full(
    key: &str,
    imports: Vec<String>,
    gotcha_keys: Vec<String>,
    decision_keys: Vec<String>,
    last_modified_session: u64,
) -> Record {
    let fr = FileRecord {
        path: key.strip_prefix("file:").unwrap_or(key).to_string(),
        purpose: String::new(),
        entry_points: vec![],
        imports,
        gotcha_keys: gotcha_keys.clone(),
        decision_keys: decision_keys.clone(),
        todos: vec![],
        unsafe_count: 0,
        unwrap_count: 0,
        change_frequency: 0,
        last_author: None,
        is_hotspot: false,
        token_cost_estimate: 0,
        last_modified_session,
        content_hash: None,
        line_count: 0,
        blast_radius: None,
        propagated_staleness: None,
    };
    Record {
        key: key.to_string(),
        value: serde_json::to_string(&fr).unwrap(),
        category: Category::File,
        priority: Priority::Normal,
        tags: vec![],
        created_at: 1_000_000,
        updated_at: 1_000_000,
        ref_url: None,
        staleness: StalenessScore::fresh(),
        lifecycle: RecordLifecycle::Active,
        version: RecordVersion {
            device_id: uuid::Uuid::new_v4(),
            logical_clock: 1,
            wall_clock: 1_000_000,
        },
        quality: QualityScore::layer0_default(),
        access_count: 0,
        last_accessed: 0,
        source: RecordSource::StaticAnalysis,
        confidence: ConfidenceScore::for_new_record(&RecordSource::StaticAnalysis),
        gap_analysis_score: 0.0,
        payload: None,
    }
}

// ── time_factor tests ───────────────────────────────────────────────────

#[test]
fn time_factor_zero_when_just_updated() {
    let now = 10_000_000u64;
    let record = make_record_at("file:test.rs", now, 0);
    let factor = time_factor(&record, now);
    assert!(factor.abs() < 0.001, "expected ~0.0, got {factor}");
}

#[test]
fn time_factor_half_at_45_days() {
    let now = 10_000_000u64;
    let forty_five_days_ago = now - (45 * 86400);
    let record = make_record_at("file:test.rs", forty_five_days_ago, 0);
    let factor = time_factor(&record, now);
    assert!(
        (factor - 0.5).abs() < 0.02,
        "expected ~0.5 at 45 days, got {factor}"
    );
}

#[test]
fn time_factor_max_at_90_days() {
    let now = 10_000_000u64;
    let ninety_days_ago = now - (90 * 86400);
    let record = make_record_at("file:test.rs", ninety_days_ago, 0);
    let factor = time_factor(&record, now);
    assert!(
        (factor - 1.0).abs() < 0.02,
        "expected ~1.0 at 90 days, got {factor}"
    );
}

#[test]
fn time_factor_uses_last_accessed_when_newer() {
    let now = 10_000_000u64;
    // updated_at is old, but last_accessed is recent.
    let record = make_record_at("file:test.rs", now - (90 * 86400), now - 86400);
    let factor = time_factor(&record, now);
    // Should use last_accessed (1 day ago), not updated_at (90 days ago).
    assert!(
        factor < 0.05,
        "expected near-zero with recent access, got {factor}"
    );
}

// ── git_factor tests ────────────────────────────────────────────────────

#[test]
fn git_factor_zero_when_no_repo() {
    let analyzer = StalenessAnalyzer {
        repo: None,
        root: PathBuf::from("/nonexistent"),
        root_from_git: false,
        now: 2_000_000,
        head_commit: None,
    };
    assert_eq!(
        analyzer.git_factor_for("file:src/main.rs", "deadbeef", far_deadline()),
        (0.0, None)
    );
}

// ── dep_factor tests ────────────────────────────────────────────────────

#[test]
fn dep_factor_zero_when_no_imports() {
    let fr = FileRecord {
        path: "src/main.rs".into(),
        purpose: String::new(),
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
        token_cost_estimate: 0,
        last_modified_session: 1_000_000,
        content_hash: None,
        line_count: 0,
        blast_radius: None,
        propagated_staleness: None,
    };
    let cache = HashMap::new();
    let factor = dep_factor(Some(&fr), &cache);
    assert!(factor.abs() < 0.001);
}

#[test]
fn dep_factor_detects_bumped_dep() {
    let fr = FileRecord {
        path: "src/main.rs".into(),
        purpose: String::new(),
        entry_points: vec![],
        imports: vec!["tokio::sync::Mutex".into()],
        gotcha_keys: vec![],
        decision_keys: vec![],
        todos: vec![],
        unsafe_count: 0,
        unwrap_count: 0,
        change_frequency: 0,
        last_author: None,
        is_hotspot: false,
        token_cost_estimate: 0,
        last_modified_session: 1_000_000,
        content_hash: None,
        line_count: 0,
        blast_radius: None,
        propagated_staleness: None,
    };

    // Create a dep record for tokio that was updated after the file.
    let mut dep_rec = Record {
        key: "dep:cargo:tokio".to_string(),
        value: String::new(),
        category: Category::Dependency,
        priority: Priority::Normal,
        tags: vec![],
        created_at: 500_000,
        updated_at: 2_000_000, // Updated after file's last_modified_session.
        ref_url: None,
        staleness: StalenessScore {
            value: 0.0,
            tier: StalenessTier::Fresh,
            signals: vec![StalenessSignal::DependencyBumped {
                dep: "tokio".into(),
                old_ver: "1.0".into(),
                new_ver: "1.1".into(),
            }],
            computed_at: 0,
            last_record_sha: String::new(),
        },
        lifecycle: RecordLifecycle::Active,
        version: RecordVersion {
            device_id: uuid::Uuid::new_v4(),
            logical_clock: 1,
            wall_clock: 2_000_000,
        },
        quality: QualityScore::layer0_default(),
        access_count: 0,
        last_accessed: 0,
        source: RecordSource::StaticAnalysis,
        confidence: ConfidenceScore::for_new_record(&RecordSource::StaticAnalysis),
        gap_analysis_score: 0.0,
        payload: None,
    };

    let mut cache = HashMap::new();
    cache.insert("dep:cargo:tokio".to_string(), dep_rec.clone());

    let factor = dep_factor(Some(&fr), &cache);
    assert!(
        factor > 0.5,
        "expected high dep factor for bumped dep, got {factor}"
    );

    // With no bump signal and same updated_at, factor should be zero.
    dep_rec.staleness.signals.clear();
    dep_rec.updated_at = 1_000_000; // Same as file.
    cache.insert("dep:cargo:tokio".to_string(), dep_rec);
    let factor2 = dep_factor(Some(&fr), &cache);
    assert!(
        factor2.abs() < 0.001,
        "expected zero when dep not bumped, got {factor2}"
    );
}

#[test]
fn dep_factor_detects_bumped_npm_dep_from_subpath_import() {
    let fr = FileRecord {
        path: "src/app.ts".into(),
        purpose: String::new(),
        entry_points: vec![],
        imports: vec!["@types/node/fs".into()],
        gotcha_keys: vec![],
        decision_keys: vec![],
        todos: vec![],
        unsafe_count: 0,
        unwrap_count: 0,
        change_frequency: 0,
        last_author: None,
        is_hotspot: false,
        token_cost_estimate: 0,
        line_count: 0,
        blast_radius: None,
        propagated_staleness: None,
        last_modified_session: 1_000_000,
        content_hash: None,
    };

    let dep_rec = Record {
        key: "dep:npm:@types/node".to_string(),
        value: String::new(),
        category: Category::Dependency,
        priority: Priority::Normal,
        tags: vec![],
        created_at: 500_000,
        updated_at: 2_000_000,
        ref_url: None,
        staleness: StalenessScore {
            value: 0.0,
            tier: StalenessTier::Fresh,
            signals: vec![StalenessSignal::DependencyBumped {
                dep: "@types/node".into(),
                old_ver: "20.0.0".into(),
                new_ver: "20.1.0".into(),
            }],
            computed_at: 0,
            last_record_sha: String::new(),
        },
        lifecycle: RecordLifecycle::Active,
        version: RecordVersion {
            device_id: uuid::Uuid::new_v4(),
            logical_clock: 1,
            wall_clock: 2_000_000,
        },
        quality: QualityScore::layer0_default(),
        access_count: 0,
        last_accessed: 0,
        source: RecordSource::StaticAnalysis,
        confidence: ConfidenceScore::for_new_record(&RecordSource::StaticAnalysis),
        gap_analysis_score: 0.0,
        payload: None,
    };

    let mut cache = HashMap::new();
    cache.insert(dep_rec.key.clone(), dep_rec);

    let factor = dep_factor(Some(&fr), &cache);
    assert!(
        factor > 0.5,
        "expected high dep factor for bumped npm dep, got {factor}"
    );
}

#[test]
fn dep_factor_detects_bumped_go_dep_from_subpackage_import() {
    let fr = FileRecord {
        path: "internal/server.go".into(),
        purpose: String::new(),
        entry_points: vec![],
        imports: vec!["github.com/gin-gonic/gin/render".into()],
        gotcha_keys: vec![],
        decision_keys: vec![],
        todos: vec![],
        unsafe_count: 0,
        unwrap_count: 0,
        change_frequency: 0,
        last_author: None,
        is_hotspot: false,
        token_cost_estimate: 0,
        line_count: 0,
        blast_radius: None,
        propagated_staleness: None,
        last_modified_session: 1_000_000,
        content_hash: None,
    };

    let dep_rec = Record {
        key: "dep:go:github.com/gin-gonic/gin".to_string(),
        value: String::new(),
        category: Category::Dependency,
        priority: Priority::Normal,
        tags: vec![],
        created_at: 500_000,
        updated_at: 2_000_000,
        ref_url: None,
        staleness: StalenessScore {
            value: 0.0,
            tier: StalenessTier::Fresh,
            signals: vec![StalenessSignal::DependencyBumped {
                dep: "github.com/gin-gonic/gin".into(),
                old_ver: "1.9.0".into(),
                new_ver: "1.9.1".into(),
            }],
            computed_at: 0,
            last_record_sha: String::new(),
        },
        lifecycle: RecordLifecycle::Active,
        version: RecordVersion {
            device_id: uuid::Uuid::new_v4(),
            logical_clock: 1,
            wall_clock: 2_000_000,
        },
        quality: QualityScore::layer0_default(),
        access_count: 0,
        last_accessed: 0,
        source: RecordSource::StaticAnalysis,
        confidence: ConfidenceScore::for_new_record(&RecordSource::StaticAnalysis),
        gap_analysis_score: 0.0,
        payload: None,
    };

    let mut cache = HashMap::new();
    cache.insert(dep_rec.key.clone(), dep_rec);

    let factor = dep_factor(Some(&fr), &cache);
    assert!(
        factor > 0.5,
        "expected high dep factor for bumped go dep, got {factor}"
    );
}

// ── cascade_factor tests ────────────────────────────────────────────────

#[tokio::test]
async fn cascade_factor_zero_when_no_linked() {
    let dir = TempDir::new().unwrap();
    let store = Store::open(dir.path()).await.unwrap();

    let fr = FileRecord {
        path: "src/main.rs".into(),
        purpose: String::new(),
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
        token_cost_estimate: 0,
        last_modified_session: 0,
        content_hash: None,
        line_count: 0,
        blast_radius: None,
        propagated_staleness: None,
    };

    let record = make_file_record_full("file:src/main.rs", vec![], vec![], vec![], 0);

    let factor = cascade_factor(&record, Some(&fr), &store).await;
    assert!(factor.abs() < 0.001);

    store.close().await.unwrap();
}

#[tokio::test]
async fn cascade_factor_detects_stale_linked_gotcha() {
    let dir = TempDir::new().unwrap();
    let store = Store::open(dir.path()).await.unwrap();

    // Create a stale gotcha.
    let mut gotcha = make_gotcha_record("gotcha:stale-rule");
    gotcha.staleness.value = 0.6;
    gotcha.staleness.tier = StalenessTier::Stale;
    store.put("gotcha:stale-rule", &gotcha).await.unwrap();

    let fr = FileRecord {
        path: "src/main.rs".into(),
        purpose: String::new(),
        entry_points: vec![],
        imports: vec![],
        gotcha_keys: vec!["gotcha:stale-rule".into()],
        decision_keys: vec![],
        todos: vec![],
        unsafe_count: 0,
        unwrap_count: 0,
        change_frequency: 0,
        last_author: None,
        is_hotspot: false,
        token_cost_estimate: 0,
        last_modified_session: 0,
        content_hash: None,
        line_count: 0,
        blast_radius: None,
        propagated_staleness: None,
    };

    let record = make_file_record_full(
        "file:src/main.rs",
        vec![],
        vec!["gotcha:stale-rule".into()],
        vec![],
        0,
    );

    let factor = cascade_factor(&record, Some(&fr), &store).await;
    assert!(
        factor > 0.5,
        "expected positive cascade factor for stale linked gotcha, got {factor}"
    );

    store.close().await.unwrap();
}

#[tokio::test]
async fn cascade_factor_gotcha_detects_stale_affected_file() {
    let dir = TempDir::new().unwrap();
    let store = Store::open(dir.path()).await.unwrap();

    // Create a stale file record.
    let mut file_rec = make_file_record_with_staleness(0.6);
    file_rec.key = "file:src/main.rs".to_string();
    store.put("file:src/main.rs", &file_rec).await.unwrap();

    // Create a gotcha that references this file.
    let gotcha_record = make_gotcha_record("gotcha:test-cascade");
    let factor = cascade_factor(&gotcha_record, None, &store).await;
    assert!(
        factor > 0.5,
        "expected positive cascade factor for stale affected file, got {factor}"
    );

    store.close().await.unwrap();
}

// ── Hard override tests ─────────────────────────────────────────────────

#[tokio::test]
async fn hard_override_file_deleted_sets_tombstone() {
    let dir = TempDir::new().unwrap();
    let store = Store::open(dir.path()).await.unwrap();
    // Deletion is only asserted from a git-proven root — establish one.
    git2::Repository::init(dir.path()).unwrap();

    // Use a path that definitely doesn't exist on disk.
    let mut record = make_file_record_with_staleness(0.0);
    record.key = "file:/tmp/definitely_nonexistent_mati_test_file_xyz.rs".to_string();
    store.put(&record.key, &record).await.unwrap();

    let analyzer = StalenessAnalyzer::new_with_now(dir.path(), 2_000_000);
    let dep_cache = HashMap::new();
    analyzer
        .compute_staleness(&mut record, &store, &dep_cache, far_deadline())
        .await
        .unwrap();

    assert_eq!(record.staleness.tier, StalenessTier::Tombstone);
    assert!((record.staleness.value - 1.0).abs() < 0.01);

    store.close().await.unwrap();
}

/// The tombstone override is the only path that reaches `Tombstone`, and a
/// tombstoned file record makes `hooks::decide::evaluate` pass every read
/// through before it reaches the gotcha loop. Without a git-proven root the
/// analyzer cannot tell "deleted" from "wrong working directory", so it must
/// assert nothing — otherwise a daemon started outside the repo would switch
/// enforcement off for the whole project.
#[tokio::test]
async fn missing_file_is_not_tombstoned_without_a_git_root() {
    let dir = TempDir::new().unwrap();
    let store = Store::open(dir.path()).await.unwrap();

    let mut record = make_file_record_with_staleness(0.0);
    record.key = "file:src/definitely_nonexistent_mati_xyz.rs".to_string();

    // No `Repository::init` — `root_from_git` is false.
    let analyzer = StalenessAnalyzer::new_with_now(dir.path(), 2_000_000);
    assert!(!analyzer.root_from_git);

    analyzer
        .compute_staleness(&mut record, &store, &HashMap::new(), far_deadline())
        .await
        .unwrap();

    assert_ne!(record.staleness.tier, StalenessTier::Tombstone);
    assert!(!record
        .staleness
        .signals
        .iter()
        .any(|s| matches!(s, StalenessSignal::FileDeleted)));

    store.close().await.unwrap();
}

/// Relative record paths resolve against the analyzer's root, not the
/// process CWD. The daemon inherits its CWD from whichever hook spawned it.
#[tokio::test]
async fn relative_paths_resolve_against_the_repo_root_not_the_cwd() {
    let dir = TempDir::new().unwrap();
    let store = Store::open(dir.path()).await.unwrap();
    git2::Repository::init(dir.path()).unwrap();
    std::fs::create_dir_all(dir.path().join("src")).unwrap();
    std::fs::write(dir.path().join("src/present.rs"), "fn main() {}").unwrap();

    let analyzer = StalenessAnalyzer::new_with_now(dir.path(), 2_000_000);

    // `src/present.rs` does not exist relative to the test process CWD.
    assert!(!Path::new("src/present.rs").exists());

    let mut record = make_file_record_with_staleness(0.0);
    record.key = "file:src/present.rs".to_string();
    analyzer
        .compute_staleness(&mut record, &store, &HashMap::new(), far_deadline())
        .await
        .unwrap();

    assert_ne!(record.staleness.tier, StalenessTier::Tombstone);

    store.close().await.unwrap();
}

#[tokio::test]
async fn hard_override_file_renamed_sets_liability() {
    let dir = TempDir::new().unwrap();
    let store = Store::open(dir.path()).await.unwrap();

    // Create both old and new files on disk.
    let old_path = dir.path().join("old_file.rs");
    let new_path = dir.path().join("renamed.rs");
    std::fs::write(&old_path, "fn main() {}").unwrap();
    std::fs::write(&new_path, "fn main() {}").unwrap();

    let mut record = make_file_record_with_staleness(0.0);
    record.key = format!("file:{}", old_path.to_string_lossy());
    record.staleness.signals.push(StalenessSignal::FileRenamed {
        new_path: new_path.to_string_lossy().to_string(),
    });

    let analyzer = StalenessAnalyzer::new_with_now(dir.path(), 2_000_000);
    let dep_cache = HashMap::new();
    analyzer
        .compute_staleness(&mut record, &store, &dep_cache, far_deadline())
        .await
        .unwrap();

    assert_eq!(record.staleness.tier, StalenessTier::Liability);
    assert!((record.staleness.value - 0.85).abs() < 0.01);

    store.close().await.unwrap();
}

#[tokio::test]
async fn file_restored_clears_deleted_override() {
    let dir = TempDir::new().unwrap();
    let store = Store::open(dir.path()).await.unwrap();

    // Create a file on disk.
    let file_path = dir.path().join("restored.rs");
    std::fs::write(&file_path, "fn main() {}").unwrap();

    // Record has a FileDeleted signal, but the file now exists on disk.
    let mut record = make_file_record_with_staleness(0.5);
    record.key = format!("file:{}", file_path.to_string_lossy());
    record.staleness.signals.push(StalenessSignal::FileDeleted);

    let analyzer = StalenessAnalyzer::new_with_now(dir.path(), 2_000_000);
    let dep_cache = HashMap::new();
    analyzer
        .compute_staleness(&mut record, &store, &dep_cache, far_deadline())
        .await
        .unwrap();

    // Should NOT be tombstoned since file exists.
    assert_ne!(record.staleness.tier, StalenessTier::Tombstone);
    // FileDeleted signal should be cleared.
    assert!(
        !record
            .staleness
            .signals
            .iter()
            .any(|s| matches!(s, StalenessSignal::FileDeleted)),
        "FileDeleted signal should be cleared when file is restored"
    );

    store.close().await.unwrap();
}

// ── staleness_changed tests ─────────────────────────────────────────────

#[test]
fn staleness_changed_detects_tier_change() {
    let mut old = make_file_record_with_staleness(0.19);
    let mut new = old.clone();
    new.staleness.value = 0.21;
    new.staleness.tier = StalenessTier::Aging;
    old.staleness.tier = StalenessTier::Fresh;
    assert!(staleness_changed(&old, &new));
}

#[test]
fn staleness_changed_ignores_small_delta() {
    let old = make_file_record_with_staleness(0.10);
    let mut new = old.clone();
    new.staleness.value = 0.105; // Delta 0.005 < 0.01 threshold.
    assert!(!staleness_changed(&old, &new));
}

#[test]
fn staleness_changed_detects_sha_change() {
    let old = make_file_record_with_staleness(0.10);
    let mut new = old.clone();
    new.staleness.last_record_sha = "abc123".to_string();
    assert!(staleness_changed(&old, &new));
}

#[test]
fn staleness_changed_detects_signal_count_change() {
    let old = make_file_record_with_staleness(0.10);
    let mut new = old.clone();
    new.staleness
        .signals
        .push(StalenessSignal::LinesChangedPct(0.5));
    assert!(staleness_changed(&old, &new));
}

// ── analyze_all tests ───────────────────────────────────────────────────

/// The scan checks the deadline before every prefix and every record, so an
/// already-expired budget must stop it before it touches anything.
#[tokio::test]
async fn expired_time_budget_stops_the_scan_before_any_write() {
    let dir = TempDir::new().unwrap();
    let store = Store::open(dir.path()).await.unwrap();
    let file_path = dir.path().join("old_file.rs");
    std::fs::write(&file_path, "fn main() {}").unwrap();

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut record = make_record_at(
        &format!("file:{}", file_path.to_string_lossy()),
        now - (60 * 86400),
        0,
    );
    record.lifecycle = RecordLifecycle::Active;
    store.put(&record.key, &record).await.unwrap();
    let before = store.get(&record.key).await.unwrap().unwrap();

    let analyzer = StalenessAnalyzer::new(dir.path());
    let expired = Instant::now() - std::time::Duration::from_millis(1);
    let report = analyzer.analyze_until(&store, expired).await.unwrap();

    assert_eq!(report.scanned, 0);
    assert_eq!(report.updated, 0);
    let after = store.get(&record.key).await.unwrap().unwrap();
    assert_eq!(after.version.logical_clock, before.version.logical_clock);

    // Same store, same analyzer, real budget — proves the assertion above is
    // the deadline talking and not an empty scan.
    let report = analyzer.analyze_all(&store).await.unwrap();
    assert!(report.scanned >= 1);
    assert!(report.updated >= 1);

    store.close().await.unwrap();
}

/// The budget bounds the SessionEnd hook, whose scaffold timeout is 4s.
#[test]
fn time_budget_is_unchanged() {
    assert_eq!(ANALYZE_TIME_BUDGET_MS, 2000);
}

#[tokio::test]
async fn analyze_all_updates_stale_records() {
    let dir = TempDir::new().unwrap();
    let store = Store::open(dir.path()).await.unwrap();

    // Create a record that should become stale (old timestamp).
    // Use a file path that exists on disk so it doesn't get tombstoned.
    let file_path = dir.path().join("old_file.rs");
    std::fs::write(&file_path, "fn main() {}").unwrap();

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let sixty_days_ago = now - (60 * 86400);

    let mut record = make_record_at(
        &format!("file:{}", file_path.to_string_lossy()),
        sixty_days_ago,
        0,
    );
    record.lifecycle = RecordLifecycle::Active;
    store.put(&record.key, &record).await.unwrap();

    let analyzer = StalenessAnalyzer::new(dir.path());
    let report = analyzer.analyze_all(&store).await.unwrap();

    assert!(report.scanned >= 1, "should scan at least 1 record");
    // The time factor at 60 days = 60/90 = ~0.67 * 0.20 = ~0.13
    // That's enough to register a change from 0.0.
    assert!(report.updated >= 1, "should update stale record");

    store.close().await.unwrap();
}

#[tokio::test]
async fn analyze_all_skips_non_active() {
    let dir = TempDir::new().unwrap();
    let store = Store::open(dir.path()).await.unwrap();

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let old = now - (60 * 86400);

    let mut record = make_record_at("file:tombstoned.rs", old, 0);
    record.lifecycle = RecordLifecycle::Tombstoned {
        reason: TombstoneReason::ManualDeletion,
        at: now,
    };
    store.put(&record.key, &record).await.unwrap();

    let analyzer = StalenessAnalyzer::new_with_now(dir.path(), now);
    let report = analyzer.analyze_all(&store).await.unwrap();

    // Record was scanned but not updated because it's tombstoned.
    assert_eq!(report.updated, 0);

    store.close().await.unwrap();
}

// ── resume cursor tests ─────────────────────────────────────────────────

/// Every prefix, seeded old enough that the first computation changes the
/// score and therefore persists `computed_at`.
async fn seed_one_record_per_prefix(store: &Store, now: u64) -> Vec<String> {
    let old = now - (60 * 86_400);
    let keys = [
        "file:zzz_last.rs",
        "gotcha:g1",
        "decision:d1",
        "dep:cargo:serde",
        "dev_note:n1",
    ];
    for key in keys {
        let mut record = make_record_at(key, old, 0);
        record.category = match key.split(':').next().unwrap() {
            "gotcha" => Category::Gotcha,
            "decision" => Category::Decision,
            "dep" => Category::Dependency,
            "dev_note" => Category::DevNote,
            _ => Category::File,
        };
        store.put(key, &record).await.unwrap();
    }
    keys.iter().map(|k| k.to_string()).collect()
}

/// A `file:` record that costs a whole budget to score: `cascade_factor`
/// issues one store read per linked key, and none of these exist.
fn make_budget_eating_record(key: &str, now: u64, links: usize) -> Record {
    let mut record = make_record_at(key, now - (60 * 86_400), 0);
    let gotcha_keys: Vec<String> = (0..links).map(|i| format!("gotcha:absent-{i}")).collect();
    let fr = make_file_record_full(key, vec![], gotcha_keys, vec![], 0);
    record.payload = serde_json::from_str(&fr.value).ok();
    record
}

/// The scan order is fixed, so a budget that expires always expires inside
/// `file:`, and the four prefixes behind it would never recompute. The
/// cursor is what bounds coverage: pass 2 must start where pass 1 stopped
/// and finish the store, not restart at `file:` and starve the tail again.
#[tokio::test]
async fn a_truncated_pass_parks_a_cursor_and_the_next_pass_finishes_the_store() {
    let dir = TempDir::new().unwrap();
    let store = Store::open(dir.path()).await.unwrap();
    let now = 20_000_000u64;

    let mut keys = seed_one_record_per_prefix(&store, now).await;
    // Sorts first inside `file:`, so it is what a truncated pass spends
    // its whole budget on.
    let hog = "file:aaa_expensive.rs";
    let record = make_budget_eating_record(hog, now, 20_000);
    store.put(hog, &record).await.unwrap();
    keys.push(hog.to_string());

    let analyzer = StalenessAnalyzer::new_with_now(dir.path(), now);

    let deadline = Instant::now() + std::time::Duration::from_millis(5);
    let first = analyzer.analyze_until(&store, deadline).await.unwrap();
    assert!(first.scanned >= 1, "a pass must make progress");
    assert!(
        first.scanned < keys.len() as u32,
        "the budget did not truncate: scanned {} of {}",
        first.scanned,
        keys.len()
    );
    assert_eq!(
        read_cursor(&store).await.as_deref(),
        Some(hog),
        "a truncated pass parks the cursor on the last record it finished"
    );

    let second = analyzer.analyze_all(&store).await.unwrap();
    assert_eq!(
        second.scanned,
        keys.len() as u32 - first.scanned,
        "the resumed pass must not re-scan what the cursor already covered"
    );
    assert!(
        read_cursor(&store).await.is_none(),
        "a pass that reaches the end clears the cursor"
    );

    for key in &keys {
        let record = store.get(key).await.unwrap().unwrap();
        assert_eq!(
            record.staleness.computed_at, now,
            "{key} was never recomputed across the sweep"
        );
    }

    store.close().await.unwrap();
}

/// The cursor is scheduling state on the Eventual path, so it can be lost,
/// stale, or left behind by a prefix list that has since changed. Anything
/// the sweep cannot place must restart it, never skip.
#[tokio::test]
async fn an_unplaceable_cursor_restarts_the_sweep() {
    let dir = TempDir::new().unwrap();
    let store = Store::open(dir.path()).await.unwrap();
    let now = 20_000_000u64;

    let keys = seed_one_record_per_prefix(&store, now).await;
    write_cursor(&store, "retired_namespace:zzz", now).await;

    let analyzer = StalenessAnalyzer::new_with_now(dir.path(), now);
    let report = analyzer.analyze_all(&store).await.unwrap();

    assert_eq!(
        report.scanned,
        keys.len() as u32,
        "an unplaceable cursor must not skip any record"
    );
    assert!(read_cursor(&store).await.is_none());

    store.close().await.unwrap();
}

/// An empty position is absence, not position zero.
#[tokio::test]
async fn an_empty_cursor_position_reads_as_no_cursor() {
    let dir = TempDir::new().unwrap();
    let store = Store::open(dir.path()).await.unwrap();

    write_cursor(&store, "", 20_000_000).await;
    assert!(read_cursor(&store).await.is_none());

    store.close().await.unwrap();
}

/// The position must not reach the search index: it is a record key, and a
/// `mem_query` for that path would otherwise match the cursor.
#[tokio::test]
async fn the_cursor_position_is_not_searchable() {
    let dir = TempDir::new().unwrap();
    let store = Store::open(dir.path()).await.unwrap();

    write_cursor(&store, "file:src/distinctive_marker.rs", 20_000_000).await;
    let hits = store.search("distinctive_marker", 10).await.unwrap();

    assert!(
        !hits.iter().any(|r| r.key == STALENESS_CURSOR_KEY),
        "cursor leaked into the search index: {hits:?}"
    );

    store.close().await.unwrap();
}

/// The budget still stops the scan. An expired one writes no cursor either:
/// a pass that visited nothing has no position to record, and rewinding to
/// one it did not reach would re-run work the previous pass already did.
#[tokio::test]
async fn an_expired_budget_leaves_the_cursor_untouched() {
    let dir = TempDir::new().unwrap();
    let store = Store::open(dir.path()).await.unwrap();
    let now = 20_000_000u64;

    seed_one_record_per_prefix(&store, now).await;
    write_cursor(&store, "file:zzz_last.rs", now).await;

    let analyzer = StalenessAnalyzer::new_with_now(dir.path(), now);
    let expired = Instant::now() - std::time::Duration::from_millis(1);
    let report = analyzer.analyze_until(&store, expired).await.unwrap();

    assert_eq!(report.scanned, 0);
    assert_eq!(
        read_cursor(&store).await.as_deref(),
        Some("file:zzz_last.rs")
    );

    store.close().await.unwrap();
}

// ── commits_to_factor tests ─────────────────────────────────────────────

#[test]
fn commits_to_factor_mapping() {
    assert!((commits_to_factor(0) - 0.0).abs() < 0.001);
    assert!((commits_to_factor(1) - 0.15).abs() < 0.001);
    assert!((commits_to_factor(2) - 0.30).abs() < 0.001);
    assert!((commits_to_factor(3) - 0.50).abs() < 0.001);
    assert!((commits_to_factor(4) - 0.70).abs() < 0.001);
    assert!((commits_to_factor(5) - 1.0).abs() < 0.001);
    assert!((commits_to_factor(100) - 1.0).abs() < 0.001);
}

// ── reparse signal preservation tests ───────────────────────────────────

#[tokio::test]
async fn reparse_signals_preserved_within_24h() {
    let dir = TempDir::new().unwrap();
    let store = Store::open(dir.path()).await.unwrap();

    let file_path = dir.path().join("recent_reparse.rs");
    std::fs::write(&file_path, "fn main() {}").unwrap();

    let now = 2_000_000u64;
    let recent = now - 3600; // 1 hour ago

    let mut record = make_record_at(
        &format!("file:{}", file_path.to_string_lossy()),
        now - 100,
        0,
    );
    // Simulate recent reparse: computed_at within 24h, with reparse signals.
    record.staleness.computed_at = recent;
    record.staleness.value = 0.3;
    record.staleness.tier = StalenessTier::Aging;
    record.staleness.signals = vec![
        StalenessSignal::EntryPointsChanged(2),
        StalenessSignal::ImportsChanged(1),
    ];

    let analyzer = StalenessAnalyzer::new_with_now(dir.path(), now);
    let dep_cache = HashMap::new();
    analyzer
        .compute_staleness(&mut record, &store, &dep_cache, far_deadline())
        .await
        .unwrap();

    // The 5-factor formula would compute a low value (record is ~100s old),
    // but reparse signal preservation should keep the higher value.
    assert!(
        record.staleness.value >= 0.3,
        "reparse signal preservation should keep value >= 0.3, got {}",
        record.staleness.value
    );

    // Reparse signals should be preserved.
    let has_ep = record
        .staleness
        .signals
        .iter()
        .any(|s| matches!(s, StalenessSignal::EntryPointsChanged(_)));
    assert!(has_ep, "EntryPointsChanged signal should be preserved");

    store.close().await.unwrap();
}

#[test]
fn signal_cap_at_20_for_reparse_signals() {
    let mut record = make_file_record_with_staleness(0.0);

    // Add 25 signals via repeated reparse applications.
    for i in 0..25 {
        let diff = ReparseDiff {
            entry_points_added: vec![format!("fn_{i}")],
            ..empty_diff()
        };
        apply_reparse_staleness(&mut record, &diff);
    }

    // Signal list should be capped at 20.
    assert!(
        record.staleness.signals.len() <= 20,
        "signals should be capped at 20, got {}",
        record.staleness.signals.len()
    );
}

// ── is_reparse_signal tests ─────────────────────────────────────────────

#[test]
fn is_reparse_signal_identifies_reparse_signals() {
    assert!(is_reparse_signal(&StalenessSignal::EntryPointsChanged(1)));
    assert!(is_reparse_signal(&StalenessSignal::ImportsChanged(2)));
    assert!(is_reparse_signal(&StalenessSignal::TodosChanged));
    assert!(is_reparse_signal(&StalenessSignal::UnsafeCountChanged(1)));
    assert!(is_reparse_signal(&StalenessSignal::UnwrapCountChanged(-1)));

    // Non-reparse signals.
    assert!(!is_reparse_signal(&StalenessSignal::FileDeleted));
    assert!(!is_reparse_signal(&StalenessSignal::LinesChangedPct(0.5)));
    assert!(!is_reparse_signal(&StalenessSignal::NotAccessedDays(7)));
}

// ── Reparse accumulation cannot disable enforcement ─────────────────────

/// `hooks::decide::evaluate` runs the gotcha loop before it looks at the
/// file's staleness tier — pinned by `decide::tests::gate_never_silently_
/// disables`. So `Liability`/`Tombstone` no longer disable enforcement of
/// a confirmed gotcha. They still gate *injection*: `Liability` degrades
/// the file's cached purpose blurb to a bare warning, and `Tombstone`
/// (absent a `FileDeleted` signal) suppresses it entirely. Reparse
/// staleness is applied per edit, so without a ceiling across passes,
/// editing one file a handful of times in a session would cross that
/// boundary and mark its cached blurb untrustworthy — a false signal,
/// since the file wasn't abandoned, just actively edited.
///
/// These tests bound the reparse contribution. They do not touch the tier
/// thresholds or what the tiers mean.
mod reparse_cannot_disable_enforcement {
    use super::*;
    use crate::hooks::decide::{evaluate, Decision, EnforcementInput};

    /// A diff big enough to saturate a single pass at
    /// [`MAX_REPARSE_INCREMENT`].
    fn saturating_diff() -> ReparseDiff {
        ReparseDiff {
            entry_points_added: vec!["a".into(), "b".into(), "c".into(), "d".into()],
            imports_added: vec!["x".into(), "y".into(), "z".into()],
            ..empty_diff()
        }
    }

    /// A file record carrying one maximally-valid confirmed gotcha, plus
    /// that gotcha, in the JSON shape `evaluate` reads.
    fn enforcement_input_for(record: &Record) -> EnforcementInput {
        let mut gotcha = make_gotcha_record("gotcha:test");
        gotcha.confidence.value = 1.0;
        gotcha.quality.value = 1.0;

        let mut file = record.clone();
        file.confidence.value = 0.7;
        file.quality.value = 0.5;
        file.payload = serde_json::json!({ "gotcha_keys": ["gotcha:test"] }).into();

        let mut gotchas = HashMap::new();
        gotchas.insert(
            "gotcha:test".to_string(),
            serde_json::to_value(&gotcha).unwrap(),
        );
        EnforcementInput {
            rel_path: "src/main.rs".into(),
            file_record: Some(serde_json::to_value(&file).unwrap()),
            gotcha_records: gotchas,
            already_consulted: false,
            file_exists: None,
        }
    }

    /// The anchor: no number of reparse passes reaches a tier that
    /// degrades injection, and a confirmed gotcha keeps denying
    /// regardless — the second assertion holds even without the ceiling
    /// now, but stays here as a regression guard.
    #[test]
    fn repeated_reparse_never_reaches_a_tier_that_degrades_injection() {
        let mut record = make_file_record_with_staleness(0.0);

        for pass in 1..=50 {
            apply_reparse_staleness(&mut record, &saturating_diff());
            assert!(
                !matches!(
                    record.staleness.tier,
                    StalenessTier::Liability | StalenessTier::Tombstone
                ),
                "INJECTION DEGRADED: {} reparse passes reached tier {:?} \
                     (value {}). Liability and Tombstone still gate what gets \
                     injected for this file, even though they no longer gate \
                     gotcha enforcement",
                pass,
                record.staleness.tier,
                record.staleness.value
            );

            let decision = evaluate(&enforcement_input_for(&record)).decision;
            assert!(
                matches!(decision, Decision::Deny { .. }),
                "ENFORCEMENT DISABLED: after {pass} reparse passes a confirmed \
                     gotcha produced {decision:?} instead of Deny"
            );
        }

        assert!(record.staleness.value <= MAX_REPARSE_STALENESS + f32::EPSILON);
    }

    /// The ceiling is only meaningful while it stays inside `Stale`.
    #[test]
    fn ceiling_sits_below_the_liability_floor() {
        assert_eq!(
            StalenessScore::tier_from_value(MAX_REPARSE_STALENESS),
            StalenessTier::Stale,
            "MAX_REPARSE_STALENESS must stay below the 0.7 Liability floor"
        );
    }

    /// The signal is not neutered: one pass still moves the score, and the
    /// score keeps climbing until it saturates.
    #[test]
    fn a_single_reparse_still_raises_staleness() {
        let mut record = make_file_record_with_staleness(0.0);
        let signals = apply_reparse_staleness(&mut record, &saturating_diff());

        assert!(!signals.is_empty(), "a non-empty diff must emit signals");
        assert!(
            (record.staleness.value - MAX_REPARSE_INCREMENT).abs() < 0.01,
            "one saturating pass must still add the full increment, got {}",
            record.staleness.value
        );
        assert_eq!(record.staleness.tier, StalenessTier::Stale);

        let after_first = record.staleness.value;
        apply_reparse_staleness(&mut record, &saturating_diff());
        assert!(
            record.staleness.value > after_first,
            "a second pass must still raise the score below the ceiling"
        );
    }

    /// Another factor may legitimately hold a record above the ceiling.
    /// Reparse must not drag it back down.
    #[test]
    fn reparse_never_lowers_a_score_set_by_another_factor() {
        let mut record = make_file_record_with_staleness(0.95);
        apply_reparse_staleness(&mut record, &saturating_diff());
        assert!((record.staleness.value - 0.95).abs() < f32::EPSILON);
        assert_eq!(record.staleness.tier, StalenessTier::Tombstone);
    }

    /// The cascade to linked gotchas accumulates the same way. A tombstoned
    /// gotcha is dropped by `mcp::tools::is_injectable_gotcha`.
    #[tokio::test]
    async fn cascade_to_gotchas_saturates_below_liability() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();
        store
            .put("gotcha:test-rule", &make_gotcha_record("gotcha:test-rule"))
            .await
            .unwrap();

        let mut file_record = make_linked_file_record();
        file_record.gotcha_keys = vec!["gotcha:test-rule".into()];

        for _ in 0..30 {
            cascade_staleness_to_gotchas(&store, &file_record)
                .await
                .unwrap();
        }

        let updated = store.get("gotcha:test-rule").await.unwrap().unwrap();
        assert!(
            updated.staleness.value <= MAX_REPARSE_STALENESS + f32::EPSILON,
            "cascade accumulated to {}",
            updated.staleness.value
        );
        assert_eq!(updated.staleness.tier, StalenessTier::Stale);

        store.close().await.unwrap();
    }

    /// `compute_staleness` preserves a recent reparse score against a lower
    /// recompute. A record already over the ceiling — accumulated before it
    /// existed — must recompute down instead of staying pinned.
    #[tokio::test]
    async fn analyze_recomputes_an_over_accumulated_record_down() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();

        let file_path = dir.path().join("hot.rs");
        std::fs::write(&file_path, "fn main() {}").unwrap();

        let now = 2_000_000u64;
        let key = format!("file:{}", file_path.to_string_lossy());
        let mut record = make_record_at(&key, now - 100, 0);
        record.staleness.value = 0.95;
        record.staleness.tier = StalenessTier::Tombstone;
        record.staleness.computed_at = now - 3600;
        record.staleness.signals = vec![
            StalenessSignal::ImportsChanged(2),
            StalenessSignal::UnwrapCountChanged(12),
        ];

        let analyzer = StalenessAnalyzer::new_with_now(dir.path(), now);
        analyzer
            .compute_staleness(&mut record, &store, &HashMap::new(), far_deadline())
            .await
            .unwrap();

        assert!(
            record.staleness.value <= MAX_REPARSE_STALENESS + f32::EPSILON,
            "the 24h preservation window pinned the record at {}",
            record.staleness.value
        );
        assert!(!matches!(
            record.staleness.tier,
            StalenessTier::Liability | StalenessTier::Tombstone
        ));
        assert!(
            record
                .staleness
                .signals
                .iter()
                .any(|s| matches!(s, StalenessSignal::ImportsChanged(_))),
            "recomputing down must not erase the reparse signals"
        );

        store.close().await.unwrap();
    }
}

// ── revwalk deadline ────────────────────────────────────────────────────

/// Commit `content` to `name` and return the commit SHA.
fn commit_file(repo: &git2::Repository, name: &str, content: &str) -> String {
    let workdir = repo.workdir().expect("bare repo").to_path_buf();
    std::fs::write(workdir.join(name), content).unwrap();
    let mut index = repo.index().unwrap();
    index.add_path(Path::new(name)).unwrap();
    index.write().unwrap();
    let tree = repo.find_tree(index.write_tree().unwrap()).unwrap();
    let sig = git2::Signature::now("t", "t@example.com").unwrap();
    let parent = repo.head().ok().and_then(|h| h.peel_to_commit().ok());
    let parents: Vec<&git2::Commit> = parent.iter().collect();
    repo.commit(Some("HEAD"), &sig, &sig, "c", &tree, &parents)
        .unwrap()
        .to_string()
}

/// The revwalk stops at the pass deadline instead of running to
/// `GIT_REVWALK_LIMIT`.
///
/// `analyze_until` gates only when a record *starts*, so before the
/// deadline reached here one record could walk 2000 commits — seconds —
/// after the pass had already spent its budget, and the SessionEnd hook
/// overshot by that much.
#[test]
fn count_commits_since_stops_at_the_deadline() {
    let dir = TempDir::new().unwrap();
    let repo = git2::Repository::init(dir.path()).unwrap();
    let mut shas = Vec::new();
    for i in 0..12 {
        shas.push(commit_file(&repo, "a.txt", &format!("v{i}\n")));
    }
    let analyzer = StalenessAnalyzer::new(dir.path());
    let root_sha = &shas[0];

    assert_eq!(
        analyzer.count_commits_since(&repo, "a.txt", root_sha, far_deadline()),
        11,
        "an unbounded walk reaches the root commit and counts the rest"
    );

    assert_eq!(
        analyzer.count_commits_since(&repo, "a.txt", root_sha, Instant::now()),
        GIT_CAP_HIT_COMMITS,
        "an expired deadline stops the walk and reports the conservative floor"
    );
}

/// A record whose walk cannot finish inside the budget still gets a
/// staleness signal — undercounting keeps enforcement on, silence would
/// read as "unchanged".
#[test]
fn deadline_truncated_walk_reports_a_nonzero_git_factor() {
    let dir = TempDir::new().unwrap();
    let repo = git2::Repository::init(dir.path()).unwrap();
    let root_sha = commit_file(&repo, "a.txt", "v0\n");
    commit_file(&repo, "a.txt", "v1\n");
    let analyzer = StalenessAnalyzer::new(dir.path());

    let (factor, sha) = analyzer.git_factor(&repo, "a.txt", &root_sha, Instant::now());
    assert!(factor > 0.0, "truncated walk must not report 'unchanged'");
    assert!(sha.is_some(), "baseline still advances to HEAD");
}
