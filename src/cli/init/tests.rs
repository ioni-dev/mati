use super::*;
use mati_core::analysis::GitSignals;

fn make_signals(pairs: &[(&str, &str, u32)], freq: &[(&str, u32)]) -> GitSignals {
    let mut signals = GitSignals::empty();
    for (a, b, count) in pairs {
        signals
            .co_change_pairs
            .push((a.to_string(), b.to_string(), *count));
    }
    for (path, f) in freq {
        signals.change_frequency.insert(path.to_string(), *f);
    }
    signals
}

fn dummy() -> (Uuid, u64) {
    (Uuid::new_v4(), 0)
}

fn make_record_with_category(key: &str, category: Category) -> Record {
    Record {
        key: key.to_string(),
        value: "value".to_string(),
        category,
        priority: Priority::Normal,
        tags: vec![],
        created_at: 1,
        updated_at: 1,
        ref_url: None,
        staleness: StalenessScore::fresh(),
        lifecycle: RecordLifecycle::Active,
        version: RecordVersion {
            device_id: Uuid::nil(),
            logical_clock: 1,
            wall_clock: 1,
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

// ── Rule text format ──────────────────────────────────────────────────────

#[test]
fn rule_text_contains_ratio_and_pct() {
    let (dev, now) = dummy();
    let signals = make_signals(&[("a.rs", "b.rs", 9)], &[("a.rs", 10), ("b.rs", 10)]);
    let gotchas = build_cochange_gotchas(&signals, dev, 0, now);
    // Both symmetric → both get a gotcha.
    let ga = gotchas.iter().find(|g| g.source_path == "a.rs").unwrap();
    assert!(ga.record.value.contains("9/10"), "rule should contain 9/10");
    assert!(ga.record.value.contains("90%"), "rule should contain 90%");
    assert!(
        ga.record.value.contains("`b.rs`"),
        "rule should name the target"
    );
}

// ── Directionality ────────────────────────────────────────────────────────

#[test]
fn symmetric_pair_produces_two_gotchas() {
    let (dev, now) = dummy();
    let signals = make_signals(&[("a.rs", "b.rs", 8)], &[("a.rs", 10), ("b.rs", 10)]);
    let gotchas = build_cochange_gotchas(&signals, dev, 0, now);
    assert_eq!(gotchas.len(), 2);
    assert!(gotchas.iter().any(|g| g.source_path == "a.rs"));
    assert!(gotchas.iter().any(|g| g.source_path == "b.rs"));
}

#[test]
fn asymmetric_pair_only_constrained_file_gets_gotcha() {
    // a: 30 commits, b: 4 commits, pair: 4.
    // ratio_a = 4/30 = 13% (below 0.70) → no gotcha on a.
    // ratio_b = 4/4  = 100% (above 0.70) AND count=4 >= MIN_COUNT → gotcha on b only.
    let (dev, now) = dummy();
    let signals = make_signals(&[("a.rs", "b.rs", 4)], &[("a.rs", 30), ("b.rs", 4)]);
    let gotchas = build_cochange_gotchas(&signals, dev, 0, now);
    assert_eq!(gotchas.len(), 1);
    assert_eq!(gotchas[0].source_path, "b.rs");
    assert!(gotchas[0].record.value.contains("`a.rs`"));
    assert!(gotchas[0].record.value.contains("4/4"));
    assert!(gotchas[0].record.value.contains("100%"));
}

#[test]
fn key_is_directional() {
    let (dev, now) = dummy();
    let signals = make_signals(&[("a.rs", "b.rs", 4)], &[("a.rs", 30), ("b.rs", 4)]);
    let gotchas = build_cochange_gotchas(&signals, dev, 0, now);
    assert_eq!(gotchas[0].key, "gotcha:cochange:b.rs|a.rs");
}

// ── Quality/confidence tiers ──────────────────────────────────────────────

#[test]
fn normal_signal_gets_additionalcontext_tier() {
    let (dev, now) = dummy();
    // ratio = 8/10 = 80%, count = 8 — strong ratio but count < 20, so normal tier.
    let signals = make_signals(&[("a.rs", "b.rs", 8)], &[("a.rs", 10), ("b.rs", 10)]);
    let gotchas = build_cochange_gotchas(&signals, dev, 0, now);
    let ga = gotchas.iter().find(|g| g.source_path == "a.rs").unwrap();
    assert!((ga.record.confidence.value - 0.45).abs() < 0.001);
    assert!((ga.record.quality.value - 0.40).abs() < 0.001);
}

#[test]
fn strong_signal_gets_inject_tier() {
    let (dev, now) = dummy();
    // ratio = 95%, count = 21 — clears both strong thresholds.
    let signals = make_signals(&[("a.rs", "b.rs", 20)], &[("a.rs", 21), ("b.rs", 21)]);
    let gotchas = build_cochange_gotchas(&signals, dev, 0, now);
    let ga = gotchas.iter().find(|g| g.source_path == "a.rs").unwrap();
    assert!((ga.record.confidence.value - 0.65).abs() < 0.001);
    assert!((ga.record.quality.value - 0.60).abs() < 0.001);
}

// ── Volume cap ────────────────────────────────────────────────────────────

#[test]
fn volume_cap_is_five_per_source() {
    let (dev, now) = dummy();
    // hub.rs always co-changes with 7 other files — should be capped at 5.
    // All counts >= 3 to clear MIN_COUNT; ratios all = 1.0 (always together).
    let pairs: Vec<(&str, &str, u32)> = (0..7)
        .map(|i| {
            (
                "hub.rs",
                Box::leak(format!("dep{i}.rs").into_boxed_str()) as &str,
                10 - i as u32,
            )
        })
        .collect();
    let mut freqs: Vec<(&str, u32)> = vec![("hub.rs", 10)];
    for i in 0..7u32 {
        freqs.push((Box::leak(format!("dep{i}.rs").into_boxed_str()), 10 - i));
    }
    let signals = make_signals(&pairs, &freqs);
    let gotchas = build_cochange_gotchas(&signals, dev, 0, now);
    let hub_gotchas: Vec<_> = gotchas
        .iter()
        .filter(|g| g.source_path == "hub.rs")
        .collect();
    assert!(
        hub_gotchas.len() <= 5,
        "expected ≤ 5 gotchas for hub.rs, got {}",
        hub_gotchas.len()
    );
}

// ── GotchaRecord payload ──────────────────────────────────────────────────

#[test]
fn payload_deserializes_as_gotcha_record() {
    let (dev, now) = dummy();
    let signals = make_signals(&[("a.rs", "b.rs", 8)], &[("a.rs", 10), ("b.rs", 10)]);
    let gotchas = build_cochange_gotchas(&signals, dev, 0, now);
    let ga = gotchas.iter().find(|g| g.source_path == "a.rs").unwrap();
    let gr: GotchaRecord = ga.record.payload_as().expect("payload should deserialize");
    // Cochange gotchas are Layer 0 stubs — `confirmed=false` until the
    // developer reviews them via `mati review`. Marking them confirmed
    // at init would assert confidence >= 0.80 (the developer-manual
    // threshold), but cochange records sit at 0.45 / 0.65 — a schema
    // invariant violation that surfaces as `mem_get` returning
    // confidence below 0.80 for a record flagged confirmed=Y.
    assert!(!gr.confirmed);
    assert!(gr.rule.contains("b.rs"));
    assert_eq!(gr.affected_files, vec!["a.rs"]);
}

// ── Empty / no git ────────────────────────────────────────────────────────

#[test]
fn empty_signals_produce_no_gotchas() {
    let (dev, now) = dummy();
    let signals = GitSignals::empty();
    let gotchas = build_cochange_gotchas(&signals, dev, 0, now);
    assert!(gotchas.is_empty());
}

// ── File record quality bump ──────────────────────────────────────────────

/// A file record with a co-change gotcha key but no doc comment should be
/// promoted to at least quality 0.40 (Acceptable) so the pre-read hook
/// surfaces it as additionalContext. Without this bump, files without doc
/// comments stay at quality 0.10 (Suppressed) and the hook never fires —
/// even though they have confirmed co-change coupling signals.
#[test]
fn quality_bump_for_file_with_cochange_gotcha_but_no_doc() {
    let mut quality = QualityScore::layer0_default();
    let mut conf_value: f32 = 0.10;
    let gotcha_keys: Vec<String> = vec!["gotcha:cochange:src/a.rs|src/b.rs".to_string()];
    let purpose = "";

    // Simulate the promotion logic from init.rs
    if !purpose.is_empty() {
        quality = QualityScore::doc_comment_default();
        conf_value = 0.45;
    }
    if quality.value < 0.40
        && gotcha_keys
            .iter()
            .any(|k| k.starts_with("gotcha:cochange:"))
    {
        quality = QualityScore::doc_comment_default();
        if conf_value < 0.45 {
            conf_value = 0.45;
        }
    }

    assert!(
        (quality.value - 0.40).abs() < 0.001,
        "expected quality 0.40, got {:.2}",
        quality.value
    );
    assert!(
        (conf_value - 0.45).abs() < 0.001,
        "expected confidence 0.45, got {:.2}",
        conf_value
    );
}

/// A file with a doc comment AND a co-change gotcha should not be degraded —
/// the doc comment path already sets 0.40/0.45, the bump is a no-op.
#[test]
fn quality_bump_noop_when_doc_comment_already_promotes() {
    let mut quality = QualityScore::layer0_default();
    let mut conf_value: f32 = 0.10;
    let gotcha_keys: Vec<String> = vec!["gotcha:cochange:src/a.rs|src/b.rs".to_string()];
    let purpose = "Handles authentication logic for the web server.";

    if !purpose.is_empty() {
        quality = QualityScore::doc_comment_default();
        conf_value = 0.45;
    }
    if quality.value < 0.40
        && gotcha_keys
            .iter()
            .any(|k| k.starts_with("gotcha:cochange:"))
    {
        quality = QualityScore::doc_comment_default();
        if conf_value < 0.45 {
            conf_value = 0.45;
        }
    }

    // Doc comment path already set 0.40/0.45 — result is identical.
    assert!((quality.value - 0.40).abs() < 0.001);
    assert!((conf_value - 0.45).abs() < 0.001);
}

/// A file with no co-change gotchas and no doc comment stays at 0.10 —
/// we should not bump files that have no coupling signal.
#[test]
fn no_bump_for_file_without_cochange_keys() {
    let mut quality = QualityScore::layer0_default();
    let mut conf_value: f32 = 0.10;
    let gotcha_keys: Vec<String> = vec![];
    let purpose = "";

    if !purpose.is_empty() {
        quality = QualityScore::doc_comment_default();
        conf_value = 0.45;
    }
    if quality.value < 0.40
        && gotcha_keys
            .iter()
            .any(|k| k.starts_with("gotcha:cochange:"))
    {
        quality = QualityScore::doc_comment_default();
        if conf_value < 0.45 {
            conf_value = 0.45;
        }
    }

    assert!(
        (quality.value - 0.10).abs() < 0.001,
        "expected quality 0.10 (no bump), got {:.2}",
        quality.value
    );
    assert!((conf_value - 0.10).abs() < 0.001);
}

#[test]
fn stale_dependency_keys_delete_legacy_and_removed_dep_records() {
    let existing = vec![
        make_record_with_category("dep:serde", Category::Dependency),
        make_record_with_category("dep:cargo:serde", Category::Dependency),
        make_record_with_category("dep:npm:react", Category::Dependency),
        make_record_with_category("dep:cargo:old", Category::Dependency),
        make_record_with_category("file:src/main.rs", Category::File),
    ];
    let new_keys: HashSet<&str> = ["dep:cargo:serde", "dep:npm:react"].into_iter().collect();

    let stale = stale_dependency_keys(&existing, &new_keys);

    assert_eq!(stale.len(), 2);
    assert!(stale.contains(&"dep:serde".to_string()));
    assert!(stale.contains(&"dep:cargo:old".to_string()));
}

// ── Rename migration ──────────────────────────────────────────────────────
//
// A gotcha binds to a file by exact `affected_files` string, so a `git mv`
// unbinds it and the gate degrades to a pass-through once the orphaned
// `file:<old>` is tombstoned. These cover the follow, and — more important,
// since init runs constantly — that following is a one-shot.

/// Lay out `files` under a fresh tempdir so the planner's disk probes see a
/// real tree. Returns the root.
fn scratch_tree(files: &[&str]) -> tempfile::TempDir {
    crate::cli::ensure_test_home();
    let dir = tempfile::TempDir::new().unwrap();
    for f in files {
        let p = dir.path().join(f);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, "fn main() {}\n").unwrap();
    }
    dir
}

fn make_gotcha(key: &str, files: &[&str], confirmed: bool) -> Record {
    let gotcha = GotchaRecord {
        rule: "hold the lock before touching the index".into(),
        reason: "concurrent writers corrupt it otherwise".into(),
        severity: Priority::High,
        affected_files: files.iter().map(|s| s.to_string()).collect(),
        ref_url: None,
        discovered_session: 1_000_000,
        confirmed,
        confirmed_content: Default::default(),
    };
    let mut rec = make_record_with_category(key, Category::Gotcha);
    rec.value = "hold the lock because concurrent writers corrupt the index".into();
    rec.payload = serde_json::to_value(&gotcha).ok();
    rec.source = RecordSource::DeveloperManual;
    rec.confidence = ConfidenceScore::for_new_record(&RecordSource::DeveloperManual);
    rec.quality = QualityScore::doc_comment_default();
    rec
}

fn renames(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs
        .iter()
        .map(|(a, b)| (a.to_string(), b.to_string()))
        .collect()
}

fn affected(rec: &Record) -> Vec<String> {
    rec.payload_as::<GotchaRecord>().unwrap().affected_files
}

#[test]
fn plan_follows_a_simple_rename() {
    let dir = scratch_tree(&["src/new.rs"]);
    let gotchas = vec![make_gotcha("gotcha:lock", &["src/old.rs"], true)];

    let plans = plan_rename_migrations(
        &renames(&[("src/old.rs", "src/new.rs")]),
        &gotchas,
        dir.path(),
    );

    assert_eq!(plans.len(), 1);
    assert_eq!(plans[0].key, "gotcha:lock");
    assert_eq!(plans[0].old_files, vec!["src/old.rs"]);
    assert_eq!(plans[0].new_files, vec!["src/new.rs"]);
    assert_eq!(
        plans[0].followed,
        vec![("src/old.rs".to_string(), "src/new.rs".to_string())]
    );
}

/// The steady state. `recent_renames` still reports the move on every
/// subsequent init — git history does not forget — so the no-op has to come
/// from the gotcha no longer naming the old path.
#[test]
fn plan_is_empty_once_the_rename_is_followed() {
    let dir = scratch_tree(&["src/new.rs"]);
    let gotchas = vec![make_gotcha("gotcha:lock", &["src/new.rs"], true)];

    let plans = plan_rename_migrations(
        &renames(&[("src/old.rs", "src/new.rs")]),
        &gotchas,
        dir.path(),
    );

    assert!(plans.is_empty(), "re-running init must not re-migrate");
}

/// A file still at the old path is a copy, not a move — git reports the
/// delta either way when the content matches. The gotcha still describes a
/// real file, so leave it alone.
#[test]
fn plan_skips_a_copy_where_the_old_path_survives() {
    let dir = scratch_tree(&["src/old.rs", "src/new.rs"]);
    let gotchas = vec![make_gotcha("gotcha:lock", &["src/old.rs"], true)];

    let plans = plan_rename_migrations(
        &renames(&[("src/old.rs", "src/new.rs")]),
        &gotchas,
        dir.path(),
    );

    assert!(plans.is_empty());
}

#[test]
fn plan_skips_when_the_new_path_is_gone_too() {
    let dir = scratch_tree(&[]);
    let gotchas = vec![make_gotcha("gotcha:lock", &["src/old.rs"], true)];

    let plans = plan_rename_migrations(
        &renames(&[("src/old.rs", "src/new.rs")]),
        &gotchas,
        dir.path(),
    );

    assert!(plans.is_empty());
}

/// Unconfirmed gotchas are re-keyed too: they are pending `mati review`,
/// and a reviewer confirming one later must get the current path.
#[test]
fn plan_follows_an_unconfirmed_gotcha() {
    let dir = scratch_tree(&["src/new.rs"]);
    let gotchas = vec![make_gotcha("gotcha:lock", &["src/old.rs"], false)];

    let plans = plan_rename_migrations(
        &renames(&[("src/old.rs", "src/new.rs")]),
        &gotchas,
        dir.path(),
    );

    assert_eq!(plans.len(), 1);
    assert_eq!(plans[0].new_files, vec!["src/new.rs"]);
}

#[test]
fn plan_skips_auto_generated_and_tombstoned_gotchas() {
    let dir = scratch_tree(&["src/new.rs"]);
    let mut tombstoned = make_gotcha("gotcha:dead", &["src/old.rs"], true);
    tombstoned.lifecycle = RecordLifecycle::Tombstoned {
        reason: mati_core::store::TombstoneReason::ManualDeletion,
        at: 1,
    };
    let gotchas = vec![
        make_gotcha("gotcha:cochange:src/old.rs|src/x.rs", &["src/old.rs"], true),
        make_gotcha("gotcha:revert:src/old.rs", &["src/old.rs"], true),
        make_gotcha("gotcha:ownership:src/old.rs", &["src/old.rs"], true),
        tombstoned,
    ];

    let plans = plan_rename_migrations(
        &renames(&[("src/old.rs", "src/new.rs")]),
        &gotchas,
        dir.path(),
    );

    assert!(plans.is_empty());
}

/// A gotcha that already listed both paths must not end up naming the
/// target twice — the write-side normalizer collapses the duplicate, and
/// `old_files` still carries the old spelling so the link is unwound.
#[test]
fn plan_collapses_a_gotcha_naming_both_paths() {
    let dir = scratch_tree(&["src/new.rs"]);
    let gotchas = vec![make_gotcha(
        "gotcha:lock",
        &["src/old.rs", "src/new.rs"],
        true,
    )];

    let plans = plan_rename_migrations(
        &renames(&[("src/old.rs", "src/new.rs")]),
        &gotchas,
        dir.path(),
    );

    assert_eq!(plans.len(), 1);
    assert_eq!(plans[0].new_files, vec!["src/new.rs"]);
    assert_eq!(plans[0].old_files, vec!["src/old.rs", "src/new.rs"]);
}

/// `recent_renames` is newest-first, so the newest move off a path wins and
/// a replayed delta does not produce a second plan.
#[test]
fn plan_takes_the_newest_move_off_a_path() {
    let dir = scratch_tree(&["src/newest.rs"]);
    let gotchas = vec![make_gotcha("gotcha:lock", &["src/old.rs"], true)];

    let plans = plan_rename_migrations(
        &renames(&[
            ("src/old.rs", "src/newest.rs"),
            ("src/old.rs", "src/older.rs"),
            ("src/old.rs", "src/newest.rs"),
        ]),
        &gotchas,
        dir.path(),
    );

    assert_eq!(plans.len(), 1);
    assert_eq!(plans[0].new_files, vec!["src/newest.rs"]);
}

// ── Store-backed ──────────────────────────────────────────────────────────

async fn seed_file_record(store: &Store, path: &str, gotcha_keys: &[&str]) {
    let key = format!("file:{path}");
    let mut rec = make_record_with_category(&key, Category::File);
    rec.payload = Some(serde_json::json!({
        "path": path,
        "purpose": "",
        "entry_points": [],
        "imports": [],
        "gotcha_keys": gotcha_keys,
        "decision_keys": [],
        "todos": [],
        "unsafe_count": 0,
        "unwrap_count": 0,
        "change_frequency": 0,
        "last_author": null,
        "is_hotspot": false,
        "token_cost_estimate": 0,
        "last_modified_session": 0,
        "line_count": 0,
    }));
    store.put(&key, &rec).await.unwrap();
}

#[tokio::test]
async fn migration_rekeys_the_gotcha_and_moves_the_file_link() {
    let dir = scratch_tree(&["src/new.rs"]);
    let store = Store::open(dir.path()).await.unwrap();

    let mut gotchas = vec![make_gotcha("gotcha:lock", &["src/old.rs"], true)];
    store.put("gotcha:lock", &gotchas[0]).await.unwrap();
    seed_file_record(&store, "src/old.rs", &["gotcha:lock"]).await;
    seed_file_record(&store, "src/new.rs", &[]).await;

    let applied = migrate_renamed_gotchas(
        &store,
        dir.path(),
        &renames(&[("src/old.rs", "src/new.rs")]),
        &mut gotchas,
    )
    .await;

    assert_eq!(applied.len(), 1);
    assert!(!applied[0].sandbox_tagged);

    // Canonical record re-keyed, and the in-memory copy §8c reads matches.
    let stored = store.get("gotcha:lock").await.unwrap().unwrap();
    assert_eq!(affected(&stored), vec!["src/new.rs"]);
    assert_eq!(affected(&gotchas[0]), vec!["src/new.rs"]);

    // Enforcement inputs untouched — a followed rename keeps enforcing.
    let g = stored.payload_as::<GotchaRecord>().unwrap();
    assert!(g.confirmed);
    assert!(stored.confidence.value >= 0.6, "confidence must not drop");
    assert!(stored.quality.value >= 0.4, "quality must not drop");
    assert!(stored.tags.iter().any(|t| t == TAG_PATH_MIGRATED));

    // Link moved onto the new file record.
    let new_file = store.get("file:src/new.rs").await.unwrap().unwrap();
    let keys = new_file.payload_as::<FileRecord>().unwrap().gotcha_keys;
    assert_eq!(keys, vec!["gotcha:lock"]);

    // Orphan retired outright rather than left to be tombstoned, which the
    // gate would read as an unconditional allow.
    assert!(store.get("file:src/old.rs").await.unwrap().is_none());

    store.close().await.unwrap();
}

/// init runs on every session, so a second pass over the same git history
/// must write nothing at all — asserted on the record version, which
/// `apply_gotcha_write` would bump.
#[tokio::test]
async fn re_running_the_migration_is_a_no_op() {
    let dir = scratch_tree(&["src/new.rs"]);
    let store = Store::open(dir.path()).await.unwrap();

    let mut gotchas = vec![make_gotcha("gotcha:lock", &["src/old.rs"], true)];
    store.put("gotcha:lock", &gotchas[0]).await.unwrap();
    seed_file_record(&store, "src/old.rs", &["gotcha:lock"]).await;
    seed_file_record(&store, "src/new.rs", &[]).await;

    let pairs = renames(&[("src/old.rs", "src/new.rs")]);
    assert_eq!(
        migrate_renamed_gotchas(&store, dir.path(), &pairs, &mut gotchas)
            .await
            .len(),
        1
    );
    let after_first = store.get("gotcha:lock").await.unwrap().unwrap();

    let second = migrate_renamed_gotchas(&store, dir.path(), &pairs, &mut gotchas).await;

    assert!(second.is_empty(), "second init must not re-migrate");
    let after_second = store.get("gotcha:lock").await.unwrap().unwrap();
    assert_eq!(
        after_second.version.logical_clock, after_first.version.logical_clock,
        "no-op pass must not write the record"
    );
    assert_eq!(
        after_second
            .tags
            .iter()
            .filter(|t| *t == TAG_PATH_MIGRATED)
            .count(),
        1,
        "tag must not accumulate"
    );

    store.close().await.unwrap();
}

/// An unconfirmed gotcha follows the rename so a later `mati review`
/// confirmation lands on the current path — but following must not itself
/// promote it: the gate still allows, because `confirmed` is untouched.
#[tokio::test]
async fn migration_of_an_unconfirmed_gotcha_does_not_start_enforcing() {
    use mati_core::hooks::decide::{evaluate, Decision, EnforcementInput};

    let dir = scratch_tree(&["src/new.rs"]);
    let store = Store::open(dir.path()).await.unwrap();

    let mut gotchas = vec![make_gotcha("gotcha:draft", &["src/old.rs"], false)];
    store.put("gotcha:draft", &gotchas[0]).await.unwrap();
    seed_file_record(&store, "src/old.rs", &["gotcha:draft"]).await;
    seed_file_record(&store, "src/new.rs", &[]).await;

    let applied = migrate_renamed_gotchas(
        &store,
        dir.path(),
        &renames(&[("src/old.rs", "src/new.rs")]),
        &mut gotchas,
    )
    .await;

    assert_eq!(applied.len(), 1);
    let stored = store.get("gotcha:draft").await.unwrap().unwrap();
    assert_eq!(affected(&stored), vec!["src/new.rs"]);
    assert!(!stored.payload_as::<GotchaRecord>().unwrap().confirmed);

    let file_record = store.get("file:src/new.rs").await.unwrap().unwrap();
    let decision = evaluate(&EnforcementInput {
        rel_path: "src/new.rs".into(),
        file_record: serde_json::to_value(&file_record).ok(),
        gotcha_records: HashMap::from([(
            "gotcha:draft".to_string(),
            serde_json::to_value(&stored).unwrap(),
        )]),
        already_consulted: false,
        file_exists: None,
    })
    .decision;
    assert!(
        matches!(decision, Decision::Allow),
        "an unconfirmed gotcha must not deny after being re-keyed"
    );

    store.close().await.unwrap();
}

/// Both paths already carry a gotcha. Keys are distinct, so the new file
/// record ends up enforcing both rather than either being dropped.
#[tokio::test]
async fn migration_merges_when_both_paths_have_gotchas() {
    let dir = scratch_tree(&["src/new.rs"]);
    let store = Store::open(dir.path()).await.unwrap();

    let mut gotchas = vec![
        make_gotcha("gotcha:on-old", &["src/old.rs"], true),
        make_gotcha("gotcha:on-new", &["src/new.rs"], true),
    ];
    store.put("gotcha:on-old", &gotchas[0]).await.unwrap();
    store.put("gotcha:on-new", &gotchas[1]).await.unwrap();
    seed_file_record(&store, "src/old.rs", &["gotcha:on-old"]).await;
    seed_file_record(&store, "src/new.rs", &["gotcha:on-new"]).await;

    let applied = migrate_renamed_gotchas(
        &store,
        dir.path(),
        &renames(&[("src/old.rs", "src/new.rs")]),
        &mut gotchas,
    )
    .await;

    assert_eq!(applied.len(), 1, "only the gotcha naming `old` moves");
    let new_file = store.get("file:src/new.rs").await.unwrap().unwrap();
    let mut keys = new_file.payload_as::<FileRecord>().unwrap().gotcha_keys;
    keys.sort();
    assert_eq!(keys, vec!["gotcha:on-new", "gotcha:on-old"]);
    assert!(store.get("file:src/old.rs").await.unwrap().is_none());

    store.close().await.unwrap();
}

/// The point of the whole pass: the read gate must deny on the new path.
#[tokio::test]
async fn gate_denies_on_the_new_path_after_migration() {
    use mati_core::hooks::decide::{evaluate, Decision, EnforcementInput};

    let dir = scratch_tree(&["src/new.rs"]);
    let store = Store::open(dir.path()).await.unwrap();

    let mut gotchas = vec![make_gotcha("gotcha:lock", &["src/old.rs"], true)];
    store.put("gotcha:lock", &gotchas[0]).await.unwrap();
    seed_file_record(&store, "src/old.rs", &["gotcha:lock"]).await;
    seed_file_record(&store, "src/new.rs", &[]).await;

    // Before: the new path has no gotcha attached, so the gate allows.
    let before = evaluate(&EnforcementInput {
        rel_path: "src/new.rs".into(),
        file_record: serde_json::to_value(store.get("file:src/new.rs").await.unwrap().unwrap())
            .ok(),
        gotcha_records: HashMap::new(),
        already_consulted: false,
        file_exists: None,
    });
    assert!(matches!(before.decision, Decision::Allow));

    migrate_renamed_gotchas(
        &store,
        dir.path(),
        &renames(&[("src/old.rs", "src/new.rs")]),
        &mut gotchas,
    )
    .await;

    let file_record = store.get("file:src/new.rs").await.unwrap().unwrap();
    let gotcha = store.get("gotcha:lock").await.unwrap().unwrap();
    let after = evaluate(&EnforcementInput {
        rel_path: "src/new.rs".into(),
        file_record: serde_json::to_value(&file_record).ok(),
        gotcha_records: HashMap::from([(
            "gotcha:lock".to_string(),
            serde_json::to_value(&gotcha).unwrap(),
        )]),
        already_consulted: false,
        file_exists: None,
    });
    assert!(
        matches!(after.decision, Decision::Deny { .. }),
        "expected a deny on the renamed path, got {:?}",
        std::mem::discriminant(&after.decision)
    );

    store.close().await.unwrap();
}

/// A sandbox-tagged gotcha is flagged so init can tell the user the
/// materialized deny floor still names the old path.
#[tokio::test]
async fn migration_flags_a_sandbox_tagged_gotcha() {
    let dir = scratch_tree(&["src/new.rs"]);
    let store = Store::open(dir.path()).await.unwrap();

    let mut rec = make_gotcha("gotcha:secrets", &["src/old.rs"], true);
    rec.tags = vec![super::super::sandbox::TAG_DENY_READ.to_string()];
    store.put("gotcha:secrets", &rec).await.unwrap();
    let mut gotchas = vec![rec];
    seed_file_record(&store, "src/old.rs", &["gotcha:secrets"]).await;

    let applied = migrate_renamed_gotchas(
        &store,
        dir.path(),
        &renames(&[("src/old.rs", "src/new.rs")]),
        &mut gotchas,
    )
    .await;

    assert_eq!(applied.len(), 1);
    assert!(applied[0].sandbox_tagged);

    store.close().await.unwrap();
}
