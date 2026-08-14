use super::*;
use crate::store::record::{
    Category, ConfidenceScore, GotchaRecord, Priority, QualityScore, RecordSource, RecordVersion,
    StalenessScore,
};

fn make_gotcha_record(key: &str, files: &[&str]) -> Record {
    let gotcha = GotchaRecord {
        rule: "test rule".into(),
        reason: "test reason".into(),
        severity: Priority::High,
        affected_files: files.iter().map(|s| s.to_string()).collect(),
        ref_url: None,
        discovered_session: 1_000_000,
        confirmed: true,
        confirmed_content: Default::default(),
    };
    Record {
        key: key.to_string(),
        value: "test rule because test reason".into(),
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

/// `make_file_record` with a content digest, as `mati init` writes it.
fn make_file_record_hashed(path: &str, content_hash: &str) -> Record {
    let mut rec = make_file_record(path);
    if let Some(obj) = rec.payload.as_mut().and_then(|p| p.as_object_mut()) {
        obj.insert(
            "content_hash".into(),
            serde_json::Value::String(content_hash.to_string()),
        );
    }
    rec
}

fn stored_stamp(record: &Record) -> BTreeMap<String, String> {
    record
        .payload_as::<GotchaRecord>()
        .map(|g| g.confirmed_content)
        .unwrap_or_default()
}

fn make_file_record(path: &str) -> Record {
    Record {
        key: format!("file:{path}"),
        value: String::new(),
        payload: Some(serde_json::json!({
            "path": path,
            "purpose": "",
            "entry_points": [],
            "imports": [],
            "gotcha_keys": [],
            "decision_keys": [],
            "todos": [],
            "unsafe_count": 0,
            "unwrap_count": 0,
            "change_frequency": 0,
            "is_hotspot": false,
            "token_cost_estimate": 0,
            "last_modified_session": 0,
            "line_count": 0
        })),
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
    }
}

fn file_gotcha_keys(record: &Record) -> Vec<String> {
    record
        .payload
        .as_ref()
        .and_then(|p| p.get("gotcha_keys"))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

#[tokio::test]
async fn ensure_key_available_rejects_existing() {
    let dir = tempfile::TempDir::new().unwrap();
    let store = Store::open(dir.path()).await.unwrap();
    let record = make_gotcha_record("gotcha:exists", &["src/a.rs"]);
    store.put("gotcha:exists", &record).await.unwrap();

    let err = ensure_gotcha_key_available(&store, "gotcha:exists")
        .await
        .unwrap_err();
    assert!(err.to_string().contains("already exists"));
    store.close().await.unwrap();
}

#[tokio::test]
async fn ensure_key_available_passes_for_missing() {
    let dir = tempfile::TempDir::new().unwrap();
    let store = Store::open(dir.path()).await.unwrap();
    ensure_gotcha_key_available(&store, "gotcha:new")
        .await
        .unwrap();
    store.close().await.unwrap();
}

#[tokio::test]
async fn apply_write_adds_file_links_and_edges() {
    let dir = tempfile::TempDir::new().unwrap();
    let store = Store::open(dir.path()).await.unwrap();

    // Seed file records
    store
        .put("file:src/a.rs", &make_file_record("src/a.rs"))
        .await
        .unwrap();
    store
        .put("file:src/b.rs", &make_file_record("src/b.rs"))
        .await
        .unwrap();

    let record = make_gotcha_record("gotcha:test", &["src/a.rs", "src/b.rs"]);
    let files = vec!["src/a.rs".into(), "src/b.rs".into()];

    apply_gotcha_write(&store, dir.path(), &record, &[], &files, true)
        .await
        .unwrap();

    // Both files should have the gotcha key
    let a = store.get("file:src/a.rs").await.unwrap().unwrap();
    let b = store.get("file:src/b.rs").await.unwrap().unwrap();
    assert!(file_gotcha_keys(&a).contains(&"gotcha:test".to_string()));
    assert!(file_gotcha_keys(&b).contains(&"gotcha:test".to_string()));

    // Graph edges should exist
    let edge_keys = store.scan_keys("graph:edge:").await.unwrap();
    let edge_a = Edge::new("file:src/a.rs", EdgeKind::HasGotcha, "gotcha:test").to_key();
    let edge_b = Edge::new("file:src/b.rs", EdgeKind::HasGotcha, "gotcha:test").to_key();
    assert!(edge_keys.contains(&edge_a));
    assert!(edge_keys.contains(&edge_b));

    store.close().await.unwrap();
}

#[tokio::test]
async fn apply_write_rejects_collision_when_is_new() {
    let dir = tempfile::TempDir::new().unwrap();
    let store = Store::open(dir.path()).await.unwrap();

    let record = make_gotcha_record("gotcha:dup", &["src/a.rs"]);
    store.put("gotcha:dup", &record).await.unwrap();

    let record2 = make_gotcha_record("gotcha:dup", &["src/b.rs"]);
    let err = apply_gotcha_write(
        &store,
        dir.path(),
        &record2,
        &[],
        &["src/b.rs".into()],
        true,
    )
    .await
    .unwrap_err();
    assert!(err.to_string().contains("already exists"));

    store.close().await.unwrap();
}

#[tokio::test]
async fn apply_write_edit_moves_links_between_files() {
    let dir = tempfile::TempDir::new().unwrap();
    let store = Store::open(dir.path()).await.unwrap();

    store
        .put("file:src/a.rs", &make_file_record("src/a.rs"))
        .await
        .unwrap();
    store
        .put("file:src/b.rs", &make_file_record("src/b.rs"))
        .await
        .unwrap();

    // Initial write targeting src/a.rs
    let record = make_gotcha_record("gotcha:move", &["src/a.rs"]);
    apply_gotcha_write(&store, dir.path(), &record, &[], &["src/a.rs".into()], true)
        .await
        .unwrap();

    // Edit: move from src/a.rs to src/b.rs
    let record2 = make_gotcha_record("gotcha:move", &["src/b.rs"]);
    apply_gotcha_write(
        &store,
        dir.path(),
        &record2,
        &["src/a.rs".into()],
        &["src/b.rs".into()],
        false,
    )
    .await
    .unwrap();

    let a = store.get("file:src/a.rs").await.unwrap().unwrap();
    let b = store.get("file:src/b.rs").await.unwrap().unwrap();
    assert!(!file_gotcha_keys(&a).contains(&"gotcha:move".to_string()));
    assert!(file_gotcha_keys(&b).contains(&"gotcha:move".to_string()));

    // Edge should move too
    let edge_keys = store.scan_keys("graph:edge:").await.unwrap();
    let edge_a = Edge::new("file:src/a.rs", EdgeKind::HasGotcha, "gotcha:move").to_key();
    let edge_b = Edge::new("file:src/b.rs", EdgeKind::HasGotcha, "gotcha:move").to_key();
    assert!(!edge_keys.contains(&edge_a));
    assert!(edge_keys.contains(&edge_b));

    store.close().await.unwrap();
}

#[tokio::test]
async fn apply_tombstone_cleans_links_and_edges() {
    let dir = tempfile::TempDir::new().unwrap();
    let store = Store::open(dir.path()).await.unwrap();

    store
        .put("file:src/a.rs", &make_file_record("src/a.rs"))
        .await
        .unwrap();
    store
        .put("file:src/b.rs", &make_file_record("src/b.rs"))
        .await
        .unwrap();

    // Write gotcha first
    let record = make_gotcha_record("gotcha:del", &["src/a.rs", "src/b.rs"]);
    let files = vec!["src/a.rs".into(), "src/b.rs".into()];
    apply_gotcha_write(&store, dir.path(), &record, &[], &files, true)
        .await
        .unwrap();

    // Tombstone it
    apply_gotcha_tombstone(&store, "gotcha:del", &files)
        .await
        .unwrap();

    // Record should be tombstoned
    let rec = store.get("gotcha:del").await.unwrap().unwrap();
    assert!(matches!(rec.lifecycle, RecordLifecycle::Tombstoned { .. }));

    // File records should have empty gotcha_keys
    let a = store.get("file:src/a.rs").await.unwrap().unwrap();
    let b = store.get("file:src/b.rs").await.unwrap().unwrap();
    assert!(file_gotcha_keys(&a).is_empty());
    assert!(file_gotcha_keys(&b).is_empty());

    // Graph edges should be gone
    let edge_keys = store.scan_keys("graph:edge:").await.unwrap();
    let edge_a = Edge::new("file:src/a.rs", EdgeKind::HasGotcha, "gotcha:del").to_key();
    let edge_b = Edge::new("file:src/b.rs", EdgeKind::HasGotcha, "gotcha:del").to_key();
    assert!(!edge_keys.contains(&edge_a));
    assert!(!edge_keys.contains(&edge_b));

    store.close().await.unwrap();
}

#[tokio::test]
async fn apply_tombstone_errors_on_missing_key() {
    let dir = tempfile::TempDir::new().unwrap();
    let store = Store::open(dir.path()).await.unwrap();

    let err = apply_gotcha_tombstone(&store, "gotcha:ghost", &[])
        .await
        .unwrap_err();
    assert!(err.to_string().contains("not found"));

    store.close().await.unwrap();
}

/// Simulates the mem_set → sync_gotcha_file_links path: a gotcha is
/// written directly (as mem_set does), then file links are synced
/// separately. Verifies that the file record's gotcha_keys are updated.
#[tokio::test]
async fn sync_file_links_backfills_after_direct_write() {
    let dir = tempfile::TempDir::new().unwrap();
    let store = Store::open(dir.path()).await.unwrap();

    // Seed file record with no gotcha_keys
    store
        .put("file:src/a.rs", &make_file_record("src/a.rs"))
        .await
        .unwrap();

    // Simulate mem_set: write gotcha record directly (no apply_gotcha_write)
    let record = make_gotcha_record("gotcha:mcp-created", &["src/a.rs"]);
    store.put("gotcha:mcp-created", &record).await.unwrap();

    // File should NOT have the link yet (this is the pre-fix state)
    let a = store.get("file:src/a.rs").await.unwrap().unwrap();
    assert!(!file_gotcha_keys(&a).contains(&"gotcha:mcp-created".to_string()));

    // Now call sync_gotcha_file_links (what mem_set now does after the fix)
    sync_gotcha_file_links(&store, "gotcha:mcp-created", &[], &["src/a.rs".into()])
        .await
        .unwrap();

    // File should now have the link
    let a2 = store.get("file:src/a.rs").await.unwrap().unwrap();
    assert!(file_gotcha_keys(&a2).contains(&"gotcha:mcp-created".to_string()));

    store.close().await.unwrap();
}

/// Regression: `now_secs()` is storage-class — its return value is
/// persisted as a graph edge timestamp. A clock that has slipped before
/// the UNIX epoch (e.g. unset RTC on first boot, VM resumed against a
/// 1969-stamped image) must abort the write rather than silently
/// fabricating a 0-second timestamp that lives forever in the
/// versioned store. This test reproduces the same `duration_since(...).expect(...)`
/// pattern against a known-pre-epoch `SystemTime` and asserts the panic
/// message identifies UNIX epoch as the cause so operators can diagnose
/// it from the lifecycle.log "panic" entry.
#[test]
fn now_secs_panics_on_pre_epoch_clock_with_unix_epoch_in_message() {
    use std::panic;
    use std::time::{Duration, UNIX_EPOCH};

    // SystemTime one second before the epoch — `duration_since(UNIX_EPOCH)`
    // returns Err for any t < UNIX_EPOCH, mirroring what `SystemTime::now()`
    // would return on a backwards-walked system clock.
    let pre_epoch = UNIX_EPOCH - Duration::from_secs(1);

    // The next four lines must mirror the production `now_secs()` body
    // verbatim (modulo the `SystemTime::now()` substitution); the whole
    // point is to exercise the same `expect` literal that ships in the
    // hot path.
    let result = panic::catch_unwind(|| {
        let _ = pre_epoch
                .duration_since(UNIX_EPOCH)
                .expect("system clock is before UNIX epoch — refusing to write a corrupt timestamp into the gotcha store")
                .as_secs();
    });

    let payload = result.expect_err("pre-epoch SystemTime must panic, not silently return 0");
    let msg = if let Some(s) = payload.downcast_ref::<&'static str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        panic!("panic payload was neither &str nor String");
    };

    assert!(
            msg.contains("UNIX epoch"),
            "panic message should mention 'UNIX epoch' so operators can diagnose clock-backward; got: {msg}"
        );
    assert!(
        msg.contains("refusing to write"),
        "panic message should indicate the write was refused (not silently zeroed); got: {msg}"
    );
}

/// Sanity check that `now_secs()` returns a sensible value under normal
/// conditions (post-epoch wall clock). Guards against a future refactor
/// accidentally turning the `expect` into something that returns 0.
#[test]
fn now_secs_returns_recent_post_epoch_seconds() {
    let s = now_secs();
    // 2024-01-01 UTC = 1_704_067_200; any sane CI box runs after this.
    assert!(
        s > 1_704_067_200,
        "now_secs() returned {s}; expected a post-2024 timestamp"
    );
}

/// D3 regression: enrichment-tagged gotchas must produce an
/// ExtractionRecord on write (outcome=Pending). Confirming the
/// gotcha must flip the outcome to Confirmed; tombstoning to
/// Tombstoned. Untagged gotchas (manual `mati gotcha add`) must
/// NOT produce an ExtractionRecord — keeps the analytics scoped
/// to the enrichment pipeline.
#[tokio::test]
async fn enriched_gotcha_lifecycle_flips_extraction_outcome() {
    use crate::store::extraction::{key_for, ExtractionOutcome, ExtractionRecord};

    let dir = tempfile::TempDir::new().unwrap();
    let store = Store::open(dir.path()).await.unwrap();

    // Build an "enriched" gotcha record with depth:deep tag.
    let mut record = make_gotcha_record("gotcha:enriched-rule", &["src/cli/repair.rs"]);
    record.tags = vec!["enriched".into(), "depth:deep".into()];

    apply_gotcha_write(
        &store,
        dir.path(),
        &record,
        &[],
        &["src/cli/repair.rs".into()],
        true,
    )
    .await
    .unwrap();

    // After write, ExtractionRecord must exist with outcome=Pending,
    // depth=Deep, file_path set.
    let rec = store
        .get(&key_for("gotcha:enriched-rule"))
        .await
        .unwrap()
        .expect("extraction record must exist for enriched gotcha");
    let extraction: ExtractionRecord =
        serde_json::from_value(rec.payload.expect("payload")).unwrap();
    assert_eq!(extraction.outcome, ExtractionOutcome::Pending);
    assert_eq!(
        extraction.depth,
        Some(crate::health::enrichment::EnrichmentDepth::Deep)
    );
    assert_eq!(extraction.file_path, "src/cli/repair.rs");
    assert!(extraction.outcome_at.is_none());

    // Confirm → outcome must flip to Confirmed.
    apply_gotcha_confirm(&store, dir.path(), &record, &["src/cli/repair.rs".into()])
        .await
        .unwrap();
    let rec = store
        .get(&key_for("gotcha:enriched-rule"))
        .await
        .unwrap()
        .unwrap();
    let extraction: ExtractionRecord = serde_json::from_value(rec.payload.unwrap()).unwrap();
    assert_eq!(extraction.outcome, ExtractionOutcome::Confirmed);
    assert!(extraction.outcome_at.is_some());

    // Now write + tombstone another enriched gotcha — outcome flips to Tombstoned.
    let mut t_record = make_gotcha_record("gotcha:tombstone-me", &["src/cli/init.rs"]);
    t_record.tags = vec!["enriched".into(), "depth:fast".into()];
    apply_gotcha_write(
        &store,
        dir.path(),
        &t_record,
        &[],
        &["src/cli/init.rs".into()],
        true,
    )
    .await
    .unwrap();
    apply_gotcha_tombstone(&store, "gotcha:tombstone-me", &["src/cli/init.rs".into()])
        .await
        .unwrap();

    let rec = store
        .get(&key_for("gotcha:tombstone-me"))
        .await
        .unwrap()
        .unwrap();
    let extraction: ExtractionRecord = serde_json::from_value(rec.payload.unwrap()).unwrap();
    assert_eq!(extraction.outcome, ExtractionOutcome::Tombstoned);
    assert_eq!(
        extraction.depth,
        Some(crate::health::enrichment::EnrichmentDepth::Fast)
    );

    // Untagged gotcha must NOT produce an ExtractionRecord.
    let untagged = make_gotcha_record("gotcha:manual-add", &["src/foo.rs"]);
    // tags vec is empty by default in make_gotcha_record
    apply_gotcha_write(
        &store,
        dir.path(),
        &untagged,
        &[],
        &["src/foo.rs".into()],
        true,
    )
    .await
    .unwrap();
    assert!(store
        .get(&key_for("gotcha:manual-add"))
        .await
        .unwrap()
        .is_none());

    store.close().await.unwrap();
}

// ── confirm-time content stamp ───────────────────────────────────────
//
// The stamp is the baseline `health::drift` compares against. It is
// written only by the confirm paths, hashes each affected file as it
// stands on disk, and never touches a score.

/// Write `contents` to `<dir>/<rel>`, creating parents.
fn write_source(dir: &std::path::Path, rel: &str, contents: &str) {
    let path = dir.join(rel);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, contents).unwrap();
}

/// The digest `confirm_content_stamp` produces for a file on disk.
fn disk_hash(dir: &std::path::Path, rel: &str) -> String {
    disk_content_hash(dir, rel).expect("file must be readable")
}

#[tokio::test]
async fn confirm_stamps_the_current_file_digest() {
    let dir = tempfile::TempDir::new().unwrap();
    let store = Store::open(dir.path()).await.unwrap();
    write_source(dir.path(), "src/a.rs", "fn a() {}\n");

    let record = make_gotcha_record("gotcha:stamped", &["src/a.rs"]);
    apply_gotcha_confirm(&store, dir.path(), &record, &["src/a.rs".into()])
        .await
        .unwrap();

    let stored = store.get("gotcha:stamped").await.unwrap().unwrap();
    assert_eq!(
        stored_stamp(&stored).get("src/a.rs"),
        Some(&disk_hash(dir.path(), "src/a.rs"))
    );

    // Stamping must not disturb anything the read gate reads. Quality and
    // confidence are set by the callers of this function, so the check here
    // is that they came through untouched.
    let gotcha = stored.payload_as::<GotchaRecord>().unwrap();
    assert!(gotcha.confirmed);
    assert_eq!(stored.confidence.value, record.confidence.value);
    assert_eq!(stored.quality.value, record.quality.value);
    assert!(matches!(
        stored.staleness.tier,
        crate::store::record::StalenessTier::Fresh
    ));

    store.close().await.unwrap();
}

/// Multi-file gotchas get one entry per affected file. A path with nothing
/// readable on disk (a glob, a file not written yet) is simply absent — the
/// reader treats that as unknown, never as drift.
#[tokio::test]
async fn confirm_stamps_each_affected_file_and_skips_unreadable_ones() {
    let dir = tempfile::TempDir::new().unwrap();
    let store = Store::open(dir.path()).await.unwrap();
    write_source(dir.path(), "src/a.rs", "fn a() {}\n");
    write_source(dir.path(), "src/b.rs", "fn b() {}\n");

    let files: Vec<String> = ["src/a.rs", "src/b.rs", "src/gone.rs", "src/payments/**"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let record = make_gotcha_record(
        "gotcha:multi",
        &["src/a.rs", "src/b.rs", "src/gone.rs", "src/payments/**"],
    );
    apply_gotcha_confirm(&store, dir.path(), &record, &files)
        .await
        .unwrap();

    let stamp = stored_stamp(&store.get("gotcha:multi").await.unwrap().unwrap());
    assert_eq!(
        stamp.get("src/a.rs"),
        Some(&disk_hash(dir.path(), "src/a.rs"))
    );
    assert_eq!(
        stamp.get("src/b.rs"),
        Some(&disk_hash(dir.path(), "src/b.rs"))
    );
    assert_eq!(stamp.len(), 2, "unreadable paths must not be stamped");

    store.close().await.unwrap();
}

/// The curation loop: edit the file, re-confirm, drift clears. Exercised
/// end-to-end through `health::drift` so the test fails if either side of
/// the comparison moves.
#[tokio::test]
async fn reconfirm_restamps_and_clears_drift() {
    use crate::health::drift::{detect_drift, disk_content_hashes};

    let dir = tempfile::TempDir::new().unwrap();
    let store = Store::open(dir.path()).await.unwrap();
    write_source(dir.path(), "src/a.rs", "fn a() {}\n");

    let record = make_gotcha_record("gotcha:curated", &["src/a.rs"]);
    apply_gotcha_confirm(&store, dir.path(), &record, &["src/a.rs".into()])
        .await
        .unwrap();

    // The developer edits the file.
    write_source(dir.path(), "src/a.rs", "fn a() { changed(); }\n");

    let gotchas = store.scan_prefix("gotcha:").await.unwrap();
    let drifted = detect_drift(&gotchas, &disk_content_hashes(dir.path(), &gotchas));
    assert_eq!(drifted.len(), 1, "edited file must report drift");
    assert_eq!(drifted[0].drifted_files, vec!["src/a.rs".to_string()]);

    // Developer re-reads and re-confirms.
    let current = store.get("gotcha:curated").await.unwrap().unwrap();
    apply_gotcha_confirm(&store, dir.path(), &current, &["src/a.rs".into()])
        .await
        .unwrap();

    let gotchas = store.scan_prefix("gotcha:").await.unwrap();
    assert!(
        detect_drift(&gotchas, &disk_content_hashes(dir.path(), &gotchas)).is_empty(),
        "re-confirming must re-stamp the current digest and clear the drift"
    );

    store.close().await.unwrap();
}

/// The defect this stamp path was moved to disk for: a developer edits a
/// file and confirms a rule against the edited code while the `file:*`
/// record still carries the pre-edit digest. That confirmation is honest,
/// so it must not report drift — not now, and not once a rescan finally
/// refreshes the file record.
#[tokio::test]
async fn confirming_against_edited_code_is_not_drift_behind_a_stale_index() {
    use crate::health::drift::{detect_drift, disk_content_hashes};

    let dir = tempfile::TempDir::new().unwrap();
    let store = Store::open(dir.path()).await.unwrap();
    write_source(dir.path(), "src/a.rs", "fn a() {}\n");
    let indexed_at_init = disk_hash(dir.path(), "src/a.rs");
    store
        .put(
            "file:src/a.rs",
            &make_file_record_hashed("src/a.rs", &indexed_at_init),
        )
        .await
        .unwrap();

    // Edit, then confirm. No rescan runs, so `file:src/a.rs` still says
    // `indexed_at_init`.
    write_source(dir.path(), "src/a.rs", "fn a() { edited(); }\n");
    let record = make_gotcha_record("gotcha:fresh-eyes", &["src/a.rs"]);
    apply_gotcha_confirm(&store, dir.path(), &record, &["src/a.rs".into()])
        .await
        .unwrap();

    let stored = store.get("gotcha:fresh-eyes").await.unwrap().unwrap();
    assert_eq!(
        stored_stamp(&stored).get("src/a.rs"),
        Some(&disk_hash(dir.path(), "src/a.rs")),
        "the stamp must be the edited file, not the digest the index still holds"
    );

    let gotchas = store.scan_prefix("gotcha:").await.unwrap();
    assert!(
        detect_drift(&gotchas, &disk_content_hashes(dir.path(), &gotchas)).is_empty(),
        "a rule confirmed against the code as it stands is not drifted"
    );

    store.close().await.unwrap();
}

/// `mati gotcha add` writes an already-confirmed record straight through
/// `apply_gotcha_write`, so that path stamps too — otherwise the most
/// common way to create an enforcing gotcha could never report drift.
/// Unconfirmed writes (Layer 0 stubs, `mem_set`) must stay unstamped.
#[tokio::test]
async fn new_confirmed_write_stamps_and_unconfirmed_does_not() {
    let dir = tempfile::TempDir::new().unwrap();
    let store = Store::open(dir.path()).await.unwrap();
    write_source(dir.path(), "src/a.rs", "fn a() {}\n");

    let confirmed = make_gotcha_record("gotcha:added", &["src/a.rs"]);
    apply_gotcha_write(
        &store,
        dir.path(),
        &confirmed,
        &[],
        &["src/a.rs".into()],
        true,
    )
    .await
    .unwrap();
    assert_eq!(
        stored_stamp(&store.get("gotcha:added").await.unwrap().unwrap()).get("src/a.rs"),
        Some(&disk_hash(dir.path(), "src/a.rs"))
    );

    let mut candidate = make_gotcha_record("gotcha:candidate", &["src/a.rs"]);
    if let Some(obj) = candidate.payload.as_mut().and_then(|p| p.as_object_mut()) {
        obj.insert("confirmed".into(), serde_json::Value::Bool(false));
    }
    apply_gotcha_write(
        &store,
        dir.path(),
        &candidate,
        &[],
        &["src/a.rs".into()],
        true,
    )
    .await
    .unwrap();
    assert!(
        stored_stamp(&store.get("gotcha:candidate").await.unwrap().unwrap()).is_empty(),
        "an unconfirmed candidate has no human sign-off to stamp"
    );

    store.close().await.unwrap();
}

/// An edit is not a re-confirmation: `apply_gotcha_write` with
/// `is_new = false` must leave the baseline alone, so a rule whose text
/// was tweaked (or whose path the rename migration moved) stays drifted.
#[tokio::test]
async fn edit_does_not_restamp_a_confirmed_gotcha() {
    let dir = tempfile::TempDir::new().unwrap();
    let store = Store::open(dir.path()).await.unwrap();
    write_source(dir.path(), "src/a.rs", "fn a() {}\n");
    let at_confirm = disk_hash(dir.path(), "src/a.rs");

    let record = make_gotcha_record("gotcha:edited", &["src/a.rs"]);
    apply_gotcha_confirm(&store, dir.path(), &record, &["src/a.rs".into()])
        .await
        .unwrap();
    write_source(dir.path(), "src/a.rs", "fn a() { changed(); }\n");

    // Re-write the record the way `mati gotcha edit` does — payload carried
    // forward, `is_new = false`.
    let edited = store.get("gotcha:edited").await.unwrap().unwrap();
    apply_gotcha_write(
        &store,
        dir.path(),
        &edited,
        &["src/a.rs".into()],
        &["src/a.rs".into()],
        false,
    )
    .await
    .unwrap();

    assert_eq!(
        stored_stamp(&store.get("gotcha:edited").await.unwrap().unwrap()).get("src/a.rs"),
        Some(&at_confirm),
        "an edit must not silently re-baseline a drifted rule"
    );

    store.close().await.unwrap();
}

/// A record confirmed before the stamp existed deserializes with an empty
/// map, which `detect_drift` treats as unknown. Written as raw JSON with
/// no `confirmed_content` key so it exercises the actual serde default.
#[tokio::test]
async fn pre_upgrade_record_has_no_stamp_and_is_not_drifted() {
    use crate::health::drift::{detect_drift, disk_content_hashes};

    let dir = tempfile::TempDir::new().unwrap();
    let store = Store::open(dir.path()).await.unwrap();
    write_source(dir.path(), "src/a.rs", "fn a() {}\n");

    let mut legacy = make_gotcha_record("gotcha:legacy", &["src/a.rs"]);
    legacy.payload = Some(serde_json::json!({
        "rule": "test rule",
        "reason": "test reason",
        "severity": "high",
        "affected_files": ["src/a.rs"],
        "discovered_session": 1_000_000,
        "confirmed": true
    }));
    store.put("gotcha:legacy", &legacy).await.unwrap();

    let stored = store.get("gotcha:legacy").await.unwrap().unwrap();
    let gotcha = stored
        .payload_as::<GotchaRecord>()
        .expect("a payload without confirmed_content must still deserialize");
    assert!(gotcha.confirmed);
    assert!(gotcha.confirmed_content.is_empty());

    let hashes = disk_content_hashes(dir.path(), std::slice::from_ref(&stored));
    assert!(
        detect_drift(&[stored], &hashes).is_empty(),
        "no stamp must read as unknown, never as drifted"
    );

    store.close().await.unwrap();
}

// ── affected_files normalization ─────────────────────────────────────
//
// The write side has to produce exactly the string the read gate looks up
// (`hooks::decide::normalize_path`, via `cli::hook_decide`). Anything else
// and the `file:<rel_path>` join silently misses and the gotcha never
// fires.

fn norm(files: &[&str], root: Option<&str>) -> Vec<String> {
    let owned: Vec<String> = files.iter().map(|s| s.to_string()).collect();
    normalize_affected_files_with_root(&owned, root)
}

#[test]
fn normalize_strips_dot_slash_prefix() {
    assert_eq!(norm(&["./src/foo.rs"], None), vec!["src/foo.rs"]);
    assert_eq!(norm(&["././src/foo.rs"], None), vec!["src/foo.rs"]);
    assert_eq!(norm(&["src/./foo.rs"], None), vec!["src/foo.rs"]);
    assert_eq!(norm(&["src/bar/../foo.rs"], None), vec!["src/foo.rs"]);
    assert_eq!(norm(&["src//foo.rs"], None), vec!["src/foo.rs"]);
}

#[test]
fn normalize_strips_repo_root_from_absolute_path() {
    assert_eq!(
        norm(&["/home/dev/repo/src/foo.rs"], Some("/home/dev/repo")),
        vec!["src/foo.rs"]
    );
    // Trailing slash on the entry's root prefix, and a `.` mid-path.
    assert_eq!(
        norm(&["/home/dev/repo/./src/foo.rs"], Some("/home/dev/repo")),
        vec!["src/foo.rs"]
    );
}

/// `normalize_affected_files` (the filesystem-aware wrapper) has to resolve
/// an absolute entry through symlinks before the repo-root strip, or the
/// macOS `/tmp` → `/private/tmp` split turns a valid absolute path into the
/// nonsense relative key `tmp/.../src/a.rs`. Exercised with a real symlink
/// so it fails on any platform where the resolution is skipped.
#[test]
fn normalize_resolves_symlinked_absolute_entry() {
    let dir = tempfile::TempDir::new().unwrap();
    let real = dir.path().join("real");
    std::fs::create_dir_all(real.join("src")).unwrap();
    std::fs::write(real.join("src/a.rs"), "fn main() {}\n").unwrap();
    let link = dir.path().join("link");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&real, &link).unwrap();

    // Root canonicalizes to `.../real`; the entry comes in via `.../link`.
    let root = std::fs::canonicalize(&real).unwrap();
    let entry = link.join("src/a.rs").to_string_lossy().into_owned();
    let resolved = resolve_lenient(&entry).expect("symlink must resolve");
    assert_eq!(
        normalize_affected_files_with_root(&[resolved], Some(root.to_str().unwrap())),
        vec!["src/a.rs"]
    );
}

/// Resolution must not require the file to exist — `mati gotcha add` on a
/// path that has not been created yet is a real flow (the create-on-write
/// stub in `update_file_gotcha_key` exists for exactly that).
#[test]
fn resolve_lenient_tolerates_a_missing_leaf() {
    let dir = tempfile::TempDir::new().unwrap();
    let root = std::fs::canonicalize(dir.path()).unwrap();
    let missing = dir.path().join("does_not_exist.rs");
    let resolved = resolve_lenient(missing.to_str().unwrap()).expect("parent resolves");
    assert_eq!(
        normalize_affected_files_with_root(&[resolved], Some(root.to_str().unwrap())),
        vec!["does_not_exist.rs"]
    );
}

/// Without a repo root there is nothing to strip. The gate behaves the
/// same way (`normalize_path(path, None)`), so both sides still agree —
/// which is the property that matters, even though neither can produce a
/// useful key here.
#[test]
fn normalize_absolute_path_without_root_matches_read_side() {
    let expected = crate::hooks::decide::normalize_path("/elsewhere/foo.rs", None);
    assert_eq!(norm(&["/elsewhere/foo.rs"], None), vec![expected]);
}

/// Globs (`analysis::onboarding`'s CODEOWNERS candidates) must survive
/// untouched — `*` is an ordinary path component to `normalize_path`.
#[test]
fn normalize_preserves_globs() {
    assert_eq!(norm(&["src/payments/**"], None), vec!["src/payments/**"]);
    assert_eq!(norm(&["src/*.rs"], None), vec!["src/*.rs"]);
    assert_eq!(norm(&["**/*.rs"], None), vec!["**/*.rs"]);
    // A glob still gets the `./` treatment, and nothing else.
    assert_eq!(norm(&["./src/payments/**"], None), vec!["src/payments/**"]);
}

#[test]
fn normalize_is_a_no_op_for_already_normalized_paths() {
    let files = &["src/a.rs", "src/nested/b.rs", "Cargo.toml"];
    assert_eq!(norm(files, Some("/home/dev/repo")), files.to_vec());
}

/// Two spellings of one path collapse to a single entry, so the gotcha
/// does not end up double-linked to the same file record.
#[test]
fn normalize_dedupes_and_drops_empties() {
    assert_eq!(
        norm(&["./src/a.rs", "src/a.rs", "", "src/b.rs"], None),
        vec!["src/a.rs", "src/b.rs"]
    );
}

/// `analysis::walker` and `analysis::git` rewrite `\` to `/` before a
/// `file:*` key is ever minted, so an entry carrying a backslash could
/// never match. Match the producers.
#[test]
fn normalize_rewrites_backslashes_like_the_key_producers() {
    assert_eq!(norm(&["src\\foo.rs"], None), vec!["src/foo.rs"]);
    assert_eq!(norm(&[".\\src\\foo.rs"], None), vec!["src/foo.rs"]);
}

/// End-to-end: a gotcha written with `./src/a.rs` must link `file:src/a.rs`
/// — the key the read gate looks up — and must store the corrected path in
/// its own payload, since `mati repair` rebuilds the indexes from there.
#[tokio::test]
async fn apply_write_normalizes_affected_files_before_linking() {
    let dir = tempfile::TempDir::new().unwrap();
    let store = Store::open(dir.path()).await.unwrap();

    store
        .put("file:src/a.rs", &make_file_record("src/a.rs"))
        .await
        .unwrap();

    let record = make_gotcha_record("gotcha:dotslash", &["./src/a.rs"]);
    apply_gotcha_write(
        &store,
        dir.path(),
        &record,
        &[],
        &["./src/a.rs".into()],
        true,
    )
    .await
    .unwrap();

    let a = store.get("file:src/a.rs").await.unwrap().unwrap();
    assert!(file_gotcha_keys(&a).contains(&"gotcha:dotslash".to_string()));
    assert!(
        store.get("file:./src/a.rs").await.unwrap().is_none(),
        "the raw spelling must not be linked or stubbed"
    );

    let stored = store.get("gotcha:dotslash").await.unwrap().unwrap();
    let gotcha = stored.payload_as::<GotchaRecord>().unwrap();
    assert_eq!(gotcha.affected_files, vec!["src/a.rs".to_string()]);

    let edge_keys = store.scan_keys("graph:edge:").await.unwrap();
    let edge = Edge::new("file:src/a.rs", EdgeKind::HasGotcha, "gotcha:dotslash").to_key();
    assert!(edge_keys.contains(&edge));

    store.close().await.unwrap();
}

/// An already-correct path must round-trip byte-for-byte: the payload is
/// not rewritten and no clone is taken.
#[tokio::test]
async fn apply_write_leaves_normalized_affected_files_untouched() {
    let dir = tempfile::TempDir::new().unwrap();
    let store = Store::open(dir.path()).await.unwrap();

    let record = make_gotcha_record("gotcha:clean", &["src/a.rs", "src/payments/**"]);
    let files = vec!["src/a.rs".to_string(), "src/payments/**".to_string()];
    apply_gotcha_write(&store, dir.path(), &record, &[], &files, true)
        .await
        .unwrap();

    let stored = store.get("gotcha:clean").await.unwrap().unwrap();
    let gotcha = stored.payload_as::<GotchaRecord>().unwrap();
    assert_eq!(gotcha.affected_files, files);

    store.close().await.unwrap();
}

/// D3 foundation regression: tombstone must write a negative-exemplar
/// record for each unique dirname in `affected_files`, capturing the
/// rule/reason/severity from the tombstoned gotcha. The exemplar is
/// what feeds back into future `/mati-enrich` runs on the same
/// directory so the extractor can avoid re-proposing similar
/// rejected rules. See `src/store/negative_exemplar.rs`.
#[tokio::test]
async fn tombstone_writes_negative_exemplar_per_unique_dirname() {
    let dir = tempfile::TempDir::new().unwrap();
    let store = Store::open(dir.path()).await.unwrap();

    // Seed a gotcha that affects two files in different directories
    // plus a second file in one of those dirnames (dedup target).
    let record = make_gotcha_record(
        "gotcha:vague-rule",
        &["src/cli/repair.rs", "src/cli/init.rs", "src/store/db.rs"],
    );
    store.put("gotcha:vague-rule", &record).await.unwrap();

    // Tombstone it.
    apply_gotcha_tombstone(
        &store,
        "gotcha:vague-rule",
        &[
            "src/cli/repair.rs".into(),
            "src/cli/init.rs".into(),
            "src/store/db.rs".into(),
        ],
    )
    .await
    .unwrap();

    // src/cli and src/store → 2 unique dirnames → 2 exemplars.
    let cli_exemplar = store
        .get("analytics:negative_exemplar:src/cli:vague-rule")
        .await
        .unwrap()
        .expect("src/cli exemplar must exist");
    let store_exemplar = store
        .get("analytics:negative_exemplar:src/store:vague-rule")
        .await
        .unwrap()
        .expect("src/store exemplar must exist");

    // Payload carries rule/reason/severity from the make_gotcha_record helper.
    for rec in [&cli_exemplar, &store_exemplar] {
        let payload = rec.payload.clone().expect("payload present");
        let exemplar: crate::store::negative_exemplar::NegativeExemplar =
            serde_json::from_value(payload).unwrap();
        assert_eq!(exemplar.gotcha_key, "gotcha:vague-rule");
        assert_eq!(exemplar.rule, "test rule");
        assert_eq!(exemplar.reason, "test reason");
        assert_eq!(exemplar.severity, Priority::High);
        assert!(exemplar.tombstoned_at > 0);
    }

    store.close().await.unwrap();
}
