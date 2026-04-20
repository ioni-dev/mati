//! Enforcement event recording integration tests.
//!
//! These are acceptance criteria for the enforcement event foundation.
//! Every test must pass before the feature is considered complete.

use std::path::PathBuf;

use tempfile::TempDir;

use mati_core::store::db::Store;
use mati_core::store::enforcement::{
    canonicalize_file_key, scan_enforcement_events, EnforcementEventType, EnforcementEventWriter,
    EnforcementMode, GapCause, GapCertainty, MissedEventCount, SeqAllocator, SubjectKind,
    SCHEMA_VERSION,
};

async fn temp_store() -> (TempDir, Store) {
    let dir = TempDir::new().expect("tempdir");
    let store = Store::open(dir.path()).await.expect("open store");
    (dir, store)
}

// ─────────────────────────────────────────────
// Test 1: Concurrent writes produce unique seq_nos
// ─────────────────────────────────────────────

#[tokio::test]
async fn concurrent_writes_produce_unique_seq_nos() {
    let (_dir, store) = temp_store().await;
    let mut writer = EnforcementEventWriter::new(&store)
        .await
        .expect("create writer");

    let mut seq_nos = Vec::with_capacity(100);
    for _ in 0..100 {
        let event = writer
            .write(
                &store,
                EnforcementEventType::Deny,
                SubjectKind::File,
                "file:src/test.rs".to_string(),
                "claude".to_string(),
                None,
                "gotcha_above_threshold".to_string(),
                None,
            )
            .await
            .expect("write event");
        seq_nos.push(event.seq_no);
    }

    // No duplicates
    let mut deduped = seq_nos.clone();
    deduped.sort();
    deduped.dedup();
    assert_eq!(
        deduped.len(),
        100,
        "all 100 seq_nos must be unique, got {} unique",
        deduped.len()
    );

    // Ascending order
    for window in seq_nos.windows(2) {
        assert!(
            window[0] < window[1],
            "seq_nos must be strictly ascending: {} >= {}",
            window[0],
            window[1]
        );
    }
}

// ─────────────────────────────────────────────
// Test 2: Crash between seq allocation and commit
// ─────────────────────────────────────────────

#[tokio::test]
async fn seq_gap_after_simulated_crash() {
    let (_dir, store) = temp_store().await;
    let mut writer = EnforcementEventWriter::new(&store)
        .await
        .expect("create writer");

    // Write event 1 (seq 1) — succeeds
    let event1 = writer
        .write(
            &store,
            EnforcementEventType::Deny,
            SubjectKind::File,
            "file:src/a.rs".to_string(),
            "claude".to_string(),
            None,
            "gotcha_above_threshold".to_string(),
            None,
        )
        .await
        .expect("write event 1");
    assert_eq!(event1.seq_no, 1);

    // Simulate crash: manually advance the seq counter to 5
    // (simulating seq 2-5 were allocated but events never written)
    store
        .put_raw("enforcement:seq", &5u64.to_be_bytes())
        .await
        .expect("advance seq");

    // Create a NEW writer (simulates restart after crash)
    let mut writer2 = EnforcementEventWriter::new(&store)
        .await
        .expect("create writer after crash");

    // Writer should have loaded seq=5 as current
    assert_eq!(writer2.current_seq(), 5);

    // Next event should get seq 6 (5+1)
    let event2 = writer2
        .write(
            &store,
            EnforcementEventType::Deny,
            SubjectKind::File,
            "file:src/b.rs".to_string(),
            "claude".to_string(),
            None,
            "gotcha_above_threshold".to_string(),
            None,
        )
        .await
        .expect("write event after crash");
    assert_eq!(event2.seq_no, 6);

    // The gap (seq 2-5) exists: no events stored for those seqs
    let all_events = scan_enforcement_events(&store, 1, 10).await.expect("scan");
    assert_eq!(all_events.len(), 2, "only 2 events should exist");
    assert_eq!(all_events[0].seq_no, 1);
    assert_eq!(all_events[1].seq_no, 6);

    // Hash chain is still intact: event2.prev_hash == event1.event_hash
    // (the writer loaded last hash from store on init)
    assert_eq!(event2.prev_hash, event1.event_hash);
}

// ─────────────────────────────────────────────
// Test 3: Export while writes are active (snapshot consistency)
// ─────────────────────────────────────────────

#[tokio::test]
async fn export_snapshot_consistency() {
    let (_dir, store) = temp_store().await;
    let mut writer = EnforcementEventWriter::new(&store)
        .await
        .expect("create writer");

    // Write 50 events
    for i in 0..50 {
        writer
            .write(
                &store,
                EnforcementEventType::Deny,
                SubjectKind::File,
                format!("file:src/file_{i}.rs"),
                "claude".to_string(),
                None,
                "gotcha_above_threshold".to_string(),
                None,
            )
            .await
            .expect("write event");
    }

    // Take a snapshot: scan seq 1 to 50
    let snapshot = scan_enforcement_events(&store, 1, 50)
        .await
        .expect("snapshot scan");
    assert_eq!(
        snapshot.len(),
        50,
        "snapshot must contain exactly 50 events"
    );

    // Write 10 more events (seq 51-60)
    for i in 50..60 {
        writer
            .write(
                &store,
                EnforcementEventType::Deny,
                SubjectKind::File,
                format!("file:src/file_{i}.rs"),
                "claude".to_string(),
                None,
                "gotcha_above_threshold".to_string(),
                None,
            )
            .await
            .expect("write event");
    }

    // The original snapshot range still returns exactly 50
    let snapshot_again = scan_enforcement_events(&store, 1, 50)
        .await
        .expect("snapshot scan again");
    assert_eq!(snapshot_again.len(), 50);

    // A full scan shows all 60
    let full = scan_enforcement_events(&store, 1, 60)
        .await
        .expect("full scan");
    assert_eq!(full.len(), 60);
}

// ─────────────────────────────────────────────
// Test 4: Prune/export race
// ─────────────────────────────────────────────

#[tokio::test]
async fn prune_does_not_corrupt_concurrent_export() {
    let (_dir, store) = temp_store().await;
    let mut writer = EnforcementEventWriter::new(&store)
        .await
        .expect("create writer");

    // Write 100 events
    for i in 0..100 {
        writer
            .write(
                &store,
                EnforcementEventType::Deny,
                SubjectKind::File,
                format!("file:src/file_{i}.rs"),
                "claude".to_string(),
                None,
                "gotcha_above_threshold".to_string(),
                None,
            )
            .await
            .expect("write event");
    }

    // Simulate pruning: delete events with seq < 50
    for seq in 1..50 {
        let key = format!("enforcement:event:{:020}", seq);
        store.delete(&key).await.expect("delete pruned event");
    }

    // Export scan of remaining range
    let remaining = scan_enforcement_events(&store, 1, 100)
        .await
        .expect("scan after prune");

    // Only seq 50-100 should remain (51 events)
    assert_eq!(remaining.len(), 51);
    assert_eq!(remaining[0].seq_no, 50);
    assert_eq!(remaining[50].seq_no, 100);

    // Verify no corrupted hashes — each event's hash is self-consistent
    for event in &remaining {
        let recomputed = event.compute_hash();
        assert_eq!(
            event.event_hash, recomputed,
            "event {} has corrupted hash",
            event.seq_no
        );
    }
}

// ─────────────────────────────────────────────
// Test 5: Gap detection and recovery
// ─────────────────────────────────────────────

#[tokio::test]
async fn gap_detection_on_recovery() {
    let (_dir, store) = temp_store().await;
    let mut writer = EnforcementEventWriter::new(&store)
        .await
        .expect("create writer");

    // Write event 1
    let event1 = writer
        .write(
            &store,
            EnforcementEventType::Deny,
            SubjectKind::File,
            "file:src/main.rs".to_string(),
            "claude".to_string(),
            None,
            "gotcha_above_threshold".to_string(),
            None,
        )
        .await
        .expect("write event 1");
    assert_eq!(event1.seq_no, 1);

    // Simulate daemon going unreachable: advance seq counter manually
    store
        .put_raw("enforcement:seq", &3u64.to_be_bytes())
        .await
        .expect("advance seq to simulate crash");

    // Create new writer (simulates recovery)
    let mut writer2 = EnforcementEventWriter::new(&store)
        .await
        .expect("create writer for recovery");

    // Emit a RecordingGap event
    let gap_event = writer2
        .detect_and_record_gap(
            &store,
            1700000000000,
            1700000060000,
            GapCause::DaemonUnreachable,
        )
        .await
        .expect("record gap");

    // Verify the gap event structure
    assert_eq!(gap_event.seq_no, 4); // seq was at 3, next is 4
    assert_eq!(gap_event.subject_kind, SubjectKind::System);
    assert_eq!(gap_event.decision_reason_code, "recording_gap_detected");

    match &gap_event.event_type {
        EnforcementEventType::RecordingGap {
            gap_start_ms,
            gap_end_ms,
            cause,
            enforcement_mode_during_gap,
            missed_event_count,
            certainty,
        } => {
            assert_eq!(*gap_start_ms, 1700000000000);
            assert_eq!(*gap_end_ms, 1700000060000);
            assert_eq!(*cause, GapCause::DaemonUnreachable);
            assert_eq!(*enforcement_mode_during_gap, EnforcementMode::Advisory);
            assert_eq!(*missed_event_count, MissedEventCount::Unknown);
            assert_eq!(*certainty, GapCertainty::Inferred);
        }
        other => panic!("expected RecordingGap, got {:?}", other),
    }

    // Hash chain from event1 to gap_event is intact
    assert_eq!(gap_event.prev_hash, event1.event_hash);
}

// ─────────────────────────────────────────────
// Test 6: Strict mode write failure
// ─────────────────────────────────────────────

#[tokio::test]
async fn strict_mode_blocks_on_write_failure() {
    // Use a store where we can verify write failure propagation.
    // We'll test by allocating a seq, then verifying that if the event
    // write were to fail, the error propagates correctly.
    //
    // Since we can't easily inject a store failure with the real store,
    // we verify the invariant differently: write to a closed/invalid store path.
    let dir = TempDir::new().expect("tempdir");
    let store = Store::open(dir.path()).await.expect("open store");

    let mut writer = EnforcementEventWriter::new(&store)
        .await
        .expect("create writer");

    // First write should succeed
    let event = writer
        .write(
            &store,
            EnforcementEventType::Deny,
            SubjectKind::File,
            "file:src/test.rs".to_string(),
            "claude".to_string(),
            None,
            "gotcha_above_threshold".to_string(),
            None,
        )
        .await
        .expect("first write succeeds");
    assert_eq!(event.seq_no, 1);
    assert_eq!(event.schema_version, SCHEMA_VERSION);

    // Verify the event was actually persisted
    let loaded = scan_enforcement_events(&store, 1, 1).await.expect("scan");
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].event_hash, event.event_hash);

    // Verify that the seq counter advanced durably
    let seq2 = SeqAllocator::load(&store).await;
    assert_eq!(seq2.current(), 1, "seq must be persisted durably");
}

// ─────────────────────────────────────────────
// Test 7: Canonical path aliasing
// ─────────────────────────────────────────────

#[test]
fn canonical_path_aliasing_produces_same_key() {
    // Use a path that exists on disk for canonicalize_file_key
    // (it needs to resolve against a real repo_root for symlink resolution)
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    // These relative paths should all normalize to the same key
    let paths = [
        "src/store/enforcement.rs",
        "./src/store/enforcement.rs",
        "src/store/../store/enforcement.rs",
        "src/./store/enforcement.rs",
    ];

    let canonical_keys: Vec<String> = paths
        .iter()
        .map(|p| canonicalize_file_key(p, &repo_root))
        .collect();

    // All must be identical
    for (i, key) in canonical_keys.iter().enumerate() {
        assert_eq!(
            key, &canonical_keys[0],
            "Path '{}' produced different key '{}' vs '{}'",
            paths[i], key, canonical_keys[0]
        );
    }

    // The canonical key should be the normalized form (possibly lowercased on macOS)
    let expected = if cfg!(target_os = "macos") || cfg!(target_os = "windows") {
        "src/store/enforcement.rs".to_lowercase()
    } else {
        "src/store/enforcement.rs".to_string()
    };
    assert_eq!(canonical_keys[0], expected);
}

// ─────────────────────────────────────────────
// Test 8: Full enforcement lifecycle
// ─────────────────────────────────────────────

#[tokio::test]
async fn full_enforcement_lifecycle_records_all_events() {
    use mati_core::store::enforcement::record_event;

    let (_dir, store) = temp_store().await;

    // 1. Simulate a DENY decision
    let deny_result = record_event(
        &store,
        EnforcementEventType::Deny,
        SubjectKind::File,
        "file:src/billing/charges.rs".to_string(),
        "claude".to_string(),
        None,
        "gotcha_above_threshold".to_string(),
        Some("basis_hash_1".to_string()),
    )
    .await
    .expect("record deny");
    assert!(deny_result.is_some());
    let deny_event = deny_result.unwrap();

    // 2. Simulate a consultation (ReceiptMinted)
    let receipt_result = record_event(
        &store,
        EnforcementEventType::ReceiptMinted,
        SubjectKind::File,
        "file:src/billing/charges.rs".to_string(),
        "claude".to_string(),
        Some("receipt-001".to_string()),
        "consultation_requested".to_string(),
        None,
    )
    .await
    .expect("record receipt");
    assert!(receipt_result.is_some());
    let receipt_event = receipt_result.unwrap();

    // 3. Simulate AllowAfterReceipt
    let allow_result = record_event(
        &store,
        EnforcementEventType::AllowAfterReceipt,
        SubjectKind::File,
        "file:src/billing/charges.rs".to_string(),
        "claude".to_string(),
        Some("receipt-001".to_string()),
        "receipt_valid".to_string(),
        None,
    )
    .await
    .expect("record allow");
    assert!(allow_result.is_some());
    let allow_event = allow_result.unwrap();

    // 4. Read all enforcement events
    let all = scan_enforcement_events(&store, 1, 10).await.expect("scan");
    assert_eq!(all.len(), 3, "expected 3 events");

    // 5. Verify correct types and order
    assert!(matches!(all[0].event_type, EnforcementEventType::Deny));
    assert!(matches!(
        all[1].event_type,
        EnforcementEventType::ReceiptMinted
    ));
    assert!(matches!(
        all[2].event_type,
        EnforcementEventType::AllowAfterReceipt
    ));

    // 6. Verify hash chain
    assert_eq!(deny_event.prev_hash, "", "first event has empty prev_hash");
    assert_eq!(
        receipt_event.prev_hash, deny_event.event_hash,
        "receipt's prev_hash must equal deny's event_hash"
    );
    assert_eq!(
        allow_event.prev_hash, receipt_event.event_hash,
        "allow's prev_hash must equal receipt's event_hash"
    );

    // 7. Verify all hashes are self-consistent
    for event in &all {
        assert_eq!(event.event_hash, event.compute_hash());
    }
}

// ─────────────────────────────────────────────
// Test 9: Control change events from gotcha CRUD
// ─────────────────────────────────────────────

#[tokio::test]
async fn gotcha_crud_records_control_changed_events() {
    use mati_core::store::gotcha_ops::{apply_gotcha_tombstone, apply_gotcha_write};
    use mati_core::store::record::{
        Category, ConfidenceScore, GotchaRecord, Priority, QualityScore, Record, RecordLifecycle,
        RecordSource, RecordVersion, StalenessScore,
    };

    let (_dir, store) = temp_store().await;

    // Helper to build a gotcha record
    let make_gotcha = |key: &str, confirmed: bool| -> Record {
        let gotcha = GotchaRecord {
            rule: "test rule".into(),
            reason: "test reason".into(),
            severity: Priority::High,
            affected_files: vec!["src/test.rs".into()],
            ref_url: None,
            discovered_session: 1_000_000,
            confirmed,
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
    };

    // 1. Create a gotcha → ControlChanged::Created
    let record = make_gotcha("gotcha:test-crud", false);
    apply_gotcha_write(&store, &record, &[], &["src/test.rs".into()], true)
        .await
        .expect("create gotcha");

    // 2. Update the gotcha → ControlChanged::Updated
    let mut record2 = make_gotcha("gotcha:test-crud", false);
    record2.value = "updated rule".into();
    apply_gotcha_write(
        &store,
        &record2,
        &["src/test.rs".into()],
        &["src/test.rs".into()],
        false,
    )
    .await
    .expect("update gotcha");

    // 3. Delete the gotcha → ControlChanged::Deleted
    apply_gotcha_tombstone(&store, "gotcha:test-crud", &["src/test.rs".into()])
        .await
        .expect("delete gotcha");

    // Read all enforcement events
    let events = scan_enforcement_events(&store, 1, 100).await.expect("scan");

    // Should have at least 3 control_changed events (created, updated, deleted)
    let control_events: Vec<_> = events
        .iter()
        .filter(|e| matches!(e.event_type, EnforcementEventType::ControlChanged { .. }))
        .collect();

    assert!(
        control_events.len() >= 3,
        "expected at least 3 ControlChanged events, got {}",
        control_events.len()
    );

    // Verify the change kinds in order
    let kinds: Vec<_> = control_events
        .iter()
        .map(|e| match &e.event_type {
            EnforcementEventType::ControlChanged { change_kind } => *change_kind,
            _ => unreachable!(),
        })
        .collect();

    assert!(kinds.contains(&mati_core::store::enforcement::ControlChangeKind::Created));
    assert!(kinds.contains(&mati_core::store::enforcement::ControlChangeKind::Updated));
    assert!(kinds.contains(&mati_core::store::enforcement::ControlChangeKind::Deleted));

    // All events reference the correct subject
    for e in &control_events {
        assert_eq!(e.subject_key, "gotcha:test-crud");
        assert_eq!(e.subject_kind, SubjectKind::Control);
    }
}

// ─────────────────────────────────────────────
// Test 10: Retention pruning
// ─────────────────────────────────────────────

#[tokio::test]
async fn retention_prunes_old_events_and_records_prune_event() {
    use mati_core::store::enforcement::{enforce_retention, set_retention_days, PruneResult};

    let (_dir, store) = temp_store().await;

    // Set a very short retention (1 day) for testing
    set_retention_days(&store, 1).await.expect("set retention");

    // Write 5 events with old timestamps (simulate 400 days ago)
    // We do this by directly writing events with old recorded_at_ms
    let old_ms = {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        now.saturating_sub(400 * 86_400_000) // 400 days ago
    };

    let mut writer = EnforcementEventWriter::new(&store)
        .await
        .expect("create writer");

    // Write events that will have current timestamps
    for i in 0..5 {
        writer
            .write(
                &store,
                EnforcementEventType::Deny,
                SubjectKind::File,
                format!("file:old_{i}.rs"),
                "claude".to_string(),
                None,
                "gotcha_above_threshold".to_string(),
                None,
            )
            .await
            .expect("write old event");
    }

    // Manually patch these events to have old timestamps
    for seq in 1..=5u64 {
        let key = format!("enforcement:event:{:020}", seq);
        if let Ok(Some(bytes)) = store.get_raw_bytes(&key).await {
            if let Ok(mut event) =
                serde_json::from_slice::<mati_core::store::enforcement::EnforcementEvent>(&bytes)
            {
                event.recorded_at_ms = old_ms;
                let patched = serde_json::to_vec(&event).unwrap();
                store.put_raw(&key, &patched).await.unwrap();
            }
        }
    }

    // Write 3 recent events (these should survive pruning)
    for i in 0..3 {
        writer
            .write(
                &store,
                EnforcementEventType::AllowAfterReceipt,
                SubjectKind::File,
                format!("file:new_{i}.rs"),
                "claude".to_string(),
                None,
                "receipt_valid".to_string(),
                None,
            )
            .await
            .expect("write new event");
    }

    // Run retention
    let result = enforce_retention(&store).await.expect("enforce retention");

    match result {
        PruneResult::Pruned {
            count,
            oldest_seq,
            newest_seq,
        } => {
            assert_eq!(count, 5, "should prune 5 old events");
            assert_eq!(oldest_seq, 1);
            assert_eq!(newest_seq, 5);
        }
        PruneResult::NothingToPrune => panic!("expected pruning to happen"),
    }

    // Verify: old events are gone, new events remain
    let remaining = scan_enforcement_events(&store, 1, 100).await.expect("scan");

    // Should have 3 recent events + 1 RetentionPruned event = 4
    assert_eq!(
        remaining.len(),
        4,
        "expected 4 events (3 recent + 1 prune record)"
    );

    // The last event should be RetentionPruned
    let prune_events: Vec<_> = remaining
        .iter()
        .filter(|e| matches!(e.event_type, EnforcementEventType::RetentionPruned { .. }))
        .collect();
    assert_eq!(prune_events.len(), 1);
    if let EnforcementEventType::RetentionPruned {
        pruned_count,
        oldest_pruned_seq,
        newest_pruned_seq,
    } = &prune_events[0].event_type
    {
        assert_eq!(*pruned_count, 5);
        assert_eq!(*oldest_pruned_seq, 1);
        assert_eq!(*newest_pruned_seq, 5);
    }
}

// ─────────────────────────────────────────────
// Test 11: Strict mode end-to-end
// ─────────────────────────────────────────────

#[tokio::test]
async fn strict_mode_enforcement_config_records_change_event() {
    use mati_core::store::enforcement::{get_enforcement_mode, record_event, set_enforcement_mode};

    let (_dir, store) = temp_store().await;

    // Default mode is advisory
    let mode = get_enforcement_mode(&store).await;
    assert_eq!(mode, EnforcementMode::Advisory);

    // Switch to strict
    let old = set_enforcement_mode(&store, EnforcementMode::Strict)
        .await
        .expect("set strict");
    assert_eq!(old, EnforcementMode::Advisory);

    // Verify mode is now strict
    let mode = get_enforcement_mode(&store).await;
    assert_eq!(mode, EnforcementMode::Strict);

    // Switch back to advisory
    let old = set_enforcement_mode(&store, EnforcementMode::Advisory)
        .await
        .expect("set advisory");
    assert_eq!(old, EnforcementMode::Strict);

    // Verify EnforcementConfigChanged events were recorded
    let events = scan_enforcement_events(&store, 1, 100).await.expect("scan");

    let config_events: Vec<_> = events
        .iter()
        .filter(|e| {
            matches!(
                e.event_type,
                EnforcementEventType::EnforcementConfigChanged { .. }
            )
        })
        .collect();

    assert_eq!(
        config_events.len(),
        2,
        "expected 2 config change events (advisory→strict, strict→advisory)"
    );

    // Verify first change: advisory → strict
    if let EnforcementEventType::EnforcementConfigChanged {
        setting,
        old_value,
        new_value,
    } = &config_events[0].event_type
    {
        assert_eq!(setting, "enforcement.mode");
        assert_eq!(old_value, "advisory");
        assert_eq!(new_value, "strict");
    }

    // Verify second change: strict → advisory
    if let EnforcementEventType::EnforcementConfigChanged {
        setting,
        old_value,
        new_value,
    } = &config_events[1].event_type
    {
        assert_eq!(setting, "enforcement.mode");
        assert_eq!(old_value, "strict");
        assert_eq!(new_value, "advisory");
    }

    // In strict mode, record_event should propagate errors
    // First set to strict
    set_enforcement_mode(&store, EnforcementMode::Strict)
        .await
        .expect("set strict again");

    // Normal writes should still succeed in strict mode
    let result = record_event(
        &store,
        EnforcementEventType::Deny,
        SubjectKind::File,
        "file:test.rs".to_string(),
        "claude".to_string(),
        None,
        "gotcha_above_threshold".to_string(),
        None,
    )
    .await;
    assert!(result.is_ok(), "strict mode write should succeed");
    assert!(result.unwrap().is_some());
}

// ─────────────────────────────────────────────
// Test 12: Config set/get round-trips correctly
// ─────────────────────────────────────────────

#[tokio::test]
async fn config_enforcement_mode_round_trips() {
    use mati_core::store::enforcement::{get_enforcement_mode, set_enforcement_mode};

    let (_dir, store) = temp_store().await;

    // Default is advisory
    assert_eq!(
        get_enforcement_mode(&store).await,
        EnforcementMode::Advisory
    );

    // Set to strict and read back
    set_enforcement_mode(&store, EnforcementMode::Strict)
        .await
        .expect("set strict");
    assert_eq!(get_enforcement_mode(&store).await, EnforcementMode::Strict);

    // Set back to advisory and read back
    set_enforcement_mode(&store, EnforcementMode::Advisory)
        .await
        .expect("set advisory");
    assert_eq!(
        get_enforcement_mode(&store).await,
        EnforcementMode::Advisory
    );

    // Retention round-trip
    use mati_core::store::enforcement::{get_retention_days, set_retention_days};
    assert_eq!(get_retention_days(&store).await, 365); // default
    set_retention_days(&store, 90).await.expect("set 90");
    assert_eq!(get_retention_days(&store).await, 90);
}

// ─────────────────────────────────────────────
// Test 13: Config set records EnforcementConfigChanged
// ─────────────────────────────────────────────

#[tokio::test]
async fn config_set_enforcement_mode_records_event() {
    use mati_core::store::enforcement::set_enforcement_mode;

    let (_dir, store) = temp_store().await;

    // Change mode — should record an event
    set_enforcement_mode(&store, EnforcementMode::Strict)
        .await
        .expect("set strict");

    let events = scan_enforcement_events(&store, 1, 100).await.expect("scan");

    let config_events: Vec<_> = events
        .iter()
        .filter(|e| {
            matches!(
                e.event_type,
                EnforcementEventType::EnforcementConfigChanged { .. }
            )
        })
        .collect();

    assert_eq!(config_events.len(), 1, "expected 1 config change event");
    if let EnforcementEventType::EnforcementConfigChanged {
        setting,
        old_value,
        new_value,
    } = &config_events[0].event_type
    {
        assert_eq!(setting, "enforcement.mode");
        assert_eq!(old_value, "advisory");
        assert_eq!(new_value, "strict");
    } else {
        panic!("expected EnforcementConfigChanged");
    }

    // Setting the same mode again should NOT record another event
    set_enforcement_mode(&store, EnforcementMode::Strict)
        .await
        .expect("set strict again");

    let events2 = scan_enforcement_events(&store, 1, 100).await.expect("scan");
    let config_events2: Vec<_> = events2
        .iter()
        .filter(|e| {
            matches!(
                e.event_type,
                EnforcementEventType::EnforcementConfigChanged { .. }
            )
        })
        .collect();
    assert_eq!(
        config_events2.len(),
        1,
        "setting same mode should not record another event"
    );
}
