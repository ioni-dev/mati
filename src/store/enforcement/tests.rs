use super::*;

fn sample_policy() -> crate::store::PolicyRecord {
    crate::store::PolicyRecord {
        name: "Mode collision test".into(),
        rule: "Consult the schema first.".into(),
        reason: "Schemas drift because production changes independently.".into(),
        scope: "repo".into(),
        mode: crate::store::PolicyMode::Block,
        trigger: crate::store::PolicyTrigger {
            tool: Some("db_client".into()),
            ..Default::default()
        },
        requires: crate::store::PolicyRequires {
            key: "schema:orders".into(),
            via: vec![crate::store::ReceiptSource::MemGet],
            freshness: crate::store::PolicyFreshness {
                ttl_secs: 900,
                fingerprint: false,
            },
        },
        stage: crate::store::PolicyStage::Enforce,
        severity: crate::store::Priority::High,
        created_by: "developer".into(),
    }
}

#[tokio::test]
async fn policy_mode_reads_new_key() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).await.unwrap();
    store.put_raw(POLICY_MODE_KEY, b"advisory").await.unwrap();
    assert_eq!(get_policy_mode(&store).await, EnforcementMode::Advisory);
}

/// The posture key must stay out of the `policy:` record namespace, or
/// writing it destroys a policy slugged `mode` and vice versa.
#[tokio::test]
async fn policy_mode_does_not_collide_with_a_policy_slugged_mode() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).await.unwrap();
    crate::store::policy_ops::create(&store, "policy:mode", &sample_policy())
        .await
        .unwrap();
    set_policy_mode(&store, EnforcementMode::Advisory)
        .await
        .unwrap();
    let records = store.scan_prefix("policy:").await.unwrap();
    assert_eq!(records.len(), 1, "the policy record must survive");
    assert_eq!(records[0].key, "policy:mode");
    assert_eq!(get_policy_mode(&store).await, EnforcementMode::Advisory);
}

#[tokio::test]
async fn policy_mode_unrecognized_value_is_strict() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).await.unwrap();
    store.put_raw(POLICY_MODE_KEY, b"not-a-mode").await.unwrap();
    assert_eq!(get_policy_mode(&store).await, EnforcementMode::Strict);
}

/// Construct a deterministic event for hash testing.
fn frozen_test_event() -> EnforcementEvent {
    EnforcementEvent {
        event_id: "01900000-0000-7000-8000-000000000001".to_string(),
        schema_version: 1,
        seq_no: 1,
        recorded_at_ms: 1700000000000,
        event_type: EnforcementEventType::Deny,
        event_hash: String::new(),
        prev_hash: String::new(),
        installation_id: "test-install-id".to_string(),
        actor_local: Some(ActorLocal {
            username: "testuser".to_string(),
            uid: Some(1000),
            verified: false,
        }),
        agent_type: "claude".to_string(),
        subject_kind: SubjectKind::File,
        subject_key: "file:src/billing/charges.rs".to_string(),
        canonical_subject_hash: Some("abc123".to_string()),
        receipt_id: None,
        decision_reason_code: "gotcha_above_threshold".to_string(),
        decision_basis_hash: Some("def456".to_string()),
        agent_session: None,
    }
}

#[test]
fn canonical_hash_is_deterministic_and_frozen() {
    let event = frozen_test_event();
    let hash = event.compute_hash();

    // This hash is frozen. If this test fails, either the canonical
    // serialization changed (which breaks all existing hash chains)
    // or the hash algorithm changed. Neither is acceptable without
    // incrementing SCHEMA_VERSION.
    assert_eq!(
        hash,
        "e8a42cb3c1c4dde12f807f46678c5d4393466a831007540a85ff84a003203e37"
    );

    // Verify determinism — same input always produces same hash.
    assert_eq!(hash, event.compute_hash());
    assert_eq!(hash, event.compute_hash());
}

#[test]
fn hash_changes_when_field_changes() {
    let mut event = frozen_test_event();
    let hash1 = event.compute_hash();

    event.seq_no = 2;
    let hash2 = event.compute_hash();

    assert_ne!(hash1, hash2, "changing seq_no must change the hash");
}

/// Build an event of a given type from the frozen template.
fn event_of(event_type: EnforcementEventType) -> EnforcementEvent {
    EnforcementEvent {
        event_type,
        ..frozen_test_event()
    }
}

/// Build a valid, hash-linked chain of `n` events (seq 1..=n).
fn chained(n: u64) -> Vec<EnforcementEvent> {
    let mut out = Vec::new();
    let mut prev = String::new();
    for i in 1..=n {
        let mut e = EnforcementEvent {
            seq_no: i,
            prev_hash: prev.clone(),
            event_hash: String::new(),
            ..frozen_test_event()
        };
        e.event_hash = e.compute_hash();
        prev = e.event_hash.clone();
        out.push(e);
    }
    out
}

#[test]
fn verify_chain_accepts_intact_chain() {
    let events = chained(4);
    let v = verify_chain(&events);
    assert!(v.is_valid());
    assert_eq!(v.checked, 4);
    assert_eq!(v.tampered_events, 0);
    assert_eq!(v.linkage_breaks, 0);
    assert_eq!(v.unknown_schema, 0);
}

#[test]
fn verify_chain_is_order_independent() {
    let mut events = chained(4);
    events.reverse();
    assert!(verify_chain(&events).is_valid());
}

#[test]
fn verify_chain_detects_content_tamper_without_rehash() {
    // The exact attack the linkage-only verifier missed: alter the body but
    // leave the stored event_hash untouched, so the chain still links.
    let mut events = chained(3);
    events[1].subject_key = "file:src/evil.rs".to_string();
    let v = verify_chain(&events);
    assert_eq!(v.tampered_events, 1);
    assert_eq!(v.linkage_breaks, 0);
    assert!(!v.is_valid());
}

#[test]
fn verify_chain_detects_linkage_break_from_deleted_event() {
    let mut events = chained(3);
    events.remove(1); // drop the middle event (seq 2)
    let v = verify_chain(&events);
    assert_eq!(v.linkage_breaks, 1);
    assert_eq!(v.tampered_events, 0);
    assert!(!v.is_valid());
}

#[test]
fn verify_chain_reports_a_skipped_event_as_unknown_schema_not_tampering() {
    // Same event vector as the deleted-event case above — a gap at seq 2. The
    // only difference is that the scan reported seq 2 as JSON it could not
    // parse, which is what a newer writer's event looks like to this binary.
    // That must not read as tampering in a signed audit.
    let mut events = chained(3);
    events.remove(1);
    let v = verify_chain_with_skips(&events, &[2]);
    assert_eq!(v.linkage_breaks, 0, "version skew is not a linkage break");
    assert_eq!(v.unknown_schema, 1);
    assert_eq!(v.tampered_events, 0);
    assert_eq!(v.breaks.len(), 1);
    assert_eq!(v.breaks[0].kind, ChainBreakKind::UnknownSchema);
    // Still not "valid": unverifiable is not the same as verified.
    assert!(!v.is_valid());
}

#[test]
fn verify_chain_skips_outside_the_gap_do_not_excuse_a_deletion() {
    // A skip must explain *this* gap. One at an unrelated seq leaves the
    // deletion classified as a linkage break.
    let mut events = chained(3);
    events.remove(1);
    let v = verify_chain_with_skips(&events, &[99]);
    assert_eq!(v.linkage_breaks, 1);
    assert_eq!(v.unknown_schema, 0);
    assert!(!v.is_valid());
}

#[test]
fn verify_chain_ignores_retention_pruned_prefix() {
    let mut events = chained(3);
    events.remove(0); // prune the earliest event (seq 1)
    let v = verify_chain(&events);
    assert!(
        v.is_valid(),
        "pruned prefix must not be a false linkage break"
    );
    assert_eq!(v.linkage_breaks, 0);
    assert_eq!(v.tampered_events, 0);
}

#[test]
fn verify_chain_flags_unknown_schema_version() {
    let mut e = frozen_test_event();
    e.schema_version = SCHEMA_VERSION + 1;
    e.event_hash = e.compute_hash();
    let v = verify_chain(&[e]);
    assert_eq!(v.unknown_schema, 1);
    assert_eq!(v.checked, 0);
    assert!(!v.is_valid());
}

#[test]
fn verify_chain_verifies_v2_events_clean() {
    let mut e = frozen_test_event();
    e.schema_version = 2;
    e.agent_session = Some("session-xyz".to_string());
    e.event_hash = e.compute_hash();
    let v = verify_chain(&[e]);
    assert!(v.is_valid());
    assert_eq!(v.checked, 1);
}

#[test]
fn verify_chain_empty_is_valid() {
    let v = verify_chain(&[]);
    assert!(v.is_valid());
    assert_eq!(v.checked, 0);
}

#[test]
fn verify_chain_records_tampered_break_location() {
    let mut events = chained(3);
    events[2].subject_key = "file:src/evil.rs".to_string();
    let v = verify_chain(&events);
    assert_eq!(v.breaks.len(), 1);
    let b = &v.breaks[0];
    assert_eq!(b.kind, ChainBreakKind::Tampered);
    assert_eq!(b.seq_no, 3);
    assert!(b.prev_seq_no.is_none());
}

#[test]
fn verify_chain_records_linkage_break_with_predecessor() {
    let mut events = chained(3);
    events.remove(1); // delete seq 2; seq 3 now directly follows seq 1
    let v = verify_chain(&events);
    assert_eq!(v.breaks.len(), 1);
    let b = &v.breaks[0];
    assert_eq!(b.kind, ChainBreakKind::Linkage);
    assert_eq!(b.seq_no, 3);
    assert_eq!(b.prev_seq_no, Some(1));
}

/// Regression: concurrent `record_event` calls must produce an intact,
/// collision-free chain. Before the per-store serialized writer, each call
/// built a fresh writer that independently captured `prev_hash`/seq, so racing
/// writers shared a `prev_hash` (linkage break) or collided on a seq (event
/// loss). Multi-threaded + 64 writers reliably exercises the race.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_record_event_keeps_chain_intact() {
    use std::sync::Arc;
    let dir = tempfile::TempDir::new().unwrap();
    let store = Arc::new(Store::open(dir.path()).await.unwrap());

    let n: u64 = 64;
    let mut handles = Vec::new();
    for i in 0..n {
        let s = store.clone();
        handles.push(tokio::spawn(async move {
            record_event(
                &s,
                EnforcementEventType::Deny,
                SubjectKind::File,
                format!("file:src/f{i}.rs"),
                "claude".to_string(),
                None,
                "gotcha_above_threshold".to_string(),
                None,
            )
            .await
            .expect("record_event")
        }));
    }
    for h in handles {
        h.await.expect("task join");
    }

    let events = scan_enforcement_events(&store, 0, u64::MAX).await.unwrap();
    // No seq collisions → every concurrent write persisted as a distinct event.
    assert_eq!(
        events.len() as u64,
        n,
        "all {n} concurrent writes must persist (no seq collision / event loss)"
    );
    // No prev_hash races → the chain verifies intact.
    let v = verify_chain(&events);
    assert!(
        v.is_valid(),
        "concurrent writes must yield an intact chain, got {v:?}"
    );
}

#[test]
fn aggregate_event_counts_breaks_out_control_lifecycle() {
    use EnforcementEventType::*;
    let events = vec![
        event_of(Deny),
        event_of(Deny),
        event_of(AllowAfterReceipt),
        event_of(ReceiptMinted),
        event_of(BypassDetected),
        event_of(ControlChanged {
            change_kind: ControlChangeKind::Created,
        }),
        event_of(ControlChanged {
            change_kind: ControlChangeKind::Confirmed,
        }),
        event_of(ControlChanged {
            change_kind: ControlChangeKind::Confirmed,
        }),
        event_of(ControlChanged {
            change_kind: ControlChangeKind::Updated,
        }),
        event_of(ControlChanged {
            change_kind: ControlChangeKind::Deleted,
        }),
    ];

    let counts = aggregate_event_counts(&events);

    assert_eq!(counts.total, 10);
    assert_eq!(counts.denials, 2);
    assert_eq!(counts.allowed_after_receipt, 1);
    assert_eq!(counts.receipts_minted, 1);
    assert_eq!(counts.bypasses, 1);

    // Lifecycle breakout.
    assert_eq!(counts.controls_created, 1);
    assert_eq!(counts.controls_confirmed, 2);
    assert_eq!(counts.controls_updated, 1);
    assert_eq!(counts.controls_removed, 1);

    // The total must equal the sum of the four lifecycle counters.
    assert_eq!(counts.controls_changed, 5);
    assert_eq!(
        counts.controls_changed,
        counts.controls_created
            + counts.controls_confirmed
            + counts.controls_updated
            + counts.controls_removed
    );
}

#[test]
fn aggregate_event_counts_empty_is_all_zero() {
    let counts = aggregate_event_counts(&[]);
    assert_eq!(counts.total, 0);
    assert_eq!(counts.controls_changed, 0);
    assert_eq!(counts.denials, 0);
}

/// `receipt_id`, `decision_basis_hash` and `agent_session` are all already
/// part of the v2 canonical layout, so filling them in where they used to be
/// null needs no `SCHEMA_VERSION` bump: an event that predates the fix keeps
/// hashing under the layout it was written with, and both eras verify in one
/// chain.
#[test]
fn populating_the_optional_fields_keeps_a_mixed_era_chain_valid() {
    assert_eq!(SCHEMA_VERSION, 2, "these fields live in the v2 layout");

    // Pre-change shape: v2 event with every optional attribution left null.
    let mut before = EnforcementEvent {
        schema_version: 2,
        seq_no: 1,
        receipt_id: None,
        decision_basis_hash: None,
        agent_session: None,
        ..frozen_test_event()
    };
    before.event_hash = before.compute_hash();

    // Post-change shape: same layout, real values.
    let mut after = EnforcementEvent {
        schema_version: 2,
        seq_no: 2,
        prev_hash: before.event_hash.clone(),
        receipt_id: Some("0199aaaa-0000-7000-8000-00000000000f".to_string()),
        decision_basis_hash: Some(compute_decision_basis_hash(&[(
            "gotcha:x",
            &serde_json::json!({"value": "rule", "confidence": {"value": 0.8}}),
        )])),
        agent_session: Some("sess-1".to_string()),
        ..frozen_test_event()
    };
    after.event_hash = after.compute_hash();

    let result = verify_chain(&[before.clone(), after]);
    assert_eq!(result.checked, 2);
    assert_eq!(result.tampered_events, 0);
    assert_eq!(result.linkage_breaks, 0);
    assert!(result.is_valid());

    // The pre-change event still hashes to what it was written with.
    assert_eq!(before.event_hash, before.compute_hash());
}

/// Callers hold gotchas in a `HashMap`, whose order varies per process. An
/// order-dependent digest would make two decisions on identical state prove
/// different bases.
#[test]
fn decision_basis_hash_ignores_gotcha_order() {
    let a = serde_json::json!({"value": "rule a", "confidence": {"value": 0.7}});
    let b = serde_json::json!({"value": "rule b", "confidence": {"value": 0.9}});
    assert_eq!(
        compute_decision_basis_hash(&[("gotcha:a", &a), ("gotcha:b", &b)]),
        compute_decision_basis_hash(&[("gotcha:b", &b), ("gotcha:a", &a)])
    );
    assert_ne!(
        compute_decision_basis_hash(&[("gotcha:a", &a)]),
        compute_decision_basis_hash(&[("gotcha:a", &b)]),
        "a changed rule must change the basis"
    );
}

/// Build an event with explicit type/subject/time/session over the template.
fn ev(
    event_type: EnforcementEventType,
    subject: &str,
    at_ms: u64,
    session: Option<&str>,
) -> EnforcementEvent {
    EnforcementEvent {
        event_type,
        subject_key: subject.to_string(),
        recorded_at_ms: at_ms,
        agent_session: session.map(str::to_string),
        ..frozen_test_event()
    }
}

#[test]
fn derive_metrics_blocks_per_session_and_time_to_consult() {
    use EnforcementEventType::*;
    let events = vec![
        // sessA blocked on x@1000, consulted x@1500 (delta 500)
        ev(Deny, "file:x.rs", 1000, Some("sessA")),
        ev(ReceiptMinted, "file:x.rs", 1500, None),
        // sessB blocked on y@2000, consulted y@2300 (delta 300)
        ev(Deny, "file:y.rs", 2000, Some("sessB")),
        ev(ReceiptMinted, "file:y.rs", 2300, None),
        // sessA blocked again on y@3000 — no later receipt on y → no pair
        ev(Deny, "file:y.rs", 3000, Some("sessA")),
    ];

    let m = derive_enforcement_metrics(&events);

    assert_eq!(m.blocked_sessions, 2, "distinct sessions with a deny");
    assert_eq!(m.attributed_denials, 3);
    assert_eq!(m.blocks_per_session, Some(1.5)); // 3 denials / 2 sessions
    assert_eq!(m.consult_pairs, 2); // only denies with a later same-subject receipt
    assert_eq!(m.median_time_to_consult_ms, Some(400)); // median([300,500])
}

#[test]
fn derive_metrics_no_sessioned_denials_yields_none() {
    use EnforcementEventType::*;
    // Denies without a session id (e.g. pre-v2 events) cannot be attributed.
    let events = vec![
        ev(Deny, "file:x.rs", 1000, None),
        ev(ReceiptMinted, "file:x.rs", 1200, None),
    ];
    let m = derive_enforcement_metrics(&events);
    assert_eq!(m.blocked_sessions, 0);
    assert_eq!(m.attributed_denials, 0);
    assert_eq!(m.blocks_per_session, None);
    // Time-to-consult still pairs by subject regardless of session.
    assert_eq!(m.consult_pairs, 1);
    assert_eq!(m.median_time_to_consult_ms, Some(200));
}

#[test]
fn derive_metrics_excludes_consults_beyond_window() {
    use EnforcementEventType::*;
    let window_ms = crate::store::session::CONSULTED_RECENT_TTL_SECS * 1_000;
    let events = vec![
        // In-window consult (delta == window boundary, inclusive) → counts.
        ev(Deny, "file:a.rs", 0, Some("s1")),
        ev(ReceiptMinted, "file:a.rs", window_ms, None),
        // Out-of-window consult (1ms past) → excluded (a separate interaction).
        ev(Deny, "file:b.rs", 0, Some("s2")),
        ev(ReceiptMinted, "file:b.rs", window_ms + 1, None),
    ];
    let m = derive_enforcement_metrics(&events);
    assert_eq!(m.consult_pairs, 1, "only the in-window pair counts");
    assert_eq!(m.median_time_to_consult_ms, Some(window_ms));
}

/// "One consultation is one consultation."
///
/// `ReceiptMinted` has three emitters (`mcp::handlers::handle_mem_get`,
/// `Command::ConsultationHit`, `store::session::log_hit`) and on a
/// fully-installed Claude Code setup two of them fire for a single
/// `mem_get` — measured, not assumed: driving the real dispatch path for
/// one `mem_get` plus its `post-memget.sh` hook writes two `ReceiptMinted`
/// events 8–100ms apart, both on the same `subject_key`, both with
/// `receipt_id: None`, one session-attributed and one not. `mati stats`
/// reported that raw count as "consulted", so every consultation counted
/// twice.
///
/// The emitters stay: each is the only record when the others' path is not
/// installed, and only the hook path carries a session id. The log is
/// append-only and hash-chained, so the duplicates are already in every
/// existing store — the correction can only live at read time. These tests
/// are what keeps it there.
///
/// The end-to-end companion — the same property against the real
/// emitters rather than hand-built events — is
/// `mcp::dispatch_v2::tests::one_mem_get_counts_as_one_consultation`.
mod one_consultation_counts_once {
    use super::*;

    /// The exact sequence measured from the real dispatch path: the MCP
    /// handler's unattributed receipt, then the PostToolUse hook's
    /// session-attributed one 91ms later, same subject.
    fn one_mem_get_on_a_full_install(at_ms: u64, subject: &str) -> Vec<EnforcementEvent> {
        vec![
            ev(EnforcementEventType::ReceiptMinted, subject, at_ms, None),
            ev(
                EnforcementEventType::ReceiptMinted,
                subject,
                at_ms + 91,
                Some("sess-1"),
            ),
        ]
    }

    /// The anchor. If this starts reporting 2, the metric is broken again.
    #[test]
    fn one_mem_get_counts_once_however_many_events_it_emitted() {
        let events = one_mem_get_on_a_full_install(1_000, "file:src/a.rs");
        let counts = aggregate_event_counts(&events);

        assert_eq!(
            counts.receipts_minted, 2,
            "the raw event count must stay raw — the audit log records \
                 every emitter, and mati-cloud reads those rows"
        );
        assert_eq!(
            counts.consultations, 1,
            "INFLATED CONSULTATION COUNT: one mem_get emitted \
                 {} ReceiptMinted events and was counted as {} consultations. \
                 `mati stats` reports `consultations` as \"consulted\"; it must \
                 count consultations, not events.",
            counts.receipts_minted, counts.consultations
        );
    }

    /// All three emitters at once — the worst case the log can hold for a
    /// single action.
    #[test]
    fn three_emitters_on_one_action_still_count_once() {
        let mut events = one_mem_get_on_a_full_install(1_000, "file:src/a.rs");
        // `log_hit`, e.g. a `mati explain` on the same file in the same beat.
        events.push(ev(
            EnforcementEventType::ReceiptMinted,
            "file:src/a.rs",
            1_150,
            None,
        ));
        let counts = aggregate_event_counts(&events);
        assert_eq!(counts.receipts_minted, 3);
        assert_eq!(counts.consultations, 1);
    }

    /// De-duplication must not swallow real work: two consultations far
    /// apart are two consultations, even on the same file.
    #[test]
    fn consultations_outside_the_window_stay_separate() {
        let mut events = one_mem_get_on_a_full_install(1_000, "file:src/a.rs");
        events.extend(one_mem_get_on_a_full_install(
            1_000 + CONSULTATION_COALESCE_MS * 10,
            "file:src/a.rs",
        ));
        let counts = aggregate_event_counts(&events);
        assert_eq!(counts.receipts_minted, 4);
        assert_eq!(
            counts.consultations, 2,
            "two mem_gets ten windows apart are two consultations"
        );
    }

    /// Different files are never the same consultation, however close.
    #[test]
    fn different_subjects_never_coalesce() {
        let mut events = one_mem_get_on_a_full_install(1_000, "file:src/a.rs");
        events.extend(one_mem_get_on_a_full_install(1_000, "file:src/b.rs"));
        let counts = aggregate_event_counts(&events);
        assert_eq!(counts.receipts_minted, 4);
        assert_eq!(counts.consultations, 2);
    }

    /// The window boundary is inclusive, and one millisecond past it is a
    /// new consultation. Pins the comparison direction.
    #[test]
    fn the_window_boundary_is_inclusive() {
        let at = |delta: u64| {
            vec![
                ev(EnforcementEventType::ReceiptMinted, "file:a.rs", 0, None),
                ev(
                    EnforcementEventType::ReceiptMinted,
                    "file:a.rs",
                    delta,
                    None,
                ),
            ]
        };
        assert_eq!(count_consultations(&at(CONSULTATION_COALESCE_MS)), 1);
        assert_eq!(count_consultations(&at(CONSULTATION_COALESCE_MS + 1)), 2);
    }

    /// The run is anchored to its first event, not chained to the previous
    /// one. A drip of receipts every `window - 1` ms would otherwise
    /// collapse into a single unbounded "consultation" and hide real usage.
    #[test]
    fn a_steady_drip_cannot_collapse_into_one_consultation() {
        let step = CONSULTATION_COALESCE_MS - 1;
        let events: Vec<EnforcementEvent> = (0..10)
            .map(|i| {
                ev(
                    EnforcementEventType::ReceiptMinted,
                    "file:a.rs",
                    i * step,
                    None,
                )
            })
            .collect();
        // Each anchor covers itself plus the next event (2 * step > window
        // for step = window - 1), so 10 events land in 5 runs.
        assert_eq!(count_consultations(&events), 5);
    }

    /// Out-of-order arrival must not change the answer: events are sorted
    /// per subject before coalescing, and `scan_enforcement_events` orders
    /// by seq_no, which is allocation order, not wall-clock order.
    #[test]
    fn coalescing_is_independent_of_event_order() {
        let mut forward = one_mem_get_on_a_full_install(1_000, "file:src/a.rs");
        forward.extend(one_mem_get_on_a_full_install(50_000, "file:src/a.rs"));
        let mut reversed = forward.clone();
        reversed.reverse();
        assert_eq!(
            count_consultations(&forward),
            count_consultations(&reversed)
        );
        assert_eq!(count_consultations(&forward), 2);
    }

    /// The two bounds that must hold for any input: de-duplication can only
    /// remove, never invent, and it must not erase a subject entirely.
    #[test]
    fn consultations_are_bounded_by_receipt_events_and_by_subject_count() {
        use std::collections::BTreeSet;
        let subjects = ["file:a.rs", "file:b.rs", "file:c.rs"];
        let mut events = Vec::new();
        for (i, subject) in subjects.iter().enumerate() {
            for step in 0..4u64 {
                events.push(ev(
                    EnforcementEventType::ReceiptMinted,
                    subject,
                    (i as u64) * 7 + step * 500,
                    None,
                ));
            }
        }
        // Non-receipt events must be ignored entirely.
        events.push(ev(EnforcementEventType::Deny, "file:a.rs", 0, Some("s")));

        let counts = aggregate_event_counts(&events);
        let distinct: BTreeSet<&str> = events
            .iter()
            .filter(|e| matches!(e.event_type, EnforcementEventType::ReceiptMinted))
            .map(|e| e.subject_key.as_str())
            .collect();

        assert!(
            counts.consultations <= counts.receipts_minted,
            "de-duplication may only remove events, never invent them"
        );
        assert!(
            counts.consultations >= distinct.len() as u64,
            "every consulted subject must contribute at least one consultation"
        );
    }

    /// Nothing consulted, nothing counted — and non-receipt events on their
    /// own must not produce a consultation.
    #[test]
    fn no_receipts_means_no_consultations() {
        assert_eq!(count_consultations(&[]), 0);
        let others = vec![
            ev(EnforcementEventType::Deny, "file:a.rs", 0, Some("s")),
            ev(
                EnforcementEventType::AllowAfterReceipt,
                "file:a.rs",
                1,
                None,
            ),
            ev(EnforcementEventType::BypassDetected, "file:a.rs", 2, None),
        ];
        assert_eq!(count_consultations(&others), 0);
        assert_eq!(aggregate_event_counts(&others).consultations, 0);
    }

    /// The claim in `derive_enforcement_metrics` that duplicate receipts do
    /// not move the median, tested rather than reasoned. Pairing takes the
    /// first receipt at or after the deny, so a second report of the same
    /// consultation — always at or after the first — can never become that
    /// minimum, and `consult_pairs` counts denials rather than receipts.
    #[test]
    fn duplicate_receipts_do_not_move_the_median() {
        use EnforcementEventType::*;
        let single = vec![
            ev(Deny, "file:x.rs", 1_000, Some("sessA")),
            ev(ReceiptMinted, "file:x.rs", 1_500, None),
            ev(Deny, "file:y.rs", 2_000, Some("sessB")),
            ev(ReceiptMinted, "file:y.rs", 2_300, None),
        ];
        // Same history as a full install records it: every receipt reported
        // twice, the hook's copy arriving 91ms after the handler's.
        let mut doubled = Vec::new();
        for e in &single {
            doubled.push(e.clone());
            if matches!(e.event_type, ReceiptMinted) {
                doubled.push(ev(
                    ReceiptMinted,
                    &e.subject_key,
                    e.recorded_at_ms + 91,
                    Some("sess-1"),
                ));
            }
        }

        let m_single = derive_enforcement_metrics(&single);
        let m_doubled = derive_enforcement_metrics(&doubled);

        assert_eq!(
            m_doubled.median_time_to_consult_ms, m_single.median_time_to_consult_ms,
            "duplicate receipts must not move the median: {:?} vs {:?}",
            m_doubled.median_time_to_consult_ms, m_single.median_time_to_consult_ms
        );
        assert_eq!(
            m_doubled.consult_pairs, m_single.consult_pairs,
            "consult_pairs counts denials, not receipts"
        );
        assert_eq!(m_single.median_time_to_consult_ms, Some(400));
    }

    /// The duplicate landing *before* the original is the one case where a
    /// naive "keep the last" de-duplication would move the median. Sorting
    /// per subject makes the pairing take the earliest either way.
    #[test]
    fn median_is_unmoved_when_the_duplicate_arrives_first() {
        use EnforcementEventType::*;
        let events = vec![
            ev(Deny, "file:x.rs", 1_000, Some("sessA")),
            // Hook copy recorded (and scanned) before the handler's, e.g.
            // clock jitter between two writers.
            ev(ReceiptMinted, "file:x.rs", 1_591, Some("sess-1")),
            ev(ReceiptMinted, "file:x.rs", 1_500, None),
        ];
        let m = derive_enforcement_metrics(&events);
        assert_eq!(m.median_time_to_consult_ms, Some(500));
        assert_eq!(m.consult_pairs, 1);
        assert_eq!(count_consultations(&events), 1);
    }
}

#[test]
fn median_u64_odd_even_and_empty() {
    assert_eq!(median_u64(&mut []), None);
    assert_eq!(median_u64(&mut [5]), Some(5));
    assert_eq!(median_u64(&mut [3, 1, 2]), Some(2)); // odd → middle
    assert_eq!(median_u64(&mut [4, 1, 3, 2]), Some(2)); // even → (2+3)/2 = 2
}

#[test]
fn hash_excludes_event_hash_field() {
    let mut event = frozen_test_event();
    let hash1 = event.compute_hash();

    // Setting event_hash should not affect compute_hash output
    event.event_hash = "something_completely_different".to_string();
    let hash2 = event.compute_hash();

    assert_eq!(
        hash1, hash2,
        "event_hash field must be excluded from canonical form"
    );
}

#[test]
fn canonical_path_aliasing_produces_same_key() {
    let repo_root = PathBuf::from("/tmp/test-repo");

    // These should all produce the same canonical key (lexical normalization)
    let paths = [
        "src/billing/charges.rs",
        "./src/billing/charges.rs",
        "src/billing/../billing/charges.rs",
        "src/./billing/charges.rs",
    ];

    // Use normalize_components only (no fs access in test)
    let canonical_keys: Vec<String> = paths
        .iter()
        .map(|p| {
            let abs = repo_root.join(p);
            let normalized = normalize_components(&abs);
            let relative = normalized
                .strip_prefix(&repo_root)
                .unwrap_or(&normalized)
                .to_string_lossy()
                .replace('\\', "/");
            if is_case_insensitive() {
                relative.to_lowercase()
            } else {
                relative
            }
        })
        .collect();

    for key in &canonical_keys {
        assert_eq!(
            key, &canonical_keys[0],
            "Path aliasing produced different keys"
        );
    }

    assert_eq!(canonical_keys[0], "src/billing/charges.rs");
}

#[test]
fn canonical_subject_hash_is_deterministic() {
    let hash1 = canonical_subject_hash("src/billing/charges.rs");
    let hash2 = canonical_subject_hash("src/billing/charges.rs");
    assert_eq!(hash1, hash2);

    let hash3 = canonical_subject_hash("src/billing/other.rs");
    assert_ne!(hash1, hash3);
}

#[test]
fn schema_version_is_two() {
    assert_eq!(SCHEMA_VERSION, 2);
    assert_eq!(HASH_ALGORITHM, "sha256");
}

#[test]
fn v2_hash_includes_agent_session() {
    // A v2 event hashes `agent_session`, so changing it changes the hash —
    // tamper-evident per-actor attribution. v1 events (frozen_test_event) are
    // unaffected: their hash stays the v1 golden value asserted above.
    let mut e_none = frozen_test_event();
    e_none.schema_version = 2;
    e_none.agent_session = None;
    let h_none = e_none.compute_hash();

    let mut e_session = e_none.clone();
    e_session.agent_session = Some("sess-abc".to_string());
    let h_session = e_session.compute_hash();

    assert_ne!(
        h_none, h_session,
        "agent_session must be part of the v2 canonical hash"
    );
    // Determinism: same v2 event → same hash.
    assert_eq!(h_session, e_session.compute_hash());

    // The v2 form (even with agent_session=None) differs from the v1 form of
    // the same event — proving compute_hash branches on schema_version.
    let mut as_v1 = e_none.clone();
    as_v1.schema_version = 1;
    assert_ne!(
        h_none,
        as_v1.compute_hash(),
        "v1 and v2 canonical forms must differ (14 vs 15 fields)"
    );
}

/// Write an event straight into the store at a given seq/timestamp,
/// bypassing `record_event`'s hash chain (irrelevant to scan windowing).
async fn put_event_at(store: &Store, seq_no: u64, recorded_at_ms: u64) {
    let event = EnforcementEvent {
        seq_no,
        recorded_at_ms,
        ..frozen_test_event()
    };
    let key = format!("{EVENT_PREFIX}{seq_no:020}");
    store
        .put_raw(&key, &serde_json::to_vec(&event).unwrap())
        .await
        .unwrap();
}

/// `mati stats` used to call `scan_enforcement_events(0, u64::MAX)` and
/// `retain` everything older than 30 days — an unbounded scan of the whole
/// chain. It now calls `scan_enforcement_events_since_ms`, the bounded
/// primitive `policy.rs` already uses. This proves the bounded scan returns
/// exactly the set the old scan-then-retain produced for events inside the
/// window (inclusive at both the `since_ms` and `until_ms` boundary), and
/// that it does not read past the window to get there.
#[tokio::test]
async fn scan_since_ms_matches_legacy_scan_then_retain() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).await.unwrap();

    // seq_no order must track recorded_at_ms order — the bounded scan
    // binary-searches the timestamp boundary assuming that invariant.
    let timestamps: &[(u64, u64)] = &[
        (1, 1_000),  // before the window
        (2, 1_999),  // one ms before since_ms — excluded
        (3, 2_000),  // exactly since_ms — included (inclusive lower bound)
        (4, 2_001),  // inside the window
        (5, 3_000),  // inside the window
        (6, 5_000),  // exactly until_ms (now) — included (inclusive upper bound)
        (7, 5_001),  // one ms after until_ms — excluded
        (8, 9_000),  // well after the window
        (9, 20_000), // well after the window
    ];
    for &(seq, ts) in timestamps {
        put_event_at(&store, seq, ts).await;
    }

    let since_ms = 2_000;
    let until_ms = 5_000;

    // Old behavior: scan everything, retain by the lower bound the code
    // actually applied. `mati stats` never had an upper-bound filter, but
    // for events at or before "now" (the only valid case — a recorded
    // event cannot postdate the moment `stats` computes `now`) that has
    // the same effect as also retaining `<= until_ms`.
    let mut legacy = scan_enforcement_events(&store, 0, u64::MAX).await.unwrap();
    legacy.retain(|e| e.recorded_at_ms >= since_ms && e.recorded_at_ms <= until_ms);
    let legacy_seqs: Vec<u64> = legacy.iter().map(|e| e.seq_no).collect();

    let bounded = scan_enforcement_events_since_ms(&store, since_ms, until_ms)
        .await
        .unwrap();
    let bounded_seqs: Vec<u64> = bounded.events.iter().map(|e| e.seq_no).collect();

    assert_eq!(bounded_seqs, legacy_seqs);
    assert_eq!(bounded_seqs, vec![3, 4, 5, 6]);

    // Must not walk past the window to get there: only seq 3..=7 need
    // reading (7 is read and rejected to confirm the boundary, then the
    // scan stops) — seq 8 and 9 are never touched.
    assert!(
        bounded.scanned_keys <= 5,
        "scan read past the until_ms boundary: scanned_keys={}",
        bounded.scanned_keys
    );
}
