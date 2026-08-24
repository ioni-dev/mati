use super::*;
use crate::graph::Graph;
use crate::mcp::metadata::PeerContext;
use crate::mcp::protocol::*;
use crate::store::{
    PolicyFreshness, PolicyMode, PolicyRecord, PolicyRequires, PolicyTrigger,
    Priority as StorePriority, ReceiptSource, Store,
};

/// Explicit test PeerContext — makes it obvious that auth is bypassed
/// for handler isolation testing.
fn test_peer() -> PeerContext {
    PeerContext {
        uid: 501,
        pid: Some(99999),
    }
}

/// Stable session UUID shared by test_ctx and make_request so the
/// session fence passes. Tests that need a mismatch construct their
/// own Request/RequestContext.
fn test_session() -> Uuid {
    // Deterministic but non-nil so it exercises the real comparison path.
    Uuid::from_bytes([0xAA; 16])
}

fn test_ctx(repo_root: &std::path::Path) -> RequestContext {
    RequestContext {
        peer: test_peer(),
        daemon_session: test_session(),
        repo_root: repo_root.to_path_buf(),
        policy_matcher: Arc::new(tokio::sync::RwLock::new(PolicyMatcherSet::empty())),
    }
}

fn make_request(cmd: Command) -> Request {
    Request {
        v: PROTOCOL_VERSION,
        id: Uuid::new_v4(),
        session: test_session(),
        agent: None,
        cmd,
    }
}

#[tokio::test]
async fn v2_ping_dispatches() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).await.unwrap();
    let graph = Graph::load(store).await.unwrap();
    let graph = Arc::new(tokio::sync::RwLock::new(graph));
    let ctx = test_ctx(dir.path());

    let req = make_request(Command::Ping);
    let resp = dispatch_v2(&graph, &ctx, req).await;

    match resp {
        Response::Ok { data, .. } => {
            assert_eq!(data, serde_json::json!("pong"));
        }
        Response::Err { message, .. } => panic!("expected Ok, got Err: {message}"),
    }
}

#[tokio::test]
async fn policy_write_dispatches_against_daemon_store() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).await.unwrap();
    let graph = Graph::load(store).await.unwrap();
    let graph = Arc::new(tokio::sync::RwLock::new(graph));
    let ctx = test_ctx(dir.path());
    let policy = PolicyRecord {
        name: "Daemon policy".into(),
        rule: "Consult first.".into(),
        reason: "The schema changes because production is live.".into(),
        scope: "repo".into(),
        mode: PolicyMode::Block,
        trigger: PolicyTrigger {
            tool: Some("db_client".into()),
            ..Default::default()
        },
        requires: PolicyRequires {
            key: "schema:orders".into(),
            via: vec![ReceiptSource::MemGet],
            freshness: PolicyFreshness {
                ttl_secs: 900,
                fingerprint: false,
            },
        },
        stage: crate::store::PolicyStage::Off,
        severity: StorePriority::High,
        created_by: "test".into(),
    };
    let key = "policy:daemon";

    let create = make_request(Command::PolicyWrite(PolicyWriteInput {
        op: PolicyWriteOp::Create,
        key: key.into(),
        policy: Some(policy),
        stage: None,
    }));
    let Response::Ok { data, .. } = dispatch_v2(&graph, &ctx, create).await else {
        panic!("policy create should succeed")
    };
    assert_eq!(data["ok"], true);
    assert_eq!(data["key"], key);
    assert_eq!(data["stage"], "off");
    assert!(data["warnings"].is_array());

    let disable = make_request(Command::PolicyWrite(PolicyWriteInput {
        op: PolicyWriteOp::Disable,
        key: key.into(),
        policy: None,
        stage: None,
    }));
    assert!(matches!(
        dispatch_v2(&graph, &ctx, disable).await,
        Response::Ok { .. }
    ));

    let g = graph.read().await;
    let stored = g.store().get(key).await.unwrap().unwrap();
    assert!(matches!(
        stored.payload_as::<PolicyRecord>().unwrap().stage,
        crate::store::PolicyStage::Off
    ));
}

#[tokio::test]
async fn policy_evaluate_uses_live_matcher_and_receipt_state() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).await.unwrap();
    let graph = Graph::load(store).await.unwrap();
    let graph = Arc::new(tokio::sync::RwLock::new(graph));
    let ctx = test_ctx(dir.path());
    let policy = PolicyRecord {
        name: "Production query safety".into(),
        rule: "Consult the schema first.".into(),
        reason: "Production schemas drift because deployments change.".into(),
        scope: "repo".into(),
        mode: PolicyMode::Block,
        trigger: PolicyTrigger {
            tool: Some("db_client".into()),
            host_glob: Some("*prod*".into()),
            target_path_glob: None,
            command_glob: None,
        },
        requires: PolicyRequires {
            key: "schema:orders".into(),
            via: vec![ReceiptSource::MemGet],
            freshness: PolicyFreshness {
                ttl_secs: 900,
                fingerprint: false,
            },
        },
        stage: crate::store::PolicyStage::Enforce,
        severity: StorePriority::High,
        created_by: "test".into(),
    };
    let key = "policy:query-safety";
    let create = make_request(Command::PolicyWrite(PolicyWriteInput {
        op: PolicyWriteOp::Create,
        key: key.into(),
        policy: Some(policy),
        stage: None,
    }));
    assert!(matches!(
        dispatch_v2(&graph, &ctx, create).await,
        Response::Ok { .. }
    ));

    let action = crate::hooks::decide::Action {
        tool: "db_client".into(),
        target_path: None,
        host: Some("db.prod.internal".into()),
        argv: vec!["psql".into()],
        files: vec![],
    };
    let evaluate = || {
        dispatch_v2(
            &graph,
            &ctx,
            make_request(Command::PolicyEvaluate(PolicyEvaluateInput {
                action: action.clone(),
                actor: None,
                raw_command: None,
            })),
        )
    };

    let first = evaluate().await;
    let Response::Ok { data, .. } = first else {
        panic!("policy evaluation should succeed")
    };
    let result: PolicyEvaluateResult = serde_json::from_value(data).unwrap();
    let verdicts = result.verdicts;
    assert_eq!(verdicts.len(), 1);
    assert!(!verdicts[0].satisfied);
    assert!(
        verdicts[0].strict,
        "fresh stores default policy.mode to strict"
    );

    let advisory = make_request(Command::ConfigSet(ConfigSetInput {
        key: "policy.mode".into(),
        value: "advisory".into(),
    }));
    assert!(matches!(
        dispatch_v2(&graph, &ctx, advisory).await,
        Response::Ok { .. }
    ));
    let Response::Ok { data, .. } = evaluate().await else {
        panic!("policy evaluation should succeed in advisory mode")
    };
    let result: PolicyEvaluateResult = serde_json::from_value(data).unwrap();
    let verdicts = result.verdicts;
    assert!(!verdicts[0].strict);

    let strict = make_request(Command::ConfigSet(ConfigSetInput {
        key: "policy.mode".into(),
        value: "strict".into(),
    }));
    assert!(matches!(
        dispatch_v2(&graph, &ctx, strict).await,
        Response::Ok { .. }
    ));
    let best_effort = make_request(Command::ConfigSet(ConfigSetInput {
        key: "audit.write_durability".into(),
        value: "best_effort".into(),
    }));
    assert!(matches!(
        dispatch_v2(&graph, &ctx, best_effort).await,
        Response::Ok { .. }
    ));
    let Response::Ok { data, .. } = evaluate().await else {
        panic!("policy evaluation should remain available after audit mode change")
    };
    let result: PolicyEvaluateResult = serde_json::from_value(data).unwrap();
    let verdicts = result.verdicts;
    assert!(
        verdicts[0].strict,
        "audit write durability must not soften policies"
    );

    {
        // Mint as MemGet, the source this policy's `requires.via` accepts.
        // `log_hit` records no source and therefore satisfies nothing — it was
        // usable here only while satisfaction ignored `via`.
        let g = graph.read().await;
        let staged = crate::store::session::consultation_receipt_staged_for_store(
            g.store(),
            "schema:orders",
            None,
            false,
            Some(crate::store::ReceiptSource::MemGet),
        )
        .await
        .unwrap();
        let receipt: crate::store::Record = rmp_serde::from_slice(&staged.bytes).unwrap();
        g.store().put(&staged.key, &receipt).await.unwrap();
    }
    let second = evaluate().await;
    let Response::Ok { data, .. } = second else {
        panic!("policy evaluation should succeed after receipt")
    };
    let result: PolicyEvaluateResult = serde_json::from_value(data).unwrap();
    let verdicts = result.verdicts;
    assert!(verdicts[0].satisfied);

    let disable = make_request(Command::PolicyWrite(PolicyWriteInput {
        op: PolicyWriteOp::Disable,
        key: key.into(),
        policy: None,
        stage: None,
    }));
    assert!(matches!(
        dispatch_v2(&graph, &ctx, disable).await,
        Response::Ok { .. }
    ));
    let third = evaluate().await;
    let Response::Ok { data, .. } = third else {
        panic!("policy evaluation should succeed after refresh")
    };
    let result: PolicyEvaluateResult = serde_json::from_value(data).unwrap();
    let verdicts = result.verdicts;
    assert!(verdicts.is_empty());
}

#[tokio::test]
async fn policies_sharing_requires_key_respect_different_via_sources() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).await.unwrap();
    let graph = Arc::new(tokio::sync::RwLock::new(Graph::load(store).await.unwrap()));
    let ctx = test_ctx(dir.path());
    let action = crate::hooks::decide::normalize_action(
        Some("psql -h db.prod.internal -c 'SELECT 1'"),
        None,
    );
    let make_policy = |via| PolicyRecord {
        name: "Shared schema requirement".into(),
        rule: "Consult the schema first.".into(),
        reason: "Production schemas drift because deployments change.".into(),
        scope: "repo".into(),
        mode: PolicyMode::Block,
        trigger: PolicyTrigger {
            tool: Some("db_client".into()),
            host_glob: Some("*prod*".into()),
            target_path_glob: None,
            command_glob: None,
        },
        requires: PolicyRequires {
            key: "schema:shared".into(),
            via,
            freshness: PolicyFreshness {
                ttl_secs: 900,
                fingerprint: false,
            },
        },
        stage: crate::store::PolicyStage::Enforce,
        severity: StorePriority::High,
        created_by: "test".into(),
    };
    for (key, via) in [
        ("policy:shared-mem", vec![ReceiptSource::MemGet]),
        ("policy:shared-db", vec![ReceiptSource::DbIntrospection]),
    ] {
        assert!(matches!(
            dispatch_v2(
                &graph,
                &ctx,
                make_request(Command::PolicyWrite(PolicyWriteInput {
                    op: PolicyWriteOp::Create,
                    key: key.into(),
                    policy: Some(make_policy(via)),
                    stage: None,
                })),
            )
            .await,
            Response::Ok { .. }
        ));
    }

    let mint = make_request(Command::ConsultationHit(ConsultationHitInput {
        key: "schema:shared".into(),
        capture_fingerprint: false,
        actor: None,
        session_id: None,
        agent_id: None,
        decision_basis_hash: None,
        source: Some(ReceiptSource::MemGet),
    }));
    assert!(matches!(
        dispatch_v2(&graph, &ctx, mint).await,
        Response::Ok { .. }
    ));

    let Response::Ok { data, .. } = dispatch_v2(
        &graph,
        &ctx,
        make_request(Command::PolicyEvaluate(PolicyEvaluateInput {
            action,
            actor: None,
            raw_command: None,
        })),
    )
    .await
    else {
        panic!("policy evaluation should succeed")
    };
    let result: PolicyEvaluateResult = serde_json::from_value(data).unwrap();
    let verdicts = result
        .verdicts
        .into_iter()
        .map(|verdict| (verdict.key, verdict.satisfied))
        .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(verdicts.get("policy:shared-mem"), Some(&true));
    assert_eq!(verdicts.get("policy:shared-db"), Some(&false));
}

#[tokio::test]
async fn unclassified_policy_literal_bypass_records_and_verifies_chain() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).await.unwrap();
    let graph = Arc::new(tokio::sync::RwLock::new(Graph::load(store).await.unwrap()));
    let ctx = test_ctx(dir.path());
    let policy_key = "policy:prod-db";
    let policy = PolicyRecord {
        name: "Production database safety".into(),
        rule: "Consult the production schema first.".into(),
        reason: "Production data changes because deployments are live.".into(),
        scope: "repo".into(),
        mode: PolicyMode::Block,
        trigger: PolicyTrigger {
            tool: Some("db_client".into()),
            host_glob: Some("*prod-codex*".into()),
            target_path_glob: None,
            command_glob: None,
        },
        requires: PolicyRequires {
            key: "schema:orders".into(),
            via: vec![ReceiptSource::MemGet],
            freshness: PolicyFreshness {
                ttl_secs: 900,
                fingerprint: false,
            },
        },
        stage: crate::store::PolicyStage::Enforce,
        severity: StorePriority::High,
        created_by: "test".into(),
    };
    assert!(matches!(
        dispatch_v2(
            &graph,
            &ctx,
            make_request(Command::PolicyWrite(PolicyWriteInput {
                op: PolicyWriteOp::Create,
                key: policy_key.into(),
                policy: Some(policy),
                stage: None,
            })),
        )
        .await,
        Response::Ok { .. }
    ));

    let raw = r#"db_client=psql; "$db_client" -h db.prod-codex.internal -c 'SELECT 1'"#;
    let action = crate::hooks::decide::normalize_action(Some(raw), None);
    assert_eq!(action.tool, "unknown");
    let Response::Ok { data, .. } = dispatch_v2(
        &graph,
        &ctx,
        make_request(Command::PolicyEvaluate(PolicyEvaluateInput {
            action,
            actor: None,
            raw_command: Some(raw.into()),
        })),
    )
    .await
    else {
        panic!("policy evaluation should succeed")
    };
    let evaluation: PolicyEvaluateResult = serde_json::from_value(data).unwrap();
    assert!(evaluation.verdicts.is_empty());
    assert_eq!(evaluation.bypass_key.as_deref(), Some(policy_key));

    assert!(matches!(
        dispatch_v2(
            &graph,
            &ctx,
            make_request(Command::SessionLog(SessionLogInput {
                event: SessionEvent::UnclassifiedPolicyLiteralBypass,
                key: policy_key.into(),
                session_id: None,
                actor: None,
                decision_basis_hash: None,
            })),
        )
        .await,
        Response::Ok { .. }
    ));

    let g = graph.read().await;
    let aggregate = g
        .store()
        .scan_keys("compliance:unclassified_policy_literal_bypass_")
        .await
        .unwrap();
    assert!(!aggregate.is_empty());
    let events = crate::store::enforcement::scan_events_since(g.store(), 0)
        .await
        .unwrap();
    let bypass = events
        .iter()
        .find(|event| {
            matches!(
                event.event_type,
                crate::store::enforcement::EnforcementEventType::BypassDetected
            )
        })
        .expect("literal detector must record a bypass event");
    assert_eq!(bypass.decision_reason_code, "unclassified_policy_literal");
    assert_eq!(bypass.subject_key, policy_key);
    assert!(crate::store::enforcement::verify_chain(&events).is_valid());
}

#[tokio::test]
async fn v2_version_mismatch_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).await.unwrap();
    let graph = Graph::load(store).await.unwrap();
    let graph = Arc::new(tokio::sync::RwLock::new(graph));
    let ctx = test_ctx(dir.path());

    let req = Request {
        v: 99,
        id: Uuid::new_v4(),
        session: Uuid::new_v4(),
        agent: None,
        cmd: Command::Ping,
    };
    let resp = dispatch_v2(&graph, &ctx, req).await;

    match resp {
        Response::Err { code, .. } => {
            assert_eq!(code, ErrorCode::VersionMismatch);
        }
        Response::Ok { .. } => panic!("expected VersionMismatch error"),
    }
}

#[tokio::test]
async fn v2_get_returns_null_for_missing_key() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).await.unwrap();
    let graph = Graph::load(store).await.unwrap();
    let graph = Arc::new(tokio::sync::RwLock::new(graph));
    let ctx = test_ctx(dir.path());

    let req = make_request(Command::Get(GetInput {
        key: "file:nonexistent".into(),
    }));
    let resp = dispatch_v2(&graph, &ctx, req).await;

    match resp {
        Response::Ok { data, .. } => {
            assert!(data.is_null(), "missing key should return null");
        }
        Response::Err { message, .. } => panic!("expected Ok(null), got Err: {message}"),
    }
}

#[tokio::test]
async fn v2_session_log_writes_audit_to_sessions_tree() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).await.unwrap();
    let graph = Graph::load(store).await.unwrap();
    let graph = Arc::new(tokio::sync::RwLock::new(graph));
    let ctx = test_ctx(dir.path());

    let req = make_request(Command::SessionLog(SessionLogInput {
        event: SessionEvent::Miss,
        key: "file:test".into(),
        session_id: None,
        actor: None,
        decision_basis_hash: None,
    }));
    let resp = dispatch_v2(&graph, &ctx, req).await;
    assert!(matches!(resp, Response::Ok { .. }));

    // Audit should be in sessions tree (audit:session:* prefix).
    let g = graph.read().await;
    let session_audit_keys = g.store().scan_keys("audit:session:").await.unwrap();
    assert!(
        !session_audit_keys.is_empty(),
        "session-side mutation should produce audit:session:* entry"
    );
    // And NOT in knowledge tree.
    let knowledge_audit_keys = g.store().scan_keys("audit:knowledge:").await.unwrap();
    assert!(
        knowledge_audit_keys.is_empty(),
        "session-side mutation should not produce audit:knowledge:* entry"
    );
}

/// The end-to-end half of the "one consultation is one consultation"
/// invariant (`store::enforcement::tests::one_consultation_counts_once`
/// holds the pure half). This one drives the two emitters that actually
/// co-fire — the MCP `mem_get` handler and the `post-memget.sh` PostToolUse
/// hook's `ConsultationHit` — through real dispatch against a real store,
/// so it measures the multiplicity rather than restating it.
#[tokio::test]
async fn one_mem_get_counts_as_one_consultation() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).await.unwrap();
    let graph = Graph::load(store).await.unwrap();
    let graph = Arc::new(tokio::sync::RwLock::new(graph));
    let ctx = test_ctx(dir.path());
    let key = "file:src/billing/charges.rs";

    // A record must exist or the handler skips its deferred write path.
    {
        let g = graph.read().await;
        let record = crate::store::session::session_record(key, "charges".into());
        g.store().put(key, &record).await.unwrap();
    }

    // 1. The agent calls `mem_get`.
    let mem_get = make_request(Command::MemGet(MemGetInput {
        key: key.into(),
        actor: None,
    }));
    assert!(matches!(
        dispatch_v2(&graph, &ctx, mem_get).await,
        Response::Ok { .. }
    ));

    // 2. Claude Code fires post-memget.sh, which sends ConsultationHit with
    //    the session id. Same logical action, second reporter.
    let hit = make_request(Command::ConsultationHit(ConsultationHitInput {
        key: key.into(),
        capture_fingerprint: true,
        actor: None,
        session_id: Some("sess-e2e".into()),
        agent_id: None,
        decision_basis_hash: None,
        source: None,
    }));
    assert!(matches!(
        dispatch_v2(&graph, &ctx, hit).await,
        Response::Ok { .. }
    ));

    let g = graph.read().await;
    let events = crate::store::enforcement::scan_events_since(g.store(), 0)
        .await
        .unwrap();
    let counts = crate::store::enforcement::aggregate_event_counts(&events);

    assert_eq!(
        counts.receipts_minted, 2,
        "one mem_get on a full install emits two ReceiptMinted events (the \
             handler's unattributed one and the hook's session-attributed one); \
             if this changed, re-derive the de-duplication window before \
             touching the assertion below"
    );
    assert_eq!(
        counts.consultations, 1,
        "INFLATED CONSULTATION COUNT: one mem_get produced \
             {} ReceiptMinted events and was counted as {} consultations. \
             `mati stats` reports this as \"consulted\" — it must count \
             consultations, not events. The emitters are deliberate (each is \
             the only record when the other's path is absent, and only the hook \
             path carries a session id) and the log is append-only, so the fix \
             belongs in `store::enforcement::count_consultations`, not here.",
        counts.receipts_minted, counts.consultations
    );
}

#[tokio::test]
async fn v2_session_clear_consults_deletes_receipts_silently() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).await.unwrap();
    let graph = Graph::load(store).await.unwrap();
    let graph = Arc::new(tokio::sync::RwLock::new(graph));
    let ctx = test_ctx(dir.path());

    // Mint two consult receipts through the real v2 path.
    for key in ["file:a.rs", "file:b.rs"] {
        let req = make_request(Command::ConsultationHit(ConsultationHitInput {
            key: key.into(),
            capture_fingerprint: true,
            actor: None,
            session_id: None,
            agent_id: None,
            decision_basis_hash: None,
            source: None,
        }));
        assert!(matches!(
            dispatch_v2(&graph, &ctx, req).await,
            Response::Ok { .. }
        ));
    }

    // Two receipts exist; capture the audit count so we can prove the clear adds none.
    let audit_before = {
        let g = graph.read().await;
        assert_eq!(
            g.store()
                .scan_keys("session:consulted:")
                .await
                .unwrap()
                .len(),
            2,
            "two receipts should exist before clear"
        );
        g.store().scan_keys("audit:session:").await.unwrap().len()
    };

    // Clear through the v2 dispatch path.
    let req = make_request(Command::SessionClearConsults);
    assert!(matches!(
        dispatch_v2(&graph, &ctx, req).await,
        Response::Ok { .. }
    ));

    let g = graph.read().await;
    assert!(
        g.store()
            .scan_keys("session:consulted:")
            .await
            .unwrap()
            .is_empty(),
        "all receipts should be gone after clear"
    );
    assert_eq!(
        g.store().scan_keys("audit:session:").await.unwrap().len(),
        audit_before,
        "clear must be silent — it must not write an audit:session:* entry"
    );
}

#[tokio::test]
async fn v2_pure_read_does_not_write_audit() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).await.unwrap();
    let graph = Graph::load(store).await.unwrap();
    let graph = Arc::new(tokio::sync::RwLock::new(graph));
    let ctx = test_ctx(dir.path());

    let req = make_request(Command::Ping);
    let _ = dispatch_v2(&graph, &ctx, req).await;

    let g = graph.read().await;
    let session_keys = g.store().scan_keys("audit:session:").await.unwrap();
    let knowledge_keys = g.store().scan_keys("audit:knowledge:").await.unwrap();
    assert!(session_keys.is_empty() && knowledge_keys.is_empty());
}

#[tokio::test]
async fn v2_audit_entry_contains_peer_identity() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).await.unwrap();
    let graph = Graph::load(store).await.unwrap();
    let graph = Arc::new(tokio::sync::RwLock::new(graph));

    let peer = PeerContext {
        uid: 12345,
        pid: Some(67890),
    };
    let daemon_session = test_session();
    let ctx = RequestContext {
        peer,
        daemon_session,
        repo_root: dir.path().to_path_buf(),
        policy_matcher: Arc::new(tokio::sync::RwLock::new(PolicyMatcherSet::empty())),
    };

    let req = make_request(Command::ConsultationHit(ConsultationHitInput {
        key: "file:test".into(),
        capture_fingerprint: true,
        actor: None,
        session_id: None,
        agent_id: None,
        decision_basis_hash: None,
        source: None,
    }));
    let request_id = req.id;
    let _ = dispatch_v2(&graph, &ctx, req).await;

    // Read back the audit entry from sessions tree.
    let g = graph.read().await;
    let audit_keys = g.store().scan_keys("audit:session:").await.unwrap();
    assert_eq!(audit_keys.len(), 1);

    let txn = g
        .store()
        .sessions_tree()
        .begin_with_mode(surrealkv::Mode::ReadOnly)
        .unwrap();
    let raw = txn.get(audit_keys[0].as_bytes()).unwrap().unwrap();
    let entry: AuditEntry = rmp_serde::from_slice(&raw).unwrap();

    assert_eq!(entry.peer_uid, 12345);
    assert_eq!(entry.peer_pid, Some(67890));
    assert_eq!(entry.daemon_session, daemon_session);
    assert_eq!(entry.request_id, request_id);
    assert_eq!(entry.command_kind, "consultation_hit");
    assert_eq!(entry.target_key, "file:test");
    assert!(entry.accepted);
    assert!(entry.error_code.is_none());
}

#[tokio::test]
async fn v1_bridge_only_handles_pure_reads() {
    // The v1 bridge handles ONLY pure reads that have no native dispatch
    // arm. Mutations, side-effecting reads, AND `Command::MemQuery`
    // (γ-C1.5) are all handled natively. Verify the remaining v1 bridge
    // commands never produce "put" or "delete".
    //
    // Pre-γ-C1.5 this list contained 9 entries; MemQuery was the 9th.
    // It now lives in `dispatch_mem_query` — see the byte-identical
    // parity tests in `handlers::tests::mem_query_*`.
    let pure_read_commands: Vec<Command> = vec![
        Command::Ping,
        Command::Get(GetInput { key: "k".into() }),
        Command::HookEvaluate(HookEvaluateInput {
            file_key: "file:k".into(),
            include_recent: false,
            actor: None,
        }),
        Command::ScanPrefix(ScanPrefixInput { prefix: "p".into() }),
        Command::History(HistoryInput {
            key: "k".into(),
            limit: 10,
        }),
        Command::HistorySince(HistorySinceInput {
            key: "k".into(),
            since_ts: 0,
            limit: 10,
        }),
        Command::SessionCheckConsulted(SessionCheckConsultedInput { key: "k".into() }),
        Command::SessionCheckConsultedRecent(SessionCheckConsultedRecentInput {
            key: "k".into(),
            ttl_secs: 900,
        }),
    ];

    assert_eq!(
        pure_read_commands.len(),
        8,
        "must cover all 8 pure read commands still routed via v1 bridge \
             (was 9 before γ-C1.5 moved MemQuery to a native arm)"
    );
    for cmd in pure_read_commands {
        assert!(!cmd.is_mutation(), "{} must not be a mutation", cmd.kind());
        assert!(
            !is_side_effecting_read(&cmd),
            "{} must not be a side-effecting read",
            cmd.kind()
        );
        let (v1_cmd, _) = command_to_v1(&cmd);
        assert_ne!(
            v1_cmd,
            "put",
            "v1 bridge must never produce 'put': got it for {}",
            cmd.kind()
        );
        assert_ne!(
            v1_cmd,
            "delete",
            "v1 bridge must never produce 'delete': got it for {}",
            cmd.kind()
        );
    }
}

#[test]
fn command_to_v1_hook_evaluate_carries_actor() {
    // Regression: the v2->v1 bridge dropped `actor`, so the daemon ran an
    // actor-blind consult lookup (subagents rode the global receipt).
    // Live-E2E caught it; this locks it in.
    let cmd = Command::HookEvaluate(HookEvaluateInput {
        file_key: "file:x".into(),
        include_recent: false,
        actor: Some("agentZ".into()),
    });
    let (kind, args) = command_to_v1(&cmd);
    assert_eq!(kind, "hook_evaluate");
    assert_eq!(args.get("actor").and_then(|v| v.as_str()), Some("agentZ"));
}

#[test]
fn no_mutation_or_side_effecting_read_reaches_v1_bridge() {
    // All 8 knowledge-side mutations + 4 session-side mutations + 1 compound
    // + 2 side-effecting reads are handled natively. Only pure reads go
    // through the v1 bridge.
    let all_mutations: Vec<Command> = vec![
        Command::GotchaUpsert(GotchaDraftInput {
            key: "gotcha:t".into(),
            rule: "r".into(),
            reason: "r".into(),
            severity: Severity::Normal,
            affected_files: vec![],
            ref_url: None,
            tags: vec![],
            priority: Priority::Normal,
            source: None,
            confirmed: false,
        }),
        Command::GotchaConfirm(GotchaConfirmInput {
            key: "gotcha:t".into(),
            via_elicitation: false,
        }),
        Command::GotchaTombstone(GotchaTombstoneInput {
            key: "gotcha:t".into(),
        }),
        Command::FileEnrich(FileEnrichInput {
            path: "p".into(),
            purpose: "p".into(),
            entry_points: vec![],
            decision_keys: vec![],
            todos: vec![],
            tags: vec![],
            priority: Priority::Normal,
        }),
        Command::FileReparse(FileReparseInput { path: "p".into() }),
        Command::FileEditHook(FileEditHookInput { path: "p".into() }),
        Command::DocCapture(DocCaptureInput { path: "p".into() }),
        Command::DecisionUpsert(DecisionUpsertInput {
            slug: "s".into(),
            value: "v".into(),
            summary: "s".into(),
            rationale: "r".into(),
            tags: vec![],
            priority: Priority::Normal,
        }),
        Command::DevNoteUpsert(DevNoteUpsertInput {
            key: None,
            text: "t".into(),
            tags: vec![],
            priority: Priority::Normal,
        }),
        Command::SessionLog(SessionLogInput {
            event: SessionEvent::Miss,
            key: "k".into(),
            session_id: None,
            actor: None,
            decision_basis_hash: None,
        }),
        Command::ConsultationHit(ConsultationHitInput {
            key: "k".into(),
            capture_fingerprint: true,
            actor: None,
            session_id: None,
            agent_id: None,
            decision_basis_hash: None,
            source: None,
        }),
        Command::SessionFlush,
        Command::SessionHarvest,
        Command::SessionClearConsults,
        // Side-effecting reads.
        Command::MemGet(MemGetInput {
            key: "k".into(),
            actor: None,
        }),
        Command::MemBootstrap(MemBootstrapInput {
            context_files: vec![],
        }),
    ];
    for cmd in &all_mutations {
        assert!(
            is_knowledge_mutation(cmd)
                || is_session_side(cmd)
                || is_compound(cmd)
                || is_side_effecting_read(cmd),
            "{} must be handled natively, not via v1 bridge",
            cmd.kind()
        );
    }
}

#[tokio::test]
async fn knowledge_side_mutation_audit_goes_to_knowledge_tree() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).await.unwrap();
    let graph = Graph::load(store).await.unwrap();
    let graph = Arc::new(tokio::sync::RwLock::new(graph));
    let ctx = test_ctx(dir.path());

    // GotchaConfirm is knowledge-side. It will fail (no record), but
    // should still produce a knowledge-tree audit entry.
    let req = make_request(Command::GotchaConfirm(GotchaConfirmInput {
        key: "gotcha:nonexistent".into(),
        via_elicitation: false,
    }));
    let resp = dispatch_v2(&graph, &ctx, req).await;
    assert!(matches!(resp, Response::Err { .. }));

    let g = graph.read().await;
    let knowledge_audit = g.store().scan_keys("audit:knowledge:").await.unwrap();
    assert!(
        !knowledge_audit.is_empty(),
        "knowledge-side mutation should produce audit:knowledge:* entry"
    );
    let session_audit = g.store().scan_keys("audit:session:").await.unwrap();
    assert!(
        session_audit.is_empty(),
        "knowledge-side mutation should NOT produce audit:session:* entry"
    );
}

/// `confirmed` crosses the wire, but only a developer-originated write may
/// assert it. Before the field existed, `mati gotcha add` produced an
/// enforcing gotcha without a daemon and a dormant one with; after it,
/// an agent's `mem_set` still cannot mint one.
#[tokio::test]
async fn only_developer_originated_upserts_may_arrive_confirmed() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).await.unwrap();
    let graph = Graph::load(store).await.unwrap();
    let graph = Arc::new(tokio::sync::RwLock::new(graph));
    let ctx = test_ctx(dir.path());

    let draft = |key: &str, source: Option<&str>| {
        make_request(Command::GotchaUpsert(GotchaDraftInput {
            key: key.into(),
            rule: "Never swallow the error returned by Store::put".into(),
            reason: "a dropped error loses the write silently".into(),
            severity: Severity::High,
            affected_files: vec!["src/a.rs".into()],
            ref_url: None,
            tags: vec![],
            priority: Priority::Normal,
            source: source.map(str::to_string),
            confirmed: true,
        }))
    };

    for (key, source, expected) in [
        ("gotcha:from-developer", Some("developer_manual"), true),
        ("gotcha:from-agent", None, false),
        ("gotcha:from-import", Some("import"), false),
    ] {
        let resp = dispatch_v2(&graph, &ctx, draft(key, source)).await;
        assert!(matches!(resp, Response::Ok { .. }), "{key} must be written");
        let g = graph.read().await;
        let gotcha = g
            .store()
            .get(key)
            .await
            .unwrap()
            .expect("record written")
            .payload_as::<crate::store::GotchaRecord>()
            .expect("gotcha payload");
        assert_eq!(gotcha.confirmed, expected, "{key}");
    }
}

/// `handle_gotcha_upsert` commits through its own `transact_knowledge`
/// loop and never touches `gotcha_ops::apply_gotcha_write`, so the
/// normalization there does not cover the MCP write path. It has to do its
/// own — otherwise a `mem_set` with `./src/a.rs` stores a path that joins
/// to no `file:*` record and the gotcha is silently inert.
#[tokio::test]
async fn gotcha_upsert_normalizes_affected_files() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).await.unwrap();
    let graph = Graph::load(store).await.unwrap();
    let graph = Arc::new(tokio::sync::RwLock::new(graph));
    let ctx = test_ctx(dir.path());

    let req = make_request(Command::GotchaUpsert(GotchaDraftInput {
        key: "gotcha:mcp-dotslash".into(),
        rule: "never call foo() directly".into(),
        reason: "it bypasses the retry wrapper".into(),
        severity: Severity::High,
        affected_files: vec!["./src/a.rs".into(), "src/payments/**".into()],
        ref_url: None,
        tags: vec![],
        priority: Priority::Normal,
        source: None,
        confirmed: false,
    }));
    let resp = dispatch_v2(&graph, &ctx, req).await;
    assert!(matches!(resp, Response::Ok { .. }), "upsert must succeed");

    let g = graph.read().await;
    let stored = g
        .store()
        .get("gotcha:mcp-dotslash")
        .await
        .unwrap()
        .expect("record written");
    let gotcha = stored
        .payload_as::<crate::store::GotchaRecord>()
        .expect("gotcha payload");
    assert_eq!(
        gotcha.affected_files,
        vec!["src/a.rs".to_string(), "src/payments/**".to_string()],
        "`./` stripped, glob left alone"
    );

    // The file link must land on the key the read gate looks up.
    let linked = g
        .store()
        .get("file:src/a.rs")
        .await
        .unwrap()
        .expect("corrected path linked");
    let keys: Vec<String> = linked
        .payload
        .as_ref()
        .and_then(|p| p.get("gotcha_keys"))
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();
    assert_eq!(keys, vec!["gotcha:mcp-dotslash".to_string()]);
    assert!(g.store().get("file:./src/a.rs").await.unwrap().is_none());
}

/// `handle_gotcha_confirm` also commits through its own
/// `transact_knowledge` loop and never calls
/// `gotcha_ops::apply_gotcha_confirm`, so the content stamp there does not
/// cover the daemon path — which is the path every socket-mode
/// `mati gotcha confirm` and `mem_set` confirm takes. Without its own
/// stamp, drift would only ever be detectable on direct-store runs.
#[tokio::test]
async fn gotcha_confirm_stamps_content_hash_on_the_daemon_path() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).await.unwrap();
    let graph = Graph::load(store).await.unwrap();
    let graph = Arc::new(tokio::sync::RwLock::new(graph));
    let ctx = test_ctx(dir.path());

    // The stamp comes from the working tree, so the file has to exist on disk.
    // The `file:*` record carries a deliberately wrong digest: if confirm ever
    // regresses to reading the index, this test fails instead of passing on a
    // value that agrees by accident.
    std::fs::create_dir_all(dir.path().join("src")).unwrap();
    std::fs::write(dir.path().join("src/a.rs"), b"fn a() {}\n").unwrap();
    let on_disk = format!(
        "{:x}",
        <sha2::Sha256 as sha2::Digest>::digest(b"fn a() {}\n")
    );
    {
        let g = graph.read().await;
        let mut file = crate::store::record::Record::layer0_file_stub(
            "file:src/a.rs",
            crate::store::stable_device_id(),
            1,
            1_000_000,
        );
        file.payload = Some(serde_json::json!({
            "path": "src/a.rs",
            "gotcha_keys": [],
            "content_hash": "hash-v1",
        }));
        g.store().put("file:src/a.rs", &file).await.unwrap();
    }

    let upsert = make_request(Command::GotchaUpsert(GotchaDraftInput {
        key: "gotcha:daemon-confirm".into(),
        rule: "hold the write lock before touching the index".into(),
        reason: "concurrent writers corrupt it otherwise".into(),
        severity: Severity::High,
        affected_files: vec!["src/a.rs".into()],
        ref_url: None,
        tags: vec![],
        priority: Priority::Normal,
        source: None,
        confirmed: false,
    }));
    assert!(matches!(
        dispatch_v2(&graph, &ctx, upsert).await,
        Response::Ok { .. }
    ));

    let confirm = make_request(Command::GotchaConfirm(GotchaConfirmInput {
        key: "gotcha:daemon-confirm".into(),
        via_elicitation: false,
    }));
    assert!(matches!(
        dispatch_v2(&graph, &ctx, confirm).await,
        Response::Ok { .. }
    ));

    let g = graph.read().await;
    let stored = g
        .store()
        .get("gotcha:daemon-confirm")
        .await
        .unwrap()
        .expect("confirmed record");
    let gotcha = stored
        .payload_as::<crate::store::GotchaRecord>()
        .expect("gotcha payload");
    assert!(gotcha.confirmed);
    assert_eq!(
        gotcha.confirmed_content.get("src/a.rs"),
        Some(&on_disk),
        "daemon confirm must stamp the file's current on-disk digest"
    );
    // Confirmation must not weaken anything the read gate reads. Confidence
    // is set to the DeveloperManual base by the handler; quality is whatever
    // `quality::analyze` scores this (deliberately terse) test rule at, so
    // only assert it was not zeroed by the stamp write.
    assert!(stored.confidence.value >= 0.6);
    assert!(stored.quality.value > 0.0);
}

/// A confirm that came from an in-session elicitation accept records a distinct
/// reason code, so the audit chain can tell it apart from a CLI/direct confirm.
#[tokio::test]
async fn daemon_confirm_via_elicitation_records_elicited_reason_code() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).await.unwrap();
    let graph = Graph::load(store).await.unwrap();
    let graph = Arc::new(tokio::sync::RwLock::new(graph));
    let ctx = test_ctx(dir.path());

    let upsert = make_request(Command::GotchaUpsert(GotchaDraftInput {
        key: "gotcha:elicited".into(),
        rule: "hold the write lock before touching the index".into(),
        reason: "concurrent writers corrupt it otherwise".into(),
        severity: Severity::High,
        affected_files: vec![],
        ref_url: None,
        tags: vec![],
        priority: Priority::Normal,
        source: None,
        confirmed: false,
    }));
    assert!(matches!(
        dispatch_v2(&graph, &ctx, upsert).await,
        Response::Ok { .. }
    ));

    let confirm = make_request(Command::GotchaConfirm(GotchaConfirmInput {
        key: "gotcha:elicited".into(),
        via_elicitation: true,
    }));
    assert!(matches!(
        dispatch_v2(&graph, &ctx, confirm).await,
        Response::Ok { .. }
    ));

    let g = graph.read().await;
    let events = crate::store::enforcement::scan_enforcement_events(g.store(), 0, u64::MAX)
        .await
        .expect("scan");
    let confirmed = events
        .iter()
        .find(|e| {
            matches!(
                e.event_type,
                crate::store::enforcement::EnforcementEventType::ControlChanged {
                    change_kind: crate::store::enforcement::ControlChangeKind::Confirmed
                }
            )
        })
        .expect("a Confirmed control event");
    assert_eq!(confirmed.decision_reason_code, "control_confirmed_elicited");
}

// ── Native MemGet / MemBootstrap tests ──────────────────────────────

#[tokio::test]
async fn native_mem_get_empty_key_returns_error_with_rejection_audit() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).await.unwrap();
    let graph = Graph::load(store).await.unwrap();
    let graph = Arc::new(tokio::sync::RwLock::new(graph));
    let ctx = test_ctx(dir.path());

    let req = make_request(Command::MemGet(MemGetInput {
        key: "".into(),
        actor: None,
    }));
    let resp = dispatch_v2(&graph, &ctx, req).await;

    // Must return Response::Err, not Response::Ok with error payload.
    match resp {
        Response::Err { code, .. } => {
            assert_eq!(code, ErrorCode::ValidationFailed);
        }
        Response::Ok { data, .. } => {
            panic!("empty key must return Response::Err, got Ok with: {data}")
        }
    }

    // Rejection audit must exist in sessions tree with accepted=false.
    let g = graph.read().await;
    let audit_keys = g.store().scan_keys("audit:session:").await.unwrap();
    assert!(
        !audit_keys.is_empty(),
        "empty-key rejection must produce session audit"
    );
    let txn = g
        .store()
        .sessions_tree()
        .begin_with_mode(surrealkv::Mode::ReadOnly)
        .unwrap();
    let raw = txn.get(audit_keys[0].as_bytes()).unwrap().unwrap();
    let entry: AuditEntry = rmp_serde::from_slice(&raw).unwrap();
    assert!(!entry.accepted, "rejection audit must have accepted=false");
    assert_eq!(entry.error_code, Some(ErrorCode::ValidationFailed));
}

#[tokio::test]
async fn native_mem_get_returns_null_for_missing_key() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).await.unwrap();
    let graph = Graph::load(store).await.unwrap();
    let graph = Arc::new(tokio::sync::RwLock::new(graph));
    let ctx = test_ctx(dir.path());

    let req = make_request(Command::MemGet(MemGetInput {
        key: "file:nonexistent".into(),
        actor: None,
    }));
    let resp = dispatch_v2(&graph, &ctx, req).await;

    match resp {
        Response::Ok { data, .. } => assert!(data.is_null()),
        Response::Err { message, .. } => panic!("expected Ok(null): {message}"),
    }
}

#[tokio::test]
async fn native_mem_get_writes_session_audit_and_consultation_receipt() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).await.unwrap();
    let graph = Graph::load(store).await.unwrap();
    let graph = Arc::new(tokio::sync::RwLock::new(graph));
    let ctx = test_ctx(dir.path());

    let req = make_request(Command::MemGet(MemGetInput {
        key: "file:src/main.rs".into(),
        actor: None,
    }));
    let _ = dispatch_v2(&graph, &ctx, req).await;

    let g = graph.read().await;
    // Audit should be in sessions tree.
    let audit_keys = g.store().scan_keys("audit:session:").await.unwrap();
    assert!(
        !audit_keys.is_empty(),
        "MemGet should produce session-side audit"
    );

    // Consultation receipt should exist.
    let consulted = g
        .store()
        .get("session:consulted:file:src/main.rs")
        .await
        .unwrap();
    assert!(
        consulted.is_some(),
        "MemGet should write consultation receipt"
    );

    let events = crate::store::enforcement::scan_events_since(g.store(), 0)
        .await
        .unwrap();
    assert!(
        events.iter().any(|event| {
            matches!(
                event.event_type,
                crate::store::enforcement::EnforcementEventType::ReceiptMinted
            ) && event.subject_key == "file:src/main.rs"
        }),
        "MemGet receipt must have a matching receipt_minted event"
    );

    // No knowledge-side audit.
    let k_audit = g.store().scan_keys("audit:knowledge:").await.unwrap();
    assert!(
        k_audit.is_empty(),
        "MemGet should NOT produce knowledge-side audit"
    );
}

/// `mati serve` stamps its own worktree tag onto every `mem_get` call as
/// `actor` (F4/Half 1). The native handler must key the receipt on that
/// scope, not the unscoped global key — otherwise a receipt minted by one
/// worktree's `mati serve` would satisfy every other worktree sharing the
/// same store.
#[tokio::test]
async fn native_mem_get_scopes_receipt_to_the_caller_supplied_actor() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).await.unwrap();
    let graph = Graph::load(store).await.unwrap();
    let graph = Arc::new(tokio::sync::RwLock::new(graph));
    let ctx = test_ctx(dir.path());

    let req = make_request(Command::MemGet(MemGetInput {
        key: "file:src/main.rs".into(),
        actor: Some("wtA".into()),
    }));
    let _ = dispatch_v2(&graph, &ctx, req).await;

    let g = graph.read().await;
    assert!(
        g.store()
            .get("session:consulted:wtA:file:src/main.rs")
            .await
            .unwrap()
            .is_some(),
        "MemGet with actor=wtA must write the wtA-scoped receipt key"
    );
    assert!(
        g.store()
            .get("session:consulted:file:src/main.rs")
            .await
            .unwrap()
            .is_none(),
        "MemGet with actor=wtA must NOT also write the unscoped global receipt"
    );
}

#[tokio::test]
async fn native_mem_bootstrap_writes_session_audit() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).await.unwrap();
    let graph = Graph::load(store).await.unwrap();
    let graph = Arc::new(tokio::sync::RwLock::new(graph));
    let ctx = test_ctx(dir.path());

    let req = make_request(Command::MemBootstrap(MemBootstrapInput {
        context_files: vec![],
    }));
    let resp = dispatch_v2(&graph, &ctx, req).await;

    // Should return an injection string.
    match resp {
        Response::Ok { data, .. } => {
            assert!(data.is_string(), "MemBootstrap should return a string");
        }
        Response::Err { message, .. } => panic!("expected Ok: {message}"),
    }

    let g = graph.read().await;
    let audit_keys = g.store().scan_keys("audit:session:").await.unwrap();
    assert!(
        !audit_keys.is_empty(),
        "MemBootstrap should produce session-side audit"
    );
}

#[tokio::test]
async fn bootstrap_does_not_unlock_the_gate_or_emit_unpaired_receipt() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).await.unwrap();
    let graph = Graph::load(store).await.unwrap();
    let graph = Arc::new(tokio::sync::RwLock::new(graph));
    let ctx = test_ctx(dir.path());
    let key = "file:src/store/db.rs";

    let req = make_request(Command::MemBootstrap(MemBootstrapInput {
        context_files: vec![key.to_string()],
    }));
    assert!(matches!(
        dispatch_v2(&graph, &ctx, req).await,
        Response::Ok { .. }
    ));

    let g = graph.read().await;
    let already_consulted =
        crate::store::session::check_consulted_recent(g.store(), key, 900, None)
            .await
            .unwrap();
    assert!(
        !already_consulted,
        "bootstrap context must not mint a consultation receipt"
    );

    let file_record = serde_json::json!({
        "value": "Database storage",
        "confidence": {"value": 0.8},
        "quality": {"value": 0.7},
        "staleness": {"value": 0.0, "tier": "fresh"},
        "payload": {"gotcha_keys": ["gotcha:hash-algorithm-frozen-at-sha256"]}
    });
    let gotcha_record = serde_json::json!({
        "value": "Keep HASH_ALGORITHM at sha256",
        "confidence": {"value": 0.8},
        "quality": {"value": 0.7},
        "payload": {"confirmed": true}
    });
    let result = crate::hooks::decide::evaluate(&crate::hooks::decide::EnforcementInput {
        rel_path: "src/store/db.rs".to_string(),
        file_record: Some(file_record),
        gotcha_records: std::collections::HashMap::from([(
            "gotcha:hash-algorithm-frozen-at-sha256".to_string(),
            gotcha_record,
        )]),
        already_consulted,
        file_exists: None,
    });
    assert!(
        matches!(result.decision, crate::hooks::decide::Decision::Deny { .. }),
        "an unconsulted apply-patch target must remain denied after bootstrap"
    );

    let events = crate::store::enforcement::scan_events_since(g.store(), 0)
        .await
        .unwrap();
    assert!(
        events.iter().all(|event| !matches!(
            event.event_type,
            crate::store::enforcement::EnforcementEventType::ReceiptMinted
        )),
        "bootstrap must not create a receipt_minted event without minting a receipt"
    );
}

#[tokio::test]
async fn version_mismatch_cannot_reach_side_effecting_read() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).await.unwrap();
    let graph = Graph::load(store).await.unwrap();
    let graph = Arc::new(tokio::sync::RwLock::new(graph));
    let ctx = test_ctx(dir.path());

    // Version 99 + MemGet: version check must reject before any side effect.
    let req = Request {
        v: 99,
        id: Uuid::new_v4(),
        session: Uuid::new_v4(),
        agent: None,
        cmd: Command::MemGet(MemGetInput {
            key: "file:test".into(),
            actor: None,
        }),
    };
    let resp = dispatch_v2(&graph, &ctx, req).await;
    assert!(matches!(
        resp,
        Response::Err {
            code: ErrorCode::VersionMismatch,
            ..
        }
    ));

    // No consultation receipt should exist.
    let g = graph.read().await;
    let consulted = g.store().get("session:consulted:file:test").await.unwrap();
    assert!(
        consulted.is_none(),
        "version mismatch must not write consultation receipt"
    );
}

#[tokio::test]
async fn session_log_mutation_and_audit_are_both_in_sessions_tree() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).await.unwrap();
    let graph = Graph::load(store).await.unwrap();
    let graph = Arc::new(tokio::sync::RwLock::new(graph));
    let ctx = test_ctx(dir.path());

    let req = make_request(Command::SessionLog(SessionLogInput {
        event: SessionEvent::ComplianceMiss,
        key: "file:src/auth.rs".into(),
        session_id: None,
        actor: None,
        decision_basis_hash: None,
    }));
    let resp = dispatch_v2(&graph, &ctx, req).await;
    assert!(matches!(resp, Response::Ok { .. }));

    let g = graph.read().await;
    // Both the compliance agg and audit should be in sessions tree.
    let compliance_keys = g.store().scan_keys("compliance:miss_").await.unwrap();
    assert!(
        !compliance_keys.is_empty(),
        "SessionLog should write compliance agg"
    );
    let audit_keys = g.store().scan_keys("audit:session:").await.unwrap();
    assert!(
        !audit_keys.is_empty(),
        "SessionLog should write session-side audit"
    );
    // Nothing in knowledge tree.
    let k_audit = g.store().scan_keys("audit:knowledge:").await.unwrap();
    assert!(k_audit.is_empty());
}

#[tokio::test]
async fn session_log_policy_steered_is_analytics_only() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).await.unwrap();
    let graph = Graph::load(store).await.unwrap();
    let graph = Arc::new(tokio::sync::RwLock::new(graph));
    let ctx = test_ctx(dir.path());

    let req = make_request(Command::SessionLog(SessionLogInput {
        event: SessionEvent::PolicySteered,
        key: "policy:steer-test".into(),
        session_id: None,
        actor: None,
        decision_basis_hash: None,
    }));
    let resp = dispatch_v2(&graph, &ctx, req).await;
    assert!(matches!(resp, Response::Ok { .. }));

    let g = graph.read().await;
    let key = sess::today_key("analytics:policy_steer_");
    let record = g.store().get(&key).await.unwrap().expect("steer aggregate");
    let agg = record
        .payload_as::<sess::DailyAgg>()
        .expect("steer aggregate is a DailyAgg Record");
    assert_eq!(agg.count, 1);
    assert_eq!(agg.key_counts.get("policy:steer-test"), Some(&1));
    assert!(
        crate::store::enforcement::scan_enforcement_events(g.store(), 0, u64::MAX)
            .await
            .unwrap()
            .is_empty(),
        "steering must not enter the enforcement chain"
    );
}

/// Regression: SessionLog with CodexShellMiss must produce a
/// `BypassDetected` enforcement event in the hash-chained log, not just
/// a daily aggregate. Smoke finding #128 — pre-fix, the event was
/// invisible to `mati history --enforcement`.
#[tokio::test]
async fn session_log_codex_shell_miss_records_bypass_enforcement_event() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).await.unwrap();
    let graph = Graph::load(store).await.unwrap();
    let graph = Arc::new(tokio::sync::RwLock::new(graph));
    let ctx = test_ctx(dir.path());

    let req = make_request(Command::SessionLog(SessionLogInput {
        event: SessionEvent::CodexShellMiss,
        key: "file:src/cli/repair.rs".into(),
        session_id: None,
        actor: None,
        decision_basis_hash: None,
    }));
    let resp = dispatch_v2(&graph, &ctx, req).await;
    assert!(matches!(resp, Response::Ok { .. }));

    let g = graph.read().await;

    // Daily aggregate (unchanged from pre-fix behavior).
    let agg = g
        .store()
        .scan_keys("compliance:codex_shell_miss_")
        .await
        .unwrap();
    assert!(
        !agg.is_empty(),
        "codex_shell_miss daily agg must be written"
    );

    // NEW: enforcement event in the hash-chained log so `mati history`
    // surfaces it. Pre-fix the scan returned empty.
    let events = crate::store::enforcement::scan_events_since(g.store(), 0)
        .await
        .expect("scan enforcement events");
    assert!(
        !events.is_empty(),
        "CodexShellMiss must record a hash-chained enforcement event \
             (label='bypass') — regression for smoke finding #128"
    );

    let evt = &events[0];
    assert_eq!(
        evt.agent_type, "codex",
        "codex-post-bash event must attribute agent=codex, got: {evt:?}"
    );
    assert_eq!(
        evt.subject_key, "file:src/cli/repair.rs",
        "subject_key must match input.key"
    );
    assert!(
        matches!(
            evt.event_type,
            crate::store::enforcement::EnforcementEventType::BypassDetected
        ),
        "event_type must be BypassDetected, got: {:?}",
        evt.event_type
    );

    // Sanity: the CLI label that `mati history --enforcement` would show
    // for this event is "bypass" (per src/store/enforcement/metrics.rs:256-257).
    assert_eq!(
        crate::store::enforcement::event_type_label(&evt.event_type),
        "bypass"
    );
}

/// A Codex PRE-hook block is a DENY. `fire_events` routed
/// `HookEvent::CodexShellBlocked` onto `SessionEvent::CodexShellMiss`, so
/// every Codex block landed as `BypassDetected` and `mati stats` reported
/// zero Codex denials even while Codex was blocking the action.
#[tokio::test]
async fn session_log_codex_shell_blocked_records_a_deny() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).await.unwrap();
    let graph = Arc::new(tokio::sync::RwLock::new(Graph::load(store).await.unwrap()));
    let ctx = test_ctx(dir.path());

    let req = make_request(Command::SessionLog(SessionLogInput {
        event: SessionEvent::CodexShellBlocked,
        key: "file:src/cli/repair.rs".into(),
        session_id: None,
        actor: None,
        decision_basis_hash: None,
    }));
    assert!(matches!(
        dispatch_v2(&graph, &ctx, req).await,
        Response::Ok { .. }
    ));

    let g = graph.read().await;
    let events = crate::store::enforcement::scan_events_since(g.store(), 0)
        .await
        .unwrap();
    assert_eq!(events.len(), 1);
    let evt = &events[0];
    assert!(
        matches!(
            evt.event_type,
            crate::store::enforcement::EnforcementEventType::Deny
        ),
        "a Codex pre-hook block must record Deny, got: {:?}",
        evt.event_type
    );
    assert_eq!(evt.agent_type, "codex");
    assert_eq!(evt.decision_reason_code, "codex_pre_consult_blocked");
    assert_eq!(
        crate::store::enforcement::aggregate_event_counts(&events).denials,
        1,
        "the block must count as a denial in `mati stats`"
    );
    // The post-bash bypass aggregate must stay clean: nothing was bypassed.
    assert!(g
        .store()
        .scan_keys("compliance:codex_shell_miss_")
        .await
        .unwrap()
        .is_empty());
}

/// `receipt_minted` must name the receipt it minted, and the
/// `allow_after_receipt` it later authorizes must name the same one.
/// Both were `None` on every event in the log.
#[tokio::test]
async fn receipt_id_links_a_mint_to_the_allow_it_authorizes() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).await.unwrap();
    let graph = Arc::new(tokio::sync::RwLock::new(Graph::load(store).await.unwrap()));
    let ctx = test_ctx(dir.path());

    let key = "file:src/main.rs";
    let mint = make_request(Command::ConsultationHit(ConsultationHitInput {
        key: key.into(),
        capture_fingerprint: false,
        actor: None,
        session_id: None,
        agent_id: None,
        decision_basis_hash: None,
        source: None,
    }));
    assert!(matches!(
        dispatch_v2(&graph, &ctx, mint).await,
        Response::Ok { .. }
    ));

    let allow = make_request(Command::SessionLog(SessionLogInput {
        event: SessionEvent::ComplianceHit,
        key: key.into(),
        session_id: None,
        actor: None,
        decision_basis_hash: None,
    }));
    assert!(matches!(
        dispatch_v2(&graph, &ctx, allow).await,
        Response::Ok { .. }
    ));

    let g = graph.read().await;
    let stored = crate::store::session::receipt_id_in_force(g.store(), key, None)
        .await
        .expect("minted receipt must carry an id");
    let events = crate::store::enforcement::scan_events_since(g.store(), 0)
        .await
        .unwrap();
    let minted = events
        .iter()
        .find(|e| {
            matches!(
                e.event_type,
                crate::store::enforcement::EnforcementEventType::ReceiptMinted
            )
        })
        .expect("receipt_minted event");
    let allowed = events
        .iter()
        .find(|e| {
            matches!(
                e.event_type,
                crate::store::enforcement::EnforcementEventType::AllowAfterReceipt
            )
        })
        .expect("allow_after_receipt event");
    assert_eq!(minted.receipt_id.as_deref(), Some(stored.as_str()));
    assert_eq!(allowed.receipt_id.as_deref(), Some(stored.as_str()));
}

/// The gate's `decision_basis_hash` must reach the chained event. It was
/// `None` on all 1472 events despite `compute_decision_basis_hash` existing.
#[tokio::test]
async fn deny_records_the_decision_basis_it_was_made_on() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).await.unwrap();
    let graph = Arc::new(tokio::sync::RwLock::new(Graph::load(store).await.unwrap()));
    let ctx = test_ctx(dir.path());

    let basis = crate::store::enforcement::compute_decision_basis_hash(&[(
        "gotcha:no-raw-put",
        &serde_json::json!({"value": "Never call put_raw", "confidence": {"value": 0.9}}),
    )]);
    let req = make_request(Command::SessionLog(SessionLogInput {
        event: SessionEvent::ComplianceMiss,
        key: "file:src/main.rs".into(),
        session_id: Some("sess-1".into()),
        actor: None,
        decision_basis_hash: Some(basis.clone()),
    }));
    assert!(matches!(
        dispatch_v2(&graph, &ctx, req).await,
        Response::Ok { .. }
    ));

    let g = graph.read().await;
    let events = crate::store::enforcement::scan_events_since(g.store(), 0)
        .await
        .unwrap();
    assert_eq!(
        events[0].decision_basis_hash.as_deref(),
        Some(basis.as_str())
    );
    assert_eq!(events[0].agent_session.as_deref(), Some("sess-1"));
}

/// A wrapped, unclassifiable db-client introspection command (e.g.
/// `rtk psql -h prod -c "\d orders"`) diagnoses the same way as
/// `CodexShellMiss`: a `BypassDetected` event in the hash-chained log,
/// tagged with its own reason code so it is distinguishable from an
/// actual bypass. Nothing was denied by this event — it records a
/// receipt that could never mint, not an access that slipped through.
#[tokio::test]
async fn session_log_wrapped_db_client_miss_records_diagnosable_event() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).await.unwrap();
    let graph = Graph::load(store).await.unwrap();
    let graph = Arc::new(tokio::sync::RwLock::new(graph));
    let ctx = test_ctx(dir.path());

    let req = make_request(Command::SessionLog(SessionLogInput {
        event: SessionEvent::WrappedDbClientMiss,
        key: "enforcement:wrapped_client:rtk".into(),
        session_id: None,
        actor: None,
        decision_basis_hash: None,
    }));
    let resp = dispatch_v2(&graph, &ctx, req).await;
    assert!(matches!(resp, Response::Ok { .. }));

    let g = graph.read().await;

    let agg = g
        .store()
        .scan_keys("compliance:wrapped_db_client_miss_")
        .await
        .unwrap();
    assert!(
        !agg.is_empty(),
        "wrapped_db_client_miss daily agg must be written"
    );

    let events = crate::store::enforcement::scan_events_since(g.store(), 0)
        .await
        .expect("scan enforcement events");
    assert_eq!(
        events.len(),
        1,
        "exactly one diagnosable event, no correlation state"
    );

    let evt = &events[0];
    assert_eq!(evt.agent_type, "claude");
    assert_eq!(evt.subject_key, "enforcement:wrapped_client:rtk");
    assert!(matches!(
        evt.subject_kind,
        crate::store::enforcement::SubjectKind::System
    ));
    assert!(matches!(
        evt.event_type,
        crate::store::enforcement::EnforcementEventType::BypassDetected
    ));
    assert_eq!(evt.decision_reason_code, "wrapped_client_unclassifiable");
    assert_eq!(
        crate::store::enforcement::event_type_label(&evt.event_type),
        "bypass"
    );
}

#[tokio::test]
async fn v2_session_mismatch_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).await.unwrap();
    let graph = Graph::load(store).await.unwrap();
    let graph = Arc::new(tokio::sync::RwLock::new(graph));
    let ctx = test_ctx(dir.path());

    // Construct a request with a different session UUID.
    let req = Request {
        v: PROTOCOL_VERSION,
        id: Uuid::new_v4(),
        session: Uuid::new_v4(), // does NOT match test_session()
        agent: None,
        cmd: Command::Ping,
    };
    let resp = dispatch_v2(&graph, &ctx, req).await;

    match resp {
        Response::Err { code, message, .. } => {
            assert_eq!(code, ErrorCode::SessionMismatch);
            assert!(
                message.contains("re-read daemon metadata"),
                "error should guide the client to retry: {message}"
            );
        }
        Response::Ok { .. } => panic!("expected SessionMismatch error"),
    }
}

#[tokio::test]
async fn v2_matching_session_passes_fence() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).await.unwrap();
    let graph = Graph::load(store).await.unwrap();
    let graph = Arc::new(tokio::sync::RwLock::new(graph));
    let ctx = test_ctx(dir.path());

    // make_request uses test_session() which matches ctx.daemon_session.
    let req = make_request(Command::Ping);
    let resp = dispatch_v2(&graph, &ctx, req).await;

    match resp {
        Response::Ok { data, .. } => {
            assert_eq!(data, serde_json::json!("pong"));
        }
        Response::Err { message, .. } => panic!("expected Ok, got Err: {message}"),
    }
}

/// An edit is not a consultation. Minting a receipt here let an edit that
/// slipped through a fail-open suppress every later deny on that file, and
/// kept refreshing the TTL the `claude-pre-edit` backstop keys on.
#[tokio::test]
async fn file_edit_hook_mints_no_consultation_receipt() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).await.unwrap();
    let graph = Graph::load(store).await.unwrap();
    let graph = Arc::new(tokio::sync::RwLock::new(graph));
    let ctx = test_ctx(dir.path());

    // Create a dummy file so reparse doesn't need real filesystem.
    let test_path = dir.path().join("test.rs");
    std::fs::write(&test_path, "fn main() {}").unwrap();

    let req = make_request(Command::FileEditHook(FileEditHookInput {
        path: "test.rs".into(),
    }));
    let resp = dispatch_v2(&graph, &ctx, req).await;
    assert!(matches!(resp, Response::Ok { .. }));

    let g = graph.read().await;

    // Session-side audit must exist (from the activity substep).
    let audit_keys = g.store().scan_keys("audit:session:").await.unwrap();
    assert!(
        !audit_keys.is_empty(),
        "FileEditHook activity substep must produce session-side audit"
    );

    // No consultation receipt: editing a file never proves the agent read
    // its record.
    let receipts = g.store().scan_keys("session:consulted:").await.unwrap();
    assert!(
        receipts.is_empty(),
        "an edit must mint no consultation receipt, got {receipts:?}"
    );

    // Daily hit agg must exist (staged + committed atomically with audit).
    let hit_keys = g.store().scan_keys("analytics:hit_").await.unwrap();
    assert!(
        !hit_keys.is_empty(),
        "FileEditHook activity substep must write daily hit agg"
    );

    // Verify the audit entry is for the activity substep.
    let txn = g
        .store()
        .sessions_tree()
        .begin_with_mode(surrealkv::Mode::ReadOnly)
        .unwrap();
    let raw = txn.get(audit_keys[0].as_bytes()).unwrap().unwrap();
    let entry: AuditEntry = rmp_serde::from_slice(&raw).unwrap();
    assert_eq!(entry.command_kind, "file_edit_hook:activity");
    assert!(entry.accepted);
}

/// ConfigGet routes through the dedicated native dispatcher and returns
/// the default value (`advisory`) when nothing has been written yet.
#[tokio::test]
async fn config_get_returns_default_enforcement_mode() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).await.unwrap();
    let graph = Graph::load(store).await.unwrap();
    let graph = Arc::new(tokio::sync::RwLock::new(graph));
    let ctx = test_ctx(dir.path());

    let req = make_request(Command::ConfigGet(ConfigGetInput {
        key: "audit.write_durability".into(),
    }));
    let resp = dispatch_v2(&graph, &ctx, req).await;

    match resp {
        Response::Ok { data, .. } => assert_eq!(data, serde_json::json!("best_effort")),
        Response::Err { message, .. } => panic!("expected Ok, got Err: {message}"),
    }
}

#[tokio::test]
async fn policy_mode_defaults_strict_and_round_trips() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).await.unwrap();
    let graph = Graph::load(store).await.unwrap();
    let graph = Arc::new(tokio::sync::RwLock::new(graph));
    let ctx = test_ctx(dir.path());

    let get = make_request(Command::ConfigGet(ConfigGetInput {
        key: "policy.mode".into(),
    }));
    assert!(matches!(
        dispatch_v2(&graph, &ctx, get).await,
        Response::Ok { data, .. } if data == "strict"
    ));

    let set = make_request(Command::ConfigSet(ConfigSetInput {
        key: "policy.mode".into(),
        value: "advisory".into(),
    }));
    assert!(matches!(
        dispatch_v2(&graph, &ctx, set).await,
        Response::Ok { data, .. } if data == serde_json::json!({"old": "strict"})
    ));
}

#[tokio::test]
async fn policy_mode_rejects_invalid_values() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).await.unwrap();
    let graph = Graph::load(store).await.unwrap();
    let graph = Arc::new(tokio::sync::RwLock::new(graph));
    let ctx = test_ctx(dir.path());
    let req = make_request(Command::ConfigSet(ConfigSetInput {
        key: "policy.mode".into(),
        value: "best_effort".into(),
    }));
    assert!(matches!(
        dispatch_v2(&graph, &ctx, req).await,
        Response::Err {
            code: ErrorCode::ValidationFailed,
            ..
        }
    ));
}

/// ConfigSet writes the value via the daemon path; the next ConfigGet
/// reflects the new value end-to-end through dispatch_v2.
#[tokio::test]
async fn config_set_then_get_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).await.unwrap();
    let graph = Graph::load(store).await.unwrap();
    let graph = Arc::new(tokio::sync::RwLock::new(graph));
    let ctx = test_ctx(dir.path());

    let set_req = make_request(Command::ConfigSet(ConfigSetInput {
        key: "audit.write_durability".into(),
        value: "strict".into(),
    }));
    let set_resp = dispatch_v2(&graph, &ctx, set_req).await;
    match set_resp {
        Response::Ok { data, .. } => {
            assert_eq!(data, serde_json::json!({ "old": "best_effort" }));
        }
        Response::Err { message, .. } => panic!("expected Ok, got Err: {message}"),
    }

    let get_req = make_request(Command::ConfigGet(ConfigGetInput {
        key: "audit.write_durability".into(),
    }));
    let get_resp = dispatch_v2(&graph, &ctx, get_req).await;
    match get_resp {
        Response::Ok { data, .. } => assert_eq!(data, serde_json::json!("strict")),
        Response::Err { message, .. } => panic!("expected Ok, got Err: {message}"),
    }
}

/// Invalid enforcement mode value is rejected with ValidationFailed —
/// the daemon never persists garbage values.
#[tokio::test]
async fn config_set_rejects_invalid_enforcement_mode() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).await.unwrap();
    let graph = Graph::load(store).await.unwrap();
    let graph = Arc::new(tokio::sync::RwLock::new(graph));
    let ctx = test_ctx(dir.path());

    let req = make_request(Command::ConfigSet(ConfigSetInput {
        key: "audit.write_durability".into(),
        value: "paranoid".into(),
    }));
    let resp = dispatch_v2(&graph, &ctx, req).await;
    match resp {
        Response::Err { code, .. } => assert_eq!(code, ErrorCode::ValidationFailed),
        Response::Ok { .. } => panic!("expected Err, got Ok"),
    }
}

/// Unknown config key surfaces ValidationFailed on both get and set.
#[tokio::test]
async fn config_unknown_key_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).await.unwrap();
    let graph = Graph::load(store).await.unwrap();
    let graph = Arc::new(tokio::sync::RwLock::new(graph));
    let ctx = test_ctx(dir.path());

    let get_req = make_request(Command::ConfigGet(ConfigGetInput {
        key: "nope.nope".into(),
    }));
    match dispatch_v2(&graph, &ctx, get_req).await {
        Response::Err { code, .. } => assert_eq!(code, ErrorCode::ValidationFailed),
        Response::Ok { .. } => panic!("expected ValidationFailed for unknown get key"),
    }

    let set_req = make_request(Command::ConfigSet(ConfigSetInput {
        key: "nope.nope".into(),
        value: "x".into(),
    }));
    match dispatch_v2(&graph, &ctx, set_req).await {
        Response::Err { code, .. } => assert_eq!(code, ErrorCode::ValidationFailed),
        Response::Ok { .. } => panic!("expected ValidationFailed for unknown set key"),
    }
}

#[tokio::test]
async fn subagent_edge_records_nested_lineage() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).await.unwrap();
    let graph = Graph::load(store).await.unwrap();
    let graph = Arc::new(tokio::sync::RwLock::new(graph));
    let ctx = test_ctx(dir.path());

    let req = make_request(Command::SubagentEdge(SubagentEdgeInput {
        child_agent_id: Some("child-1".into()),
        parent_agent_id: Some("parent-1".into()),
        session_id: Some("sess-1".into()),
        agent_type: Some("general-purpose".into()),
    }));
    assert!(matches!(
        dispatch_v2(&graph, &ctx, req).await,
        Response::Ok { .. }
    ));

    let g = graph.read().await;
    let events = crate::store::enforcement::scan_events_since(g.store(), 0)
        .await
        .unwrap();
    let edge = events
        .iter()
        .find(|e| {
            matches!(
                e.event_type,
                crate::store::enforcement::EnforcementEventType::SubagentEdge
            )
        })
        .expect("a SubagentEdge event must be recorded");

    // The child is the actor; the parent is the spawner. Both are carried so the
    // audit can walk the tree; parent_agent_id is hashed by the v4 canonical form.
    assert_eq!(edge.agent_id.as_deref(), Some("child-1"));
    assert_eq!(edge.parent_agent_id.as_deref(), Some("parent-1"));
    assert_eq!(edge.agent_session.as_deref(), Some("sess-1"));
    assert_eq!(edge.subject_key, "child-1");
}

#[tokio::test]
async fn subagent_edge_without_parent_is_noop() {
    // A root-session spawn (no parent) is already recorded by SubagentSpawned;
    // the edge handler must not double-record it.
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).await.unwrap();
    let graph = Graph::load(store).await.unwrap();
    let graph = Arc::new(tokio::sync::RwLock::new(graph));
    let ctx = test_ctx(dir.path());

    let req = make_request(Command::SubagentEdge(SubagentEdgeInput {
        child_agent_id: Some("child-1".into()),
        parent_agent_id: None,
        session_id: Some("sess-1".into()),
        agent_type: Some("general-purpose".into()),
    }));
    assert!(matches!(
        dispatch_v2(&graph, &ctx, req).await,
        Response::Ok { .. }
    ));

    let g = graph.read().await;
    let events = crate::store::enforcement::scan_events_since(g.store(), 0)
        .await
        .unwrap();
    assert!(
        !events.iter().any(|e| matches!(
            e.event_type,
            crate::store::enforcement::EnforcementEventType::SubagentEdge
        )),
        "no SubagentEdge event should be recorded without a parent"
    );
}
