use crate::store::AgentKind;
use uuid::Uuid;

use super::*;

// ── Wire / protocol ─────────────────────────────────────────────────

/// γ-C3a: QueryMode owns string-to-enum validation at the protocol
/// boundary now that tools::mem_query no longer accepts a free-form
/// string. Pin the unknown-variant rejection so future schema changes
/// don't silently accept invalid modes.
#[test]
fn query_mode_deserialize_rejects_unknown_variant() {
    let result: Result<QueryMode, _> = serde_json::from_str("\"invalid_mode\"");
    assert!(
        result.is_err(),
        "QueryMode deserialization must reject unknown variants, got: {result:?}"
    );
}

#[test]
fn query_mode_deserialize_accepts_all_known_variants() {
    // Snake-case wire form per `#[serde(rename_all = "snake_case")]`.
    for variant in &[
        "text",
        "tag",
        "graph",
        "dir_gotchas",
        "semantic",
        "policy_observations",
        "policy_activity",
        "analytics",
    ] {
        let json = format!("\"{variant}\"");
        let result: Result<QueryMode, _> = serde_json::from_str(&json);
        assert!(
            result.is_ok(),
            "QueryMode must accept {variant:?}, got: {result:?}"
        );
    }
}

#[test]
fn valid_v2_ping_request_decodes() {
    let json = serde_json::json!({
        "v": 2,
        "id": "550e8400-e29b-41d4-a716-446655440000",
        "session": "660e8400-e29b-41d4-a716-446655440000",
        "cmd": { "type": "ping" }
    });
    let req: Request = serde_json::from_value(json).unwrap();
    assert_eq!(req.v, PROTOCOL_VERSION);
    assert!(matches!(req.cmd, Command::Ping));
}

#[test]
fn valid_v2_get_request_decodes() {
    let json = serde_json::json!({
        "v": 2,
        "id": "550e8400-e29b-41d4-a716-446655440000",
        "session": "660e8400-e29b-41d4-a716-446655440000",
        "cmd": { "type": "get", "key": "file:src/main.rs" }
    });
    let req: Request = serde_json::from_value(json).unwrap();
    match req.cmd {
        Command::Get(input) => assert_eq!(input.key, "file:src/main.rs"),
        _ => panic!("expected Get"),
    }
}

#[test]
fn valid_gotcha_upsert_decodes() {
    let json = serde_json::json!({
        "v": 2,
        "id": "550e8400-e29b-41d4-a716-446655440000",
        "session": "660e8400-e29b-41d4-a716-446655440000",
        "cmd": {
            "type": "gotcha_upsert",
            "key": "gotcha:stripe-idempotency",
            "rule": "Always include an idempotency key",
            "reason": "Stripe retries without it cause double charges",
            "severity": "high",
            "affected_files": ["src/payments/stripe.rs"],
            "tags": ["payments", "stripe"]
        }
    });
    let req: Request = serde_json::from_value(json).unwrap();
    match req.cmd {
        Command::GotchaUpsert(input) => {
            assert_eq!(input.key, "gotcha:stripe-idempotency");
            assert_eq!(input.severity, Severity::High);
            assert_eq!(input.affected_files, vec!["src/payments/stripe.rs"]);
            assert_eq!(input.priority, Priority::Normal); // default
        }
        _ => panic!("expected GotchaUpsert"),
    }
}

#[test]
fn valid_decision_upsert_decodes() {
    let json = serde_json::json!({
        "v": 2,
        "id": "550e8400-e29b-41d4-a716-446655440000",
        "session": "660e8400-e29b-41d4-a716-446655440000",
        "cmd": {
            "type": "decision_upsert",
            "slug": "unified-retry-strategy",
            "value": "We use exponential backoff because linear retry overloads downstream",
            "summary": "Exponential backoff for all retries",
            "rationale": "Linear retry caused cascading failures in prod 2024-01"
        }
    });
    let req: Request = serde_json::from_value(json).unwrap();
    match req.cmd {
        Command::DecisionUpsert(input) => {
            assert_eq!(input.slug, "unified-retry-strategy");
            assert!(!input.rationale.is_empty());
        }
        _ => panic!("expected DecisionUpsert"),
    }
}

#[test]
fn valid_session_log_decodes() {
    let json = serde_json::json!({
        "v": 2,
        "id": "550e8400-e29b-41d4-a716-446655440000",
        "session": "660e8400-e29b-41d4-a716-446655440000",
        "cmd": {
            "type": "session_log",
            "event": "compliance_miss",
            "key": "file:src/main.rs"
        }
    });
    let req: Request = serde_json::from_value(json).unwrap();
    match req.cmd {
        Command::SessionLog(input) => {
            assert_eq!(input.event, SessionEvent::ComplianceMiss);
            assert_eq!(input.key, "file:src/main.rs");
        }
        _ => panic!("expected SessionLog"),
    }
}

#[test]
fn valid_file_enrich_decodes() {
    let json = serde_json::json!({
        "v": 2,
        "id": "550e8400-e29b-41d4-a716-446655440000",
        "session": "660e8400-e29b-41d4-a716-446655440000",
        "cmd": {
            "type": "file_enrich",
            "path": "src/store/db.rs",
            "purpose": "Own the storage boundary for all SurrealKV operations",
            "entry_points": ["open", "put", "get"],
            "decision_keys": ["decision:storage-engine"]
        }
    });
    let req: Request = serde_json::from_value(json).unwrap();
    match req.cmd {
        Command::FileEnrich(input) => {
            assert_eq!(input.path, "src/store/db.rs");
            assert_eq!(input.entry_points.len(), 3);
            assert!(input.todos.is_empty()); // default
        }
        _ => panic!("expected FileEnrich"),
    }
}

// ── Rejection tests ─────────────────────────────────────────────────

#[test]
fn bad_version_still_decodes_for_error_handling() {
    // v=99 is parseable but the handler must reject it after decode.
    let json = serde_json::json!({
        "v": 99,
        "id": "550e8400-e29b-41d4-a716-446655440000",
        "session": "660e8400-e29b-41d4-a716-446655440000",
        "cmd": { "type": "ping" }
    });
    let req: Request = serde_json::from_value(json).unwrap();
    assert_ne!(req.v, PROTOCOL_VERSION);
}

#[test]
fn unknown_field_in_request_rejected() {
    let json = serde_json::json!({
        "v": 2,
        "id": "550e8400-e29b-41d4-a716-446655440000",
        "session": "660e8400-e29b-41d4-a716-446655440000",
        "cmd": { "type": "ping" },
        "extra_field": true
    });
    let result = serde_json::from_value::<Request>(json);
    assert!(result.is_err(), "unknown top-level field must be rejected");
}

#[test]
fn unknown_field_in_command_args_rejected() {
    let json = serde_json::json!({
        "v": 2,
        "id": "550e8400-e29b-41d4-a716-446655440000",
        "session": "660e8400-e29b-41d4-a716-446655440000",
        "cmd": { "type": "get", "key": "file:foo", "smuggled": true }
    });
    let result = serde_json::from_value::<Request>(json);
    assert!(
        result.is_err(),
        "unknown field in command args must be rejected"
    );
}

#[test]
fn unknown_command_type_rejected() {
    let json = serde_json::json!({
        "v": 2,
        "id": "550e8400-e29b-41d4-a716-446655440000",
        "session": "660e8400-e29b-41d4-a716-446655440000",
        "cmd": { "type": "raw_put", "key": "gotcha:x", "value": "hacked" }
    });
    let result = serde_json::from_value::<Request>(json);
    assert!(result.is_err(), "unknown command type must be rejected");
}

#[test]
fn malformed_uuid_rejected() {
    let json = serde_json::json!({
        "v": 2,
        "id": "not-a-uuid",
        "session": "660e8400-e29b-41d4-a716-446655440000",
        "cmd": { "type": "ping" }
    });
    let result = serde_json::from_value::<Request>(json);
    assert!(result.is_err(), "malformed UUID must be rejected");
}

#[test]
fn missing_session_rejected() {
    let json = serde_json::json!({
        "v": 2,
        "id": "550e8400-e29b-41d4-a716-446655440000",
        "cmd": { "type": "ping" }
    });
    let result = serde_json::from_value::<Request>(json);
    assert!(result.is_err(), "missing session UUID must be rejected");
}

/// Confidence, quality, lifecycle and timestamps stay daemon-derived: they
/// have no field on the DTO, so `deny_unknown_fields` refuses them.
///
/// `confirmed` is deliberately not on that list any more. It crosses the
/// wire so `mati gotcha add` behaves the same with and without a daemon,
/// and `handle_gotcha_upsert` gates it on `source: "developer_manual"` —
/// see `dispatch_v2::tests::only_developer_originated_upserts_may_arrive_confirmed`.
#[test]
fn gotcha_upsert_rejects_server_owned_fields() {
    let with_field = |name: &str, value: serde_json::Value| {
        let mut cmd = serde_json::json!({
            "type": "gotcha_upsert",
            "key": "gotcha:test",
            "rule": "test rule",
            "reason": "test reason",
            "severity": "normal"
        });
        cmd[name] = value;
        serde_json::from_value::<Request>(serde_json::json!({
            "v": 2,
            "id": "550e8400-e29b-41d4-a716-446655440000",
            "session": "660e8400-e29b-41d4-a716-446655440000",
            "cmd": cmd
        }))
    };

    for name in ["confidence", "quality", "lifecycle", "created_at"] {
        assert!(
            with_field(name, serde_json::json!(1)).is_err(),
            "server-owned field `{name}` must be rejected"
        );
    }
    assert!(
        with_field("confirmed", serde_json::json!(true)).is_ok(),
        "`confirmed` carries developer intent and must parse"
    );
}

#[test]
fn file_enrich_rejects_gotcha_keys() {
    // gotcha_keys is daemon-managed, must not cross the wire
    let json = serde_json::json!({
        "v": 2,
        "id": "550e8400-e29b-41d4-a716-446655440000",
        "session": "660e8400-e29b-41d4-a716-446655440000",
        "cmd": {
            "type": "file_enrich",
            "path": "src/main.rs",
            "purpose": "entry point",
            "gotcha_keys": ["gotcha:smuggled"]
        }
    });
    let result = serde_json::from_value::<Request>(json);
    assert!(
        result.is_err(),
        "daemon-managed field `gotcha_keys` must be rejected"
    );
}

#[test]
fn file_enrich_rejects_imports() {
    // imports is daemon-derived from tree-sitter
    let json = serde_json::json!({
        "v": 2,
        "id": "550e8400-e29b-41d4-a716-446655440000",
        "session": "660e8400-e29b-41d4-a716-446655440000",
        "cmd": {
            "type": "file_enrich",
            "path": "src/main.rs",
            "purpose": "entry point",
            "imports": ["std::io"]
        }
    });
    let result = serde_json::from_value::<Request>(json);
    assert!(
        result.is_err(),
        "daemon-derived field `imports` must be rejected"
    );
}

#[test]
fn invalid_severity_rejected() {
    let json = serde_json::json!({
        "v": 2,
        "id": "550e8400-e29b-41d4-a716-446655440000",
        "session": "660e8400-e29b-41d4-a716-446655440000",
        "cmd": {
            "type": "gotcha_upsert",
            "key": "gotcha:test",
            "rule": "test",
            "reason": "test",
            "severity": "EXTREME"
        }
    });
    let result = serde_json::from_value::<Request>(json);
    assert!(
        result.is_err(),
        "invalid severity enum value must be rejected"
    );
}

#[test]
fn invalid_session_event_rejected() {
    let json = serde_json::json!({
        "v": 2,
        "id": "550e8400-e29b-41d4-a716-446655440000",
        "session": "660e8400-e29b-41d4-a716-446655440000",
        "cmd": {
            "type": "session_log",
            "event": "hit",
            "key": "file:foo"
        }
    });
    let result = serde_json::from_value::<Request>(json);
    assert!(
        result.is_err(),
        "hit is not a SessionEvent variant — must use consultation_hit command"
    );
}

// ── Response serialization ──────────────────────────────────────────

#[test]
fn ok_response_serializes() {
    let id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
    let resp = Response::ok(id, serde_json::json!({"pong": true}));
    let json = serde_json::to_value(&resp).unwrap();
    assert_eq!(json["status"], "ok");
    assert_eq!(json["data"]["pong"], true);
}

#[test]
fn err_response_serializes_with_code() {
    let id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
    let resp = Response::err(id, ErrorCode::ValidationFailed, "key must not be empty");
    let json = serde_json::to_value(&resp).unwrap();
    assert_eq!(json["status"], "err");
    assert_eq!(json["code"], "validation_failed");
    assert_eq!(json["message"], "key must not be empty");
}

#[test]
fn error_code_roundtrips() {
    let codes = vec![
        ErrorCode::VersionMismatch,
        ErrorCode::FrameTooLarge,
        ErrorCode::MalformedRequest,
        ErrorCode::SessionMismatch,
        ErrorCode::ValidationFailed,
        ErrorCode::NotFound,
        ErrorCode::Conflict,
        ErrorCode::InvalidStateTransition,
        ErrorCode::StoreError,
        ErrorCode::Internal,
    ];
    for code in codes {
        let json = serde_json::to_value(&code).unwrap();
        let back: ErrorCode = serde_json::from_value(json).unwrap();
        assert_eq!(back, code);
    }
}

// ── Unit variant commands ───────────────────────────────────────────

#[test]
fn session_flush_decodes() {
    let json = serde_json::json!({
        "v": 2,
        "id": "550e8400-e29b-41d4-a716-446655440000",
        "session": "660e8400-e29b-41d4-a716-446655440000",
        "cmd": { "type": "session_flush" }
    });
    let req: Request = serde_json::from_value(json).unwrap();
    assert!(matches!(req.cmd, Command::SessionFlush));
}

#[test]
fn hook_evaluate_v1_to_v2_preserves_actor() {
    // Regression (per-actor enforcement): the client→daemon round-trip is
    // v1 args → v1_to_v2_command → typed Command. `actor` must survive — it
    // was once dropped here, and HookEvaluateInput's deny_unknown_fields even
    // made a partial fix fail-open. Live-E2E caught it; this locks it in.
    let v1_args = serde_json::json!({
        "file_key": "file:x", "include_recent": false, "actor": "agentZ"
    });
    let v2 = v1_to_v2_command("hook_evaluate", &v1_args);
    let cmd: Command =
        serde_json::from_value(v2).expect("v1->v2 hook_evaluate must deserialize WITH actor");
    match cmd {
        Command::HookEvaluate(i) => assert_eq!(i.actor.as_deref(), Some("agentZ")),
        other => panic!("expected HookEvaluate, got {other:?}"),
    }
}

#[test]
fn session_harvest_decodes() {
    let json = serde_json::json!({
        "v": 2,
        "id": "550e8400-e29b-41d4-a716-446655440000",
        "session": "660e8400-e29b-41d4-a716-446655440000",
        "cmd": { "type": "session_harvest" }
    });
    let req: Request = serde_json::from_value(json).unwrap();
    // An older hook sends no `worktree`; it decodes to `None` (backward compat).
    assert!(matches!(
        req.cmd,
        Command::SessionHarvest(SessionHarvestInput { worktree: None })
    ));
}

#[test]
fn session_harvest_decodes_with_worktree() {
    let json = serde_json::json!({
        "v": 2,
        "id": "550e8400-e29b-41d4-a716-446655440000",
        "session": "660e8400-e29b-41d4-a716-446655440000",
        "cmd": { "type": "session_harvest", "worktree": "deadbeef" }
    });
    let req: Request = serde_json::from_value(json).unwrap();
    match req.cmd {
        Command::SessionHarvest(input) => assert_eq!(input.worktree.as_deref(), Some("deadbeef")),
        other => panic!("expected SessionHarvest, got {other:?}"),
    }
}

#[test]
fn subagent_harvest_decodes_with_defaults() {
    // Only `summary` is required; the rest default to None.
    let json = serde_json::json!({
        "v": 2,
        "id": "550e8400-e29b-41d4-a716-446655440000",
        "session": "660e8400-e29b-41d4-a716-446655440000",
        "cmd": { "type": "subagent_harvest", "summary": "did the thing" }
    });
    let req: Request = serde_json::from_value(json).unwrap();
    match req.cmd {
        Command::SubagentHarvest(input) => {
            assert_eq!(input.summary, "did the thing");
            assert!(input.agent_id.is_none());
            assert!(input.session_id.is_none());
        }
        other => panic!("expected SubagentHarvest, got {other:?}"),
    }
}

#[test]
fn subagent_spawned_decodes_with_defaults() {
    let json = serde_json::json!({
        "v": 2,
        "id": "550e8400-e29b-41d4-a716-446655440000",
        "session": "660e8400-e29b-41d4-a716-446655440000",
        "cmd": { "type": "subagent_spawned", "agent_id": "sub-1", "session_id": "sess-1" }
    });
    let req: Request = serde_json::from_value(json).unwrap();
    match req.cmd {
        Command::SubagentSpawned(input) => {
            assert_eq!(input.agent_id.as_deref(), Some("sub-1"));
            assert_eq!(input.session_id.as_deref(), Some("sess-1"));
            assert!(input.agent_type.is_none());
        }
        other => panic!("expected SubagentSpawned, got {other:?}"),
    }
}

#[test]
fn session_clear_consults_decodes() {
    let json = serde_json::json!({
        "v": 2,
        "id": "550e8400-e29b-41d4-a716-446655440000",
        "session": "660e8400-e29b-41d4-a716-446655440000",
        "cmd": { "type": "session_clear_consults" }
    });
    let req: Request = serde_json::from_value(json).unwrap();
    assert!(matches!(req.cmd, Command::SessionClearConsults));
}

#[test]
fn dev_note_upsert_create_mode() {
    let json = serde_json::json!({
        "v": 2,
        "id": "550e8400-e29b-41d4-a716-446655440000",
        "session": "660e8400-e29b-41d4-a716-446655440000",
        "cmd": {
            "type": "dev_note_upsert",
            "text": "Remember to update the changelog"
        }
    });
    let req: Request = serde_json::from_value(json).unwrap();
    match req.cmd {
        Command::DevNoteUpsert(input) => {
            assert!(input.key.is_none()); // create mode
            assert_eq!(input.text, "Remember to update the changelog");
        }
        _ => panic!("expected DevNoteUpsert"),
    }
}

#[test]
fn dev_note_upsert_update_mode() {
    let json = serde_json::json!({
        "v": 2,
        "id": "550e8400-e29b-41d4-a716-446655440000",
        "session": "660e8400-e29b-41d4-a716-446655440000",
        "cmd": {
            "type": "dev_note_upsert",
            "key": "dev_note:changelog-reminder-1712345678",
            "text": "Updated: remember to update changelog AND version"
        }
    });
    let req: Request = serde_json::from_value(json).unwrap();
    match req.cmd {
        Command::DevNoteUpsert(input) => {
            assert_eq!(
                input.key.as_deref(),
                Some("dev_note:changelog-reminder-1712345678")
            );
        }
        _ => panic!("expected DevNoteUpsert"),
    }
}

// ── Command helper tests ────────────────────────────────────────────

#[test]
fn command_kind_covers_all_variants() {
    // Build one instance of each variant and verify kind() matches serde rename.
    let cases: Vec<(&str, Command)> = vec![
        ("ping", Command::Ping),
        ("metrics", Command::Metrics),
        ("get", Command::Get(GetInput { key: "k".into() })),
        (
            "hook_evaluate",
            Command::HookEvaluate(HookEvaluateInput {
                file_key: "f".into(),
                include_recent: false,
                actor: None,
            }),
        ),
        (
            "scan_prefix",
            Command::ScanPrefix(ScanPrefixInput { prefix: "p".into() }),
        ),
        (
            "scan_keys",
            Command::ScanKeys(ScanKeysInput { prefix: "p".into() }),
        ),
        (
            "history",
            Command::History(HistoryInput {
                key: "k".into(),
                limit: 10,
            }),
        ),
        (
            "history_since",
            Command::HistorySince(HistorySinceInput {
                key: "k".into(),
                since_ts: 0,
                limit: 10,
            }),
        ),
        (
            "session_check_consulted",
            Command::SessionCheckConsulted(SessionCheckConsultedInput {
                key: "k".into(),
                actor: None,
            }),
        ),
        (
            "session_check_consulted_recent",
            Command::SessionCheckConsultedRecent(SessionCheckConsultedRecentInput {
                key: "k".into(),
                ttl_secs: 900,
                actor: None,
            }),
        ),
        (
            "mem_query",
            Command::MemQuery(MemQueryInput {
                query: "q".into(),
                mode: QueryMode::Text,
                limit: 20,
                since: None,
            }),
        ),
        (
            "mem_get",
            Command::MemGet(MemGetInput {
                key: "k".into(),
                actor: None,
            }),
        ),
        (
            "mem_bootstrap",
            Command::MemBootstrap(MemBootstrapInput {
                context_files: vec![],
            }),
        ),
        (
            "gotcha_upsert",
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
        ),
        (
            "gotcha_confirm",
            Command::GotchaConfirm(GotchaConfirmInput {
                key: "gotcha:t".into(),
                via_elicitation: false,
            }),
        ),
        (
            "gotcha_tombstone",
            Command::GotchaTombstone(GotchaTombstoneInput {
                key: "gotcha:t".into(),
            }),
        ),
        (
            "file_enrich",
            Command::FileEnrich(FileEnrichInput {
                path: "p".into(),
                purpose: "p".into(),
                entry_points: vec![],
                decision_keys: vec![],
                todos: vec![],
                tags: vec![],
                priority: Priority::Normal,
            }),
        ),
        (
            "file_reparse",
            Command::FileReparse(FileReparseInput { path: "p".into() }),
        ),
        (
            "file_edit_hook",
            Command::FileEditHook(FileEditHookInput { path: "p".into() }),
        ),
        (
            "doc_capture",
            Command::DocCapture(DocCaptureInput { path: "p".into() }),
        ),
        (
            "decision_upsert",
            Command::DecisionUpsert(DecisionUpsertInput {
                slug: "s".into(),
                value: "v".into(),
                summary: "s".into(),
                rationale: "r".into(),
                tags: vec![],
                priority: Priority::Normal,
            }),
        ),
        (
            "dev_note_upsert",
            Command::DevNoteUpsert(DevNoteUpsertInput {
                key: None,
                text: "t".into(),
                tags: vec![],
                priority: Priority::Normal,
            }),
        ),
        (
            "session_log",
            Command::SessionLog(SessionLogInput {
                event: SessionEvent::Miss,
                key: "k".into(),
                session_id: None,
                actor: None,
                decision_basis_hash: None,
            }),
        ),
        (
            "consultation_hit",
            Command::ConsultationHit(ConsultationHitInput {
                key: "k".into(),
                capture_fingerprint: true,
                actor: None,
                session_id: None,
                agent_id: None,
                decision_basis_hash: None,
                source: None,
            }),
        ),
        ("session_flush", Command::SessionFlush),
        (
            "session_harvest",
            Command::SessionHarvest(SessionHarvestInput::default()),
        ),
        ("session_clear_consults", Command::SessionClearConsults),
    ];

    assert_eq!(cases.len(), 27, "must cover all 27 command variants");
    for (expected_kind, cmd) in &cases {
        assert_eq!(
            cmd.kind(),
            *expected_kind,
            "kind() mismatch for {:?}",
            expected_kind
        );
    }
}

#[test]
fn command_is_mutation_classification() {
    // Pure reads — must NOT be mutations
    assert!(!Command::Ping.is_mutation());
    assert!(!Command::Metrics.is_mutation());
    assert!(!Command::Get(GetInput { key: "k".into() }).is_mutation());
    assert!(!Command::ScanKeys(ScanKeysInput { prefix: "p".into() }).is_mutation());
    assert!(!Command::MemQuery(MemQueryInput {
        query: "q".into(),
        mode: QueryMode::Text,
        limit: 20,
        since: None,
    })
    .is_mutation());

    // Reads with side effects — ARE mutations (audited)
    assert!(Command::MemGet(MemGetInput {
        key: "k".into(),
        actor: None
    })
    .is_mutation());
    assert!(Command::MemBootstrap(MemBootstrapInput {
        context_files: vec![]
    })
    .is_mutation());

    // Semantic mutations — ARE mutations
    assert!(Command::GotchaConfirm(GotchaConfirmInput {
        key: "gotcha:t".into(),
        via_elicitation: false,
    })
    .is_mutation());
    assert!(Command::SessionLog(SessionLogInput {
        event: SessionEvent::Miss,
        key: "k".into(),
        session_id: None,
        actor: None,
        decision_basis_hash: None,
    })
    .is_mutation());
    assert!(Command::SessionFlush.is_mutation());
    assert!(Command::SessionHarvest(SessionHarvestInput::default()).is_mutation());
    assert!(Command::SessionClearConsults.is_mutation());
}

#[test]
fn command_target_key_returns_expected_values() {
    assert_eq!(Command::Ping.target_key(), "");
    assert_eq!(
        Command::Get(GetInput {
            key: "file:src/main.rs".into()
        })
        .target_key(),
        "file:src/main.rs"
    );
    assert_eq!(
        Command::GotchaUpsert(GotchaDraftInput {
            key: "gotcha:test".into(),
            rule: "r".into(),
            reason: "r".into(),
            severity: Severity::Normal,
            affected_files: vec![],
            ref_url: None,
            tags: vec![],
            priority: Priority::Normal,
            source: None,
            confirmed: false,
        })
        .target_key(),
        "gotcha:test"
    );
    assert_eq!(
        Command::DecisionUpsert(DecisionUpsertInput {
            slug: "my-decision".into(),
            value: "v".into(),
            summary: "s".into(),
            rationale: "r".into(),
            tags: vec![],
            priority: Priority::Normal,
        })
        .target_key(),
        "my-decision"
    );
    // DevNoteUpsert in create mode — no key
    assert_eq!(
        Command::DevNoteUpsert(DevNoteUpsertInput {
            key: None,
            text: "t".into(),
            tags: vec![],
            priority: Priority::Normal,
        })
        .target_key(),
        ""
    );
    assert_eq!(Command::SessionFlush.target_key(), "");
    assert_eq!(Command::SessionClearConsults.target_key(), "");
}

#[test]
fn audit_entry_serializes() {
    let entry = AuditEntry {
        ts: 1700000000,
        peer_uid: 501,
        peer_pid: Some(1234),
        daemon_session: Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap(),
        request_id: Uuid::parse_str("660e8400-e29b-41d4-a716-446655440000").unwrap(),
        command_kind: "gotcha_upsert".into(),
        target_key: "gotcha:test".into(),
        accepted: true,
        error_code: None,
    };
    let json = serde_json::to_value(&entry).unwrap();
    assert_eq!(json["peer_uid"], 501);
    assert_eq!(json["command_kind"], "gotcha_upsert");
    assert_eq!(json["accepted"], true);
    // error_code should be absent (skip_serializing_if)
    assert!(json.get("error_code").is_none());
}

#[test]
fn audit_entry_rejected_includes_error_code() {
    let entry = AuditEntry {
        ts: 1700000000,
        peer_uid: 501,
        peer_pid: None,
        daemon_session: Uuid::nil(),
        request_id: Uuid::nil(),
        command_kind: "gotcha_confirm".into(),
        target_key: "gotcha:missing".into(),
        accepted: false,
        error_code: Some(ErrorCode::NotFound),
    };
    let json = serde_json::to_value(&entry).unwrap();
    assert_eq!(json["accepted"], false);
    assert_eq!(json["error_code"], "not_found");
    assert!(json["peer_pid"].is_null());
}

// ── store::Priority → protocol type conversions ────────────────────

#[test]
fn store_priority_to_protocol_severity_preserves_all_variants() {
    use crate::store::Priority as SP;
    assert_eq!(Severity::from(SP::Low), Severity::Low);
    assert_eq!(Severity::from(SP::Normal), Severity::Normal);
    assert_eq!(Severity::from(SP::High), Severity::High);
    assert_eq!(Severity::from(SP::Critical), Severity::Critical);
}

#[test]
fn store_priority_to_protocol_priority_preserves_all_variants() {
    use crate::store::Priority as SP;
    assert_eq!(Priority::from(SP::Low), Priority::Low);
    assert_eq!(Priority::from(SP::Normal), Priority::Normal);
    assert_eq!(Priority::from(SP::High), Priority::High);
    assert_eq!(Priority::from(SP::Critical), Priority::Critical);
}

// ── v1_to_v2_command translation tests (pass-29 regression) ─────────
//
// Pass 28 shipped a panic-on-default mapper that crashed every Socket-
// backed `mem_get` and `mem_bootstrap` call (rmcp task panic →
// "Transport closed"). The test below locks the mapper to the same
// wire shape the daemon's typed DTOs (`MemGetInput`, `MemBootstrapInput`)
// expect — both have `deny_unknown_fields`, so the test doubles as a
// contract check between the proxy layer and `dispatch_v2`.

#[test]
fn v1_to_v2_command_handles_mem_get() {
    let mapped = v1_to_v2_command("mem_get", &serde_json::json!({ "key": "file:src/main.rs" }));
    assert_eq!(
        mapped,
        serde_json::json!({ "type": "mem_get", "key": "file:src/main.rs", "actor": null })
    );

    // Round-trip into a typed Command — proves the wire shape decodes
    // through `MemGetInput::deny_unknown_fields`.
    let cmd: Command = serde_json::from_value(mapped).expect("mem_get must decode as Command");
    match cmd {
        Command::MemGet(input) => {
            assert_eq!(input.key, "file:src/main.rs");
            assert_eq!(input.actor, None);
        }
        other => panic!("expected Command::MemGet, got {:?}", other.kind()),
    }
}

/// `mati serve` stamps its own worktree tag as `actor` (F4/Half 1) — the v1
/// bridge must carry it through, not drop it like an ordinary unknown field.
#[test]
fn v1_to_v2_command_passes_mem_get_actor_through() {
    let mapped = v1_to_v2_command(
        "mem_get",
        &serde_json::json!({ "key": "file:src/main.rs", "actor": "wtA" }),
    );
    let cmd: Command = serde_json::from_value(mapped).expect("mem_get must decode as Command");
    match cmd {
        Command::MemGet(input) => assert_eq!(input.actor.as_deref(), Some("wtA")),
        other => panic!("expected Command::MemGet, got {:?}", other.kind()),
    }
}

#[test]
fn v1_to_v2_command_handles_mem_bootstrap() {
    // Args present.
    let mapped = v1_to_v2_command(
        "mem_bootstrap",
        &serde_json::json!({ "context_files": ["src/lib.rs", "src/main.rs"] }),
    );
    let cmd: Command =
        serde_json::from_value(mapped).expect("mem_bootstrap must decode as Command");
    match cmd {
        Command::MemBootstrap(input) => {
            assert_eq!(input.context_files, vec!["src/lib.rs", "src/main.rs"]);
        }
        other => panic!("expected Command::MemBootstrap, got {:?}", other.kind()),
    }

    // Args missing — must default to an empty list, not panic.
    let mapped_empty = v1_to_v2_command("mem_bootstrap", &serde_json::json!({}));
    let cmd_empty: Command = serde_json::from_value(mapped_empty).unwrap();
    match cmd_empty {
        Command::MemBootstrap(input) => assert!(input.context_files.is_empty()),
        other => panic!("expected MemBootstrap, got {:?}", other.kind()),
    }
}

#[test]
#[should_panic(expected = "v1_to_v2_command called with unsupported command")]
fn v1_to_v2_command_panic_message_lists_only_unsupported() {
    // Genuinely unsupported strings (mutations / typos) must still
    // panic loudly — that signals a misrouted Socket-backend caller
    // that should be using `daemon_v2()` with a typed Command.
    let _ = v1_to_v2_command("totally_bogus_cmd_xyz", &serde_json::json!({}));
}

#[test]
fn v1_to_v2_command_no_mutations_silently_accepted() {
    // Fence: every mutating command name must panic — they have no
    // place in the mapper. If a future contributor adds (say) "mem_set"
    // here, this test must catch it.
    let mutation_names = [
        "mem_set",
        "gotcha_upsert",
        "gotcha_confirm",
        "gotcha_tombstone",
        "decision_upsert",
        "dev_note_upsert",
        "file_enrich",
        "file_reparse",
        "file_edit_hook",
        "doc_capture",
        "session_log",
        "consultation_hit",
        "session_flush",
        "session_harvest",
        "session_clear_consults",
    ];
    for name in mutation_names {
        let result = std::panic::catch_unwind(|| {
            v1_to_v2_command(name, &serde_json::json!({}));
        });
        assert!(
            result.is_err(),
            "mutation command '{name}' must panic in v1_to_v2_command — \
                 mutating callers must use daemon_v2() with typed Command"
        );
    }
}

// ── ADR-018: Request.agent additive field ───────────────────────────

/// Pre-multi-agent clients send wire JSON without an `agent` field.
/// ADR-018 requires this to keep deserializing. This test is the
/// backward-compatibility regression bar.
#[test]
fn request_without_agent_field_deserializes_as_none() {
    let json = serde_json::json!({
        "v": 2,
        "id": "550e8400-e29b-41d4-a716-446655440000",
        "session": "660e8400-e29b-41d4-a716-446655440000",
        "cmd": { "type": "ping" }
    });
    let req: Request = serde_json::from_value(json).unwrap();
    assert!(
        req.agent.is_none(),
        "missing `agent` must decode to None (ADR-018 additive contract)"
    );
}

#[test]
fn request_with_agent_field_deserializes_and_preserves_value() {
    for (wire, expected) in [
        ("claude", AgentKind::Claude),
        ("codex", AgentKind::Codex),
        ("cli", AgentKind::Cli),
        ("supervisor", AgentKind::Supervisor),
        ("unknown", AgentKind::Unknown),
    ] {
        let json = serde_json::json!({
            "v": 2,
            "id": "550e8400-e29b-41d4-a716-446655440000",
            "session": "660e8400-e29b-41d4-a716-446655440000",
            "agent": wire,
            "cmd": { "type": "ping" }
        });
        let req: Request = serde_json::from_value(json)
            .unwrap_or_else(|e| panic!("decode failed for agent={wire}: {e}"));
        assert_eq!(req.agent, Some(expected));
    }
}

#[test]
fn request_with_unknown_agent_variant_rejected() {
    let json = serde_json::json!({
        "v": 2,
        "id": "550e8400-e29b-41d4-a716-446655440000",
        "session": "660e8400-e29b-41d4-a716-446655440000",
        "agent": "gemini",
        "cmd": { "type": "ping" }
    });
    let res = serde_json::from_value::<Request>(json);
    assert!(
        res.is_err(),
        "unknown agent variant must reject at decode (closed enum)"
    );
}

#[test]
fn request_with_agent_round_trips_through_serialize_deserialize() {
    let original = Request {
        v: PROTOCOL_VERSION,
        id: Uuid::new_v4(),
        session: Uuid::new_v4(),
        agent: Some(AgentKind::Codex),
        cmd: Command::Ping,
    };
    let bytes = serde_json::to_vec(&original).unwrap();
    let round_tripped: Request = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(round_tripped.agent, Some(AgentKind::Codex));
    assert_eq!(round_tripped.v, PROTOCOL_VERSION);
}

#[test]
fn consultation_hit_input_actor_is_optional() {
    // Without actor field: must decode to actor: None (new fields also default to None).
    let without_actor: ConsultationHitInput =
        serde_json::from_value(serde_json::json!({"key": "file:x"})).unwrap();
    assert_eq!(without_actor.key, "file:x");
    assert_eq!(without_actor.actor, None);
    assert_eq!(without_actor.session_id, None);
    assert_eq!(without_actor.agent_id, None);

    // With actor field: must decode actor correctly; new fields default to None.
    let with_actor: ConsultationHitInput =
        serde_json::from_value(serde_json::json!({"key": "file:x", "actor": "a"})).unwrap();
    assert_eq!(with_actor.key, "file:x");
    assert_eq!(with_actor.actor, Some("a".to_string()));
    assert_eq!(with_actor.session_id, None);
    assert_eq!(with_actor.agent_id, None);

    // session_id and agent_id round-trip correctly.
    let with_session: ConsultationHitInput = serde_json::from_value(serde_json::json!({
        "key": "file:x",
        "session_id": "sess-abc",
        "agent_id": "agent-xyz"
    }))
    .unwrap();
    assert_eq!(with_session.key, "file:x");
    assert_eq!(with_session.actor, None);
    assert_eq!(with_session.session_id, Some("sess-abc".to_string()));
    assert_eq!(with_session.agent_id, Some("agent-xyz".to_string()));

    // Round-trip through serde_json preserves all fields.
    let round_tripped: ConsultationHitInput =
        serde_json::from_str(&serde_json::to_string(&with_session).unwrap()).unwrap();
    assert_eq!(round_tripped.session_id, Some("sess-abc".to_string()));
    assert_eq!(round_tripped.agent_id, Some("agent-xyz".to_string()));
}
