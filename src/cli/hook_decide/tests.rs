use super::*;
use serde_json::json;

#[test]
fn schema_introspection_exempts_matching_strict_block() {
    let input = json!({
        "tool_input": {"command": "psql -h db.prod.internal -c \"\\d orders\""}
    });
    assert!(policy_block_exempt(HookVariant::ClaudePreBash, &input));
    assert!(policy_block_exempt(HookVariant::CodexPreBash, &input));

    let result = decide::evaluate_policy_verdicts(
        &[decide::PolicyVerdict {
            key: "policy:prod-query".into(),
            content: mati_core::store::ContentOutcome::None,
            rule: "Inspect production schema first.".into(),
            requires_key: "schema:orders".into(),
            block: false,
            satisfied: false,
            stage: mati_core::store::PolicyStage::Enforce,
        }],
        true,
    );
    assert!(matches!(result.decision, Decision::Advisory { .. }));
}

#[test]
fn schema_introspection_exemption_produces_no_shadow_observation() {
    let input = json!({
        "tool_input": {"command": "psql -h db.prod.internal -c \"\\d orders\""}
    });
    assert!(policy_block_exempt(HookVariant::ClaudePreBash, &input));
    assert!(policy_block_exempt(HookVariant::CodexPreBash, &input));
    let verdicts = policy_core_verdicts(
        &[mati_core::mcp::protocol::PolicyVerdict {
            key: "policy:prod-query".into(),
            content: mati_core::store::ContentOutcome::None,
            stage: mati_core::store::PolicyStage::Shadow,
            mode: mati_core::store::PolicyMode::Block,
            rule: "Inspect production schema first.".into(),
            reason: "Schema drift matters.".into(),
            severity: mati_core::store::Priority::High,
            requires_key: "schema:orders".into(),
            satisfied: false,
            via: vec![],
            strict: true,
        }],
        true,
        false,
    );
    let result = decide::evaluate_policy_verdicts(&verdicts, true);
    assert_eq!(result.decision, Decision::Allow);
    assert!(!result
        .events
        .iter()
        .any(|event| matches!(event, HookEvent::PolicyShadowObserved { .. })));
    assert!(!result
        .events
        .iter()
        .any(|event| matches!(event, HookEvent::PolicyConsulted { .. })));
}

#[test]
fn codex_policy_without_a_producible_source_degrades_to_steering() {
    let verdicts = policy_core_verdicts(
        &[mati_core::mcp::protocol::PolicyVerdict {
            key: "policy:db-schema".into(),
            content: mati_core::store::ContentOutcome::None,
            stage: mati_core::store::PolicyStage::Enforce,
            mode: mati_core::store::PolicyMode::Block,
            rule: "Inspect the schema first.".into(),
            reason: "Production schemas drift.".into(),
            severity: mati_core::store::Priority::High,
            requires_key: "schema:orders".into(),
            satisfied: false,
            via: vec![mati_core::store::ReceiptSource::DbIntrospection],
            strict: true,
        }],
        false,
        true,
    );
    let result = decide::evaluate_policy_verdicts(&verdicts, true);
    assert!(
        matches!(result.decision, Decision::Advisory { ref context } if context.contains("cannot be satisfied in Codex"))
    );
    assert!(!result
        .events
        .iter()
        .any(|event| matches!(event, HookEvent::PolicyConsultBlocked { .. })));
}

/// H1: a content-deny must NOT be lowered by the schema-introspection
/// exemption. The exemption is the remedy for a *consult* gate, meaningless for
/// a content restriction — so a `deny_if` policy denies even when the same call
/// path grants the introspection exemption that clears a consult block.
#[test]
fn content_deny_ignores_the_introspection_exemption() {
    let verdict =
        |content: mati_core::store::ContentOutcome| mati_core::mcp::protocol::PolicyVerdict {
            key: "policy:no-write".into(),
            content,
            stage: mati_core::store::PolicyStage::Enforce,
            mode: mati_core::store::PolicyMode::Block,
            rule: "Deny writes.".into(),
            reason: "Read-only.".into(),
            severity: mati_core::store::Priority::High,
            requires_key: "schema:orders".into(),
            satisfied: false,
            via: vec![mati_core::store::ReceiptSource::DbIntrospection],
            strict: true,
        };

    // introspection_exemption = true. A plain consult block is lowered by it...
    let consult = policy_core_verdicts(
        &[verdict(mati_core::store::ContentOutcome::None)],
        true,
        false,
    );
    assert!(
        !matches!(
            decide::evaluate_policy_verdicts(&consult, true).decision,
            Decision::Deny { .. }
        ),
        "consult block should be lowered under the introspection exemption"
    );

    // ...but a content-deny is not — it still denies, with its own origin.
    let content = policy_core_verdicts(
        &[verdict(mati_core::store::ContentOutcome::Deny)],
        true,
        false,
    );
    assert!(matches!(
        decide::evaluate_policy_verdicts(&content, true).decision,
        Decision::Deny {
            origin: decide::DenyOrigin::PolicyContentDenied,
            ..
        }
    ));
}

/// A Codex policy that names a source Codex CAN mint must keep blocking.
///
/// `HookContext` is produced on the Codex pre-bash and apply-patch paths
/// (`fire_events` runs there), so degrading it would silently switch off an
/// enforceable policy. Written because the first version of the check asked
/// only whether `via` contained `MemGet`, which was true when there were
/// two variants and wrong the moment a third was added.
#[test]
fn codex_policy_naming_a_producible_source_still_blocks() {
    for via in [
        vec![mati_core::store::ReceiptSource::HookContext],
        vec![
            mati_core::store::ReceiptSource::DbIntrospection,
            mati_core::store::ReceiptSource::HookContext,
        ],
    ] {
        let verdicts = policy_core_verdicts(
            &[mati_core::mcp::protocol::PolicyVerdict {
                key: "policy:db-schema".into(),
                content: mati_core::store::ContentOutcome::None,
                stage: mati_core::store::PolicyStage::Enforce,
                mode: mati_core::store::PolicyMode::Block,
                rule: "Inspect the schema first.".into(),
                reason: "Production schemas drift.".into(),
                severity: mati_core::store::Priority::High,
                requires_key: "schema:orders".into(),
                satisfied: false,
                via: via.clone(),
                strict: true,
            }],
            false,
            true,
        );
        assert!(
            verdicts[0].block,
            "via {via:?} is producible in Codex and must still block"
        );
        assert_eq!(
            verdicts[0].rule, "Inspect the schema first.",
            "a policy that still blocks must keep its own rule text"
        );
    }
}

#[test]
fn schema_introspection_exemption_preserves_satisfied_block() {
    let result = decide::evaluate_policy_verdicts(
        &[decide::PolicyVerdict {
            key: "policy:prod-query".into(),
            content: mati_core::store::ContentOutcome::None,
            rule: "Inspect production schema first.".into(),
            requires_key: "schema:orders".into(),
            block: true,
            satisfied: true,
            stage: mati_core::store::PolicyStage::Enforce,
        }],
        true,
    );
    assert_eq!(result.decision, Decision::Allow);
    assert_eq!(
        result.events,
        vec![HookEvent::PolicyConsulted {
            key: "policy:prod-query".into()
        }]
    );
}

#[test]
fn post_bash_success_gating_rejects_failures() {
    let command = "psql -c \"\\d orders\"";
    assert!(post_bash_succeeded(&json!({
        "tool_input": {"command": command},
        "tool_response": {"isError": false, "exit_code": 0}
    })));
    // The real Claude Code shape: no isError, no exit status.
    assert!(post_bash_succeeded(&json!({
        "tool_input": {"command": command},
        "tool_response": {
            "stdout": "Table \"public.inventory\"", "stderr": "",
            "interrupted": false, "isImage": false, "noOutputExpected": false
        }
    })));
    // exit_code alone is still honored when a payload carries it.
    assert!(post_bash_succeeded(&json!({
        "tool_input": {"command": command},
        "tool_response": {"exit_code": 0}
    })));
    for response in [
        json!({"isError": true}),
        json!({"is_error": true}),
        json!({"exit_code": 1}),
        json!({"exitCode": 2}),
        json!({"interrupted": true}),
        json!({"stdout": "x", "interrupted": true, "isImage": false}),
    ] {
        assert!(!post_bash_succeeded(&json!({
            "tool_input": {"command": command},
            "tool_response": response
        })));
    }
    assert!(!post_bash_succeeded(&json!({
        "tool_input": {"command": command}
    })));
}

#[test]
fn post_bash_receipts_ignore_memget_only_policies() {
    assert!(!accepts_db_introspection(&[
        mati_core::store::ReceiptSource::MemGet
    ]));
    assert!(accepts_db_introspection(&[
        mati_core::store::ReceiptSource::DbIntrospection
    ]));
    assert!(accepts_db_introspection(&[
        mati_core::store::ReceiptSource::MemGet,
        mati_core::store::ReceiptSource::DbIntrospection,
    ]));
}

#[test]
fn hook_context_hit_records_hook_context_source() {
    let Some(mati_core::mcp::protocol::Command::ConsultationHit(input)) = session_command(
        &HookEvent::Hit {
            key: "file:src/main.rs".into(),
        },
        None,
        None,
        None,
        None,
    ) else {
        panic!("HookEvent::Hit must mint a consultation receipt")
    };
    assert_eq!(
        input.source,
        Some(mati_core::store::ReceiptSource::HookContext)
    );
}

async fn assert_main_thread_receipt_is_global(key: &str) {
    crate::cli::ensure_test_home();
    let dir = tempfile::tempdir().unwrap();
    let store = mati_core::store::Store::open(dir.path()).await.unwrap();
    // No worktree (tempdir is not a git repo) and no agent: still global scope.
    let actor = receipt_actor(None, None);
    let staged = mati_core::store::session::consultation_receipt_staged_for_store(
        &store,
        key,
        actor.as_deref(),
        false,
        None,
    )
    .await
    .unwrap();
    let (receipt_key, bytes) = (staged.key, staged.bytes);
    let receipt: mati_core::store::Record = rmp_serde::from_slice(&bytes).unwrap();
    store.put(&receipt_key, &receipt).await.unwrap();
    assert_eq!(receipt_key, format!("session:consulted:{key}"));
    assert!(
        mati_core::store::session::check_consulted_recent(&store, key, 900, None)
            .await
            .unwrap()
    );
    assert!(!mati_core::store::session::check_consulted_recent(
        &store,
        key,
        900,
        Some("session-main")
    )
    .await
    .unwrap());
}

/// Both mint paths derive their actor identically, so one test covers
/// them. With no worktree discoverable and no agent, the gate reads the
/// global receipt for the main thread.
#[tokio::test]
async fn main_thread_receipt_uses_global_gate_scope() {
    assert_main_thread_receipt_is_global("schema:orders").await;
}

/// The other half: an agent_id is real scope, and its receipt must not
/// satisfy the gate for anyone else.
#[tokio::test]
async fn subagent_receipt_stays_actor_scoped() {
    crate::cli::ensure_test_home();
    let dir = tempfile::tempdir().unwrap();
    let store = mati_core::store::Store::open(dir.path()).await.unwrap();
    let key = "schema:orders";
    let actor = receipt_actor(None, Some("agent-a"));
    assert_eq!(actor.as_deref(), Some("agent-a"));

    let staged = mati_core::store::session::consultation_receipt_staged_for_store(
        &store,
        key,
        actor.as_deref(),
        false,
        None,
    )
    .await
    .unwrap();
    let (receipt_key, bytes) = (staged.key, staged.bytes);
    let receipt: mati_core::store::Record = rmp_serde::from_slice(&bytes).unwrap();
    store.put(&receipt_key, &receipt).await.unwrap();
    assert_eq!(receipt_key, format!("session:consulted:agent-a:{key}"));

    assert!(
        mati_core::store::session::check_consulted_recent(&store, key, 900, Some("agent-a"))
            .await
            .unwrap()
    );
    assert!(
        !mati_core::store::session::check_consulted_recent(&store, key, 900, Some("agent-b"))
            .await
            .unwrap()
    );
    assert!(
        !mati_core::store::session::check_consulted_recent(&store, key, 900, None)
            .await
            .unwrap()
    );
}

// ── extract_path ────────────────────────────────────────────────────

#[test]
fn extract_path_claude_pre_read_file_path() {
    let input = json!({"tool_input": {"file_path": "/home/user/project/src/main.rs"}});
    assert_eq!(
        extract_path(&input, HookVariant::ClaudePreRead),
        Some("/home/user/project/src/main.rs".into())
    );
}

#[test]
fn extract_path_claude_pre_read_path_fallback() {
    let input = json!({"tool_input": {"path": "src/main.rs"}});
    assert_eq!(
        extract_path(&input, HookVariant::ClaudePreRead),
        Some("src/main.rs".into())
    );
}

// ── Event mapping ───────────────────────────────────────────────────
//
/// A Codex pre-hook block must be recorded as a BLOCK. The mapping sent it
/// to `CodexShellMiss`, the post-bash hook's after-the-fact bypass event, so
/// every Codex deny was logged as `bypass_detected` and Codex showed zero
/// denials in `mati stats` and in the audit built on the chain.
#[test]
fn codex_pre_hook_block_maps_to_a_block_not_a_bypass() {
    use mati_core::mcp::protocol as p;
    let cmd = session_command(
        &HookEvent::CodexShellBlocked {
            key: "file:src/main.rs".into(),
        },
        None,
        None,
        None,
        None,
    )
    .expect("a block must be recorded");
    match cmd {
        p::Command::SessionLog(input) => assert_eq!(
            input.event,
            p::SessionEvent::CodexShellBlocked,
            "a pre-hook block is not the post-bash miss"
        ),
        other => panic!("expected SessionLog, got {other:?}"),
    }
}

/// The post-bash miss keeps its own event: nothing was denied there.
#[test]
fn codex_post_bash_miss_stays_a_miss() {
    use mati_core::mcp::protocol as p;
    // `run_post_bash` builds this event directly; pin the two apart.
    assert_ne!(
        p::SessionEvent::CodexShellMiss,
        p::SessionEvent::CodexShellBlocked
    );
}

/// The gate's decision basis and receipt scope must reach the daemon, or the
/// chained event has nothing to record them from.
#[test]
fn gate_events_carry_the_basis_hash_and_receipt_scope() {
    use mati_core::mcp::protocol as p;
    let cmd = session_command(
        &HookEvent::BlockedUnconsultedRead {
            key: "file:src/main.rs".into(),
        },
        Some("sess-1"),
        Some("agent-a"),
        Some("agent-a"),
        Some("deadbeef"),
    )
    .unwrap();
    match cmd {
        p::Command::SessionLog(input) => {
            assert_eq!(input.session_id.as_deref(), Some("sess-1"));
            assert_eq!(input.actor.as_deref(), Some("agent-a"));
            assert_eq!(input.decision_basis_hash.as_deref(), Some("deadbeef"));
        }
        other => panic!("expected SessionLog, got {other:?}"),
    }
}

#[test]
fn decision_basis_hash_is_none_without_gotchas() {
    assert_eq!(decision_basis_hash(&HashMap::new()), None);
    let mut records = HashMap::new();
    records.insert(
        "gotcha:x".to_string(),
        json!({"value": "rule", "confidence": {"value": 0.8}}),
    );
    assert!(decision_basis_hash(&records).is_some());
}

#[test]
fn extract_path_claude_pre_read_empty() {
    let input = json!({"tool_input": {"file_path": ""}});
    assert_eq!(extract_path(&input, HookVariant::ClaudePreRead), None);
}

#[test]
fn extract_path_codex_pre_bash_cat() {
    let input = json!({"tool_input": {"command": "cat src/main.rs"}});
    assert_eq!(
        extract_path(&input, HookVariant::CodexPreBash),
        Some("src/main.rs".into())
    );
}

#[test]
fn extract_path_codex_pre_bash_non_file_command() {
    let input = json!({"tool_input": {"command": "ls -la"}});
    assert_eq!(extract_path(&input, HookVariant::CodexPreBash), None);
}

#[test]
fn extract_path_codex_pre_bash_empty_command() {
    let input = json!({"tool_input": {"command": ""}});
    assert_eq!(extract_path(&input, HookVariant::CodexPreBash), None);
}

#[test]
fn extract_path_codex_fixture_tool_input_command() {
    // The supported Codex input fixture — proves no regression.
    let input = json!({"tool_input": {"command": "cat src/main.rs"}});
    assert_eq!(
        extract_path(&input, HookVariant::CodexPreBash),
        Some("src/main.rs".into())
    );
}

// ── extract_path: reject non-path shell tokens (miss aggregate pollution) ──
//
// Regression for live `analytics:miss_*` entries like
// `"file:2>/dev/null": 7` and `"file:>>": 3` — the GrepLike extractor
// took the last non-flag token, which can be a redirect fragment rather
// than a real path. These must now be rejected as "not a file read op",
// matching section 10.2's fallthrough for non-file commands.

#[test]
fn extract_path_rejects_stderr_redirect() {
    let input = json!({"tool_input": {"command": "grep pattern file.rs 2>/dev/null"}});
    assert_eq!(extract_path(&input, HookVariant::CodexPreBash), None);
}

#[test]
fn extract_path_rejects_bare_append_redirect() {
    let input = json!({"tool_input": {"command": "grep pattern file.txt >>"}});
    assert_eq!(extract_path(&input, HookVariant::CodexPreBash), None);
}

#[test]
fn extract_path_rejects_multiline_quoted_blob() {
    let input = json!({"tool_input": {"command": "grep -n \"pattern\nacross lines\""}});
    assert_eq!(extract_path(&input, HookVariant::CodexPreBash), None);
}

#[test]
fn extract_path_still_accepts_real_path_with_digits() {
    // Guard against over-rejection: a real filename that starts with a
    // digit must not be caught by the redirect-fragment filter.
    let input = json!({"tool_input": {"command": "cat 2024-report.txt"}});
    assert_eq!(
        extract_path(&input, HookVariant::CodexPreBash),
        Some("2024-report.txt".into())
    );
}

#[test]
fn extract_path_rejects_unexpanded_shell_variable() {
    let input = json!({"tool_input": {"command": "cat $F"}});
    assert_eq!(extract_path(&input, HookVariant::CodexPreBash), None);
}

#[test]
fn extract_path_rejects_unexpanded_shell_variable_path() {
    let input = json!({"tool_input": {"command": "cat $SP/t_memset.txt"}});
    assert_eq!(extract_path(&input, HookVariant::CodexPreBash), None);
}

#[test]
fn extract_path_rejects_unexpanded_shell_glob() {
    let input = json!({"tool_input": {"command": "cat *.rs"}});
    assert_eq!(extract_path(&input, HookVariant::CodexPreBash), None);
}

#[test]
fn extract_path_rejects_bare_current_directory() {
    let input = json!({"tool_input": {"command": "cat ."}});
    assert_eq!(extract_path(&input, HookVariant::CodexPreBash), None);
}

#[test]
fn extract_path_keeps_bare_directory_looking_token() {
    let input = json!({"tool_input": {"command": "cat src"}});
    assert_eq!(
        extract_path(&input, HookVariant::CodexPreBash),
        Some("src".into())
    );
}

// ── platform_events ─────────────────────────────────────────────────

#[test]
fn codex_deny_translates_to_shell_blocked() {
    let events = vec![HookEvent::BlockedUnconsultedRead {
        key: "file:src/main.rs".into(),
    }];
    let decision = Decision::Deny {
        file_key: "file:src/main.rs".into(),
        reason: "test".into(),
        origin: decide::DenyOrigin::Gotcha,
    };
    let result = platform_events(HookVariant::CodexPreBash, &decision, events);
    assert_eq!(result.len(), 1);
    assert!(matches!(
        &result[0],
        HookEvent::CodexShellBlocked { key } if key == "file:src/main.rs"
    ));
}

#[test]
fn codex_advisory_suppresses_hit() {
    let events = vec![HookEvent::Hit {
        key: "file:src/main.rs".into(),
    }];
    let decision = Decision::Advisory {
        context: "test".into(),
    };
    let result = platform_events(HookVariant::CodexPreBash, &decision, events);
    assert!(
        result.is_empty(),
        "Codex should not mint receipts for silent outcomes"
    );
}

#[test]
fn codex_liability_suppresses_hit() {
    let events = vec![HookEvent::Hit {
        key: "file:src/main.rs".into(),
    }];
    let decision = Decision::Liability {
        staleness: 0.85,
        context: "test".into(),
    };
    let result = platform_events(HookVariant::CodexPreBash, &decision, events);
    assert!(result.is_empty());
}

#[test]
fn codex_already_consulted_suppresses_hit() {
    // Codex AlreadyConsulted emits ComplianceHit (post-Bug 1). Codex
    // pre-bash still suppresses it so codex-post-bash owns it.
    let events = vec![HookEvent::ComplianceHit {
        key: "file:src/main.rs".into(),
    }];
    let decision = Decision::AlreadyConsulted {
        context: "test".into(),
    };
    let result = platform_events(HookVariant::CodexPreBash, &decision, events);
    assert!(result.is_empty());
}

#[test]
fn codex_no_record_keeps_miss() {
    let events = vec![HookEvent::Miss {
        key: "file:src/main.rs".into(),
    }];
    let decision = Decision::NoRecord;
    let result = platform_events(HookVariant::CodexPreBash, &decision, events);
    assert_eq!(result.len(), 1);
    assert!(matches!(&result[0], HookEvent::Miss { .. }));
}

#[test]
fn claude_keeps_all_events() {
    let events = vec![HookEvent::Hit {
        key: "file:src/main.rs".into(),
    }];
    let decision = Decision::Advisory {
        context: "test".into(),
    };
    let result = platform_events(HookVariant::ClaudePreRead, &decision, events);
    assert_eq!(
        result.len(),
        1,
        "Claude should keep Hit for advisory outcomes"
    );
}

#[test]
fn claude_deny_keeps_blocked_event() {
    let events = vec![HookEvent::BlockedUnconsultedRead {
        key: "file:src/main.rs".into(),
    }];
    let decision = Decision::Deny {
        file_key: "file:src/main.rs".into(),
        reason: "test".into(),
        origin: decide::DenyOrigin::Gotcha,
    };
    let result = platform_events(HookVariant::ClaudePreBash, &decision, events);
    assert_eq!(result.len(), 1);
    assert!(matches!(
        &result[0],
        HookEvent::BlockedUnconsultedRead { .. }
    ));
}

// ── End-to-end adapter tests ────────────────────────────────────────
//
// These test the full adapter pipeline: mock hook_evaluate response →
// EnforcementInput → evaluate → platform_events → format output.
// Exercises the same code path as run() without daemon I/O.

fn deny_eligible_eval_data() -> serde_json::Value {
    json!({
        "file_key": "file:src/main.rs",
        "file_record": {
            "value": "Entry point",
            "confidence": { "value": 0.7 },
            "quality": { "value": 0.5 },
            "staleness": { "value": 0.1, "tier": "fresh" },
            "payload": { "gotcha_keys": ["gotcha:test-rule"] }
        },
        "gotcha_records": {
            "gotcha:test-rule": {
                "value": "Never call unwrap in this file",
                "confidence": { "value": 0.8 },
                "quality": { "value": 0.6 },
                "payload": { "confirmed": true }
            }
        },
        "consulted": false,
        "consulted_recent": false,
        "store_error": false,
        "gotcha_error": false
    })
}

#[test]
fn e2e_codex_deny_exit2_stderr_and_shell_blocked_event() {
    let data = deny_eligible_eval_data();
    let result = process_eval_response(HookVariant::CodexPreBash, "src/main.rs", &data, None);

    assert_eq!(result.exit_code, 2, "Codex deny must exit 2");
    assert!(
        result.stderr.contains("mem_get"),
        "stderr must instruct agent to call mem_get, got: {}",
        result.stderr
    );
    assert!(result.stdout.is_empty(), "Codex deny should have no stdout");
    assert_eq!(result.events.len(), 1);
    assert!(
        matches!(&result.events[0], HookEvent::CodexShellBlocked { key } if key == "file:src/main.rs"),
        "Codex deny must emit CodexShellBlocked, got: {:?}",
        result.events
    );
    assert!(matches!(result.decision, Decision::Deny { .. }));
}

#[test]
fn e2e_codex_apply_patch_deny_exit2_when_unconsulted() {
    // apply_patch reads the recent-TTL receipt (consulted_recent). With no
    // receipt, a confirmed gotcha on a touched file must deny the edit.
    let data = deny_eligible_eval_data();
    let result = process_eval_response(HookVariant::CodexPreApplyPatch, "src/main.rs", &data, None);

    assert_eq!(result.exit_code, 2, "apply_patch deny must exit 2");
    assert!(matches!(result.decision, Decision::Deny { .. }));
    assert_eq!(result.events.len(), 1);
    assert!(
        matches!(&result.events[0], HookEvent::CodexShellBlocked { key } if key == "file:src/main.rs"),
        "apply_patch deny must emit CodexShellBlocked, got: {:?}",
        result.events
    );
}

#[test]
fn e2e_codex_apply_patch_allows_after_consult() {
    // Once the file has a recent consultation receipt, the edit is allowed.
    let mut data = deny_eligible_eval_data();
    data["consulted_recent"] = json!(true);
    let result = process_eval_response(HookVariant::CodexPreApplyPatch, "src/main.rs", &data, None);

    assert_eq!(result.exit_code, 0, "consulted edit must be allowed");
    assert!(!matches!(result.decision, Decision::Deny { .. }));
}

#[test]
fn e2e_claude_deny_json_output_and_blocked_event() {
    let data = deny_eligible_eval_data();
    let result = process_eval_response(HookVariant::ClaudePreBash, "src/main.rs", &data, None);

    assert_eq!(result.exit_code, 0, "Claude always exits 0");
    let json: serde_json::Value =
        serde_json::from_str(&result.stdout).expect("stdout must be valid JSON");
    assert_eq!(
        json.pointer("/hookSpecificOutput/permissionDecision")
            .and_then(|v| v.as_str()),
        Some("deny")
    );
    assert!(
        json.pointer("/hookSpecificOutput/permissionDecisionReason")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .contains("mem_get"),
        "deny reason must mention mem_get"
    );
    assert_eq!(result.events.len(), 1);
    assert!(matches!(
        &result.events[0],
        HookEvent::BlockedUnconsultedRead { .. }
    ));
}

#[test]
fn e2e_codex_advisory_silent_no_hit() {
    let data = json!({
        "file_key": "file:src/lib.rs",
        "file_record": {
            "value": "Library root",
            "confidence": { "value": 0.45 },
            "quality": { "value": 0.5 },
            "staleness": { "value": 0.1, "tier": "fresh" },
            "payload": { "gotcha_keys": [] }
        },
        "gotcha_records": {},
        "consulted": false,
        "consulted_recent": false,
        "store_error": false,
        "gotcha_error": false
    });
    let result = process_eval_response(HookVariant::CodexPreBash, "src/lib.rs", &data, None);

    assert_eq!(result.exit_code, 0);
    assert!(result.stdout.is_empty(), "Codex advisory must be silent");
    assert!(result.stderr.is_empty());
    // Advisory emits Hit in the core, but Codex suppresses it.
    assert!(
        result.events.is_empty(),
        "Codex must NOT mint consultation receipt for advisory, got: {:?}",
        result.events
    );
    assert!(matches!(result.decision, Decision::Advisory { .. }));
}

#[test]
fn e2e_claude_advisory_injects_context() {
    let data = json!({
        "file_key": "file:src/lib.rs",
        "file_record": {
            "value": "Library root",
            "confidence": { "value": 0.45 },
            "quality": { "value": 0.5 },
            "staleness": { "value": 0.1, "tier": "fresh" },
            "payload": { "gotcha_keys": [] }
        },
        "gotcha_records": {},
        "consulted": false,
        "consulted_recent": false,
        "store_error": false,
        "gotcha_error": false
    });
    let result = process_eval_response(HookVariant::ClaudePreRead, "src/lib.rs", &data, None);

    assert_eq!(result.exit_code, 0);
    let json: serde_json::Value =
        serde_json::from_str(&result.stdout).expect("stdout must be valid JSON");
    assert_eq!(
        json.pointer("/hookSpecificOutput/permissionDecision")
            .and_then(|v| v.as_str()),
        Some("allow")
    );
    assert!(
        json.pointer("/hookSpecificOutput/additionalContext")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .contains("[mati]"),
        "Claude advisory must inject context"
    );
    // Claude DOES fire Hit for advisory.
    assert_eq!(result.events.len(), 1);
    assert!(matches!(&result.events[0], HookEvent::Hit { .. }));
}

#[test]
fn e2e_codex_consulted_allows_silently() {
    let mut data = deny_eligible_eval_data();
    data["consulted_recent"] = json!(true);
    let result = process_eval_response(HookVariant::CodexPreBash, "src/main.rs", &data, None);

    assert_eq!(result.exit_code, 0, "consulted file must not be blocked");
    assert!(result.stdout.is_empty());
    assert!(result.stderr.is_empty());
    // AlreadyConsulted is silent for Codex pre-bash — ComplianceHit is
    // suppressed so codex-post-bash is the sole emitter of AllowAfterReceipt
    // for shell commands.
    assert!(result.events.is_empty());
}

#[test]
fn e2e_claude_consulted_records_allow_after_receipt() {
    // Bug 1 regression guard: when Claude pre-read allows a consulted
    // read, the adapter must emit ComplianceHit so the daemon records
    // an AllowAfterReceipt enforcement event.
    let mut data = deny_eligible_eval_data();
    data["consulted"] = json!(true);
    let result = process_eval_response(HookVariant::ClaudePreRead, "src/main.rs", &data, None);

    assert_eq!(result.exit_code, 0, "Claude always exits 0");
    let json: serde_json::Value =
        serde_json::from_str(&result.stdout).expect("stdout must be valid JSON");
    assert_eq!(
        json.pointer("/hookSpecificOutput/permissionDecision")
            .and_then(|v| v.as_str()),
        Some("allow")
    );
    assert!(matches!(result.decision, Decision::AlreadyConsulted { .. }));
    assert_eq!(result.events.len(), 1);
    assert!(
        matches!(&result.events[0], HookEvent::ComplianceHit { key } if key == "file:src/main.rs"),
        "AlreadyConsulted must emit ComplianceHit so AllowAfterReceipt is recorded, got: {:?}",
        result.events
    );
}

#[test]
fn e2e_store_error_fails_open() {
    let data = json!({
        "file_key": "file:src/main.rs",
        "file_record": null,
        "gotcha_records": {},
        "consulted": false,
        "consulted_recent": false,
        "store_error": true,
        "gotcha_error": false
    });
    let result = process_eval_response(HookVariant::CodexPreBash, "src/main.rs", &data, None);

    assert_eq!(result.exit_code, 0, "store error must fail open");
    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn e2e_gotcha_error_fails_open() {
    let data = json!({
        "file_key": "file:src/main.rs",
        "file_record": {
            "value": "test",
            "confidence": { "value": 0.7 },
            "quality": { "value": 0.5 },
            "staleness": { "value": 0.1, "tier": "fresh" },
            "payload": { "gotcha_keys": ["gotcha:broken"] }
        },
        "gotcha_records": {},
        "consulted": false,
        "consulted_recent": false,
        "store_error": false,
        "gotcha_error": true
    });
    let result = process_eval_response(HookVariant::ClaudePreBash, "src/main.rs", &data, None);

    assert_eq!(result.exit_code, 0, "gotcha error must fail open");
    assert!(
        result.stdout.is_empty(),
        "Bash fail-open must DEFER (empty stdout), never force-allow — \
             Bash is permission-required; got: {}",
        result.stdout
    );
    assert_eq!(result.decision, Decision::Allow);
}

#[tokio::test]
async fn deadline_logs_and_terminates_on_timeout() {
    use std::time::Instant;

    crate::cli::ensure_test_home();
    let deadline_ms = 100u64;
    let inner_sleep_ms = 5_000u64;
    let hook = "deadline-test";
    let rel_path = "timeout.rs";
    let reason = "deadline test stalled";

    let start = Instant::now();
    let result =
        crate::cli::hooks::run_with_deadline(hook, rel_path, deadline_ms, reason, async move {
            tokio::time::sleep(Duration::from_millis(inner_sleep_ms)).await;
            Ok(())
        })
        .await;
    let elapsed = start.elapsed();

    assert!(
        matches!(result, Ok(HookRunOutcome::Terminate(0))),
        "deadline wrapper must terminate on timeout, got: {result:?}"
    );

    assert!(
        elapsed < Duration::from_millis(deadline_ms + 400),
        "wrapper took {elapsed:?} — should fire near deadline ({deadline_ms}ms), not wait for inner sleep ({inner_sleep_ms}ms)"
    );
    assert!(
        elapsed >= Duration::from_millis(deadline_ms),
        "wrapper took {elapsed:?} — must wait at least the deadline ({deadline_ms}ms) before timing out"
    );

    // The production wrapper records the fail-open event; unlike the
    // hook-decide process wrapper, it does not emit protocol output.
    let log_path = mati_core::store::mati_home_opt()
        .expect("test home must be configured")
        .join("fail_open.log");
    let log = std::fs::read_to_string(log_path).expect("deadline must write fail_open.log");
    assert!(
        log.lines().any(|line| {
            line.contains(
                "FAIL_OPEN hook=deadline-test file=timeout.rs reason=deadline test stalled",
            )
        }),
        "deadline log entry missing from fail_open.log: {log}"
    );
}

#[test]
fn daemon_data_rejects_error_envelope() {
    // The client wraps daemon-side errors (backpressure, session
    // mismatch, handler failure) as DaemonResult::Ok({"ok": false}).
    // The gate must treat those as eval failures — evaluating the
    // missing `data` as Null would record a false Miss.
    let ok = json!({"ok": true, "v": 2, "data": {"consulted": true}});
    assert_eq!(
        daemon_data(&ok),
        Some(json!({"consulted": true})),
        "ok envelope must yield its data"
    );
    let err = json!({"ok": false, "v": 2, "error": "backpressure", "code": "backpressure"});
    assert!(
        daemon_data(&err).is_none(),
        "error envelope must not evaluate as data"
    );
    assert!(daemon_data(&json!({"v": 2})).is_none());
}

// ── Coverage-widening guard ─────────────────────────────────────────
//
// `permissionDecision:"allow"` bypasses Claude Code's permission system.
// Only the read gate (Read/Glob/Grep — no-permission tools) may ever emit
// it. If this test fails, a change has reintroduced the Bash/edit
// permission-prompt bypass.

#[test]
fn only_pre_read_force_allows() {
    use HookVariant::*;
    for variant in [
        ClaudeConfigChange,
        ClaudePreRead,
        ClaudePreEdit,
        ClaudePreBash,
        CodexPreBash,
        CodexPostBash,
        CodexPreApplyPatch,
        ClaudePostMemGet,
        ClaudePostBash,
    ] {
        // 1. The fail-open / no-path allow output.
        match variant {
            ClaudeConfigChange => assert_eq!(
                allow_output(variant),
                Some(r#"{"decision":"allow"}"#),
                "ConfigChange uses its separate top-level decision shape"
            ),
            ClaudePreRead => assert!(
                allow_output(variant).is_some(),
                "read gate keeps its no-op allow"
            ),
            _ => assert!(
                allow_output(variant).is_none(),
                "{variant:?} must DEFER on allow — force-allow would bypass \
                     the user's permission prompt"
            ),
        }
        // 2. Every non-deny decision outcome.
        let non_deny_decisions = [
            Decision::Allow,
            Decision::NoRecord,
            Decision::Tombstone,
            Decision::AlreadyConsulted {
                context: "ctx".into(),
            },
            Decision::Advisory {
                context: "ctx".into(),
            },
            Decision::Liability {
                staleness: 0.9,
                context: "ctx".into(),
            },
        ];
        for decision in &non_deny_decisions {
            let (stdout, _, _) = format_decision(variant, decision, "src/x.rs");
            if variant != ClaudePreRead {
                assert!(
                    !stdout.contains(r#""permissionDecision":"allow""#),
                    "{variant:?} emitted a force-allow for {decision:?}: {stdout}"
                );
            }
        }
    }
}

#[test]
fn policy_bash_output_denies_or_injects_without_force_allow() {
    let deny = Decision::Deny {
            file_key: "policy:prod-query".into(),
            reason: "mati: policy policy:prod-query blocked this action. Consult first: mem_get(\"schema:orders\")".into(),
            origin: decide::DenyOrigin::Policy,
        };
    let (stdout, _, _) = format_decision(HookVariant::ClaudePreBash, &deny, "<policy>");
    assert!(stdout.contains(r#""permissionDecision":"deny""#));
    assert!(stdout.contains("policy:prod-query"));
    assert!(stdout.contains("schema:orders"));

    let steer = Decision::Advisory {
        context: "Consult the schema first.".into(),
    };
    let (stdout, _, _) = format_decision(HookVariant::ClaudePreBash, &steer, "<policy>");
    assert!(stdout.contains("additionalContext"));
    assert!(!stdout.contains("permissionDecision"));
}

#[test]
fn codex_db_client_policy_gates_cover_fileless_file_bearing_and_introspection() {
    let deny_verdict = decide::PolicyVerdict {
        key: "policy:prod-query".into(),
        content: mati_core::store::ContentOutcome::None,
        rule: "Consult the schema first.".into(),
        requires_key: "schema:orders".into(),
        block: true,
        satisfied: false,
        stage: mati_core::store::PolicyStage::Enforce,
    };

    let fileless = decide::normalize_action(Some("psql -h db.prod.internal -c \"select 1\""), None);
    let file_bearing = decide::normalize_action(
        Some("psql -h db.prod.internal -f migrations/prod.sql"),
        None,
    );
    assert_eq!(fileless.tool, "db_client");
    assert!(fileless.files.is_empty());
    assert_eq!(file_bearing.tool, "db_client");
    assert_eq!(file_bearing.files, vec!["migrations/prod.sql"]);

    for action in [fileless, file_bearing] {
        assert_eq!(action.host.as_deref(), Some("db.prod.internal"));
        let result = decide::evaluate_policy_verdicts(std::slice::from_ref(&deny_verdict), true);
        let (stdout, stderr, exit_code) =
            format_decision(HookVariant::CodexPreBash, &result.decision, "<policy>");
        assert!(stdout.is_empty());
        assert!(stderr.starts_with("mati:"));
        assert_eq!(exit_code, 2);
    }

    let introspection_input = json!({
        "tool_input": {"command": "psql -h db.prod.internal -c \"\\d orders\""}
    });
    assert!(policy_block_exempt(
        HookVariant::CodexPreBash,
        &introspection_input
    ));
    let mut exempt_verdict = deny_verdict;
    exempt_verdict.block = false;
    let steered = decide::evaluate_policy_verdicts(std::slice::from_ref(&exempt_verdict), true);
    let (stdout, stderr, exit_code) =
        format_decision(HookVariant::CodexPreBash, &steered.decision, "<policy>");
    assert!(stdout.is_empty());
    assert!(stderr.is_empty());
    assert_eq!(exit_code, 0);
}

#[test]
fn claude_pre_edit_context_never_force_allows() {
    let outcomes = [
        Decision::AlreadyConsulted {
            context: "Already consulted.".into(),
        },
        Decision::Advisory {
            context: "Consult the schema first.".into(),
        },
        Decision::Liability {
            staleness: 0.8,
            context: "This record is stale.".into(),
        },
        Decision::Allow,
        Decision::NoRecord,
        Decision::Tombstone,
        Decision::NotFileRead,
    ];
    for decision in outcomes {
        let (stdout, _, _) = format_decision(HookVariant::ClaudePreEdit, &decision, "x.sql");
        assert!(!stdout.contains(r#""permissionDecision":"allow""#));
    }

    let (stdout, _, _) = format_decision(
        HookVariant::ClaudePreEdit,
        &Decision::Advisory {
            context: "Consult first.".into(),
        },
        "x.sql",
    );
    assert!(stdout.contains("additionalContext"));
    assert!(!stdout.contains("permissionDecision"));
}

#[test]
fn file_gate_and_policy_merge_escalate_only() {
    let mut adapter = AdapterResult {
        stdout: String::new(),
        stderr: String::new(),
        exit_code: 0,
        events: vec![HookEvent::Hit {
            key: "file:prod.sql".into(),
        }],
        decision: Decision::Advisory {
            context: "File guidance.".into(),
        },
        basis_hash: None,
    };
    merge_policy_result(
        &mut adapter,
        HookVariant::ClaudePreBash,
        Decision::Advisory {
            context: "Consult the schema first.".into(),
        },
        vec![HookEvent::PolicyConsulted {
            key: "policy:prod-query".into(),
        }],
    );
    assert_eq!(
        adapter.decision,
        Decision::Advisory {
            context: "File guidance.\nConsult the schema first.".into(),
        }
    );
    assert_eq!(adapter.events.len(), 2);
    assert!(adapter.stdout.contains("additionalContext"));
    assert!(!adapter.stdout.contains("permissionDecision"));

    merge_policy_result(
        &mut adapter,
        HookVariant::ClaudePreBash,
        Decision::Deny {
            file_key: "policy:prod-query".into(),
            reason: "policy denied".into(),
            origin: decide::DenyOrigin::Policy,
        },
        vec![HookEvent::PolicyConsultBlocked {
            key: "policy:prod-query".into(),
        }],
    );
    assert!(matches!(adapter.decision, Decision::Deny { .. }));
    assert!(adapter.stdout.contains(r#""permissionDecision":"deny""#));

    let mut edit_adapter = AdapterResult {
        stdout: String::new(),
        stderr: String::new(),
        exit_code: 0,
        events: vec![],
        decision: Decision::NoRecord,
        basis_hash: None,
    };
    merge_policy_result(
        &mut edit_adapter,
        HookVariant::ClaudePreEdit,
        Decision::Advisory {
            context: "Edit policy guidance.".into(),
        },
        vec![],
    );
    assert!(edit_adapter.stdout.contains("additionalContext"));
    assert!(!edit_adapter.stdout.contains("permissionDecision"));

    edit_adapter.decision = Decision::Deny {
        file_key: "file:x.sql".into(),
        reason: "gotcha denied".into(),
        origin: decide::DenyOrigin::Gotcha,
    };
    merge_policy_result(
        &mut edit_adapter,
        HookVariant::ClaudePreEdit,
        Decision::Advisory {
            context: "Must not lower the edit deny.".into(),
        },
        vec![],
    );
    assert!(matches!(edit_adapter.decision, Decision::Deny { .. }));
    assert!(edit_adapter
        .stdout
        .contains(r#""permissionDecision":"deny""#));

    let mut edit_consulted = AdapterResult {
        stdout: String::new(),
        stderr: String::new(),
        exit_code: 0,
        events: vec![],
        decision: Decision::AlreadyConsulted {
            context: "Record already consulted. Gotcha guidance.".into(),
        },
        basis_hash: None,
    };
    merge_policy_result(
        &mut edit_consulted,
        HookVariant::ClaudePreEdit,
        Decision::Advisory {
            context: "Policy rule for this edit.".into(),
        },
        vec![],
    );
    assert!(matches!(edit_consulted.decision, Decision::Advisory { .. }));
    assert!(edit_consulted.stdout.contains("Policy rule for this edit."));
    assert!(edit_consulted.stdout.contains("additionalContext"));
    assert!(!edit_consulted.stdout.contains("permissionDecision"));
    assert!(!edit_consulted.stdout.contains("Record already consulted"));

    let mut bash_consulted = AdapterResult {
        stdout: String::new(),
        stderr: String::new(),
        exit_code: 0,
        events: vec![],
        decision: Decision::AlreadyConsulted {
            context: "Record already consulted. Gotcha guidance.".into(),
        },
        basis_hash: None,
    };
    merge_policy_result(
        &mut bash_consulted,
        HookVariant::ClaudePreBash,
        Decision::Advisory {
            context: "Policy rule for this command.".into(),
        },
        vec![],
    );
    assert!(matches!(
        bash_consulted.decision,
        Decision::AlreadyConsulted { ref context }
            if context.contains("Record already consulted")
                && context.contains("Policy rule for this command.")
    ));
    assert!(bash_consulted
        .stdout
        .contains("Record already consulted. Gotcha guidance."));
    assert!(bash_consulted
        .stdout
        .contains("Policy rule for this command."));
}

#[test]
fn e2e_claude_pre_bash_defers_no_record() {
    // A bash command touching a file with no record must DEFER — empty
    // stdout, so the user's Bash permission prompt is preserved.
    let data = json!({
        "file_key": "file:src/new.rs",
        "file_record": null,
        "gotcha_records": {},
        "consulted": false,
        "consulted_recent": false,
        "store_error": false,
        "gotcha_error": false
    });
    let result = process_eval_response(HookVariant::ClaudePreBash, "src/new.rs", &data, None);

    assert_eq!(result.exit_code, 0);
    assert!(
        result.stdout.is_empty(),
        "no-record bash read must defer, got: {}",
        result.stdout
    );
    assert!(matches!(result.decision, Decision::NoRecord));
}

#[test]
fn e2e_claude_pre_bash_advisory_injects_context_without_permission_decision() {
    // Advisory on the bash path: context is injected via additionalContext
    // ONLY — no permissionDecision field at all, so the permission flow
    // proceeds normally.
    let data = json!({
        "file_key": "file:src/lib.rs",
        "file_record": {
            "value": "Library root",
            "confidence": { "value": 0.45 },
            "quality": { "value": 0.5 },
            "staleness": { "value": 0.1, "tier": "fresh" },
            "payload": { "gotcha_keys": [] }
        },
        "gotcha_records": {},
        "consulted": false,
        "consulted_recent": false,
        "store_error": false,
        "gotcha_error": false
    });
    let result = process_eval_response(HookVariant::ClaudePreBash, "src/lib.rs", &data, None);

    assert_eq!(result.exit_code, 0);
    let json: serde_json::Value =
        serde_json::from_str(&result.stdout).expect("stdout must be valid JSON");
    assert!(
        json.pointer("/hookSpecificOutput/permissionDecision")
            .is_none(),
        "bash advisory must NOT carry a permissionDecision, got: {}",
        result.stdout
    );
    assert!(
        json.pointer("/hookSpecificOutput/additionalContext")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .contains("[mati]"),
        "bash advisory must inject context, got: {}",
        result.stdout
    );
    assert!(matches!(result.decision, Decision::Advisory { .. }));
}

#[test]
fn e2e_claude_pre_bash_deny_still_denies() {
    // The defer change must not weaken the deny: a confirmed unconsulted
    // gotcha on the bash path still emits permissionDecision:"deny".
    let data = deny_eligible_eval_data();
    let result = process_eval_response(HookVariant::ClaudePreBash, "src/main.rs", &data, None);

    let json: serde_json::Value =
        serde_json::from_str(&result.stdout).expect("stdout must be valid JSON");
    assert_eq!(
        json.pointer("/hookSpecificOutput/permissionDecision")
            .and_then(|v| v.as_str()),
        Some("deny")
    );
}

#[test]
fn escape_json_string_escapes_control_chars() {
    // All of U+0000–U+001F must be escaped, not just \n \r \t — an
    // unescaped control char makes the deny JSON unparseable (lost deny).
    let hostile = "a\u{08}b\u{0C}c\u{1B}d\"e\\f\ng";
    let escaped = escape_json_string(hostile);
    let wrapped = format!("{{\"v\":\"{escaped}\"}}");
    let parsed: serde_json::Value =
        serde_json::from_str(&wrapped).expect("escaped output must be valid inside JSON");
    assert_eq!(parsed.pointer("/v").and_then(|v| v.as_str()), Some(hostile));
}

#[test]
fn e2e_no_record_allows() {
    let data = json!({
        "file_key": "file:src/new.rs",
        "file_record": null,
        "gotcha_records": {},
        "consulted": false,
        "consulted_recent": false,
        "store_error": false,
        "gotcha_error": false
    });
    let result = process_eval_response(HookVariant::ClaudePreRead, "src/new.rs", &data, None);

    assert_eq!(result.exit_code, 0);
    assert!(matches!(result.decision, Decision::NoRecord));
    assert_eq!(result.events.len(), 1);
    assert!(matches!(&result.events[0], HookEvent::Miss { .. }));
}

// ── ClaudePreEdit (WI-01, L1 edit-gate) ─────────────────────────────

#[test]
fn extract_path_claude_pre_edit_file_path() {
    // Edit/Write both pass the target at tool_input.file_path, same as Read.
    let input = json!({"tool_input": {"file_path": "/repo/src/pay.rs"}});
    assert_eq!(
        extract_path(&input, HookVariant::ClaudePreEdit),
        Some("/repo/src/pay.rs".into())
    );
}

#[test]
fn extract_path_claude_pre_edit_notebook_path() {
    // NotebookEdit carries the target at tool_input.notebook_path, not
    // file_path — the edit gate must still extract it so notebooks are gated.
    let input = json!({"tool_input": {"notebook_path": "/repo/nb/analysis.ipynb"}});
    assert_eq!(
        extract_path(&input, HookVariant::ClaudePreEdit),
        Some("/repo/nb/analysis.ipynb".into())
    );
}

#[test]
fn edit_policy_actions_use_the_path_category_and_target() {
    let action = decide::normalize_action(None, Some("migrations/prod.sql"));
    assert_eq!(action.tool, "path");
    assert_eq!(action.target_path.as_deref(), Some("migrations/prod.sql"));
    assert_eq!(action.files, vec!["migrations/prod.sql"]);
}

#[test]
fn extract_path_codex_pre_bash_egrep_and_fgrep() {
    // egrep/fgrep satisfy Claude's read-before-edit; mati now detects them so
    // they can't be used to satisfy the read requirement unconsulted.
    let egrep = json!({"tool_input": {"command": "egrep TODO src/main.rs"}});
    assert_eq!(
        extract_path(&egrep, HookVariant::CodexPreBash),
        Some("src/main.rs".into())
    );
    let fgrep = json!({"tool_input": {"command": "fgrep needle src/main.rs"}});
    assert_eq!(
        extract_path(&fgrep, HookVariant::CodexPreBash),
        Some("src/main.rs".into())
    );
}

#[test]
fn e2e_claude_pre_edit_denies_blind_edit() {
    // Blind edit (no consultation receipt) to a confirmed-gotcha file must be
    // denied with an edit-flavored Claude PreToolUse deny JSON.
    let data = deny_eligible_eval_data();
    let result = process_eval_response(HookVariant::ClaudePreEdit, "src/main.rs", &data, None);

    assert_eq!(
        result.exit_code, 0,
        "Claude always exits 0; deny is in the JSON"
    );
    let json: serde_json::Value =
        serde_json::from_str(&result.stdout).expect("deny stdout must be valid JSON");
    assert_eq!(
        json.pointer("/hookSpecificOutput/permissionDecision")
            .and_then(|v| v.as_str()),
        Some("deny")
    );
    // The message now comes from the decision's own reason (like the read gate), so it
    // instructs the agent to consult; the edit-vs-read distinction lives in the event below
    // (EditBlocked → `edit_blocked_unconsulted`), not the message wording.
    assert!(
        json.pointer("/hookSpecificOutput/permissionDecisionReason")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .contains("mem_get"),
        "deny reason must instruct the agent to consult, got: {}",
        result.stdout
    );
    // Plane 2: records an edit-attributed Deny enforcement event.
    assert_eq!(result.events.len(), 1);
    assert!(matches!(&result.events[0], HookEvent::EditBlocked { .. }));
    assert!(matches!(result.decision, Decision::Deny { .. }));
}

#[test]
fn e2e_claude_pre_edit_defers_after_consult() {
    // With a RECENT consultation receipt (consulted_recent, matching the
    // Codex apply_patch edit gate), the edit keeps its normal permission
    // flow and defers silently — deliberately NOT a forced allow.
    let mut data = deny_eligible_eval_data();
    data["consulted_recent"] = json!(true);
    let result = process_eval_response(HookVariant::ClaudePreEdit, "src/main.rs", &data, None);

    assert_eq!(result.exit_code, 0);
    assert!(result.stdout.is_empty());
    assert!(result.stderr.is_empty());
    assert!(matches!(result.decision, Decision::AlreadyConsulted { .. }));
    // Plane 2: a consulted edit records an EditConsulted event (→
    // AllowAfterReceipt, reason `edit_after_receipt`) — the audit evidence
    // that this edit was preceded by a recent consult.
    assert_eq!(result.events.len(), 1);
    assert!(matches!(&result.events[0], HookEvent::EditConsulted { .. }));
}

#[test]
fn e2e_claude_pre_edit_defers_no_record() {
    // No record / no gotcha → defer (never force-allow, never block) so the
    // user's normal edit-permission flow applies.
    let data = json!({
        "file_key": "file:src/new.rs",
        "file_record": null,
        "gotcha_records": {},
        "consulted": false,
        "consulted_recent": false,
        "store_error": false,
        "gotcha_error": false
    });
    let result = process_eval_response(HookVariant::ClaudePreEdit, "src/new.rs", &data, None);

    assert_eq!(result.exit_code, 0);
    assert!(result.stdout.is_empty(), "no-record edit must defer");
    assert!(matches!(result.decision, Decision::NoRecord));
    // No block event for a non-gotcha file.
    assert!(result.events.is_empty());
}

#[test]
fn e2e_claude_pre_edit_store_error_defers() {
    // Fail-open: a store error must defer (empty stdout), never block the edit.
    let data = json!({
        "file_key": "file:src/main.rs",
        "file_record": null,
        "gotcha_records": {},
        "consulted": false,
        "consulted_recent": false,
        "store_error": true,
        "gotcha_error": false
    });
    let result = process_eval_response(HookVariant::ClaudePreEdit, "src/main.rs", &data, None);

    assert_eq!(result.exit_code, 0, "store error must fail open (defer)");
    assert!(result.stdout.is_empty());
    assert_eq!(result.decision, Decision::Allow);
}

// ── canonical_rel_path (WI-20 symlink-bypass fallback) ──────────────────
//
// These exercise the canonical-key resolver directly against a real
// filesystem (tempdir + real symlinks). The full deny-through-symlink
// enforcement is proven end-to-end in `tests/hook_decide_integration.rs`.

// Unix-only: these create real symlinks via `std::os::unix::fs::symlink`.
// The CI test matrix is Unix-only (ubuntu + macos); gating at the function
// level keeps them honest if a Windows runner is ever added, matching the
// integration test's `#[cfg(unix)]`.
#[cfg(unix)]
#[test]
fn canonical_rel_resolves_symlink_to_real_target_key() {
    // A symlink to a real in-repo file must canonicalize to the REAL
    // target's repo-relative key — this is the bypass-closing resolution.
    let repo = tempfile::TempDir::new().expect("tempdir");
    let root = repo.path();
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(root.join("src/real.rs"), "fn x() {}\n").unwrap();
    // link.rs (at repo root) → src/real.rs
    std::os::unix::fs::symlink(root.join("src/real.rs"), root.join("link.rs")).unwrap();

    // Accessed via the symlink. Lexical key would be "link.rs"; canonical
    // must resolve to "src/real.rs".
    let got = canonical_rel_path(
        root.join("link.rs").to_str().unwrap(),
        root,
        Some(root),
        "link.rs",
    );
    assert_eq!(got.as_deref(), Some("src/real.rs"));
}

#[cfg(unix)]
#[test]
fn canonical_rel_relative_access_resolves_against_cwd() {
    // A bare relative shell arg (`cat link.rs`) resolves against cwd (the
    // repo root) before canonicalization.
    let repo = tempfile::TempDir::new().expect("tempdir");
    let root = repo.path();
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(root.join("src/real.rs"), "fn x() {}\n").unwrap();
    std::os::unix::fs::symlink(root.join("src/real.rs"), root.join("link.rs")).unwrap();

    let got = canonical_rel_path("link.rs", root, Some(root), "link.rs");
    assert_eq!(got.as_deref(), Some("src/real.rs"));
}

#[test]
fn canonical_rel_non_symlink_is_noop() {
    // A plain (non-symlink) in-repo file canonicalizes back to its own
    // lexical key — the helper returns None so we skip the redundant
    // second daemon round-trip (zero-cost common path).
    let repo = tempfile::TempDir::new().expect("tempdir");
    let root = repo.path();
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(root.join("src/real.rs"), "fn x() {}\n").unwrap();

    let got = canonical_rel_path(
        root.join("src/real.rs").to_str().unwrap(),
        root,
        Some(root),
        "src/real.rs",
    );
    assert_eq!(got, None, "non-symlink access must not trigger a fallback");
}

#[cfg(unix)]
#[test]
fn canonical_rel_outside_repo_is_none() {
    // A symlink pointing OUTSIDE the repo must NOT yield a key — it can't
    // match a store record and must never deny. Falls back to lexical-only.
    let repo = tempfile::TempDir::new().expect("tempdir");
    let outside = tempfile::TempDir::new().expect("tempdir");
    let root = repo.path();
    std::fs::write(outside.path().join("secret.rs"), "fn x() {}\n").unwrap();
    std::os::unix::fs::symlink(outside.path().join("secret.rs"), root.join("escape.rs")).unwrap();

    let got = canonical_rel_path(
        root.join("escape.rs").to_str().unwrap(),
        root,
        Some(root),
        "escape.rs",
    );
    assert_eq!(got, None, "out-of-repo symlink target must yield no key");
}

#[test]
fn canonical_rel_no_repo_root_is_none() {
    // Without a repo root we can't form a repo-relative key — fall back to
    // lexical-only (never crash).
    let got = canonical_rel_path("/some/abs/path.rs", Path::new("/tmp"), None, "path.rs");
    assert_eq!(got, None);
}

#[test]
fn canonical_rel_nonexistent_leaf_under_real_dir() {
    // canonicalize_lenient tolerates a missing leaf: a not-yet-created file
    // under a real (possibly symlinked) directory still yields its key.
    let repo = tempfile::TempDir::new().expect("tempdir");
    let root = repo.path();
    std::fs::create_dir_all(root.join("src")).unwrap();

    // No symlink, leaf does not exist → canonicalizes to its own lexical
    // key → no-op (None).
    let got = canonical_rel_path(
        root.join("src/ghost.rs").to_str().unwrap(),
        root,
        Some(root),
        "src/ghost.rs",
    );
    assert_eq!(got, None);
}

// ── Floor consult mandate overlay ────────────────────────────────────────

fn allow_adapter() -> AdapterResult {
    AdapterResult {
        stdout: "allow".to_string(),
        stderr: String::new(),
        exit_code: 0,
        events: vec![],
        basis_hash: None,
        decision: Decision::Allow,
    }
}

fn phi_globs() -> GlobSet {
    consult_globset_from(r#"["phi/**"]"#).unwrap()
}

#[test]
fn consult_globset_from_parses_and_rejects() {
    assert!(consult_globset_from(r#"["phi/**","src/pay/**"]"#).is_some());
    assert!(consult_globset_from("[]").is_none());
    assert!(consult_globset_from("not json").is_none());
}

#[test]
fn mandate_denies_unconsulted_match() {
    let g = phi_globs();
    let mut a = allow_adapter();
    apply_consult_mandate(
        &mut a,
        HookVariant::ClaudePreRead,
        "phi/records.rs",
        false,
        Some(&g),
    );
    assert!(matches!(a.decision, Decision::Deny { .. }));
    assert!(
        a.stdout.contains("deny"),
        "pre-read deny output must be emitted"
    );
    assert!(
        matches!(
            a.events.first(),
            Some(HookEvent::FloorConsultBlocked { .. })
        ),
        "floor mandate deny must emit its own event (distinct audit reason code)"
    );
}

#[test]
fn mandate_pre_edit_deny_uses_org_policy_message() {
    let g = phi_globs();
    let mut a = allow_adapter();
    apply_consult_mandate(
        &mut a,
        HookVariant::ClaudePreEdit,
        "phi/records.rs",
        false,
        Some(&g),
    );
    assert!(matches!(a.decision, Decision::Deny { .. }));
    assert!(
        a.stdout.contains("deny") && a.stdout.contains("Org policy"),
        "pre-edit mandate deny must show the org-policy reason, not 'Confirmed gotcha'; got {}",
        a.stdout
    );
}

#[test]
fn mandate_allows_when_consulted() {
    let g = phi_globs();
    let mut a = allow_adapter();
    apply_consult_mandate(
        &mut a,
        HookVariant::ClaudePreRead,
        "phi/records.rs",
        true,
        Some(&g),
    );
    assert!(
        matches!(a.decision, Decision::Allow),
        "consultation satisfies the mandate"
    );
}

#[test]
fn mandate_noop_on_nonmatch_or_no_globs() {
    let g = phi_globs();
    let mut a = allow_adapter();
    apply_consult_mandate(
        &mut a,
        HookVariant::ClaudePreRead,
        "src/main.rs",
        false,
        Some(&g),
    );
    assert!(
        matches!(a.decision, Decision::Allow),
        "non-matching path is untouched"
    );

    let mut b = allow_adapter();
    apply_consult_mandate(
        &mut b,
        HookVariant::ClaudePreRead,
        "phi/records.rs",
        false,
        None,
    );
    assert!(
        matches!(b.decision, Decision::Allow),
        "no mandate -> no change"
    );
}

#[test]
fn mandate_applies_to_apply_patch_variant() {
    // Parity: the enterprise consult mandate gates Codex apply_patch edits
    // exactly like reads/edits — deny with exit 2 + mem_get instruction.
    let g = phi_globs();
    let mut a = allow_adapter();
    apply_consult_mandate(
        &mut a,
        HookVariant::CodexPreApplyPatch,
        "phi/records.rs",
        false,
        Some(&g),
    );
    assert!(matches!(a.decision, Decision::Deny { .. }));
    assert_eq!(a.exit_code, 2, "apply_patch mandate deny must exit 2");
    assert!(
        a.stderr.contains("mem_get"),
        "apply_patch mandate deny must instruct consultation, got: {}",
        a.stderr
    );
}

#[test]
fn mandate_preserves_existing_deny() {
    let g = phi_globs();
    let mut a = AdapterResult {
        stdout: "x".to_string(),
        stderr: String::new(),
        exit_code: 0,
        events: vec![],
        decision: Decision::Deny {
            file_key: "file:phi/x.rs".to_string(),
            reason: "gotcha-deny".to_string(),
            origin: decide::DenyOrigin::Gotcha,
        },
        basis_hash: None,
    };
    apply_consult_mandate(
        &mut a,
        HookVariant::ClaudePreRead,
        "phi/x.rs",
        false,
        Some(&g),
    );
    match &a.decision {
        Decision::Deny { reason, .. } => {
            assert_eq!(reason, "gotcha-deny", "deny > consult; not overwritten")
        }
        _ => panic!("expected the pre-existing Deny to survive"),
    }
}

#[test]
fn extract_path_keeps_bracketed_route_files() {
    // Next.js dynamic routes: `app/[slug]/page.tsx`, `pages/[id].tsx`.
    // Ordinary indexed files, not globs.
    let input = json!({"tool_input": {"command": "cat app/[slug]/page.tsx"}});
    assert_eq!(
        extract_path(&input, HookVariant::CodexPreBash).as_deref(),
        Some("app/[slug]/page.tsx")
    );
}

// ── FileChanged path resolution ─────────────────────────────────────────────

/// Claude Code echoes `file_path` back in the spelling mati handed to
/// `watchPaths`, uncanonicalized, while `cwd` is canonical. On macOS that is
/// `/tmp` vs `/private/tmp` — the lexical compare that made F1 block nothing.
#[test]
fn watched_rel_path_survives_the_symlinked_tmp_prefix() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    std::fs::create_dir_all(root.join("src")).expect("mkdir");
    std::fs::write(root.join("src/a.rs"), "fn main() {}").expect("write");

    let watched = root.join("src/a.rs").display().to_string();
    assert_eq!(
        super::entry::watched_rel_path(&watched, root).as_deref(),
        Some("src/a.rs")
    );

    // The same file reached through an uncanonicalized prefix must resolve to
    // the same key, not fall out of the repo.
    if let Ok(canon_root) = root.canonicalize() {
        if canon_root != root {
            assert_eq!(
                super::entry::watched_rel_path(&watched, &canon_root).as_deref(),
                Some("src/a.rs"),
                "an uncanonicalized watch path must still resolve under a canonical root"
            );
        }
    }
}

#[test]
fn watched_rel_path_rejects_paths_outside_the_repo() {
    let dir = tempfile::tempdir().expect("tempdir");
    assert!(super::entry::watched_rel_path("/etc/hosts", dir.path()).is_none());
}

/// A deleted leaf cannot canonicalize; the lexical strip must still produce
/// the key so the record can be found.
#[test]
fn watched_rel_path_falls_back_for_a_missing_leaf() {
    let dir = tempfile::tempdir().expect("tempdir");
    let gone = dir.path().join("src/gone.rs").display().to_string();
    assert_eq!(
        super::entry::watched_rel_path(&gone, dir.path()).as_deref(),
        Some("src/gone.rs")
    );
}
