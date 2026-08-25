//! Spike: prove the content-deny/steer (`deny_if`) axis is buildable end to end.
//!
//! Covers the claims the frontier design rests on:
//! 1. block mode → `Decision::Deny` with the distinct `PolicyContentDenied`;
//! 2. it is unconditional — denies independent of `satisfied`/`requires`;
//! 3. steer mode warns ONLY when the content matches (`Warn`), and is silent on
//!    a non-match (`Inert`);
//! 4. the global kill-switch (`!strict`) degrades a content-deny to a warning;
//! 5. `PolicyRecord` stays back-compatible (old payload → `None`; new round-trips);
//! 6. `CommandGlob` is category-agnostic and matches on `argv`;
//!    `PathGlob` governs the path channel (`target_path ∪ files`) that edits and
//!    reads carry, and never reads `argv`.

use mati_core::hooks::decide::{self, Decision, DenyOrigin, PolicyVerdict};
use mati_core::store::{ActionPredicate, ContentOutcome, PolicyRecord, PolicyStage};

fn verdict(content: ContentOutcome, block: bool, satisfied: bool) -> PolicyVerdict {
    PolicyVerdict {
        key: "policy:content".into(),
        rule: "content rule".into(),
        requires_key: String::new(),
        block,
        satisfied,
        stage: PolicyStage::Enforce,
        content,
    }
}

#[test]
fn block_mode_denies_with_distinct_origin() {
    let result =
        decide::evaluate_policy_verdicts(&[verdict(ContentOutcome::Deny, true, false)], true);
    match result.decision {
        Decision::Deny { origin, .. } => assert_eq!(origin, DenyOrigin::PolicyContentDenied),
        other => panic!("expected Deny, got {other:?}"),
    }
}

#[test]
fn content_deny_is_unconditional_even_when_consult_satisfied() {
    let result =
        decide::evaluate_policy_verdicts(&[verdict(ContentOutcome::Deny, true, true)], true);
    assert!(matches!(
        result.decision,
        Decision::Deny {
            origin: DenyOrigin::PolicyContentDenied,
            ..
        }
    ));
}

#[test]
fn steer_mode_warns_only_on_a_content_match() {
    // Warn (content matched, steer author) → advisory context, no deny.
    let matched =
        decide::evaluate_policy_verdicts(&[verdict(ContentOutcome::Warn, false, true)], true);
    assert!(matches!(matched.decision, Decision::Advisory { .. }));

    // Inert (content did not match) → silent: no deny, no advisory.
    let unmatched =
        decide::evaluate_policy_verdicts(&[verdict(ContentOutcome::Inert, false, true)], true);
    assert!(matches!(unmatched.decision, Decision::Allow));
}

#[test]
fn global_kill_switch_degrades_content_deny_to_a_warning() {
    // strict = false → a would-be content deny degrades to advisory, not Deny.
    let result =
        decide::evaluate_policy_verdicts(&[verdict(ContentOutcome::Deny, true, false)], false);
    assert!(matches!(result.decision, Decision::Advisory { .. }));
}

#[test]
fn old_policy_json_without_deny_if_deserializes_to_none() {
    let json = r#"{
        "name":"guard","rule":"r","reason":"why","scope":"repo",
        "mode":"block",
        "trigger":{"command_glob":"git push*--force*"},
        "requires":{"key":"","via":[],"freshness":{"ttl_secs":900,"fingerprint":false}},
        "stage":"enforce","severity":"normal","created_by":"dev"
    }"#;
    let policy: PolicyRecord = serde_json::from_str(json).expect("old payload must deserialize");
    assert!(policy.deny_if.is_none());
}

#[test]
fn deny_if_roundtrips_through_serde() {
    let json = r#"{
        "name":"no-force-push","rule":"r","reason":"why","scope":"repo",
        "mode":"block",
        "trigger":{},
        "deny_if":{"command_glob":"git push*--force*"},
        "requires":{"key":"","via":[],"freshness":{"ttl_secs":900,"fingerprint":false}},
        "stage":"enforce","severity":"normal","created_by":"dev"
    }"#;
    let policy: PolicyRecord = serde_json::from_str(json).expect("new payload must deserialize");
    let back: PolicyRecord =
        serde_json::from_str(&serde_json::to_string(&policy).unwrap()).unwrap();
    assert_eq!(
        back.deny_if,
        Some(ActionPredicate::CommandGlob("git push*--force*".into()))
    );
}

#[test]
fn command_glob_is_category_agnostic() {
    use mati_core::store::PolicyMode;
    // Same mechanism governs a git flag and a shell verb — not DB-specific.
    let force = ActionPredicate::CommandGlob("git push*--force*".into());
    assert_eq!(
        force.outcome(
            &args(&["git", "push", "--force", "origin"]),
            &[],
            PolicyMode::Block
        ),
        ContentOutcome::Deny
    );
    assert_eq!(
        force.outcome(&args(&["git", "push", "origin"]), &[], PolicyMode::Block),
        ContentOutcome::Inert
    );

    let rmrf = ActionPredicate::CommandGlob("rm *-rf*".into());
    assert_eq!(
        rmrf.outcome(&args(&["rm", "-rf", "build"]), &[], PolicyMode::Steer),
        ContentOutcome::Warn
    );
}

#[test]
fn path_glob_governs_the_path_channel_not_argv() {
    use mati_core::store::PolicyMode;
    // A path predicate fires on target_path ∪ files — the edit/read channel that
    // carries no argv — and ignores argv entirely.
    let secrets = ActionPredicate::PathGlob("**/secrets/**".into());
    assert_eq!(
        secrets.outcome(&[], &args(&["src/secrets/key.pem"]), PolicyMode::Block),
        ContentOutcome::Deny
    );
    // Match anywhere in the file set, not just the first path.
    assert_eq!(
        secrets.outcome(
            &[],
            &args(&["src/main.rs", "config/secrets/db.env"]),
            PolicyMode::Steer
        ),
        ContentOutcome::Warn
    );
    // No path match → Inert, even when argv is non-empty.
    assert_eq!(
        secrets.outcome(
            &args(&["cat", "secrets"]),
            &args(&["src/main.rs"]),
            PolicyMode::Block
        ),
        ContentOutcome::Inert
    );
    // A PathGlob never reads argv: an argv-only "secrets" mention does not match.
    assert_eq!(
        secrets.outcome(
            &args(&["psql", "-c", "select * from secrets"]),
            &[],
            PolicyMode::Block
        ),
        ContentOutcome::Inert
    );
}

#[test]
fn path_glob_roundtrips_through_serde() {
    let predicate = ActionPredicate::PathGlob("**/prod/**".into());
    let json = serde_json::to_string(&predicate).unwrap();
    assert_eq!(json, r#"{"path_glob":"**/prod/**"}"#);
    let back: ActionPredicate = serde_json::from_str(&json).unwrap();
    assert_eq!(back, predicate);
}

fn args(tokens: &[&str]) -> Vec<String> {
    tokens.iter().map(|token| token.to_string()).collect()
}
