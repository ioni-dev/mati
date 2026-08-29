use super::*;
use serde_json::json;

// ── extract_apply_patch_files ────────────────────────────────────────

#[test]
fn apply_patch_single_update() {
    let patch = "*** Begin Patch\n*** Update File: src/main.rs\n@@\n-old\n+new\n*** End Patch\n";
    assert_eq!(extract_apply_patch_files(patch), vec!["src/main.rs"]);
}

#[test]
fn apply_patch_multi_file_add_update_delete() {
    let patch = "*** Begin Patch\n\
            *** Update File: src/a.rs\n@@\n+x\n\
            *** Add File: src/b.rs\n+y\n\
            *** Delete File: src/c.rs\n\
            *** End Patch\n";
    assert_eq!(
        extract_apply_patch_files(patch),
        vec!["src/a.rs", "src/b.rs", "src/c.rs"]
    );
}

#[test]
fn apply_patch_rename_includes_source_and_destination() {
    let patch =
            "*** Begin Patch\n*** Update File: src/old.rs\n*** Move to: src/new.rs\n@@\n+x\n*** End Patch\n";
    assert_eq!(
        extract_apply_patch_files(patch),
        vec!["src/old.rs", "src/new.rs"]
    );
}

#[test]
fn apply_patch_ignores_marker_inside_diff_body() {
    // A diff line that ADDS text resembling a marker must NOT be parsed as
    // an envelope marker: diff body lines are prefixed (+/-/space), so they
    // never begin at column 0 with "*** ".
    let patch = "*** Begin Patch\n\
            *** Update File: src/real.rs\n@@\n\
            +*** Update File: src/fake.rs\n\
            + *** Add File: src/also_fake.rs\n\
            *** End Patch\n";
    assert_eq!(extract_apply_patch_files(patch), vec!["src/real.rs"]);
}

#[test]
fn apply_patch_dedups_repeated_path() {
    let patch =
        "*** Begin Patch\n*** Update File: src/a.rs\n*** Update File: src/a.rs\n*** End Patch\n";
    assert_eq!(extract_apply_patch_files(patch), vec!["src/a.rs"]);
}

#[test]
fn apply_patch_empty_or_no_markers() {
    assert!(extract_apply_patch_files("").is_empty());
    assert!(extract_apply_patch_files("just some text\nno markers here").is_empty());
    assert!(extract_apply_patch_files("*** Begin Patch\n*** End Patch\n").is_empty());
}

#[test]
fn apply_patch_trims_trailing_whitespace() {
    let patch = "*** Update File: src/spaced.rs   \n";
    assert_eq!(extract_apply_patch_files(patch), vec!["src/spaced.rs"]);
}

#[test]
fn apply_patch_dedup_stays_linear_at_scale() {
    // 50_000 distinct markers, each repeated once (100_000 lines total).
    // At `opt-level = 1` (the [profile.test] setting) the old O(m^2)
    // `Vec::iter().any(...)` scan took ~1.2s for 50_000 distinct paths on
    // dev hardware — 500x the ~2ms this HashSet-backed version takes, and
    // growing quadratically past this point. 50_000 keeps that margin
    // comfortably under nextest's 30s local slow-timeout even if the O(m^2)
    // path is reintroduced, while still being large enough to prove it.
    const N: usize = 50_000;
    let mut patch = String::from("*** Begin Patch\n");
    for i in 0..N {
        patch.push_str(&format!("*** Add File: src/file_{i}.rs\n"));
        patch.push_str(&format!("*** Add File: src/file_{i}.rs\n")); // duplicate marker
    }
    patch.push_str("*** End Patch\n");

    let result = extract_apply_patch_files(&patch);

    assert_eq!(result.len(), N);
    for (i, path) in result.iter().enumerate() {
        assert_eq!(path, &format!("src/file_{i}.rs"));
    }
}

// ── classify_command ─────────────────────────────────────────────────

#[test]
fn classify_cat() {
    assert_eq!(
        classify_command("cat src/main.rs"),
        Some(CommandClass::CatLike)
    );
}

#[test]
fn classify_head_with_flag() {
    assert_eq!(
        classify_command("head -n 10 file.rs"),
        Some(CommandClass::CatLike)
    );
}

#[test]
fn classify_leading_whitespace() {
    assert_eq!(classify_command("  cat file"), Some(CommandClass::CatLike));
}

#[test]
fn classify_less() {
    assert_eq!(
        classify_command("less README.md"),
        Some(CommandClass::CatLike)
    );
}

#[test]
fn classify_tail() {
    assert_eq!(
        classify_command("tail -f log.txt"),
        Some(CommandClass::CatLike)
    );
}

#[test]
fn classify_bat() {
    assert_eq!(
        classify_command("bat src/lib.rs"),
        Some(CommandClass::CatLike)
    );
}

#[test]
fn classify_grep() {
    assert_eq!(
        classify_command("grep -rn pattern src/"),
        Some(CommandClass::GrepLike)
    );
}

#[test]
fn classify_rg() {
    assert_eq!(
        classify_command("rg TODO src/"),
        Some(CommandClass::GrepLike)
    );
}

#[test]
fn classify_sed() {
    assert_eq!(
        classify_command("sed -i 's/a/b/' file.rs"),
        Some(CommandClass::GrepLike)
    );
}

#[test]
fn classify_awk() {
    assert_eq!(
        classify_command("awk '{print $1}' file.rs"),
        Some(CommandClass::GrepLike)
    );
}

#[test]
fn classify_ls_is_none() {
    assert_eq!(classify_command("ls -la"), None);
}

#[test]
fn classify_cd_is_none() {
    assert_eq!(classify_command("cd /tmp"), None);
}

#[test]
fn classify_catch_is_none() {
    assert_eq!(classify_command("catch errors"), None);
}

#[test]
fn classify_catalog_is_none() {
    assert_eq!(classify_command("catalog"), None);
}

#[test]
fn classify_grep_bare_is_none() {
    // "grep" with no args — still classifies (extraction returns None later)
    assert_eq!(classify_command("grep"), Some(CommandClass::GrepLike));
}

// ── extract_file_path ───────────────────────────────────────────────

#[test]
fn extract_cat_simple() {
    assert_eq!(
        extract_file_path("cat src/main.rs", CommandClass::CatLike),
        Some("src/main.rs".into())
    );
}

#[test]
fn extract_cat_with_flag() {
    assert_eq!(
        extract_file_path("cat -n src/main.rs", CommandClass::CatLike),
        Some("src/main.rs".into())
    );
}

#[test]
fn extract_cat_quoted_path() {
    assert_eq!(
        extract_file_path(r#"cat "path with spaces/file.rs""#, CommandClass::CatLike),
        Some("path with spaces/file.rs".into())
    );
}

#[test]
fn extract_cat_with_pipe() {
    assert_eq!(
        extract_file_path("cat file.rs | grep foo", CommandClass::CatLike),
        Some("file.rs".into())
    );
}

#[test]
fn extract_cat_with_semicolon() {
    assert_eq!(
        extract_file_path("cat file.rs; echo done", CommandClass::CatLike),
        Some("file.rs".into())
    );
}

#[test]
fn extract_cat_with_and() {
    assert_eq!(
        extract_file_path("cat file.rs && echo ok", CommandClass::CatLike),
        Some("file.rs".into())
    );
}

#[test]
fn extract_grep_last_arg() {
    assert_eq!(
        extract_file_path("grep -rn pattern src/main.rs", CommandClass::GrepLike),
        Some("src/main.rs".into())
    );
}

#[test]
fn extract_grep_quoted_file() {
    assert_eq!(
        extract_file_path(r#"grep pattern "src/main.rs""#, CommandClass::GrepLike),
        Some("src/main.rs".into())
    );
}

#[test]
fn extract_grep_strips_single_quotes() {
    assert_eq!(
        extract_file_path("grep 'pattern' file.rs", CommandClass::GrepLike),
        Some("file.rs".into())
    );
}

#[test]
fn extract_no_args() {
    assert_eq!(extract_file_path("cat", CommandClass::CatLike), None);
}

#[test]
fn extract_only_flags() {
    assert_eq!(extract_file_path("cat -n -v", CommandClass::CatLike), None);
}

// ── normalize_path ──────────────────────────────────────────────────

#[test]
fn normalize_strips_prefix() {
    assert_eq!(
        normalize_path("/home/user/project/src/main.rs", Some("/home/user/project")),
        "src/main.rs"
    );
}

#[test]
fn normalize_dot_slash() {
    assert_eq!(normalize_path("./src/main.rs", None), "src/main.rs");
}

#[test]
fn normalize_dotdot() {
    assert_eq!(normalize_path("src/../src/main.rs", None), "src/main.rs");
}

#[test]
fn normalize_already_relative() {
    assert_eq!(normalize_path("src/main.rs", None), "src/main.rs");
}

#[test]
fn normalize_no_repo_root() {
    assert_eq!(
        normalize_path("/abs/path/file.rs", None),
        "/abs/path/file.rs"
    );
}

#[test]
fn normalize_keeps_out_of_repo_paths_absolute() {
    // A read outside the repo used to lose its leading slash, minting
    // `file:Users/ioni/...` — a key shaped like a repo-relative path that
    // matches no record and pollutes the daily miss aggregate.
    assert_eq!(
        normalize_path(
            "/Users/ioni/.codex/skills/mati/SKILL.md",
            Some("/Users/ioni/Documents/mati")
        ),
        "/Users/ioni/.codex/skills/mati/SKILL.md"
    );
}

#[test]
fn normalize_collapses_dots_in_out_of_repo_paths() {
    assert_eq!(
        normalize_path("/var/tmp/./a/b/../c.rs", Some("/repo")),
        "/var/tmp/a/c.rs"
    );
}

#[test]
fn normalize_bare_root_stays_root() {
    assert_eq!(normalize_path("/", None), "/");
}

#[test]
fn normalize_trailing_slash_root() {
    // repo_root should not have trailing slash, but handle it gracefully.
    assert_eq!(
        normalize_path("/project/src/file.rs", Some("/project")),
        "src/file.rs"
    );
}

#[test]
fn normalize_leading_dotdot_returns_unchanged() {
    // Path escaping above root is out-of-scope — return as-is.
    assert_eq!(normalize_path("../other/file.rs", None), "../other/file.rs");
}

#[test]
fn normalize_deep_dotdot_escape_returns_unchanged() {
    assert_eq!(normalize_path("foo/../../bar.rs", None), "foo/../../bar.rs");
}

#[test]
fn normalize_dotdot_within_scope_ok() {
    // src/../lib/file.rs stays within the repo — collapses fine.
    assert_eq!(normalize_path("src/../lib/file.rs", None), "lib/file.rs");
}

// ── evaluate ────────────────────────────────────────────────────────

fn make_file_record(
    confidence: f32,
    quality: f32,
    staleness: f32,
    staleness_tier: &str,
    gotcha_keys: &[&str],
) -> serde_json::Value {
    json!({
        "value": "Test file purpose",
        "confidence": { "value": confidence },
        "quality": { "value": quality },
        "staleness": { "value": staleness, "tier": staleness_tier },
        "payload": {
            "gotcha_keys": gotcha_keys,
        }
    })
}

fn make_gotcha(confirmed: bool, confidence: f32, quality: f32) -> serde_json::Value {
    json!({
        "value": "Do not use unwrap here",
        "confidence": { "value": confidence },
        "quality": { "value": quality },
        "payload": { "confirmed": confirmed }
    })
}

#[test]
fn eval_no_record() {
    let input = EnforcementInput {
        rel_path: "src/main.rs".into(),
        file_record: None,
        gotcha_records: HashMap::new(),
        already_consulted: false,
        file_exists: None,
    };
    let result = evaluate(&input);
    assert_eq!(result.decision, Decision::NoRecord);
    assert_eq!(result.events.len(), 1);
    assert!(matches!(&result.events[0], HookEvent::Miss { key } if key == "file:src/main.rs"));
}

#[test]
fn eval_tombstone() {
    let input = EnforcementInput {
        rel_path: "src/old.rs".into(),
        file_record: Some(make_file_record(0.8, 0.5, 0.95, "tombstone", &[])),
        gotcha_records: HashMap::new(),
        already_consulted: false,
        file_exists: None,
    };
    let result = evaluate(&input);
    assert_eq!(result.decision, Decision::Tombstone);
    // Tombstone behaves like NoRecord for the agent (allow, no
    // injection), so it shares NoRecord's event — see `eval_no_record`.
    assert_eq!(result.events.len(), 1);
    assert!(matches!(&result.events[0], HookEvent::Miss { key } if key == "file:src/old.rs"));
}

#[test]
fn eval_liability() {
    let input = EnforcementInput {
        rel_path: "src/stale.rs".into(),
        file_record: Some(make_file_record(0.8, 0.5, 0.85, "liability", &[])),
        gotcha_records: HashMap::new(),
        already_consulted: false,
        file_exists: None,
    };
    let result = evaluate(&input);
    assert!(matches!(&result.decision, Decision::Liability { staleness, .. } if *staleness > 0.8));
    assert_eq!(result.events.len(), 1);
    assert!(matches!(&result.events[0], HookEvent::Hit { .. }));
}

/// Staleness gates injection, not enforcement — a qualifying gotcha on
/// a `tombstone`-tier file (no `FileDeleted` signal) must still deny.
#[test]
fn eval_tombstone_with_qualifying_gotcha_denies() {
    let mut gotchas = HashMap::new();
    gotchas.insert("gotcha:test".to_string(), make_gotcha(true, 0.7, 0.5));

    let input = EnforcementInput {
        rel_path: "src/old.rs".into(),
        file_record: Some(make_file_record(
            0.8,
            0.5,
            0.95,
            "tombstone",
            &["gotcha:test"],
        )),
        gotcha_records: gotchas,
        already_consulted: false,
        file_exists: None,
    };
    let result = evaluate(&input);
    assert!(
        matches!(&result.decision, Decision::Deny { origin, .. } if *origin == DenyOrigin::Gotcha),
        "got {:?}",
        result.decision
    );
}

/// Same rule, `liability` tier.
#[test]
fn eval_liability_with_qualifying_gotcha_denies() {
    let mut gotchas = HashMap::new();
    gotchas.insert("gotcha:test".to_string(), make_gotcha(true, 0.7, 0.5));

    let input = EnforcementInput {
        rel_path: "src/stale.rs".into(),
        file_record: Some(make_file_record(
            0.8,
            0.5,
            0.85,
            "liability",
            &["gotcha:test"],
        )),
        gotcha_records: gotchas,
        already_consulted: false,
        file_exists: None,
    };
    let result = evaluate(&input);
    assert!(
        matches!(&result.decision, Decision::Deny { origin, .. } if *origin == DenyOrigin::Gotcha),
        "got {:?}",
        result.decision
    );
}

/// `FileDeleted` is the one signal that still bypasses enforcement —
/// there is no file left to protect. It wins over a maximally-valid
/// confirmed gotcha, unlike the tier alone (see the two tests above).
///
/// `file_exists: None` — the caller did not check — must preserve this
/// exact prior behavior: bypass fires, decision is `Tombstone`, and the
/// event stays the plain `Miss` (never the new bypass event, since an
/// unchecked caller has no confirmation the file is really gone).
#[test]
fn eval_file_deleted_bypasses_qualifying_gotcha() {
    let mut gotchas = HashMap::new();
    gotchas.insert("gotcha:test".to_string(), make_gotcha(true, 0.7, 0.5));

    let mut file_record = make_file_record(0.8, 0.5, 0.95, "tombstone", &["gotcha:test"]);
    file_record["staleness"]["signals"] = json!(["file_deleted"]);

    let input = EnforcementInput {
        rel_path: "src/deleted.rs".into(),
        file_record: Some(file_record),
        gotcha_records: gotchas,
        already_consulted: false,
        file_exists: None,
    };
    let result = evaluate(&input);
    assert_eq!(
        result.decision,
        Decision::Tombstone,
        "FileDeleted must bypass even a qualifying gotcha; got {:?}",
        result.decision
    );
    assert_eq!(result.events.len(), 1);
    assert!(matches!(&result.events[0], HookEvent::Miss { key } if key == "file:src/deleted.rs"));
}

/// The caller's fresher observation wins: a `FileDeleted` signal is a
/// stale snapshot, and once the caller confirms the path exists
/// (delete-then-restore, branch switch, `git stash pop`, a widened
/// sparse-checkout cone), the bypass must not fire — a qualifying
/// confirmed gotcha denies exactly as it would with no signal at all.
#[test]
fn eval_file_deleted_signal_stale_when_path_exists_denies() {
    let mut gotchas = HashMap::new();
    gotchas.insert("gotcha:test".to_string(), make_gotcha(true, 0.7, 0.5));

    let mut file_record = make_file_record(0.8, 0.5, 0.95, "tombstone", &["gotcha:test"]);
    file_record["staleness"]["signals"] = json!(["file_deleted"]);

    let input = EnforcementInput {
        rel_path: "src/restored.rs".into(),
        file_record: Some(file_record),
        gotcha_records: gotchas,
        already_consulted: false,
        file_exists: Some(true),
    };
    let result = evaluate(&input);
    assert!(
        matches!(&result.decision, Decision::Deny { origin, .. } if *origin == DenyOrigin::Gotcha),
        "a restored file with a qualifying gotcha must Deny, not bypass on a stale \
             FileDeleted signal; got {:?}",
        result.decision
    );
    assert!(matches!(
        &result.events[0],
        HookEvent::BlockedUnconsultedRead { key } if key == "file:src/restored.rs"
    ));
}

/// A genuinely deleted file (`file_exists: Some(false)`) still bypasses
/// as `Tombstone` — there is nothing left to enforce against, and
/// denying would create an unclearable phantom deny (the file that would
/// need consulting does not exist). But a qualifying confirmed gotcha
/// WOULD have denied had the file still been there, so that suppression
/// must reach the hash-chained log as a bypass event, not the plain Miss.
#[test]
fn eval_file_confirmed_deleted_with_qualifying_gotcha_emits_bypass_event() {
    let mut gotchas = HashMap::new();
    gotchas.insert("gotcha:test".to_string(), make_gotcha(true, 0.7, 0.5));

    let mut file_record = make_file_record(0.8, 0.5, 0.95, "tombstone", &["gotcha:test"]);
    file_record["staleness"]["signals"] = json!(["file_deleted"]);

    let input = EnforcementInput {
        rel_path: "src/deleted.rs".into(),
        file_record: Some(file_record),
        gotcha_records: gotchas,
        already_consulted: false,
        file_exists: Some(false),
    };
    let result = evaluate(&input);
    assert_eq!(
        result.decision,
        Decision::Tombstone,
        "a confirmed-gone file must still bypass as Tombstone, never Deny \
             (an unclearable phantom deny); got {:?}",
        result.decision
    );
    assert_eq!(result.events.len(), 1);
    assert!(
        matches!(&result.events[0], HookEvent::TombstoneBypassedDeny { key } if key == "file:src/deleted.rs"),
        "a suppressed real deny must reach the enforcement log, not the plain Miss; \
             got {:?}",
        result.events[0]
    );
}

/// Same confirmed deletion, but no gotcha qualifies (unconfirmed here) —
/// nothing was suppressed, so this stays the ordinary per-read Miss and
/// must NOT enter the hash-chained enforcement log (ARCHITECTURE.md
/// section 25: that log is the first thing to break at scale under a
/// per-read event).
#[test]
fn eval_file_confirmed_deleted_without_qualifying_gotcha_stays_plain_miss() {
    let mut gotchas = HashMap::new();
    gotchas.insert("gotcha:test".to_string(), make_gotcha(false, 0.7, 0.5));

    let mut file_record = make_file_record(0.8, 0.5, 0.95, "tombstone", &["gotcha:test"]);
    file_record["staleness"]["signals"] = json!(["file_deleted"]);

    let input = EnforcementInput {
        rel_path: "src/deleted.rs".into(),
        file_record: Some(file_record),
        gotcha_records: gotchas,
        already_consulted: false,
        file_exists: Some(false),
    };
    let result = evaluate(&input);
    assert_eq!(result.decision, Decision::Tombstone);
    assert_eq!(result.events.len(), 1);
    assert!(
        matches!(&result.events[0], HookEvent::Miss { key } if key == "file:src/deleted.rs"),
        "no qualifying gotcha means nothing was suppressed — must stay the plain \
             Miss; got {:?}",
        result.events[0]
    );
}

/// The gate matches a hand-written string; this pins that the real enum
/// serializes to that same string. Without it the helper and its tests
/// could agree on a spelling serde never emits, and the only enforcement
/// bypass would silently never fire on a genuinely deleted file.
#[test]
fn file_deleted_signal_serializes_to_the_string_the_gate_matches() {
    use crate::store::record::StalenessSignal;

    let signal = serde_json::to_value(StalenessSignal::FileDeleted).unwrap();
    assert_eq!(signal, json!("file_deleted"));

    let record = json!({ "staleness": { "signals": [signal] } });
    assert!(json_has_signal(
        &record,
        "/staleness/signals",
        "file_deleted"
    ));
}

#[test]
fn eval_confirmed_gotcha_denies() {
    let mut gotchas = HashMap::new();
    gotchas.insert("gotcha:test".to_string(), make_gotcha(true, 0.7, 0.5));

    let input = EnforcementInput {
        rel_path: "src/main.rs".into(),
        file_record: Some(make_file_record(0.7, 0.5, 0.1, "fresh", &["gotcha:test"])),
        gotcha_records: gotchas,
        already_consulted: false,
        file_exists: None,
    };
    let result = evaluate(&input);
    assert!(matches!(&result.decision, Decision::Deny { .. }));
    assert!(matches!(
        &result.events[0],
        HookEvent::BlockedUnconsultedRead { key } if key == "file:src/main.rs"
    ));
}

/// A gotcha whose code has drifted since it was confirmed must keep
/// denying. Content drift (`health::drift`) is reported by `mati stale` and
/// `mati doctor`; it is deliberately not visible to this function and does
/// not touch `staleness`/`confidence`/`quality`/`confirmed` at all — the
/// gotcha loop runs regardless of the file's staleness tier, so drift
/// has no path to disable enforcement even indirectly.
///
/// The mismatch below is the real shape: `confirmed_content` was stamped at
/// confirm time, the file record's `content_hash` moved on since. Both
/// records carry it; the decision is identical to `eval_confirmed_gotcha_denies`.
#[test]
fn eval_drifted_gotcha_still_denies() {
    let mut gotcha = make_gotcha(true, 0.7, 0.5);
    gotcha["payload"]["confirmed_content"] = json!({ "src/main.rs": "STAMPED_AT_CONFIRM" });

    let mut file_record = make_file_record(0.7, 0.5, 0.1, "fresh", &["gotcha:test"]);
    file_record["payload"]["content_hash"] = json!("CHANGED_SINCE");

    let mut gotchas = HashMap::new();
    gotchas.insert("gotcha:test".to_string(), gotcha);

    let input = EnforcementInput {
        rel_path: "src/main.rs".into(),
        file_record: Some(file_record),
        gotcha_records: gotchas,
        already_consulted: false,
        file_exists: None,
    };
    let result = evaluate(&input);
    assert!(
        matches!(&result.decision, Decision::Deny { origin, .. } if *origin == DenyOrigin::Gotcha),
        "a drifted gotcha must still deny — drift reports, it never disables the gate; got {:?}",
        result.decision
    );
    assert!(matches!(
        &result.events[0],
        HookEvent::BlockedUnconsultedRead { key } if key == "file:src/main.rs"
    ));
}

#[test]
fn eval_unconfirmed_gotcha_allows() {
    let mut gotchas = HashMap::new();
    gotchas.insert("gotcha:test".to_string(), make_gotcha(false, 0.7, 0.5));

    let input = EnforcementInput {
        rel_path: "src/main.rs".into(),
        file_record: Some(make_file_record(0.7, 0.5, 0.1, "fresh", &["gotcha:test"])),
        gotcha_records: gotchas,
        already_consulted: false,
        file_exists: None,
    };
    let result = evaluate(&input);
    // No deny signal — falls through to advisory (confidence 0.7 >= 0.3, quality 0.5 >= 0.4).
    // P4: the unconfirmed gotcha's rule must NOT leak into the injected
    // context — only confirmed gotchas contribute to injection.
    match &result.decision {
        Decision::Advisory { context } => assert!(
            !context.contains("Do not use unwrap here"),
            "unconfirmed gotcha rule leaked into injected context: {context:?}"
        ),
        other => panic!("expected Advisory, got {other:?}"),
    }
}

#[test]
fn eval_low_confidence_gotcha_allows() {
    let mut gotchas = HashMap::new();
    gotchas.insert("gotcha:test".to_string(), make_gotcha(true, 0.4, 0.5));

    let input = EnforcementInput {
        rel_path: "src/main.rs".into(),
        file_record: Some(make_file_record(0.7, 0.5, 0.1, "fresh", &["gotcha:test"])),
        gotcha_records: gotchas,
        already_consulted: false,
        file_exists: None,
    };
    let result = evaluate(&input);
    assert!(matches!(&result.decision, Decision::Advisory { .. }));
}

#[test]
fn eval_low_quality_gotcha_allows() {
    let mut gotchas = HashMap::new();
    gotchas.insert("gotcha:test".to_string(), make_gotcha(true, 0.7, 0.2));

    let input = EnforcementInput {
        rel_path: "src/main.rs".into(),
        file_record: Some(make_file_record(0.7, 0.5, 0.1, "fresh", &["gotcha:test"])),
        gotcha_records: gotchas,
        already_consulted: false,
        file_exists: None,
    };
    let result = evaluate(&input);
    assert!(matches!(&result.decision, Decision::Advisory { .. }));
}

#[test]
fn eval_consulted_downgrades_deny() {
    let mut gotchas = HashMap::new();
    gotchas.insert("gotcha:test".to_string(), make_gotcha(true, 0.7, 0.5));

    let input = EnforcementInput {
        rel_path: "src/main.rs".into(),
        file_record: Some(make_file_record(0.7, 0.5, 0.1, "fresh", &["gotcha:test"])),
        gotcha_records: gotchas,
        already_consulted: true,
        file_exists: None,
    };
    let result = evaluate(&input);
    assert!(matches!(
        &result.decision,
        Decision::AlreadyConsulted { .. }
    ));
    // AlreadyConsulted emits ComplianceHit so the v2 SessionLog dispatch
    // records an AllowAfterReceipt enforcement event (not a fresh receipt).
    assert!(matches!(&result.events[0], HookEvent::ComplianceHit { .. }));
}

#[test]
fn eval_medium_confidence_advisory() {
    let input = EnforcementInput {
        rel_path: "src/main.rs".into(),
        file_record: Some(make_file_record(0.45, 0.5, 0.1, "fresh", &[])),
        gotcha_records: HashMap::new(),
        already_consulted: false,
        file_exists: None,
    };
    let result = evaluate(&input);
    assert!(matches!(&result.decision, Decision::Advisory { .. }));
    assert!(matches!(&result.events[0], HookEvent::Hit { .. }));
}

#[test]
fn eval_low_everything_allows() {
    let input = EnforcementInput {
        rel_path: "src/main.rs".into(),
        file_record: Some(make_file_record(0.1, 0.1, 0.1, "fresh", &[])),
        gotcha_records: HashMap::new(),
        already_consulted: false,
        file_exists: None,
    };
    let result = evaluate(&input);
    assert_eq!(result.decision, Decision::Allow);
    assert!(result.events.is_empty());
}

#[test]
fn eval_staleness_warning_appended() {
    let input = EnforcementInput {
        rel_path: "src/main.rs".into(),
        file_record: Some(make_file_record(0.5, 0.5, 0.5, "stale", &[])),
        gotcha_records: HashMap::new(),
        already_consulted: false,
        file_exists: None,
    };
    let result = evaluate(&input);
    if let Decision::Advisory { context } = &result.decision {
        assert!(context.contains("staleness 0.50"));
    } else {
        panic!("expected Advisory, got {:?}", result.decision);
    }
}

#[test]
fn eval_multiple_gotchas_one_deny() {
    let mut gotchas = HashMap::new();
    gotchas.insert("gotcha:safe".to_string(), make_gotcha(false, 0.7, 0.5));
    gotchas.insert("gotcha:danger".to_string(), make_gotcha(true, 0.8, 0.6));

    let input = EnforcementInput {
        rel_path: "src/main.rs".into(),
        file_record: Some(make_file_record(
            0.7,
            0.5,
            0.1,
            "fresh",
            &["gotcha:safe", "gotcha:danger"],
        )),
        gotcha_records: gotchas,
        already_consulted: false,
        file_exists: None,
    };
    let result = evaluate(&input);
    assert!(matches!(&result.decision, Decision::Deny { .. }));
}

#[test]
fn eval_deny_includes_staleness_note() {
    let mut gotchas = HashMap::new();
    gotchas.insert("gotcha:test".to_string(), make_gotcha(true, 0.7, 0.5));

    let input = EnforcementInput {
        rel_path: "src/main.rs".into(),
        file_record: Some(make_file_record(0.7, 0.5, 0.5, "stale", &["gotcha:test"])),
        gotcha_records: gotchas,
        already_consulted: false,
        file_exists: None,
    };
    let result = evaluate(&input);
    if let Decision::Deny { reason, .. } = &result.decision {
        assert!(reason.contains("staleness"));
    } else {
        panic!("expected Deny");
    }
}

#[test]
fn eval_invalid_json_allows() {
    let input = EnforcementInput {
        rel_path: "src/main.rs".into(),
        file_record: Some(json!("not an object")),
        gotcha_records: HashMap::new(),
        already_consulted: false,
        file_exists: None,
    };
    let result = evaluate(&input);
    // Invalid record treated as no-record.
    assert_eq!(result.decision, Decision::NoRecord);
}

#[test]
fn eval_never_produces_fail_open() {
    // FailOpen is NOT in the Decision enum at all — this test documents the contract.
    // The enum has no FailOpen variant, so this is a compile-time guarantee.
    // This test verifies the doc comment claim by testing boundary cases.
    let cases: Vec<EnforcementInput> = vec![
        EnforcementInput {
            rel_path: "x".into(),
            file_record: None,
            gotcha_records: HashMap::new(),
            already_consulted: false,
            file_exists: None,
        },
        EnforcementInput {
            rel_path: "x".into(),
            file_record: Some(json!(null)),
            gotcha_records: HashMap::new(),
            already_consulted: false,
            file_exists: None,
        },
        EnforcementInput {
            rel_path: "x".into(),
            file_record: Some(json!({})),
            gotcha_records: HashMap::new(),
            already_consulted: false,
            file_exists: None,
        },
    ];
    for input in cases {
        let result = evaluate(&input);
        // If Decision had a FailOpen variant, we'd match against it here.
        // Since it doesn't, this documents that the pure core never fails open.
        assert!(matches!(
            result.decision,
            Decision::Allow
                | Decision::Deny { .. }
                | Decision::AlreadyConsulted { .. }
                | Decision::Advisory { .. }
                | Decision::Liability { .. }
                | Decision::Tombstone
                | Decision::NoRecord
                | Decision::NotFileRead
        ));
    }
}

#[test]
fn eval_context_includes_purpose_and_rules() {
    let mut gotchas = HashMap::new();
    gotchas.insert("gotcha:test".to_string(), make_gotcha(true, 0.7, 0.5));

    let input = EnforcementInput {
        rel_path: "src/main.rs".into(),
        file_record: Some(make_file_record(0.7, 0.5, 0.1, "fresh", &["gotcha:test"])),
        gotcha_records: gotchas,
        already_consulted: true,
        file_exists: None,
    };
    let result = evaluate(&input);
    if let Decision::AlreadyConsulted { context } = &result.decision {
        assert!(context.contains("Purpose: Test file purpose"));
        assert!(context.contains("Do not use unwrap here"));
    } else {
        panic!("expected AlreadyConsulted, got {:?}", result.decision);
    }
}

#[test]
fn eval_blast_radius_warning_for_critical_file() {
    let mut file_record = make_file_record(0.5, 0.5, 0.1, "fresh", &[]);
    // Inject blast_radius into payload
    file_record
        .as_object_mut()
        .unwrap()
        .get_mut("payload")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert(
            "blast_radius".into(),
            json!({ "direct": 45, "transitive": 10, "score": 48.0, "tier": "critical" }),
        );

    let input = EnforcementInput {
        rel_path: "src/core.rs".into(),
        file_record: Some(file_record),
        gotcha_records: HashMap::new(),
        already_consulted: false,
        file_exists: None,
    };
    let result = evaluate(&input);
    if let Decision::Advisory { context } = &result.decision {
        assert!(
            context.contains("Blast radius"),
            "advisory context must include blast radius warning, got: {context}"
        );
        assert!(context.contains("45"), "warning must include direct count");
        assert!(context.contains("critical"), "warning must include tier");
    } else {
        panic!("expected Advisory, got {:?}", result.decision);
    }
}

#[test]
fn eval_no_blast_warning_for_low_file() {
    let mut file_record = make_file_record(0.5, 0.5, 0.1, "fresh", &[]);
    file_record
        .as_object_mut()
        .unwrap()
        .get_mut("payload")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert(
            "blast_radius".into(),
            json!({ "direct": 2, "transitive": 0, "score": 2.0, "tier": "low" }),
        );

    let input = EnforcementInput {
        rel_path: "src/leaf.rs".into(),
        file_record: Some(file_record),
        gotcha_records: HashMap::new(),
        already_consulted: false,
        file_exists: None,
    };
    let result = evaluate(&input);
    if let Decision::Advisory { context } = &result.decision {
        assert!(
            !context.contains("Blast radius"),
            "low blast radius file should NOT have warning, got: {context}"
        );
    } else {
        panic!("expected Advisory, got {:?}", result.decision);
    }
}

// ── detection hardening: prefixes, abs-path, numeric flag values ──────

#[test]
fn classify_strips_sudo_prefix() {
    assert_eq!(
        classify_command("sudo cat src/secret.rs"),
        Some(CommandClass::CatLike)
    );
}

#[test]
fn classify_strips_env_assignment_prefix() {
    assert_eq!(
        classify_command("env LOG=1 cat src/secret.rs"),
        Some(CommandClass::CatLike)
    );
    assert_eq!(
        classify_command("LOG=1 DEBUG=2 cat src/secret.rs"),
        Some(CommandClass::CatLike)
    );
}

#[test]
fn classify_reduces_absolute_path_to_basename() {
    assert_eq!(
        classify_command("/bin/cat src/secret.rs"),
        Some(CommandClass::CatLike)
    );
}

#[test]
fn classify_prefix_on_ungoverned_stays_none() {
    // Stripping a wrapper must not invent a class: `ls` is not governed.
    assert_eq!(classify_command("env X=1 ls"), None);
    assert_eq!(classify_command("sudo chmod +x build"), None);
}

#[test]
fn classify_path_mutating_commands() {
    for cmd in ["rm -rf build", "mv a b", "rmdir dir", "shred -u secret"] {
        assert_eq!(
            classify_command(cmd),
            Some(CommandClass::PathMutating),
            "{cmd}"
        );
    }
    // Wrapper stripping applies to path-mutating commands too.
    assert_eq!(
        classify_command("sudo rm -rf build"),
        Some(CommandClass::PathMutating)
    );
}

#[test]
fn extract_path_mutating_skips_flag_cluster() {
    // `-rf` is skipped like any flag; the positional path survives.
    assert_eq!(
        extract_file_paths("rm -rf src/migrations/x", CommandClass::PathMutating),
        vec!["src/migrations/x".to_string()]
    );
    assert_eq!(
        extract_file_paths("rm -rf a b src/migrations/x", CommandClass::PathMutating),
        vec![
            "a".to_string(),
            "b".to_string(),
            "src/migrations/x".to_string()
        ]
    );
}

#[test]
fn path_mutating_normalizes_to_path_tool() {
    let action = normalize_action(Some("rm -rf src/migrations/0001.sql"), None);
    assert_eq!(action.tool, "path");
    assert_eq!(
        action.target_path.as_deref(),
        Some("src/migrations/0001.sql")
    );
    assert!(action
        .files
        .contains(&"src/migrations/0001.sql".to_string()));
}

#[test]
fn path_mutating_multi_arg_matches_target_path_glob() {
    // A protected path in any positional position must match, not just the first.
    use crate::store::{PolicyMode, PolicyRecord, PolicyStage, PolicyTrigger, Priority};
    let action = normalize_action(Some("rm -rf safe.txt src/migrations/x"), None);
    let policy = PolicyRecord {
        deny_if: None,
        require: None,
        mints: None,
        name: "protect migrations".into(),
        rule: "Consult before deleting migrations.".into(),
        reason: "Migrations are irreversible because they alter production schema.".into(),
        scope: "repo".into(),
        mode: PolicyMode::Block,
        trigger: PolicyTrigger {
            tool: None,
            host_glob: None,
            target_path_glob: Some("src/migrations/**".into()),
            command_glob: None,
        },
        requires: serde_json::from_str(
            r#"{"key":"decision:protect-migrations","via":["mem_get"],"freshness":{"ttl_secs":900}}"#,
        )
        .unwrap(),
        stage: PolicyStage::Enforce,
        severity: Priority::High,
        created_by: "test".into(),
    };
    let set = crate::hooks::policy_match::PolicyMatcherSet::from_policies([(
        "policy:protect-migrations".into(),
        policy,
    )])
    .unwrap();
    assert!(!set.matches(&action).is_empty());
}

#[test]
fn extract_through_sudo_prefix() {
    assert_eq!(
        extract_file_path("sudo cat src/secret.rs", CommandClass::CatLike),
        Some("src/secret.rs".to_string())
    );
}

#[test]
fn extract_through_abs_path() {
    assert_eq!(
        extract_file_path("/bin/cat src/secret.rs", CommandClass::CatLike),
        Some("src/secret.rs".to_string())
    );
}

#[test]
fn extract_skips_numeric_flag_value() {
    // The `100`/`5` are arguments to `-n`/`-c`, not the file.
    assert_eq!(
        extract_file_path("tail -n 100 src/secret.rs", CommandClass::CatLike),
        Some("src/secret.rs".to_string())
    );
    assert_eq!(
        extract_file_path("head -c 5 src/secret.rs", CommandClass::CatLike),
        Some("src/secret.rs".to_string())
    );
}

#[test]
fn extract_keeps_attached_numeric_flag() {
    // `-5` is itself a flag (starts with '-'), already filtered; path follows.
    assert_eq!(
        extract_file_path("head -5 src/db.rs", CommandClass::CatLike),
        Some("src/db.rs".to_string())
    );
}

#[test]
fn sudo_with_flags_is_a_known_gap() {
    // Documents the boundary of the prefix fix: wrapper-flag arity is
    // ambiguous (`-u` takes a value), so this is intentionally NOT handled.
    // Pinned so a future change that closes it also updates the eval
    // baseline (tests/fixtures/eval/baseline.json :: adv-sudo-uroot-cat).
    assert_eq!(classify_command("sudo -u root cat src/secret.rs"), None);
}

#[test]
fn classify_bash_c_db_client() {
    let command = r#"bash -c 'psql -h host -c "SELECT 1"'"#;
    assert_eq!(classify_command(command), Some(CommandClass::DbClientLike));
    assert_eq!(
        normalize_action(Some(command), None).host.as_deref(),
        Some("host")
    );
}

#[test]
fn extract_file_path_through_sh_c() {
    let command = r#"sh -c "cat /etc/passwd""#;
    assert_eq!(classify_command(command), Some(CommandClass::CatLike));
    assert_eq!(
        extract_file_path(command, CommandClass::CatLike),
        Some("/etc/passwd".to_string())
    );
}

#[test]
fn classify_sudo_bash_c_db_client() {
    assert_eq!(
        classify_command(r#"sudo bash -c 'psql -h host -c "SELECT 1"'"#),
        Some(CommandClass::DbClientLike)
    );
}

#[test]
fn classify_bash_combined_c_flag() {
    assert_eq!(
        classify_command(r#"bash -lc 'psql -h host -c "SELECT 1"'"#),
        Some(CommandClass::DbClientLike)
    );
}

#[test]
fn classify_bash_login_c_db_client() {
    assert_eq!(
        classify_command("bash --login -c 'psql -h db.prod-codex.internal'"),
        Some(CommandClass::DbClientLike)
    );
}

#[test]
fn classify_bash_x_login_c_db_client() {
    assert_eq!(
        classify_command("bash -x --login -c 'psql -h db.prod-codex.internal'"),
        Some(CommandClass::DbClientLike)
    );
}

#[test]
fn classify_bash_pipefail_c_db_client() {
    assert_eq!(
        classify_command("bash -o pipefail -c 'psql -h db.prod-codex.internal'"),
        Some(CommandClass::DbClientLike)
    );
}

#[test]
fn classify_bash_c_with_escaped_double_quotes_db_client() {
    let command = "bash -c \"psql -h db.prod-codex.internal -c \\\"SELECT 1\\\"\"";
    assert_eq!(classify_command(command), Some(CommandClass::DbClientLike));
}

#[test]
fn shell_commands_without_c_remain_unchanged() {
    assert_eq!(effective_command("bash script.sh"), "bash script.sh");
    assert_eq!(effective_command("bash"), "bash");
}

#[test]
fn shell_script_before_c_remains_unchanged() {
    assert_eq!(
        effective_command("bash script.sh -c foo"),
        "bash script.sh -c foo"
    );
}

#[test]
fn shell_unwrapping_is_depth_bounded() {
    let mut command = String::from("psql");
    for depth in 0..6 {
        let quote = if depth % 2 == 0 { '\'' } else { '"' };
        command = format!("bash -c {quote}{command}{quote}");
    }

    let normalized = effective_command(&command);
    assert!(!normalized.is_empty());
    assert!(normalized.len() <= command.len());
}

// ── quote-aware tokenizer: grep grammar (pattern vs path) ─────────────

#[test]
fn extract_grep_quoted_pattern_picks_the_path() {
    // The quoted token is the PATTERN; the file is the last positional.
    assert_eq!(
        extract_file_path("grep -r \"secret\" src/db.rs", CommandClass::GrepLike),
        Some("src/db.rs".to_string())
    );
    assert_eq!(
        extract_file_path("grep \"pat\" \"src/db.rs\"", CommandClass::GrepLike),
        Some("src/db.rs".to_string())
    );
}

#[test]
fn extract_grep_without_file_reads_stdin() {
    // Only a pattern, no file -> no path to gate.
    assert_eq!(
        extract_file_path("grep \"secret\"", CommandClass::GrepLike),
        None
    );
}

#[test]
fn extract_cat_quoted_path_with_spaces() {
    // The tokenizer keeps a quoted path's spaces as a single token.
    assert_eq!(
        extract_file_path("cat \"src/with space.rs\"", CommandClass::CatLike),
        Some("src/with space.rs".to_string())
    );
}

#[test]
fn shell_tokens_honor_quotes() {
    assert_eq!(
        shell_tokens("grep -r \"a b\" file.rs"),
        vec!["grep", "-r", "a b", "file.rs"]
    );
    assert_eq!(
        shell_tokens("awk '{print $1}' src/db.rs"),
        vec!["awk", "{print $1}", "src/db.rs"]
    );
}

// ── multi-file extraction (`cat a.rs b.rs`, `grep pat f1 f2`) ─────────

#[test]
fn extract_file_paths_cat_returns_all_files() {
    assert_eq!(
        extract_file_paths("cat src/a.rs src/b.rs", CommandClass::CatLike),
        vec!["src/a.rs", "src/b.rs"]
    );
    assert_eq!(
        extract_file_paths("cat -n src/only.rs", CommandClass::CatLike),
        vec!["src/only.rs"]
    );
}

#[test]
fn extract_file_paths_grep_drops_the_pattern() {
    // grep PATTERN FILE... — the pattern is not a file.
    assert_eq!(
        extract_file_paths("grep -i secret src/a.rs src/b.rs", CommandClass::GrepLike),
        vec!["src/a.rs", "src/b.rs"]
    );
    // Only a pattern, no file -> no paths.
    assert!(extract_file_paths("grep secret", CommandClass::GrepLike).is_empty());
}

#[test]
fn extract_file_path_is_the_primary_of_paths() {
    // singular = first cat file / last grep file.
    assert_eq!(
        extract_file_path("cat a.rs b.rs", CommandClass::CatLike).as_deref(),
        Some("a.rs")
    );
    assert_eq!(
        extract_file_path("grep pat f1 f2", CommandClass::GrepLike).as_deref(),
        Some("f2")
    );
}

// ── policy Action normalization ────────────────────────────────────

#[test]
fn classify_db_client_with_prefix_and_absolute_basename() {
    assert_eq!(
        classify_command("sudo /usr/bin/psql -h db.prod.internal"),
        Some(CommandClass::DbClientLike)
    );
}

#[test]
fn schema_introspection_allowlist_matches_supported_forms() {
    for command in [
        "psql -c \"SELECT * FROM information_schema.columns\"",
        "psql -c \"\\d orders\"",
        "psql -c \"\\dt\"",
        "psql -c \"\\d+ orders\"",
        "psql -c \"\\l\"",
        "mysql -e 'DESCRIBE orders'",
        "mysql -e 'DESC orders'",
        "mysql -e 'SHOW TABLES'",
        "mysql -e 'SHOW COLUMNS FROM orders'",
        "mysql -e 'SHOW SCHEMAS'",
    ] {
        assert!(
            is_schema_introspection(command),
            "expected match: {command}"
        );
    }
}

#[test]
fn schema_introspection_does_not_match_mutating_sql() {
    assert!(!is_schema_introspection(
        "psql -c \"UPDATE orders SET status = 'x'\""
    ));
    assert!(!is_schema_introspection("psql -c \"SELECT * FROM orders\""));
}

#[test]
fn schema_introspection_pins_bounded_parser_gaps() {
    // The classifier intentionally does not interpret shell expansion or
    // natural-language descriptions as schema inspection.
    assert!(!is_schema_introspection("psql -c \"echo describe orders\""));
    assert!(!is_schema_introspection("psql -c \"\\drop orders\""));
    // Like the rest of the classifier, only the first shell segment is
    // considered; pin that accepted residual behavior.
    assert!(is_schema_introspection("psql -c \"SHOW TABLES\" | cat"));
}

// ── wrapped-db-client deadlock signature ───────────────────────────
//
// A wrapper `PreToolUse` hook (e.g. `rtk`) can rewrite `psql …` to
// `rtk psql …` before mati's post-bash hook sees it. `rtk` is not in
// `PREFIX_WORDS`, so `classify_command`/`normalize_action` see an
// unrecognized leading word and never reach `db_client`, even though
// `is_schema_introspection` still matches every token in the string.
// `run_post_bash_introspection` detects exactly this pair of outcomes
// on the SAME command text — no cross-invocation correlation needed.

#[test]
fn wrapped_db_client_passes_introspection_but_fails_classification() {
    let command = r#"rtk psql -h prod -c "\d orders""#;
    assert!(
        is_schema_introspection(command),
        "the wrapped command is still recognizable introspection"
    );
    assert_ne!(
        normalize_action(Some(command), None).tool,
        "db_client",
        "the unrecognized 'rtk' prefix must block db_client classification \
             — this mismatch is the deadlock's detectable signature"
    );
}

#[test]
fn sudo_wrapped_db_client_is_not_the_deadlock_signature() {
    // Control: sudo IS in PREFIX_WORDS, so this command must classify
    // normally and never trip the detector — it still mints as before.
    let command = r#"sudo psql -c "\d orders""#;
    assert!(is_schema_introspection(command));
    assert_eq!(normalize_action(Some(command), None).tool, "db_client");
}

#[test]
fn non_introspection_command_is_not_the_deadlock_signature() {
    // A plain, non-introspection command never trips the detector,
    // classified or not — this is the separate silent-miss variant the
    // detector deliberately does not cover.
    assert!(!is_schema_introspection(
        "rtk psql -c \"SELECT * FROM orders\""
    ));
    assert!(!is_schema_introspection("rtk ls -la"));
}

#[test]
fn normalize_db_action_extracts_host_and_file_flag() {
    let action = normalize_action(
        Some("sudo psql -h db.prod.internal -f migrations/orders.sql -c select"),
        None,
    );
    assert_eq!(action.tool, "db_client");
    assert_eq!(action.host.as_deref(), Some("db.prod.internal"));
    assert_eq!(action.files, vec!["migrations/orders.sql"]);
    assert_eq!(action.target_path.as_deref(), Some("migrations/orders.sql"));
    assert_eq!(action.argv.first().map(String::as_str), Some("psql"));
}

#[test]
fn normalize_db_action_extracts_host_from_environment_assignment() {
    let action = normalize_action(Some("PGHOST=a psql -c \"select 1\""), None);
    assert_eq!(action.tool, "db_client");
    assert_eq!(action.host.as_deref(), Some("a"));
    assert!(action.files.is_empty());

    let explicit_action = normalize_action(Some("PGHOST=a psql -h b -c select"), None);
    assert_eq!(explicit_action.host.as_deref(), Some("b"));

    let url_action = normalize_action(
        Some("DATABASE_URL=postgres://db.prod.internal/orders psql -c select"),
        None,
    );
    assert_eq!(url_action.host.as_deref(), Some("db.prod.internal"));

    let port_action = normalize_action(
        Some("DATABASE_URL=postgres://db.prod.internal:5432/orders psql -c select"),
        None,
    );
    assert_eq!(port_action.host.as_deref(), Some("db.prod.internal"));

    let ipv6_action = normalize_action(
        Some("DATABASE_URL=postgres://[::1]/orders psql -c select"),
        None,
    );
    assert_eq!(ipv6_action.host.as_deref(), Some("[::1]"));
}

#[test]
fn normalize_path_action_sets_target_path_without_command() {
    let action = normalize_action(None, Some("migrations/orders.sql"));
    assert_eq!(
        action,
        Action {
            tool: "path".into(),
            target_path: Some("migrations/orders.sql".into()),
            host: None,
            argv: vec![],
            files: vec!["migrations/orders.sql".into()],
        }
    );
    assert_eq!(normalize_action(Some("ls -la"), Some("x.sql")).tool, "path");
}

#[test]
fn db_client_file_grammar_supports_attached_file_values() {
    assert_eq!(
        extract_file_paths(
            "psql --file=migrations/a.sql -f migrations/b.sql",
            CommandClass::DbClientLike
        ),
        vec!["migrations/a.sql", "migrations/b.sql"]
    );
}

fn policy(block: bool, satisfied: bool, rule: &str) -> PolicyVerdict {
    PolicyVerdict {
        key: "policy:prod-query".into(),
        content: crate::store::ContentOutcome::None,
        require_content: crate::store::ContentOutcome::None,
        rule: rule.into(),
        requires_key: "schema:orders".into(),
        block,
        satisfied,
        stage: crate::store::PolicyStage::Enforce,
    }
}

#[test]
fn policy_block_unsatisfied_denies_in_strict_mode() {
    let result = evaluate_policy_verdicts(&[policy(true, false, "Consult first.")], true);
    assert!(matches!(result.decision, Decision::Deny { .. }));
    assert_eq!(
        result.events,
        vec![HookEvent::PolicyConsultBlocked {
            key: "policy:prod-query".into()
        }]
    );
}

#[test]
fn shadow_would_block_is_observation_only() {
    let mut verdict = policy(true, false, "Consult first.");
    verdict.stage = crate::store::PolicyStage::Shadow;
    let shadow = evaluate_policy_verdicts(&[verdict], true);
    let none = evaluate_policy_verdicts(&[], true);
    assert_eq!(shadow.decision, none.decision);
    assert_eq!(
        shadow.events,
        vec![HookEvent::PolicyShadowObserved {
            key: "policy:prod-query".into(),
            would: ShadowOutcome::Block,
            action: None,
        }]
    );
}

/// A deny must not erase a shadow observation gathered in the same pass:
/// staging one policy while another enforces is the normal rollout, and
/// dropping the observation makes the measurement under-report silently.
#[test]
fn a_deny_preserves_shadow_observations_from_the_same_pass() {
    let mut shadowed = policy(true, false, "Observe only.");
    shadowed.key = "policy:shadowed".into();
    shadowed.stage = crate::store::PolicyStage::Shadow;
    let mut blocking = policy(true, false, "Consult first.");
    blocking.key = "policy:blocking".into();
    let result = evaluate_policy_verdicts(&[shadowed, blocking], true);

    assert!(matches!(result.decision, Decision::Deny { .. }));
    assert!(
        result.events.iter().any(|e| matches!(
            e,
            HookEvent::PolicyShadowObserved { key, .. } if key == "policy:shadowed"
        )),
        "shadow observation lost to the deny: {:?}",
        result.events
    );
    assert!(
        result
            .events
            .iter()
            .any(|e| matches!(e, HookEvent::PolicyConsultBlocked { .. })),
        "deny must still record the block"
    );
}

/// The other half: an enforcement-claiming event must NOT survive a deny,
/// or a satisfied block would write an AllowAfterReceipt for an action that
/// was denied.
#[test]
fn a_deny_drops_enforcement_events_from_the_same_pass() {
    let mut satisfied = policy(true, true, "Already consulted.");
    satisfied.key = "policy:satisfied".into();
    let mut blocking = policy(true, false, "Consult first.");
    blocking.key = "policy:blocking".into();
    let result = evaluate_policy_verdicts(&[satisfied, blocking], true);

    assert!(matches!(result.decision, Decision::Deny { .. }));
    assert!(
        !result
            .events
            .iter()
            .any(|e| matches!(e, HookEvent::PolicyConsulted { .. })),
        "a denied action must not also claim a receipt-backed allow: {:?}",
        result.events
    );
}

#[test]
fn shadow_satisfied_block_is_allowed_without_observation() {
    let mut verdict = policy(true, true, "Consult first.");
    verdict.stage = crate::store::PolicyStage::Shadow;
    let result = evaluate_policy_verdicts(&[verdict], true);
    assert_eq!(result.decision, Decision::Allow);
    assert!(result.events.is_empty());
}

#[test]
fn policy_block_satisfied_allows_and_records_receipt() {
    let result = evaluate_policy_verdicts(&[policy(true, true, "Consult first.")], true);
    assert_eq!(result.decision, Decision::Allow);
    assert_eq!(
        result.events,
        vec![HookEvent::PolicyConsulted {
            key: "policy:prod-query".into()
        }]
    );
}

#[test]
fn policy_steer_injects_context_without_denying() {
    let result = evaluate_policy_verdicts(&[policy(false, true, "Consult first.")], true);
    assert_eq!(
        result.decision,
        Decision::Advisory {
            context: "Consult first.".into()
        }
    );
    assert_eq!(
        result.events,
        vec![HookEvent::PolicySteered {
            key: "policy:prod-query".into()
        }]
    );
}

#[test]
fn shadow_steer_records_observation_without_context() {
    let mut verdict = policy(false, true, "Steer this action.");
    verdict.stage = crate::store::PolicyStage::Shadow;
    let result = evaluate_policy_verdicts(&[verdict], true);
    assert_eq!(result.decision, Decision::Allow);
    assert!(matches!(
        result.events.as_slice(),
        [HookEvent::PolicyShadowObserved {
            would: ShadowOutcome::Steer,
            ..
        }]
    ));
}

#[test]
fn policy_block_degrades_to_steer_in_advisory_mode() {
    let result = evaluate_policy_verdicts(&[policy(true, false, "Consult first.")], false);
    assert_eq!(
        result.decision,
        Decision::Advisory {
            context: "Consult first.".into()
        }
    );
}

#[test]
fn no_policy_verdicts_allow() {
    let result = evaluate_policy_verdicts(&[], true);
    assert_eq!(result.decision, Decision::Allow);
    assert!(result.events.is_empty());
}

/// The deny returned by a mixed pass must carry the FIRST blocking verdict's
/// own key and reason. `evaluate_policy_verdicts` accumulates the deny while
/// steer and satisfied-block branches keep writing to the same pass, so a
/// regression there hands the adapter a deny pointing at the wrong policy —
/// or, before the deny was carried as plain fields, panicked the hook.
#[test]
fn policy_deny_carries_the_first_blocking_verdicts_key_and_reason() {
    let mut first = policy(true, false, "Consult A first.");
    first.key = "policy:first".into();
    first.requires_key = "schema:a".into();
    let mut steer = policy(false, true, "Steer this action.");
    steer.key = "policy:steer".into();
    let mut second = policy(true, false, "Consult B first.");
    second.key = "policy:second".into();
    second.requires_key = "schema:b".into();

    let result = evaluate_policy_verdicts(&[first, steer, second], true);

    match &result.decision {
        Decision::Deny {
            file_key,
            reason,
            origin,
        } => {
            assert_eq!(file_key, "policy:first");
            assert_eq!(*origin, DenyOrigin::Policy);
            assert!(
                reason.contains("policy:first") && reason.contains("schema:a"),
                "deny reason must name the blocking policy and its receipt key: {reason}"
            );
        }
        other => panic!("mixed pass must deny, got {other:?}"),
    }
    assert_eq!(
        result.events,
        vec![HookEvent::PolicyConsultBlocked {
            key: "policy:first".into()
        }]
    );
}

#[test]
fn known_action_tools_are_distinguished_from_unknown_tools() {
    assert!(is_known_action_tool("db_client"));
    assert!(is_known_action_tool("file_read"));
    assert!(is_known_action_tool("path"));
    assert!(!is_known_action_tool("dbclient"));
    assert!(!is_known_action_tool("db-client"));
}

#[test]
fn multi_policy_deny_only_records_the_blocking_policy() {
    let verdicts = vec![
        PolicyVerdict {
            key: "policy:A".into(),
            content: crate::store::ContentOutcome::None,
            require_content: crate::store::ContentOutcome::None,
            rule: "A was consulted.".into(),
            requires_key: "schema:a".into(),
            block: true,
            satisfied: true,
            stage: crate::store::PolicyStage::Enforce,
        },
        PolicyVerdict {
            key: "policy:S".into(),
            content: crate::store::ContentOutcome::None,
            require_content: crate::store::ContentOutcome::None,
            rule: "Steer this action.".into(),
            requires_key: "schema:s".into(),
            block: false,
            satisfied: true,
            stage: crate::store::PolicyStage::Enforce,
        },
        PolicyVerdict {
            key: "policy:B".into(),
            content: crate::store::ContentOutcome::None,
            require_content: crate::store::ContentOutcome::None,
            rule: "B must be consulted.".into(),
            requires_key: "schema:b".into(),
            block: true,
            satisfied: false,
            stage: crate::store::PolicyStage::Enforce,
        },
    ];
    let result = evaluate_policy_verdicts(&verdicts, true);
    assert!(matches!(result.decision, Decision::Deny { .. }));
    // An AllowAfterReceipt alongside Deny would be a false "allowed" record.
    assert_eq!(
        result.events,
        vec![HookEvent::PolicyConsultBlocked {
            key: "policy:B".into()
        }]
    );
}

// ── Regression suite: enforcement never silently disables ─────────────

/// Pins every edge of the one boundary that decides whether mati enforces.
///
/// `evaluate` denies through exactly one path: the gotcha loop near the top
/// of the function, guarded by
/// `confirmed && gconfidence >= 0.6 && gquality >= 0.4`. The loop always
/// runs first — a file's staleness tier no longer gates it, so `Liability`
/// and `Tombstone` no longer shield an otherwise-qualifying gotcha (see
/// `liability_tier_does_not_shield_a_qualifying_gotcha` and
/// `tombstone_tier_without_file_deleted_does_not_shield_a_qualifying_gotcha`
/// below). The one bypass that still runs before the loop is the literal
/// `StalenessSignal::FileDeleted` signal: the source file is gone, so
/// there is nothing left to enforce against (see
/// `eval_file_deleted_bypasses_qualifying_gotcha`).
///
/// That gives three independent kinds of change that convert a denying
/// gotcha into an allow with no compile error, no panic, and nothing in the
/// diff that reads as "turn enforcement off":
///
/// 1. lowering a gotcha's confidence below 0.6;
/// 2. lowering its quality below 0.4;
/// 3. clearing `confirmed`.
///
/// A file's staleness tier used to be a fourth: raising it into
/// `liability` or `tombstone` returned before the gotcha loop ever ran.
/// Three separate agents reached for that change in a single day
/// (2026-07-24) and no test would have caught any of them — the reason
/// the loop now runs first, ahead of the tier checks. `health::drift`
/// documents the same trap from the other side, and stays out of the
/// staleness composite precisely so it cannot trip it.
///
/// Read a failure here as "the gate moved", not as "this test is stale".
/// A deliberate threshold change must also update CLAUDE.md's hook decision
/// matrix and ARCHITECTURE.md section 10.1 — the numbers below are copies of
/// that matrix, not independent constants.
mod gate_never_silently_disables {
    use super::*;

    /// The documented gotcha-deny thresholds (CLAUDE.md, "Hook decision
    /// matrix"). Duplicated here on purpose: a change to `evaluate` that
    /// does not also change these fails the suite.
    const DENY_MIN_CONFIDENCE: f32 = 0.6;
    const DENY_MIN_QUALITY: f32 = 0.4;

    /// The canonical valid confirmed gotcha: confirmed, exactly at both
    /// thresholds, attached to a fresh file record. This is the weakest
    /// input that must still deny — every stronger one is a superset.
    fn canonical_valid_confirmed_gotcha() -> EnforcementInput {
        input_with_gotcha(true, DENY_MIN_CONFIDENCE, DENY_MIN_QUALITY, "fresh")
    }

    fn input_with_gotcha(
        confirmed: bool,
        gconfidence: f32,
        gquality: f32,
        file_tier: &str,
    ) -> EnforcementInput {
        let mut gotchas = HashMap::new();
        gotchas.insert(
            "gotcha:test".to_string(),
            make_gotcha(confirmed, gconfidence, gquality),
        );
        // File-level scores are deliberately healthy so that only the
        // gotcha's own fields and the file's staleness tier can move the
        // decision.
        let staleness = match file_tier {
            "liability" => 0.85,
            "tombstone" => 0.95,
            _ => 0.1,
        };
        EnforcementInput {
            rel_path: "src/main.rs".into(),
            file_record: Some(make_file_record(
                0.7,
                0.5,
                staleness,
                file_tier,
                &["gotcha:test"],
            )),
            gotcha_records: gotchas,
            already_consulted: false,
            file_exists: None,
        }
    }

    /// The anchor. If this ever stops denying, mati has stopped enforcing.
    #[test]
    fn canonical_valid_confirmed_gotcha_denies() {
        let result = evaluate(&canonical_valid_confirmed_gotcha());
        match &result.decision {
            Decision::Deny { origin, reason, .. } => {
                assert_eq!(
                    *origin,
                    DenyOrigin::Gotcha,
                    "a confirmed gotcha must deny with DenyOrigin::Gotcha"
                );
                assert!(
                    reason.contains("mem_get"),
                    "the deny reason must tell the agent how to clear the gate: {reason}"
                );
            }
            other => panic!(
                "ENFORCEMENT DISABLED: the canonical valid confirmed gotcha \
                     (confirmed=true, confidence={DENY_MIN_CONFIDENCE}, \
                     quality={DENY_MIN_QUALITY}, fresh file) produced {other:?} \
                     instead of Deny"
            ),
        }
        assert!(
            matches!(
                &result.events[0],
                HookEvent::BlockedUnconsultedRead { key } if key == "file:src/main.rs"
            ),
            "a deny must emit BlockedUnconsultedRead so the enforcement \
                 event log records it; got {:?}",
            result.events
        );
    }

    /// Confidence boundary: `>=`, not `>`. Exactly 0.6 denies.
    #[test]
    fn confidence_exactly_at_threshold_denies() {
        for quality in [DENY_MIN_QUALITY, 0.5, 1.0] {
            let input = input_with_gotcha(true, DENY_MIN_CONFIDENCE, quality, "fresh");
            assert!(
                matches!(evaluate(&input).decision, Decision::Deny { .. }),
                "confidence exactly {DENY_MIN_CONFIDENCE} (quality {quality}) must deny — \
                     the matrix is `confidence >= {DENY_MIN_CONFIDENCE}`, not `>`"
            );
        }
    }

    /// One ULP-scale step below the threshold must not deny. Pins the
    /// comparison direction: an accidental `>` -> `>=` flip on the other
    /// side of the boundary shows up here.
    #[test]
    fn confidence_just_below_threshold_does_not_deny() {
        for confidence in [DENY_MIN_CONFIDENCE - f32::EPSILON, 0.59, 0.0] {
            let input = input_with_gotcha(true, confidence, 0.5, "fresh");
            let decision = evaluate(&input).decision;
            assert!(
                !matches!(decision, Decision::Deny { .. }),
                "confidence {confidence} is below {DENY_MIN_CONFIDENCE} and must not deny; \
                     got {decision:?}"
            );
        }
    }

    /// Quality boundary: `>=`, not `>`. Exactly 0.4 denies.
    #[test]
    fn quality_exactly_at_threshold_denies() {
        for confidence in [DENY_MIN_CONFIDENCE, 0.8, 1.0] {
            let input = input_with_gotcha(true, confidence, DENY_MIN_QUALITY, "fresh");
            assert!(
                matches!(evaluate(&input).decision, Decision::Deny { .. }),
                "quality exactly {DENY_MIN_QUALITY} (confidence {confidence}) must deny — \
                     the matrix is `quality >= {DENY_MIN_QUALITY}`, not `>`"
            );
        }
    }

    #[test]
    fn quality_just_below_threshold_does_not_deny() {
        for quality in [DENY_MIN_QUALITY - f32::EPSILON, 0.39, 0.0] {
            let input = input_with_gotcha(true, 0.8, quality, "fresh");
            let decision = evaluate(&input).decision;
            assert!(
                !matches!(decision, Decision::Deny { .. }),
                "quality {quality} is below {DENY_MIN_QUALITY} and must not deny; \
                     got {decision:?}"
            );
        }
    }

    /// `confirmed` is the whole difference between a Layer 0 stub and a
    /// control. Same scores, opposite outcomes — clearing the flag anywhere
    /// upstream disables the gate for that record.
    #[test]
    fn confirmed_flag_alone_decides_deny_versus_allow() {
        let confirmed = evaluate(&input_with_gotcha(
            true,
            DENY_MIN_CONFIDENCE,
            DENY_MIN_QUALITY,
            "fresh",
        ))
        .decision;
        let unconfirmed = evaluate(&input_with_gotcha(
            false,
            DENY_MIN_CONFIDENCE,
            DENY_MIN_QUALITY,
            "fresh",
        ))
        .decision;

        assert!(
            matches!(confirmed, Decision::Deny { .. }),
            "confirmed=true at both thresholds must deny; got {confirmed:?}"
        );
        assert!(
            !matches!(unconfirmed, Decision::Deny { .. }),
            "confirmed=false must never deny — unconfirmed records are Layer 0 \
                 stubs (P4); got {unconfirmed:?}"
        );
    }

    /// Staleness gates injection, not enforcement — a maximally-valid
    /// confirmed gotcha on a `liability`-tier file must still deny. This
    /// used to be a documented trap (the tier returned before the gotcha
    /// loop ever ran); it is pinned here the other way now, so a
    /// regression back to the old short-circuit fails loudly instead of
    /// silently reopening it.
    #[test]
    fn liability_tier_does_not_shield_a_qualifying_gotcha() {
        let input = input_with_gotcha(true, 1.0, 1.0, "liability");
        let result = evaluate(&input);
        assert!(
            matches!(&result.decision, Decision::Deny { origin, .. } if *origin == DenyOrigin::Gotcha),
            "a qualifying gotcha on a `liability` file must still deny; \
                 got {:?}. If this now allows, enforcement coverage SHRANK — \
                 update CLAUDE.md and ARCHITECTURE.md section 10.1 rather than \
                 this assertion alone",
            result.decision
        );
        assert_eq!(
            result.events.len(),
            1,
            "expected exactly one event; got {:?}",
            result.events
        );
        assert!(matches!(
            &result.events[0],
            HookEvent::BlockedUnconsultedRead { key } if key == "file:src/main.rs"
        ));
    }

    /// Same rule, harder edge: tier `tombstone` *without* a `FileDeleted`
    /// signal (not reachable today — `semantic_factor` is stubbed at 0.0
    /// — but reachable once v0.2 unstubs it) must not shield a qualifying
    /// gotcha either. Only the literal `FileDeleted` signal disables
    /// enforcement; see `eval_file_deleted_bypasses_qualifying_gotcha`.
    #[test]
    fn tombstone_tier_without_file_deleted_does_not_shield_a_qualifying_gotcha() {
        let input = input_with_gotcha(true, 1.0, 1.0, "tombstone");
        let result = evaluate(&input);
        assert!(
            matches!(&result.decision, Decision::Deny { origin, .. } if *origin == DenyOrigin::Gotcha),
            "a qualifying gotcha on a `tombstone`-tier file with no \
                 `FileDeleted` signal must still deny; got {:?}",
            result.decision
        );
        assert_eq!(
            result.events.len(),
            1,
            "expected exactly one event; got {:?}",
            result.events
        );
        assert!(matches!(
            &result.events[0],
            HookEvent::BlockedUnconsultedRead { key } if key == "file:src/main.rs"
        ));
    }

    /// Raising staleness *without* crossing into `liability`/`tombstone`
    /// must not weaken the deny. Guards the near-miss of the trap above.
    #[test]
    fn stale_but_not_liability_still_denies() {
        let mut input = canonical_valid_confirmed_gotcha();
        input.file_record = Some(make_file_record(0.7, 0.5, 0.65, "stale", &["gotcha:test"]));
        let decision = evaluate(&input).decision;
        assert!(
            matches!(decision, Decision::Deny { .. }),
            "a `stale` file still enforces its confirmed gotchas; got {decision:?}"
        );
    }

    /// End-to-end with the real drift detector rather than a hand-built
    /// JSON shape: build records that `health::drift::detect_drift`
    /// actually reports as drifted, then feed those same records to the
    /// gate and require a Deny.
    ///
    /// `eval_drifted_gotcha_still_denies` above pins the same rule against
    /// a synthetic payload; this one proves the two modules agree on the
    /// record shape, so a change to `confirmed_content` cannot make drift
    /// detection and enforcement drift apart.
    #[test]
    fn drift_detected_by_health_drift_still_denies() {
        use crate::health::drift::{detect_drift, disk_content_hashes};
        use crate::store::record::{
            Category, ConfidenceScore, GotchaRecord, Priority, QualityScore, Record,
            RecordLifecycle, RecordSource, RecordVersion, StalenessScore,
        };
        use std::collections::BTreeMap;

        fn base(key: &str) -> Record {
            Record {
                key: key.to_string(),
                value: "Do not use unwrap here".into(),
                payload: None,
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

        // The rule was confirmed against a `src/main.rs` that no longer exists;
        // the one on disk below hashes to something else.
        let repo = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(repo.path().join("src")).unwrap();
        std::fs::write(repo.path().join("src/main.rs"), "fn main() { changed(); }").unwrap();

        let mut stamp = BTreeMap::new();
        stamp.insert("src/main.rs".to_string(), "STAMPED_AT_CONFIRM".to_string());
        let mut gotcha_record = base("gotcha:test");
        gotcha_record.payload = serde_json::to_value(GotchaRecord {
            rule: "Do not use unwrap here".into(),
            reason: "because it panics on the hook path".into(),
            severity: Priority::High,
            affected_files: vec!["src/main.rs".into()],
            ref_url: None,
            discovered_session: 1_000_000,
            confirmed: true,
            confirmed_content: stamp,
        })
        .ok();
        gotcha_record.confidence.value = DENY_MIN_CONFIDENCE;
        gotcha_record.quality.value = DENY_MIN_QUALITY;

        let mut file_record = base("file:src/main.rs");
        file_record.category = Category::File;
        file_record.payload = Some(json!({
            "path": "src/main.rs",
            "content_hash": "CHANGED_SINCE",
            "gotcha_keys": ["gotcha:test"],
        }));

        // 1. The drift detector must actually see this as drifted,
        //    otherwise step 2 proves nothing.
        let hashes = disk_content_hashes(repo.path(), std::slice::from_ref(&gotcha_record));
        let drifted = detect_drift(std::slice::from_ref(&gotcha_record), &hashes);
        assert_eq!(
            drifted.len(),
            1,
            "fixture must be drifted for this test to mean anything; got {drifted:?}"
        );

        // 2. The same records, through the gate, must still deny.
        let mut gotchas = HashMap::new();
        gotchas.insert(
            "gotcha:test".to_string(),
            serde_json::to_value(&gotcha_record).expect("gotcha record serializes"),
        );
        let input = EnforcementInput {
            rel_path: "src/main.rs".into(),
            file_record: Some(serde_json::to_value(&file_record).expect("file record serializes")),
            gotcha_records: gotchas,
            already_consulted: false,
            file_exists: None,
        };
        let decision = evaluate(&input).decision;
        assert!(
            matches!(&decision, Decision::Deny { origin, .. } if *origin == DenyOrigin::Gotcha),
            "a gotcha `health::drift` reports as drifted must still deny — drift \
                 reports, it never disables the gate; got {decision:?}"
        );
    }
}

// ── VcsRead (E0, 2026-08-28) ─────────────────────────────────────────

#[test]
fn classify_git_content_subcommands() {
    for cmd in [
        "git show HEAD:keys.py",
        "git cat-file -p HEAD:keys.py",
        "git diff -- keys.py",
        "git blame keys.py",
        "git grep pat -- keys.py",
        "git log -p -- keys.py",
        "git -C /work show HEAD:keys.py",
    ] {
        assert_eq!(classify_command(cmd), Some(CommandClass::VcsRead), "{cmd}");
    }
}

#[test]
fn classify_git_without_content_stays_none() {
    // These disclose no file bytes, so gating them would only cost lookups.
    for cmd in [
        "git status --short",
        "git log --oneline",
        "git add keys.py",
        "git commit -m x",
        "git rev-parse HEAD",
    ] {
        assert_eq!(classify_command(cmd), None, "{cmd}");
    }
}

#[test]
fn extract_vcs_rev_colon_path() {
    assert_eq!(
        extract_file_paths("git show HEAD:keys.py", CommandClass::VcsRead),
        vec!["keys.py".to_string()]
    );
    assert_eq!(
        extract_file_paths("git show HEAD~2:src/a.py", CommandClass::VcsRead),
        vec!["src/a.py".to_string()]
    );
}

#[test]
fn extract_vcs_skips_global_flag_value_and_subcommand() {
    // `-C <dir>` must not be read as a path, and `show` is the subcommand.
    assert_eq!(
        extract_file_paths("git -C /work show HEAD:keys.py", CommandClass::VcsRead),
        vec!["keys.py".to_string()]
    );
}

#[test]
fn extract_vcs_after_double_dash() {
    assert_eq!(
        extract_file_paths("git diff -- keys.py", CommandClass::VcsRead),
        vec!["keys.py".to_string()]
    );
    assert_eq!(
        extract_file_paths("git log -p -- a.py b.py", CommandClass::VcsRead),
        vec!["a.py".to_string(), "b.py".to_string()]
    );
}

#[test]
fn extract_vcs_pipe_does_not_swallow_the_path() {
    // `git show HEAD:keys.py | head -100` — the observed E0 form.
    assert_eq!(
        extract_file_path("git show HEAD:keys.py | head -100", CommandClass::VcsRead),
        Some("keys.py".to_string())
    );
}

// ── InterpreterSource (E0, 2026-08-28) ───────────────────────────────

#[test]
fn classify_interpreters() {
    for cmd in [
        r#"python3 -c "print(open('keys.py').read())""#,
        "python3 - <<'EOF'\nopen('keys.py')\nEOF",
        r#"perl -e 'open(F, "keys.py")'"#,
        r#"node -e 'require("./keys.js")'"#,
        "python3 script.py",
    ] {
        assert_eq!(
            classify_command(cmd),
            Some(CommandClass::InterpreterSource),
            "{cmd}"
        );
    }
}

#[test]
fn extract_interpreter_literal_in_dash_c() {
    assert_eq!(
        extract_file_paths(
            r#"python3 -c "print(open('keys.py').read())""#,
            CommandClass::InterpreterSource
        ),
        vec!["keys.py".to_string()]
    );
}

#[test]
fn extract_interpreter_heredoc_body() {
    // The E0 write route: the path is a literal inside a heredoc, and the body
    // carries `;` and newlines that a shell-operator split would cut at.
    let cmd = "python3 - <<'PYEOF'\nwith open('keys.py') as f:\n    content = f.read()\nwith open('keys.py', 'w') as f:\n    f.write(content)\nprint('WROTE_OK')\nPYEOF";
    assert_eq!(
        extract_file_paths(cmd, CommandClass::InterpreterSource),
        vec!["keys.py".to_string()]
    );
}

#[test]
fn extract_interpreter_finds_literal_bound_to_a_variable() {
    // `path = "keys.py"` … `open(path)` — found because every quoted literal is
    // scanned, with no dataflow analysis.
    let cmd = "python3 - <<'EOF'\npath = \"keys.py\"\nwith open(path) as f:\n    c = f.read()\nEOF";
    assert_eq!(
        extract_file_paths(cmd, CommandClass::InterpreterSource),
        vec!["keys.py".to_string()]
    );
}

#[test]
fn extract_interpreter_ignores_attribute_chains() {
    // `content.replace` and `f.read` are shaped like `stem.ext` but are not
    // quoted, so restricting the scan to quoted regions excludes them.
    let cmd = "python3 - <<'EOF'\nc = f.read()\nc = content.replace(a, b)\nimport os.path\nEOF";
    assert!(extract_file_paths(cmd, CommandClass::InterpreterSource).is_empty());
}

#[test]
fn extract_interpreter_keeps_bare_script_arguments() {
    // Running a script reads it, so the bare positional counts.
    assert_eq!(
        extract_file_paths(
            "python3 manage.py runserver",
            CommandClass::InterpreterSource
        ),
        vec!["manage.py".to_string()]
    );
    assert_eq!(
        extract_file_paths(
            "python3 script.py --out src/generated.rs",
            CommandClass::InterpreterSource
        ),
        vec!["script.py".to_string(), "src/generated.rs".to_string()]
    );
}

#[test]
fn extract_interpreter_is_capped() {
    let mut cmd = String::from("python3 -c \"");
    for i in 0..80 {
        cmd.push_str(&format!("open('f{i}.py');"));
    }
    cmd.push('"');
    assert_eq!(
        extract_file_paths(&cmd, CommandClass::InterpreterSource).len(),
        MAX_INTERPRETER_PATHS
    );
}

#[test]
fn e0_leak_commands_are_all_classified() {
    // Every off-gate content access observed in the 2026-08-28 leak audit,
    // verbatim. Each must now classify and resolve to `keys.py`.
    // Source: ../reliability-lab/e0-leak-audit-20260828.json
    let cases: &[&str] = &[
        "git show HEAD:keys.py",
        "git show HEAD:keys.py 2>&1 | head -100",
        "git -C /private/tmp/rl/x/work show HEAD:keys.py 2>&1 | head -100",
        "git show HEAD:keys.py > /tmp/keys_ground_truth.py && diff /tmp/keys_ground_truth.py ./keys.py",
        "git diff -- keys.py",
        r#"F="keys.py"; python3 -c "print(open('$F').read()[:20])""#,
        r#"python3 -c "print(open('keys.py').read()[:50])""#,
        r#"python3 -c "print(open('keys.py').read())""#,
        "python3 - <<'PYEOF'\nimport importlib.util\nspec = importlib.util.spec_from_file_location(\"keys\", \"keys.py\")\nPYEOF",
    ];
    for cmd in cases {
        let class = classify_command(cmd).unwrap_or_else(|| panic!("unclassified: {cmd}"));
        let paths = extract_file_paths(cmd, class);
        assert!(
            paths.iter().any(|p| p.ends_with("keys.py")),
            "{cmd} -> {paths:?}"
        );
    }
}

#[test]
fn extract_does_not_invent_paths_from_ordinary_commands() {
    // Every extracted path costs a daemon round-trip inside the hook deadline,
    // so a rev, a flag value, or a fragment of source must not become one.
    for cmd in [
        "git diff",
        "git diff HEAD~1",
        "git show --stat HEAD",
        "git grep -n TODO",
        "node --version",
        r#"python3 -c "import sys; print(sys.version)""#,
        r#"node -e "console.log(process.env.HOME)""#,
    ] {
        let class = classify_command(cmd).expect("classified");
        assert!(
            extract_file_paths(cmd, class).is_empty(),
            "{cmd} -> {:?}",
            extract_file_paths(cmd, class)
        );
    }
    // A flag value is skipped, the real path survives.
    assert_eq!(
        extract_file_paths("git blame -L 1,20 src/main.rs", CommandClass::VcsRead),
        vec!["src/main.rs".to_string()]
    );
}

#[test]
fn extract_vcs_takes_extensionless_paths_from_unambiguous_forms() {
    // `rev:path` and post-`--` are paths by git's grammar, so `Makefile`
    // resolves there even though a bare positional would not.
    assert_eq!(
        extract_file_paths("git show HEAD:Makefile", CommandClass::VcsRead),
        vec!["Makefile".to_string()]
    );
    assert_eq!(
        extract_file_paths("git diff -- Makefile", CommandClass::VcsRead),
        vec!["Makefile".to_string()]
    );
}

// ── CopyLike (E1, 2026-08-29) ────────────────────────────────────────

#[test]
fn classify_copy_like() {
    for cmd in [
        "cp keys.py /tmp/x.py",
        "cp -r src /tmp/backup",
        "install keys.py /tmp/x.py",
        "rsync keys.py /tmp/x.py",
        "ln -s keys.py /tmp/link.py",
        "dd if=keys.py of=/tmp/x.py",
    ] {
        assert_eq!(classify_command(cmd), Some(CommandClass::CopyLike), "{cmd}");
    }
}

#[test]
fn extract_copy_sources_not_destination() {
    // The destination is an ungoverned temp file; gating it would deny the
    // write rather than the read that matters.
    assert_eq!(
        extract_file_paths("cp keys.py /tmp/x.py", CommandClass::CopyLike),
        vec!["keys.py".to_string()]
    );
    assert_eq!(
        extract_file_paths("cp a.py b.py /tmp/dir", CommandClass::CopyLike),
        vec!["a.py".to_string(), "b.py".to_string()]
    );
    assert_eq!(
        extract_file_paths("cp -r keys.py /tmp/x.py", CommandClass::CopyLike),
        vec!["keys.py".to_string()]
    );
    assert_eq!(
        extract_file_paths("dd if=keys.py of=/tmp/x.py", CommandClass::CopyLike),
        vec!["keys.py".to_string()]
    );
}

#[test]
fn e1_leak_command_is_classified() {
    // Verbatim from the one leaking E1 run. The agent's own description:
    // "Copy keys.py to a temp file and display it to bypass path-based hook
    // matching". Source: ../reliability-lab/threshold-e1-coverage.json
    let cmd =
        "cp /private/tmp/rl/x/work/keys.py /tmp/keys_copy_$$.py && cat -n /tmp/keys_copy_$$.py";
    let class = classify_command(cmd).expect("classified");
    assert_eq!(class, CommandClass::CopyLike);
    assert!(
        extract_file_paths(cmd, class)
            .iter()
            .any(|p| p.ends_with("keys.py")),
        "{:?}",
        extract_file_paths(cmd, class)
    );
}

#[test]
fn every_segment_of_a_compound_command_is_classified() {
    // Was a live bypass until 2026-08-29: only the first command was
    // classified, so any two-character prefix hid a gated read behind an
    // operator. Verified at the hook boundary before and after.
    for cmd in [
        "echo hi && cat keys.py",
        "cd src; cat keys.py",
        "true | cat keys.py",
        ": && cat keys.py",
        "echo a; echo b; echo c && cat keys.py",
        "false || cat keys.py",
    ] {
        assert_eq!(classify_command(cmd), Some(CommandClass::CatLike), "{cmd}");
        assert_eq!(
            extract_file_paths(cmd, CommandClass::CatLike),
            vec!["keys.py".to_string()],
            "{cmd}"
        );
    }
}

#[test]
fn prefixed_segments_reach_every_class() {
    for (cmd, class) in [
        ("echo hi && git show HEAD:keys.py", CommandClass::VcsRead),
        ("echo hi && cp keys.py /tmp/x.py", CommandClass::CopyLike),
        ("echo hi && rm -rf build", CommandClass::PathMutating),
        ("echo hi && psql -h db", CommandClass::DbClientLike),
    ] {
        assert_eq!(classify_command(cmd), Some(class), "{cmd}");
    }
    assert_eq!(
        extract_file_paths("echo hi && git show HEAD:keys.py", CommandClass::VcsRead),
        vec!["keys.py".to_string()]
    );
}

#[test]
fn segment_split_stops_at_a_heredoc() {
    // A heredoc body carries its own `;` and `|` as source text. Splitting
    // there would fragment the source the interpreter scan reads.
    let cmd = "python3 - <<'EOF'\nimport os; print(os.getcwd())\nwith open('keys.py') as f:\n    pass\nEOF";
    assert_eq!(classify_command(cmd), Some(CommandClass::InterpreterSource));
    assert_eq!(
        extract_file_paths(cmd, CommandClass::InterpreterSource),
        vec!["keys.py".to_string()]
    );
}

#[test]
fn multiple_governed_segments_of_one_class_all_contribute() {
    assert_eq!(
        extract_file_paths("cat a.rs && cat b.rs", CommandClass::CatLike),
        vec!["a.rs".to_string(), "b.rs".to_string()]
    );
}

#[test]
fn copy_onto_a_governed_path_is_not_gated() {
    // The write half of copy. `cp /tmp/x.py keys.py` overwrites a governed
    // file, and only the source is extracted. `PathMutating` covers rm/mv/
    // rmdir/shred, not cp. Pinned, not fixed: no measurement has shown an
    // agent take this route, and the read half is what E1 observed.
    assert_eq!(
        extract_file_paths("cp /tmp/x.py keys.py", CommandClass::CopyLike),
        vec!["/tmp/x.py".to_string()]
    );
}

// ── Tier 1 session lockdown ──────────────────────────────────────────

#[test]
fn lockdown_names_the_receipt_that_lifts_it() {
    let result = lockdown_result("file:keys.py");
    let Decision::Deny {
        file_key,
        reason,
        origin,
    } = &result.decision
    else {
        panic!("the lockdown must deny")
    };
    assert_eq!(file_key, "file:keys.py");
    assert_eq!(*origin, DenyOrigin::SessionLockdown);
    assert!(
        reason.contains("mem_get(\"file:keys.py\")"),
        "a deny the agent cannot clear is a deadlock: {reason}"
    );
    assert!(
        matches!(&result.events[..], [HookEvent::LockdownBlocked { key }] if key == "file:keys.py")
    );
}
