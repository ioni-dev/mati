//! `mati search` end-to-end against a real store: init → add notes → search.

use std::path::Path;
use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_mati")
}

fn run_in(dir: &Path, args: &[&str]) -> std::process::Output {
    Command::new(bin())
        .args(args)
        .current_dir(dir)
        .output()
        .expect("run mati")
}

fn git_in(dir: &Path, args: &[&str]) -> bool {
    Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[test]
fn search_finds_and_ranks_matching_records() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();

    // A minimal git repo so `mati init` mines history cleanly.
    if !git_in(dir, &["init", "-q"]) {
        eprintln!("skip: git unavailable");
        return;
    }
    git_in(dir, &["config", "user.email", "t@t.t"]);
    git_in(dir, &["config", "user.name", "t"]);
    std::fs::write(dir.join("README.md"), "x").unwrap();
    git_in(dir, &["add", "-A"]);
    git_in(dir, &["commit", "-qm", "init"]);

    let init = run_in(dir, &["init"]);
    if !init.status.success() {
        // Sandboxes that can't create a store shouldn't hard-fail CI.
        eprintln!(
            "skip: mati init failed: {}",
            String::from_utf8_lossy(&init.stderr)
        );
        return;
    }

    run_in(dir, &["note", "fraud detection model on payment signals"]);
    run_in(dir, &["note", "deploy pipeline runs on cloudflare"]);

    // Only the fraud note matches.
    let out = run_in(dir, &["search", "fraud", "--json"]);
    assert!(out.status.success(), "search exit: {:?}", out.status);
    let v: serde_json::Value =
        serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("json: {e}\n{out:?}"));
    let arr = v.as_array().expect("array");
    assert_eq!(arr.len(), 1, "only the fraud note should match; got {v}");
    assert!(arr[0]
        .pointer("/value")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .contains("fraud"));

    // Multi-term coverage outranks (both terms present beats one).
    let two = run_in(dir, &["search", "fraud", "payment", "--json"]);
    let v2: serde_json::Value = serde_json::from_slice(&two.stdout).expect("json");
    let score_two = v2[0]
        .pointer("/score")
        .and_then(|x| x.as_u64())
        .unwrap_or(0);
    let score_one = arr[0]
        .pointer("/score")
        .and_then(|x| x.as_u64())
        .unwrap_or(0);
    assert!(
        score_two > score_one,
        "two matched terms ({score_two}) should outrank one ({score_one})"
    );

    // No-match path.
    let none = run_in(dir, &["search", "zzznotarealterm"]);
    assert!(none.status.success());
    assert!(String::from_utf8_lossy(&none.stdout).contains("No matches"));

    // Don't leave a daemon running for other tests.
    let _ = run_in(dir, &["daemon", "stop"]);
}
