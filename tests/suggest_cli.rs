//! `mati suggest --dry-run` end-to-end: scans CODEOWNERS + load-bearing/security
//! markers and proposes candidates without touching the store or daemon.

use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_mati")
}

#[test]
fn suggest_dry_run_proposes_codeowners_and_marker_candidates() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path();
    std::fs::create_dir_all(root.join(".github")).unwrap();
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(root.join(".github/CODEOWNERS"), "src/payments/** @pay-team\n").unwrap();
    std::fs::write(
        root.join("src/main.rs"),
        "fn main() {\n    // DO NOT REMOVE: load-bearing init order\n}\n",
    )
    .unwrap();

    let out = Command::new(bin())
        .args(["suggest", "--dry-run", "--path", root.to_str().unwrap()])
        .output()
        .expect("run mati suggest");
    assert!(out.status.success(), "exit: {:?}", out.status);
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        s.contains("gotcha:codeowners:src/payments/**"),
        "expected CODEOWNERS candidate; got:\n{s}"
    );
    assert!(
        s.contains("gotcha:marker:src/main.rs:2"),
        "expected marker candidate at line 2; got:\n{s}"
    );
}

#[test]
fn suggest_dry_run_empty_repo_finds_nothing() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let out = Command::new(bin())
        .args(["suggest", "--dry-run", "--path", tmp.path().to_str().unwrap()])
        .output()
        .expect("run mati suggest");
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        s.contains("No onboarding candidates"),
        "empty repo should find nothing; got:\n{s}"
    );
}
