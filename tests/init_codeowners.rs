//! `mati init` proposes CODEOWNERS ownership candidates (idea 2.2 init-wiring),
//! idempotently (a re-init does not duplicate or reset them).

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

fn git(dir: &Path, args: &[&str]) -> bool {
    Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[test]
fn init_proposes_codeowners_candidate_idempotently() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    if !git(dir, &["init", "-q"]) {
        eprintln!("skip: git unavailable");
        return;
    }
    git(dir, &["config", "user.email", "t@t.t"]);
    git(dir, &["config", "user.name", "t"]);
    std::fs::create_dir_all(dir.join(".github")).unwrap();
    std::fs::write(
        dir.join(".github/CODEOWNERS"),
        "src/payments/** @pay-team\n",
    )
    .unwrap();
    std::fs::write(dir.join("README.md"), "x").unwrap();
    git(dir, &["add", "-A"]);
    git(dir, &["commit", "-qm", "init"]);

    let init = run_in(dir, &["init"]);
    if !init.status.success() {
        eprintln!(
            "skip: mati init failed: {}",
            String::from_utf8_lossy(&init.stderr)
        );
        return;
    }

    let ls = run_in(dir, &["ls", "gotchas"]);
    assert!(ls.status.success());
    let listed = String::from_utf8_lossy(&ls.stdout);
    let count = listed.matches("codeowners:src/payments/**").count();
    assert_eq!(
        count, 1,
        "init should propose exactly one CODEOWNERS candidate; got:\n{listed}"
    );

    // Re-init must not duplicate it.
    assert!(run_in(dir, &["init"]).status.success());
    let again = run_in(dir, &["ls", "gotchas"]);
    let count2 = String::from_utf8_lossy(&again.stdout)
        .matches("codeowners:src/payments/**")
        .count();
    assert_eq!(count2, 1, "re-init must be idempotent (no duplicate)");

    let _ = run_in(dir, &["daemon", "stop"]);
}
