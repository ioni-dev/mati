//! `mati demo` runs the real deny → consult → allow loop on a throwaway repo.

use std::process::Command;

mod common;

#[test]
fn demo_shows_deny_then_allow_and_cleans_up() {
    // The demo must use its own store, never the caller's.
    let caller_home = common::mati_home();
    let out = Command::new(env!("CARGO_BIN_EXE_mati"))
        .arg("demo")
        .env("MATI_HOME", &caller_home)
        .env("MATI_LOCKDOWN", "1")
        .env("MATI_DISABLE_AUTO_SPAWN", "1")
        .output()
        .expect("run mati demo");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "demo failed:\nstdout: {stdout}\nstderr: {stderr}"
    );

    let deny = stdout.find("DENY").expect("demo must show a deny");
    let allow = stdout.find("ALLOW").expect("demo must show an allow");
    assert!(deny < allow, "deny must come before allow:\n{stdout}");
    // On macOS the demo repo sits under the /var -> /private/var symlink, so
    // this also pins the canonical-key fallback keeping the consulted context.
    assert!(
        stdout[allow..].contains("Record already consulted"),
        "the allow must carry the gotcha as context:\n{stdout}"
    );
    assert!(
        stdout.contains("mem_get"),
        "deny reason names the unlock:\n{stdout}"
    );

    let repo_line = stdout
        .lines()
        .find(|l| l.contains("repo:"))
        .expect("repo line");
    let repo = repo_line.split_whitespace().nth(1).expect("repo path");
    assert!(
        !std::path::Path::new(repo).exists(),
        "demo repo must be removed: {repo}"
    );

    let touched = std::fs::read_dir(&caller_home)
        .map(|d| d.count())
        .unwrap_or(0);
    assert_eq!(touched, 0, "demo wrote into the caller's MATI_HOME");
}
