//! `mati suggest` end-to-end: scans CODEOWNERS + load-bearing/security markers
//! and proposes candidates.
//!
//! Every test here needs a real store. `suggest` opens one before the
//! `--dry-run` branch, because the `governed_files` filter — which keeps
//! `suggest` from minting a record out of a file the read gate is denying —
//! runs on both paths and is fail-closed.
//!
//! `mati init` does not need a git repo, so these tests do not create one and
//! never skip: an assertion failure here is always a real failure.

use std::path::Path;
use std::process::Command;

mod common;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_mati")
}

fn run_in(dir: &Path, args: &[&str]) -> std::process::Output {
    // Redirect the store off the developer's real ~/.mati (inherited by the
    // spawned `mati`). Set before the first spawn; idempotent thereafter.
    common::isolate_mati_home();
    Command::new(bin())
        .args(args)
        .current_dir(dir)
        .output()
        .expect("run mati")
}

/// Run against a private `MATI_HOME` with daemon auto-spawn disabled, forcing
/// `StoreProxy` down its direct-open branch.
///
/// The home must be private, not `common::mati_home()`: that helper honors an
/// inherited `MATI_HOME`, and `StoreProxy::open` pings for a live daemon BEFORE
/// consulting the spawn gate, so a daemon already running for a shared home
/// puts the run back on the socket path. `MATI_DISABLE_AUTO_SPAWN` suppresses
/// spawning, not reuse.
fn run_direct_in(dir: &Path, home: &Path, args: &[&str]) -> std::process::Output {
    Command::new(bin())
        .args(args)
        .current_dir(dir)
        .env("MATI_HOME", home)
        .env("MATI_DISABLE_AUTO_SPAWN", "1")
        .output()
        .expect("run mati")
}

fn ok_direct_in(dir: &Path, home: &Path, args: &[&str]) -> String {
    let out = run_direct_in(dir, home, args);
    assert!(
        out.status.success(),
        "`mati {}` failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Socket paths anywhere under `home`, i.e. a daemon was involved.
fn sockets(home: &Path) -> Vec<std::path::PathBuf> {
    fn walk(dir: &Path, found: &mut Vec<std::path::PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for e in entries.flatten() {
            let path = e.path();
            if path.is_dir() {
                walk(&path, found);
            } else if path.file_name().is_some_and(|n| n == "mati.sock") {
                found.push(path);
            }
        }
    }
    let mut found = Vec::new();
    walk(home, &mut found);
    found
}

fn ok_in(dir: &Path, args: &[&str]) -> String {
    let out = run_in(dir, args);
    assert!(
        out.status.success(),
        "`mati {}` failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn write(dir: &Path, rel: &str, body: &str) {
    let path = dir.join(rel);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, body).unwrap();
}

#[test]
fn suggest_dry_run_proposes_codeowners_and_marker_candidates() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path();
    common::isolate_mati_home();
    let _daemon_guard = common::DaemonGuard::for_mati_home(root, common::mati_home());
    write(root, ".github/CODEOWNERS", "src/payments/** @pay-team\n");
    // The pattern only yields a candidate if it owns a real file.
    write(root, "src/payments/stripe.rs", "fn charge() {}\n");
    write(
        root,
        "src/main.rs",
        "fn main() {\n    // DO NOT REMOVE: load-bearing init order\n}\n",
    );
    ok_in(root, &["init"]);

    let s = ok_in(root, &["suggest", "--dry-run"]);
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
fn suggest_dry_run_writes_nothing() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path();
    common::isolate_mati_home();
    let _daemon_guard = common::DaemonGuard::for_mati_home(root, common::mati_home());
    write(
        root,
        "src/main.rs",
        "fn main() {\n    // DO NOT REMOVE: load-bearing init order\n}\n",
    );
    ok_in(root, &["init"]);

    assert!(ok_in(root, &["suggest", "--dry-run"]).contains("Would propose"));
    let listed = ok_in(root, &["ls", "gotchas"]);
    assert!(
        !listed.contains("marker:src/main.rs:2"),
        "--dry-run must not write the candidate it previewed; got:\n{listed}"
    );
}

#[test]
fn suggest_empty_repo_finds_nothing() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path();
    common::isolate_mati_home();
    let _daemon_guard = common::DaemonGuard::for_mati_home(root, common::mati_home());
    write(root, "README.md", "x\n");
    ok_in(root, &["init"]);

    let s = ok_in(root, &["suggest", "--dry-run"]);
    assert!(
        s.contains("No onboarding candidates"),
        "a repo carrying only `mati init` scaffold should find nothing; got:\n{s}"
    );
}

/// The write path: a file already covered by a confirmed gotcha is skipped, the
/// skip is reported, and a re-run proposes nothing new.
///
/// The skip is the disclosure fix — `suggest` used to mint a
/// `gotcha:marker:<path>:<line>` record quoting a `SECURITY:` line out of a file
/// the read gate was denying, which `mati show` then printed without a receipt.
#[test]
fn suggest_skips_governed_files_and_is_idempotent() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path();
    common::isolate_mati_home();
    let _daemon_guard = common::DaemonGuard::for_mati_home(root, common::mati_home());
    write(root, "README.md", "x\n");
    // Init before the marker files exist, so the candidates below are new on the
    // first `suggest` and the "already present" branch is reached only on the second.
    ok_in(root, &["init"]);
    write(
        root,
        "src/gated.rs",
        "fn a() {\n    // SECURITY: validate the token before use\n}\n",
    );
    write(
        root,
        "src/other.rs",
        "fn b() {\n    // DO NOT REMOVE: load-bearing init order\n}\n",
    );
    let added = ok_in(
        root,
        &[
            "gotcha",
            "add",
            "src/gated.rs",
            "-r",
            "Validate the token before use",
            "-m",
            "Because an unvalidated token authenticates anyone",
        ],
    );
    assert!(
        added.contains("Created gotcha:"),
        "gotcha add did not create a record; got:\n{added}"
    );

    let first = ok_in(root, &["suggest"]);
    assert!(
        first.contains("Proposed 1 new candidate(s)"),
        "expected exactly the ungoverned file's candidate; got:\n{first}"
    );
    assert!(
        first.contains("(1 governed file(s) skipped)"),
        "the skip must be reported on the write path; got:\n{first}"
    );

    let listed = ok_in(root, &["ls", "gotchas"]);
    assert!(
        listed.contains("marker:src/other.rs:2"),
        "the ungoverned file's candidate should be written; got:\n{listed}"
    );
    assert!(
        !listed.contains("marker:src/gated.rs"),
        "a confirmed gotcha's file must not be re-mined for markers; got:\n{listed}"
    );

    let second = ok_in(root, &["suggest"]);
    assert!(
        second.contains("All 1 candidate(s) already present"),
        "a re-run must propose nothing new; got:\n{second}"
    );
    assert!(
        second.contains("(1 governed file(s) skipped)"),
        "the skip must be reported on the already-present branch; got:\n{second}"
    );
}

/// A confirmed gotcha can name a path that no longer exists. Nothing is skipped
/// in that case, so nothing should be reported as skipped.
#[test]
fn governed_note_counts_actual_skips_not_the_governed_set() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path();
    common::isolate_mati_home();
    let _daemon_guard = common::DaemonGuard::for_mati_home(root, common::mati_home());
    write(root, "README.md", "x\n");
    ok_in(root, &["init"]);
    write(
        root,
        "src/gone.rs",
        "fn a() {\n    // SECURITY: check the token\n}\n",
    );
    ok_in(
        root,
        &[
            "gotcha",
            "add",
            "src/gone.rs",
            "-r",
            "Check the token first",
            "-m",
            "Because an unchecked token authenticates anyone",
        ],
    );
    std::fs::remove_file(root.join("src/gone.rs")).unwrap();
    write(
        root,
        "src/live.rs",
        "fn b() {\n    // DO NOT REMOVE: load-bearing init order\n}\n",
    );

    let s = ok_in(root, &["suggest"]);
    assert!(
        !s.contains("governed file(s) skipped"),
        "no file was skipped, so no skip should be reported; got:\n{s}"
    );
}

/// The same governed skip and write, on the direct-open store path.
///
/// Every other test here reaches the store through a daemon socket, so the
/// `StoreProxy::Direct` branch of `scan_prefix`/`get`/`put` is otherwise
/// unexercised. This one runs against a private `MATI_HOME` with auto-spawn
/// disabled, so no daemon exists for it and every command opens the store
/// directly.
///
/// It does NOT prove the proxy is closed. `gotcha:*` is `Immediate` durability,
/// so each write is fsynced on its own and survives a skipped close — verified
/// by mutation: dropping the proxy unclosed leaves this passing.
#[test]
fn suggest_skips_governed_files_on_the_direct_store_path() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path().join("repo");
    let home = tmp.path().join("home");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    let root = root.as_path();
    let home = home.as_path();
    write(root, "README.md", "x\n");
    ok_direct_in(root, home, &["init"]);
    write(
        root,
        "src/gated.rs",
        "fn a() {\n    // SECURITY: validate the token before use\n}\n",
    );
    write(
        root,
        "src/other.rs",
        "fn b() {\n    // DO NOT REMOVE: load-bearing init order\n}\n",
    );
    ok_direct_in(
        root,
        home,
        &[
            "gotcha",
            "add",
            "src/gated.rs",
            "-r",
            "Validate the token before use",
            "-m",
            "Because an unvalidated token authenticates anyone",
        ],
    );

    let out = ok_direct_in(root, home, &["suggest"]);
    assert!(
        out.contains("Proposed 1 new candidate(s)"),
        "expected exactly the ungoverned file's candidate; got:\n{out}"
    );
    assert!(
        out.contains("(1 governed file(s) skipped)"),
        "the skip must be reported on the direct path too; got:\n{out}"
    );

    // A separate process, so this reads what actually reached disk.
    let listed = ok_direct_in(root, home, &["ls", "gotchas"]);
    assert!(
        listed.contains("marker:src/other.rs:2"),
        "the candidate should persist across processes; got:\n{listed}"
    );
    assert!(
        !listed.contains("marker:src/gated.rs"),
        "a confirmed gotcha's file must not be re-mined for markers; got:\n{listed}"
    );

    // Without this the test silently degrades into a duplicate of the
    // socket-mode one the moment anything puts a daemon back in the path.
    let sockets = sockets(home);
    assert!(
        sockets.is_empty(),
        "a daemon socket exists, so this ran on the socket path: {sockets:?}"
    );
}
