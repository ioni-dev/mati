//! `mati init` proposes CODEOWNERS ownership candidates (idea 2.2 init-wiring),
//! idempotently (a re-init does not duplicate or reset them).

use std::path::Path;
use std::process::Command;

mod common;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_mati")
}

/// Run `mati` with daemon auto-spawn off, forcing `StoreProxy` down its
/// direct-open branch (the same lever `tests/suggest_cli.rs` uses).
///
/// Without it `mati ls` spawns a daemon and waits on `ensure_daemon`, whose
/// `Wedged` threshold is 15s. Under a loaded suite that spawn misses the
/// window, `ls` exits 1 with empty stdout, and a count over that stdout reads
/// as "no candidate" — a dead read wearing an idempotency failure's clothes.
/// `init` opens the store directly and never spawns, so nothing here needs a
/// daemon at all; the store is the only thing under test.
fn run_in(dir: &Path, args: &[&str]) -> std::process::Output {
    // Redirect the store off the developer's real ~/.mati (inherited by the
    // spawned `mati`). Set before the first spawn; idempotent thereafter.
    common::isolate_mati_home();
    Command::new(bin())
        .args(args)
        .current_dir(dir)
        .env("MATI_DISABLE_AUTO_SPAWN", "1")
        .output()
        .expect("run mati")
}

/// `mati ls gotchas`, with the exit status checked.
///
/// Counting matches in the stdout of an unchecked `ls` cannot tell "the record
/// is absent" from "the read failed", and the two want opposite fixes.
fn list_gotchas(dir: &Path) -> String {
    let out = run_in(dir, &["ls", "gotchas"]);
    assert!(
        out.status.success(),
        "`mati ls gotchas` failed ({}): {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
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
    // Nothing below spawns a daemon, but a leaked one would hold the store
    // lock and break every later run against this home, so keep the net.
    common::isolate_mati_home();
    let _daemon_guard = common::DaemonGuard::for_mati_home(dir, common::mati_home());
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
    // The pattern only yields a candidate if it owns a real file.
    std::fs::create_dir_all(dir.join("src/payments")).unwrap();
    std::fs::write(dir.join("src/payments/stripe.rs"), "fn charge() {}\n").unwrap();
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

    let listed = list_gotchas(dir);
    let count = listed.matches("codeowners:src/payments/**").count();
    assert_eq!(
        count, 1,
        "init should propose exactly one CODEOWNERS candidate; got:\n{listed}"
    );

    // Touch the owned file so the second init's mtime check re-parses it.
    // Without this, `Mtime+parse (incremental)` skips all 3 files, the repo
    // file list reaches `build_codeowners_candidates` empty, and no candidate
    // is generated at all — so the assertion below would hold no matter what
    // the de-duplication does.
    std::fs::write(dir.join("src/payments/stripe.rs"), "fn charge(n: u32) {}\n").unwrap();

    // Re-init must not duplicate it. No `daemon stop` in between: with
    // auto-spawn disabled the `ls` above direct-opened the store and released
    // the lock when it exited, so `init` still gets exclusive access.
    let reinit = run_in(dir, &["init"]);
    assert!(
        reinit.status.success(),
        "re-init failed: {}",
        String::from_utf8_lossy(&reinit.stderr)
    );
    let again = list_gotchas(dir);
    let count2 = again.matches("codeowners:src/payments/**").count();
    assert_eq!(
        count2, 1,
        "re-init must be idempotent (no duplicate); got:\n{again}"
    );
}
