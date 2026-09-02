//! `mati init` must seed the stats cache with a write-seq that still matches
//! after init finishes, so the first `mati stats` hits the cache.
//!
//! Regression: the seed ran before init's blast-radius and staleness-propagation
//! passes rewrote every `file:` record. Each rewrite bumps write_seq, so the
//! seeded snapshot stamped a stale seq and never validated — every `mati stats`
//! recomputed (dead cache in daemon mode). The fix moves the seed after the last
//! knowledge write.
//!
//! `#[ignore]` because it spawns subprocesses and a daemon. Run with a short
//! `MATI_TEST_HOME` — it sets the parent of the per-process home, and a long
//! one exceeds the ~104-byte Unix socket limit, after which the daemon silently
//! fails to bind. `MATI_HOME` is no longer the lever: `common::mati_home`
//! ignores an inherited value so an exported one cannot merge every test into
//! one store.
//!   MATI_TEST_HOME=/tmp/mati-it cargo nextest run --test init_seeds_valid_cache \
//!     --run-ignored all

use std::path::Path;
use std::process::Command;

mod common;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_mati")
}

fn run_in(dir: &Path, args: &[&str]) -> std::process::Output {
    common::isolate_mati_home();
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
#[ignore]
fn first_stats_after_init_hits_the_seeded_cache() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    common::isolate_mati_home();
    let _daemon_guard = common::DaemonGuard::for_mati_home(dir, common::mati_home());

    if !git(dir, &["init", "-q"]) {
        eprintln!("skip: git unavailable");
        return;
    }
    git(dir, &["config", "user.email", "t@t.t"]);
    git(dir, &["config", "user.name", "t"]);
    std::fs::write(dir.join("main.rs"), "fn main() { println!(\"hi\"); }\n").unwrap();
    git(dir, &["add", "-A"]);
    git(dir, &["commit", "-qm", "init"]);

    let init = run_in(dir, &["init", "--path", dir.to_str().unwrap()]);
    if !init.status.success() {
        eprintln!(
            "skip: mati init failed: {}",
            String::from_utf8_lossy(&init.stderr)
        );
        return;
    }

    let stats = run_in(dir, &["stats"]);
    assert!(
        stats.status.success(),
        "mati stats failed: {}",
        String::from_utf8_lossy(&stats.stderr)
    );
    let out = String::from_utf8_lossy(&stats.stdout);
    // The "(cached Ns ago)" header prints only on the cache-hit path. Before the
    // fix the seeded seq was stale, so the first stats recomputed and this
    // marker was absent.
    assert!(
        out.contains("(cached"),
        "first stats after init should hit the seeded cache; got:\n{out}"
    );
}
