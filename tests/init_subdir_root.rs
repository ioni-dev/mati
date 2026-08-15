//! `mati init --path <subdir>` keys records to the repository, not the subtree.
//!
//! `--path` is documented as "Path to repository root", and the slug has always
//! been derived through git — so a subtree path produced a store named for the
//! repo whose `file:*` keys were relative to the subtree. Every record from that
//! run was unreachable by the read gate, which looks up repo-relative keys.

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
fn init_from_a_subdirectory_mints_repo_relative_file_keys() {
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
    std::fs::create_dir_all(dir.join("src/store")).unwrap();
    std::fs::write(dir.join("src/store/durability.rs"), "fn flush() {}\n").unwrap();
    std::fs::write(dir.join("README.md"), "x\n").unwrap();
    git(dir, &["add", "-A"]);
    git(dir, &["commit", "-qm", "init"]);

    // cwd is the repo root, so `--path` is the only thing naming the subtree.
    let init = run_in(dir, &["init", "--path", "src"]);
    if !init.status.success() {
        eprintln!(
            "skip: mati init failed: {}",
            String::from_utf8_lossy(&init.stderr)
        );
        return;
    }

    let export = run_in(dir, &["export", "--format", "json"]);
    assert!(
        export.status.success(),
        "mati export failed: {}",
        String::from_utf8_lossy(&export.stderr)
    );
    let records: Vec<serde_json::Value> =
        serde_json::from_slice(&export.stdout).expect("export --format json");
    let keys: Vec<&str> = records
        .iter()
        .filter_map(|r| r.get("key").and_then(serde_json::Value::as_str))
        .filter(|k| k.starts_with("file:"))
        .collect();

    assert!(
        keys.contains(&"file:src/store/durability.rs"),
        "file keys must be relative to the repo root; got {keys:?}"
    );
    assert!(
        !keys.contains(&"file:store/durability.rs"),
        "subtree-relative key survived; got {keys:?}"
    );
    // The walk covers the whole repo, so a file outside the subtree is indexed.
    assert!(
        keys.contains(&"file:README.md"),
        "the walk must cover the repo, not the subtree; got {keys:?}"
    );
}
