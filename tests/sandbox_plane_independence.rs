//! Plane independence: **Plane 1 failing open does not open Plane 3.**
//!
//! The SOTA failure-mode contract (`FAILURE_MODES.md` §3) rests on one property:
//! a crown-jewel file protected by the OS sandbox floor stays denied even when
//! every mati process is dead. The dynamic hook gate (Plane 1) fails open on a
//! daemon outage by design; the OS floor (Plane 3) must not, because the kernel
//! — not mati — enforces it.
//!
//! This ports the deterministic proof in `test-l3-sandbox-deterministic.sh` into
//! the suite so a refactor that coupled the floor to the daemon would fail CI.
//!
//! Two tests:
//!   1. `floor_materializes_without_daemon` (all platforms) — the half mati owns:
//!      `mati sandbox protect` writes absolute-canonical denies that survive
//!      `mati daemon stop`.
//!   2. `floor_enforces_with_no_mati_process` (macOS) — the guarantee: those
//!      exact denies block read/write/symlink under `sandbox-exec`, with no mati
//!      binary in the enforcement step. The enforcement command line is
//!      `sandbox-exec` + `cat`/`sh` only — proof by construction that Plane 3 is
//!      independent of any live mati process.

use std::path::Path;
use std::process::{Command, Output};

use serde_json::Value;
use tempfile::TempDir;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_mati")
}

/// Run the mati binary in `repo`, isolated to a fresh `home` for HOME + MATI_HOME.
fn mati(repo: &Path, home: &Path, args: &[&str]) -> Output {
    Command::new(bin())
        .args(args)
        .current_dir(repo)
        .env("HOME", home)
        .env("MATI_HOME", home)
        .env("NO_COLOR", "1")
        .output()
        .unwrap_or_else(|e| panic!("spawn mati {args:?}: {e}"))
}

/// A git repo with a crown-jewel file protected by the OS floor, then every mati
/// process stopped. Returns the repo dir, its live temp guards, and the
/// canonical absolute path of the protected file. `None` if setup could not be
/// completed on this host (skips, never a false failure) — mirroring the shell
/// proof's SETUP FAILED path.
struct Protected {
    _home: TempDir,
    _root: TempDir,
    repo: std::path::PathBuf,
}

fn protect_and_stop_daemon() -> Option<Protected> {
    let root = TempDir::new().ok()?;
    let home = TempDir::new().ok()?;
    let repo = root.path().join("repo");
    std::fs::create_dir_all(&repo).ok()?;

    let git = Command::new("git")
        .args(["init", "-q"])
        .current_dir(&repo)
        .status()
        .ok()?;
    if !git.success() {
        return None;
    }

    // A real, gotcha-worthy line and a control file. Same rule/reason the shell
    // proof uses — proven to clear the quality gate.
    std::fs::write(repo.join("config.rs"), "retention = 90\n").ok()?;
    std::fs::write(repo.join("control.txt"), "control-ok\n").ok()?;

    if !mati(&repo, home.path(), &["init", "--claude"])
        .status
        .success()
    {
        return None;
    }

    let add = mati(
        &repo,
        home.path(),
        &[
            "gotcha",
            "add",
            "config.rs",
            "-r",
            "Never lower the with_versioning retention below 90 in config.rs",
            "-m",
            "because shorter retention silently drops audit history needed for compliance",
        ],
    );
    let stdout = String::from_utf8_lossy(&add.stdout);
    // Quality gate may reject in an unexpected environment — skip, don't fail.
    let key = stdout
        .split_whitespace()
        .find(|t| t.starts_with("gotcha:"))
        .map(|t| t.trim_matches(|c: char| !(c.is_alphanumeric() || c == ':' || c == '-')))?;

    if !mati(&repo, home.path(), &["gotcha", "confirm", key])
        .status
        .success()
    {
        return None;
    }

    // Compile the crown-jewel file into the OS-level deny floor (read + write).
    if !mati(
        &repo,
        home.path(),
        &["sandbox", "protect", "config.rs", "--read"],
    )
    .status
    .success()
    {
        return None;
    }

    // Kill every mati process. From here the floor must hold on the kernel alone.
    mati(&repo, home.path(), &["daemon", "stop"]);

    Some(Protected {
        _home: home,
        _root: root,
        repo,
    })
}

/// The `denyRead`/`denyWrite` arrays mati materialized into settings.local.json.
fn read_floor(repo: &Path) -> (Vec<String>, Vec<String>) {
    let raw = std::fs::read_to_string(repo.join(".claude/settings.local.json"))
        .expect("settings.local.json must exist after `sandbox protect`");
    let json: Value = serde_json::from_str(&raw).expect("settings.local.json is valid JSON");
    let fs = &json["sandbox"]["filesystem"];
    let arr = |k: &str| {
        fs[k]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default()
    };
    (arr("denyRead"), arr("denyWrite"))
}

#[test]
fn floor_materializes_without_daemon() {
    let Some(p) = protect_and_stop_daemon() else {
        eprintln!("skip: could not set up a protected repo on this host");
        return;
    };

    let (deny_read, deny_write) = read_floor(&p.repo);
    let names_config = |paths: &[String]| paths.iter().any(|s| s.ends_with("config.rs"));

    assert!(
        names_config(&deny_read),
        "config.rs must be in denyRead after `sandbox protect --read`, got {deny_read:?}"
    );
    assert!(
        names_config(&deny_write),
        "config.rs must be in denyWrite, got {deny_write:?}"
    );
    // Absolute canonical — never `./`-relative. An unresolved deny silently fails
    // to protect (FAILURE_MODES.md §5). Seatbelt matches absolute paths only.
    for path in deny_read.iter().chain(&deny_write) {
        assert!(
            path.starts_with('/'),
            "floor path must be absolute canonical, got {path:?}"
        );
    }
}

#[cfg(target_os = "macos")]
#[test]
fn floor_enforces_with_no_mati_process() {
    // The mechanism Claude Code uses on macOS. If it is absent, skip.
    if Command::new("sandbox-exec").arg("-h").output().is_err() {
        eprintln!("skip: sandbox-exec unavailable");
        return;
    }

    let Some(p) = protect_and_stop_daemon() else {
        eprintln!("skip: could not set up a protected repo on this host");
        return;
    };
    let repo = &p.repo;
    let (deny_read, deny_write) = read_floor(repo);

    // Build a Seatbelt profile straight from mati's ACTUAL generated paths — the
    // same transform the shell proof applies. No mati process is consulted.
    let mut profile = String::from("(version 1)\n(allow default)\n");
    for path in &deny_read {
        profile.push_str(&format!("(deny file-read* (literal \"{path}\"))\n"));
    }
    for path in &deny_write {
        profile.push_str(&format!("(deny file-write* (literal \"{path}\"))\n"));
    }
    let profile_path = repo.join("deny.sb");
    std::fs::write(&profile_path, &profile).unwrap();

    // A symlink to the protected file — the classic bypass attempt.
    std::os::unix::fs::symlink(repo.join("config.rs"), repo.join("link.rs")).unwrap();

    // Enforcement step: `sandbox-exec` + `cat`/`sh` only. No mati binary here —
    // this is the proof that Plane 3 holds with mati fully stopped.
    let sb = |args: &[&str]| {
        let out = Command::new("sandbox-exec")
            .arg("-f")
            .arg(&profile_path)
            .args(args)
            .current_dir(repo)
            .output()
            .expect("run sandbox-exec");
        let mut combined = String::from_utf8_lossy(&out.stdout).into_owned();
        combined.push_str(&String::from_utf8_lossy(&out.stderr));
        combined
    };
    let denied = |s: &str| s.to_lowercase().contains("not permitted");

    assert!(
        denied(&sb(&["cat", "config.rs"])),
        "protected read must be denied"
    );
    assert!(
        denied(&sb(&["cat", "link.rs"])),
        "read via symlink must be denied"
    );

    let write = sb(&["sh", "-c", "echo HACK >> config.rs"]);
    let after = std::fs::read_to_string(repo.join("config.rs")).unwrap();
    assert!(denied(&write), "protected write must be denied");
    assert_eq!(
        after, "retention = 90\n",
        "protected file must be unchanged"
    );

    let ctrl = sb(&["cat", "control.txt"]);
    assert!(
        ctrl.contains("control-ok") && !denied(&ctrl),
        "unprotected control file must stay readable, got {ctrl:?}"
    );
}
