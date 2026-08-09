//! `mati sandbox compile --codex --apply` acknowledgment gate (F2, fixed
//! ordering in `7609349`).
//!
//! The gate — and the warning that must precede it — has to run before
//! `StoreProxy::open`, or a slow/wedged daemon would sit between the user and
//! the refusal on every accidental `--apply` without `--acknowledge-...`.
//! These tests never call `mati init`, so a reflex "no store" failure past the
//! gate is not a fluke: it is proof the store path was actually reached.
//!
//! No `MATI_HOME` directory is ever created by the refused case — direct
//! evidence `StoreProxy::open` (which would create/touch it) never ran.

use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};

use tempfile::TempDir;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_mati")
}

/// A bare git repo (so `repo_root_for` resolves) with its own unused
/// `MATI_HOME`, never populated by `mati init`.
struct BareRepo {
    _dir: TempDir,
    repo: std::path::PathBuf,
    mati_home: std::path::PathBuf,
}

fn bare_repo() -> BareRepo {
    let dir = TempDir::new().expect("tempdir");
    let repo = dir.path().join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    std::process::Command::new("git")
        .args(["init", "-q"])
        .current_dir(&repo)
        .status()
        .expect("git init");
    let mati_home = dir.path().join("mati-home-unused");
    BareRepo {
        _dir: dir,
        repo,
        mati_home,
    }
}

/// Run `mati sandbox compile --codex [args]` with stdout+stderr merged into
/// one file (same fd), so their relative order on disk reflects the real
/// write order — two separate `Stdio::piped()` streams cannot prove that.
fn run_merged(repo: &Path, mati_home: &Path, args: &[&str]) -> (i32, String) {
    let out_path = repo.join("combined.out");
    let out_file = std::fs::File::create(&out_path).unwrap();
    let err_file = out_file.try_clone().unwrap();
    let status = Command::new(bin())
        .arg("sandbox")
        .arg("compile")
        .arg("--codex")
        .args(args)
        .current_dir(repo)
        .env("MATI_HOME", mati_home)
        .stdin(Stdio::null())
        .stdout(Stdio::from(out_file))
        .stderr(Stdio::from(err_file))
        .status()
        .expect("run mati sandbox compile --codex");
    let mut combined = String::new();
    std::fs::File::open(&out_path)
        .unwrap()
        .read_to_string(&mut combined)
        .unwrap();
    (status.code().unwrap_or(-1), combined)
}

#[test]
fn codex_apply_without_acknowledge_warns_then_refuses_before_touching_store() {
    let r = bare_repo();
    let (code, combined) = run_merged(&r.repo, &r.mati_home, &["--apply"]);

    assert_eq!(code, 1, "must exit non-zero; got output:\n{combined}");

    let warn_at = combined
        .find("WARNING: Codex does not currently enforce filesystem deny_read/deny_write entries.");
    let refuse_at = combined.find(
        "Error: Codex does not currently enforce these entries; refusing --codex --apply \
         without --acknowledge-codex-non-enforcement",
    );
    assert!(
        warn_at.is_some() && refuse_at.is_some(),
        "expected both the warning and the refusal in combined output, got:\n{combined}"
    );
    assert!(
        warn_at.unwrap() < refuse_at.unwrap(),
        "warning must be written before the refusal, got:\n{combined}"
    );

    // Never reached StoreProxy::open: no store dir, no daemon socket, no
    // .codex/config.toml — the gate fired before any of that could exist.
    assert!(
        !r.mati_home.exists(),
        "MATI_HOME must never be created — the store path was never opened"
    );
    assert!(!r.repo.join(".codex/config.toml").exists());
}

#[test]
fn codex_apply_with_acknowledge_passes_the_gate_and_fails_for_a_different_reason() {
    // Negative twin: the same flag, but WITH acknowledgment, must not hit the
    // acknowledgment refusal at all — proven by a distinct downstream error
    // (no store initialized), reached only past the gate.
    let r = bare_repo();
    let (code, combined) = run_merged(
        &r.repo,
        &r.mati_home,
        &["--apply", "--acknowledge-codex-non-enforcement"],
    );

    assert_eq!(code, 1, "still fails, but for lack of a store:\n{combined}");
    assert!(
        !combined.contains("acknowledge-codex-non-enforcement"),
        "the acknowledgment refusal must not fire when the flag is present:\n{combined}"
    );
    assert!(
        combined.contains("no mati store initialized for this directory"),
        "expected the store-open error past the gate, got:\n{combined}"
    );
}

#[test]
fn codex_preview_without_apply_never_needs_acknowledge_but_still_opens_the_store() {
    // The gate is scoped to `--apply`. Preview mode (no --apply) skips the
    // acknowledgment check entirely but still reaches StoreProxy::open —
    // distinguishing this from the --apply-without-acknowledge case, which
    // never does.
    let r = bare_repo();
    let (code, combined) = run_merged(&r.repo, &r.mati_home, &[]);

    assert_eq!(
        code, 1,
        "no store initialized, so preview fails too:\n{combined}"
    );
    assert!(
        !combined.contains("acknowledge-codex-non-enforcement"),
        "preview must never require acknowledgment:\n{combined}"
    );
    assert!(combined.contains("no mati store initialized for this directory"));
}
