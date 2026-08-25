//! Integration test for the `mati hook-decide` enforcement flow.
//!
//! Exercises the real binary against a real daemon with real confirmed gotchas.
//! Verifies the full deny -> consult -> allow lifecycle:
//!
//!   1. `hook-decide codex-pre-bash` denies a `cat` command (exit 2) when the
//!      target file has a confirmed gotcha and no consultation receipt exists.
//!   2. `mati explain` writes a consultation receipt via `log_hit`.
//!   3. The same `hook-decide` call now allows (exit 0) because the receipt exists.
//!
//! # Running
//!
//! The lifecycle tests are `#[ignore]`d by default -- they spawn daemon
//! processes, write to disk, and are slower than unit tests. Run them
//! explicitly:
//!
//! ```sh
//! cargo test --test hook_decide_integration -- --ignored --nocapture
//! ```
//!
//! `hook_deadline_terminates_the_process` is not ignored. It spawns no daemon
//! and needs no repo, and the regression it pins is invisible to a suite that
//! skips it.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
#[cfg(unix)]
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
#[cfg(unix)]
use std::thread;
use std::time::Duration;

use tempfile::TempDir;

// ── Helpers ─────────────────────────────────────────────────────────────────

fn mati_bin() -> PathBuf {
    if let Ok(p) = std::env::var("CARGO_BIN_EXE_MATI") {
        return PathBuf::from(p);
    }
    let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(manifest)
        .join("target")
        .join("debug")
        .join("mati")
}

/// Run mati with the given args, isolating MATI_HOME and HOME to `home`, and CWD to `repo`.
fn run(bin: &Path, repo: &Path, home: &Path, args: &[&str]) -> RunResult {
    let out = Command::new(bin)
        .args(args)
        .current_dir(repo)
        .env("HOME", home)
        .env("MATI_HOME", home)
        .env("NO_COLOR", "1")
        .output()
        .expect("failed to run mati");
    RunResult {
        stdout: String::from_utf8_lossy(&out.stdout).to_string(),
        stderr: String::from_utf8_lossy(&out.stderr).to_string(),
        code: out.status.code().unwrap_or(-1),
    }
}

/// Run mati with piped stdin, isolating MATI_HOME, HOME, and CWD.
fn run_with_stdin(
    bin: &Path,
    repo: &Path,
    home: &Path,
    args: &[&str],
    stdin_data: &str,
) -> RunResult {
    let mut child = Command::new(bin)
        .args(args)
        .current_dir(repo)
        .env("HOME", home)
        .env("MATI_HOME", home)
        .env("NO_COLOR", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn mati");

    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(stdin_data.as_bytes())
            .expect("failed to write stdin");
        // Drop stdin to close the pipe, signaling EOF.
    }

    let out = child
        .wait_with_output()
        .expect("failed to wait for mati process");

    RunResult {
        stdout: String::from_utf8_lossy(&out.stdout).to_string(),
        stderr: String::from_utf8_lossy(&out.stderr).to_string(),
        code: out.status.code().unwrap_or(-1),
    }
}

/// Run a real mati binary with an explicit short MATI_HOME.
#[cfg(unix)]
fn run_with_mati_home(
    bin: &Path,
    repo: &Path,
    home: &Path,
    mati_home: &Path,
    args: &[&str],
) -> RunResult {
    let out = Command::new(bin)
        .args(args)
        .current_dir(repo)
        .env("HOME", home)
        .env("MATI_HOME", mati_home)
        .env("NO_COLOR", "1")
        .output()
        .expect("failed to run mati");
    RunResult {
        stdout: String::from_utf8_lossy(&out.stdout).to_string(),
        stderr: String::from_utf8_lossy(&out.stderr).to_string(),
        code: out.status.code().unwrap_or(-1),
    }
}

struct RunResult {
    stdout: String,
    stderr: String,
    code: i32,
}

/// Create a minimal git repo with a Rust source file and one commit.
/// Returns (repo_dir, home_dir).
fn setup_repo() -> (TempDir, TempDir) {
    let repo_dir = TempDir::new().expect("create repo dir");
    let home_dir = TempDir::new().expect("create home dir");
    let repo = repo_dir.path();

    // git init + configure identity
    Command::new("git")
        .args(["init"])
        .current_dir(repo)
        .output()
        .expect("git init");
    Command::new("git")
        .args(["config", "user.email", "test@test.com"])
        .current_dir(repo)
        .output()
        .expect("git config email");
    Command::new("git")
        .args(["config", "user.name", "Test"])
        .current_dir(repo)
        .output()
        .expect("git config name");

    // Create src/test.rs -- the file we will attach a gotcha to.
    std::fs::create_dir_all(repo.join("src")).expect("mkdir src");
    std::fs::write(
        repo.join("src/test.rs"),
        r#"fn authenticate(token: &str) -> bool {
    // TODO: validate token properly
    !token.is_empty()
}
"#,
    )
    .expect("write test.rs");

    // Create Cargo.toml so mati init recognizes it as a project.
    std::fs::write(
        repo.join("Cargo.toml"),
        r#"[package]
name = "test-project"
version = "0.1.0"
edition = "2021"
"#,
    )
    .expect("write Cargo.toml");

    // Initial commit.
    Command::new("git")
        .args(["add", "-A"])
        .current_dir(repo)
        .output()
        .expect("git add");
    Command::new("git")
        .args(["commit", "-m", "initial commit"])
        .current_dir(repo)
        .output()
        .expect("git commit");

    (repo_dir, home_dir)
}

/// Wait for the daemon to become reachable via `mati ping --daemon-only`.
/// Returns true if the daemon responded within the timeout.
fn wait_for_daemon(bin: &Path, repo: &Path, home: &Path, timeout: Duration) -> bool {
    let start = std::time::Instant::now();
    let poll_interval = Duration::from_millis(100);

    while start.elapsed() < timeout {
        let r = run(bin, repo, home, &["ping", "--daemon-only"]);
        if r.code == 0 {
            return true;
        }
        std::thread::sleep(poll_interval);
    }
    false
}

/// Guard that kills a child process on drop.
struct ChildGuard(std::process::Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A short `MATI_HOME` under `/tmp`, removed on drop.
///
/// `TempDir` will not do here. The daemon binds `$MATI_HOME/<slug>/mati.sock`
/// and macOS rejects Unix socket paths over 104 bytes, which the standard temp
/// location blows past — the daemon then silently fails to bind and every
/// timing measures the fail-open path instead. Dropping removes the store even
/// when the test panics, so a failing run does not leave one behind.
#[cfg(unix)]
struct ShortHome(PathBuf);

#[cfg(unix)]
impl ShortHome {
    fn new(tag: &str) -> Self {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before Unix epoch")
            .as_nanos();
        let path = PathBuf::from(format!("/tmp/m9-{tag}-{}-{nonce}", std::process::id()));
        std::fs::create_dir_all(&path).expect("create short MATI_HOME");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

#[cfg(unix)]
impl Drop for ShortHome {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Test
// ═══════════════════════════════════════════════════════════════════════════════

/// Full hook-decide enforcement lifecycle:
///   deny (exit 2) -> consult via explain -> allow (exit 0).
///
/// This test spawns a real daemon process, writes real records to a real store,
/// and verifies exit codes from the real `mati hook-decide` binary.
#[test]
#[ignore]
fn hook_decide_deny_then_allow_after_consultation() {
    let bin = mati_bin();
    let (repo_dir, home_dir) = setup_repo();
    let repo = repo_dir.path();
    let home = home_dir.path();

    // ── 1. Initialize mati store ────────────────────────────────────────────
    let r = run(&bin, repo, home, &["init", "--no-hooks"]);
    assert_eq!(
        r.code, 0,
        "mati init failed (exit {}):\nstdout: {}\nstderr: {}",
        r.code, r.stdout, r.stderr,
    );

    // SurrealKV WAL compaction: `ping` opens and closes the store, ensuring
    // the WAL is replayed and records are visible to subsequent processes.
    // Without this, records written by `init` may not be readable.
    let r = run(&bin, repo, home, &["ping"]);
    assert_eq!(r.code, 0, "ping after init failed");
    eprintln!("[hook-decide] init complete");

    // ── 2. Add a confirmed gotcha for src/test.rs ───────────────────────────
    //
    // `gotcha add -r` creates a confirmed gotcha (confirmed=true) with:
    //   confidence 0.80 (DeveloperManual source), quality >= 0.4
    // This makes it deny-eligible per the decision matrix.
    let r = run(
        &bin,
        repo,
        home,
        &[
            "gotcha",
            "add",
            "src/test.rs",
            "-r",
            "Never bypass auth token validation",
            "-m",
            "Skipping validation allows unauthorized access to protected endpoints",
        ],
    );
    assert_eq!(
        r.code, 0,
        "mati gotcha add failed (exit {}):\nstdout: {}\nstderr: {}",
        r.code, r.stdout, r.stderr,
    );
    // Verify the gotcha was created.
    assert!(
        r.stdout.contains("Created gotcha:"),
        "expected 'Created gotcha:' in output, got: {}",
        r.stdout,
    );
    eprintln!("[hook-decide] gotcha added: {}", r.stdout.trim());

    // Flush store again after gotcha write.
    let r = run(&bin, repo, home, &["ping"]);
    assert_eq!(r.code, 0, "ping after gotcha add failed");

    // ── 3. Start the daemon ─────────────────────────────────────────────────
    let daemon = Command::new(&bin)
        .args(["daemon", "start"])
        .current_dir(repo)
        .env("HOME", home)
        .env("MATI_HOME", home)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn daemon");
    let _guard = ChildGuard(daemon);

    assert!(
        wait_for_daemon(&bin, repo, home, Duration::from_secs(5)),
        "daemon did not become reachable within 5 seconds",
    );
    eprintln!("[hook-decide] daemon ready");

    // ── 4. hook-decide: first call should DENY (exit 2) ─────────────────────
    //
    // Simulates Codex running `cat src/test.rs`. The file has a confirmed
    // gotcha and no consultation receipt -- hook-decide must deny.
    let stdin_json = r#"{"tool_input":{"command":"cat src/test.rs"}}"#;

    let r = run_with_stdin(
        &bin,
        repo,
        home,
        &["hook-decide", "codex-pre-bash"],
        stdin_json,
    );
    assert_eq!(
        r.code, 2,
        "expected exit code 2 (deny) on first hook-decide call, got {}.\n\
         stdout: {}\nstderr: {}",
        r.code, r.stdout, r.stderr,
    );
    // Codex deny writes a guidance message to stderr.
    assert!(
        r.stderr.contains("mem_get"),
        "deny stderr should instruct the agent to call mem_get.\nstderr: {}",
        r.stderr,
    );
    eprintln!("[hook-decide] first call: exit 2 (deny) -- correct");

    // ── 5. Consult the record via `mati explain` ────────────────────────────
    //
    // `explain` calls `proxy.log_hit("file:src/test.rs")` which writes a
    // `session:consulted:file:src/test.rs` marker via the daemon. The next
    // hook_evaluate will see `consulted_recent: true`.
    let r = run(&bin, repo, home, &["explain", "src/test.rs"]);
    assert_eq!(
        r.code, 0,
        "mati explain failed (exit {}):\nstdout: {}\nstderr: {}",
        r.code, r.stdout, r.stderr,
    );
    eprintln!("[hook-decide] explain (consultation receipt written)");

    // ── 6. hook-decide: second call should ALLOW (exit 0) ───────────────────
    //
    // Same command, same file -- but now a consultation receipt exists.
    // The decision should be AlreadyConsulted -> exit 0.
    let r = run_with_stdin(
        &bin,
        repo,
        home,
        &["hook-decide", "codex-pre-bash"],
        stdin_json,
    );
    assert_eq!(
        r.code, 0,
        "expected exit code 0 (allow) after consultation, got {}.\n\
         stdout: {}\nstderr: {}",
        r.code, r.stdout, r.stderr,
    );
    eprintln!("[hook-decide] second call: exit 0 (allow) -- correct");

    // ── 7. Verify non-file commands pass through ────────────────────────────
    //
    // Commands that don't read files (e.g. `ls -la`) should always exit 0.
    let r = run_with_stdin(
        &bin,
        repo,
        home,
        &["hook-decide", "codex-pre-bash"],
        r#"{"tool_input":{"command":"ls -la"}}"#,
    );
    assert_eq!(
        r.code, 0,
        "non-file command should always exit 0, got {}.\n\
         stdout: {}\nstderr: {}",
        r.code, r.stdout, r.stderr,
    );
    eprintln!("[hook-decide] non-file command: exit 0 -- correct");

    // ── 8. Verify claude-pre-read variant (JSON output, exit 0 always) ──────
    //
    // Claude hooks always exit 0 (deny is communicated via JSON, not exit code).
    // Since we already consulted, the response should be "allow" with context.
    let r = run_with_stdin(
        &bin,
        repo,
        home,
        &["hook-decide", "claude-pre-read"],
        r#"{"tool_input":{"file_path":"src/test.rs"}}"#,
    );
    assert_eq!(
        r.code, 0,
        "claude-pre-read should always exit 0, got {}.\n\
         stdout: {}\nstderr: {}",
        r.code, r.stdout, r.stderr,
    );
    let response: serde_json::Value = serde_json::from_str(r.stdout.trim()).unwrap_or_else(|e| {
        panic!(
            "claude-pre-read stdout is not valid JSON: {e}\n{}",
            r.stdout
        )
    });
    let permission = response
        .pointer("/hookSpecificOutput/permissionDecision")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    assert_eq!(
        permission, "allow",
        "claude-pre-read should allow after consultation.\nJSON: {}",
        r.stdout,
    );
    eprintln!("[hook-decide] claude-pre-read: allow with context -- correct");

    // ── Cleanup ─────────────────────────────────────────────────────────────
    // _guard drops here -> daemon killed.
    // repo_dir and home_dir drop here -> temp directories cleaned up.
    eprintln!("[hook-decide] all assertions passed");
}

/// WI-20 symlink-bypass closure (end-to-end).
///
/// Proves the canonical-key enforcement fallback closes the symlink bypass:
///
///   1. A confirmed gotcha on the REAL file `src/test.rs`, accessed via a
///      SYMLINK `link.rs` → `src/test.rs`, DENIES (exit 2). Before WI-20 the
///      symlink's distinct lexical key (`file:link.rs`) had no gotcha, so the
///      gate was bypassed. The canonical fallback resolves the symlink to the
///      real target's key and the gate fires.
///   2. A symlink to a NON-gotcha'd file (`safe_link.rs` → `src/safe.rs`)
///      ALLOWS (exit 0) — no false positive.
///   3. Direct (non-symlink) access of the gotcha'd file still DENIES (exit 2),
///      proving the lexical gate is unchanged.
///
/// Unix-only: relies on `std::os::unix::fs::symlink`.
#[cfg(unix)]
#[test]
#[ignore]
fn hook_decide_denies_gotcha_through_symlink() {
    let bin = mati_bin();
    let (repo_dir, home_dir) = setup_repo();
    let repo = repo_dir.path();
    let home = home_dir.path();

    // A second, non-gotcha'd source file for the no-false-positive case.
    std::fs::write(repo.join("src/safe.rs"), "pub fn ok() -> bool { true }\n")
        .expect("write safe.rs");

    // Symlinks (created before `mati init` so they're part of the tree):
    //   link.rs      → src/test.rs  (the gotcha'd file)
    //   safe_link.rs → src/safe.rs  (no gotcha)
    std::os::unix::fs::symlink(repo.join("src/test.rs"), repo.join("link.rs"))
        .expect("symlink link.rs");
    std::os::unix::fs::symlink(repo.join("src/safe.rs"), repo.join("safe_link.rs"))
        .expect("symlink safe_link.rs");

    // ── Init store ──────────────────────────────────────────────────────────
    let r = run(&bin, repo, home, &["init", "--no-hooks"]);
    assert_eq!(r.code, 0, "mati init failed:\n{}\n{}", r.stdout, r.stderr);
    let r = run(&bin, repo, home, &["ping"]);
    assert_eq!(r.code, 0, "ping after init failed");

    // ── Confirmed gotcha on the REAL file ───────────────────────────────────
    let r = run(
        &bin,
        repo,
        home,
        &[
            "gotcha",
            "add",
            "src/test.rs",
            "-r",
            "Never bypass auth token validation",
            "-m",
            "Skipping validation allows unauthorized access to protected endpoints",
        ],
    );
    assert_eq!(
        r.code, 0,
        "mati gotcha add failed:\n{}\n{}",
        r.stdout, r.stderr
    );
    assert!(
        r.stdout.contains("Created gotcha:"),
        "expected 'Created gotcha:', got: {}",
        r.stdout
    );
    let r = run(&bin, repo, home, &["ping"]);
    assert_eq!(r.code, 0, "ping after gotcha add failed");

    // ── Daemon ──────────────────────────────────────────────────────────────
    let daemon = Command::new(&bin)
        .args(["daemon", "start"])
        .current_dir(repo)
        .env("HOME", home)
        .env("MATI_HOME", home)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn daemon");
    let _guard = ChildGuard(daemon);
    assert!(
        wait_for_daemon(&bin, repo, home, Duration::from_secs(5)),
        "daemon did not become reachable within 5 seconds",
    );

    // ── 1. cat THROUGH THE SYMLINK must DENY (the bypass is closed) ──────────
    let r = run_with_stdin(
        &bin,
        repo,
        home,
        &["hook-decide", "codex-pre-bash"],
        r#"{"tool_input":{"command":"cat link.rs"}}"#,
    );
    assert_eq!(
        r.code, 2,
        "symlink to a gotcha'd file must DENY (exit 2) — the bypass must be closed.\n\
         stdout: {}\nstderr: {}",
        r.stdout, r.stderr,
    );
    assert!(
        r.stderr.contains("mem_get"),
        "deny stderr should instruct mem_get.\nstderr: {}",
        r.stderr,
    );
    eprintln!("[wi20] cat through symlink: exit 2 (deny) -- bypass closed");

    // ── 2. cat a symlink to a NON-gotcha'd file must ALLOW (no false +) ──────
    let r = run_with_stdin(
        &bin,
        repo,
        home,
        &["hook-decide", "codex-pre-bash"],
        r#"{"tool_input":{"command":"cat safe_link.rs"}}"#,
    );
    assert_eq!(
        r.code, 0,
        "symlink to a non-gotcha'd file must ALLOW (exit 0) — no false positive.\n\
         stdout: {}\nstderr: {}",
        r.stdout, r.stderr,
    );
    eprintln!("[wi20] cat safe symlink: exit 0 (allow) -- no false positive");

    // ── 3. Direct (non-symlink) access still DENIES (lexical gate intact) ────
    let r = run_with_stdin(
        &bin,
        repo,
        home,
        &["hook-decide", "codex-pre-bash"],
        r#"{"tool_input":{"command":"cat src/test.rs"}}"#,
    );
    assert_eq!(
        r.code, 2,
        "direct access of the gotcha'd file must still DENY (exit 2).\n\
         stdout: {}\nstderr: {}",
        r.stdout, r.stderr,
    );
    eprintln!("[wi20] direct cat: exit 2 (deny) -- lexical gate unchanged");

    // ── 4. Claude pre-read THROUGH the symlink: JSON deny, exit 0 ───────────
    // Claude communicates deny via JSON (permissionDecision=deny), exit 0.
    let r = run_with_stdin(
        &bin,
        repo,
        home,
        &["hook-decide", "claude-pre-read"],
        // Absolute symlink path, as Claude Code passes file_path.
        &format!(
            r#"{{"tool_input":{{"file_path":"{}"}}}}"#,
            repo.join("link.rs").display()
        ),
    );
    assert_eq!(r.code, 0, "claude-pre-read always exits 0");
    let response: serde_json::Value = serde_json::from_str(r.stdout.trim())
        .unwrap_or_else(|e| panic!("claude-pre-read stdout not JSON: {e}\n{}", r.stdout));
    let permission = response
        .pointer("/hookSpecificOutput/permissionDecision")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    assert_eq!(
        permission, "deny",
        "claude-pre-read through a symlink to a gotcha'd file must deny.\nJSON: {}",
        r.stdout,
    );
    eprintln!("[wi20] claude-pre-read through symlink: deny -- correct");

    eprintln!("[wi20] all symlink-bypass assertions passed");
}

/// Live E2E for the `deny_if` content-deny axis through the real hook path.
///
/// Authors a `deny_if` policy via the library (there is no CLI flag yet), starts
/// a real daemon, and drives the real `mati hook-decide` binary:
///   1. `psql ... drop table` DENIES (codex exit 2; claude JSON deny);
///   2. `psql ... select 1` ALLOWS (no false positive);
///   3. the hash-chained log records a `policy_content_denied` Deny event.
#[test]
#[ignore]
fn hook_decide_content_deny_denies_and_records() {
    let bin = mati_bin();
    let (repo_dir, home_dir) = setup_repo();
    let repo = repo_dir.path();
    let home = home_dir.path();

    // Pin this process's MATI_HOME to the test dir so the final in-process event
    // read (after the daemon stops) cannot inherit a leaked ambient MATI_HOME.
    std::env::set_var("MATI_HOME", home);

    // ── 1. init the store ───────────────────────────────────────────────────
    let r = run(&bin, repo, home, &["init", "--no-hooks"]);
    assert_eq!(r.code, 0, "mati init failed:\n{}\n{}", r.stdout, r.stderr);
    let r = run(&bin, repo, home, &["ping"]);
    assert_eq!(r.code, 0, "ping after init failed");

    // ── 2. author + enable a content-deny policy via the real CLI ───────────
    let r = run(
        &bin,
        repo,
        home,
        &[
            "policy",
            "add",
            "no-drop-table",
            "--name",
            "No destructive prod SQL",
            "--rule",
            "Deny DROP TABLE via db clients.",
            "--reason",
            "Dropping a table is irreversible data loss.",
            "--mode",
            "block",
            "--trigger",
            r#"{"tool":"db_client"}"#,
            "--deny-if-command-glob",
            "*drop table*",
            "--enable",
        ],
    );
    assert_eq!(
        r.code, 0,
        "mati policy add failed:\n{}\n{}",
        r.stdout, r.stderr
    );
    let r = run(&bin, repo, home, &["ping"]);
    assert_eq!(r.code, 0, "ping after policy add failed");

    // ── 3. start a real daemon (loads the policy into its matcher at boot) ───
    let daemon = Command::new(&bin)
        .args(["daemon", "start"])
        .current_dir(repo)
        .env("HOME", home)
        .env("MATI_HOME", home)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn daemon");
    let _guard = ChildGuard(daemon);
    assert!(
        wait_for_daemon(&bin, repo, home, Duration::from_secs(5)),
        "daemon did not become reachable",
    );

    // Sanity: the daemon actually knows the policy we just authored.
    let show = run(
        &bin,
        repo,
        home,
        &["policy", "show", "policy:no-drop-table"],
    );
    assert_eq!(
        show.code, 0,
        "daemon does not know policy:no-drop-table:\n{}\n{}",
        show.stdout, show.stderr,
    );

    // ── 4. matching DROP → codex-pre-bash DENIES (exit 2) ───────────────────
    let deny = run_with_stdin(
        &bin,
        repo,
        home,
        &["hook-decide", "codex-pre-bash"],
        r#"{"tool_input":{"command":"psql -h prod -c \"drop table orders\""}}"#,
    );
    assert_eq!(
        deny.code, 2,
        "content-deny must DENY (exit 2).\nstdout: {}\nstderr: {}",
        deny.stdout, deny.stderr,
    );
    assert!(
        deny.stderr.to_lowercase().contains("deny")
            || deny.stderr.contains("content")
            || deny.stderr.contains("no-drop-table"),
        "deny stderr should carry the content-deny reason.\nstderr: {}",
        deny.stderr,
    );
    eprintln!("[content-deny] codex drop: exit 2 (deny) -- correct");

    // ── 5. non-matching SELECT → ALLOWS (exit 0), no false positive ─────────
    let allow = run_with_stdin(
        &bin,
        repo,
        home,
        &["hook-decide", "codex-pre-bash"],
        r#"{"tool_input":{"command":"psql -h prod -c \"select 1\""}}"#,
    );
    assert_eq!(
        allow.code, 0,
        "a read must ALLOW (exit 0).\nstdout: {}\nstderr: {}",
        allow.stdout, allow.stderr,
    );
    eprintln!("[content-deny] codex select: exit 0 (allow) -- no false positive");

    // ── 6. claude-pre-bash → JSON permissionDecision deny ───────────────────
    let claude = run_with_stdin(
        &bin,
        repo,
        home,
        &["hook-decide", "claude-pre-bash"],
        r#"{"tool_input":{"command":"psql -h prod -c \"drop table orders\""}}"#,
    );
    assert_eq!(claude.code, 0, "claude hooks always exit 0");
    let json: serde_json::Value = serde_json::from_str(claude.stdout.trim())
        .unwrap_or_else(|e| panic!("claude-pre-bash stdout not JSON: {e}\n{}", claude.stdout));
    assert_eq!(
        json.pointer("/hookSpecificOutput/permissionDecision")
            .and_then(|v| v.as_str()),
        Some("deny"),
        "claude-pre-bash must deny the drop.\nJSON: {}",
        claude.stdout,
    );
    eprintln!("[content-deny] claude drop: permissionDecision=deny -- correct");

    // ── 7. confirm the daemon recorded the content-deny as a Deny event ─────
    //
    // The live daemon is the oracle: its hash-chained enforcement log surfaces
    // through `stats --json`. The only denies this test can produce come from
    // the content-deny policy, so a non-zero `denials` is attributable to it.
    // (The distinct `policy_content_denied` reason code is unit-tested in
    // `src/mcp/dispatch_v2/session.rs` and `events_output.rs`.)
    let stats = run(&bin, repo, home, &["stats", "--json"]);
    assert_eq!(
        stats.code, 0,
        "mati stats failed:\n{}\n{}",
        stats.stdout, stats.stderr
    );
    let json: serde_json::Value = serde_json::from_str(stats.stdout.trim())
        .unwrap_or_else(|e| panic!("stats --json not JSON: {e}\n{}", stats.stdout));
    let denials = json
        .pointer("/enforcement_30d/denials")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    assert!(
        denials >= 1,
        "the content-deny must be recorded as a Deny enforcement event; stats: {}",
        stats.stdout,
    );
    eprintln!("[content-deny] daemon recorded {denials} deny enforcement event(s) -- correct");
}

/// Live E2E for the path channel of the `deny_if` axis (`--deny-if-path-glob`).
///
/// The command E2E above proves the argv channel. This proves the path channel:
/// an EDIT carries no argv, only `target_path ∪ files`, so a `PathGlob` predicate
/// is the only thing that can gate it. Authors a `path` policy via the new CLI
/// flag, starts a real daemon, and drives `mati hook-decide claude-pre-edit`:
///   1. editing a file under `**/secrets/**` DENIES (permissionDecision=deny);
///   2. editing a file outside it ALLOWS (no false positive);
///   3. the daemon records the deny.
#[test]
#[ignore]
fn hook_decide_path_content_deny_denies_edit() {
    let bin = mati_bin();
    let (repo_dir, home_dir) = setup_repo();
    let repo = repo_dir.path();
    let home = home_dir.path();

    std::env::set_var("MATI_HOME", home);

    // A secret file to edit, under a nested `secrets/` segment so `**/secrets/**`
    // matches whether the hook keys on the relative or canonical-relative path.
    std::fs::create_dir_all(repo.join("config/secrets")).expect("mkdir secrets");
    std::fs::write(repo.join("config/secrets/prod.env"), "TOKEN=abc\n").expect("write secret");

    let r = run(&bin, repo, home, &["init", "--no-hooks"]);
    assert_eq!(r.code, 0, "mati init failed:\n{}\n{}", r.stdout, r.stderr);

    // Author + enable a path content-deny policy via the real CLI.
    let r = run(
        &bin,
        repo,
        home,
        &[
            "policy",
            "add",
            "no-edit-secrets",
            "--name",
            "No editing secrets",
            "--rule",
            "Deny edits to files under secrets/.",
            "--reason",
            "Secret material must not be edited through the agent.",
            "--mode",
            "block",
            "--trigger",
            r#"{"tool":"path"}"#,
            "--deny-if-path-glob",
            "**/secrets/**",
            "--enable",
        ],
    );
    assert_eq!(
        r.code, 0,
        "mati policy add failed:\n{}\n{}",
        r.stdout, r.stderr
    );

    let daemon = Command::new(&bin)
        .args(["daemon", "start"])
        .current_dir(repo)
        .env("HOME", home)
        .env("MATI_HOME", home)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn daemon");
    let _guard = ChildGuard(daemon);
    assert!(
        wait_for_daemon(&bin, repo, home, Duration::from_secs(5)),
        "daemon did not become reachable",
    );

    // 1. editing the secret → claude-pre-edit denies via JSON.
    let deny = run_with_stdin(
        &bin,
        repo,
        home,
        &["hook-decide", "claude-pre-edit"],
        r#"{"tool_input":{"file_path":"config/secrets/prod.env"}}"#,
    );
    assert_eq!(deny.code, 0, "claude hooks always exit 0");
    let json: serde_json::Value = serde_json::from_str(deny.stdout.trim())
        .unwrap_or_else(|e| panic!("claude-pre-edit stdout not JSON: {e}\n{}", deny.stdout));
    assert_eq!(
        json.pointer("/hookSpecificOutput/permissionDecision")
            .and_then(|v| v.as_str()),
        Some("deny"),
        "editing a secret must deny on the path predicate.\nJSON: {}",
        deny.stdout,
    );
    eprintln!("[path-content-deny] edit secret: permissionDecision=deny -- correct");

    // 2. editing a non-secret existing file → no false positive.
    let allow = run_with_stdin(
        &bin,
        repo,
        home,
        &["hook-decide", "claude-pre-edit"],
        r#"{"tool_input":{"file_path":"src/test.rs"}}"#,
    );
    assert_eq!(allow.code, 0, "claude hooks always exit 0");
    // A non-denied edit defers with empty stdout: the ClaudePreEdit adapter never
    // force-allows a permission-required edit. Empty (or any non-deny) stdout is
    // the correct no-false-positive outcome.
    let not_denied = allow.stdout.trim().is_empty()
        || serde_json::from_str::<serde_json::Value>(allow.stdout.trim())
            .ok()
            .and_then(|json| {
                json.pointer("/hookSpecificOutput/permissionDecision")
                    .and_then(|v| v.as_str())
                    .map(str::to_string)
            })
            != Some("deny".to_string());
    assert!(
        not_denied,
        "a non-secret edit must not deny.\nstdout: {}",
        allow.stdout,
    );
    eprintln!("[path-content-deny] edit non-secret: not denied -- no false positive");

    // 3. the daemon recorded the path content-deny.
    let stats = run(&bin, repo, home, &["stats", "--json"]);
    assert_eq!(
        stats.code, 0,
        "mati stats failed:\n{}\n{}",
        stats.stdout, stats.stderr
    );
    let json: serde_json::Value = serde_json::from_str(stats.stdout.trim())
        .unwrap_or_else(|e| panic!("stats --json not JSON: {e}\n{}", stats.stdout));
    let denials = json
        .pointer("/enforcement_30d/denials")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    assert!(
        denials >= 1,
        "the path content-deny must record a Deny event; stats: {}",
        stats.stdout,
    );
    eprintln!("[path-content-deny] daemon recorded {denials} deny event(s) -- correct");
}

/// Live E2E for the `file_read` category through the Read tool.
///
/// The Read tool carries no argv and, before this, never entered policy
/// evaluation at all — reads were governed only by the file gate. This proves
/// the read-path routing: a `file_read` policy with a `deny_if` path predicate
/// gates the Read tool.
///   1. reading a file under `**/secrets/**` DENIES (permissionDecision=deny);
///   2. reading a file outside it ALLOWS (permissionDecision=allow);
///   3. the daemon records the deny.
#[test]
#[ignore]
fn hook_decide_file_read_content_deny_denies_read() {
    let bin = mati_bin();
    let (repo_dir, home_dir) = setup_repo();
    let repo = repo_dir.path();
    let home = home_dir.path();

    std::env::set_var("MATI_HOME", home);

    std::fs::create_dir_all(repo.join("config/secrets")).expect("mkdir secrets");
    std::fs::write(repo.join("config/secrets/prod.env"), "TOKEN=abc\n").expect("write secret");

    let r = run(&bin, repo, home, &["init", "--no-hooks"]);
    assert_eq!(r.code, 0, "mati init failed:\n{}\n{}", r.stdout, r.stderr);

    // Author + enable a file_read content-deny policy via the real CLI.
    let r = run(
        &bin,
        repo,
        home,
        &[
            "policy",
            "add",
            "no-read-secrets",
            "--name",
            "No reading secrets",
            "--rule",
            "Deny reads of files under secrets/.",
            "--reason",
            "Secret material must not be read through the agent.",
            "--mode",
            "block",
            "--trigger",
            r#"{"tool":"file_read"}"#,
            "--deny-if-path-glob",
            "**/secrets/**",
            "--enable",
        ],
    );
    assert_eq!(
        r.code, 0,
        "mati policy add failed:\n{}\n{}",
        r.stdout, r.stderr
    );

    let daemon = Command::new(&bin)
        .args(["daemon", "start"])
        .current_dir(repo)
        .env("HOME", home)
        .env("MATI_HOME", home)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn daemon");
    let _guard = ChildGuard(daemon);
    assert!(
        wait_for_daemon(&bin, repo, home, Duration::from_secs(5)),
        "daemon did not become reachable",
    );

    // 1. reading the secret → claude-pre-read denies via JSON.
    let deny = run_with_stdin(
        &bin,
        repo,
        home,
        &["hook-decide", "claude-pre-read"],
        r#"{"tool_input":{"file_path":"config/secrets/prod.env"}}"#,
    );
    assert_eq!(deny.code, 0, "claude hooks always exit 0");
    let json: serde_json::Value = serde_json::from_str(deny.stdout.trim())
        .unwrap_or_else(|e| panic!("claude-pre-read stdout not JSON: {e}\n{}", deny.stdout));
    assert_eq!(
        json.pointer("/hookSpecificOutput/permissionDecision")
            .and_then(|v| v.as_str()),
        Some("deny"),
        "reading a secret must deny on the file_read path predicate.\nJSON: {}",
        deny.stdout,
    );
    eprintln!("[file-read-content-deny] read secret: permissionDecision=deny -- correct");

    // 2. reading a non-secret existing file → allow (reads always emit JSON).
    let allow = run_with_stdin(
        &bin,
        repo,
        home,
        &["hook-decide", "claude-pre-read"],
        r#"{"tool_input":{"file_path":"src/test.rs"}}"#,
    );
    assert_eq!(allow.code, 0, "claude hooks always exit 0");
    let json: serde_json::Value = serde_json::from_str(allow.stdout.trim())
        .unwrap_or_else(|e| panic!("claude-pre-read stdout not JSON: {e}\n{}", allow.stdout));
    assert_eq!(
        json.pointer("/hookSpecificOutput/permissionDecision")
            .and_then(|v| v.as_str()),
        Some("allow"),
        "a non-secret read must allow.\nJSON: {}",
        allow.stdout,
    );
    eprintln!("[file-read-content-deny] read non-secret: allow -- no false positive");

    // 3. the daemon recorded the read content-deny.
    let stats = run(&bin, repo, home, &["stats", "--json"]);
    assert_eq!(
        stats.code, 0,
        "mati stats failed:\n{}\n{}",
        stats.stdout, stats.stderr
    );
    let json: serde_json::Value = serde_json::from_str(stats.stdout.trim())
        .unwrap_or_else(|e| panic!("stats --json not JSON: {e}\n{}", stats.stdout));
    let denials = json
        .pointer("/enforcement_30d/denials")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    assert!(
        denials >= 1,
        "the file_read content-deny must record a Deny event; stats: {}",
        stats.stdout,
    );
    eprintln!("[file-read-content-deny] daemon recorded {denials} deny event(s) -- correct");
}

/// The internal deadline must end the process, not merely decide.
///
/// `run_inner` reads stdin through Tokio's blocking reader. When
/// `HOOK_DEADLINE_MS` fires mid-read the timeout branch writes its fail-open
/// allow, but the runtime will not shut down while that reader is outstanding.
/// The process therefore used to live until stdin reached EOF — measured at
/// 4028ms against a 2500ms deadline — and a hook runner waiting on exit stalls
/// for all of it. `HookRunOutcome::Terminate` exists to cut that short.
///
/// This holds stdin open and never closes it, so the pre-fix binary does not
/// exit at all and the test fails on the upper bound.
///
/// Not `#[ignore]`d, unlike the rest of this file: it spawns no daemon and
/// needs no git repo, and an ignored test would not have caught the regression
/// it exists to pin.
#[test]
fn hook_deadline_terminates_the_process() {
    // Mirrors `cli::hook_decide::HOOK_DEADLINE_MS`, which is private.
    const DEADLINE_MS: u64 = 2500;
    // Generous enough to absorb a cold binary load (~1s measured) without
    // reaching the EOF-tracking failure mode, which never exits at all.
    const UPPER_BOUND_MS: u64 = 8000;

    let bin = mati_bin();
    let repo_dir = TempDir::new().expect("create repo dir");
    let home_dir = TempDir::new().expect("create home dir");

    let mut child = Command::new(&bin)
        .args(["hook-decide", "claude-pre-read"])
        .current_dir(repo_dir.path())
        .env("HOME", home_dir.path())
        .env("MATI_HOME", home_dir.path())
        .env("NO_COLOR", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn mati hook-decide");

    let mut stdin = child.stdin.take().expect("child stdin");
    stdin
        .write_all(br#"{"tool_name":"Read","tool_input":{"file_path":"src/main.rs"}}"#)
        .expect("write hook payload");
    stdin.flush().expect("flush hook payload");

    let start = std::time::Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll child") {
            break status;
        }
        if start.elapsed() > Duration::from_millis(UPPER_BOUND_MS) {
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "hook-decide did not exit within {UPPER_BOUND_MS}ms with stdin held open. \
                 The internal deadline decided but the process kept running until EOF — \
                 the failure HookRunOutcome::Terminate fixes."
            );
        }
        std::thread::sleep(Duration::from_millis(25));
    };
    let elapsed = start.elapsed();

    // Held until here so the pipe cannot close early and hand the process an
    // EOF, which would let it exit through the normal path and pass vacuously.
    drop(stdin);

    assert!(
        elapsed >= Duration::from_millis(DEADLINE_MS - 500),
        "exited after {elapsed:?}, before the {DEADLINE_MS}ms deadline could fire — \
         the process died early rather than failing open on schedule"
    );
    assert_eq!(
        status.code(),
        Some(0),
        "the deadline must fail open: exit 0 is allow for both hook protocols, \
         and exit 2 would turn a timeout into a deny"
    );

    let mut stdout = String::new();
    if let Some(mut out) = child.stdout.take() {
        use std::io::Read as _;
        out.read_to_string(&mut stdout).expect("read child stdout");
    }
    let json: serde_json::Value =
        serde_json::from_str(stdout.trim()).unwrap_or(serde_json::json!({}));
    assert_eq!(
        json.pointer("/hookSpecificOutput/permissionDecision")
            .and_then(|v| v.as_str()),
        Some("allow"),
        "the deadline must emit its allow before exiting, not just exit.\nstdout: {stdout}"
    );

    eprintln!("[deadline] exited at {elapsed:?} with stdin still open -- correct");
}

/// SessionEnd must terminate after its internal deadline, even when the real
/// binary is blocked in the daemon round trip.
///
/// The listener is deliberately a silent daemon substitute: it accepts the
/// actual v2 request and never writes a response. Removing the production
/// deadline makes this test wait for daemon_v2's 10s transport timeout, so it
/// fails on the 7s upper bound rather than passing through an invented wrapper.
#[cfg(unix)]
#[test]
fn session_harvest_deadline_terminates_the_process() {
    const DEADLINE_MS: u64 = 2500;
    const UPPER_BOUND_MS: u64 = 7000;
    /// The scaffold ceiling from `scaffold::settings`, in ms. The internal
    /// deadline is worthless if the host kills the process first, and the
    /// margin is easy to spend by accident: startup elapses before the
    /// deadline starts counting, so a value chosen by adding startup to the
    /// budget rather than subtracting it from the ceiling overshoots. That
    /// mistake measured 4234ms here on a cold binary.
    const SCAFFOLD_CEILING_MS: u64 = 4000;

    let bin = mati_bin();
    let (repo_dir, home_dir) = setup_repo();
    let repo = repo_dir.path();
    let home_guard = ShortHome::new("sh");
    let mati_home = home_guard.path().to_path_buf();

    let init = run_with_mati_home(
        &bin,
        repo,
        home_dir.path(),
        &mati_home,
        &["init", "--no-hooks"],
    );
    assert_eq!(init.code, 0, "mati init failed: {}", init.stderr);

    let project_root = std::fs::read_dir(&mati_home)
        .expect("read MATI_HOME")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| path.is_dir())
        .expect("init did not create a project store");
    let socket_path = project_root.join("mati.sock");
    let listener =
        std::os::unix::net::UnixListener::bind(&socket_path).expect("bind stalled daemon socket");
    let accepted = Arc::new(AtomicBool::new(false));
    let stop_listener = Arc::new(AtomicBool::new(false));
    let accepted_for_thread = Arc::clone(&accepted);
    let stop_for_thread = Arc::clone(&stop_listener);
    let listener_thread = thread::spawn(move || {
        listener
            .set_nonblocking(true)
            .expect("set listener nonblocking");
        while !stop_for_thread.load(Ordering::Acquire) {
            match listener.accept() {
                Ok((_stream, _)) => {
                    accepted_for_thread.store(true, Ordering::Release);
                    while !stop_for_thread.load(Ordering::Acquire) {
                        thread::sleep(Duration::from_millis(25));
                    }
                    return;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("stalled daemon listener failed: {error}"),
            }
        }
    });

    let start = std::time::Instant::now();
    let mut child = Command::new(&bin)
        .args(["session-harvest"])
        .current_dir(repo)
        .env("HOME", home_dir.path())
        .env("MATI_HOME", &mati_home)
        .env("NO_COLOR", "1")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn mati session-harvest");

    let status = loop {
        if let Some(status) = child.try_wait().expect("poll session-harvest") {
            break status;
        }
        if start.elapsed() > Duration::from_millis(UPPER_BOUND_MS) {
            let _ = child.kill();
            let _ = child.wait();
            stop_listener.store(true, Ordering::Release);
            let _ = listener_thread.join();
            panic!(
                "session-harvest did not exit within {UPPER_BOUND_MS}ms; stderr: {}",
                child
                    .stderr
                    .take()
                    .and_then(|mut stderr| {
                        let mut text = String::new();
                        std::io::Read::read_to_string(&mut stderr, &mut text).ok()?;
                        Some(text)
                    })
                    .unwrap_or_default()
            );
        }
        thread::sleep(Duration::from_millis(25));
    };
    let elapsed = start.elapsed();
    stop_listener.store(true, Ordering::Release);
    listener_thread.join().expect("listener thread");

    assert!(
        accepted.load(Ordering::Acquire),
        "the child never reached the stalled socket"
    );
    assert!(
        elapsed >= Duration::from_millis(DEADLINE_MS - 500),
        "exited after {elapsed:?}, before the internal deadline could fire"
    );
    assert!(
        elapsed < Duration::from_millis(SCAFFOLD_CEILING_MS),
        "took {elapsed:?}, at or past the {SCAFFOLD_CEILING_MS}ms scaffold ceiling — \
         the host would kill the process before the deadline could fail open, \
         so no fail_open.log entry would ever be written"
    );
    assert_eq!(status.code(), Some(0), "timeout must fail open");

    let log = std::fs::read_to_string(mati_home.join("fail_open.log"))
        .expect("SessionEnd timeout did not write fail_open.log");
    assert!(
        log.lines().any(|line| {
            line.contains("hook=session-end")
                && line.contains("file=<session-harvest>")
                && line.contains("session harvest exceeded internal deadline")
        }),
        "missing SessionEnd timeout evidence in fail_open.log: {log}"
    );
    eprintln!("[session-harvest deadline] exited at {elapsed:?} with daemon response withheld");
}

/// Each synchronous lifecycle hook must fail open against a real stalled UDS.
///
/// This drives the production binary and the production command path. Before
/// the deadlines, pre-compact and post-compact waited for the daemon's 10s
/// response timeout; subagent-context took about 4.1s through StoreProxy's
/// retry path before falling back. The per-hook upper bounds therefore fail
/// against the pre-fix binary rather than asserting against a copied wrapper.
#[cfg(unix)]
#[test]
fn blocking_lifecycle_hooks_terminate_and_log_against_stalled_daemon() {
    let cases = [
        (
            "session-flush",
            // Named for the command, not a hook: pre-compact.sh and stop.sh
            // both run `mati session-flush`, so a hook-shaped label would
            // record every Stop-hook stall as PreCompact.
            "session-flush",
            "<session-flush>",
            "session flush exceeded internal deadline",
            5000_u64,
            7000_u64,
        ),
        (
            "session-clear-consults",
            "post-compact",
            "<session-clear-consults>",
            "post-compact receipt cleanup exceeded internal deadline",
            3000_u64,
            4500_u64,
        ),
        (
            "subagent-context",
            "subagent-start",
            "<subagent-context>",
            "subagent context exceeded internal deadline",
            3000_u64,
            4500_u64,
        ),
    ];

    for (command, hook, rel_path, reason, deadline_ms, upper_bound_ms) in cases {
        let bin = mati_bin();
        let (repo_dir, home_dir) = setup_repo();
        let repo = repo_dir.path();
        let home_guard = ShortHome::new("bl");
        let mati_home = home_guard.path().to_path_buf();

        let init = run_with_mati_home(
            &bin,
            repo,
            home_dir.path(),
            &mati_home,
            &["init", "--no-hooks"],
        );
        assert_eq!(init.code, 0, "mati init failed: {}", init.stderr);

        let project_root = std::fs::read_dir(&mati_home)
            .expect("read MATI_HOME")
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .find(|path| path.is_dir())
            .expect("init did not create a project store");
        let socket_path = project_root.join("mati.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket_path)
            .expect("bind stalled daemon socket");
        let accepted = Arc::new(AtomicBool::new(false));
        let stop_listener = Arc::new(AtomicBool::new(false));
        let accepted_for_thread = Arc::clone(&accepted);
        let stop_for_thread = Arc::clone(&stop_listener);
        let listener_thread = thread::spawn(move || {
            listener
                .set_nonblocking(true)
                .expect("set listener nonblocking");
            while !stop_for_thread.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((_stream, _)) => {
                        accepted_for_thread.store(true, Ordering::Release);
                        while !stop_for_thread.load(Ordering::Acquire) {
                            thread::sleep(Duration::from_millis(25));
                        }
                        return;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => panic!("stalled daemon listener failed: {error}"),
                }
            }
        });

        let start = std::time::Instant::now();
        let mut child = Command::new(&bin)
            .args([command])
            .current_dir(repo)
            .env("HOME", home_dir.path())
            .env("MATI_HOME", &mati_home)
            .env("MATI_DISABLE_AUTO_SPAWN", "1")
            .env("NO_COLOR", "1")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("failed to spawn lifecycle hook");

        let status = loop {
            if let Some(status) = child.try_wait().expect("poll lifecycle hook") {
                break status;
            }
            if start.elapsed() > Duration::from_millis(upper_bound_ms) {
                let _ = child.kill();
                let output = child
                    .wait_with_output()
                    .expect("wait for timed-out lifecycle hook");
                stop_listener.store(true, Ordering::Release);
                let _ = listener_thread.join();
                panic!(
                    "{command} did not exit within {upper_bound_ms}ms; stderr: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            thread::sleep(Duration::from_millis(25));
        };
        let elapsed = start.elapsed();
        child
            .wait_with_output()
            .expect("collect lifecycle hook output");
        stop_listener.store(true, Ordering::Release);
        listener_thread.join().expect("listener thread");

        assert!(
            accepted.load(Ordering::Acquire),
            "{command} never reached the stalled socket"
        );
        assert!(
            elapsed >= Duration::from_millis(deadline_ms - 500),
            "{command} exited after {elapsed:?}, before its internal deadline could fire"
        );
        assert!(
            elapsed < Duration::from_millis(upper_bound_ms),
            "{command} exceeded its fail-open bound: {elapsed:?}"
        );
        assert_eq!(status.code(), Some(0), "{command} timeout must fail open");

        let log =
            std::fs::read_to_string(mati_home.join("fail_open.log")).unwrap_or_else(|error| {
                panic!("{command} timeout did not write fail_open.log: {error}")
            });
        assert!(
            log.lines().any(|line| {
                line.contains(&format!("hook={hook}"))
                    && line.contains(&format!("file={rel_path}"))
                    && line.contains(reason)
            }),
            "missing {hook} timeout evidence in fail_open.log: {log}"
        );
        eprintln!("[{hook} deadline] exited at {elapsed:?} with daemon response withheld");
    }
}

/// Live E2E for the `require` (allowlist) axis — the polarity mirror of
/// `deny_if`. A `require: PathGlob("src/**")` policy denies an edit UNLESS its
/// path is under `src/`. Inverse of the path content-deny test:
///   1. editing a file OUTSIDE `src/**` DENIES (requirement missed);
///   2. editing a file under `src/**` ALLOWS (requirement met, no false positive);
///   3. the daemon records the deny.
#[test]
#[ignore]
fn hook_decide_require_allowlist_denies_edit_outside_src() {
    let bin = mati_bin();
    let (repo_dir, home_dir) = setup_repo();
    let repo = repo_dir.path();
    let home = home_dir.path();

    std::env::set_var("MATI_HOME", home);

    std::fs::create_dir_all(repo.join("scripts")).expect("mkdir scripts");
    std::fs::write(repo.join("scripts/seo.js"), "// generated\n").expect("write script");
    std::fs::create_dir_all(repo.join("src")).expect("mkdir src");
    std::fs::write(repo.join("src/app.rs"), "fn main() {}\n").expect("write src");

    let r = run(&bin, repo, home, &["init", "--no-hooks"]);
    assert_eq!(r.code, 0, "mati init failed:\n{}\n{}", r.stdout, r.stderr);

    // Author + enable an allowlist policy: edits must stay under src/.
    let r = run(
        &bin,
        repo,
        home,
        &[
            "policy",
            "add",
            "edits-under-src-only",
            "--name",
            "Edits under src only",
            "--rule",
            "Only edit files under src/.",
            "--reason",
            "Generated and config files must not be edited through the agent.",
            "--mode",
            "block",
            "--trigger",
            r#"{"tool":"path"}"#,
            "--require-path-glob",
            "src/**",
            "--enable",
        ],
    );
    assert_eq!(
        r.code, 0,
        "mati policy add failed:\n{}\n{}",
        r.stdout, r.stderr
    );

    let daemon = Command::new(&bin)
        .args(["daemon", "start"])
        .current_dir(repo)
        .env("HOME", home)
        .env("MATI_HOME", home)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn daemon");
    let _guard = ChildGuard(daemon);
    assert!(
        wait_for_daemon(&bin, repo, home, Duration::from_secs(5)),
        "daemon did not become reachable",
    );

    // 1. editing outside src/ → requirement missed → deny.
    let deny = run_with_stdin(
        &bin,
        repo,
        home,
        &["hook-decide", "claude-pre-edit"],
        r#"{"tool_input":{"file_path":"scripts/seo.js"}}"#,
    );
    assert_eq!(deny.code, 0, "claude hooks always exit 0");
    let json: serde_json::Value = serde_json::from_str(deny.stdout.trim())
        .unwrap_or_else(|e| panic!("claude-pre-edit stdout not JSON: {e}\n{}", deny.stdout));
    assert_eq!(
        json.pointer("/hookSpecificOutput/permissionDecision")
            .and_then(|v| v.as_str()),
        Some("deny"),
        "editing outside src/ must deny on the require predicate.\nJSON: {}",
        deny.stdout,
    );
    eprintln!("[require-allowlist] edit outside src: permissionDecision=deny -- correct");

    // 2. editing under src/ → requirement met → not denied.
    let allow = run_with_stdin(
        &bin,
        repo,
        home,
        &["hook-decide", "claude-pre-edit"],
        r#"{"tool_input":{"file_path":"src/app.rs"}}"#,
    );
    assert_eq!(allow.code, 0, "claude hooks always exit 0");
    let not_denied = allow.stdout.trim().is_empty()
        || serde_json::from_str::<serde_json::Value>(allow.stdout.trim())
            .ok()
            .and_then(|json| {
                json.pointer("/hookSpecificOutput/permissionDecision")
                    .and_then(|v| v.as_str())
                    .map(str::to_string)
            })
            != Some("deny".to_string());
    assert!(
        not_denied,
        "an edit under src/ must satisfy the requirement and not deny.\nstdout: {}",
        allow.stdout,
    );
    eprintln!("[require-allowlist] edit under src: not denied -- requirement met");

    // 3. the daemon recorded the requirement deny.
    let stats = run(&bin, repo, home, &["stats", "--json"]);
    assert_eq!(
        stats.code, 0,
        "mati stats failed:\n{}\n{}",
        stats.stdout, stats.stderr
    );
    let json: serde_json::Value = serde_json::from_str(stats.stdout.trim())
        .unwrap_or_else(|e| panic!("stats --json not JSON: {e}\n{}", stats.stdout));
    let denials = json
        .pointer("/enforcement_30d/denials")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    assert!(
        denials >= 1,
        "the require deny must record a Deny event; stats: {}",
        stats.stdout,
    );
    eprintln!("[require-allowlist] daemon recorded {denials} deny event(s) -- correct");
}
