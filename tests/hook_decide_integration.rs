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
//! This test is `#[ignore]`d by default -- it spawns daemon processes, writes to
//! disk, and is slower than unit tests. Run it explicitly:
//!
//! ```sh
//! cargo test --test hook_decide_integration -- --ignored --nocapture
//! ```

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
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

/// Run mati with the given args, isolating HOME to `home` and CWD to `repo`.
fn run(bin: &Path, repo: &Path, home: &Path, args: &[&str]) -> RunResult {
    let out = Command::new(bin)
        .args(args)
        .current_dir(repo)
        .env("HOME", home)
        .env("NO_COLOR", "1")
        .output()
        .expect("failed to run mati");
    RunResult {
        stdout: String::from_utf8_lossy(&out.stdout).to_string(),
        stderr: String::from_utf8_lossy(&out.stderr).to_string(),
        code: out.status.code().unwrap_or(-1),
    }
}

/// Run mati with piped stdin, isolating HOME and CWD.
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
