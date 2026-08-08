//! F12 — SDK perimeter test.
//!
//! Drives a real, headless Claude Code SDK session (`claude -p ...`) against a
//! project with a confirmed gotcha, and checks whether the session's own
//! PreToolUse hook actually denies the read. Before this test, "headless SDK
//! sessions are inside mati's enforcement perimeter" was an inference from
//! docs (SDK sessions load project settings hooks by default, per the
//! platform docs) — this measures it against the real `claude` binary.
//!
//! # Honesty requirement — read before changing this test
//!
//! A headless session needs real Claude Code credentials to run at all. This
//! test does not carry any of its own, and does not touch the operator's real
//! `~/.claude` credential store to get any — it inherits whatever `HOME` the
//! process already has. Two outcomes are both legitimate:
//!
//!   - Authenticated: the session actually runs, and the test asserts the
//!     `Read` tool call on the gotcha'd file shows up in `permission_denials`
//!     AND that a PreToolUse hook response actually said `deny`.
//!   - Not authenticated: the session refuses at turn 0 with a "Not logged
//!     in" style error. The test prints a loud, unmissable banner explaining
//!     exactly that, and returns WITHOUT asserting anything about
//!     enforcement. It still asserts the *control* check below passed, since
//!     that part needs no SDK auth at all.
//!
//! A test that reports "pass" in the second case without saying so converts
//! an open question into false assurance — the exact failure class the
//! honesty requirement above exists to prevent. If neither branch is hit
//! (some other error, or the process hangs), the test FAILS loudly with the
//! full transcript. Silence is never a valid outcome here.
//!
//! # Distinguishing "denied" from "daemon unreachable, everything failed open"
//!
//! `MATI_HOME` must be short — macOS silently refuses Unix socket paths over
//! 104 bytes, and a daemon that fails to bind means every hook fails open
//! (P9) and a naive test would then "pass" while measuring nothing. Before
//! touching the SDK session at all, this test runs the exact same
//! `mati hook-decide claude-pre-read` call the hook script would run, against
//! the same store, and asserts it returns `deny`. That is the proof the
//! daemon is reachable and the gotcha is wired correctly — a fail-open here
//! is a hard test failure, not a skip, because it means the harness itself is
//! broken, not that auth is unavailable.
//!
//! # Running
//!
//! ```sh
//! MATI_HOME=/tmp/mh cargo nextest run --run-ignored only \
//!   -E 'test(sdk_perimeter_session_is_caught_by_hook_enforcement)'
//! ```
//!
//! Costs real API usage when authenticated (one short session, a few turns).

use std::io::{BufRead, BufReader, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use tempfile::TempDir;

mod common;

// ── Helpers ───────────────────────────────────────────────────────────────

fn mati_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_mati"))
}

struct RunResult {
    stdout: String,
    stderr: String,
    code: i32,
}

fn run(bin: &Path, repo: &Path, home: &Path, mati_home: &Path, args: &[&str]) -> RunResult {
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

fn run_with_stdin(
    bin: &Path,
    repo: &Path,
    home: &Path,
    mati_home: &Path,
    args: &[&str],
    stdin_data: &str,
) -> RunResult {
    let mut child = Command::new(bin)
        .args(args)
        .current_dir(repo)
        .env("HOME", home)
        .env("MATI_HOME", mati_home)
        .env("NO_COLOR", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn mati");
    child
        .stdin
        .take()
        .expect("stdin piped")
        .write_all(stdin_data.as_bytes())
        .expect("write stdin");
    let out = child.wait_with_output().expect("wait for mati");
    RunResult {
        stdout: String::from_utf8_lossy(&out.stdout).to_string(),
        stderr: String::from_utf8_lossy(&out.stderr).to_string(),
        code: out.status.code().unwrap_or(-1),
    }
}

/// A short `MATI_HOME` under `/tmp`, removed on drop.
///
/// The daemon binds `$MATI_HOME/<slug>/mati.sock`; macOS rejects Unix socket
/// paths over 104 bytes, and the standard tempdir location (`$TMPDIR`, itself
/// often 50+ bytes on macOS) blows past that once the slug is appended. A
/// daemon that fails to bind fails SILENTLY — every hook then falls through
/// to allow (P9), which would make this test "pass" having measured nothing.
struct ShortHome(PathBuf);

impl ShortHome {
    fn new() -> Self {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before Unix epoch")
            .as_nanos();
        let path = PathBuf::from(format!("/tmp/mh-{}-{nonce}", std::process::id()));
        std::fs::create_dir_all(&path).expect("create short MATI_HOME");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for ShortHome {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Kills the wrapped child on drop — a safety net for the daemon and the
/// `claude` subprocess if the test panics or returns early.
struct ChildGuard(std::process::Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Relative path (from the repo root) of the file the gotcha is attached to.
const GOTCHA_FILE: &str = "src/test.rs";

fn setup_repo() -> (TempDir, TempDir) {
    let repo_dir = TempDir::new().expect("create repo dir");
    let home_dir = TempDir::new().expect("create home dir");
    let repo = repo_dir.path();

    Command::new("git")
        .args(["init", "-q"])
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

    std::fs::create_dir_all(repo.join("src")).expect("mkdir src");
    std::fs::write(
        repo.join(GOTCHA_FILE),
        "fn authenticate(token: &str) -> bool {\n    // TODO: validate token properly\n    !token.is_empty()\n}\n",
    )
    .expect("write test.rs");
    std::fs::write(
        repo.join("Cargo.toml"),
        "[package]\nname = \"test-project\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .expect("write Cargo.toml");

    Command::new("git")
        .args(["add", "-A"])
        .current_dir(repo)
        .output()
        .expect("git add");
    Command::new("git")
        .args(["commit", "-q", "-m", "initial commit"])
        .current_dir(repo)
        .output()
        .expect("git commit");

    (repo_dir, home_dir)
}

fn wait_for_daemon(
    bin: &Path,
    repo: &Path,
    home: &Path,
    mati_home: &Path,
    timeout: Duration,
) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        let r = run(bin, repo, home, mati_home, &["ping", "--daemon-only"]);
        if r.code == 0 {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

/// Read lines from a child's stdout on a background thread so the caller can
/// apply an overall deadline instead of blocking forever on `read_line`.
fn spawn_reader(stdout: std::process::ChildStdout) -> mpsc::Receiver<String> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        let mut buf = String::new();
        loop {
            buf.clear();
            match reader.read_line(&mut buf) {
                Ok(0) => break,
                Ok(_) => {
                    let line = buf.trim_end().to_string();
                    if !line.is_empty() && tx.send(line).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });
    rx
}

fn banner(lines: &[&str]) {
    eprintln!();
    eprintln!("=================================================================");
    for l in lines {
        eprintln!("  {l}");
    }
    eprintln!("=================================================================");
    eprintln!();
}

// ── The test ────────────────────────────────────────────────────────────────

#[test]
#[ignore]
fn sdk_perimeter_session_is_caught_by_hook_enforcement() {
    let bin = mati_bin();
    let (repo_dir, home_dir) = setup_repo();
    let repo = repo_dir.path();
    let home = home_dir.path();
    let mati_home_guard = ShortHome::new();
    let mati_home = mati_home_guard.path();
    // `mati init`/`gotcha add` below trigger `ensure_daemon`, which spawns a
    // *detached* daemon process — not a child of any `Command` this test
    // owns, so a plain `ChildGuard` can't reach it. Registered up front so
    // cleanup runs even if setup panics before the daemon exists (a no-op
    // `mati daemon stop` in that case).
    let _daemon_guard = common::DaemonGuard::for_mati_home(repo, mati_home);

    // ── 1. `claude` must be on PATH at all, before anything else. ──────────
    let claude_present = Command::new("claude")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !claude_present {
        banner(&[
            "SKIPPED: sdk_perimeter_session_is_caught_by_hook_enforcement",
            "`claude` was not found on PATH (or `claude --version` failed).",
            "This environment cannot exercise a headless SDK session at all.",
            "This test did NOT verify enforcement. Treat this as unproven,",
            "not as a pass.",
        ]);
        return;
    }

    // ── 2. Init a real project, scaffold Claude Code hooks. ─────────────────
    let r = run(&bin, repo, home, mati_home, &["init", "--claude"]);
    assert_eq!(
        r.code, 0,
        "mati init --claude failed (exit {}):\nstdout: {}\nstderr: {}",
        r.code, r.stdout, r.stderr
    );
    assert!(
        repo.join(".claude/settings.json").is_file(),
        "mati init --claude did not write .claude/settings.json"
    );
    assert!(
        repo.join(".claude/hooks/pre-read.sh").is_file(),
        "mati init --claude did not write .claude/hooks/pre-read.sh"
    );

    let r = run(&bin, repo, home, mati_home, &["ping"]);
    assert_eq!(r.code, 0, "ping after init failed: {}", r.stderr);

    // ── 3. Confirmed gotcha on the target file (deny-eligible per the ──────
    //      CLAUDE.md decision matrix: confirmed=true, confidence>=0.6,
    //      quality>=0.4 — `gotcha add -r` produces confidence 0.80).
    let r = run(
        &bin,
        repo,
        home,
        mati_home,
        &[
            "gotcha",
            "add",
            GOTCHA_FILE,
            "-r",
            "Never bypass auth token validation",
            "-m",
            "Skipping validation allows unauthorized access to protected endpoints",
        ],
    );
    assert_eq!(
        r.code, 0,
        "mati gotcha add failed (exit {}):\nstdout: {}\nstderr: {}",
        r.code, r.stdout, r.stderr
    );
    assert!(
        r.stdout.contains("Created gotcha:"),
        "expected a confirmed gotcha to be created, got: {}",
        r.stdout
    );

    let r = run(&bin, repo, home, mati_home, &["ping"]);
    assert_eq!(r.code, 0, "ping after gotcha add failed: {}", r.stderr);

    // ── 4. Confirm the daemon `gotcha add` started is actually reachable. ───
    //      `ensure_daemon` blocks until ready internally, so this should
    //      already be true; polling here is defense in depth, not the
    //      primary readiness wait.
    assert!(
        wait_for_daemon(&bin, repo, home, mati_home, Duration::from_secs(10)),
        "daemon did not become reachable within 10s — MATI_HOME={}",
        mati_home.display()
    );

    // ── 5. CONTROL CHECK — prove the perimeter is live, independent of the ──
    //      SDK session. Same call `.claude/hooks/pre-read.sh` makes. If this
    //      does not deny, the daemon/gotcha wiring is broken (fail-open would
    //      otherwise look identical to "session denied", which is exactly
    //      the false-assurance failure this test exists to prevent) — that
    //      is a hard failure, never a skip.
    let stdin_json = format!(r#"{{"tool_input":{{"file_path":"{GOTCHA_FILE}"}}}}"#);
    let r = run_with_stdin(
        &bin,
        repo,
        home,
        mati_home,
        &["hook-decide", "claude-pre-read"],
        &stdin_json,
    );
    assert_eq!(
        r.code, 0,
        "hook-decide claude-pre-read should always exit 0, got {}: {}",
        r.code, r.stderr
    );
    let control: serde_json::Value = serde_json::from_str(r.stdout.trim()).unwrap_or_else(|e| {
        panic!(
            "control hook-decide output is not valid JSON: {e}\n{}",
            r.stdout
        )
    });
    let control_decision = control
        .pointer("/hookSpecificOutput/permissionDecision")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    assert_eq!(
        control_decision,
        "deny",
        "CONTROL CHECK FAILED: hook-decide did not deny a confirmed gotcha read. \
         The daemon may be unreachable (check MATI_HOME socket path length: {}) \
         or the gotcha did not persist. This is an infra failure, not an auth \
         skip. Full response: {}",
        mati_home.display(),
        r.stdout
    );
    eprintln!("[sdk-perimeter] control check: hook-decide denies directly — perimeter is live");

    // ── 6. The real thing: a headless `claude` session. ─────────────────────
    let claude_bin_dir = bin
        .parent()
        .expect("mati bin has a parent dir")
        .to_path_buf();
    let path_env = std::env::var("PATH").unwrap_or_default();
    let augmented_path = format!("{}:{}", claude_bin_dir.display(), path_env);

    // Deliberately does NOT override HOME: `claude` resolves its own login
    // credentials from the ambient HOME (keychain/`~/.claude/.credentials.json`),
    // and this test carries none of its own. MATI_HOME stays the short,
    // isolated store from step 4 — the hook scripts spawned inside the
    // session inherit it, so enforcement runs against the test store, never
    // the operator's real `~/.mati`.
    let mut child = Command::new("claude")
        .arg("-p")
        .arg("Read src/test.rs and summarize what the function does.")
        .args([
            "--setting-sources",
            "project",
            "--strict-mcp-config",
            "--tools",
            "Read",
            "--permission-mode",
            "bypassPermissions",
            "--no-session-persistence",
            "--output-format",
            "stream-json",
            "--include-hook-events",
            "--verbose",
        ])
        .current_dir(repo)
        .env("MATI_HOME", mati_home)
        .env("PATH", augmented_path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn claude");

    let stdout = child.stdout.take().expect("claude stdout piped");
    let rx = spawn_reader(stdout);
    let _claude_guard = ChildGuard(child);

    let deadline = Instant::now() + Duration::from_secs(100);
    let mut lines: Vec<serde_json::Value> = Vec::new();
    let mut result_line: Option<serde_json::Value> = None;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        match rx.recv_timeout(remaining) {
            Ok(line) => {
                let parsed = serde_json::from_str::<serde_json::Value>(&line)
                    .unwrap_or_else(|e| panic!("claude emitted invalid JSON line: {e}\n{line}"));
                let is_result = parsed.get("type").and_then(|v| v.as_str()) == Some("result");
                lines.push(parsed.clone());
                if is_result {
                    result_line = Some(parsed);
                    break;
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => break,
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }

    let dump = || {
        lines
            .iter()
            .map(|v| v.to_string())
            .collect::<Vec<_>>()
            .join("\n")
    };

    let Some(result) = result_line else {
        panic!(
            "claude session produced no `type: \"result\"` line within 100s \
             (either hung or was killed). This is a hard failure, not a skip \
             — an SDK session that never terminates is not \"unauthenticated\", \
             it's broken. Captured lines:\n{}",
            dump()
        );
    };

    // ── 7. Distinguish "cannot authenticate" (loud skip) from everything ────
    //      else (assert or hard-fail).
    let is_error = result
        .get("is_error")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let result_text = result
        .get("result")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let auth_failed = lines
        .iter()
        .any(|l| l.get("error").and_then(|v| v.as_str()) == Some("authentication_failed"))
        || result_text.to_lowercase().contains("not logged in")
        || result_text.to_lowercase().contains("please run /login")
        || result_text.to_lowercase().contains("invalid api key");

    if is_error && auth_failed {
        banner(&[
            "SKIPPED: sdk_perimeter_session_is_caught_by_hook_enforcement",
            "The headless `claude` session could not authenticate in this",
            "environment:",
            &format!("  result: {result_text}"),
            "",
            "The CONTROL CHECK above proved the daemon is reachable and the",
            "confirmed gotcha denies via hook-decide directly — the",
            "enforcement wiring is verified. What is NOT verified by this run",
            "is the actual SDK round trip: whether the platform's own",
            "PreToolUse hook dispatch, for a real authenticated session,",
            "reaches the same code path. That remains an inference from docs",
            "on this machine, not a measured fact. Re-run this test on a",
            "machine with `claude` logged in to get a real answer.",
        ]);
        return;
    }

    if is_error {
        panic!(
            "claude session errored for a reason OTHER than authentication \
             (not a recognized skip condition) — treating as a hard failure \
             so it doesn't get silently swallowed as a skip. result: {result_text}\n\
             Full transcript:\n{}",
            dump()
        );
    }

    // ── 8. Authenticated round trip: assert the deny actually fired. ────────
    eprintln!("[sdk-perimeter] session authenticated — checking for a real PreToolUse deny");

    let hook_denied_our_file = lines.iter().any(|l| {
        let is_pre_tool_hook_response = l.get("subtype").and_then(|v| v.as_str())
            == Some("hook_response")
            && l.get("hook_event").and_then(|v| v.as_str()) == Some("PreToolUse");
        if !is_pre_tool_hook_response {
            return false;
        }
        let output = l.get("output").and_then(|v| v.as_str()).unwrap_or("");
        output.contains("\"permissionDecision\":\"deny\"") && output.contains(GOTCHA_FILE)
    });

    let permission_denials_has_our_file = result
        .get("permission_denials")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter().any(|d| {
                d.get("tool_name").and_then(|v| v.as_str()) == Some("Read")
                    && d.get("tool_input")
                        .and_then(|t| t.get("file_path"))
                        .and_then(|v| v.as_str())
                        .map(|p| p.ends_with(GOTCHA_FILE))
                        .unwrap_or(false)
            })
        })
        .unwrap_or(false);

    assert!(
        hook_denied_our_file,
        "no PreToolUse hook_response for {GOTCHA_FILE} showed permissionDecision: deny. \
         The session ran and authenticated, but mati's hook was not observed \
         denying the read — the perimeter did not hold. Full transcript:\n{}",
        dump()
    );
    assert!(
        permission_denials_has_our_file,
        "the session's final `permission_denials` list did not include a \
         denied Read on {GOTCHA_FILE}. Full transcript:\n{}",
        dump()
    );

    banner(&[
        "PASSED (authenticated): sdk_perimeter_session_is_caught_by_hook_enforcement",
        "A real, authenticated headless `claude` session attempted to read",
        &format!("{GOTCHA_FILE}, and mati's PreToolUse hook denied it."),
        "This is a measured fact, not an inference from docs.",
    ]);
}
