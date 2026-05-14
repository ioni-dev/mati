//! End-to-end test for the `mati daemon start` lifecycle path.
//!
//! Validates that `cli::daemon::run_daemon_start`:
//!   1. Writes a `serve_start` lifecycle event on startup.
//!   2. Comes up cleanly (mati.sock + mati.pid present).
//!   3. Exits cleanly on SIGTERM and writes a `serve_shutdown` event.
//!
//! This is the path driven by `mati supervisor install`, which had no
//! end-to-end test before — and which previously had a hang bug where a
//! handler panic would cause `tokio::join!` to wait forever for an OS
//! signal that never arrived. The signaler now also wakes via
//! `shutdown.wait()`, so the daemon exits cleanly even when the accept
//! loop self-exits.
//!
//! Marked `#[ignore]` because subprocess tests are slow and depend on a
//! writable `~/`. Run with:
//!
//!     cargo test --test daemon_lifecycle -- --ignored

use std::path::Path;
use std::process::Stdio;
use std::time::{Duration, Instant};

use tempfile::TempDir;
use tokio::process::Command;

use mati_core::store::derive_slug;

const READY_TIMEOUT: Duration = Duration::from_secs(20);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(15);
const POLL: Duration = Duration::from_millis(100);

#[tokio::test]
#[ignore]
async fn daemon_start_writes_lifecycle_events_and_exits_cleanly_on_sigterm() {
    let project_temp = TempDir::new().expect("project tempdir");
    let project = std::fs::canonicalize(project_temp.path()).expect("canonicalize project");

    // ── 1. Spawn mati daemon start. ───────────────────────────────────────
    let bin = env!("CARGO_BIN_EXE_mati");
    let stderr_path = project.join("daemon.stderr");
    let stderr_file = std::fs::File::create(&stderr_path).unwrap();
    let mut child = Command::new(bin)
        .arg("daemon")
        .arg("start")
        .current_dir(&project)
        .env("RUST_LOG", "info")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(stderr_file))
        .kill_on_drop(true) // safety net if the test panics before explicit kill
        .spawn()
        .expect("failed to spawn `mati daemon start`");
    let pid = child.id().expect("child pid available pre-wait");

    // ── 2. Wait for daemon-ready. ─────────────────────────────────────────
    let slug = derive_slug(&project);
    let mati_root = dirs::home_dir().unwrap().join(".mati").join(&slug);
    let lifecycle_log = mati_root.join("lifecycle.log");
    let sock = mati_root.join("mati.sock");

    if wait_for_path(&sock, READY_TIMEOUT).is_err() {
        let _ = child.kill().await;
        let stderr = std::fs::read_to_string(&stderr_path).unwrap_or_default();
        panic!("mati.sock never appeared.\nstderr:\n{stderr}");
    }

    let start_seen = wait_for_log_event(&lifecycle_log, "serve_start", READY_TIMEOUT);
    assert!(
        start_seen,
        "lifecycle.log should contain serve_start; contents:\n{:?}",
        std::fs::read_to_string(&lifecycle_log).ok()
    );

    // ── 3. Send SIGTERM and await clean exit via tokio's async wait. ──────
    // Using `child.wait()` (not raw libc::kill(0)) ensures we observe the
    // *actual* process exit rather than the zombie state, AND it reaps so
    // the OS doesn't leak a zombie. `tokio::time::timeout` bounds the wait.
    unsafe {
        // SAFETY: SIGTERM to our own child is well-defined; this is the
        // daemon's documented graceful-shutdown signal.
        libc::kill(pid as libc::pid_t, libc::SIGTERM);
    }
    let exit = tokio::time::timeout(SHUTDOWN_TIMEOUT, child.wait()).await;
    match exit {
        Ok(Ok(status)) => {
            // Daemon should exit successfully on SIGTERM (graceful path).
            // Some platforms report 0, some 143 (128+15). Either is fine.
            let _ = status;
        }
        Ok(Err(e)) => {
            let _ = child.kill().await;
            panic!("child wait error: {e}");
        }
        Err(_) => {
            let _ = child.kill().await;
            let stderr = std::fs::read_to_string(&stderr_path).unwrap_or_default();
            panic!(
                "daemon did not exit within {SHUTDOWN_TIMEOUT:?} after SIGTERM\n\
                 stderr:\n{stderr}"
            );
        }
    }

    // ── 4. lifecycle.log must contain serve_shutdown. ─────────────────────
    let shutdown_seen =
        wait_for_log_event(&lifecycle_log, "serve_shutdown", Duration::from_secs(2));
    assert!(
        shutdown_seen,
        "lifecycle.log should contain serve_shutdown after SIGTERM; contents:\n{:?}",
        std::fs::read_to_string(&lifecycle_log).ok()
    );

    // The reason should specifically be signal_sigterm.
    let log_contents = std::fs::read_to_string(&lifecycle_log).unwrap();
    assert!(
        log_contents.contains("\tserve_shutdown\tsignal_sigterm"),
        "expected serve_shutdown reason 'signal_sigterm'; got:\n{log_contents}"
    );

    // Cleanup state on disk: sock + pid removed by the cleanup path.
    assert!(!sock.exists(), "mati.sock should be removed on shutdown");
    assert!(
        !mati_root.join("mati.pid").exists(),
        "mati.pid should be removed on shutdown"
    );
}

/// Test that `mati serve` (MCP stdio server) exits cleanly on SIGTERM after
/// the MCP client disconnects (idle-wait phase).
///
/// This is the path exercised by Fix 2: `spawn_signal_listener` owns the sole
/// SIGTERM subscription. When SIGTERM arrives it calls `shutdown.signal()`,
/// which resolves the `signal_shutdown.wait()` arm of the outer `select!` in
/// `serve()`. `wait_for_idle_or_signal` has no signal handler of its own —
/// the duplicate was removed. This test verifies the fix is complete: SIGTERM
/// during idle-wait reaches cleanup and the process exits cleanly.
///
/// Ready probe: we wait for `mati.sock` to appear. The socket is bound in a
/// task spawned before `spawn_signal_listener`; by the time the socket file
/// exists the signal registration (which has no I/O) has already completed.
#[tokio::test]
#[ignore]
async fn serve_exits_cleanly_on_sigterm_after_client_disconnect() {
    let project_temp = TempDir::new().expect("project tempdir");
    let project = std::fs::canonicalize(project_temp.path()).expect("canonicalize project");

    let bin = env!("CARGO_BIN_EXE_mati");
    let stderr_path = project.join("serve.stderr");
    let stderr_file = std::fs::File::create(&stderr_path).unwrap();

    // ── 1. Spawn mati serve with piped stdin. ────────────────────────────────
    // Dropping the write end simulates MCP client disconnect: rmcp transport
    // sees EOF → service.waiting() returns → serve() enters idle-wait select.
    let mut child = Command::new(bin)
        .arg("serve")
        .current_dir(&project)
        .env("RUST_LOG", "info")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::from(stderr_file))
        .kill_on_drop(true)
        .spawn()
        .expect("failed to spawn `mati serve`");
    let pid = child.id().expect("child pid available pre-wait");

    // Drop stdin write end → EOF → client disconnect → enters idle-wait.
    drop(child.stdin.take());

    // ── 2. Wait for mati.sock — confirms idle-wait + signal handler ready. ──
    let slug = derive_slug(&project);
    let mati_root = dirs::home_dir().unwrap().join(".mati").join(&slug);
    let lifecycle_log = mati_root.join("lifecycle.log");
    let sock = mati_root.join("mati.sock");

    if wait_for_path(&sock, READY_TIMEOUT).is_err() {
        let _ = child.kill().await;
        let stderr = std::fs::read_to_string(&stderr_path).unwrap_or_default();
        panic!("mati.sock never appeared after stdin close.\nstderr:\n{stderr}");
    }

    let start_seen = wait_for_log_event(&lifecycle_log, "serve_start", Duration::from_secs(5));
    assert!(
        start_seen,
        "lifecycle.log should contain serve_start; contents:\n{:?}",
        std::fs::read_to_string(&lifecycle_log).ok()
    );

    // ── 3. Send SIGTERM and await clean exit. ────────────────────────────────
    // The signal goes to spawn_signal_listener's task → shutdown.signal() →
    // signal_shutdown.wait() in the inner select! resolves → cleanup runs.
    unsafe {
        libc::kill(pid as libc::pid_t, libc::SIGTERM);
    }
    let exit = tokio::time::timeout(SHUTDOWN_TIMEOUT, child.wait()).await;
    match exit {
        Ok(Ok(_status)) => { /* 0 or 143 (128+SIGTERM) are both acceptable */ }
        Ok(Err(e)) => {
            let _ = child.kill().await;
            panic!("child wait error: {e}");
        }
        Err(_) => {
            let _ = child.kill().await;
            let stderr = std::fs::read_to_string(&stderr_path).unwrap_or_default();
            panic!(
                "mati serve did not exit within {SHUTDOWN_TIMEOUT:?} after SIGTERM\n\
                 stderr:\n{stderr}"
            );
        }
    }

    // ── 4. Lifecycle events and cleanup. ────────────────────────────────────
    let shutdown_seen =
        wait_for_log_event(&lifecycle_log, "serve_shutdown", Duration::from_secs(2));
    assert!(
        shutdown_seen,
        "lifecycle.log should contain serve_shutdown after SIGTERM; contents:\n{:?}",
        std::fs::read_to_string(&lifecycle_log).ok()
    );

    // mcp/server.rs uses "signal_shutdown" (unlike cli/daemon.rs which uses
    // the REASONS-array string "signal_sigterm").
    let log_contents = std::fs::read_to_string(&lifecycle_log).unwrap();
    assert!(
        log_contents.contains("\tserve_shutdown\tsignal_shutdown"),
        "expected serve_shutdown reason 'signal_shutdown'; got:\n{log_contents}"
    );

    // Graceful shutdown must unlink both files so sibling processes can restart.
    assert!(
        !sock.exists(),
        "mati.sock should be removed on SIGTERM shutdown"
    );
    assert!(
        !mati_root.join("mati.pid").exists(),
        "mati.pid should be removed on SIGTERM shutdown"
    );
}

fn wait_for_path(path: &Path, timeout: Duration) -> Result<(), &'static str> {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if path.exists() {
            return Ok(());
        }
        std::thread::sleep(POLL);
    }
    Err("timeout")
}

fn wait_for_log_event(log_path: &Path, event: &str, timeout: Duration) -> bool {
    let needle = format!("\t{event}\t");
    let start = Instant::now();
    while start.elapsed() < timeout {
        if let Ok(contents) = std::fs::read_to_string(log_path) {
            if contents.contains(&needle) {
                return true;
            }
        }
        std::thread::sleep(POLL);
    }
    false
}
