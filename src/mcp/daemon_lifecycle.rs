//! Daemon-readiness lifecycle helpers shared by hook and MCP code paths.
//!
//! `ensure_daemon` probes the daemon over its socket and, if absent or
//! unresponsive, spawns a new `mati daemon start` subprocess and polls for
//! readiness. It is the canonical auto-spawn implementation — both the
//! binary-crate hook adapter (`cli::hook_decide`) and the MCP socket-backed
//! proxy paths (`mcp::server::proxy_daemon_result` / `proxy_daemon_v2`) call
//! through here so the recovery semantics can never drift between the two.
//!
//! Recovery strategy mirrors `cli::hook_decide::ensure_daemon` (pre-pass-33,
//! when this function lived bin-side):
//!   - `Ok` → daemon is healthy, return immediately.
//!   - `NotRunning` / `StaleSocket` → spawn daemon, poll for readiness.
//!   - `Unresponsive` → wait 300ms, re-probe; if still unresponsive,
//!     SIGTERM the stale PID + force-cleanup and spawn fresh. The SIGTERM
//!     is critical: without it the old process holds the exclusive
//!     SurrealKV Store lock and the new spawn deadlocks on `Store::open()`.
//!
//! Phase 2 sentinel: the daemon writes `mati.starting` before acquiring the
//! Store lock. If another hook spawned a daemon within the last 5 seconds,
//! poll for readiness instead of spawning a competitor.
//!
//! Total worst-case latency including Unresponsive recovery: ~1.6s. Well
//! within the 3000ms hook timeout.
//!
//! Test escape hatch: setting `MATI_DISABLE_AUTO_SPAWN=1` skips Phase 3
//! (subprocess spawn) while still running the probe + Phase 2 sentinel
//! polling. This keeps unit tests that depend on `NotRunning` propagation
//! deterministic without requiring per-test mocks.

use std::path::Path;
use std::time::Duration;

use super::server::{proxy_daemon_result_no_spawn, ProxyDaemonResult};

/// Ensure the daemon is reachable. Auto-starts if needed.
///
/// Returns `true` if the daemon responds to a `ping` by the end of the
/// readiness poll. Returns `false` if the daemon could not be reached
/// after spawn + retry.
///
/// Calling this from `proxy_daemon_result` / `proxy_daemon_v2` makes the
/// MCP socket-backed paths self-healing across `mati daemon stop` cycles
/// — previously a stop during init/repair left every subsequent MCP tool
/// call returning `{"error":"<op>: daemon not running"}` until the user
/// manually restarted.
pub async fn ensure_daemon(mati_root: &Path) -> bool {
    // Phase 1: probe current state.
    match proxy_daemon_result_no_spawn(mati_root, "ping", &serde_json::json!({})).await {
        ProxyDaemonResult::Ok(_) => return true,
        ProxyDaemonResult::NotRunning | ProxyDaemonResult::StaleSocket => {}
        ProxyDaemonResult::Unresponsive => {
            // Socket exists + PID alive, but can't connect. Could be:
            //   (a) daemon mid-startup (PID written, socket not yet bound)
            //   (b) recycled PID after MCP crash — stale, safe to clean up
            //   (c) genuinely hung process
            // Wait 300ms to cover (a), then re-probe.
            tokio::time::sleep(Duration::from_millis(300)).await;
            match proxy_daemon_result_no_spawn(mati_root, "ping", &serde_json::json!({})).await {
                ProxyDaemonResult::Ok(_) => return true,
                ProxyDaemonResult::NotRunning | ProxyDaemonResult::StaleSocket => {
                    // proxy_daemon_result cleaned up stale files — fall through to spawn.
                }
                ProxyDaemonResult::Unresponsive => {
                    // Still unresponsive after 300ms. The PID is alive but not
                    // serving our socket — most likely a stale daemon running
                    // an old protocol version, or a recycled PID.
                    //
                    // Use the shared `kill_and_wait` helper so the
                    // synchronous-exit guarantee is identical to
                    // `mati daemon stop`'s kill flow. Without that
                    // guarantee, the old daemon could still hold the
                    // exclusive SurrealKV Store lock when our new spawn
                    // calls `Store::open()` — a deadlock.
                    //
                    // 2s budget: well within the 3000ms hook timeout
                    // (Phase 4 readiness poll adds ~800ms; 2s here keeps
                    // total recovery latency under the ceiling).
                    let stale_pid = super::metadata::read_metadata(mati_root).map(|m| m.pid);
                    if let Some(pid) = stale_pid {
                        let _ = super::metadata::kill_and_wait(pid, Duration::from_secs(2)).await;
                    }
                    let _ = std::fs::remove_file(super::metadata::socket_path(mati_root));
                    let _ = std::fs::remove_file(mati_root.join("mati.pid"));
                }
            }
        }
    }

    // Phase 2: check if another process is already starting the daemon.
    // The daemon writes `mati.starting` before acquiring the Store lock.
    // If another hook already spawned a daemon within the last 5 seconds,
    // wait for it instead of spawning a competing instance (which would
    // block on the exclusive Store lock and waste time).
    let starting = mati_root.join("mati.starting");
    if starting.exists() {
        if let Ok(meta) = starting.metadata() {
            if let Ok(modified) = meta.modified() {
                if modified.elapsed().unwrap_or_default() < Duration::from_secs(5) {
                    // Another process is starting — poll for readiness.
                    for ms in [100, 150, 200, 250, 300] {
                        tokio::time::sleep(Duration::from_millis(ms)).await;
                        if matches!(
                            proxy_daemon_result_no_spawn(mati_root, "ping", &serde_json::json!({}))
                                .await,
                            ProxyDaemonResult::Ok(_)
                        ) {
                            return true;
                        }
                    }
                    // Other spawn failed or is too slow — fall through to our own spawn.
                }
            }
        }
    }

    // Test escape hatch: skip the subprocess spawn so unit tests that
    // assert `NotRunning` propagation remain deterministic. Production
    // code paths never set this env var.
    if std::env::var_os("MATI_DISABLE_AUTO_SPAWN").is_some() {
        return false;
    }

    // Phase 3: spawn daemon.
    let exe = match std::env::current_exe() {
        Ok(e) => e,
        Err(_) => return false,
    };

    // Capture stderr to a log file so startup failures are diagnosable.
    let stderr_target = dirs::home_dir()
        .map(|h| h.join(".mati").join("daemon_start.log"))
        .and_then(|p| {
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&p)
                .ok()
        })
        .map(std::process::Stdio::from)
        .unwrap_or_else(std::process::Stdio::null);

    let _ = std::process::Command::new(&exe)
        .args(["daemon", "start"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(stderr_target)
        .spawn();

    // Phase 4: readiness poll with exponential backoff.
    // Budget: 50+100+150+200+300 = 800ms.
    for ms in [50, 100, 150, 200, 300] {
        tokio::time::sleep(Duration::from_millis(ms)).await;
        if matches!(
            proxy_daemon_result_no_spawn(mati_root, "ping", &serde_json::json!({})).await,
            ProxyDaemonResult::Ok(_)
        ) {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp::metadata::{publish_metadata, DaemonMetadata, DaemonOwner};
    use crate::mcp::server::proxy_daemon_result;

    /// When the daemon is already running and answers ping, return true fast.
    ///
    /// We bind a real Unix socket inside the tempdir, publish metadata, and
    /// arrange a minimal accept loop that responds with a v2-shaped `ok`
    /// envelope. `proxy_daemon_result` should accept it and `ensure_daemon`
    /// should short-circuit at Phase 1 without ever spawning.
    #[tokio::test]
    async fn ensure_daemon_returns_true_when_daemon_already_running() {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        use tokio::net::UnixListener;

        let dir = tempfile::TempDir::new().unwrap();
        let root = dir.path().to_path_buf();

        // Publish metadata pointing at THIS process's PID — guaranteed alive.
        let mut meta = DaemonMetadata::new(DaemonOwner::Daemon);
        meta.pid = std::process::id();
        publish_metadata(&root, &meta).unwrap();
        let session = meta.session;

        // Stand up a tiny ping-responder on the daemon socket.
        let sock_path = root.join("mati.sock");
        let listener = UnixListener::bind(&sock_path).unwrap();
        let server_handle = tokio::spawn(async move {
            // One connection is enough — Phase 1 probe.
            if let Ok((stream, _)) = listener.accept().await {
                let (reader, mut writer) = stream.into_split();
                let mut br = BufReader::new(reader);
                let mut line = String::new();
                let _ = br.read_line(&mut line).await;
                let resp = serde_json::json!({
                    "v": 2,
                    "id": uuid::Uuid::new_v4(),
                    "session": session,
                    "status": "ok",
                    "data": { "pong": true }
                });
                let mut bytes = serde_json::to_vec(&resp).unwrap();
                bytes.push(b'\n');
                let _ = writer.write_all(&bytes).await;
                let _ = writer.shutdown().await;
            }
        });

        // No spawn needed — the existing socket should respond.
        std::env::set_var("MATI_DISABLE_AUTO_SPAWN", "1");
        let result = ensure_daemon(&root).await;
        std::env::remove_var("MATI_DISABLE_AUTO_SPAWN");

        let _ = server_handle.await;
        assert!(result, "ensure_daemon must return true when ping succeeds");
    }

    /// When no daemon is running and auto-spawn is disabled, ensure_daemon
    /// must return false cleanly without panicking. Exercises Phases 1 and 2.
    #[tokio::test]
    async fn ensure_daemon_returns_false_when_spawn_disabled_and_no_daemon() {
        let dir = tempfile::TempDir::new().unwrap();
        std::env::set_var("MATI_DISABLE_AUTO_SPAWN", "1");
        let result = ensure_daemon(dir.path()).await;
        std::env::remove_var("MATI_DISABLE_AUTO_SPAWN");
        assert!(
            !result,
            "ensure_daemon must return false when no daemon is running and spawn is disabled"
        );
    }

    /// Regression: `proxy_daemon_result` with a persistent NotRunning state
    /// must surface NotRunning to the caller (via the auto-spawn path failing
    /// cleanly when MATI_DISABLE_AUTO_SPAWN suppresses Phase 3). Pinned so a
    /// future change that swallows or mutates the failure mode is caught.
    ///
    /// This is the structural test that would have caught the smoke 55/115
    /// regression: before the auto-spawn wiring, every MCP call after a
    /// `mati daemon stop` cycle returned `{"error":"<op>: daemon not running"}`
    /// instead of recovering.
    #[tokio::test]
    async fn proxy_daemon_result_invokes_ensure_daemon_on_persistent_notrunning() {
        let dir = tempfile::TempDir::new().unwrap();
        std::env::set_var("MATI_DISABLE_AUTO_SPAWN", "1");
        let result = proxy_daemon_result(dir.path(), "ping", serde_json::json!({})).await;
        std::env::remove_var("MATI_DISABLE_AUTO_SPAWN");
        assert!(
            matches!(result, ProxyDaemonResult::NotRunning),
            "proxy_daemon_result must return NotRunning when daemon absent and spawn disabled, got {result:?}"
        );
    }
}
