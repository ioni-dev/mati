//! Daemon mode — keeps Store open to eliminate CLI startup overhead (M-17-A).
//!
//! The daemon listens on a Unix socket (`~/.mati/<slug>/mati.sock`) and handles
//! newline-delimited JSON requests. Hook commands route through [`daemon_result`]
//! to skip the ~150ms SurrealKV init cost on every hook invocation.
//!
//! ## Protocol
//!
//! One JSON request per connection, one JSON response, then close.
//!
//! ```json
//! // Request
//! {"v":1,"cmd":"get","args":{"key":"file:src/main.rs"}}
//! {"v":1,"cmd":"log_hit","args":{"key":"file:src/main.rs"}}
//! {"v":1,"cmd":"log_miss","args":{"key":"file:src/main.rs"}}
//! {"v":1,"cmd":"log_compliance_miss","args":{"key":"file:src/main.rs"}}
//! {"v":1,"cmd":"session_check_consulted","args":{"key":"file:src/main.rs"}}
//! {"v":1,"cmd":"edit_hook","args":{"path":"src/main.rs"}}
//! {"v":1,"cmd":"session_flush","args":{}}
//! {"v":1,"cmd":"ping","args":{}}
//!
//! // Response
//! {"ok":true,"v":1,"data":<value>}
//! {"ok":false,"v":1,"error":"description"}
//! ```
//!
//! ## Lifecycle
//!
//! Self-managing — no agent-specific session hooks required:
//! - Start: `mati daemon start` (or any agent's session-start script)
//! - Auto-shutdown: after [`IDLE_SHUTDOWN_SECS`] with no requests, using **wall clock**
//!   so sleep/wake cycles correctly count toward idle time (tokio monotonic clock
//!   freezes during system sleep and would never fire after a long hibernate).
//! - Signal shutdown: SIGINT / SIGTERM → flush store, remove socket + PID file.
//! - `mati init` and other commands needing direct store access must stop the daemon
//!   first — SurrealKV holds a process-level exclusive lock.
//!
//! ## Connection model
//!
//! Sequential (one connection at a time). Hooks fire serially within a session, so
//! parallel handling is unnecessary and avoids `Store` Send/Sync requirements.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

use mati_core::graph::Graph;
use mati_core::store::{derive_slug, Store};

// ── CLI subcommand types ──────────────────────────────────────────────────────

/// `mati daemon <start|stop|status>` — manage the background daemon process.
#[derive(Args, Debug)]
pub struct DaemonArgs {
    #[command(subcommand)]
    pub command: DaemonCommand,
}

#[derive(Subcommand, Debug)]
pub enum DaemonCommand {
    /// Start the daemon in the foreground (blocks until shutdown)
    Start,
    /// Stop a running daemon (sends SIGTERM, removes socket + PID file)
    Stop,
    /// Show whether the daemon is running and its socket path
    Status,
}

// ── Protocol constants ───────────────────────────────────────────────────────

/// Bump when request/response format changes incompatibly. Clients that send a
/// different version get an error and must fall back to direct `Store::open`.
pub const PROTOCOL_VERSION: u32 = 1;

/// Idle shutdown threshold — wall-clock seconds with no requests.
/// Uses wall time (not monotonic) so sleep/wake contributes correctly.
const IDLE_SHUTDOWN_SECS: u64 = 30 * 60; // 30 min

/// Unix domain socket path length limit.
/// macOS allows 104 bytes; Linux allows 108. Use the stricter macOS limit as
/// a universal guard so paths valid on Linux are also valid on macOS.
const UNIX_SOCK_PATH_MAX: usize = 104;

/// How often to sample wall-clock idle time. Fine enough to catch post-wake
/// idle windows; coarse enough not to burn cycles.
const IDLE_CHECK_INTERVAL_SECS: u64 = 5 * 60; // every 5 min

/// Outcome of a [`daemon_result`] call. Each variant carries the information
/// the caller needs to decide whether to fall back to `Store::open`.
#[derive(Debug)]
pub enum DaemonResult {
    /// Daemon responded. The value is the full JSON response (`ok`, `v`, `data`/`error`).
    Ok(serde_json::Value),
    /// No socket file — daemon is not running. **Safe** to use `Store::open`.
    NotRunning,
    /// Socket was stale (ECONNREFUSED + PID dead). Files cleaned up.
    /// **Safe** to use `Store::open`.
    StaleSocket,
    /// Daemon process is alive but not responding (or protocol version mismatch).
    /// **Not safe** to use `Store::open` — daemon likely holds the SurrealKV lock.
    /// Callers must degrade gracefully (P9) rather than attempt direct store access.
    Unresponsive,
}

// ── Connection timeout ───────────────────────────────────────────────────────

// ── Server ───────────────────────────────────────────────────────────────────

/// Start the daemon: open the Store, bind the Unix socket, and serve forever.
///
/// Exits cleanly on SIGINT, SIGTERM, or after [`IDLE_SHUTDOWN_SECS`] of wall-clock
/// idle time. Removes the socket and PID file on any exit path.
pub async fn run_daemon_start() -> Result<()> {
    let cwd = std::env::current_dir()?;
    // Compute mati_root separately so we can write the starting sentinel before
    // Store::open (which may fail). The sentinel tells `mati init` that a daemon
    // is starting and the store lock may be held imminently.
    let mati_root = mati_root_for(&cwd)?;

    // 1. Ensure runtime directory exists with correct permissions (0700).
    mati_core::mcp::metadata::ensure_runtime_dir(&mati_root)?;

    // 2. Stale-socket cleanup — refuse startup if a live daemon is detected.
    {
        use mati_core::mcp::metadata::{self as meta, StaleCheckResult};
        match meta::check_and_cleanup_stale(&mati_root) {
            StaleCheckResult::Clean | StaleCheckResult::StaleRemoved => {}
            StaleCheckResult::LiveDaemon { pid, owner, .. } => {
                anyhow::bail!(
                    "another mati {owner} (pid {pid}) is already running.\n\
                     Stop it with: mati daemon stop"
                );
            }
            StaleCheckResult::OrphanSocket => {
                // No metadata but socket file exists — unclean shutdown.
                // Safe to remove: no PID file means no owner.
                let _ = std::fs::remove_file(meta::socket_path(&mati_root));
            }
        }
    }

    let starting_path = mati_root.join("mati.starting");
    let _ = std::fs::write(
        &starting_path,
        format_sentinel(wall_secs(), std::process::id()),
    );

    let repo_root = Arc::new(std::fs::canonicalize(&cwd)?);
    let store = Store::open(&cwd).await?;

    // Clear stale session:consulted:* markers from previous sessions.
    if let Ok(keys) = store.scan_keys("session:consulted:").await {
        for k in &keys {
            let _ = store.delete(k).await;
        }
        if !keys.is_empty() {
            tracing::debug!(
                "daemon: cleared {} stale session:consulted markers",
                keys.len()
            );
        }
    }

    // Load the graph so the daemon can handle MCP tool commands (mem_get,
    // mem_query, mem_bootstrap, mem_set) in addition to hook commands.
    // Graph::load consumes the Store — access via graph.read().await.store().
    let graph = Graph::load(store)
        .await
        .context("failed to load knowledge graph")?;
    let graph = Arc::new(tokio::sync::RwLock::new(graph));

    let (sock_path, pid_path) = {
        let g = graph.read().await;
        let root = &g.store().root;
        (root.join("mati.sock"), root.join("mati.pid"))
    };

    // Unix domain socket paths are limited to 104 bytes on macOS / 108 on Linux.
    // Use the stricter macOS limit as a universal guard.
    let sock_path_bytes = sock_path.as_os_str().len();
    if sock_path_bytes > UNIX_SOCK_PATH_MAX {
        anyhow::bail!(
            "socket path too long ({sock_path_bytes} > {UNIX_SOCK_PATH_MAX} bytes): {}\n\
             Shorten your home directory path or symlink ~/.mati to a shorter location.",
            sock_path.display()
        );
    }

    // Bind socket BEFORE writing PID file. This eliminates the race window
    // where the PID file exists but the socket isn't ready yet — which causes
    // `daemon_result` to return `Unresponsive` and `ensure_daemon` to fail open.
    let listener = UnixListener::bind(&sock_path)
        .with_context(|| format!("failed to bind Unix socket at {}", sock_path.display()))?;

    // Harden socket permissions after bind.
    if let Err(e) = mati_core::mcp::metadata::harden_socket(&sock_path) {
        tracing::warn!("failed to harden socket permissions: {e}");
    }

    // Publish v2 daemon metadata (with session UUID) atomically.
    let daemon_meta = mati_core::mcp::metadata::DaemonMetadata::new(
        mati_core::mcp::metadata::DaemonOwner::Daemon,
    );
    let daemon_session = daemon_meta.session;
    if let Err(e) = mati_core::mcp::metadata::publish_metadata(
        sock_path.parent().unwrap_or(std::path::Path::new(".")),
        &daemon_meta,
    ) {
        // Fall back to legacy PID file.
        tracing::warn!("failed to publish v2 daemon metadata: {e}");
        std::fs::write(
            &pid_path,
            format!(r#"{{"pid":{},"owner":"daemon"}}"#, std::process::id()),
        )
        .with_context(|| format!("failed to write PID file at {}", pid_path.display()))?;
    }
    // PID is written — remove the starting sentinel so `mati init` won't block.
    let _ = std::fs::remove_file(&starting_path);

    tracing::info!(
        path = %sock_path.display(),
        pid = std::process::id(),
        "mati daemon listening"
    );
    eprintln!(
        "mati daemon listening on {} (idle shutdown: {}min)",
        sock_path.display(),
        IDLE_SHUTDOWN_SECS / 60
    );

    // Wall-clock timestamp of last accepted connection.
    let last_wall = Arc::new(AtomicU64::new(wall_secs()));

    // Idle-check background task (unchanged — same logic as before).
    let idle_notify = Arc::new(tokio::sync::Notify::new());
    {
        let last_wall = last_wall.clone();
        let notify = idle_notify.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(IDLE_CHECK_INTERVAL_SECS));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                let now = wall_secs();
                let last = last_wall.load(Ordering::Relaxed);
                if now.saturating_sub(last) >= IDLE_SHUTDOWN_SECS {
                    tracing::info!(
                        idle_secs = now.saturating_sub(last),
                        "mati daemon: idle shutdown"
                    );
                    eprintln!(
                        "mati daemon: idle {}min — shutting down",
                        IDLE_SHUTDOWN_SECS / 60
                    );
                    notify.notify_one();
                    break;
                }
            }
        });
    }

    // Graceful shutdown signal — used to stop serve_loop_graceful after the
    // current in-flight connection completes (never mid-write).
    let shutdown = tokio::sync::Notify::new();

    // Run serve_loop and the shutdown-watcher concurrently with join! so that
    // serve_loop is NEVER cancelled by tokio. It exits only after handle_connection
    // returns, ensuring all writes are committed before store.close() is called.
    // Capture daemon effective UID once — used for every peer credential check.
    let daemon_euid = mati_core::mcp::metadata::current_euid();

    tokio::join!(
        serve_loop_graceful(
            Arc::clone(&graph),
            &repo_root,
            &listener,
            &last_wall,
            &shutdown,
            daemon_euid,
            daemon_session,
        ),
        async {
            // Wait for either a signal or the idle-check notification.
            let ctrl_c = tokio::signal::ctrl_c();
            #[cfg(unix)]
            {
                let mut sigterm =
                    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                        .expect("failed to register SIGTERM handler");
                tokio::select! {
                    _ = ctrl_c => {
                        tracing::info!("mati daemon: signal shutdown (SIGINT)");
                        eprintln!("mati daemon shutting down");
                    }
                    _ = sigterm.recv() => {
                        tracing::info!("mati daemon: signal shutdown (SIGTERM)");
                        eprintln!("mati daemon shutting down");
                    }
                    _ = idle_notify.notified() => {
                        // Idle shutdown message already printed in idle-check task.
                    }
                }
            }
            #[cfg(not(unix))]
            {
                tokio::select! {
                    _ = ctrl_c => {
                        tracing::info!("mati daemon: signal shutdown");
                        eprintln!("mati daemon shutting down");
                    }
                    _ = idle_notify.notified() => {}
                }
            }
            // Signal serve_loop_graceful to stop accepting after current connection.
            shutdown.notify_one();
        }
    );

    // Cleanup — runs only AFTER serve_loop_graceful has finished the in-flight
    // connection. Store is closed cleanly with no concurrent writers.
    let _ = std::fs::remove_file(&starting_path); // belt-and-suspenders
    let _ = std::fs::remove_file(&sock_path);
    let _ = std::fs::remove_file(&pid_path);
    // Unwrap the Arc to close the graph (which closes the store).
    match Arc::try_unwrap(graph) {
        Ok(rwlock) => {
            if let Err(e) = rwlock.into_inner().close().await {
                tracing::warn!("daemon: store close warning on shutdown: {e}");
            }
        }
        Err(_) => tracing::warn!("daemon: graph Arc still referenced on shutdown"),
    }
    Ok(())
}

/// Accept and handle connections sequentially. Exits cleanly after the current
/// connection completes when `shutdown` is notified — never cancels a connection
/// mid-execution.
///
/// Delegates to the shared `socket_handle_connection` from `mcp::server`, which
/// handles both hook commands (get, log_hit, etc.) and MCP tool commands
/// (mem_get, mem_query, mem_bootstrap, mem_set).
async fn serve_loop_graceful(
    graph: Arc<tokio::sync::RwLock<Graph>>,
    repo_root: &Path,
    listener: &UnixListener,
    last_wall: &AtomicU64,
    shutdown: &tokio::sync::Notify,
    daemon_euid: u32,
    daemon_session: uuid::Uuid,
) {
    loop {
        // Race between a new connection and the shutdown signal.
        // `biased` ensures shutdown is checked first on every iteration so a
        // notify_one() that arrived during handle_connection is never missed.
        let stream = tokio::select! {
            biased;
            _ = shutdown.notified() => break,
            result = listener.accept() => {
                match result {
                    Ok((s, _)) => s,
                    Err(e) => {
                        tracing::warn!(error = %e, "daemon: accept error");
                        continue;
                    }
                }
            }
        };
        last_wall.store(wall_secs(), Ordering::Relaxed);
        // Peer credential check — mismatch or failure drops the connection.
        let peer = match mati_core::mcp::metadata::check_peer_cred(&stream, daemon_euid) {
            Some(p) => p,
            None => continue,
        };
        // Runs to completion — NOT cancellable by shutdown.
        if let Err(e) = mati_core::mcp::server::socket_handle_connection(
            Arc::clone(&graph),
            repo_root,
            stream,
            peer,
            daemon_session,
        )
        .await
        {
            tracing::warn!(error = %e, "daemon: connection error");
        }
    }
}

// Local dispatch and command handlers removed — the daemon now delegates to
// `mcp::server::socket_handle_connection` which handles both hook commands
// and MCP tool commands through the shared `socket_dispatch` function.

// (write_response removed — using server::write_socket_response)

// (All dispatch + cmd_* handlers removed — using shared socket_dispatch)

// ── Client ───────────────────────────────────────────────────────────────────

/// Send a v2 protocol request to the daemon and return a [`DaemonResult`].
///
/// Internally constructs a v2 `protocol::Request` from the v1-style `(cmd, args)`
/// parameters. The daemon session UUID is read from `DaemonMetadata`; a fresh
/// request UUID is generated per call.
///
/// Callers receive `DaemonResult::Ok(json)` where `json` is a v1-compatible
/// envelope: `{"ok":true,"data":<value>}` or `{"ok":false,"error":"msg"}`.
///
/// Handles three failure modes:
/// - **No socket** → [`DaemonResult::NotRunning`] — safe to use `Store::open`
/// - **ECONNREFUSED + PID dead** → clean up stale files, [`DaemonResult::StaleSocket`] — safe to use `Store::open`
/// - **PID alive but not responding** → [`DaemonResult::Unresponsive`] — **unsafe** to use `Store::open`
/// Send a typed v2 Command to the daemon and return a [`DaemonResult`].
///
/// This is the preferred API for internal callers. Constructs a v2
/// `protocol::Request` directly from a typed `Command` — no legacy
/// string command names involved.
pub async fn daemon_v2(root: &Path, cmd: mati_core::mcp::protocol::Command) -> DaemonResult {
    let v2_cmd = match serde_json::to_value(&cmd) {
        Ok(v) => v,
        Err(_) => return DaemonResult::Unresponsive,
    };
    send_v2_raw(root, v2_cmd).await
}

/// Send a v2 request using legacy `(cmd_str, args)` parameters.
///
/// Retained for pure-read callers (ping, get, scan_prefix, history, etc.)
/// that have not yet migrated to typed `daemon_v2`. Mutation and
/// side-effecting-read callers should use `daemon_v2` directly.
pub async fn daemon_result(root: &Path, cmd: &str, args: serde_json::Value) -> DaemonResult {
    let v2_cmd = mati_core::mcp::protocol::v1_to_v2_command(cmd, &args);
    send_v2_raw(root, v2_cmd).await
}

/// Low-level: connect to daemon socket, send a pre-built v2 Command JSON,
/// read and parse the v2 Response.
async fn send_v2_raw(root: &Path, v2_cmd: serde_json::Value) -> DaemonResult {
    let sock_path = root.join("mati.sock");

    if sock_path.as_os_str().len() > UNIX_SOCK_PATH_MAX {
        tracing::warn!(
            path = %sock_path.display(),
            "daemon: socket path exceeds Unix limit — daemon unavailable"
        );
        return DaemonResult::NotRunning;
    }

    if !sock_path.exists() {
        return DaemonResult::NotRunning;
    }

    let stream = match UnixStream::connect(&sock_path).await {
        Ok(s) => s,
        Err(e) => {
            let is_refused = e.kind() == std::io::ErrorKind::ConnectionRefused;
            if is_refused {
                use mati_core::mcp::metadata::{self as meta, StaleCheckResult};
                match meta::check_and_cleanup_stale(root) {
                    StaleCheckResult::StaleRemoved | StaleCheckResult::Clean => {
                        tracing::debug!("daemon: removed stale socket");
                        return DaemonResult::StaleSocket;
                    }
                    StaleCheckResult::OrphanSocket => {
                        let _ = std::fs::remove_file(&sock_path);
                        tracing::debug!("daemon: removed orphan socket");
                        return DaemonResult::StaleSocket;
                    }
                    StaleCheckResult::LiveDaemon { .. } => {
                        tracing::warn!("daemon: socket refused but PID alive — unresponsive");
                        return DaemonResult::Unresponsive;
                    }
                }
            }
            tracing::debug!(error = %e, "daemon: connect failed, treating as not running");
            return DaemonResult::NotRunning;
        }
    };

    let daemon_session = mati_core::mcp::metadata::read_metadata(root)
        .map(|m| m.session)
        .unwrap_or_else(uuid::Uuid::nil);

    let v2_request = serde_json::json!({
        "v": mati_core::mcp::protocol::PROTOCOL_VERSION,
        "id": uuid::Uuid::new_v4(),
        "session": daemon_session,
        "cmd": v2_cmd,
    });

    let (reader, mut writer) = stream.into_split();
    let mut bytes = match serde_json::to_vec(&v2_request) {
        Ok(b) => b,
        Err(_) => return DaemonResult::Unresponsive,
    };
    bytes.push(b'\n');

    if writer.write_all(&bytes).await.is_err() {
        return DaemonResult::Unresponsive;
    }
    if writer.shutdown().await.is_err() {
        return DaemonResult::Unresponsive;
    }

    let mut buf_reader = BufReader::new(reader);
    let mut line = String::new();
    match tokio::time::timeout(Duration::from_secs(2), buf_reader.read_line(&mut line)).await {
        Ok(Ok(n)) if n > 0 => {}
        _ => return DaemonResult::Unresponsive,
    }

    let resp: serde_json::Value = match serde_json::from_str(line.trim()) {
        Ok(v) => v,
        Err(_) => return DaemonResult::Unresponsive,
    };

    // Convert v2 Response to DaemonResult envelope.
    match resp.get("status").and_then(|s| s.as_str()) {
        Some("ok") => {
            let data = resp.get("data").cloned().unwrap_or(serde_json::Value::Null);
            DaemonResult::Ok(serde_json::json!({"ok": true, "v": 2, "data": data}))
        }
        Some("err") => {
            let code = resp
                .get("code")
                .and_then(|c| c.as_str())
                .unwrap_or("internal");
            let message = resp
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("unknown error");
            if code == "session_mismatch" {
                tracing::debug!("daemon: session mismatch — daemon may have restarted");
            }
            DaemonResult::Ok(
                serde_json::json!({"ok": false, "v": 2, "error": message, "code": code}),
            )
        }
        _ => DaemonResult::Unresponsive,
    }
}

/// Convenience wrapper: extract the `data` field from a successful `get` response.
///
/// Returns the JSON string of the record (or `"null"`), or `None` if the daemon
/// is unavailable or the result should not be used.
#[allow(dead_code)]
pub async fn daemon_get(root: &Path, key: &str) -> Option<String> {
    match daemon_result(root, "get", serde_json::json!({ "key": key })).await {
        DaemonResult::Ok(resp) => {
            if resp.get("ok") != Some(&serde_json::Value::Bool(true)) {
                return None;
            }
            match resp.get("data") {
                Some(d) if d.is_null() => Some("null".to_string()),
                Some(d) => Some(d.to_string()),
                None => None,
            }
        }
        DaemonResult::NotRunning | DaemonResult::StaleSocket => None,
        DaemonResult::Unresponsive => None,
    }
}

// ── Auto-start ───────────────────────────────────────────────────────────────

/// Spawn `mati daemon start` in the background if no daemon is currently running.
///
/// Fire-and-forget: does **not** wait for the daemon to be ready. The calling
/// hook falls through to direct `Store::open` for this invocation; the daemon
/// will be ready for all subsequent hook calls in the same session.
///
/// Stale timeout for the starting sentinel. A sentinel older than this with a
/// dead owner PID is considered abandoned.
pub const STARTING_STALE_SECS: u64 = 30;

/// Sentinel file format: `<unix_timestamp> <pid>\n`
///
/// The PID allows liveness checks so we don't have to rely solely on a fixed
/// timeout. If the owner PID is dead, the sentinel is stale regardless of age.
fn format_sentinel(ts: u64, pid: u32) -> String {
    format!("{ts} {pid}\n")
}

pub fn parse_sentinel(content: &str) -> Option<(u64, u32)> {
    let mut parts = content.split_whitespace();
    let ts = parts.next()?.parse::<u64>().ok()?;
    let pid = parts.next()?.parse::<u32>().ok()?;
    Some((ts, pid))
}

/// Check whether a PID is still alive using `kill(pid, 0)`.
#[cfg(unix)]
pub fn is_pid_alive(pid: u32) -> bool {
    // kill(pid, 0) checks existence without sending a signal.
    // Returns 0 if process exists and we can signal it.
    // Returns -1 with ESRCH if process does not exist.
    // Returns -1 with EPERM if process exists but we can't signal it (still alive).
    let ret = unsafe { libc::kill(pid as libc::pid_t, 0) };
    if ret == 0 {
        return true;
    }
    // EPERM means the process exists but belongs to another user — still alive.
    std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

#[cfg(not(unix))]
pub fn is_pid_alive(_pid: u32) -> bool {
    // On non-Unix, fall back to the timeout-only approach.
    true
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Derive `~/.mati/<slug>/` for the given working directory (repo root).
///
/// Public so `hooks.rs` and `init.rs` can compute the socket/PID path without
/// duplicating the slug derivation logic.
pub fn mati_root_for(cwd: &Path) -> Result<PathBuf> {
    let slug = derive_slug(cwd);
    let home = dirs::home_dir().context("cannot determine home directory")?;
    Ok(home.join(".mati").join(slug))
}

/// Parse the PID file and return `(pid, owner)`.
///
/// Supports both the new JSON format `{"pid":1234,"owner":"daemon"}` and
/// the legacy plain-text PID format `1234` for backward compatibility.
/// When the owner field is absent (legacy format) it defaults to `"daemon"`.
pub fn read_pid_file(root: &Path) -> Option<(u32, String)> {
    let content = std::fs::read_to_string(root.join("mati.pid")).ok()?;
    let trimmed = content.trim();

    // Try JSON format first.
    if let Ok(val) = serde_json::from_str::<serde_json::Value>(trimmed) {
        let pid = val.get("pid").and_then(|v| v.as_u64())? as u32;
        let owner = val
            .get("owner")
            .and_then(|v| v.as_str())
            .unwrap_or("daemon")
            .to_string();
        return Some((pid, owner));
    }

    // Fall back to legacy plain PID.
    if let Ok(pid) = trimmed.parse::<u32>() {
        return Some((pid, "daemon".to_string()));
    }

    None
}

/// Derive the `~/.mati/<slug>/` path for the current working directory.
fn project_root() -> Result<PathBuf> {
    let cwd = std::env::current_dir()?;
    mati_root_for(&cwd)
}

/// Unix seconds from wall clock (not monotonic — survives sleep/wake).
fn wall_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ── Stop ─────────────────────────────────────────────────────────────────────

/// Stop a running daemon by sending SIGTERM to the PID in the PID file.
pub async fn run_daemon_stop() -> Result<()> {
    let root = project_root()?;
    let pid_path = root.join("mati.pid");
    let sock_path = root.join("mati.sock");

    if !pid_path.exists() && !sock_path.exists() {
        println!("mati daemon is not running");
        return Ok(());
    }

    let pid_info = read_pid_file(&root);

    // Refuse if owned by MCP server (PID file present and says "mcp").
    if let Some((_, ref owner)) = pid_info {
        if owner == "mcp" {
            println!(
                "mati daemon stop: the socket is owned by the active MCP server (mati serve).\n\
                 Stopping it would disconnect Claude Code's MCP tools.\n\
                 To stop it: close the Claude Code session that uses mati."
            );
            return Ok(());
        }
    }

    // PID file absent but socket file exists — ownership unknown.
    // This happens when the socket was created by an older mati binary that
    // did not write a PID file (e.g. the MCP server before v0.1 PID format change).
    // Ping the socket: if it is alive we refuse to avoid disconnecting a live
    // session. If it is unresponsive we clean it up as stale.
    if pid_info.is_none() && sock_path.exists() {
        match daemon_result(&root, "ping", serde_json::json!({})).await {
            DaemonResult::Ok(_) => {
                // Live socket with unknown owner — assume MCP to be safe.
                println!(
                    "mati daemon stop: socket is live but owner is unknown (PID file absent).\n\
                     This is likely an active MCP server session (mati serve).\n\
                     Stopping it would disconnect Claude Code's MCP tools.\n\
                     To stop it: close the Claude Code session that uses mati.\n\
                     To remove a confirmed stale socket: rm {}",
                    sock_path.display()
                );
                return Ok(());
            }
            DaemonResult::StaleSocket => {
                // daemon_result already deleted the socket file.
                println!("mati daemon: stale socket cleaned up");
                return Ok(());
            }
            DaemonResult::Unresponsive => {
                println!("mati daemon: socket unresponsive — cleaning up stale files");
                let _ = std::fs::remove_file(&sock_path);
                let _ = std::fs::remove_file(&pid_path);
                return Ok(());
            }
            DaemonResult::NotRunning => {
                println!("mati daemon is not running");
                return Ok(());
            }
        }
    }

    if let Some((pid, _)) = pid_info {
        let status = std::process::Command::new("kill")
            .arg("-TERM")
            .arg(pid.to_string())
            .status();
        match status {
            Ok(s) if s.success() => {
                tokio::time::sleep(Duration::from_millis(300)).await;
                println!("mati daemon stopped (pid {pid})");
            }
            Ok(_) => {
                println!("mati daemon process {pid} already exited — cleaning up");
            }
            Err(e) => {
                tracing::warn!(error = %e, pid, "failed to send SIGTERM");
                println!("mati daemon: failed to signal pid {pid} — cleaning up stale files");
            }
        }
    }

    let _ = std::fs::remove_file(&sock_path);
    let _ = std::fs::remove_file(&pid_path);
    Ok(())
}

// ── Status ───────────────────────────────────────────────────────────────────

/// Check if the daemon is running and responsive.
pub async fn run_daemon_status() -> Result<()> {
    let root = project_root()?;
    let sock_path = root.join("mati.sock");

    if !sock_path.exists() {
        println!("mati daemon is not running (no socket)");
        return Ok(());
    }

    let pid_info = read_pid_file(&root);

    match daemon_result(&root, "ping", serde_json::json!({})).await {
        DaemonResult::Ok(resp) if resp.get("ok") == Some(&serde_json::Value::Bool(true)) => {
            if let Some((pid, owner)) = &pid_info {
                println!("mati daemon is running (pid {pid})");
                println!("  owner: {owner}");
            } else {
                println!("mati daemon is running (pid unknown — PID file absent)");
                println!("  owner: likely mcp (socket created by older binary without PID file)");
                println!(
                    "  note: mati daemon stop will refuse to close a live unknown-owner socket"
                );
                println!("  to stop: close the Claude Code session that uses mati");
            }
            println!("  socket: {}", sock_path.display());
            println!(
                "  protocol version: {}",
                resp.get("v")
                    .and_then(|v| v.as_u64())
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "unknown".to_string())
            );
        }
        DaemonResult::Unresponsive => {
            println!("mati daemon socket exists but is not responding");
            println!("  socket: {}", sock_path.display());
            if let Some((pid, owner)) = &pid_info {
                println!("  pid: {pid} (alive)");
                println!("  owner: {owner}");
            }
            println!("  run `mati daemon stop` to clean up");
        }
        DaemonResult::StaleSocket => {
            println!("mati daemon: stale socket cleaned up");
        }
        _ => {
            println!("mati daemon is not running");
            if let Some((pid, _)) = &pid_info {
                println!("  stale pid: {pid}");
            }
            println!("  run `mati daemon stop` to clean up");
        }
    }

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // Protocol type serialization tests removed — Request/Response types
    // now live in mcp::server as SocketRequest/SocketResponse and are
    // tested there.

    #[tokio::test]
    async fn daemon_result_not_running_without_socket() {
        let tmp = tempfile::tempdir().unwrap();
        let result = daemon_result(tmp.path(), "ping", serde_json::json!({})).await;
        assert!(matches!(result, DaemonResult::NotRunning));
    }

    #[tokio::test]
    async fn daemon_get_returns_none_without_socket() {
        let tmp = tempfile::tempdir().unwrap();
        let result = daemon_get(tmp.path(), "file:src/main.rs").await;
        assert!(result.is_none());
    }

    #[test]
    fn parse_sentinel_roundtrip() {
        let s = format_sentinel(1234567890, 42);
        let (ts, pid) = parse_sentinel(&s).unwrap();
        assert_eq!(ts, 1234567890);
        assert_eq!(pid, 42);
    }

    #[test]
    fn parse_sentinel_legacy_format_returns_none() {
        // Legacy format has only a timestamp, no PID
        assert!(parse_sentinel("1234567890").is_none());
    }

    #[test]
    fn is_pid_alive_for_current_process() {
        assert!(is_pid_alive(std::process::id()));
    }

    #[test]
    fn is_pid_alive_for_dead_pid() {
        // PID 4_000_000 is almost certainly not running
        assert!(!is_pid_alive(4_000_000));
    }
}
