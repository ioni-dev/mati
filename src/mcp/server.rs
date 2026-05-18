//! MCP stdio server entry point (M-07).
//!
//! `serve()` is the entry point. It opens the store, loads the graph,
//! constructs `MatiServer`, and runs the rmcp stdio transport. After the
//! client disconnects, the process auto-promotes to a headless daemon and
//! waits for an idle timeout or signal before shutting down (a panic hook
//! is installed at startup; lifecycle events are recorded throughout;
//! a boot-time auto-drain bounded by `AUTO_DRAIN_TIMEOUT` runs the dirty
//! gotcha-index repair).
//!
//! Also binds the Unix daemon socket (`~/.mati/<slug>/mati.sock`) so that hook
//! scripts using `mati get`/`mati ping` can route through the daemon protocol
//! instead of trying to open the SurrealKV store directly (which would fail with
//! a lock error while the MCP server holds the exclusive handle). The socket
//! task is supervised: a watcher signals graceful shutdown if it dies, and
//! a `SHUTDOWN_DRAIN_TIMEOUT` ceiling falls back to `abort_handle` so a
//! wedged handler can never block exit.
//!
//! Public surface: `serve`, `socket_handle_connection`, `Shutdown` (+
//! methods), and the policy constants `AUTO_DRAIN_TIMEOUT`,
//! `MAX_CONCURRENT_CONNECTIONS`, `IDLE_SHUTDOWN_SECS`,
//! `IDLE_CHECK_INTERVAL_SECS`, `UNIX_SOCK_PATH_MAX` — all shared with
//! `cli::daemon` so both daemon paths use identical operational policy.

use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use rmcp::model::{ServerCapabilities, ServerInfo};
use rmcp::{tool_handler, ServerHandler, ServiceExt};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use crate::graph::edges::EdgeKind;
use crate::graph::Graph;

use super::tools::MatiServer;
use super::types::{MemBootstrapParams, MemGetParams, MemQueryParams, MemSetParams};

#[derive(Debug)]
pub(crate) enum ProxyDaemonResult {
    Ok(serde_json::Value),
    NotRunning,
    StaleSocket,
    Unresponsive,
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for MatiServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_tool_list_changed()
                .build(),
        )
        .with_instructions(
            "mati is a persistent engineering knowledge store for the current \
                 codebase. Use mem_get for direct record lookup, mem_query for \
                 search and graph traversal, mem_bootstrap for session context, \
                 and mem_set for writing knowledge records.",
        )
    }
}

/// Start the MCP stdio proxy for the project rooted at `repo_root`.
///
/// After γ-C4, `mati serve` is a thin MCP-stdio ↔ UDS forwarder: every
/// tool call is proxied over the Unix domain socket to a separate daemon
/// process which owns the store, the graph, the socket listener, the
/// idle-shutdown loop, signal handling, and the auto-drain pipeline.
///
/// On startup:
/// 1. Resolve `~/.mati/<slug>/` from `repo_root`.
/// 2. Ensure a daemon is running (auto-spawning one if necessary via the
///    state-aware readiness machinery in `daemon_lifecycle::ensure_daemon`).
/// 3. Bind the rmcp stdio transport and forward every request to the
///    daemon via `MatiServer::with_socket_root`.
///
/// On client disconnect, this process exits cleanly — the daemon (separate
/// process) is unaffected and remains available for the next `mati serve`
/// invocation that Codex / Claude Code spawns.
///
/// Lifecycle events (`serve_start`, `serve_failed`, `serve_shutdown`,
/// `startup`) are appended throughout so `mati doctor` can observe the
/// proxy's cold-start path.
pub async fn serve(repo_root: &Path) -> Result<()> {
    let startup_t0 = std::time::Instant::now();

    // Resolve the daemon root so we can emit lifecycle events even before
    // the daemon is reachable.
    let mati_root: PathBuf = dirs::home_dir()
        .map(|h| h.join(".mati").join(crate::store::derive_slug(repo_root)))
        .ok_or_else(|| anyhow::anyhow!("cannot resolve home directory for mati_root"))?;

    super::metadata::record_lifecycle_event(&mati_root, "startup", "phase=ensure_daemon");

    // The daemon owns the store. `ensure_daemon` spawns a daemon if needed
    // and waits for it to be ready via the state-aware readiness machinery
    // (`daemon_lifecycle::wait_for_ready`).
    if !super::daemon_lifecycle::ensure_daemon(&mati_root).await {
        super::metadata::record_lifecycle_event(
            &mati_root,
            "serve_failed",
            "daemon unreachable after auto-spawn",
        );
        anyhow::bail!(
            "mati serve: daemon unreachable. \
             Run `mati daemon start` manually and check the lifecycle.log."
        );
    }

    super::metadata::record_lifecycle_event(
        &mati_root,
        "serve_start",
        &format!("pid={} owner=proxy", std::process::id()),
    );

    // Initialize the metrics handle so any local recording is no-op rather
    // than panicking. The daemon owns the authoritative metrics surface.
    super::metrics::init();

    super::metadata::record_lifecycle_event(
        &mati_root,
        "startup",
        &format!("phase=ready elapsed_ms={}", startup_t0.elapsed().as_millis()),
    );

    // MCP stdio proxy: every tool call forwards over UDS to the daemon.
    let transport = rmcp::transport::io::stdio();
    let service = MatiServer::with_socket_root(mati_root.clone())
        .serve(transport)
        .await
        .map_err(|e| anyhow::anyhow!("MCP proxy initialization failed: {e}"))
        .inspect_err(|e| {
            super::metadata::record_lifecycle_event(
                &mati_root,
                "serve_failed",
                &format!("proxy init: {e:#}"),
            )
        })?;

    let shutdown_reason: &'static str = match service.waiting().await {
        Ok(_) => "client_disconnect",
        Err(e) => {
            super::metadata::record_lifecycle_event(
                &mati_root,
                "serve_failed",
                &format!("proxy waiting: {e}"),
            );
            "mcp_waiting_error"
        }
    };
    super::metadata::record_lifecycle_event(
        &mati_root,
        "serve_shutdown",
        &format!("reason={shutdown_reason}"),
    );
    Ok(())
}

pub(crate) async fn proxy_daemon_result(
    root: &Path,
    cmd: &str,
    args: serde_json::Value,
) -> ProxyDaemonResult {
    // Daemon-restart resilience: when `mati daemon stop` followed by
    // `mati daemon start` happens during an active MCP-stdio session, the
    // first call after the restart can fail in three ways:
    //   1. Socket file transiently absent (NotRunning)
    //   2. Connection refused before the new daemon's accept loop is up
    //      (StaleSocket / Unresponsive depending on metadata state)
    //   3. Connection succeeds but the request carries a stale session UUID
    //      (cached by the rmcp tool dispatcher) → daemon returns
    //      "session_mismatch" via the v2 fence in `dispatch_v2`.
    //
    // Without retry, every subsequent MCP tool call returns a structured
    // error to Claude/Codex — a P9 violation in spirit since the agent's
    // entire MCP session becomes unusable until restart.
    //
    // The retry is bounded: at most one re-connect after a brief delay,
    // re-reading daemon metadata so the new session UUID is picked up.
    // We do NOT retry indefinitely — a hard-down daemon must surface an
    // error eventually so the caller can fall back.
    let result = proxy_daemon_result_no_spawn(root, cmd, &args).await;

    // Pass-33: if both retries failed because the daemon is gone (not
    // because of a session mismatch or a transient stall), auto-spawn a
    // fresh daemon and try one final time. Phase 3's `mati daemon stop`
    // cycles for repair/init left the daemon unrun, breaking every MCP
    // tool call until manual restart — this closes that hole.
    //
    // Only NotRunning/StaleSocket are eligible: Unresponsive means
    // ensure_daemon has its own SIGTERM-and-cleanup recovery path that
    // would conflict with our retry, and Ok / session-mismatch don't
    // need a spawn.
    if matches!(
        &result,
        ProxyDaemonResult::NotRunning | ProxyDaemonResult::StaleSocket
    ) && super::daemon_lifecycle::ensure_daemon(root).await
    {
        match proxy_daemon_result_once(root, cmd, &args).await {
            AttemptOutcome::Final(r) | AttemptOutcome::Retryable(r) => return r,
        }
    }

    result
}

/// Inner: the original two-attempt retry without auto-spawn. Extracted so
/// `daemon_lifecycle::ensure_daemon`'s probe can call this without
/// triggering its own auto-spawn (which would loop indefinitely).
pub(crate) async fn proxy_daemon_result_no_spawn(
    root: &Path,
    cmd: &str,
    args: &serde_json::Value,
) -> ProxyDaemonResult {
    match proxy_daemon_result_once(root, cmd, args).await {
        AttemptOutcome::Final(result) => result,
        AttemptOutcome::Retryable(_) => {
            // Brief settle — give the new daemon time to bind socket and
            // publish metadata. 100ms is generous; daemon startup is ~50ms.
            tokio::time::sleep(Duration::from_millis(100)).await;
            match proxy_daemon_result_once(root, cmd, args).await {
                AttemptOutcome::Final(result) | AttemptOutcome::Retryable(result) => result,
            }
        }
    }
}

/// Outcome of a single `proxy_daemon_result` attempt.
///
/// `Retryable` carries the result the caller would have returned if no
/// retry were attempted — used as the fallback if the second attempt also
/// fails. This keeps the original error shape stable for callers that
/// distinguish StaleSocket vs Unresponsive vs structured session_mismatch.
enum AttemptOutcome {
    Final(ProxyDaemonResult),
    Retryable(ProxyDaemonResult),
}

async fn proxy_daemon_result_once(
    root: &Path,
    cmd: &str,
    args: &serde_json::Value,
) -> AttemptOutcome {
    // Build v2 request from v1-style (cmd, args) using the same mapping
    // as cli::daemon::daemon_result. Pure-reads only — mutating callers
    // must use [`proxy_daemon_v2`] with a typed Command (see pass-29).
    let v2_cmd = super::protocol::v1_to_v2_command(cmd, args);
    proxy_daemon_send_v2(root, v2_cmd).await
}

/// Send a typed v2 [`super::protocol::Command`] to the daemon socket.
///
/// Mirrors [`proxy_daemon_result`] for callers (currently the MCP Socket-
/// backend `mem_set` path) that have moved to typed commands and would
/// otherwise have to round-trip through the legacy v1 mapper, which has
/// no entries for mutating commands and panics on them.
///
/// Bounded auto-reconnect mirrors `proxy_daemon_result` so a daemon
/// restart during an active session is recovered transparently.
pub(crate) async fn proxy_daemon_v2(
    root: &Path,
    cmd: super::protocol::Command,
) -> ProxyDaemonResult {
    // Serialize once — every retry uses the same wire bytes.
    let v2_cmd = match serde_json::to_value(&cmd) {
        Ok(v) => v,
        Err(_) => return ProxyDaemonResult::Unresponsive,
    };

    let result = match proxy_daemon_send_v2(root, v2_cmd.clone()).await {
        AttemptOutcome::Final(result) => result,
        AttemptOutcome::Retryable(_) => {
            tokio::time::sleep(Duration::from_millis(100)).await;
            match proxy_daemon_send_v2(root, v2_cmd.clone()).await {
                AttemptOutcome::Final(result) | AttemptOutcome::Retryable(result) => result,
            }
        }
    };

    // Pass-33: parallel auto-spawn for the typed-Command path. Same
    // policy as `proxy_daemon_result`: if the two retries failed because
    // the daemon is gone, ensure_daemon spawns one and we try once more.
    if matches!(
        &result,
        ProxyDaemonResult::NotRunning | ProxyDaemonResult::StaleSocket
    ) && super::daemon_lifecycle::ensure_daemon(root).await
    {
        match proxy_daemon_send_v2(root, v2_cmd).await {
            AttemptOutcome::Final(r) | AttemptOutcome::Retryable(r) => return r,
        }
    }

    result
}

/// Inner socket transaction: connect, send a pre-built v2 command JSON,
/// read the response. Shared between v1-style and typed-Command callers
/// so the connect/refused/session-mismatch policy stays identical.
async fn proxy_daemon_send_v2(root: &Path, v2_cmd: serde_json::Value) -> AttemptOutcome {
    let sock_path = root.join("mati.sock");

    if sock_path.as_os_str().len() > UNIX_SOCK_PATH_MAX {
        tracing::warn!(
            path = %sock_path.display(),
            "mcp proxy: socket path exceeds Unix limit"
        );
        // Path-length violation is not transient — never retry.
        return AttemptOutcome::Final(ProxyDaemonResult::NotRunning);
    }

    if !sock_path.exists() {
        // Socket missing — daemon may be mid-restart. Retry once.
        return AttemptOutcome::Retryable(ProxyDaemonResult::NotRunning);
    }

    let stream = match UnixStream::connect(&sock_path).await {
        Ok(s) => s,
        Err(e) => {
            let is_refused = e.kind() == std::io::ErrorKind::ConnectionRefused;
            if is_refused {
                // Socket refused — use the metadata + PID liveness protocol
                // to decide whether to clean up. Never blindly remove.
                use super::metadata::{self as meta, StaleCheckResult};
                match meta::check_and_cleanup_stale(root) {
                    StaleCheckResult::StaleRemoved | StaleCheckResult::Clean => {
                        return AttemptOutcome::Retryable(ProxyDaemonResult::StaleSocket);
                    }
                    StaleCheckResult::OrphanSocket => {
                        // No metadata + ECONNREFUSED → stale
                        let _ = std::fs::remove_file(&sock_path);
                        return AttemptOutcome::Retryable(ProxyDaemonResult::StaleSocket);
                    }
                    StaleCheckResult::LiveDaemon { .. } => {
                        // PID alive but socket refused — daemon is starting or broken
                        return AttemptOutcome::Retryable(ProxyDaemonResult::Unresponsive);
                    }
                }
            }
            return AttemptOutcome::Retryable(ProxyDaemonResult::NotRunning);
        }
    };

    // Read daemon metadata fresh per attempt so a session UUID rotated by
    // a daemon restart between attempt 1 and attempt 2 is picked up.
    let daemon_session = super::metadata::read_metadata(root)
        .map(|m| m.session)
        .unwrap_or_else(uuid::Uuid::nil);
    let request = serde_json::json!({
        "v": super::protocol::PROTOCOL_VERSION,
        "id": uuid::Uuid::new_v4(),
        "session": daemon_session,
        "cmd": v2_cmd,
    });

    let (reader, mut writer) = stream.into_split();
    let mut bytes = match serde_json::to_vec(&request) {
        Ok(b) => b,
        Err(_) => return AttemptOutcome::Final(ProxyDaemonResult::Unresponsive),
    };
    bytes.push(b'\n');

    if writer.write_all(&bytes).await.is_err() {
        return AttemptOutcome::Retryable(ProxyDaemonResult::Unresponsive);
    }
    if writer.shutdown().await.is_err() {
        return AttemptOutcome::Retryable(ProxyDaemonResult::Unresponsive);
    }

    let mut buf_reader = BufReader::new(reader);
    let mut line = String::new();
    match tokio::time::timeout(Duration::from_secs(2), buf_reader.read_line(&mut line)).await {
        Ok(Ok(n)) if n > 0 => {}
        _ => return AttemptOutcome::Retryable(ProxyDaemonResult::Unresponsive),
    }

    // Parse v2 Response and convert to v1-compatible envelope for callers.
    let resp: serde_json::Value = match serde_json::from_str(line.trim()) {
        Ok(v) => v,
        Err(_) => return AttemptOutcome::Final(ProxyDaemonResult::Unresponsive),
    };

    match resp.get("status").and_then(|s| s.as_str()) {
        Some("ok") => {
            let data = resp.get("data").cloned().unwrap_or(serde_json::Value::Null);
            AttemptOutcome::Final(ProxyDaemonResult::Ok(
                serde_json::json!({"ok": true, "v": 2, "data": data}),
            ))
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
            let envelope = serde_json::json!({
                "ok": false, "v": 2, "error": message, "code": code
            });
            // Session mismatch is the canonical "daemon restarted, your
            // cached session is stale" signal — see dispatch_v2.rs's fence
            // and the symmetric handling in cli::daemon::send_v2_raw. The
            // retry will re-read metadata and pick up the new session UUID.
            if code == "session_mismatch" {
                tracing::debug!(
                    "mcp proxy: session mismatch — daemon may have restarted, will retry"
                );
                AttemptOutcome::Retryable(ProxyDaemonResult::Ok(envelope))
            } else {
                AttemptOutcome::Final(ProxyDaemonResult::Ok(envelope))
            }
        }
        _ => AttemptOutcome::Retryable(ProxyDaemonResult::Unresponsive),
    }
}

// cleanup_stale_pid and local is_pid_alive removed — callers now use
// metadata::check_and_cleanup_stale which centralizes PID liveness checks.

// ── Daemon socket — hook script bridge ───────────────────────────────────────

/// Unix domain socket path length limit (macOS-compatible).
///
/// Public so the parallel daemon path in `cli::daemon` shares the same
/// value — preventing one path's bound from drifting from the other's.
pub const UNIX_SOCK_PATH_MAX: usize = 104;

/// Max wait for a complete request line per connection.
const READ_TIMEOUT: Duration = Duration::from_secs(3);

/// Maximum number of daemon-socket connections handled concurrently.
///
/// A flood beyond this limit blocks at `accept` (TCP backlog absorbs the
/// surplus); this gives natural backpressure rather than unbounded memory
/// use. 64 is generous for a per-user daemon — typical hook traffic is
/// O(1) concurrent. Public so `cli::daemon` shares the same bound.
pub const MAX_CONCURRENT_CONNECTIONS: usize = 64;

/// Maximum time the boot-time auto-drain (dirty-marker queue) can run
/// before we give up and proceed to serve. Prevents a pathological dirty
/// queue from blocking daemon startup. The dirty marker stays set; the
/// user can run `mati repair` manually.
///
/// Public so `cli::daemon::run_daemon_start` can share the same ceiling.
pub const AUTO_DRAIN_TIMEOUT: Duration = Duration::from_secs(10);

/// Race-free shutdown signal for daemon-socket loops.
///
/// `signal()` is idempotent and `wait()` resolves immediately if the signal
/// has already fired. The `enable()` pattern on `Notify::notified()`
/// registers the future before the flag check, so a `signal()` race between
/// flag-set and notify-fire cannot strand a waiter.
///
/// Shared with `cli::daemon` so both the embedded MCP-server socket loop
/// and the headless `mati daemon start` loop use identical shutdown
/// semantics.
#[derive(Default)]
pub struct Shutdown {
    flag: std::sync::atomic::AtomicBool,
    notify: tokio::sync::Notify,
}

impl Shutdown {
    pub fn new() -> Self {
        Self::default()
    }

    /// Idempotent — safe to call multiple times. Wakes every active waiter.
    pub fn signal(&self) {
        self.flag.store(true, std::sync::atomic::Ordering::SeqCst);
        self.notify.notify_waiters();
    }

    pub fn is_set(&self) -> bool {
        // SeqCst (matching the store): defense-in-depth correctness on
        // weakly-ordered architectures (ARM/POWER). Without it, the load
        // would rely on Notify's internal mutex acquire to synchronize
        // with `signal()`'s store — which is the pattern in our `wait()`
        // body and works in practice, but depends on Notify's
        // implementation detail. Explicit SC pairing is cheap (one
        // memory barrier at most) and removes the implicit dependency.
        self.flag.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Future resolves once `signal()` has been called. Safe to call
    /// repeatedly; safe to race with concurrent `signal()`.
    pub async fn wait(&self) {
        let notified = self.notify.notified();
        tokio::pin!(notified);
        // Register the receiver BEFORE the flag check so a `signal()` that
        // fires between check and notify cannot be missed.
        notified.as_mut().enable();
        if self.is_set() {
            return;
        }
        notified.await;
    }
}

/// Daemon protocol version (must match `cli::daemon::PROTOCOL_VERSION`).
const PROTOCOL_VERSION: u32 = 1;

#[derive(Debug, Deserialize)]
pub(crate) struct SocketRequest {
    pub cmd: String,
    #[allow(dead_code)] // Wire protocol field — must exist for deserialization
    #[serde(default, rename = "v")]
    pub version: Option<u32>,
    #[serde(default)]
    pub args: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub(crate) struct SocketResponse {
    pub(crate) ok: bool,
    #[serde(rename = "v")]
    version: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) data: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) error: Option<String>,
}

impl SocketResponse {
    pub(crate) fn ok(data: serde_json::Value) -> Self {
        Self {
            ok: true,
            version: PROTOCOL_VERSION,
            data: Some(data),
            error: None,
        }
    }
    pub(crate) fn err(msg: impl Into<String>) -> Self {
        Self {
            ok: false,
            version: PROTOCOL_VERSION,
            data: None,
            error: Some(msg.into()),
        }
    }
}

pub async fn socket_handle_connection(
    graph: Arc<tokio::sync::RwLock<Graph>>,
    repo_root: &Path,
    stream: UnixStream,
    peer: super::metadata::PeerContext,
    daemon_session: uuid::Uuid,
) -> Result<()> {
    use super::protocol::MAX_FRAME_SIZE;
    use tokio::io::AsyncReadExt;

    let (reader, mut writer) = stream.into_split();
    let mut buf = String::new();

    // Cap the read at MAX_FRAME_SIZE + 1 bytes so the allocation is bounded
    // before any JSON parsing occurs. If the client sends more data than
    // MAX_FRAME_SIZE before the newline delimiter, `read_line` will stop at
    // the take limit and the size check below will reject the request.
    let limited = reader.take(MAX_FRAME_SIZE as u64 + 1);
    let mut buf_reader = BufReader::new(limited);
    match tokio::time::timeout(READ_TIMEOUT, buf_reader.read_line(&mut buf)).await {
        Ok(Ok(0)) => return Ok(()),
        Ok(Ok(_)) => {}
        Ok(Err(e)) => anyhow::bail!("read error: {e}"),
        Err(_) => anyhow::bail!("read timeout"),
    }

    if buf.len() > MAX_FRAME_SIZE {
        let resp = super::protocol::Response::err(
            uuid::Uuid::nil(),
            super::protocol::ErrorCode::FrameTooLarge,
            format!("request exceeds {MAX_FRAME_SIZE} byte limit"),
        );
        let json = serde_json::to_string(&resp)?;
        writer.write_all(json.as_bytes()).await?;
        writer.write_all(b"\n").await?;
        writer.flush().await?;
        return Ok(());
    }

    let trimmed = buf.trim();

    // V2 protocol ONLY — no v1 fallback on the public wire.
    // The v2 format requires `id` (UUID), `session` (UUID), and `cmd` as
    // a tagged object with `type`. If decode fails, the request is rejected
    // with a protocol error — there is no legacy v1 dispatch path.
    let v2_req = match serde_json::from_str::<super::protocol::Request>(trimmed) {
        Ok(r) => r,
        Err(e) => {
            // Return a v2-shaped error. Use nil UUID since we can't extract
            // the request ID from a malformed payload.
            let resp = super::protocol::Response::err(
                uuid::Uuid::nil(),
                super::protocol::ErrorCode::MalformedRequest,
                format!("invalid v2 request: {e}"),
            );
            let json = serde_json::to_string(&resp)?;
            writer.write_all(json.as_bytes()).await?;
            writer.write_all(b"\n").await?;
            writer.flush().await?;
            return Ok(());
        }
    };

    let ctx = super::dispatch_v2::RequestContext {
        peer,
        daemon_session,
        repo_root: repo_root.to_path_buf(),
    };
    let resp = super::dispatch_v2::dispatch_v2(&graph, &ctx, v2_req).await;
    let json = serde_json::to_string(&resp)?;
    writer.write_all(json.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;
    Ok(())
}

/// Build a `RequestContext` for the in-process v1 socket_dispatch path.
///
/// The wire layer (`socket_handle_connection`) carries authentic peer
/// credentials and the daemon session UUID; v1 callers are in-process
/// (e.g. tests), so they synthesize a context with the current process'
/// identity. Used by the mem_* arms which now delegate to native handlers.
fn build_v1_dispatch_ctx(repo_root: &Path) -> super::dispatch_v2::RequestContext {
    super::dispatch_v2::RequestContext {
        peer: super::metadata::PeerContext {
            uid: super::metadata::current_euid(),
            pid: Some(std::process::id()),
        },
        daemon_session: uuid::Uuid::nil(),
        repo_root: repo_root.to_path_buf(),
    }
}

pub(crate) async fn socket_dispatch(
    graph: &Arc<tokio::sync::RwLock<Graph>>,
    repo_root: &Path,
    req: &SocketRequest,
) -> SocketResponse {
    use crate::store::session as sess;

    match req.cmd.as_str() {
        "ping" => SocketResponse::ok(serde_json::Value::String("pong".into())),

        // Live daemon metrics snapshot — per-command counters, error rates,
        // and p50/p95/p99 latencies. Pure read, no side effects, no audit.
        // Returns `null` if the global metrics handle was never initialized
        // (which only happens in tests that bypass `serve`).
        "metrics" => match super::metrics::snapshot() {
            Some(snap) => match serde_json::to_value(&snap) {
                Ok(v) => SocketResponse::ok(v),
                Err(e) => SocketResponse::err(format!("metrics serialize: {e}")),
            },
            None => SocketResponse::ok(serde_json::Value::Null),
        },

        // ── MCP tool commands ────────────────────────────────────────────
        //
        // γ-C4: the wire layer (`socket_handle_connection`) accepts only v2
        // requests, which route MemGet / MemQuery / MemBootstrap / MemSet
        // through `dispatch_v2` to the native handlers in `mcp::handlers`.
        // These v1 arms are reachable only via in-process callers — they
        // dispatch directly to the same canonical handlers so v1 and v2
        // paths cannot drift.
        "mem_get" => {
            let params = match serde_json::from_value::<MemGetParams>(req.args.clone()) {
                Ok(p) => p,
                Err(e) => return SocketResponse::err(format!("invalid mem_get args: {e}")),
            };
            let input = super::protocol::MemGetInput { key: params.key };
            let ctx = build_v1_dispatch_ctx(repo_root);
            let g = graph.read().await;
            match super::handlers::handle_mem_get(
                g.store(),
                graph,
                &ctx,
                uuid::Uuid::new_v4(),
                &input,
            )
            .await
            {
                Ok(v) => SocketResponse::ok(serde_json::Value::String(
                    serde_json::to_string_pretty(&v).unwrap_or_else(|_| "{}".into()),
                )),
                Err((_code, msg)) => SocketResponse::err(msg),
            }
        }

        "mem_query" => {
            let params = match serde_json::from_value::<MemQueryParams>(req.args.clone()) {
                Ok(p) => p,
                Err(e) => return SocketResponse::err(format!("invalid mem_query args: {e}")),
            };
            let mode = match params.mode.as_str() {
                "text" => super::protocol::QueryMode::Text,
                "tag" => super::protocol::QueryMode::Tag,
                "graph" => super::protocol::QueryMode::Graph,
                "semantic" => super::protocol::QueryMode::Semantic,
                other => {
                    return SocketResponse::err(format!(
                        "unknown mode: {other}. Valid modes: text, tag, graph, semantic"
                    ));
                }
            };
            let input = super::protocol::MemQueryInput {
                query: params.query,
                mode,
                limit: params.limit as u32,
            };
            let g = graph.read().await;
            match super::handlers::handle_mem_query(g.store(), &g, &input).await {
                Ok(v) => SocketResponse::ok(serde_json::Value::String(
                    serde_json::to_string_pretty(&v).unwrap_or_else(|_| "{}".into()),
                )),
                Err((_code, msg)) => SocketResponse::err(msg),
            }
        }

        "mem_bootstrap" => {
            let params = match serde_json::from_value::<MemBootstrapParams>(req.args.clone()) {
                Ok(p) => p,
                Err(e) => return SocketResponse::err(format!("invalid mem_bootstrap args: {e}")),
            };
            let input = super::protocol::MemBootstrapInput {
                context_files: params.context_files,
            };
            let ctx = build_v1_dispatch_ctx(repo_root);
            let g = graph.read().await;
            match super::handlers::handle_mem_bootstrap(
                g.store(),
                &g,
                graph,
                &ctx,
                uuid::Uuid::new_v4(),
                &input,
            )
            .await
            {
                Ok(s) => SocketResponse::ok(serde_json::Value::String(s)),
                Err((_code, msg)) => SocketResponse::err(msg),
            }
        }

        "mem_set" => {
            let params = match serde_json::from_value::<MemSetParams>(req.args.clone()) {
                Ok(p) => p,
                Err(e) => return SocketResponse::err(format!("invalid mem_set args: {e}")),
            };
            let ctx = build_v1_dispatch_ctx(repo_root);
            let response =
                super::handlers::handle_mem_set(graph, &ctx, uuid::Uuid::new_v4(), &params).await;
            return SocketResponse::ok(serde_json::Value::String(response));
        }

        // ── Hook commands (store-only) ─────────────────────────────────
        // Acquire a short-lived read lock for store access. The lock is
        // released at the end of each arm — no risk of deadlock.
        "get" => {
            let key = match req.args.get("key").and_then(|v| v.as_str()) {
                Some(k) => k,
                None => return SocketResponse::err("missing args.key"),
            };
            let g = graph.read().await;
            let store = g.store();
            match store.get(key).await {
                Ok(Some(record)) => {
                    let confirmed = record
                        .payload_as::<crate::store::GotchaRecord>()
                        .map(|g| g.confirmed)
                        .unwrap_or(false);
                    match serde_json::to_value(&record) {
                        Ok(mut val) => {
                            if let Some(obj) = val.as_object_mut() {
                                obj.insert(
                                    "confirmed".to_string(),
                                    serde_json::Value::Bool(confirmed),
                                );
                            }
                            SocketResponse::ok(val)
                        }
                        Err(e) => SocketResponse::err(format!("serialize: {e}")),
                    }
                }
                Ok(None) => SocketResponse::ok(serde_json::Value::Null),
                Err(e) => SocketResponse::err(format!("store: {e}")),
            }
        }

        // ── Internal hook-decide bulk command ────────────────────────────
        // Returns file record + all linked gotcha records + consultation
        // status in a single round-trip. NOT an MCP tool.
        "hook_evaluate" => {
            let file_key = match req.args.get("file_key").and_then(|v| v.as_str()) {
                Some(k) => k,
                None => return SocketResponse::err("missing args.file_key"),
            };
            let include_recent = req
                .args
                .get("include_recent")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            let g = graph.read().await;
            let store = g.store();

            // 1. Fetch file record. Distinguish Ok(None) from Err.
            let (file_record, store_error) = match store.get(file_key).await {
                Ok(Some(r)) => (serde_json::to_value(&r).ok(), false),
                Ok(None) => (None, false),
                Err(e) => {
                    tracing::warn!("hook_evaluate: store.get({file_key}) failed: {e}");
                    (None, true)
                }
            };

            // 2. Fetch all linked gotcha records.
            //
            // The canonical link is `file_record.payload.gotcha_keys`, written
            // atomically by `compute_file_link_updates`. But CLAUDE.md flags
            // this field as a *derived* index that can drift from the
            // canonical `gotcha:*` records (e.g. if a gotcha was created
            // before the file record existed, or if a partial-write left the
            // file link stale). To make enforcement robust against that
            // drift, we union three sources:
            //   (a) `file_record.payload.gotcha_keys`               (primary)
            //   (b) in-memory graph edges `HasGotcha` from file_key  (secondary)
            //   (c) reverse scan of `gotcha:*` records whose
            //       `affected_files` contains the relative path     (fallback)
            // Source (c) is bounded by the active-gotcha count and
            // short-circuited when (a) or (b) already produced results, so
            // it does not add cost on the hot path.
            let mut gotcha_records = serde_json::Map::new();
            let mut gotcha_error = false;
            let mut linked_keys: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();

            if let Some(ref fr) = file_record {
                if let Some(keys) = fr
                    .pointer("/payload/gotcha_keys")
                    .and_then(|v| v.as_array())
                {
                    for gk in keys {
                        if let Some(key_str) = gk.as_str() {
                            linked_keys.insert(key_str.to_string());
                        }
                    }
                }
            }

            // (b) Graph-edge fallback. Loaded at boot from `graph:edge:*`,
            // independent of the file record's denormalized list.
            for nkey in g.neighbors(file_key, &crate::graph::EdgeKind::HasGotcha) {
                linked_keys.insert(nkey);
            }

            // (c) Canonical reverse-lookup fallback. Only run when both
            // derived indexes were empty AND a file record exists — covers
            // the "file record present but gotcha_keys never synced" drift
            // path that CLAUDE.md documents as a known trap. Bounded scan
            // strips the relative path from the file_key once.
            if linked_keys.is_empty() && file_record.is_some() {
                let rel_path = file_key.strip_prefix("file:").unwrap_or(file_key);
                if let Ok(all_gotchas) = store.scan_prefix("gotcha:").await {
                    for r in all_gotchas {
                        if !matches!(r.lifecycle, crate::store::RecordLifecycle::Active) {
                            continue;
                        }
                        if let Some(g) = r.payload_as::<crate::store::GotchaRecord>() {
                            if g.affected_files.iter().any(|af| af == rel_path) {
                                linked_keys.insert(r.key.clone());
                            }
                        }
                    }
                }
            }

            for key_str in &linked_keys {
                match store.get(key_str).await {
                    Ok(Some(grec)) => {
                        // Skip tombstoned gotchas so they never feed into enforcement.
                        if !matches!(grec.lifecycle, crate::store::RecordLifecycle::Active) {
                            continue;
                        }
                        // Inline confirmed flag (same as "get" handler).
                        let confirmed = grec
                            .payload_as::<crate::store::GotchaRecord>()
                            .map(|g| g.confirmed)
                            .unwrap_or(false);
                        if let Ok(mut val) = serde_json::to_value(&grec) {
                            if let Some(obj) = val.as_object_mut() {
                                obj.insert(
                                    "confirmed".to_string(),
                                    serde_json::Value::Bool(confirmed),
                                );
                            }
                            gotcha_records.insert(key_str.clone(), val);
                        }
                    }
                    Ok(None) => {}
                    Err(e) => {
                        tracing::warn!("hook_evaluate: store.get({key_str}) failed: {e}");
                        gotcha_error = true;
                    }
                }
            }

            // Project the unified gotcha_keys back into the returned
            // file_record so decide.rs::evaluate (which iterates
            // `payload.gotcha_keys`) sees every gotcha we just unioned —
            // not just the ones the canonical link recorded.
            let file_record = if let Some(mut fr) = file_record {
                if !gotcha_records.is_empty() {
                    if let Some(payload) = fr.pointer_mut("/payload") {
                        if let Some(obj) = payload.as_object_mut() {
                            let keys: Vec<serde_json::Value> = gotcha_records
                                .keys()
                                .map(|k| serde_json::Value::String(k.clone()))
                                .collect();
                            obj.insert(
                                "gotcha_keys".to_string(),
                                serde_json::Value::Array(keys),
                            );
                        }
                    }
                }
                Some(fr)
            } else {
                None
            };

            // 3. Consultation status.
            let consulted = sess::check_consulted(store, file_key)
                .await
                .unwrap_or(false);
            let consulted_recent = if include_recent {
                sess::check_consulted_recent(store, file_key, 900)
                    .await
                    .unwrap_or(false)
            } else {
                false
            };

            SocketResponse::ok(serde_json::json!({
                "file_key": file_key,
                "file_record": file_record,
                "gotcha_records": gotcha_records,
                "consulted": consulted,
                "consulted_recent": consulted_recent,
                "store_error": store_error,
                "gotcha_error": gotcha_error,
            }))
        }

        "log_hit" => {
            let key = match req.args.get("key").and_then(|v| v.as_str()) {
                Some(k) => k,
                None => return SocketResponse::err("missing args.key"),
            };
            let g = graph.read().await;
            if let Err(e) = sess::log_hit(g.store(), key).await {
                tracing::warn!("daemon socket log_hit: {e}");
            }
            SocketResponse::ok(serde_json::Value::Null)
        }

        "log_miss" => {
            let key = match req.args.get("key").and_then(|v| v.as_str()) {
                Some(k) => k,
                None => return SocketResponse::err("missing args.key"),
            };
            let g = graph.read().await;
            if let Err(e) = sess::log_miss(g.store(), key).await {
                tracing::warn!("daemon socket log_miss: {e}");
            }
            SocketResponse::ok(serde_json::Value::Null)
        }

        "log_compliance_miss" => {
            let key = match req.args.get("key").and_then(|v| v.as_str()) {
                Some(k) => k,
                None => return SocketResponse::err("missing args.key"),
            };
            let g = graph.read().await;
            let store = g.store();
            if let Err(e) = sess::log_compliance_miss(store, key).await {
                tracing::warn!("daemon socket log_compliance_miss: {e}");
            }
            // Record Deny enforcement event — best-effort
            let _ = crate::store::enforcement::record_event(
                store,
                crate::store::enforcement::EnforcementEventType::Deny,
                crate::store::enforcement::SubjectKind::File,
                key.to_string(),
                "claude".to_string(),
                None,
                "gotcha_above_threshold".to_string(),
                None,
            )
            .await;
            SocketResponse::ok(serde_json::Value::Null)
        }

        "log_compliance_hit" => {
            let key = match req.args.get("key").and_then(|v| v.as_str()) {
                Some(k) => k,
                None => return SocketResponse::err("missing args.key"),
            };
            let g = graph.read().await;
            let store = g.store();
            if let Err(e) = sess::log_compliance_hit(store, key).await {
                tracing::warn!("daemon socket log_compliance_hit: {e}");
            }
            // Record AllowAfterReceipt enforcement event — best-effort
            let _ = crate::store::enforcement::record_event(
                store,
                crate::store::enforcement::EnforcementEventType::AllowAfterReceipt,
                crate::store::enforcement::SubjectKind::File,
                key.to_string(),
                "claude".to_string(),
                None,
                "receipt_valid".to_string(),
                None,
            )
            .await;
            SocketResponse::ok(serde_json::Value::Null)
        }

        "log_codex_shell_miss" => {
            let key = match req.args.get("key").and_then(|v| v.as_str()) {
                Some(k) => k,
                None => return SocketResponse::err("missing args.key"),
            };
            let g = graph.read().await;
            if let Err(e) = sess::log_codex_shell_miss(g.store(), key).await {
                tracing::warn!("daemon socket log_codex_shell_miss: {e}");
            }
            SocketResponse::ok(serde_json::Value::Null)
        }

        "log_bootstrap" => {
            let key = match req.args.get("key").and_then(|v| v.as_str()) {
                Some(k) => k,
                None => return SocketResponse::err("missing args.key"),
            };
            let g = graph.read().await;
            if let Err(e) = sess::log_bootstrap(g.store(), key).await {
                tracing::warn!("daemon socket log_bootstrap: {e}");
            }
            SocketResponse::ok(serde_json::Value::Null)
        }

        "log_prompt_nudge" => {
            let key = match req.args.get("key").and_then(|v| v.as_str()) {
                Some(k) => k,
                None => return SocketResponse::err("missing args.key"),
            };
            let g = graph.read().await;
            if let Err(e) = sess::log_prompt_nudge(g.store(), key).await {
                tracing::warn!("daemon socket log_prompt_nudge: {e}");
            }
            SocketResponse::ok(serde_json::Value::Null)
        }

        "session_check_consulted" => {
            let key = match req.args.get("key").and_then(|v| v.as_str()) {
                Some(k) => k,
                None => return SocketResponse::err("missing args.key"),
            };
            let g = graph.read().await;
            match sess::check_consulted(g.store(), key).await {
                Ok(found) => SocketResponse::ok(serde_json::Value::Bool(found)),
                Err(e) => SocketResponse::err(format!("store: {e}")),
            }
        }

        "session_check_consulted_recent" => {
            let key = match req.args.get("key").and_then(|v| v.as_str()) {
                Some(k) => k,
                None => return SocketResponse::err("missing args.key"),
            };
            let ttl_secs = req
                .args
                .get("ttl_secs")
                .and_then(|v| v.as_u64())
                .unwrap_or(900);
            let g = graph.read().await;
            match sess::check_consulted_recent(g.store(), key, ttl_secs).await {
                Ok(found) => SocketResponse::ok(serde_json::Value::Bool(found)),
                Err(e) => SocketResponse::err(format!("store: {e}")),
            }
        }

        "session_flush" => {
            let g = graph.read().await;
            if let Err(e) = sess::session_flush(g.store()).await {
                tracing::warn!("daemon socket session_flush: {e}");
            }
            SocketResponse::ok(serde_json::Value::Null)
        }

        "session_harvest" => {
            // Note: uses no-staleness variant because StalenessAnalyzer (git2) is !Send.
            // Git-based staleness analysis runs on the next CLI-path harvest.
            let g = graph.read().await;
            if let Err(e) = sess::session_harvest_no_staleness(g.store()).await {
                tracing::warn!("daemon socket session_harvest: {e}");
            }
            SocketResponse::ok(serde_json::Value::Null)
        }

        "reparse" => {
            let path = match req.args.get("path").and_then(|v| v.as_str()) {
                Some(p) => p,
                None => return SocketResponse::err("missing args.path"),
            };
            let g = graph.read().await;
            if let Err(e) = crate::analysis::reparse::reparse_impl(g.store(), repo_root, path).await
            {
                tracing::warn!("daemon socket reparse: {e}");
            }
            SocketResponse::ok(serde_json::Value::Null)
        }

        "edit_hook" => {
            let path = match req.args.get("path").and_then(|v| v.as_str()) {
                Some(p) => p,
                None => return SocketResponse::err("missing args.path"),
            };
            let file_key = format!("file:{path}");
            let g = graph.read().await;
            let store = g.store();
            if let Err(e) = sess::log_hit(store, &file_key).await {
                tracing::warn!("daemon socket edit_hook: log_hit failed: {e}");
            }
            if let Err(e) = crate::analysis::reparse::reparse_impl(store, repo_root, path).await {
                tracing::warn!("daemon socket edit_hook: reparse failed (non-fatal): {e}");
            }

            // Incremental blast radius update: recompute for the modified file,
            // its direct importers, and the files it imports.
            {
                use crate::analysis::blast_radius::BlastRadius;
                use crate::graph::edges::EdgeKind;

                let mut keys_to_update = vec![file_key.clone()];
                // Files that import this file (their blast radius may change if
                // this file's import list changed).
                keys_to_update.extend(g.neighbors_incoming(&file_key, &EdgeKind::Imports));
                // Files this file imports (this file now counts as an importer).
                keys_to_update.extend(g.neighbors(&file_key, &EdgeKind::Imports));

                for key in keys_to_update {
                    let br = BlastRadius::compute(&key, &g);
                    if let Ok(Some(mut rec)) = store.get(&key).await {
                        if let Some(mut fr) = rec.payload_as::<crate::store::record::FileRecord>() {
                            fr.blast_radius = Some(br);
                            rec.payload = serde_json::to_value(&fr).ok();
                            let _ = store.put(&key, &rec).await;
                        }
                    }
                }
            }

            // Incremental staleness propagation: recompute for the edited
            // file's direct importers and their importers (depth 2 only).
            // Does NOT recompute the full repo — keeps the hook fast.
            {
                let mut affected_keys = vec![file_key.clone()];
                let d1 = g.neighbors_incoming(&file_key, &EdgeKind::Imports);
                for d1k in &d1 {
                    affected_keys.push(d1k.clone());
                    affected_keys.extend(g.neighbors_incoming(d1k, &EdgeKind::Imports));
                }
                // Collect records for just the affected neighborhood
                let mut neighborhood_recs = Vec::new();
                for key in &affected_keys {
                    if let Ok(Some(rec)) = store.get(key).await {
                        neighborhood_recs.push(rec);
                    }
                }
                // Also include the edited file itself as a potential source
                if let Ok(Some(rec)) = store.get(&file_key).await {
                    if !neighborhood_recs.iter().any(|r| r.key == file_key) {
                        neighborhood_recs.push(rec);
                    }
                }
                let propagation =
                    crate::analysis::propagation::compute_propagation(&neighborhood_recs, &g);
                for (key, prop) in &propagation {
                    if let Ok(Some(mut rec)) = store.get(key).await {
                        if let Some(mut fr) = rec.payload_as::<crate::store::record::FileRecord>() {
                            fr.propagated_staleness = Some(prop.clone());
                            rec.payload = serde_json::to_value(&fr).ok();
                            let _ = store.put(key, &rec).await;
                        }
                    }
                }
            }

            SocketResponse::ok(serde_json::Value::Null)
        }

        "doc_capture" => {
            let path = match req.args.get("path").and_then(|v| v.as_str()) {
                Some(p) => p,
                None => return SocketResponse::err("missing args.path"),
            };
            let content = req
                .args
                .get("content")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let g = graph.read().await;
            if let Err(e) = sess::doc_capture(g.store(), path, content).await {
                tracing::warn!("daemon socket doc_capture: {e}");
            }
            SocketResponse::ok(serde_json::Value::Null)
        }

        "scan_prefix" => {
            let prefix = match req.args.get("prefix").and_then(|v| v.as_str()) {
                Some(p) => p,
                None => return SocketResponse::err("missing args.prefix"),
            };
            let g = graph.read().await;
            match g.store().scan_prefix(prefix).await {
                Ok(records) => match serde_json::to_value(&records) {
                    Ok(val) => SocketResponse::ok(val),
                    Err(e) => SocketResponse::err(format!("serialize: {e}")),
                },
                Err(e) => SocketResponse::err(format!("store: {e}")),
            }
        }

        "scan_enforcement_events" => {
            let since_seq = req
                .args
                .get("since_seq")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let until_seq = req
                .args
                .get("until_seq")
                .and_then(|v| v.as_u64())
                .unwrap_or(u64::MAX);
            let g = graph.read().await;
            match crate::store::enforcement::scan_enforcement_events(
                g.store(),
                since_seq,
                until_seq,
            )
            .await
            {
                Ok(events) => match serde_json::to_value(&events) {
                    Ok(val) => SocketResponse::ok(val),
                    Err(e) => SocketResponse::err(format!("serialize: {e}")),
                },
                Err(e) => SocketResponse::err(format!("store: {e}")),
            }
        }

        "put" => {
            use crate::store::Record;
            let key = match req.args.get("key").and_then(|v| v.as_str()) {
                Some(k) => k,
                None => return SocketResponse::err("missing args.key"),
            };
            let record: Record = match req
                .args
                .get("record")
                .and_then(|v| serde_json::from_value(v.clone()).ok())
            {
                Some(r) => r,
                None => return SocketResponse::err("put: invalid record"),
            };
            let g = graph.read().await;
            match g.store().put(key, &record).await {
                Ok(()) => SocketResponse::ok(serde_json::Value::Null),
                Err(e) => SocketResponse::err(format!("store put: {e}")),
            }
        }

        "delete" => {
            let key = match req.args.get("key").and_then(|v| v.as_str()) {
                Some(k) => k,
                None => return SocketResponse::err("missing args.key"),
            };
            let g = graph.read().await;
            match g.store().delete(key).await {
                Ok(()) => SocketResponse::ok(serde_json::Value::Null),
                Err(e) => SocketResponse::err(format!("delete: {e}")),
            }
        }

        "history" => {
            let key = match req.args.get("key").and_then(|v| v.as_str()) {
                Some(k) => k,
                None => return SocketResponse::err("missing args.key"),
            };
            let limit = req.args.get("limit").and_then(|v| v.as_u64()).unwrap_or(50) as usize;
            let g = graph.read().await;
            match g.store().history(key, limit) {
                Ok(entries) => match serde_json::to_value(&entries) {
                    Ok(val) => SocketResponse::ok(val),
                    Err(e) => SocketResponse::err(format!("serialize: {e}")),
                },
                Err(e) => SocketResponse::err(format!("history: {e}")),
            }
        }

        "history_since" => {
            let key = match req.args.get("key").and_then(|v| v.as_str()) {
                Some(k) => k,
                None => return SocketResponse::err("missing args.key"),
            };
            let since_ts = req
                .args
                .get("since_ts")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let limit = req.args.get("limit").and_then(|v| v.as_u64()).unwrap_or(50) as usize;
            let g = graph.read().await;
            match g.store().history_since(key, since_ts, limit) {
                Ok(entries) => match serde_json::to_value(&entries) {
                    Ok(val) => SocketResponse::ok(val),
                    Err(e) => SocketResponse::err(format!("serialize: {e}")),
                },
                Err(e) => SocketResponse::err(format!("history_since: {e}")),
            }
        }

        "gotcha_write" => {
            use crate::store::gotcha_ops::apply_gotcha_write;
            use crate::store::Record;

            let record: Record = match req
                .args
                .get("record")
                .and_then(|v| serde_json::from_value(v.clone()).ok())
            {
                Some(r) => r,
                None => return SocketResponse::err("missing or invalid args.record"),
            };
            let new_files: Vec<String> = req
                .args
                .get("new_files")
                .and_then(|v| serde_json::from_value(v.clone()).ok())
                .unwrap_or_default();
            let old_files: Vec<String> = req
                .args
                .get("old_files")
                .and_then(|v| serde_json::from_value(v.clone()).ok())
                .unwrap_or_default();
            let is_new = req
                .args
                .get("is_new")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            {
                let g = graph.read().await;
                match apply_gotcha_write(g.store(), &record, &old_files, &new_files, is_new).await {
                    Ok(()) => {}
                    Err(e) => return SocketResponse::err(format!("{e}")),
                }
            }

            // Sync the in-memory graph: add HasGotcha edges for newly-affected files,
            // remove edges for files no longer affected. The persistent store was already
            // updated by apply_gotcha_write above; this keeps the in-memory adjacency list
            // in sync so that assemble_context_packet (bootstrap) sees the edges immediately
            // without requiring a daemon restart.
            let record_key = record.key.clone();
            let old_set: std::collections::HashSet<&str> =
                old_files.iter().map(String::as_str).collect();
            let new_set: std::collections::HashSet<&str> =
                new_files.iter().map(String::as_str).collect();
            {
                let mut g = graph.write().await;
                for file_path in new_set.difference(&old_set) {
                    let file_key = format!("file:{file_path}");
                    let _ = g
                        .add_edge(&file_key, EdgeKind::HasGotcha, &record_key)
                        .await;
                }
                for file_path in old_set.difference(&new_set) {
                    let file_key = format!("file:{file_path}");
                    let _ = g
                        .remove_edge(&file_key, &EdgeKind::HasGotcha, &record_key)
                        .await;
                }
            }

            SocketResponse::ok(serde_json::Value::String("written".into()))
        }

        "gotcha_tombstone" => {
            use crate::store::gotcha_ops::apply_gotcha_tombstone;

            let key = match req.args.get("key").and_then(|v| v.as_str()) {
                Some(k) => k,
                None => return SocketResponse::err("missing args.key"),
            };
            if !key.starts_with("gotcha:") {
                return SocketResponse::err("delete action only applies to gotcha: keys");
            }
            // Read affected_files from args if provided, otherwise look up the
            // record to get them. The MCP proxy sends delete without affected_files.
            let mut affected_files: Vec<String> = req
                .args
                .get("affected_files")
                .and_then(|v| serde_json::from_value(v.clone()).ok())
                .unwrap_or_default();

            let g = graph.read().await;
            if affected_files.is_empty() {
                if let Ok(Some(record)) = g.store().get(key).await {
                    if let Some(gotcha) = record.payload_as::<crate::store::GotchaRecord>() {
                        affected_files = gotcha.affected_files;
                    }
                }
            }
            match apply_gotcha_tombstone(g.store(), key, &affected_files).await {
                Ok(()) => SocketResponse::ok(serde_json::Value::String("tombstoned".into())),
                Err(e) => SocketResponse::err(format!("{e}")),
            }
        }

        "gotcha_confirm" => {
            let key = match req.args.get("key").and_then(|v| v.as_str()) {
                Some(k) => k,
                None => return SocketResponse::err("missing args.key"),
            };

            // Read record
            let g = graph.read().await;
            let store = g.store();
            let mut record = match store.get(key).await {
                Ok(Some(r)) => r,
                Ok(None) => return SocketResponse::err(format!("record not found: {key}")),
                Err(e) => return SocketResponse::err(format!("store get: {e}")),
            };

            if record.category != crate::store::record::Category::Gotcha {
                return SocketResponse::err(format!("{key} is not a gotcha record"));
            }

            if !matches!(
                record.lifecycle,
                crate::store::record::RecordLifecycle::Active
            ) {
                return SocketResponse::err(format!(
                    "{key} is tombstoned — cannot confirm a deleted record"
                ));
            }

            // Set confirmed + normalize severity
            if let Some(ref mut payload) = record.payload {
                if let Some(obj) = payload.as_object_mut() {
                    if let Some(sev) = obj
                        .get("severity")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_lowercase())
                    {
                        obj.insert("severity".to_string(), serde_json::Value::String(sev));
                    }
                    obj.insert("confirmed".to_string(), serde_json::Value::Bool(true));
                }
            }

            record.source = crate::store::record::RecordSource::DeveloperManual;
            record.confidence.value = crate::store::record::ConfidenceScore::base_for_source(
                &crate::store::record::RecordSource::DeveloperManual,
            );
            record.confidence.confirmation_count += 1;
            record.quality = crate::health::quality::analyze(&record);

            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            record.updated_at = now;
            record.version.logical_clock += 1;
            record.version.wall_clock = now;

            // Extract affected_files for file-link sync
            let affected_files: Vec<String> = record
                .payload_as::<crate::store::record::GotchaRecord>()
                .map(|g| g.affected_files)
                .unwrap_or_default();

            if let Err(e) = store.put(key, &record).await {
                return SocketResponse::err(format!("store put: {e}"));
            }

            // Sync file:*.gotcha_keys — best-effort
            for file_path in &affected_files {
                let file_key = format!("file:{file_path}");
                if let Ok(Some(mut file_record)) = store.get(&file_key).await {
                    let needs_link = file_record
                        .payload
                        .as_ref()
                        .and_then(|p| p.get("gotcha_keys"))
                        .and_then(|v| v.as_array())
                        .map(|arr| !arr.iter().any(|v| v.as_str() == Some(key)))
                        .unwrap_or(true);
                    if needs_link {
                        if let Some(ref mut payload) = file_record.payload {
                            if let Some(obj) = payload.as_object_mut() {
                                let arr = obj.entry("gotcha_keys").or_insert(serde_json::json!([]));
                                if let Some(arr) = arr.as_array_mut() {
                                    arr.push(serde_json::Value::String(key.to_string()));
                                }
                            }
                        }
                        let _ = store.put(&file_key, &file_record).await;
                    }
                }
            }

            // Propagate confirmation_count to linked file records
            crate::store::gotcha_ops::propagate_confirmation_to_files(store, &affected_files).await;

            // Record ControlChanged::Confirmed enforcement event — best-effort.
            let _ = crate::store::enforcement::record_event(
                store,
                crate::store::enforcement::EnforcementEventType::ControlChanged {
                    change_kind: crate::store::enforcement::ControlChangeKind::Confirmed,
                },
                crate::store::enforcement::SubjectKind::Control,
                key.to_string(),
                "developer".to_string(),
                None,
                "control_confirmed".to_string(),
                None,
            )
            .await;

            SocketResponse::ok(serde_json::json!({"confirmed": true, "key": key}))
        }

        other => SocketResponse::err(format!("unknown command: {other}")),
    }
}

// ── Auto-promotion: MCP server → headless daemon ─────────────────────────────

/// Idle shutdown threshold — wall-clock seconds with no daemon socket requests.
///
/// Shared with `cli::daemon` so both daemon paths use the same idle policy.
pub const IDLE_SHUTDOWN_SECS: u64 = 30 * 60; // 30 min

/// How often to check wall-clock idle time. Shared with `cli::daemon`.
pub const IDLE_CHECK_INTERVAL_SECS: u64 = 5 * 60; // 5 min


// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod shutdown_tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;

    #[tokio::test]
    async fn shutdown_signal_before_wait_returns_immediately() {
        // Pre-signal: subsequent wait must NOT block. Tests the flag-check
        // arm of `wait()` before the notified.await.
        let s = Shutdown::new();
        s.signal();
        // Should return well under timeout — generous bound to avoid CI flake.
        tokio::time::timeout(Duration::from_millis(100), s.wait())
            .await
            .expect("wait must return immediately when already signaled");
        assert!(s.is_set());
    }

    #[tokio::test]
    async fn shutdown_wait_then_signal_wakes_waiter() {
        let s = Arc::new(Shutdown::new());
        let s_clone = Arc::clone(&s);
        let waiter = tokio::spawn(async move { s_clone.wait().await });

        // Give the waiter a moment to register on `notified()`.
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!s.is_set());

        s.signal();

        tokio::time::timeout(Duration::from_millis(200), waiter)
            .await
            .expect("waiter must wake within timeout")
            .expect("waiter task should not panic");
        assert!(s.is_set());
    }

    #[tokio::test]
    async fn shutdown_multiple_concurrent_waiters_all_wake() {
        // The notify_waiters() in signal() must wake every active waiter.
        let s = Arc::new(Shutdown::new());
        let mut handles = Vec::new();
        for _ in 0..16 {
            let s = Arc::clone(&s);
            handles.push(tokio::spawn(async move { s.wait().await }));
        }
        // Let waiters register.
        tokio::time::sleep(Duration::from_millis(20)).await;

        s.signal();

        for h in handles {
            tokio::time::timeout(Duration::from_millis(200), h)
                .await
                .expect("each waiter must wake within timeout")
                .expect("waiter task should not panic");
        }
    }

    #[tokio::test]
    async fn shutdown_signal_is_idempotent() {
        // Second signal must be a no-op. Subsequent waits still return.
        let s = Shutdown::new();
        s.signal();
        s.signal();
        s.signal();
        tokio::time::timeout(Duration::from_millis(100), s.wait())
            .await
            .expect("wait must still return on idempotent re-signal");
    }

    /// Contract test: the bounded-drain pattern in `serve_loop_graceful`
    /// (and the caller-side hammer for `serve_daemon_socket`) relies on
    /// `JoinSet::abort_all()` actually causing in-flight tasks to wake
    /// with a cancellation error, so a subsequent `join_next` loop
    /// completes. If tokio ever changes this — e.g., requires polling
    /// each task explicitly — our drain-timeout fallback silently
    /// regresses to "wait forever after abort_all".
    #[tokio::test]
    async fn joinset_abort_all_makes_drain_finite() {
        let mut set: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();
        // Spawn a task that would otherwise run for a long time.
        set.spawn(async {
            tokio::time::sleep(Duration::from_secs(60)).await;
        });

        // First drain attempt: time out (task is mid-sleep).
        let primary = tokio::time::timeout(Duration::from_millis(100), async {
            while set.join_next().await.is_some() {}
        })
        .await;
        assert!(
            primary.is_err(),
            "primary drain should time out while task is still sleeping"
        );

        // Now abort and drain again — must complete promptly.
        set.abort_all();
        let secondary = tokio::time::timeout(Duration::from_millis(500), async {
            while set.join_next().await.is_some() {}
        })
        .await;
        assert!(
            secondary.is_ok(),
            "drain after abort_all must complete quickly"
        );
        assert!(set.is_empty(), "JoinSet should be empty after drain");
    }

    /// Contract test: the panic-detection logic in `serve_daemon_socket`
    /// (and `cli::daemon::serve_loop_graceful`) relies on tokio's `JoinSet`
    /// reporting panicked tasks via `try_join_next() -> Some(Err(e))` with
    /// `e.is_panic() == true`. If tokio ever changes that, our handler-
    /// panic-is-terminal property silently regresses. Lock it down here.
    #[tokio::test]
    async fn joinset_panics_are_observable_via_try_join_next() {
        let mut set: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();
        set.spawn(async {
            panic!("simulated handler panic");
        });

        // Wait until the panicked task has been catch_unwind'd at the
        // tokio spawn boundary and parked on the JoinSet's completion queue.
        // Poll try_join_next briefly; assert we see the panic.
        let deadline = std::time::Instant::now() + Duration::from_millis(500);
        loop {
            if let Some(res) = set.try_join_next() {
                let err = res.expect_err("panicked task should yield Err");
                assert!(
                    err.is_panic(),
                    "JoinError must report is_panic for panicking task; got: {err:?}"
                );
                return;
            }
            if std::time::Instant::now() >= deadline {
                panic!("try_join_next never reported the panic within 500ms");
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// Race contract — exercises the enable() pattern. A waiter that is
    /// JUST being constructed (between the `notified()` call and the flag
    /// check) must NOT miss a `signal()` that fires concurrently.
    ///
    /// Probabilistic: runs many trials and asserts every one wakes.
    #[tokio::test]
    async fn shutdown_no_lost_signal_under_race() {
        for trial in 0..50 {
            let s = Arc::new(Shutdown::new());
            let s_waiter = Arc::clone(&s);
            let s_signaler = Arc::clone(&s);

            let waiter = tokio::spawn(async move { s_waiter.wait().await });

            // Yield briefly so the waiter has a chance to start `wait()`.
            tokio::task::yield_now().await;

            // Signal at the moment the waiter is racing to register.
            s_signaler.signal();

            tokio::time::timeout(Duration::from_millis(500), waiter)
                .await
                .unwrap_or_else(|_| panic!("trial {trial}: waiter stranded by lost signal"))
                .expect("waiter task should not panic");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::record::{
        Category, ConfidenceScore, FileRecord, GotchaRecord, Priority, QualityScore, Record,
        RecordLifecycle, RecordSource, RecordVersion, StalenessScore,
    };
    use crate::store::Store;

    fn make_gotcha_record(key: &str, files: &[&str]) -> Record {
        let gotcha = GotchaRecord {
            rule: "test rule".into(),
            reason: "test reason".into(),
            severity: Priority::High,
            affected_files: files.iter().map(|s| s.to_string()).collect(),
            ref_url: None,
            discovered_session: 1_000_000,
            confirmed: true,
        };
        Record {
            key: key.to_string(),
            value: "test rule because test reason".into(),
            payload: serde_json::to_value(&gotcha).ok(),
            category: Category::Gotcha,
            priority: Priority::High,
            tags: vec![],
            created_at: 1_000_000,
            updated_at: 1_000_000,
            ref_url: None,
            staleness: StalenessScore::fresh(),
            lifecycle: RecordLifecycle::Active,
            version: RecordVersion {
                device_id: uuid::Uuid::new_v4(),
                logical_clock: 1,
                wall_clock: 1_000_000,
            },
            quality: QualityScore::layer0_default(),
            access_count: 0,
            last_accessed: 0,
            source: RecordSource::DeveloperManual,
            confidence: ConfidenceScore::for_new_record(&RecordSource::DeveloperManual),
            gap_analysis_score: 0.0,
        }
    }

    fn make_file_record(path: &str) -> Record {
        let file = FileRecord {
            path: path.to_string(),
            purpose: String::new(),
            entry_points: vec![],
            imports: vec![],
            gotcha_keys: vec![],
            decision_keys: vec![],
            todos: vec![],
            unsafe_count: 0,
            unwrap_count: 0,
            change_frequency: 0,
            last_author: None,
            is_hotspot: false,
            token_cost_estimate: 0,
            last_modified_session: 0,
            content_hash: None,
            line_count: 0,
            blast_radius: None,
            propagated_staleness: None,
        };
        Record {
            key: format!("file:{path}"),
            value: String::new(),
            payload: serde_json::to_value(&file).ok(),
            category: Category::File,
            priority: Priority::Normal,
            tags: vec![],
            created_at: 1_000_000,
            updated_at: 1_000_000,
            ref_url: None,
            staleness: StalenessScore::fresh(),
            lifecycle: RecordLifecycle::Active,
            version: RecordVersion {
                device_id: uuid::Uuid::new_v4(),
                logical_clock: 1,
                wall_clock: 1_000_000,
            },
            quality: QualityScore::layer0_default(),
            access_count: 0,
            last_accessed: 0,
            source: RecordSource::StaticAnalysis,
            confidence: ConfidenceScore::for_new_record(&RecordSource::StaticAnalysis),
            gap_analysis_score: 0.0,
        }
    }

    fn file_gotcha_keys(record: &Record) -> Vec<String> {
        record
            .payload
            .as_ref()
            .and_then(|p| p.get("gotcha_keys"))
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Test helper: wraps a Store in a Graph + Arc for socket_dispatch.
    ///
    /// Consumes the Store (Graph owns it). Returns the Arc and a reference
    /// to access the store through the graph for assertions.
    async fn make_test_graph(store: Store) -> Arc<tokio::sync::RwLock<Graph>> {
        let graph = Graph::load(store).await.expect("failed to load test graph");
        Arc::new(tokio::sync::RwLock::new(graph))
    }

    async fn dispatch_with_graph(
        graph: &Arc<tokio::sync::RwLock<Graph>>,
        cmd: &str,
        args: serde_json::Value,
    ) -> SocketResponse {
        let req = SocketRequest {
            cmd: cmd.to_string(),
            version: Some(PROTOCOL_VERSION),
            args,
        };
        socket_dispatch(graph, Path::new("/tmp/mati-test"), &req).await
    }

    // ── Regression: gotcha_write via socket syncs file links ─────────────

    #[tokio::test]
    async fn socket_gotcha_write_adds_keys_to_file_records() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();
        store
            .put("file:src/a.rs", &make_file_record("src/a.rs"))
            .await
            .unwrap();
        store
            .put("file:src/b.rs", &make_file_record("src/b.rs"))
            .await
            .unwrap();
        let graph = make_test_graph(store).await;

        let record = make_gotcha_record("gotcha:socket-test", &["src/a.rs", "src/b.rs"]);
        let resp = dispatch_with_graph(&graph, "gotcha_write", serde_json::json!({
            "record": record, "new_files": ["src/a.rs", "src/b.rs"], "old_files": [], "is_new": true,
        })).await;
        assert!(resp.ok, "gotcha_write failed: {:?}", resp.error);

        let g = graph.read().await;
        let a = g.store().get("file:src/a.rs").await.unwrap().unwrap();
        let b = g.store().get("file:src/b.rs").await.unwrap().unwrap();
        assert!(file_gotcha_keys(&a).contains(&"gotcha:socket-test".into()));
        assert!(file_gotcha_keys(&b).contains(&"gotcha:socket-test".into()));
    }

    #[tokio::test]
    async fn socket_gotcha_write_edit_removes_key_from_old_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();
        store
            .put("file:src/a.rs", &make_file_record("src/a.rs"))
            .await
            .unwrap();
        store
            .put("file:src/b.rs", &make_file_record("src/b.rs"))
            .await
            .unwrap();
        let graph = make_test_graph(store).await;

        let record = make_gotcha_record("gotcha:edit-socket", &["src/a.rs"]);
        let resp = dispatch_with_graph(
            &graph,
            "gotcha_write",
            serde_json::json!({
                "record": record, "new_files": ["src/a.rs"], "old_files": [], "is_new": true,
            }),
        )
        .await;
        assert!(resp.ok);

        let record2 = make_gotcha_record("gotcha:edit-socket", &["src/b.rs"]);
        let resp2 = dispatch_with_graph(&graph, "gotcha_write", serde_json::json!({
            "record": record2, "new_files": ["src/b.rs"], "old_files": ["src/a.rs"], "is_new": false,
        })).await;
        assert!(resp2.ok);

        let g = graph.read().await;
        let a = g.store().get("file:src/a.rs").await.unwrap().unwrap();
        let b = g.store().get("file:src/b.rs").await.unwrap().unwrap();
        assert!(!file_gotcha_keys(&a).contains(&"gotcha:edit-socket".into()));
        assert!(file_gotcha_keys(&b).contains(&"gotcha:edit-socket".into()));
    }

    #[tokio::test]
    async fn socket_gotcha_tombstone_removes_keys_from_file_records() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();
        store
            .put("file:src/a.rs", &make_file_record("src/a.rs"))
            .await
            .unwrap();
        store
            .put("file:src/b.rs", &make_file_record("src/b.rs"))
            .await
            .unwrap();
        let graph = make_test_graph(store).await;

        let record = make_gotcha_record("gotcha:tomb-socket", &["src/a.rs", "src/b.rs"]);
        let resp = dispatch_with_graph(&graph, "gotcha_write", serde_json::json!({
            "record": record, "new_files": ["src/a.rs", "src/b.rs"], "old_files": [], "is_new": true,
        })).await;
        assert!(resp.ok);

        let resp2 = dispatch_with_graph(
            &graph,
            "gotcha_tombstone",
            serde_json::json!({
                "key": "gotcha:tomb-socket", "affected_files": ["src/a.rs", "src/b.rs"],
            }),
        )
        .await;
        assert!(resp2.ok, "gotcha_tombstone failed: {:?}", resp2.error);

        let g = graph.read().await;
        let rec = g.store().get("gotcha:tomb-socket").await.unwrap().unwrap();
        assert!(matches!(rec.lifecycle, RecordLifecycle::Tombstoned { .. }));
        let a = g.store().get("file:src/a.rs").await.unwrap().unwrap();
        let b = g.store().get("file:src/b.rs").await.unwrap().unwrap();
        assert!(file_gotcha_keys(&a).is_empty());
        assert!(file_gotcha_keys(&b).is_empty());
    }

    #[tokio::test]
    async fn socket_gotcha_write_rejects_duplicate_key() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();
        let record1 = make_gotcha_record("gotcha:dup-socket", &["src/a.rs"]);
        store.put("gotcha:dup-socket", &record1).await.unwrap();
        let graph = make_test_graph(store).await;

        let record2 = make_gotcha_record("gotcha:dup-socket", &["src/b.rs"]);
        let resp = dispatch_with_graph(
            &graph,
            "gotcha_write",
            serde_json::json!({
                "record": record2, "new_files": ["src/b.rs"], "old_files": [], "is_new": true,
            }),
        )
        .await;
        assert!(!resp.ok, "duplicate key should be rejected");
        assert!(resp
            .error
            .as_deref()
            .unwrap_or("")
            .contains("already exists"));

        let g = graph.read().await;
        let original = g.store().get("gotcha:dup-socket").await.unwrap().unwrap();
        let payload = original.payload_as::<GotchaRecord>().unwrap();
        assert_eq!(payload.affected_files, vec!["src/a.rs"]);
    }

    // ── Wire-level size enforcement ────────────────────────────────────

    #[tokio::test]
    async fn oversized_request_returns_frame_too_large_with_response() {
        use super::super::protocol::MAX_FRAME_SIZE;
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

        let dir = tempfile::TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();
        let graph = make_test_graph(store).await;

        let (client, server) = UnixStream::pair().unwrap();
        let peer = super::super::metadata::PeerContext {
            uid: 501,
            pid: None,
        };

        // Payload larger than MAX_FRAME_SIZE.
        let oversized = "x".repeat(MAX_FRAME_SIZE + 100);
        let payload = format!("{oversized}\n");

        // Split client: write oversized request, then read response.
        let (client_read, client_write) = client.into_split();

        let write_handle = tokio::spawn(async move {
            let mut w = client_write;
            w.write_all(payload.as_bytes()).await.unwrap();
            w.shutdown().await.unwrap();
        });

        let handle_result =
            socket_handle_connection(graph, dir.path(), server, peer, uuid::Uuid::nil()).await;
        assert!(handle_result.is_ok());

        write_handle.await.unwrap();

        // Read the error response from the server.
        let mut reader = tokio::io::BufReader::new(client_read);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        let resp: serde_json::Value = serde_json::from_str(line.trim()).unwrap();

        assert_eq!(resp["status"], "err");
        assert_eq!(resp["code"], "frame_too_large");
        assert!(
            resp["message"]
                .as_str()
                .unwrap()
                .contains(&MAX_FRAME_SIZE.to_string()),
            "error message should mention the size limit"
        );
    }

    #[tokio::test]
    async fn normal_sized_request_is_not_rejected_by_size_check() {
        use super::super::protocol::MAX_FRAME_SIZE;
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

        let dir = tempfile::TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();
        let graph = make_test_graph(store).await;

        let (client, server) = UnixStream::pair().unwrap();
        let peer = super::super::metadata::PeerContext {
            uid: 501,
            pid: None,
        };

        // A valid v2 ping request — well under MAX_FRAME_SIZE.
        let request = serde_json::json!({
            "v": 2,
            "id": uuid::Uuid::new_v4(),
            "session": uuid::Uuid::nil(),
            "cmd": { "type": "ping" }
        });
        let payload = format!("{}\n", serde_json::to_string(&request).unwrap());
        assert!(
            payload.len() < MAX_FRAME_SIZE,
            "test payload should be small"
        );

        let (client_read, client_write) = client.into_split();

        let write_handle = tokio::spawn(async move {
            let mut w = client_write;
            w.write_all(payload.as_bytes()).await.unwrap();
            w.shutdown().await.unwrap();
        });

        let handle_result =
            socket_handle_connection(graph, dir.path(), server, peer, uuid::Uuid::nil()).await;
        assert!(handle_result.is_ok());

        write_handle.await.unwrap();

        // Read response — should be a successful pong, not FrameTooLarge.
        let mut reader = tokio::io::BufReader::new(client_read);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        let resp: serde_json::Value = serde_json::from_str(line.trim()).unwrap();

        assert_eq!(resp["status"], "ok", "ping should succeed, got: {resp}");
    }

    // ── Daemon-restart resilience ──────────────────────────────────────
    //
    // Regression for the smoke-test failure: after a daemon stop+start,
    // the MCP-stdio bridge sees `session_mismatch` (or transient
    // `Unresponsive`) on the first call because its cached daemon session
    // UUID predates the restart. Without retry, every subsequent
    // mem_get/mem_query/mem_bootstrap/mem_set returns a structured error
    // that effectively wedges the agent's MCP session.
    //
    // The fix in `proxy_daemon_result` is one bounded auto-reconnect: the
    // helper re-reads daemon metadata fresh (picking up the new session
    // UUID) and re-issues the request. This test asserts the reconnect
    // succeeds end-to-end and DOES NOT propagate the session_mismatch
    // error envelope to the caller.

    /// Spawn a tiny daemon-substitute that binds the given socket and
    /// answers each connection with the supplied JSON response (one line),
    /// then closes the connection. Returns the JoinHandle so the test can
    /// await it.
    async fn spawn_canned_responder(
        sock_path: std::path::PathBuf,
        responses: Vec<serde_json::Value>,
    ) -> tokio::task::JoinHandle<()> {
        // Bind in this task synchronously so the caller can issue
        // requests immediately without a sleep race.
        let listener = tokio::net::UnixListener::bind(&sock_path).expect("bind responder socket");
        tokio::spawn(async move {
            for resp in responses {
                let (stream, _) = match listener.accept().await {
                    Ok(s) => s,
                    Err(_) => return,
                };
                let (reader, mut writer) = stream.into_split();
                // Drain the request line so the peer's `shutdown()` returns Ok.
                let mut buf_reader = tokio::io::BufReader::new(reader);
                let mut line = String::new();
                let _ = tokio::io::AsyncBufReadExt::read_line(&mut buf_reader, &mut line).await;
                let mut bytes = serde_json::to_vec(&resp).unwrap();
                bytes.push(b'\n');
                let _ = tokio::io::AsyncWriteExt::write_all(&mut writer, &bytes).await;
                let _ = tokio::io::AsyncWriteExt::shutdown(&mut writer).await;
            }
        })
    }

    #[tokio::test]
    async fn mcp_call_after_daemon_restart_does_not_kill_transport() {
        // Scenario: the proxy's first attempt hits a daemon whose session
        // UUID does not match (simulating a daemon restart between two
        // tool calls). The fix retries once, re-reads metadata, and the
        // second attempt succeeds.

        let dir = tempfile::TempDir::new().unwrap();
        let root = dir.path().to_path_buf();
        let sock_path = root.join("mati.sock");

        // Initial daemon session "before restart". The proxy will read
        // this UUID, but our canned responder pretends not to recognize
        // it (returning session_mismatch). After the retry delay, we
        // rotate metadata to a new UUID — exactly what `mati daemon stop`
        // + `mati daemon start` would do in production.
        let session_before = uuid::Uuid::new_v4();
        let session_after = uuid::Uuid::new_v4();

        let meta_before = super::super::metadata::DaemonMetadata {
            pid: std::process::id(),
            session: session_before,
            owner: super::super::metadata::DaemonOwner::Daemon,
        };
        super::super::metadata::publish_metadata(&root, &meta_before).unwrap();

        // Stage two responses on the same socket: the first is a
        // SessionMismatch err (pre-restart daemon view), the second is a
        // successful pong (post-restart daemon view).
        let responder_handle = spawn_canned_responder(
            sock_path.clone(),
            vec![
                serde_json::json!({
                    "v": 2,
                    "id": uuid::Uuid::new_v4(),
                    "status": "err",
                    "code": "session_mismatch",
                    "message": "session mismatch: re-read daemon metadata and retry",
                }),
                serde_json::json!({
                    "v": 2,
                    "id": uuid::Uuid::new_v4(),
                    "status": "ok",
                    "data": "pong",
                }),
            ],
        )
        .await;

        // Concurrent metadata rotation — fires during the retry delay.
        // Mirrors what a real daemon restart does: writes fresh metadata.
        let root_for_rotate = root.clone();
        let rotate_handle = tokio::spawn(async move {
            // Sleep just less than the proxy's 100ms retry settle so the
            // metadata rewrite is committed before the second attempt.
            tokio::time::sleep(Duration::from_millis(20)).await;
            let meta_after = super::super::metadata::DaemonMetadata {
                pid: std::process::id(),
                session: session_after,
                owner: super::super::metadata::DaemonOwner::Daemon,
            };
            super::super::metadata::publish_metadata(&root_for_rotate, &meta_after).unwrap();
        });

        // Wrap in a tokio timeout: if the retry path is missing, the
        // proxy returns the first attempt's envelope without ever
        // dialing the second responder, which would leave the test
        // hanging on the spare canned response. The timeout converts
        // that latent hang into a deterministic failure with a clear
        // error message.
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            super::proxy_daemon_result(&root, "ping", serde_json::json!({})),
        )
        .await
        .expect("proxy_daemon_result should resolve within 5s — retry path appears wedged");

        rotate_handle.await.unwrap();
        // Drop the responder task — the second canned response may go
        // unconsumed in failure modes. Aborting prevents the test from
        // hanging on `responder_handle.await` in failure mode.
        responder_handle.abort();

        // The proxy must transparently recover: caller sees Ok, not the
        // session_mismatch error envelope from the first attempt.
        match result {
            super::ProxyDaemonResult::Ok(v) => {
                let ok = v.get("ok") == Some(&serde_json::Value::Bool(true));
                let code = v.get("code").and_then(|c| c.as_str()).unwrap_or("");
                assert!(
                    ok,
                    "second attempt should succeed after metadata rotation, \
                     but caller saw the first attempt's session_mismatch envelope: \
                     ok={ok} code={code:?} v={v}"
                );
            }
            other => panic!(
                "expected Ok(true) after auto-reconnect, got {other:?}; \
                 the daemon-restart retry path is not engaging"
            ),
        }
    }

    #[tokio::test]
    async fn mcp_call_session_mismatch_no_retry_target_returns_envelope() {
        // Negative-side guard: if the second attempt also fails with the
        // same error (e.g. the daemon was not actually restarted), the
        // proxy still returns the structured error envelope to the
        // caller — it does NOT panic, hang, or close the rmcp transport.
        // This preserves the per-call structured-error discipline that
        // keeps Claude's MCP session alive.

        let dir = tempfile::TempDir::new().unwrap();
        let root = dir.path().to_path_buf();
        let sock_path = root.join("mati.sock");

        let session = uuid::Uuid::new_v4();
        let meta = super::super::metadata::DaemonMetadata {
            pid: std::process::id(),
            session,
            owner: super::super::metadata::DaemonOwner::Daemon,
        };
        super::super::metadata::publish_metadata(&root, &meta).unwrap();

        // Both attempts get a session_mismatch — emulates a daemon that
        // truly cannot be reconciled (wedged in a state the proxy can't
        // recover from).
        let responder_handle = spawn_canned_responder(
            sock_path.clone(),
            vec![
                serde_json::json!({
                    "v": 2,
                    "id": uuid::Uuid::new_v4(),
                    "status": "err",
                    "code": "session_mismatch",
                    "message": "session mismatch (1)",
                }),
                serde_json::json!({
                    "v": 2,
                    "id": uuid::Uuid::new_v4(),
                    "status": "err",
                    "code": "session_mismatch",
                    "message": "session mismatch (2)",
                }),
            ],
        )
        .await;

        let result = tokio::time::timeout(
            Duration::from_secs(5),
            super::proxy_daemon_result(&root, "ping", serde_json::json!({})),
        )
        .await
        .expect("proxy_daemon_result must resolve within 5s");
        responder_handle.abort();

        // The caller MUST get a structured Ok envelope with ok:false +
        // the session_mismatch code, never a panic or transport-killing
        // surprise. socket_call (in tools.rs) renders this to a JSON
        // error string — which is exactly the contract the rmcp loop
        // expects: a String response, not a Result::Err.
        match result {
            super::ProxyDaemonResult::Ok(v) => {
                assert_eq!(v.get("ok"), Some(&serde_json::Value::Bool(false)));
                assert_eq!(
                    v.get("code").and_then(|c| c.as_str()),
                    Some("session_mismatch")
                );
            }
            other => panic!("expected structured Ok envelope, got {other:?}"),
        }
    }

    // ── Pass-29 regression: proxy_daemon_result handles side-effecting reads ──
    //
    // Pre-fix: every Socket-backed `mem_get` and `mem_bootstrap` MCP call
    // panicked the rmcp task at `v1_to_v2_command` (no match arm), which
    // surfaced to the client as `Transport closed` and wedged Phases 6–17
    // of the smoke. The translation layer is the load-bearing artifact
    // — pass 27's mock-UnixListener test bypassed it entirely, so the
    // bug shipped.
    //
    // These tests drive `proxy_daemon_result` with the exact strings
    // tools.rs sends today. Without the new arms in v1_to_v2_command,
    // both panic. With the fix, both return a clean `NotRunning` because
    // the socket doesn't exist — proving the translation succeeded
    // before the connect attempt.

    #[tokio::test]
    async fn proxy_daemon_result_handles_mem_get_translation_no_panic() {
        let dir = tempfile::TempDir::new().unwrap();
        // No socket file present — the call must reach the
        // sock_path.exists() guard, which it cannot do if v1_to_v2_command
        // panics first.
        let result = super::proxy_daemon_result(
            dir.path(),
            "mem_get",
            serde_json::json!({ "key": "file:src/main.rs" }),
        )
        .await;
        assert!(
            matches!(result, super::ProxyDaemonResult::NotRunning),
            "mem_get without daemon must return NotRunning, got {result:?}"
        );
    }

    #[tokio::test]
    async fn proxy_daemon_result_handles_mem_bootstrap_translation_no_panic() {
        let dir = tempfile::TempDir::new().unwrap();
        let result = super::proxy_daemon_result(
            dir.path(),
            "mem_bootstrap",
            serde_json::json!({ "context_files": ["src/lib.rs"] }),
        )
        .await;
        assert!(
            matches!(result, super::ProxyDaemonResult::NotRunning),
            "mem_bootstrap without daemon must return NotRunning, got {result:?}"
        );
    }

    #[tokio::test]
    async fn proxy_daemon_v2_typed_path_handles_mem_set_mutations_no_panic() {
        // The Socket-backend mem_set now takes the typed path. With no
        // daemon present, the typed-Command serialize→connect path must
        // surface as a clean NotRunning, never a panic. This is the
        // load-bearing fence: any future caller that accidentally routes
        // gotcha_upsert through the v1 mapper would fail
        // v1_to_v2_command_no_mutations_silently_accepted in protocol.rs;
        // here we make sure the typed path itself is wired end-to-end.
        let dir = tempfile::TempDir::new().unwrap();
        let cmd = super::super::protocol::Command::GotchaConfirm(
            super::super::protocol::GotchaConfirmInput {
                key: "gotcha:test".into(),
            },
        );
        let result = super::proxy_daemon_v2(dir.path(), cmd).await;
        assert!(
            matches!(result, super::ProxyDaemonResult::NotRunning),
            "typed proxy_daemon_v2 must return NotRunning when daemon is absent, got {result:?}"
        );
    }
}
