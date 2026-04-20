//! MCP stdio server entry point (M-07).
//!
//! `serve()` is the only public function. It opens the store, loads the graph,
//! constructs `MatiServer`, and runs the rmcp stdio transport until the client
//! disconnects.
//!
//! Also binds the Unix daemon socket (`~/.mati/<slug>/mati.sock`) so that hook
//! scripts using `mati get`/`mati ping` can route through the daemon protocol
//! instead of trying to open the SurrealKV store directly (which would fail with
//! a lock error while the MCP server holds the exclusive handle).

use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{ServerCapabilities, ServerInfo};
use rmcp::{tool_handler, ServerHandler, ServiceExt};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

use crate::graph::edges::EdgeKind;
use crate::graph::Graph;
use crate::store::{derive_slug, Store};

use super::tools::MatiServer;
use super::types::{MemBootstrapParams, MemGetParams, MemQueryParams, MemSetParams};

enum ServerOpen {
    Direct(Box<Store>),
    Proxy(PathBuf),
}

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

/// Start the MCP stdio server for the project rooted at `repo_root`.
///
/// Opens the store (with search index rebuild if needed), loads the graph,
/// and serves tools over stdin/stdout until the client disconnects.
///
/// Also binds the daemon Unix socket so hook scripts (`mati ping`, `mati get`)
/// can reach the store without conflicting with the MCP server's exclusive lock.
pub async fn serve(repo_root: &Path) -> Result<()> {
    // Codex may spawn multiple instances of the MCP server concurrently.
    // Only one can acquire the SurrealKV exclusive lock. If the first attempt
    // fails with a lock error, retry a few times with backoff — the other
    // instance may be a transient spawn that exits quickly, or it may be the
    // "winner" that holds the lock for the session lifetime.
    // Retry window must be long enough to outlast transient daemon processes
    // spawned by Codex hooks (try_auto_start) during session startup. These
    // daemons hold the lock for 1-3 seconds before exiting. 8 retries with
    // exponential backoff (250ms→500ms→1s→2s→4s→4s→4s→4s ≈ 16s total) covers
    // the worst case.
    match open_with_retry(repo_root, 8, Duration::from_millis(250)).await? {
        ServerOpen::Direct(store) => {
            // Clear session:consulted:* markers from the previous session.
            // These are written by log_hit and used by pre-read/pre-bash hooks to downgrade
            // deny → allow+context after a mem_get call. They must be scoped to the current
            // session — any leftovers from a previous session would permanently bypass deny.
            if let Ok(keys) = store.scan_keys("session:consulted:").await {
                for k in &keys {
                    let _ = store.delete(k).await;
                }
                if !keys.is_empty() {
                    tracing::debug!(
                        "serve: cleared {} stale session:consulted markers",
                        keys.len()
                    );
                }
            }

            let graph = Graph::load(*store)
                .await
                .context("failed to load knowledge graph")?;

            let graph_arc = Arc::new(tokio::sync::RwLock::new(graph));
            let server = MatiServer::with_graph_arc(Arc::clone(&graph_arc));

            // Spawn the daemon socket listener so hook scripts (mati ping / mati get)
            // can route through this process instead of opening the store directly.
            // Non-fatal: if binding fails, hooks degrade gracefully via mati ping check.
            let repo_root_arc = Arc::new(repo_root.to_path_buf());
            tokio::spawn(serve_daemon_socket(Arc::clone(&graph_arc), repo_root_arc));

            let transport = rmcp::transport::io::stdio();
            let service = server
                .serve(transport)
                .await
                .map_err(|e| anyhow::anyhow!("MCP server initialization failed: {e}"))?;

            service.waiting().await?;

            // MCP client disconnected. Instead of exiting, auto-promote to a
            // headless daemon so subsequent `mati serve` instances (spawned by
            // Codex for the next tool call) can enter proxy mode against this
            // process. The daemon socket is already running in a spawned task.
            //
            // On Claude Code this rarely fires (pipe stays open for the full
            // session). On Codex it fires after every tool call due to the
            // stdio pipe closure bug (openai/codex#5677).
            tracing::info!("mati serve: MCP client disconnected — continuing as daemon");
            wait_for_idle_or_signal().await;

            // Cleanup socket + PID files on exit (same as standalone daemon).
            {
                let g = graph_arc.read().await;
                let root = &g.store().root;
                let _ = std::fs::remove_file(root.join("mati.sock"));
                let _ = std::fs::remove_file(root.join("mati.pid"));
            }
        }
        ServerOpen::Proxy(root) => {
            tracing::info!(
                "mati serve: store locked by another instance, starting socket-backed MCP proxy"
            );
            let transport = rmcp::transport::io::stdio();
            let service = MatiServer::with_socket_root(root)
                .serve(transport)
                .await
                .map_err(|e| anyhow::anyhow!("MCP proxy initialization failed: {e}"))?;

            service.waiting().await?;
        }
    }
    Ok(())
}

pub(crate) fn mati_root_for(repo_root: &Path) -> Result<PathBuf> {
    let slug = derive_slug(repo_root);
    let home = dirs::home_dir().context("cannot determine home directory")?;
    Ok(home.join(".mati").join(slug))
}

pub(crate) async fn proxy_daemon_result(
    root: &Path,
    cmd: &str,
    args: serde_json::Value,
) -> ProxyDaemonResult {
    let sock_path = root.join("mati.sock");

    if sock_path.as_os_str().len() > UNIX_SOCK_PATH_MAX {
        tracing::warn!(
            path = %sock_path.display(),
            "mcp proxy: socket path exceeds Unix limit"
        );
        return ProxyDaemonResult::NotRunning;
    }

    if !sock_path.exists() {
        return ProxyDaemonResult::NotRunning;
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
                        return ProxyDaemonResult::StaleSocket;
                    }
                    StaleCheckResult::OrphanSocket => {
                        // No metadata + ECONNREFUSED → stale
                        let _ = std::fs::remove_file(&sock_path);
                        return ProxyDaemonResult::StaleSocket;
                    }
                    StaleCheckResult::LiveDaemon { .. } => {
                        // PID alive but socket refused — daemon is starting or broken
                        return ProxyDaemonResult::Unresponsive;
                    }
                }
            }
            return ProxyDaemonResult::NotRunning;
        }
    };

    // Build v2 request from v1-style (cmd, args) using the same mapping
    // as cli::daemon::daemon_result.
    let daemon_session = super::metadata::read_metadata(root)
        .map(|m| m.session)
        .unwrap_or_else(uuid::Uuid::nil);
    let v2_cmd = super::protocol::v1_to_v2_command(cmd, &args);
    let request = serde_json::json!({
        "v": super::protocol::PROTOCOL_VERSION,
        "id": uuid::Uuid::new_v4(),
        "session": daemon_session,
        "cmd": v2_cmd,
    });

    let (reader, mut writer) = stream.into_split();
    let mut bytes = match serde_json::to_vec(&request) {
        Ok(b) => b,
        Err(_) => return ProxyDaemonResult::Unresponsive,
    };
    bytes.push(b'\n');

    if writer.write_all(&bytes).await.is_err() {
        return ProxyDaemonResult::Unresponsive;
    }
    if writer.shutdown().await.is_err() {
        return ProxyDaemonResult::Unresponsive;
    }

    let mut buf_reader = BufReader::new(reader);
    let mut line = String::new();
    match tokio::time::timeout(Duration::from_secs(2), buf_reader.read_line(&mut line)).await {
        Ok(Ok(n)) if n > 0 => {}
        _ => return ProxyDaemonResult::Unresponsive,
    }

    // Parse v2 Response and convert to v1-compatible envelope for callers.
    let resp: serde_json::Value = match serde_json::from_str(line.trim()) {
        Ok(v) => v,
        Err(_) => return ProxyDaemonResult::Unresponsive,
    };

    match resp.get("status").and_then(|s| s.as_str()) {
        Some("ok") => {
            let data = resp.get("data").cloned().unwrap_or(serde_json::Value::Null);
            ProxyDaemonResult::Ok(serde_json::json!({"ok": true, "v": 2, "data": data}))
        }
        Some("err") => {
            let message = resp
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("unknown error");
            ProxyDaemonResult::Ok(serde_json::json!({"ok": false, "v": 2, "error": message}))
        }
        _ => ProxyDaemonResult::Unresponsive,
    }
}

/// Open the store, handling lock contention from duplicate MCP server spawns.
///
/// Codex spawns the same MCP server command twice on startup. Only one instance
/// can acquire the SurrealKV exclusive flock — the other gets a lock error.
///
/// If we crash with exit(1) + stderr, Codex records the failure and shows
/// "Tools: (none)" even though the first instance is serving correctly.
///
/// Fix: on lock contention, retry with backoff. If we still can't get the lock
/// after all retries, exit silently (exit 0, no stderr) so Codex doesn't
/// overwrite the successful instance's tool registration with an error state.
async fn open_with_retry(
    repo_root: &Path,
    max_retries: u32,
    initial_delay: Duration,
) -> Result<ServerOpen> {
    let mut delay = initial_delay;
    let mati_root = mati_root_for(repo_root)?;

    // Ensure runtime directory exists with correct permissions.
    if let Err(e) = super::metadata::ensure_runtime_dir(&mati_root) {
        tracing::warn!("ensure_runtime_dir failed: {e}");
    }

    // Clean up stale lock holder from a previous session. If the PID in
    // metadata is dead, remove the socket and PID file so we can acquire
    // the lock directly instead of entering proxy mode against a ghost.
    {
        use super::metadata::{self as meta, StaleCheckResult};
        match meta::check_and_cleanup_stale(&mati_root) {
            StaleCheckResult::Clean | StaleCheckResult::StaleRemoved => {}
            StaleCheckResult::LiveDaemon { .. } => {
                // Live daemon — let the retry loop handle proxy mode.
            }
            StaleCheckResult::OrphanSocket => {
                let _ = std::fs::remove_file(meta::socket_path(&mati_root));
            }
        }
    }

    for attempt in 0..=max_retries {
        match Store::open_and_rebuild(repo_root).await {
            Ok(store) => return Ok(ServerOpen::Direct(Box::new(store))),
            Err(e) => {
                let is_lock = e.chain().any(|cause| {
                    let msg = cause.to_string();
                    msg.contains("already locked") || msg.contains("WouldBlock")
                });
                if !is_lock {
                    return Err(e).context("failed to open mati store");
                }
                if attempt == max_retries {
                    // Enter proxy mode if the lock holder is a known mati
                    // process (owner: "mcp" or "daemon"). Both load the graph
                    // and handle MCP tool commands via the shared socket dispatch.
                    let owner = std::fs::read_to_string(mati_root.join("mati.pid"))
                        .ok()
                        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
                        .and_then(|v| v.get("owner").and_then(|o| o.as_str()).map(String::from))
                        .unwrap_or_default();
                    if owner != "mcp" && owner != "daemon" {
                        return Err(anyhow::anyhow!(
                            "store locked by an unknown process (owner: {owner}).\n\
                             Stop it first: mati daemon stop"
                        ));
                    }
                    return match proxy_daemon_result(&mati_root, "ping", serde_json::json!({}))
                        .await
                    {
                        ProxyDaemonResult::Ok(_) => Ok(ServerOpen::Proxy(mati_root)),
                        other => Err(anyhow::anyhow!(
                            "store locked after retries and no proxy target was reachable: {:?}",
                            other
                        )),
                    };
                }
                tracing::info!(
                    attempt = attempt + 1,
                    max_retries,
                    delay_ms = delay.as_millis() as u64,
                    "store locked by another process, retrying"
                );
                tokio::time::sleep(delay).await;
                delay = delay.saturating_mul(2).min(Duration::from_secs(4));
            }
        }
    }
    unreachable!()
}

// cleanup_stale_pid and local is_pid_alive removed — callers now use
// metadata::check_and_cleanup_stale which centralizes PID liveness checks.

// ── Daemon socket — hook script bridge ───────────────────────────────────────

/// Unix domain socket path length limit (macOS-compatible).
const UNIX_SOCK_PATH_MAX: usize = 104;

/// Max wait for a complete request line per connection.
const READ_TIMEOUT: Duration = Duration::from_secs(3);

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

/// Bind the daemon Unix socket and serve hook requests using the already-open
/// graph/store. Runs until cancelled (MCP server exits). Non-fatal — logs and
/// continues on accept/connection errors.
async fn serve_daemon_socket(
    graph: Arc<tokio::sync::RwLock<Graph>>,
    repo_root: Arc<std::path::PathBuf>,
) {
    let sock_path = {
        let g = graph.read().await;
        g.store().root.join("mati.sock")
    };
    let pid_path = sock_path.with_file_name("mati.pid");

    let sock_len = sock_path.as_os_str().len();
    if sock_len > UNIX_SOCK_PATH_MAX {
        tracing::warn!(
            "daemon socket path too long ({sock_len} > {UNIX_SOCK_PATH_MAX}) — \
             hook scripts will degrade gracefully (mati ping will fail)"
        );
        return;
    }

    // Stale-socket cleanup — only remove if PID is dead or metadata absent.
    {
        use super::metadata::{self as meta, StaleCheckResult};
        let root = sock_path.parent().unwrap_or(std::path::Path::new("."));
        match meta::check_and_cleanup_stale(root) {
            StaleCheckResult::Clean | StaleCheckResult::StaleRemoved => {}
            StaleCheckResult::LiveDaemon { pid, owner, .. } => {
                tracing::warn!(
                    "another mati {owner} (pid {pid}) owns the socket — \
                     skipping embedded daemon socket"
                );
                return;
            }
            StaleCheckResult::OrphanSocket => {
                let _ = std::fs::remove_file(&sock_path);
            }
        }
    }
    let listener = match UnixListener::bind(&sock_path) {
        Ok(l) => l,
        Err(e) => {
            tracing::warn!(
                "mati serve: failed to bind daemon socket at {}: {e}",
                sock_path.display()
            );
            return;
        }
    };
    // Harden socket permissions after bind (before any client can connect).
    if let Err(e) = super::metadata::harden_socket(&sock_path) {
        tracing::warn!("failed to harden socket permissions: {e}");
    }
    // Publish v2 daemon metadata (with session UUID) atomically.
    let daemon_meta = super::metadata::DaemonMetadata::new(super::metadata::DaemonOwner::Mcp);
    let daemon_session = daemon_meta.session;
    if let Err(e) = super::metadata::publish_metadata(
        sock_path.parent().unwrap_or(std::path::Path::new(".")),
        &daemon_meta,
    ) {
        tracing::warn!("failed to publish daemon metadata: {e}");
        // Fall back to legacy PID file so existing clients still work.
        let _ = std::fs::write(
            &pid_path,
            format!(r#"{{"pid":{},"owner":"mcp"}}"#, std::process::id()),
        );
    }
    tracing::debug!(
        "daemon socket ready at {} (MCP-embedded, session={})",
        sock_path.display(),
        daemon_session,
    );

    // Capture daemon effective UID once — used for every peer credential check.
    let daemon_euid = super::metadata::current_euid();

    loop {
        let stream = match listener.accept().await {
            Ok((s, _)) => s,
            Err(e) => {
                tracing::warn!("daemon socket accept: {e}");
                continue;
            }
        };
        // Peer credential check — mismatch or failure drops the connection.
        let peer = match super::metadata::check_peer_cred(&stream, daemon_euid) {
            Some(p) => p,
            None => continue,
        };
        if let Err(e) =
            socket_handle_connection(Arc::clone(&graph), &repo_root, stream, peer, daemon_session)
                .await
        {
            tracing::debug!("daemon socket connection: {e}");
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

pub(crate) async fn socket_dispatch(
    graph: &Arc<tokio::sync::RwLock<Graph>>,
    repo_root: &Path,
    req: &SocketRequest,
) -> SocketResponse {
    use crate::store::session as sess;

    match req.cmd.as_str() {
        "ping" => SocketResponse::ok(serde_json::Value::String("pong".into())),

        // ── MCP tool commands ────────────────────────────────────────────
        "mem_get" => {
            let params = match serde_json::from_value::<MemGetParams>(req.args.clone()) {
                Ok(p) => p,
                Err(e) => return SocketResponse::err(format!("invalid mem_get args: {e}")),
            };
            let server = MatiServer::with_graph_arc(Arc::clone(graph));
            SocketResponse::ok(serde_json::Value::String(
                server.mem_get(Parameters(params)).await,
            ))
        }

        "mem_query" => {
            let params = match serde_json::from_value::<MemQueryParams>(req.args.clone()) {
                Ok(p) => p,
                Err(e) => return SocketResponse::err(format!("invalid mem_query args: {e}")),
            };
            let server = MatiServer::with_graph_arc(Arc::clone(graph));
            SocketResponse::ok(serde_json::Value::String(
                server.mem_query(Parameters(params)).await,
            ))
        }

        "mem_bootstrap" => {
            let params = match serde_json::from_value::<MemBootstrapParams>(req.args.clone()) {
                Ok(p) => p,
                Err(e) => return SocketResponse::err(format!("invalid mem_bootstrap args: {e}")),
            };
            let server = MatiServer::with_graph_arc(Arc::clone(graph));
            SocketResponse::ok(serde_json::Value::String(
                server.mem_bootstrap(Parameters(params)).await,
            ))
        }

        "mem_set" => {
            let params = match serde_json::from_value::<MemSetParams>(req.args.clone()) {
                Ok(p) => p,
                Err(e) => return SocketResponse::err(format!("invalid mem_set args: {e}")),
            };
            let server = MatiServer::with_graph_arc(Arc::clone(graph));
            return SocketResponse::ok(serde_json::Value::String(
                server.mem_set(Parameters(params)).await,
            ));
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
            let mut gotcha_records = serde_json::Map::new();
            let mut gotcha_error = false;
            if let Some(ref fr) = file_record {
                if let Some(keys) = fr
                    .pointer("/payload/gotcha_keys")
                    .and_then(|v| v.as_array())
                {
                    for gk in keys {
                        if let Some(key_str) = gk.as_str() {
                            match store.get(key_str).await {
                                Ok(Some(grec)) => {
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
                                        gotcha_records.insert(key_str.to_string(), val);
                                    }
                                }
                                Ok(None) => {}
                                Err(e) => {
                                    tracing::warn!(
                                        "hook_evaluate: store.get({key_str}) failed: {e}"
                                    );
                                    gotcha_error = true;
                                }
                            }
                        }
                    }
                }
            }

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

            SocketResponse::ok(serde_json::json!({"confirmed": true, "key": key}))
        }

        other => SocketResponse::err(format!("unknown command: {other}")),
    }
}

// ── Auto-promotion: MCP server → headless daemon ─────────────────────────────

/// Idle shutdown threshold — wall-clock seconds with no daemon socket requests.
const IDLE_SHUTDOWN_SECS: u64 = 30 * 60; // 30 min

/// How often to check wall-clock idle time.
const IDLE_CHECK_INTERVAL_SECS: u64 = 5 * 60; // 5 min

/// Block until idle timeout or OS signal (SIGINT/SIGTERM).
///
/// Called after the MCP stdio client disconnects. The daemon socket task is
/// already running in a spawned tokio task — this function just keeps the
/// runtime alive until there's a reason to shut down.
async fn wait_for_idle_or_signal() {
    let wall_secs = || {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    };

    let start = wall_secs();

    // Idle-check: exits after IDLE_SHUTDOWN_SECS from pipe closure.
    // The daemon socket handler runs independently in a spawned task —
    // incoming connections do not reset this timer. 30 minutes is generous
    // enough for Codex sessions where tool calls arrive seconds apart.
    let idle_shutdown = async {
        let mut interval = tokio::time::interval(Duration::from_secs(IDLE_CHECK_INTERVAL_SECS));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            let elapsed = wall_secs().saturating_sub(start);
            if elapsed >= IDLE_SHUTDOWN_SECS {
                tracing::info!(
                    idle_secs = elapsed,
                    "mati serve: idle shutdown (auto-promoted daemon)"
                );
                break;
            }
        }
    };

    // Signal handler: SIGINT or SIGTERM.
    let signal_shutdown = async {
        let ctrl_c = tokio::signal::ctrl_c();
        #[cfg(unix)]
        {
            let mut sigterm =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("failed to register SIGTERM handler");
            tokio::select! {
                _ = ctrl_c => {
                    tracing::info!("mati serve: signal shutdown (SIGINT)");
                }
                _ = sigterm.recv() => {
                    tracing::info!("mati serve: signal shutdown (SIGTERM)");
                }
            }
        }
        #[cfg(not(unix))]
        {
            let _ = ctrl_c.await;
            tracing::info!("mati serve: signal shutdown");
        }
    };

    // Wait for whichever comes first — idle timeout or OS signal.
    tokio::select! {
        _ = idle_shutdown => {}
        _ = signal_shutdown => {}
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

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
}
