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

use crate::graph::Graph;
use crate::store::{derive_slug, Store};

use super::tools::MatiServer;
use super::types::{MemBootstrapParams, MemGetParams, MemQueryParams, MemSetParams};

enum ServerOpen {
    Direct(Store),
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

            let graph = Graph::load(store)
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
                let pid_path = root.join("mati.pid");
                let _ = std::fs::remove_file(&sock_path);
                let _ = std::fs::remove_file(pid_path);
                return ProxyDaemonResult::StaleSocket;
            }
            return ProxyDaemonResult::NotRunning;
        }
    };

    let (reader, mut writer) = stream.into_split();
    let request = serde_json::json!({ "v": PROTOCOL_VERSION, "cmd": cmd, "args": args });
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

    match serde_json::from_str(line.trim()) {
        Ok(v) => ProxyDaemonResult::Ok(v),
        Err(_) => ProxyDaemonResult::Unresponsive,
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
    for attempt in 0..=max_retries {
        match Store::open_and_rebuild(repo_root).await {
            Ok(store) => return Ok(ServerOpen::Direct(store)),
            Err(e) => {
                let is_lock = e.chain().any(|cause| {
                    let msg = cause.to_string();
                    msg.contains("already locked") || msg.contains("WouldBlock")
                });
                if !is_lock {
                    return Err(e).context("failed to open mati store");
                }
                if attempt == max_retries {
                    return match proxy_daemon_result(&mati_root, "ping", serde_json::json!({})).await {
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

// ── Daemon socket — hook script bridge ───────────────────────────────────────

/// Unix domain socket path length limit (macOS-compatible).
const UNIX_SOCK_PATH_MAX: usize = 104;

/// Max wait for a complete request line per connection.
const READ_TIMEOUT: Duration = Duration::from_secs(3);

/// Daemon protocol version (must match `cli::daemon::PROTOCOL_VERSION`).
const PROTOCOL_VERSION: u32 = 1;

#[derive(Debug, Deserialize)]
struct SocketRequest {
    cmd: String,
    #[serde(default, rename = "v")]
    version: Option<u32>,
    #[serde(default)]
    args: serde_json::Value,
}

#[derive(Debug, Serialize)]
struct SocketResponse {
    ok: bool,
    #[serde(rename = "v")]
    version: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl SocketResponse {
    fn ok(data: serde_json::Value) -> Self {
        Self {
            ok: true,
            version: PROTOCOL_VERSION,
            data: Some(data),
            error: None,
        }
    }
    fn err(msg: impl Into<String>) -> Self {
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

    let _ = std::fs::remove_file(&sock_path);
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
    let _ = std::fs::write(
        &pid_path,
        format!(r#"{{"pid":{},"owner":"mcp"}}"#, std::process::id()),
    );
    tracing::debug!(
        "daemon socket ready at {} (MCP-embedded)",
        sock_path.display()
    );

    loop {
        let stream = match listener.accept().await {
            Ok((s, _)) => s,
            Err(e) => {
                tracing::warn!("daemon socket accept: {e}");
                continue;
            }
        };
        if let Err(e) = socket_handle_connection(Arc::clone(&graph), &repo_root, stream).await {
            tracing::debug!("daemon socket connection: {e}");
        }
    }
}

async fn socket_handle_connection(
    graph: Arc<tokio::sync::RwLock<Graph>>,
    repo_root: &Path,
    stream: UnixStream,
) -> Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut buf = String::new();
    match tokio::time::timeout(READ_TIMEOUT, BufReader::new(reader).read_line(&mut buf)).await {
        Ok(Ok(0)) => return Ok(()),
        Ok(Ok(_)) => {}
        Ok(Err(e)) => anyhow::bail!("read error: {e}"),
        Err(_) => anyhow::bail!("read timeout"),
    }

    let req: SocketRequest = match serde_json::from_str(buf.trim()) {
        Ok(r) => r,
        Err(e) => {
            let resp = SocketResponse::err(format!("invalid JSON: {e}"));
            write_socket_response(&mut writer, &resp).await?;
            return Ok(());
        }
    };

    if let Some(v) = req.version {
        if v != PROTOCOL_VERSION {
            let resp = SocketResponse::err(format!(
                "protocol version mismatch: client={v} server={PROTOCOL_VERSION}"
            ));
            write_socket_response(&mut writer, &resp).await?;
            return Ok(());
        }
    }

    let graph_guard = graph.read().await;
    let resp = socket_dispatch(graph_guard.store(), Some(Arc::clone(&graph)), repo_root, &req).await;
    write_socket_response(&mut writer, &resp).await
}

async fn write_socket_response(
    writer: &mut tokio::net::unix::OwnedWriteHalf,
    resp: &SocketResponse,
) -> Result<()> {
    let json = serde_json::to_string(resp)?;
    writer.write_all(json.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;
    Ok(())
}

async fn socket_dispatch(
    store: &Store,
    graph: Option<Arc<tokio::sync::RwLock<Graph>>>,
    repo_root: &Path,
    req: &SocketRequest,
) -> SocketResponse {
    use crate::store::session as sess;

    match req.cmd.as_str() {
        "ping" => SocketResponse::ok(serde_json::Value::String("pong".into())),

        "mem_get" => {
            let Some(graph) = graph.as_ref() else {
                return SocketResponse::err("mem_get requires graph-backed dispatch");
            };
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
            let Some(graph) = graph.as_ref() else {
                return SocketResponse::err("mem_query requires graph-backed dispatch");
            };
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
            let Some(graph) = graph.as_ref() else {
                return SocketResponse::err("mem_bootstrap requires graph-backed dispatch");
            };
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
            let Some(graph) = graph.as_ref() else {
                return SocketResponse::err("mem_set requires graph-backed dispatch");
            };
            let params = match serde_json::from_value::<MemSetParams>(req.args.clone()) {
                Ok(p) => p,
                Err(e) => return SocketResponse::err(format!("invalid mem_set args: {e}")),
            };
            let server = MatiServer::with_graph_arc(Arc::clone(graph));
            return SocketResponse::ok(serde_json::Value::String(
                server.mem_set(Parameters(params)).await,
            ));
        }

        "get" => {
            let key = match req.args.get("key").and_then(|v| v.as_str()) {
                Some(k) => k,
                None => return SocketResponse::err("missing args.key"),
            };
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

        "log_hit" => {
            let key = match req.args.get("key").and_then(|v| v.as_str()) {
                Some(k) => k,
                None => return SocketResponse::err("missing args.key"),
            };
            if let Err(e) = sess::log_hit(store, key).await {
                tracing::warn!("daemon socket log_hit: {e}");
            }
            SocketResponse::ok(serde_json::Value::Null)
        }

        "log_miss" => {
            let key = match req.args.get("key").and_then(|v| v.as_str()) {
                Some(k) => k,
                None => return SocketResponse::err("missing args.key"),
            };
            if let Err(e) = sess::log_miss(store, key).await {
                tracing::warn!("daemon socket log_miss: {e}");
            }
            SocketResponse::ok(serde_json::Value::Null)
        }

        "log_compliance_miss" => {
            let key = match req.args.get("key").and_then(|v| v.as_str()) {
                Some(k) => k,
                None => return SocketResponse::err("missing args.key"),
            };
            if let Err(e) = sess::log_compliance_miss(store, key).await {
                tracing::warn!("daemon socket log_compliance_miss: {e}");
            }
            SocketResponse::ok(serde_json::Value::Null)
        }

        "log_compliance_hit" => {
            let key = match req.args.get("key").and_then(|v| v.as_str()) {
                Some(k) => k,
                None => return SocketResponse::err("missing args.key"),
            };
            if let Err(e) = sess::log_compliance_hit(store, key).await {
                tracing::warn!("daemon socket log_compliance_hit: {e}");
            }
            SocketResponse::ok(serde_json::Value::Null)
        }

        "log_codex_shell_miss" => {
            let key = match req.args.get("key").and_then(|v| v.as_str()) {
                Some(k) => k,
                None => return SocketResponse::err("missing args.key"),
            };
            if let Err(e) = sess::log_codex_shell_miss(store, key).await {
                tracing::warn!("daemon socket log_codex_shell_miss: {e}");
            }
            SocketResponse::ok(serde_json::Value::Null)
        }

        "log_bootstrap" => {
            let key = match req.args.get("key").and_then(|v| v.as_str()) {
                Some(k) => k,
                None => return SocketResponse::err("missing args.key"),
            };
            if let Err(e) = sess::log_bootstrap(store, key).await {
                tracing::warn!("daemon socket log_bootstrap: {e}");
            }
            SocketResponse::ok(serde_json::Value::Null)
        }

        "log_prompt_nudge" => {
            let key = match req.args.get("key").and_then(|v| v.as_str()) {
                Some(k) => k,
                None => return SocketResponse::err("missing args.key"),
            };
            if let Err(e) = sess::log_prompt_nudge(store, key).await {
                tracing::warn!("daemon socket log_prompt_nudge: {e}");
            }
            SocketResponse::ok(serde_json::Value::Null)
        }

        "session_check_consulted" => {
            let key = match req.args.get("key").and_then(|v| v.as_str()) {
                Some(k) => k,
                None => return SocketResponse::err("missing args.key"),
            };
            match sess::check_consulted(store, key).await {
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
            match sess::check_consulted_recent(store, key, ttl_secs).await {
                Ok(found) => SocketResponse::ok(serde_json::Value::Bool(found)),
                Err(e) => SocketResponse::err(format!("store: {e}")),
            }
        }

        "session_flush" => {
            if let Err(e) = sess::session_flush(store).await {
                tracing::warn!("daemon socket session_flush: {e}");
            }
            SocketResponse::ok(serde_json::Value::Null)
        }

        "session_harvest" => {
            // Note: uses no-staleness variant because StalenessAnalyzer (git2) is !Send.
            // Git-based staleness analysis runs on the next CLI-path harvest.
            if let Err(e) = sess::session_harvest_no_staleness(store).await {
                tracing::warn!("daemon socket session_harvest: {e}");
            }
            SocketResponse::ok(serde_json::Value::Null)
        }

        "edit_hook" => {
            let path = match req.args.get("path").and_then(|v| v.as_str()) {
                Some(p) => p,
                None => return SocketResponse::err("missing args.path"),
            };
            let file_key = format!("file:{path}");
            if let Err(e) = sess::log_hit(store, &file_key).await {
                tracing::warn!("daemon socket edit_hook: log_hit failed: {e}");
            }
            if let Err(e) = crate::analysis::reparse::reparse_impl(store, repo_root, path).await {
                tracing::warn!("daemon socket edit_hook: reparse failed (non-fatal): {e}");
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
            if let Err(e) = sess::doc_capture(store, path, content).await {
                tracing::warn!("daemon socket doc_capture: {e}");
            }
            SocketResponse::ok(serde_json::Value::Null)
        }

        "scan_prefix" => {
            let prefix = match req.args.get("prefix").and_then(|v| v.as_str()) {
                Some(p) => p,
                None => return SocketResponse::err("missing args.prefix"),
            };
            match store.scan_prefix(prefix).await {
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
            match store.put(key, &record).await {
                Ok(()) => SocketResponse::ok(serde_json::Value::Null),
                Err(e) => SocketResponse::err(format!("store put: {e}")),
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

            match apply_gotcha_write(store, &record, &old_files, &new_files, is_new).await {
                Ok(()) => SocketResponse::ok(serde_json::Value::String("written".into())),
                Err(e) => SocketResponse::err(format!("{e}")),
            }
        }

        "gotcha_tombstone" => {
            use crate::store::gotcha_ops::apply_gotcha_tombstone;

            let key = match req.args.get("key").and_then(|v| v.as_str()) {
                Some(k) => k,
                None => return SocketResponse::err("missing args.key"),
            };
            let affected_files: Vec<String> = req
                .args
                .get("affected_files")
                .and_then(|v| serde_json::from_value(v.clone()).ok())
                .unwrap_or_default();

            match apply_gotcha_tombstone(store, key, &affected_files).await {
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
            let mut record = match store.get(key).await {
                Ok(Some(r)) => r,
                Ok(None) => return SocketResponse::err(format!("record not found: {key}")),
                Err(e) => return SocketResponse::err(format!("store get: {e}")),
            };

            if record.category != crate::store::record::Category::Gotcha {
                return SocketResponse::err(format!("{key} is not a gotcha record"));
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
                                let arr = obj
                                    .entry("gotcha_keys")
                                    .or_insert(serde_json::json!([]));
                                if let Some(arr) = arr.as_array_mut() {
                                    arr.push(serde_json::Value::String(key.to_string()));
                                }
                            }
                        }
                        let _ = store.put(&file_key, &file_record).await;
                    }
                }
            }

            SocketResponse::ok(serde_json::json!({"confirmed": true, "key": key}))
        }

        other => SocketResponse::err(format!("unknown command: {other}")),
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

    async fn dispatch(store: &Store, cmd: &str, args: serde_json::Value) -> SocketResponse {
        let req = SocketRequest {
            cmd: cmd.to_string(),
            version: Some(PROTOCOL_VERSION),
            args,
        };
        socket_dispatch(store, None, Path::new("/tmp/mati-test"), &req).await
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

        let record = make_gotcha_record("gotcha:socket-test", &["src/a.rs", "src/b.rs"]);
        let resp = dispatch(
            &store,
            "gotcha_write",
            serde_json::json!({
                "record": record,
                "new_files": ["src/a.rs", "src/b.rs"],
                "old_files": [],
                "is_new": true,
            }),
        )
        .await;

        assert!(resp.ok, "gotcha_write failed: {:?}", resp.error);

        let a = store.get("file:src/a.rs").await.unwrap().unwrap();
        let b = store.get("file:src/b.rs").await.unwrap().unwrap();
        assert!(file_gotcha_keys(&a).contains(&"gotcha:socket-test".into()));
        assert!(file_gotcha_keys(&b).contains(&"gotcha:socket-test".into()));

        store.close().await.unwrap();
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

        // Initial write targeting src/a.rs
        let record = make_gotcha_record("gotcha:edit-socket", &["src/a.rs"]);
        let resp = dispatch(
            &store,
            "gotcha_write",
            serde_json::json!({
                "record": record,
                "new_files": ["src/a.rs"],
                "old_files": [],
                "is_new": true,
            }),
        )
        .await;
        assert!(resp.ok);

        // Edit: move from src/a.rs to src/b.rs
        let record2 = make_gotcha_record("gotcha:edit-socket", &["src/b.rs"]);
        let resp2 = dispatch(
            &store,
            "gotcha_write",
            serde_json::json!({
                "record": record2,
                "new_files": ["src/b.rs"],
                "old_files": ["src/a.rs"],
                "is_new": false,
            }),
        )
        .await;
        assert!(resp2.ok);

        let a = store.get("file:src/a.rs").await.unwrap().unwrap();
        let b = store.get("file:src/b.rs").await.unwrap().unwrap();
        assert!(
            !file_gotcha_keys(&a).contains(&"gotcha:edit-socket".into()),
            "old file should not have gotcha key after edit"
        );
        assert!(
            file_gotcha_keys(&b).contains(&"gotcha:edit-socket".into()),
            "new file should have gotcha key after edit"
        );

        store.close().await.unwrap();
    }

    // ── Regression: gotcha_tombstone via socket cleans file links ─────────

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

        // Write gotcha first
        let record = make_gotcha_record("gotcha:tomb-socket", &["src/a.rs", "src/b.rs"]);
        let resp = dispatch(
            &store,
            "gotcha_write",
            serde_json::json!({
                "record": record,
                "new_files": ["src/a.rs", "src/b.rs"],
                "old_files": [],
                "is_new": true,
            }),
        )
        .await;
        assert!(resp.ok);

        // Tombstone it
        let resp2 = dispatch(
            &store,
            "gotcha_tombstone",
            serde_json::json!({
                "key": "gotcha:tomb-socket",
                "affected_files": ["src/a.rs", "src/b.rs"],
            }),
        )
        .await;
        assert!(resp2.ok, "gotcha_tombstone failed: {:?}", resp2.error);

        // Record should be tombstoned
        let rec = store.get("gotcha:tomb-socket").await.unwrap().unwrap();
        assert!(matches!(rec.lifecycle, RecordLifecycle::Tombstoned { .. }));

        // File records should have empty gotcha_keys
        let a = store.get("file:src/a.rs").await.unwrap().unwrap();
        let b = store.get("file:src/b.rs").await.unwrap().unwrap();
        assert!(
            file_gotcha_keys(&a).is_empty(),
            "file:src/a.rs should have no gotcha keys after tombstone, got: {:?}",
            file_gotcha_keys(&a)
        );
        assert!(
            file_gotcha_keys(&b).is_empty(),
            "file:src/b.rs should have no gotcha keys after tombstone, got: {:?}",
            file_gotcha_keys(&b)
        );

        store.close().await.unwrap();
    }

    // ── Regression: gotcha_write via socket rejects collisions ────────────

    #[tokio::test]
    async fn socket_gotcha_write_rejects_duplicate_key() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();

        let record1 = make_gotcha_record("gotcha:dup-socket", &["src/a.rs"]);
        store.put("gotcha:dup-socket", &record1).await.unwrap();

        let record2 = make_gotcha_record("gotcha:dup-socket", &["src/b.rs"]);
        let resp = dispatch(
            &store,
            "gotcha_write",
            serde_json::json!({
                "record": record2,
                "new_files": ["src/b.rs"],
                "old_files": [],
                "is_new": true,
            }),
        )
        .await;

        assert!(!resp.ok, "duplicate key should be rejected");
        assert!(
            resp.error
                .as_deref()
                .unwrap_or("")
                .contains("already exists"),
            "error should mention collision: {:?}",
            resp.error
        );

        // Original should be untouched
        let original = store.get("gotcha:dup-socket").await.unwrap().unwrap();
        let payload = original.payload_as::<GotchaRecord>().unwrap();
        assert_eq!(payload.affected_files, vec!["src/a.rs"]);

        store.close().await.unwrap();
    }
}
