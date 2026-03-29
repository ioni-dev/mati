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
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

use mati_core::store::gotcha_ops::{apply_gotcha_tombstone, apply_gotcha_write};
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

// ── Protocol types ───────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct Request {
    cmd: String,
    /// Protocol version from client. `None` for legacy clients (treated as compatible).
    #[serde(default, rename = "v")]
    version: Option<u32>,
    #[serde(default)]
    args: serde_json::Value,
}

#[derive(Debug, Serialize)]
struct Response {
    ok: bool,
    /// Always the daemon's version so clients can detect skew.
    #[serde(rename = "v")]
    version: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl Response {
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

/// Max wait for a complete request line per connection.
const READ_TIMEOUT: Duration = Duration::from_secs(3);

// ── Server ───────────────────────────────────────────────────────────────────

/// Start the daemon: open the Store, bind the Unix socket, and serve forever.
///
/// Exits cleanly on SIGINT, SIGTERM, or after [`IDLE_SHUTDOWN_SECS`] of wall-clock
/// idle time. Removes the socket and PID file on any exit path.
pub async fn run_daemon_start() -> Result<()> {
    let cwd = std::env::current_dir()?;
    // Compute mati_root separately so we can write the starting sentinel before
    // Store::open (which may fail). This prevents try_auto_start from spawning
    // a second daemon while this one is initializing.
    let mati_root = mati_root_for(&cwd)?;
    let starting_path = mati_root.join("mati.starting");
    let _ = std::fs::write(&starting_path, wall_secs().to_string());

    let repo_root = Arc::new(std::fs::canonicalize(&cwd)?);
    let store = Store::open(&cwd).await?;

    let sock_path = store.root.join("mati.sock");
    let pid_path = store.root.join("mati.pid");

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

    // Remove stale socket from a previous unclean shutdown.
    let _ = std::fs::remove_file(&sock_path);

    std::fs::write(
        &pid_path,
        format!(r#"{{"pid":{},"owner":"daemon"}}"#, std::process::id()),
    )
    .with_context(|| format!("failed to write PID file at {}", pid_path.display()))?;
    // PID is written — remove the starting sentinel so try_auto_start won't block.
    let _ = std::fs::remove_file(&starting_path);

    let listener = UnixListener::bind(&sock_path)
        .with_context(|| format!("failed to bind Unix socket at {}", sock_path.display()))?;

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
    tokio::join!(
        serve_loop_graceful(&store, &repo_root, &listener, &last_wall, &shutdown),
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
    if let Err(e) = store.close().await {
        tracing::warn!("daemon: store close warning on shutdown: {e}");
    }
    Ok(())
}

/// Accept and handle connections sequentially. Exits cleanly after the current
/// connection completes when `shutdown` is notified — never cancels a connection
/// mid-execution.
async fn serve_loop_graceful(
    store: &Store,
    repo_root: &Path,
    listener: &UnixListener,
    last_wall: &AtomicU64,
    shutdown: &tokio::sync::Notify,
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
        // Runs to completion — NOT cancellable by shutdown.
        if let Err(e) = handle_connection(store, repo_root, stream).await {
            tracing::warn!(error = %e, "daemon: connection error");
        }
    }
}

/// Read one JSON request, dispatch, write one JSON response.
async fn handle_connection(store: &Store, repo_root: &Path, stream: UnixStream) -> Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut buf_reader = BufReader::new(reader);
    let mut line = String::new();

    match tokio::time::timeout(READ_TIMEOUT, buf_reader.read_line(&mut line)).await {
        Ok(Ok(0)) => return Ok(()), // client closed without sending
        Ok(Ok(_)) => {}
        Ok(Err(e)) => anyhow::bail!("read error: {e}"),
        Err(_) => anyhow::bail!("read timeout after {}s", READ_TIMEOUT.as_secs()),
    }

    let request: Request = match serde_json::from_str(line.trim()) {
        Ok(r) => r,
        Err(e) => {
            write_response(&mut writer, &Response::err(format!("invalid JSON: {e}"))).await?;
            return Ok(());
        }
    };

    let response = dispatch(store, repo_root, &request).await;
    write_response(&mut writer, &response).await?;
    Ok(())
}

async fn write_response(
    writer: &mut tokio::net::unix::OwnedWriteHalf,
    response: &Response,
) -> Result<()> {
    let json = serde_json::to_string(response)?;
    writer.write_all(json.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;
    Ok(())
}

/// Route a request to the appropriate handler.
async fn dispatch(store: &Store, repo_root: &Path, req: &Request) -> Response {
    // Version check. Explicit mismatch → error so client falls back rather than
    // misinterpreting a response from an incompatible daemon.
    if let Some(v) = req.version {
        if v != PROTOCOL_VERSION {
            return Response::err(format!(
                "protocol version mismatch: client={v} daemon={PROTOCOL_VERSION}; \
                 run `mati daemon stop && mati daemon start` to upgrade"
            ));
        }
    }

    match req.cmd.as_str() {
        "get" => cmd_get(store, &req.args).await,
        "log_hit" => cmd_log_hit(store, &req.args).await,
        "log_miss" => cmd_log_miss(store, &req.args).await,
        "log_compliance_miss" => cmd_log_compliance_miss(store, &req.args).await,
        "session_check_consulted" => cmd_session_check_consulted(store, &req.args).await,
        "edit_hook" => cmd_edit_hook(store, repo_root, &req.args).await,
        "session_flush" => cmd_session_flush(store).await,
        "scan_prefix" => cmd_scan_prefix(store, &req.args).await,
        "put" => cmd_put(store, &req.args).await,
        "gotcha_write" => cmd_gotcha_write(store, &req.args).await,
        "gotcha_tombstone" => cmd_gotcha_tombstone(store, &req.args).await,
        "ping" => Response::ok(serde_json::Value::String("pong".into())),
        other => Response::err(format!("unknown command: {other}")),
    }
}

// ── Command handlers ─────────────────────────────────────────────────────────

async fn cmd_get(store: &Store, args: &serde_json::Value) -> Response {
    let key = match args.get("key").and_then(|v| v.as_str()) {
        Some(k) => k,
        None => return Response::err("missing args.key"),
    };
    match store.get(key).await {
        Ok(Some(record)) => {
            // Add top-level `confirmed` field so hook scripts can read `.confirmed`
            // without knowing the category. Mirrors extract_confirmed in cli/hooks.rs.
            let confirmed = record
                .payload_as::<mati_core::store::GotchaRecord>()
                .map(|g| g.confirmed)
                .unwrap_or(false);
            match serde_json::to_value(&record) {
                Ok(mut val) => {
                    if let Some(obj) = val.as_object_mut() {
                        obj.insert("confirmed".to_string(), serde_json::Value::Bool(confirmed));
                    }
                    Response::ok(val)
                }
                Err(e) => Response::err(format!("serialize error: {e}")),
            }
        }
        Ok(None) => Response::ok(serde_json::Value::Null),
        Err(e) => Response::err(format!("store error: {e}")),
    }
}

async fn cmd_log_hit(store: &Store, args: &serde_json::Value) -> Response {
    let key = match args.get("key").and_then(|v| v.as_str()) {
        Some(k) => k,
        None => return Response::err("missing args.key"),
    };
    let now = now_secs();

    let agg_key = today_key("analytics:hit_");
    if let Err(e) = upsert_daily_agg(store, &agg_key, key).await {
        tracing::warn!(error = %e, "daemon: hit aggregation failed");
    }

    let consulted_key = format!("session:consulted:{key}");
    if let Err(e) = store
        .put(
            &consulted_key,
            &session_record(&consulted_key, String::new()),
        )
        .await
    {
        tracing::warn!(error = %e, "daemon: consulted marker failed");
    }

    if let Ok(Some(mut record)) = store.get(key).await {
        record.access_count += 1;
        record.last_accessed = now;
        if let Err(e) = store.put(key, &record).await {
            tracing::warn!(error = %e, "daemon: access_count bump failed");
        }
    }

    Response::ok(serde_json::Value::String("hit logged".into()))
}

async fn cmd_log_miss(store: &Store, args: &serde_json::Value) -> Response {
    let key = match args.get("key").and_then(|v| v.as_str()) {
        Some(k) => k,
        None => return Response::err("missing args.key"),
    };
    let agg_key = today_key("analytics:miss_");
    if let Err(e) = upsert_daily_agg(store, &agg_key, key).await {
        return Response::err(format!("miss aggregation failed: {e}"));
    }
    Response::ok(serde_json::Value::String("miss logged".into()))
}

async fn cmd_log_compliance_miss(store: &Store, args: &serde_json::Value) -> Response {
    let key = match args.get("key").and_then(|v| v.as_str()) {
        Some(k) => k,
        None => return Response::err("missing args.key"),
    };
    let agg_key = today_key("compliance:miss_");
    if let Err(e) = upsert_daily_agg(store, &agg_key, key).await {
        return Response::err(format!("compliance miss aggregation failed: {e}"));
    }
    Response::ok(serde_json::Value::String("compliance miss logged".into()))
}

async fn cmd_session_check_consulted(store: &Store, args: &serde_json::Value) -> Response {
    let key = match args.get("key").and_then(|v| v.as_str()) {
        Some(k) => k,
        None => return Response::err("missing args.key"),
    };
    let consulted_key = format!("session:consulted:{key}");
    match store.get(&consulted_key).await {
        Ok(Some(_)) => Response::ok(serde_json::Value::Bool(true)),
        Ok(None) => Response::ok(serde_json::Value::Bool(false)),
        Err(e) => Response::err(format!("store error: {e}")),
    }
}

/// Combined log-hit + reparse. The daemon already has the store open so this
/// avoids the ~200ms SurrealKV re-open cost that `run_edit_hook` incurs as a
/// standalone process.
async fn cmd_edit_hook(store: &Store, repo_root: &Path, args: &serde_json::Value) -> Response {
    let path = match args.get("path").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return Response::err("missing args.path"),
    };
    let file_key = format!("file:{path}");
    let now = now_secs();

    // log-hit (best-effort — mirrors log_hit_impl in hooks.rs)
    let agg_key = today_key("analytics:hit_");
    let _ = upsert_daily_agg(store, &agg_key, &file_key).await;
    let consulted_key = format!("session:consulted:{file_key}");
    let _ = store
        .put(
            &consulted_key,
            &session_record(&consulted_key, String::new()),
        )
        .await;
    if let Ok(Some(mut record)) = store.get(&file_key).await {
        record.access_count += 1;
        record.last_accessed = now;
        let _ = store.put(&file_key, &record).await;
    }

    // reparse (best-effort — non-fatal per P9)
    if let Err(e) = crate::cli::reparse::reparse_impl(store, repo_root, path).await {
        tracing::warn!(path, error = %e, "daemon edit_hook: reparse failed (non-fatal)");
    }

    Response::ok(serde_json::Value::Null)
}

/// Flush consulted-key markers into `session:current`.
/// Mirrors `session_flush_impl` in hooks.rs. Called at session end before harvest.
async fn cmd_session_flush(store: &Store) -> Response {
    let now = now_secs();
    let consulted_keys = match store.scan_keys("session:consulted:").await {
        Ok(keys) => keys,
        Err(e) => return Response::err(format!("scan_keys error: {e}")),
    };
    let stripped: Vec<String> = consulted_keys
        .iter()
        .map(|k| {
            k.strip_prefix("session:consulted:")
                .unwrap_or(k)
                .to_string()
        })
        .collect();
    let value = match serde_json::to_string(&serde_json::json!({
        "consulted_keys": stripped,
        "flushed_at": now,
    })) {
        Ok(v) => v,
        Err(e) => return Response::err(format!("serialize error: {e}")),
    };
    match store
        .put("session:current", &session_record("session:current", value))
        .await
    {
        Ok(()) => Response::ok(serde_json::Value::String("flushed".into())),
        Err(e) => Response::err(format!("store error: {e}")),
    }
}

async fn cmd_scan_prefix(store: &Store, args: &serde_json::Value) -> Response {
    let prefix = match args.get("prefix").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return Response::err("missing args.prefix"),
    };
    match store.scan_prefix(prefix).await {
        Ok(records) => match serde_json::to_value(&records) {
            Ok(val) => Response::ok(val),
            Err(e) => Response::err(format!("serialize error: {e}")),
        },
        Err(e) => Response::err(format!("store error: {e}")),
    }
}

async fn cmd_put(store: &Store, args: &serde_json::Value) -> Response {
    let key = match args.get("key").and_then(|v| v.as_str()) {
        Some(k) => k,
        None => return Response::err("missing args.key"),
    };
    let record: Record = match args
        .get("record")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
    {
        Some(r) => r,
        None => return Response::err("put: invalid record"),
    };
    match store.put(key, &record).await {
        Ok(()) => Response::ok(serde_json::Value::Null),
        Err(e) => Response::err(format!("store put: {e}")),
    }
}

/// Write a gotcha record + update affected file records + persist graph edges.
/// Used by `mati gotcha add/edit` when the daemon holds the store lock.
async fn cmd_gotcha_write(store: &Store, args: &serde_json::Value) -> Response {
    let record: Record = match args
        .get("record")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
    {
        Some(r) => r,
        None => return Response::err("missing or invalid args.record"),
    };
    let new_files: Vec<String> = args
        .get("new_files")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();
    let old_files: Vec<String> = args
        .get("old_files")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();
    let is_new = args
        .get("is_new")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    match apply_gotcha_write(store, &record, &old_files, &new_files, is_new).await {
        Ok(()) => Response::ok(serde_json::Value::String("written".into())),
        Err(e) => Response::err(format!("{e}")),
    }
}

/// Tombstone a gotcha record and remove its HasGotcha graph edges.
/// Used by `mati gotcha delete` when the daemon holds the store lock.
async fn cmd_gotcha_tombstone(store: &Store, args: &serde_json::Value) -> Response {
    let key = match args.get("key").and_then(|v| v.as_str()) {
        Some(k) => k,
        None => return Response::err("missing args.key"),
    };
    let affected_files: Vec<String> = args
        .get("affected_files")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();

    match apply_gotcha_tombstone(store, key, &affected_files).await {
        Ok(()) => Response::ok(serde_json::Value::String("tombstoned".into())),
        Err(e) => Response::err(format!("{e}")),
    }
}

// ── Client ───────────────────────────────────────────────────────────────────

/// Send a request to the daemon and return a [`DaemonResult`].
///
/// Handles three failure modes:
/// - **No socket** → [`DaemonResult::NotRunning`] — safe to use `Store::open`
/// - **ECONNREFUSED + PID dead** → clean up stale files, [`DaemonResult::StaleSocket`] — safe to use `Store::open`
/// - **PID alive but not responding** → [`DaemonResult::Unresponsive`] — **unsafe** to use `Store::open`
pub async fn daemon_result(root: &Path, cmd: &str, args: serde_json::Value) -> DaemonResult {
    let sock_path = root.join("mati.sock");

    if sock_path.as_os_str().len() > UNIX_SOCK_PATH_MAX {
        tracing::warn!(
            path = %sock_path.display(),
            "daemon_result: socket path exceeds Unix limit — daemon unavailable"
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
                if is_pid_dead(root) {
                    // Stale socket — clean up so next direct open works.
                    let _ = std::fs::remove_file(&sock_path);
                    let _ = std::fs::remove_file(root.join("mati.pid"));
                    tracing::debug!("daemon: removed stale socket");
                    return DaemonResult::StaleSocket;
                } else {
                    tracing::warn!("daemon: socket refused but PID alive — unresponsive");
                    return DaemonResult::Unresponsive;
                }
            }
            // Any other error (ENOENT race, permission, etc.) — treat as not running.
            tracing::debug!(error = %e, "daemon: connect failed, treating as not running");
            return DaemonResult::NotRunning;
        }
    };

    let (reader, mut writer) = stream.into_split();
    let request = serde_json::json!({ "v": PROTOCOL_VERSION, "cmd": cmd, "args": args });
    let mut bytes = match serde_json::to_vec(&request) {
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

    // Protocol version mismatch — client must not interpret this response.
    // Treat as Unresponsive: daemon is alive (holds the lock) but incompatible.
    if let Some(v) = resp.get("v").and_then(|v| v.as_u64()) {
        if v as u32 != PROTOCOL_VERSION {
            tracing::warn!(
                daemon_v = v,
                client_v = PROTOCOL_VERSION,
                "daemon: protocol version mismatch — restart daemon to upgrade"
            );
            return DaemonResult::Unresponsive;
        }
    }

    DaemonResult::Ok(resp)
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
/// Guards against double-spawn: if a PID file or socket already exists the
/// function returns immediately — the daemon is either running or already
/// starting.
pub fn try_auto_start(project_cwd: &Path) {
    let root = match mati_root_for(project_cwd) {
        Ok(r) => r,
        Err(e) => {
            tracing::debug!(error = %e, "auto-start: could not derive mati root");
            return;
        }
    };

    // Already running or a prior auto-start is in progress.
    if root.join("mati.pid").exists() || root.join("mati.sock").exists() {
        return;
    }

    // Cooldown: a recent auto-start attempt wrote mati.starting before calling
    // Store::open. If the daemon process failed (store error), mati.starting
    // persists. Retry only after 10 seconds to avoid a spawn loop.
    let starting_path = root.join("mati.starting");
    if let Ok(content) = std::fs::read_to_string(&starting_path) {
        if let Ok(ts) = content.trim().parse::<u64>() {
            if wall_secs().saturating_sub(ts) < 10 {
                tracing::debug!("auto-start: recent attempt in progress or failed (10s cooldown)");
                return;
            }
        }
        // Sentinel older than 10s — stale, remove and retry.
        let _ = std::fs::remove_file(&starting_path);
    }

    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            tracing::debug!(error = %e, "auto-start: could not find current exe");
            return;
        }
    };

    match std::process::Command::new(&exe)
        .args(["daemon", "start"])
        .current_dir(project_cwd)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
    {
        Ok(child) => {
            tracing::debug!(pid = child.id(), "auto-started mati daemon");
            // Detach — do not wait. The child runs independently.
            std::mem::forget(child);
        }
        Err(e) => {
            // Non-fatal: hooks fall back to direct Store::open automatically.
            tracing::debug!(error = %e, "auto-start: failed to spawn daemon");
        }
    }
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

/// Returns `true` if the PID recorded in the PID file is no longer alive.
/// Uses `kill -0` (no signal sent, just checks process existence).
/// Returns `true` (assume dead) if the PID file is absent or unreadable.
pub fn is_pid_dead(root: &Path) -> bool {
    match read_pid_file(root) {
        Some((pid, _)) => !std::process::Command::new("kill")
            .args(["-0", &pid.to_string()])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false),
        None => true,
    }
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

fn now_secs() -> u64 {
    wall_secs()
}

fn today_key(prefix: &str) -> String {
    let now = chrono::Utc::now().format("%Y-%m-%d");
    format!("{prefix}{now}")
}

fn new_device_id() -> uuid::Uuid {
    uuid::Uuid::new_v4()
}

use mati_core::store::{
    Category, ConfidenceScore, Priority, QualityScore, Record, RecordLifecycle, RecordSource,
    RecordVersion, StalenessScore,
};

fn session_record(key: &str, value: String) -> Record {
    let now = now_secs();
    Record {
        key: key.to_string(),
        value,
        category: Category::Session,
        priority: Priority::Normal,
        tags: vec![],
        created_at: now,
        updated_at: now,
        ref_url: None,
        staleness: StalenessScore::fresh(),
        lifecycle: RecordLifecycle::Active,
        version: RecordVersion {
            device_id: new_device_id(),
            logical_clock: 1,
            wall_clock: now,
        },
        quality: QualityScore::layer0_default(),
        access_count: 0,
        last_accessed: 0,
        source: RecordSource::SessionHook,
        confidence: ConfidenceScore::for_new_record(&RecordSource::SessionHook),
        gap_analysis_score: 0.0,
        payload: None,
    }
}

fn analytics_record(key: &str, value: String) -> Record {
    let mut r = session_record(key, value);
    r.category = Category::Analytics;
    r
}

#[derive(Serialize, Deserialize)]
struct DailyAgg {
    count: u64,
    keys: Vec<String>,
}

const MAX_AGG_KEYS: usize = 100;

async fn upsert_daily_agg(store: &Store, agg_key: &str, target_key: &str) -> Result<()> {
    let now = now_secs();
    match store.get(agg_key).await? {
        Some(mut record) => {
            let mut agg: DailyAgg = serde_json::from_str(&record.value).unwrap_or(DailyAgg {
                count: 0,
                keys: vec![],
            });
            agg.count += 1;
            if agg.keys.len() < MAX_AGG_KEYS && !agg.keys.iter().any(|k| k == target_key) {
                agg.keys.push(target_key.to_string());
            }
            record.value = serde_json::to_string(&agg)?;
            record.updated_at = now;
            record.version.logical_clock += 1;
            record.version.wall_clock = now;
            store.put(agg_key, &record).await?;
        }
        None => {
            let agg = DailyAgg {
                count: 1,
                keys: vec![target_key.to_string()],
            };
            let record = analytics_record(agg_key, serde_json::to_string(&agg)?);
            store.put(agg_key, &record).await?;
        }
    }
    Ok(())
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

    #[test]
    fn response_ok_serialization() {
        let resp = Response::ok(serde_json::json!("pong"));
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains(r#""ok":true"#));
        assert!(json.contains(r#""data":"pong""#));
        assert!(json.contains(r#""v":1"#));
        assert!(!json.contains("error"));
    }

    #[test]
    fn response_err_serialization() {
        let resp = Response::err("bad request");
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains(r#""ok":false"#));
        assert!(json.contains(r#""error":"bad request""#));
        assert!(json.contains(r#""v":1"#));
        assert!(!json.contains("data"));
    }

    #[test]
    fn request_with_version() {
        let json = r#"{"v":1,"cmd":"get","args":{"key":"file:src/main.rs"}}"#;
        let req: Request = serde_json::from_str(json).unwrap();
        assert_eq!(req.cmd, "get");
        assert_eq!(req.version, Some(1));
        assert_eq!(req.args["key"], "file:src/main.rs");
    }

    #[test]
    fn request_without_version_is_backward_compatible() {
        let json = r#"{"cmd":"ping"}"#;
        let req: Request = serde_json::from_str(json).unwrap();
        assert_eq!(req.cmd, "ping");
        assert_eq!(req.version, None); // legacy client — treated as compatible
    }

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
}
