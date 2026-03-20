//! Daemon mode — keeps Store open to eliminate CLI startup overhead (M-17-A).
//!
//! The daemon listens on a Unix socket (`~/.mati/<slug>/mati.sock`) and handles
//! newline-delimited JSON requests. Hook commands (`mati get`, `mati log-hit`,
//! `mati log-miss`) connect via [`daemon_request`] to skip the ~150ms
//! SurrealKV + tantivy init that a cold `Store::open` incurs.
//!
//! **Protocol:** One JSON request per connection, one JSON response, then close.
//!
//! Request:
//! ```json
//! {"cmd":"get","args":{"key":"file:src/main.rs"}}
//! {"cmd":"log_hit","args":{"key":"file:src/main.rs"}}
//! {"cmd":"log_miss","args":{"key":"file:src/main.rs"}}
//! {"cmd":"ping","args":{}}
//! ```
//!
//! Response:
//! ```json
//! {"ok":true,"data":"<json value>"}
//! {"ok":false,"error":"description"}
//! ```
//!
//! **Connection model:** Sequential (one connection at a time on the main task).
//! Claude hooks fire serially within a session, so parallel handling is
//! unnecessary. This sidesteps `Store` not being `Send`/`Sync`.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

use mati_core::store::{derive_slug, Store};

// ── Protocol types ──────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct Request {
    cmd: String,
    #[serde(default)]
    args: serde_json::Value,
}

#[derive(Debug, Serialize)]
struct Response {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl Response {
    fn ok(data: serde_json::Value) -> Self {
        Self { ok: true, data: Some(data), error: None }
    }

    fn err(msg: impl Into<String>) -> Self {
        Self { ok: false, data: None, error: Some(msg.into()) }
    }
}

// ── Read timeout ────────────────────────────────────────────────────────────

/// Maximum time to wait for a complete request line from a client connection.
/// Prevents a stale or misbehaving connection from blocking the sequential
/// serve loop indefinitely.
const READ_TIMEOUT: Duration = Duration::from_secs(3);

// ── Server ──────────────────────────────────────────────────────────────────

/// Start the daemon: open the Store, bind the Unix socket, and serve forever.
///
/// Blocks until SIGINT/SIGTERM. Cleans up the socket and PID file on exit.
pub async fn run_daemon_start() -> Result<()> {
    let cwd = std::env::current_dir()?;
    let store = Store::open(&cwd).await?;

    let sock_path = store.root.join("mati.sock");
    let pid_path = store.root.join("mati.pid");

    // Remove stale socket from a previous unclean shutdown
    let _ = std::fs::remove_file(&sock_path);

    // Write PID file so `mati daemon stop` can signal us
    std::fs::write(&pid_path, std::process::id().to_string())
        .with_context(|| format!("failed to write PID file at {}", pid_path.display()))?;

    let listener = UnixListener::bind(&sock_path)
        .with_context(|| format!("failed to bind Unix socket at {}", sock_path.display()))?;

    tracing::info!(path = %sock_path.display(), pid = std::process::id(), "mati daemon listening");
    eprintln!("mati daemon listening on {}", sock_path.display());

    // Graceful shutdown on SIGINT (ctrl-c) or SIGTERM
    let shutdown = async {
        let ctrl_c = tokio::signal::ctrl_c();
        #[cfg(unix)]
        {
            let mut sigterm =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("failed to register SIGTERM handler");
            tokio::select! {
                _ = ctrl_c => {}
                _ = sigterm.recv() => {}
            }
        }
        #[cfg(not(unix))]
        {
            ctrl_c.await.ok();
        }
    };

    tokio::select! {
        _ = serve_loop(&store, &listener) => {}
        _ = shutdown => {
            tracing::info!("mati daemon shutting down");
            eprintln!("mati daemon shutting down");
        }
    }

    // Cleanup
    let _ = std::fs::remove_file(&sock_path);
    let _ = std::fs::remove_file(&pid_path);
    store.close().await?;

    Ok(())
}

/// Accept and handle connections sequentially — one at a time.
///
/// Sequential handling is intentional: `Store` is not `Send`/`Sync`, and hooks
/// fire serially within a single Claude session. This keeps the implementation
/// simple and avoids any interior mutability overhead.
async fn serve_loop(store: &Store, listener: &UnixListener) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                if let Err(e) = handle_connection(store, stream).await {
                    tracing::warn!(error = %e, "daemon connection error");
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "daemon accept error");
            }
        }
    }
}

/// Read one JSON request line, dispatch it, write one JSON response line.
async fn handle_connection(store: &Store, stream: UnixStream) -> Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut buf_reader = BufReader::new(reader);
    let mut line = String::new();

    // Read with timeout to avoid blocking the serve loop on a stale connection
    match tokio::time::timeout(READ_TIMEOUT, buf_reader.read_line(&mut line)).await {
        Ok(Ok(0)) => return Ok(()), // client closed without sending
        Ok(Ok(_)) => {}
        Ok(Err(e)) => anyhow::bail!("read error: {e}"),
        Err(_) => anyhow::bail!("read timeout after {}s", READ_TIMEOUT.as_secs()),
    }

    let request: Request = match serde_json::from_str(line.trim()) {
        Ok(r) => r,
        Err(e) => {
            let resp = Response::err(format!("invalid JSON: {e}"));
            write_response(&mut writer, &resp).await?;
            return Ok(());
        }
    };

    let response = dispatch(store, &request).await;
    write_response(&mut writer, &response).await?;

    Ok(())
}

/// Write a JSON response followed by a newline, then flush.
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

/// Route a request to the appropriate store operation.
async fn dispatch(store: &Store, req: &Request) -> Response {
    match req.cmd.as_str() {
        "get" => cmd_get(store, &req.args).await,
        "log_hit" => cmd_log_hit(store, &req.args).await,
        "log_miss" => cmd_log_miss(store, &req.args).await,
        "log_compliance_miss" => cmd_log_compliance_miss(store, &req.args).await,
        "session_check_consulted" => cmd_session_check_consulted(store, &req.args).await,
        "ping" => Response::ok(serde_json::Value::String("pong".into())),
        other => Response::err(format!("unknown command: {other}")),
    }
}

// ── Command handlers ────────────────────────────────────────────────────────

/// Fetch a record by key — mirrors `hooks::run_get` logic.
async fn cmd_get(store: &Store, args: &serde_json::Value) -> Response {
    let key = match args.get("key").and_then(|v| v.as_str()) {
        Some(k) => k,
        None => return Response::err("missing args.key"),
    };

    match store.get(key).await {
        Ok(Some(record)) => match serde_json::to_value(&record) {
            Ok(val) => Response::ok(val),
            Err(e) => Response::err(format!("serialize error: {e}")),
        },
        Ok(None) => Response::ok(serde_json::Value::Null),
        Err(e) => Response::err(format!("store error: {e}")),
    }
}

/// Bump access_count and mark consulted — mirrors `hooks::log_hit_impl` logic.
async fn cmd_log_hit(store: &Store, args: &serde_json::Value) -> Response {
    let key = match args.get("key").and_then(|v| v.as_str()) {
        Some(k) => k,
        None => return Response::err("missing args.key"),
    };

    let now = now_secs();

    // 1. Daily hit aggregation
    let agg_key = today_key("analytics:hit_");
    if let Err(e) = upsert_daily_agg(store, &agg_key, key).await {
        tracing::warn!(error = %e, "daemon: hit aggregation failed");
    }

    // 2. Mark as consulted for session tracking
    let consulted_key = format!("session:consulted:{key}");
    let marker = session_record(&consulted_key, String::new());
    if let Err(e) = store.put(&consulted_key, &marker).await {
        tracing::warn!(error = %e, "daemon: consulted marker failed");
    }

    // 3. Bump access_count and last_accessed on the target record
    match store.get(key).await {
        Ok(Some(mut record)) => {
            record.access_count += 1;
            record.last_accessed = now;
            if let Err(e) = store.put(key, &record).await {
                tracing::warn!(error = %e, "daemon: access_count bump failed");
            }
        }
        Ok(None) => {}
        Err(e) => {
            tracing::warn!(error = %e, "daemon: get for access_count failed");
        }
    }

    Response::ok(serde_json::Value::String("hit logged".into()))
}

/// Record a miss — mirrors `hooks::log_miss_impl` logic.
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

/// Record a compliance miss — mirrors `hooks::log_compliance_miss_impl` logic.
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

/// Check if a key was consulted this session — mirrors `hooks::check_consulted_impl`.
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

// ── Shared helpers (mirrors hooks.rs) ───────────────────────────────────────

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn today_key(prefix: &str) -> String {
    let now = chrono::Utc::now().format("%Y-%m-%d");
    format!("{prefix}{now}")
}

fn new_device_id() -> uuid::Uuid {
    uuid::Uuid::new_v4()
}

use mati_core::store::{
    Category, ConfidenceScore, Priority, QualityScore, Record, RecordLifecycle,
    RecordSource, RecordVersion, StalenessScore,
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
    }
}

fn analytics_record(key: &str, value: String) -> Record {
    let mut r = session_record(key, value);
    r.category = Category::Analytics;
    r
}

/// Daily aggregation value.
#[derive(Serialize, Deserialize)]
struct DailyAgg {
    count: u64,
    keys: Vec<String>,
}

const MAX_AGG_KEYS: usize = 100;

/// Upsert a daily aggregation record (hit or miss counter).
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

// ── Stop ────────────────────────────────────────────────────────────────────

/// Stop a running daemon by sending SIGTERM to the PID in the PID file.
pub async fn run_daemon_stop() -> Result<()> {
    let root = project_root()?;
    let pid_path = root.join("mati.pid");
    let sock_path = root.join("mati.sock");

    if !pid_path.exists() && !sock_path.exists() {
        println!("mati daemon is not running");
        return Ok(());
    }

    if let Ok(pid_str) = std::fs::read_to_string(&pid_path) {
        if let Ok(pid) = pid_str.trim().parse::<u32>() {
            // Use kill(1) to send SIGTERM — no libc/nix dependency needed
            let status = std::process::Command::new("kill")
                .arg("-TERM")
                .arg(pid.to_string())
                .status();

            match status {
                Ok(s) if s.success() => {
                    // Wait briefly for the daemon to clean up
                    tokio::time::sleep(Duration::from_millis(300)).await;
                    println!("mati daemon stopped (pid {pid})");
                }
                Ok(_) => {
                    // kill failed (process already dead) — clean up stale files
                    println!("mati daemon process {pid} already exited — cleaning up");
                }
                Err(e) => {
                    tracing::warn!(error = %e, pid, "failed to send SIGTERM");
                    println!("mati daemon: failed to signal pid {pid} — cleaning up stale files");
                }
            }
        }
    }

    // Always clean up stale socket and PID files
    let _ = std::fs::remove_file(&sock_path);
    let _ = std::fs::remove_file(&pid_path);

    Ok(())
}

// ── Status ──────────────────────────────────────────────────────────────────

/// Check if the daemon is running and responsive.
pub async fn run_daemon_status() -> Result<()> {
    let root = project_root()?;
    let sock_path = root.join("mati.sock");
    let pid_path = root.join("mati.pid");

    if !sock_path.exists() {
        println!("mati daemon is not running (no socket)");
        return Ok(());
    }

    let pid_info = std::fs::read_to_string(&pid_path)
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok());

    // Try to ping the daemon
    match daemon_request(&root, "ping", serde_json::json!({})).await {
        Some(resp) if resp.get("ok") == Some(&serde_json::Value::Bool(true)) => {
            if let Some(pid) = pid_info {
                println!("mati daemon is running (pid {pid})");
            } else {
                println!("mati daemon is running");
            }
            println!("  socket: {}", sock_path.display());
        }
        _ => {
            println!("mati daemon socket exists but is not responding");
            println!("  socket: {}", sock_path.display());
            if let Some(pid) = pid_info {
                println!("  stale pid: {pid}");
            }
            println!("  run `mati daemon stop` to clean up");
        }
    }

    Ok(())
}

// ── Client ──────────────────────────────────────────────────────────────────

/// Send a request to the daemon and return the parsed response.
///
/// Returns `None` if the daemon is not running, the socket doesn't exist,
/// or any I/O error occurs. Callers should fall back to direct `Store::open`.
pub async fn daemon_request(
    root: &Path,
    cmd: &str,
    args: serde_json::Value,
) -> Option<serde_json::Value> {
    let sock_path = root.join("mati.sock");
    if !sock_path.exists() {
        return None;
    }

    let stream = UnixStream::connect(&sock_path).await.ok()?;
    let (reader, mut writer) = stream.into_split();

    let request = serde_json::json!({ "cmd": cmd, "args": args });
    let mut request_bytes = serde_json::to_vec(&request).ok()?;
    request_bytes.push(b'\n');

    writer.write_all(&request_bytes).await.ok()?;
    writer.shutdown().await.ok()?;

    let mut buf_reader = BufReader::new(reader);
    let mut line = String::new();

    // Read with a short timeout — daemon should respond in <10ms
    match tokio::time::timeout(Duration::from_secs(2), buf_reader.read_line(&mut line)).await {
        Ok(Ok(n)) if n > 0 => {}
        _ => return None,
    }

    serde_json::from_str(line.trim()).ok()
}

/// Convenience wrapper: send a `get` command to the daemon.
///
/// Returns `Some(json_string)` with the record JSON (or `"null"` if not found),
/// or `None` if the daemon is unavailable.
pub async fn daemon_get(root: &Path, key: &str) -> Option<String> {
    let resp = daemon_request(root, "get", serde_json::json!({ "key": key })).await?;

    if resp.get("ok") != Some(&serde_json::Value::Bool(true)) {
        return None;
    }

    let data = resp.get("data")?;
    if data.is_null() {
        Some("null".to_string())
    } else {
        Some(data.to_string())
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Derive the `~/.mati/<slug>/` path for the current working directory.
fn project_root() -> Result<PathBuf> {
    let cwd = std::env::current_dir()?;
    let slug = derive_slug(&cwd);
    let home = dirs::home_dir().context("cannot determine home directory")?;
    Ok(home.join(".mati").join(slug))
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_response_ok_serialization() {
        let resp = Response::ok(serde_json::json!("pong"));
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains(r#""ok":true"#));
        assert!(json.contains(r#""data":"pong""#));
        assert!(!json.contains("error"));
    }

    #[test]
    fn test_response_err_serialization() {
        let resp = Response::err("bad request");
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains(r#""ok":false"#));
        assert!(json.contains(r#""error":"bad request""#));
        assert!(!json.contains("data"));
    }

    #[test]
    fn test_request_deserialization() {
        let json = r#"{"cmd":"get","args":{"key":"file:src/main.rs"}}"#;
        let req: Request = serde_json::from_str(json).unwrap();
        assert_eq!(req.cmd, "get");
        assert_eq!(req.args["key"], "file:src/main.rs");
    }

    #[test]
    fn test_request_deserialization_no_args() {
        let json = r#"{"cmd":"ping"}"#;
        let req: Request = serde_json::from_str(json).unwrap();
        assert_eq!(req.cmd, "ping");
        assert!(req.args.is_null());
    }

    #[tokio::test]
    async fn test_daemon_get_returns_none_without_socket() {
        let tmp = tempfile::tempdir().unwrap();
        let result = daemon_get(tmp.path(), "file:src/main.rs").await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_daemon_request_returns_none_without_socket() {
        let tmp = tempfile::tempdir().unwrap();
        let result =
            daemon_request(tmp.path(), "ping", serde_json::json!({})).await;
        assert!(result.is_none());
    }
}
