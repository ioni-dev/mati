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
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use rmcp::model::{ServerCapabilities, ServerInfo};
use rmcp::{ServerHandler, ServiceExt, tool_handler};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

use crate::graph::Graph;
use crate::store::Store;

use super::tools::MatiServer;

#[tool_handler(router = self.tool_router)]
impl ServerHandler for MatiServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_instructions(
                "mati — engineering knowledge that survives turnover. \
                 Use mem_get to look up records, mem_query to search, \
                 and mem_bootstrap at session start.",
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
    let store = Store::open_and_rebuild(repo_root)
        .await
        .context("failed to open mati store")?;

    // Clear session:consulted:* markers from the previous session.
    // These are written by log_hit and used by pre-read/pre-bash hooks to downgrade
    // deny → allow+context after a mem_get call. They must be scoped to the current
    // session — any leftovers from a previous session would permanently bypass deny.
    if let Ok(keys) = store.scan_keys("session:consulted:").await {
        for k in &keys {
            let _ = store.delete(k).await;
        }
        if !keys.is_empty() {
            tracing::debug!("serve: cleared {} stale session:consulted markers", keys.len());
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
    let service = server.serve(transport).await.map_err(|e| {
        anyhow::anyhow!("MCP server initialization failed: {e}")
    })?;

    service.waiting().await?;
    Ok(())
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
        Self { ok: true, version: PROTOCOL_VERSION, data: Some(data), error: None }
    }
    fn err(msg: impl Into<String>) -> Self {
        Self { ok: false, version: PROTOCOL_VERSION, data: None, error: Some(msg.into()) }
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
            tracing::warn!("mati serve: failed to bind daemon socket at {}: {e}", sock_path.display());
            return;
        }
    };
    let _ = std::fs::write(&pid_path, format!(r#"{{"pid":{},"owner":"mcp"}}"#, std::process::id()));
    tracing::debug!("daemon socket ready at {} (MCP-embedded)", sock_path.display());

    loop {
        let stream = match listener.accept().await {
            Ok((s, _)) => s,
            Err(e) => { tracing::warn!("daemon socket accept: {e}"); continue; }
        };
        // Read lock covers one full request/response cycle.
        // Store methods use interior mutability — a read lock is sufficient.
        let g = graph.read().await;
        if let Err(e) = socket_handle_connection(g.store(), &repo_root, stream).await {
            tracing::debug!("daemon socket connection: {e}");
        }
    }
}

async fn socket_handle_connection(
    store: &Store,
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

    let resp = socket_dispatch(store, repo_root, &req).await;
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

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn today_key(prefix: &str) -> String {
    let now = chrono::Utc::now().format("%Y-%m-%d");
    format!("{prefix}{now}")
}

async fn socket_dispatch(store: &Store, repo_root: &Path, req: &SocketRequest) -> SocketResponse {
    use crate::store::{
        Category, ConfidenceScore, Priority, QualityScore, Record, RecordLifecycle,
        RecordSource, RecordVersion, StalenessScore, TombstoneReason,
    };
    use crate::graph::edges::{Edge, EdgeKind};

    match req.cmd.as_str() {
        "ping" => SocketResponse::ok(serde_json::Value::String("pong".into())),

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
                                obj.insert("confirmed".to_string(), serde_json::Value::Bool(confirmed));
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
            let now = now_secs();
            let agg_key = today_key("analytics:hit_");
            if let Err(e) = upsert_daily_agg(store, &agg_key, key).await {
                tracing::warn!("daemon socket log_hit agg: {e}");
            }
            let consulted_key = format!("session:consulted:{key}");
            let session_rec = make_session_record(&consulted_key, String::new(), now);
            let _ = store.put(&consulted_key, &session_rec).await;
            if let Ok(Some(mut record)) = store.get(key).await {
                record.access_count += 1;
                record.last_accessed = now;
                let _ = store.put(key, &record).await;
            }
            SocketResponse::ok(serde_json::Value::Null)
        }

        "log_miss" => {
            let key = match req.args.get("key").and_then(|v| v.as_str()) {
                Some(k) => k,
                None => return SocketResponse::err("missing args.key"),
            };
            let agg_key = today_key("analytics:miss_");
            if let Err(e) = upsert_daily_agg(store, &agg_key, key).await {
                tracing::warn!("daemon socket log_miss: {e}");
            }
            SocketResponse::ok(serde_json::Value::Null)
        }

        "log_compliance_miss" => {
            let key = match req.args.get("key").and_then(|v| v.as_str()) {
                Some(k) => k,
                None => return SocketResponse::err("missing args.key"),
            };
            let agg_key = today_key("compliance:miss_");
            if let Err(e) = upsert_daily_agg(store, &agg_key, key).await {
                tracing::warn!("daemon socket log_compliance_miss: {e}");
            }
            SocketResponse::ok(serde_json::Value::Null)
        }

        "session_check_consulted" => {
            let key = match req.args.get("key").and_then(|v| v.as_str()) {
                Some(k) => k,
                None => return SocketResponse::err("missing args.key"),
            };
            let consulted_key = format!("session:consulted:{key}");
            match store.get(&consulted_key).await {
                Ok(found) => SocketResponse::ok(serde_json::Value::Bool(found.is_some())),
                Err(e) => SocketResponse::err(format!("store: {e}")),
            }
        }

        "session_flush" => {
            let now = now_secs();
            let consulted_keys = match store.scan_keys("session:consulted:").await {
                Ok(keys) => keys,
                Err(e) => return SocketResponse::err(format!("scan_keys: {e}")),
            };
            let stripped: Vec<String> = consulted_keys
                .iter()
                .map(|k| k.strip_prefix("session:consulted:").unwrap_or(k).to_string())
                .collect();
            let value = match serde_json::to_string(&serde_json::json!({
                "consulted_keys": stripped,
                "flushed_at": now,
            })) {
                Ok(v) => v,
                Err(e) => return SocketResponse::err(format!("serialize: {e}")),
            };
            let rec = make_session_record("session:current", value, now);
            if let Err(e) = store.put("session:current", &rec).await {
                tracing::warn!("daemon socket session_flush: {e}");
            }
            SocketResponse::ok(serde_json::Value::Null)
        }

        "session_harvest" => {
            // Lightweight harvest: write permanent session record without staleness analysis.
            // Staleness analysis (git2) is !Send and runs on the CLI-path harvest instead.
            let now = now_secs();
            let session_rec = match store.get("session:current").await {
                Ok(Some(r)) => r,
                Ok(None) => return SocketResponse::ok(serde_json::Value::Null),
                Err(e) => return SocketResponse::err(format!("store: {e}")),
            };
            let session_value = match session_rec.payload.as_ref() {
                Some(p) => serde_json::to_string(p).unwrap_or_default(),
                None => session_rec.value.clone(),
            };
            let session_key = format!("session:{now}");
            let mut perm = make_session_record(&session_key, session_value, now);
            perm.payload = session_rec.payload;
            if let Err(e) = store.put(&session_key, &perm).await {
                tracing::warn!("daemon socket session_harvest: {e}");
            }
            // Clean up consulted markers
            if let Ok(keys) = store.scan_keys("session:consulted:").await {
                for k in &keys {
                    let _ = store.delete(k).await;
                }
            }
            SocketResponse::ok(serde_json::Value::Null)
        }

        "edit_hook" => {
            let path = match req.args.get("path").and_then(|v| v.as_str()) {
                Some(p) => p,
                None => return SocketResponse::err("missing args.path"),
            };
            let file_key = format!("file:{path}");
            let now = now_secs();
            let agg_key = today_key("analytics:hit_");
            let _ = upsert_daily_agg(store, &agg_key, &file_key).await;
            let consulted_key = format!("session:consulted:{file_key}");
            let session_rec = make_session_record(&consulted_key, String::new(), now);
            let _ = store.put(&consulted_key, &session_rec).await;
            if let Ok(Some(mut record)) = store.get(&file_key).await {
                record.access_count += 1;
                record.last_accessed = now;
                let _ = store.put(&file_key, &record).await;
            }
            if let Err(e) = crate::analysis::reparse::reparse_impl(store, repo_root, path).await {
                tracing::warn!("daemon socket edit_hook: reparse failed (non-fatal): {e}");
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
            let key = match req.args.get("key").and_then(|v| v.as_str()) {
                Some(k) => k,
                None => return SocketResponse::err("missing args.key"),
            };
            let record: Record = match req.args.get("record")
                .and_then(|v| serde_json::from_value(v.clone()).ok())
            {
                Some(r) => r,
                None => return SocketResponse::err("put: invalid record"),
            };
            match store.put(key, &record).await {
                Ok(()) => SocketResponse::ok(serde_json::Value::Null),
                Err(e) => SocketResponse::err(format!("store: {e}")),
            }
        }

        "gotcha_write" => {
            let record: Record = match req.args.get("record")
                .and_then(|v| serde_json::from_value(v.clone()).ok())
            {
                Some(r) => r,
                None => return SocketResponse::err("missing or invalid args.record"),
            };
            let key = record.key.clone();
            let new_files: Vec<String> = req.args.get("new_files")
                .and_then(|v| serde_json::from_value(v.clone()).ok())
                .unwrap_or_default();
            let old_files: Vec<String> = req.args.get("old_files")
                .and_then(|v| serde_json::from_value(v.clone()).ok())
                .unwrap_or_default();

            if let Err(e) = store.put(&key, &record).await {
                return SocketResponse::err(format!("store put: {e}"));
            }

            let old_set: std::collections::HashSet<&str> =
                old_files.iter().map(String::as_str).collect();
            let new_set: std::collections::HashSet<&str> =
                new_files.iter().map(String::as_str).collect();

            for file_path in &new_files {
                let file_key = format!("file:{file_path}");
                if let Ok(Some(mut file_record)) = store.get(&file_key).await {
                    match file_record.payload.as_mut() {
                        Some(payload) => {
                            if let Some(arr) = payload.get_mut("gotcha_keys")
                                .and_then(|v| v.as_array_mut())
                            {
                                if !arr.iter().any(|v| v.as_str() == Some(key.as_str())) {
                                    arr.push(serde_json::Value::String(key.clone()));
                                }
                            } else if let Some(obj) = payload.as_object_mut() {
                                obj.insert("gotcha_keys".into(), serde_json::json!([&key]));
                            }
                        }
                        None => {
                            file_record.payload = Some(serde_json::json!({ "gotcha_keys": [&key] }));
                        }
                    }
                    let _ = store.put(&file_key, &file_record).await;
                }
                if !old_set.contains(file_path.as_str()) {
                    let edge_key = Edge::new(&file_key, EdgeKind::HasGotcha, &key).to_key();
                    let ts = now_secs().to_le_bytes();
                    let _ = store.put_raw(&edge_key, &ts).await;
                }
            }
            for file_path in &old_files {
                if !new_set.contains(file_path.as_str()) {
                    let file_key = format!("file:{file_path}");
                    let edge_key = Edge::new(&file_key, EdgeKind::HasGotcha, &key).to_key();
                    let _ = store.delete(&edge_key).await;
                }
            }
            SocketResponse::ok(serde_json::Value::String("written".into()))
        }

        "gotcha_tombstone" => {
            let key = match req.args.get("key").and_then(|v| v.as_str()) {
                Some(k) => k,
                None => return SocketResponse::err("missing args.key"),
            };
            let affected_files: Vec<String> = req.args.get("affected_files")
                .and_then(|v| serde_json::from_value(v.clone()).ok())
                .unwrap_or_default();

            match store.get(key).await {
                Ok(Some(mut record)) => {
                    let now = now_secs();
                    record.lifecycle = RecordLifecycle::Tombstoned {
                        reason: TombstoneReason::ManualDeletion,
                        at: now,
                    };
                    record.updated_at = now;
                    record.version.logical_clock += 1;
                    record.version.wall_clock = now;
                    if let Err(e) = store.put(key, &record).await {
                        return SocketResponse::err(format!("store put: {e}"));
                    }
                }
                Ok(None) => return SocketResponse::err(format!("not found: {key}")),
                Err(e) => return SocketResponse::err(format!("store get: {e}")),
            }
            for file_path in &affected_files {
                let file_key = format!("file:{file_path}");
                let edge_key = Edge::new(&file_key, EdgeKind::HasGotcha, key).to_key();
                let _ = store.delete(&edge_key).await;
            }
            SocketResponse::ok(serde_json::Value::String("tombstoned".into()))
        }

        other => SocketResponse::err(format!("unknown command: {other}")),
    }
}

fn make_session_record(key: &str, value: String, now: u64) -> crate::store::Record {
    use crate::store::{
        Category, ConfidenceScore, Priority, QualityScore, Record, RecordLifecycle,
        RecordSource, RecordVersion, StalenessScore,
    };
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
            device_id: uuid::Uuid::new_v4(),
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

fn make_analytics_record(key: &str, value: String, now: u64) -> crate::store::Record {
    let mut r = make_session_record(key, value, now);
    r.category = crate::store::Category::Analytics;
    r
}

#[derive(serde::Serialize, serde::Deserialize)]
struct DailyAgg {
    count: u64,
    keys: Vec<String>,
}

const MAX_AGG_KEYS: usize = 100;

async fn upsert_daily_agg(store: &Store, agg_key: &str, target_key: &str) -> anyhow::Result<()> {
    let now = now_secs();
    match store.get(agg_key).await? {
        Some(mut record) => {
            let mut agg: DailyAgg = record
                .payload_as::<DailyAgg>()
                .unwrap_or(DailyAgg { count: 0, keys: vec![] });
            agg.count += 1;
            if agg.keys.len() < MAX_AGG_KEYS && !agg.keys.iter().any(|k| k == target_key) {
                agg.keys.push(target_key.to_string());
            }
            record.payload = serde_json::to_value(&agg).ok();
            record.updated_at = now;
            record.version.logical_clock += 1;
            record.version.wall_clock = now;
            store.put(agg_key, &record).await?;
        }
        None => {
            let agg = DailyAgg { count: 1, keys: vec![target_key.to_string()] };
            let mut record = make_analytics_record(agg_key, String::new(), now);
            record.payload = serde_json::to_value(&agg).ok();
            store.put(agg_key, &record).await?;
        }
    }
    Ok(())
}
