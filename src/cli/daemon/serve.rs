use super::*;

// MAX_DAEMON_CONNECTIONS removed — now imported as an alias for
// `mcp::server::MAX_CONCURRENT_CONNECTIONS` so both daemon paths share
// the canonical bound. Renaming retained as the local alias to keep the
// existing readability ("daemon connections" matches this module's voice).

/// Accept and dispatch connections with bounded concurrency, draining
/// in-flight handlers on shutdown.
///
/// Each accepted connection is spawned into a `JoinSet` holding a
/// `Semaphore` permit; up to `MAX_DAEMON_CONNECTIONS` run in parallel. The
/// permit drops on task completion (clean exit, error, or panic — tokio
/// drops it via the JoinSet either way).
///
/// On `shutdown.signal()`: the accept loop exits and every in-flight
/// handler is awaited (`join_next`) before this function returns. Each
/// handler has its own `READ_TIMEOUT` ceiling, so the drain is bounded.
/// Caller relies on this guarantee — store close happens only after this
/// function returns.
///
/// Delegates per-connection work to the shared `socket_handle_connection`
/// in `mcp::server`, which handles hook commands and MCP tool commands.
//
// Eight args (one over clippy's default `too_many_arguments` cap of 7) —
// added `active_connections` in γ-C5. Single internal call site from
// `run_daemon_start`; bundling into a config struct just to satisfy a
// style lint for a one-callsite helper is over-engineering.
#[allow(clippy::too_many_arguments)]
pub(super) async fn serve_loop_graceful(
    graph: Arc<tokio::sync::RwLock<Graph>>,
    policy_matcher: Arc<tokio::sync::RwLock<PolicyMatcherSet>>,
    repo_root: &Path,
    listener: &UnixListener,
    last_wall: &AtomicU64,
    active_connections: &Arc<AtomicU64>,
    shutdown: &mati_core::mcp::server::Shutdown,
    daemon_euid: u32,
    daemon_session: uuid::Uuid,
) {
    let semaphore = Arc::new(tokio::sync::Semaphore::new(MAX_DAEMON_CONNECTIONS));
    let mut in_flight: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();
    let repo_root_arc: Arc<PathBuf> = Arc::new(repo_root.to_path_buf());

    // RAII guard: decrement `active_connections` on task drop. Survives
    // panics in the handler body (JoinSet catches panics, but the guard's
    // Drop still runs as the future is dropped). Without this, an
    // abnormal handler exit would leak the slot and stall the daemon's
    // idle-shutdown forever.
    struct ConnGuard(Arc<AtomicU64>);
    impl Drop for ConnGuard {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::Relaxed);
        }
    }

    'accept: loop {
        // Reap completed handlers; treat panics as terminal so a single
        // bad handler doesn't strand the daemon (panic hook would have
        // already unlinked sock+pid, breaking new client connect).
        while let Some(res) = in_flight.try_join_next() {
            if let Err(e) = res {
                if e.is_panic() {
                    tracing::error!(error = ?e, "daemon: handler panicked");
                    break 'accept;
                }
            }
        }

        // Acquire concurrency permit; shutdown pre-empts.
        let permit = tokio::select! {
            biased;
            _ = shutdown.wait() => break 'accept,
            res = Arc::clone(&semaphore).acquire_owned() => match res {
                Ok(p) => p,
                Err(_) => break 'accept,
            },
        };

        // Accept connection; shutdown pre-empts.
        let stream = tokio::select! {
            biased;
            _ = shutdown.wait() => break 'accept,
            res = listener.accept() => match res {
                Ok((s, _)) => s,
                Err(e) => {
                    tracing::warn!(error = %e, "daemon: accept error");
                    drop(permit);
                    continue 'accept;
                }
            },
        };

        last_wall.store(wall_secs(), Ordering::Relaxed);

        // Peer credential check — mismatch or failure drops the connection.
        let peer = match mati_core::mcp::metadata::check_peer_cred(&stream, daemon_euid) {
            Some(p) => p,
            None => {
                drop(permit);
                continue;
            }
        };

        // Spawn the handler. The permit lives inside the task body and
        // releases on task completion (any exit kind). γ-C5: also bump
        // the active-connection counter and arm an RAII guard so the
        // count decrements on any task exit (clean, error, or panic).
        let graph_clone = Arc::clone(&graph);
        let policy_matcher_clone = Arc::clone(&policy_matcher);
        let repo_root_clone = Arc::clone(&repo_root_arc);
        active_connections.fetch_add(1, Ordering::Relaxed);
        let conn_guard = ConnGuard(Arc::clone(active_connections));
        in_flight.spawn(async move {
            let _permit = permit;
            let _conn_guard = conn_guard;
            if let Err(e) = mati_core::mcp::server::socket_handle_connection(
                graph_clone,
                policy_matcher_clone,
                &repo_root_clone,
                stream,
                peer,
                daemon_session,
            )
            .await
            {
                tracing::warn!(error = %e, "daemon: connection error");
            }
        });
    }

    let drained = in_flight.len();
    if drained > 0 {
        tracing::debug!("daemon: draining {drained} in-flight handler(s)");
    }

    // Bounded drain — symmetric with `mcp::server::serve_daemon_socket`'s
    // caller-side `SHUTDOWN_DRAIN_TIMEOUT`. Each handler has its own
    // `READ_TIMEOUT` (3s), so normal drain is fast; this ceiling exists for
    // the pathological case where SurrealKV fsync or another non-cancellable
    // path stalls under disk pressure. Without it, a single wedged handler
    // can hang `tokio::join!` indefinitely and block store close.
    const DRAIN_TIMEOUT: Duration = Duration::from_secs(5);
    let drain = tokio::time::timeout(DRAIN_TIMEOUT, async {
        while in_flight.join_next().await.is_some() {}
    })
    .await;
    if drain.is_err() {
        tracing::warn!(
            remaining = in_flight.len(),
            "daemon: drain timed out after {DRAIN_TIMEOUT:?} — aborting handlers"
        );
        in_flight.abort_all();
        // Best-effort second drain so abort takes effect before we return.
        // If a handler is genuinely uncancellable (extremely rare), the
        // outer process exit will still terminate everything.
        let _ = tokio::time::timeout(Duration::from_secs(1), async {
            while in_flight.join_next().await.is_some() {}
        })
        .await;
    }

    // Signal shutdown on exit. Critical for the unexpected-exit case
    // (handler panic detected via JoinSet → break 'accept above): the
    // outer signaler in `run_daemon_start` is awaiting OS signals that
    // never arrive, but its `_ = shutdown.wait()` branch wakes here.
    // Without this, `tokio::join!` hangs forever after a handler panic.
    // Idempotent — also safe if the outer signal already fired.
    shutdown.signal();
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
///
/// Client-side timeout for daemon ping. Health-check semantics — fail fast so
/// `StoreProxy::open` can fall back to direct mode quickly when the daemon is
/// dead. Must stay tight; raising it would slow every CLI startup.
const PING_RESPONSE_TIMEOUT: Duration = Duration::from_secs(2);

/// Client-side timeout for all other daemon requests. Comfortably above the
/// daemon's own 3s `READ_TIMEOUT` plus normal handler work, so commands that
/// issue many serial round-trips (e.g. `mati diff` over 20+ files) don't
/// spuriously fail when the daemon is also serving the MCP client.
const REQUEST_RESPONSE_TIMEOUT: Duration = Duration::from_secs(10);

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
    send_v2_raw(root, v2_cmd, REQUEST_RESPONSE_TIMEOUT).await
}

/// Send a v2 request using legacy `(cmd_str, args)` parameters.
///
/// Retained for pure-read callers (ping, get, scan_prefix, history, etc.)
/// that have not yet migrated to typed `daemon_v2`. Mutation and
/// side-effecting-read callers should use `daemon_v2` directly.
pub async fn daemon_result(root: &Path, cmd: &str, args: serde_json::Value) -> DaemonResult {
    let v2_cmd = mati_core::mcp::protocol::v1_to_v2_command(cmd, &args);
    let timeout = if cmd == "ping" {
        PING_RESPONSE_TIMEOUT
    } else {
        REQUEST_RESPONSE_TIMEOUT
    };
    send_v2_raw(root, v2_cmd, timeout).await
}

/// Low-level: connect to daemon socket, send a pre-built v2 Command JSON,
/// read and parse the v2 Response.
async fn send_v2_raw(
    root: &Path,
    v2_cmd: serde_json::Value,
    response_timeout: Duration,
) -> DaemonResult {
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
            // Denied by permission (EACCES/EPERM): the socket exists but this
            // process cannot connect — almost always a sandbox blocking UDS.
            // Distinct from NotRunning so callers can give an accurate,
            // non-retryable error instead of "daemon busy".
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                return DaemonResult::PermissionDenied;
            }
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
    match tokio::time::timeout(response_timeout, buf_reader.read_line(&mut line)).await {
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
        DaemonResult::Unresponsive | DaemonResult::PermissionDenied => None,
    }
}
