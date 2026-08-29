use super::*;

/// The root repo-relative record paths resolve against.
///
/// `Commands::Serve` canonicalizes its `--path` but never discovers, so the
/// launch cwd can sit below the repo root while `derive_slug` discovers upward
/// and opens the store keyed to the root. Joining a root-relative `file:` key
/// onto the subdirectory would stat a path that does not exist and read as
/// "still deleted", so the `FileDeleted` bypass would stay open on exactly the
/// restore this check exists to catch. `slug_root` is the repo's own answer —
/// "callers that must resolve repo-relative record paths against the same root
/// the store was named for" — and is what `StoreProxy::open` already uses.
fn stat_root(repo_root: &Path) -> PathBuf {
    crate::store::RepoIdent::discover(repo_root).slug_root(repo_root)
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
    let mati_root: PathBuf = crate::store::mati_home_opt()
        .map(|h| h.join(crate::store::derive_slug(repo_root)))
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
        &format!(
            "phase=ready elapsed_ms={}",
            startup_t0.elapsed().as_millis()
        ),
    );

    // MCP stdio proxy: every tool call forwards over UDS to the daemon.
    // The worktree tag is computed once, here, from this process's own
    // launch cwd — `mati serve` never changes directory afterward, so a
    // single git2 lookup at startup is enough for the life of the session.
    let worktree_tag = crate::store::session::worktree_scope_tag(repo_root);
    let transport = rmcp::transport::io::stdio();
    let service =
        MatiServer::with_socket_root(mati_root.clone(), stat_root(repo_root), worktree_tag)
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

#[cfg(test)]
mod tests {
    use super::stat_root;
    use tempfile::TempDir;

    /// `mati serve --path <repo>/sub` canonicalizes but never discovers, while
    /// `derive_slug` discovers upward and opens the store keyed to the root.
    /// The stat root must follow the store, or a root-relative `file:` key
    /// joins onto the subdirectory, stats a path that does not exist, and the
    /// `FileDeleted` bypass stays open on the restore it exists to catch.
    #[test]
    fn stat_root_resolves_a_subdirectory_launch_to_the_repo_root() {
        let dir = TempDir::new().unwrap();
        git2::Repository::init(dir.path()).unwrap();
        let sub = dir.path().join("crates").join("inner");
        std::fs::create_dir_all(&sub).unwrap();

        let root = std::fs::canonicalize(dir.path()).unwrap();
        assert_eq!(
            stat_root(&sub),
            root,
            "a subdir launch must stat from the root"
        );
        assert_eq!(stat_root(dir.path()), root, "a root launch is unchanged");
    }

    /// Outside a repo there is nothing to discover, so the launch path stands.
    #[test]
    fn stat_root_falls_back_to_the_launch_path_outside_a_repo() {
        let dir = TempDir::new().unwrap();
        assert_eq!(
            stat_root(dir.path()),
            std::fs::canonicalize(dir.path()).unwrap()
        );
    }
}
