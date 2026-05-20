//! Daemon mode — keeps Store open to eliminate CLI startup overhead (M-17-A).
//!
//! The daemon listens on a Unix socket (`~/.mati/<slug>/mati.sock`) and handles
//! newline-delimited JSON requests. Hook commands and CLI commands (via
//! `StoreProxy`) route through the socket to skip the ~150ms SurrealKV init
//! cost and avoid lock contention against the daemon's exclusive flock.
//!
//! ## Protocol — v2 only on the public wire
//!
//! One v2 `protocol::Request` per connection, one v2 `protocol::Response`,
//! then close. There is no v1 fallback path on the public socket; the
//! legacy `(cmd_str, args)` form is mapped to v2 internally by
//! `daemon_result` / `protocol::v1_to_v2_command` for callers that have
//! not yet migrated to typed `daemon_v2`.
//!
//! ```json
//! // Request — v2
//! {"v":2,"id":"<uuid>","session":"<uuid>","cmd":{"type":"Ping"}}
//! {"v":2,"id":"<uuid>","session":"<uuid>","cmd":{"type":"Get","key":"file:src/main.rs"}}
//!
//! // Response — v2
//! {"v":2,"id":"<uuid>","status":"ok","data":<value>}
//! {"v":2,"id":"<uuid>","status":"err","code":"<error_code>","message":"description"}
//! ```
//!
//! ## Lifecycle
//!
//! Self-managing — no agent-specific session hooks required:
//! - Start: `mati daemon start` (or any agent's session-start script)
//! - Auto-shutdown: after [`IDLE_SHUTDOWN_SECS`] of wall-clock inactivity
//!   AND zero active UDS connections. Wall-clock (vs tokio monotonic) so
//!   sleep/wake cycles count toward idle time. The active-connection
//!   gate (γ-C5) prevents the daemon from exiting while an `mati serve`
//!   MCP proxy is holding a long-lived UDS connection — without the
//!   gate, a long Claude/Codex session that paused between tool calls
//!   would silently lose its daemon.
//! - Signal shutdown: SIGINT / SIGTERM → flush store, remove socket + PID file.
//! - Stop: `mati daemon stop` is **synchronous and authoritative**: when the
//!   command returns Ok, the daemon process is gone, the SurrealKV flock is
//!   released, and `mati.sock` / `mati.pid` are unlinked. Refuses (exit 1)
//!   when the socket is owned by an active `mati serve` (MCP) unless the
//!   caller passes `--force`.
//! - `mati init` bypasses `StoreProxy` and opens the store directly, so it
//!   requires the daemon to be stopped first. Most other CLI commands
//!   route through the socket and run while the daemon is up.
//!
//! ## Connection model
//!
//! Bounded-concurrent: handlers are spawned into a `JoinSet` capped by a
//! `Semaphore(MAX_DAEMON_CONNECTIONS)`. Reads on the underlying
//! `RwLock<Graph>` parallelize; writes serialize at the lock layer. Beyond
//! the limit, the accept loop pauses (the OS socket backlog absorbs the
//! surplus) — bounded memory under flood. Mirrors the embedded
//! `serve_daemon_socket` loop in `mcp/server.rs` so both daemon paths share
//! identical concurrency + drain semantics.

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
    Stop(DaemonStopArgs),
    /// Show whether the daemon is running and its socket path
    Status,
}

/// Arguments for `mati daemon stop`.
///
/// `--force` is required to stop a socket owned by `mati serve` (MCP) or
/// any unknown owner — preventing accidental disconnection of an active
/// Claude Code MCP session. `--timeout` bounds the SIGTERM wait before
/// escalating to SIGKILL. `--no-wait` is an escape hatch that signals
/// SIGTERM and returns without waiting (useful for supervisor scripts
/// that drive their own polling).
#[derive(Args, Debug, Default, Clone)]
pub struct DaemonStopArgs {
    /// Stop even if the socket is owned by an active MCP server (`mati serve`).
    ///
    /// Without this flag, an MCP-owned daemon refuses to stop and exits 1
    /// so callers can detect the no-op and decide how to proceed. With it,
    /// the daemon is signaled like any other.
    #[arg(long)]
    pub force: bool,

    /// Maximum seconds to wait for the daemon to exit after SIGTERM
    /// before escalating to SIGKILL. Clamped to `[1, 60]`.
    #[arg(long, default_value_t = 7)]
    pub timeout: u64,

    /// Send SIGTERM and return immediately without waiting for the process
    /// to exit. The next CLI call may still race the SurrealKV flock —
    /// only use when an external supervisor will poll for exit.
    #[arg(long)]
    pub no_wait: bool,
}

impl DaemonStopArgs {
    /// Apply the documented `[1, 60]` clamp to `timeout`.
    fn timeout_clamped(&self) -> Duration {
        Duration::from_secs(self.timeout.clamp(1, 60))
    }
}

// ── Protocol constants ───────────────────────────────────────────────────────
//
// These previously had local definitions duplicating values in
// `mcp::server`. Both daemon paths share the same operational policy
// (same idle thresholds, same socket-path limit, same concurrency cap),
// and drift between them was a real risk: pass-11 found `auto_drain`
// missing from one path while present in the other for exactly this
// reason. All now resolve to a single canonical definition.
use mati_core::mcp::server::{
    IDLE_CHECK_INTERVAL_SECS, IDLE_SHUTDOWN_SECS,
    MAX_CONCURRENT_CONNECTIONS as MAX_DAEMON_CONNECTIONS, UNIX_SOCK_PATH_MAX,
};

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
/// inactivity with no active UDS connections (γ-C5 gate). For the historic wall-clock
/// idle time. Removes the socket and PID file on any exit path.
pub async fn run_daemon_start() -> Result<()> {
    // Cold-start clock. Used to emit `startup phase=X elapsed_ms=N` lifecycle
    // events so callers waiting in `ensure_daemon` can observe progress
    // through `lifecycle.log` rather than blindly polling the socket. See
    // `src/mcp/daemon_lifecycle.rs::wait_for_ready`.
    let startup_t0 = std::time::Instant::now();

    let cwd = std::env::current_dir()?;
    // Compute mati_root separately so we can write the starting sentinel before
    // Store::open (which may fail). The sentinel tells `mati init` that a daemon
    // is starting and the store lock may be held imminently.
    let mati_root = mati_root_for(&cwd)?;

    // 1. Ensure runtime directory exists with correct permissions (0700).
    mati_core::mcp::metadata::ensure_runtime_dir(&mati_root)?;

    // 2. Stale-socket cleanup — refuse startup if a live daemon is detected.
    //
    // Run BEFORE install_panic_hook + serve_start record. Two reasons:
    //   a. If we bail on LiveDaemon, we'd otherwise leave an orphan
    //      serve_start in lifecycle.log with no terminating event.
    //   b. If our process panicked between install_panic_hook and the
    //      bail, the hook would unlink the *other* daemon's sock+pid
    //      (same paths under our slug). Hostile to the live daemon.
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

    // 2b. Concurrent-start coordination via `mati.starting` sentinel.
    //
    // The window between `check_and_cleanup_stale` and `publish_metadata` is
    // ~50–100ms (Store::open dominates). Two `mati daemon start` invocations
    // landing in this window both see Clean/StaleRemoved at step 2, both
    // proceed past it, and then race on `Store::open` — the loser surfaces
    // a "store already locked" error AFTER having clobbered the winner's
    // sentinel and emitted a confusing serve_failed lifecycle event.
    //
    // The sentinel was added precisely as a "daemon is starting" signal for
    // observers (init.rs, hook_decide.rs) but `check_and_cleanup_stale` does
    // not consult it. Doing the check inline here — only on the daemon-start
    // path — avoids changing `StaleCheckResult`'s public API while closing
    // the most damaging window.
    if check_starting_peer_active(&mati_root) {
        anyhow::bail!(
            "another mati daemon is starting up. Wait a few seconds, then retry:\n\
             \n  mati daemon status\n\
             \nIf the previous start crashed, the sentinel will expire after {STARTING_STALE_SECS}s."
        );
    }

    // Past the stale check — we are now committed to becoming THE daemon
    // for this slug. Install the panic hook + record `serve_start` here so
    // the panic hook only ever unlinks files we own, and lifecycle.log
    // only ever has a serve_start that corresponds to a real serve attempt.
    mati_core::mcp::metadata::install_panic_hook(mati_root.clone());
    mati_core::mcp::metadata::record_lifecycle_event(
        &mati_root,
        "serve_start",
        &format!("pid={} owner=daemon", std::process::id()),
    );

    let starting_path = mati_root.join("mati.starting");
    let _ = std::fs::write(
        &starting_path,
        format_sentinel(wall_secs(), std::process::id()),
    );

    // Helper closure: on every failure path between sentinel-write and
    // sentinel-removal-on-success, also remove the sentinel so we don't
    // leak a "I'm starting" marker that confuses init.rs / hook_decide.rs
    // observers (and that no future success path will clean up). Mirrors
    // the panic hook's responsibility for sock+pid (see run_panic_cleanup).
    let cleanup_sentinel = || {
        let _ = std::fs::remove_file(&starting_path);
    };

    let repo_root = Arc::new(std::fs::canonicalize(&cwd).inspect_err(|e| {
        mati_core::mcp::metadata::record_lifecycle_event(
            &mati_root,
            "serve_failed",
            &format!("canonicalize cwd: {e}"),
        );
        cleanup_sentinel();
    })?);

    // Phase: opening_store. Migration (if pending) runs inside Store::open and
    // emits its own granular events; see `src/store/migrations.rs::migrate`.
    mati_core::mcp::metadata::record_lifecycle_event(
        &mati_root,
        "startup",
        "phase=opening_store",
    );
    let store_t0 = std::time::Instant::now();
    let store = Store::open(&cwd).await.inspect_err(|e| {
        mati_core::mcp::metadata::record_lifecycle_event(
            &mati_root,
            "serve_failed",
            &format!("store open: {e:#}"),
        );
        cleanup_sentinel();
    })?;
    mati_core::mcp::metadata::record_lifecycle_event(
        &mati_root,
        "startup",
        &format!("phase=store_opened elapsed_ms={}", store_t0.elapsed().as_millis()),
    );

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
        .context("failed to load knowledge graph")
        .inspect_err(|e| {
            mati_core::mcp::metadata::record_lifecycle_event(
                &mati_root,
                "serve_failed",
                &format!("graph load: {e:#}"),
            );
            cleanup_sentinel();
        })?;

    // Auto-drain dirty-marker queue from a previous unclean shutdown.
    // Mirrors the path in `mcp::server::serve()` so the supervisor-driven
    // daemon (which uses this code path) gets the same boot-time crash
    // recovery as the MCP-spawned auto-promoted daemon. Bounded by
    // AUTO_DRAIN_TIMEOUT so a pathological queue can't block startup.
    if mati_core::store::repair::is_dirty(graph.store()).await {
        let drain_fut = mati_core::store::repair::repair_gotcha_indexes(
            graph.store(),
            mati_core::store::repair::RepairMode::Fast,
        );
        match tokio::time::timeout(mati_core::mcp::server::AUTO_DRAIN_TIMEOUT, drain_fut).await {
            Ok(Ok(report)) => {
                tracing::info!(
                    "daemon: auto-drained dirty gotcha index (drift_remaining={})",
                    report.total_drift()
                );
                mati_core::mcp::metadata::record_lifecycle_event(
                    &mati_root,
                    "auto_repair",
                    &format!("drift_remaining={}", report.total_drift()),
                );
            }
            Ok(Err(e)) => {
                tracing::warn!("daemon: auto-drain failed: {e}");
                mati_core::mcp::metadata::record_lifecycle_event(
                    &mati_root,
                    "auto_repair_failed",
                    &format!("{e}"),
                );
            }
            Err(_) => {
                tracing::warn!("daemon: auto-drain timed out — serving with stale derived state");
                mati_core::mcp::metadata::record_lifecycle_event(
                    &mati_root,
                    "auto_repair_timeout",
                    &format!("timeout={:?}", mati_core::mcp::server::AUTO_DRAIN_TIMEOUT),
                );
            }
        }
    }

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
        mati_core::mcp::metadata::record_lifecycle_event(
            &mati_root,
            "serve_failed",
            &format!("sock_path_too_long: {sock_path_bytes}>{UNIX_SOCK_PATH_MAX}"),
        );
        cleanup_sentinel();
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
        .with_context(|| format!("failed to bind Unix socket at {}", sock_path.display()))
        .inspect_err(|e| {
            mati_core::mcp::metadata::record_lifecycle_event(
                &mati_root,
                "serve_failed",
                &format!("bind: {e:#}"),
            );
            cleanup_sentinel();
        })?;

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
        .with_context(|| format!("failed to write PID file at {}", pid_path.display()))
        .inspect_err(|e2| {
            mati_core::mcp::metadata::record_lifecycle_event(
                &mati_root,
                "serve_failed",
                &format!("publish+pid fallback both failed: publish={e:#} legacy={e2:#}"),
            );
            cleanup_sentinel();
        })?;
    }
    // PID is written — remove the starting sentinel so `mati init` won't block.
    let _ = std::fs::remove_file(&starting_path);

    // Phase: ready. Terminal success state of the cold-start sequence. The
    // socket is bound, metadata is published, and the daemon is committed to
    // accepting connections. Callers waiting in `ensure_daemon` look for
    // this event to break out of their state-aware readiness loop.
    mati_core::mcp::metadata::record_lifecycle_event(
        &mati_root,
        "startup",
        &format!("phase=ready elapsed_ms={}", startup_t0.elapsed().as_millis()),
    );

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

    // γ-C5: live count of UDS connections currently being handled.
    // Idle-shutdown is gated on BOTH last_wall staleness AND zero active
    // connections — a long-running `mati serve` MCP proxy that keeps a
    // UDS connection open between tool calls must not have the daemon
    // exit out from under it. Incremented at accept time; decremented
    // via RAII drop guard in the spawned handler so panics and abnormal
    // task exits both correctly bring the count back down.
    let active_connections = Arc::new(AtomicU64::new(0));

    // Idle-check background task. After γ-C5 the predicate is:
    //   shutdown ⇔ (now - last_wall >= IDLE_SHUTDOWN_SECS)
    //              ∧ (active_connections == 0)
    // The double condition prevents the historical foot-gun where a
    // long-lived MCP-proxy connection kept appearing "idle" by the
    // wall-clock metric and got shut down mid-session.
    let idle_notify = Arc::new(tokio::sync::Notify::new());
    {
        let last_wall = last_wall.clone();
        let active_connections = active_connections.clone();
        let notify = idle_notify.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(IDLE_CHECK_INTERVAL_SECS));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                let now = wall_secs();
                let last = last_wall.load(Ordering::Relaxed);
                let active = active_connections.load(Ordering::Relaxed);
                if now.saturating_sub(last) >= IDLE_SHUTDOWN_SECS && active == 0 {
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
    // in-flight connections drain (never cancelled mid-write).
    //
    // Uses the shared `Shutdown` primitive from `mcp::server` whose
    // `wait()` is race-free: the `Notified::enable()` registration happens
    // before the flag check, so a `signal()` between flag-check and
    // notify-fire cannot strand a waiter.
    let shutdown = mati_core::mcp::server::Shutdown::new();

    // Atomic-indexed reason slot. Avoids the need for `Arc<Mutex<...>>` or
    // `oneshot` plumbing through the join arm. Index → REASONS lookup.
    use std::sync::atomic::AtomicUsize;
    const REASONS: &[&str] = &[
        "unknown",         // 0
        "signal_sigint",   // 1
        "signal_sigterm",  // 2
        "idle_timeout",    // 3
        "serve_loop_exit", // 4
        "signal_sighup",   // 5
    ];
    let reason_idx = Arc::new(AtomicUsize::new(0));

    // Run serve_loop and the shutdown-watcher concurrently with join! so
    // that serve_loop is NEVER cancelled by tokio. It exits only after
    // every in-flight handler returns, ensuring all writes are committed
    // before store.close() is called.
    //
    // The signaler arm includes `shutdown.wait()` as one of its select
    // branches: when serve_loop_graceful exits unexpectedly (handler
    // panic detected via JoinSet) it signals shutdown on its way out, so
    // the signaler wakes via that branch instead of hanging on an OS
    // signal that never arrives.
    let daemon_euid = mati_core::mcp::metadata::current_euid();

    let reason_idx_clone = Arc::clone(&reason_idx);
    tokio::join!(
        serve_loop_graceful(
            Arc::clone(&graph),
            &repo_root,
            &listener,
            &last_wall,
            &active_connections,
            &shutdown,
            daemon_euid,
            daemon_session,
        ),
        async {
            let ctrl_c = tokio::signal::ctrl_c();
            #[cfg(unix)]
            let idx = {
                let mut sigterm =
                    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                        .expect("failed to register SIGTERM handler");
                // SIGHUP default action is termination, bypassing graceful shutdown.
                // A daemon may receive SIGHUP if its session leader disconnects without
                // a supervisor taking over. Treat as SIGTERM. If registration fails,
                // log and continue — SIGTERM is the critical signal for managed daemons.
                let sighup_result =
                    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup());
                if let Err(ref e) = sighup_result {
                    tracing::warn!(
                        error = %e,
                        "daemon: failed to install SIGHUP handler — \
                         SIGHUP will use OS default (terminate without cleanup)"
                    );
                }
                let mut sighup_opt = sighup_result.ok();
                tokio::select! {
                    _ = ctrl_c => {
                        tracing::info!("mati daemon: signal shutdown (SIGINT)");
                        eprintln!("mati daemon shutting down");
                        1
                    }
                    _ = sigterm.recv() => {
                        tracing::info!("mati daemon: signal shutdown (SIGTERM)");
                        eprintln!("mati daemon shutting down");
                        2
                    }
                    _ = idle_notify.notified() => {
                        // Idle shutdown message already printed in idle-check task.
                        3
                    }
                    _ = shutdown.wait() => {
                        // serve_loop_graceful self-exited (e.g., handler panic).
                        tracing::warn!("mati daemon: serve_loop exited — initiating shutdown");
                        4
                    }
                    Some(_) = async {
                        if let Some(ref mut s) = sighup_opt { s.recv().await } else { None }
                    } => {
                        tracing::info!("mati daemon: signal shutdown (SIGHUP)");
                        eprintln!("mati daemon shutting down");
                        5
                    }
                }
            };
            #[cfg(not(unix))]
            let idx = tokio::select! {
                _ = ctrl_c => {
                    tracing::info!("mati daemon: signal shutdown");
                    eprintln!("mati daemon shutting down");
                    1
                }
                _ = idle_notify.notified() => 3,
                _ = shutdown.wait() => 4,
            };
            reason_idx_clone.store(idx, std::sync::atomic::Ordering::SeqCst);
            // Signal serve_loop_graceful to stop accepting and drain in-flight.
            // Idempotent — also safe if serve_loop already signaled on its own exit.
            shutdown.signal();
        }
    );

    let shutdown_reason: &'static str = {
        let i = reason_idx.load(std::sync::atomic::Ordering::SeqCst);
        REASONS.get(i).copied().unwrap_or("unknown")
    };

    // Cleanup — runs only AFTER serve_loop_graceful has finished the in-flight
    // connection. Store is closed cleanly with no concurrent writers.
    let _ = std::fs::remove_file(&starting_path); // belt-and-suspenders
    let _ = std::fs::remove_file(&sock_path);
    let _ = std::fs::remove_file(&pid_path);
    mati_core::mcp::metadata::record_lifecycle_event(&mati_root, "serve_shutdown", shutdown_reason);
    // Reclaim exclusive ownership of the Store so we can run the full close
    // (which flushes both trees AND the search index, then releases the
    // kernel flock). If `Arc::try_unwrap` fails — which can happen briefly
    // if `serve_loop_graceful`'s drain timed out and aborted handlers are
    // still completing their current await — fall back to a non-consuming
    // `flush_for_shutdown` via the shared Arc. Without that fallback,
    // SurrealKV's `Tree::Drop` only fire-and-forget-spawns the close,
    // which the runtime may not finish before process exit, losing
    // committed-but-buffered Eventual-durability writes.
    match Arc::try_unwrap(graph) {
        Ok(rwlock) => {
            if let Err(e) = rwlock.into_inner().close().await {
                tracing::warn!("daemon: store close warning on shutdown: {e}");
            }
        }
        Err(graph) => {
            tracing::warn!(
                "daemon: graph Arc still referenced on shutdown — flushing without close"
            );
            let g = graph.read().await;
            g.store().flush_for_shutdown().await;
        }
    }
    Ok(())
}

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
async fn serve_loop_graceful(
    graph: Arc<tokio::sync::RwLock<Graph>>,
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
        let repo_root_clone = Arc::clone(&repo_root_arc);
        active_connections.fetch_add(1, Ordering::Relaxed);
        let conn_guard = ConnGuard(Arc::clone(active_connections));
        in_flight.spawn(async move {
            let _permit = permit;
            let _conn_guard = conn_guard;
            if let Err(e) = mati_core::mcp::server::socket_handle_connection(
                graph_clone,
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

/// Returns true when `~/.mati/<slug>/mati.starting` indicates that another
/// daemon-start is currently in progress (PID alive, or — for legacy
/// timestamp-only sentinels — written within `STARTING_STALE_SECS`).
///
/// Side effect: when the sentinel is present but stale (PID dead or legacy
/// timestamp expired), it is removed so our own subsequent write doesn't
/// race a separate stale-cleanup path. A sentinel naming our own PID is
/// treated as inactive (re-entry case where a prior failure path didn't
/// clean up; we own it, we replace it).
///
/// Mirrors the sentinel semantics used by `cli::init` and
/// `cli::hook_decide` so the three observers agree on what counts as
/// "another mati is starting".
fn check_starting_peer_active(mati_root: &Path) -> bool {
    let starting_path = mati_root.join("mati.starting");
    let content = match std::fs::read_to_string(&starting_path) {
        Ok(c) => c,
        Err(_) => return false, // sentinel absent → no peer
    };
    let now = wall_secs();
    let active = if let Some((_ts, pid)) = parse_sentinel(&content) {
        pid != std::process::id() && mati_core::mcp::metadata::is_pid_alive(pid)
    } else if let Ok(ts) = content.trim().parse::<u64>() {
        now.saturating_sub(ts) < STARTING_STALE_SECS
    } else {
        false
    };
    if !active {
        // Stale sentinel — remove so our own write below isn't a clobber
        // racing with another stale-cleanup path.
        let _ = std::fs::remove_file(&starting_path);
    }
    active
}

// `is_pid_alive` previously duplicated `mcp::metadata::is_pid_alive`.
// Removed — single canonical implementation in `mcp::metadata` is used by
// all callers (supervisor, init, hooks, stale-checks).

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

/// Re-exported alias of the shared kill-outcome enum. Lives in
/// `mati_core::mcp::metadata` so the unresponsive-recovery branch in
/// `daemon_lifecycle::ensure_daemon` can share the same primitive.
pub(crate) use mati_core::mcp::metadata::KillOutcome as ExitOutcome;

/// Classification of the daemon's on-disk state. Drives the stop state machine.
#[derive(Debug)]
enum DaemonState {
    /// No pid file, no socket — nothing to stop.
    Empty,
    /// Files present but no live owner — safe to clean up unconditionally.
    StaleFiles,
    /// Live daemon process owned by `mati daemon start`.
    LiveOwnerDaemon { pid: u32 },
    /// Live socket+pid owned by `mati serve` (MCP).
    /// Refused without `--force` because killing it disconnects Claude Code.
    LiveOwnerMcp { pid: u32 },
    /// Pid file absent but socket pings ok — some live owner exists.
    /// We try to recover an owning PID for the kill flow; without it,
    /// the user must clean up manually.
    LiveOwnerUnknown {
        pid: Option<u32>,
        /// True if we recovered the PID via `read_metadata`. False if
        /// even metadata is missing — `lsof` was the only fallback.
        from_metadata: bool,
    },
    /// Only `mati.starting` exists with a live PID — daemon is mid-startup.
    /// Refused without `--force` to avoid racing the startup sentinel.
    StartingSentinelOnly { pid: u32 },
    /// PID alive, socket exists, but ping fails. The daemon is broken.
    /// Force is not required — we are recovering, not interrupting.
    Unresponsive { pid: u32 },
}

/// Read the starting sentinel and return `Some(pid)` only when its PID is alive.
fn live_starting_pid(root: &Path) -> Option<u32> {
    let content = std::fs::read_to_string(root.join("mati.starting")).ok()?;
    let (_, pid) = parse_sentinel(&content)?;
    if mati_core::mcp::metadata::is_pid_alive(pid) {
        Some(pid)
    } else {
        None
    }
}

/// Last-resort PID recovery for the `LiveOwnerUnknown` state, gated by
/// `--force`. Asks `lsof -tU <sock>` (Darwin/Linux) which prints the PID(s)
/// of every process that has the socket open. The first parseable u32 wins.
///
/// The shell out is intentional: there is no portable libc API to query
/// Unix-socket peers without binding to a peer-cred-bearing endpoint, and
/// `lsof` is present on every supported development platform. Failures
/// are returned as `None` — the caller surfaces a clear error.
#[cfg(unix)]
fn lsof_owning_pid(sock_path: &Path) -> Option<u32> {
    let out = std::process::Command::new("lsof")
        .args(["-tU"])
        .arg(sock_path)
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .find_map(|tok| tok.parse::<u32>().ok())
}

#[cfg(not(unix))]
fn lsof_owning_pid(_sock_path: &Path) -> Option<u32> {
    None
}

/// Classify the daemon state into the matrix above. Pure: no signals, no fs
/// mutations beyond the ping path which is read-only on the daemon side.
async fn classify_daemon(root: &Path, force: bool) -> DaemonState {
    let pid_path = root.join("mati.pid");
    let sock_path = root.join("mati.sock");
    let starting_path = root.join("mati.starting");

    let has_pid = pid_path.exists();
    let has_sock = sock_path.exists();
    let has_starting = starting_path.exists();

    if !has_pid && !has_sock {
        if has_starting {
            if let Some(pid) = live_starting_pid(root) {
                return DaemonState::StartingSentinelOnly { pid };
            }
        }
        return DaemonState::Empty;
    }

    let pid_info = read_pid_file(root);

    match pid_info {
        Some((pid, owner)) => {
            if !mati_core::mcp::metadata::is_pid_alive(pid) {
                return DaemonState::StaleFiles;
            }
            if owner == "mcp" {
                return DaemonState::LiveOwnerMcp { pid };
            }
            // Owner reported as "daemon" but socket may be unresponsive —
            // distinguish so we can communicate the right reason to the user.
            if has_sock {
                match daemon_result(root, "ping", serde_json::json!({})).await {
                    DaemonResult::Ok(_) => DaemonState::LiveOwnerDaemon { pid },
                    DaemonResult::Unresponsive => DaemonState::Unresponsive { pid },
                    DaemonResult::NotRunning | DaemonResult::StaleSocket => DaemonState::StaleFiles,
                }
            } else {
                DaemonState::LiveOwnerDaemon { pid }
            }
        }
        None => {
            if !has_sock {
                return DaemonState::StaleFiles;
            }
            match daemon_result(root, "ping", serde_json::json!({})).await {
                DaemonResult::Ok(_) => {
                    // Try metadata first (richer than the legacy pid file).
                    let meta_pid = mati_core::mcp::metadata::read_metadata(root).map(|m| m.pid);
                    if meta_pid.is_some() {
                        return DaemonState::LiveOwnerUnknown {
                            pid: meta_pid,
                            from_metadata: true,
                        };
                    }
                    let lsof_pid = if force {
                        lsof_owning_pid(&sock_path)
                    } else {
                        None
                    };
                    DaemonState::LiveOwnerUnknown {
                        pid: lsof_pid,
                        from_metadata: false,
                    }
                }
                DaemonResult::StaleSocket | DaemonResult::NotRunning => DaemonState::StaleFiles,
                DaemonResult::Unresponsive => {
                    let pid = mati_core::mcp::metadata::read_metadata(root).map(|m| m.pid);
                    match pid {
                        Some(pid) => DaemonState::Unresponsive { pid },
                        None => DaemonState::StaleFiles,
                    }
                }
            }
        }
    }
}

/// Re-export the shared `kill_and_wait` helper for in-crate callers.
pub(crate) use mati_core::mcp::metadata::kill_and_wait;

/// Send SIGTERM directly via `libc::kill`. Returns `true` on success or
/// when the kernel reports the process is already gone. Used by the
/// `--no-wait` escape hatch where we skip the bundled wait loop.
#[cfg(unix)]
fn send_sigterm_only(pid: u32) -> bool {
    // SAFETY: `kill(pid, SIGTERM)` is a standard POSIX system call. The
    // worst case is an ESRCH return — we treat that as success because
    // the contract is "stop this process" and a nonexistent process is
    // already stopped.
    let ret = unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
    if ret == 0 {
        return true;
    }
    let errno = std::io::Error::last_os_error().raw_os_error();
    matches!(errno, Some(libc::ESRCH))
}

#[cfg(not(unix))]
fn send_sigterm_only(_pid: u32) -> bool {
    false
}

/// Wait up to 500ms for the daemon to unlink its sock + pid files.
/// If still present, unlink ourselves so the next CLI call doesn't see
/// a half-dead daemon. Returns `true` if removal completed cleanly.
async fn wait_for_files_removed(root: &Path) -> bool {
    const FILE_POLL_BUDGET: Duration = Duration::from_millis(500);
    const FILE_POLL_INTERVAL: Duration = Duration::from_millis(20);

    let sock = root.join("mati.sock");
    let pid = root.join("mati.pid");
    let starting = root.join("mati.starting");

    let deadline = std::time::Instant::now() + FILE_POLL_BUDGET;
    while std::time::Instant::now() < deadline {
        if !sock.exists() && !pid.exists() {
            let _ = std::fs::remove_file(&starting);
            return true;
        }
        tokio::time::sleep(FILE_POLL_INTERVAL).await;
    }

    let _ = std::fs::remove_file(&sock);
    let _ = std::fs::remove_file(&pid);
    let _ = std::fs::remove_file(&starting);
    false
}

/// Stop a running daemon authoritatively: classify the on-disk state, send
/// SIGTERM (with optional SIGKILL escalation), wait for exit, and clean up
/// any residual sock/pid files. Returns Ok(()) only when the daemon is
/// guaranteed to be gone or there was nothing to stop. Refuses (exits 1)
/// when the socket is owned by an active MCP server unless `--force` is set.
pub async fn run_daemon_stop(args: DaemonStopArgs) -> Result<()> {
    let root = project_root()?;
    let timeout = args.timeout_clamped();

    // Lifecycle: stop_start. Best-effort PID/owner discovery for the event.
    let (start_pid, start_owner) = match read_pid_file(&root) {
        Some((p, o)) => (Some(p), Some(o)),
        None => (None, None),
    };
    let pid_target = start_pid
        .map(|p| p.to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let owner_str = start_owner.unwrap_or_else(|| "unknown".to_string());
    mati_core::mcp::metadata::record_lifecycle_event(
        &root,
        "stop_start",
        &format!(
            "pid_target={pid_target} owner={owner_str} force={}",
            args.force
        ),
    );

    let state = classify_daemon(&root, args.force).await;

    match state {
        DaemonState::Empty => {
            println!("mati daemon: not running");
            mati_core::mcp::metadata::record_lifecycle_event(
                &root,
                "stop_end",
                "pid=none reason=noop elapsed_ms=0 signal=none",
            );
            Ok(())
        }
        DaemonState::StaleFiles => {
            // No live process — unlink everything and report.
            let sock = root.join("mati.sock");
            let pid = root.join("mati.pid");
            let starting = root.join("mati.starting");
            let _ = std::fs::remove_file(&sock);
            let _ = std::fs::remove_file(&pid);
            let _ = std::fs::remove_file(&starting);
            println!("mati daemon: cleaned up stale files (no live process)");
            mati_core::mcp::metadata::record_lifecycle_event(
                &root,
                "stop_end",
                "pid=none reason=stale elapsed_ms=0 signal=none",
            );
            Ok(())
        }
        DaemonState::LiveOwnerDaemon { pid } => {
            kill_flow(&root, pid, "daemon", &args, timeout).await
        }
        DaemonState::LiveOwnerMcp { pid } => {
            if !args.force {
                println!(
                    "mati daemon: refused — owner=mcp, rerun with --force to stop the MCP server"
                );
                mati_core::mcp::metadata::record_lifecycle_event(
                    &root,
                    "stop_end",
                    &format!("pid={pid} reason=refused elapsed_ms=0 signal=none"),
                );
                anyhow::bail!(
                    "refused to stop the active MCP server (pid {pid}); rerun with --force"
                );
            }
            kill_flow(&root, pid, "mcp", &args, timeout).await
        }
        DaemonState::LiveOwnerUnknown { pid, from_metadata } => {
            if !args.force {
                println!(
                    "mati daemon: refused — owner=unknown, rerun with --force to stop the active socket"
                );
                mati_core::mcp::metadata::record_lifecycle_event(
                    &root,
                    "stop_end",
                    "pid=unknown reason=refused elapsed_ms=0 signal=none",
                );
                anyhow::bail!("refused to stop a socket with unknown owner; rerun with --force");
            }
            match pid {
                Some(pid) => {
                    let owner_label = if from_metadata { "unknown" } else { "lsof" };
                    kill_flow(&root, pid, owner_label, &args, timeout).await
                }
                None => {
                    mati_core::mcp::metadata::record_lifecycle_event(
                        &root,
                        "stop_end",
                        "pid=unknown reason=refused elapsed_ms=0 signal=none",
                    );
                    anyhow::bail!(
                        "could not identify the owning process (no metadata, lsof returned nothing); manual intervention required"
                    );
                }
            }
        }
        DaemonState::StartingSentinelOnly { pid } => {
            if !args.force {
                println!(
                    "mati daemon: refused — a daemon is starting (pid {pid}), rerun with --force to abort"
                );
                mati_core::mcp::metadata::record_lifecycle_event(
                    &root,
                    "stop_end",
                    &format!("pid={pid} reason=refused elapsed_ms=0 signal=none"),
                );
                anyhow::bail!("refused to abort starting daemon (pid {pid}); rerun with --force");
            }
            kill_flow(&root, pid, "starting", &args, timeout).await
        }
        DaemonState::Unresponsive { pid } => {
            // Force is not required — daemon is broken and we are recovering.
            kill_flow(&root, pid, "unresponsive", &args, timeout).await
        }
    }
}

/// Send SIGTERM to `pid`, optionally wait for exit, and clean up files.
///
/// Records a `stop_end` lifecycle event with the elapsed time and signal
/// classification. On `--no-wait`, returns immediately after sending TERM.
///
/// Concurrent-stop safety: we capture the daemon session UUID before signaling
/// and re-check after exit. If the UUID changed, a fresh daemon claimed the
/// slot in the gap — we abort our cleanup so as not to clobber the new one.
async fn kill_flow(
    root: &Path,
    pid: u32,
    owner_label: &str,
    args: &DaemonStopArgs,
    timeout: Duration,
) -> Result<()> {
    let pre_session = mati_core::mcp::metadata::read_metadata(root).map(|m| m.session);

    if args.no_wait {
        if !send_sigterm_only(pid) {
            mati_core::mcp::metadata::record_lifecycle_event(
                root,
                "stop_end",
                &format!("pid={pid} reason=signal_failed elapsed_ms=0 signal=TERM"),
            );
            anyhow::bail!("failed to send SIGTERM to pid {pid}");
        }
        println!("mati daemon: SIGTERM sent (pid {pid}); not waiting");
        mati_core::mcp::metadata::record_lifecycle_event(
            root,
            "stop_end",
            &format!("pid={pid} reason=no_wait elapsed_ms=0 signal=TERM"),
        );
        return Ok(());
    }

    let outer_start = std::time::Instant::now();
    let outcome = kill_and_wait(pid, timeout).await;

    match outcome {
        ExitOutcome::ExitedClean(elapsed) => {
            let elapsed_ms = elapsed.as_millis();
            // Re-check session UUID — if a fresh daemon spun up in the gap,
            // do NOT touch its files. Cleaner classifies as "noop success".
            let post_session = mati_core::mcp::metadata::read_metadata(root).map(|m| m.session);
            let recycled = matches!((pre_session, post_session), (Some(a), Some(b)) if a != b);
            if !recycled {
                wait_for_files_removed(root).await;
            }
            println!(
                "mati daemon: stopped (pid {pid}, owner={owner_label}, took {elapsed_ms}ms, signal=TERM)"
            );
            mati_core::mcp::metadata::record_lifecycle_event(
                root,
                "stop_end",
                &format!("pid={pid} reason=clean_exit elapsed_ms={elapsed_ms} signal=TERM"),
            );
            Ok(())
        }
        ExitOutcome::KilledHard(elapsed) => {
            let elapsed_ms = elapsed.as_millis();
            let post_session = mati_core::mcp::metadata::read_metadata(root).map(|m| m.session);
            let recycled = matches!((pre_session, post_session), (Some(a), Some(b)) if a != b);
            if !recycled {
                wait_for_files_removed(root).await;
            }
            eprintln!(
                "[mati] WARNING: daemon (pid {pid}) did not respond to SIGTERM; killed with SIGKILL"
            );
            println!(
                "mati daemon: force-killed (pid {pid}, owner={owner_label}, took {elapsed_ms}ms, signal=KILL)"
            );
            mati_core::mcp::metadata::record_lifecycle_event(
                root,
                "stop_end",
                &format!("pid={pid} reason=hard_kill elapsed_ms={elapsed_ms} signal=KILL"),
            );
            Ok(())
        }
        ExitOutcome::Stuck => {
            let elapsed_ms = outer_start.elapsed().as_millis();
            mati_core::mcp::metadata::record_lifecycle_event(
                root,
                "stop_end",
                &format!("pid={pid} reason=stuck elapsed_ms={elapsed_ms} signal=KILL"),
            );
            anyhow::bail!(
                "mati daemon: failed (pid {pid}) — process did not exit even after SIGKILL; manual intervention required"
            );
        }
    }
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

    // Regression tests for the multi-process daemon-start race (audit pass 20,
    // checkpoint A). Two `mati daemon start` invocations landing inside the
    // ~100ms window between `check_and_cleanup_stale` and `publish_metadata`
    // both used to see Clean and race on the SurrealKV flock. The sentinel
    // check closes that window.

    #[test]
    fn check_starting_peer_active_absent_sentinel_returns_false() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!check_starting_peer_active(dir.path()));
    }

    #[test]
    fn check_starting_peer_active_dead_pid_returns_false_and_cleans_up() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mati.starting");
        // Use a PID that's almost certainly dead.
        std::fs::write(&path, format_sentinel(wall_secs(), 4_000_000)).unwrap();

        assert!(!check_starting_peer_active(dir.path()));
        // Stale sentinel must be removed so the next start path doesn't
        // race a separate stale-cleanup.
        assert!(
            !path.exists(),
            "stale sentinel must be cleaned up so concurrent stale-cleanup paths don't race"
        );
    }

    #[test]
    fn check_starting_peer_active_alive_pid_returns_true() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mati.starting");
        // Use a PID guaranteed to be alive AND not our own (a peer process).
        // PID 1 is init/launchd on Unix and is always alive. We assert in a
        // separate path below that this PID is not our own — if for some
        // reason the test runs as PID 1, skip rather than false-fail.
        let peer_pid = 1u32;
        if std::process::id() == peer_pid {
            return;
        }
        std::fs::write(&path, format_sentinel(wall_secs(), peer_pid)).unwrap();

        assert!(
            check_starting_peer_active(dir.path()),
            "alive peer PID must be classified as active starting peer"
        );
        // The sentinel must be preserved when the peer is active — removing
        // it would confuse other observers (init.rs, hook_decide.rs) that
        // also rely on this signal.
        assert!(path.exists(), "active sentinel must NOT be removed");
    }

    #[test]
    fn check_starting_peer_active_self_pid_returns_false() {
        // A sentinel naming our own PID is the "I crashed without cleaning
        // up, restarting in the same shell" case. Returning true would
        // wedge the user in a permanent bail loop. Returning false (and
        // cleaning up) lets the new start replace it.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mati.starting");
        std::fs::write(&path, format_sentinel(wall_secs(), std::process::id())).unwrap();

        assert!(
            !check_starting_peer_active(dir.path()),
            "sentinel for our own PID must not block our own restart"
        );
        assert!(!path.exists(), "self-pid sentinel must be removed");
    }

    #[test]
    fn check_starting_peer_active_legacy_recent_timestamp_returns_true() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mati.starting");
        // Legacy format: timestamp only (no PID). Recent → still active.
        std::fs::write(&path, format!("{}\n", wall_secs())).unwrap();

        assert!(check_starting_peer_active(dir.path()));
    }

    #[test]
    fn check_starting_peer_active_legacy_old_timestamp_returns_false() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mati.starting");
        // Legacy format, well past STARTING_STALE_SECS in the past.
        let stale_ts = wall_secs().saturating_sub(STARTING_STALE_SECS + 60);
        std::fs::write(&path, format!("{stale_ts}\n")).unwrap();

        assert!(!check_starting_peer_active(dir.path()));
        assert!(!path.exists(), "stale legacy sentinel must be removed");
    }

    #[test]
    fn check_starting_peer_active_garbage_content_returns_false() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mati.starting");
        std::fs::write(&path, "not a real sentinel ~~").unwrap();

        // Unparseable content — treated as inactive and cleaned up so it
        // doesn't permanently block startups.
        assert!(!check_starting_peer_active(dir.path()));
        assert!(!path.exists());
    }

    // is_pid_alive tests live in `mcp::metadata::tests` since the canonical
    // implementation is there; the cli/daemon duplicate was removed.

    // ── Regression: daemon-stop must wait for process exit ────────────────
    //
    // `mati daemon stop` previously sent SIGTERM and returned immediately,
    // which let the next CLI invocation (e.g. `mati repair --check`) race
    // the daemon on the SurrealKV flock at `knowledge.db/LOCK`. The Codex
    // smoke driver hit this race, misdiagnosed it as a hung daemon, and
    // ran `pkill -f mati` — killing its own MCP server child.
    //
    // These tests pin the contract: `kill_and_wait` returns ExitedClean
    // only when the PID is actually gone (OS-level liveness check), and
    // escalates to SIGKILL when the SIGTERM budget elapses.

    #[cfg(unix)]
    #[tokio::test]
    async fn kill_and_wait_returns_exited_clean_on_sigterm_responsive_process() {
        // Spawn `sleep 60` — a real long-running process that exits cleanly
        // on SIGTERM. `kill_and_wait` sends SIGTERM and verifies it waits
        // until the process is actually gone.
        //
        // IMPORTANT: a child of *this test process* turns into a zombie on
        // exit until we `wait()` it. `kill(pid, 0)` returns success for
        // zombies, so `is_pid_alive` would never report it as gone unless
        // we reap concurrently. Spawn a reaper task that calls `child.wait()`
        // while `kill_and_wait` polls — this matches production, where
        // the daemon is reaped by its supervisor / shell, not by `mati`.
        let mut child = tokio::process::Command::new("sleep")
            .arg("60")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .expect("spawn sleep");
        let pid = child.id().expect("child pid available pre-wait");

        assert!(
            mati_core::mcp::metadata::is_pid_alive(pid),
            "spawned sleep should be alive"
        );

        // Concurrent reaper — drains the zombie so kill(pid, 0) reports
        // ESRCH once the child exits. Mirrors how a supervisor/shell parent
        // would reap the daemon in production.
        let reaper = tokio::spawn(async move { child.wait().await });

        let start = std::time::Instant::now();
        let outcome = kill_and_wait(pid, Duration::from_secs(7)).await;
        let elapsed = start.elapsed();

        let _ = reaper.await;

        assert!(
            matches!(outcome, ExitOutcome::ExitedClean(_)),
            "expected ExitedClean, got {outcome:?}"
        );
        assert!(
            !mati_core::mcp::metadata::is_pid_alive(pid),
            "after kill_and_wait returns ExitedClean, the PID must be gone — the SurrealKV flock guarantee depends on this"
        );
        assert!(
            elapsed < Duration::from_secs(2),
            "sleep exits cleanly on SIGTERM in well under 1s — kill_and_wait took {elapsed:?}, suggesting the poll loop is broken"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn kill_and_wait_escalates_to_sigkill_on_uncooperative_process() {
        // Spawn a shell that traps SIGTERM and ignores it: this is a
        // portable way to exercise the SIGKILL escalation branch on both
        // macOS and Linux. The shell is `sh`, present on every Unix.
        let mut child = tokio::process::Command::new("sh")
            .arg("-c")
            .arg("trap '' TERM; sleep 60")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .expect("spawn trap sh");
        let pid = child.id().expect("child pid available pre-wait");

        // Give the shell a moment to install its trap before we signal.
        tokio::time::sleep(Duration::from_millis(200)).await;

        assert!(
            mati_core::mcp::metadata::is_pid_alive(pid),
            "spawned trap sh should be alive"
        );

        let reaper = tokio::spawn(async move { child.wait().await });

        // Use a 2s budget — the trap absorbs SIGTERM so we want to hit the
        // SIGKILL branch quickly. Production default is 7s.
        let budget = Duration::from_secs(2);
        let start = std::time::Instant::now();
        let outcome = kill_and_wait(pid, budget).await;
        let elapsed = start.elapsed();

        let _ = reaper.await;

        assert!(
            matches!(outcome, ExitOutcome::KilledHard(_)),
            "expected KilledHard, got {outcome:?}"
        );
        assert!(
            !mati_core::mcp::metadata::is_pid_alive(pid),
            "after SIGKILL, the PID must be gone — process is still alive"
        );
        // The full SIGTERM budget must elapse before SIGKILL fires —
        // proves the escalation path was actually taken.
        assert!(
            elapsed >= budget,
            "SIGKILL escalation must wait the full SIGTERM budget ({budget:?}); took only {elapsed:?}"
        );
        // SIGKILL reaping plus 500ms window — generous upper bound for CI.
        assert!(
            elapsed < budget + Duration::from_secs(3),
            "SIGKILL should have reaped within ~500ms of escalation; took {elapsed:?}"
        );
    }
}
