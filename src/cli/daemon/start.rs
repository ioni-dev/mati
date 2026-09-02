use super::*;

pub async fn run_daemon_start() -> Result<()> {
    // Cold-start clock. Used to emit `startup phase=X elapsed_ms=N` lifecycle
    // events so callers waiting in `ensure_daemon` can observe progress
    // through `lifecycle.log` rather than blindly polling the socket. See
    // `src/mcp/daemon_lifecycle.rs::wait_for_ready`.
    let startup_t0 = std::time::Instant::now();

    let cwd = std::env::current_dir()?;
    // One discover call grounds both `mati_root` (the slug) and `repo_root`
    // (below) in the same git identity. Computed separately from Store::open
    // so we can write the starting sentinel before it (which may fail). The
    // sentinel tells `mati init` that a daemon is starting and the store
    // lock may be held imminently.
    let repo_ident = RepoIdent::discover(&cwd);
    let mati_root = mati_root_for_ident(&repo_ident, &cwd)?;

    // 1. Ensure runtime directory exists with correct permissions (0700).
    mati_core::mcp::metadata::ensure_runtime_dir(&mati_root)?;

    // Redirect this process's tracing output into <root>/daemon.log now that
    // the directory exists. Anything logged before this — and anything logged
    // if the redirect fails — still goes to stderr, which `ensure_daemon`
    // captures into daemon_start.log.
    mati_core::mcp::daemon_log::install(&mati_root);

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

    // Git-grounded, not raw cwd: `repo_ident.slug_root` is the same value
    // `mati_root`'s slug falls back to when the repo has no remote, so this
    // can never name a different repo than the store it just resolved —
    // unlike a bare `canonicalize(cwd)`, which knows nothing about gitlinks
    // (submodules, linked worktrees) and previously could.
    let repo_root = Arc::new(repo_ident.slug_root(&cwd));

    // Phase: opening_store. Migration (if pending) runs inside Store::open and
    // emits its own granular events; see `src/store/migrations.rs::migrate`.
    mati_core::mcp::metadata::record_lifecycle_event(&mati_root, "startup", "phase=opening_store");
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
        &format!(
            "phase=store_opened elapsed_ms={}",
            store_t0.elapsed().as_millis()
        ),
    );

    // Clear stale session:consulted:* markers from previous sessions. Lockdown
    // markers go with them — a debt from a dead session must not lock this one
    // down before it has run anything.
    if let Ok(keys) = store
        .scan_keys(mati_core::store::session::OWED_PREFIX)
        .await
    {
        for k in &keys {
            let _ = store.delete(k).await;
        }
    }
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

    // Tier 2: the wipe above lapsed every consultation in this worktree, so
    // every file the manifest lists goes back to mode 000. Store-free, and it
    // reads `store.root` rather than recomputing the slug so it can never name
    // a different manifest than the receipt lift does.
    let rearmed = mati_core::seal::rearm_all(&store.root);
    if !rearmed.is_empty() {
        tracing::info!("daemon: re-armed {} sealed file(s)", rearmed.len());
    }

    // Every window with no daemon is a window with no enforcement. Best-effort:
    // a daemon that refuses to start because it could not write an audit event
    // is worse than the missing event (P9).
    match mati_core::store::enforcement::detect_startup_gap(
        &store,
        mati_core::store::enforcement::STARTUP_GAP_THRESHOLD_MS,
    )
    .await
    {
        Ok(Some(event)) => {
            tracing::info!(
                "daemon: recorded RecordingGap (seq {}) — the event log was quiet past the threshold",
                event.seq_no
            );
        }
        Ok(None) => {}
        Err(e) => tracing::warn!("daemon: startup gap detection failed: {e}"),
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
            &repo_root,
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
    let policy_matcher = Arc::new(tokio::sync::RwLock::new(
        mati_core::mcp::dispatch_v2::load_policy_matcher(graph.read().await.store()).await,
    ));

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

    // The daemon is the authoritative metrics surface (dispatch_v2 records
    // every command here, not on the `mati serve` proxy path) -- initialize
    // before the serve loop starts accepting connections, or every sample
    // dies at METRICS.get() in metrics::record.
    mati_core::mcp::metrics::init();

    // Phase: ready. Terminal success state of the cold-start sequence. The
    // socket is bound, metadata is published, and the daemon is committed to
    // accepting connections. Callers waiting in `ensure_daemon` look for
    // this event to break out of their state-aware readiness loop.
    mati_core::mcp::metadata::record_lifecycle_event(
        &mati_root,
        "startup",
        &format!(
            "phase=ready elapsed_ms={}",
            startup_t0.elapsed().as_millis()
        ),
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
        let mati_root = mati_root.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(IDLE_CHECK_INTERVAL_SECS));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;

                // A daemon kept alive by continuous use never restarts, so
                // the startup-only trim in `install_panic_hook` never fires
                // again — and every `mati serve` proxy it hands off to also
                // appends lifecycle lines. Re-trim here so `lifecycle.log`
                // stays bounded across an arbitrarily long-lived daemon.
                mati_core::mcp::metadata::trim_lifecycle_log(
                    &mati_root,
                    mati_core::mcp::metadata::MAX_LIFECYCLE_LINES,
                );

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
            Arc::clone(&policy_matcher),
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

    // The chain-native record that this run stopped deliberately. Must be the
    // LAST event of the run — it sits here, after `serve_loop_graceful` has
    // drained in-flight handlers, because a handler still running writes
    // enforcement events and any event after the terminator makes the next
    // start read a clean stop as a crash (ARCHITECTURE.md section 18.2).
    // Best-effort (P9): a failed write degrades to looking like a crash.
    {
        let store = graph.read().await;
        match mati_core::store::enforcement::record_clean_shutdown(store.store(), shutdown_reason)
            .await
        {
            Ok(Some(event)) => tracing::debug!(
                "daemon: recorded CleanShutdown (seq {}) reason={shutdown_reason}",
                event.seq_no
            ),
            Ok(None) => {}
            Err(e) => tracing::warn!("daemon: clean-shutdown terminator write failed: {e}"),
        }
    }

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
