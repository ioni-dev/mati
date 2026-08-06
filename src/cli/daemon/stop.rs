use super::*;

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
        // γ-C6: --force + --no-wait → SIGKILL directly.
        let (sent, signal_label) = if args.force {
            (send_sigkill_only(pid), "KILL")
        } else {
            (send_sigterm_only(pid), "TERM")
        };
        if !sent {
            mati_core::mcp::metadata::record_lifecycle_event(
                root,
                "stop_end",
                &format!("pid={pid} reason=signal_failed elapsed_ms=0 signal={signal_label}"),
            );
            anyhow::bail!("failed to send SIG{signal_label} to pid {pid}");
        }
        println!("mati daemon: SIG{signal_label} sent (pid {pid}); not waiting");
        mati_core::mcp::metadata::record_lifecycle_event(
            root,
            "stop_end",
            &format!("pid={pid} reason=no_wait elapsed_ms=0 signal={signal_label}"),
        );
        if args.include_mcp {
            kill_mati_serve_processes(root).await;
        }
        return Ok(());
    }

    let outer_start = std::time::Instant::now();
    // γ-C6: --force skips the SIGTERM grace period and sends SIGKILL
    // directly. The historical "override safety refusal" meaning of
    // --force is preserved by the refusal-bypass at the call sites
    // upstream; here it now also reshapes the kill itself.
    let outcome = if args.force {
        mati_core::mcp::metadata::kill_directly(pid).await
    } else {
        kill_and_wait(pid, timeout).await
    };

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
            let signal_label = if args.force { "KILL" } else { "TERM" };
            println!(
                "mati daemon: stopped (pid {pid}, owner={owner_label}, took {elapsed_ms}ms, signal={signal_label})"
            );
            mati_core::mcp::metadata::record_lifecycle_event(
                root,
                "stop_end",
                &format!(
                    "pid={pid} reason=clean_exit elapsed_ms={elapsed_ms} signal={signal_label}"
                ),
            );
            if args.include_mcp {
                kill_mati_serve_processes(root).await;
            }
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
            if args.include_mcp {
                kill_mati_serve_processes(root).await;
            }
            Ok(())
        }
        ExitOutcome::Stuck(diag) => {
            let elapsed_ms = outer_start.elapsed().as_millis();
            // Render the diagnostic so post-mortem analysis can pinpoint
            // the actual cause: kill(0)-lying-after-SIGKILL, zombie,
            // PID reuse, or genuinely-stuck. See `StuckDiagnostic` and
            // `PidSnapshot` docstrings for the interpretation key.
            let initial = diag.initial_snapshot.render();
            let final_snap = diag.final_snapshot.render();
            let sigterm_part = diag
                .sigterm_elapsed_ms
                .map(|ms| format!(" sigterm_ms={ms}"))
                .unwrap_or_default();
            let detail = format!(
                "pid={pid} reason=stuck elapsed_ms={elapsed_ms} signal=KILL{sigterm_part} \
                 sigkill_ms={} initial={{{initial}}} final={{{final_snap}}}",
                diag.sigkill_elapsed_ms,
            );
            mati_core::mcp::metadata::record_lifecycle_event(root, "stop_end", &detail);
            eprintln!(
                "[mati] daemon-stop Stuck diagnostic — \
                 pid={pid} total_ms={} sigterm_ms={:?} sigkill_ms={}",
                diag.total_elapsed_ms, diag.sigterm_elapsed_ms, diag.sigkill_elapsed_ms
            );
            eprintln!("[mati]   initial snapshot: {initial}");
            eprintln!("[mati]   final snapshot:   {final_snap}");
            anyhow::bail!(
                "mati daemon: failed (pid {pid}) — process did not exit even after SIGKILL; \
                 manual intervention required (see lifecycle.log and stderr for diagnostic)"
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
                "  log:    {}",
                mati_core::mcp::daemon_log::log_path(&root).display()
            );
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
