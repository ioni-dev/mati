use super::*;

// Protocol type serialization tests removed — Request/Response types
// now live in mcp::server as SocketRequest/SocketResponse and are
// tested there.

// ── --include-mcp scoping ───────────────────────────────────────────

fn write_lifecycle(root: &std::path::Path, lines: &[(u32, &str, &str)]) {
    let body: String = lines
        .iter()
        .map(|(pid, event, detail)| format!("1700000000\t{pid}\t{event}\t{detail}\n"))
        .collect();
    std::fs::write(root.join("lifecycle.log"), body).unwrap();
}

/// The whole point of the fix: a `mati serve` this store never recorded is
/// not ours to kill.
///
/// `pgrep -f "mati serve"` matches every proxy on the host, and `root` used
/// to reach only the audit line — so `mati daemon stop --include-mcp` on a
/// disposable `MATI_HOME` SIGKILLed the MCP server of an unrelated store.
#[test]
fn include_mcp_spares_serves_this_store_never_recorded() {
    let dir = tempfile::tempdir().unwrap();
    write_lifecycle(dir.path(), &[(4242, "serve_start", "pid=4242 owner=proxy")]);

    assert_eq!(
        serve_pids_to_kill(dir.path(), &[4242, 9999]),
        vec![4242],
        "9999 belongs to some other store's lifecycle.log"
    );
}

/// No log, no claim. A store that has never seen a proxy kills nothing,
/// even with proxies running on the host.
#[test]
fn include_mcp_kills_nothing_without_a_lifecycle_log() {
    let dir = tempfile::tempdir().unwrap();
    assert!(serve_pids_to_kill(dir.path(), &[4242, 9999]).is_empty());
}

#[test]
fn recorded_serve_pids_tracks_start_and_termination() {
    let dir = tempfile::tempdir().unwrap();
    write_lifecycle(
        dir.path(),
        &[
            (10, "serve_start", "pid=10 owner=proxy"),
            (11, "serve_start", "pid=11 owner=proxy"),
            // The daemon writes serve_start too — never a kill target.
            (12, "serve_start", "pid=12 owner=daemon"),
            (11, "serve_shutdown", "reason=client_disconnect"),
        ],
    );

    let pids = recorded_serve_pids(dir.path());
    assert!(pids.contains(&10));
    assert!(!pids.contains(&11), "a shut-down proxy is gone");
    assert!(!pids.contains(&12), "owner=daemon is not a proxy");
}

/// A recycled PID must not resurrect a claim: the proxy that owned it
/// recorded its exit, so the process running under it now is someone else's.
#[test]
fn a_terminated_pid_is_not_reclaimed_by_a_later_run() {
    let dir = tempfile::tempdir().unwrap();
    write_lifecycle(
        dir.path(),
        &[
            (77, "serve_start", "pid=77 owner=proxy"),
            (77, "serve_failed", "proxy init: boom"),
        ],
    );
    assert!(serve_pids_to_kill(dir.path(), &[77]).is_empty());
}

#[test]
fn include_mcp_never_targets_itself() {
    let dir = tempfile::tempdir().unwrap();
    let me = std::process::id();
    write_lifecycle(
        dir.path(),
        &[(me, "serve_start", &format!("pid={me} owner=proxy"))],
    );
    assert!(serve_pids_to_kill(dir.path(), &[me]).is_empty());
}

#[test]
fn read_tail_returns_whole_file_when_under_cap() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("lifecycle.log");
    std::fs::write(&path, b"short content\n").unwrap();
    assert_eq!(read_tail(&path, 1024).unwrap(), "short content\n");
}

#[test]
fn read_tail_drops_the_partial_leading_line() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("lifecycle.log");
    std::fs::write(&path, b"111111\ttrunc\n222222\tkeep\n").unwrap();
    // Cap lands mid-way through the first line, not on a line boundary.
    assert_eq!(read_tail(&path, 16).unwrap(), "222222\tkeep\n");
}

/// The bug: `recorded_serve_pids` used to `read_to_string` the whole log
/// on every `--include-mcp` scan. A store whose daemon has run long
/// enough to accumulate a multi-megabyte log (the periodic trim bounds
/// growth going forward, but does nothing for a log that predates it)
/// would load the entire thing into memory on every stop. Confirms the
/// scan is now capped: an event outside the trailing scan window is not
/// seen, exactly like a truncated log — under-inclusive, not unbounded.
#[test]
fn recorded_serve_pids_ignores_events_outside_the_scan_window() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("lifecycle.log");

    let mut body = String::new();
    body.push_str("1700000000\t111\tserve_start\tpid=111 owner=proxy\n");
    let filler_line = "1700000000\t0\tnoise\tpadding\n";
    let repeats = (RECORDED_SERVE_SCAN_MAX_BYTES as usize / filler_line.len()) + 1000;
    body.push_str(&filler_line.repeat(repeats));
    body.push_str("1700000000\t222\tserve_start\tpid=222 owner=proxy\n");
    std::fs::write(&path, &body).unwrap();
    assert!(
        body.len() as u64 > RECORDED_SERVE_SCAN_MAX_BYTES,
        "test log must exceed the scan cap to be meaningful"
    );

    let pids = recorded_serve_pids(dir.path());
    assert!(pids.contains(&222), "recent event must be seen");
    assert!(
        !pids.contains(&111),
        "event outside the scan window must not be seen"
    );
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
