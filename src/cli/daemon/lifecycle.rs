use super::*;

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
pub(super) fn format_sentinel(ts: u64, pid: u32) -> String {
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
pub(super) fn check_starting_peer_active(mati_root: &Path) -> bool {
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
    mati_root_for_ident(&RepoIdent::discover(cwd), cwd)
}

/// [`mati_root_for`] for a caller that already discovered a [`RepoIdent`]
/// this invocation — avoids a second `git2::Repository::discover` call for
/// the same repo (see `cli::hook_decide::entry::run_inner` and
/// `run_daemon_start`).
pub fn mati_root_for_ident(ident: &RepoIdent, fallback: &Path) -> Result<PathBuf> {
    let slug = ident.slug(fallback);
    // Single source of truth for the mati root — honors `$MATI_HOME` so the
    // daemon socket/root resolves to the same place `Store::open` writes.
    Ok(mati_core::store::mati_home()?.join(slug))
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
pub(super) fn project_root() -> Result<PathBuf> {
    let cwd = std::env::current_dir()?;
    mati_root_for(&cwd)
}

/// Unix seconds from wall clock (not monotonic — survives sleep/wake).
pub(super) fn wall_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ── Stop ─────────────────────────────────────────────────────────────────────

/// Re-exported alias of the shared kill-outcome enum. Lives in
/// `mati_core::mcp::metadata` so the unresponsive-recovery branch in
/// `daemon_lifecycle::ensure_daemon` can share the same primitive.
pub(super) use mati_core::mcp::metadata::KillOutcome as ExitOutcome;

/// Classification of the daemon's on-disk state. Drives the stop state machine.
#[derive(Debug)]
pub(super) enum DaemonState {
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
pub(super) async fn classify_daemon(root: &Path, force: bool) -> DaemonState {
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
                    DaemonResult::Unresponsive | DaemonResult::PermissionDenied => {
                        DaemonState::Unresponsive { pid }
                    }
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
                DaemonResult::Unresponsive | DaemonResult::PermissionDenied => {
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
pub(super) use mati_core::mcp::metadata::kill_and_wait;

/// Send SIGTERM directly via `libc::kill`. Returns `true` on success or
/// when the kernel reports the process is already gone. Used by the
/// `--no-wait` escape hatch where we skip the bundled wait loop.
#[cfg(unix)]
pub(super) fn send_sigterm_only(pid: u32) -> bool {
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
pub(super) fn send_sigterm_only(_pid: u32) -> bool {
    false
}

/// Send SIGKILL directly via `libc::kill`. γ-C6: pairs with `--force
/// --no-wait` to send the unblockable signal without entering the wait
/// loop. Returns `true` on success or ESRCH (already gone).
#[cfg(unix)]
pub(super) fn send_sigkill_only(pid: u32) -> bool {
    // SAFETY: SIGKILL is non-catchable; the kernel either delivers
    // (process exits) or returns ESRCH (already gone). `kill(2)` is a
    // standard POSIX system call.
    let ret = unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
    if ret == 0 {
        return true;
    }
    let errno = std::io::Error::last_os_error().raw_os_error();
    matches!(errno, Some(libc::ESRCH))
}

#[cfg(not(unix))]
pub(super) fn send_sigkill_only(_pid: u32) -> bool {
    false
}

/// Hard ceiling on how much of `lifecycle.log` [`recorded_serve_pids`] reads
/// into memory. Sized well above the ~1.5 MB the periodic trim keeps the log
/// under, so this only bites on a log the trim hasn't reached yet.
pub(super) const RECORDED_SERVE_SCAN_MAX_BYTES: u64 = 2 * 1024 * 1024;

/// Read at most the last `max_bytes` of `path`. If that cuts into the middle
/// of a line, the partial leading fragment is dropped so every line handed
/// to the caller is complete.
pub(super) fn read_tail(path: &Path, max_bytes: u64) -> std::io::Result<String> {
    use std::io::{Read, Seek, SeekFrom};
    let mut file = std::fs::File::open(path)?;
    let len = file.metadata()?.len();
    if len <= max_bytes {
        let mut s = String::new();
        file.read_to_string(&mut s)?;
        return Ok(s);
    }
    file.seek(SeekFrom::Start(len - max_bytes))?;
    let mut buf = Vec::with_capacity(max_bytes as usize);
    file.read_to_end(&mut buf)?;
    let text = String::from_utf8_lossy(&buf);
    Ok(match text.find('\n') {
        Some(i) => text[i + 1..].to_string(),
        None => String::new(),
    })
}

/// PIDs of `mati serve` proxies attached to **this** store, from the store's
/// own `lifecycle.log`.
///
/// `mati serve` appends `serve_start pid=<n> owner=proxy` to
/// `<root>/lifecycle.log` before it forwards anything, and a terminating event
/// when it goes away. A proxy serving a different store writes to that store's
/// log and can never appear here.
///
/// That indirection is necessary because the process itself carries no usable
/// discriminator. Its command line is a bare `mati serve` (that is what `mati
/// init` registers in `.mcp.json` and Codex's `config.toml`), so `pgrep`
/// cannot tell two stores apart. Its CWD is not the project either — Codex
/// spawns MCP servers with `CWD=/`. It holds no long-lived socket to match on:
/// `proxy_daemon_result` connects per call. `MATI_HOME` in its environment
/// would only narrow the home, not the slug, and reading another process's
/// environment is not portable. The log entry is written by the process we
/// want to identify, into the directory that defines the store — the only
/// place the association actually exists.
///
/// Under-inclusive by construction: a truncated log, or a proxy started by a
/// binary too old to record the event, yields a PID we will not kill. That is
/// the correct direction to fail — the bug being fixed is killing MCP sessions
/// that belong to other stores.
///
/// Only reads the most recent [`RECORDED_SERVE_SCAN_MAX_BYTES`] of the log —
/// see [`read_tail`]. The idle-loop trim in `metadata::trim_lifecycle_log`
/// keeps the file within that window in the common case; this cap is the
/// defense-in-depth for a log the trim hasn't reached yet.
pub(super) fn recorded_serve_pids(root: &Path) -> std::collections::HashSet<u32> {
    let mut live = std::collections::HashSet::new();
    let Ok(contents) = read_tail(&root.join("lifecycle.log"), RECORDED_SERVE_SCAN_MAX_BYTES) else {
        return live;
    };
    for line in contents.lines() {
        // ts \t pid \t event \t detail — see `mcp::metadata::record_lifecycle_event`.
        let mut cols = line.split('\t');
        let (Some(_ts), Some(pid), Some(event)) = (cols.next(), cols.next(), cols.next()) else {
            continue;
        };
        let Ok(pid) = pid.trim().parse::<u32>() else {
            continue;
        };
        let detail = cols.next().unwrap_or("");
        match event {
            // `mati daemon start` writes serve_start too, with owner=daemon.
            "serve_start" if detail.contains("owner=proxy") => {
                live.insert(pid);
            }
            "serve_shutdown" | "serve_failed" | "panic" => {
                live.remove(&pid);
            }
            _ => {}
        }
    }
    live
}

/// Which of the `mati serve` processes currently running belong to `root`.
///
/// Split out from [`kill_mati_serve_processes`] so the selection is testable
/// without signalling anything.
pub(super) fn serve_pids_to_kill(root: &Path, running: &[u32]) -> Vec<u32> {
    let recorded = recorded_serve_pids(root);
    let my_pid = std::process::id();
    running
        .iter()
        .copied()
        // Don't suicide — `mati daemon stop`'s own argv is not `mati serve`,
        // but belt-and-suspenders against pgrep pattern slop.
        .filter(|pid| *pid != my_pid && recorded.contains(pid))
        .collect()
}

/// γ-C6: SIGKILL the `mati serve` processes attached to this store.
///
/// After γ, `mati serve` is a separate process from the daemon; killing
/// the daemon alone does not end the MCP session. `--include-mcp` adds
/// this cleanup so operators can fully terminate an active MCP session
/// when needed (e.g. agent gone rogue, or operator wants to force a
/// fresh session start).
///
/// `pgrep -f "mati serve"` enumerates candidates portably across macOS +
/// Linux, but it matches every proxy on the host, and `root` used to be read
/// only by the audit line — so stopping a daemon for one store killed the MCP
/// sessions of every other store on the machine. [`serve_pids_to_kill`]
/// narrows the list to proxies this store recorded.
///
/// Best-effort — failures are logged but don't fail the stop command,
/// because the daemon stop itself already succeeded by the time we're
/// here. The user's primary intent (stop the daemon) is honored even if
/// proxy cleanup fails.
pub(super) async fn kill_mati_serve_processes(root: &Path) {
    let output = match std::process::Command::new("pgrep")
        .arg("-f")
        .arg("mati serve")
        .output()
    {
        Ok(o) => o,
        Err(e) => {
            tracing::warn!(
                "kill_mati_serve_processes: pgrep failed: {e} \
                 (is pgrep installed? skipping --include-mcp cleanup)"
            );
            eprintln!(
                "[mati] warning: pgrep not available; could not locate `mati serve` processes"
            );
            return;
        }
    };

    if !output.status.success() {
        // pgrep returns exit 1 when no matches — that's success for us.
        return;
    }

    let running: Vec<u32> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|l| l.trim().parse::<u32>().ok())
        .collect();
    let targets = serve_pids_to_kill(root, &running);
    let spared = running.len().saturating_sub(targets.len());

    let mut killed: Vec<u32> = Vec::new();
    for pid in targets {
        #[cfg(unix)]
        {
            // SAFETY: SIGKILL is non-catchable. ESRCH on already-
            // gone process is a benign no-op; any other error is
            // logged but not fatal.
            let ret = unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
            if ret == 0 {
                killed.push(pid);
            } else {
                let errno = std::io::Error::last_os_error().raw_os_error();
                if !matches!(errno, Some(libc::ESRCH)) {
                    tracing::warn!(pid, ?errno, "kill_mati_serve_processes: SIGKILL failed");
                }
            }
        }
    }

    if spared > 0 {
        println!(
            "mati daemon: --include-mcp left {spared} `mati serve` process(es) alone \
             (not recorded against this store)"
        );
    }

    if !killed.is_empty() {
        let pid_list = killed
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(",");
        println!(
            "mati daemon: --include-mcp killed {} serve proxy/proxies (pid={pid_list})",
            killed.len()
        );
        mati_core::mcp::metadata::record_lifecycle_event(
            root,
            "stop_include_mcp",
            &format!("killed={} pids={pid_list}", killed.len()),
        );
    }
}

/// Wait up to 500ms for the daemon to unlink its sock + pid files.
/// If still present, unlink ourselves so the next CLI call doesn't see
/// a half-dead daemon. Returns `true` if removal completed cleanly.
pub(super) async fn wait_for_files_removed(root: &Path) -> bool {
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
