//! Daemon metadata — PID file, session UUID, and Unix permission hardening.
//!
//! The on-disk file is `~/.mati/<slug>/mati.pid`. Its internal representation
//! is [`DaemonMetadata`], which carries the daemon PID and a session UUID.
//!
//! ## Atomic publication
//!
//! Metadata is published atomically: write to `mati.pid.tmp`, set mode 0600,
//! then rename over `mati.pid`. This eliminates the window where a reader sees
//! a partially-written file.
//!
//! ## Permission model (Unix-only)
//!
//! - Runtime dir (`~/.mati/<slug>/`): mode 0700
//! - Metadata file (`mati.pid`): mode 0600
//! - Socket file (`mati.sock`): mode 0600 (set after bind)
//!
//! ## Stale-socket cleanup
//!
//! On startup, the daemon checks for an existing socket+metadata. If the
//! recorded PID is dead, the files are removed. If the PID is alive, startup
//! is refused. The socket is never blindly unlinked.

use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Owner identity — who created this daemon socket.
///
/// Used by `mati daemon stop` to refuse killing an MCP server session,
/// and by proxy mode to determine whether to connect.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DaemonOwner {
    /// Started via `mati daemon start`.
    Daemon,
    /// Started via `mati serve` (MCP stdio server with embedded socket).
    Mcp,
}

impl std::fmt::Display for DaemonOwner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Daemon => write!(f, "daemon"),
            Self::Mcp => write!(f, "mcp"),
        }
    }
}

/// On-disk daemon metadata. Persisted as `mati.pid`, read by the CLI proxy
/// and hook scripts to route through the daemon socket.
///
/// The session UUID is a session marker for audit/provenance — NOT an
/// authentication token. Peer identity is established via Unix peer
/// credentials (`peer_cred()`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonMetadata {
    /// PID of the daemon process.
    pub pid: u32,
    /// Session UUID — included in every IPC request for audit correlation.
    /// Generated fresh on each daemon startup.
    pub session: Uuid,
    /// Who started this daemon (daemon vs mcp server).
    pub owner: DaemonOwner,
}

impl DaemonMetadata {
    /// Create metadata for the current process.
    pub fn new(owner: DaemonOwner) -> Self {
        Self {
            pid: std::process::id(),
            session: Uuid::new_v4(),
            owner,
        }
    }
}

// ── File paths ──────────────────────────────────────────────────────────────

const METADATA_FILENAME: &str = "mati.pid";
const METADATA_TMP_FILENAME: &str = "mati.pid.tmp";
const SOCKET_FILENAME: &str = "mati.sock";

/// Return the metadata file path for a given mati root.
///
/// Crate-internal: callers in `mcp::server` use it for rollback-on-bind-fail
/// in the daemon-socket task. Outside the crate, prefer `read_metadata` /
/// `publish_metadata` rather than constructing paths directly.
pub(crate) fn metadata_path(root: &Path) -> std::path::PathBuf {
    root.join(METADATA_FILENAME)
}

/// Return the socket file path for a given mati root.
pub fn socket_path(root: &Path) -> std::path::PathBuf {
    root.join(SOCKET_FILENAME)
}

// ── Permission hardening (Unix-only) ────────────────────────────────────────

/// Ensure the runtime directory exists with mode 0700.
///
/// Creates `~/.mati/<slug>/` if absent. Always re-applies 0700 in case a
/// previous run or manual change left weaker permissions.
pub fn ensure_runtime_dir(root: &Path) -> Result<()> {
    std::fs::create_dir_all(root)
        .with_context(|| format!("cannot create runtime dir at {}", root.display()))?;
    set_mode(root, 0o700).with_context(|| format!("cannot set mode 0700 on {}", root.display()))?;
    Ok(())
}

/// Set mode 0600 on the socket file after `UnixListener::bind()`.
///
/// `bind()` creates the socket with permissions derived from the process umask.
/// This call tightens them to owner-only regardless of umask.
pub fn harden_socket(sock_path: &Path) -> Result<()> {
    set_mode(sock_path, 0o600)
        .with_context(|| format!("cannot set mode 0600 on {}", sock_path.display()))
}

/// Set Unix file mode. No-op on non-Unix (compile-gated).
#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(mode);
    std::fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> Result<()> {
    Ok(())
}

// ── Atomic metadata publication ─────────────────────────────────────────────

/// Atomically publish daemon metadata to `mati.pid`.
///
/// Writes to `mati.pid.tmp` with mode 0600, then renames over `mati.pid`.
/// The rename is atomic on Unix when both paths are on the same filesystem
/// (always true within `~/.mati/<slug>/`).
pub fn publish_metadata(root: &Path, metadata: &DaemonMetadata) -> Result<()> {
    let tmp_path = root.join(METADATA_TMP_FILENAME);
    let final_path = metadata_path(root);

    let json = serde_json::to_string(metadata).context("failed to serialize daemon metadata")?;

    std::fs::write(&tmp_path, json.as_bytes())
        .with_context(|| format!("failed to write {}", tmp_path.display()))?;

    // Set permissions BEFORE rename so the file is never visible with wrong mode.
    set_mode(&tmp_path, 0o600)?;

    std::fs::rename(&tmp_path, &final_path).with_context(|| {
        format!(
            "failed to rename {} → {}",
            tmp_path.display(),
            final_path.display()
        )
    })?;

    Ok(())
}

// ── Metadata reading ────────────────────────────────────────────────────────

/// Read daemon metadata from `mati.pid`.
///
/// Returns `None` if the file does not exist or cannot be parsed.
/// Supports the v2 JSON format `{"pid":N,"session":"uuid","owner":"daemon"}`.
/// Falls back to the legacy v1 formats for backward compatibility during
/// the migration window.
pub fn read_metadata(root: &Path) -> Option<DaemonMetadata> {
    let content = std::fs::read_to_string(metadata_path(root)).ok()?;
    let trimmed = content.trim();

    // Try v2 format first (full DaemonMetadata).
    if let Ok(meta) = serde_json::from_str::<DaemonMetadata>(trimmed) {
        return Some(meta);
    }

    // Legacy plain PID format: "1234" — try before generic JSON parse
    // so a bare number is not consumed by serde_json::Value.
    if let Ok(pid) = trimmed.parse::<u32>() {
        return Some(DaemonMetadata {
            pid,
            session: Uuid::nil(),
            owner: DaemonOwner::Daemon,
        });
    }

    // Legacy v1 JSON: {"pid":N,"owner":"daemon"|"mcp"} — no session field.
    if let Ok(val) = serde_json::from_str::<serde_json::Value>(trimmed) {
        let pid = val.get("pid").and_then(|v| v.as_u64())? as u32;
        let owner_str = val
            .get("owner")
            .and_then(|v| v.as_str())
            .unwrap_or("daemon");
        let owner = match owner_str {
            "mcp" => DaemonOwner::Mcp,
            _ => DaemonOwner::Daemon,
        };
        return Some(DaemonMetadata {
            pid,
            // Legacy metadata has no session — generate one so callers always
            // have a UUID. The daemon will reject requests with this UUID
            // (SessionMismatch), forcing the proxy to re-read after daemon restart.
            session: Uuid::nil(),
            owner,
        });
    }

    None
}

// ── PID liveness ────────────────────────────────────────────────────────────

/// Check whether a PID is still alive.
///
/// Uses `kill(pid, 0)` which checks existence without sending a signal.
/// Returns true if the process exists (even if owned by another user — EPERM).
#[cfg(unix)]
pub fn is_pid_alive(pid: u32) -> bool {
    // SAFETY: kill(pid, 0) is a standard POSIX liveness check. It sends no
    // signal — it only tests whether the PID exists and is reachable.
    let ret = unsafe { libc::kill(pid as libc::pid_t, 0) };
    if ret == 0 {
        return true;
    }
    // EPERM means the process exists but belongs to another user — still alive.
    std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

#[cfg(not(unix))]
pub fn is_pid_alive(_pid: u32) -> bool {
    true // Conservative: assume alive on non-Unix
}

/// Returns the effective UID of the current process.
///
/// Used by the peer credential check to compare against connecting peers.
#[cfg(unix)]
pub fn current_euid() -> u32 {
    // SAFETY: geteuid() is a pure read with no side effects.
    unsafe { libc::geteuid() }
}

#[cfg(not(unix))]
pub fn current_euid() -> u32 {
    0
}

/// Returns the calling thread's QoS class as a human-readable string.
///
/// Included in `serve_start` lifecycle events so that a silent failure of
/// `pthread_set_qos_class_self_np` is visible in `mati doctor` output
/// before the kernel-panic symptoms recur.
#[cfg(target_os = "macos")]
pub fn current_qos_class_str() -> &'static str {
    extern "C" {
        fn qos_class_self() -> libc::c_uint;
    }
    // SAFETY: qos_class_self() is a pure read; it queries the current thread's
    // QoS class from the kernel without any side effects.
    match unsafe { qos_class_self() } {
        0x21 => "user_interactive",
        0x19 => "user_initiated",
        0x15 => "default",
        0x11 => "utility",
        0x09 => "background",
        _ => "unknown",
    }
}

#[cfg(not(target_os = "macos"))]
pub fn current_qos_class_str() -> &'static str {
    "n/a"
}

// ── SIGTERM / SIGKILL escalation ────────────────────────────────────────────

/// How long to poll for `is_pid_alive` after sending SIGKILL before
/// declaring the process [`KillOutcome::Stuck`].
///
/// 500ms was the historical default; γ-C7 smoke surfaced cases where a
/// daemon exited cleanly but only after ~600ms because its shutdown path
/// completed a SurrealKV WAL fsync before letting the process die. The
/// 500ms poll gave up too early and reported a false `Stuck` even though
/// the next CLI call (~10ms later) saw the PID gone. 2s gives comfortable
/// headroom for realistic shutdown work (WAL flush, in-flight handler
/// drain) while still being well under any reasonable user wait
/// threshold. SIGKILL itself is unblockable — anything that genuinely
/// takes >2s to reap is either kernel-level uninterruptible I/O (rare)
/// or a real bug worth surfacing.
const SIGKILL_REAP_WINDOW: std::time::Duration = std::time::Duration::from_secs(2);

/// Outcome of [`kill_and_wait`]. Carries elapsed wall time so callers can
/// report or log exactly how the kill resolved.
#[derive(Debug)]
pub enum KillOutcome {
    /// Process exited within the SIGTERM budget.
    ExitedClean(std::time::Duration),
    /// SIGTERM was ignored or absorbed; SIGKILL succeeded.
    KilledHard(std::time::Duration),
    /// Process is still alive after SIGKILL — manual intervention required.
    /// Carries a [`StuckDiagnostic`] so callers can surface the actual
    /// process state at the moment we gave up. γ smoke surfaced cases
    /// where the daemon was effectively gone (lock released, next CLI
    /// command worked) but our `kill(0)` poll kept reporting alive; the
    /// diagnostic snapshot lets us distinguish kill(0)-lying-after-SIGKILL,
    /// zombie state, PID reuse (different process at that PID now), and
    /// genuinely-still-alive cases on the next failure.
    Stuck(StuckDiagnostic),
}

/// Diagnostic data captured at the moment [`KillOutcome::Stuck`] is
/// returned. Includes timing for each phase and a `ps`-driven snapshot
/// of the process state at both the start of the kill and the giving-up
/// point — enabling root-cause analysis without re-running the failure.
#[derive(Debug, Clone)]
pub struct StuckDiagnostic {
    pub pid: u32,
    /// Elapsed wall time from [`kill_and_wait`] / [`kill_directly`] entry.
    pub total_elapsed_ms: u64,
    /// Time spent in the SIGTERM phase. `None` if [`kill_directly`] was
    /// used (no SIGTERM phase).
    pub sigterm_elapsed_ms: Option<u64>,
    /// Time spent polling after SIGKILL.
    pub sigkill_elapsed_ms: u64,
    /// Process state when the kill started (via `ps -o ...`).
    pub initial_snapshot: PidSnapshot,
    /// Process state when we gave up (via `ps -o ...`).
    pub final_snapshot: PidSnapshot,
}

/// `ps -o`-derived snapshot of a PID. Used by [`StuckDiagnostic`] to
/// pin down why `kill_and_wait` gave up.
///
/// On the failure path we cross-check `kill(pid, 0)`'s lying-alive report
/// against three orthogonal indicators:
///
/// - **`lstart`** changed between initial and final → the PID was reused
///   by a different process (kernel reaped the old one, assigned PID to a
///   new spawn).
/// - **`state`** is `Z` → process really is a zombie awaiting reap by its
///   parent. `kill(0)` succeeds because the proc entry exists; the
///   process holds no resources.
/// - **all fields `None`** → `ps` reports the PID is gone but `kill(0)`
///   still says alive: macOS kernel proc-table lag (the proc structure
///   hasn't been fully torn down even though the process has exited).
/// - **same `lstart`, normal `state`** → process is genuinely still
///   alive. Real Stuck case — daemon shutdown is wedged.
#[derive(Debug, Clone, Default)]
pub struct PidSnapshot {
    /// Process start time as reported by `ps -o lstart=`. `None` if ps
    /// can't find the PID.
    pub lstart: Option<String>,
    /// Process state: 'R' running, 'S' sleeping, 'Z' zombie, etc.
    pub state: Option<String>,
    /// Process command name as reported by `ps -o comm=`.
    pub comm: Option<String>,
}

impl PidSnapshot {
    /// Render as a compact one-line diagnostic string suitable for
    /// inclusion in lifecycle events and stderr.
    pub fn render(&self) -> String {
        match (&self.lstart, &self.state, &self.comm) {
            (None, None, None) => "ps:gone".into(),
            _ => format!(
                "lstart={:?} state={:?} comm={:?}",
                self.lstart.as_deref().unwrap_or("?"),
                self.state.as_deref().unwrap_or("?"),
                self.comm.as_deref().unwrap_or("?")
            ),
        }
    }
}

/// Snapshot the named `ps` field for `pid`. Returns `None` if `ps` can't
/// find the PID (process gone) or the call fails.
fn ps_field(pid: u32, field: &str) -> Option<String> {
    let pid_str = pid.to_string();
    let output = std::process::Command::new("ps")
        .args(["-o", &format!("{field}="), "-p", &pid_str])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let trimmed = String::from_utf8_lossy(&output.stdout)
        .trim()
        .to_string();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

/// Capture a `PidSnapshot` via three `ps` calls (lstart, state, comm).
/// Each call is ~10ms on macOS; total ~30ms. Only invoked on the Stuck
/// path so the cost doesn't touch the hot path.
pub fn snapshot_pid(pid: u32) -> PidSnapshot {
    PidSnapshot {
        lstart: ps_field(pid, "lstart"),
        state: ps_field(pid, "state"),
        comm: ps_field(pid, "comm"),
    }
}

/// Send SIGTERM to `pid`. Returns `true` on success or when the kernel
/// reports the process is already gone (`ESRCH`). `kill(2)` returning
/// any other error counts as failure — caller surfaces it to the user.
#[cfg(unix)]
fn send_sigterm(pid: u32) -> bool {
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
fn send_sigterm(_pid: u32) -> bool {
    false
}

/// Send SIGKILL to `pid` and poll for exit. γ-C6: used by
/// `mati daemon stop --force` to bypass the SIGTERM grace period and
/// terminate the daemon immediately. The reaping window matches the
/// SIGKILL escalation phase of [`kill_and_wait`] — see
/// [`SIGKILL_REAP_WINDOW`] for the rationale.
pub async fn kill_directly(pid: u32) -> KillOutcome {
    let started = std::time::Instant::now();
    let initial_snapshot = snapshot_pid(pid);
    #[cfg(unix)]
    {
        // SAFETY: SIGKILL is non-catchable; the process either exits or
        // we surface Stuck. `kill(2)` is a standard system call.
        let ret = unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
        if ret != 0 {
            let errno = std::io::Error::last_os_error().raw_os_error();
            if !matches!(errno, Some(libc::ESRCH)) {
                tracing::warn!(pid, ?errno, "kill_directly: SIGKILL rejected by kernel");
                let elapsed_ms = started.elapsed().as_millis() as u64;
                return KillOutcome::Stuck(StuckDiagnostic {
                    pid,
                    total_elapsed_ms: elapsed_ms,
                    sigterm_elapsed_ms: None,
                    sigkill_elapsed_ms: elapsed_ms,
                    initial_snapshot,
                    final_snapshot: snapshot_pid(pid),
                });
            }
            // ESRCH — already gone, treat as success.
            return KillOutcome::KilledHard(started.elapsed());
        }
    }

    let sigkill_start = std::time::Instant::now();
    if poll_until_exit(pid, SIGKILL_REAP_WINDOW, started).await {
        return KillOutcome::KilledHard(started.elapsed());
    }
    let sigkill_elapsed_ms = sigkill_start.elapsed().as_millis() as u64;
    KillOutcome::Stuck(StuckDiagnostic {
        pid,
        total_elapsed_ms: started.elapsed().as_millis() as u64,
        sigterm_elapsed_ms: None,
        sigkill_elapsed_ms,
        initial_snapshot,
        final_snapshot: snapshot_pid(pid),
    })
}

/// Send SIGTERM to `pid`, wait up to `timeout` for the process to exit, and
/// escalate to SIGKILL with [`SIGKILL_REAP_WINDOW`] of reaping budget if it
/// does not.
///
/// Used by both `mati daemon stop` and the unresponsive-recovery branch of
/// `ensure_daemon` so the synchronous-exit guarantee is identical across
/// both paths. Pre-condition: caller has authorized the kill (`--force`
/// gate, ownership check) and knows the PID is alive.
pub async fn kill_and_wait(pid: u32, timeout: std::time::Duration) -> KillOutcome {
    let started = std::time::Instant::now();
    let initial_snapshot = snapshot_pid(pid);

    if !send_sigterm(pid) {
        tracing::warn!(pid, "kill_and_wait: SIGTERM rejected by kernel");
        let elapsed_ms = started.elapsed().as_millis() as u64;
        return KillOutcome::Stuck(StuckDiagnostic {
            pid,
            total_elapsed_ms: elapsed_ms,
            sigterm_elapsed_ms: Some(elapsed_ms),
            sigkill_elapsed_ms: 0,
            initial_snapshot,
            final_snapshot: snapshot_pid(pid),
        });
    }

    let sigterm_start = std::time::Instant::now();
    if poll_until_exit(pid, timeout, started).await {
        return KillOutcome::ExitedClean(started.elapsed());
    }
    let sigterm_elapsed_ms = sigterm_start.elapsed().as_millis() as u64;

    tracing::warn!(
        pid,
        timeout_secs = timeout.as_secs(),
        "process did not exit within SIGTERM budget — sending SIGKILL"
    );
    #[cfg(unix)]
    {
        // SAFETY: SIGKILL is non-catchable; the process either exits or
        // we surface Stuck. `kill(2)` is a standard system call.
        let _ = unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
    }

    let sigkill_start = std::time::Instant::now();
    if poll_until_exit(pid, SIGKILL_REAP_WINDOW, sigkill_start).await {
        return KillOutcome::KilledHard(started.elapsed());
    }
    let sigkill_elapsed_ms = sigkill_start.elapsed().as_millis() as u64;

    KillOutcome::Stuck(StuckDiagnostic {
        pid,
        total_elapsed_ms: started.elapsed().as_millis() as u64,
        sigterm_elapsed_ms: Some(sigterm_elapsed_ms),
        sigkill_elapsed_ms,
        initial_snapshot,
        final_snapshot: snapshot_pid(pid),
    })
}

/// Poll [`is_pid_alive`] until the PID is gone or `budget` elapses (from `started`).
async fn poll_until_exit(
    pid: u32,
    budget: std::time::Duration,
    started: std::time::Instant,
) -> bool {
    const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(50);
    let deadline = started + budget;
    while std::time::Instant::now() < deadline {
        if !is_pid_alive(pid) {
            return true;
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
    false
}

// ── Peer credentials ────────────────────────────────────────────────────────

/// Peer identity from a Unix socket connection. Carried through the request
/// pipeline into handlers and the audit record.
#[derive(Debug, Clone)]
pub struct PeerContext {
    /// Effective UID of the connecting process.
    pub uid: u32,
    /// PID of the connecting process (available on Linux and macOS, None on
    /// platforms where `peer_cred()` does not expose it).
    pub pid: Option<u32>,
}

/// Verify that a connecting peer has the same effective UID as the daemon.
///
/// Returns `Some(PeerContext)` on success, `None` on mismatch or failure.
/// On `None`, the caller MUST drop the connection and continue the accept
/// loop — never crash.
///
/// This enforces the Unix-socket UID boundary: only processes running as
/// the same user can talk to the daemon.
pub fn check_peer_cred(stream: &tokio::net::UnixStream, daemon_euid: u32) -> Option<PeerContext> {
    match stream.peer_cred() {
        Ok(cred) => {
            let peer_uid = cred.uid();
            if peer_uid != daemon_euid {
                tracing::warn!(
                    peer_uid,
                    daemon_uid = daemon_euid,
                    "peer UID mismatch — dropping connection"
                );
                return None;
            }
            let peer_pid = cred.pid().map(|p| p as u32);
            tracing::trace!(peer_uid, ?peer_pid, "peer credential check passed");
            Some(PeerContext {
                uid: peer_uid,
                pid: peer_pid,
            })
        }
        Err(e) => {
            tracing::warn!(error = %e, "peer_cred() failed — dropping connection");
            None
        }
    }
}

// ── Stale-socket cleanup ────────────────────────────────────────────────────

/// Outcome of a stale-socket check.
#[derive(Debug, PartialEq, Eq)]
pub enum StaleCheckResult {
    /// No metadata or socket — safe to proceed with startup.
    Clean,
    /// Metadata references a dead PID — stale files cleaned up, safe to proceed.
    StaleRemoved,
    /// Metadata references a live PID — daemon is running, refuse startup.
    LiveDaemon {
        pid: u32,
        owner: DaemonOwner,
        session: Uuid,
    },
    /// Metadata is absent but socket file exists — ambiguous state.
    /// Caller should probe the socket before deciding.
    OrphanSocket,
}

/// Check for stale daemon state and clean up if safe.
///
/// This implements the safe stale-socket protocol:
/// 1. Read metadata if present
/// 2. Test PID liveness
/// 3. If live daemon exists, return `LiveDaemon` (refuse startup)
/// 4. Only remove stale socket+metadata when PID is dead
///
/// The socket is NEVER blindly unlinked.
pub fn check_and_cleanup_stale(root: &Path) -> StaleCheckResult {
    let meta_path = metadata_path(root);
    let sock_path = socket_path(root);

    let has_metadata = meta_path.exists();
    let has_socket = sock_path.exists();

    if !has_metadata && !has_socket {
        return StaleCheckResult::Clean;
    }

    // Socket exists but no metadata — ambiguous. Caller must probe.
    if !has_metadata && has_socket {
        return StaleCheckResult::OrphanSocket;
    }

    // Metadata exists — parse and check PID liveness.
    let metadata = match read_metadata(root) {
        Some(m) => m,
        None => {
            // Metadata file exists but is corrupt/unreadable.
            // Treat as stale: remove both files.
            tracing::warn!("daemon metadata corrupt — removing stale files");
            let _ = std::fs::remove_file(&meta_path);
            let _ = std::fs::remove_file(&sock_path);
            return StaleCheckResult::StaleRemoved;
        }
    };

    if is_pid_alive(metadata.pid) {
        return StaleCheckResult::LiveDaemon {
            pid: metadata.pid,
            owner: metadata.owner,
            session: metadata.session,
        };
    }

    // PID is dead — clean up stale files.
    tracing::info!(
        pid = metadata.pid,
        owner = %metadata.owner,
        "removing stale daemon files (PID dead)"
    );
    let _ = std::fs::remove_file(&sock_path);
    let _ = std::fs::remove_file(&meta_path);
    // Also remove the starting sentinel if present.
    let _ = std::fs::remove_file(root.join("mati.starting"));

    StaleCheckResult::StaleRemoved
}

// ── Lifecycle log ───────────────────────────────────────────────────────────

const LIFECYCLE_FILENAME: &str = "lifecycle.log";

/// Maximum number of lines retained in `lifecycle.log`. Trimmed at
/// `install_panic_hook` time (single-writer window: we hold the kernel
/// flock, so no concurrent daemon can race the rotation). At ~150 bytes
/// per line, 10k lines ≈ 1.5 MB — enough to retain a year of normal
/// lifecycle events while bounding growth in pathological respawn loops.
const MAX_LIFECYCLE_LINES: usize = 10_000;

/// Hard ceiling on the byte size of `lifecycle.log` we will read into
/// memory at startup. The legitimate cap (10k lines × ~150 B ≈ 1.5 MB)
/// fits comfortably inside this; the ceiling exists only to prevent
/// startup OOM if an external process or buggy actor wrote pathological
/// content into the log (e.g. a 4 GB file of garbage). Above this size,
/// the trim path nukes the file rather than reading it. Lifecycle events
/// are best-effort observability — losing them on extreme corruption is
/// strictly preferable to refusing to start the daemon (P9: graceful
/// degradation, never block Claude on a mati outage).
const LIFECYCLE_TRIM_MAX_READ_BYTES: u64 = 64 * 1024 * 1024;

/// Best-effort one-time trim of `lifecycle.log` to its last N lines.
///
/// Uses tmp+rename for atomic replacement so a crash during rotation
/// leaves either the old log or the new log on disk, never a partial
/// truncation. Errors are silently ignored — log rotation must never
/// block startup.
///
/// Hard size guard: if the on-disk file exceeds
/// `LIFECYCLE_TRIM_MAX_READ_BYTES`, the file is truncated to empty
/// without being read. This protects startup from OOM on a pathological
/// log (P9). The legitimate cap is ~1.5 MB so the threshold is not hit
/// under any normal operation.
fn trim_lifecycle_log(root: &Path, max_lines: usize) {
    let path = root.join(LIFECYCLE_FILENAME);

    // Size guard: refuse to read pathological files into memory. Truncate
    // to empty and continue. Best-effort — if `metadata` or `write` fails,
    // we just return; startup must not block on log rotation.
    if let Ok(meta) = std::fs::metadata(&path) {
        if meta.is_file() && meta.len() > LIFECYCLE_TRIM_MAX_READ_BYTES {
            let _ = std::fs::write(&path, b"");
            return;
        }
    }

    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return, // log doesn't exist yet, or can't be read
    };
    // `lines()` does not yield trailing empty line, so length == event count.
    let line_count = content.lines().count();
    if line_count <= max_lines {
        return;
    }
    let skip = line_count - max_lines;
    let kept: String = content.lines().skip(skip).flat_map(|l| [l, "\n"]).collect();
    // Atomic replace.
    let tmp = path.with_extension("log.tmp");
    if std::fs::write(&tmp, kept).is_err() {
        return;
    }
    let _ = std::fs::rename(&tmp, &path);
}

/// Hard cap on a single lifecycle.log line, in bytes.
///
/// POSIX guarantees that `write(2)` calls of size ≤ `PIPE_BUF` (4096 bytes
/// on Linux, ≥512 on every conformant system) on a file opened with
/// `O_APPEND` are atomic with respect to other writers. Above that, two
/// concurrent appenders can interleave bytes mid-line, producing torn
/// records that confuse `lines()` consumers and the trim path.
///
/// Multiple processes can write here simultaneously: any running daemon
/// instance, the panic hook firing in a background thread, sibling-process
/// startup logging during stale cleanup. A pathological panic payload
/// (large `Debug`-formatted struct, JSON dump of a serde error) can easily
/// exceed 4 KB and tear the log.
///
/// 3900 bytes leaves headroom for the `{ts}\t{pid}\t{event}\t` prefix (well
/// under 100 bytes in practice) plus the trailing `\n`, while staying
/// safely below PIPE_BUF.
const LIFECYCLE_MAX_LINE_BYTES: usize = 3900;

/// Append a single event to `~/.mati/<slug>/lifecycle.log`.
///
/// Format: `unix_ts<TAB>pid<TAB>event<TAB>detail<NL>`. Newlines and tabs in
/// `detail` are replaced with spaces so each event remains exactly one line.
/// Lines exceeding `LIFECYCLE_MAX_LINE_BYTES` are truncated at a UTF-8 char
/// boundary so concurrent appenders never produce torn records.
///
/// Best-effort — every failure path is silenced. Lifecycle logging must
/// never block startup, shutdown, or panic paths.
pub fn record_lifecycle_event(root: &Path, event: &str, detail: &str) {
    use std::io::Write;
    let path = root.join(LIFECYCLE_FILENAME);
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let pid = std::process::id();
    let safe_detail: String = detail
        .chars()
        .map(|c| match c {
            '\t' | '\n' | '\r' => ' ',
            c => c,
        })
        .collect();
    let mut line = format!("{ts}\t{pid}\t{event}\t{safe_detail}\n");
    if line.len() > LIFECYCLE_MAX_LINE_BYTES {
        // Reserve one byte for the trailing '\n' we re-add below. Walk back
        // to the nearest UTF-8 char boundary so we never split a multibyte
        // character — a torn UTF-8 sequence would corrupt `read_to_string`
        // consumers. UTF-8 chars are ≤4 bytes, so this loop runs at most
        // 3 iterations. Equivalent to `floor_char_boundary` (stable in
        // 1.91) but works on the project's MSRV (1.82).
        let mut cut = LIFECYCLE_MAX_LINE_BYTES - 1;
        while cut > 0 && !line.is_char_boundary(cut) {
            cut -= 1;
        }
        line.truncate(cut);
        line.push('\n');
    }
    // Use the pre-opened fd when it matches this exact log path — avoids
    // open(2) in the panic hook where VFS stalls are possible under memory
    // pressure on macOS. Fall back to open-by-path for any other root
    // (including test callers with arbitrary temp dirs).
    //
    // No mutex is needed: `O_APPEND` + line ≤ PIPE_BUF makes `write(2)`
    // atomic at the kernel level, so concurrent emitters can share the fd
    // without user-space locking. `<&File as Write>::write_all` lets us emit
    // through a shared reference.
    let used_preopen = if let Some(pre) = LIFECYCLE_LOG_FILE.get() {
        if pre.path == path {
            let _ = (&pre.file).write_all(line.as_bytes());
            true
        } else {
            false
        }
    } else {
        false
    };

    if !used_preopen {
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
        {
            let _ = f.write_all(line.as_bytes());
        }
    }
}

// ── Panic hook ──────────────────────────────────────────────────────────────

/// Cached daemon root used by the panic hook to clean up sock + pid files.
/// Set by [`install_panic_hook`]; never overwritten.
static PANIC_HOOK_ROOT: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();

/// Pre-opened lifecycle log file handle, paired with its canonical path
/// and a pre-formatted pid prefix.
///
/// Opened at `install_panic_hook` time so the panic hook can call `write(2)`
/// directly instead of `open(2)`. On macOS under memory pressure, `open(2)`
/// can stall waiting for VFS resources; a pre-opened fd avoids that window.
///
/// `record_lifecycle_event` uses this handle only when the requested path
/// matches, so test callers with arbitrary temp dirs always open by path.
///
/// **No `Mutex` around the file.** The fd is opened with `O_APPEND` and every
/// emitted line is capped below `PIPE_BUF` (`LIFECYCLE_MAX_LINE_BYTES = 3900`),
/// so the kernel guarantees `write(2)` calls are atomic w.r.t. concurrent
/// appenders — both intra-process and cross-process. We use
/// `<&File as std::io::Write>::write_all` to emit through a shared reference.
/// Dropping the user-space mutex also removes a deadlock hazard on the panic
/// path (a thread holding the mutex while panicking would self-deadlock when
/// the hook tried to relock it).
///
/// `pid_prefix` is the bytes of `"<pid>\t"` formatted once at install time so
/// the no-alloc panic path can copy it into a stack buffer without calling
/// `format!`.
struct PreOpenedLog {
    path: std::path::PathBuf,
    file: std::fs::File,
    pid_prefix: Vec<u8>,
}

static LIFECYCLE_LOG_FILE: std::sync::OnceLock<PreOpenedLog> = std::sync::OnceLock::new();

/// Test/diagnostic helper: returns `true` if `install_panic_hook` has run and
/// successfully pre-opened the lifecycle log fd. Integration tests use this
/// to assert the panic hook is wired up; it is `#[doc(hidden)]` to discourage
/// production callers from depending on the pre-open state.
#[doc(hidden)]
pub fn is_lifecycle_log_preopened() -> bool {
    LIFECYCLE_LOG_FILE.get().is_some()
}

// ── No-alloc panic write path ───────────────────────────────────────────────
//
// The panic hook may run with a corrupted allocator (e.g., panic-on-OOM,
// allocator state poisoned by the bug being reported). Heap allocations on
// the panic path can hang or abort the runtime before the lifecycle event is
// recorded. The functions below let the hook emit a lifecycle line with zero
// heap allocations: timestamp formatted into a stack buffer via
// `u64_to_decimal_bytes`, pid pre-formatted at install time, detail strings
// sanitized in place, and the line written directly through the pre-opened
// fd via `<&File as Write>::write_all`.
//
// This is best-effort. If `LIFECYCLE_LOG_FILE` is unset (install_panic_hook
// never ran, or the open(2) at install time failed), the no-alloc writer
// returns false and the caller falls back to the heap path.

/// Format `n` as decimal ASCII into the start of `out`, returning the number
/// of bytes written. Stack-only — never allocates. `out` must be ≥ 20 bytes
/// (u64 max = `18_446_744_073_709_551_615` is 20 digits).
fn u64_to_decimal_bytes(mut n: u64, out: &mut [u8]) -> usize {
    if n == 0 {
        if out.is_empty() {
            return 0;
        }
        out[0] = b'0';
        return 1;
    }
    // Write digits backwards into a tmp stack buffer, then reverse-copy.
    let mut tmp = [0u8; 20];
    let mut len = 0;
    while n > 0 && len < tmp.len() {
        tmp[len] = b'0' + (n % 10) as u8;
        n /= 10;
        len += 1;
    }
    let take = len.min(out.len());
    for i in 0..take {
        out[i] = tmp[len - 1 - i];
    }
    take
}

/// Build a lifecycle log line into `out` with no heap allocations. Returns
/// the number of bytes written (always ≤ `LIFECYCLE_MAX_LINE_BYTES`).
///
/// Mirrors the heap path's format: `{ts}\t{pid}\t{event}\t{detail}\n`, where
/// `detail` is `detail_parts` joined by single spaces. Bytes from
/// `detail_parts` matching `\t \n \r` are replaced with space (same
/// sanitization as the heap path's `safe_detail`).
///
/// Truncation rules match the heap path: fill the buffer up to
/// `LIFECYCLE_MAX_LINE_BYTES - 1`, walk back to the most recent UTF-8 char
/// boundary if a truncation would split a multibyte character, then append
/// the trailing `\n`. Each `&str` part is itself valid UTF-8, so we use
/// `str::is_char_boundary` per-part rather than scanning the whole buffer.
fn write_lifecycle_line(
    out: &mut [u8; LIFECYCLE_MAX_LINE_BYTES],
    ts: u64,
    pid_prefix: &[u8],
    event: &str,
    detail_parts: &[&str],
) -> usize {
    // Reserve the final byte for the trailing newline.
    let cap = LIFECYCLE_MAX_LINE_BYTES - 1;
    let mut pos: usize = 0;

    // Copy raw bytes (no sanitization) up to `cap`.
    fn push_raw(out: &mut [u8], pos: &mut usize, src: &[u8], cap: usize) {
        let remaining = cap.saturating_sub(*pos);
        let n = src.len().min(remaining);
        out[*pos..*pos + n].copy_from_slice(&src[..n]);
        *pos += n;
    }

    // ts (decimal ASCII, stack-only).
    let mut ts_buf = [0u8; 20];
    let ts_len = u64_to_decimal_bytes(ts, &mut ts_buf);
    push_raw(out, &mut pos, &ts_buf[..ts_len], cap);
    push_raw(out, &mut pos, b"\t", cap);

    // pid prefix (already includes trailing tab).
    push_raw(out, &mut pos, pid_prefix, cap);

    // event tag — never sanitized (matches heap path, where the format-string
    // separators are real \t and only `safe_detail` is mapped).
    push_raw(out, &mut pos, event.as_bytes(), cap);
    push_raw(out, &mut pos, b"\t", cap);

    // detail_parts joined by single space, sanitized byte-by-byte. We
    // sanitize per-part because (a) the join separator is already a space
    // and (b) `\t \n \r` are 1-byte ASCII so a byte-level swap preserves
    // UTF-8 validity.
    for (i, part) in detail_parts.iter().enumerate() {
        if i > 0 {
            push_raw(out, &mut pos, b" ", cap);
        }
        let bytes = part.as_bytes();
        let remaining = cap.saturating_sub(pos);
        let mut take = bytes.len().min(remaining);
        // If we'd split a multibyte char, walk back to the previous boundary.
        // `bytes` is the byte view of a `&str`, so we can use the str API.
        if take < bytes.len() {
            while take > 0 && !part.is_char_boundary(take) {
                take -= 1;
            }
        }
        for j in 0..take {
            out[pos + j] = match bytes[j] {
                b'\t' | b'\n' | b'\r' => b' ',
                b => b,
            };
        }
        pos += take;
    }

    // Trailing newline — always fits because `cap = LIFECYCLE_MAX_LINE_BYTES - 1`.
    out[pos] = b'\n';
    pos + 1
}

/// No-alloc lifecycle writer used by the panic hook. Returns `false` if the
/// pre-opened fd is unavailable, or if the requested `root` does not match
/// the root the panic hook was installed for, so the caller can fall back
/// to the heap path.
///
/// Allocation budget: zero. The line is built into a `[u8; LIFECYCLE_MAX_LINE_BYTES]`
/// stack buffer; emission is `(&File).write_all(...)`, a single `write(2)`
/// for the small (< PIPE_BUF) line. The path-equality gate uses
/// `Path::parent()` (returns `&Path`, no heap) and `PartialEq` on `Path`
/// (component iteration, no heap), mirroring the heap writer's `pre.path == path`
/// check without the `root.join(LIFECYCLE_FILENAME)` allocation.
fn record_lifecycle_event_no_alloc(root: &Path, event: &str, detail_parts: &[&str]) -> bool {
    use std::io::Write;
    let Some(pre) = LIFECYCLE_LOG_FILE.get() else {
        return false;
    };
    // Discriminate by root so test/dev callers with arbitrary temp dirs
    // route through the heap fallback. `pre.path` was constructed as
    // `root.join(LIFECYCLE_FILENAME)`, so its parent is exactly the root
    // that was registered at install time.
    if pre.path.parent() != Some(root) {
        return false;
    }
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let mut buf = [0u8; LIFECYCLE_MAX_LINE_BYTES];
    let n = write_lifecycle_line(&mut buf, ts, &pre.pid_prefix, event, detail_parts);
    (&pre.file).write_all(&buf[..n]).is_ok()
}

/// Idempotent cleanup the panic hook performs on every panic.
///
/// Removes daemon sock + pid files (kernel auto-releases the SurrealKV flock,
/// so file unlink is enough for sibling-process recovery) and appends a
/// `panic` lifecycle event with location + payload. Best-effort throughout:
/// every fs operation swallows its error so the panic still surfaces.
///
/// **Lifecycle event is written via the no-alloc path when possible** — the
/// hook may run with a corrupted allocator, so we avoid `format!` /
/// `PathBuf::join` / `chars().collect()` on the panic path. If the pre-opened
/// fd is unavailable (install_panic_hook never ran or its open(2) failed),
/// we fall back to the heap path so the event still lands on disk.
///
/// Crate-internal: the only callers are this module's `install_panic_hook`
/// and its `#[cfg(test)]` block. Same-module tests have access to private
/// items, so this does not need to be `pub` for testability.
pub(crate) fn run_panic_cleanup(root: &Path, location: &str, payload: &str) {
    let _ = std::fs::remove_file(socket_path(root));
    let _ = std::fs::remove_file(metadata_path(root));
    if !record_lifecycle_event_no_alloc(root, "panic", &[location, payload]) {
        record_lifecycle_event(root, "panic", &format!("{location} {payload}"));
    }
}

/// Install a global panic hook that runs `run_panic_cleanup` before
/// delegating to the default hook.
///
/// Idempotent — only the first call's `root` is honored (subsequent calls are
/// no-ops). Safe to call from any startup path.
///
/// The hook runs on the panicking thread before unwinding, so it fires for
/// every panic in every tokio worker (tokio's spawn-boundary `catch_unwind`
/// invokes the hook before catching).
pub fn install_panic_hook(root: std::path::PathBuf) {
    if PANIC_HOOK_ROOT.set(root.clone()).is_err() {
        return;
    }
    // One-time lifecycle.log rotation. Single-writer window: we just
    // acquired the kernel flock to start serving, so no concurrent daemon
    // is rotating in parallel.
    trim_lifecycle_log(&root, MAX_LIFECYCLE_LINES);

    // Pre-open the lifecycle log so the panic hook only calls write(2), not
    // open(2). On macOS under memory pressure, open(2) can stall in the VFS
    // layer; holding the fd from startup removes that stall from the panic path.
    //
    // Also pre-format the "<pid>\t" prefix bytes here so the no-alloc panic
    // writer can copy them into a stack buffer without calling `format!`.
    // pid is process-global and stable, so caching it once is sound.
    let log_path = root.join(LIFECYCLE_FILENAME);
    if let Ok(f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
    {
        let pid = std::process::id();
        let mut pid_buf = [0u8; 20];
        let pid_len = u64_to_decimal_bytes(pid as u64, &mut pid_buf);
        let mut pid_prefix = Vec::with_capacity(pid_len + 1);
        pid_prefix.extend_from_slice(&pid_buf[..pid_len]);
        pid_prefix.push(b'\t');
        let _ = LIFECYCLE_LOG_FILE.set(PreOpenedLog {
            path: log_path,
            file: f,
            pid_prefix,
        });
    }

    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        if let Some(root) = PANIC_HOOK_ROOT.get() {
            let location = info
                .location()
                .map(|l| format!("{}:{}", l.file(), l.line()))
                .unwrap_or_else(|| "<unknown>".to_string());
            let payload = info
                .payload()
                .downcast_ref::<&str>()
                .copied()
                .or_else(|| info.payload().downcast_ref::<String>().map(String::as_str))
                .unwrap_or("<non-string panic>");
            run_panic_cleanup(root, &location, payload);
        }
        default_hook(info);
    }));
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_roundtrip() {
        let meta = DaemonMetadata::new(DaemonOwner::Daemon);
        let json = serde_json::to_string(&meta).unwrap();
        let back: DaemonMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(back.pid, meta.pid);
        assert_eq!(back.session, meta.session);
        assert_eq!(back.owner, DaemonOwner::Daemon);
    }

    #[test]
    fn metadata_mcp_owner_roundtrip() {
        let meta = DaemonMetadata {
            pid: 42,
            session: Uuid::new_v4(),
            owner: DaemonOwner::Mcp,
        };
        let json = serde_json::to_string(&meta).unwrap();
        let back: DaemonMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(back.owner, DaemonOwner::Mcp);
    }

    #[test]
    fn read_metadata_v2_format() {
        let dir = tempfile::tempdir().unwrap();
        let session = Uuid::new_v4();
        let meta = DaemonMetadata {
            pid: 1234,
            session,
            owner: DaemonOwner::Daemon,
        };
        publish_metadata(dir.path(), &meta).unwrap();

        let read = read_metadata(dir.path()).unwrap();
        assert_eq!(read.pid, 1234);
        assert_eq!(read.session, session);
        assert_eq!(read.owner, DaemonOwner::Daemon);
    }

    #[test]
    fn read_metadata_legacy_v1_json() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("mati.pid"), r#"{"pid":5678,"owner":"mcp"}"#).unwrap();

        let read = read_metadata(dir.path()).unwrap();
        assert_eq!(read.pid, 5678);
        assert_eq!(read.owner, DaemonOwner::Mcp);
        // Legacy format has no session — should get nil UUID.
        assert!(read.session.is_nil());
    }

    #[test]
    fn read_metadata_legacy_plain_pid() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("mati.pid"), "9999\n").unwrap();

        let read = read_metadata(dir.path()).unwrap();
        assert_eq!(read.pid, 9999);
        assert_eq!(read.owner, DaemonOwner::Daemon);
        assert!(read.session.is_nil());
    }

    #[test]
    fn read_metadata_missing_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read_metadata(dir.path()).is_none());
    }

    #[test]
    fn read_metadata_corrupt_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("mati.pid"), "not json at all ~~~").unwrap();
        assert!(read_metadata(dir.path()).is_none());
    }

    #[cfg(unix)]
    #[test]
    fn publish_metadata_sets_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let meta = DaemonMetadata::new(DaemonOwner::Daemon);
        publish_metadata(dir.path(), &meta).unwrap();

        let perms = std::fs::metadata(dir.path().join("mati.pid"))
            .unwrap()
            .permissions();
        assert_eq!(
            perms.mode() & 0o777,
            0o600,
            "metadata file should be mode 0600"
        );
    }

    #[cfg(unix)]
    #[test]
    fn publish_metadata_is_atomic() {
        let dir = tempfile::tempdir().unwrap();

        // Write initial metadata.
        let meta1 = DaemonMetadata {
            pid: 1,
            session: Uuid::new_v4(),
            owner: DaemonOwner::Daemon,
        };
        publish_metadata(dir.path(), &meta1).unwrap();

        // Overwrite atomically.
        let meta2 = DaemonMetadata {
            pid: 2,
            session: Uuid::new_v4(),
            owner: DaemonOwner::Mcp,
        };
        publish_metadata(dir.path(), &meta2).unwrap();

        // Read should see meta2, not a partial mix.
        let read = read_metadata(dir.path()).unwrap();
        assert_eq!(read.pid, 2);
        assert_eq!(read.owner, DaemonOwner::Mcp);

        // Temp file should not be left behind.
        assert!(!dir.path().join("mati.pid.tmp").exists());
    }

    #[cfg(unix)]
    #[test]
    fn ensure_runtime_dir_sets_mode_0700() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("test_root");

        ensure_runtime_dir(&root).unwrap();

        let perms = std::fs::metadata(&root).unwrap().permissions();
        assert_eq!(
            perms.mode() & 0o777,
            0o700,
            "runtime dir should be mode 0700"
        );
    }

    #[test]
    fn is_pid_alive_for_current_process() {
        assert!(is_pid_alive(std::process::id()));
    }

    #[test]
    fn is_pid_alive_for_dead_pid() {
        assert!(!is_pid_alive(4_000_000));
    }

    #[test]
    fn stale_check_clean_when_no_files() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(check_and_cleanup_stale(dir.path()), StaleCheckResult::Clean);
    }

    #[test]
    fn stale_check_removes_dead_pid() {
        let dir = tempfile::tempdir().unwrap();
        let meta = DaemonMetadata {
            pid: 4_000_000, // almost certainly dead
            session: Uuid::new_v4(),
            owner: DaemonOwner::Daemon,
        };
        publish_metadata(dir.path(), &meta).unwrap();
        std::fs::write(dir.path().join("mati.sock"), "").unwrap();

        let result = check_and_cleanup_stale(dir.path());
        assert_eq!(result, StaleCheckResult::StaleRemoved);
        assert!(!dir.path().join("mati.pid").exists());
        assert!(!dir.path().join("mati.sock").exists());
    }

    #[test]
    fn stale_check_live_daemon_detected() {
        let dir = tempfile::tempdir().unwrap();
        let meta = DaemonMetadata {
            pid: std::process::id(), // our own PID — alive
            session: Uuid::new_v4(),
            owner: DaemonOwner::Daemon,
        };
        publish_metadata(dir.path(), &meta).unwrap();

        match check_and_cleanup_stale(dir.path()) {
            StaleCheckResult::LiveDaemon { pid, .. } => {
                assert_eq!(pid, std::process::id());
            }
            other => panic!("expected LiveDaemon, got {:?}", other),
        }
    }

    #[test]
    fn stale_check_orphan_socket() {
        let dir = tempfile::tempdir().unwrap();
        // Socket exists but no metadata file.
        std::fs::write(dir.path().join("mati.sock"), "").unwrap();

        assert_eq!(
            check_and_cleanup_stale(dir.path()),
            StaleCheckResult::OrphanSocket
        );
    }

    #[test]
    fn stale_check_corrupt_metadata_cleaned_up() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("mati.pid"), "garbage!!!").unwrap();
        std::fs::write(dir.path().join("mati.sock"), "").unwrap();

        let result = check_and_cleanup_stale(dir.path());
        assert_eq!(result, StaleCheckResult::StaleRemoved);
        assert!(!dir.path().join("mati.pid").exists());
        assert!(!dir.path().join("mati.sock").exists());
    }

    // ── Peer credential tests ───────────────────────────────────────────

    /// Test peer credential check with a real Unix socket pair.
    /// Both endpoints run as the same user (test process), so the UID matches.
    #[cfg(unix)]
    #[tokio::test]
    async fn peer_cred_accepts_same_uid() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("test.sock");

        let listener = tokio::net::UnixListener::bind(&sock_path).unwrap();
        let connect_fut = tokio::net::UnixStream::connect(&sock_path);
        let accept_fut = listener.accept();

        let (client_result, accept_result) = tokio::join!(connect_fut, accept_fut);
        let _client = client_result.unwrap();
        let (server_stream, _) = accept_result.unwrap();

        let daemon_euid = current_euid();
        let peer = check_peer_cred(&server_stream, daemon_euid);
        assert!(
            peer.is_some(),
            "same-user connection should pass peer check"
        );

        let ctx = peer.unwrap();
        assert_eq!(ctx.uid, daemon_euid);
        // PID should be available on macOS and Linux.
        assert!(ctx.pid.is_some(), "peer PID should be available");
    }

    /// Test that a UID mismatch is correctly rejected.
    /// We simulate this by passing a fake daemon_euid that doesn't match.
    #[cfg(unix)]
    #[tokio::test]
    async fn peer_cred_rejects_uid_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("test_mismatch.sock");

        let listener = tokio::net::UnixListener::bind(&sock_path).unwrap();
        let connect_fut = tokio::net::UnixStream::connect(&sock_path);
        let accept_fut = listener.accept();

        let (client_result, accept_result) = tokio::join!(connect_fut, accept_fut);
        let _client = client_result.unwrap();
        let (server_stream, _) = accept_result.unwrap();

        // Use a fake daemon_euid that won't match the test process.
        let fake_euid = current_euid().wrapping_add(1);
        let peer = check_peer_cred(&server_stream, fake_euid);
        assert!(peer.is_none(), "mismatched UID should be rejected");
    }

    #[test]
    fn lifecycle_log_appends_one_line_per_event() {
        let dir = tempfile::tempdir().unwrap();
        record_lifecycle_event(dir.path(), "start", "owner=mcp");
        record_lifecycle_event(dir.path(), "shutdown", "reason=signal");
        let contents = std::fs::read_to_string(dir.path().join("lifecycle.log")).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 2, "exactly two events recorded");
        for line in &lines {
            // ts<TAB>pid<TAB>event<TAB>detail
            let cols: Vec<&str> = line.split('\t').collect();
            assert_eq!(cols.len(), 4, "each line has 4 tab-separated fields");
            // ts and pid must be valid integers.
            assert!(cols[0].parse::<u64>().is_ok());
            assert!(cols[1].parse::<u32>().is_ok());
        }
        assert!(lines[0].contains("\tstart\towner=mcp"));
        assert!(lines[1].contains("\tshutdown\treason=signal"));
    }

    #[test]
    fn lifecycle_log_strips_newlines_and_tabs_in_detail() {
        let dir = tempfile::tempdir().unwrap();
        record_lifecycle_event(dir.path(), "panic", "line1\nline2\twith tab\rcr");
        let contents = std::fs::read_to_string(dir.path().join("lifecycle.log")).unwrap();
        // Exactly one newline (the trailing one) — so exactly one logical line.
        assert_eq!(contents.matches('\n').count(), 1);
        assert!(contents.contains("line1 line2 with tab cr"));
    }

    #[test]
    fn lifecycle_log_silently_succeeds_when_dir_missing() {
        // Should not panic when target directory does not exist — best-effort.
        let dir = tempfile::tempdir().unwrap();
        let bogus = dir.path().join("nonexistent-subdir");
        record_lifecycle_event(&bogus, "start", "x");
        assert!(!bogus.join("lifecycle.log").exists());
    }

    /// Concurrent appenders interleave bytes mid-line above PIPE_BUF. A
    /// pathological panic payload (large Debug-formatted struct, JSON dump
    /// from a serde error) can easily exceed 4 KB. We cap the on-disk line
    /// well below PIPE_BUF so POSIX append atomicity holds. The line still
    /// ends with `\n` so `lines()` consumers and the trim path see a clean
    /// record, and the truncation point sits on a UTF-8 char boundary so a
    /// multibyte character is never split mid-encoding.
    #[test]
    fn lifecycle_log_caps_line_below_pipe_buf() {
        let dir = tempfile::tempdir().unwrap();
        // 10 KB of `é` (2-byte UTF-8) — exercises both the size cap AND the
        // char-boundary requirement. A naive byte-truncate would land mid-
        // multibyte and produce invalid UTF-8 on disk.
        let huge_detail: String = "é".repeat(5_000); // 10_000 bytes
        record_lifecycle_event(dir.path(), "panic", &huge_detail);

        let log = std::fs::read_to_string(dir.path().join("lifecycle.log")).unwrap();
        assert!(
            log.len() <= LIFECYCLE_MAX_LINE_BYTES,
            "line on disk ({} bytes) must not exceed cap ({})",
            log.len(),
            LIFECYCLE_MAX_LINE_BYTES
        );
        assert!(
            log.ends_with('\n'),
            "truncated line must still end with newline so lines() yields one record"
        );
        assert!(
            log.contains("\tpanic\t"),
            "event tag must survive truncation (it sits in the prefix)"
        );
        // `read_to_string` itself would have errored if truncation split a
        // UTF-8 char, but assert explicitly so the failure mode is named.
        assert!(
            log.is_char_boundary(log.len()),
            "truncation must land on UTF-8 char boundary"
        );
    }

    #[test]
    fn run_panic_cleanup_removes_sock_pid_and_appends_lifecycle_event() {
        let dir = tempfile::tempdir().unwrap();
        // Pre-create the daemon files the panic hook is supposed to remove.
        std::fs::write(dir.path().join("mati.sock"), "").unwrap();
        std::fs::write(dir.path().join("mati.pid"), r#"{"pid":42}"#).unwrap();

        run_panic_cleanup(dir.path(), "src/example.rs:99", "boom");

        // Files removed.
        assert!(
            !dir.path().join("mati.sock").exists(),
            "panic hook must remove mati.sock so sibling daemons can rebind"
        );
        assert!(
            !dir.path().join("mati.pid").exists(),
            "panic hook must remove mati.pid so sibling stale-checks see no live daemon"
        );
        // Lifecycle event recorded with location + payload preserved.
        let log = std::fs::read_to_string(dir.path().join("lifecycle.log")).unwrap();
        assert!(log.contains("\tpanic\t"), "event tagged 'panic'");
        assert!(log.contains("src/example.rs:99"), "location preserved");
        assert!(log.contains("boom"), "payload preserved");
    }

    #[test]
    fn run_panic_cleanup_is_safe_when_files_already_absent() {
        // The panic hook may run after another path has already cleaned up
        // (e.g., explicit shutdown ran first, then a panic during exit).
        // Cleanup must be idempotent — no crash, no error.
        let dir = tempfile::tempdir().unwrap();
        run_panic_cleanup(dir.path(), "src/x.rs:1", "noop");
        // Lifecycle log should still be written even when no files needed removal.
        assert!(dir.path().join("lifecycle.log").exists());
    }

    #[test]
    fn trim_lifecycle_log_keeps_last_n_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(LIFECYCLE_FILENAME);
        // Write 100 events, trim to last 10.
        let body: String = (0..100)
            .map(|i| format!("{i}\t{i}\tevent{i}\tdetail{i}\n"))
            .collect();
        std::fs::write(&path, body).unwrap();

        trim_lifecycle_log(dir.path(), 10);

        let after = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = after.lines().collect();
        assert_eq!(lines.len(), 10, "trimmed log should have exactly N lines");
        // Kept the last 10: events 90..=99.
        assert!(
            lines[0].contains("\tevent90\t"),
            "first kept line: {}",
            lines[0]
        );
        assert!(
            lines[9].contains("\tevent99\t"),
            "last kept line: {}",
            lines[9]
        );
        // No leftover .tmp.
        assert!(!path.with_extension("log.tmp").exists());
    }

    #[test]
    fn trim_lifecycle_log_noop_when_under_cap() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(LIFECYCLE_FILENAME);
        let body = "0\t0\tstart\tdetail\n1\t0\tstop\tclean\n";
        std::fs::write(&path, body).unwrap();
        let before = std::fs::read(&path).unwrap();

        trim_lifecycle_log(dir.path(), 10);

        let after = std::fs::read(&path).unwrap();
        assert_eq!(before, after, "trim must be a no-op when under cap");
    }

    /// Regression: pass-21 checkpoint B. If a hostile or buggy actor wrote
    /// a multi-gigabyte `lifecycle.log` (or filled the file with binary
    /// garbage that happens to be huge), the previous trim path would
    /// `read_to_string` the entire file at daemon startup and OOM the
    /// process. Startup must never block or OOM on a corrupt log
    /// (P9: graceful degradation). The size guard truncates pathological
    /// files to empty and continues, sacrificing the (already corrupt)
    /// observability in favor of a successful daemon start.
    #[test]
    fn trim_lifecycle_log_truncates_pathologically_huge_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(LIFECYCLE_FILENAME);

        // Write a file just over the read-cap. We don't need a real 64 MB
        // file to exercise the guard — we sparse-extend the file so the
        // metadata len() reads above the threshold without actually
        // allocating that much disk. (On the systems mati supports this
        // produces a sparse file; on filesystems that don't honor sparse
        // writes the test just uses a real 64 MB+1 byte file. Either way
        // the assertion holds.)
        {
            use std::io::{Seek, SeekFrom, Write};
            let mut f = std::fs::File::create(&path).unwrap();
            // Seek past the threshold so the file's reported length
            // exceeds LIFECYCLE_TRIM_MAX_READ_BYTES without writing the
            // intervening bytes. set_len would also work but seek+write
            // is the most portable form.
            f.seek(SeekFrom::Start(LIFECYCLE_TRIM_MAX_READ_BYTES + 1))
                .unwrap();
            f.write_all(b"x").unwrap();
        }
        let pre_size = std::fs::metadata(&path).unwrap().len();
        assert!(
            pre_size > LIFECYCLE_TRIM_MAX_READ_BYTES,
            "test setup: file must exceed the read cap"
        );

        // The trim must not panic, must not OOM, and must reduce the
        // file's size to zero (it was truncated as pathological).
        trim_lifecycle_log(dir.path(), 10);

        let post_meta = std::fs::metadata(&path).unwrap();
        assert!(
            post_meta.is_file(),
            "lifecycle.log should still exist after pathological trim"
        );
        assert_eq!(
            post_meta.len(),
            0,
            "pathologically large lifecycle.log must be truncated to empty so startup does not OOM"
        );
        // No leftover .tmp from the truncation path (we don't use tmp+rename here).
        assert!(!path.with_extension("log.tmp").exists());
    }

    /// The size guard must not fire on legitimate (sub-cap) files —
    /// regression check that the new ceiling does not break the normal
    /// trim path.
    #[test]
    fn trim_lifecycle_log_size_guard_does_not_fire_under_cap() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(LIFECYCLE_FILENAME);
        // 100 events ≈ 2 KB, well under the 64 MB cap.
        let body: String = (0..100)
            .map(|i| format!("{i}\t{i}\tevent{i}\tdetail{i}\n"))
            .collect();
        std::fs::write(&path, &body).unwrap();

        trim_lifecycle_log(dir.path(), 10);

        // Size guard should NOT have nuked the file — normal trim path
        // ran instead and kept the last 10 events.
        let after = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = after.lines().collect();
        assert_eq!(
            lines.len(),
            10,
            "normal trim path must run for sub-cap files"
        );
        assert!(lines[0].contains("event90"));
        assert!(lines[9].contains("event99"));
    }

    #[test]
    fn trim_lifecycle_log_silently_succeeds_on_missing_log() {
        let dir = tempfile::tempdir().unwrap();
        // No log file yet — must not panic, must not create one.
        trim_lifecycle_log(dir.path(), 10);
        assert!(!dir.path().join(LIFECYCLE_FILENAME).exists());
    }

    #[test]
    fn install_panic_hook_is_idempotent() {
        // Multiple calls must not crash. We can't easily test that the
        // FIRST root is honored across subsequent calls (that would
        // require process-global state inspection), but the contract is
        // "second call is a no-op" — exercised here.
        let dir = tempfile::tempdir().unwrap();
        install_panic_hook(dir.path().to_path_buf());
        install_panic_hook(dir.path().join("a-different-root"));
        // No assertion needed — test passes if neither call panics.
    }

    /// `u64_to_decimal_bytes` must produce the same digits as `format!("{n}")`
    /// across boundary cases (zero, single digit, max u64). Any divergence
    /// would silently corrupt the panic-path lifecycle entry's timestamp.
    #[test]
    fn u64_to_decimal_bytes_matches_format() {
        for n in [
            0u64,
            1,
            9,
            10,
            99,
            100,
            12345,
            1_700_000_000,
            u64::MAX / 2,
            u64::MAX,
        ] {
            let mut buf = [0u8; 20];
            let len = u64_to_decimal_bytes(n, &mut buf);
            assert_eq!(
                std::str::from_utf8(&buf[..len]).unwrap(),
                n.to_string(),
                "decimal mismatch for {n}"
            );
        }
    }

    /// Parity guard for Fix 3: the no-alloc panic-path formatter
    /// (`write_lifecycle_line`) must produce byte-identical output to the
    /// heap path's `format!("{ts}\t{pid}\t{event}\t{safe_detail}\n")` for
    /// representative inputs. If they ever drift, an external log consumer
    /// (`mati doctor`'s `read_lifecycle_tail`, the integration tests' line
    /// parsers) will silently see panic-path entries differently from
    /// normal-path entries.
    #[test]
    fn no_alloc_panic_format_matches_heap_format() {
        // Fixed inputs so the test is deterministic — the real writer reads
        // ts from the wall clock; here we pass it explicitly.
        let ts: u64 = 1_700_000_000;
        let pid: u32 = 42;
        let pid_prefix = format!("{pid}\t");
        let event = "panic";

        // Helper: reproduce the heap path's full formatting + truncation
        // from `record_lifecycle_event` so we can compare bytes.
        fn heap_format(ts: u64, pid_prefix: &str, event: &str, detail: &str) -> String {
            let safe_detail: String = detail
                .chars()
                .map(|c| match c {
                    '\t' | '\n' | '\r' => ' ',
                    c => c,
                })
                .collect();
            let mut line = format!("{ts}\t{pid_prefix}{event}\t{safe_detail}\n");
            if line.len() > LIFECYCLE_MAX_LINE_BYTES {
                let mut cut = LIFECYCLE_MAX_LINE_BYTES - 1;
                while cut > 0 && !line.is_char_boundary(cut) {
                    cut -= 1;
                }
                line.truncate(cut);
                line.push('\n');
            }
            line
        }

        // Representative case 1: a typical panic with location + payload.
        let location = "src/mcp/server.rs:128";
        let payload = "boom!";
        let detail = format!("{location} {payload}");
        let heap = heap_format(ts, &pid_prefix, event, &detail);
        let mut buf = [0u8; LIFECYCLE_MAX_LINE_BYTES];
        let n = write_lifecycle_line(
            &mut buf,
            ts,
            pid_prefix.as_bytes(),
            event,
            &[location, payload],
        );
        assert_eq!(
            std::str::from_utf8(&buf[..n]).unwrap(),
            heap,
            "panic-path format must match heap path for typical input"
        );

        // Representative case 2: payload contains \t \n \r — sanitization
        // must produce identical output through both paths.
        let location_2 = "src/x.rs:1";
        let payload_2 = "line1\nline2\twith tab\rcr";
        let detail_2 = format!("{location_2} {payload_2}");
        let heap_2 = heap_format(ts, &pid_prefix, event, &detail_2);
        let mut buf_2 = [0u8; LIFECYCLE_MAX_LINE_BYTES];
        let n2 = write_lifecycle_line(
            &mut buf_2,
            ts,
            pid_prefix.as_bytes(),
            event,
            &[location_2, payload_2],
        );
        assert_eq!(
            std::str::from_utf8(&buf_2[..n2]).unwrap(),
            heap_2,
            "panic-path format must match heap path with embedded control chars"
        );

        // Representative case 3: empty detail (e.g., a `start` event with no
        // detail string). Heap path passes "" as detail; no-alloc passes
        // a single empty `&str`.
        let heap_3 = heap_format(ts, &pid_prefix, "start", "");
        let mut buf_3 = [0u8; LIFECYCLE_MAX_LINE_BYTES];
        let n3 = write_lifecycle_line(&mut buf_3, ts, pid_prefix.as_bytes(), "start", &[""]);
        assert_eq!(
            std::str::from_utf8(&buf_3[..n3]).unwrap(),
            heap_3,
            "panic-path format must match heap path with empty detail"
        );
    }

    /// `record_lifecycle_event_no_alloc` must return `false` (not panic, not
    /// silently succeed) when the requested root does not match the
    /// preopened-fd root — that's how `run_panic_cleanup` knows to fall back
    /// to the heap path. The `Some` branch with a matching root is covered
    /// by `tests/panic_hook_preopen.rs`, which owns its own process.
    #[test]
    fn record_lifecycle_event_no_alloc_returns_false_for_unknown_root() {
        // Use a temp dir that no test would have called install_panic_hook
        // on. Whether or not LIFECYCLE_LOG_FILE has been set by a sibling
        // test in this binary, this temp dir cannot be the registered root,
        // so the path-equality gate must reject it.
        let dir = tempfile::tempdir().unwrap();
        assert!(!record_lifecycle_event_no_alloc(
            dir.path(),
            "smoke",
            &["from-tests"]
        ));
    }

    #[test]
    fn peer_context_pid_is_optional() {
        let ctx = PeerContext {
            uid: 501,
            pid: None,
        };
        assert!(ctx.pid.is_none());

        let ctx2 = PeerContext {
            uid: 501,
            pid: Some(1234),
        };
        assert_eq!(ctx2.pid, Some(1234));
    }
}
