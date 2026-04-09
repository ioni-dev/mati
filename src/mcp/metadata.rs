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
pub fn metadata_path(root: &Path) -> std::path::PathBuf {
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
    set_mode(root, 0o700)
        .with_context(|| format!("cannot set mode 0700 on {}", root.display()))?;
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

    let json = serde_json::to_string(metadata)
        .context("failed to serialize daemon metadata")?;

    std::fs::write(&tmp_path, json.as_bytes())
        .with_context(|| format!("failed to write {}", tmp_path.display()))?;

    // Set permissions BEFORE rename so the file is never visible with wrong mode.
    set_mode(&tmp_path, 0o600)?;

    std::fs::rename(&tmp_path, &final_path)
        .with_context(|| format!("failed to rename {} → {}", tmp_path.display(), final_path.display()))?;

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
        let owner_str = val.get("owner").and_then(|v| v.as_str()).unwrap_or("daemon");
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
pub fn check_peer_cred(
    stream: &tokio::net::UnixStream,
    daemon_euid: u32,
) -> Option<PeerContext> {
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
        std::fs::write(
            dir.path().join("mati.pid"),
            r#"{"pid":5678,"owner":"mcp"}"#,
        )
        .unwrap();

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
        assert!(peer.is_some(), "same-user connection should pass peer check");

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
        assert!(
            peer.is_none(),
            "mismatched UID should be rejected"
        );
    }

    #[test]
    fn peer_context_pid_is_optional() {
        let ctx = PeerContext { uid: 501, pid: None };
        assert!(ctx.pid.is_none());

        let ctx2 = PeerContext {
            uid: 501,
            pid: Some(1234),
        };
        assert_eq!(ctx2.pid, Some(1234));
    }
}
