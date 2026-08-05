//! Tree construction helpers for the SurrealKV-backed store.

use super::*;

// 90 days expressed as nanoseconds — retention period for sessions.db
const SESSIONS_RETENTION_NS: u64 = 90 * 24 * 60 * 60 * 1_000_000_000u64;

/// If a store open fails and the LOCK file exists, another mati process (MCP
/// server or daemon) holds the exclusive SurrealKV lock. Replace the raw OS
/// error with an actionable message.
/// Improve SurrealKV open errors with actionable context.
///
/// SurrealKV's LOCK file always exists after first use — it is never deleted.
/// The OS-level flock is what prevents concurrent access, not the file's
/// existence. So we detect lock contention by checking the *error message*,
/// not by checking if the LOCK file exists.
pub(super) fn lock_error_hint(err: anyhow::Error, db_path: &std::path::Path) -> anyhow::Error {
    let msg = format!("{err}");
    if msg.contains("already locked") || msg.contains("WouldBlock") {
        // Real lock contention — another process holds the flock.
        // Read the PID from the LOCK file if available.
        let lock_file = db_path.join("LOCK");
        let pid_hint = std::fs::read_to_string(&lock_file)
            .ok()
            .and_then(|s| s.trim().parse::<u32>().ok())
            .map(|pid| format!(" (holder PID: {pid})"))
            .unwrap_or_default();
        anyhow::anyhow!(
            "cannot open {} — another mati process holds the lock{pid_hint}.\n\
             This is usually the MCP server (mati serve) or a background daemon.\n\
             To stop the daemon: `mati daemon stop`\n\
             To check: `lsof {}/LOCK`",
            db_path.display(),
            db_path.display()
        )
    } else {
        err
    }
}

pub(super) fn open_knowledge_tree(path: PathBuf) -> Result<Tree> {
    // vlog_value_threshold must be 0 when versioning is enabled — SurrealKV
    // requires all values to be in the VLog for time-travel to work.
    let opts = Options::new()
        .with_path(path)
        .with_versioning(true, 0) // indefinite retention
        .with_enable_vlog(true)
        .with_vlog_value_threshold(0)
        .with_vlog_checksum_verification(VLogChecksumLevel::Full);
    TreeBuilder::with_options(opts)
        .build()
        .context("failed to open knowledge.db")
}

pub(super) fn open_sessions_tree(path: PathBuf) -> Result<Tree> {
    // Same constraint: vlog_value_threshold = 0 required when versioning is on.
    // VLogChecksumLevel is intentionally omitted — session writes are high-frequency
    // and acceptable to lose on crash. Do not add checksum verification here.
    let opts = Options::new()
        .with_path(path)
        .with_versioning(true, SESSIONS_RETENTION_NS)
        .with_enable_vlog(true)
        .with_vlog_value_threshold(0);
    TreeBuilder::with_options(opts)
        .build()
        .context("failed to open sessions.db")
}
