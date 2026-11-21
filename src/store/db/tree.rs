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

/// Copy a surrealkv 0.x store to `<db>.bak-0.21` before 1.x converts it.
///
/// The conversion runs on open and is one-way: an older mati cannot read the
/// result, and surrealkv's own `_surrealkv_v0_backup/` is not a rollback
/// point. A 0.x store has a version-1 manifest; an interrupted conversion
/// leaves `MIGRATING`. The copy lands under a temporary name first, so a copy
/// cut short is never mistaken for a backup. Returns whether a copy was made.
fn backup_legacy_store(db: &std::path::Path) -> Result<bool> {
    let manifest = db.join("manifest/00000000000000000000.manifest");
    let legacy = std::fs::read(&manifest).is_ok_and(|b| b.starts_with(&[0, 1]))
        || db.join("MIGRATING").exists();
    let name = db.file_name().and_then(|n| n.to_str()).unwrap_or("store");
    let backup = db.with_file_name(format!("{name}.bak-0.21"));
    if !legacy || backup.exists() {
        return Ok(false);
    }
    let partial = db.with_file_name(format!("{name}.bak-0.21.tmp"));
    let _ = std::fs::remove_dir_all(&partial);
    crate::store::migrations::copy_dir_recursive(db, &partial)
        .and_then(|()| std::fs::rename(&partial, &backup))
        .with_context(|| {
            format!(
                "refusing to upgrade {} without a backup: could not copy it to {}",
                db.display(),
                backup.display()
            )
        })?;
    Ok(true)
}

/// Build a tree, backing a 0.x store up first. A failed open (another process
/// holds the lock) drops the fresh backup: it may have been copied mid-write.
fn build_tree(opts: Options, path: &std::path::Path, what: &str) -> Result<Tree> {
    let backed_up = backup_legacy_store(path)?;
    let built = TreeBuilder::with_options(opts)
        .build()
        .with_context(|| format!("failed to open {what}"));
    if built.is_err() && backed_up {
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("store");
        let _ = std::fs::remove_dir_all(path.with_file_name(format!("{name}.bak-0.21")));
    }
    built
}

pub(super) fn open_knowledge_tree(path: PathBuf) -> Result<Tree> {
    // vlog_value_threshold must be 0 when versioning is enabled — SurrealKV
    // requires all values to be in the VLog for time-travel to work.
    let opts = Options::new()
        .with_path(path.clone())
        .with_versioning(true, 0) // indefinite retention
        .with_enable_vlog(true)
        .with_vlog_value_threshold(0)
        .with_vlog_checksum_verification(VLogChecksumLevel::Full);
    build_tree(opts, &path, "knowledge.db")
}

pub(super) fn open_sessions_tree(path: PathBuf) -> Result<Tree> {
    // Same constraint: vlog_value_threshold = 0 required when versioning is on.
    // VLogChecksumLevel is intentionally omitted — session writes are high-frequency
    // and acceptable to lose on crash. Do not add checksum verification here.
    let opts = Options::new()
        .with_path(path.clone())
        .with_versioning(true, SESSIONS_RETENTION_NS)
        .with_enable_vlog(true)
        .with_vlog_value_threshold(0);
    build_tree(opts, &path, "sessions.db")
}
