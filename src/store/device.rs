//! Stable per-device identity.
//!
//! `Record.version.device_id` identifies the AUTHORING DEVICE — it is the
//! tiebreaker axis for the planned v0.2 `MergeEngine` (see `record.rs`,
//! `DeviceId`). The original design ("UUID v7 generated once, persisted")
//! was deferred at M-05 and every write path used a fresh `Uuid::new_v4()`
//! placeholder instead, which made the field meaningless: two records from
//! the same machine looked like two devices. This module implements the
//! documented design — one v7 UUID per user+machine, created on first use
//! at `~/.mati/device_id` and memoized for the process lifetime.
//!
//! Fail-open: if the home directory is missing or unwritable, a
//! process-lifetime random id is used — a degraded device id must never
//! block a record write.

use std::path::Path;
use std::sync::OnceLock;

use uuid::Uuid;

static DEVICE_ID: OnceLock<Uuid> = OnceLock::new();

/// The stable device id for this user+machine.
///
/// Reads (or creates, first-writer-wins) `~/.mati/device_id`. All record
/// write paths must use this instead of a per-record `Uuid::new_v4()`.
pub fn stable_device_id() -> Uuid {
    *DEVICE_ID.get_or_init(|| {
        let Some(home) = dirs::home_dir() else {
            return Uuid::now_v7();
        };
        load_or_create_at(&home.join(".mati").join("device_id"))
    })
}

/// Testable core of [`stable_device_id`]: load the id from `path`, creating
/// it if absent and repairing it if unparseable. Never fails — every error
/// path degrades to a fresh id for this process.
fn load_or_create_at(path: &Path) -> Uuid {
    if let Ok(existing) = std::fs::read_to_string(path) {
        if let Ok(id) = Uuid::parse_str(existing.trim()) {
            return id;
        }
        // Corrupt file: fall through and repair (last-wins overwrite below).
        let id = Uuid::now_v7();
        let _ = std::fs::write(path, id.to_string());
        return id;
    }

    let id = Uuid::now_v7();
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    // First-writer-wins: `create_new` never clobbers a concurrent writer;
    // if another process won the race, adopt its id.
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
    {
        Ok(mut f) => {
            use std::io::Write as _;
            let _ = f.write_all(id.to_string().as_bytes());
            id
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => std::fs::read_to_string(path)
            .ok()
            .and_then(|s| Uuid::parse_str(s.trim()).ok())
            .unwrap_or(id),
        Err(_) => id,
    }
}

/// Test-only accessor so unit tests can exercise the load/create/repair
/// logic against a temp path without touching the real `~/.mati/device_id`.
#[cfg(test)]
pub(crate) fn load_or_create_for_test(path: &Path) -> Uuid {
    load_or_create_at(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn creates_then_reloads_same_id() {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("device_id");
        let first = load_or_create_for_test(&path);
        let second = load_or_create_for_test(&path);
        assert_eq!(first, second, "id must be stable across loads");
        let on_disk = std::fs::read_to_string(&path).expect("file must exist");
        assert_eq!(
            Uuid::parse_str(on_disk.trim()).expect("valid uuid"),
            first,
            "persisted id must match the returned id"
        );
    }

    #[test]
    fn repairs_corrupt_file() {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("device_id");
        std::fs::write(&path, "not-a-uuid\n").expect("write");
        let repaired = load_or_create_for_test(&path);
        let reloaded = load_or_create_for_test(&path);
        assert_eq!(repaired, reloaded, "repair must persist a stable id");
    }

    #[test]
    fn creates_parent_dir_when_missing() {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("nested").join("device_id");
        let id = load_or_create_for_test(&path);
        assert_eq!(load_or_create_for_test(&path), id);
    }

    #[test]
    fn stable_device_id_is_memoized() {
        // Whatever the id resolves to on this machine, two calls in one
        // process must agree (OnceLock memoization).
        assert_eq!(stable_device_id(), stable_device_id());
    }
}
