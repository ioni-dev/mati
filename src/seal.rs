//! Tier 2 read floor: the mode bit and the manifest that undoes it.
//!
//! A sealed file sits at mode `000`, so a kernel `EACCES` reaches every caller
//! — including the native `Grep` tool, which is not a subprocess and so never
//! meets the `mati sandbox` floor. The mode lifts when a consultation receipt
//! for the file is minted, and re-arms when that receipt lapses.
//!
//! The `chmod` destroys the original mode, so every seal is recorded in a
//! fsynced manifest at `~/.mati/<slug>/sealed.json` *before* the `chmod`, never
//! after. `mati seal clear` restores from that manifest without opening the
//! store, so a wedged daemon cannot strand a locked tree.
//!
//! `mati seal` (`src/cli/seal.rs`) arms and disarms the floor; the lift lives
//! here because the daemon holds the receipt path and cannot reach the binary
//! crate.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use crate::store::{derive_slug, mati_home};

/// Tier 2 selector. Dynamic, unlike the four `mati sandbox` tags: the floor
/// lifts on a receipt and re-arms when it lapses.
pub const TAG_CONSULT_TO_READ: &str = "consult-to-read";

/// The mode a sealed file is held at.
pub const SEALED_MODE: u32 = 0o000;

const MANIFEST_FILE: &str = "sealed.json";

/// Rungs 1 and 3 of the restore ladder, in the manifest a human opens at rung 2.
pub const RESTORE_NOTE: &str = "These files were set to mode 000 by `mati seal`. \
To restore them, run `mati seal clear`. If mati will not run at all, \
`chmod -R u+rwX <worktree>` restores owner read/write without it.";

/// One sealed file. `mode` is octal without a prefix (`"644"`) so a human
/// reading the manifest at rung 2 can hand it straight to `chmod`.
///
/// The stamp fields are the sweep's baseline, taken while the file was last
/// readable. All four default, so a manifest written before the sweep existed
/// still parses — a row with no stamp is simply never reported as changed.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct SealedFile {
    pub path: String,
    pub mode: String,
    /// SHA-256 of the bytes at seal time, lowercase hex — the same form
    /// `gotcha_ops::disk_content_hash` writes, so the two are comparable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    /// Modification time in nanoseconds since the epoch. Nanoseconds, not
    /// seconds: a chmod-write-chmod sequence inside one shell command lands
    /// well inside a second.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtime_ns: Option<u64>,
    /// Inode change time in nanoseconds, read after the `chmod` that sealed
    /// the file. mtime alone is not enough: `utimensat` restores it to the
    /// nanosecond, and an agent that tampers and puts mtime back defeats a
    /// size-and-mtime check (measured 2026-08-30). ctime moves on any inode
    /// change, including the two `chmod`s such a tamper needs, and nothing in
    /// userspace sets it backwards.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ctime_ns: Option<u64>,
    /// When the sweep last put this row back to mode `000`. A lift dated
    /// before it cannot have come from a receipt, because the only thing that
    /// lifts on a receipt runs at mint time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rearmed_at: Option<u64>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Manifest {
    #[serde(rename = "_restore", default)]
    restore: String,
    #[serde(default)]
    pub files: Vec<SealedFile>,
}

impl Manifest {
    pub fn find(&self, path: &str) -> Option<&SealedFile> {
        self.files.iter().find(|f| f.path == path)
    }
}

/// The manifest for a repo, resolved the way [`crate::store::Store::open`]
/// resolves the store root it sits in.
pub fn manifest_path(repo_root: &Path) -> Result<PathBuf> {
    Ok(manifest_in(&mati_home()?.join(derive_slug(repo_root))))
}

/// The manifest inside an already-resolved `~/.mati/<slug>/`.
pub fn manifest_in(store_root: &Path) -> PathBuf {
    store_root.join(MANIFEST_FILE)
}

/// A missing or unreadable manifest reads as empty: nothing is sealed that we
/// know of, and refusing here would block `clear` when it is needed most.
pub fn read_manifest(path: &Path) -> Manifest {
    std::fs::read(path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

/// Temp-file, fsync, rename. `std::fs::write` does not fsync on macOS, and a
/// manifest that loses a row to a crash leaves a locked file the ladder cannot
/// repair above rung 3.
pub fn write_manifest(path: &Path, manifest: &Manifest) -> Result<()> {
    let dir = path.parent().context("manifest path has no parent")?;
    std::fs::create_dir_all(dir)?;

    let mut out = manifest.clone();
    out.restore = RESTORE_NOTE.to_string();
    let body = serde_json::to_vec_pretty(&out)?;

    let tmp = path.with_extension("json.tmp");
    let mut f =
        std::fs::File::create(&tmp).with_context(|| format!("cannot create {}", tmp.display()))?;
    f.write_all(&body)?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp, path)?;

    // The rename itself is only durable once the directory entry is synced.
    if let Ok(d) = std::fs::File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

pub fn parse_mode(mode: &str) -> Result<u32> {
    u32::from_str_radix(mode, 8).with_context(|| format!("`{mode}` is not an octal mode"))
}

/// Restore one file's mode. A path that is gone counts as restored — there is
/// nothing left to unseal, and keeping the row would fail `clear` forever.
pub fn restore_one(f: &SealedFile) -> Result<()> {
    let path = Path::new(&f.path);
    if !path.exists() {
        return Ok(());
    }
    let mode = parse_mode(&f.mode)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .with_context(|| format!("cannot chmod {}", path.display()))
}

/// Lift the floor on `rel` because a consultation receipt for it was just
/// minted. Returns the restored mode, or `None` when the file is not sealed.
///
/// The manifest row survives the lift: the file is still under Tier 2, and the
/// row is what re-arms it and what `mati seal clear` restores from.
///
/// Worktree-scoped, not per-actor, and not by choice — the mode lives on the
/// inode, so one receipt opens the file for every actor sharing that worktree.
/// The per-actor gate stays with the read gate on top of it.
pub fn lift_on_receipt(repo_root: &Path, store_root: &Path, rel: &str) -> Option<u32> {
    // Ordered cheapest first: one stat rejects every unsealed file, so the
    // manifest is only ever read for a file that is actually at mode 000.
    let joined = repo_root.join(rel);
    let meta = std::fs::metadata(&joined).ok()?;
    if meta.permissions().mode() & 0o7777 != SEALED_MODE {
        return None;
    }

    // `mati seal add` records the canonicalized path, so match on that.
    let abs = std::fs::canonicalize(&joined).ok()?;
    let manifest = read_manifest(&manifest_in(store_root));
    let mode = parse_mode(&manifest.find(&abs.to_string_lossy())?.mode).ok()?;

    std::fs::set_permissions(&abs, std::fs::Permissions::from_mode(mode)).ok()?;
    Some(mode)
}

/// Re-arm every file the manifest lists, whatever mode it currently holds.
/// Returns the paths actually set back to [`SEALED_MODE`].
///
/// Store-free and manifest-read-only, like `mati seal clear`: it runs before
/// the store opens at daemon start, and it cannot damage the one artifact the
/// restore ladder depends on.
///
/// Keyed on the manifest row, not the `consult-to-read` tag. `mati seal clear`
/// empties the manifest and cannot drop the tag — it is rung 1 of the ladder
/// and never opens the store — so a tag-keyed re-arm would undo the break-glass
/// escape at the next daemon start.
///
/// Sets the mode directly rather than restoring first and re-sealing after.
/// Same end state, and no window in which the file is readable.
pub fn rearm_all(store_root: &Path) -> Vec<PathBuf> {
    let mut rearmed = Vec::new();
    for f in read_manifest(&manifest_in(store_root)).files {
        let path = PathBuf::from(&f.path);
        // A row whose file is gone re-arms nothing; `mati seal clear` drops it.
        if !path.exists() {
            continue;
        }
        match std::fs::set_permissions(&path, std::fs::Permissions::from_mode(SEALED_MODE)) {
            Ok(()) => rearmed.push(path),
            Err(e) => tracing::warn!("seal: cannot re-arm {}: {e}", path.display()),
        }
    }
    rearmed
}

// ── The post-Bash sweep ─────────────────────────────────────────────────────

/// What the sweep found for one row. Neither variant is a verdict on its own:
/// the caller has to ask the daemon a receipt question before it knows whether
/// a lowered floor was a lapsed lift or a bypass.
#[derive(Debug, Clone, PartialEq)]
pub enum Finding {
    /// The mode is no longer `000`.
    FloorDown {
        rel: String,
        /// When the sweep last re-armed this row, or 0 if it never has. A
        /// receipt minted at or after this moment explains the lift; anything
        /// older cannot have caused it.
        rearmed_at: u64,
    },
    /// The bytes moved while mode `000` still stood. Unambiguous: nothing
    /// legitimate writes through a mode the kernel is enforcing, and the
    /// only way in is a chmod-write-chmod sequence inside one command, or a
    /// rename into the directory, which needs no permission on the file.
    ContentMoved { rel: String },
}

impl Finding {
    pub fn rel(&self) -> &str {
        match self {
            Finding::FloorDown { rel, .. } | Finding::ContentMoved { rel } => rel,
        }
    }

    /// The consultable key for this row.
    pub fn key(&self) -> String {
        format!("file:{}", self.rel())
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn mtime_ns_of(meta: &std::fs::Metadata) -> Option<u64> {
    let t = meta.modified().ok()?;
    let d = t.duration_since(std::time::UNIX_EPOCH).ok()?;
    u64::try_from(d.as_nanos()).ok()
}

fn ctime_ns_of(meta: &std::fs::Metadata) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;
    let secs = u64::try_from(meta.ctime()).ok()?;
    let nanos = u64::try_from(meta.ctime_nsec()).ok()?;
    secs.checked_mul(1_000_000_000)?.checked_add(nanos)
}

fn sha256_of(path: &Path) -> Option<String> {
    use sha2::{Digest, Sha256};
    Some(format!("{:x}", Sha256::digest(std::fs::read(path).ok()?)))
}

/// Hash a file that may be sealed, lifting the mode only for the read.
///
/// This is the one privileged read Tier 2 grants (9.8), and it is bounded on
/// purpose: it runs only after a `stat` already showed the bytes moved, which
/// is a change the agent made. `mati stale` and `mati doctor` open no window,
/// so there is no `mati`-shaped lever for opening a file on demand.
fn hash_through_the_floor(path: &Path, sealed: bool) -> Option<String> {
    if !sealed {
        return sha256_of(path);
    }
    let restore = std::fs::Permissions::from_mode(SEALED_MODE);
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o400)).ok()?;
    let digest = sha256_of(path);
    let _ = std::fs::set_permissions(path, restore);
    digest
}

/// Stat every manifest row and report what moved since it was sealed.
///
/// Opens no store, so it runs on the async PostToolUse path with nothing to
/// wait for. Steady state is one `stat` per row and nothing else: a row at
/// mode `000` whose size and mtime match its stamp is silent.
///
/// A row with no stamp — written before the sweep existed — is checked for a
/// lowered floor but never reported as changed. There is no baseline to
/// compare it against, and inventing one would report every old row once.
pub fn scan(store_root: &Path, repo_root: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();
    for f in read_manifest(&manifest_in(store_root)).files {
        let path = PathBuf::from(&f.path);
        let Ok(rel) = path.strip_prefix(repo_root) else {
            continue;
        };
        let rel = rel.to_string_lossy().to_string();
        let Ok(meta) = std::fs::metadata(&path) else {
            continue;
        };

        if meta.permissions().mode() & 0o7777 != SEALED_MODE {
            findings.push(Finding::FloorDown {
                rel,
                rearmed_at: f.rearmed_at.unwrap_or(0),
            });
            continue;
        }

        // Still sealed. Only a moved stat is worth a read. ctime is the one
        // that cannot be forged back: an agent restoring mtime to the
        // nanosecond still leaves ctime ahead of the seal.
        let moved = match (f.size, f.mtime_ns) {
            (Some(size), Some(mtime)) => {
                meta.len() != size
                    || mtime_ns_of(&meta) != Some(mtime)
                    || f.ctime_ns.is_some_and(|c| ctime_ns_of(&meta) != Some(c))
            }
            _ => false,
        };
        if moved && hash_through_the_floor(&path, true) != f.sha256 {
            findings.push(Finding::ContentMoved { rel });
        }
    }
    findings
}

/// Put one row back to mode `000` and refresh its stamp.
///
/// Re-stamps from the file as it stands now, not as it was sealed: the sweep
/// runs after the change, so the new bytes are the baseline the next sweep
/// compares against. Reporting the same violation on every later command would
/// bury the one that mattered.
///
/// Returns false when the row is unknown or the `chmod` failed.
pub fn reseal(store_root: &Path, repo_root: &Path, rel: &str) -> bool {
    let mpath = manifest_in(store_root);
    let mut manifest = read_manifest(&mpath);
    let path = repo_root.join(rel);
    let Ok(canonical) = std::fs::canonicalize(&path) else {
        return false;
    };
    let key = canonical.to_string_lossy().to_string();
    let Some(row) = manifest.files.iter_mut().find(|f| f.path == key) else {
        return false;
    };

    let sealed = std::fs::metadata(&canonical)
        .map(|m| m.permissions().mode() & 0o7777 == SEALED_MODE)
        .unwrap_or(false);
    row.sha256 = hash_through_the_floor(&canonical, sealed);
    if let Ok(meta) = std::fs::metadata(&canonical) {
        row.size = Some(meta.len());
        row.mtime_ns = mtime_ns_of(&meta);
    }
    row.rearmed_at = Some(now_secs());

    if std::fs::set_permissions(&canonical, std::fs::Permissions::from_mode(SEALED_MODE)).is_err() {
        return false;
    }
    // ctime is read AFTER the chmod, because the chmod moves it. Stamping it
    // before would make the very next sweep report a change mati itself made.
    row.ctime_ns = std::fs::metadata(&canonical)
        .ok()
        .and_then(|m| ctime_ns_of(&m));

    // Manifest last: a crash before it leaves a sealed file with a stale
    // stamp, which the next sweep reports as changed. Noisy, and the safe
    // direction — the reverse would record a re-arm that never happened.
    write_manifest(&mpath, &manifest).is_ok()
}

// ── Read-only inventory ─────────────────────────────────────────────────────

/// What the manifest holds, against what the filesystem says about each row.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Inventory {
    /// Rows still at mode `000`.
    pub at_floor: usize,
    /// Rows readable right now, because a live receipt lifted them.
    pub lifted: usize,
    /// Rows whose file is gone. `mati seal remove` drops the row.
    pub missing: usize,
}

impl Inventory {
    pub fn total(&self) -> usize {
        self.at_floor + self.lifted + self.missing
    }
}

/// Stat every manifest row for `mati doctor` and `mati stats`.
///
/// One `stat` per row and nothing else. Unlike [`scan`] it never hashes, so it
/// never lifts the mode — a reporting surface must not be a lever for opening
/// a sealed file.
pub fn inventory(manifest: &Path) -> Inventory {
    let mut inv = Inventory::default();
    for f in read_manifest(manifest).files {
        match std::fs::metadata(&f.path) {
            Err(_) => inv.missing += 1,
            Ok(m) if m.permissions().mode() & 0o7777 == SEALED_MODE => inv.at_floor += 1,
            Ok(_) => inv.lifted += 1,
        }
    }
    inv
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sealed(path: &str, mode: &str) -> SealedFile {
        SealedFile {
            path: path.to_string(),
            mode: mode.to_string(),
            ..Default::default()
        }
    }

    /// A repo holding one file at `mode`, plus a store root whose manifest
    /// records it. Returns `(repo, store_root, relative path)`.
    fn seal_fixture(mode: u32) -> (tempfile::TempDir, tempfile::TempDir, &'static str) {
        let repo = tempfile::tempdir().unwrap();
        let store = tempfile::tempdir().unwrap();
        let rel = "src/gated.rs";
        let abs = repo.path().join(rel);
        std::fs::create_dir_all(abs.parent().unwrap()).unwrap();
        std::fs::write(&abs, b"secret").unwrap();

        let canonical = std::fs::canonicalize(&abs).unwrap();
        write_manifest(
            &manifest_in(store.path()),
            &Manifest {
                restore: String::new(),
                files: vec![sealed(&canonical.to_string_lossy(), "644")],
            },
        )
        .unwrap();
        std::fs::set_permissions(&abs, std::fs::Permissions::from_mode(mode)).unwrap();
        (repo, store, rel)
    }

    fn mode_of(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o7777
    }

    #[test]
    fn manifest_round_trips_through_the_written_form() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("sealed.json");
        let m = Manifest {
            restore: String::new(),
            files: vec![sealed("/repo/a.rs", "644"), sealed("/repo/b.rs", "600")],
        };
        write_manifest(&p, &m).unwrap();
        assert_eq!(read_manifest(&p).files, m.files);
    }

    #[test]
    fn the_written_manifest_names_the_restore_command() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("sealed.json");
        write_manifest(&p, &Manifest::default()).unwrap();
        let body = std::fs::read_to_string(&p).unwrap();
        assert!(body.contains("mati seal clear"));
        assert!(body.contains("chmod -R u+rwX"));
    }

    #[test]
    fn a_missing_manifest_reads_as_empty_rather_than_failing() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read_manifest(&dir.path().join("absent.json"))
            .files
            .is_empty());
    }

    #[test]
    fn a_corrupt_manifest_reads_as_empty_rather_than_failing() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("sealed.json");
        std::fs::write(&p, b"{not json").unwrap();
        assert!(read_manifest(&p).files.is_empty());
    }

    #[test]
    fn modes_survive_the_octal_string_round_trip() {
        for mode in [0o644u32, 0o600, 0o755, 0o640] {
            assert_eq!(parse_mode(&format!("{mode:o}")).unwrap(), mode);
        }
    }

    #[test]
    fn restore_returns_a_sealed_file_to_its_recorded_mode() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("f.rs");
        std::fs::write(&p, b"x").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(SEALED_MODE)).unwrap();

        restore_one(&sealed(&p.to_string_lossy(), "644")).unwrap();
        assert_eq!(mode_of(&p), 0o644);
    }

    #[test]
    fn restoring_a_deleted_file_succeeds_so_clear_can_drop_the_row() {
        restore_one(&sealed("/nonexistent/gone.rs", "644")).unwrap();
    }

    #[test]
    fn restore_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("f.rs");
        std::fs::write(&p, b"x").unwrap();
        let f = sealed(&p.to_string_lossy(), "600");
        restore_one(&f).unwrap();
        restore_one(&f).unwrap();
        assert_eq!(mode_of(&p), 0o600);
    }

    #[test]
    fn a_receipt_lifts_a_sealed_file_to_its_recorded_mode() {
        let (repo, store, rel) = seal_fixture(SEALED_MODE);
        assert_eq!(lift_on_receipt(repo.path(), store.path(), rel), Some(0o644));
        assert_eq!(mode_of(&repo.path().join(rel)), 0o644);
    }

    /// The file stays under Tier 2 after the lift — the row is what re-arms it
    /// and what `mati seal clear` restores from.
    #[test]
    fn the_lift_leaves_the_manifest_row_in_place() {
        let (repo, store, rel) = seal_fixture(SEALED_MODE);
        lift_on_receipt(repo.path(), store.path(), rel).unwrap();
        assert_eq!(read_manifest(&manifest_in(store.path())).files.len(), 1);
    }

    #[test]
    fn a_receipt_for_an_unsealed_file_lifts_nothing() {
        let (repo, store, rel) = seal_fixture(0o600);
        assert_eq!(lift_on_receipt(repo.path(), store.path(), rel), None);
        assert_eq!(mode_of(&repo.path().join(rel)), 0o600);
    }

    /// Mode 000 alone is not consent: without a row mati does not know the
    /// original mode, so guessing one would widen the file.
    #[test]
    fn a_mode_000_file_mati_did_not_seal_is_left_alone() {
        let repo = tempfile::tempdir().unwrap();
        let store = tempfile::tempdir().unwrap();
        let abs = repo.path().join("locked.rs");
        std::fs::write(&abs, b"x").unwrap();
        std::fs::set_permissions(&abs, std::fs::Permissions::from_mode(SEALED_MODE)).unwrap();

        assert_eq!(
            lift_on_receipt(repo.path(), store.path(), "locked.rs"),
            None
        );
        assert_eq!(mode_of(&abs), SEALED_MODE);
    }

    #[test]
    fn a_receipt_for_a_path_that_is_not_on_disk_lifts_nothing() {
        let (repo, store, _) = seal_fixture(SEALED_MODE);
        assert_eq!(
            lift_on_receipt(repo.path(), store.path(), "src/gone.rs"),
            None
        );
    }

    // ── the post-Bash sweep ─────────────────────────────────────────────

    /// A fully stamped fixture, produced the way `mati seal add` produces one:
    /// a write-ahead row, then `reseal` to hash, chmod and stamp.
    fn stamped_fixture() -> (tempfile::TempDir, tempfile::TempDir, PathBuf, &'static str) {
        let repo = tempfile::tempdir().unwrap();
        let store = tempfile::tempdir().unwrap();
        let rel = "src/gated.rs";
        let abs = repo.path().join(rel);
        std::fs::create_dir_all(abs.parent().unwrap()).unwrap();
        std::fs::write(&abs, b"secret").unwrap();

        let canonical = std::fs::canonicalize(&abs).unwrap();
        write_manifest(
            &manifest_in(store.path()),
            &Manifest {
                restore: String::new(),
                files: vec![SealedFile {
                    path: canonical.to_string_lossy().into(),
                    mode: "644".to_string(),
                    ..Default::default()
                }],
            },
        )
        .unwrap();
        let root = std::fs::canonicalize(repo.path()).unwrap();
        assert!(reseal(store.path(), &root, rel));
        (repo, store, root, rel)
    }

    fn rearmed_at_of(store: &Path) -> u64 {
        read_manifest(&manifest_in(store)).files[0]
            .rearmed_at
            .unwrap()
    }

    /// The steady state: sealed, untouched, nothing to say.
    #[test]
    fn a_sealed_file_that_nobody_touched_reports_nothing() {
        let (_repo, store, root, _) = stamped_fixture();
        assert!(scan(store.path(), &root).is_empty());
    }

    #[test]
    fn a_lowered_floor_is_reported_with_the_moment_it_was_last_rearmed() {
        let (repo, store, root, rel) = stamped_fixture();
        let stamped = rearmed_at_of(store.path());
        std::fs::set_permissions(
            repo.path().join(rel),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert_eq!(
            scan(store.path(), &root),
            vec![Finding::FloorDown {
                rel: rel.to_string(),
                rearmed_at: stamped
            }]
        );
    }

    /// The chmod-write-chmod window: the mode is back at 000 and the bytes are
    /// not the ones that were sealed. Only the privileged read can see it.
    #[test]
    fn content_changed_under_an_intact_mode_000_is_caught() {
        let (repo, store, root, rel) = stamped_fixture();
        let abs = repo.path().join(rel);
        std::fs::set_permissions(&abs, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::write(&abs, b"tampered").unwrap();
        std::fs::set_permissions(&abs, std::fs::Permissions::from_mode(SEALED_MODE)).unwrap();

        assert_eq!(
            scan(store.path(), &root),
            vec![Finding::ContentMoved {
                rel: rel.to_string()
            }]
        );
        // The privileged read must put the mode back.
        assert_eq!(mode_of(&abs), SEALED_MODE);
    }

    /// mtime can be restored to the nanosecond — measured 2026-08-30,
    /// `os.utime(ns=)` does it — so a same-length tamper that puts mtime back
    /// is invisible to a size-and-mtime check. ctime is what survives: the two
    /// `chmod`s such a tamper needs move it, and nothing in userspace sets it
    /// backwards. Here the size and mtime in the row are made to agree with
    /// the tampered file, so ctime is the only thing left that can fire.
    #[test]
    fn a_moved_ctime_alone_is_enough_to_catch_a_tamper() {
        let (repo, store, root, rel) = stamped_fixture();
        let abs = repo.path().join(rel);
        std::fs::set_permissions(&abs, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::write(&abs, b"tamper").unwrap(); // same length as "secret"
        std::fs::set_permissions(&abs, std::fs::Permissions::from_mode(SEALED_MODE)).unwrap();

        let mpath = manifest_in(store.path());
        let mut m = read_manifest(&mpath);
        let meta = std::fs::metadata(&abs).unwrap();
        m.files[0].size = Some(meta.len());
        m.files[0].mtime_ns = mtime_ns_of(&meta);
        write_manifest(&mpath, &m).unwrap();

        assert_eq!(
            scan(store.path(), &root),
            vec![Finding::ContentMoved {
                rel: rel.to_string()
            }],
            "ctime is the only signal left, and it has to be enough"
        );
    }

    /// ctime moves on the `chmod` a legitimate lift performs too, so it can
    /// only ever trigger the read — the hash decides. Otherwise every lift
    /// would be reported as a tamper.
    #[test]
    fn a_moved_ctime_with_unchanged_bytes_reports_nothing() {
        let (_repo, store, root, _) = stamped_fixture();
        let mpath = manifest_in(store.path());
        let mut m = read_manifest(&mpath);
        m.files[0].ctime_ns = Some(1);
        write_manifest(&mpath, &m).unwrap();

        assert!(scan(store.path(), &root).is_empty());
    }

    /// A row written before the sweep existed has no baseline. Check its
    /// floor, never its bytes — inventing a baseline reports every old row.
    #[test]
    fn an_unstamped_row_is_never_reported_as_changed() {
        let (repo, store, rel) = seal_fixture(SEALED_MODE);
        let root = std::fs::canonicalize(repo.path()).unwrap();
        let abs = repo.path().join(rel);
        std::fs::set_permissions(&abs, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::write(&abs, b"tampered").unwrap();
        std::fs::set_permissions(&abs, std::fs::Permissions::from_mode(SEALED_MODE)).unwrap();

        assert!(scan(store.path(), &root).is_empty());
    }

    #[test]
    fn reseal_restores_the_floor_and_restamps_it() {
        let (repo, store, root, rel) = stamped_fixture();
        let abs = repo.path().join(rel);
        std::fs::set_permissions(&abs, std::fs::Permissions::from_mode(0o644)).unwrap();

        assert!(reseal(store.path(), &root, rel));
        assert_eq!(mode_of(&abs), SEALED_MODE);
        let row = read_manifest(&manifest_in(store.path())).files.remove(0);
        assert!(row.rearmed_at.is_some() && row.ctime_ns.is_some());
        assert_eq!(row.mode, "644", "the original mode must survive a reseal");
    }

    /// The new bytes become the baseline, so one violation is reported once
    /// rather than on every command that follows it.
    #[test]
    fn reseal_rebaselines_so_the_same_change_is_not_reported_twice() {
        let (repo, store, root, rel) = stamped_fixture();
        let abs = repo.path().join(rel);
        std::fs::set_permissions(&abs, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::write(&abs, b"tampered").unwrap();
        std::fs::set_permissions(&abs, std::fs::Permissions::from_mode(SEALED_MODE)).unwrap();

        assert_eq!(scan(store.path(), &root).len(), 1);
        assert!(reseal(store.path(), &root, rel));
        assert!(scan(store.path(), &root).is_empty());
    }

    // ── rearm_all ───────────────────────────────────────────────────────

    #[test]
    fn rearm_seals_a_file_a_receipt_had_lifted() {
        let (repo, store, rel) = seal_fixture(0o644);
        let abs = repo.path().join(rel);
        assert_eq!(rearm_all(store.path()).len(), 1);
        assert_eq!(mode_of(&abs), SEALED_MODE);
    }

    #[test]
    fn rearm_is_idempotent_on_a_file_that_never_lifted() {
        let (repo, store, rel) = seal_fixture(SEALED_MODE);
        rearm_all(store.path());
        rearm_all(store.path());
        assert_eq!(mode_of(&repo.path().join(rel)), SEALED_MODE);
    }

    /// Re-arm never writes the manifest, so it cannot damage the artifact rung
    /// 2 of the restore ladder reads.
    #[test]
    fn rearm_leaves_the_manifest_untouched() {
        let (_repo, store, _) = seal_fixture(0o644);
        let before = read_manifest(&manifest_in(store.path())).files;
        rearm_all(store.path());
        assert_eq!(read_manifest(&manifest_in(store.path())).files, before);
    }

    #[test]
    fn rearm_skips_a_row_whose_file_is_gone() {
        let (repo, store, rel) = seal_fixture(0o644);
        std::fs::remove_file(repo.path().join(rel)).unwrap();
        assert!(rearm_all(store.path()).is_empty());
        assert_eq!(read_manifest(&manifest_in(store.path())).files.len(), 1);
    }

    /// `mati seal clear` empties the manifest and cannot drop the
    /// `consult-to-read` tag, so a re-arm that read the tag would undo rung 1.
    #[test]
    fn rearm_after_a_clear_seals_nothing() {
        let (repo, store, rel) = seal_fixture(0o644);
        write_manifest(&manifest_in(store.path()), &Manifest::default()).unwrap();
        assert!(rearm_all(store.path()).is_empty());
        assert_eq!(mode_of(&repo.path().join(rel)), 0o644);
    }

    /// The daemon resolves a repo-relative record key against its own repo
    /// root; a lift keyed on another repo's root must not reach across.
    #[test]
    fn a_receipt_resolved_against_another_repo_root_lifts_nothing() {
        let (repo, store, rel) = seal_fixture(SEALED_MODE);
        let other = tempfile::tempdir().unwrap();
        assert_eq!(lift_on_receipt(other.path(), store.path(), rel), None);
        assert_eq!(mode_of(&repo.path().join(rel)), SEALED_MODE);
    }

    #[test]
    fn inventory_counts_a_row_still_at_the_floor() {
        let (_repo, store, _rel) = seal_fixture(SEALED_MODE);
        let inv = inventory(&manifest_in(store.path()));
        assert_eq!(
            inv,
            Inventory {
                at_floor: 1,
                lifted: 0,
                missing: 0
            }
        );
        assert_eq!(inv.total(), 1);
    }

    #[test]
    fn inventory_counts_a_lifted_row_separately() {
        let (_repo, store, _rel) = seal_fixture(0o644);
        assert_eq!(
            inventory(&manifest_in(store.path())),
            Inventory {
                at_floor: 0,
                lifted: 1,
                missing: 0
            }
        );
    }

    #[test]
    fn inventory_counts_a_row_whose_file_is_gone() {
        let (repo, store, rel) = seal_fixture(SEALED_MODE);
        std::fs::remove_file(repo.path().join(rel)).unwrap();
        assert_eq!(
            inventory(&manifest_in(store.path())),
            Inventory {
                at_floor: 0,
                lifted: 0,
                missing: 1
            }
        );
    }

    #[test]
    fn inventory_of_a_missing_manifest_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(inventory(&manifest_in(dir.path())), Inventory::default());
    }

    /// The reporting surface must not become a lever: a sealed row is still at
    /// mode `000` after an inventory, whatever the stamp says about its bytes.
    #[test]
    fn inventory_never_lifts_the_mode() {
        let (repo, store, rel) = seal_fixture(SEALED_MODE);
        inventory(&manifest_in(store.path()));
        assert_eq!(mode_of(&repo.path().join(rel)), SEALED_MODE);
    }
}
