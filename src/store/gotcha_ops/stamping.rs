use sha2::{Digest, Sha256};

use super::*;

// ── Confirm-time content stamp ───────────────────────────────────────────────

/// The SHA-256 digest of the file at `repo_root/path`, as it stands on disk.
///
/// Lowercase hex over the raw bytes — byte-for-byte the form
/// `analysis::parser::analyze_file_bytes` writes into a `file:*` record's
/// `content_hash`, so a stamp taken here and a digest taken there are
/// comparable.
///
/// `repo_root` must be the root the store's slug was keyed on
/// ([`crate::store::slug_root`]), never `Store::root` (which is
/// `~/.mati/<slug>`) and never the process cwd.
///
/// `None` for anything that is not a readable file: a glob entry such as
/// `src/payments/**`, a deleted path. Every caller treats that as "unknown",
/// never as drift.
///
/// The one exception is a Tier 2 file, which is unreadable *by design* and is
/// by construction the file whose rule matters most — reporting it as unknown
/// is exactly the silence `mati seal` must not buy. Its digest was taken at
/// lock time and the post-Bash sweep re-baselines it on any change, so the
/// stamp is the answer and no privileged read is needed here.
pub fn disk_content_hash(repo_root: &Path, path: &str) -> Option<String> {
    match std::fs::read(repo_root.join(path)) {
        Ok(bytes) => Some(format!("{:x}", Sha256::digest(&bytes))),
        // Keyed on the error kind, not on a manifest lookup: a glob entry and
        // a deleted path are `NotFound` and must not pay for a manifest read.
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            sealed_digest(repo_root, path)
        }
        Err(_) => None,
    }
}

/// The lock-time digest `mati seal` recorded for `path`, if it is sealed.
fn sealed_digest(repo_root: &Path, path: &str) -> Option<String> {
    let abs = std::fs::canonicalize(repo_root.join(path)).ok()?;
    let manifest = crate::seal::read_manifest(&crate::seal::manifest_path(repo_root).ok()?);
    manifest.find(&abs.to_string_lossy())?.sha256.clone()
}

/// Collect the confirm-time content stamp for `affected_files`.
///
/// Confirmation is the moment a human vouched for a rule against *specific*
/// code, so that is the moment worth stamping: a later mismatch means the
/// code moved out from under a rule someone signed off on, which is a
/// stronger claim than "this record is old". See
/// [`crate::store::GotchaRecord::confirmed_content`].
///
/// Hashes the working tree, not the `file:*` index. The index only refreshes
/// on a rescan, so stamping from it baselines a developer who edits a file and
/// then confirms against the *pre-edit* code: the record reads clean until the
/// next `mati init` refreshes that file record, then reports drift the human
/// already resolved. Reading disk on both sides makes drift mean "the code
/// changed since a human confirmed the rule", independent of index freshness.
///
/// Unreadable paths are omitted, and read failures are swallowed: an unstamped
/// entry under-reports drift, which is the safe direction. Confirmation must
/// not fail because a file could not be read.
pub fn confirm_content_stamp(
    repo_root: &Path,
    affected_files: &[String],
) -> BTreeMap<String, String> {
    affected_files
        .iter()
        .filter_map(|path| disk_content_hash(repo_root, path).map(|hash| (path.clone(), hash)))
        .collect()
}

/// Whether a gotcha record's payload says the rule is developer-confirmed.
///
/// Reads the raw JSON rather than deserializing a
/// [`crate::store::GotchaRecord`]: the caller may hold a payload merged by
/// `mem_set` that does not round-trip through the struct.
pub(super) fn payload_is_confirmed(record: &Record) -> bool {
    record
        .payload
        .as_ref()
        .and_then(|p| p.get("confirmed"))
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
}

/// Replace the `confirmed_content` field of a gotcha payload with `stamp`.
///
/// Patches the JSON object in place for the same reason
/// `with_normalized_affected_files` does: `mem_set` merges caller-supplied
/// payloads, so re-serializing a [`crate::store::GotchaRecord`] would drop any
/// field the struct does not know about.
///
/// Replaces rather than merges. A confirmation asserts the rule is right
/// against the files it names *now*, so any earlier baseline — including one
/// for a path the gotcha no longer covers — is spent. Merging would let a
/// stale entry keep reporting drift after a human explicitly re-confirmed,
/// which would break the curation loop; dropping an entry we could not read
/// only under-reports, which is the safe direction.
pub fn set_confirm_stamp(record: &mut Record, stamp: &BTreeMap<String, String>) {
    let Some(obj) = record.payload.as_mut().and_then(|p| p.as_object_mut()) else {
        return;
    };
    let stamped: serde_json::Map<String, serde_json::Value> = stamp
        .iter()
        .map(|(path, hash)| (path.clone(), serde_json::Value::String(hash.clone())))
        .collect();
    obj.insert(
        "confirmed_content".into(),
        serde_json::Value::Object(stamped),
    );
}

// ── Tier 2 fallback ─────────────────────────────────────────────────────────

#[cfg(test)]
mod sealed_digest_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// A repo whose sealed file's digest lives in a manifest under the
    /// per-process test home. Returns the repo dir, kept alive by the caller.
    ///
    /// Deliberately does not set `MATI_HOME`: `mati_home_opt` drops an
    /// inherited value at its first resolution, which would land after a
    /// `set_var` here and wipe it. The manifest is written and read through the
    /// same `manifest_path`, and the slug comes from this tempdir repo, so the
    /// per-process home isolates it just as well.
    fn sealed_repo(with_digest: bool) -> (tempfile::TempDir, String) {
        let repo = tempfile::tempdir().unwrap();
        let rel = "src/gated.rs";
        let abs = repo.path().join(rel);
        std::fs::create_dir_all(abs.parent().unwrap()).unwrap();
        std::fs::write(&abs, b"secret").unwrap();

        let root = std::fs::canonicalize(repo.path()).unwrap();
        let digest = disk_content_hash(&root, rel).unwrap();
        let mpath = crate::seal::manifest_path(&root).unwrap();
        let mut manifest = crate::seal::Manifest::default();
        manifest.files.push(crate::seal::SealedFile {
            path: std::fs::canonicalize(&abs)
                .unwrap()
                .to_string_lossy()
                .into(),
            mode: "644".to_string(),
            sha256: with_digest.then(|| digest.clone()),
            ..Default::default()
        });
        crate::seal::write_manifest(&mpath, &manifest).unwrap();
        std::fs::set_permissions(&abs, std::fs::Permissions::from_mode(0o000)).unwrap();
        (repo, digest)
    }

    /// Without the fallback a sealed file reads as "unknown", which is silence
    /// on exactly the file whose rule matters most.
    #[test]
    fn a_sealed_file_hashes_to_its_lock_time_digest() {
        let (repo, digest) = sealed_repo(true);
        let root = std::fs::canonicalize(repo.path()).unwrap();
        assert!(std::fs::read(root.join("src/gated.rs")).is_err(), "sealed");
        assert_eq!(disk_content_hash(&root, "src/gated.rs"), Some(digest));
    }

    /// A row written before the stamp existed has no digest. Unknown is the
    /// right answer there — inventing one would report false drift.
    #[test]
    fn a_sealed_file_with_no_recorded_digest_stays_unknown() {
        let (repo, _) = sealed_repo(false);
        let root = std::fs::canonicalize(repo.path()).unwrap();
        assert_eq!(disk_content_hash(&root, "src/gated.rs"), None);
    }

    /// A glob entry and a deleted path are `NotFound`, so they must never
    /// reach the manifest read.
    #[test]
    fn a_missing_path_stays_unknown_and_never_consults_the_manifest() {
        let (repo, _) = sealed_repo(true);
        let root = std::fs::canonicalize(repo.path()).unwrap();
        assert_eq!(disk_content_hash(&root, "src/payments/**"), None);
        assert_eq!(disk_content_hash(&root, "src/gone.rs"), None);
    }
}
