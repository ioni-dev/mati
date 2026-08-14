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
/// `src/payments/**`, a deleted path, an unreadable one. Every caller treats
/// that as "unknown", never as drift.
pub fn disk_content_hash(repo_root: &Path, path: &str) -> Option<String> {
    let bytes = std::fs::read(repo_root.join(path)).ok()?;
    Some(format!("{:x}", Sha256::digest(&bytes)))
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
