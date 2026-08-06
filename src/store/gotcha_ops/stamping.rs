use super::*;

// ── Confirm-time content stamp ───────────────────────────────────────────────

/// Read the SHA-256 content digest a `file:*` record already carries.
///
/// Returns `None` for a record with no payload, no `content_hash` (a file
/// indexed before content hashing existed, or a language Layer 0 does not
/// parse), or a hash stored as something other than a string. Reads the JSON
/// key directly rather than deserializing a whole
/// [`crate::store::FileRecord`] — one field is wanted and the rest of that
/// struct is comparatively expensive to build.
pub fn content_hash_of(file_record: &Record) -> Option<String> {
    file_record
        .payload
        .as_ref()?
        .get("content_hash")?
        .as_str()
        .map(str::to_string)
}

/// Collect the confirm-time content stamp for `affected_files`.
///
/// Confirmation is the moment a human vouched for a rule against *specific*
/// code, so that is the moment worth stamping: a later mismatch means the
/// code moved out from under a rule someone signed off on, which is a
/// stronger claim than "this record is old". See
/// [`crate::store::GotchaRecord::confirmed_content`].
///
/// Reuses the digest `mati init` already computed and stored on the file
/// record — no file is opened and nothing is hashed a second time. Paths with
/// no file record or no stored digest (globs, unparsed files, a path added
/// before the next init) are simply omitted; the reader treats a missing
/// entry as "unknown", never as drift.
///
/// Store-read failures are swallowed for the same reason: an unstamped entry
/// under-reports drift, which is the safe direction. Confirmation must not
/// fail because a file record could not be read.
pub async fn confirm_content_stamp(
    store: &Store,
    affected_files: &[String],
) -> BTreeMap<String, String> {
    let mut stamp = BTreeMap::new();
    for path in affected_files {
        let file_key = format!("file:{path}");
        if let Ok(Some(file_record)) = store.get(&file_key).await {
            if let Some(hash) = content_hash_of(&file_record) {
                stamp.insert(path.clone(), hash);
            }
        }
    }
    stamp
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
