//! Staged file-link computation shared by the gotcha write handlers.

use super::*;

// ── File-link staged computation ────────────────────────────────────────────
//
// These helpers read file records, compute the gotcha_keys diff, and return
// updated Records WITHOUT persisting them. The caller stages them into the
// same transact_knowledge call as the gotcha mutation + audit.

use std::collections::HashSet;

/// Compute file-record updates for gotcha_keys link sync.
///
/// Returns a vec of `(file_key, updated_record)` for files that need their
/// `gotcha_keys` array modified. Records that don't exist or don't need
/// changes are excluded. The per-file mutation (including the create-on-write
/// Layer 0 stub) is shared with the direct-store path via
/// `gotcha_ops::stage_file_link_update`; this loop only decides which files
/// changed and reads their current record.
pub(super) async fn compute_file_link_updates(
    store: &Store,
    gotcha_key: &str,
    old_files: &[String],
    new_files: &[String],
) -> Vec<(String, Record)> {
    let old_set: HashSet<&str> = old_files.iter().map(String::as_str).collect();
    let new_set: HashSet<&str> = new_files.iter().map(String::as_str).collect();
    let mut updates = Vec::new();

    // A `store.get` error is treated as "leave this file alone", not as
    // "unindexed" — only `Ok(None)` earns a create-on-write stub. Matches
    // `Ok(existing)`/`Ok(Some(existing))` below, not `.ok().flatten()`, which
    // would conflate the two.
    for file_path in new_set.difference(&old_set) {
        let file_key = format!("file:{file_path}");
        if let Ok(existing) = store.get(&file_key).await {
            if let Some(record) = crate::store::gotcha_ops::stage_file_link_update(
                existing, file_path, gotcha_key, true,
            ) {
                updates.push((file_key, record));
            }
        }
    }

    for file_path in old_set.difference(&new_set) {
        let file_key = format!("file:{file_path}");
        if let Ok(Some(existing)) = store.get(&file_key).await {
            if let Some(record) = crate::store::gotcha_ops::stage_file_link_update(
                Some(existing),
                file_path,
                gotcha_key,
                false,
            ) {
                updates.push((file_key, record));
            }
        }
    }

    updates
}

/// Bump `confirmation_count` on each affected file record, **in place** on any
/// entry `updates` already stages.
///
/// Staging a second copy read straight from the store would clobber the
/// gotcha-key link `compute_file_link_updates` just added: both name the same
/// `file:*` key and the last op in `transact_knowledge` wins.
pub(super) async fn apply_confirmation_propagation(
    store: &Store,
    affected_files: &[String],
    updates: &mut Vec<(String, Record)>,
) {
    let now = now_secs();
    for file_path in affected_files {
        let file_key = format!("file:{file_path}");
        let staged = match updates.iter_mut().find(|(key, _)| key == &file_key) {
            Some((_, record)) => record,
            None => match store.get(&file_key).await {
                Ok(Some(record)) => {
                    updates.push((file_key, record));
                    &mut updates.last_mut().expect("just pushed").1
                }
                _ => continue,
            },
        };
        staged.confidence.confirmation_count += 1;
        staged.updated_at = now;
        staged.version.logical_clock += 1;
        staged.version.wall_clock = now;
    }
}
