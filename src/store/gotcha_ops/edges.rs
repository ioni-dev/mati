use super::*;

// ── Graph edges ───────────────────────────────────────────────────────────────

/// Best-effort `HasGotcha` edge sync (cross-tree, so it can never share a
/// transaction with the knowledge-tree record — see the module-level doc).
///
/// Adds edges for files in `new_files` not in `old_files`, removes edges for
/// files in `old_files` not in `new_files`. Returns `true` if every write
/// succeeded. Does **not** own the dirty-marker guard — the caller's guard
/// must already be armed before this runs and stay armed until it returns,
/// so cancellation mid-loop is covered too; see the module doc's
/// "Cancellation safety" section. On a write failure this still calls
/// `mark_dirty` itself, since that failure is the explicit branch the guard
/// is a backstop for, not a substitute for it.
pub async fn sync_has_gotcha_edges(
    store: &Store,
    gotcha_key: &str,
    old_files: &[String],
    new_files: &[String],
) -> bool {
    let old_set: HashSet<&str> = old_files.iter().map(String::as_str).collect();
    let new_set: HashSet<&str> = new_files.iter().map(String::as_str).collect();

    let mut failed = false;
    let ts = now_secs().to_le_bytes();

    for file_path in new_set.difference(&old_set) {
        let file_key = format!("file:{file_path}");
        let edge_key = Edge::new(&file_key, EdgeKind::HasGotcha, gotcha_key).to_key();
        if let Err(e) = store.put_raw(&edge_key, &ts).await {
            tracing::warn!("gotcha_edges: add failed for {file_key} → {gotcha_key}: {e}");
            failed = true;
            crate::store::repair::mark_dirty(store, gotcha_key, &format!("edge add failed: {e}"))
                .await;
        }
    }
    for file_path in old_set.difference(&new_set) {
        let file_key = format!("file:{file_path}");
        let edge_key = Edge::new(&file_key, EdgeKind::HasGotcha, gotcha_key).to_key();
        if let Err(e) = store.delete(&edge_key).await {
            tracing::warn!("gotcha_edges: remove failed for {file_key} → {gotcha_key}: {e}");
            failed = true;
            crate::store::repair::mark_dirty(
                store,
                gotcha_key,
                &format!("edge remove failed: {e}"),
            )
            .await;
        }
    }

    !failed
}

// ── Confirmation propagation ─────────────────────────────────────────────────

/// Drop stale `session:consulted:file:<path>` receipts for a newly-confirmed
/// gotcha. A receipt minted before confirmation predates the rule; leaving it
/// in place would let an agent bypass the pre-read/pre-bash hook and act on
/// the file without ever seeing the rule it just gained.
pub async fn invalidate_consultation_receipts(store: &Store, affected_files: &[String]) {
    for file_path in affected_files {
        let consulted_key = format!("session:consulted:file:{file_path}");
        let _ = store.delete(&consulted_key).await;
    }
}

/// Increment `confirmation_count` on all file records linked to a confirmed gotcha.
///
/// Best-effort: failures are logged but do not fail the confirmation.
/// This propagates the signal that a human verified knowledge about this file,
/// which feeds into the confidence formula via `log2(confirmation_count + 2)`.
pub async fn propagate_confirmation_to_files(store: &Store, affected_files: &[String]) {
    for file_path in affected_files {
        let file_key = format!("file:{file_path}");
        if let Ok(Some(mut file_record)) = store.get(&file_key).await {
            file_record.confidence.confirmation_count += 1;
            let now = now_secs();
            file_record.updated_at = now;
            file_record.version.logical_clock += 1;
            file_record.version.wall_clock = now;
            if let Err(e) = store.put(&file_key, &file_record).await {
                tracing::warn!("propagate_confirmation: failed to update {file_key}: {e}");
            }
        }
    }
}
