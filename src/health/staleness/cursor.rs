use super::*;

// ── Resume cursor ───────────────────────────────────────────────────────────
//
// Every cursor operation is best-effort. Staleness runs on the SessionEnd hook
// path, so a store fault here must cost a fair sweep and nothing more: a lost
// cursor restarts at `file:`, exactly the behaviour that existed before it.

/// Payload field holding the resume position.
///
/// The position lives in `payload`, not `value`: `Store::put` indexes `value`
/// into tantivy, and the position is a record key — a `mem_query` for a path
/// would match the cursor as if it were knowledge about that path.
pub(crate) const CURSOR_FIELD: &str = "after";

/// The key the last truncated scan stopped on, or `None` to start at the top.
pub(crate) async fn read_cursor(store: &Store) -> Option<String> {
    let record = match store.get(STALENESS_CURSOR_KEY).await {
        Ok(record) => record?,
        Err(e) => {
            tracing::warn!("staleness cursor read failed: {e}");
            return None;
        }
    };
    record
        .payload
        .as_ref()
        .and_then(|p| p.get(CURSOR_FIELD))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

pub(crate) async fn clear_cursor(store: &Store) {
    if let Err(e) = store.delete(STALENESS_CURSOR_KEY).await {
        tracing::warn!("staleness cursor clear failed: {e}");
    }
}
