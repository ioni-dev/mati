//! Version history queries (M-14).

use super::*;

/// A single versioned entry from the SurrealKV history iterator.
///
/// Timestamps come from SurrealKV's internal clock (nanoseconds since epoch).
/// Both seconds and nanoseconds are exposed for callers that need either
/// precision level.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryEntry {
    /// Timestamp in whole seconds (nanosecond timestamp / 1_000_000_000).
    pub timestamp_secs: u64,
    /// Raw nanosecond timestamp from SurrealKV.
    pub timestamp_ns: u64,
    /// Deserialized record, `None` for tombstones or corrupt values.
    pub record: Option<Record>,
    /// `true` when this version represents a deletion.
    pub is_tombstone: bool,
}

/// Shared synchronous implementation for key history queries.
///
/// Iterates all versions of `key` using `history_with_options` with the tight
/// upper bound `key + \0` (not `prefix_end`) to guarantee no adjacent key
/// spills. Returns entries sorted newest first.
fn history_impl(txn: &Transaction, key: &str, opts: &HistoryOptions) -> Result<Vec<HistoryEntry>> {
    // Upper bound: key + NUL byte — tighter than prefix_end which increments
    // the last byte. This ensures only exact-key versions are returned.
    let mut upper = key.as_bytes().to_vec();
    upper.push(0x00);

    let mut cursor = txn.history_with_options(key.as_bytes(), upper.as_slice(), opts)?;

    let mut entries = Vec::new();
    while cursor.next()? {
        let key_ref = cursor.key();

        // Guard: only process entries whose user_key matches exactly
        if key_ref.user_key() != key.as_bytes() {
            continue;
        }

        let is_tombstone = key_ref.is_tombstone();
        let ts_ns = key_ref.timestamp();
        let ts_secs = ts_ns / 1_000_000_000;

        let record = if is_tombstone {
            None
        } else {
            match cursor.value() {
                Ok(bytes) => rmps::from_slice::<Record>(&bytes).ok(),
                Err(_) => None,
            }
        };

        entries.push(HistoryEntry {
            timestamp_secs: ts_secs,
            timestamp_ns: ts_ns,
            record,
            is_tombstone,
        });
    }

    // Newest first — SurrealKV history iterator order is not guaranteed to be
    // reverse-chronological, so sort explicitly.
    entries.sort_by_key(|e| std::cmp::Reverse(e.timestamp_ns));
    Ok(entries)
}

impl Store {
    /// Return version history for a single key, newest first.
    ///
    /// Includes tombstones (deletions). Uses the tight upper bound `key + \0`
    /// so adjacent keys never spill into the result set.
    ///
    /// `limit` caps the number of entries returned; `0` means unlimited.
    pub fn history(&self, key: &str, limit: usize) -> Result<Vec<HistoryEntry>> {
        anyhow::ensure!(!key.is_empty(), "history key must not be empty");
        let tree = self.tree_for(key);
        let txn = tree.begin_with_mode(Mode::ReadOnly)?;

        let mut opts = HistoryOptions::new().with_tombstones(true);
        if limit > 0 {
            opts = opts.with_limit(limit);
        }

        history_impl(&txn, key, &opts)
    }

    /// Return version history for a single key since `since_ts` (seconds),
    /// newest first.
    ///
    /// Timestamps are converted to nanoseconds for the SurrealKV range filter.
    pub fn history_since(
        &self,
        key: &str,
        since_ts: u64,
        limit: usize,
    ) -> Result<Vec<HistoryEntry>> {
        anyhow::ensure!(!key.is_empty(), "history key must not be empty");
        let tree = self.tree_for(key);
        let txn = tree.begin_with_mode(Mode::ReadOnly)?;

        let since_ns = since_ts.saturating_mul(1_000_000_000);
        let mut opts = HistoryOptions::new()
            .with_tombstones(true)
            .with_ts_range(since_ns, u64::MAX);
        if limit > 0 {
            opts = opts.with_limit(limit);
        }

        history_impl(&txn, key, &opts)
    }

    /// Return all records updated since `since_ts` (seconds), newest first.
    ///
    /// Scans every knowledge namespace (including `dep:`) and returns records
    /// whose `updated_at >= since_ts`. Results are sorted by `updated_at`
    /// descending with secondary sort by key for deterministic ordering.
    pub async fn records_since(&self, since_ts: u64, limit: usize) -> Result<Vec<Record>> {
        let mut results = Vec::new();
        for ns in KNOWLEDGE_NAMESPACES {
            let records = self.scan_prefix(ns).await?;
            for r in records {
                if r.updated_at >= since_ts {
                    results.push(r);
                }
            }
        }
        // Newest first, secondary sort by key for determinism
        results.sort_by(|a, b| {
            b.updated_at
                .cmp(&a.updated_at)
                .then_with(|| a.key.cmp(&b.key))
        });
        if limit > 0 && results.len() > limit {
            results.truncate(limit);
        }
        Ok(results)
    }
}
