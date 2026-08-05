//! Core CRUD and transactional batch writes.

use super::*;

/// Returns `true` for keys whose writes should invalidate cached stats snapshots.
///
/// These are the namespaces that affect the knowledge coverage aggregates
/// displayed by `mati stats` and `mati gaps`. Must stay in sync with
/// [`KNOWLEDGE_NAMESPACES`].
fn is_knowledge_key(key: &str) -> bool {
    key.starts_with("file:")
        || key.starts_with("gotcha:")
        || key.starts_with("decision:")
        || key.starts_with("dep:")
        || key.starts_with("dev_note:")
        || key.starts_with("stage:")
}

/// Read and deserialize a record from an active transaction.
fn read_record(txn: &Transaction, key: &str) -> Result<Option<Record>> {
    match txn.get(key.as_bytes())? {
        None => Ok(None),
        Some(bytes) => {
            let record = rmps::from_slice::<Record>(&bytes)
                .with_context(|| format!("corrupt record at key '{key}'"))?;
            Ok(Some(record))
        }
    }
}

/// Map mati's `Durability` enum to SurrealKV's `Durability`.
fn skv_durability(d: Durability) -> SkvDurability {
    match d {
        Durability::Immediate => SkvDurability::Immediate,
        Durability::Eventual => SkvDurability::Eventual,
    }
}

/// Return the smallest string that is lexicographically greater than all keys
/// starting with `prefix`. Used to form the exclusive upper bound for range
/// scans.
pub(super) fn prefix_end(prefix: &str) -> String {
    let mut bytes = prefix.as_bytes().to_vec();
    // Increment the last byte; if it wraps (0xff → 0x00) keep carrying.
    for b in bytes.iter_mut().rev() {
        if *b < 0xff {
            *b += 1;
            return String::from_utf8(bytes).unwrap_or_else(|_| "\u{ffff}".to_owned());
        }
        *b = 0x00;
    }
    // All bytes were 0xff — no upper bound needed; use a sentinel
    "\u{ffff}".to_owned()
}

impl Store {
    // -------------------------------------------------------------------------
    // Core CRUD
    // -------------------------------------------------------------------------

    /// Read a record by key. Returns `None` if not found.
    pub async fn get(&self, key: &str) -> Result<Option<Record>> {
        let txn = self.tree_for(key).begin_with_mode(Mode::ReadOnly)?;
        read_record(&txn, key)
    }

    /// Write a record with the appropriate durability level.
    ///
    /// Durability is derived from the key prefix via [`Durability::for_key`].
    pub async fn put(&self, key: &str, record: &Record) -> Result<()> {
        debug_assert_eq!(
            Encoding::for_key(key),
            Encoding::Record,
            "put() writes a Record into {key}, which is a Raw namespace; see store::durability::Encoding"
        );
        let durability = Durability::for_key(key);
        let tree = self.tree_for(key);
        let mut txn = tree.begin_with_mode(Mode::WriteOnly)?;
        txn.set_durability(skv_durability(durability));

        let bytes = rmps::to_vec_named(record)
            .with_context(|| format!("failed to serialize record for key '{key}'"))?;
        txn.set(key.as_bytes(), bytes)?;
        txn.commit().await?;

        // Crash-fence: written after KV commit, removed after tantivy commit.
        // If the process dies between these two points, open_and_rebuild sees
        // the marker on the next start and triggers a full index rebuild.
        if is_knowledge_key(key) {
            let _ = std::fs::write(self.root.join(SEARCH_SYNC_PENDING), b"");
        }

        // Update search index — KV write is primary, search is secondary.
        // We replace by key rather than append, so tantivy stays aligned with
        // the latest KV state without waiting for a full rebuild.
        //
        // Wrapped in catch_unwind: a tantivy panic (e.g., corrupted segment)
        // must never crash the server. The KV write already committed above —
        // the search index will be rebuilt on next startup via the
        // SEARCH_SYNC_PENDING crash-fence marker.
        let mut search_synced = false;
        match self.ensure_search() {
            Ok(search) => {
                match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    search.add_record(record)
                })) {
                    Ok(Ok(())) => {
                        search_synced = true;
                    }
                    Ok(Err(e)) => {
                        tracing::warn!("search index update failed for '{key}': {e}");
                    }
                    Err(_panic) => {
                        tracing::error!(
                            "search index panicked during put for '{key}' — \
                             index will be rebuilt on next startup"
                        );
                    }
                }
            }
            Err(e) => {
                tracing::warn!("search index unavailable during put: {e}");
            }
        }
        if is_knowledge_key(key) {
            self.bump_write_seq();
            if search_synced {
                let _ = std::fs::remove_file(self.root.join(SEARCH_SYNC_PENDING));
            }
        }
        Ok(())
    }

    /// Write multiple records to KV only, skipping the tantivy search index.
    ///
    /// Use this during bulk init passes where search indexing would block the
    /// critical path. Follow with [`Self::rebuild_search_index`] to update tantivy
    /// from the same in-memory records without a KV round-trip.
    ///
    /// Same durability semantics as [`Self::put_batch`]: at most 2 fsyncs.
    pub async fn put_batch_kv_only(&self, records: &[(&str, &Record)]) -> Result<()> {
        if records.is_empty() {
            return Ok(());
        }
        let mut immediate: Vec<(&str, &Record)> = Vec::new();
        let mut eventual: Vec<(&str, &Record)> = Vec::new();
        for &(key, record) in records {
            match Durability::for_key(key) {
                Durability::Immediate => immediate.push((key, record)),
                Durability::Eventual => eventual.push((key, record)),
            }
        }
        if !immediate.is_empty() {
            let mut txn = self.knowledge.begin_with_mode(Mode::WriteOnly)?;
            txn.set_durability(SkvDurability::Immediate);
            for (key, record) in &immediate {
                let bytes = rmps::to_vec_named(record)
                    .with_context(|| format!("failed to serialize record for key '{key}'"))?;
                txn.set(key.as_bytes(), bytes)?;
            }
            txn.commit().await?;
        }
        if !eventual.is_empty() {
            let mut txn = self.sessions.begin_with_mode(Mode::WriteOnly)?;
            txn.set_durability(SkvDurability::Eventual);
            for (key, record) in &eventual {
                let bytes = rmps::to_vec_named(record)
                    .with_context(|| format!("failed to serialize record for key '{key}'"))?;
                txn.set(key.as_bytes(), bytes)?;
            }
            txn.commit().await?;
        }
        if records.iter().any(|(k, _)| is_knowledge_key(k)) {
            self.bump_write_seq();
        }
        Ok(())
    }

    /// Mark the search index as stale so the next [`Self::open_and_rebuild`]
    /// call wipes and rebuilds it from KV.
    ///
    /// Written by `mati init` after a cold init pass to defer the tantivy
    /// indexing cost (~400ms on 27k records) to the first MCP server startup.
    /// Best-effort: a write failure is silently discarded — the worst outcome
    /// is that the search index contains stale data until the next full rebuild.
    pub fn mark_search_stale(&self) {
        let _ = std::fs::write(self.root.join(SEARCH_STALE_MARKER), b"");
    }

    /// Write multiple records in a single transaction per durability class.
    ///
    /// Records are grouped by their key prefix: all `Immediate` keys share one
    /// transaction on `knowledge` (1 fsync), all `Eventual` keys share one on
    /// `sessions` (1 fsync). The whole batch costs at most 2 fsyncs regardless
    /// of how many records it contains — critical for Layer 0 bulk inserts.
    ///
    /// Empty slice is a no-op. Mixed-durability batches are handled correctly.
    pub async fn put_batch(&self, records: &[(&str, &Record)]) -> Result<()> {
        if records.is_empty() {
            return Ok(());
        }

        // Partition by durability class so each tree gets exactly one commit.
        let mut immediate: Vec<(&str, &Record)> = Vec::new();
        let mut eventual: Vec<(&str, &Record)> = Vec::new();
        for &(key, record) in records {
            match Durability::for_key(key) {
                Durability::Immediate => immediate.push((key, record)),
                Durability::Eventual => eventual.push((key, record)),
            }
        }

        if !immediate.is_empty() {
            let mut txn = self.knowledge.begin_with_mode(Mode::WriteOnly)?;
            txn.set_durability(SkvDurability::Immediate);
            for (key, record) in &immediate {
                let bytes = rmps::to_vec_named(record)
                    .with_context(|| format!("failed to serialize record for key '{key}'"))?;
                txn.set(key.as_bytes(), bytes)?;
            }
            txn.commit().await?;
        }

        if !eventual.is_empty() {
            let mut txn = self.sessions.begin_with_mode(Mode::WriteOnly)?;
            txn.set_durability(SkvDurability::Eventual);
            for (key, record) in &eventual {
                let bytes = rmps::to_vec_named(record)
                    .with_context(|| format!("failed to serialize record for key '{key}'"))?;
                txn.set(key.as_bytes(), bytes)?;
            }
            txn.commit().await?;
        }

        let has_knowledge = records.iter().any(|(k, _)| is_knowledge_key(k));

        // Crash-fence — same pattern as put().
        if has_knowledge {
            let _ = std::fs::write(self.root.join(SEARCH_SYNC_PENDING), b"");
        }

        // Update search index — KV write is primary, search is secondary.
        // If tantivy fails to initialize, the KV writes still succeeded.
        // Wrapped in catch_unwind for the same reason as put().
        let mut search_synced = false;
        match self.ensure_search() {
            Ok(search) => {
                let search_records: Vec<&Record> = records.iter().map(|(_, r)| *r).collect();
                match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    search.add_records(&search_records)
                })) {
                    Ok(Ok(_)) => {
                        search_synced = true;
                    }
                    Ok(Err(e)) => {
                        tracing::warn!("search index update failed in put_batch: {e}");
                    }
                    Err(_panic) => {
                        tracing::error!(
                            "search index panicked during put_batch — \
                             index will be rebuilt on next startup"
                        );
                    }
                }
            }
            Err(e) => {
                tracing::warn!("search index unavailable during put_batch: {e}");
            }
        }
        if has_knowledge {
            self.bump_write_seq();
            if search_synced {
                let _ = std::fs::remove_file(self.root.join(SEARCH_SYNC_PENDING));
            }
        }
        Ok(())
    }

    /// Delete a record by key. No-op if the key does not exist.
    pub async fn delete(&self, key: &str) -> Result<()> {
        let tree = self.tree_for(key);
        let mut txn = tree.begin_with_mode(Mode::WriteOnly)?;
        txn.set_durability(skv_durability(Durability::for_key(key)));
        txn.delete(key.as_bytes())?;
        txn.commit().await?;

        if is_knowledge_key(key) {
            let _ = std::fs::write(self.root.join(SEARCH_SYNC_PENDING), b"");
        }

        let mut search_synced = false;
        match self.ensure_search() {
            Ok(search) => {
                search.delete_key(key)?;
                search_synced = true;
            }
            Err(e) => {
                tracing::warn!("search index unavailable during delete: {e}");
            }
        }

        if is_knowledge_key(key) {
            self.bump_write_seq();
            if search_synced {
                let _ = std::fs::remove_file(self.root.join(SEARCH_SYNC_PENDING));
            }
        }
        Ok(())
    }

    /// Return all records whose key starts with `prefix`.
    ///
    /// Prefix must use one of the known key namespaces so the correct tree is
    /// selected. Unknown prefixes are scanned from `knowledge`.
    ///
    /// Return order is not guaranteed. Callers that need a stable order must sort.
    pub async fn scan_prefix(&self, prefix: &str) -> Result<Vec<Record>> {
        debug_assert_eq!(
            Encoding::for_key(prefix),
            Encoding::Record,
            "scan_prefix() deserializes Records from {prefix}, which is a Raw namespace; use scan_keys instead"
        );
        let tree = self.tree_for(prefix);
        let txn = tree.begin_with_mode(Mode::ReadOnly)?;

        // Range: [prefix, prefix\xff) covers all keys with this prefix
        let end = prefix_end(prefix);
        let iter = txn.range(prefix.as_bytes(), end.as_bytes())?;

        let mut records = Vec::new();
        let mut cursor = iter;
        while cursor.next()? {
            let bytes = cursor.value()?;
            match rmps::from_slice::<Record>(&bytes) {
                Ok(record) => records.push(record),
                Err(e) => {
                    tracing::warn!("skipping malformed record during scan: {e}");
                }
            }
        }
        Ok(records)
    }

    /// Scan records whose key starts with `prefix`, invoking `callback` for each.
    ///
    /// Same tree routing and prefix semantics as [`Self::scan_prefix`], but records
    /// are deserialized and passed to `callback` one at a time rather than
    /// collected into a `Vec`. Callers can begin processing (e.g. printing to
    /// stdout) before the full scan completes, giving time-to-first-row
    /// latency proportional to a single deserialization rather than the full
    /// scan.
    ///
    /// Return order is lexicographic (underlying KV order). Callers that need
    /// a different order must collect and sort after the fact.
    pub async fn scan_prefix_each<F>(&self, prefix: &str, mut callback: F) -> Result<()>
    where
        F: FnMut(Record),
    {
        debug_assert_eq!(
            Encoding::for_key(prefix),
            Encoding::Record,
            "scan_prefix_each() deserializes Records from {prefix}, which is a Raw namespace; use scan_keys instead"
        );
        let tree = self.tree_for(prefix);
        let txn = tree.begin_with_mode(Mode::ReadOnly)?;
        let end = prefix_end(prefix);
        let mut cursor = txn.range(prefix.as_bytes(), end.as_bytes())?;
        while cursor.next()? {
            let bytes = cursor.value()?;
            match rmps::from_slice::<Record>(&bytes) {
                Ok(record) => callback(record),
                Err(e) => {
                    tracing::warn!("skipping malformed record during scan: {e}");
                }
            }
        }
        Ok(())
    }

    /// Full-text BM25 search over all indexed records.
    ///
    /// Calls tantivy for the top `limit` matching keys, then fetches each full
    /// record from SurrealKV. Keys that tantivy returns but are not found in
    /// the store (e.g. deleted since last commit) are silently skipped.
    ///
    /// Returns results ordered by descending BM25 relevance score. Returns an
    /// empty `Vec` when `text` is blank or `limit` is 0.
    pub async fn search(&self, text: &str, limit: usize) -> Result<Vec<Record>> {
        let search = self.ensure_search()?;
        let keys = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            search.query_keys(text, limit)
        })) {
            Ok(result) => result?,
            Err(_panic) => {
                tracing::error!("search index panicked during query — returning empty results");
                return Ok(vec![]);
            }
        };
        let mut records = Vec::with_capacity(keys.len());
        for key in &keys {
            if let Some(record) = self.get(key).await? {
                records.push(record);
            }
        }
        Ok(records)
    }

    /// Full-text BM25 search returning `(score, Record)` pairs.
    ///
    /// Same semantics as [`Self::search`] but preserves the raw BM25
    /// relevance score from tantivy. Used by `mem_query` text mode to
    /// include relevance in the agent-facing response.
    pub async fn search_scored(&self, text: &str, limit: usize) -> Result<Vec<(f32, Record)>> {
        let search = self.ensure_search()?;
        let scored_keys = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            search.query_keys_scored(text, limit)
        })) {
            Ok(result) => result?,
            Err(_panic) => {
                tracing::error!(
                    "search index panicked during scored query — returning empty results"
                );
                return Ok(vec![]);
            }
        };
        let mut results = Vec::with_capacity(scored_keys.len());
        for (score, key) in &scored_keys {
            if let Some(record) = self.get(key).await? {
                results.push((*score, record));
            }
        }
        Ok(results)
    }

    /// Read raw bytes by key. Returns `None` if the key does not exist.
    ///
    /// Counterpart to [`Self::put_raw`]. Used for structural metadata,
    /// enforcement events, and other non-Record values stored as raw bytes.
    pub async fn get_raw_bytes(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let tree = self.tree_for(key);
        let txn = tree.begin_with_mode(Mode::ReadOnly)?;
        match txn.get(key.as_bytes())? {
            None => Ok(None),
            Some(bytes) => Ok(Some(bytes.to_vec())),
        }
    }

    /// Write raw bytes under `key` with automatically routed durability.
    ///
    /// Same durability routing as [`Self::put`] — callers do not need to know
    /// which tree a key belongs to. Use this for structural metadata (graph
    /// edges, etc.) where the value is not a [`Record`] and does not need to
    /// be deserialised on reads.
    pub async fn put_raw(&self, key: &str, value: &[u8]) -> Result<()> {
        debug_assert_eq!(
            Encoding::for_key(key),
            Encoding::Raw,
            "put_raw() writes bare bytes into {key}, which is a Record namespace; a prefix scan would skip it. See store::durability::Encoding"
        );
        let durability = Durability::for_key(key);
        let tree = self.tree_for(key);
        let mut txn = tree.begin_with_mode(Mode::WriteOnly)?;
        txn.set_durability(skv_durability(durability));
        txn.set(key.as_bytes(), value.to_vec())?;
        txn.commit().await?;
        Ok(())
    }

    /// Write multiple raw-byte values in a single transaction per durability class.
    ///
    /// Same batch semantics as [`Self::put_batch`] (at most 2 fsyncs for the
    /// whole batch). Use for bulk structural writes like graph edge inserts.
    pub async fn put_batch_raw(&self, records: &[(&str, &[u8])]) -> Result<()> {
        if records.is_empty() {
            return Ok(());
        }

        let mut immediate: Vec<(&str, &[u8])> = Vec::new();
        let mut eventual: Vec<(&str, &[u8])> = Vec::new();
        for &(key, value) in records {
            match Durability::for_key(key) {
                Durability::Immediate => immediate.push((key, value)),
                Durability::Eventual => eventual.push((key, value)),
            }
        }

        if !immediate.is_empty() {
            let mut txn = self.knowledge.begin_with_mode(Mode::WriteOnly)?;
            txn.set_durability(SkvDurability::Immediate);
            for (key, value) in &immediate {
                txn.set(key.as_bytes(), value.to_vec())?;
            }
            txn.commit().await?;
        }

        if !eventual.is_empty() {
            let mut txn = self.sessions.begin_with_mode(Mode::WriteOnly)?;
            txn.set_durability(SkvDurability::Eventual);
            for (key, value) in &eventual {
                txn.set(key.as_bytes(), value.to_vec())?;
            }
            txn.commit().await?;
        }

        Ok(())
    }

    // -------------------------------------------------------------------------
    // Transactional batch writes (mutation + audit atomic commit)
    //
    // SurrealKV supports multi-key atomic transactions within a single tree.
    // The real constraint is mati's two-tree architecture: no single
    // transaction can span both the knowledge and sessions trees.
    // -------------------------------------------------------------------------

    /// Atomically commit multiple writes to the knowledge tree in a single
    /// transaction.
    ///
    /// Supports mixed Record + raw byte writes. All keys MUST route to the
    /// knowledge tree (`Durability::Immediate`). Returns an error if any key
    /// routes to sessions.
    ///
    /// Handles crash-fence + tantivy sync + write-seq after commit.
    /// Use this for mutation + audit atomic commit on knowledge-side commands.
    pub async fn transact_knowledge(&self, ops: &[KnowledgeWriteOp<'_>]) -> Result<()> {
        if ops.is_empty() {
            return Ok(());
        }
        for op in ops {
            let k = match op {
                KnowledgeWriteOp::PutRecord { key, .. } => *key,
                KnowledgeWriteOp::PutRaw { key, .. } => *key,
            };
            if Durability::for_key(k) != Durability::Immediate {
                anyhow::bail!(
                    "transact_knowledge: key '{k}' routes to sessions tree, not knowledge"
                );
            }
        }

        // Collect Records for tantivy sync before committing (we need &Record refs).
        let mut record_refs: Vec<&Record> = Vec::new();

        let mut txn = self.knowledge.begin_with_mode(Mode::WriteOnly)?;
        txn.set_durability(SkvDurability::Immediate);
        for op in ops {
            match op {
                KnowledgeWriteOp::PutRecord { key, record } => {
                    let bytes = rmps::to_vec_named(record)
                        .with_context(|| format!("failed to serialize record for key '{key}'"))?;
                    txn.set(key.as_bytes(), bytes)?;
                    record_refs.push(record);
                }
                KnowledgeWriteOp::PutRaw { key, value } => {
                    txn.set(key.as_bytes(), value.to_vec())?;
                }
            }
        }
        txn.commit().await?;

        // Crash-fence + tantivy sync (same pattern as put/put_batch).
        let has_knowledge = ops.iter().any(|op| {
            let k = match op {
                KnowledgeWriteOp::PutRecord { key, .. } => key,
                KnowledgeWriteOp::PutRaw { key, .. } => key,
            };
            is_knowledge_key(k)
        });
        if has_knowledge {
            let _ = std::fs::write(self.root.join(SEARCH_SYNC_PENDING), b"");
        }
        let mut search_synced = false;
        if !record_refs.is_empty() {
            if let Ok(search) = self.ensure_search() {
                match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    search.add_records(&record_refs)
                })) {
                    Ok(Ok(_)) => search_synced = true,
                    Ok(Err(e)) => tracing::warn!("transact_knowledge: tantivy sync failed: {e}"),
                    Err(_) => tracing::error!("transact_knowledge: tantivy panicked"),
                }
            }
        }
        if has_knowledge {
            self.bump_write_seq();
            if search_synced {
                let _ = std::fs::remove_file(self.root.join(SEARCH_SYNC_PENDING));
            }
        }
        Ok(())
    }

    /// Atomically commit multiple raw byte writes to the sessions tree in a
    /// single transaction.
    ///
    /// All keys MUST route to the sessions tree (`Durability::Eventual`).
    /// Returns an error if any key routes to knowledge.
    ///
    /// Use this for mutation + audit atomic commit on session-side commands.
    pub async fn transact_sessions_raw(&self, entries: &[(&str, &[u8])]) -> Result<()> {
        if entries.is_empty() {
            return Ok(());
        }
        for (k, _) in entries {
            if Durability::for_key(k) != Durability::Eventual {
                anyhow::bail!(
                    "transact_sessions_raw: key '{k}' routes to knowledge tree, not sessions"
                );
            }
        }

        let mut txn = self.sessions.begin_with_mode(Mode::WriteOnly)?;
        txn.set_durability(SkvDurability::Eventual);
        for (key, value) in entries {
            txn.set(key.as_bytes(), value.to_vec())?;
        }
        txn.commit().await?;
        Ok(())
    }

    /// Return all keys whose prefix matches, without deserialising values.
    ///
    /// Cheaper than [`Self::scan_prefix`] when only the key is needed (e.g.
    /// graph edge loading, existence checks). Uses the SurrealKV iterator
    /// `key().user_key()` path so value bytes are never read from disk.
    pub async fn scan_keys(&self, prefix: &str) -> Result<Vec<String>> {
        let tree = self.tree_for(prefix);
        let txn = tree.begin_with_mode(Mode::ReadOnly)?;
        let end = prefix_end(prefix);
        let mut cursor = txn.range(prefix.as_bytes(), end.as_bytes())?;

        let mut keys = Vec::new();
        while cursor.next()? {
            let user_key = cursor.key().user_key();
            match std::str::from_utf8(user_key) {
                Ok(s) => keys.push(s.to_string()),
                Err(e) => tracing::warn!("skipping non-UTF8 key in scan_keys: {e}"),
            }
        }
        Ok(keys)
    }
}
