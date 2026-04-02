//! StoreProxy — transparent routing to daemon socket or direct Store.
//!
//! CLI commands use `StoreProxy` instead of `Store::open` directly.
//! When a daemon socket is reachable, all operations go through it (no lock conflict).
//! When no daemon is running, it opens the Store directly as before.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde_json::json;

use mati_core::store::db::HistoryEntry;
use mati_core::store::repair::{DirtyMarker, DIRTY_MARKER_KEY};
use mati_core::store::{
    Category, ConfidenceScore, Priority, QualityScore, Record, RecordLifecycle, RecordSource,
    RecordVersion, StalenessScore, Store,
};

use super::daemon::{daemon_result, mati_root_for, DaemonResult};

#[allow(clippy::large_enum_variant)]
enum ProxyInner {
    Direct(Store),
    Socket { root: PathBuf },
}

pub struct StoreProxy {
    inner: ProxyInner,
}

impl StoreProxy {
    /// Open a proxy. Routes through the socket if a daemon is running,
    /// falls back to direct `Store::open` otherwise.
    pub async fn open(cwd: &Path) -> Result<Self> {
        let root = mati_root_for(cwd)?;
        match daemon_result(&root, "ping", json!({})).await {
            DaemonResult::Ok(_) => Ok(Self {
                inner: ProxyInner::Socket { root },
            }),
            DaemonResult::NotRunning | DaemonResult::StaleSocket => {
                let store = Store::open(cwd).await?;
                Ok(Self {
                    inner: ProxyInner::Direct(store),
                })
            }
            DaemonResult::Unresponsive => {
                anyhow::bail!(
                    "mati daemon is running but not responding.\n\
                     Cannot open the store while the daemon holds the lock.\n\
                     Try: mati daemon stop"
                )
            }
        }
    }

    /// Returns a reference to the direct store if in direct mode, or `None` if
    /// routed through the daemon socket.
    pub fn direct_store(&self) -> Option<&Store> {
        match &self.inner {
            ProxyInner::Direct(s) => Some(s),
            ProxyInner::Socket { .. } => None,
        }
    }

    /// Read the write-sequence counter. This is a plain filesystem read — no lock needed.
    pub fn read_write_seq(&self) -> u64 {
        let root = match &self.inner {
            ProxyInner::Direct(s) => s.root.clone(),
            ProxyInner::Socket { root } => root.clone(),
        };
        std::fs::read_to_string(root.join("health_write_seq"))
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0)
    }

    /// Fetch a single record by key.
    pub async fn get(&self, key: &str) -> Result<Option<Record>> {
        match &self.inner {
            ProxyInner::Direct(s) => s.get(key).await,
            ProxyInner::Socket { root } => {
                match daemon_result(root, "get", json!({ "key": key })).await {
                    DaemonResult::Ok(v) => {
                        let data = &v["data"];
                        if data.is_null() {
                            Ok(None)
                        } else {
                            Ok(Some(
                                serde_json::from_value(data.clone())
                                    .context("proxy get: failed to deserialize record")?,
                            ))
                        }
                    }
                    other => Err(socket_read_error("get", other)),
                }
            }
        }
    }

    /// Scan all records whose key starts with `prefix`.
    pub async fn scan_prefix(&self, prefix: &str) -> Result<Vec<Record>> {
        match &self.inner {
            ProxyInner::Direct(s) => s.scan_prefix(prefix).await,
            ProxyInner::Socket { root } => {
                match daemon_result(root, "scan_prefix", json!({ "prefix": prefix })).await {
                    DaemonResult::Ok(v) => {
                        let data = &v["data"];
                        if data.is_null() {
                            Ok(vec![])
                        } else {
                            Ok(serde_json::from_value(data.clone())
                                .context("proxy scan_prefix: failed to deserialize records")?)
                        }
                    }
                    other => Err(socket_read_error("scan_prefix", other)),
                }
            }
        }
    }

    /// Write a record. In socket mode, sends via the `put` socket command.
    pub async fn put(&self, key: &str, record: &Record) -> Result<()> {
        match &self.inner {
            ProxyInner::Direct(s) => s.put(key, record).await,
            ProxyInner::Socket { root } => {
                let record_value = serde_json::to_value(record)?;
                match daemon_result(root, "put", json!({ "key": key, "record": record_value }))
                    .await
                {
                    DaemonResult::Ok(resp) => {
                        if resp.get("ok") == Some(&serde_json::Value::Bool(true)) {
                            Ok(())
                        } else {
                            let err = resp
                                .get("error")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown");
                            anyhow::bail!("daemon put failed: {err}")
                        }
                    }
                    other => Err(socket_read_error("put", other)),
                }
            }
        }
    }

    /// Mark the gotcha index dirty after a best-effort link/edge sync failure.
    #[allow(dead_code)]
    ///
    /// Works in both direct and socket modes so callers can preserve the
    /// repair/status observability contract without needing raw store access.
    pub async fn mark_dirty(&self, gotcha_key: &str, cause: &str) -> Result<()> {
        match &self.inner {
            ProxyInner::Direct(store) => {
                mati_core::store::repair::mark_dirty(store, gotcha_key, cause).await;
                Ok(())
            }
            ProxyInner::Socket { .. } => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                let existing_record = self.get(DIRTY_MARKER_KEY).await?;
                let mut marker = existing_record
                    .as_ref()
                    .and_then(|r| r.payload_as::<DirtyMarker>())
                    .unwrap_or_else(DirtyMarker::clean);
                marker.dirty = true;
                if marker.dirty_since == 0 {
                    marker.dirty_since = now;
                }
                marker.cause = cause.to_string();
                if !marker.affected_keys.iter().any(|k| k == gotcha_key) {
                    marker.affected_keys.push(gotcha_key.to_string());
                }

                let mut record = existing_record.unwrap_or(Record {
                    key: DIRTY_MARKER_KEY.to_string(),
                    value: cause.to_string(),
                    category: Category::Analytics,
                    priority: Priority::Normal,
                    tags: vec![],
                    created_at: now,
                    updated_at: now,
                    ref_url: None,
                    staleness: StalenessScore::fresh(),
                    lifecycle: RecordLifecycle::Active,
                    version: RecordVersion {
                        device_id: uuid::Uuid::new_v4(),
                        logical_clock: 1,
                        wall_clock: now,
                    },
                    quality: QualityScore::layer0_default(),
                    access_count: 0,
                    last_accessed: 0,
                    source: RecordSource::StaticAnalysis,
                    confidence: ConfidenceScore::for_new_record(&RecordSource::StaticAnalysis),
                    gap_analysis_score: 0.0,
                    payload: None,
                });

                record.value = cause.to_string();
                record.updated_at = now;
                record.version.logical_clock += 1;
                record.version.wall_clock = now;
                record.payload = serde_json::to_value(&marker).ok();

                self.put(DIRTY_MARKER_KEY, &record).await
            }
        }
    }

    /// Record a consultation receipt for a key.
    pub async fn log_hit(&self, key: &str) -> Result<()> {
        match &self.inner {
            ProxyInner::Direct(store) => mati_core::store::session::log_hit(store, key).await,
            ProxyInner::Socket { root } => {
                match daemon_result(root, "log_hit", json!({ "key": key })).await {
                    DaemonResult::Ok(_) => Ok(()),
                    other => Err(socket_read_error("log_hit", other)),
                }
            }
        }
    }

    /// Delete a record by key (hard delete, not tombstone).
    #[allow(dead_code)]
    pub async fn delete(&self, key: &str) -> Result<()> {
        match &self.inner {
            ProxyInner::Direct(store) => store.delete(key).await,
            ProxyInner::Socket { root } => {
                match daemon_result(root, "delete", json!({ "key": key })).await {
                    DaemonResult::Ok(_) => Ok(()),
                    other => Err(socket_read_error("delete", other)),
                }
            }
        }
    }

    /// Write a batch of records.
    pub async fn put_batch(&self, records: &[(&str, &Record)]) -> Result<()> {
        match &self.inner {
            ProxyInner::Direct(store) => store.put_batch(records).await,
            ProxyInner::Socket { .. } => {
                // Socket mode: write records one at a time via put.
                // Each record is a separate daemon socket round-trip.
                if records.len() > 100 {
                    tracing::warn!(
                        "put_batch: {} records via socket (O(N) round-trips) — \
                         consider stopping the daemon for bulk imports",
                        records.len()
                    );
                }
                for &(key, record) in records {
                    self.put(key, record).await?;
                }
                Ok(())
            }
        }
    }

    /// Confirm a gotcha record — sets confirmed=true, syncs file links.
    ///
    /// Works in both direct and socket modes. The confirm logic (setting
    /// confirmed=true, bumping confidence, syncing file-record gotcha_keys)
    /// runs through `confirm_gotcha` which uses `self.get`/`self.put` — both
    /// of which route correctly through the proxy.
    pub async fn gotcha_confirm(&self, key: &str) -> Result<()> {
        super::gotcha::confirm_gotcha(self, key).await
    }

    /// Write a gotcha record with file-link sync and graph edges.
    ///
    /// In direct mode, delegates to `apply_gotcha_write`.
    /// In socket mode, routes through the `gotcha_write` daemon command.
    pub async fn gotcha_write(
        &self,
        record: &Record,
        old_files: &[String],
        new_files: &[String],
        is_new: bool,
    ) -> Result<()> {
        match &self.inner {
            ProxyInner::Direct(store) => {
                mati_core::store::gotcha_ops::apply_gotcha_write(
                    store, record, old_files, new_files, is_new,
                )
                .await
            }
            ProxyInner::Socket { root } => {
                let record_value = serde_json::to_value(record)?;
                match daemon_result(
                    root,
                    "gotcha_write",
                    json!({
                        "record": record_value,
                        "old_files": old_files,
                        "new_files": new_files,
                        "is_new": is_new,
                    }),
                )
                .await
                {
                    DaemonResult::Ok(resp) => {
                        if resp.get("ok") == Some(&serde_json::Value::Bool(true)) {
                            Ok(())
                        } else {
                            let err = resp
                                .get("error")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown");
                            anyhow::bail!("daemon gotcha_write failed: {err}")
                        }
                    }
                    other => Err(socket_read_error("gotcha_write", other)),
                }
            }
        }
    }

    /// Tombstone a gotcha and remove its graph edges.
    ///
    /// In direct mode, delegates to `apply_gotcha_tombstone`.
    /// In socket mode, routes through the `gotcha_tombstone` daemon command.
    pub async fn gotcha_tombstone(&self, key: &str, affected_files: &[String]) -> Result<()> {
        match &self.inner {
            ProxyInner::Direct(store) => {
                mati_core::store::gotcha_ops::apply_gotcha_tombstone(store, key, affected_files)
                    .await
            }
            ProxyInner::Socket { root } => {
                match daemon_result(
                    root,
                    "gotcha_tombstone",
                    json!({ "key": key, "affected_files": affected_files }),
                )
                .await
                {
                    DaemonResult::Ok(resp) => {
                        if resp.get("ok") == Some(&serde_json::Value::Bool(true)) {
                            Ok(())
                        } else {
                            let err = resp
                                .get("error")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown");
                            anyhow::bail!("daemon gotcha_tombstone failed: {err}")
                        }
                    }
                    other => Err(socket_read_error("gotcha_tombstone", other)),
                }
            }
        }
    }

    /// Version history for a single key, newest first.
    ///
    /// Only works in direct mode. In socket mode this errors with a message
    /// telling the user to stop the daemon first.
    pub fn history(&self, key: &str, limit: usize) -> Result<Vec<HistoryEntry>> {
        match &self.inner {
            ProxyInner::Direct(s) => s.history(key, limit),
            ProxyInner::Socket { .. } => anyhow::bail!(
                "mati history requires direct store access, which is unavailable while the MCP \
                 server is running.\n\
                 The MCP server (mati serve) holds the store lock for the duration of your \
                 Claude Code session.\n\
                 To use mati history: close your Claude Code session, then re-run the command."
            ),
        }
    }

    /// Version history for a single key since `since_ts`, newest first.
    ///
    /// Only works in direct mode. In socket mode this errors with a message
    /// explaining why and what to do.
    pub fn history_since(
        &self,
        key: &str,
        since_ts: u64,
        limit: usize,
    ) -> Result<Vec<HistoryEntry>> {
        match &self.inner {
            ProxyInner::Direct(s) => s.history_since(key, since_ts, limit),
            ProxyInner::Socket { .. } => anyhow::bail!(
                "mati history requires direct store access, which is unavailable while the MCP \
                 server is running.\n\
                 The MCP server (mati serve) holds the store lock for the duration of your \
                 Claude Code session.\n\
                 To use mati history: close your Claude Code session, then re-run the command."
            ),
        }
    }

    /// All records updated since `since_ts` (seconds), newest first.
    ///
    /// Implemented via `scan_prefix` so it works in both direct and socket modes.
    pub async fn records_since(&self, since_ts: u64, limit: usize) -> Result<Vec<Record>> {
        let namespaces = &[
            "gotcha:",
            "decision:",
            "file:",
            "stage:",
            "dev_note:",
            "dep:",
        ];
        let mut results: Vec<Record> = Vec::new();
        for ns in namespaces {
            let records = self.scan_prefix(ns).await?;
            for r in records {
                if r.updated_at >= since_ts {
                    results.push(r);
                }
            }
        }
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

    /// Consume the proxy to get a direct `Store`. Panics in socket mode.
    /// Only use when you KNOW you're in direct mode (e.g., after checking `is_direct()`).
    pub fn into_store(self) -> Store {
        match self.inner {
            ProxyInner::Direct(s) => s,
            ProxyInner::Socket { .. } => panic!("StoreProxy::into_store called in socket mode"),
        }
    }

    pub fn is_direct(&self) -> bool {
        matches!(self.inner, ProxyInner::Direct(_))
    }

    pub async fn close(self) -> Result<()> {
        match self.inner {
            ProxyInner::Direct(s) => s.close().await,
            ProxyInner::Socket { .. } => Ok(()),
        }
    }

    /// Close the proxy, preserving an existing operation error if present.
    ///
    /// If the operation succeeded, propagate any close error.
    /// If the operation failed, best-effort close and return the original error.
    /// This prevents `proxy.close().await?` from masking the real failure.
    pub async fn close_with_result<T>(self, result: Result<T>) -> Result<T> {
        match &result {
            Ok(_) => {
                self.close().await?;
                result
            }
            Err(_) => {
                let _ = self.close().await;
                result
            }
        }
    }
}

fn socket_read_error(op: &str, result: DaemonResult) -> anyhow::Error {
    let detail = match result {
        DaemonResult::NotRunning => "daemon stopped",
        DaemonResult::StaleSocket => "daemon socket became stale",
        DaemonResult::Unresponsive => "daemon did not respond",
        DaemonResult::Ok(_) => unreachable!("socket_read_error only handles non-ok daemon results"),
    };
    anyhow::anyhow!(
        "mati daemon {detail} while handling '{op}' read; retry after restarting the daemon"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    use tempfile::TempDir;

    #[tokio::test]
    async fn socket_get_errors_when_daemon_is_missing() {
        let dir = TempDir::new().unwrap();
        let proxy = StoreProxy {
            inner: ProxyInner::Socket {
                root: dir.path().to_path_buf(),
            },
        };

        let err = proxy.get("file:missing").await.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("get"));
        assert!(msg.contains("restarting the daemon"));
    }

    #[tokio::test]
    async fn socket_scan_prefix_errors_when_daemon_is_missing() {
        let dir = TempDir::new().unwrap();
        let proxy = StoreProxy {
            inner: ProxyInner::Socket {
                root: dir.path().to_path_buf(),
            },
        };

        let err = proxy.scan_prefix("file:").await.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("scan_prefix"));
        assert!(msg.contains("restarting the daemon"));
    }

    #[tokio::test]
    async fn direct_mark_dirty_writes_marker_record() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).await.unwrap();
        let proxy = StoreProxy {
            inner: ProxyInner::Direct(store),
        };

        proxy
            .mark_dirty("gotcha:test", "link sync failed")
            .await
            .unwrap();

        let marker = proxy.get(DIRTY_MARKER_KEY).await.unwrap().unwrap();
        let payload = marker.payload_as::<DirtyMarker>().unwrap();
        assert!(payload.dirty);
        assert_eq!(payload.cause, "link sync failed");
        assert_eq!(payload.affected_keys, vec!["gotcha:test".to_string()]);
    }
}
