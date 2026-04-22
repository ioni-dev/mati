//! StoreProxy — transparent routing to daemon socket or direct Store.
//!
//! CLI commands use `StoreProxy` instead of `Store::open` directly.
//! When a daemon socket is reachable, all operations go through it (no lock conflict).
//! When no daemon is running, it opens the Store directly as before.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde_json::json;

use mati_core::store::db::HistoryEntry;
use mati_core::store::{Record, Store};

use super::daemon::{daemon_result, daemon_v2, mati_root_for, DaemonResult};

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

    /// Write a record. In socket mode, dispatches to the appropriate typed
    /// v2 command based on key prefix. There is no raw `put` in the v2 protocol.
    pub async fn put(&self, key: &str, record: &Record) -> Result<()> {
        match &self.inner {
            ProxyInner::Direct(s) => s.put(key, record).await,
            ProxyInner::Socket { root } => {
                use mati_core::mcp::protocol as p;

                let cmd = if key.starts_with("gotcha:") {
                    let gotcha = record.payload_as::<mati_core::store::GotchaRecord>();
                    p::Command::GotchaUpsert(p::GotchaDraftInput {
                        key: key.to_string(),
                        rule: gotcha.as_ref().map(|g| g.rule.clone()).unwrap_or_default(),
                        reason: gotcha
                            .as_ref()
                            .map(|g| g.reason.clone())
                            .unwrap_or_default(),
                        severity: gotcha
                            .as_ref()
                            .map(|g| g.severity.clone().into())
                            .unwrap_or_default(),
                        affected_files: gotcha
                            .as_ref()
                            .map(|g| g.affected_files.clone())
                            .unwrap_or_default(),
                        ref_url: gotcha.as_ref().and_then(|g| g.ref_url.clone()),
                        tags: record.tags.clone(),
                        priority: record.priority.clone().into(),
                        source: match &record.source {
                            mati_core::store::RecordSource::DeveloperManual => {
                                Some("developer_manual".to_string())
                            }
                            mati_core::store::RecordSource::Import => Some("import".to_string()),
                            _ => None,
                        },
                    })
                } else if key.starts_with("file:") {
                    let path = key.strip_prefix("file:").unwrap_or(key);
                    p::Command::FileEnrich(p::FileEnrichInput {
                        path: path.to_string(),
                        purpose: record.value.clone(),
                        entry_points: vec![],
                        decision_keys: vec![],
                        todos: vec![],
                        tags: record.tags.clone(),
                        priority: p::Priority::Normal,
                    })
                } else if key.starts_with("decision:") {
                    let slug = key.strip_prefix("decision:").unwrap_or(key);
                    let payload = record.payload.as_ref().cloned().unwrap_or(json!({}));
                    p::Command::DecisionUpsert(p::DecisionUpsertInput {
                        slug: slug.to_string(),
                        value: record.value.clone(),
                        summary: payload
                            .get("summary")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        rationale: payload
                            .get("rationale")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        tags: record.tags.clone(),
                        priority: p::Priority::Normal,
                    })
                } else if key.starts_with("dev_note:") {
                    p::Command::DevNoteUpsert(p::DevNoteUpsertInput {
                        key: Some(key.to_string()),
                        text: record.value.clone(),
                        tags: record.tags.clone(),
                        priority: record.priority.clone().into(),
                    })
                } else {
                    // Reject unsupported namespaces — never fabricate a
                    // DevNote from an unrecognised key prefix. Callers that
                    // write advisory caches (analytics:*) use `let _ =` and
                    // will silently skip the write in socket mode.
                    anyhow::bail!(
                        "StoreProxy::put: unsupported namespace in socket mode: {key}\n\
                         Supported: gotcha:*, file:*, decision:*, dev_note:*"
                    );
                };

                match daemon_v2(root, cmd).await {
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
                // In socket mode the daemon manages gotcha consistency
                // (write + file-link sync + graph edges) atomically. Client-side
                // dirty markers are unnecessary — the daemon's own repair path
                // handles any internal failures. The analytics:* key used by
                // DIRTY_MARKER_KEY is not a supported socket-mode namespace.
                tracing::debug!(
                    "mark_dirty({gotcha_key}): skipped in socket mode — \
                     daemon manages its own consistency"
                );
                Ok(())
            }
        }
    }

    /// Record a consultation receipt for a key.
    pub async fn log_hit(&self, key: &str) -> Result<()> {
        match &self.inner {
            ProxyInner::Direct(store) => mati_core::store::session::log_hit(store, key).await,
            ProxyInner::Socket { root } => {
                let cmd = mati_core::mcp::protocol::Command::ConsultationHit(
                    mati_core::mcp::protocol::ConsultationHitInput {
                        key: key.to_string(),
                    },
                );
                match daemon_v2(root, cmd).await {
                    DaemonResult::Ok(_) => Ok(()),
                    other => Err(socket_read_error("consultation_hit", other)),
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

    /// Propagate confirmation_count to file records linked to a confirmed gotcha.
    ///
    /// In direct mode, delegates to `propagate_confirmation_to_files` which
    /// writes via `store.put` without going through `FileEnrich`.
    ///
    /// In socket mode, this is a no-op: the daemon's `handle_gotcha_confirm`
    /// stages `compute_confirmation_propagation` inside the same
    /// `transact_knowledge` call that writes the confirmed gotcha, so
    /// propagation is already atomic and complete by the time the client
    /// returns. A redundant round-trip here would route through `FileEnrich`,
    /// which rejects Layer 0 stubs (empty purpose) and would also reset
    /// `confirmation_count` to its for-new-record default.
    pub async fn propagate_confirmation(&self, affected_files: &[String]) {
        match &self.inner {
            ProxyInner::Direct(store) => {
                mati_core::store::gotcha_ops::propagate_confirmation_to_files(
                    store,
                    affected_files,
                )
                .await;
            }
            ProxyInner::Socket { .. } => {
                // Daemon path already propagated atomically — nothing to do.
            }
        }
    }

    /// Write a gotcha record with file-link sync and graph edges.
    ///
    /// In direct mode, delegates to `apply_gotcha_write`.
    /// In socket mode, sends a typed `GotchaUpsert` v2 command.
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
                use mati_core::mcp::protocol as p;
                let gotcha = record
                    .payload_as::<mati_core::store::GotchaRecord>()
                    .unwrap_or(mati_core::store::GotchaRecord {
                        rule: record.value.clone(),
                        reason: String::new(),
                        severity: mati_core::store::Priority::Normal,
                        affected_files: new_files.to_vec(),
                        ref_url: None,
                        discovered_session: 0,
                        confirmed: false,
                    });
                let source = match &record.source {
                    mati_core::store::RecordSource::DeveloperManual => {
                        Some("developer_manual".to_string())
                    }
                    mati_core::store::RecordSource::Import => Some("import".to_string()),
                    _ => None,
                };
                let cmd = p::Command::GotchaUpsert(p::GotchaDraftInput {
                    key: record.key.clone(),
                    rule: gotcha.rule,
                    reason: gotcha.reason,
                    severity: gotcha.severity.into(),
                    affected_files: new_files.to_vec(),
                    ref_url: gotcha.ref_url,
                    tags: record.tags.clone(),
                    priority: record.priority.clone().into(),
                    source,
                });
                match daemon_v2(root, cmd).await {
                    DaemonResult::Ok(resp) => {
                        if resp.get("ok") == Some(&serde_json::Value::Bool(true)) {
                            Ok(())
                        } else {
                            let err = resp
                                .get("error")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown");
                            anyhow::bail!("daemon gotcha_upsert failed: {err}")
                        }
                    }
                    other => Err(socket_read_error("gotcha_upsert", other)),
                }
            }
        }
    }

    /// Tombstone a gotcha and remove its graph edges.
    ///
    /// In direct mode, delegates to `apply_gotcha_tombstone`.
    /// In socket mode, sends a typed `GotchaTombstone` v2 command.
    pub async fn gotcha_tombstone(&self, key: &str, affected_files: &[String]) -> Result<()> {
        match &self.inner {
            ProxyInner::Direct(store) => {
                mati_core::store::gotcha_ops::apply_gotcha_tombstone(store, key, affected_files)
                    .await
            }
            ProxyInner::Socket { root } => {
                let cmd = mati_core::mcp::protocol::Command::GotchaTombstone(
                    mati_core::mcp::protocol::GotchaTombstoneInput {
                        key: key.to_string(),
                    },
                );
                match daemon_v2(root, cmd).await {
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

    /// Persist a confirmed gotcha record with file-link sync in direct mode.
    ///
    /// Records a `ControlChanged::Confirmed` enforcement event — used instead
    /// of `gotcha_write` so confirmations show up as `Confirmed` in the audit
    /// stream instead of generic `Updated`. No-op in socket mode; socket mode
    /// uses [`daemon_gotcha_confirm`] which the daemon handler audits.
    pub async fn gotcha_confirm_direct(
        &self,
        record: &Record,
        affected_files: &[String],
    ) -> Result<()> {
        match &self.inner {
            ProxyInner::Direct(store) => {
                mati_core::store::gotcha_ops::apply_gotcha_confirm(store, record, affected_files)
                    .await
            }
            ProxyInner::Socket { .. } => Ok(()),
        }
    }

    /// Send a `GotchaConfirm` v2 command to the daemon.
    ///
    /// Only used in socket mode. The daemon's native handler atomically sets
    /// `DeveloperManual` source, 0.80 confidence, and file-link updates.
    /// In direct mode this is a no-op — the caller handles local writes.
    pub async fn daemon_gotcha_confirm(&self, key: &str) -> Result<()> {
        match &self.inner {
            ProxyInner::Direct(_) => Ok(()),
            ProxyInner::Socket { root } => {
                let cmd = mati_core::mcp::protocol::Command::GotchaConfirm(
                    mati_core::mcp::protocol::GotchaConfirmInput {
                        key: key.to_string(),
                    },
                );
                match daemon_v2(root, cmd).await {
                    DaemonResult::Ok(resp) => {
                        if resp.get("ok") == Some(&serde_json::Value::Bool(true)) {
                            Ok(())
                        } else {
                            let err = resp
                                .get("error")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown");
                            anyhow::bail!("daemon gotcha_confirm failed: {err}")
                        }
                    }
                    other => Err(socket_read_error("gotcha_confirm", other)),
                }
            }
        }
    }

    /// Version history for a single key, newest first.
    pub async fn history(&self, key: &str, limit: usize) -> Result<Vec<HistoryEntry>> {
        match &self.inner {
            ProxyInner::Direct(s) => s.history(key, limit),
            ProxyInner::Socket { root } => {
                match daemon_result(root, "history", json!({ "key": key, "limit": limit })).await {
                    DaemonResult::Ok(v) => {
                        let data = &v["data"];
                        Ok(serde_json::from_value(data.clone())
                            .context("proxy history: failed to deserialize entries")?)
                    }
                    other => Err(socket_read_error("history", other)),
                }
            }
        }
    }

    /// Version history for a single key since `since_ts`, newest first.
    pub async fn history_since(
        &self,
        key: &str,
        since_ts: u64,
        limit: usize,
    ) -> Result<Vec<HistoryEntry>> {
        match &self.inner {
            ProxyInner::Direct(s) => s.history_since(key, since_ts, limit),
            ProxyInner::Socket { root } => {
                match daemon_result(
                    root,
                    "history_since",
                    json!({ "key": key, "since_ts": since_ts, "limit": limit }),
                )
                .await
                {
                    DaemonResult::Ok(v) => {
                        let data = &v["data"];
                        Ok(serde_json::from_value(data.clone())
                            .context("proxy history_since: failed to deserialize entries")?)
                    }
                    other => Err(socket_read_error("history_since", other)),
                }
            }
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

    use mati_core::store::repair::{DirtyMarker, DIRTY_MARKER_KEY};
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

    /// Socket-mode `put` must reject unsupported namespaces with a clear error
    /// instead of silently fabricating a DevNoteUpsert.
    #[tokio::test]
    async fn socket_put_rejects_unsupported_namespace() {
        let dir = TempDir::new().unwrap();
        let proxy = StoreProxy {
            inner: ProxyInner::Socket {
                root: dir.path().to_path_buf(),
            },
        };

        let record = Record::layer0_file_stub("dummy", uuid::Uuid::new_v4(), 1, 0);
        for ns in &[
            "analytics:test",
            "session:123",
            "dep:rust:serde",
            "stage:current",
            "graph:edge:a:b:c",
        ] {
            let err = proxy.put(ns, &record).await.unwrap_err();
            let msg = err.to_string();
            assert!(
                msg.contains("unsupported namespace"),
                "expected 'unsupported namespace' error for key '{ns}', got: {msg}"
            );
        }
    }

    /// Socket-mode `mark_dirty` is a no-op (daemon manages its own consistency).
    #[tokio::test]
    async fn socket_mark_dirty_is_noop() {
        let dir = TempDir::new().unwrap();
        let proxy = StoreProxy {
            inner: ProxyInner::Socket {
                root: dir.path().to_path_buf(),
            },
        };

        // Should succeed without trying to write analytics:* through put().
        proxy
            .mark_dirty("gotcha:test", "link sync failed")
            .await
            .unwrap();
    }
}
