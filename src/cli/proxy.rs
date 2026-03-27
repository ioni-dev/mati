//! StoreProxy — transparent routing to daemon socket or direct Store.
//!
//! CLI commands use `StoreProxy` instead of `Store::open` directly.
//! When a daemon socket is reachable, all operations go through it (no lock conflict).
//! When no daemon is running, it opens the Store directly as before.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde_json::json;

use mati_core::store::{Record, Store};
use mati_core::store::db::HistoryEntry;

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
            DaemonResult::Ok(_) => {
                Ok(Self { inner: ProxyInner::Socket { root } })
            }
            DaemonResult::NotRunning | DaemonResult::StaleSocket => {
                let store = Store::open(cwd).await?;
                Ok(Self { inner: ProxyInner::Direct(store) })
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
                    _ => Ok(None),
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
                    _ => Ok(vec![]),
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
                match daemon_result(root, "put", json!({ "key": key, "record": record_value })).await {
                    DaemonResult::Ok(_) => Ok(()),
                    // Non-fatal: cache write failure is acceptable.
                    _ => Ok(()),
                }
            }
        }
    }

    /// Version history for a single key, newest first.
    ///
    /// Only works in direct mode. In socket mode this errors with a message
    /// telling the user to stop the daemon first.
    #[allow(dead_code)]
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
    #[allow(dead_code)]
    pub fn history_since(&self, key: &str, since_ts: u64, limit: usize) -> Result<Vec<HistoryEntry>> {
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
    #[allow(dead_code)]
    pub async fn records_since(&self, since_ts: u64, limit: usize) -> Result<Vec<Record>> {
        let namespaces = &["gotcha:", "decision:", "file:", "stage:", "dev_note:", "dep:"];
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
}
