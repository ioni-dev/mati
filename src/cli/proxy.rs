//! StoreProxy — transparent routing to daemon socket or direct Store.
//!
//! CLI commands use `StoreProxy` instead of `Store::open` directly.
//! When a daemon socket is reachable, all operations go through it (no lock conflict).
//! When no daemon is running, it opens the Store directly as before.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde_json::json;

use mati_core::store::{Record, Store};

use super::daemon::{daemon_result, mati_root_for, DaemonResult};

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
