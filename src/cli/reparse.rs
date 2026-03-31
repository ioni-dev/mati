//! `mati reparse <path>` — re-parse a single file and update its FileRecord (M-12-A).
//!
//! Hidden CLI command. Uses `StoreProxy` so it works both when a daemon/MCP
//! server is running (routes through socket) and standalone (direct store open).

use anyhow::Result;

use super::proxy::StoreProxy;

pub use mati_core::analysis::reparse::reparse_impl;

pub async fn run(path: &str) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let proxy = StoreProxy::open(&cwd).await?;

    // StoreProxy doesn't expose reparse directly, so we check if we have
    // direct store access. If routed through socket, use the edit_hook
    // daemon command which includes reparse.
    if let Some(store) = proxy.direct_store() {
        reparse_impl(store, &cwd, path).await?;
    } else {
        // Route through daemon socket
        use crate::cli::daemon::{daemon_result, mati_root_for, DaemonResult};
        let root = mati_root_for(&cwd)?;
        match daemon_result(&root, "edit_hook", serde_json::json!({ "path": path })).await {
            DaemonResult::Ok(_) => {}
            _ => {
                tracing::warn!("mati reparse: daemon unreachable — skipping");
            }
        }
    }

    proxy.close().await?;
    Ok(())
}
