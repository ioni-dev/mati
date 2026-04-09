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

    if let Some(store) = proxy.direct_store() {
        reparse_impl(store, &cwd, path).await?;
    } else {
        // Route through the typed v2 FileReparse command.
        use crate::cli::daemon::{daemon_v2, mati_root_for, DaemonResult};
        let root = mati_root_for(&cwd)?;
        let cmd = mati_core::mcp::protocol::Command::FileReparse(
            mati_core::mcp::protocol::FileReparseInput {
                path: path.to_string(),
            },
        );
        match daemon_v2(&root, cmd).await {
            DaemonResult::Ok(_) => {}
            _ => tracing::warn!("mati reparse: daemon unreachable — skipping"),
        }
    }

    proxy.close().await?;
    Ok(())
}
