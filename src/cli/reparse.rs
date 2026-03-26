//! `mati reparse <path>` — re-parse a single file and update its FileRecord (M-12-A).
//!
//! Hidden CLI command called by `post-edit.sh` in background. Must be fast
//! (<50ms target) — uses `Store::open`, not `open_and_rebuild`.
//!
//! Core logic lives in `mati_core::analysis::reparse` (accessible from both
//! the binary CLI and the MCP server socket handler).

use anyhow::Result;
use mati_core::store::Store;

pub use mati_core::analysis::reparse::reparse_impl;

pub async fn run(path: &str) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let store = Store::open(&cwd).await?;
    reparse_impl(&store, &cwd, path).await?;
    store.close().await?;
    Ok(())
}
