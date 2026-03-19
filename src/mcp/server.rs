//! MCP stdio server entry point (M-07).
//!
//! `serve()` is the only public function. It opens the store, loads the graph,
//! constructs `MatiServer`, and runs the rmcp stdio transport until the client
//! disconnects.

use std::path::Path;

use anyhow::{Context, Result};
use rmcp::model::{ServerCapabilities, ServerInfo};
use rmcp::{ServerHandler, ServiceExt, tool_handler};

use crate::graph::Graph;
use crate::store::Store;

use super::tools::MatiServer;

#[tool_handler(router = self.tool_router)]
impl ServerHandler for MatiServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_instructions(
                "mati — engineering knowledge that survives turnover. \
                 Use mem_get to look up records, mem_query to search, \
                 and mem_bootstrap at session start.",
            )
    }
}

/// Start the MCP stdio server for the project rooted at `repo_root`.
///
/// Opens the store (with search index rebuild if needed), loads the graph,
/// and serves tools over stdin/stdout until the client disconnects.
pub async fn serve(repo_root: &Path) -> Result<()> {
    let store = Store::open_and_rebuild(repo_root)
        .await
        .context("failed to open mati store")?;

    let graph = Graph::load(store)
        .await
        .context("failed to load knowledge graph")?;

    let server = MatiServer::new(graph);

    let transport = rmcp::transport::io::stdio();
    let service = server.serve(transport).await.map_err(|e| {
        anyhow::anyhow!("MCP server initialization failed: {e}")
    })?;

    service.waiting().await?;
    Ok(())
}
