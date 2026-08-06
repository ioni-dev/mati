//! MCP stdio server entry point (M-07).
//!
//! `serve()` is the entry point. It opens the store, loads the graph,
//! constructs `MatiServer`, and runs the rmcp stdio transport. After the
//! client disconnects, the process auto-promotes to a headless daemon and
//! waits for an idle timeout or signal before shutting down (a panic hook
//! is installed at startup; lifecycle events are recorded throughout;
//! a boot-time auto-drain bounded by `AUTO_DRAIN_TIMEOUT` runs the dirty
//! gotcha-index repair).
//!
//! Also binds the Unix daemon socket (`~/.mati/<slug>/mati.sock`) so that hook
//! scripts using `mati get`/`mati ping` can route through the daemon protocol
//! instead of trying to open the SurrealKV store directly (which would fail with
//! a lock error while the MCP server holds the exclusive handle). The socket
//! task is supervised: a watcher signals graceful shutdown if it dies, and
//! a `SHUTDOWN_DRAIN_TIMEOUT` ceiling falls back to `abort_handle` so a
//! wedged handler can never block exit.
//!
//! Public surface: `serve`, `socket_handle_connection`, `Shutdown` (+
//! methods), and the policy constants `AUTO_DRAIN_TIMEOUT`,
//! `MAX_CONCURRENT_CONNECTIONS`, `IDLE_SHUTDOWN_SECS`,
//! `IDLE_CHECK_INTERVAL_SECS`, `UNIX_SOCK_PATH_MAX` — all shared with
//! `cli::daemon` so both daemon paths use identical operational policy.

use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use rmcp::model::{ServerCapabilities, ServerInfo};
use rmcp::{tool_handler, ServerHandler, ServiceExt};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use crate::graph::edges::EdgeKind;
use crate::graph::Graph;

use super::tools::MatiServer;
use super::types::{MemBootstrapParams, MemGetParams, MemQueryParams};
use crate::mcp::{daemon_lifecycle, dispatch_v2, handlers, metadata, metrics, protocol};

#[derive(Debug)]
pub(crate) enum ProxyDaemonResult {
    Ok(serde_json::Value),
    NotRunning,
    StaleSocket,
    Unresponsive,
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for MatiServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_tool_list_changed()
                .build(),
        )
        .with_instructions(
            "mati is a persistent engineering knowledge store for the current \
                 codebase. Use mem_get for direct record lookup, mem_query for \
                 search and graph traversal, mem_bootstrap for session context, \
                 and mem_set for writing knowledge records.",
        )
    }
}

mod dispatch;
mod promotion;
mod proxy;
mod socket;

#[cfg(test)]
mod shutdown_tests;
#[cfg(test)]
mod tests;

pub(crate) use dispatch::socket_dispatch;
pub use promotion::{IDLE_CHECK_INTERVAL_SECS, IDLE_SHUTDOWN_SECS};
pub use proxy::serve;
pub(crate) use proxy::{proxy_daemon_result, proxy_daemon_result_no_spawn, proxy_daemon_v2};
use socket::build_v1_dispatch_ctx;
#[cfg(test)]
use socket::PROTOCOL_VERSION;
pub use socket::{
    socket_handle_connection, Shutdown, AUTO_DRAIN_TIMEOUT, MAX_CONCURRENT_CONNECTIONS,
    UNIX_SOCK_PATH_MAX,
};
pub(crate) use socket::{SocketRequest, SocketResponse};

// ── Tests ────────────────────────────────────────────────────────────────────
