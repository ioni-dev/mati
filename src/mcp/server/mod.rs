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
use rmcp::model::{CacheScope, DiscoverResult, ServerCapabilities, ServerInfo};
use rmcp::service::{MaybeSendFuture, RequestContext, RoleServer};
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

/// How long a client may cache the `server/discover` response (SEP-2549).
/// mati's tool set is a compile-time constant (exactly four tools) and
/// `get_info` is fully static, so the discovery result never changes within a
/// running binary — an upgrade replaces the binary and restarts the session.
/// One hour is conservative for that; raise it freely.
const DISCOVER_TTL_MS: u64 = 3_600_000;

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

    /// `server/discover` (MCP 2026-07-28): a stateless capability probe a client
    /// can issue without a full `initialize` handshake. rmcp's default derives
    /// the result from `get_info` but marks it non-cacheable (`ttl_ms = 0`,
    /// `Private`). The response is identical for every caller and static per
    /// binary, so mati returns it as `Public` and cacheable — this is the F7
    /// win: a client may cache the tool list instead of paying its token cost on
    /// every call. Answered locally in `serve`; no daemon or store access.
    fn discover(
        &self,
        _context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<DiscoverResult, rmcp::ErrorData>> + MaybeSendFuture + '_
    {
        let result = DiscoverResult::from_server_info(
            self.supported_protocol_versions().into_owned(),
            self.get_info(),
        )
        .with_ttl_ms(DISCOVER_TTL_MS)
        .with_cache_scope(CacheScope::Public);
        std::future::ready(Ok(result))
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
