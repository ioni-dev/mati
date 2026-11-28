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
use rmcp::model::{CacheScope, DiscoverResult, Implementation, ServerCapabilities, ServerConfig};
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

/// How long a client may cache the `tools/list` response (SEP-2549). Same
/// rationale as [`DISCOVER_TTL_MS`]: the tool set is a compile-time constant, so
/// the list never changes within a running binary.
const LIST_TOOLS_TTL_MS: u64 = 3_600_000;

#[tool_handler(router = self.tool_router)]
impl ServerHandler for MatiServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_tool_list_changed()
                .build(),
        )
        .with_server_info(Implementation::new("mati", env!("CARGO_PKG_VERSION")))
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

    /// `tools/list` cache hints (MCP 2026-07-28, SEP-2549). mati's tool set is a
    /// compile-time constant — exactly four tools, static per binary — so the
    /// list is safe to cache `Public`. rmcp's `#[tool_handler]` default already
    /// reports `Public` scope but with `ttl_ms = 0`, which forces revalidation
    /// on every call; this override raises the TTL so a client can actually
    /// reuse the tool list. Cache fields are emitted only when the client
    /// negotiated a protocol version that understands them — older peers get the
    /// pre-cache-hint shape unchanged.
    async fn list_tools(
        &self,
        _request: Option<rmcp::model::PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<rmcp::model::ListToolsResult, rmcp::ErrorData> {
        let supports_cache_hints = context
            .protocol_version()
            .is_some_and(|version| version >= rmcp::model::ProtocolVersion::V_2026_07_28);
        let mut result = rmcp::model::ListToolsResult::with_all_items(self.tool_router.list_all());
        if supports_cache_hints {
            result = result
                .with_ttl_ms(LIST_TOOLS_TTL_MS)
                .with_cache_scope(CacheScope::Public);
        }
        Ok(result)
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
