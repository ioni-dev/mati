//! Daemon mode — keeps Store open to eliminate CLI startup overhead (M-17-A).
//!
//! The daemon listens on a Unix socket (`~/.mati/<slug>/mati.sock`) and handles
//! newline-delimited JSON requests. Hook commands and CLI commands (via
//! `StoreProxy`) route through the socket to skip the ~150ms SurrealKV init
//! cost and avoid lock contention against the daemon's exclusive flock.
//!
//! ## Protocol — v2 only on the public wire
//!
//! One v2 `protocol::Request` per connection, one v2 `protocol::Response`,
//! then close. There is no v1 fallback path on the public socket; the
//! legacy `(cmd_str, args)` form is mapped to v2 internally by
//! `daemon_result` / `protocol::v1_to_v2_command` for callers that have
//! not yet migrated to typed `daemon_v2`.
//!
//! ```json
//! // Request — v2
//! {"v":2,"id":"<uuid>","session":"<uuid>","cmd":{"type":"Ping"}}
//! {"v":2,"id":"<uuid>","session":"<uuid>","cmd":{"type":"Get","key":"file:src/main.rs"}}
//!
//! // Response — v2
//! {"v":2,"id":"<uuid>","status":"ok","data":<value>}
//! {"v":2,"id":"<uuid>","status":"err","code":"<error_code>","message":"description"}
//! ```
//!
//! ## Lifecycle
//!
//! Self-managing — no agent-specific session hooks required:
//! - Start: `mati daemon start` (or any agent's session-start script)
//! - Auto-shutdown: after [`IDLE_SHUTDOWN_SECS`] of wall-clock inactivity
//!   AND zero active UDS connections. Wall-clock (vs tokio monotonic) so
//!   sleep/wake cycles count toward idle time. The active-connection
//!   gate (γ-C5) prevents the daemon from exiting while an `mati serve`
//!   MCP proxy is holding a long-lived UDS connection — without the
//!   gate, a long Claude/Codex session that paused between tool calls
//!   would silently lose its daemon.
//! - Signal shutdown: SIGINT / SIGTERM → flush store, remove socket + PID file.
//! - Stop: `mati daemon stop` is **synchronous and authoritative**: when the
//!   command returns Ok, the daemon process is gone, the SurrealKV flock is
//!   released, and `mati.sock` / `mati.pid` are unlinked. Refuses (exit 1)
//!   when the socket is owned by an active `mati serve` (MCP) unless the
//!   caller passes `--force`.
//! - `mati init` bypasses `StoreProxy` and opens the store directly, so it
//!   requires the daemon to be stopped first. Most other CLI commands
//!   route through the socket and run while the daemon is up.
//!
//! ## Connection model
//!
//! Bounded-concurrent: handlers are spawned into a `JoinSet` capped by a
//! `Semaphore(MAX_DAEMON_CONNECTIONS)`. Reads on the underlying
//! `RwLock<Graph>` parallelize; writes serialize at the lock layer. Beyond
//! the limit, the accept loop pauses (the OS socket backlog absorbs the
//! surplus) — bounded memory under flood. Mirrors the embedded
//! `serve_daemon_socket` loop in `mcp/server.rs` so both daemon paths share
//! identical concurrency + drain semantics.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

use mati_core::graph::Graph;
use mati_core::hooks::policy_match::PolicyMatcherSet;
use mati_core::store::{derive_slug, Store};

// ── CLI subcommand types ──────────────────────────────────────────────────────

/// `mati daemon <start|stop|status>` — manage the background daemon process.
#[derive(Args, Debug)]
pub struct DaemonArgs {
    #[command(subcommand)]
    pub command: DaemonCommand,
}

#[derive(Subcommand, Debug)]
pub enum DaemonCommand {
    /// Start the daemon in the foreground (blocks until shutdown)
    Start,
    /// Stop a running daemon (sends SIGTERM, removes socket + PID file)
    Stop(DaemonStopArgs),
    /// Show whether the daemon is running and its socket path
    Status,
}

/// Arguments for `mati daemon stop`.
///
/// Default behavior: SIGTERM the daemon, wait up to `--timeout` for exit,
/// escalate to SIGKILL on timeout. After γ, `mati serve` proxies survive
/// daemon restarts transparently via `ensure_daemon` auto-respawn, so the
/// default flow is non-destructive to active MCP sessions.
///
/// Flag semantics (γ-C6):
///
/// - `--force`: send SIGKILL directly, no SIGTERM grace period. Useful
///   when a daemon is wedged or you need an immediate kill. Also retains
///   its historical meaning of overriding the safety refusal on
///   MCP-owned / unknown-owned sockets (pre-γ daemons or out-of-band
///   processes). Active `mati serve` proxies still auto-respawn the
///   daemon — they remain reachable to their MCP clients.
/// - `--include-mcp`: additionally kill any running `mati serve` proxy
///   processes. This is the "I really want to end the MCP session"
///   destructive option. Without it, killing the daemon leaves serve
///   proxies running; with it, serve processes also die and Codex /
///   Claude's MCP transport closes.
/// - `--no-wait`: SIGTERM (or SIGKILL with `--force`) and return without
///   waiting. Escape hatch for supervisor scripts.
#[derive(Args, Debug, Default, Clone)]
pub struct DaemonStopArgs {
    /// Skip the SIGTERM grace period — send SIGKILL directly.
    ///
    /// Also overrides the historical safety refusal on MCP-owned or
    /// unknown-owned sockets (rarely triggered post-γ — `mati serve` no
    /// longer owns the daemon socket).
    #[arg(long)]
    pub force: bool,

    /// Also kill any running `mati serve` proxy processes after stopping
    /// the daemon. γ-C6: without this flag, MCP-stdio proxies survive
    /// daemon restarts transparently via ensure_daemon. Use this only
    /// when you explicitly want to end the active MCP session(s).
    #[arg(long)]
    pub include_mcp: bool,

    /// Maximum seconds to wait for the daemon to exit after SIGTERM
    /// before escalating to SIGKILL. Clamped to `[1, 60]`. Ignored when
    /// `--force` is set (no SIGTERM to wait for).
    ///
    /// Default bumped 7s → 20s in response to γ smoke evidence: under
    /// heavy concurrent load, the daemon's `store.close()` path
    /// (knowledge.db WAL fsync + sessions.db WAL fsync + tantivy index
    /// commit, run in parallel via `tokio::try_join!`) can legitimately
    /// take longer than 7 seconds. The 20s ceiling gives the close
    /// sequence room to complete cleanly without forcing SIGKILL
    /// escalation. Operators who need a faster fail-fast can pass
    /// `--timeout 3` etc. explicitly.
    #[arg(long, default_value_t = 20)]
    pub timeout: u64,

    /// Send the kill signal and return immediately without waiting for
    /// the process to exit. The next CLI call may still race the
    /// SurrealKV flock — only use when an external supervisor will poll
    /// for exit.
    #[arg(long)]
    pub no_wait: bool,
}

impl DaemonStopArgs {
    /// Apply the documented `[1, 60]` clamp to `timeout`.
    fn timeout_clamped(&self) -> Duration {
        Duration::from_secs(self.timeout.clamp(1, 60))
    }
}

// ── Protocol constants ───────────────────────────────────────────────────────
//
// These previously had local definitions duplicating values in
// `mcp::server`. Both daemon paths share the same operational policy
// (same idle thresholds, same socket-path limit, same concurrency cap),
// and drift between them was a real risk: pass-11 found `auto_drain`
// missing from one path while present in the other for exactly this
// reason. All now resolve to a single canonical definition.
use mati_core::mcp::server::{
    IDLE_CHECK_INTERVAL_SECS, IDLE_SHUTDOWN_SECS,
    MAX_CONCURRENT_CONNECTIONS as MAX_DAEMON_CONNECTIONS, UNIX_SOCK_PATH_MAX,
};

/// Outcome of a [`daemon_result`] call. Each variant carries the information
/// the caller needs to decide whether to fall back to `Store::open`.
#[derive(Debug)]
pub enum DaemonResult {
    /// Daemon responded. The value is the full JSON response (`ok`, `v`, `data`/`error`).
    Ok(serde_json::Value),
    /// No socket file — daemon is not running. **Safe** to use `Store::open`.
    NotRunning,
    /// Socket was stale (ECONNREFUSED + PID dead). Files cleaned up.
    /// **Safe** to use `Store::open`.
    StaleSocket,
    /// Daemon process is alive but not responding (or protocol version mismatch).
    /// **Not safe** to use `Store::open` — daemon likely holds the SurrealKV lock.
    /// Callers must degrade gracefully (P9) rather than attempt direct store access.
    Unresponsive,
    /// Connecting to the daemon socket was denied (`EACCES`/`EPERM`). The socket
    /// exists, so a daemon made it, but this process is forbidden from connecting
    /// — typically because it runs inside a sandbox (e.g. an AI agent's shell
    /// tool under macOS Seatbelt) that blocks Unix-domain-socket connects.
    /// **Not safe** to use `Store::open`, and retrying will not help: it is a
    /// permission wall, not a busy daemon. Hooks and the MCP server run outside
    /// the sandbox and are unaffected.
    PermissionDenied,
}

// ── Connection timeout ───────────────────────────────────────────────────────

// ── Server ───────────────────────────────────────────────────────────────────

/// Start the daemon: open the Store, bind the Unix socket, and serve forever.
///
/// Exits cleanly on SIGINT, SIGTERM, or after [`IDLE_SHUTDOWN_SECS`] of wall-clock
/// inactivity with no active UDS connections (γ-C5 gate). For the historic wall-clock
/// idle time. Removes the socket and PID file on any exit path.
mod lifecycle;
mod serve;
mod start;
mod stop;

#[cfg(test)]
mod tests;

#[allow(unused_imports)]
use lifecycle::kill_and_wait;
#[allow(unused_imports)]
use lifecycle::{
    check_starting_peer_active, classify_daemon, format_sentinel, kill_mati_serve_processes,
    project_root, read_tail, recorded_serve_pids, send_sigkill_only, send_sigterm_only,
    serve_pids_to_kill, wait_for_files_removed, wall_secs, DaemonState, ExitOutcome,
    RECORDED_SERVE_SCAN_MAX_BYTES,
};
pub use lifecycle::{mati_root_for, parse_sentinel, read_pid_file, STARTING_STALE_SECS};
#[allow(unused_imports)]
use serve::serve_loop_graceful;
#[allow(unused_imports)]
pub use serve::{daemon_get, daemon_result, daemon_v2};
pub use start::run_daemon_start;
pub use stop::{run_daemon_status, run_daemon_stop};
