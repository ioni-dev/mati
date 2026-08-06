// ── Auto-promotion: MCP server → headless daemon ─────────────────────────────

/// Idle shutdown threshold — wall-clock seconds with no daemon socket requests.
///
/// Shared with `cli::daemon` so both daemon paths use the same idle policy.
pub const IDLE_SHUTDOWN_SECS: u64 = 30 * 60; // 30 min

/// How often to check wall-clock idle time. Shared with `cli::daemon`.
pub const IDLE_CHECK_INTERVAL_SECS: u64 = 5 * 60; // 5 min
