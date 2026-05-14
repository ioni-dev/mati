// MCP stdio server — rmcp (M-07, M-11)
// Tools: mem_get, mem_query, mem_bootstrap, mem_set
// Keep the surface intentional: each tool should have concise MCP-facing
// metadata because Codex surfaces this list directly in `/mcp`.

pub mod daemon_lifecycle;
pub mod dispatch_v2;
pub mod handlers;
pub mod metadata;
pub mod metrics;
pub mod protocol;
pub mod server;
pub mod tools;
pub mod types;

pub use server::serve;
