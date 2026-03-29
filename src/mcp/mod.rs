// MCP stdio server — rmcp (M-07)
// Tools: mem_get, mem_query, mem_bootstrap, mem_set
// Keep the surface minimal: prefer extending existing tools over adding more.

pub mod server;
pub mod tools;
pub mod types;

pub use server::serve;
