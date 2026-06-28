#![warn(clippy::all)]
// `.unwrap()` discards context — production paths should propagate via `?`
// or document the invariant with `.expect("reason")`. `expect_used` is
// deliberately NOT enabled: `.expect("...")` is the sanctioned escape
// valve for programmer-error invariants (rust-analyzer / ripgrep
// convention). Gated on `not(test)` because inline `mod tests` modules
// legitimately use `.unwrap()` everywhere. CI runs `-D warnings`, so any
// new `.unwrap()` in production code is a hard failure on merge.
#![cfg_attr(not(test), warn(clippy::unwrap_used))]

pub mod analysis;
pub mod eval;
pub mod graph;
pub mod health;
pub mod hooks;
pub mod mcp;
pub mod policy;
pub mod scaffold;
pub mod search;
pub mod store;
