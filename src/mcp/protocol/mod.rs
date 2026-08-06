//! Daemon IPC protocol v2 — wire types for the Unix socket boundary.
//!
//! All mutation commands are semantic (no raw `put`/`delete`). Trust-sensitive
//! fields (timestamps, confidence, quality, lifecycle) are daemon-controlled
//! and never cross the wire as client input.
//!
//! ## Wire format
//!
//! Framing: newline-delimited JSON. One JSON object per line, terminated by `\n`.
//! Request size is capped at [`MAX_FRAME_SIZE`] bytes (enforced by the server
//! before full buffering). Oversized requests receive [`ErrorCode::FrameTooLarge`].
//!
//! ## Security properties
//!
//! - All input DTOs use `#[serde(deny_unknown_fields)]`
//! - `Command` is a closed enum — unknown commands are rejected at decode
//! - Session UUID is required on every request (session marker, not auth)
//! - Request ID is correlation only, not idempotency
//!
//! ## Transaction model
//!
//! SurrealKV supports multi-key atomic transactions within a single tree.
//! The real constraint is mati's two-tree architecture: no single transaction
//! can span both the `knowledge` tree and the `sessions` tree.
//!
//! - Same-tree commands: mutation + audit committed in one transaction
//! - Mixed-tree commands: per-tree atomic batches with explicit substep audit

mod core;
mod inputs;
mod wire;

#[cfg(test)]
mod tests;

pub use core::*;
pub use inputs::*;
pub use wire::*;
