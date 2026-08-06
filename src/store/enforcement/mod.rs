//! Enforcement event recording — the audit backbone.
//!
//! This module provides the canonical event envelope for all enforcement
//! decisions made by mati hooks. Events form a hash-chained, monotonically
//! sequenced, tamper-evident stream that can be exported for audit.
//!
//! # Invariants (FROZEN for schema_version 1)
//!
//! - The canonical hash contract (field order, serialization format, algorithm)
//!   must not change without incrementing [`SCHEMA_VERSION`].
//! - Sequence numbers are globally unique, monotonically increasing, and
//!   persisted before the event that uses them.
//! - The hash chain (`prev_hash`) links each event to its predecessor.
//!   Gaps in seq_no are acceptable (crash recovery) but hash chain breaks
//!   indicate tampering or corruption.

use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::db::Store;

mod config;
mod metrics;
mod models_chain;
mod recording;
mod retention;
mod seq_writer;

#[cfg(test)]
mod tests;

pub use config::*;
pub use metrics::*;
pub use models_chain::*;
pub use recording::*;
pub use retention::*;
pub use seq_writer::*;

#[cfg(test)]
pub(super) use config::POLICY_MODE_KEY;
#[cfg(test)]
pub(super) use metrics::median_u64;
pub(super) use models_chain::SEQ_KEY;
pub(super) use recording::shared_writer;
pub(super) use seq_writer::now_ms;
#[cfg(test)]
pub(super) use seq_writer::{is_case_insensitive, normalize_components};
