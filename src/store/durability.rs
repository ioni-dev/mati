//! Write durability levels for the SurrealKV store.
//!
//! **Never mix these.** The split is load-bearing for performance:
//! - `Immediate`: fsync on every write — slow but crash-safe.
//! - `Eventual`: OS write buffer — fast but may lose the last ~10ms on crash.
//!
//! Assignment by key prefix (from ARCHITECTURE.md §4):
//! ```text
//! Immediate  gotcha:*   decision:*   file:*   stage:*   dev_note:*
//! Eventual   session:*  analytics:*  hook_event:*  compliance:*
//! ```

/// Controls whether a `Store::put` call fsyncs before returning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Durability {
    /// fsync after write. Use for all user-visible knowledge records.
    /// Correct for: `gotcha:*`, `decision:*`, `file:*`, `stage:*`, `dev_note:*`.
    Immediate,
    /// OS write buffer only. Fast path for high-frequency internal writes.
    /// Correct for: `session:*`, `analytics:*`, `hook_event:*`, `compliance:*`.
    Eventual,
}

impl Durability {
    /// Infer durability from a record key prefix.
    ///
    /// Unknown prefixes default to `Immediate` (safe over sorry).
    pub fn for_key(key: &str) -> Self {
        if key.starts_with("session:")
            || key.starts_with("analytics:")
            || key.starts_with("hook_event:")
            || key.starts_with("compliance:")
        {
            Self::Eventual
        } else {
            Self::Immediate
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn immediate_keys() {
        assert_eq!(
            Durability::for_key("gotcha:inference-async"),
            Durability::Immediate
        );
        assert_eq!(
            Durability::for_key("decision:storage-engine"),
            Durability::Immediate
        );
        assert_eq!(
            Durability::for_key("file:src/main.rs"),
            Durability::Immediate
        );
        assert_eq!(Durability::for_key("stage:current"), Durability::Immediate);
        assert_eq!(
            Durability::for_key("dev_note:dont-refactor"),
            Durability::Immediate
        );
    }

    #[test]
    fn eventual_keys() {
        assert_eq!(
            Durability::for_key("session:1710520800"),
            Durability::Eventual
        );
        assert_eq!(
            Durability::for_key("analytics:tokens_saved_total"),
            Durability::Eventual
        );
        assert_eq!(
            Durability::for_key("hook_event:pre_read"),
            Durability::Eventual
        );
        assert_eq!(
            Durability::for_key("compliance:2026-03-15"),
            Durability::Eventual
        );
    }

    #[test]
    fn unknown_prefix_defaults_to_immediate() {
        assert_eq!(
            Durability::for_key("unknown:something"),
            Durability::Immediate
        );
    }
}
