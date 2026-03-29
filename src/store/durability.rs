//! Write durability levels for the SurrealKV store.
//!
//! **Never mix these.** The split is load-bearing for performance:
//! - `Immediate`: fsync on every write — slow but crash-safe.
//! - `Eventual`: OS write buffer — fast but may lose the last ~10ms on crash.
//!
//! Assignment by key prefix (from ARCHITECTURE.md §4):
//! ```text
//! Immediate  gotcha:*   decision:*   file:*   stage:*   dev_note:*
//! Eventual   session:*  analytics:*  hook_event:*  compliance:*  graph:edge:*
//! ```
//!
//! `graph:edge:*` is Eventual because edges are derived data (re-computed from
//! source on `mati init`) — they are not irreplaceable like user-authored records.
//! Losing a few edges on an OS crash costs one `mati init` re-run, not lost knowledge.

/// Controls whether a `Store::put` call fsyncs before returning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Durability {
    /// fsync after write. Use for all user-visible knowledge records.
    /// Correct for: `gotcha:*`, `decision:*`, `file:*`, `stage:*`, `dev_note:*`.
    Immediate,
    /// OS write buffer only. Fast path for high-frequency internal writes.
    /// Correct for: `session:*`, `analytics:*`, `hook_event:*`, `compliance:*`, `graph:edge:*`.
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
            || key.starts_with("graph:edge:")
            || key.starts_with("health:") // derived/computed data, fully recomputable
            || key.starts_with("parse:")
        // file content hashes — recomputable on re-init
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

    // ── Key shape edge cases ─────────────────────────────────────────────────

    #[test]
    fn graph_edge_key_is_eventual() {
        // Edges are derived data — Eventual so bulk init avoids per-edge fsyncs.
        assert_eq!(
            Durability::for_key("graph:edge:src/main.rs:HasGotcha:gotcha:inference-async"),
            Durability::Eventual
        );
    }

    #[test]
    fn empty_key_defaults_to_immediate() {
        // Empty string matches no eventual prefix → safe fallback.
        assert_eq!(Durability::for_key(""), Durability::Immediate);
    }

    #[test]
    fn key_without_colon_defaults_to_immediate() {
        // A bare word with no colon cannot match any "prefix:" pattern.
        assert_eq!(Durability::for_key("gotcha"), Durability::Immediate);
        assert_eq!(Durability::for_key("session"), Durability::Immediate);
    }

    #[test]
    fn prefix_only_eventual_keys_are_eventual() {
        // The bare prefix (no timestamp/slug suffix) still routes correctly.
        assert_eq!(Durability::for_key("session:"), Durability::Eventual);
        assert_eq!(Durability::for_key("analytics:"), Durability::Eventual);
        assert_eq!(Durability::for_key("hook_event:"), Durability::Eventual);
        assert_eq!(Durability::for_key("compliance:"), Durability::Eventual);
    }

    #[test]
    fn all_immediate_prefixes_from_architecture_doc() {
        // Every Immediate prefix listed in ARCHITECTURE.md §4 must route correctly.
        let cases = [
            "gotcha:inference-async",
            "decision:storage-engine",
            "file:src/store/db.rs",
            "stage:current",
            "dev_note:no-refactor",
            "dep:tokio",
        ];
        for key in cases {
            assert_eq!(
                Durability::for_key(key),
                Durability::Immediate,
                "expected Immediate for '{key}'"
            );
        }
    }

    #[test]
    fn eventual_prefix_requires_exact_colon_boundary() {
        // "session_v2:x" starts with "session" but NOT "session:" → Immediate.
        // This guards against accidental prefix collision with future namespaces.
        assert_eq!(
            Durability::for_key("session_v2:something"),
            Durability::Immediate
        );
        assert_eq!(
            Durability::for_key("analytics_v2:something"),
            Durability::Immediate
        );
        assert_eq!(
            Durability::for_key("hook_event_extra:x"),
            Durability::Immediate
        );
    }

    #[test]
    fn all_eventual_prefixes_from_architecture_doc() {
        let cases = [
            "session:1710520800",
            "analytics:tokens_saved_total",
            "hook_event:pre_read",
            "compliance:2026-03-15",
            "graph:edge:file:src/main.rs:imports:file:src/lib.rs",
        ];
        for key in cases {
            assert_eq!(
                Durability::for_key(key),
                Durability::Eventual,
                "expected Eventual for '{key}'"
            );
        }
    }

    #[test]
    fn key_containing_eventual_prefix_as_embedded_substring_is_immediate() {
        // "gotcha:session:something" contains "session:" but does NOT start_with it.
        // Must route to Immediate (knowledge tree), not Eventual (sessions tree).
        assert_eq!(
            Durability::for_key("gotcha:session:something"),
            Durability::Immediate,
            "embedded 'session:' must not trigger Eventual routing"
        );
        assert_eq!(
            Durability::for_key("file:analytics:performance.rs"),
            Durability::Immediate,
            "embedded 'analytics:' must not trigger Eventual routing"
        );
        assert_eq!(
            Durability::for_key("decision:hook_event:design"),
            Durability::Immediate,
            "embedded 'hook_event:' must not trigger Eventual routing"
        );
    }
}
