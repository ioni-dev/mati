//! Write durability levels for the SurrealKV store.
//!
//! **Never mix these.** The split is load-bearing for performance:
//! - `Immediate`: fsync on every write — slow but crash-safe.
//! - `Eventual`: OS write buffer — fast but may lose the last ~10ms on crash.
//!
//! Assignment by key prefix (from ARCHITECTURE.md section 4):
//! ```text
//! Immediate  gotcha:*   decision:*   file:*   stage:*   dev_note:*   policy:*
//! Eventual   session:*  analytics:*  hook_event:*  compliance:*  graph:edge:*
//!            health:*   parse:*      audit:session:*
//! ```
//!
//! `graph:edge:*` is Eventual because edges are derived data (re-computed from
//! source on `mati init`) — they are not irreplaceable like user-authored records.
//! Losing a few edges on an OS crash costs one `mati init` re-run, not lost knowledge.

/// How a key's value is encoded on disk.
///
/// The store keeps two encodings in one flat keyspace and distinguishes them by
/// prefix alone. Mixing them is not a type error, it is a silent one: a raw
/// scalar written into a `Record` namespace is skipped by `scan_prefix` with a
/// warning, and a `Record` written over a raw scalar is unreadable by the
/// getter that expects bytes. `policy:mode` did exactly this, colliding with
/// `policy:<slug>` records so that setting the posture destroyed a policy.
///
/// This table is the invariant. `Store` debug-asserts against it, so a new key
/// in the wrong namespace fails a test run rather than corrupting a store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    /// msgpack-serialized `Record`. Written by `put`, read by `get`/`scan_prefix`.
    Record,
    /// Bare bytes whose meaning is prefix-specific: a timestamp, a counter, a
    /// config scalar, or a JSON blob. Written by `put_raw`, read by
    /// `get_raw_bytes`/`scan_keys`.
    Raw,
}

impl Encoding {
    /// Infer a key's value encoding from its prefix.
    ///
    /// Unknown prefixes default to `Record`, which matches `for_key` defaulting
    /// to `Immediate`: a new knowledge namespace is the common case, and the
    /// assertion below turns a wrong guess into a failing test.
    pub fn for_key(key: &str) -> Self {
        // `system:` is mixed and cannot be classified by prefix:
        // `system:schema_version` is a Record while `system:installation_id` is
        // a raw string. That is the same hazard `policy:mode` had, and it only
        // stays harmless because nothing scans a bare `system:` prefix. The
        // exact-key exception below is the honest encoding of that; splitting
        // the namespace would be cleaner but installation_id shipped in v0.1.3
        // and moving it needs a migration, not a rename.
        if key == "system:installation_id" {
            return Self::Raw;
        }
        if key.starts_with("graph:edge:")
            || key.starts_with("audit:")
            || key.starts_with("enforcement:")
        {
            Self::Raw
        } else {
            Self::Record
        }
    }
}

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
            || key.starts_with("parse:")  // file content hashes — recomputable on re-init
            || key.starts_with("audit:session:")
        // session-side audit — co-located with session mutations
        {
            Self::Eventual
        } else {
            Self::Immediate
        }
    }
}

#[cfg(test)]
mod encoding_tests {
    use super::Encoding;

    #[test]
    fn record_namespaces_are_record_encoded() {
        for key in [
            "gotcha:x",
            "file:src/main.rs",
            "decision:y",
            "dev_note:z",
            "dep:cargo:serde",
            "stage:current",
            "policy:production-query-safety",
            "policy:mode",
            "session:consulted:schema:x",
            "analytics:hit_2026-07-22",
            "health:score",
            "parse:src/main.rs",
            "compliance:miss_2026-07-22",
            "system:schema_version",
        ] {
            assert_eq!(Encoding::for_key(key), Encoding::Record, "{key}");
        }
    }

    #[test]
    fn raw_namespaces_are_raw_encoded() {
        for key in [
            "graph:edge:file:a:imports:file:b",
            "audit:knowledge:1",
            "audit:session:1",
            "enforcement:seq",
            "enforcement:event:00000000000000000001",
            "enforcement:mode",
            "enforcement:policy_mode",
            "enforcement:retention_days",
            "system:installation_id",
        ] {
            assert_eq!(Encoding::for_key(key), Encoding::Raw, "{key}");
        }
    }

    /// The bug this table exists to prevent: a config scalar named into the
    /// policy record namespace. `policy:mode` must read as Record, so writing a
    /// raw posture value there trips the assertion in `Store::put_raw` instead
    /// of silently destroying the policy slugged `mode`.
    #[test]
    fn a_config_scalar_may_not_hide_in_a_record_namespace() {
        assert_eq!(Encoding::for_key("policy:mode"), Encoding::Record);
        assert_eq!(Encoding::for_key("enforcement:policy_mode"), Encoding::Raw);
    }

    /// `system:` is mixed, so it must not be classified by prefix alone.
    #[test]
    fn system_namespace_is_split_by_exact_key() {
        assert_eq!(Encoding::for_key("system:installation_id"), Encoding::Raw);
        assert_eq!(Encoding::for_key("system:schema_version"), Encoding::Record);
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
        assert_eq!(
            Durability::for_key("policy:production-query-safety"),
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
        // Every Immediate prefix listed in ARCHITECTURE.md section 4 must route correctly.
        let cases = [
            "gotcha:inference-async",
            "decision:storage-engine",
            "file:src/store/db.rs",
            "stage:current",
            "dev_note:no-refactor",
            "dep:cargo:tokio",
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

    // ── Audit routing tests ─────────────────────────────────────────────

    #[test]
    fn audit_session_is_eventual() {
        // Session-side audit co-locates with session mutations.
        assert_eq!(
            Durability::for_key("audit:session:1234567890"),
            Durability::Eventual,
            "audit:session:* must route to sessions tree"
        );
    }

    #[test]
    fn audit_knowledge_is_immediate() {
        // Knowledge-side audit co-locates with knowledge mutations.
        // "audit:knowledge:*" does NOT match any Eventual prefix → Immediate.
        assert_eq!(
            Durability::for_key("audit:knowledge:1234567890"),
            Durability::Immediate,
            "audit:knowledge:* must route to knowledge tree"
        );
    }

    #[test]
    fn audit_bare_prefix_is_immediate() {
        // "audit:" alone doesn't match "audit:session:" → Immediate.
        assert_eq!(
            Durability::for_key("audit:something"),
            Durability::Immediate,
            "unknown audit prefix must default to Immediate"
        );
    }
}
