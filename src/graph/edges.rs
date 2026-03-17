use serde::{Deserialize, Serialize};

/// A directed edge between two knowledge graph nodes.
/// Persisted in SurrealKV as `graph:edge:<from>:<kind>:<to>`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Edge {
    pub from: String,
    pub kind: EdgeKind,
    pub to: String,
}

impl Edge {
    pub fn new(from: impl Into<String>, kind: EdgeKind, to: impl Into<String>) -> Self {
        Edge { from: from.into(), kind, to: to.into() }
    }

    /// Encode to the SurrealKV key format: `graph:edge:<from>:<kind>:<to>`.
    pub fn to_key(&self) -> String {
        format!("graph:edge:{}:{}:{}", self.from, self.kind.as_key_segment(), self.to)
    }

    /// Parse an edge back from a `graph:edge:...` key.
    ///
    /// `from` and `to` may contain colons (e.g. `file:src/main.rs`), so the
    /// parser scans for kind segments left-to-right and validates that the
    /// candidate `from` value starts with a known node-key namespace. This
    /// prevents false matches when a slug itself equals a kind name (e.g.
    /// `gotcha:touched`).
    pub fn from_key(key: &str) -> Option<Self> {
        let rest = key.strip_prefix("graph:edge:")?;
        let segments: Vec<&str> = rest.split(':').collect();
        for kind_idx in 1..segments.len().saturating_sub(1) {
            if let Some(kind) = EdgeKind::from_key_segment(segments[kind_idx]) {
                let from = segments[..kind_idx].join(":");
                let to   = segments[kind_idx + 1..].join(":");
                if !from.is_empty() && !to.is_empty() && is_valid_node_key(&from) {
                    return Some(Edge { from, kind, to });
                }
            }
        }
        None
    }
}

/// Validates that a candidate `from` value starts with a recognised node-key
/// namespace prefix. This is the primary guard against ambiguous parses.
fn is_valid_node_key(key: &str) -> bool {
    const NAMESPACES: &[&str] = &[
        "file", "gotcha", "decision", "stage", "dep",
        "dev_note", "session", "analytics", "graph",
    ];
    NAMESPACES.iter().any(|ns| {
        key.starts_with(ns)
            && key[ns.len()..].starts_with(':')
            && key.len() > ns.len() + 1  // require at least one char after the colon
    })
}

/// The 10 relationship kinds that can exist between nodes in the knowledge graph.
/// Stored in SurrealKV as part of the key: `graph:edge:<from>:<kind>:<to>`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeKind {
    /// A file node has a gotcha record attached to it.
    HasGotcha,
    /// A file imports another file (from static analysis).
    Imports,
    /// A file or gotcha is affected by an architectural decision.
    AffectedBy,
    /// A file or record has a developer note attached.
    HasNote,
    /// A gotcha or decision was discovered in a specific session.
    DiscoveredIn,
    /// One gotcha or issue was caused by another.
    CausedBy,
    /// A decision or gotcha supersedes an older one.
    Supersedes,
    /// A file was touched in a session (passive learning).
    Touched,
    /// A dependency change affects a file or module.
    DependencyAffects,
    /// Two files are frequently committed together (git co-change).
    CoChanges,
}

impl EdgeKind {
    /// Canonical slug used as the key segment, e.g. `has_gotcha`.
    pub fn as_key_segment(&self) -> &'static str {
        match self {
            EdgeKind::HasGotcha        => "has_gotcha",
            EdgeKind::Imports          => "imports",
            EdgeKind::AffectedBy       => "affected_by",
            EdgeKind::HasNote          => "has_note",
            EdgeKind::DiscoveredIn     => "discovered_in",
            EdgeKind::CausedBy         => "caused_by",
            EdgeKind::Supersedes       => "supersedes",
            EdgeKind::Touched          => "touched",
            EdgeKind::DependencyAffects => "dependency_affects",
            EdgeKind::CoChanges        => "co_changes",
        }
    }

    /// Parse a key segment back into an `EdgeKind`.
    pub fn from_key_segment(s: &str) -> Option<Self> {
        match s {
            "has_gotcha"         => Some(EdgeKind::HasGotcha),
            "imports"            => Some(EdgeKind::Imports),
            "affected_by"        => Some(EdgeKind::AffectedBy),
            "has_note"           => Some(EdgeKind::HasNote),
            "discovered_in"      => Some(EdgeKind::DiscoveredIn),
            "caused_by"          => Some(EdgeKind::CausedBy),
            "supersedes"         => Some(EdgeKind::Supersedes),
            "touched"            => Some(EdgeKind::Touched),
            "dependency_affects" => Some(EdgeKind::DependencyAffects),
            "co_changes"         => Some(EdgeKind::CoChanges),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use super::*;

    #[test]
    fn all_variants_have_a_key_segment() {
        for v in all_variants() {
            assert!(!v.as_key_segment().is_empty(), "{v:?} key segment is empty");
        }
    }

    #[test]
    fn key_segment_roundtrip_all_variants() {
        for v in all_variants() {
            let seg = v.as_key_segment();
            let parsed = EdgeKind::from_key_segment(seg)
                .unwrap_or_else(|| panic!("failed to parse segment '{seg}' for {v:?}"));
            assert_eq!(v, parsed);
        }
    }

    #[test]
    fn unknown_segment_returns_none() {
        assert!(EdgeKind::from_key_segment("nonexistent").is_none());
        assert!(EdgeKind::from_key_segment("").is_none());
    }

    #[test]
    fn key_segments_are_all_distinct() {
        let segments: HashSet<&str> = all_variants().iter().map(|v| v.as_key_segment()).collect();
        assert_eq!(segments.len(), 10, "duplicate key segments detected");
    }

    // ── Edge key encode/decode ───────────────────────────────────────────────

    #[test]
    fn edge_to_key_format() {
        let e = Edge::new("file:src/main.rs", EdgeKind::HasGotcha, "gotcha:write-txn");
        assert_eq!(e.to_key(), "graph:edge:file:src/main.rs:has_gotcha:gotcha:write-txn");
    }

    #[test]
    fn edge_from_key_roundtrip_simple() {
        let e = Edge::new("file:src/main.rs", EdgeKind::HasGotcha, "gotcha:write-txn");
        assert_eq!(Edge::from_key(&e.to_key()).unwrap(), e);
    }

    #[test]
    fn edge_from_key_roundtrip_all_kinds() {
        for kind in all_variants() {
            let e = Edge::new("file:src/a.rs", kind, "file:src/b.rs");
            let key = e.to_key();
            let parsed = Edge::from_key(&key)
                .unwrap_or_else(|| panic!("failed to parse key '{key}'"));
            assert_eq!(parsed, e);
        }
    }

    #[test]
    fn edge_from_key_invalid_returns_none() {
        assert!(Edge::from_key("not-an-edge-key").is_none());
        assert!(Edge::from_key("graph:edge:").is_none());
        assert!(Edge::from_key("graph:edge:from_only").is_none());
        assert!(Edge::from_key("").is_none());
    }

    /// `from` with a valid namespace but empty slug ("file:") must be rejected.
    /// Without the slug-length guard the parser would accept it, producing a
    /// broken `from` value that can never match a real stored record.
    #[test]
    fn edge_from_key_empty_slug_rejected() {
        // from="file:" — namespace present, slug empty
        // key: "graph:edge:file::has_gotcha:gotcha:x"
        let key = "graph:edge:file::has_gotcha:gotcha:x";
        assert!(
            Edge::from_key(key).is_none(),
            "empty slug must not be accepted as a valid from value"
        );
    }

    /// Keys whose from/to use an unknown namespace must return None — the parser
    /// has no way to locate the kind boundary reliably without a known prefix.
    #[test]
    fn edge_from_key_unknown_namespace_returns_none() {
        // Neither "unknown_ns" nor "xyz" is a recognised namespace.
        let key = "graph:edge:unknown_ns:foo:has_gotcha:xyz:bar";
        assert!(
            Edge::from_key(key).is_none(),
            "unknown namespace must not be accepted"
        );
    }

    #[test]
    fn edge_key_prefix_is_graph_edge() {
        let e = Edge::new("file:a", EdgeKind::Imports, "file:b");
        assert!(e.to_key().starts_with("graph:edge:"));
    }

    /// Regression: slug that exactly matches a kind name must not confuse the parser.
    #[test]
    fn edge_from_key_slug_matches_kind_name() {
        // "touched" is both a valid gotcha slug and a kind segment name.
        let e = Edge::new("gotcha:touched", EdgeKind::HasGotcha, "gotcha:x");
        let key = e.to_key();
        // key = "graph:edge:gotcha:touched:has_gotcha:gotcha:x"
        // Without namespace validation the parser would greedily pick "touched"
        // as the kind, returning from="gotcha" (invalid). The fix rejects that
        // because "gotcha" alone is not a valid node key (no namespace colon).
        let parsed = Edge::from_key(&key)
            .unwrap_or_else(|| panic!("failed to parse key '{key}'"));
        assert_eq!(parsed, e);
    }

    /// `to` slug is a kind name — parser must not greedily pick it as the kind boundary.
    #[test]
    fn edge_from_key_to_slug_matches_kind_name() {
        // to = "gotcha:imports" — slug "imports" is also a kind segment.
        let e = Edge::new("file:a", EdgeKind::HasGotcha, "gotcha:imports");
        let key = e.to_key();
        // key = "graph:edge:file:a:has_gotcha:gotcha:imports"
        // segments = ["file", "a", "has_gotcha", "gotcha", "imports"]
        // kind_idx=2 -> "has_gotcha", from="file:a" (valid), to="gotcha:imports" ✓
        let parsed = Edge::from_key(&key).unwrap_or_else(|| panic!("failed to parse '{key}'"));
        assert_eq!(parsed, e);
    }

    /// Both `from` and `to` slugs are kind names — ambiguity on both ends.
    #[test]
    fn edge_from_key_both_slugs_match_kind_names() {
        // from="gotcha:touched", to="gotcha:imports", kind=AffectedBy
        let e = Edge::new("gotcha:touched", EdgeKind::AffectedBy, "gotcha:imports");
        let key = e.to_key();
        // key = "graph:edge:gotcha:touched:affected_by:gotcha:imports"
        // segments = ["gotcha", "touched", "affected_by", "gotcha", "imports"]
        // kind_idx=1 -> "touched" IS a kind, but from="gotcha" fails is_valid_node_key → skip
        // kind_idx=2 -> "affected_by" IS a kind, from="gotcha:touched" is valid ✓
        let parsed = Edge::from_key(&key).unwrap_or_else(|| panic!("failed to parse '{key}'"));
        assert_eq!(parsed, e);
    }

    /// `to` contains multiple colons — the parser must join all remaining segments.
    #[test]
    fn edge_from_key_to_has_multiple_colons() {
        // Unusual but possible: to="decision:auth:v2" (slug with colon).
        let e = Edge::new("file:src/main.rs", EdgeKind::AffectedBy, "decision:auth:v2");
        let key = e.to_key();
        let parsed = Edge::from_key(&key).unwrap_or_else(|| panic!("failed to parse '{key}'"));
        assert_eq!(parsed, e);
    }

    /// `from` contains multiple colons beyond the namespace separator.
    #[test]
    fn edge_from_key_from_has_multiple_colons() {
        let e = Edge::new("dep:tokio:1.40", EdgeKind::DependencyAffects, "file:src/main.rs");
        let key = e.to_key();
        let parsed = Edge::from_key(&key).unwrap_or_else(|| panic!("failed to parse '{key}'"));
        assert_eq!(parsed, e);
    }

    #[test]
    fn serde_roundtrip() {
        for v in all_variants() {
            let json = serde_json::to_string(&v).unwrap();
            let back: EdgeKind = serde_json::from_str(&json).unwrap();
            assert_eq!(v, back);
        }
    }

    fn all_variants() -> [EdgeKind; 10] {
        [
            EdgeKind::HasGotcha,
            EdgeKind::Imports,
            EdgeKind::AffectedBy,
            EdgeKind::HasNote,
            EdgeKind::DiscoveredIn,
            EdgeKind::CausedBy,
            EdgeKind::Supersedes,
            EdgeKind::Touched,
            EdgeKind::DependencyAffects,
            EdgeKind::CoChanges,
        ]
    }
}
