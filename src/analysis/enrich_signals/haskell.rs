//! Haskell enrichment-signal extractor.
//!
//! HIGH:   `error ...`, `undefined`, `fail ...`, `assert ...`, `panic ...`
//!         (panic isn't builtin but ghc-extras / pkgs use it)
//! MEDIUM: `{-# OPTIONS_GHC -W ... #-}`, `-- hlint: ignore` via shared scanner
//!
//! Haskell's tree-sitter grammar treats function calls as `apply` of an
//! `variable` head. We match on the variable identifier names.

use std::cell::RefCell;
use std::sync::LazyLock;

use anyhow::Result;

use super::{comments, Signal, SignalKind, SignalTier};
use crate::analysis::walker::Language;

static HS_LANGUAGE: LazyLock<tree_sitter::Language> =
    LazyLock::new(|| tree_sitter_haskell::LANGUAGE.into());

const HS_QUERY_SRC: &str = r#"
  (variable) @id
  (comment) @comment
"#;

static HS_QUERY: LazyLock<tree_sitter::Query> = LazyLock::new(|| {
    tree_sitter::Query::new(&HS_LANGUAGE, HS_QUERY_SRC)
        .expect("enrich_signals/haskell: invalid query")
});

thread_local! {
    static HS_PARSER: RefCell<tree_sitter::Parser> = RefCell::new({
        let mut p = tree_sitter::Parser::new();
        p.set_language(&HS_LANGUAGE).expect("enrich_signals/haskell: grammar load failed");
        p
    });
}

const PANIC_IDS: &[&str] = &["error", "undefined", "fail", "panic"];
const ASSERT_IDS: &[&str] = &["assert"];

pub fn extract(source: &str) -> Result<Vec<Signal>> {
    let tree = HS_PARSER.with(|p| {
        let mut parser = p.borrow_mut();
        parser
            .parse(source.as_bytes(), None)
            .ok_or_else(|| anyhow::anyhow!("enrich_signals/haskell: parse returned None"))
    })?;
    let bytes = source.as_bytes();
    let mut out: Vec<Signal> = Vec::new();
    let mut cursor = tree_sitter::QueryCursor::new();
    let cap = |n: &str| HS_QUERY.capture_index_for_name(n).unwrap_or(u32::MAX);
    let (i_id, i_comment) = (cap("id"), cap("comment"));

    // Haskell's tree-sitter grammar matches `variable` nodes on every
    // identifier reference, not just function-call heads. We filter to
    // identifiers whose name matches our panic/assert lists.

    for m in cursor.matches(&HS_QUERY, tree.root_node(), bytes) {
        for c in m.captures {
            let line = c.node.start_position().row as u32 + 1;
            let evidence = super::node_text(bytes, c.node);

            if c.index == i_id {
                let name = evidence.trim();
                if PANIC_IDS.contains(&name) {
                    out.push(Signal {
                        file_line: line,
                        tier: SignalTier::High,
                        kind: SignalKind::Panic,
                        evidence: super::trim_evidence(&evidence),
                    });
                } else if ASSERT_IDS.contains(&name) {
                    out.push(Signal {
                        file_line: line,
                        tier: SignalTier::High,
                        kind: SignalKind::Assert,
                        evidence: super::trim_evidence(&evidence),
                    });
                }
            } else if c.index == i_comment {
                if let Some(sig) = comments::scan_comment_text(&evidence, line) {
                    out.push(sig);
                } else if let Some(sig) =
                    comments::scan_linter_disable(&evidence, line, Language::Haskell)
                {
                    out.push(sig);
                }
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_error_and_undefined() {
        let src = "foo :: Int -> Int\nfoo x = error \"bad\"\nbar = undefined\n";
        let signals = extract(src).unwrap();
        let panics: Vec<_> = signals
            .iter()
            .filter(|s| s.kind == SignalKind::Panic)
            .collect();
        assert!(panics.len() >= 2);
    }

    #[test]
    fn detects_warning_comment() {
        let signals = extract("-- WARNING: foo is partial\nfoo = undefined").unwrap();
        // Both panic (from `undefined`) and WarnComment should be present.
        assert!(signals.iter().any(|s| s.kind == SignalKind::WarnComment));
        assert!(signals.iter().any(|s| s.kind == SignalKind::Panic));
    }
}
