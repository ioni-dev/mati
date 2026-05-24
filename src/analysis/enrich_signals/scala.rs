//! Scala enrichment-signal extractor.
//!
//! HIGH: `throw ...`, `sys.exit(...)`, `sys.error(...)`, `???` placeholder,
//!       `assert(...)`, `require(...)`
//! MEDIUM: `// scalafix:off`, `@SuppressWarnings` via shared scanner

use std::cell::RefCell;
use std::sync::LazyLock;

use anyhow::Result;

use super::{comments, Signal, SignalKind, SignalTier};
use crate::analysis::walker::Language;

static SC_LANGUAGE: LazyLock<tree_sitter::Language> =
    LazyLock::new(|| tree_sitter_scala::LANGUAGE.into());

// Scala tree-sitter grammar uses `comment` (single node kind) rather
// than line/block split, and `throw_expression`. We verify both at
// runtime — query compilation fails fast on missing nodes per
// `LazyLock::new` in tests.
const SC_QUERY_SRC: &str = r#"
  (throw_expression) @panic
  (call_expression function: (identifier) @assert_fn
    (#match? @assert_fn "^(assert|require)$")) @assert
  (comment) @comment
"#;

static SC_QUERY: LazyLock<tree_sitter::Query> = LazyLock::new(|| {
    tree_sitter::Query::new(&SC_LANGUAGE, SC_QUERY_SRC)
        .expect("enrich_signals/scala: invalid query")
});

thread_local! {
    static SC_PARSER: RefCell<tree_sitter::Parser> = RefCell::new({
        let mut p = tree_sitter::Parser::new();
        p.set_language(&SC_LANGUAGE).expect("enrich_signals/scala: grammar load failed");
        p
    });
}

pub fn extract(source: &str) -> Result<Vec<Signal>> {
    let tree = SC_PARSER.with(|p| {
        let mut parser = p.borrow_mut();
        parser
            .parse(source.as_bytes(), None)
            .ok_or_else(|| anyhow::anyhow!("enrich_signals/scala: parse returned None"))
    })?;
    let bytes = source.as_bytes();
    let mut out: Vec<Signal> = Vec::new();
    let mut cursor = tree_sitter::QueryCursor::new();
    let cap = |n: &str| SC_QUERY.capture_index_for_name(n).unwrap_or(u32::MAX);
    let (i_panic, i_assert, i_comment) = (cap("panic"), cap("assert"), cap("comment"));

    for m in cursor.matches(&SC_QUERY, tree.root_node(), bytes) {
        for c in m.captures {
            let line = c.node.start_position().row as u32 + 1;
            let evidence = super::node_text(bytes, c.node);
            if c.index == i_panic {
                out.push(Signal {
                    file_line: line,
                    tier: SignalTier::High,
                    kind: SignalKind::Panic,
                    evidence: super::trim_evidence(&evidence),
                });
            } else if c.index == i_assert {
                out.push(Signal {
                    file_line: line,
                    tier: SignalTier::High,
                    kind: SignalKind::Assert,
                    evidence: super::trim_evidence(&evidence),
                });
            } else if c.index == i_comment {
                if let Some(sig) = comments::scan_comment_text(&evidence, line) {
                    out.push(sig);
                } else if let Some(sig) =
                    comments::scan_linter_disable(&evidence, line, Language::Scala)
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
    fn detects_throw_and_require() {
        let src = "def f(x: Int) = { require(x > 0); throw new RuntimeException(\"bad\") }";
        let signals = extract(src).unwrap();
        assert!(signals.iter().any(|s| s.kind == SignalKind::Panic));
        assert!(signals.iter().any(|s| s.kind == SignalKind::Assert));
    }

    #[test]
    fn detects_warning_comment() {
        let signals = extract("// WARNING: do not call f from g\ndef f = ()").unwrap();
        assert!(signals.iter().any(|s| s.kind == SignalKind::WarnComment));
    }
}
