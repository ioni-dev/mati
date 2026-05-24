//! Ruby enrichment-signal extractor.
//!
//! HIGH: `raise ...`, `fail ...`, `abort(...)`, `exit(...)`
//! MEDIUM: `# rubocop:disable`, `# rubocop:todo` via shared scanner

use std::cell::RefCell;
use std::sync::LazyLock;

use anyhow::Result;

use super::{comments, Signal, SignalKind, SignalTier};
use crate::analysis::walker::Language;

static RB_LANGUAGE: LazyLock<tree_sitter::Language> =
    LazyLock::new(|| tree_sitter_ruby::LANGUAGE.into());

// Ruby grammar treats `raise X` as a `call` node with method=raise.
// We match both `raise`/`fail` and call expressions to `abort`/`exit`.
const RB_QUERY_SRC: &str = r#"
  (call method: (identifier) @panic_fn
    (#match? @panic_fn "^(raise|fail|abort|exit)$")) @panic
  (comment) @comment
"#;

static RB_QUERY: LazyLock<tree_sitter::Query> = LazyLock::new(|| {
    tree_sitter::Query::new(&RB_LANGUAGE, RB_QUERY_SRC)
        .expect("enrich_signals/ruby: invalid query")
});

thread_local! {
    static RB_PARSER: RefCell<tree_sitter::Parser> = RefCell::new({
        let mut p = tree_sitter::Parser::new();
        p.set_language(&RB_LANGUAGE).expect("enrich_signals/ruby: grammar load failed");
        p
    });
}

pub fn extract(source: &str) -> Result<Vec<Signal>> {
    let tree = RB_PARSER.with(|p| {
        let mut parser = p.borrow_mut();
        parser
            .parse(source.as_bytes(), None)
            .ok_or_else(|| anyhow::anyhow!("enrich_signals/ruby: parse returned None"))
    })?;
    let bytes = source.as_bytes();
    let mut out: Vec<Signal> = Vec::new();
    let mut cursor = tree_sitter::QueryCursor::new();
    let cap = |n: &str| RB_QUERY.capture_index_for_name(n).unwrap_or(u32::MAX);
    let (i_panic, i_comment) = (cap("panic"), cap("comment"));

    for m in cursor.matches(&RB_QUERY, tree.root_node(), bytes) {
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
            } else if c.index == i_comment {
                if let Some(sig) = comments::scan_comment_text(&evidence, line) {
                    out.push(sig);
                } else if let Some(sig) =
                    comments::scan_linter_disable(&evidence, line, Language::Ruby)
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
    fn detects_raise_and_fail() {
        let signals = extract("def f(x); raise ArgumentError if x.nil?; fail 'bad'; end").unwrap();
        let panics: Vec<_> = signals
            .iter()
            .filter(|s| s.kind == SignalKind::Panic)
            .collect();
        assert!(panics.len() >= 2);
    }

    #[test]
    fn detects_rubocop_disable() {
        let src = "# rubocop:disable Metrics/MethodLength\ndef f; end";
        let signals = extract(src).unwrap();
        assert!(signals.iter().any(|s| s.kind == SignalKind::LinterDisable));
    }
}
