//! C enrichment-signal extractor.
//!
//! HIGH: `abort()`, `exit(...)`, `raise(...)`, `__builtin_trap()`, `assert(...)`
//! MEDIUM: `// nolint`, `#pragma warning(disable ...)` via shared scanner

use std::cell::RefCell;
use std::sync::LazyLock;

use anyhow::Result;

use super::{comments, Signal, SignalKind, SignalTier};
use crate::analysis::walker::Language;

static C_LANGUAGE: LazyLock<tree_sitter::Language> =
    LazyLock::new(|| tree_sitter_c::LANGUAGE.into());

const C_QUERY_SRC: &str = r#"
  (call_expression function: (identifier) @panic_fn
    (#match? @panic_fn "^(abort|exit|raise|__builtin_trap|_Exit)$")) @panic
  (call_expression function: (identifier) @assert_fn
    (#match? @assert_fn "^(assert|static_assert)$")) @assert
  (comment) @comment
"#;

static C_QUERY: LazyLock<tree_sitter::Query> = LazyLock::new(|| {
    tree_sitter::Query::new(&C_LANGUAGE, C_QUERY_SRC).expect("enrich_signals/c: invalid query")
});

thread_local! {
    static C_PARSER: RefCell<tree_sitter::Parser> = RefCell::new({
        let mut p = tree_sitter::Parser::new();
        p.set_language(&C_LANGUAGE).expect("enrich_signals/c: grammar load failed");
        p
    });
}

pub fn extract(source: &str) -> Result<Vec<Signal>> {
    let tree = C_PARSER.with(|p| {
        let mut parser = p.borrow_mut();
        parser
            .parse(source.as_bytes(), None)
            .ok_or_else(|| anyhow::anyhow!("enrich_signals/c: parse returned None"))
    })?;
    let bytes = source.as_bytes();
    let mut out: Vec<Signal> = Vec::new();
    let mut cursor = tree_sitter::QueryCursor::new();
    let cap = |n: &str| C_QUERY.capture_index_for_name(n).unwrap_or(u32::MAX);
    let (i_panic, i_assert, i_comment) = (cap("panic"), cap("assert"), cap("comment"));

    for m in cursor.matches(&C_QUERY, tree.root_node(), bytes) {
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
                    comments::scan_linter_disable(&evidence, line, Language::C)
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
    fn detects_abort_exit_assert() {
        let src = "
            #include <stdlib.h>
            void f(int x) {
                assert(x > 0);
                if (x == 0) abort();
                exit(1);
            }
        ";
        let signals = extract(src).unwrap();
        assert!(signals.iter().any(|s| s.kind == SignalKind::Assert));
        let panics: Vec<_> = signals
            .iter()
            .filter(|s| s.kind == SignalKind::Panic)
            .collect();
        assert!(panics.len() >= 2, "abort + exit; got {panics:?}");
    }
}
