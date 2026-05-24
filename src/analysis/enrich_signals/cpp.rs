//! C++ enrichment-signal extractor.
//!
//! HIGH: `throw ...`, `abort()`, `exit(...)`, `std::terminate(...)`,
//!       `assert(...)`, `static_assert(...)`
//! MEDIUM: `// NOLINT`, `#pragma warning(disable ...)` via shared scanner

use std::cell::RefCell;
use std::sync::LazyLock;

use anyhow::Result;

use super::{comments, Signal, SignalKind, SignalTier};
use crate::analysis::walker::Language;

static CPP_LANGUAGE: LazyLock<tree_sitter::Language> =
    LazyLock::new(|| tree_sitter_cpp::LANGUAGE.into());

// C++ tree-sitter grammar uses `throw_statement` for `throw X;`
// (not `throw_expression`). Identifier calls match generically via
// the C dialect's `call_expression`.
const CPP_QUERY_SRC: &str = r#"
  (throw_statement) @panic
  (call_expression function: (identifier) @panic_fn
    (#match? @panic_fn "^(abort|exit|_Exit|__builtin_trap|terminate)$")) @panic
  (call_expression function: (identifier) @assert_fn
    (#match? @assert_fn "^(assert|static_assert)$")) @assert
  (comment) @comment
"#;

static CPP_QUERY: LazyLock<tree_sitter::Query> = LazyLock::new(|| {
    tree_sitter::Query::new(&CPP_LANGUAGE, CPP_QUERY_SRC)
        .expect("enrich_signals/cpp: invalid query")
});

thread_local! {
    static CPP_PARSER: RefCell<tree_sitter::Parser> = RefCell::new({
        let mut p = tree_sitter::Parser::new();
        p.set_language(&CPP_LANGUAGE).expect("enrich_signals/cpp: grammar load failed");
        p
    });
}

pub fn extract(source: &str) -> Result<Vec<Signal>> {
    let tree = CPP_PARSER.with(|p| {
        let mut parser = p.borrow_mut();
        parser
            .parse(source.as_bytes(), None)
            .ok_or_else(|| anyhow::anyhow!("enrich_signals/cpp: parse returned None"))
    })?;
    let bytes = source.as_bytes();
    let mut out: Vec<Signal> = Vec::new();
    let mut cursor = tree_sitter::QueryCursor::new();
    let cap = |n: &str| CPP_QUERY.capture_index_for_name(n).unwrap_or(u32::MAX);
    let (i_panic, i_assert, i_comment) = (cap("panic"), cap("assert"), cap("comment"));

    for m in cursor.matches(&CPP_QUERY, tree.root_node(), bytes) {
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
                    comments::scan_linter_disable(&evidence, line, Language::Cpp)
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
    fn detects_throw_and_assert() {
        let src = "void f(int x) { assert(x > 0); throw std::runtime_error(\"bad\"); }";
        let signals = extract(src).unwrap();
        assert!(signals.iter().any(|s| s.kind == SignalKind::Panic));
        assert!(signals.iter().any(|s| s.kind == SignalKind::Assert));
    }

    #[test]
    fn detects_abort_call() {
        let signals = extract("void f() { abort(); }").unwrap();
        assert!(signals
            .iter()
            .any(|s| s.kind == SignalKind::Panic && s.evidence.contains("abort")));
    }
}
