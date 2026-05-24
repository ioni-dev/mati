//! TypeScript enrichment-signal extractor.
//!
//! HIGH: `throw ...`, `assert(...)` / `console.assert(...)`
//! MEDIUM: `@ts-ignore`, `eslint-disable`, `@ts-expect-error` via shared scanner

use std::cell::RefCell;
use std::sync::LazyLock;

use anyhow::Result;

use super::{comments, Signal, SignalKind, SignalTier};
use crate::analysis::walker::Language;

static TS_LANGUAGE: LazyLock<tree_sitter::Language> =
    LazyLock::new(|| tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into());

const TS_QUERY_SRC: &str = r#"
  (throw_statement) @panic
  (call_expression function: (identifier) @assert_fn
    (#eq? @assert_fn "assert")) @assert
  (call_expression function: (member_expression
    object: (identifier) @console
    property: (property_identifier) @method)
    (#eq? @console "console") (#eq? @method "assert")) @assert
  (comment) @comment
"#;

static TS_QUERY: LazyLock<tree_sitter::Query> = LazyLock::new(|| {
    tree_sitter::Query::new(&TS_LANGUAGE, TS_QUERY_SRC)
        .expect("enrich_signals/typescript: invalid query")
});

thread_local! {
    static TS_PARSER: RefCell<tree_sitter::Parser> = RefCell::new({
        let mut p = tree_sitter::Parser::new();
        p.set_language(&TS_LANGUAGE).expect("enrich_signals/typescript: grammar load failed");
        p
    });
}

pub fn extract(source: &str) -> Result<Vec<Signal>> {
    let tree = TS_PARSER.with(|p| {
        let mut parser = p.borrow_mut();
        parser
            .parse(source.as_bytes(), None)
            .ok_or_else(|| anyhow::anyhow!("enrich_signals/typescript: parse returned None"))
    })?;
    let bytes = source.as_bytes();
    let mut out: Vec<Signal> = Vec::new();
    let mut cursor = tree_sitter::QueryCursor::new();
    let cap = |n: &str| TS_QUERY.capture_index_for_name(n).unwrap_or(u32::MAX);
    let (i_panic, i_assert, i_comment) = (cap("panic"), cap("assert"), cap("comment"));

    for m in cursor.matches(&TS_QUERY, tree.root_node(), bytes) {
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
                    comments::scan_linter_disable(&evidence, line, Language::TypeScript)
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
    fn detects_throw() {
        let signals = extract("function f() { throw new Error('bad'); }").unwrap();
        assert!(signals.iter().any(|s| s.kind == SignalKind::Panic));
    }

    #[test]
    fn detects_console_assert() {
        let signals = extract("console.assert(x > 0, 'positive');").unwrap();
        assert!(signals.iter().any(|s| s.kind == SignalKind::Assert));
    }

    #[test]
    fn detects_ts_ignore_comment() {
        let signals = extract("// @ts-ignore — fix later\nconst x: any = 1;").unwrap();
        assert!(signals.iter().any(|s| s.kind == SignalKind::LinterDisable));
    }
}
