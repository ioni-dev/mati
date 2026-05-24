//! JavaScript enrichment-signal extractor (same shape as TS but uses
//! tree-sitter-javascript so plain .js / .mjs / .cjs files parse).
//!
//! HIGH: `throw ...`, `console.assert(...)`, `assert(...)`
//! MEDIUM: `eslint-disable`, `@ts-ignore` (allowed in JSDoc), prettier-ignore

use std::cell::RefCell;
use std::sync::LazyLock;

use anyhow::Result;

use super::{comments, Signal, SignalKind, SignalTier};
use crate::analysis::walker::Language;

static JS_LANGUAGE: LazyLock<tree_sitter::Language> =
    LazyLock::new(|| tree_sitter_javascript::LANGUAGE.into());

const JS_QUERY_SRC: &str = r#"
  (throw_statement) @panic
  (call_expression function: (identifier) @assert_fn
    (#eq? @assert_fn "assert")) @assert
  (call_expression function: (member_expression
    object: (identifier) @console
    property: (property_identifier) @method)
    (#eq? @console "console") (#eq? @method "assert")) @assert
  (comment) @comment
"#;

static JS_QUERY: LazyLock<tree_sitter::Query> = LazyLock::new(|| {
    tree_sitter::Query::new(&JS_LANGUAGE, JS_QUERY_SRC)
        .expect("enrich_signals/javascript: invalid query")
});

thread_local! {
    static JS_PARSER: RefCell<tree_sitter::Parser> = RefCell::new({
        let mut p = tree_sitter::Parser::new();
        p.set_language(&JS_LANGUAGE).expect("enrich_signals/javascript: grammar load failed");
        p
    });
}

pub fn extract(source: &str) -> Result<Vec<Signal>> {
    let tree = JS_PARSER.with(|p| {
        let mut parser = p.borrow_mut();
        parser
            .parse(source.as_bytes(), None)
            .ok_or_else(|| anyhow::anyhow!("enrich_signals/javascript: parse returned None"))
    })?;
    let bytes = source.as_bytes();
    let mut out: Vec<Signal> = Vec::new();
    let mut cursor = tree_sitter::QueryCursor::new();
    let cap = |n: &str| JS_QUERY.capture_index_for_name(n).unwrap_or(u32::MAX);
    let (i_panic, i_assert, i_comment) = (cap("panic"), cap("assert"), cap("comment"));

    for m in cursor.matches(&JS_QUERY, tree.root_node(), bytes) {
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
                    comments::scan_linter_disable(&evidence, line, Language::JavaScript)
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
        let signals = extract("throw new Error('bad');").unwrap();
        assert!(signals.iter().any(|s| s.kind == SignalKind::Panic));
    }

    #[test]
    fn detects_assert() {
        let signals = extract("assert(x > 0)").unwrap();
        assert!(signals.iter().any(|s| s.kind == SignalKind::Assert));
    }

    #[test]
    fn detects_eslint_disable_comment() {
        let signals = extract("// eslint-disable-next-line no-console\nconsole.log(x);").unwrap();
        assert!(signals.iter().any(|s| s.kind == SignalKind::LinterDisable));
    }
}
