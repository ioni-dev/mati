//! Python enrichment-signal extractor.
//!
//! HIGH:   `raise ...`, `assert ...`, calls to `sys.exit(...)` / `os._exit(...)`
//! MEDIUM: `# noqa` / `# type: ignore` / `# pylint: disable` (via shared scanner)
//! HIGH/MED: WARN-marker comments via shared scanner

use std::cell::RefCell;
use std::sync::LazyLock;

use anyhow::Result;

use super::{comments, Signal, SignalKind, SignalTier};
use crate::analysis::walker::Language;

static PY_LANGUAGE: LazyLock<tree_sitter::Language> =
    LazyLock::new(|| tree_sitter_python::LANGUAGE.into());

const PY_QUERY_SRC: &str = r#"
  (raise_statement)  @panic
  (assert_statement) @assert
  (call function: (attribute object: (identifier) @mod
                                 attribute: (identifier) @fn)
    (#eq? @mod "sys") (#eq? @fn "exit")) @sys_exit
  (comment) @comment
"#;

static PY_QUERY: LazyLock<tree_sitter::Query> = LazyLock::new(|| {
    tree_sitter::Query::new(&PY_LANGUAGE, PY_QUERY_SRC)
        .expect("enrich_signals/python: invalid query")
});

thread_local! {
    static PY_PARSER: RefCell<tree_sitter::Parser> = RefCell::new({
        let mut p = tree_sitter::Parser::new();
        p.set_language(&PY_LANGUAGE).expect("enrich_signals/python: grammar load failed");
        p
    });
}

/// `def test_*`, `class Test*`, a `unittest.TestCase` subclass, or anything
/// carrying a `pytest.*` decorator.
fn is_test_node(node: tree_sitter::Node, source: &[u8]) -> bool {
    match node.kind() {
        "function_definition" => {
            super::named_field_matches(node, source, "name", |n| n.starts_with("test_"))
        }
        "class_definition" => {
            super::named_field_matches(node, source, "name", |n| n.starts_with("Test"))
                || node
                    .child_by_field_name("superclasses")
                    .is_some_and(|s| super::node_text(source, s).contains("TestCase"))
        }
        "decorated_definition" => {
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                if child.kind() == "decorator"
                    && super::node_text(source, child)
                        .trim_start_matches('@')
                        .starts_with("pytest.")
                {
                    return true;
                }
            }
            false
        }
        _ => false,
    }
}

pub fn extract(source: &str) -> Result<Vec<Signal>> {
    let tree = PY_PARSER.with(|p| {
        let mut parser = p.borrow_mut();
        parser
            .parse(source.as_bytes(), None)
            .ok_or_else(|| anyhow::anyhow!("enrich_signals/python: parse returned None"))
    })?;
    let bytes = source.as_bytes();
    let test_ranges = super::collect_test_ranges(tree.root_node(), |n| is_test_node(n, bytes));
    let mut out: Vec<Signal> = Vec::new();
    let mut cursor = tree_sitter::QueryCursor::new();
    let cap = |n: &str| PY_QUERY.capture_index_for_name(n).unwrap_or(u32::MAX);
    let (i_panic, i_assert, i_sys_exit, i_comment) =
        (cap("panic"), cap("assert"), cap("sys_exit"), cap("comment"));

    for m in cursor.matches(&PY_QUERY, tree.root_node(), bytes) {
        for c in m.captures {
            let node = c.node;
            if super::in_test_range(&test_ranges, node) {
                continue;
            }
            let line = node.start_position().row as u32 + 1;
            let evidence = super::node_text(bytes, node);
            if c.index == i_panic || c.index == i_sys_exit {
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
                    comments::scan_linter_disable(&evidence, line, Language::Python)
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
    fn detects_raise() {
        let signals = extract("def f():\n  raise ValueError('bad')\n").unwrap();
        assert!(signals.iter().any(|s| s.kind == SignalKind::Panic));
    }

    #[test]
    fn detects_assert() {
        let signals = extract("assert x > 0, 'must be positive'\n").unwrap();
        assert!(signals.iter().any(|s| s.kind == SignalKind::Assert));
    }

    #[test]
    fn detects_sys_exit_call() {
        let signals = extract("import sys\nsys.exit(1)\n").unwrap();
        assert!(signals
            .iter()
            .any(|s| s.kind == SignalKind::Panic && s.evidence.contains("sys.exit")));
    }

    #[test]
    fn detects_warning_comment_and_noqa() {
        let src = "# WARNING: don't import from .. here\nx = 1  # noqa: E501\n";
        let signals = extract(src).unwrap();
        assert!(signals
            .iter()
            .any(|s| s.kind == SignalKind::WarnComment && s.tier == SignalTier::High));
        assert!(signals.iter().any(|s| s.kind == SignalKind::LinterDisable));
    }
    #[test]
    fn test_function_signals_excluded() {
        assert!(extract("def test_f():\n    assert x\n").unwrap().is_empty());
    }

    #[test]
    fn testcase_subclass_excluded() {
        let src = "class B(unittest.TestCase):\n    def m(self):\n        assert y\n";
        assert!(extract(src).unwrap().is_empty());
    }

    #[test]
    fn pytest_decorated_definition_excluded() {
        let src = "@pytest.mark.skip\ndef helper():\n    assert z\n";
        assert!(extract(src).unwrap().is_empty());
    }

    #[test]
    fn production_function_named_testable_kept() {
        let src = "def testable():\n    assert invariant\n";
        assert_eq!(extract(src).unwrap().len(), 1);
    }
}
