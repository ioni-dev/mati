//! Java enrichment-signal extractor.
//!
//! HIGH: `throw ...`, `assert ...` (statements)
//! MEDIUM: `@SuppressWarnings`, `// CHECKSTYLE:OFF`, `// noinspection`

use std::cell::RefCell;
use std::sync::LazyLock;

use anyhow::Result;

use super::{comments, Signal, SignalKind, SignalTier};
use crate::analysis::walker::Language;

static JAVA_LANGUAGE: LazyLock<tree_sitter::Language> =
    LazyLock::new(|| tree_sitter_java::LANGUAGE.into());

const JAVA_QUERY_SRC: &str = r#"
  (throw_statement) @panic
  (assert_statement) @assert
  (line_comment)  @comment
  (block_comment) @comment
"#;

static JAVA_QUERY: LazyLock<tree_sitter::Query> = LazyLock::new(|| {
    tree_sitter::Query::new(&JAVA_LANGUAGE, JAVA_QUERY_SRC)
        .expect("enrich_signals/java: invalid query")
});

thread_local! {
    static JAVA_PARSER: RefCell<tree_sitter::Parser> = RefCell::new({
        let mut p = tree_sitter::Parser::new();
        p.set_language(&JAVA_LANGUAGE).expect("enrich_signals/java: grammar load failed");
        p
    });
}

/// JUnit lifecycle annotations live in the `modifiers` child, unlike Rust
/// where an attribute is a preceding sibling.
fn is_test_method(node: tree_sitter::Node, source: &[u8]) -> bool {
    const ANNOTATIONS: [&str; 7] = [
        "@Test",
        "@ParameterizedTest",
        "@RepeatedTest",
        "@BeforeEach",
        "@BeforeAll",
        "@AfterEach",
        "@AfterAll",
    ];
    if node.kind() != "method_declaration" {
        return false;
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() == "modifiers" {
            let text = super::node_text(source, child);
            if ANNOTATIONS.iter().any(|a| text.contains(a)) {
                return true;
            }
        }
    }
    false
}

pub fn extract(source: &str) -> Result<Vec<Signal>> {
    let tree = JAVA_PARSER.with(|p| {
        let mut parser = p.borrow_mut();
        parser
            .parse(source.as_bytes(), None)
            .ok_or_else(|| anyhow::anyhow!("enrich_signals/java: parse returned None"))
    })?;
    let bytes = source.as_bytes();
    let test_ranges = super::collect_test_ranges(tree.root_node(), |n| is_test_method(n, bytes));
    let mut out: Vec<Signal> = Vec::new();
    let mut cursor = tree_sitter::QueryCursor::new();
    let cap = |n: &str| JAVA_QUERY.capture_index_for_name(n).unwrap_or(u32::MAX);
    let (i_panic, i_assert, i_comment) = (cap("panic"), cap("assert"), cap("comment"));

    for m in cursor.matches(&JAVA_QUERY, tree.root_node(), bytes) {
        for c in m.captures {
            if super::in_test_range(&test_ranges, c.node) {
                continue;
            }
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
                    comments::scan_linter_disable(&evidence, line, Language::Java)
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
        let src = "class X { void f() { assert x > 0; throw new RuntimeException(\"bad\"); } }";
        let signals = extract(src).unwrap();
        assert!(signals.iter().any(|s| s.kind == SignalKind::Panic));
        assert!(signals.iter().any(|s| s.kind == SignalKind::Assert));
    }

    #[test]
    fn detects_checkstyle_off() {
        let src = "// CHECKSTYLE:OFF\nclass X {}";
        let signals = extract(src).unwrap();
        assert!(signals.iter().any(|s| s.kind == SignalKind::LinterDisable));
    }
    #[test]
    fn junit_test_method_excluded() {
        let src = "class T { @Test public void f() { throw new IllegalStateException(\"x\"); } }";
        assert!(extract(src).unwrap().is_empty());
    }

    #[test]
    fn unannotated_method_kept() {
        let src = "class T { public void f() { throw new IllegalStateException(\"x\"); } }";
        assert_eq!(extract(src).unwrap().len(), 1);
    }
}
