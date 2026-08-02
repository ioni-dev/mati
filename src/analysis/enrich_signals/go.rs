//! Go enrichment-signal extractor.
//!
//! HIGH: `panic(...)`, `os.Exit(...)`, `log.Fatal(...)`, `log.Panic(...)`
//! MEDIUM: `//nolint:...`, `//lint:ignore` via shared scanner

use std::cell::RefCell;
use std::sync::LazyLock;

use anyhow::Result;

use super::{comments, Signal, SignalKind, SignalTier};
use crate::analysis::walker::Language;

static GO_LANGUAGE: LazyLock<tree_sitter::Language> =
    LazyLock::new(|| tree_sitter_go::LANGUAGE.into());

const GO_QUERY_SRC: &str = r#"
  (call_expression function: (identifier) @panic_fn
    (#eq? @panic_fn "panic")) @panic
  (call_expression function: (selector_expression
    operand: (identifier) @mod
    field: (field_identifier) @fn)
    (#match? @mod "^(os|log)$")
    (#match? @fn "^(Exit|Fatal|Fatalf|Fatalln|Panic|Panicf|Panicln)$")) @panic
  (comment) @comment
"#;

static GO_QUERY: LazyLock<tree_sitter::Query> = LazyLock::new(|| {
    tree_sitter::Query::new(&GO_LANGUAGE, GO_QUERY_SRC).expect("enrich_signals/go: invalid query")
});

thread_local! {
    static GO_PARSER: RefCell<tree_sitter::Parser> = RefCell::new({
        let mut p = tree_sitter::Parser::new();
        p.set_language(&GO_LANGUAGE).expect("enrich_signals/go: grammar load failed");
        p
    });
}

/// A test function is `func TestX(t *testing.T)`. The name prefix alone is
/// not enough — `TestData()` is ordinary code — so the `testing` parameter
/// is required. `Example` functions take no parameter and are left in.
fn is_test_fn(node: tree_sitter::Node, source: &[u8]) -> bool {
    fn has_test_prefix(name: &str) -> bool {
        ["Test", "Benchmark", "Fuzz"].iter().any(|p| {
            name.strip_prefix(p)
                .is_some_and(|rest| rest.is_empty() || rest.starts_with(|c: char| c.is_uppercase()))
        })
    }

    node.kind() == "function_declaration"
        && super::named_field_matches(node, source, "name", has_test_prefix)
        && node
            .child_by_field_name("parameters")
            .is_some_and(|p| super::node_text(source, p).contains("testing."))
}

pub fn extract(source: &str) -> Result<Vec<Signal>> {
    let tree = GO_PARSER.with(|p| {
        let mut parser = p.borrow_mut();
        parser
            .parse(source.as_bytes(), None)
            .ok_or_else(|| anyhow::anyhow!("enrich_signals/go: parse returned None"))
    })?;
    let bytes = source.as_bytes();
    let test_ranges = super::collect_test_ranges(tree.root_node(), |n| is_test_fn(n, bytes));
    let mut out: Vec<Signal> = Vec::new();
    let mut cursor = tree_sitter::QueryCursor::new();
    let cap = |n: &str| GO_QUERY.capture_index_for_name(n).unwrap_or(u32::MAX);
    let (i_panic, i_comment) = (cap("panic"), cap("comment"));

    for m in cursor.matches(&GO_QUERY, tree.root_node(), bytes) {
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
            } else if c.index == i_comment {
                if let Some(sig) = comments::scan_comment_text(&evidence, line) {
                    out.push(sig);
                } else if let Some(sig) =
                    comments::scan_linter_disable(&evidence, line, Language::Go)
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
    fn detects_panic() {
        let signals = extract("package x\nfunc f() { panic(\"bad\") }").unwrap();
        assert!(signals.iter().any(|s| s.kind == SignalKind::Panic));
    }

    #[test]
    fn detects_log_fatal() {
        let src = "package x\nimport \"log\"\nfunc f() { log.Fatal(\"bye\") }";
        let signals = extract(src).unwrap();
        assert!(signals
            .iter()
            .any(|s| s.kind == SignalKind::Panic && s.evidence.contains("Fatal")));
    }

    #[test]
    fn detects_os_exit() {
        let src = "package x\nimport \"os\"\nfunc f() { os.Exit(1) }";
        let signals = extract(src).unwrap();
        assert!(signals
            .iter()
            .any(|s| s.kind == SignalKind::Panic && s.evidence.contains("Exit")));
    }

    #[test]
    fn detects_nolint_comment() {
        let signals = extract("package x\nvar x = 1 //nolint:unused\n").unwrap();
        assert!(signals.iter().any(|s| s.kind == SignalKind::LinterDisable));
    }

    #[test]
    fn test_function_signals_excluded() {
        let src = "package x\nimport \"testing\"\nfunc TestF(t *testing.T) { panic(\"boom\") }";
        assert!(extract(src).unwrap().is_empty());
    }

    #[test]
    fn test_prefixed_production_function_kept() {
        let src = "package x\nfunc TestData() { panic(\"boom\") }";
        assert_eq!(extract(src).unwrap().len(), 1);
    }
}
