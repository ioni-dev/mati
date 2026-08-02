//! Elixir enrichment-signal extractor.
//!
//! HIGH: `raise(...)`, `throw(...)`, `exit(...)`, `System.halt(...)`,
//!       `assert ...` (test-suite macro)
//! MEDIUM: `# credo:disable` / `credo-disable-for-this-file` via shared scanner
//!
//! Elixir's grammar is metaprogramming-heavy — most "calls" are
//! `call` nodes with an identifier target. We match on identifier names.

use std::cell::RefCell;
use std::sync::LazyLock;

use anyhow::Result;

use super::{comments, Signal, SignalKind, SignalTier};
use crate::analysis::walker::Language;

static EX_LANGUAGE: LazyLock<tree_sitter::Language> =
    LazyLock::new(|| tree_sitter_elixir::LANGUAGE.into());

const EX_QUERY_SRC: &str = r#"
  (call target: (identifier) @panic_fn
    (#match? @panic_fn "^(raise|throw|exit)$")) @panic
  (call target: (identifier) @assert_fn
    (#match? @assert_fn "^(assert|refute)$")) @assert
  (comment) @comment
"#;

static EX_QUERY: LazyLock<tree_sitter::Query> = LazyLock::new(|| {
    tree_sitter::Query::new(&EX_LANGUAGE, EX_QUERY_SRC)
        .expect("enrich_signals/elixir: invalid query")
});

thread_local! {
    static EX_PARSER: RefCell<tree_sitter::Parser> = RefCell::new({
        let mut p = tree_sitter::Parser::new();
        p.set_language(&EX_LANGUAGE).expect("enrich_signals/elixir: grammar load failed");
        p
    });
}

/// A module that does `use ExUnit.Case`, or an ExUnit block macro. The `use`
/// form is the reliable signal: ExUnit test files always declare it.
fn is_test_node(node: tree_sitter::Node, source: &[u8]) -> bool {
    if node.kind() != "call" {
        return false;
    }
    let Some(target) = node.child_by_field_name("target") else {
        return false;
    };
    match super::node_text(source, target).trim() {
        "defmodule" => super::node_text(source, node).contains("ExUnit.Case"),
        "test" | "describe" | "setup" | "setup_all" => {
            let mut cursor = node.walk();
            let mut has_block = false;
            for child in node.named_children(&mut cursor) {
                has_block |= child.kind() == "do_block";
            }
            has_block
        }
        _ => false,
    }
}

pub fn extract(source: &str) -> Result<Vec<Signal>> {
    let tree = EX_PARSER.with(|p| {
        let mut parser = p.borrow_mut();
        parser
            .parse(source.as_bytes(), None)
            .ok_or_else(|| anyhow::anyhow!("enrich_signals/elixir: parse returned None"))
    })?;
    let bytes = source.as_bytes();
    let test_ranges = super::collect_test_ranges(tree.root_node(), |n| is_test_node(n, bytes));
    let mut out: Vec<Signal> = Vec::new();
    let mut cursor = tree_sitter::QueryCursor::new();
    let cap = |n: &str| EX_QUERY.capture_index_for_name(n).unwrap_or(u32::MAX);
    let (i_panic, i_assert, i_comment) = (cap("panic"), cap("assert"), cap("comment"));

    for m in cursor.matches(&EX_QUERY, tree.root_node(), bytes) {
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
                    comments::scan_linter_disable(&evidence, line, Language::Elixir)
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
        let signals = extract("defmodule M do\n  def f, do: raise \"bad\"\nend\n").unwrap();
        assert!(signals.iter().any(|s| s.kind == SignalKind::Panic));
    }

    #[test]
    fn detects_assert() {
        let signals = extract("assert x > 0\n").unwrap();
        assert!(signals.iter().any(|s| s.kind == SignalKind::Assert));
    }

    #[test]
    fn detects_warning_comment() {
        let signals = extract("# WARNING: do not call from a Plug\ndef f, do: :ok").unwrap();
        assert!(signals.iter().any(|s| s.kind == SignalKind::WarnComment));
    }
    #[test]
    fn exunit_module_excluded() {
        let src =
            "defmodule FT do\n  use ExUnit.Case\n  test \"a\" do\n    raise \"x\"\n  end\nend\n";
        assert!(extract(src).unwrap().is_empty());
    }

    #[test]
    fn production_module_kept() {
        let src = "defmodule F do\n  def run do\n    raise \"x\"\n  end\nend\n";
        assert_eq!(extract(src).unwrap().len(), 1);
    }
}
