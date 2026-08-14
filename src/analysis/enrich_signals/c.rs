//! C enrichment-signal extractor.
//!
//! HIGH: `abort()`, `exit(...)`, `raise(...)`, `__builtin_trap()`, `assert(...)`
//! MEDIUM: `// nolint`, `#pragma warning(disable ...)` via shared scanner
//!
//! A `#define` body parses as an opaque `preproc_arg` leaf, so it is
//! re-parsed as a fragment via [`super::macro_body_signals`].

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
  (preproc_arg) @macro_body
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
    let i_macro_body = cap("macro_body");

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
            } else if c.index == i_macro_body {
                out.extend(C_PARSER.with(|p| {
                    super::macro_body_signals(
                        &mut p.borrow_mut(),
                        &C_QUERY,
                        c.node,
                        bytes,
                        i_panic,
                        i_assert,
                    )
                }));
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

    #[test]
    fn detects_call_in_single_line_macro_body() {
        let signals =
            extract("#define DIE(m) do { fprintf(stderr, m); exit(1); } while (0)\n").unwrap();
        assert_eq!(signals.len(), 1, "got {signals:?}");
        assert_eq!(signals[0].kind, SignalKind::Panic);
        assert_eq!(signals[0].file_line, 1);
        assert_eq!(signals[0].evidence, "exit(1)");
    }

    #[test]
    fn detects_call_in_continued_macro_body() {
        let src = "#define CHECK(c) \\\n  do {           \\\n    if (!(c)) {  \\\n      abort();   \\\n    }            \\\n  } while (0)\n";
        let signals = extract(src).unwrap();
        assert_eq!(signals.len(), 1, "got {signals:?}");
        assert_eq!(signals[0].kind, SignalKind::Panic);
        assert_eq!(signals[0].file_line, 4);
        assert_eq!(signals[0].evidence, "abort()");
    }

    #[test]
    fn macro_body_without_calls_yields_nothing() {
        let src = "#define MAX(a,b) ((a)>(b)?(a):(b))\n#define NOP\n";
        assert!(extract(src).unwrap().is_empty());
    }

    #[test]
    fn token_paste_macro_yields_nothing() {
        // `a##b` re-parses as an ERROR node — it must degrade to silence.
        assert!(extract("#define CONCAT(a,b) a##b\n").unwrap().is_empty());
    }

    #[test]
    fn comment_in_macro_body_reported_once() {
        let src = "#define CHECK(c) \\\n  /* WARNING: aborts hard */ \\\n  abort()\n";
        let signals = extract(src).unwrap();
        let warns: Vec<_> = signals
            .iter()
            .filter(|s| s.kind == SignalKind::WarnComment)
            .collect();
        assert_eq!(warns.len(), 1, "got {signals:?}");
        assert_eq!(warns[0].file_line, 2);
    }
}
