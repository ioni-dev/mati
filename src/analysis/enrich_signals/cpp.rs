//! C++ enrichment-signal extractor.
//!
//! HIGH: `throw ...`, `abort()`, `exit(...)`, `std::terminate(...)`,
//!       `assert(...)`, `static_assert(...)`
//! MEDIUM: `// NOLINT`, `#pragma warning(disable ...)` via shared scanner
//!
//! A `#define` body parses as an opaque `preproc_arg` leaf, so it is
//! re-parsed as a fragment via `macro_body_signals`.

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
  (preproc_arg) @macro_body
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
    let i_macro_body = cap("macro_body");

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
            } else if c.index == i_macro_body {
                out.extend(CPP_PARSER.with(|p| {
                    super::macro_body_signals(
                        &mut p.borrow_mut(),
                        &CPP_QUERY,
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

    #[test]
    fn detects_assert_in_single_line_macro_body() {
        let signals = extract("#define ASSERT_OK(x) assert((x).ok())\n").unwrap();
        assert_eq!(signals.len(), 1, "got {signals:?}");
        assert_eq!(signals[0].kind, SignalKind::Assert);
        assert_eq!(signals[0].file_line, 1);
        assert_eq!(signals[0].evidence, "assert((x).ok())");
    }

    #[test]
    fn detects_throw_in_continued_macro_body() {
        let src = "#define REQUIRE(c)   \\\n  do {               \\\n    if (!(c))        \\\n      throw std::runtime_error(\"bad\"); \\\n  } while (0)\n";
        let signals = extract(src).unwrap();
        assert_eq!(signals.len(), 1, "got {signals:?}");
        assert_eq!(signals[0].kind, SignalKind::Panic);
        assert_eq!(signals[0].file_line, 4);
    }

    #[test]
    fn macro_body_without_calls_yields_nothing() {
        assert!(extract("#define SQ(x) ((x) * (x))\n#define NOP\n")
            .unwrap()
            .is_empty());
    }

    #[test]
    fn token_paste_macro_yields_nothing() {
        // `a##b` re-parses as an ERROR node — it must degrade to silence.
        assert!(extract("#define TWO(a,b) a##b\n").unwrap().is_empty());
    }
}
