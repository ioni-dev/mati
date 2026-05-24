//! Rust enrichment-signal extractor.
//!
//! Tree-sitter queries identify enrichment-relevant nodes; the comment
//! handling delegates to [`super::comments`] for shared marker detection.
//!
//! Detected:
//! - HIGH: `panic!`, `unreachable!`, `todo!`, `unimplemented!`, `assert!`,
//!         `assert_eq!`, `assert_ne!`, `debug_assert!`, `compile_error!`
//!         (all via `macro_invocation` capture)
//! - HIGH: `// WARNING / FIXME / HACK / SAFETY / IMPORTANT` comments
//!         (via `super::comments::scan_comment_text`)
//! - MEDIUM: `.unwrap()`, `.expect(...)` field expressions on call sites
//! - MEDIUM: `#[allow(...)]` lint disables (via comments scanner)
//!
//! Defensive guards (early returns with custom errors) are deliberately
//! NOT captured — too noisy without per-context judgment. The LLM's
//! Stage 2 critique handles that semantic call.

use std::cell::RefCell;
use std::sync::LazyLock;

use anyhow::Result;

use super::{comments, Signal, SignalKind, SignalTier};
use crate::analysis::walker::Language;

// ── Tree-sitter handles (mirrors src/analysis/parser/rust.rs pattern) ─────

static RUST_LANGUAGE: LazyLock<tree_sitter::Language> =
    LazyLock::new(|| tree_sitter_rust::LANGUAGE.into());

const RUST_QUERY_SRC: &str = r#"
  ; Panic-equivalent macros: matched by macro name in the predicate
  ; so we capture the call sites uniformly. Tier defaults to HIGH for
  ; all of them; comment context can elevate further.
  (macro_invocation macro: (identifier) @panic_macro
    (#match? @panic_macro
      "^(panic|unreachable|todo|unimplemented|compile_error)$"))

  ; assert!/assert_eq!/assert_ne!/debug_assert!
  (macro_invocation macro: (identifier) @assert_macro
    (#match? @assert_macro "^(assert|assert_eq|assert_ne|debug_assert|debug_assert_eq|debug_assert_ne)$"))

  ; .unwrap() and .expect(...) field-call patterns
  (call_expression
    function: (field_expression
      field: (field_identifier) @unwrap_call
      (#match? @unwrap_call "^(unwrap|expect)$")))

  ; Comments — both line and block, fed into the shared marker scanner
  (line_comment)  @comment
  (block_comment) @comment
"#;

static RUST_QUERY: LazyLock<tree_sitter::Query> = LazyLock::new(|| {
    tree_sitter::Query::new(&RUST_LANGUAGE, RUST_QUERY_SRC)
        .expect("enrich_signals/rust: invalid query")
});

thread_local! {
    static RUST_PARSER: RefCell<tree_sitter::Parser> = RefCell::new({
        let mut p = tree_sitter::Parser::new();
        p.set_language(&RUST_LANGUAGE)
            .expect("enrich_signals/rust: grammar load failed");
        p
    });
}

/// Extract Rust enrichment signals from source text.
pub fn extract(source: &str) -> Result<Vec<Signal>> {
    let tree = RUST_PARSER.with(|p| {
        let mut parser = p.borrow_mut();
        parser
            .parse(source.as_bytes(), None)
            .ok_or_else(|| anyhow::anyhow!("enrich_signals/rust: parse returned None"))
    })?;

    let source_bytes = source.as_bytes();
    let mut signals: Vec<Signal> = Vec::new();
    let mut cursor = tree_sitter::QueryCursor::new();

    let cap_idx_for_name = |name: &str| RUST_QUERY.capture_index_for_name(name).unwrap_or(u32::MAX);
    let panic_macro_idx = cap_idx_for_name("panic_macro");
    let assert_macro_idx = cap_idx_for_name("assert_macro");
    let unwrap_call_idx = cap_idx_for_name("unwrap_call");
    let comment_idx = cap_idx_for_name("comment");

    for m in cursor.matches(&RUST_QUERY, tree.root_node(), source_bytes) {
        for cap in m.captures {
            let node = cap.node;
            let line = node.start_position().row as u32 + 1;
            let evidence = super::node_text(source_bytes, node);

            let (kind, tier) = if cap.index == panic_macro_idx {
                (SignalKind::Panic, SignalTier::High)
            } else if cap.index == assert_macro_idx {
                (SignalKind::Assert, SignalTier::High)
            } else if cap.index == unwrap_call_idx {
                (SignalKind::UnwrapLike, SignalTier::Medium)
            } else if cap.index == comment_idx {
                if let Some(sig) = comments::scan_comment_text(&evidence, line) {
                    signals.push(sig);
                } else if let Some(sig) =
                    comments::scan_linter_disable(&evidence, line, Language::Rust)
                {
                    signals.push(sig);
                }
                continue;
            } else {
                continue;
            };

            signals.push(Signal {
                file_line: line,
                tier,
                kind,
                evidence: super::trim_evidence(&evidence),
            });
        }
    }

    Ok(signals)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_panic_macro() {
        let src = "fn foo() { panic!(\"unexpected\"); }";
        let signals = extract(src).unwrap();
        let panics: Vec<_> = signals
            .iter()
            .filter(|s| s.kind == SignalKind::Panic)
            .collect();
        assert_eq!(panics.len(), 1);
        assert_eq!(panics[0].tier, SignalTier::High);
        assert_eq!(panics[0].file_line, 1);
    }

    #[test]
    fn detects_assert_variants() {
        let src = "
            fn foo() {
                assert!(true);
                assert_eq!(1, 1);
                debug_assert_ne!(1, 2);
            }
        ";
        let signals = extract(src).unwrap();
        let asserts: Vec<_> = signals
            .iter()
            .filter(|s| s.kind == SignalKind::Assert)
            .collect();
        assert_eq!(asserts.len(), 3);
    }

    #[test]
    fn detects_unwrap_and_expect() {
        let src = r#"
            fn foo() {
                let x = bar().unwrap();
                let y = baz().expect("bad");
            }
        "#;
        let signals = extract(src).unwrap();
        let unwraps: Vec<_> = signals
            .iter()
            .filter(|s| s.kind == SignalKind::UnwrapLike)
            .collect();
        assert_eq!(unwraps.len(), 2);
        for u in &unwraps {
            assert_eq!(u.tier, SignalTier::Medium);
        }
    }

    #[test]
    fn detects_warning_comment_via_shared_scanner() {
        let src = "// WARNING: don't call this concurrently\nfn foo() {}";
        let signals = extract(src).unwrap();
        let warns: Vec<_> = signals
            .iter()
            .filter(|s| s.kind == SignalKind::WarnComment)
            .collect();
        assert_eq!(warns.len(), 1);
        assert_eq!(warns[0].tier, SignalTier::High);
        assert_eq!(warns[0].file_line, 1);
    }

    #[test]
    fn ordinary_comments_not_signaled() {
        let src = "// just a normal comment\nfn foo() {}";
        let signals = extract(src).unwrap();
        // No high markers; no panic; no unwrap; should be empty.
        assert!(
            signals.is_empty(),
            "expected no signals from ordinary comment; got {signals:?}"
        );
    }

    #[test]
    fn detects_compile_error_macro_as_panic() {
        let src = r#"compile_error!("must enable feature foo");"#;
        let signals = extract(src).unwrap();
        let panics: Vec<_> = signals
            .iter()
            .filter(|s| s.kind == SignalKind::Panic)
            .collect();
        assert_eq!(panics.len(), 1);
    }

    #[test]
    fn evidence_contains_source_snippet() {
        let src = r#"panic!("important detail");"#;
        let signals = extract(src).unwrap();
        assert!(signals.iter().any(|s| s.evidence.contains("panic")));
    }
}
