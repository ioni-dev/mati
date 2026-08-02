//! Rust enrichment-signal extractor.
//!
//! Tree-sitter queries identify enrichment-relevant nodes; the comment
//! handling delegates to [`super::comments`] for shared marker detection.
//!
//! Detected:
//! - HIGH: `panic!`, `unreachable!`, `todo!`, `unimplemented!`, `assert!`,
//!   `assert_eq!`, `assert_ne!`, `debug_assert!`, `compile_error!`
//!   (all via `macro_invocation` capture)
//! - HIGH: `// WARNING / FIXME / HACK / SAFETY / IMPORTANT` comments
//!   (via `super::comments::scan_comment_text`)
//! - MEDIUM: `.unwrap()`, `.expect(...)` field expressions on call sites
//! - MEDIUM: `#[allow(...)]` lint disables (via comments scanner)
//!
//! Defensive guards (early returns with custom errors) are deliberately
//! NOT captured — too noisy without per-context judgment. The LLM's
//! Stage 2 critique handles that semantic call.
//!
//! Signals inside `#[cfg(test)]` modules and `#[test]` / `#[tokio::test]`
//! functions are dropped: a test asserting itself is not a gotcha, and
//! every `assert*` is HIGH tier, so test bodies otherwise dominate the
//! tier-sorted output.

use std::cell::RefCell;
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use anyhow::Result;

use super::{comments, Signal, SignalKind, SignalTier};
use crate::analysis::walker::Language;

// ── Tree-sitter handles (mirrors src/analysis/parser/rust.rs pattern) ─────

static RUST_LANGUAGE: LazyLock<tree_sitter::Language> =
    LazyLock::new(|| tree_sitter_rust::LANGUAGE.into());

const RUST_QUERY_SRC: &str = r#"
  ; Panic-equivalent macros. `bail!` and `ensure!` are anyhow-specific
  ; but extremely common in mati's own codebase (and in any Rust crate
  ; that uses anyhow) — both terminate execution by returning Err, so
  ; they're semantically panic-class for enrichment purposes. Without
  ; them, files like src/cli/repair.rs (which uses anyhow::bail! for
  ; its daemon-running guard) return 0 signals despite having clear
  ; "do not do this" intent.
  (macro_invocation macro: (identifier) @panic_macro
    (#match? @panic_macro
      "^(panic|unreachable|todo|unimplemented|compile_error|bail|ensure)$"))

  ; Same applies to anyhow::bail! / anyhow::ensure! invoked via the
  ; scoped_identifier path. The above matches the bare-name form;
  ; this matches anyhow::bail! and friends.
  (macro_invocation macro: (scoped_identifier name: (identifier) @panic_macro_scoped)
    (#match? @panic_macro_scoped "^(bail|ensure|panic|unreachable|todo|unimplemented)$"))

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
    if file_is_test_gated(tree.root_node(), source_bytes) {
        return Ok(Vec::new());
    }
    let test_ranges = test_item_ranges(tree.root_node(), source_bytes);
    let mut signals: Vec<Signal> = Vec::new();
    let mut cursor = tree_sitter::QueryCursor::new();

    let cap_idx_for_name = |name: &str| RUST_QUERY.capture_index_for_name(name).unwrap_or(u32::MAX);
    let panic_macro_idx = cap_idx_for_name("panic_macro");
    let panic_macro_scoped_idx = cap_idx_for_name("panic_macro_scoped");
    let assert_macro_idx = cap_idx_for_name("assert_macro");
    let unwrap_call_idx = cap_idx_for_name("unwrap_call");
    let comment_idx = cap_idx_for_name("comment");

    for m in cursor.matches(&RUST_QUERY, tree.root_node(), source_bytes) {
        for cap in m.captures {
            let node = cap.node;
            if test_ranges.iter().any(|r| r.contains(&node.start_byte())) {
                continue;
            }
            let line = node.start_position().row as u32 + 1;
            let evidence = super::node_text(source_bytes, node);

            let (kind, tier) =
                if cap.index == panic_macro_idx || cap.index == panic_macro_scoped_idx {
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

/// Whether the parent module declares this file's module behind a test gate
/// (`#[cfg(test)] mod compliance;`). Such a file is entirely test code without
/// containing any evidence of it.
///
/// An unreadable or unparseable parent yields `false`, so extraction proceeds
/// normally rather than failing.
pub fn parent_declares_test_module(path: &Path) -> bool {
    let Some(module) = declared_module_name(path) else {
        return false;
    };
    parent_module_candidates(path)
        .iter()
        .filter_map(|p| std::fs::read_to_string(p).ok())
        .any(|src| declares_test_module(&src, &module))
}

/// The name this file is declared under in its parent. `None` for a crate
/// root, which no parent declares.
fn declared_module_name(path: &Path) -> Option<String> {
    match path.file_stem()?.to_str()? {
        "lib" | "main" => None,
        "mod" => Some(path.parent()?.file_name()?.to_str()?.to_string()),
        stem => Some(stem.to_string()),
    }
}

/// Files that could hold the `mod <name>;` declaration: the enclosing module's
/// `mod.rs`, its Rust 2018 sibling form, or the crate root.
fn parent_module_candidates(path: &Path) -> Vec<PathBuf> {
    let scope = match path.file_stem().and_then(|s| s.to_str()) {
        Some("mod") => path.parent().and_then(|p| p.parent()),
        _ => path.parent(),
    };
    let Some(scope) = scope else {
        return Vec::new();
    };
    vec![
        scope.join("mod.rs"),
        scope.with_extension("rs"),
        scope.join("lib.rs"),
        scope.join("main.rs"),
    ]
}

/// Whether `source` declares a bodyless `mod <name>;` behind a test gate.
/// Only top-level declarations count — a nested one names a different file.
fn declares_test_module(source: &str, module: &str) -> bool {
    let Some(tree) = RUST_PARSER.with(|p| p.borrow_mut().parse(source.as_bytes(), None)) else {
        return false;
    };
    let bytes = source.as_bytes();
    let root = tree.root_node();
    let mut cursor = root.walk();

    for node in root.named_children(&mut cursor) {
        if node.kind() == "mod_item"
            && node.child_by_field_name("body").is_none()
            && super::named_field_matches(node, bytes, "name", |n| n == module)
            && has_test_attribute(node, bytes)
        {
            return true;
        }
    }
    false
}

/// Whether `#![cfg(test)]` gates the whole file. An inner attribute is a
/// child of the root, not a preceding sibling like an outer one.
fn file_is_test_gated(root: tree_sitter::Node, source: &[u8]) -> bool {
    let mut cursor = root.walk();
    for child in root.named_children(&mut cursor) {
        if child.kind() == "inner_attribute_item" && attribute_marks_test(child, source) {
            return true;
        }
    }
    false
}

/// Byte ranges covering every test-attributed module, function, impl, or
/// block. Test items are not descended into, so nested items inherit the
/// exclusion.
fn test_item_ranges(root: tree_sitter::Node, source: &[u8]) -> Vec<Range<usize>> {
    let mut ranges = Vec::new();
    let mut stack = vec![root];

    while let Some(node) = stack.pop() {
        let attributable = matches!(
            node.kind(),
            "mod_item" | "function_item" | "impl_item" | "block"
        );
        if attributable && has_test_attribute(node, source) {
            ranges.push(node.start_byte()..node.end_byte());
            continue;
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }

    ranges
}

/// In tree-sitter-rust an attribute is a *sibling* preceding its item,
/// not a child of it. Doc comments may sit between the two.
fn has_test_attribute(item: tree_sitter::Node, source: &[u8]) -> bool {
    // An attributed block inside a function body parses as an
    // `expression_statement` wrapping the block, so the attribute is the
    // wrapper's sibling, not the block's.
    let anchor = match item.parent() {
        Some(parent) if parent.kind() == "expression_statement" => parent,
        _ => item,
    };

    let mut sibling = anchor.prev_named_sibling();
    while let Some(node) = sibling {
        match node.kind() {
            "attribute_item" if attribute_marks_test(node, source) => return true,
            "attribute_item" | "line_comment" | "block_comment" => {}
            _ => return false,
        }
        sibling = node.prev_named_sibling();
    }
    false
}

/// Matches `#[test]`, any `::test` suffix (`#[tokio::test]`), and any
/// `cfg` predicate mentioning the bare `test` flag (`#[cfg(all(test, unix))]`).
fn attribute_marks_test(attr_item: tree_sitter::Node, source: &[u8]) -> bool {
    let mut item_cursor = attr_item.walk();
    let Some(attr) = attr_item
        .named_children(&mut item_cursor)
        .find(|n| n.kind() == "attribute")
    else {
        return false;
    };

    let mut attr_cursor = attr.walk();
    let Some(path) = attr.named_children(&mut attr_cursor).next() else {
        return false;
    };

    let path_text = super::node_text(source, path);
    match path_text.rsplit("::").next().unwrap_or("").trim() {
        "test" => true,
        "cfg" => mentions_test_flag(attr, source),
        _ => false,
    }
}

/// Whether a `cfg` predicate enables the bare `test` flag. Subtrees under
/// `not(...)` are skipped, so `#[cfg(not(test))]` stays production code.
fn mentions_test_flag(node: tree_sitter::Node, source: &[u8]) -> bool {
    let mut cursor = node.walk();
    let mut negated = false;

    for child in node.named_children(&mut cursor) {
        if child.kind() == "identifier" {
            let text = super::node_text(source, child);
            if text == "test" {
                return true;
            }
            negated = text == "not";
        } else if negated {
            negated = false;
        } else if mentions_test_flag(child, source) {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parent_candidates_cover_both_module_forms() {
        let c = parent_module_candidates(Path::new("src/hooks/compliance.rs"));
        assert!(c.contains(&PathBuf::from("src/hooks/mod.rs")));
        assert!(c.contains(&PathBuf::from("src/hooks.rs")));

        // A crate-root child: `src/invariants.rs` is declared in `src/lib.rs`.
        let c = parent_module_candidates(Path::new("src/invariants.rs"));
        assert!(c.contains(&PathBuf::from("src/lib.rs")));

        // `src/hooks/mod.rs` is itself declared one scope up.
        let c = parent_module_candidates(Path::new("src/hooks/mod.rs"));
        assert!(c.contains(&PathBuf::from("src/lib.rs")));
    }

    #[test]
    fn declared_module_name_uses_dir_for_mod_rs_and_skips_crate_roots() {
        assert_eq!(
            declared_module_name(Path::new("src/hooks/compliance.rs")).as_deref(),
            Some("compliance")
        );
        assert_eq!(
            declared_module_name(Path::new("src/hooks/mod.rs")).as_deref(),
            Some("hooks")
        );
        assert!(declared_module_name(Path::new("src/lib.rs")).is_none());
        assert!(declared_module_name(Path::new("src/main.rs")).is_none());
    }

    #[test]
    fn declares_test_module_matches_only_gated_bodyless_declarations() {
        assert!(declares_test_module(
            "#[cfg(test)]\nmod compliance;",
            "compliance"
        ));
        assert!(declares_test_module(
            "#[cfg(all(test, unix))]\nmod compliance;",
            "compliance"
        ));
        assert!(!declares_test_module("mod compliance;", "compliance"));
        assert!(!declares_test_module(
            "#[cfg(not(test))]\nmod compliance;",
            "compliance"
        ));
        // Inline module: names no file.
        assert!(!declares_test_module(
            "#[cfg(test)]\nmod compliance { fn x() {} }",
            "compliance"
        ));
        assert!(!declares_test_module(
            "#[cfg(test)]\nmod other;",
            "compliance"
        ));
    }

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
    fn cfg_test_module_signals_excluded() {
        let src = r#"
// WARNING: real signal
fn real() {
    assert!(cond, "production invariant");
}

#[cfg(test)]
mod tests {
    // FIXME: test-only note
    #[test]
    fn a() {
        assert_eq!(1, 1);
        panic!("in a test");
    }
}
"#;
        let signals = extract(src).unwrap();
        assert_eq!(signals.len(), 2, "got {signals:?}");
        assert!(signals.iter().all(|s| s.file_line < 7));
        assert!(signals.iter().any(|s| s.kind == SignalKind::WarnComment));
        assert!(signals.iter().any(|s| s.kind == SignalKind::Assert));
    }

    #[test]
    fn nested_cfg_test_predicate_excluded() {
        let src = r#"
#[cfg(all(test, unix))]
mod tests {
    fn a() { assert_eq!(1, 1); }
}
"#;
        assert!(extract(src).unwrap().is_empty());
    }

    #[test]
    fn test_fn_outside_test_module_excluded() {
        let src = r#"
#[test]
fn standalone() {
    assert_eq!(1, 1);
}

#[tokio::test]
async fn async_case() {
    assert!(ready);
}

fn production() {
    assert!(invariant);
}
"#;
        let signals = extract(src).unwrap();
        assert_eq!(signals.len(), 1, "got {signals:?}");
        assert_eq!(signals[0].file_line, 13);
    }

    #[test]
    fn doc_comment_between_attribute_and_item_still_excluded() {
        let src = r#"
#[cfg(test)]
/// Unit tests.
mod tests {
    fn a() { assert_eq!(1, 1); }
}
"#;
        assert!(extract(src).unwrap().is_empty());
    }

    #[test]
    fn cfg_not_test_is_production_code() {
        let src = r#"
#[cfg(not(test))]
fn production() {
    assert!(invariant);
}
"#;
        let signals = extract(src).unwrap();
        assert_eq!(signals.len(), 1, "got {signals:?}");
    }

    #[test]
    fn inner_cfg_test_attribute_gates_whole_file() {
        let src = "#![cfg(test)]\nfn helper() {\n    assert!(x);\n}\n";
        assert!(extract(src).unwrap().is_empty());
    }

    #[test]
    fn inner_attribute_that_is_not_cfg_test_keeps_signals() {
        let src = "#![allow(dead_code)]\nfn production() {\n    assert!(invariant);\n}\n";
        let signals = extract(src).unwrap();
        assert_eq!(signals.len(), 1, "got {signals:?}");
    }

    #[test]
    fn cfg_test_block_and_impl_excluded() {
        let src = r#"
fn home() -> Option<PathBuf> {
    #[cfg(test)]
    {
        assert!(in_test);
        Some(test_home())
    }
}

#[cfg(test)]
impl Fixture {
    fn new() { assert!(ok); }
}
"#;
        assert!(extract(src).unwrap().is_empty());
    }

    #[test]
    fn cfg_feature_named_test_not_excluded() {
        let src = r#"
#[cfg(feature = "testing")]
fn gated() {
    assert!(invariant);
}
"#;
        let signals = extract(src).unwrap();
        assert_eq!(signals.len(), 1, "got {signals:?}");
    }

    #[test]
    fn evidence_contains_source_snippet() {
        let src = r#"panic!("important detail");"#;
        let signals = extract(src).unwrap();
        assert!(signals.iter().any(|s| s.evidence.contains("panic")));
    }
}
