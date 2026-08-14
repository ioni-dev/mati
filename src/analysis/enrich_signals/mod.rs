//! Deterministic enrichment signal extraction (SOTA pipeline Stage 1).
//!
//! Replaces the previous "LLM scans the file looking for signals" approach
//! with tree-sitter AST queries + language-aware comment scanning. Same
//! code handles all 12 languages mati supports; adding a 13th = one new
//! per-language query module, not a 30-line prompt block in 4 scaffold
//! files.
//!
//! Outputs a structured signal list that `/mati-enrich`'s Stage 2 (LLM
//! critique) consumes. Each signal carries:
//!
//! - `file_line` — 1-based line number
//! - `tier`      — HIGH / MEDIUM / LOW
//! - `kind`      — semantic category (Panic, Assert, WarnComment, …)
//! - `evidence`  — the exact source-text snippet that triggered the signal
//!
//! Exposed via `mati extract-signals --file <path> --json`. See
//! `ENRICH_QUALITY.md` Section 4 — Proposal D, SOTA expansion.
//!
//! Test code is excluded, because assertions in a test suite are the
//! suite checking itself, not knowledge worth capturing. Three layers:
//! [`is_test_path`] skips whole files by naming convention (all
//! languages), each per-language extractor skips in-file test blocks via
//! `collect_test_ranges` with its own predicate, and — Rust only —
//! `rust::parent_declares_test_module` skips a file whose only test
//! marker is the `#[cfg(test)] mod foo;` in its parent.
//!
//! In-file filtering covers Rust, Go, Python, JavaScript, TypeScript,
//! Java, Ruby and Elixir. Three languages are deliberately not covered:
//!
//! - **C and C++** — gtest's `TEST(Suite, Name) { … }` does not parse as
//!   a function at all; tree-sitter emits an `ERROR` node and a detached
//!   `compound_statement`. There is no reliable node to anchor on.
//! - **Scala** — ScalaTest's `"x" should "y" in { … }` is arbitrary infix
//!   application, indistinguishable from ordinary code without picking a
//!   framework to special-case.
//! - **Haskell** — hspec's `describe`/`it` is plain function application
//!   with the same problem.
//!
//! Each predicate requires positive evidence rather than a name guess, so
//! the failure mode is a missed test block, never an excluded production
//! one. Excluding real code silently is the expensive direction.

use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::analysis::walker::Language;

pub mod comments;
pub mod rust;
// Additional language modules:
pub mod c;
pub mod cpp;
pub mod elixir;
pub mod go;
pub mod haskell;
pub mod java;
pub mod javascript;
pub mod python;
pub mod ruby;
pub mod scala;
pub mod typescript;

/// Signal strength tier — drives the prompt's "extract from highest first"
/// ranking in Stage 2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalTier {
    High,
    Medium,
    Low,
}

/// Semantic kind of an enrichment signal. Stable across languages: a
/// `Panic` in Rust (`panic!`) and a `Panic` in Python (`raise`) both map
/// to `SignalKind::Panic` so the consumer doesn't branch on language.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalKind {
    /// `panic!`, `throw`, `raise`, `abort`, `exit`, `die` — any
    /// language-level "halt with error" construct.
    Panic,
    /// `assert!`, `debug_assert!`, `assert`, `expect` with non-trivial
    /// messages.
    Assert,
    /// Comment markers signalling deliberate caution: WARNING, FIXME,
    /// HACK, SAFETY, IMPORTANT, XXX. Detected language-agnostically
    /// via `comments::scan`.
    WarnComment,
    /// Per-language linter-disable markers: `// noqa`, `//nolint`,
    /// `# rubocop:disable`, etc. Signals that the developer
    /// intentionally overrode a check — usually for a reason worth
    /// capturing.
    LinterDisable,
    /// `.unwrap()`, `.expect(...)`, `?` in non-error contexts —
    /// patterns that crash on failure paths.
    UnwrapLike,
    /// Defensive guard pattern: early return + custom error or panic.
    /// Indicates a precondition the developer wanted to enforce.
    Guard,
    /// Raw API usage with no surrounding comment context.
    /// Lowest signal; included for completeness.
    RawApi,
}

impl SignalKind {
    /// Default tier mapping. Languages can override per-occurrence (e.g.
    /// `WarnComment` containing "DO NOT" is HIGH; plain TODO is LOW).
    pub fn default_tier(self) -> SignalTier {
        match self {
            SignalKind::WarnComment => SignalTier::High,
            SignalKind::Panic => SignalTier::High,
            SignalKind::Assert => SignalTier::High,
            SignalKind::LinterDisable => SignalTier::Medium,
            SignalKind::Guard => SignalTier::Medium,
            SignalKind::UnwrapLike => SignalTier::Medium,
            SignalKind::RawApi => SignalTier::Low,
        }
    }
}

/// One extracted signal. Stable JSON shape across all 12 languages.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Signal {
    pub file_line: u32,
    pub tier: SignalTier,
    pub kind: SignalKind,
    pub evidence: String,
}

/// Top-level CLI output envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalReport {
    pub file: String,
    pub language: String,
    pub signal_count: usize,
    pub signals: Vec<Signal>,
}

impl SignalReport {
    /// Cap signals to `limit` (after sorting by tier descending).
    pub fn truncate(&mut self, limit: usize) {
        if limit > 0 && self.signals.len() > limit {
            self.signals.truncate(limit);
            self.signal_count = self.signals.len();
        }
    }
}

/// Convert a Language enum to the stable JSON label used in
/// SignalReport.language. Mirrors the snake_case in the parser modules.
pub fn language_label(lang: Language) -> &'static str {
    match lang {
        Language::Rust => "rust",
        Language::TypeScript => "typescript",
        Language::JavaScript => "javascript",
        Language::Python => "python",
        Language::Go => "go",
        Language::Java => "java",
        Language::C => "c",
        Language::Cpp => "cpp",
        Language::Ruby => "ruby",
        Language::Scala => "scala",
        Language::Elixir => "elixir",
        Language::Haskell => "haskell",
        Language::Unknown => "unknown",
    }
}

/// Extract enrichment signals from a single file.
///
/// Dispatches by `Language` to the appropriate per-language extractor.
/// Returns signals sorted by tier descending, then by `file_line`
/// ascending — the order the slash flow's Stage 2 consumes.
///
/// Unknown / unsupported languages fall back to comment-only scanning
/// via `comments::scan_unknown` so files like `.toml` or `.md` still
/// surface their WARN/FIXME annotations.
///
/// Files [`is_test_path`] or [`rust::parent_declares_test_module`]
/// recognises yield an empty report rather than an error — a zero-signal
/// report is a valid Stage 1 result.
pub fn extract_signals(path: &Path, language: Language) -> Result<SignalReport> {
    let source = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;

    let parent_gated = language == Language::Rust && rust::parent_declares_test_module(path);

    if is_test_path(path) || parent_gated {
        return Ok(SignalReport {
            file: path.display().to_string(),
            language: language_label(language).to_string(),
            signal_count: 0,
            signals: Vec::new(),
        });
    }

    let mut signals = match language {
        Language::Rust => rust::extract(&source)?,
        Language::Python => python::extract(&source)?,
        Language::TypeScript => typescript::extract(&source)?,
        Language::JavaScript => javascript::extract(&source)?,
        Language::Go => go::extract(&source)?,
        Language::Java => java::extract(&source)?,
        Language::C => c::extract(&source)?,
        Language::Cpp => cpp::extract(&source)?,
        Language::Ruby => ruby::extract(&source)?,
        Language::Scala => scala::extract(&source)?,
        Language::Elixir => elixir::extract(&source)?,
        Language::Haskell => haskell::extract(&source)?,
        // Unknown / unsupported file types still get caught via the
        // comment-only fallback so .toml, .md, .yaml, etc. surface
        // WARNING/FIXME markers and linter disables.
        Language::Unknown => comments::scan_unknown(&source, language),
    };

    sort_canonical(&mut signals);

    Ok(SignalReport {
        file: path.display().to_string(),
        language: language_label(language).to_string(),
        signal_count: signals.len(),
        signals,
    })
}

/// True when the path names a test file by convention, in any of the
/// supported languages. Such files are skipped wholesale.
///
/// Covers a `tests/` or `__tests__/` directory anywhere in the path, Go
/// `*_test.go`, Python `test_*.py` / `*_test.py`, and JS/TS
/// `*.test.*` / `*.spec.*`.
pub fn is_test_path(path: &Path) -> bool {
    if path
        .components()
        .any(|c| matches!(c.as_os_str().to_str(), Some("tests") | Some("__tests__")))
    {
        return true;
    }

    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };

    if name.ends_with("_test.go") {
        return true;
    }
    if name.ends_with(".py") && (name.starts_with("test_") || name.ends_with("_test.py")) {
        return true;
    }

    const JS_EXTS: [&str; 4] = ["js", "ts", "jsx", "tsx"];
    JS_EXTS.iter().any(|ext| {
        name.ends_with(&format!(".test.{ext}")) || name.ends_with(&format!(".spec.{ext}"))
    })
}

/// Read a tree-sitter node's source-text slice. Used by every per-language
/// extractor — hoisted here so each module stays focused on its query.
pub(crate) fn node_text(source: &[u8], node: tree_sitter::Node) -> String {
    let start = node.start_byte();
    let end = node.end_byte().min(source.len());
    if start >= end {
        return String::new();
    }
    String::from_utf8_lossy(&source[start..end]).into_owned()
}

/// Pull `panic` and `assert` captures out of a C/C++ `#define` body.
///
/// tree-sitter parses a macro body as an opaque `preproc_arg` leaf, so the
/// file-level query never reaches inside one. Re-parse the body on its own
/// with the same grammar and query.
///
/// The wrapper opens on the body's first line and closes on its last, so it
/// adds no rows: fragment row N is `body.start_position().row + N`. Backslash
/// continuations are left in place — error recovery finds the same calls
/// whether or not they are stripped.
pub(crate) fn macro_body_signals(
    parser: &mut tree_sitter::Parser,
    query: &tree_sitter::Query,
    body: tree_sitter::Node,
    source: &[u8],
    panic_idx: u32,
    assert_idx: u32,
) -> Vec<Signal> {
    let fragment = format!("void _(){{ {} ;}}", node_text(source, body));
    let Some(tree) = parser.parse(fragment.as_bytes(), None) else {
        return Vec::new();
    };
    let base = body.start_position().row as u32;
    let bytes = fragment.as_bytes();
    let mut out = Vec::new();
    let mut cursor = tree_sitter::QueryCursor::new();
    for m in cursor.matches(query, tree.root_node(), bytes) {
        for c in m.captures {
            let kind = if c.index == panic_idx {
                SignalKind::Panic
            } else if c.index == assert_idx {
                SignalKind::Assert
            } else {
                continue;
            };
            out.push(Signal {
                file_line: base + c.node.start_position().row as u32 + 1,
                tier: SignalTier::High,
                kind,
                evidence: trim_evidence(&node_text(bytes, c.node)),
            });
        }
    }
    out
}

/// Collect byte ranges of test-only nodes, without descending into a match.
///
/// Each language supplies its own `is_test` predicate; the traversal is
/// shared. Skipping the subtree of a match keeps nested test helpers from
/// being scanned twice.
pub(crate) fn collect_test_ranges<F>(
    root: tree_sitter::Node,
    is_test: F,
) -> Vec<std::ops::Range<usize>>
where
    F: Fn(tree_sitter::Node) -> bool,
{
    let mut ranges = Vec::new();
    let mut stack = vec![root];

    while let Some(node) = stack.pop() {
        if node.id() != root.id() && is_test(node) {
            ranges.push(node.start_byte()..node.end_byte());
            continue;
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }

    ranges
}

/// Whether a captured node starts inside any collected test range.
pub(crate) fn in_test_range(ranges: &[std::ops::Range<usize>], node: tree_sitter::Node) -> bool {
    ranges.iter().any(|r| r.contains(&node.start_byte()))
}

/// A `describe(…)`/`it(…)`/`test(…)` call taking a callback — the shape Jest,
/// Mocha and Vitest share. Requiring the callback keeps a production helper
/// named `test(value)` out of the match. Used by both JS and TS, whose
/// grammars agree on these node kinds.
pub(crate) fn is_js_test_call(node: tree_sitter::Node, source: &[u8]) -> bool {
    if node.kind() != "call_expression" {
        return false;
    }
    let Some(callee) = node.child_by_field_name("function") else {
        return false;
    };
    let text = node_text(source, callee);
    let base = text.split('.').next().unwrap_or("").trim();
    if !matches!(
        base,
        "describe" | "it" | "test" | "suite" | "context" | "beforeEach" | "afterEach"
    ) {
        return false;
    }
    let Some(args) = node.child_by_field_name("arguments") else {
        return false;
    };
    let mut cursor = args.walk();
    for arg in args.named_children(&mut cursor) {
        if matches!(
            arg.kind(),
            "arrow_function" | "function_expression" | "function"
        ) {
            return true;
        }
    }
    false
}

/// Whether a node's `name`/`method` child text matches `pred`.
pub(crate) fn named_field_matches<F>(
    node: tree_sitter::Node,
    source: &[u8],
    field: &str,
    pred: F,
) -> bool
where
    F: Fn(&str) -> bool,
{
    node.child_by_field_name(field)
        .map(|n| pred(node_text(source, n).trim()))
        .unwrap_or(false)
}

/// Collapse newlines and cap evidence at 200 characters with an ellipsis
/// suffix. Shared by all per-language extractors so SignalReport JSON
/// stays bounded regardless of source complexity.
pub(crate) fn trim_evidence(text: &str) -> String {
    let one_line = text.replace('\n', " ");
    if one_line.chars().count() <= 200 {
        one_line.trim().to_string()
    } else {
        let truncated: String = one_line.chars().take(200).collect();
        format!("{}…", truncated.trim_end())
    }
}

/// Sort signals into the canonical output order: tier desc, then line asc.
/// Stable so two extractors that produce signals in different traversal
/// orders end up with identical reports.
pub fn sort_canonical(signals: &mut [Signal]) {
    signals.sort_by(|a, b| {
        let tier_rank = |t: SignalTier| match t {
            SignalTier::High => 2,
            SignalTier::Medium => 1,
            SignalTier::Low => 0,
        };
        tier_rank(b.tier)
            .cmp(&tier_rank(a.tier))
            .then(a.file_line.cmp(&b.file_line))
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signal_tier_default_mapping() {
        assert_eq!(SignalKind::Panic.default_tier(), SignalTier::High);
        assert_eq!(SignalKind::WarnComment.default_tier(), SignalTier::High);
        assert_eq!(SignalKind::Assert.default_tier(), SignalTier::High);
        assert_eq!(SignalKind::LinterDisable.default_tier(), SignalTier::Medium);
        assert_eq!(SignalKind::Guard.default_tier(), SignalTier::Medium);
        assert_eq!(SignalKind::UnwrapLike.default_tier(), SignalTier::Medium);
        assert_eq!(SignalKind::RawApi.default_tier(), SignalTier::Low);
    }

    #[test]
    fn sort_canonical_orders_by_tier_then_line() {
        let mut signals = vec![
            Signal {
                file_line: 5,
                tier: SignalTier::Low,
                kind: SignalKind::RawApi,
                evidence: "a".into(),
            },
            Signal {
                file_line: 2,
                tier: SignalTier::High,
                kind: SignalKind::Panic,
                evidence: "b".into(),
            },
            Signal {
                file_line: 10,
                tier: SignalTier::High,
                kind: SignalKind::WarnComment,
                evidence: "c".into(),
            },
            Signal {
                file_line: 1,
                tier: SignalTier::Medium,
                kind: SignalKind::Guard,
                evidence: "d".into(),
            },
        ];
        sort_canonical(&mut signals);
        // High tier first, then Medium, then Low; within tier ascending line.
        assert_eq!(signals[0].file_line, 2); // High, line 2
        assert_eq!(signals[1].file_line, 10); // High, line 10
        assert_eq!(signals[2].file_line, 1); // Medium
        assert_eq!(signals[3].file_line, 5); // Low
    }

    #[test]
    fn language_label_is_stable_snake_case() {
        assert_eq!(language_label(Language::Rust), "rust");
        assert_eq!(language_label(Language::TypeScript), "typescript");
        assert_eq!(language_label(Language::Cpp), "cpp");
        assert_eq!(language_label(Language::Haskell), "haskell");
        assert_eq!(language_label(Language::Unknown), "unknown");
    }

    #[test]
    fn test_paths_are_recognised() {
        for p in [
            "tests/integration.rs",
            "crates/foo/tests/smoke.rs",
            "src/__tests__/helper.js",
            "pkg/server_test.go",
            "app/test_views.py",
            "app/views_test.py",
            "src/Button.test.tsx",
            "src/Button.spec.js",
        ] {
            assert!(is_test_path(Path::new(p)), "{p} should be a test path");
        }
    }

    #[test]
    fn production_paths_are_not_test_paths() {
        for p in [
            "src/store/durability.rs",
            "src/latest/contest.go",
            "src/protest.py",
            "src/testing.py",
            "src/attest.ts",
            "src/harness/testutil.go",
        ] {
            assert!(!is_test_path(Path::new(p)), "{p} should not be a test path");
        }
    }

    #[test]
    fn skipped_file_returns_empty_report_not_error() {
        let dir = std::env::temp_dir().join("mati_enrich_signals_skip");
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("thing_test.go");
        std::fs::write(&file, "func TestX(t *testing.T) { panic(\"x\") }").unwrap();

        let report = extract_signals(&file, Language::Go).unwrap();
        assert_eq!(report.signal_count, 0);
        assert!(report.signals.is_empty());
        assert_eq!(report.language, "go");

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Scratch crate: `<root>/src/<parent>` declaring `mod child;`, plus a
    /// `child.rs` full of panics. Returns the child's path.
    fn write_gated_module(name: &str, parent: &str, decl: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(name);
        std::fs::remove_dir_all(&root).ok();
        let src = root.join("src");
        std::fs::create_dir_all(src.join("hooks")).unwrap();
        std::fs::write(src.join(parent), decl).unwrap();
        let child = src.join("hooks").join("compliance.rs");
        std::fs::write(&child, "fn go() { panic!(\"boom\"); assert!(true); }").unwrap();
        child
    }

    #[test]
    fn parent_mod_rs_test_gate_yields_empty_report() {
        let child = write_gated_module(
            "mati_enrich_parent_modrs",
            "hooks/mod.rs",
            "pub mod other;\n\n#[cfg(test)]\nmod compliance;\n",
        );

        let report = extract_signals(&child, Language::Rust).unwrap();
        assert_eq!(report.signal_count, 0);
        assert!(report.signals.is_empty());
        assert_eq!(report.language, "rust");

        std::fs::remove_dir_all(child.parent().unwrap().parent().unwrap().parent().unwrap()).ok();
    }

    #[test]
    fn parent_sibling_form_test_gate_yields_empty_report() {
        let child = write_gated_module(
            "mati_enrich_parent_sibling",
            "hooks.rs",
            "#[cfg(all(test, unix))]\nmod compliance;\n",
        );

        let report = extract_signals(&child, Language::Rust).unwrap();
        assert_eq!(report.signal_count, 0);

        std::fs::remove_dir_all(child.parent().unwrap().parent().unwrap().parent().unwrap()).ok();
    }

    #[test]
    fn ungated_parent_declaration_extracts_normally() {
        let child = write_gated_module(
            "mati_enrich_parent_ungated",
            "hooks/mod.rs",
            "#[cfg(not(test))]\nmod compliance;\n",
        );

        let report = extract_signals(&child, Language::Rust).unwrap();
        assert!(report.signal_count > 0, "cfg(not(test)) is production code");

        std::fs::remove_dir_all(child.parent().unwrap().parent().unwrap().parent().unwrap()).ok();
    }

    #[test]
    fn missing_parent_file_falls_through_to_extraction() {
        let root = std::env::temp_dir().join("mati_enrich_parent_missing");
        std::fs::remove_dir_all(&root).ok();
        std::fs::create_dir_all(root.join("src")).unwrap();
        let file = root.join("src").join("orphan.rs");
        std::fs::write(&file, "fn go() { panic!(\"boom\"); }").unwrap();

        let report = extract_signals(&file, Language::Rust).unwrap();
        assert!(report.signal_count > 0);

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn truncate_respects_limit_zero_means_unlimited() {
        let mut report = SignalReport {
            file: "x".into(),
            language: "rust".into(),
            signal_count: 3,
            signals: vec![
                Signal {
                    file_line: 1,
                    tier: SignalTier::High,
                    kind: SignalKind::Panic,
                    evidence: "a".into(),
                };
                3
            ],
        };
        report.truncate(0); // 0 = unlimited
        assert_eq!(report.signal_count, 3);
        report.truncate(2);
        assert_eq!(report.signal_count, 2);
    }
}
