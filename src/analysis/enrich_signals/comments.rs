//! Language-agnostic comment-marker scanning for enrichment signals.
//!
//! Per-language extractors (`rust.rs`, `python.rs`, …) use tree-sitter
//! queries to find comment nodes and pass each one through
//! [`scan_comment_text`] for high-signal marker detection. The fallback
//! [`scan_unknown`] handles unsupported languages via heuristic comment
//! detection so files like `.toml` and `.md` still surface WARN/FIXME
//! annotations even without an AST.
//!
//! Markers detected:
//! - HIGH-signal: `WARNING`, `FIXME`, `HACK`, `SAFETY`, `IMPORTANT`,
//!   `DO NOT`, `XXX`, `DANGER`, `INVARIANT`
//! - MEDIUM-signal: `TODO`, `NOTE:`, per-language linter disables
//!   (`noqa`, `nolint`, `rubocop:disable`, etc.)

use super::{Signal, SignalKind, SignalTier};
use crate::analysis::walker::Language;

/// Markers that flag deliberate caution. Case-insensitive matched.
/// Order matters only for HIGH-vs-MEDIUM classification: anything in
/// HIGH_MARKERS shadows MEDIUM_MARKERS if both appear.
const HIGH_MARKERS: &[&str] = &[
    "WARNING",
    "FIXME",
    "HACK",
    "SAFETY",
    "IMPORTANT",
    "DO NOT",
    "DANGER",
    "INVARIANT",
    "XXX",
];

const MEDIUM_MARKERS: &[&str] = &["TODO", "NOTE:"];

/// Scan a single comment's text and return a [`Signal`] if it contains a
/// caution marker. `text` should be the comment body (with or without
/// the `//`/`#` prefix — both are stripped before matching).
pub fn scan_comment_text(text: &str, file_line: u32) -> Option<Signal> {
    let stripped = strip_comment_prefix(text);
    let upper = stripped.to_ascii_uppercase();

    // HIGH first: a comment that says both "TODO" and "FIXME" gets
    // classified HIGH, not MEDIUM.
    for marker in HIGH_MARKERS {
        if upper.contains(marker) {
            return Some(Signal {
                file_line,
                tier: SignalTier::High,
                kind: SignalKind::WarnComment,
                evidence: trim_evidence(text),
            });
        }
    }
    for marker in MEDIUM_MARKERS {
        if upper.contains(marker) {
            return Some(Signal {
                file_line,
                tier: SignalTier::Medium,
                kind: SignalKind::WarnComment,
                evidence: trim_evidence(text),
            });
        }
    }
    None
}

/// Detect language-specific linter-disable markers in a comment line.
pub fn scan_linter_disable(text: &str, file_line: u32, language: Language) -> Option<Signal> {
    let lower = text.to_ascii_lowercase();
    let patterns: &[&str] = match language {
        Language::Python => &["noqa", "type: ignore", "pylint: disable", "fmt: off"],
        Language::Rust => &["#[allow(", "// allow:", "// expect:"],
        Language::TypeScript | Language::JavaScript => &[
            "eslint-disable",
            "@ts-ignore",
            "@ts-expect-error",
            "prettier-ignore",
        ],
        Language::Go => &["//nolint", "//lint:ignore"],
        Language::Java => &["@suppresswarnings", "checkstyle:off", "// noinspection"],
        Language::C | Language::Cpp => &[
            "// nolint",
            "lint -e",
            "#pragma warning(disable",
            "// coverity",
        ],
        Language::Ruby => &["rubocop:disable", "rubocop:todo"],
        Language::Scala => &["@suppresswarnings", "scalafix:off"],
        Language::Elixir => &["credo:disable", "credo-disable"],
        Language::Haskell => &["{-# options_ghc -w", "hlint: ignore"],
        Language::Unknown => &[],
    };
    for p in patterns {
        if lower.contains(p) {
            return Some(Signal {
                file_line,
                tier: SignalTier::Medium,
                kind: SignalKind::LinterDisable,
                evidence: trim_evidence(text),
            });
        }
    }
    None
}

/// Fallback comment scan for languages without an AST-aware extractor.
/// Used by [`super::extract_signals`] when the language is Unknown or
/// when the per-language module hasn't shipped yet.
///
/// Heuristic: split on lines, recognise per-language line-comment
/// prefixes (`//`, `#`, `--`, `;`), pass each to [`scan_comment_text`]
/// and [`scan_linter_disable`].
pub fn scan_unknown(source: &str, language: Language) -> Vec<Signal> {
    let prefixes: &[&str] = match language {
        Language::Python | Language::Ruby | Language::Elixir => &["#"],
        Language::Haskell | Language::Scala => &["--", "//"],
        Language::C
        | Language::Cpp
        | Language::Go
        | Language::Java
        | Language::JavaScript
        | Language::TypeScript
        | Language::Rust => &["//"],
        Language::Unknown => &["//", "#", "--", ";"],
    };

    let mut out = Vec::new();
    for (idx, line) in source.lines().enumerate() {
        let line_no = (idx + 1) as u32;
        let trimmed = line.trim_start();

        // Look for an inline or whole-line comment.
        let comment_start = prefixes.iter().filter_map(|p| trimmed.find(p)).min();
        let Some(_) = comment_start else { continue };

        // Pull out the comment-suffix portion of the line for scanning.
        // (Cheap heuristic — doesn't handle quote-strings that LOOK like
        // comments, but those are rare and the AST-aware extractors
        // handle them correctly.)
        let comment_text = trimmed;

        if let Some(sig) = scan_comment_text(comment_text, line_no) {
            out.push(sig);
            continue;
        }
        if let Some(sig) = scan_linter_disable(comment_text, line_no, language) {
            out.push(sig);
        }
    }
    out
}

fn strip_comment_prefix(text: &str) -> &str {
    let s = text.trim_start();
    for prefix in ["///", "//!", "//", "##", "#", "--", "<!--", "/*", "/**"] {
        if let Some(rest) = s.strip_prefix(prefix) {
            return rest.trim_start();
        }
    }
    s
}

fn trim_evidence(text: &str) -> String {
    let one_line = text.replace('\n', " ");
    if one_line.chars().count() <= 200 {
        one_line.trim().to_string()
    } else {
        let truncated: String = one_line.chars().take(200).collect();
        format!("{}…", truncated.trim_end())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn high_marker_warning_detected() {
        let sig = scan_comment_text("// WARNING: don't call this from a hot path", 42).unwrap();
        assert_eq!(sig.tier, SignalTier::High);
        assert_eq!(sig.kind, SignalKind::WarnComment);
        assert_eq!(sig.file_line, 42);
    }

    #[test]
    fn high_marker_fixme_detected() {
        let sig = scan_comment_text("// FIXME(ioni): broken on macos", 7).unwrap();
        assert_eq!(sig.tier, SignalTier::High);
    }

    #[test]
    fn high_marker_safety_block_comment() {
        let sig = scan_comment_text("/* SAFETY: invariant holds because… */", 3).unwrap();
        assert_eq!(sig.tier, SignalTier::High);
    }

    #[test]
    fn do_not_phrase_detected() {
        let sig = scan_comment_text("// DO NOT add checksum verification here", 9).unwrap();
        assert_eq!(sig.tier, SignalTier::High);
    }

    #[test]
    fn medium_marker_todo_detected() {
        let sig = scan_comment_text("// TODO: replace with proper Result handling", 1).unwrap();
        assert_eq!(sig.tier, SignalTier::Medium);
    }

    #[test]
    fn high_shadows_medium_when_both_present() {
        // Has both WARNING (HIGH) and TODO (MEDIUM) → HIGH wins.
        let sig = scan_comment_text("// WARNING TODO refactor this", 1).unwrap();
        assert_eq!(sig.tier, SignalTier::High);
    }

    #[test]
    fn ordinary_comment_returns_none() {
        assert!(scan_comment_text("// just a normal explanation", 1).is_none());
    }

    #[test]
    fn case_insensitive_marker_match() {
        let sig = scan_comment_text("// warning: lowercase too", 1).unwrap();
        assert_eq!(sig.tier, SignalTier::High);
    }

    #[test]
    fn evidence_trimmed_for_long_text() {
        let long = "// ".to_string() + &"WARNING ".repeat(100);
        let sig = scan_comment_text(&long, 1).unwrap();
        assert!(sig.evidence.ends_with('…'));
        assert!(sig.evidence.chars().count() <= 201);
    }

    #[test]
    fn linter_disable_python_noqa() {
        let sig = scan_linter_disable("x = 1  # noqa: E501", 5, Language::Python).unwrap();
        assert_eq!(sig.tier, SignalTier::Medium);
        assert_eq!(sig.kind, SignalKind::LinterDisable);
    }

    #[test]
    fn linter_disable_go_nolint() {
        let sig = scan_linter_disable("foo() //nolint:errcheck", 5, Language::Go).unwrap();
        assert_eq!(sig.kind, SignalKind::LinterDisable);
    }

    #[test]
    fn linter_disable_ruby_rubocop() {
        let sig = scan_linter_disable(
            "  do_thing! # rubocop:disable Metrics/MethodLength",
            8,
            Language::Ruby,
        )
        .unwrap();
        assert_eq!(sig.kind, SignalKind::LinterDisable);
    }

    #[test]
    fn linter_disable_typescript_ts_ignore() {
        let sig = scan_linter_disable(
            "// @ts-ignore — third-party type hole",
            5,
            Language::TypeScript,
        )
        .unwrap();
        assert_eq!(sig.kind, SignalKind::LinterDisable);
    }

    #[test]
    fn linter_disable_unknown_language_returns_none() {
        assert!(scan_linter_disable("// noqa", 1, Language::Unknown).is_none());
    }

    #[test]
    fn scan_unknown_picks_up_warning_in_toml() {
        let source = "[package]\nname = \"x\"\n# WARNING: don't enable the unstable feature\n";
        let signals = scan_unknown(source, Language::Unknown);
        assert_eq!(signals.len(), 1);
        assert_eq!(signals[0].file_line, 3);
    }
}
