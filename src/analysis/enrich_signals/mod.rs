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
pub fn extract_signals(path: &Path, language: Language) -> Result<SignalReport> {
    let source = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;

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
