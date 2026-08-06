//! `mati verify-evidence` — deterministic cross-reference verification for
//! `/mati-enrich` Stage 3.
//!
//! Replaces LLM self-critique with a Rust-side check: given a file, a line
//! number, and an `evidence_quote` + optional `pattern` from a candidate
//! gotcha, confirm that:
//!
//! 1. The quote appears within `line ± WINDOW_LINES` of context, comparing
//!    both sides after comment markers and whitespace runs are normalized so
//!    a quote wrapped across source lines still matches.
//! 2. The pattern (if provided) also appears in that window — used to verify
//!    the API/literal named in the rule actually exists where the candidate
//!    claims.
//!
//! Output is JSON on stdout so the calling agent can parse it deterministically.
//!
//! Per ENRICH_QUALITY.md Section 4 (D-α), this is the SOTA upgrade that moves
//! evidence verification from "LLM grades itself" to "deterministic code grades
//! the LLM's claim." The whole point of Stage 3 is that the LLM that proposed
//! the citation cannot be trusted to verify it.
//!
//! Hidden in `--help` output; intended for programmatic use by the slash flow.

use std::path::Path;

use anyhow::{Context, Result};
use clap::Args;
use serde::Serialize;

/// Lines of context on each side of the cited line to scan.
///
/// Matches the spec — Stage 3 says "Re-read `<path>` at the cited file_line ± 5
/// lines." Eleven-line window is generous enough to absorb off-by-one drift
/// in LLM citations without losing precision.
const WINDOW_LINES: usize = 5;

#[derive(Args, Debug)]
#[command(
    long_about = "Deterministic cross-reference check for /mati-enrich Stage 3.\n\
                  Returns JSON: {verified, file, line, quote_match, pattern_match, reason}.\n\
                  Exit 0 iff verified=true."
)]
pub struct VerifyEvidenceArgs {
    /// Repo-relative file path to check.
    #[arg(long)]
    pub file: String,

    /// Cited line number. Accepts `42` or `L42` (the `L` is stripped).
    #[arg(long)]
    pub line: String,

    /// Substring expected within line ± 5 lines. Comment markers and line
    /// breaks are normalized away, so a wrapped quote may be given as one line.
    #[arg(long)]
    pub quote: String,

    /// Additional substring expected in the same window — typically the API
    /// or literal named in the candidate's draft_rule. Optional.
    #[arg(long)]
    pub pattern: Option<String>,
}

#[derive(Serialize)]
struct VerifyResult<'a> {
    verified: bool,
    file: &'a str,
    line: usize,
    quote_match: bool,
    pattern_match: Option<bool>,
    reason: Option<String>,
}

pub async fn run(args: VerifyEvidenceArgs) -> Result<()> {
    let line_num = parse_line_arg(&args.line)
        .with_context(|| format!("invalid --line value: {}", args.line))?;

    let window = read_window(&args.file, line_num, WINDOW_LINES)
        .with_context(|| format!("failed to read window from {}", args.file))?;

    let haystack = normalize(&window);
    let needle = normalize(&args.quote);

    let quote_match = !needle.is_empty() && haystack.contains(&needle);
    let pattern_match = args
        .pattern
        .as_ref()
        .map(|p| haystack.contains(&normalize(p)));

    let verified = quote_match && pattern_match.unwrap_or(true);

    let reason = if verified {
        None
    } else if !quote_match {
        Some(format!(
            "quote not found in {} lines {}..={}",
            args.file,
            line_num.saturating_sub(WINDOW_LINES),
            line_num + WINDOW_LINES,
        ))
    } else if matches!(pattern_match, Some(false)) {
        Some(format!(
            "pattern not found in {} lines {}..={} (quote matched but rule generalizes beyond visible scope)",
            args.file,
            line_num.saturating_sub(WINDOW_LINES),
            line_num + WINDOW_LINES,
        ))
    } else {
        None
    };

    let result = VerifyResult {
        verified,
        file: &args.file,
        line: line_num,
        quote_match,
        pattern_match,
        reason,
    };

    println!("{}", serde_json::to_string(&result)?);

    if !verified {
        std::process::exit(1);
    }
    Ok(())
}

/// Parse `42` or `L42` → `Some(42)`. Empty / negative / non-numeric → error.
fn parse_line_arg(raw: &str) -> Result<usize> {
    let stripped = raw
        .strip_prefix('L')
        .or_else(|| raw.strip_prefix('l'))
        .unwrap_or(raw);
    let n: usize = stripped
        .parse()
        .with_context(|| format!("expected positive integer, got {raw:?}"))?;
    if n == 0 {
        anyhow::bail!("line must be 1-based, got 0");
    }
    Ok(n)
}

/// Leading comment markers stripped before matching, longest prefix first so
/// `///` wins over `//` and `*/` over `*`. Covers the comment syntax of every
/// language mati parses: C-family, Rust, Python/Ruby/Elixir, Haskell.
const LINE_COMMENT_MARKERS: [&str; 9] = ["///", "//!", "//", "/**", "/*", "*/", "*", "--", "#"];

/// Flatten text so a quote spanning several source lines still matches.
///
/// Each line loses its leading comment marker, then all whitespace runs —
/// newlines included — collapse to one space. Applied identically to the
/// window, the quote, and the pattern, so the check still rejects text that
/// is genuinely absent.
fn normalize(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for line in text.lines() {
        let trimmed = line.trim_start();
        let body = LINE_COMMENT_MARKERS
            .iter()
            .find_map(|m| trimmed.strip_prefix(m))
            .unwrap_or(trimmed);
        for word in body.split_whitespace() {
            if !out.is_empty() {
                out.push(' ');
            }
            out.push_str(word);
        }
    }
    out
}

/// Read `file` and return the joined text of lines `[line - radius, line + radius]`
/// (1-based, clamped to file bounds). Missing lines past EOF are skipped.
fn read_window(file: &str, line: usize, radius: usize) -> Result<String> {
    let path = Path::new(file);
    let content =
        std::fs::read_to_string(path).with_context(|| format!("failed to read {file}"))?;

    let lines: Vec<&str> = content.lines().collect();
    let start = line.saturating_sub(radius + 1); // line is 1-based; vec is 0-based
    let end = (line + radius).min(lines.len());

    if start >= lines.len() {
        return Ok(String::new());
    }

    Ok(lines[start..end].join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn write_tmp(content: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f
    }

    #[test]
    fn parse_line_strips_l_prefix() {
        assert_eq!(parse_line_arg("L42").unwrap(), 42);
        assert_eq!(parse_line_arg("l42").unwrap(), 42);
        assert_eq!(parse_line_arg("42").unwrap(), 42);
    }

    #[test]
    fn parse_line_rejects_zero() {
        assert!(parse_line_arg("0").is_err());
        assert!(parse_line_arg("L0").is_err());
    }

    #[test]
    fn parse_line_rejects_non_numeric() {
        assert!(parse_line_arg("abc").is_err());
        assert!(parse_line_arg("L").is_err());
        assert!(parse_line_arg("").is_err());
    }

    #[test]
    fn window_returns_lines_around_target() {
        let content = (1..=20)
            .map(|n| format!("line {n}"))
            .collect::<Vec<_>>()
            .join("\n");
        let f = write_tmp(&content);
        let path = f.path().to_str().unwrap();

        let window = read_window(path, 10, 2).unwrap();
        // lines 8-12 inclusive (5 lines around line 10)
        assert!(window.contains("line 8"));
        assert!(window.contains("line 12"));
        assert!(!window.contains("line 7"));
        assert!(!window.contains("line 13"));
    }

    #[test]
    fn window_clamps_at_file_start() {
        let content = "a\nb\nc\nd\ne\n";
        let f = write_tmp(content);
        let path = f.path().to_str().unwrap();

        // line 1 with radius 5 → should not panic, returns lines 1..=5
        let window = read_window(path, 1, 5).unwrap();
        assert!(window.contains('a'));
        assert!(window.contains('e'));
    }

    #[test]
    fn window_clamps_at_file_end() {
        let content = "a\nb\nc\nd\ne\n";
        let f = write_tmp(content);
        let path = f.path().to_str().unwrap();

        // line 5 with radius 5 → returns lines 1..=5 (clamped)
        let window = read_window(path, 5, 5).unwrap();
        assert!(window.contains('a'));
        assert!(window.contains('e'));
    }

    /// The real shape from `src/cli/hook_decide/events_output.rs:365-370` that the flat substring
    /// match rejected: one sentence wrapped across two doc-comment lines.
    #[test]
    fn quote_wrapped_across_doc_comment_lines_matches() {
        let content = "\
/// Delegates to serde_json so ALL control characters (U+0000-U+001F) are
/// escaped, not just `\\n`/`\\r`/`\\t` — an unescaped control char anywhere in a
/// deny reason would make the whole hook output unparseable, and an
/// unparseable deny is a lost deny.
fn escape_json_string(s: &str) -> String {";
        let f = write_tmp(content);
        let window = read_window(f.path().to_str().unwrap(), 3, WINDOW_LINES).unwrap();

        assert!(normalize(&window).contains(&normalize("an unparseable deny is a lost deny")));
        assert!(!window.contains("an unparseable deny is a lost deny"));
    }

    #[test]
    fn absent_quote_still_rejected() {
        let content = "\
/// Delegates to serde_json so ALL control characters are
/// escaped, and an unparseable deny is a lost deny.
fn escape_json_string(s: &str) -> String {";
        let f = write_tmp(content);
        let window = normalize(&read_window(f.path().to_str().unwrap(), 2, WINDOW_LINES).unwrap());

        assert!(!window.contains(&normalize("a lost deny is an unparseable deny")));
        assert!(!window.contains(&normalize("fsync every write")));
    }

    #[test]
    fn pattern_outside_window_still_rejected() {
        let content = (1..=40)
            .map(|n| {
                if n == 35 {
                    "let x = with_versioning(true, 0);".to_string()
                } else {
                    format!("// line {n}")
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        let f = write_tmp(&content);
        let window = normalize(&read_window(f.path().to_str().unwrap(), 10, WINDOW_LINES).unwrap());

        assert!(window.contains(&normalize("line 10")));
        assert!(!window.contains(&normalize("with_versioning")));
    }

    #[test]
    fn normalize_strips_markers_and_collapses_whitespace() {
        assert_eq!(normalize("///  a\n//! b\n// c"), "a b c");
        assert_eq!(normalize("# py\n-- hs\n * block"), "py hs block");
        assert_eq!(normalize("  plain   code  "), "plain code");
        assert_eq!(normalize("   \n  \n"), "");
    }

    #[test]
    fn empty_quote_never_matches() {
        assert!(normalize("").is_empty());
        assert!(normalize("   \n///\n").is_empty());
    }

    #[test]
    fn window_past_eof_returns_empty() {
        let content = "a\nb\nc\n";
        let f = write_tmp(content);
        let path = f.path().to_str().unwrap();

        let window = read_window(path, 100, 5).unwrap();
        // line 100 with radius 5: start=94, end=3 → start >= len → empty
        assert!(window.is_empty());
    }
}
