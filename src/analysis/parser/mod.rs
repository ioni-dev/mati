//! Multi-language tree-sitter parser — Layer 0 static analysis.
//!
//! Each supported language lives in its own submodule with isolated statics:
//! `LazyLock<Language>`, `LazyLock<Query>`, `LazyLock<Captures>`,
//! `thread_local! Parser`. Adding a language = copy a module.
//!
//! # Performance
//!
//! - One combined query per language, single tree traversal per file.
//! - Thread-local parsers: one per rayon worker, reused across files.
//! - Disk read skipped for unsupported languages.
//! - Count-only captures: no text allocated for counting signals.

mod go;
mod python;
mod rust;
mod typescript;

use std::collections::HashMap;

use anyhow::Result;
use rayon::prelude::*;
use sha2::{Digest, Sha256};

use crate::analysis::walker::{Language, WalkedFile};
use crate::store::record::{TodoComment, TodoKind};

// ── Output type ───────────────────────────────────────────────────────────────

/// Structural signals extracted from a single source file by tree-sitter.
///
/// Intermediate representation for Layer 0. Maps onto `FileRecord` fields.
/// Git-derived fields (`change_frequency`, `last_author`, `is_hotspot`)
/// are filled later by M-06-D.
#[derive(Debug, Clone)]
pub struct StaticFileAnalysis {
    /// Repo-relative path with forward slashes.
    pub path: String,
    pub language: Language,
    /// Public functions and modules (Rust: `pub fn`; TS: exported; Python: non-`_` top-level).
    pub entry_points: Vec<String>,
    /// Public types (Rust: `pub struct/enum/trait`; TS: exported class/interface/type/enum;
    /// Python: non-`_` top-level classes).
    pub exported_types: Vec<String>,
    /// Import paths (Rust: use argument; TS/JS: module specifier; Python: dotted module name).
    pub imports: Vec<String>,
    /// TODO / FIXME / HACK / NOTE / DEPRECATED / @ts-ignore / type:ignore comments.
    pub todos: Vec<TodoComment>,
    /// `unsafe {}` blocks (Rust only).
    pub unsafe_count: u32,
    /// `.unwrap()` calls (Rust) or non-null assertions `!` (TypeScript).
    pub unwrap_count: u32,
    /// `panic!()` macro invocations (Rust only).
    pub panic_count: u32,
    /// Control-flow branches: if, match/switch, loop, while, for, ternary, try.
    pub branch_count: u32,
    /// Canonical module-level doc comment (language-specific — see ENRICHMENT.md §1.1).
    pub module_doc: Option<String>,
    /// SHA-256 hex digest of file bytes at parse time. Used for content-change detection (P3).
    pub content_hash: Option<String>,
    /// Number of newlines in the file — used for line-count delta in staleness signals.
    pub line_count: u32,
}

impl StaticFileAnalysis {
    pub(crate) fn empty(file: &WalkedFile) -> Self {
        Self {
            path: file.rel_path.clone(),
            language: file.language,
            entry_points: Vec::new(),
            exported_types: Vec::new(),
            imports: Vec::new(),
            todos: Vec::new(),
            unsafe_count: 0,
            unwrap_count: 0,
            panic_count: 0,
            branch_count: 0,
            module_doc: None,
            content_hash: None,
            line_count: 0,
        }
    }
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Parse a single file and return its structural analysis.
///
/// Returns an empty analysis (never `Err`) when:
/// - Language is unsupported (skips disk read entirely)
/// - File cannot be read from disk
/// - tree-sitter fails to produce a parse tree
pub fn parse_file(file: &WalkedFile) -> Result<StaticFileAnalysis> {
    // Guard: skip disk read for unsupported languages.
    if !is_parseable_language(file.language) {
        return Ok(StaticFileAnalysis::empty(file));
    }
    let bytes = match read_source_bytes(file) {
        Some(b) => b,
        None => return Ok(StaticFileAnalysis::empty(file)),
    };
    analyze_file_bytes(file, &bytes)
}

/// Parse a slice of files in parallel using rayon.
///
/// Parse errors are logged and produce an empty analysis — a single
/// unreadable file never aborts the entire init pass.
pub fn parse_files_parallel(files: &[WalkedFile]) -> Vec<StaticFileAnalysis> {
    files
        .par_iter()
        .map(|f| {
            parse_file(f).unwrap_or_else(|e| {
                tracing::warn!("parser: unexpected error on {}: {e}", f.rel_path);
                StaticFileAnalysis::empty(f)
            })
        })
        .collect()
}

/// Output of the combined mtime-check + parse pass.
pub struct HashParseOutput {
    /// Files whose mtime changed (new or modified), in rayon-completion order.
    pub parsed_files: Vec<WalkedFile>,
    /// Analyses for each file in `parsed_files` (same order).
    pub analyses: Vec<StaticFileAnalysis>,
    /// Updated mtimes for changed/new files only (rel_path → mtime_secs).
    /// Merge these into the stored mtime index and write one blob record.
    pub new_mtimes: HashMap<String, u64>,
    /// Count of files that were (re)parsed.
    pub parse_count: usize,
    /// Count of files whose mtime matched the stored value — skipped (no read).
    pub skipped_count: usize,
}

/// Combined mtime-check + parse pass.
///
/// For each file:
/// - If `mtime_secs` matches the stored value → skip entirely (zero disk I/O).
/// - Otherwise → read file bytes, run tree-sitter, record updated mtime.
///
/// This eliminates the full I/O sweep on re-init when files are unchanged:
/// a re-init with no edits costs only the walk + mtime comparison (≈130ms),
/// not a full disk read of all source files (≈2100ms on 58k-file repos).
pub fn hash_and_parse_parallel(
    files: &[WalkedFile],
    stored_mtimes: &HashMap<String, u64>,
) -> HashParseOutput {
    enum Slot {
        Changed(Box<(WalkedFile, StaticFileAnalysis)>),
        Unchanged,
    }

    let slots: Vec<Option<Slot>> = files
        .par_iter()
        .map(|f| {
            // Fast path: mtime unchanged → file is the same, skip entirely.
            if f.mtime_secs != 0 && stored_mtimes.get(&f.rel_path) == Some(&f.mtime_secs) {
                return Some(Slot::Unchanged);
            }
            // Non-parseable languages: record mtime from walker metadata — no disk read.
            if !is_parseable_language(f.language) {
                return Some(Slot::Changed(Box::new((
                    f.clone(),
                    StaticFileAnalysis::empty(f),
                ))));
            }
            // Parseable, changed/new: read file bytes and run tree-sitter.
            let bytes = match std::fs::read(&f.abs_path) {
                Ok(b) => b,
                Err(_) => return None, // unreadable — skip silently
            };
            let analysis = analyze_file_bytes(f, &bytes).unwrap_or_else(|e| {
                tracing::warn!("parser: error on {}: {e}", f.rel_path);
                StaticFileAnalysis::empty(f)
            });
            Some(Slot::Changed(Box::new((f.clone(), analysis))))
        })
        .collect();

    let mut parsed_files = Vec::new();
    let mut analyses = Vec::new();
    let mut new_mtimes = HashMap::new();
    let mut skipped_count = 0usize;

    for slot in slots.into_iter().flatten() {
        match slot {
            Slot::Changed(boxed) => {
                let (file, analysis) = *boxed;
                new_mtimes.insert(file.rel_path.clone(), file.mtime_secs);
                parsed_files.push(file);
                analyses.push(analysis);
            }
            Slot::Unchanged => skipped_count += 1,
        }
    }

    let parse_count = parsed_files.len();
    HashParseOutput {
        parsed_files,
        analyses,
        new_mtimes,
        parse_count,
        skipped_count,
    }
}

// ── Shared utilities ──────────────────────────────────────────────────────────

fn is_parseable_language(language: Language) -> bool {
    matches!(
        language,
        Language::Rust
            | Language::TypeScript
            | Language::JavaScript
            | Language::Python
            | Language::Go
    )
}

pub(crate) fn analyze_file_bytes(file: &WalkedFile, bytes: &[u8]) -> Result<StaticFileAnalysis> {
    let source = String::from_utf8_lossy(bytes);
    let mut analysis = parse_file_from_source(file, &source)?;
    analysis.content_hash = Some(format!("{:x}", Sha256::digest(bytes)));
    analysis.line_count = bytes.iter().filter(|&&b| b == b'\n').count() as u32;
    Ok(analysis)
}

/// Dispatch parse to the language-specific parser using pre-read source text.
fn parse_file_from_source(file: &WalkedFile, source: &str) -> Result<StaticFileAnalysis> {
    match file.language {
        Language::Rust => rust::parse_rust(file, source),
        Language::TypeScript | Language::JavaScript => typescript::parse_typescript(file, source),
        Language::Python => python::parse_python(file, source),
        Language::Go => go::parse_go(file, source),
        _ => Ok(StaticFileAnalysis::empty(file)),
    }
}

fn read_source_bytes(file: &WalkedFile) -> Option<Vec<u8>> {
    match std::fs::read(&file.abs_path) {
        Ok(bytes) => Some(bytes),
        Err(e) => {
            tracing::warn!("parser: cannot read {}: {e}", file.rel_path);
            None
        }
    }
}

/// Scan a comment node for a TODO-family or type-suppression marker.
///
/// Handles all comment syntaxes: `//`, `///`, `/* */`, `#` (Python).
/// Uses byte-level `eq_ignore_ascii_case` — no allocation until a match.
/// Line number is 1-based (editor convention).
pub(crate) fn extract_todo(comment: &str, line: u32) -> Option<TodoComment> {
    let inner = comment
        .trim_start_matches('/')
        .trim_start_matches('*')
        .trim_start_matches('#')
        .trim_end_matches('/')
        .trim_end_matches('*')
        .trim();

    let b = inner.as_bytes();

    let kind = if b.len() >= 4 && b[..4].eq_ignore_ascii_case(b"TODO") {
        TodoKind::Todo
    } else if b.len() >= 5 && b[..5].eq_ignore_ascii_case(b"FIXME") {
        TodoKind::Fixme
    } else if b.len() >= 4 && b[..4].eq_ignore_ascii_case(b"HACK") {
        TodoKind::Hack
    } else if b.len() >= 4 && b[..4].eq_ignore_ascii_case(b"NOTE") {
        TodoKind::Note
    } else if b.len() >= 10 && b[..10].eq_ignore_ascii_case(b"DEPRECATED") {
        TodoKind::Deprecated
    } else if b.len() >= 4 && b[..4].eq_ignore_ascii_case(b"@TS-") {
        // @ts-ignore, @ts-nocheck, @ts-expect-error
        TodoKind::Note
    } else if inner.contains("type: ignore") {
        // Python mypy suppression: # type: ignore[code]
        TodoKind::Note
    } else {
        return None;
    };

    Some(TodoComment {
        text: inner.to_owned(),
        line,
        kind,
    })
}

/// Normalize a doc comment string: collapse internal whitespace runs to a
/// single space and trim leading/trailing whitespace.
///
/// Used by language parsers to clean up multi-line doc comments before storing
/// them as `module_doc`.
pub(crate) fn normalize_doc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut last_was_space = true; // trim leading
    for ch in s.chars() {
        if ch.is_whitespace() {
            if !last_was_space {
                out.push(' ');
                last_was_space = true;
            }
        } else {
            out.push(ch);
            last_was_space = false;
        }
    }
    if out.ends_with(' ') {
        out.pop();
    }
    out
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn extract_todo_none_for_plain_comment() {
        assert!(extract_todo("// nothing special", 1).is_none());
    }

    #[test]
    fn extract_todo_rust_line_comment() {
        let t = extract_todo("// TODO: do something", 3).unwrap();
        assert_eq!(t.kind, TodoKind::Todo);
        assert_eq!(t.line, 3);
    }

    #[test]
    fn extract_todo_rust_block_comment() {
        let t = extract_todo("/* FIXME: clean up */", 10).unwrap();
        assert_eq!(t.kind, TodoKind::Fixme);
    }

    #[test]
    fn extract_todo_rust_doc_comment() {
        let t = extract_todo("/// TODO: document", 1).unwrap();
        assert_eq!(t.kind, TodoKind::Todo);
    }

    #[test]
    fn extract_todo_python_hash_comment() {
        let t = extract_todo("# TODO: fix this", 5).unwrap();
        assert_eq!(t.kind, TodoKind::Todo);
    }

    #[test]
    fn extract_todo_ts_ignore() {
        let t = extract_todo("// @ts-ignore", 1).unwrap();
        assert_eq!(t.kind, TodoKind::Note);
    }

    #[test]
    fn extract_todo_ts_expect_error() {
        let t = extract_todo("// @ts-expect-error", 1).unwrap();
        assert_eq!(t.kind, TodoKind::Note);
    }

    #[test]
    fn extract_todo_python_type_ignore() {
        let t = extract_todo("# type: ignore", 1).unwrap();
        assert_eq!(t.kind, TodoKind::Note);
    }

    #[test]
    fn extract_todo_python_type_ignore_with_code() {
        let t = extract_todo("# type: ignore[attr-defined]", 1).unwrap();
        assert_eq!(t.kind, TodoKind::Note);
    }

    #[test]
    fn extract_todo_case_insensitive() {
        let t = extract_todo("// todo: lowercase", 1).unwrap();
        assert_eq!(t.kind, TodoKind::Todo);
    }

    #[test]
    fn unsupported_language_skipped_without_disk_read() {
        let f = WalkedFile {
            abs_path: PathBuf::from("/nonexistent/file.java"),
            rel_path: "Main.java".to_owned(),
            language: Language::Java,
            size_bytes: 0,
            mtime_secs: 0,
        };
        let a = parse_file(&f).unwrap();
        assert!(a.entry_points.is_empty());
    }

    #[test]
    fn parse_files_parallel_preserves_order() {
        use tempfile::TempDir;
        let dir = TempDir::new().unwrap();
        let files: Vec<WalkedFile> = (0..3)
            .map(|i| {
                let rel = format!("f{i}.rs");
                let abs = dir.path().join(&rel);
                std::fs::write(&abs, format!("pub fn f{i}() {{}}")).unwrap();
                WalkedFile {
                    abs_path: abs,
                    rel_path: rel,
                    language: Language::Rust,
                    size_bytes: 20,
                    mtime_secs: 0,
                }
            })
            .collect();

        let results = parse_files_parallel(&files);
        assert_eq!(results[0].path, "f0.rs");
        assert_eq!(results[1].path, "f1.rs");
        assert_eq!(results[2].path, "f2.rs");
    }

    #[test]
    fn parse_file_populates_hash_and_line_count() {
        use tempfile::TempDir;

        let dir = TempDir::new().unwrap();
        let abs = dir.path().join("f.rs");
        std::fs::write(&abs, "pub fn f() {}\n").unwrap();

        let file = WalkedFile {
            abs_path: abs,
            rel_path: "f.rs".to_string(),
            language: Language::Rust,
            size_bytes: 13,
            mtime_secs: 0,
        };

        let analysis = parse_file(&file).unwrap();
        assert!(analysis.content_hash.is_some());
        assert_eq!(analysis.line_count, 1);
    }
}
