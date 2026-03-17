//! tree-sitter static analysis parser — Layer 0, M-06-B
//!
//! Extracts structural signals from Rust source files without executing any
//! LLM calls. All extraction is deterministic and purely syntactic.
//!
//! # Performance design
//!
//! - **One combined `Query`** compiled once at program start via `LazyLock`.
//!   A single `QueryCursor::matches()` call traverses the tree once and
//!   dispatches on capture index — no repeated tree scans.
//! - **Thread-local `Parser`** — one per rayon worker thread, reused across
//!   all files assigned to that thread. Avoids `set_language()` overhead per
//!   file (~5–10 µs each).
//! - **Skip before disk read** — `Language::Unknown` files return an empty
//!   analysis without touching the filesystem.
//! - **Count-only captures** — `unsafe`, `branch`, `unwrap`, `panic` captures
//!   just increment a counter; no text is allocated.
//!
//! # Extension (M-06-C)
//!
//! TypeScript and Python parsers follow the same pattern: one
//! `LazyLock<Language>`, one `LazyLock<Query>`, one `thread_local! Parser`,
//! one `parse_<lang>` function dispatched from `parse_file`.

use std::cell::RefCell;
use std::sync::LazyLock;

use anyhow::Result;
use rayon::prelude::*;

use crate::analysis::walker::{Language, WalkedFile};
use crate::store::record::{TodoComment, TodoKind};

// ── Static language handles ───────────────────────────────────────────────────

static RUST_LANGUAGE: LazyLock<tree_sitter::Language> =
    LazyLock::new(|| tree_sitter_rust::LANGUAGE.into());

// ── Combined Rust query ───────────────────────────────────────────────────────
//
// ALL signals extracted in one tree traversal. Capture names are stable
// identifiers used by `capture_index_for_name` in `CaptureIndices::new`.
//
// pub_fn    → public function name   → entry_points
// pub_mod   → public module name     → entry_points
// pub_type  → public type name       → exported_types (struct/enum/trait/type)
// import    → use argument text      → imports
// unsafe    → unsafe block           → unsafe_count++  (no text stored)
// unwrap    → .unwrap() call         → unwrap_count++  (no text stored)
// panic     → panic!() macro         → panic_count++   (no text stored)
// branch    → if/match/loop/while    → branch_count++  (no text stored)
// comment   → line or block comment  → todos (regex-filtered)

const RUST_QUERY_SRC: &str = r#"
  (function_item (visibility_modifier) name: (identifier) @pub_fn)
  (mod_item      (visibility_modifier) name: (identifier) @pub_mod)
  (struct_item   (visibility_modifier) name: (type_identifier) @pub_type)
  (enum_item     (visibility_modifier) name: (type_identifier) @pub_type)
  (trait_item    (visibility_modifier) name: (type_identifier) @pub_type)
  (type_item     (visibility_modifier) name: (type_identifier) @pub_type)

  (use_declaration argument: (_) @import)

  (unsafe_block) @unsafe

  (call_expression
    function: (field_expression
      field: (field_identifier) @unwrap
      (#eq? @unwrap "unwrap")))

  (macro_invocation
    macro: (identifier) @panic
    (#eq? @panic "panic"))

  (if_expression)    @branch
  (match_expression) @branch
  (loop_expression)  @branch
  (while_expression) @branch

  (line_comment)  @comment
  (block_comment) @comment
"#;

static RUST_QUERY: LazyLock<tree_sitter::Query> = LazyLock::new(|| {
    tree_sitter::Query::new(&RUST_LANGUAGE, RUST_QUERY_SRC)
        .expect("M-06-B: invalid Rust tree-sitter query — check query syntax")
});

// Capture indices are constants derived from the static query — computed once
// per process, not once per file.
static RUST_CAPTURE_INDICES: LazyLock<CaptureIndices> =
    LazyLock::new(|| CaptureIndices::new(&RUST_QUERY));

// ── Thread-local parsers ──────────────────────────────────────────────────────

thread_local! {
    // One Parser per rayon worker thread — `set_language` is called once at
    // thread init, not once per file.
    static RUST_PARSER: RefCell<tree_sitter::Parser> = RefCell::new({
        let mut p = tree_sitter::Parser::new();
        p.set_language(&*RUST_LANGUAGE)
            .expect("M-06-B: failed to load tree-sitter-rust grammar");
        p
    });
}

// ── Output type ───────────────────────────────────────────────────────────────

/// Structural signals extracted from a single source file by tree-sitter.
///
/// This is the intermediate representation produced by Layer 0 parsing.
/// It maps directly onto the tree-sitter-populated fields of [`FileRecord`]:
/// `entry_points`, `imports`, `todos`, `unsafe_count`, `unwrap_count`.
/// Git-derived fields (`change_frequency`, `last_author`, `is_hotspot`) are
/// filled later by M-06-D.
///
/// The `purpose` field is always empty at Layer 0 — Layer 1 enrichment fills
/// it in via a Claude API batch call.
///
/// [`FileRecord`]: crate::store::record::FileRecord
#[derive(Debug, Clone)]
pub struct StaticFileAnalysis {
    /// Repo-relative path with forward slashes. Mirrors `WalkedFile::rel_path`.
    pub path: String,
    pub language: Language,
    /// Names of public functions and modules (`pub fn foo`, `pub mod bar`).
    pub entry_points: Vec<String>,
    /// Names of public types: `pub struct`, `pub enum`, `pub trait`, `pub type`.
    pub exported_types: Vec<String>,
    /// Raw `use` argument text (e.g. `std::collections::HashMap`,
    /// `crate::store::{Record, Store}`).
    pub imports: Vec<String>,
    /// TODO / FIXME / HACK / NOTE / DEPRECATED comments in source order.
    pub todos: Vec<TodoComment>,
    /// Count of `unsafe { }` blocks.
    pub unsafe_count: u32,
    /// Count of `.unwrap()` call expressions.
    pub unwrap_count: u32,
    /// Count of `panic!()` macro invocations.
    pub panic_count: u32,
    /// Total control-flow branches: `if`, `match`, `loop`, `while`.
    pub branch_count: u32,
}

impl StaticFileAnalysis {
    fn empty(file: &WalkedFile) -> Self {
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
        }
    }
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Parse a single file and return its structural analysis.
///
/// Returns an empty (zero-count) analysis — never `Err` — when:
/// - `file.language` is not yet supported (skips disk read entirely)
/// - the file cannot be read from disk (logged as a warning)
/// - tree-sitter fails to produce a parse tree
///
/// This design keeps `parse_files_parallel` simple: it maps without
/// short-circuiting and the caller always gets one result per input file.
pub fn parse_file(file: &WalkedFile) -> Result<StaticFileAnalysis> {
    match file.language {
        Language::Rust => {
            let source = match std::fs::read_to_string(&file.abs_path) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!("parser: cannot read {}: {e}", file.rel_path);
                    return Ok(StaticFileAnalysis::empty(file));
                }
            };
            parse_rust(file, &source)
        }
        // M-06-C will add TypeScript and Python here.
        _ => Ok(StaticFileAnalysis::empty(file)),
    }
}

/// Parse a slice of files in parallel using rayon.
///
/// Files with unsupported languages are returned as empty analyses without
/// touching the filesystem. Parse errors are logged and produce an empty
/// analysis — a single unreadable file never aborts the entire init pass.
///
/// # Caller note
///
/// Prefer this over calling `parse_file` in a manual `par_iter` — this
/// function owns the rayon scheduling and can be tuned independently.
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

// ── Rust parser ───────────────────────────────────────────────────────────────

/// Pre-computed capture indices for the combined Rust query.
///
/// `Query::capture_index_for_name` does a linear scan over capture names.
/// Computing indices once at `parse_rust` entry (not inside the match loop)
/// ensures we pay that cost once per file, not once per capture.
struct CaptureIndices {
    pub_fn: u32,
    pub_mod: u32,
    pub_type: u32,
    import: u32,
    unsafe_: u32,
    unwrap: u32,
    panic: u32,
    branch: u32,
    comment: u32,
}

impl CaptureIndices {
    fn new(query: &tree_sitter::Query) -> Self {
        let idx = |name: &str| {
            query
                .capture_index_for_name(name)
                .unwrap_or_else(|| panic!("M-06-B: query missing capture @{name}"))
        };
        Self {
            pub_fn: idx("pub_fn"),
            pub_mod: idx("pub_mod"),
            pub_type: idx("pub_type"),
            import: idx("import"),
            unsafe_: idx("unsafe"),
            unwrap: idx("unwrap"),
            panic: idx("panic"),
            branch: idx("branch"),
            comment: idx("comment"),
        }
    }
}

fn parse_rust(file: &WalkedFile, source: &str) -> Result<StaticFileAnalysis> {
    // Parse via the thread-local parser — one set_language() per worker thread.
    let tree = RUST_PARSER.with(|cell| {
        cell.borrow_mut().parse(source.as_bytes(), None)
    });

    let tree = match tree {
        Some(t) => t,
        None => {
            tracing::warn!("parser: tree-sitter failed on {}", file.rel_path);
            return Ok(StaticFileAnalysis::empty(file));
        }
    };

    let query = &*RUST_QUERY;
    let ci = &*RUST_CAPTURE_INDICES;
    let src = source.as_bytes();

    let mut out = StaticFileAnalysis {
        path: file.rel_path.clone(),
        language: Language::Rust,
        // Capacity hints from typical Rust module sizes.
        entry_points: Vec::with_capacity(16),
        exported_types: Vec::with_capacity(8),
        imports: Vec::with_capacity(16),
        todos: Vec::new(),
        unsafe_count: 0,
        unwrap_count: 0,
        panic_count: 0,
        branch_count: 0,
    };

    // Single tree traversal — all signals collected in one pass.
    let mut cursor = tree_sitter::QueryCursor::new();
    for m in cursor.matches(query, tree.root_node(), src) {
        for capture in m.captures {
            let idx = capture.index;
            let node = capture.node;

            // Count-only captures — no text allocation.
            if idx == ci.unsafe_ {
                out.unsafe_count += 1;
            } else if idx == ci.unwrap {
                out.unwrap_count += 1;
            } else if idx == ci.panic {
                out.panic_count += 1;
            } else if idx == ci.branch {
                out.branch_count += 1;
            // Text captures — allocate only for matched nodes.
            } else if idx == ci.pub_fn || idx == ci.pub_mod {
                if let Ok(name) = node.utf8_text(src) {
                    out.entry_points.push(name.to_owned());
                }
            } else if idx == ci.pub_type {
                if let Ok(name) = node.utf8_text(src) {
                    out.exported_types.push(name.to_owned());
                }
            } else if idx == ci.import {
                if let Ok(path) = node.utf8_text(src) {
                    out.imports.push(path.to_owned());
                }
            } else if idx == ci.comment {
                if let Ok(text) = node.utf8_text(src) {
                    let line = node.start_position().row as u32 + 1; // 1-based
                    if let Some(todo) = extract_todo(text, line) {
                        out.todos.push(todo);
                    }
                }
            }
        }
    }

    Ok(out)
}

// ── TODO extraction ───────────────────────────────────────────────────────────

/// Scan a single comment node for a TODO-family marker.
///
/// Returns `None` if no marker is found — the common case for most comments.
/// Uses byte-level `eq_ignore_ascii_case` to avoid allocating an uppercase
/// copy of the comment text.
///
/// Line number is 1-based (editor convention).
fn extract_todo(comment: &str, line: u32) -> Option<TodoComment> {
    // Strip comment syntax markers, then leading/trailing whitespace.
    // Use char-based trim to handle all variants:
    //   //  → strip '/'
    //   /// → strip all leading '/', giving " TODO"
    //   //! → strip '/', leaving "! TODO" (inner doc — handled below by trim)
    //   /* */ → strip '/' then '*' at start, '*' then '/' at end
    let inner = comment
        .trim_start_matches('/')
        .trim_start_matches('*')
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
    } else {
        return None;
    };

    Some(TodoComment {
        text: inner.to_owned(),
        line,
        kind,
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::TempDir;

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// Build a `WalkedFile` backed by a real temp file.
    fn make_rust_file(dir: &TempDir, rel: &str, content: &str) -> WalkedFile {
        let abs = dir.path().join(rel);
        if let Some(parent) = abs.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&abs, content).unwrap();
        WalkedFile {
            abs_path: abs,
            rel_path: rel.to_owned(),
            language: Language::Rust,
            size_bytes: content.len() as u64,
        }
    }

    /// Parse `source` as Rust and return the analysis. Panics on error.
    fn parse(dir: &TempDir, source: &str) -> StaticFileAnalysis {
        let f = make_rust_file(dir, "test.rs", source);
        parse_file(&f).unwrap()
    }

    // ── Entry points ──────────────────────────────────────────────────────────

    #[test]
    fn pub_fn_appears_in_entry_points() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "pub fn foo() {}");
        assert!(a.entry_points.contains(&"foo".to_owned()));
    }

    #[test]
    fn private_fn_excluded_from_entry_points() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "fn bar() {}");
        assert!(!a.entry_points.contains(&"bar".to_owned()));
    }

    #[test]
    fn pub_crate_fn_appears_in_entry_points() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "pub(crate) fn internal() {}");
        assert!(a.entry_points.contains(&"internal".to_owned()));
    }

    #[test]
    fn pub_mod_appears_in_entry_points() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "pub mod utils {}");
        assert!(a.entry_points.contains(&"utils".to_owned()));
    }

    #[test]
    fn multiple_pub_fns_all_captured() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "pub fn a() {} pub fn b() {} fn c() {}");
        assert!(a.entry_points.contains(&"a".to_owned()));
        assert!(a.entry_points.contains(&"b".to_owned()));
        assert!(!a.entry_points.contains(&"c".to_owned()));
    }

    // ── Exported types ────────────────────────────────────────────────────────

    #[test]
    fn pub_struct_appears_in_exported_types() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "pub struct Foo { x: u32 }");
        assert!(a.exported_types.contains(&"Foo".to_owned()));
    }

    #[test]
    fn pub_enum_appears_in_exported_types() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "pub enum Color { Red, Green, Blue }");
        assert!(a.exported_types.contains(&"Color".to_owned()));
    }

    #[test]
    fn pub_trait_appears_in_exported_types() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "pub trait Runnable { fn run(&self); }");
        assert!(a.exported_types.contains(&"Runnable".to_owned()));
    }

    #[test]
    fn pub_type_alias_appears_in_exported_types() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "pub type Result<T> = std::result::Result<T, anyhow::Error>;");
        assert!(a.exported_types.contains(&"Result".to_owned()));
    }

    #[test]
    fn private_struct_excluded_from_exported_types() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "struct Internal { x: u32 }");
        assert!(!a.exported_types.contains(&"Internal".to_owned()));
    }

    // ── Imports ───────────────────────────────────────────────────────────────

    #[test]
    fn use_statement_captured_in_imports() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "use std::collections::HashMap;");
        assert!(a.imports.iter().any(|i| i.contains("HashMap")));
    }

    #[test]
    fn multiple_use_statements_all_captured() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "use std::fmt; use anyhow::Result;");
        assert_eq!(a.imports.len(), 2);
    }

    // ── Risk signals ──────────────────────────────────────────────────────────

    #[test]
    fn unsafe_block_increments_counter() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "fn f() { unsafe { let _ = 1; } unsafe { let _ = 2; } }");
        assert_eq!(a.unsafe_count, 2);
    }

    #[test]
    fn unwrap_call_increments_counter() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, r#"fn f() { "x".parse::<u32>().unwrap(); "y".parse::<u32>().unwrap(); }"#);
        assert_eq!(a.unwrap_count, 2);
    }

    #[test]
    fn panic_macro_increments_counter() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, r#"fn f() { panic!("oh no"); }"#);
        assert_eq!(a.panic_count, 1);
    }

    #[test]
    fn if_expression_increments_branch_count() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "fn f(x: bool) { if x { } }");
        assert_eq!(a.branch_count, 1);
    }

    #[test]
    fn match_expression_increments_branch_count() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "fn f(x: u8) { match x { 0 => {}, _ => {} } }");
        assert_eq!(a.branch_count, 1);
    }

    #[test]
    fn else_if_counts_as_two_branches() {
        // `if a {} else if b {}` produces two if_expression nodes in the AST.
        // branch_count is if-expression count, not cyclomatic complexity.
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "fn f(a: bool, b: bool) { if a {} else if b {} }");
        assert_eq!(a.branch_count, 2);
    }

    // ── TODO extraction ───────────────────────────────────────────────────────

    #[test]
    fn todo_comment_extracted() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "// TODO: fix this later\nfn f() {}");
        assert_eq!(a.todos.len(), 1);
        assert_eq!(a.todos[0].kind, TodoKind::Todo);
    }

    #[test]
    fn fixme_comment_extracted() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "// FIXME: broken edge case\nfn f() {}");
        assert_eq!(a.todos.len(), 1);
        assert_eq!(a.todos[0].kind, TodoKind::Fixme);
    }

    #[test]
    fn hack_comment_extracted() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "// HACK: workaround for upstream bug\nfn f() {}");
        assert_eq!(a.todos.len(), 1);
        assert_eq!(a.todos[0].kind, TodoKind::Hack);
    }

    #[test]
    fn note_comment_extracted() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "// NOTE: see ARCHITECTURE.md §3\nfn f() {}");
        assert_eq!(a.todos.len(), 1);
        assert_eq!(a.todos[0].kind, TodoKind::Note);
    }

    #[test]
    fn deprecated_comment_extracted() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "// DEPRECATED: use new_fn instead\nfn f() {}");
        assert_eq!(a.todos.len(), 1);
        assert_eq!(a.todos[0].kind, TodoKind::Deprecated);
    }

    #[test]
    fn todo_in_doc_comment_extracted() {
        let dir = TempDir::new().unwrap();
        // /// is a doc comment — still a line_comment node in tree-sitter
        let a = parse(&dir, "/// TODO: document this properly\nfn f() {}");
        assert_eq!(a.todos.len(), 1);
        assert_eq!(a.todos[0].kind, TodoKind::Todo);
    }

    #[test]
    fn todo_case_insensitive() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "// todo: lowercase works too\nfn f() {}");
        assert_eq!(a.todos.len(), 1);
        assert_eq!(a.todos[0].kind, TodoKind::Todo);
    }

    #[test]
    fn todo_line_number_is_one_based() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "fn f() {}\n// TODO: on line 2\n");
        assert_eq!(a.todos[0].line, 2);
    }

    #[test]
    fn plain_comment_not_extracted() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "// just a regular comment\nfn f() {}");
        assert!(a.todos.is_empty());
    }

    // ── Edge cases ────────────────────────────────────────────────────────────

    #[test]
    fn empty_file_produces_zero_counts() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "");
        assert!(a.entry_points.is_empty());
        assert_eq!(a.unsafe_count, 0);
        assert_eq!(a.unwrap_count, 0);
        assert_eq!(a.todos.len(), 0);
    }

    #[test]
    fn unknown_language_skipped_without_disk_read() {
        // Non-existent path — if the parser tried to read it, the test panics.
        let f = WalkedFile {
            abs_path: PathBuf::from("/nonexistent/path/that/does/not/exist.py"),
            rel_path: "src/app.py".to_owned(),
            language: Language::Python,
            size_bytes: 0,
        };
        let a = parse_file(&f).unwrap();
        assert!(a.entry_points.is_empty());
        assert_eq!(a.unsafe_count, 0);
    }

    #[test]
    fn path_preserved_in_analysis() {
        let dir = TempDir::new().unwrap();
        let f = make_rust_file(&dir, "src/lib.rs", "pub fn foo() {}");
        let a = parse_file(&f).unwrap();
        assert_eq!(a.path, "src/lib.rs");
    }

    // ── Parallel parsing ──────────────────────────────────────────────────────

    #[test]
    fn parse_files_parallel_returns_one_result_per_input() {
        let dir = TempDir::new().unwrap();
        let files: Vec<WalkedFile> = (0..5)
            .map(|i| make_rust_file(&dir, &format!("src/f{i}.rs"), "pub fn exported() {}"))
            .collect();
        let results = parse_files_parallel(&files);
        assert_eq!(results.len(), 5);
        for r in &results {
            assert!(r.entry_points.contains(&"exported".to_owned()));
        }
    }

    #[test]
    fn parse_files_parallel_mixed_languages() {
        let dir = TempDir::new().unwrap();
        let rust_file = make_rust_file(&dir, "main.rs", "pub fn main() {}");
        let py_file = WalkedFile {
            abs_path: PathBuf::from("/nonexistent.py"),
            rel_path: "script.py".to_owned(),
            language: Language::Python,
            size_bytes: 0,
        };
        let results = parse_files_parallel(&[rust_file, py_file]);
        assert_eq!(results.len(), 2);
        // Rust file has entry point
        assert!(results[0].entry_points.contains(&"main".to_owned()));
        // Python file is empty but not an error
        assert!(results[1].entry_points.is_empty());
    }

    // ── extract_todo unit tests ───────────────────────────────────────────────

    #[test]
    fn extract_todo_returns_none_for_plain_comment() {
        assert!(extract_todo("// nothing special", 1).is_none());
    }

    #[test]
    fn extract_todo_strips_comment_markers() {
        let t = extract_todo("// TODO: do something", 3).unwrap();
        assert_eq!(t.line, 3);
        assert_eq!(t.kind, TodoKind::Todo);
        assert!(t.text.contains("TODO"));
    }

    #[test]
    fn extract_todo_handles_block_comment() {
        let t = extract_todo("/* FIXME: clean this up */", 10).unwrap();
        assert_eq!(t.kind, TodoKind::Fixme);
        assert_eq!(t.line, 10);
    }
}
