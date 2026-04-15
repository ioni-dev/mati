//! Rust tree-sitter parser — entry points, imports, risk signals, TODOs.

use std::cell::RefCell;
use std::sync::LazyLock;

use anyhow::Result;

use super::{extract_todo, ImportKind, ImportStatement, StaticFileAnalysis};
use crate::analysis::walker::{Language, WalkedFile};

// ── Static handles ────────────────────────────────────────────────────────────

static RUST_LANGUAGE: LazyLock<tree_sitter::Language> =
    LazyLock::new(|| tree_sitter_rust::LANGUAGE.into());

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
    tree_sitter::Query::new(&RUST_LANGUAGE, RUST_QUERY_SRC).expect("parser/rust: invalid query")
});

static RUST_CAPTURES: LazyLock<RustCaptures> = LazyLock::new(|| RustCaptures::new(&RUST_QUERY));

thread_local! {
    static RUST_PARSER: RefCell<tree_sitter::Parser> = RefCell::new({
        let mut p = tree_sitter::Parser::new();
        p.set_language(&RUST_LANGUAGE).expect("parser/rust: grammar load failed");
        p
    });
}

// ── Capture indices ───────────────────────────────────────────────────────────

struct RustCaptures {
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

impl RustCaptures {
    fn new(query: &tree_sitter::Query) -> Self {
        let idx = |name: &str| {
            query
                .capture_index_for_name(name)
                .unwrap_or_else(|| panic!("parser/rust: query missing @{name}"))
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

// ── Parser ────────────────────────────────────────────────────────────────────

pub(super) fn parse_rust(file: &WalkedFile, source: &str) -> Result<StaticFileAnalysis> {
    let tree = RUST_PARSER.with(|cell| cell.borrow_mut().parse(source.as_bytes(), None));

    let tree = match tree {
        Some(t) => t,
        None => {
            tracing::warn!("parser/rust: tree-sitter failed on {}", file.rel_path);
            return Ok(StaticFileAnalysis::empty(file));
        }
    };

    let query = &*RUST_QUERY;
    let ci = &*RUST_CAPTURES;
    let src = source.as_bytes();

    let mut out = StaticFileAnalysis {
        path: file.rel_path.clone(),
        language: Language::Rust,
        entry_points: Vec::with_capacity(16),
        exported_types: Vec::with_capacity(8),
        imports: Vec::with_capacity(16),
        todos: Vec::new(),
        unsafe_count: 0,
        unwrap_count: 0,
        panic_count: 0,
        branch_count: 0,
        module_doc: None,
        content_hash: None,
        line_count: 0,
    };

    // Collect `//!` inner doc lines in file-top position (rows 0-4).
    // Joined after the loop so we handle multi-line module docs correctly.
    let mut inner_doc_lines: Vec<(usize, String)> = Vec::new();

    let mut cursor = tree_sitter::QueryCursor::new();
    for m in cursor.matches(query, tree.root_node(), src) {
        for capture in m.captures {
            let idx = capture.index;
            let node = capture.node;

            if idx == ci.unsafe_ {
                out.unsafe_count += 1;
            } else if idx == ci.unwrap {
                out.unwrap_count += 1;
            } else if idx == ci.panic {
                out.panic_count += 1;
            } else if idx == ci.branch {
                out.branch_count += 1;
            } else if idx == ci.pub_fn || idx == ci.pub_mod {
                if let Ok(name) = node.utf8_text(src) {
                    out.entry_points.push(name.to_owned());
                }
            } else if idx == ci.pub_type {
                if let Ok(name) = node.utf8_text(src) {
                    out.exported_types.push(name.to_owned());
                }
            } else if idx == ci.import {
                let line = node.start_position().row as u32 + 1;
                decompose_use_tree(node, src, "", line, &mut out.imports);
            } else if idx == ci.comment {
                if let Ok(text) = node.utf8_text(src) {
                    let row = node.start_position().row;
                    let line = row as u32 + 1;
                    if let Some(todo) = extract_todo(text, line) {
                        out.todos.push(todo);
                    }
                    // Capture inner doc comments at the file top only.
                    // Handles both `//!` line style and `/*! ... */` block style.
                    if row < 5 {
                        if text.starts_with("//!") {
                            let stripped = text
                                .trim_start_matches("//!")
                                .trim_start_matches('/')
                                .trim()
                                .to_string();
                            if !stripped.is_empty() {
                                inner_doc_lines.push((row, stripped));
                            }
                        } else if text.starts_with("/*!") {
                            let inner =
                                text.trim_start_matches("/*!").trim_end_matches("*/").trim();
                            // Collapse all lines into one summary.
                            let collapsed: String = inner
                                .lines()
                                .map(|l| l.trim().trim_start_matches('*').trim())
                                .filter(|l| !l.is_empty())
                                .collect::<Vec<_>>()
                                .join(" ");
                            if !collapsed.is_empty() {
                                inner_doc_lines.push((row, collapsed));
                            }
                        }
                    }
                }
            }
        }
    }

    // Build module_doc from contiguous inner doc lines at file top.
    if !inner_doc_lines.is_empty() {
        inner_doc_lines.sort_by_key(|(r, _)| *r);
        // Only keep a contiguous block starting at the lowest captured row.
        let start_row = inner_doc_lines[0].0;
        let contiguous: Vec<&str> = inner_doc_lines
            .iter()
            .enumerate()
            .take_while(|(i, (r, _))| *r == start_row + i)
            .map(|(_, (_, text))| text.as_str())
            .collect();
        if !contiguous.is_empty() {
            out.module_doc = Some(super::normalize_doc(&contiguous.join(" ")));
        }
    }

    Ok(out)
}

/// Classify a Rust `use` path into an ImportKind at extraction time.
///
/// - `crate::`, `self::`, `super::` prefixes → internal (Normal or Wildcard)
/// - `::*` suffix → Wildcard
/// - Everything else (std::, external crates) → External
fn classify_rust_import(path: &str) -> ImportKind {
    let is_internal =
        path.starts_with("crate::") || path.starts_with("self::") || path.starts_with("super::");

    if !is_internal {
        return ImportKind::External;
    }

    if path.ends_with("::*") {
        ImportKind::Wildcard
    } else {
        ImportKind::Normal
    }
}

/// Recursively decompose a Rust `use` tree AST node into individual import paths.
///
/// Walks the tree-sitter node for a `use_declaration` argument. When a
/// `use_list` (brace group) is found, each child is visited recursively with
/// the accumulated prefix. Leaf paths (identifiers, scoped identifiers, `self`,
/// wildcards) emit one `ImportStatement` each.
///
/// Examples:
/// - `crate::store::db` → one import `"crate::store::db"`
/// - `crate::store::{record, db}` → two imports
/// - `crate::{a::{b, c}, d}` → three imports (a::b, a::c, d)
/// - `crate::a::{self, b}` → two imports (a, a::b)
/// - `crate::a::{b as c}` → one import `"crate::a::b"` (alias dropped)
fn decompose_use_tree(
    node: tree_sitter::Node,
    src: &[u8],
    prefix: &str,
    line: u32,
    out: &mut Vec<ImportStatement>,
) {
    match node.kind() {
        // `use crate::a::{b, c}` — the top-level argument is a `scoped_use_list`
        // with `path:` field (the prefix) and `list:` field (the brace group).
        "scoped_use_list" => {
            let path_prefix = node
                .child_by_field_name("path")
                .and_then(|n| n.utf8_text(src).ok())
                .unwrap_or("");
            let full_prefix = if prefix.is_empty() {
                path_prefix.to_owned()
            } else {
                format!("{prefix}::{path_prefix}")
            };
            if let Some(list) = node.child_by_field_name("list") {
                decompose_use_tree(list, src, &full_prefix, line, out);
            }
        }
        // The brace group itself: `{b, c}` or `{self, b}`.
        // Iterate named children — each is a use tree element.
        "use_list" => {
            for i in 0..node.named_child_count() {
                if let Some(child) = node.named_child(i) {
                    decompose_use_tree(child, src, prefix, line, out);
                }
            }
        }
        // `b as c` — extract only the original name, drop the alias.
        "use_as_clause" => {
            if let Some(name_node) = node.child_by_field_name("path") {
                // For renamed scoped paths like `a::b as c`, the path field
                // contains the full original path.
                if let Ok(name) = name_node.utf8_text(src) {
                    let full = if prefix.is_empty() {
                        name.to_owned()
                    } else {
                        format!("{prefix}::{name}")
                    };
                    let kind = classify_rust_import(&full);
                    out.push(ImportStatement::new(&full, kind, line));
                }
            }
        }
        // `self` inside a brace group → emit the prefix itself.
        "self" => {
            if !prefix.is_empty() {
                let kind = classify_rust_import(prefix);
                out.push(ImportStatement::new(prefix, kind, line));
            }
        }
        // Wildcard: `*` inside a brace group, or `crate::prelude::*` at top level.
        // The node text contains any embedded path prefix (e.g. `crate::prelude::*`
        // at top level, `a::*` inside a brace group, or bare `*`).
        "use_wildcard" => {
            if let Ok(text) = node.utf8_text(src) {
                let full = if prefix.is_empty() {
                    text.to_owned()
                } else {
                    format!("{prefix}::{text}")
                };
                let kind = classify_rust_import(&full);
                out.push(ImportStatement::new(&full, kind, line));
            }
        }
        // Leaf: an identifier, scoped_identifier, or any other terminal.
        // This handles simple paths like `crate::store::db` and individual
        // names inside brace groups like `record`.
        _ => {
            if let Ok(text) = node.utf8_text(src) {
                let full = if prefix.is_empty() {
                    text.to_owned()
                } else {
                    format!("{prefix}::{text}")
                };
                let kind = classify_rust_import(&full);
                out.push(ImportStatement::new(&full, kind, line));
            }
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::record::TodoKind;
    use tempfile::TempDir;

    fn make_file(dir: &TempDir, rel: &str, content: &str) -> WalkedFile {
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
            mtime_secs: 0,
        }
    }

    fn parse(dir: &TempDir, source: &str) -> StaticFileAnalysis {
        let f = make_file(dir, "test.rs", source);
        parse_rust(&f, source).unwrap()
    }

    // ── Entry points ──────────────────────────────────────────────────────────

    #[test]
    fn pub_fn_in_entry_points() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "pub fn foo() {}");
        assert!(a.entry_points.contains(&"foo".to_owned()));
    }

    #[test]
    fn private_fn_excluded() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "fn bar() {}");
        assert!(!a.entry_points.contains(&"bar".to_owned()));
    }

    #[test]
    fn pub_crate_fn_included() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "pub(crate) fn internal() {}");
        assert!(a.entry_points.contains(&"internal".to_owned()));
    }

    #[test]
    fn pub_mod_in_entry_points() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "pub mod utils {}");
        assert!(a.entry_points.contains(&"utils".to_owned()));
    }

    #[test]
    fn multiple_pub_fns() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "pub fn a() {} pub fn b() {} fn c() {}");
        assert_eq!(a.entry_points.len(), 2);
        assert!(a.entry_points.contains(&"a".to_owned()));
        assert!(a.entry_points.contains(&"b".to_owned()));
    }

    // ── Exported types ────────────────────────────────────────────────────────

    #[test]
    fn pub_struct() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "pub struct Foo { x: u32 }");
        assert!(a.exported_types.contains(&"Foo".to_owned()));
    }

    #[test]
    fn pub_enum() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "pub enum Color { Red, Green }");
        assert!(a.exported_types.contains(&"Color".to_owned()));
    }

    #[test]
    fn pub_trait() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "pub trait Runnable { fn run(&self); }");
        assert!(a.exported_types.contains(&"Runnable".to_owned()));
    }

    #[test]
    fn pub_type_alias() {
        let dir = TempDir::new().unwrap();
        let a = parse(
            &dir,
            "pub type Result<T> = std::result::Result<T, anyhow::Error>;",
        );
        assert!(a.exported_types.contains(&"Result".to_owned()));
    }

    #[test]
    fn private_struct_excluded() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "struct Internal { x: u32 }");
        assert!(a.exported_types.is_empty());
    }

    // ── Imports ───────────────────────────────────────────────────────────────

    #[test]
    fn use_statement() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "use std::collections::HashMap;");
        assert!(a.imports.iter().any(|i| i.path.contains("HashMap")));
    }

    #[test]
    fn multiple_imports() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "use std::fmt; use anyhow::Result;");
        assert_eq!(a.imports.len(), 2);
    }

    #[test]
    fn import_classification_external() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "use std::collections::HashMap;");
        assert_eq!(a.imports[0].kind, ImportKind::External);
    }

    #[test]
    fn import_classification_internal() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "use crate::store::db;");
        assert_eq!(a.imports[0].kind, ImportKind::Normal);
    }

    #[test]
    fn import_classification_wildcard() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "use crate::prelude::*;");
        assert_eq!(a.imports[0].kind, ImportKind::Wildcard);
    }

    #[test]
    fn import_line_number() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "// comment\nuse crate::foo;\n");
        assert_eq!(a.imports[0].line, 2);
    }

    // ── Risk signals ──────────────────────────────────────────────────────────

    #[test]
    fn unsafe_blocks() {
        let dir = TempDir::new().unwrap();
        let a = parse(
            &dir,
            "fn f() { unsafe { let _ = 1; } unsafe { let _ = 2; } }",
        );
        assert_eq!(a.unsafe_count, 2);
    }

    #[test]
    fn unwrap_calls() {
        let dir = TempDir::new().unwrap();
        let a = parse(
            &dir,
            r#"fn f() { "x".parse::<u32>().unwrap(); "y".parse::<u32>().unwrap(); }"#,
        );
        assert_eq!(a.unwrap_count, 2);
    }

    #[test]
    fn panic_macro() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, r#"fn f() { panic!("oh no"); }"#);
        assert_eq!(a.panic_count, 1);
    }

    #[test]
    fn if_expression_branch() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "fn f(x: bool) { if x { } }");
        assert_eq!(a.branch_count, 1);
    }

    #[test]
    fn match_expression_branch() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "fn f(x: u8) { match x { 0 => {}, _ => {} } }");
        assert_eq!(a.branch_count, 1);
    }

    #[test]
    fn else_if_two_branches() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "fn f(a: bool, b: bool) { if a {} else if b {} }");
        assert_eq!(a.branch_count, 2);
    }

    // ── TODOs ─────────────────────────────────────────────────────────────────

    #[test]
    fn todo_extracted() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "// TODO: fix this\nfn f() {}");
        assert_eq!(a.todos.len(), 1);
        assert_eq!(a.todos[0].kind, TodoKind::Todo);
    }

    #[test]
    fn fixme_extracted() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "// FIXME: broken\nfn f() {}");
        assert_eq!(a.todos[0].kind, TodoKind::Fixme);
    }

    #[test]
    fn doc_comment_todo() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "/// TODO: document\nfn f() {}");
        assert_eq!(a.todos[0].kind, TodoKind::Todo);
    }

    #[test]
    fn todo_line_number_one_based() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "fn f() {}\n// TODO: line 2\n");
        assert_eq!(a.todos[0].line, 2);
    }

    #[test]
    fn plain_comment_ignored() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "// just a comment\nfn f() {}");
        assert!(a.todos.is_empty());
    }

    // ── Module doc (//!) ──────────────────────────────────────────────────────

    #[test]
    fn inner_doc_at_top_sets_module_doc() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "//! Handles request routing.\nfn f() {}");
        assert_eq!(a.module_doc.as_deref(), Some("Handles request routing."));
    }

    #[test]
    fn multi_line_inner_doc_joined() {
        let dir = TempDir::new().unwrap();
        let src = "//! First line.\n//! Second line.\nfn f() {}";
        let a = parse(&dir, src);
        assert_eq!(a.module_doc.as_deref(), Some("First line. Second line."));
    }

    #[test]
    fn inner_doc_mid_file_ignored() {
        let dir = TempDir::new().unwrap();
        // row 5+ (0-indexed) — beyond the early-rows window
        let src = "fn f() {}\nfn g() {}\nfn h() {}\nfn i() {}\nfn j() {}\n//! late doc\nfn k() {}";
        let a = parse(&dir, src);
        assert!(a.module_doc.is_none());
    }

    #[test]
    fn block_inner_doc_sets_module_doc() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "/*!\nThe main entry point.\n*/\nfn f() {}");
        assert_eq!(a.module_doc.as_deref(), Some("The main entry point."));
    }

    #[test]
    fn no_inner_doc_yields_none() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "/// outer doc\nfn f() {}");
        assert!(a.module_doc.is_none());
    }

    // ── Edge cases ────────────────────────────────────────────────────────────

    #[test]
    fn empty_file() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "");
        assert!(a.entry_points.is_empty());
        assert_eq!(a.unsafe_count, 0);
        assert_eq!(a.unwrap_count, 0);
    }

    #[test]
    fn path_preserved() {
        let dir = TempDir::new().unwrap();
        let f = make_file(&dir, "src/lib.rs", "pub fn foo() {}");
        let a = parse_rust(&f, "pub fn foo() {}").unwrap();
        assert_eq!(a.path, "src/lib.rs");
    }

    // ── Brace decomposition ──────────────────────────────────────────────────

    #[test]
    fn brace_group_produces_multiple_imports() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "use crate::store::{record, db};");
        assert_eq!(a.imports.len(), 2);
        let paths: Vec<&str> = a.imports.iter().map(|i| i.path.as_str()).collect();
        assert!(paths.contains(&"crate::store::record"));
        assert!(paths.contains(&"crate::store::db"));
        assert!(a.imports.iter().all(|i| i.kind == ImportKind::Normal));
    }

    #[test]
    fn nested_brace_group_decomposes_recursively() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "use crate::{a::{b, c}, d};");
        assert_eq!(a.imports.len(), 3);
        let paths: Vec<&str> = a.imports.iter().map(|i| i.path.as_str()).collect();
        assert!(paths.contains(&"crate::a::b"));
        assert!(paths.contains(&"crate::a::c"));
        assert!(paths.contains(&"crate::d"));
    }

    #[test]
    fn wildcard_inside_brace_group() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "use crate::a::{b, *};");
        assert_eq!(a.imports.len(), 2);
        let paths: Vec<&str> = a.imports.iter().map(|i| i.path.as_str()).collect();
        assert!(paths.contains(&"crate::a::b"));
        assert!(paths.contains(&"crate::a::*"));
        assert!(a.imports.iter().any(|i| i.kind == ImportKind::Wildcard));
    }

    #[test]
    fn self_inside_brace_group() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "use crate::a::{self, b};");
        assert_eq!(a.imports.len(), 2);
        let paths: Vec<&str> = a.imports.iter().map(|i| i.path.as_str()).collect();
        assert!(paths.contains(&"crate::a"));
        assert!(paths.contains(&"crate::a::b"));
    }

    #[test]
    fn renamed_import_drops_alias() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "use crate::a::{b as c};");
        assert_eq!(a.imports.len(), 1);
        assert_eq!(a.imports[0].path, "crate::a::b");
    }

    #[test]
    fn non_brace_import_still_works() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "use crate::store::record;");
        assert_eq!(a.imports.len(), 1);
        assert_eq!(a.imports[0].path, "crate::store::record");
        assert_eq!(a.imports[0].kind, ImportKind::Normal);
    }

    #[test]
    fn deep_brace_with_trailing_path() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "use crate::store::{record::FileRecord, db::Store};");
        assert_eq!(a.imports.len(), 2);
        let paths: Vec<&str> = a.imports.iter().map(|i| i.path.as_str()).collect();
        assert!(paths.contains(&"crate::store::record::FileRecord"));
        assert!(paths.contains(&"crate::store::db::Store"));
    }
}
