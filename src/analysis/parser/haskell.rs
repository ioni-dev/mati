//! Haskell tree-sitter parser — entry points, imports, TODOs.
//!
//! `haddock` is a first-class AST node separate from `comment` — used for
//! module doc. Both `comment` and `haddock` are scanned for TODOs.
//! Control flow: `case` and `conditional` (if-then-else).

use std::cell::RefCell;
use std::sync::LazyLock;

use anyhow::Result;

use super::{extract_todo, normalize_doc, ImportKind, ImportStatement, StaticFileAnalysis};
use crate::analysis::walker::{Language, WalkedFile};

// ── Static handles ────────────────────────────────────────────────────────────

static HASKELL_LANGUAGE: LazyLock<tree_sitter::Language> =
    LazyLock::new(|| tree_sitter_haskell::LANGUAGE.into());

const HASKELL_QUERY_SRC: &str = r#"
  (function name: (variable) @fn_name)
  (bind name: (variable) @fn_name)

  (data_type name: (_) @type_name)
  (newtype name: (_) @type_name)
  (class name: (_) @type_name)

  (import module: (module) @import)

  (comment) @comment
  (haddock) @haddock
"#;

static HASKELL_QUERY: LazyLock<tree_sitter::Query> = LazyLock::new(|| {
    tree_sitter::Query::new(&HASKELL_LANGUAGE, HASKELL_QUERY_SRC)
        .expect("parser/haskell: invalid query")
});

static HASKELL_CAPTURES: LazyLock<HaskellCaptures> =
    LazyLock::new(|| HaskellCaptures::new(&HASKELL_QUERY));

thread_local! {
    static HASKELL_PARSER: RefCell<tree_sitter::Parser> = RefCell::new({
        let mut p = tree_sitter::Parser::new();
        p.set_language(&HASKELL_LANGUAGE).expect("parser/haskell: grammar load failed");
        p
    });
}

// ── Capture indices ───────────────────────────────────────────────────────────

struct HaskellCaptures {
    fn_name: u32,
    type_name: u32,
    import: u32,
    comment: u32,
    haddock: u32,
}

impl HaskellCaptures {
    fn new(query: &tree_sitter::Query) -> Self {
        let idx = |name: &str| {
            query
                .capture_index_for_name(name)
                .unwrap_or_else(|| panic!("parser/haskell: query missing @{name}"))
        };
        Self {
            fn_name: idx("fn_name"),
            type_name: idx("type_name"),
            import: idx("import"),
            comment: idx("comment"),
            haddock: idx("haddock"),
        }
    }
}

// ── Parser ────────────────────────────────────────────────────────────────────

pub(super) fn parse_haskell(file: &WalkedFile, source: &str) -> Result<StaticFileAnalysis> {
    let tree = HASKELL_PARSER.with(|cell| cell.borrow_mut().parse(source.as_bytes(), None));

    let tree = match tree {
        Some(t) => t,
        None => {
            tracing::warn!("parser/haskell: tree-sitter failed on {}", file.rel_path);
            return Ok(StaticFileAnalysis::empty(file));
        }
    };

    let query = &*HASKELL_QUERY;
    let ci = &*HASKELL_CAPTURES;
    let src = source.as_bytes();

    let mut out = StaticFileAnalysis {
        path: file.rel_path.clone(),
        language: Language::Haskell,
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

    // Count branches by walking the tree (case, conditional are expression nodes,
    // not captured by our simple query to keep it safe from node-type changes).
    count_branches(tree.root_node(), &mut out.branch_count);

    let mut doc_lines: Vec<(usize, String)> = Vec::new();
    let mut cursor = tree_sitter::QueryCursor::new();
    for m in cursor.matches(query, tree.root_node(), src) {
        for capture in m.captures {
            let idx = capture.index;
            let node = capture.node;

            if idx == ci.fn_name {
                if let Ok(name) = node.utf8_text(src) {
                    out.entry_points.push(name.to_owned());
                }
            } else if idx == ci.type_name {
                if let Ok(name) = node.utf8_text(src) {
                    out.exported_types.push(name.to_owned());
                }
            } else if idx == ci.import {
                if let Ok(text) = node.utf8_text(src) {
                    out.imports.push(ImportStatement::new(
                        text.to_owned(),
                        ImportKind::Normal,
                        node.start_position().row as u32 + 1,
                    ));
                }
            } else if idx == ci.comment {
                if let Ok(text) = node.utf8_text(src) {
                    let line = node.start_position().row as u32 + 1;
                    // Haskell uses `-- ` comments; extract_todo strips `/` and `#`
                    // but not `--`. Pre-strip for Haskell.
                    let stripped = text.trim_start_matches('-').trim();
                    let prefixed = format!("// {stripped}");
                    if let Some(todo) = extract_todo(&prefixed, line) {
                        out.todos.push(todo);
                    }
                }
            } else if idx == ci.haddock {
                if let Ok(text) = node.utf8_text(src) {
                    let row = node.start_position().row;
                    let line = row as u32 + 1;
                    // Haddock uses `-- |`, `-- ^`, `{-|` prefixes.
                    // Strip them before passing to extract_todo.
                    let stripped = text
                        .trim_start_matches("-- |")
                        .trim_start_matches("-- ^")
                        .trim_start_matches("{-|")
                        .trim_end_matches("-}")
                        .trim();
                    let prefixed = format!("// {stripped}");
                    if let Some(todo) = extract_todo(&prefixed, line) {
                        out.todos.push(todo);
                    }
                    // Capture file-top Haddock as module doc.
                    if row < 10 {
                        let stripped = text
                            .trim_start_matches("-- |")
                            .trim_start_matches("-- ^")
                            .trim_start_matches("{-|")
                            .trim_end_matches("-}")
                            .trim();
                        if !stripped.is_empty() {
                            doc_lines.push((row, stripped.to_string()));
                        }
                    }
                }
            }
        }
    }

    if !doc_lines.is_empty() {
        doc_lines.sort_by_key(|(r, _)| *r);
        let combined: String = doc_lines
            .iter()
            .map(|(_, text)| text.as_str())
            .collect::<Vec<_>>()
            .join(" ");
        out.module_doc = Some(normalize_doc(&combined));
    }

    Ok(out)
}

/// Walk the AST and count branch-like named nodes.
/// Anonymous nodes (keyword tokens like `case`) are skipped to avoid double-counting.
fn count_branches(node: tree_sitter::Node, count: &mut u32) {
    if node.is_named() {
        match node.kind() {
            "case" | "conditional" | "multi_way_if" | "lambda_case" | "lambda_cases" => {
                *count += 1;
            }
            _ => {}
        }
    }
    let mut child_cursor = node.walk();
    for child in node.children(&mut child_cursor) {
        count_branches(child, count);
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
            language: Language::Haskell,
            size_bytes: content.len() as u64,
            mtime_secs: 0,
        }
    }

    fn parse(dir: &TempDir, source: &str) -> StaticFileAnalysis {
        let f = make_file(dir, "Test.hs", source);
        parse_haskell(&f, source).unwrap()
    }

    #[test]
    fn function_in_entry_points() {
        let dir = TempDir::new().unwrap();
        let a = parse(
            &dir,
            "module Main where\n\nhello :: String\nhello = \"hi\"\n",
        );
        assert!(a.entry_points.contains(&"hello".to_owned()));
    }

    #[test]
    fn data_type_in_exported_types() {
        let dir = TempDir::new().unwrap();
        let a = parse(
            &dir,
            "module Main where\n\ndata Color = Red | Green | Blue\n",
        );
        assert!(a.exported_types.contains(&"Color".to_owned()));
    }

    #[test]
    fn newtype_in_exported_types() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "module Main where\n\nnewtype Name = Name String\n");
        assert!(a.exported_types.contains(&"Name".to_owned()));
    }

    #[test]
    fn class_in_exported_types() {
        let dir = TempDir::new().unwrap();
        let a = parse(
            &dir,
            "module Main where\n\nclass Printable a where\n  display :: a -> String\n",
        );
        assert!(a.exported_types.contains(&"Printable".to_owned()));
    }

    #[test]
    fn import_captured_with_exact_value() {
        let dir = TempDir::new().unwrap();
        let a = parse(
            &dir,
            "module Main where\n\nimport Data.List\n\nmain = putStrLn \"hi\"\n",
        );
        assert!(a.imports.iter().any(|i| i.path == "Data.List"));
    }

    #[test]
    fn branch_case() {
        let dir = TempDir::new().unwrap();
        let a = parse(
            &dir,
            "module Main where\n\nf x = case x of\n  1 -> \"a\"\n  _ -> \"b\"\n",
        );
        assert_eq!(a.branch_count, 1);
    }

    #[test]
    fn branch_conditional() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "module Main where\n\nf x = if x then 1 else 0\n");
        assert_eq!(a.branch_count, 1);
    }

    #[test]
    fn haddock_module_doc_captured() {
        let dir = TempDir::new().unwrap();
        let a = parse(
            &dir,
            "-- | Main application module.\nmodule Main where\n\nmain = putStrLn \"hi\"\n",
        );
        assert_eq!(a.module_doc.as_deref(), Some("Main application module."));
    }

    #[test]
    fn todo_in_comment() {
        let dir = TempDir::new().unwrap();
        let a = parse(
            &dir,
            "module Main where\n\n-- TODO: fix this\nmain = putStrLn \"hi\"\n",
        );
        assert_eq!(a.todos.len(), 1);
        assert_eq!(a.todos[0].kind, TodoKind::Todo);
    }

    #[test]
    fn empty_file() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "");
        assert!(a.entry_points.is_empty());
        assert!(a.imports.is_empty());
        assert_eq!(a.branch_count, 0);
    }

    #[test]
    fn no_rust_specific_fields_set() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "module Main where\n\nmain = putStrLn \"hi\"\n");
        assert_eq!(a.unsafe_count, 0);
        assert_eq!(a.unwrap_count, 0);
        assert_eq!(a.panic_count, 0);
    }

    #[test]
    fn path_preserved() {
        let dir = TempDir::new().unwrap();
        let f = make_file(&dir, "src/Lib.hs", "module Lib where\n");
        let a = parse_haskell(&f, "module Lib where\n").unwrap();
        assert_eq!(a.path, "src/Lib.hs");
    }
}
