//! Go tree-sitter parser — entry points, imports, TODOs.
//!
//! Entry point filtering: captures ALL `function_declaration` and
//! `method_declaration` nodes, then filters in the dispatch loop:
//! - Only exported identifiers (first character is uppercase)
//!
//! Imports: captures both single-path and grouped import declarations.

use std::cell::RefCell;
use std::sync::LazyLock;

use anyhow::Result;

use crate::analysis::walker::{Language, WalkedFile};
use super::{StaticFileAnalysis, extract_todo};

// ── Static handles ────────────────────────────────────────────────────────────

static GO_LANGUAGE: LazyLock<tree_sitter::Language> =
    LazyLock::new(|| tree_sitter_go::LANGUAGE.into());

const GO_QUERY_SRC: &str = r#"
  (function_declaration name: (identifier) @fn_name)
  (method_declaration name: (field_identifier) @method_name)

  (import_spec path: (interpreted_string_literal) @import)

  (type_declaration (type_spec name: (type_identifier) @type_name))

  (if_statement) @branch
  (for_statement) @branch
  (expression_switch_statement) @branch
  (select_statement) @branch
  (type_switch_statement) @branch

  (comment) @comment
"#;

static GO_QUERY: LazyLock<tree_sitter::Query> = LazyLock::new(|| {
    tree_sitter::Query::new(&GO_LANGUAGE, GO_QUERY_SRC)
        .expect("parser/go: invalid query")
});

static GO_CAPTURES: LazyLock<GoCaptures> =
    LazyLock::new(|| GoCaptures::new(&GO_QUERY));

thread_local! {
    static GO_PARSER: RefCell<tree_sitter::Parser> = RefCell::new({
        let mut p = tree_sitter::Parser::new();
        p.set_language(&GO_LANGUAGE).expect("parser/go: grammar load failed");
        p
    });
}

// ── Capture indices ───────────────────────────────────────────────────────────

struct GoCaptures {
    fn_name: u32,
    method_name: u32,
    import: u32,
    type_name: u32,
    branch: u32,
    comment: u32,
}

impl GoCaptures {
    fn new(query: &tree_sitter::Query) -> Self {
        let idx = |name: &str| {
            query.capture_index_for_name(name)
                .unwrap_or_else(|| panic!("parser/go: query missing @{name}"))
        };
        Self {
            fn_name: idx("fn_name"),
            method_name: idx("method_name"),
            import: idx("import"),
            type_name: idx("type_name"),
            branch: idx("branch"),
            comment: idx("comment"),
        }
    }
}

// ── Parser ────────────────────────────────────────────────────────────────────

pub(super) fn parse_go(file: &WalkedFile, source: &str) -> Result<StaticFileAnalysis> {
    let tree = GO_PARSER.with(|cell| {
        cell.borrow_mut().parse(source.as_bytes(), None)
    });

    let tree = match tree {
        Some(t) => t,
        None => {
            tracing::warn!("parser/go: tree-sitter failed on {}", file.rel_path);
            return Ok(StaticFileAnalysis::empty(file));
        }
    };

    let query = &*GO_QUERY;
    let ci = &*GO_CAPTURES;
    let src = source.as_bytes();

    let mut out = StaticFileAnalysis {
        path: file.rel_path.clone(),
        language: Language::Go,
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

    let mut cursor = tree_sitter::QueryCursor::new();
    for m in cursor.matches(query, tree.root_node(), src) {
        for capture in m.captures {
            let idx = capture.index;
            let node = capture.node;

            if idx == ci.branch {
                out.branch_count += 1;
            } else if idx == ci.fn_name || idx == ci.method_name {
                if let Ok(name) = node.utf8_text(src) {
                    if is_exported(name) {
                        out.entry_points.push(name.to_owned());
                    }
                }
            } else if idx == ci.type_name {
                if let Ok(name) = node.utf8_text(src) {
                    if is_exported(name) {
                        out.exported_types.push(name.to_owned());
                    }
                }
            } else if idx == ci.import {
                if let Ok(path) = node.utf8_text(src) {
                    // Strip surrounding quotes from the interpreted_string_literal
                    let stripped = path.trim_matches('"');
                    out.imports.push(stripped.to_owned());
                }
            } else if idx == ci.comment {
                if let Ok(text) = node.utf8_text(src) {
                    let line = node.start_position().row as u32 + 1;
                    if let Some(todo) = extract_todo(text, line) {
                        out.todos.push(todo);
                    }
                }
            }
        }
    }

    Ok(out)
}

/// Returns true if the identifier is exported in Go (first char is uppercase).
fn is_exported(name: &str) -> bool {
    name.chars().next().is_some_and(|c| c.is_uppercase())
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
            language: Language::Go,
            size_bytes: content.len() as u64,
            mtime_secs: 0,
        }
    }

    fn parse(dir: &TempDir, source: &str) -> StaticFileAnalysis {
        let f = make_file(dir, "test.go", source);
        parse_go(&f, source).unwrap()
    }

    // ── Entry points: top-level functions ─────────────────────────────────────

    #[test]
    fn exported_func_in_entry_points() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "package main\n\nfunc ExportedFunc() {}\n");
        assert!(a.entry_points.contains(&"ExportedFunc".to_owned()));
    }

    #[test]
    fn unexported_func_excluded() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "package main\n\nfunc unexportedFunc() {}\n");
        assert!(!a.entry_points.contains(&"unexportedFunc".to_owned()));
    }

    #[test]
    fn main_func_excluded() {
        // main is lowercase — unexported by Go convention
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "package main\n\nfunc main() {}\n");
        assert!(!a.entry_points.contains(&"main".to_owned()));
    }

    // ── Entry points: methods ─────────────────────────────────────────────────

    #[test]
    fn exported_method_in_entry_points() {
        let dir = TempDir::new().unwrap();
        let src = "package main\n\ntype Foo struct{}\n\nfunc (f Foo) ServeHTTP() {}\n";
        let a = parse(&dir, src);
        assert!(a.entry_points.contains(&"ServeHTTP".to_owned()));
    }

    #[test]
    fn unexported_method_excluded() {
        let dir = TempDir::new().unwrap();
        let src = "package main\n\ntype Foo struct{}\n\nfunc (f Foo) helper() {}\n";
        let a = parse(&dir, src);
        assert!(!a.entry_points.contains(&"helper".to_owned()));
    }

    #[test]
    fn pointer_receiver_method_exported() {
        let dir = TempDir::new().unwrap();
        let src = "package main\n\ntype Bar struct{}\n\nfunc (b *Bar) Handle() {}\n";
        let a = parse(&dir, src);
        assert!(a.entry_points.contains(&"Handle".to_owned()));
    }

    // ── Imports ───────────────────────────────────────────────────────────────

    #[test]
    fn single_import() {
        let dir = TempDir::new().unwrap();
        let src = "package main\n\nimport \"fmt\"\n\nfunc main() {}\n";
        let a = parse(&dir, src);
        assert!(a.imports.contains(&"fmt".to_owned()));
    }

    #[test]
    fn grouped_imports() {
        let dir = TempDir::new().unwrap();
        let src = r#"package main

import (
    "fmt"
    "os"
    "net/http"
)

func main() {}
"#;
        let a = parse(&dir, src);
        assert!(a.imports.contains(&"fmt".to_owned()));
        assert!(a.imports.contains(&"os".to_owned()));
        assert!(a.imports.contains(&"net/http".to_owned()));
    }

    #[test]
    fn import_quotes_stripped() {
        let dir = TempDir::new().unwrap();
        let src = "package main\n\nimport \"encoding/json\"\n\nfunc F() {}\n";
        let a = parse(&dir, src);
        // Import should not contain surrounding quotes
        assert!(a.imports.iter().all(|i| !i.starts_with('"')));
        assert!(a.imports.contains(&"encoding/json".to_owned()));
    }

    // ── TODOs ─────────────────────────────────────────────────────────────────

    #[test]
    fn todo_in_line_comment() {
        let dir = TempDir::new().unwrap();
        let src = "package main\n\n// TODO: fix this\nfunc F() {}\n";
        let a = parse(&dir, src);
        assert_eq!(a.todos.len(), 1);
        assert_eq!(a.todos[0].kind, TodoKind::Todo);
    }

    #[test]
    fn fixme_in_comment() {
        let dir = TempDir::new().unwrap();
        let src = "package main\n\n// FIXME: broken\nfunc F() {}\n";
        let a = parse(&dir, src);
        assert_eq!(a.todos[0].kind, TodoKind::Fixme);
    }

    #[test]
    fn hack_in_comment() {
        let dir = TempDir::new().unwrap();
        let src = "package main\n\n// HACK: workaround\nfunc F() {}\n";
        let a = parse(&dir, src);
        assert_eq!(a.todos[0].kind, TodoKind::Hack);
    }

    #[test]
    fn plain_comment_not_captured_as_todo() {
        let dir = TempDir::new().unwrap();
        let src = "package main\n\n// just a comment\nfunc F() {}\n";
        let a = parse(&dir, src);
        assert!(a.todos.is_empty());
    }

    #[test]
    fn todo_line_number_one_based() {
        let dir = TempDir::new().unwrap();
        let src = "package main\n\nfunc F() {}\n// TODO: line 4\n";
        let a = parse(&dir, src);
        assert_eq!(a.todos[0].line, 4);
    }

    // ── Exported types ────────────────────────────────────────────────────────

    #[test]
    fn exported_type_in_exported_types() {
        let dir = TempDir::new().unwrap();
        let src = "package main\n\ntype MyHandler struct{}\n";
        let a = parse(&dir, src);
        assert!(a.exported_types.contains(&"MyHandler".to_owned()));
    }

    #[test]
    fn unexported_type_excluded() {
        let dir = TempDir::new().unwrap();
        let src = "package main\n\ntype internalState struct{}\n";
        let a = parse(&dir, src);
        assert!(!a.exported_types.contains(&"internalState".to_owned()));
    }

    // ── Edge cases ────────────────────────────────────────────────────────────

    #[test]
    fn empty_file() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "");
        assert!(a.entry_points.is_empty());
        assert!(a.imports.is_empty());
        assert_eq!(a.branch_count, 0);
    }

    #[test]
    fn path_preserved() {
        let dir = TempDir::new().unwrap();
        let f = make_file(&dir, "cmd/server/main.go", "package main\nfunc main() {}\n");
        let a = parse_go(&f, "package main\nfunc main() {}\n").unwrap();
        assert_eq!(a.path, "cmd/server/main.go");
    }

    #[test]
    fn no_rust_specific_fields_set() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "package main\nfunc F() {}\n");
        assert_eq!(a.unsafe_count, 0);
        assert_eq!(a.unwrap_count, 0);
        assert_eq!(a.panic_count, 0);
    }

    #[test]
    fn branch_if() {
        let dir = TempDir::new().unwrap();
        let src = "package main\nfunc F(x bool) {\n    if x {\n    }\n}\n";
        let a = parse(&dir, src);
        assert_eq!(a.branch_count, 1);
    }

    #[test]
    fn branch_for() {
        let dir = TempDir::new().unwrap();
        let src = "package main\nfunc F() {\n    for i := 0; i < 10; i++ {\n    }\n}\n";
        let a = parse(&dir, src);
        assert_eq!(a.branch_count, 1);
    }
}
