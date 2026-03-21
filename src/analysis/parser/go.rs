//! Go tree-sitter parser — functions, methods, types, imports, TODOs.
//!
//! Entry point filtering: ALL `function_declaration` and `method_declaration`
//! nodes are captured, then filtered:
//! - Names with uppercase first character are exported (Go convention)
//! - `function_declaration` is always top-level in Go — no parent check needed
//! - `method_declaration` is always top-level — methods on exported receivers
//!   are included regardless of receiver type name
//!
//! No unsafe/unwrap/panic detection — concepts do not apply to Go.
//! Import paths are `interpreted_string_literal` including surrounding quotes —
//! quotes are stripped before storing.

use std::cell::RefCell;
use std::sync::LazyLock;

use anyhow::Result;

use crate::analysis::walker::{Language, WalkedFile};
use super::{StaticFileAnalysis, extract_todo};

// ── Static handles ────────────────────────────────────────────────────────────

static GO_LANGUAGE: LazyLock<tree_sitter::Language> =
    LazyLock::new(|| tree_sitter_go::LANGUAGE.into());

const GO_QUERY_SRC: &str = r#"
  (function_declaration name: (identifier)       @fn_name)
  (method_declaration   name: (field_identifier) @method_name)
  (type_declaration (type_spec name: (type_identifier) @type_name))

  (import_spec path: (interpreted_string_literal) @import)

  (if_statement)                @branch
  (for_statement)               @branch
  (expression_switch_statement) @branch
  (type_switch_statement)       @branch
  (select_statement)            @branch

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
        p.set_language(&*GO_LANGUAGE).expect("parser/go: grammar load failed");
        p
    });
}

// ── Capture indices ───────────────────────────────────────────────────────────

struct GoCaptures {
    fn_name:     u32,
    method_name: u32,
    type_name:   u32,
    import:      u32,
    branch:      u32,
    comment:     u32,
}

impl GoCaptures {
    fn new(query: &tree_sitter::Query) -> Self {
        let idx = |name: &str| {
            query.capture_index_for_name(name)
                .unwrap_or_else(|| panic!("parser/go: query missing @{name}"))
        };
        Self {
            fn_name:     idx("fn_name"),
            method_name: idx("method_name"),
            type_name:   idx("type_name"),
            import:      idx("import"),
            branch:      idx("branch"),
            comment:     idx("comment"),
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
    let ci    = &*GO_CAPTURES;
    let src   = source.as_bytes();

    let mut out = StaticFileAnalysis {
        path:           file.rel_path.clone(),
        language:       Language::Go,
        entry_points:   Vec::with_capacity(16),
        exported_types: Vec::with_capacity(8),
        imports:        Vec::with_capacity(16),
        todos:          Vec::new(),
        unsafe_count:   0,
        unwrap_count:   0,
        panic_count:    0,
        branch_count:   0,
    };

    let mut cursor = tree_sitter::QueryCursor::new();
    for m in cursor.matches(query, tree.root_node(), src) {
        for capture in m.captures {
            let idx  = capture.index;
            let node = capture.node;

            if idx == ci.branch {
                out.branch_count += 1;
            } else if idx == ci.fn_name {
                if let Ok(name) = node.utf8_text(src) {
                    if is_exported(name) {
                        out.entry_points.push(name.to_owned());
                    }
                }
            } else if idx == ci.method_name {
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
                if let Ok(raw) = node.utf8_text(src) {
                    // interpreted_string_literal includes surrounding double quotes
                    let path = raw.trim_matches('"');
                    if !path.is_empty() {
                        out.imports.push(path.to_owned());
                    }
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

/// Go export convention: names starting with an uppercase letter are exported.
#[inline]
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
            abs_path:   abs,
            rel_path:   rel.to_owned(),
            language:   Language::Go,
            size_bytes: content.len() as u64,
            mtime_secs: 0,
        }
    }

    fn parse(dir: &TempDir, source: &str) -> StaticFileAnalysis {
        let f = make_file(dir, "test.go", source);
        parse_go(&f, source).unwrap()
    }

    // ── Entry points: functions ───────────────────────────────────────────────

    #[test]
    fn exported_function_is_entry_point() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "package main\nfunc Serve() {}\n");
        assert!(a.entry_points.contains(&"Serve".to_owned()));
    }

    #[test]
    fn unexported_function_excluded() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "package main\nfunc serve() {}\n");
        assert!(a.entry_points.is_empty());
    }

    #[test]
    fn main_function_is_entry_point() {
        let dir = TempDir::new().unwrap();
        // 'main' starts lowercase — not exported by Go convention, but
        // it is the program entry. We deliberately exclude it (lowercase rule).
        // This is consistent with the Python private-function rule: mati
        // captures exported API surface, not the binary entry.
        let a = parse(&dir, "package main\nfunc main() {}\n");
        assert!(a.entry_points.is_empty());
    }

    // ── Entry points: methods ─────────────────────────────────────────────────

    #[test]
    fn exported_method_is_entry_point() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "package http\nfunc (s *Server) Handle(w http.ResponseWriter, r *http.Request) {}\n");
        assert!(a.entry_points.contains(&"Handle".to_owned()));
    }

    #[test]
    fn unexported_method_excluded() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "package http\nfunc (s *Server) handle() {}\n");
        assert!(a.entry_points.is_empty());
    }

    // ── Exported types ────────────────────────────────────────────────────────

    #[test]
    fn exported_struct_captured() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "package main\ntype Server struct { port int }\n");
        assert!(a.exported_types.contains(&"Server".to_owned()));
    }

    #[test]
    fn exported_interface_captured() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "package main\ntype Handler interface { ServeHTTP() }\n");
        assert!(a.exported_types.contains(&"Handler".to_owned()));
    }

    #[test]
    fn unexported_type_excluded() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "package main\ntype server struct {}\n");
        assert!(a.exported_types.is_empty());
    }

    // ── Imports ───────────────────────────────────────────────────────────────

    #[test]
    fn single_import_no_quotes() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "package main\nimport \"fmt\"\n");
        assert!(a.imports.contains(&"fmt".to_owned()));
    }

    #[test]
    fn grouped_imports() {
        let dir = TempDir::new().unwrap();
        let src = "package main\nimport (\n\t\"fmt\"\n\t\"os\"\n)\n";
        let a = parse(&dir, src);
        assert!(a.imports.contains(&"fmt".to_owned()));
        assert!(a.imports.contains(&"os".to_owned()));
    }

    #[test]
    fn aliased_import_path_captured() {
        let dir = TempDir::new().unwrap();
        // import alias "pkg/path" — path field is still captured, alias ignored
        let a = parse(&dir, "package main\nimport myfmt \"fmt\"\n");
        assert!(a.imports.contains(&"fmt".to_owned()));
    }

    // ── Branches ─────────────────────────────────────────────────────────────

    #[test]
    fn if_branch_counted() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "package main\nfunc f() { if true {} }\n");
        assert_eq!(a.branch_count, 1);
    }

    #[test]
    fn for_branch_counted() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "package main\nfunc f() { for i := 0; i < 10; i++ {} }\n");
        assert_eq!(a.branch_count, 1);
    }

    #[test]
    fn switch_branch_counted() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "package main\nfunc f(x int) { switch x { case 1: } }\n");
        assert_eq!(a.branch_count, 1);
    }

    #[test]
    fn select_branch_counted() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "package main\nfunc f(ch chan int) { select { case <-ch: } }\n");
        assert_eq!(a.branch_count, 1);
    }

    // ── TODOs ─────────────────────────────────────────────────────────────────

    #[test]
    fn todo_extracted() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "package main\n// TODO: fix this\nfunc f() {}\n");
        assert_eq!(a.todos.len(), 1);
        assert_eq!(a.todos[0].kind, TodoKind::Todo);
    }

    #[test]
    fn fixme_extracted() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "package main\n// FIXME: broken\nfunc f() {}\n");
        assert_eq!(a.todos.len(), 1);
        assert_eq!(a.todos[0].kind, TodoKind::Fixme);
    }

    #[test]
    fn plain_comment_not_captured_as_todo() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "package main\n// this is just a comment\n");
        assert!(a.todos.is_empty());
    }

    // ── Risk counts always zero ───────────────────────────────────────────────

    #[test]
    fn no_risk_counts() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "package main\nfunc Foo() { if true {} }\n");
        assert_eq!(a.unsafe_count, 0);
        assert_eq!(a.unwrap_count, 0);
        assert_eq!(a.panic_count, 0);
    }

    // ── Edge cases ────────────────────────────────────────────────────────────

    #[test]
    fn empty_file() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "");
        assert!(a.entry_points.is_empty());
        assert!(a.exported_types.is_empty());
        assert!(a.imports.is_empty());
        assert_eq!(a.branch_count, 0);
    }

    #[test]
    fn path_preserved() {
        let dir = TempDir::new().unwrap();
        let f = make_file(&dir, "pkg/server/server.go", "package server\nfunc New() {}\n");
        let a = parse_go(&f, "package server\nfunc New() {}\n").unwrap();
        assert_eq!(a.path, "pkg/server/server.go");
    }
}
