//! C++ tree-sitter parser — entry points, includes, TODOs.
//!
//! Entry points: `function_declarator` inside `function_definition` only —
//! prototypes and forward declarations are excluded.
//! Extends C patterns with `class_specifier`, `field_identifier` for methods,
//! and `try_statement`. Single `comment` node type.

use std::cell::RefCell;
use std::sync::LazyLock;

use anyhow::Result;

use super::{extract_todo, normalize_doc, StaticFileAnalysis};
use crate::analysis::walker::{Language, WalkedFile};

// ── Static handles ────────────────────────────────────────────────────────────

static CPP_LANGUAGE: LazyLock<tree_sitter::Language> =
    LazyLock::new(|| tree_sitter_cpp::LANGUAGE.into());

const CPP_QUERY_SRC: &str = r#"
  ; --- plain return ---
  (function_definition
    declarator: (function_declarator
      declarator: (identifier) @fn_name))
  (function_definition
    declarator: (function_declarator
      declarator: (field_identifier) @fn_name))
  (function_definition
    declarator: (function_declarator
      declarator: (qualified_identifier name: (identifier) @fn_name)))

  ; --- pointer return ---
  (function_definition
    declarator: (pointer_declarator
      declarator: (function_declarator
        declarator: (identifier) @fn_name)))
  (function_definition
    declarator: (pointer_declarator
      declarator: (function_declarator
        declarator: (field_identifier) @fn_name)))
  (function_definition
    declarator: (pointer_declarator
      declarator: (function_declarator
        declarator: (qualified_identifier name: (identifier) @fn_name))))

  ; --- reference return ---
  (function_definition
    declarator: (reference_declarator
      (function_declarator
        declarator: (identifier) @fn_name)))
  (function_definition
    declarator: (reference_declarator
      (function_declarator
        declarator: (field_identifier) @fn_name)))
  (function_definition
    declarator: (reference_declarator
      (function_declarator
        declarator: (qualified_identifier name: (identifier) @fn_name))))

  (class_specifier name: (type_identifier) @type_name)
  (struct_specifier name: (type_identifier) @type_name body: (_))
  (union_specifier name: (type_identifier) @type_name body: (_))
  (enum_specifier name: (type_identifier) @type_name body: (_))

  (preproc_include path: (_) @include)

  (if_statement) @branch
  (for_statement) @branch
  (while_statement) @branch
  (do_statement) @branch
  (switch_statement) @branch
  (try_statement) @branch
  (conditional_expression) @branch

  (comment) @comment
"#;

static CPP_QUERY: LazyLock<tree_sitter::Query> = LazyLock::new(|| {
    tree_sitter::Query::new(&CPP_LANGUAGE, CPP_QUERY_SRC).expect("parser/cpp: invalid query")
});

static CPP_CAPTURES: LazyLock<CppCaptures> = LazyLock::new(|| CppCaptures::new(&CPP_QUERY));

thread_local! {
    static CPP_PARSER: RefCell<tree_sitter::Parser> = RefCell::new({
        let mut p = tree_sitter::Parser::new();
        p.set_language(&CPP_LANGUAGE).expect("parser/cpp: grammar load failed");
        p
    });
}

// ── Capture indices ───────────────────────────────────────────────────────────

struct CppCaptures {
    fn_name: u32,
    type_name: u32,
    include: u32,
    branch: u32,
    comment: u32,
}

impl CppCaptures {
    fn new(query: &tree_sitter::Query) -> Self {
        let idx = |name: &str| {
            query
                .capture_index_for_name(name)
                .unwrap_or_else(|| panic!("parser/cpp: query missing @{name}"))
        };
        Self {
            fn_name: idx("fn_name"),
            type_name: idx("type_name"),
            include: idx("include"),
            branch: idx("branch"),
            comment: idx("comment"),
        }
    }
}

// ── Parser ────────────────────────────────────────────────────────────────────

pub(super) fn parse_cpp(file: &WalkedFile, source: &str) -> Result<StaticFileAnalysis> {
    let tree = CPP_PARSER.with(|cell| cell.borrow_mut().parse(source.as_bytes(), None));

    let tree = match tree {
        Some(t) => t,
        None => {
            tracing::warn!("parser/cpp: tree-sitter failed on {}", file.rel_path);
            return Ok(StaticFileAnalysis::empty(file));
        }
    };

    let query = &*CPP_QUERY;
    let ci = &*CPP_CAPTURES;
    let src = source.as_bytes();

    let mut out = StaticFileAnalysis {
        path: file.rel_path.clone(),
        language: Language::Cpp,
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

    let mut doc_lines: Vec<(usize, String)> = Vec::new();
    let mut cursor = tree_sitter::QueryCursor::new();
    for m in cursor.matches(query, tree.root_node(), src) {
        for capture in m.captures {
            let idx = capture.index;
            let node = capture.node;

            if idx == ci.branch {
                out.branch_count += 1;
            } else if idx == ci.fn_name {
                if let Ok(name) = node.utf8_text(src) {
                    out.entry_points.push(name.to_owned());
                }
            } else if idx == ci.type_name {
                if let Ok(name) = node.utf8_text(src) {
                    out.exported_types.push(name.to_owned());
                }
            } else if idx == ci.include {
                if let Ok(path) = node.utf8_text(src) {
                    let stripped = path
                        .trim_matches('"')
                        .trim_start_matches('<')
                        .trim_end_matches('>');
                    out.imports.push(stripped.to_owned());
                }
            } else if idx == ci.comment {
                if let Ok(text) = node.utf8_text(src) {
                    let row = node.start_position().row;
                    let line = row as u32 + 1;
                    if let Some(todo) = extract_todo(text, line) {
                        out.todos.push(todo);
                    }
                    if row < 10 && text.starts_with("/*") {
                        let stripped = text
                            .trim_start_matches("/*")
                            .trim_end_matches("*/")
                            .lines()
                            .map(|l| l.trim().trim_start_matches('*').trim())
                            .filter(|l| !l.is_empty())
                            .collect::<Vec<_>>()
                            .join(" ");
                        if !stripped.is_empty() {
                            doc_lines.push((row, stripped));
                        }
                    } else if row < 10 && text.starts_with("//") {
                        let stripped = text.trim_start_matches("//").trim().to_string();
                        if !stripped.is_empty() {
                            doc_lines.push((row, stripped));
                        }
                    }
                }
            }
        }
    }

    if !doc_lines.is_empty() {
        doc_lines.sort_by_key(|(r, _)| *r);
        let start_row = doc_lines[0].0;
        let contiguous: Vec<&str> = doc_lines
            .iter()
            .enumerate()
            .take_while(|(i, (r, _))| *r == start_row + i)
            .map(|(_, (_, text))| text.as_str())
            .collect();
        if !contiguous.is_empty() {
            out.module_doc = Some(normalize_doc(&contiguous.join(" ")));
        }
    }

    Ok(out)
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
            language: Language::Cpp,
            size_bytes: content.len() as u64,
            mtime_secs: 0,
        }
    }

    fn parse(dir: &TempDir, source: &str) -> StaticFileAnalysis {
        let f = make_file(dir, "test.cpp", source);
        parse_cpp(&f, source).unwrap()
    }

    #[test]
    fn free_function_in_entry_points() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "int main() { return 0; }\n");
        assert!(a.entry_points.contains(&"main".to_owned()));
    }

    #[test]
    fn pointer_return_function_captured() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "char* dup() { return nullptr; }\n");
        assert!(a.entry_points.contains(&"dup".to_owned()));
    }

    #[test]
    fn reference_return_function_captured() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "int& getRef() { static int x; return x; }\n");
        assert!(a.entry_points.contains(&"getRef".to_owned()));
    }

    #[test]
    fn qualified_method_captured() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "class Foo {};\nvoid Foo::bar() {}\n");
        assert!(a.entry_points.contains(&"bar".to_owned()));
    }

    #[test]
    fn pointer_return_qualified_method_captured() {
        let dir = TempDir::new().unwrap();
        let a = parse(
            &dir,
            "class Foo {};\nchar* Foo::dup() { return nullptr; }\n",
        );
        assert!(a.entry_points.contains(&"dup".to_owned()));
    }

    #[test]
    fn reference_return_qualified_method_captured() {
        let dir = TempDir::new().unwrap();
        let a = parse(
            &dir,
            "class Widget {};\nint& Widget::value() { static int x; return x; }\n",
        );
        assert!(a.entry_points.contains(&"value".to_owned()));
    }

    #[test]
    fn prototype_excluded_from_entry_points() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "int f(int x);\nvoid g();\n");
        assert!(a.entry_points.is_empty());
    }

    #[test]
    fn branch_ternary() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "int f(int x) { return x ? 1 : 0; }\n");
        assert_eq!(a.branch_count, 1);
    }

    #[test]
    fn union_in_exported_types() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "union Data { int i; float f; };\n");
        assert!(a.exported_types.contains(&"Data".to_owned()));
    }

    #[test]
    fn class_method_in_entry_points() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "class Foo { public: void bar() {} };\n");
        assert!(a.entry_points.contains(&"bar".to_owned()));
    }

    #[test]
    fn class_in_exported_types() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "class Widget {};\n");
        assert!(a.exported_types.contains(&"Widget".to_owned()));
    }

    #[test]
    fn struct_definition_in_exported_types() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "struct Point { int x; int y; };\n");
        assert!(a.exported_types.contains(&"Point".to_owned()));
    }

    #[test]
    fn include_captured() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "#include <iostream>\nint main() { return 0; }\n");
        assert!(a.imports.contains(&"iostream".to_owned()));
    }

    #[test]
    fn todo_captured() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "// TODO: refactor\nint main() { return 0; }\n");
        assert_eq!(a.todos.len(), 1);
        assert_eq!(a.todos[0].kind, TodoKind::Todo);
    }

    #[test]
    fn branch_try() {
        let dir = TempDir::new().unwrap();
        let a = parse(
            &dir,
            "int f() { try { throw 1; } catch (...) { return 0; } }\n",
        );
        assert_eq!(a.branch_count, 1);
    }

    #[test]
    fn empty_file() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "");
        assert!(a.entry_points.is_empty());
        assert_eq!(a.branch_count, 0);
    }

    #[test]
    fn no_rust_specific_fields_set() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "int f() { return 0; }\n");
        assert_eq!(a.unsafe_count, 0);
        assert_eq!(a.unwrap_count, 0);
        assert_eq!(a.panic_count, 0);
    }
}
