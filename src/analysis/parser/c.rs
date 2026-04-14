//! C tree-sitter parser — entry points, includes, TODOs.
//!
//! Entry points: `function_declarator` identifiers inside `function_definition`
//! only — prototypes and forward declarations are excluded.
//! Types: `struct`, `union`, `enum` with `body` (definitions only, not forward decls).
//! Includes: `preproc_include` path with `<>` and `""` stripped.
//! Single `comment` node type for both `//` and `/* */`.

use std::cell::RefCell;
use std::sync::LazyLock;

use anyhow::Result;

use super::{extract_todo, normalize_doc, ImportKind, ImportStatement, StaticFileAnalysis};
use crate::analysis::walker::{Language, WalkedFile};

// ── Static handles ────────────────────────────────────────────────────────────

static C_LANGUAGE: LazyLock<tree_sitter::Language> =
    LazyLock::new(|| tree_sitter_c::LANGUAGE.into());

const C_QUERY_SRC: &str = r#"
  (function_definition
    declarator: (function_declarator
      declarator: (identifier) @fn_name))
  (function_definition
    declarator: (pointer_declarator
      declarator: (function_declarator
        declarator: (identifier) @fn_name)))

  (struct_specifier name: (type_identifier) @type_name body: (_))
  (union_specifier name: (type_identifier) @type_name body: (_))
  (enum_specifier name: (type_identifier) @type_name body: (_))

  (preproc_include path: (_) @include)

  (if_statement) @branch
  (for_statement) @branch
  (while_statement) @branch
  (switch_statement) @branch
  (do_statement) @branch
  (conditional_expression) @branch

  (comment) @comment
"#;

static C_QUERY: LazyLock<tree_sitter::Query> = LazyLock::new(|| {
    tree_sitter::Query::new(&C_LANGUAGE, C_QUERY_SRC).expect("parser/c: invalid query")
});

static C_CAPTURES: LazyLock<CCaptures> = LazyLock::new(|| CCaptures::new(&C_QUERY));

thread_local! {
    static C_PARSER: RefCell<tree_sitter::Parser> = RefCell::new({
        let mut p = tree_sitter::Parser::new();
        p.set_language(&C_LANGUAGE).expect("parser/c: grammar load failed");
        p
    });
}

// ── Capture indices ───────────────────────────────────────────────────────────

struct CCaptures {
    fn_name: u32,
    type_name: u32,
    include: u32,
    branch: u32,
    comment: u32,
}

impl CCaptures {
    fn new(query: &tree_sitter::Query) -> Self {
        let idx = |name: &str| {
            query
                .capture_index_for_name(name)
                .unwrap_or_else(|| panic!("parser/c: query missing @{name}"))
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

pub(super) fn parse_c(file: &WalkedFile, source: &str) -> Result<StaticFileAnalysis> {
    let tree = C_PARSER.with(|cell| cell.borrow_mut().parse(source.as_bytes(), None));

    let tree = match tree {
        Some(t) => t,
        None => {
            tracing::warn!("parser/c: tree-sitter failed on {}", file.rel_path);
            return Ok(StaticFileAnalysis::empty(file));
        }
    };

    let query = &*C_QUERY;
    let ci = &*C_CAPTURES;
    let src = source.as_bytes();

    let mut out = StaticFileAnalysis {
        path: file.rel_path.clone(),
        language: Language::C,
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
                    // Angle-bracket includes (<stdio.h>) are system/external.
                    // Quoted includes ("myheader.h") are local/relative.
                    let kind = if path.starts_with('<') {
                        ImportKind::External
                    } else {
                        ImportKind::Relative
                    };
                    let stripped = path
                        .trim_matches('"')
                        .trim_start_matches('<')
                        .trim_end_matches('>');
                    out.imports.push(ImportStatement::new(
                        stripped.to_owned(),
                        kind,
                        node.start_position().row as u32 + 1,
                    ));
                }
            } else if idx == ci.comment {
                if let Ok(text) = node.utf8_text(src) {
                    let row = node.start_position().row;
                    let line = row as u32 + 1;
                    if let Some(todo) = extract_todo(text, line) {
                        out.todos.push(todo);
                    }
                    // Capture file-top block comment as module doc.
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
            language: Language::C,
            size_bytes: content.len() as u64,
            mtime_secs: 0,
        }
    }

    fn parse(dir: &TempDir, source: &str) -> StaticFileAnalysis {
        let f = make_file(dir, "test.c", source);
        parse_c(&f, source).unwrap()
    }

    #[test]
    fn function_in_entry_points() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "int main(int argc, char **argv) { return 0; }\n");
        assert!(a.entry_points.contains(&"main".to_owned()));
    }

    #[test]
    fn pointer_return_function_captured() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "char *dup(const char *s) { return 0; }\n");
        assert!(a.entry_points.contains(&"dup".to_owned()));
    }

    #[test]
    fn prototype_excluded_from_entry_points() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "int f(int x);\n");
        assert!(a.entry_points.is_empty());
    }

    #[test]
    fn branch_ternary() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "int f(int x) { return x ? 1 : 0; }\n");
        assert_eq!(a.branch_count, 1);
    }

    #[test]
    fn struct_definition_in_exported_types() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "struct Point { int x; int y; };\n");
        assert!(a.exported_types.contains(&"Point".to_owned()));
    }

    #[test]
    fn struct_forward_decl_excluded() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "struct Point;\n");
        assert!(!a.exported_types.contains(&"Point".to_owned()));
    }

    #[test]
    fn enum_definition_in_exported_types() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "enum Color { RED, GREEN, BLUE };\n");
        assert!(a.exported_types.contains(&"Color".to_owned()));
    }

    #[test]
    fn include_angle_brackets() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "#include <stdio.h>\nint main() { return 0; }\n");
        assert!(a.imports.iter().any(|i| i.path == "stdio.h"));
    }

    #[test]
    fn include_quotes() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "#include \"myheader.h\"\nint main() { return 0; }\n");
        assert!(a.imports.iter().any(|i| i.path == "myheader.h"));
    }

    #[test]
    fn todo_in_comment() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "// TODO: fix this\nint main() { return 0; }\n");
        assert_eq!(a.todos.len(), 1);
        assert_eq!(a.todos[0].kind, TodoKind::Todo);
    }

    #[test]
    fn branch_if() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "int f(int x) { if (x) { return 1; } return 0; }\n");
        assert_eq!(a.branch_count, 1);
    }

    #[test]
    fn branch_switch() {
        let dir = TempDir::new().unwrap();
        let a = parse(
            &dir,
            "int f(int x) { switch (x) { case 0: return 0; default: return 1; } }\n",
        );
        assert_eq!(a.branch_count, 1);
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
    fn path_preserved() {
        let dir = TempDir::new().unwrap();
        let f = make_file(&dir, "src/utils.c", "int f() { return 0; }\n");
        let a = parse_c(&f, "int f() { return 0; }\n").unwrap();
        assert_eq!(a.path, "src/utils.c");
    }

    #[test]
    fn no_rust_specific_fields_set() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "int f() { return 0; }\n");
        assert_eq!(a.unsafe_count, 0);
        assert_eq!(a.unwrap_count, 0);
        assert_eq!(a.panic_count, 0);
    }

    #[test]
    fn block_comment_module_doc() {
        let dir = TempDir::new().unwrap();
        let a = parse(
            &dir,
            "/* Main utility functions. */\nint f() { return 0; }\n",
        );
        assert_eq!(a.module_doc.as_deref(), Some("Main utility functions."));
    }
}
