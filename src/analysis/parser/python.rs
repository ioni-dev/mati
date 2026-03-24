//! Python tree-sitter parser — functions, classes, imports, TODOs.
//!
//! Entry point filtering: captures ALL `function_definition` and
//! `class_definition` nodes, then filters in the dispatch loop:
//! - Only top-level definitions (parent is `module` or `decorated_definition`
//!   whose parent is `module`)
//! - Names starting with `_` are excluded (Python private convention)

use std::cell::RefCell;
use std::sync::LazyLock;

use anyhow::Result;

use crate::analysis::walker::{Language, WalkedFile};
use super::{StaticFileAnalysis, extract_todo};

// ── Static handles ────────────────────────────────────────────────────────────

static PY_LANGUAGE: LazyLock<tree_sitter::Language> =
    LazyLock::new(|| tree_sitter_python::LANGUAGE.into());

const PY_QUERY_SRC: &str = r#"
  (function_definition name: (identifier) @fn_name)
  (class_definition    name: (identifier) @class_name)

  (import_statement (dotted_name) @import)
  (import_statement (aliased_import name: (dotted_name) @import))
  (import_from_statement module_name: (dotted_name) @import)
  (import_from_statement module_name: (relative_import) @import)

  (if_statement) @branch
  (for_statement) @branch
  (while_statement) @branch
  (try_statement) @branch

  (comment) @comment

  (module . (expression_statement (string) @module_doc))
"#;

static PY_QUERY: LazyLock<tree_sitter::Query> = LazyLock::new(|| {
    tree_sitter::Query::new(&PY_LANGUAGE, PY_QUERY_SRC)
        .expect("parser/python: invalid query")
});

static PY_CAPTURES: LazyLock<PyCaptures> =
    LazyLock::new(|| PyCaptures::new(&PY_QUERY));

thread_local! {
    static PY_PARSER: RefCell<tree_sitter::Parser> = RefCell::new({
        let mut p = tree_sitter::Parser::new();
        p.set_language(&PY_LANGUAGE).expect("parser/python: grammar load failed");
        p
    });
}

// ── Capture indices ───────────────────────────────────────────────────────────

struct PyCaptures {
    fn_name:    u32,
    class_name: u32,
    import:     u32,
    branch:     u32,
    comment:    u32,
    module_doc: u32,
}

impl PyCaptures {
    fn new(query: &tree_sitter::Query) -> Self {
        let idx = |name: &str| {
            query.capture_index_for_name(name)
                .unwrap_or_else(|| panic!("parser/python: query missing @{name}"))
        };
        Self {
            fn_name:    idx("fn_name"),
            class_name: idx("class_name"),
            import:     idx("import"),
            branch:     idx("branch"),
            comment:    idx("comment"),
            module_doc: idx("module_doc"),
        }
    }
}

// ── Parser ────────────────────────────────────────────────────────────────────

pub(super) fn parse_python(file: &WalkedFile, source: &str) -> Result<StaticFileAnalysis> {
    let tree = PY_PARSER.with(|cell| {
        cell.borrow_mut().parse(source.as_bytes(), None)
    });

    let tree = match tree {
        Some(t) => t,
        None => {
            tracing::warn!("parser/python: tree-sitter failed on {}", file.rel_path);
            return Ok(StaticFileAnalysis::empty(file));
        }
    };

    let query = &*PY_QUERY;
    let ci = &*PY_CAPTURES;
    let src = source.as_bytes();

    let mut out = StaticFileAnalysis {
        path: file.rel_path.clone(),
        language: Language::Python,
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
            } else if idx == ci.fn_name {
                if let Ok(name) = node.utf8_text(src) {
                    // Only top-level, non-private functions.
                    if !name.starts_with('_') {
                        if let Some(fn_node) = node.parent() {
                            if is_top_level(fn_node) {
                                out.entry_points.push(name.to_owned());
                            }
                        }
                    }
                }
            } else if idx == ci.class_name {
                if let Ok(name) = node.utf8_text(src) {
                    if !name.starts_with('_') {
                        if let Some(class_node) = node.parent() {
                            if is_top_level(class_node) {
                                out.exported_types.push(name.to_owned());
                            }
                        }
                    }
                }
            } else if idx == ci.import {
                if let Ok(path) = node.utf8_text(src) {
                    out.imports.push(path.to_owned());
                }
            } else if idx == ci.comment {
                if let Ok(text) = node.utf8_text(src) {
                    let line = node.start_position().row as u32 + 1;
                    if let Some(todo) = extract_todo(text, line) {
                        out.todos.push(todo);
                    }
                }
            } else if idx == ci.module_doc && out.module_doc.is_none() {
                // First string at module level = module docstring.
                if let Ok(raw) = node.utf8_text(src) {
                    if let Some(cleaned) = strip_python_docstring(raw) {
                        out.module_doc = Some(super::normalize_doc(&cleaned));
                    }
                }
            }
        }
    }

    Ok(out)
}

/// Check if a definition node (function_definition or class_definition) is
/// at module top-level.
///
/// Handles both plain and decorated definitions:
/// - `def foo():` → parent is `module` → top-level
/// - `@decorator def foo():` → parent is `decorated_definition` whose
///   parent is `module` → top-level
/// - `class Foo: def bar(self):` → parent is `block` → NOT top-level
fn is_top_level(node: tree_sitter::Node) -> bool {
    match node.parent().map(|p| p.kind()) {
        Some("module") => true,
        Some("decorated_definition") => {
            node.parent()
                .and_then(|p| p.parent())
                .is_some_and(|gp| gp.kind() == "module")
        }
        _ => false,
    }
}

/// Strip Python string delimiters from a raw `string` node text.
///
/// Returns `None` if the content is empty after stripping.
/// Handles triple-double, triple-single, double, and single-quoted strings.
fn strip_python_docstring(raw: &str) -> Option<String> {
    let s = raw.trim();
    // Try longest delimiters first.
    let inner = if (s.starts_with("\"\"\"") && s.ends_with("\"\"\"")
        || s.starts_with("'''") && s.ends_with("'''"))
        && s.len() >= 6
    {
        &s[3..s.len() - 3]
    } else if (s.starts_with('"') && s.ends_with('"')
        || s.starts_with('\'') && s.ends_with('\''))
        && s.len() >= 2
    {
        &s[1..s.len() - 1]
    } else {
        s
    };
    let trimmed = inner.trim();
    if trimmed.is_empty() { None } else { Some(trimmed.to_string()) }
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
            language: Language::Python,
            size_bytes: content.len() as u64,
            mtime_secs: 0,
        }
    }

    fn parse(dir: &TempDir, source: &str) -> StaticFileAnalysis {
        let f = make_file(dir, "test.py", source);
        parse_python(&f, source).unwrap()
    }

    // ── Entry points ──────────────────────────────────────────────────────────

    #[test]
    fn top_level_function() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "def foo():\n    pass\n");
        assert!(a.entry_points.contains(&"foo".to_owned()));
    }

    #[test]
    fn private_function_excluded() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "def _private():\n    pass\n");
        assert!(a.entry_points.is_empty());
    }

    #[test]
    fn dunder_function_excluded() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "def __init__(self):\n    pass\n");
        assert!(a.entry_points.is_empty());
    }

    #[test]
    fn class_method_excluded() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "class Foo:\n    def bar(self):\n        pass\n");
        // bar is a method, not a module entry point
        assert!(!a.entry_points.contains(&"bar".to_owned()));
    }

    #[test]
    fn async_function_included() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "async def handler():\n    pass\n");
        assert!(a.entry_points.contains(&"handler".to_owned()));
    }

    #[test]
    fn decorated_top_level_function() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "@app.route('/')\ndef index():\n    pass\n");
        assert!(a.entry_points.contains(&"index".to_owned()));
    }

    #[test]
    fn decorated_method_excluded() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "class Foo:\n    @property\n    def name(self):\n        return self._name\n");
        assert!(!a.entry_points.contains(&"name".to_owned()));
    }

    // ── Exported types ────────────────────────────────────────────────────────

    #[test]
    fn top_level_class() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "class MyModel:\n    pass\n");
        assert!(a.exported_types.contains(&"MyModel".to_owned()));
    }

    #[test]
    fn private_class_excluded() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "class _Internal:\n    pass\n");
        assert!(a.exported_types.is_empty());
    }

    #[test]
    fn nested_class_excluded() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "class Outer:\n    class Inner:\n        pass\n");
        assert!(a.exported_types.contains(&"Outer".to_owned()));
        assert!(!a.exported_types.contains(&"Inner".to_owned()));
    }

    // ── Imports ───────────────────────────────────────────────────────────────

    #[test]
    fn import_statement() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "import os\n");
        assert!(a.imports.contains(&"os".to_owned()));
    }

    #[test]
    fn import_dotted() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "import os.path\n");
        assert!(a.imports.iter().any(|i| i.contains("os.path") || i.contains("os")));
    }

    #[test]
    fn from_import() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "from os import path\n");
        assert!(a.imports.contains(&"os".to_owned()));
    }

    #[test]
    fn from_import_relative() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "from . import utils\n");
        assert!(!a.imports.is_empty());
    }

    // ── Branches ──────────────────────────────────────────────────────────────

    #[test]
    fn if_branch() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "if True:\n    pass\n");
        assert_eq!(a.branch_count, 1);
    }

    #[test]
    fn for_branch() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "for x in range(10):\n    pass\n");
        assert_eq!(a.branch_count, 1);
    }

    #[test]
    fn while_branch() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "while True:\n    break\n");
        assert_eq!(a.branch_count, 1);
    }

    #[test]
    fn try_branch() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "try:\n    pass\nexcept Exception:\n    pass\n");
        assert_eq!(a.branch_count, 1);
    }

    // ── TODOs ─────────────────────────────────────────────────────────────────

    #[test]
    fn todo_extracted() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "# TODO: fix this\ndef f():\n    pass\n");
        assert_eq!(a.todos.len(), 1);
        assert_eq!(a.todos[0].kind, TodoKind::Todo);
    }

    #[test]
    fn type_ignore_captured() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "x = foo()  # type: ignore\n");
        assert_eq!(a.todos.len(), 1);
        assert_eq!(a.todos[0].kind, TodoKind::Note);
    }

    #[test]
    fn type_ignore_with_code_captured() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "x = foo()  # type: ignore[attr-defined]\n");
        assert_eq!(a.todos.len(), 1);
    }

    // ── Edge cases ────────────────────────────────────────────────────────────

    #[test]
    fn empty_file() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "");
        assert!(a.entry_points.is_empty());
        assert_eq!(a.branch_count, 0);
    }

    #[test]
    fn no_unsafe_or_unwrap() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "def foo():\n    pass\n");
        assert_eq!(a.unsafe_count, 0);
        assert_eq!(a.unwrap_count, 0);
        assert_eq!(a.panic_count, 0);
    }

    #[test]
    fn path_preserved() {
        let dir = TempDir::new().unwrap();
        let f = make_file(&dir, "src/app.py", "def main():\n    pass\n");
        let a = parse_python(&f, "def main():\n    pass\n").unwrap();
        assert_eq!(a.path, "src/app.py");
    }

    // ── Module doc (docstring) ────────────────────────────────────────────────

    #[test]
    fn triple_double_quote_docstring() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "\"\"\"Handles payment processing.\"\"\"\ndef pay(): pass\n");
        assert_eq!(a.module_doc.as_deref(), Some("Handles payment processing."));
    }

    #[test]
    fn triple_single_quote_docstring() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "'''Auth utilities.'''\ndef auth(): pass\n");
        assert_eq!(a.module_doc.as_deref(), Some("Auth utilities."));
    }

    #[test]
    fn single_double_quote_docstring() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "\"Short description.\"\ndef f(): pass\n");
        assert_eq!(a.module_doc.as_deref(), Some("Short description."));
    }

    #[test]
    fn no_docstring_yields_none() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "# comment\ndef f(): pass\n");
        assert!(a.module_doc.is_none());
    }

    #[test]
    fn docstring_after_function_not_captured() {
        let dir = TempDir::new().unwrap();
        // String is NOT the first statement → not a module docstring.
        let a = parse(&dir, "x = 1\n\"\"\"Not a module docstring.\"\"\"\n");
        assert!(a.module_doc.is_none());
    }
}
