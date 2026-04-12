//! Scala tree-sitter parser — entry points, imports, TODOs.
//!
//! Control flow uses `_expression` suffix (not `_statement`).
//! Two comment types: `comment` and `block_comment`.

use std::cell::RefCell;
use std::sync::LazyLock;

use anyhow::Result;

use super::{extract_todo, normalize_doc, ImportKind, ImportStatement, StaticFileAnalysis};
use crate::analysis::walker::{Language, WalkedFile};

// ── Static handles ────────────────────────────────────────────────────────────

static SCALA_LANGUAGE: LazyLock<tree_sitter::Language> =
    LazyLock::new(|| tree_sitter_scala::LANGUAGE.into());

const SCALA_QUERY_SRC: &str = r#"
  (function_definition name: (identifier) @fn_name)

  (class_definition name: (identifier) @type_name)
  (object_definition name: (identifier) @type_name)
  (trait_definition name: (identifier) @type_name)
  (enum_definition name: (identifier) @type_name)
  (type_definition name: (type_identifier) @type_name)

  (import_declaration) @import

  (if_expression) @branch
  (match_expression) @branch
  (for_expression) @branch
  (while_expression) @branch
  (try_expression) @branch

  (comment) @comment
  (block_comment) @comment
"#;

static SCALA_QUERY: LazyLock<tree_sitter::Query> = LazyLock::new(|| {
    tree_sitter::Query::new(&SCALA_LANGUAGE, SCALA_QUERY_SRC).expect("parser/scala: invalid query")
});

static SCALA_CAPTURES: LazyLock<ScalaCaptures> = LazyLock::new(|| ScalaCaptures::new(&SCALA_QUERY));

thread_local! {
    static SCALA_PARSER: RefCell<tree_sitter::Parser> = RefCell::new({
        let mut p = tree_sitter::Parser::new();
        p.set_language(&SCALA_LANGUAGE).expect("parser/scala: grammar load failed");
        p
    });
}

// ── Capture indices ───────────────────────────────────────────────────────────

struct ScalaCaptures {
    fn_name: u32,
    type_name: u32,
    import: u32,
    branch: u32,
    comment: u32,
}

impl ScalaCaptures {
    fn new(query: &tree_sitter::Query) -> Self {
        let idx = |name: &str| {
            query
                .capture_index_for_name(name)
                .unwrap_or_else(|| panic!("parser/scala: query missing @{name}"))
        };
        Self {
            fn_name: idx("fn_name"),
            type_name: idx("type_name"),
            import: idx("import"),
            branch: idx("branch"),
            comment: idx("comment"),
        }
    }
}

// ── Parser ────────────────────────────────────────────────────────────────────

pub(super) fn parse_scala(file: &WalkedFile, source: &str) -> Result<StaticFileAnalysis> {
    let tree = SCALA_PARSER.with(|cell| cell.borrow_mut().parse(source.as_bytes(), None));

    let tree = match tree {
        Some(t) => t,
        None => {
            tracing::warn!("parser/scala: tree-sitter failed on {}", file.rel_path);
            return Ok(StaticFileAnalysis::empty(file));
        }
    };

    let query = &*SCALA_QUERY;
    let ci = &*SCALA_CAPTURES;
    let src = source.as_bytes();

    let mut out = StaticFileAnalysis {
        path: file.rel_path.clone(),
        language: Language::Scala,
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
            } else if idx == ci.import {
                if let Ok(text) = node.utf8_text(src) {
                    // Strip "import " prefix from full import_declaration text.
                    let cleaned = text.trim_start_matches("import ").trim();
                    out.imports.push(ImportStatement::new(
                        cleaned.to_owned(),
                        ImportKind::Normal,
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
                    // Capture file-top Scaladoc block comment as module doc.
                    if row < 10 && text.starts_with("/**") {
                        let stripped = text
                            .trim_start_matches("/**")
                            .trim_end_matches("*/")
                            .lines()
                            .map(|l| l.trim().trim_start_matches('*').trim())
                            .filter(|l| !l.is_empty() && !l.starts_with('@'))
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
            language: Language::Scala,
            size_bytes: content.len() as u64,
            mtime_secs: 0,
        }
    }

    fn parse(dir: &TempDir, source: &str) -> StaticFileAnalysis {
        let f = make_file(dir, "Test.scala", source);
        parse_scala(&f, source).unwrap()
    }

    #[test]
    fn function_in_entry_points() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "object Main {\n  def hello(): Unit = {}\n}\n");
        assert!(a.entry_points.contains(&"hello".to_owned()));
    }

    #[test]
    fn class_in_exported_types() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "class MyService {}\n");
        assert!(a.exported_types.contains(&"MyService".to_owned()));
    }

    #[test]
    fn object_in_exported_types() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "object Config {}\n");
        assert!(a.exported_types.contains(&"Config".to_owned()));
    }

    #[test]
    fn trait_in_exported_types() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "trait Handler {}\n");
        assert!(a.exported_types.contains(&"Handler".to_owned()));
    }

    #[test]
    fn enum_in_exported_types() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "enum Color {\n  case Red, Green, Blue\n}\n");
        assert!(a.exported_types.contains(&"Color".to_owned()));
    }

    #[test]
    fn type_alias_in_exported_types() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "type Name = String\n");
        assert!(a.exported_types.contains(&"Name".to_owned()));
    }

    #[test]
    fn import_captured() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "import scala.collection.mutable\nobject Foo {}\n");
        assert!(a.imports.iter().any(|i| i.path == "scala.collection.mutable"));
    }

    #[test]
    fn branch_try() {
        let dir = TempDir::new().unwrap();
        let a = parse(
            &dir,
            "object Foo {\n  def f(): Int = try { 1 } catch { case _: Exception => 0 }\n}\n",
        );
        assert_eq!(a.branch_count, 1);
    }

    #[test]
    fn todo_in_comment() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "// TODO: fix this\nobject Foo {}\n");
        assert_eq!(a.todos.len(), 1);
        assert_eq!(a.todos[0].kind, TodoKind::Todo);
    }

    #[test]
    fn branch_if() {
        let dir = TempDir::new().unwrap();
        let a = parse(
            &dir,
            "object Foo {\n  def f(x: Boolean): Int = if (x) 1 else 0\n}\n",
        );
        assert_eq!(a.branch_count, 1);
    }

    #[test]
    fn branch_match() {
        let dir = TempDir::new().unwrap();
        let a = parse(
            &dir,
            "object Foo {\n  def f(x: Int): String = x match {\n    case 1 => \"a\"\n    case _ => \"b\"\n  }\n}\n",
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
    fn no_rust_specific_fields_set() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "object Foo {}\n");
        assert_eq!(a.unsafe_count, 0);
        assert_eq!(a.unwrap_count, 0);
        assert_eq!(a.panic_count, 0);
    }

    #[test]
    fn path_preserved() {
        let dir = TempDir::new().unwrap();
        let f = make_file(&dir, "com/example/Main.scala", "object Main {}\n");
        let a = parse_scala(&f, "object Main {}\n").unwrap();
        assert_eq!(a.path, "com/example/Main.scala");
    }

    #[test]
    fn scaladoc_module_doc_captured() {
        let dir = TempDir::new().unwrap();
        let a = parse(
            &dir,
            "/**\n * Main application entry.\n * @author dev\n */\nobject Main {}\n",
        );
        assert_eq!(a.module_doc.as_deref(), Some("Main application entry."));
    }
}
