//! Java tree-sitter parser — entry points, imports, TODOs.
//!
//! Captures all methods and type declarations (no visibility filtering —
//! Java modifiers are keyword tokens, not named AST nodes).
//!
//! Comments: two node types — `line_comment` and `block_comment`.
//! Branches: `switch_expression` (NOT `switch_statement`), plus
//! `enhanced_for_statement` and `try_with_resources_statement`.

use std::cell::RefCell;
use std::sync::LazyLock;

use anyhow::Result;

use super::{extract_todo, normalize_doc, ImportKind, ImportStatement, StaticFileAnalysis};
use crate::analysis::walker::{Language, WalkedFile};

// ── Static handles ────────────────────────────────────────────────────────────

static JAVA_LANGUAGE: LazyLock<tree_sitter::Language> =
    LazyLock::new(|| tree_sitter_java::LANGUAGE.into());

const JAVA_QUERY_SRC: &str = r#"
  (method_declaration name: (identifier) @method_name)

  (class_declaration name: (identifier) @type_name)
  (interface_declaration name: (identifier) @type_name)
  (enum_declaration name: (identifier) @type_name)
  (record_declaration name: (identifier) @type_name)
  (annotation_type_declaration name: (identifier) @type_name)

  (import_declaration) @import

  (if_statement) @branch
  (for_statement) @branch
  (enhanced_for_statement) @branch
  (while_statement) @branch
  (do_statement) @branch
  (switch_expression) @branch
  (try_statement) @branch
  (try_with_resources_statement) @branch
  (ternary_expression) @branch

  (line_comment) @comment
  (block_comment) @comment
"#;

static JAVA_QUERY: LazyLock<tree_sitter::Query> = LazyLock::new(|| {
    tree_sitter::Query::new(&JAVA_LANGUAGE, JAVA_QUERY_SRC).expect("parser/java: invalid query")
});

static JAVA_CAPTURES: LazyLock<JavaCaptures> = LazyLock::new(|| JavaCaptures::new(&JAVA_QUERY));

thread_local! {
    static JAVA_PARSER: RefCell<tree_sitter::Parser> = RefCell::new({
        let mut p = tree_sitter::Parser::new();
        p.set_language(&JAVA_LANGUAGE).expect("parser/java: grammar load failed");
        p
    });
}

// ── Capture indices ───────────────────────────────────────────────────────────

struct JavaCaptures {
    method_name: u32,
    type_name: u32,
    import: u32,
    branch: u32,
    comment: u32,
}

impl JavaCaptures {
    fn new(query: &tree_sitter::Query) -> Self {
        let idx = |name: &str| {
            query
                .capture_index_for_name(name)
                .unwrap_or_else(|| panic!("parser/java: query missing @{name}"))
        };
        Self {
            method_name: idx("method_name"),
            type_name: idx("type_name"),
            import: idx("import"),
            branch: idx("branch"),
            comment: idx("comment"),
        }
    }
}

// ── Parser ────────────────────────────────────────────────────────────────────

pub(super) fn parse_java(file: &WalkedFile, source: &str) -> Result<StaticFileAnalysis> {
    let tree = JAVA_PARSER.with(|cell| cell.borrow_mut().parse(source.as_bytes(), None));

    let tree = match tree {
        Some(t) => t,
        None => {
            tracing::warn!("parser/java: tree-sitter failed on {}", file.rel_path);
            return Ok(StaticFileAnalysis::empty(file));
        }
    };

    let query = &*JAVA_QUERY;
    let ci = &*JAVA_CAPTURES;
    let src = source.as_bytes();

    let mut out = StaticFileAnalysis {
        path: file.rel_path.clone(),
        language: Language::Java,
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
            } else if idx == ci.method_name {
                if let Ok(name) = node.utf8_text(src) {
                    out.entry_points.push(name.to_owned());
                }
            } else if idx == ci.type_name {
                if let Ok(name) = node.utf8_text(src) {
                    out.exported_types.push(name.to_owned());
                }
            } else if idx == ci.import {
                if let Ok(text) = node.utf8_text(src) {
                    // Strip "import " prefix and trailing ";"
                    let cleaned = text
                        .trim_start_matches("import ")
                        .trim_start_matches("static ")
                        .trim_end_matches(';')
                        .trim();
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
                    // Capture file-top Javadoc block comment as module doc.
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
            language: Language::Java,
            size_bytes: content.len() as u64,
            mtime_secs: 0,
        }
    }

    fn parse(dir: &TempDir, source: &str) -> StaticFileAnalysis {
        let f = make_file(dir, "Test.java", source);
        parse_java(&f, source).unwrap()
    }

    // ── Entry points ─────────────────────────────────────────────────────────

    #[test]
    fn method_in_entry_points() {
        let dir = TempDir::new().unwrap();
        let a = parse(
            &dir,
            "public class Foo { public void bar() {} void baz() {} }",
        );
        assert!(a.entry_points.contains(&"bar".to_owned()));
        assert!(a.entry_points.contains(&"baz".to_owned()));
    }

    // ── Exported types ───────────────────────────────────────────────────────

    #[test]
    fn class_in_exported_types() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "public class MyService {}");
        assert!(a.exported_types.contains(&"MyService".to_owned()));
    }

    #[test]
    fn interface_in_exported_types() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "public interface Handler {}");
        assert!(a.exported_types.contains(&"Handler".to_owned()));
    }

    #[test]
    fn enum_in_exported_types() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "public enum Status { OK, ERROR }");
        assert!(a.exported_types.contains(&"Status".to_owned()));
    }

    #[test]
    fn record_in_exported_types() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "public record Point(int x, int y) {}");
        assert!(a.exported_types.contains(&"Point".to_owned()));
    }

    #[test]
    fn annotation_type_in_exported_types() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "public @interface MyAnnotation {}");
        assert!(a.exported_types.contains(&"MyAnnotation".to_owned()));
    }

    // ── Imports ──────────────────────────────────────────────────────────────

    #[test]
    fn import_captured() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "import java.util.List;\npublic class Foo {}");
        assert!(a.imports.iter().any(|i| i.path == "java.util.List"));
    }

    #[test]
    fn static_import_captured() {
        let dir = TempDir::new().unwrap();
        let a = parse(
            &dir,
            "import static java.lang.Math.PI;\npublic class Foo {}",
        );
        assert!(a.imports.iter().any(|i| i.path == "java.lang.Math.PI"));
    }

    // ── TODOs ────────────────────────────────────────────────────────────────

    #[test]
    fn todo_in_line_comment() {
        let dir = TempDir::new().unwrap();
        let a = parse(
            &dir,
            "public class Foo {\n// TODO: fix this\nvoid bar() {}\n}",
        );
        assert_eq!(a.todos.len(), 1);
        assert_eq!(a.todos[0].kind, TodoKind::Todo);
    }

    #[test]
    fn fixme_in_block_comment() {
        let dir = TempDir::new().unwrap();
        let a = parse(
            &dir,
            "public class Foo { /* FIXME: broken */ void bar() {} }",
        );
        assert_eq!(a.todos.len(), 1);
        assert_eq!(a.todos[0].kind, TodoKind::Fixme);
    }

    // ── Branches ─────────────────────────────────────────────────────────────

    #[test]
    fn branch_if() {
        let dir = TempDir::new().unwrap();
        let a = parse(
            &dir,
            "public class Foo { void bar(boolean x) { if (x) {} } }",
        );
        assert_eq!(a.branch_count, 1);
    }

    #[test]
    fn branch_switch_expression() {
        let dir = TempDir::new().unwrap();
        let a = parse(
            &dir,
            "public class Foo { void bar(int x) { switch (x) { case 1: break; } } }",
        );
        assert_eq!(a.branch_count, 1);
    }

    #[test]
    fn branch_enhanced_for() {
        let dir = TempDir::new().unwrap();
        let a = parse(
            &dir,
            "import java.util.List;\npublic class Foo { void bar(List<String> items) { for (String s : items) {} } }",
        );
        assert_eq!(a.branch_count, 1);
    }

    #[test]
    fn branch_try_with_resources() {
        let dir = TempDir::new().unwrap();
        let a = parse(
            &dir,
            "import java.io.*;\npublic class Foo { void bar() throws Exception { try (InputStream is = null) {} } }",
        );
        assert_eq!(a.branch_count, 1);
    }

    #[test]
    fn branch_ternary() {
        let dir = TempDir::new().unwrap();
        let a = parse(
            &dir,
            "public class Foo { int bar(boolean x) { return x ? 1 : 0; } }",
        );
        assert_eq!(a.branch_count, 1);
    }

    // ── Module doc ───────────────────────────────────────────────────────────

    #[test]
    fn javadoc_at_top_captured() {
        let dir = TempDir::new().unwrap();
        let a = parse(
            &dir,
            "/**\n * Service entry point.\n * @author dev\n */\npublic class Foo {}",
        );
        assert_eq!(a.module_doc.as_deref(), Some("Service entry point."));
    }

    // ── Edge cases ───────────────────────────────────────────────────────────

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
        let f = make_file(
            dir.path().join("src").to_str().map(|_| &dir).unwrap(),
            "com/example/Main.java",
            "public class Main {}",
        );
        let a = parse_java(&f, "public class Main {}").unwrap();
        assert_eq!(a.path, "com/example/Main.java");
    }

    #[test]
    fn no_rust_specific_fields_set() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "public class Foo {}");
        assert_eq!(a.unsafe_count, 0);
        assert_eq!(a.unwrap_count, 0);
        assert_eq!(a.panic_count, 0);
    }
}
