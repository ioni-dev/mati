//! Ruby tree-sitter parser — entry points, requires, TODOs.
//!
//! Entry points: `method` and `singleton_method` — filtered by `_` prefix
//! (Python-style convention for internal methods; Ruby's `private`/`protected`
//! are runtime method-call modifiers not visible in the AST as named nodes).
//! Imports: `require` and `require_relative` are method calls, not AST nodes.
//! Detected via `(call method: (identifier) @call_name)` with dispatch filtering.
//! Single `comment` node type.

use std::cell::RefCell;
use std::sync::LazyLock;

use anyhow::Result;

use super::{extract_todo, normalize_doc, ImportKind, ImportStatement, StaticFileAnalysis};
use crate::analysis::walker::{Language, WalkedFile};

// ── Static handles ────────────────────────────────────────────────────────────

static RUBY_LANGUAGE: LazyLock<tree_sitter::Language> =
    LazyLock::new(|| tree_sitter_ruby::LANGUAGE.into());

const RUBY_QUERY_SRC: &str = r#"
  (method name: (_) @method_name)
  (singleton_method name: (_) @method_name)

  (class name: (_) @type_name)
  (module name: (_) @type_name)

  (call method: (identifier) @call_name arguments: (argument_list (string (string_content) @call_arg)))

  (if) @branch
  (unless) @branch
  (while) @branch
  (until) @branch
  (for) @branch
  (case) @branch
  (begin) @branch
  (if_modifier) @branch
  (unless_modifier) @branch
  (while_modifier) @branch
  (until_modifier) @branch
  (rescue) @branch
  (rescue_modifier) @branch

  (comment) @comment
"#;

static RUBY_QUERY: LazyLock<tree_sitter::Query> = LazyLock::new(|| {
    tree_sitter::Query::new(&RUBY_LANGUAGE, RUBY_QUERY_SRC).expect("parser/ruby: invalid query")
});

static RUBY_CAPTURES: LazyLock<RubyCaptures> = LazyLock::new(|| RubyCaptures::new(&RUBY_QUERY));

thread_local! {
    static RUBY_PARSER: RefCell<tree_sitter::Parser> = RefCell::new({
        let mut p = tree_sitter::Parser::new();
        p.set_language(&RUBY_LANGUAGE).expect("parser/ruby: grammar load failed");
        p
    });
}

// ── Capture indices ───────────────────────────────────────────────────────────

struct RubyCaptures {
    method_name: u32,
    type_name: u32,
    call_name: u32,
    call_arg: u32,
    branch: u32,
    comment: u32,
}

impl RubyCaptures {
    fn new(query: &tree_sitter::Query) -> Self {
        let idx = |name: &str| {
            query
                .capture_index_for_name(name)
                .unwrap_or_else(|| panic!("parser/ruby: query missing @{name}"))
        };
        Self {
            method_name: idx("method_name"),
            type_name: idx("type_name"),
            call_name: idx("call_name"),
            call_arg: idx("call_arg"),
            branch: idx("branch"),
            comment: idx("comment"),
        }
    }
}

// ── Parser ────────────────────────────────────────────────────────────────────

pub(super) fn parse_ruby(file: &WalkedFile, source: &str) -> Result<StaticFileAnalysis> {
    let tree = RUBY_PARSER.with(|cell| cell.borrow_mut().parse(source.as_bytes(), None));

    let tree = match tree {
        Some(t) => t,
        None => {
            tracing::warn!("parser/ruby: tree-sitter failed on {}", file.rel_path);
            return Ok(StaticFileAnalysis::empty(file));
        }
    };

    let query = &*RUBY_QUERY;
    let ci = &*RUBY_CAPTURES;
    let src = source.as_bytes();

    let mut out = StaticFileAnalysis {
        path: file.rel_path.clone(),
        language: Language::Ruby,
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
        // For call-based require detection, we need both call_name and call_arg
        // from the same match.
        let mut match_call_name: Option<&str> = None;
        let mut match_call_arg: Option<&str> = None;

        for capture in m.captures {
            let idx = capture.index;
            let node = capture.node;

            if idx == ci.branch {
                out.branch_count += 1;
            } else if idx == ci.method_name {
                if let Ok(name) = node.utf8_text(src) {
                    if !name.starts_with('_') {
                        out.entry_points.push(name.to_owned());
                    }
                }
            } else if idx == ci.type_name {
                if let Ok(name) = node.utf8_text(src) {
                    out.exported_types.push(name.to_owned());
                }
            } else if idx == ci.call_name {
                match_call_name = node.utf8_text(src).ok();
            } else if idx == ci.call_arg {
                match_call_arg = node.utf8_text(src).ok();
            } else if idx == ci.comment {
                if let Ok(text) = node.utf8_text(src) {
                    let row = node.start_position().row;
                    let line = row as u32 + 1;
                    if let Some(todo) = extract_todo(text, line) {
                        out.todos.push(todo);
                    }
                    // Capture file-top # comments as module doc.
                    if row < 10 {
                        let stripped = text.trim_start_matches('#').trim().to_string();
                        if !stripped.is_empty()
                            && !stripped.starts_with('!')
                            && !stripped.starts_with("frozen_string_literal")
                            && !stripped.starts_with("encoding:")
                        {
                            doc_lines.push((row, stripped));
                        }
                    }
                }
            }
        }

        // Process require/require_relative calls.
        if let (Some(name), Some(arg)) = (match_call_name, match_call_arg) {
            if name == "require" || name == "require_relative" {
                // Use the call_name node's parent (the call node) for line info.
                // Fall back to row 0 if we can't determine the line.
                let line = m
                    .captures
                    .iter()
                    .find(|c| c.index == ci.call_name)
                    .map(|c| c.node.start_position().row as u32 + 1)
                    .unwrap_or(1);
                out.imports.push(ImportStatement::new(
                    arg.to_owned(),
                    ImportKind::Normal,
                    line,
                ));
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
            language: Language::Ruby,
            size_bytes: content.len() as u64,
            mtime_secs: 0,
        }
    }

    fn parse(dir: &TempDir, source: &str) -> StaticFileAnalysis {
        let f = make_file(dir, "test.rb", source);
        parse_ruby(&f, source).unwrap()
    }

    #[test]
    fn public_method_in_entry_points() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "def hello\n  puts 'hi'\nend\n");
        assert!(a.entry_points.contains(&"hello".to_owned()));
    }

    #[test]
    fn underscore_prefixed_method_excluded() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "def _internal\n  nil\nend\n");
        assert!(!a.entry_points.contains(&"_internal".to_owned()));
    }

    #[test]
    fn class_in_exported_types() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "class MyService\nend\n");
        assert!(a.exported_types.contains(&"MyService".to_owned()));
    }

    #[test]
    fn module_in_exported_types() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "module Utils\nend\n");
        assert!(a.exported_types.contains(&"Utils".to_owned()));
    }

    #[test]
    fn require_captured() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "require 'json'\n");
        assert!(a.imports.iter().any(|i| i.path == "json"));
    }

    #[test]
    fn require_relative_captured() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "require_relative 'helpers/utils'\n");
        assert!(a.imports.iter().any(|i| i.path == "helpers/utils"));
    }

    #[test]
    fn todo_in_comment() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "# TODO: fix this\ndef f\nend\n");
        assert_eq!(a.todos.len(), 1);
        assert_eq!(a.todos[0].kind, TodoKind::Todo);
    }

    #[test]
    fn branch_if() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "def f(x)\n  if x\n    1\n  end\nend\n");
        assert_eq!(a.branch_count, 1);
    }

    #[test]
    fn branch_unless() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "def f(x)\n  unless x\n    1\n  end\nend\n");
        assert_eq!(a.branch_count, 1);
    }

    #[test]
    fn branch_case() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "def f(x)\n  case x\n  when 1\n    'a'\n  end\nend\n");
        assert_eq!(a.branch_count, 1);
    }

    #[test]
    fn branch_rescue() {
        let dir = TempDir::new().unwrap();
        let a = parse(
            &dir,
            "def f\n  begin\n    1\n  rescue => e\n    0\n  end\nend\n",
        );
        // begin + rescue = 2 branches
        assert!(a.branch_count >= 2);
    }

    #[test]
    fn branch_if_modifier() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "def f(x)\n  puts 'hi' if x\nend\n");
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
        let a = parse(&dir, "def f\nend\n");
        assert_eq!(a.unsafe_count, 0);
        assert_eq!(a.unwrap_count, 0);
        assert_eq!(a.panic_count, 0);
    }
}
