//! Elixir tree-sitter parser — entry points, imports, TODOs.
//!
//! CRITICAL QUIRK: Elixir's grammar represents everything as `call` nodes.
//! `def`, `defmodule`, `if`, `case` — all are `(call target: (identifier))`.
//! Dispatch is done in Rust code, not in the query.
//!
//! Module doc is extracted from `@moduledoc` attributes via `unary_operator`
//! with `"@"` operator.

use std::cell::RefCell;
use std::sync::LazyLock;

use anyhow::Result;

use super::{extract_todo, normalize_doc, StaticFileAnalysis};
use crate::analysis::walker::{Language, WalkedFile};

// ── Static handles ────────────────────────────────────────────────────────────

static ELIXIR_LANGUAGE: LazyLock<tree_sitter::Language> =
    LazyLock::new(|| tree_sitter_elixir::LANGUAGE.into());

const ELIXIR_QUERY_SRC: &str = r#"
  (call target: (identifier) @call_target)

  (comment) @comment

  (unary_operator
    operator: "@"
    operand: (call
      target: (identifier) @attr_name))
"#;

static ELIXIR_QUERY: LazyLock<tree_sitter::Query> = LazyLock::new(|| {
    tree_sitter::Query::new(&ELIXIR_LANGUAGE, ELIXIR_QUERY_SRC)
        .expect("parser/elixir: invalid query")
});

static ELIXIR_CAPTURES: LazyLock<ElixirCaptures> =
    LazyLock::new(|| ElixirCaptures::new(&ELIXIR_QUERY));

thread_local! {
    static ELIXIR_PARSER: RefCell<tree_sitter::Parser> = RefCell::new({
        let mut p = tree_sitter::Parser::new();
        p.set_language(&ELIXIR_LANGUAGE).expect("parser/elixir: grammar load failed");
        p
    });
}

// ── Capture indices ───────────────────────────────────────────────────────────

struct ElixirCaptures {
    call_target: u32,
    comment: u32,
    attr_name: u32,
}

impl ElixirCaptures {
    fn new(query: &tree_sitter::Query) -> Self {
        let idx = |name: &str| {
            query
                .capture_index_for_name(name)
                .unwrap_or_else(|| panic!("parser/elixir: query missing @{name}"))
        };
        Self {
            call_target: idx("call_target"),
            comment: idx("comment"),
            attr_name: idx("attr_name"),
        }
    }
}

// ── Parser ────────────────────────────────────────────────────────────────────

pub(super) fn parse_elixir(file: &WalkedFile, source: &str) -> Result<StaticFileAnalysis> {
    let tree = ELIXIR_PARSER.with(|cell| cell.borrow_mut().parse(source.as_bytes(), None));

    let tree = match tree {
        Some(t) => t,
        None => {
            tracing::warn!("parser/elixir: tree-sitter failed on {}", file.rel_path);
            return Ok(StaticFileAnalysis::empty(file));
        }
    };

    let query = &*ELIXIR_QUERY;
    let ci = &*ELIXIR_CAPTURES;
    let src = source.as_bytes();

    let mut out = StaticFileAnalysis {
        path: file.rel_path.clone(),
        language: Language::Elixir,
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

            if idx == ci.call_target {
                if let Ok(target) = node.utf8_text(src) {
                    // Get the parent `call` node to extract arguments.
                    let call_node = node.parent();
                    match target {
                        "def" | "defmacro" => {
                            if let Some(name) = extract_elixir_fn_name(call_node, src) {
                                out.entry_points.push(name);
                            }
                        }
                        "defp" | "defmacrop" => {
                            // Private — skip.
                        }
                        "defmodule" | "defprotocol" => {
                            if let Some(name) = extract_elixir_module_name(call_node, src) {
                                out.exported_types.push(name);
                            }
                        }
                        "import" | "alias" | "use" | "require" => {
                            if let Some(name) = extract_elixir_module_name(call_node, src) {
                                out.imports.push(name);
                            }
                        }
                        "if" | "unless" | "cond" | "case" | "with" | "try" | "receive" => {
                            out.branch_count += 1;
                        }
                        _ => {}
                    }
                }
            } else if idx == ci.comment {
                if let Ok(text) = node.utf8_text(src) {
                    let line = node.start_position().row as u32 + 1;
                    if let Some(todo) = extract_todo(text, line) {
                        out.todos.push(todo);
                    }
                }
            } else if idx == ci.attr_name {
                if let Ok(attr) = node.utf8_text(src) {
                    if attr == "moduledoc" && out.module_doc.is_none() {
                        // The attr_name's parent is the `call` inside the unary_operator.
                        // Extract string content from arguments.
                        if let Some(call) = node.parent() {
                            out.module_doc = extract_elixir_doc_string(call, src);
                        }
                    }
                }
            }
        }
    }

    Ok(out)
}

/// Find the first child of `node` with a given kind.
fn find_child_by_kind<'a>(
    node: tree_sitter::Node<'a>,
    kind: &str,
) -> Option<tree_sitter::Node<'a>> {
    (0..node.child_count())
        .filter_map(|i| node.child(i))
        .find(|c| c.kind() == kind)
}

/// Extract the function name from a `call` node like `def foo(args)`.
/// The first argument to the `def` call is either an `identifier` (simple name)
/// or a `call` node (function with args, e.g., `def foo(x, y)`).
fn extract_elixir_fn_name(call_node: Option<tree_sitter::Node>, src: &[u8]) -> Option<String> {
    let call = call_node?;
    // `arguments` is an unnamed child, not a field — find by kind.
    let args = find_child_by_kind(call, "arguments")?;
    let first_arg = args.named_child(0)?;
    match first_arg.kind() {
        "identifier" => first_arg.utf8_text(src).ok().map(|s| s.to_owned()),
        "call" => {
            // `def foo(x, y) do ... end` — the first arg is a call node,
            // its target is the function name.
            let target = first_arg.child_by_field_name("target")?;
            target.utf8_text(src).ok().map(|s| s.to_owned())
        }
        "binary_operator" => {
            // `def foo(x) when is_integer(x)` — binary_operator with `when`.
            let left = first_arg.named_child(0)?;
            if left.kind() == "call" {
                let target = left.child_by_field_name("target")?;
                target.utf8_text(src).ok().map(|s| s.to_owned())
            } else if left.kind() == "identifier" {
                left.utf8_text(src).ok().map(|s| s.to_owned())
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Extract a module name (alias) from a `call` node like `defmodule Foo`.
fn extract_elixir_module_name(call_node: Option<tree_sitter::Node>, src: &[u8]) -> Option<String> {
    let call = call_node?;
    // `arguments` is an unnamed child — find by kind.
    let args = find_child_by_kind(call, "arguments")?;
    let first_arg = args.named_child(0)?;
    // Module names are `alias` nodes (e.g., `MyApp.Router`).
    if first_arg.kind() == "alias" {
        return first_arg.utf8_text(src).ok().map(|s| s.to_owned());
    }
    // Sometimes just an atom or identifier.
    first_arg.utf8_text(src).ok().map(|s| s.to_owned())
}

/// Extract the doc string from a `@moduledoc` attribute call.
fn extract_elixir_doc_string(call: tree_sitter::Node, src: &[u8]) -> Option<String> {
    let args = find_child_by_kind(call, "arguments")?;
    let first_arg = args.named_child(0)?;
    if first_arg.kind() == "string" || first_arg.kind() == "charlist" {
        let text = first_arg.utf8_text(src).ok()?;
        // Strip triple quotes and single quotes.
        let stripped = text
            .trim_start_matches("\"\"\"")
            .trim_end_matches("\"\"\"")
            .trim_start_matches('"')
            .trim_end_matches('"')
            .trim();
        if stripped.is_empty() {
            return None;
        }
        return Some(normalize_doc(stripped));
    }
    // `false` means "@moduledoc false" — no doc.
    None
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
            language: Language::Elixir,
            size_bytes: content.len() as u64,
            mtime_secs: 0,
        }
    }

    fn parse(dir: &TempDir, source: &str) -> StaticFileAnalysis {
        let f = make_file(dir, "test.ex", source);
        parse_elixir(&f, source).unwrap()
    }

    #[test]
    fn public_function_in_entry_points() {
        let dir = TempDir::new().unwrap();
        let a = parse(
            &dir,
            "defmodule Foo do\n  def hello do\n    :ok\n  end\nend\n",
        );
        assert!(a.entry_points.contains(&"hello".to_owned()));
    }

    #[test]
    fn private_function_excluded() {
        let dir = TempDir::new().unwrap();
        let a = parse(
            &dir,
            "defmodule Foo do\n  defp internal do\n    :ok\n  end\nend\n",
        );
        assert!(!a.entry_points.contains(&"internal".to_owned()));
    }

    #[test]
    fn function_with_args_captured() {
        let dir = TempDir::new().unwrap();
        let a = parse(
            &dir,
            "defmodule Foo do\n  def greet(name) do\n    name\n  end\nend\n",
        );
        assert!(a.entry_points.contains(&"greet".to_owned()));
    }

    #[test]
    fn module_in_exported_types() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "defmodule MyApp.Router do\nend\n");
        assert!(a.exported_types.contains(&"MyApp.Router".to_owned()));
    }

    #[test]
    fn import_captured() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "defmodule Foo do\n  import Enum\nend\n");
        assert!(a.imports.contains(&"Enum".to_owned()));
    }

    #[test]
    fn alias_captured() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "defmodule Foo do\n  alias MyApp.Utils\nend\n");
        assert!(a.imports.contains(&"MyApp.Utils".to_owned()));
    }

    #[test]
    fn use_captured() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "defmodule Foo do\n  use GenServer\nend\n");
        assert!(a.imports.contains(&"GenServer".to_owned()));
    }

    #[test]
    fn require_captured() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "defmodule Foo do\n  require Logger\nend\n");
        assert!(a.imports.contains(&"Logger".to_owned()));
    }

    #[test]
    fn branch_receive() {
        let dir = TempDir::new().unwrap();
        let a = parse(
            &dir,
            "defmodule Foo do\n  def f do\n    receive do\n      :ok -> :ok\n    end\n  end\nend\n",
        );
        assert_eq!(a.branch_count, 1);
    }

    #[test]
    fn todo_in_comment() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "# TODO: fix this\ndefmodule Foo do\nend\n");
        assert_eq!(a.todos.len(), 1);
        assert_eq!(a.todos[0].kind, TodoKind::Todo);
    }

    #[test]
    fn branch_if() {
        let dir = TempDir::new().unwrap();
        let a = parse(
            &dir,
            "defmodule Foo do\n  def f(x) do\n    if x, do: 1, else: 0\n  end\nend\n",
        );
        assert_eq!(a.branch_count, 1);
    }

    #[test]
    fn branch_case() {
        let dir = TempDir::new().unwrap();
        let a = parse(
            &dir,
            "defmodule Foo do\n  def f(x) do\n    case x do\n      :a -> 1\n      _ -> 0\n    end\n  end\nend\n",
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
    fn moduledoc_captured() {
        let dir = TempDir::new().unwrap();
        let a = parse(
            &dir,
            "defmodule Foo do\n  @moduledoc \"Handles requests.\"\nend\n",
        );
        assert_eq!(a.module_doc.as_deref(), Some("Handles requests."));
    }

    #[test]
    fn path_preserved() {
        let dir = TempDir::new().unwrap();
        let f = make_file(
            &dir,
            "lib/my_app/router.ex",
            "defmodule MyApp.Router do\nend\n",
        );
        let a = parse_elixir(&f, "defmodule MyApp.Router do\nend\n").unwrap();
        assert_eq!(a.path, "lib/my_app/router.ex");
    }

    #[test]
    fn no_rust_specific_fields_set() {
        let dir = TempDir::new().unwrap();
        let a = parse(&dir, "defmodule Foo do\nend\n");
        assert_eq!(a.unsafe_count, 0);
        assert_eq!(a.unwrap_count, 0);
        assert_eq!(a.panic_count, 0);
    }
}
