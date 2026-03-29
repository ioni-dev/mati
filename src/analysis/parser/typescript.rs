//! TypeScript / JavaScript tree-sitter parser.
//!
//! Handles `.ts`, `.tsx`, `.js`, `.jsx`, `.mjs`, `.cjs` via three grammars:
//! - `tree_sitter_typescript::LANGUAGE_TYPESCRIPT` for `.ts`
//! - `tree_sitter_typescript::LANGUAGE_TSX` for `.tsx` (and `.jsx` via JS path)
//! - `tree_sitter_javascript::LANGUAGE` for `.js`, `.jsx`, `.mjs`, `.cjs`
//!
//! TSX is a superset of TS — the same query string compiles against both.
//! JS has a separate query that omits TS-specific node types.

use std::cell::RefCell;
use std::sync::LazyLock;

use anyhow::Result;

use super::{extract_todo, StaticFileAnalysis};
use crate::analysis::walker::{Language, WalkedFile};

// ── Static handles ────────────────────────────────────────────────────────────

static TS_LANGUAGE: LazyLock<tree_sitter::Language> =
    LazyLock::new(|| tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into());
static TSX_LANGUAGE: LazyLock<tree_sitter::Language> =
    LazyLock::new(|| tree_sitter_typescript::LANGUAGE_TSX.into());
static JS_LANGUAGE: LazyLock<tree_sitter::Language> =
    LazyLock::new(|| tree_sitter_javascript::LANGUAGE.into());

// ── Queries ───────────────────────────────────────────────────────────────────

/// TypeScript query — works for both TS and TSX grammars.
///
/// TS-specific patterns: interface, type_alias, enum, non_null_expression.
/// Class names use `type_identifier` in TS (not `identifier`).
const TS_QUERY_SRC: &str = r#"
  (export_statement declaration: (function_declaration name: (identifier) @pub_fn))
  (export_statement declaration: (generator_function_declaration name: (identifier) @pub_fn))
  (export_statement declaration: (lexical_declaration
    (variable_declarator name: (identifier) @pub_fn)))

  (export_statement declaration: (class_declaration name: (type_identifier) @pub_type))
  (export_statement declaration: (interface_declaration name: (type_identifier) @pub_type))
  (export_statement declaration: (type_alias_declaration name: (type_identifier) @pub_type))
  (export_statement declaration: (enum_declaration name: (identifier) @pub_type))

  (export_statement (export_clause (export_specifier name: (identifier) @re_export)))

  (import_statement source: (string) @import)
  (export_statement source: (string) @import)

  (non_null_expression) @unwrap

  (if_statement) @branch
  (switch_statement) @branch
  (ternary_expression) @branch
  (for_statement) @branch
  (for_in_statement) @branch
  (while_statement) @branch
  (do_statement) @branch

  (comment) @comment
"#;

/// JavaScript query — omits TS-only node types (interface, type_alias, enum,
/// non_null_expression). Class names use `identifier` in JS.
const JS_QUERY_SRC: &str = r#"
  (export_statement declaration: (function_declaration name: (identifier) @pub_fn))
  (export_statement declaration: (generator_function_declaration name: (identifier) @pub_fn))
  (export_statement declaration: (lexical_declaration
    (variable_declarator name: (identifier) @pub_fn)))

  (export_statement declaration: (class_declaration name: (identifier) @pub_type))

  (export_statement (export_clause (export_specifier name: (identifier) @re_export)))

  (import_statement source: (string) @import)
  (export_statement source: (string) @import)

  (if_statement) @branch
  (switch_statement) @branch
  (ternary_expression) @branch
  (for_statement) @branch
  (for_in_statement) @branch
  (while_statement) @branch
  (do_statement) @branch

  (comment) @comment
"#;

static TS_QUERY: LazyLock<tree_sitter::Query> = LazyLock::new(|| {
    tree_sitter::Query::new(&TS_LANGUAGE, TS_QUERY_SRC)
        .expect("parser/typescript: invalid TS query")
});
static TSX_QUERY: LazyLock<tree_sitter::Query> = LazyLock::new(|| {
    tree_sitter::Query::new(&TSX_LANGUAGE, TS_QUERY_SRC)
        .expect("parser/typescript: invalid TSX query")
});
static JS_QUERY: LazyLock<tree_sitter::Query> = LazyLock::new(|| {
    tree_sitter::Query::new(&JS_LANGUAGE, JS_QUERY_SRC)
        .expect("parser/typescript: invalid JS query")
});

// Capture indices: same names for TS and TSX (same query source).
static TS_CAPTURES: LazyLock<EcmaCaptures> = LazyLock::new(|| EcmaCaptures::new(&TS_QUERY));
static JS_CAPTURES: LazyLock<EcmaCaptures> = LazyLock::new(|| EcmaCaptures::new(&JS_QUERY));

// ── Thread-local parsers ──────────────────────────────────────────────────────

thread_local! {
    static TS_PARSER: RefCell<tree_sitter::Parser> = RefCell::new({
        let mut p = tree_sitter::Parser::new();
        p.set_language(&TS_LANGUAGE).expect("parser/typescript: TS grammar load failed");
        p
    });
    static TSX_PARSER: RefCell<tree_sitter::Parser> = RefCell::new({
        let mut p = tree_sitter::Parser::new();
        p.set_language(&TSX_LANGUAGE).expect("parser/typescript: TSX grammar load failed");
        p
    });
    static JS_PARSER: RefCell<tree_sitter::Parser> = RefCell::new({
        let mut p = tree_sitter::Parser::new();
        p.set_language(&JS_LANGUAGE).expect("parser/typescript: JS grammar load failed");
        p
    });
}

// ── Capture indices ───────────────────────────────────────────────────────────

struct EcmaCaptures {
    pub_fn: u32,
    pub_type: u32,
    re_export: u32,
    import: u32,
    unwrap: Option<u32>, // TS-only: non_null_expression
    branch: u32,
    comment: u32,
}

impl EcmaCaptures {
    fn new(query: &tree_sitter::Query) -> Self {
        let idx = |name: &str| {
            query
                .capture_index_for_name(name)
                .unwrap_or_else(|| panic!("parser/typescript: query missing @{name}"))
        };
        Self {
            pub_fn: idx("pub_fn"),
            pub_type: idx("pub_type"),
            re_export: idx("re_export"),
            import: idx("import"),
            unwrap: query.capture_index_for_name("unwrap"), // None for JS
            branch: idx("branch"),
            comment: idx("comment"),
        }
    }
}

// ── Parser ────────────────────────────────────────────────────────────────────

/// Dispatch to the correct grammar based on language + file extension.
pub(super) fn parse_typescript(file: &WalkedFile, source: &str) -> Result<StaticFileAnalysis> {
    let src = source.as_bytes();

    let (tree, query, captures) = match file.language {
        Language::JavaScript => {
            let tree = JS_PARSER.with(|p| p.borrow_mut().parse(src, None));
            (tree, &*JS_QUERY, &*JS_CAPTURES)
        }
        Language::TypeScript => {
            if file.rel_path.ends_with(".tsx") {
                let tree = TSX_PARSER.with(|p| p.borrow_mut().parse(src, None));
                (tree, &*TSX_QUERY, &*TS_CAPTURES)
            } else {
                let tree = TS_PARSER.with(|p| p.borrow_mut().parse(src, None));
                (tree, &*TS_QUERY, &*TS_CAPTURES)
            }
        }
        _ => unreachable!("parse_typescript called with {:?}", file.language),
    };

    let tree = match tree {
        Some(t) => t,
        None => {
            tracing::warn!("parser/ts: tree-sitter failed on {}", file.rel_path);
            return Ok(StaticFileAnalysis::empty(file));
        }
    };

    parse_ecma(file, source, &tree, query, captures)
}

/// Shared dispatch loop for all ECMAScript-family languages.
fn parse_ecma(
    file: &WalkedFile,
    source: &str,
    tree: &tree_sitter::Tree,
    query: &tree_sitter::Query,
    ci: &EcmaCaptures,
) -> Result<StaticFileAnalysis> {
    let src = source.as_bytes();

    let mut out = StaticFileAnalysis {
        path: file.rel_path.clone(),
        language: file.language,
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

            // Count-only captures.
            if idx == ci.branch {
                out.branch_count += 1;
            } else if ci.unwrap.is_some_and(|u| u == idx) {
                out.unwrap_count += 1;
            // Text captures.
            } else if idx == ci.pub_fn {
                if let Ok(name) = node.utf8_text(src) {
                    out.entry_points.push(name.to_owned());
                }
            } else if idx == ci.pub_type {
                if let Ok(name) = node.utf8_text(src) {
                    out.exported_types.push(name.to_owned());
                }
            } else if idx == ci.re_export {
                if let Ok(name) = node.utf8_text(src) {
                    out.entry_points.push(name.to_owned());
                }
            } else if idx == ci.import {
                if let Ok(raw) = node.utf8_text(src) {
                    // Strip surrounding quotes: "react" → react
                    let path = raw.trim_matches(|c| c == '"' || c == '\'');
                    out.imports.push(path.to_owned());
                }
            } else if idx == ci.comment {
                if let Ok(text) = node.utf8_text(src) {
                    let row = node.start_position().row;
                    let line = row as u32 + 1;
                    if let Some(todo) = extract_todo(text, line) {
                        out.todos.push(todo);
                    }
                    // Capture file-top comments as module doc.
                    // Handles JSDoc block (`/** ... */`) and line (`// ...`) styles.
                    if row < 5 {
                        if text.starts_with("/**") {
                            let inner =
                                text.trim_start_matches("/**").trim_end_matches("*/").trim();
                            let collapsed: String = inner
                                .lines()
                                .map(|l| l.trim().trim_start_matches('*').trim())
                                .filter(|l| !l.is_empty() && !l.starts_with('@'))
                                .collect::<Vec<_>>()
                                .join(" ");
                            if !collapsed.is_empty() {
                                doc_lines.push((row, collapsed));
                            }
                        } else if text.starts_with("//") {
                            let stripped = text.trim_start_matches("//").trim().to_string();
                            if !stripped.is_empty() {
                                doc_lines.push((row, stripped));
                            }
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
            out.module_doc = Some(super::normalize_doc(&contiguous.join(" ")));
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

    fn make_file(dir: &TempDir, rel: &str, content: &str, lang: Language) -> WalkedFile {
        let abs = dir.path().join(rel);
        if let Some(parent) = abs.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&abs, content).unwrap();
        WalkedFile {
            abs_path: abs,
            rel_path: rel.to_owned(),
            language: lang,
            size_bytes: content.len() as u64,
            mtime_secs: 0,
        }
    }

    fn parse_ts(dir: &TempDir, source: &str) -> StaticFileAnalysis {
        let f = make_file(dir, "test.ts", source, Language::TypeScript);
        parse_typescript(&f, source).unwrap()
    }

    fn parse_js(dir: &TempDir, source: &str) -> StaticFileAnalysis {
        let f = make_file(dir, "test.js", source, Language::JavaScript);
        parse_typescript(&f, source).unwrap()
    }

    // ── TypeScript entry points ───────────────────────────────────────────────

    #[test]
    fn ts_exported_function() {
        let dir = TempDir::new().unwrap();
        let a = parse_ts(&dir, "export function foo() {}");
        assert!(a.entry_points.contains(&"foo".to_owned()));
    }

    #[test]
    fn ts_non_exported_function_excluded() {
        let dir = TempDir::new().unwrap();
        let a = parse_ts(&dir, "function bar() {}");
        assert!(!a.entry_points.contains(&"bar".to_owned()));
    }

    #[test]
    fn ts_export_const_arrow() {
        let dir = TempDir::new().unwrap();
        let a = parse_ts(&dir, "export const handler = () => {};");
        assert!(a.entry_points.contains(&"handler".to_owned()));
    }

    // ── TypeScript exported types ─────────────────────────────────────────────

    #[test]
    fn ts_exported_class() {
        let dir = TempDir::new().unwrap();
        let a = parse_ts(&dir, "export class MyService {}");
        assert!(a.exported_types.contains(&"MyService".to_owned()));
    }

    #[test]
    fn ts_exported_interface() {
        let dir = TempDir::new().unwrap();
        let a = parse_ts(&dir, "export interface Props { name: string; }");
        assert!(a.exported_types.contains(&"Props".to_owned()));
    }

    #[test]
    fn ts_exported_type_alias() {
        let dir = TempDir::new().unwrap();
        let a = parse_ts(
            &dir,
            "export type Result<T> = { ok: true; value: T } | { ok: false };",
        );
        assert!(a.exported_types.contains(&"Result".to_owned()));
    }

    #[test]
    fn ts_exported_enum() {
        let dir = TempDir::new().unwrap();
        let a = parse_ts(&dir, "export enum Color { Red, Green, Blue }");
        assert!(a.exported_types.contains(&"Color".to_owned()));
    }

    // ── Re-exports ────────────────────────────────────────────────────────────

    #[test]
    fn ts_re_export_names() {
        let dir = TempDir::new().unwrap();
        let a = parse_ts(&dir, "export { foo, bar } from './module';");
        assert!(a.entry_points.contains(&"foo".to_owned()));
        assert!(a.entry_points.contains(&"bar".to_owned()));
    }

    #[test]
    fn ts_re_export_source_in_imports() {
        let dir = TempDir::new().unwrap();
        let a = parse_ts(&dir, "export { foo } from './module';");
        assert!(a.imports.contains(&"./module".to_owned()));
    }

    // ── Imports ───────────────────────────────────────────────────────────────

    #[test]
    fn ts_import_strips_quotes() {
        let dir = TempDir::new().unwrap();
        let a = parse_ts(&dir, "import { useState } from 'react';");
        assert!(a.imports.contains(&"react".to_owned()));
    }

    #[test]
    fn ts_import_double_quotes() {
        let dir = TempDir::new().unwrap();
        let a = parse_ts(&dir, r#"import express from "express";"#);
        assert!(a.imports.contains(&"express".to_owned()));
    }

    #[test]
    fn ts_multiple_imports() {
        let dir = TempDir::new().unwrap();
        let a = parse_ts(&dir, "import a from 'a';\nimport b from 'b';");
        assert_eq!(a.imports.len(), 2);
    }

    // ── Risk signals ──────────────────────────────────────────────────────────

    #[test]
    fn ts_non_null_assertion() {
        let dir = TempDir::new().unwrap();
        let a = parse_ts(&dir, "const x = document.getElementById('app')!;");
        assert_eq!(a.unwrap_count, 1);
    }

    #[test]
    fn ts_multiple_non_null() {
        let dir = TempDir::new().unwrap();
        let a = parse_ts(&dir, "const a = x!; const b = y!;");
        assert_eq!(a.unwrap_count, 2);
    }

    #[test]
    fn ts_if_branch() {
        let dir = TempDir::new().unwrap();
        let a = parse_ts(&dir, "if (true) {}");
        assert_eq!(a.branch_count, 1);
    }

    #[test]
    fn ts_switch_branch() {
        let dir = TempDir::new().unwrap();
        let a = parse_ts(&dir, "switch (x) { case 1: break; }");
        assert_eq!(a.branch_count, 1);
    }

    #[test]
    fn ts_ternary_branch() {
        let dir = TempDir::new().unwrap();
        let a = parse_ts(&dir, "const x = true ? 1 : 2;");
        assert_eq!(a.branch_count, 1);
    }

    // ── TODOs ─────────────────────────────────────────────────────────────────

    #[test]
    fn ts_todo_extracted() {
        let dir = TempDir::new().unwrap();
        let a = parse_ts(&dir, "// TODO: refactor this\nconst x = 1;");
        assert_eq!(a.todos.len(), 1);
        assert_eq!(a.todos[0].kind, TodoKind::Todo);
    }

    #[test]
    fn ts_ignore_captured() {
        let dir = TempDir::new().unwrap();
        let a = parse_ts(&dir, "// @ts-ignore\nconst x: any = {};");
        assert_eq!(a.todos.len(), 1);
        assert_eq!(a.todos[0].kind, TodoKind::Note);
    }

    // ── TSX ───────────────────────────────────────────────────────────────────

    #[test]
    fn tsx_parses_without_error() {
        let dir = TempDir::new().unwrap();
        let f = make_file(
            &dir,
            "App.tsx",
            "export function App() { return <div>hello</div>; }",
            Language::TypeScript,
        );
        let a = parse_typescript(&f, "export function App() { return <div>hello</div>; }").unwrap();
        assert!(a.entry_points.contains(&"App".to_owned()));
    }

    // ── JavaScript ────────────────────────────────────────────────────────────

    #[test]
    fn js_exported_function() {
        let dir = TempDir::new().unwrap();
        let a = parse_js(&dir, "export function foo() {}");
        assert!(a.entry_points.contains(&"foo".to_owned()));
    }

    #[test]
    fn js_exported_class() {
        let dir = TempDir::new().unwrap();
        let a = parse_js(&dir, "export class Bar {}");
        assert!(a.exported_types.contains(&"Bar".to_owned()));
    }

    #[test]
    fn js_no_unwrap_count() {
        let dir = TempDir::new().unwrap();
        // JS has no non_null_expression — unwrap stays 0
        let a = parse_js(&dir, "const x = 1;");
        assert_eq!(a.unwrap_count, 0);
    }

    #[test]
    fn js_import() {
        let dir = TempDir::new().unwrap();
        let a = parse_js(&dir, "import express from 'express';");
        assert!(a.imports.contains(&"express".to_owned()));
    }

    // ── Edge cases ────────────────────────────────────────────────────────────

    #[test]
    fn empty_ts_file() {
        let dir = TempDir::new().unwrap();
        let a = parse_ts(&dir, "");
        assert!(a.entry_points.is_empty());
        assert_eq!(a.branch_count, 0);
    }

    #[test]
    fn empty_js_file() {
        let dir = TempDir::new().unwrap();
        let a = parse_js(&dir, "");
        assert!(a.entry_points.is_empty());
    }
}
