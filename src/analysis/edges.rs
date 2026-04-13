//! Graph edge construction from Layer 0 signals (M-06-G).
//!
//! Converts import statements and git co-change pairs into typed edges
//! ready for [`crate::graph::Graph::add_edges_batch`].
//!
//! Import resolution is best-effort: structured `ImportStatement` values
//! are resolved via the [`ResolverRegistry`] against the set of known
//! walked files. External imports (classified at parse time) are skipped.
//! Unresolvable imports are silently counted — Layer 0 favours precision
//! over recall.

use std::collections::HashSet;
use std::path::Path;

use crate::analysis::parser::import::ImportKind;
use crate::analysis::parser::StaticFileAnalysis;
use crate::analysis::resolvers::{FileIndex, ResolverRegistry};
use crate::analysis::walker::WalkedFile;
use crate::graph::EdgeKind;

/// All edges produced by Layer 0 analysis, ready for batch insertion.
pub struct Layer0Edges {
    pub edges: Vec<(String, EdgeKind, String)>,
    /// Import paths that could not be resolved to a known file.
    pub unresolved_imports: usize,
}

/// Build graph edges from static analysis and git signals.
///
/// Returns `Imports` edges from resolved import statements and `CoChanges`
/// edges from git co-change pairs. Both use `file:<rel_path>` keys matching
/// the record key format.
pub fn build_edges(
    files: &[WalkedFile],
    analyses: &[StaticFileAnalysis],
    co_change_pairs: &[(String, String, u32)],
) -> Layer0Edges {
    build_edges_with_root(files, analyses, co_change_pairs, None)
}

/// Build edges with an explicit repo root for resolvers that need file content
/// access (e.g. Go's go.mod parsing).
pub fn build_edges_with_root(
    files: &[WalkedFile],
    analyses: &[StaticFileAnalysis],
    co_change_pairs: &[(String, String, u32)],
    repo_root: Option<&Path>,
) -> Layer0Edges {
    assert_eq!(
        files.len(),
        analyses.len(),
        "build_edges expects one analysis per walked file"
    );

    let file_set: HashSet<&str> = files.iter().map(|f| f.rel_path.as_str()).collect();

    // Derive the repo root from the first file if not provided explicitly.
    let derived_root = repo_root.map(|p| p.to_path_buf()).or_else(|| {
        files.first().and_then(|f| {
            f.abs_path
                .to_str()
                .and_then(|abs| abs.strip_suffix(&f.rel_path))
                .map(|r| Path::new(r.trim_end_matches('/')).to_path_buf())
        })
    });

    let file_index = match derived_root {
        Some(root) => FileIndex::new_with_root(root, files.iter().map(|f| f.rel_path.clone())),
        None => FileIndex::new(files.iter().map(|f| f.rel_path.clone())),
    };
    let registry = ResolverRegistry::new();

    let mut edges: Vec<(String, EdgeKind, String)> = Vec::new();
    let mut unresolved_imports = 0usize;

    // ── Import edges ────────────────────────────────────────────────────────
    for (file, analysis) in files.iter().zip(analyses.iter()) {
        // Skip files with no imports — avoid allocating from_key.
        if analysis.imports.is_empty() {
            continue;
        }

        let from_key = file_key(&file.rel_path);

        for import_stmt in &analysis.imports {
            // Skip imports classified as external at parse time.
            if import_stmt.kind == ImportKind::External {
                continue;
            }

            if let Some(target_rel) =
                registry.resolve(import_stmt, &file.rel_path, file.language, &file_index)
            {
                let to_key = file_key(&target_rel);
                // No self-edges.
                if from_key != to_key {
                    edges.push((from_key.clone(), EdgeKind::Imports, to_key));
                }
            } else {
                unresolved_imports += 1;
            }
        }
    }

    // ── Co-change edges ─────────────────────────────────────────────────────
    // Pairs are (a, b, count) with a < b. Create edges in both directions
    // so graph traversal works regardless of starting node.
    for (a, b, _count) in co_change_pairs {
        if file_set.contains(a.as_str()) && file_set.contains(b.as_str()) {
            let key_a = file_key(a);
            let key_b = file_key(b);
            edges.push((key_a.clone(), EdgeKind::CoChanges, key_b.clone()));
            edges.push((key_b, EdgeKind::CoChanges, key_a));
        }
    }

    Layer0Edges {
        edges,
        unresolved_imports,
    }
}

/// Format a repo-relative path as a record key.
fn file_key(rel_path: &str) -> String {
    format!("file:{rel_path}")
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::parser::import::ImportStatement;
    use crate::analysis::parser::StaticFileAnalysis;
    use crate::analysis::walker::Language;

    fn walked(rel_path: &str, lang: Language) -> WalkedFile {
        WalkedFile {
            abs_path: std::path::PathBuf::from(format!("/repo/{rel_path}")),
            rel_path: rel_path.to_string(),
            language: lang,
            size_bytes: 100,
            mtime_secs: 0,
        }
    }

    /// Classify an import string the same way the parsers do, for test ergonomics.
    fn classify_import(path: &str, lang: Language) -> ImportStatement {
        let kind = match lang {
            Language::Rust => {
                if path.ends_with("::*") {
                    if path.starts_with("crate::")
                        || path.starts_with("self::")
                        || path.starts_with("super::")
                    {
                        ImportKind::Wildcard
                    } else {
                        ImportKind::External
                    }
                } else if path.starts_with("crate::")
                    || path.starts_with("self::")
                    || path.starts_with("super::")
                {
                    ImportKind::Normal
                } else {
                    ImportKind::External
                }
            }
            Language::TypeScript | Language::JavaScript => {
                if path.starts_with('.') {
                    ImportKind::Relative
                } else {
                    ImportKind::External
                }
            }
            Language::Python => {
                if path.starts_with('.') {
                    ImportKind::Relative
                } else {
                    ImportKind::Normal
                }
            }
            _ => ImportKind::Normal,
        };
        ImportStatement::new(path, kind, 0)
    }

    fn analysis(path: &str, lang: Language, imports: &[&str]) -> StaticFileAnalysis {
        StaticFileAnalysis {
            path: path.to_string(),
            language: lang,
            entry_points: vec![],
            exported_types: vec![],
            imports: imports.iter().map(|s| classify_import(s, lang)).collect(),
            todos: vec![],
            unsafe_count: 0,
            unwrap_count: 0,
            panic_count: 0,
            branch_count: 0,
            module_doc: None,
            content_hash: None,
            line_count: 0,
        }
    }

    // ── Rust import resolution ──────────────────────────────────────────────

    #[test]
    fn rust_crate_import_resolves_to_file() {
        let files = vec![
            walked("src/lib.rs", Language::Rust),
            walked("src/utils.rs", Language::Rust),
        ];
        let analyses = vec![
            analysis("src/lib.rs", Language::Rust, &["crate::utils"]),
            analysis("src/utils.rs", Language::Rust, &[]),
        ];

        let result = build_edges(&files, &analyses, &[]);
        assert_eq!(result.edges.len(), 1);
        assert_eq!(result.edges[0].0, "file:src/lib.rs");
        assert_eq!(result.edges[0].1, EdgeKind::Imports);
        assert_eq!(result.edges[0].2, "file:src/utils.rs");
        assert_eq!(result.unresolved_imports, 0);
    }

    #[test]
    fn rust_crate_import_resolves_to_mod_rs() {
        let files = vec![
            walked("src/lib.rs", Language::Rust),
            walked("src/store/mod.rs", Language::Rust),
        ];
        let analyses = vec![
            analysis("src/lib.rs", Language::Rust, &["crate::store"]),
            analysis("src/store/mod.rs", Language::Rust, &[]),
        ];

        let result = build_edges(&files, &analyses, &[]);
        assert_eq!(result.edges.len(), 1);
        assert_eq!(result.edges[0].2, "file:src/store/mod.rs");
    }

    #[test]
    fn rust_self_import_resolves_relative_module() {
        let files = vec![
            walked("src/store/mod.rs", Language::Rust),
            walked("src/store/helpers.rs", Language::Rust),
        ];
        let analyses = vec![
            analysis("src/store/mod.rs", Language::Rust, &["self::helpers"]),
            analysis("src/store/helpers.rs", Language::Rust, &[]),
        ];

        let result = build_edges(&files, &analyses, &[]);
        assert_eq!(result.edges.len(), 1);
        assert_eq!(result.edges[0].2, "file:src/store/helpers.rs");
        assert_eq!(result.unresolved_imports, 0);
    }

    #[test]
    fn rust_super_import_resolves_parent_module() {
        let files = vec![
            walked("src/store/db.rs", Language::Rust),
            walked("src/store/helpers.rs", Language::Rust),
        ];
        let analyses = vec![
            analysis("src/store/db.rs", Language::Rust, &["super::helpers"]),
            analysis("src/store/helpers.rs", Language::Rust, &[]),
        ];

        let result = build_edges(&files, &analyses, &[]);
        assert_eq!(result.edges.len(), 1);
        assert_eq!(result.edges[0].2, "file:src/store/helpers.rs");
        assert_eq!(result.unresolved_imports, 0);
    }

    #[test]
    fn rust_super_import_unresolved_when_target_missing() {
        let files = vec![walked("src/store/db.rs", Language::Rust)];
        let analyses = vec![analysis(
            "src/store/db.rs",
            Language::Rust,
            &["super::helpers"],
        )];

        let result = build_edges(&files, &analyses, &[]);
        assert_eq!(result.edges.len(), 0);
        assert_eq!(result.unresolved_imports, 1);
    }

    #[test]
    fn rust_nested_crate_import() {
        let files = vec![
            walked("src/main.rs", Language::Rust),
            walked("src/store/db.rs", Language::Rust),
        ];
        let analyses = vec![
            analysis("src/main.rs", Language::Rust, &["crate::store::db"]),
            analysis("src/store/db.rs", Language::Rust, &[]),
        ];

        let result = build_edges(&files, &analyses, &[]);
        assert_eq!(result.edges.len(), 1);
        assert_eq!(result.edges[0].2, "file:src/store/db.rs");
    }

    #[test]
    fn rust_std_import_skipped() {
        let files = vec![walked("src/lib.rs", Language::Rust)];
        let analyses = vec![analysis(
            "src/lib.rs",
            Language::Rust,
            &["std::collections::HashMap"],
        )];

        let result = build_edges(&files, &analyses, &[]);
        assert_eq!(result.edges.len(), 0);
        // std:: is external — filtered before resolution, not counted as unresolved.
        assert_eq!(result.unresolved_imports, 0);
    }

    #[test]
    fn rust_external_crate_import_skipped() {
        let files = vec![walked("src/lib.rs", Language::Rust)];
        let analyses = vec![analysis(
            "src/lib.rs",
            Language::Rust,
            &["anyhow::Result", "serde::Serialize"],
        )];

        let result = build_edges(&files, &analyses, &[]);
        assert_eq!(result.edges.len(), 0);
        // External crates filtered before resolution.
        assert_eq!(result.unresolved_imports, 0);
    }

    #[test]
    fn rust_no_self_edges() {
        let files = vec![walked("src/store.rs", Language::Rust)];
        let analyses = vec![analysis("src/store.rs", Language::Rust, &["crate::store"])];

        let result = build_edges(&files, &analyses, &[]);
        assert_eq!(result.edges.len(), 0);
    }

    // ── Python import resolution ────────────────────────────────────────────

    #[test]
    fn python_absolute_import_resolves() {
        let files = vec![
            walked("app/main.py", Language::Python),
            walked("app/utils.py", Language::Python),
        ];
        let analyses = vec![
            analysis("app/main.py", Language::Python, &["app.utils"]),
            analysis("app/utils.py", Language::Python, &[]),
        ];

        let result = build_edges(&files, &analyses, &[]);
        assert_eq!(result.edges.len(), 1);
        assert_eq!(result.edges[0].2, "file:app/utils.py");
    }

    #[test]
    fn python_relative_import_resolves() {
        let files = vec![
            walked("app/main.py", Language::Python),
            walked("app/helpers.py", Language::Python),
        ];
        let analyses = vec![
            analysis("app/main.py", Language::Python, &[".helpers"]),
            analysis("app/helpers.py", Language::Python, &[]),
        ];

        let result = build_edges(&files, &analyses, &[]);
        assert_eq!(result.edges.len(), 1);
        assert_eq!(result.edges[0].2, "file:app/helpers.py");
    }

    #[test]
    fn python_package_init_resolves() {
        let files = vec![
            walked("main.py", Language::Python),
            walked("pkg/__init__.py", Language::Python),
        ];
        let analyses = vec![
            analysis("main.py", Language::Python, &["pkg"]),
            analysis("pkg/__init__.py", Language::Python, &[]),
        ];

        let result = build_edges(&files, &analyses, &[]);
        assert_eq!(result.edges.len(), 1);
        assert_eq!(result.edges[0].2, "file:pkg/__init__.py");
    }

    #[test]
    fn rust_unknown_import_returns_none() {
        let files = vec![walked("src/lib.rs", Language::Rust)];
        let analyses = vec![analysis(
            "src/lib.rs",
            Language::Rust,
            &["crate::nonexistent"],
        )];

        let result = build_edges(&files, &analyses, &[]);
        assert_eq!(result.edges.len(), 0);
        assert_eq!(result.unresolved_imports, 1);
    }

    #[test]
    fn python_unknown_import_returns_none() {
        let files = vec![walked("app/main.py", Language::Python)];
        let analyses = vec![analysis(
            "app/main.py",
            Language::Python,
            &["app.nonexistent"],
        )];

        let result = build_edges(&files, &analyses, &[]);
        assert_eq!(result.edges.len(), 0);
        assert_eq!(result.unresolved_imports, 1);
    }

    // ── TypeScript/JavaScript import resolution ─────────────────────────────

    #[test]
    fn ts_relative_import_resolves() {
        let files = vec![
            walked("src/app.ts", Language::TypeScript),
            walked("src/utils.ts", Language::TypeScript),
        ];
        let analyses = vec![
            analysis("src/app.ts", Language::TypeScript, &["./utils"]),
            analysis("src/utils.ts", Language::TypeScript, &[]),
        ];

        let result = build_edges(&files, &analyses, &[]);
        assert_eq!(result.edges.len(), 1);
        assert_eq!(result.edges[0].2, "file:src/utils.ts");
    }

    #[test]
    fn ts_relative_import_parent_dir() {
        let files = vec![
            walked("src/components/button.tsx", Language::TypeScript),
            walked("src/utils.ts", Language::TypeScript),
        ];
        let analyses = vec![
            analysis(
                "src/components/button.tsx",
                Language::TypeScript,
                &["../utils"],
            ),
            analysis("src/utils.ts", Language::TypeScript, &[]),
        ];

        let result = build_edges(&files, &analyses, &[]);
        assert_eq!(result.edges.len(), 1);
        assert_eq!(result.edges[0].2, "file:src/utils.ts");
    }

    #[test]
    fn ts_index_file_resolves() {
        let files = vec![
            walked("src/app.ts", Language::TypeScript),
            walked("src/components/index.ts", Language::TypeScript),
        ];
        let analyses = vec![
            analysis("src/app.ts", Language::TypeScript, &["./components"]),
            analysis("src/components/index.ts", Language::TypeScript, &[]),
        ];

        let result = build_edges(&files, &analyses, &[]);
        assert_eq!(result.edges.len(), 1);
        assert_eq!(result.edges[0].2, "file:src/components/index.ts");
    }

    #[test]
    fn ts_bare_specifier_skipped() {
        let files = vec![walked("src/app.ts", Language::TypeScript)];
        let analyses = vec![analysis(
            "src/app.ts",
            Language::TypeScript,
            &["react", "@tanstack/query"],
        )];

        let result = build_edges(&files, &analyses, &[]);
        assert_eq!(result.edges.len(), 0);
        // Bare specifiers are not counted as unresolved — they're intentionally skipped.
        assert_eq!(result.unresolved_imports, 0);
    }

    #[test]
    fn js_relative_import_resolves_to_js() {
        let files = vec![
            walked("lib/index.js", Language::JavaScript),
            walked("lib/helpers.js", Language::JavaScript),
        ];
        let analyses = vec![
            analysis("lib/index.js", Language::JavaScript, &["./helpers"]),
            analysis("lib/helpers.js", Language::JavaScript, &[]),
        ];

        let result = build_edges(&files, &analyses, &[]);
        assert_eq!(result.edges.len(), 1);
        assert_eq!(result.edges[0].2, "file:lib/helpers.js");
    }

    // ── Co-change edges ─────────────────────────────────────────────────────

    #[test]
    fn co_change_creates_bidirectional_edges() {
        let files = vec![
            walked("src/a.rs", Language::Rust),
            walked("src/b.rs", Language::Rust),
        ];
        let analyses = vec![
            analysis("src/a.rs", Language::Rust, &[]),
            analysis("src/b.rs", Language::Rust, &[]),
        ];
        let pairs = vec![("src/a.rs".to_string(), "src/b.rs".to_string(), 5)];

        let result = build_edges(&files, &analyses, &pairs);
        assert_eq!(result.edges.len(), 2);

        let has_a_to_b = result.edges.iter().any(|(from, kind, to)| {
            from == "file:src/a.rs" && *kind == EdgeKind::CoChanges && to == "file:src/b.rs"
        });
        let has_b_to_a = result.edges.iter().any(|(from, kind, to)| {
            from == "file:src/b.rs" && *kind == EdgeKind::CoChanges && to == "file:src/a.rs"
        });
        assert!(has_a_to_b, "missing a→b edge");
        assert!(has_b_to_a, "missing b→a edge");
    }

    #[test]
    fn co_change_skips_unknown_files() {
        let files = vec![walked("src/a.rs", Language::Rust)];
        let analyses = vec![analysis("src/a.rs", Language::Rust, &[])];
        // b.rs is in the co-change pair but not in walked files
        let pairs = vec![("src/a.rs".to_string(), "src/b.rs".to_string(), 3)];

        let result = build_edges(&files, &analyses, &pairs);
        assert_eq!(result.edges.len(), 0);
    }

    // ── Mixed ───────────────────────────────────────────────────────────────

    #[test]
    fn imports_and_co_changes_combined() {
        let files = vec![
            walked("src/lib.rs", Language::Rust),
            walked("src/store.rs", Language::Rust),
            walked("src/search.rs", Language::Rust),
        ];
        let analyses = vec![
            analysis(
                "src/lib.rs",
                Language::Rust,
                &["crate::store", "crate::search"],
            ),
            analysis("src/store.rs", Language::Rust, &[]),
            analysis("src/search.rs", Language::Rust, &[]),
        ];
        let pairs = vec![("src/search.rs".to_string(), "src/store.rs".to_string(), 4)];

        let result = build_edges(&files, &analyses, &pairs);

        let import_count = result
            .edges
            .iter()
            .filter(|(_, k, _)| *k == EdgeKind::Imports)
            .count();
        let co_change_count = result
            .edges
            .iter()
            .filter(|(_, k, _)| *k == EdgeKind::CoChanges)
            .count();

        assert_eq!(import_count, 2); // lib→store, lib→search
        assert_eq!(co_change_count, 2); // search↔store (bidirectional)
    }

    #[test]
    fn empty_inputs_produce_no_edges() {
        let result = build_edges(&[], &[], &[]);
        assert_eq!(result.edges.len(), 0);
        assert_eq!(result.unresolved_imports, 0);
    }
}
