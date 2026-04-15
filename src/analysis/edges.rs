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
use crate::analysis::walker::{Language, WalkedFile};
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

    let mut file_index = match derived_root {
        Some(ref root) => {
            FileIndex::new_with_root(root.clone(), files.iter().map(|f| f.rel_path.clone()))
        }
        None => FileIndex::new(files.iter().map(|f| f.rel_path.clone())),
    };

    // Detect Rust crate roots and workspace members from Cargo.toml.
    if let Some(ref root) = derived_root {
        let crate_roots = detect_rust_crate_roots(root, &file_index);
        if !crate_roots.is_empty() {
            file_index.set_crate_roots(crate_roots);
        }
        let members = detect_workspace_members(root);
        if !members.is_empty() {
            file_index.set_workspace_members(members);
        }
    }

    // Detect Scala source roots from file paths (multi-project sbt layouts).
    let scala_roots = detect_scala_source_roots(files);
    if !scala_roots.is_empty() {
        file_index.set_scala_source_roots(scala_roots);
    }

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
            // Skip imports classified as external at parse time —
            // but for Rust files in a workspace, try cross-crate resolution first.
            if import_stmt.kind == ImportKind::External {
                if file.language == Language::Rust && file_index.has_workspace_members() {
                    if let Some(target_rel) = crate::analysis::resolvers::rust::resolve_cross_crate(
                        &import_stmt.path,
                        &file_index,
                    ) {
                        let to_key = file_key(&target_rel);
                        if from_key != to_key {
                            edges.push((from_key.clone(), EdgeKind::Imports, to_key));
                        }
                    }
                }
                // C/C++ angle-bracket includes classified as External may
                // actually be project-internal (e.g. `#include <nlohmann/json.hpp>`).
                // Try to resolve them against the file index before skipping.
                if matches!(file.language, Language::C | Language::Cpp) {
                    let resolved = match file.language {
                        Language::Cpp => crate::analysis::resolvers::cpp::resolve_angle_bracket(
                            &import_stmt.path,
                            &file.rel_path,
                            &file_index,
                        ),
                        _ => crate::analysis::resolvers::c::resolve_angle_bracket(
                            &import_stmt.path,
                            &file.rel_path,
                            &file_index,
                        ),
                    };
                    if let Some(target_rel) = resolved {
                        let to_key = file_key(&target_rel);
                        if from_key != to_key {
                            edges.push((from_key.clone(), EdgeKind::Imports, to_key));
                        }
                    }
                }
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

/// Detect Rust crate root prefixes from `Cargo.toml`.
///
/// For workspace projects, reads `[workspace].members` and expands globs to
/// produce roots like `"crates/regex/src/"`. For single-crate projects,
/// produces `["src/"]` if `src/` contains Rust files.
pub fn detect_rust_crate_roots(repo_root: &Path, file_index: &FileIndex) -> Vec<String> {
    let cargo_path = repo_root.join("Cargo.toml");
    let content = match std::fs::read_to_string(&cargo_path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let doc = match content.parse::<toml_edit::DocumentMut>() {
        Ok(d) => d,
        Err(_) => return Vec::new(),
    };

    let mut roots = Vec::new();

    // Check for [workspace] section with members.
    if let Some(workspace) = doc.get("workspace").and_then(|w| w.as_table()) {
        if let Some(members) = workspace.get("members").and_then(|m| m.as_array()) {
            for member in members.iter() {
                if let Some(pattern) = member.as_str() {
                    expand_workspace_member(repo_root, pattern, &mut roots);
                }
            }
        }
    }

    // If workspace members produced roots, also check if the root crate has src/.
    if !roots.is_empty() {
        if file_index.contains("src/lib.rs") || file_index.contains("src/main.rs") {
            roots.push("src/".to_string());
        }
        return roots;
    }

    // Single-crate project: if [package] exists and src/ has Rust files.
    if doc.get("package").is_some()
        && (file_index.contains("src/lib.rs") || file_index.contains("src/main.rs"))
    {
        roots.push("src/".to_string());
    }

    roots
}

/// Expand a workspace member pattern (e.g. `"crates/*"`) into `<member>/src/` roots.
fn expand_workspace_member(repo_root: &Path, pattern: &str, roots: &mut Vec<String>) {
    if pattern.contains('*') {
        // Glob: e.g. "crates/*" — enumerate matching directories.
        let base_dir = repo_root.join(pattern.split('*').next().unwrap_or(""));
        if let Ok(entries) = std::fs::read_dir(&base_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() && path.join("src").is_dir() {
                    if let Ok(rel) = path.strip_prefix(repo_root) {
                        let root = format!("{}/src/", rel.to_string_lossy().replace('\\', "/"));
                        roots.push(root);
                    }
                }
            }
        }
    } else {
        // Literal member: e.g. "crates/foo"
        let member_dir = repo_root.join(pattern);
        if member_dir.join("src").is_dir() {
            let root = format!("{}/src/", pattern.trim_end_matches('/'));
            roots.push(root);
        }
    }
}

/// Detect workspace member crate names from each member's `Cargo.toml`.
///
/// Returns a map from snake_case crate name (as used in `use` statements)
/// to the crate root path (e.g. `"crates/regex/src/"`).
pub fn detect_workspace_members(repo_root: &Path) -> std::collections::HashMap<String, String> {
    let mut members = std::collections::HashMap::new();

    let cargo_path = repo_root.join("Cargo.toml");
    let content = match std::fs::read_to_string(&cargo_path) {
        Ok(c) => c,
        Err(_) => return members,
    };
    let doc = match content.parse::<toml_edit::DocumentMut>() {
        Ok(d) => d,
        Err(_) => return members,
    };

    let workspace = match doc.get("workspace").and_then(|w| w.as_table()) {
        Some(w) => w,
        None => return members,
    };
    let member_patterns = match workspace.get("members").and_then(|m| m.as_array()) {
        Some(a) => a,
        None => return members,
    };

    // Collect all member directories (expanding globs).
    let mut member_dirs: Vec<std::path::PathBuf> = Vec::new();
    for member in member_patterns.iter() {
        if let Some(pattern) = member.as_str() {
            collect_member_dirs(repo_root, pattern, &mut member_dirs);
        }
    }

    // Also check if the root crate is part of the workspace.
    if doc.get("package").is_some() {
        member_dirs.push(repo_root.to_path_buf());
    }

    // Read each member's Cargo.toml to extract [package].name.
    for dir in &member_dirs {
        let member_cargo = dir.join("Cargo.toml");
        let member_content = match std::fs::read_to_string(&member_cargo) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let member_doc = match member_content.parse::<toml_edit::DocumentMut>() {
            Ok(d) => d,
            Err(_) => continue,
        };
        let name = match member_doc
            .get("package")
            .and_then(|p| p.get("name"))
            .and_then(|n| n.as_str())
        {
            Some(n) => n,
            None => continue,
        };

        // Compute the crate root path relative to repo root.
        let crate_root = if dir == repo_root {
            "src/".to_string()
        } else if let Ok(rel) = dir.strip_prefix(repo_root) {
            format!("{}/src/", rel.to_string_lossy().replace('\\', "/"))
        } else {
            continue;
        };

        // Normalize kebab-case to snake_case (grep-regex → grep_regex).
        let snake_name = name.replace('-', "_");
        members.insert(snake_name, crate_root);
    }

    members
}

/// Collect member directories from a workspace member pattern, expanding globs.
fn collect_member_dirs(repo_root: &Path, pattern: &str, dirs: &mut Vec<std::path::PathBuf>) {
    if pattern.contains('*') {
        let base_dir = repo_root.join(pattern.split('*').next().unwrap_or(""));
        if let Ok(entries) = std::fs::read_dir(&base_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    dirs.push(path);
                }
            }
        }
    } else {
        let dir = repo_root.join(pattern);
        if dir.is_dir() {
            dirs.push(dir);
        }
    }
}

/// Discover Scala source root prefixes from walked file paths.
///
/// Scans for directories matching sbt/Maven conventions:
/// `**/src/main/scala/`, `**/src/test/scala/`, and Scala-version-specific
/// variants. Returns each discovered root as a path prefix suitable for
/// prepending to a dotted-import-derived relative path.
fn detect_scala_source_roots(files: &[WalkedFile]) -> Vec<String> {
    const SCALA_PATTERNS: &[&str] = &[
        "src/main/scala/",
        "src/test/scala/",
        "src/main/scala-2.13/",
        "src/main/scala-2.12/",
        "src/main/scala-3/",
        "src/test/scala-2.13/",
        "src/test/scala-3/",
    ];

    let mut roots: HashSet<String> = HashSet::new();

    for file in files {
        if file.language != Language::Scala {
            continue;
        }
        for pattern in SCALA_PATTERNS {
            if let Some(pos) = file.rel_path.find(pattern) {
                let root = &file.rel_path[..pos + pattern.len()];
                roots.insert(root.to_string());
            }
        }
    }

    let mut result: Vec<String> = roots.into_iter().collect();
    result.sort(); // Deterministic order for tests.
    result
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

    // ── C/C++ angle-bracket resolution ─────────────────────────────────

    /// Helper: build a StaticFileAnalysis with explicit ImportStatements.
    fn analysis_with_imports(
        path: &str,
        lang: Language,
        imports: Vec<ImportStatement>,
    ) -> StaticFileAnalysis {
        StaticFileAnalysis {
            path: path.to_string(),
            language: lang,
            entry_points: vec![],
            exported_types: vec![],
            imports,
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

    #[test]
    fn cpp_angle_bracket_internal_include_resolves() {
        // #include <nlohmann/json.hpp> from a test file — the header exists
        // under include/, so the angle-bracket exception should create an edge.
        let files = vec![
            walked("tests/test.cpp", Language::Cpp),
            walked("include/nlohmann/json.hpp", Language::Cpp),
        ];
        let analyses = vec![
            analysis_with_imports(
                "tests/test.cpp",
                Language::Cpp,
                vec![ImportStatement::new(
                    "nlohmann/json.hpp",
                    ImportKind::External,
                    1,
                )],
            ),
            analysis_with_imports("include/nlohmann/json.hpp", Language::Cpp, vec![]),
        ];

        let result = build_edges(&files, &analyses, &[]);
        assert_eq!(
            result.edges.len(),
            1,
            "angle-bracket include that resolves to a repo file should produce an edge"
        );
        assert_eq!(result.edges[0].2, "file:include/nlohmann/json.hpp");
    }

    #[test]
    fn cpp_angle_bracket_external_stays_skipped() {
        // #include <vector> — no matching file, should produce no edge.
        let files = vec![walked("src/main.cpp", Language::Cpp)];
        let analyses = vec![analysis_with_imports(
            "src/main.cpp",
            Language::Cpp,
            vec![ImportStatement::new("vector", ImportKind::External, 1)],
        )];

        let result = build_edges(&files, &analyses, &[]);
        assert_eq!(result.edges.len(), 0);
        // External imports that fail resolution are not counted as unresolved.
        assert_eq!(result.unresolved_imports, 0);
    }

    #[test]
    fn cpp_quoted_include_unchanged() {
        // #include "helper.h" — Relative kind, resolved through the normal path.
        let files = vec![
            walked("src/main.cpp", Language::Cpp),
            walked("src/helper.h", Language::Cpp),
        ];
        let analyses = vec![
            analysis_with_imports(
                "src/main.cpp",
                Language::Cpp,
                vec![ImportStatement::new("helper.h", ImportKind::Relative, 1)],
            ),
            analysis_with_imports("src/helper.h", Language::Cpp, vec![]),
        ];

        let result = build_edges(&files, &analyses, &[]);
        assert_eq!(result.edges.len(), 1);
        assert_eq!(result.edges[0].2, "file:src/helper.h");
    }
}
