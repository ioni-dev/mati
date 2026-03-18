//! Graph edge construction from Layer 0 signals (M-06-G).
//!
//! Converts import statements and git co-change pairs into typed edges
//! ready for [`crate::graph::Graph::add_edges_batch`].
//!
//! Import resolution is best-effort: raw import paths (e.g. `crate::utils`)
//! are resolved against the set of known walked files. Unresolvable imports
//! (external crates, std lib, ambiguous paths) are silently skipped — Layer 0
//! favours precision over recall.

use std::collections::HashSet;
use std::path::Path;

use crate::analysis::parser::StaticFileAnalysis;
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
    assert_eq!(
        files.len(),
        analyses.len(),
        "build_edges expects one analysis per walked file"
    );

    let file_set: HashSet<&str> = files.iter().map(|f| f.rel_path.as_str()).collect();

    // Build lookup tables for import resolution.
    let resolver = ImportResolver::new(files);

    let mut edges: Vec<(String, EdgeKind, String)> = Vec::new();
    let mut unresolved_imports = 0usize;

    // ── Import edges ────────────────────────────────────────────────────────
    for (file, analysis) in files.iter().zip(analyses.iter()) {
        // Skip files with no imports — avoid allocating from_key.
        if analysis.imports.is_empty() {
            continue;
        }

        let from_key = file_key(&file.rel_path);

        for import_path in &analysis.imports {
            // Skip imports that are known-external (not intra-repo).
            if is_external_import(import_path, file.language) {
                continue;
            }

            if let Some(target_rel) = resolver.resolve(import_path, &file.rel_path, file.language)
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

/// Returns true if the import is known to be external (not intra-repo)
/// and should be skipped without counting as unresolved.
fn is_external_import(import_path: &str, language: Language) -> bool {
    match language {
        // Rust: only `crate::` is intra-repo. Everything else (std, external crates,
        // super, self) is either external or handled differently.
        Language::Rust => !import_path.starts_with("crate::"),
        // TS/JS: bare specifiers (no `.` prefix) are npm packages.
        Language::TypeScript | Language::JavaScript => !import_path.starts_with('.'),
        // Python: can't easily distinguish stdlib from local without a venv scan.
        // Treat all Python imports as potentially resolvable.
        _ => false,
    }
}

// ── Import resolver ─────────────────────────────────────────────────────────

/// Best-effort resolver that maps raw import paths to repo-relative file paths.
///
/// Strategy per language:
/// - **Rust**: `crate::foo::bar` → try `src/foo/bar.rs`, `src/foo/bar/mod.rs`.
///   Assumes standard `src/` layout — non-standard crate roots (e.g. `lib/`,
///   workspace `crates/*/src/`) are not resolved. Acceptable Layer 0 limitation.
/// - **Python**: `foo.bar` → try `foo/bar.py`, `foo/bar/__init__.py`;
///   relative imports (`.foo`, `..foo`) resolved from importing file's directory.
///   Triple-dot and deeper relative imports are not supported.
/// - **TypeScript/JavaScript**: `./foo` → try with `.ts`, `.tsx`, `.js`, `.jsx`,
///   `/index.ts`, `/index.js` suffixes; bare specifiers (no `.` prefix) are
///   filtered by `is_external_import` before reaching the resolver.
struct ImportResolver {
    /// Set of all known repo-relative file paths for O(1) existence checks.
    known_files: HashSet<String>,
}

impl ImportResolver {
    fn new(files: &[WalkedFile]) -> Self {
        let known_files: HashSet<String> = files.iter().map(|f| f.rel_path.clone()).collect();
        Self { known_files }
    }

    /// Try to resolve an import path to a known repo-relative file path.
    fn resolve(
        &self,
        import_path: &str,
        importing_file: &str,
        language: Language,
    ) -> Option<String> {
        match language {
            Language::Rust => self.resolve_rust(import_path),
            Language::Python => self.resolve_python(import_path, importing_file),
            Language::TypeScript | Language::JavaScript => {
                self.resolve_ts_js(import_path, importing_file)
            }
            _ => None,
        }
    }

    /// Rust: `crate::foo::bar` → `src/foo/bar.rs` or `src/foo/bar/mod.rs`
    ///
    /// Only resolves `crate::` prefixed paths (intra-crate imports).
    /// `std::`, `super::`, `self::`, and external crate imports are filtered
    /// by `is_external_import` before reaching this method.
    fn resolve_rust(&self, import_path: &str) -> Option<String> {
        let path = import_path.strip_prefix("crate::")?;

        // Convert `foo::bar` → `src/foo/bar`
        let fs_path = format!("src/{}", path.replace("::", "/"));

        // Try direct file: src/foo/bar.rs
        let direct = format!("{fs_path}.rs");
        if self.known_files.contains(&direct) {
            return Some(direct);
        }

        // Try module directory: src/foo/bar/mod.rs
        let mod_rs = format!("{fs_path}/mod.rs");
        if self.known_files.contains(&mod_rs) {
            return Some(mod_rs);
        }

        None
    }

    /// Python: `foo.bar` → `foo/bar.py` or `foo/bar/__init__.py`
    ///
    /// Relative imports (`.foo`, `..foo`) resolve from the importing file's
    /// directory. Absolute imports resolve from the repo root.
    fn resolve_python(&self, import_path: &str, importing_file: &str) -> Option<String> {
        let (base_dir, module_path) = if let Some(stripped) = import_path.strip_prefix('.') {
            // Relative import: resolve from importing file's parent.
            let parent = Path::new(importing_file)
                .parent()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default();

            // Handle `..module` (double-dot = go up one more level)
            if let Some(double_stripped) = stripped.strip_prefix('.') {
                let grandparent = Path::new(&parent)
                    .parent()
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_default();
                (grandparent, double_stripped)
            } else {
                (parent, stripped)
            }
        } else {
            (String::new(), import_path)
        };

        // Convert dots to slashes: foo.bar → foo/bar
        let rel = module_path.replace('.', "/");

        let prefix = if base_dir.is_empty() {
            rel
        } else {
            format!("{base_dir}/{rel}")
        };

        // Try direct file: foo/bar.py
        let py_file = format!("{prefix}.py");
        if self.known_files.contains(&py_file) {
            return Some(py_file);
        }

        // Try package: foo/bar/__init__.py
        let init_file = format!("{prefix}/__init__.py");
        if self.known_files.contains(&init_file) {
            return Some(init_file);
        }

        None
    }

    /// TypeScript/JavaScript: resolve relative imports.
    ///
    /// Bare specifiers are already filtered by `is_external_import` before
    /// this method is called. Relative paths are tried with standard extensions.
    fn resolve_ts_js(&self, import_path: &str, importing_file: &str) -> Option<String> {
        // Strip quotes if present (parser may include them).
        let clean = import_path.trim_matches(|c| c == '\'' || c == '"');

        let parent = Path::new(importing_file)
            .parent()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();

        // Resolve the relative path.
        let resolved = if parent.is_empty() {
            // File is at repo root.
            clean
                .strip_prefix("./")
                .unwrap_or(clean)
                .to_string()
        } else {
            let stripped = clean.strip_prefix("./").unwrap_or(clean);
            normalize_path(&format!("{parent}/{stripped}"))
        };

        // If it already has an extension and exists, return it.
        if self.known_files.contains(&resolved) {
            return Some(resolved);
        }

        // Try standard extensions.
        for ext in &[".ts", ".tsx", ".js", ".jsx"] {
            let with_ext = format!("{resolved}{ext}");
            if self.known_files.contains(&with_ext) {
                return Some(with_ext);
            }
        }

        // Try index file in directory.
        for ext in &[".ts", ".tsx", ".js", ".jsx"] {
            let index = format!("{resolved}/index{ext}");
            if self.known_files.contains(&index) {
                return Some(index);
            }
        }

        None
    }
}

/// Normalize `../` segments in a path string.
fn normalize_path(path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for segment in path.split('/') {
        match segment {
            ".." => {
                parts.pop();
            }
            "." | "" => {}
            s => parts.push(s),
        }
    }
    parts.join("/")
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::parser::StaticFileAnalysis;
    use crate::analysis::walker::Language;

    fn walked(rel_path: &str, lang: Language) -> WalkedFile {
        WalkedFile {
            abs_path: std::path::PathBuf::from(format!("/repo/{rel_path}")),
            rel_path: rel_path.to_string(),
            language: lang,
            size_bytes: 100,
        }
    }

    fn analysis(path: &str, lang: Language, imports: &[&str]) -> StaticFileAnalysis {
        StaticFileAnalysis {
            path: path.to_string(),
            language: lang,
            entry_points: vec![],
            exported_types: vec![],
            imports: imports.iter().map(|s| s.to_string()).collect(),
            todos: vec![],
            unsafe_count: 0,
            unwrap_count: 0,
            panic_count: 0,
            branch_count: 0,
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
        let analyses = vec![analysis(
            "src/store.rs",
            Language::Rust,
            &["crate::store"],
        )];

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
            from == "file:src/a.rs"
                && *kind == EdgeKind::CoChanges
                && to == "file:src/b.rs"
        });
        let has_b_to_a = result.edges.iter().any(|(from, kind, to)| {
            from == "file:src/b.rs"
                && *kind == EdgeKind::CoChanges
                && to == "file:src/a.rs"
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
            analysis("src/lib.rs", Language::Rust, &["crate::store", "crate::search"]),
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

    // ── normalize_path ──────────────────────────────────────────────────────

    #[test]
    fn normalize_path_resolves_parent_refs() {
        assert_eq!(normalize_path("src/components/../utils"), "src/utils");
        assert_eq!(normalize_path("a/b/c/../../d"), "a/d");
        assert_eq!(normalize_path("./foo/bar"), "foo/bar");
    }
}
