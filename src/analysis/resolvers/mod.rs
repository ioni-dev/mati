//! Trait-based import resolution system.
//!
//! Each supported language implements [`LanguageResolver`] to map import
//! statements into repo-relative file paths. The [`ResolverRegistry`] provides
//! dispatch by language, and [`FileIndex`] provides O(1) file existence checks
//! plus helper queries needed by language-specific resolvers.
//!
//! # Architecture
//!
//! ```text
//! build_edges()
//!   → ResolverRegistry::resolve(import, file, language, &file_index)
//!       → dispatches to LanguageResolver::resolve(import, file, &file_index)
//!           → returns Option<String> (repo-relative target path)
//! ```
//!
//! Adding a new language resolver:
//! 1. Create `src/analysis/resolvers/<lang>.rs`
//! 2. Implement `LanguageResolver` for your struct
//! 3. Register in `ResolverRegistry::new()`

pub mod python;
pub mod rust;
pub mod typescript;

use std::collections::HashMap;
use std::collections::HashSet;

use crate::analysis::parser::import::ImportKind;
use crate::analysis::parser::ImportStatement;
use crate::analysis::walker::Language;

// ── LanguageResolver trait ──────────────────────────────────────────────────

/// Trait for language-specific import resolution.
///
/// Each implementation maps an `ImportStatement` from a source file to a
/// repo-relative file path, using the `FileIndex` for existence checks.
pub trait LanguageResolver: Send + Sync {
    /// Resolve an import statement from `importing_file` into a repo-relative
    /// file path that exists in `file_index`. Return `None` if resolution fails
    /// or the import is external.
    fn resolve(
        &self,
        import: &ImportStatement,
        importing_file: &str,
        file_index: &FileIndex,
    ) -> Option<String>;

    /// The language(s) this resolver handles.
    fn language(&self) -> Language;

    /// A short human-readable name for debugging and logging.
    fn name(&self) -> &'static str;
}

// ── FileIndex ───────────────────────────────────────────────────────────────

/// Index of all known repo-relative file paths for O(1) existence checks.
///
/// Wraps a `HashSet<String>` with helper methods that language resolvers
/// commonly need. Linear-scan helpers (`files_with_prefix`, `files_with_stem`)
/// are acceptable at Layer 0 scale — optimize if benchmarks show a hot spot.
pub struct FileIndex {
    files: HashSet<String>,
}

impl FileIndex {
    /// Create a new FileIndex from an iterator of repo-relative paths.
    pub fn new(paths: impl IntoIterator<Item = String>) -> Self {
        Self {
            files: paths.into_iter().collect(),
        }
    }

    /// Check if a repo-relative path exists in the index.
    pub fn contains(&self, path: &str) -> bool {
        self.files.contains(path)
    }

    /// Find all files whose path starts with the given prefix.
    /// Returns references to avoid allocation when only checking existence.
    pub fn files_with_prefix(&self, prefix: &str) -> Vec<&String> {
        self.files.iter().filter(|f| f.starts_with(prefix)).collect()
    }

    /// Find all files whose stem (filename without extension) matches.
    /// Useful for Go package resolution where `foo.go` matches package `foo`.
    pub fn files_with_stem(&self, stem: &str) -> Vec<&String> {
        self.files
            .iter()
            .filter(|f| {
                std::path::Path::new(f.as_str())
                    .file_stem()
                    .and_then(|s| s.to_str())
                    == Some(stem)
            })
            .collect()
    }
}

// ── ResolverRegistry ────────────────────────────────────────────────────────

/// Dispatch registry that maps languages to their resolvers.
///
/// Constructed once per `build_edges` call. Languages without a registered
/// resolver simply return `None` for all imports (no edges created).
pub struct ResolverRegistry {
    resolvers: HashMap<Language, Box<dyn LanguageResolver>>,
}

impl ResolverRegistry {
    /// Create a registry with all currently implemented resolvers.
    pub fn new() -> Self {
        let mut resolvers: HashMap<Language, Box<dyn LanguageResolver>> = HashMap::new();
        resolvers.insert(Language::Rust, Box::new(rust::RustResolver));
        resolvers.insert(Language::Python, Box::new(python::PythonResolver));
        resolvers.insert(
            Language::TypeScript,
            Box::new(typescript::TypeScriptResolver),
        );
        resolvers.insert(
            Language::JavaScript,
            Box::new(typescript::TypeScriptResolver),
        );
        Self { resolvers }
    }

    /// Resolve an import statement for the given language.
    ///
    /// Returns `None` if:
    /// - The import is classified as `External` (skipped without resolution)
    /// - No resolver is registered for the language
    /// - The resolver cannot find a matching file
    pub fn resolve(
        &self,
        import: &ImportStatement,
        importing_file: &str,
        language: Language,
        file_index: &FileIndex,
    ) -> Option<String> {
        // External imports are never resolved — the parser already classified them.
        if import.kind == ImportKind::External {
            return None;
        }
        self.resolvers
            .get(&language)?
            .resolve(import, importing_file, file_index)
    }
}

impl Default for ResolverRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_index_contains() {
        let idx = FileIndex::new(vec!["src/main.rs".into(), "src/lib.rs".into()]);
        assert!(idx.contains("src/main.rs"));
        assert!(!idx.contains("src/foo.rs"));
    }

    #[test]
    fn file_index_prefix() {
        let idx = FileIndex::new(vec![
            "src/store/db.rs".into(),
            "src/store/mod.rs".into(),
            "src/main.rs".into(),
        ]);
        let results = idx.files_with_prefix("src/store/");
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn file_index_stem() {
        let idx = FileIndex::new(vec![
            "src/utils.rs".into(),
            "lib/utils.py".into(),
            "src/main.rs".into(),
        ]);
        let results = idx.files_with_stem("utils");
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn registry_skips_external() {
        let registry = ResolverRegistry::new();
        let idx = FileIndex::new(vec!["src/main.rs".into()]);
        let import = ImportStatement::new("react", ImportKind::External, 1);
        assert_eq!(
            registry.resolve(&import, "src/app.ts", Language::TypeScript, &idx),
            None
        );
    }

    #[test]
    fn registry_returns_none_for_unregistered_language() {
        let registry = ResolverRegistry::new();
        let idx = FileIndex::new(vec!["main.go".into()]);
        let import = ImportStatement::new("fmt", ImportKind::Normal, 1);
        assert_eq!(
            registry.resolve(&import, "main.go", Language::Go, &idx),
            None
        );
    }
}
