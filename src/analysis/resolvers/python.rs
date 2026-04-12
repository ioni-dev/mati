//! Python import resolver.
//!
//! Resolves dotted module paths to `.py` files or `__init__.py` packages.
//! Relative imports (`.foo`, `..foo`) resolve from the importing file's
//! directory. Absolute imports resolve from the repo root.
//!
//! Limitation: cannot distinguish stdlib from local modules without a venv
//! scan. All imports are treated as potentially resolvable. False negatives
//! (unresolved count) are acceptable at Layer 0.

use std::path::Path;

use super::{FileIndex, LanguageResolver};
use crate::analysis::parser::ImportStatement;
use crate::analysis::walker::Language;

/// Python import resolver for dotted module paths and relative imports.
pub struct PythonResolver;

impl LanguageResolver for PythonResolver {
    fn resolve(
        &self,
        import: &ImportStatement,
        importing_file: &str,
        file_index: &FileIndex,
    ) -> Option<String> {
        resolve_python(&import.path, importing_file, file_index)
    }

    fn language(&self) -> Language {
        Language::Python
    }

    fn name(&self) -> &'static str {
        "python"
    }
}

/// Core resolution logic, extracted for direct testing.
fn resolve_python(
    import_path: &str,
    importing_file: &str,
    file_index: &FileIndex,
) -> Option<String> {
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
    if file_index.contains(&py_file) {
        return Some(py_file);
    }

    // Try package: foo/bar/__init__.py
    let init_file = format!("{prefix}/__init__.py");
    if file_index.contains(&init_file) {
        return Some(init_file);
    }

    None
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::parser::import::ImportKind;

    fn idx(paths: &[&str]) -> FileIndex {
        FileIndex::new(paths.iter().map(|s| s.to_string()))
    }

    fn import(path: &str, kind: ImportKind) -> ImportStatement {
        ImportStatement::new(path, kind, 1)
    }

    #[test]
    fn absolute_import_resolves() {
        let file_index = idx(&["app/main.py", "app/utils.py"]);
        let resolver = PythonResolver;
        let result = resolver.resolve(
            &import("app.utils", ImportKind::Normal),
            "app/main.py",
            &file_index,
        );
        assert_eq!(result, Some("app/utils.py".into()));
    }

    #[test]
    fn relative_import_resolves() {
        let file_index = idx(&["app/main.py", "app/helpers.py"]);
        let resolver = PythonResolver;
        let result = resolver.resolve(
            &import(".helpers", ImportKind::Relative),
            "app/main.py",
            &file_index,
        );
        assert_eq!(result, Some("app/helpers.py".into()));
    }

    #[test]
    fn package_init_resolves() {
        let file_index = idx(&["main.py", "pkg/__init__.py"]);
        let resolver = PythonResolver;
        let result = resolver.resolve(
            &import("pkg", ImportKind::Normal),
            "main.py",
            &file_index,
        );
        assert_eq!(result, Some("pkg/__init__.py".into()));
    }

    #[test]
    fn double_dot_relative() {
        let file_index = idx(&["app/sub/deep.py", "app/utils.py"]);
        let resolver = PythonResolver;
        let result = resolver.resolve(
            &import("..utils", ImportKind::Relative),
            "app/sub/deep.py",
            &file_index,
        );
        assert_eq!(result, Some("app/utils.py".into()));
    }

    #[test]
    fn unresolvable_returns_none() {
        let file_index = idx(&["app/main.py"]);
        let resolver = PythonResolver;
        let result = resolver.resolve(
            &import("app.nonexistent", ImportKind::Normal),
            "app/main.py",
            &file_index,
        );
        assert_eq!(result, None);
    }
}
