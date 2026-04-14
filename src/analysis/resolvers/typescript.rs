//! TypeScript / JavaScript import resolver.
//!
//! Resolves relative imports (`./foo`, `../bar`) by trying standard extensions
//! (`.ts`, `.tsx`, `.js`, `.jsx`) and index files (`index.ts`, `index.js`).
//!
//! Bare specifiers (npm packages like `react`, `@tanstack/query`) are
//! classified as `ImportKind::External` at parse time and never reach this
//! resolver.

use std::path::Path;

use super::{FileIndex, LanguageResolver};
use crate::analysis::parser::ImportStatement;
use crate::analysis::walker::Language;

/// TypeScript/JavaScript resolver for relative imports.
///
/// Shared between TypeScript and JavaScript — both use the same resolution
/// strategy for relative paths.
pub struct TypeScriptResolver;

impl LanguageResolver for TypeScriptResolver {
    fn resolve(
        &self,
        import: &ImportStatement,
        importing_file: &str,
        file_index: &FileIndex,
    ) -> Option<String> {
        resolve_ts_js(&import.path, importing_file, file_index)
    }

    fn language(&self) -> Language {
        Language::TypeScript
    }

    fn name(&self) -> &'static str {
        "typescript"
    }
}

/// Core resolution logic, extracted for direct testing.
fn resolve_ts_js(
    import_path: &str,
    importing_file: &str,
    file_index: &FileIndex,
) -> Option<String> {
    // Strip quotes if present (parser may include them).
    let clean = import_path.trim_matches(|c| c == '\'' || c == '"');

    let parent = Path::new(importing_file)
        .parent()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();

    // Resolve the relative path.
    let resolved = if parent.is_empty() {
        // File is at repo root.
        clean.strip_prefix("./").unwrap_or(clean).to_string()
    } else {
        let stripped = clean.strip_prefix("./").unwrap_or(clean);
        normalize_path(&format!("{parent}/{stripped}"))
    };

    // If it already has an extension and exists, return it.
    if file_index.contains(&resolved) {
        return Some(resolved);
    }

    // Try standard extensions.
    for ext in &[".ts", ".tsx", ".js", ".jsx"] {
        let with_ext = format!("{resolved}{ext}");
        if file_index.contains(&with_ext) {
            return Some(with_ext);
        }
    }

    // Try index file in directory.
    for ext in &[".ts", ".tsx", ".js", ".jsx"] {
        let index = format!("{resolved}/index{ext}");
        if file_index.contains(&index) {
            return Some(index);
        }
    }

    None
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

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::parser::import::ImportKind;

    fn idx(paths: &[&str]) -> FileIndex {
        FileIndex::new(paths.iter().map(|s| s.to_string()))
    }

    fn import(path: &str) -> ImportStatement {
        ImportStatement::new(path, ImportKind::Relative, 1)
    }

    #[test]
    fn relative_import_resolves() {
        let file_index = idx(&["src/app.ts", "src/utils.ts"]);
        let resolver = TypeScriptResolver;
        let result = resolver.resolve(&import("./utils"), "src/app.ts", &file_index);
        assert_eq!(result, Some("src/utils.ts".into()));
    }

    #[test]
    fn parent_dir_resolves() {
        let file_index = idx(&["src/components/button.tsx", "src/utils.ts"]);
        let resolver = TypeScriptResolver;
        let result = resolver.resolve(
            &import("../utils"),
            "src/components/button.tsx",
            &file_index,
        );
        assert_eq!(result, Some("src/utils.ts".into()));
    }

    #[test]
    fn index_file_resolves() {
        let file_index = idx(&["src/app.ts", "src/components/index.ts"]);
        let resolver = TypeScriptResolver;
        let result = resolver.resolve(&import("./components"), "src/app.ts", &file_index);
        assert_eq!(result, Some("src/components/index.ts".into()));
    }

    #[test]
    fn exact_extension_resolves() {
        let file_index = idx(&["lib/index.js", "lib/helpers.js"]);
        let resolver = TypeScriptResolver;
        let result = resolver.resolve(&import("./helpers"), "lib/index.js", &file_index);
        assert_eq!(result, Some("lib/helpers.js".into()));
    }

    #[test]
    fn unresolvable_returns_none() {
        let file_index = idx(&["src/app.ts"]);
        let resolver = TypeScriptResolver;
        let result = resolver.resolve(&import("./nonexistent"), "src/app.ts", &file_index);
        assert_eq!(result, None);
    }

    #[test]
    fn normalize_path_resolves_parent_refs() {
        assert_eq!(normalize_path("src/components/../utils"), "src/utils");
        assert_eq!(normalize_path("a/b/c/../../d"), "a/d");
        assert_eq!(normalize_path("./foo/bar"), "foo/bar");
    }
}
