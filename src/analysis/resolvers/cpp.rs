//! C++ import resolver.
//!
//! Same strategy as the C resolver but also tries C++ header extensions
//! (`.hpp`, `.hxx`, `.hh`). Angle-bracket includes are classified as
//! `External` at parse time.
//!
//! # Known limitations
//!
//! - No `-I` include path support — only checks relative to the importing
//!   file, project root, and `include/` / `src/` directories
//! - Template-heavy headers (Boost, Eigen, STL implementations) produce
//!   no edges since they use angle-bracket includes
//! - Module imports (`import <module>;` in C++20) are not recognized —
//!   only preprocessor `#include` directives are parsed
//! - Extensionless includes (`#include "mylib"`) try `.hpp`, `.hxx`,
//!   `.hh`, `.h` in order — but not `.H` or other uncommon extensions
//! - Conditional includes and macro-based includes are not resolved
//!   (same as the C resolver)
//! - PCH (precompiled header) references are not detected
//!
//! These limitations mean C++ projects relying heavily on template
//! libraries or C++20 modules will have lower edge counts. Projects
//! using quoted includes with standard extensions get good coverage.

use std::path::Path;

use super::{FileIndex, LanguageResolver};
use crate::analysis::parser::ImportStatement;
use crate::analysis::walker::Language;

pub struct CppResolver;

impl LanguageResolver for CppResolver {
    fn resolve(
        &self,
        import: &ImportStatement,
        importing_file: &str,
        file_index: &FileIndex,
    ) -> Option<String> {
        resolve_cpp_include(&import.path, importing_file, file_index)
    }

    fn language(&self) -> Language {
        Language::Cpp
    }

    fn name(&self) -> &'static str {
        "cpp"
    }
}

fn resolve_cpp_include(
    include_path: &str,
    importing_file: &str,
    file_index: &FileIndex,
) -> Option<String> {
    let parent = Path::new(importing_file)
        .parent()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();

    // Try relative to importing file's directory
    let relative = if parent.is_empty() {
        include_path.to_string()
    } else {
        format!("{parent}/{include_path}")
    };
    if file_index.contains(&relative) {
        return Some(relative);
    }

    // Try from project root
    if file_index.contains(include_path) {
        return Some(include_path.to_string());
    }

    // Try under common include directories
    for prefix in &["include", "src"] {
        let candidate = format!("{prefix}/{include_path}");
        if file_index.contains(&candidate) {
            return Some(candidate);
        }
    }

    // If the include has no extension, try C++ header extensions
    if Path::new(include_path).extension().is_none() {
        for ext in &[".hpp", ".hxx", ".hh", ".h"] {
            let with_ext = format!("{include_path}{ext}");
            // Try relative
            let rel = if parent.is_empty() {
                with_ext.clone()
            } else {
                format!("{parent}/{with_ext}")
            };
            if file_index.contains(&rel) {
                return Some(rel);
            }
            // Try root
            if file_index.contains(&with_ext) {
                return Some(with_ext);
            }
        }
    }

    None
}

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
    fn relative_include_resolves() {
        let file_index = idx(&["src/main.cpp", "src/utils.hpp"]);
        let result = CppResolver.resolve(&import("utils.hpp"), "src/main.cpp", &file_index);
        assert_eq!(result, Some("src/utils.hpp".into()));
    }

    #[test]
    fn extensionless_include_tries_hpp() {
        let file_index = idx(&["src/main.cpp", "src/utils.hpp"]);
        let result = CppResolver.resolve(&import("utils"), "src/main.cpp", &file_index);
        assert_eq!(result, Some("src/utils.hpp".into()));
    }

    #[test]
    fn include_dir_resolves() {
        let file_index = idx(&["src/main.cpp", "include/types.h"]);
        let result = CppResolver.resolve(&import("types.h"), "src/main.cpp", &file_index);
        assert_eq!(result, Some("include/types.h".into()));
    }

    #[test]
    fn nonexistent_returns_none() {
        let file_index = idx(&["src/main.cpp"]);
        assert_eq!(CppResolver.resolve(&import("missing.h"), "src/main.cpp", &file_index), None);
    }
}
