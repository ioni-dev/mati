//! C import resolver.
//!
//! Resolves quoted includes (`#include "myheader.h"`) relative to the
//! importing file's directory, then the project root. Angle-bracket
//! includes (`#include <stdio.h>`) are classified as `External` at parse
//! time and never reach this resolver.
//!
//! # Known limitations
//!
//! - No `-I` include path support — only checks relative to the importing
//!   file, project root, and `include/` / `src/` directories
//! - Conditional includes (`#ifdef`-guarded `#include`) are always counted
//!   regardless of which branch is active at compile time
//! - `#include` directives using macros (`#include HEADER_NAME`) are not
//!   resolved — the macro is opaque to tree-sitter
//! - Symlinked header directories are not followed beyond the walker's
//!   default traversal
//! - Multi-level relative paths (`../../common/types.h`) resolve correctly
//!   but only if the target is within the walked repo root
//!
//! These limitations mean edge counts for C projects with complex build
//! systems (CMake, autotools) will be lower than the actual dependency
//! graph. Projects using a flat `include/` layout will get better coverage.

use std::path::Path;

use super::{FileIndex, LanguageResolver};
use crate::analysis::parser::ImportStatement;
use crate::analysis::walker::Language;

pub struct CResolver;

impl LanguageResolver for CResolver {
    fn resolve(
        &self,
        import: &ImportStatement,
        importing_file: &str,
        file_index: &FileIndex,
    ) -> Option<String> {
        resolve_c_include(&import.path, importing_file, file_index)
    }

    fn language(&self) -> Language {
        Language::C
    }

    fn name(&self) -> &'static str {
        "c"
    }
}

fn resolve_c_include(
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
        let file_index = idx(&["src/main.c", "src/utils.h"]);
        let result = CResolver.resolve(&import("utils.h"), "src/main.c", &file_index);
        assert_eq!(result, Some("src/utils.h".into()));
    }

    #[test]
    fn root_include_resolves() {
        let file_index = idx(&["src/main.c", "config.h"]);
        let result = CResolver.resolve(&import("config.h"), "src/main.c", &file_index);
        assert_eq!(result, Some("config.h".into()));
    }

    #[test]
    fn include_dir_resolves() {
        let file_index = idx(&["src/main.c", "include/types.h"]);
        let result = CResolver.resolve(&import("types.h"), "src/main.c", &file_index);
        assert_eq!(result, Some("include/types.h".into()));
    }

    #[test]
    fn nonexistent_returns_none() {
        let file_index = idx(&["src/main.c"]);
        assert_eq!(
            CResolver.resolve(&import("missing.h"), "src/main.c", &file_index),
            None
        );
    }
}
