//! Rust import resolver.
//!
//! Resolves `crate::`, `self::`, and `super::` module paths against the
//! standard `src/` layout. Assumes a single crate root at `src/` — workspace
//! `crates/*/src/` and non-standard roots are not resolved (acceptable Layer 0
//! limitation, tracked for Phase 3).

use std::path::Path;

use super::{FileIndex, LanguageResolver};
use crate::analysis::parser::ImportStatement;
use crate::analysis::walker::Language;

/// Rust import resolver for `crate::`, `self::`, and `super::` paths.
pub struct RustResolver;

impl LanguageResolver for RustResolver {
    fn resolve(
        &self,
        import: &ImportStatement,
        importing_file: &str,
        file_index: &FileIndex,
    ) -> Option<String> {
        resolve_rust(&import.path, importing_file, file_index)
    }

    fn language(&self) -> Language {
        Language::Rust
    }

    fn name(&self) -> &'static str {
        "rust"
    }
}

/// Core resolution logic, extracted for direct testing.
fn resolve_rust(import_path: &str, importing_file: &str, file_index: &FileIndex) -> Option<String> {
    // Strip `as` alias and `::*` wildcard suffix for path resolution.
    let clean = import_path
        .split(" as ")
        .next()
        .unwrap_or(import_path)
        .trim()
        .trim_end_matches("::*");

    let current_module = rust_module_segments(importing_file)?;

    let segments = if let Some(path) = clean.strip_prefix("crate::") {
        parse_rust_segments(path)
    } else if let Some(path) = clean.strip_prefix("self::") {
        current_module
            .iter()
            .cloned()
            .chain(parse_rust_segments(path))
            .collect()
    } else if clean.starts_with("super::") {
        let mut remaining = clean;
        let mut up = 0usize;
        while let Some(rest) = remaining.strip_prefix("super::") {
            remaining = rest;
            up += 1;
        }
        if up > current_module.len() {
            return None;
        }
        current_module[..current_module.len() - up]
            .iter()
            .cloned()
            .chain(parse_rust_segments(remaining))
            .collect()
    } else {
        return None;
    };

    if segments.is_empty() {
        return None;
    }

    let fs_path = format!("src/{}", segments.join("/"));

    // Try direct file: src/foo/bar.rs
    let direct = format!("{fs_path}.rs");
    if file_index.contains(&direct) {
        return Some(direct);
    }

    // Try module directory: src/foo/bar/mod.rs
    let mod_rs = format!("{fs_path}/mod.rs");
    if file_index.contains(&mod_rs) {
        return Some(mod_rs);
    }

    None
}

fn parse_rust_segments(path: &str) -> Vec<String> {
    path.split("::")
        .map(str::trim)
        .filter(|segment| !segment.is_empty() && *segment != "self")
        .map(|segment| segment.to_string())
        .collect()
}

fn rust_module_segments(importing_file: &str) -> Option<Vec<String>> {
    let rel = importing_file.strip_prefix("src/")?;

    if rel == "lib.rs" || rel == "main.rs" {
        return Some(Vec::new());
    }

    if let Some(parent) = rel.strip_suffix("/mod.rs") {
        return Some(
            parent
                .split('/')
                .filter(|segment| !segment.is_empty())
                .map(|segment| segment.to_string())
                .collect(),
        );
    }

    let path = Path::new(rel);
    let stem = path.file_stem()?.to_str()?;
    let mut segments: Vec<String> = path
        .parent()
        .into_iter()
        .flat_map(|parent| parent.iter())
        .filter_map(|segment| segment.to_str())
        .filter(|segment| !segment.is_empty())
        .map(|segment| segment.to_string())
        .collect();
    segments.push(stem.to_string());
    Some(segments)
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
        ImportStatement::new(path, ImportKind::Normal, 1)
    }

    #[test]
    fn crate_import_resolves_to_file() {
        let file_index = idx(&["src/lib.rs", "src/utils.rs"]);
        let resolver = RustResolver;
        let result = resolver.resolve(&import("crate::utils"), "src/lib.rs", &file_index);
        assert_eq!(result, Some("src/utils.rs".into()));
    }

    #[test]
    fn crate_import_resolves_to_mod_rs() {
        let file_index = idx(&["src/lib.rs", "src/store/mod.rs"]);
        let resolver = RustResolver;
        let result = resolver.resolve(&import("crate::store"), "src/lib.rs", &file_index);
        assert_eq!(result, Some("src/store/mod.rs".into()));
    }

    #[test]
    fn self_import_resolves() {
        let file_index = idx(&["src/store/mod.rs", "src/store/helpers.rs"]);
        let resolver = RustResolver;
        let result =
            resolver.resolve(&import("self::helpers"), "src/store/mod.rs", &file_index);
        assert_eq!(result, Some("src/store/helpers.rs".into()));
    }

    #[test]
    fn super_import_resolves() {
        let file_index = idx(&["src/store/db.rs", "src/store/helpers.rs"]);
        let resolver = RustResolver;
        let result =
            resolver.resolve(&import("super::helpers"), "src/store/db.rs", &file_index);
        assert_eq!(result, Some("src/store/helpers.rs".into()));
    }

    #[test]
    fn nested_crate_import() {
        let file_index = idx(&["src/main.rs", "src/store/db.rs"]);
        let resolver = RustResolver;
        let result = resolver.resolve(&import("crate::store::db"), "src/main.rs", &file_index);
        assert_eq!(result, Some("src/store/db.rs".into()));
    }

    #[test]
    fn unresolvable_returns_none() {
        let file_index = idx(&["src/lib.rs"]);
        let resolver = RustResolver;
        let result =
            resolver.resolve(&import("crate::nonexistent"), "src/lib.rs", &file_index);
        assert_eq!(result, None);
    }

    #[test]
    fn wildcard_stripped_before_resolution() {
        let file_index = idx(&["src/lib.rs", "src/prelude.rs"]);
        let resolver = RustResolver;
        let imp = ImportStatement::new("crate::prelude::*", ImportKind::Wildcard, 1);
        let result = resolver.resolve(&imp, "src/lib.rs", &file_index);
        assert_eq!(result, Some("src/prelude.rs".into()));
    }

    #[test]
    fn alias_stripped_before_resolution() {
        let file_index = idx(&["src/lib.rs", "src/utils.rs"]);
        let resolver = RustResolver;
        let imp = ImportStatement::new("crate::utils as u", ImportKind::Normal, 1);
        let result = resolver.resolve(&imp, "src/lib.rs", &file_index);
        assert_eq!(result, Some("src/utils.rs".into()));
    }
}
