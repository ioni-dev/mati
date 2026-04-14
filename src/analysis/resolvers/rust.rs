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

    // Handle bare keyword paths left after wildcard stripping:
    // `super::*` → `super`, `self::*` → `self`, `crate::*` → `crate`.
    let segments = if clean == "crate" {
        // `use crate::*` — re-export of entire crate root, no single file target.
        return None;
    } else if clean == "self" {
        // `use self::*` — re-export of current module directory.
        current_module.clone()
    } else if clean == "super" {
        // `use super::*` — re-export of parent module.
        if current_module.is_empty() {
            return None;
        }
        current_module[..current_module.len() - 1].to_vec()
    } else if let Some(path) = clean.strip_prefix("crate::") {
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

    // Prefix-stripping resolution loop: try the full path first, then
    // progressively drop the last segment (which may be a symbol name like
    // `FileRecord` rather than a module). This correctly resolves paths like
    // `crate::store::record::FileRecord` → `src/store/record.rs` and
    // brace-grouped imports like `crate::store::{A, B}` → `src/store/mod.rs`.
    let mut depth = segments.len();
    while depth > 0 {
        let fs_path = format!("src/{}", segments[..depth].join("/"));

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

        depth -= 1;
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

    // ── Prefix-stripping resolution tests ────────────────────────────────────

    #[test]
    fn crate_import_with_trailing_symbol_resolves_to_file() {
        // crate::store::record::FileRecord → src/store/record.rs
        let file_index = idx(&["src/lib.rs", "src/store/record.rs"]);
        let result = resolve_rust("crate::store::record::FileRecord", "src/lib.rs", &file_index);
        assert_eq!(result, Some("src/store/record.rs".into()));
    }

    #[test]
    fn crate_import_with_trailing_symbol_resolves_to_mod_rs() {
        // crate::analysis::parser::Language → src/analysis/parser/mod.rs
        let file_index = idx(&["src/lib.rs", "src/analysis/parser/mod.rs"]);
        let result =
            resolve_rust("crate::analysis::parser::Language", "src/lib.rs", &file_index);
        assert_eq!(result, Some("src/analysis/parser/mod.rs".into()));
    }

    #[test]
    fn crate_import_deep_symbol_chain_strips_multiple() {
        // crate::error::MatiError::NotFound → src/error.rs (strips 2 segments)
        let file_index = idx(&["src/lib.rs", "src/error.rs"]);
        let result =
            resolve_rust("crate::error::MatiError::NotFound", "src/lib.rs", &file_index);
        assert_eq!(result, Some("src/error.rs".into()));
    }

    #[test]
    fn brace_group_import_resolves_to_parent_module() {
        // crate::store::{FileRecord, GotchaRecord} → src/store/mod.rs
        // Tree-sitter captures the full text including braces
        let file_index = idx(&["src/lib.rs", "src/store/mod.rs"]);
        let result = resolve_rust(
            "crate::store::{FileRecord, GotchaRecord}",
            "src/lib.rs",
            &file_index,
        );
        assert_eq!(result, Some("src/store/mod.rs".into()));
    }

    #[test]
    fn super_import_with_trailing_symbol() {
        // super::helpers::format_score from src/cli/review.rs → src/cli/helpers.rs
        let file_index = idx(&["src/cli/review.rs", "src/cli/helpers.rs"]);
        let result =
            resolve_rust("super::helpers::format_score", "src/cli/review.rs", &file_index);
        assert_eq!(result, Some("src/cli/helpers.rs".into()));
    }

    #[test]
    fn self_import_with_trailing_symbol() {
        // self::types::MyType from src/store/mod.rs → src/store/types.rs
        let file_index = idx(&["src/store/mod.rs", "src/store/types.rs"]);
        let result =
            resolve_rust("self::types::MyType", "src/store/mod.rs", &file_index);
        assert_eq!(result, Some("src/store/types.rs".into()));
    }

    #[test]
    fn crate_direct_module_still_resolves() {
        // crate::util → src/util.rs (no trailing symbol, existing behavior preserved)
        let file_index = idx(&["src/lib.rs", "src/util.rs"]);
        let result = resolve_rust("crate::util", "src/lib.rs", &file_index);
        assert_eq!(result, Some("src/util.rs".into()));
    }

    #[test]
    fn crate_direct_module_prefers_file_over_mod_rs() {
        // crate::util where src/util.rs exists → src/util.rs (not src/util/mod.rs)
        let file_index = idx(&["src/lib.rs", "src/util.rs", "src/util/mod.rs"]);
        let result = resolve_rust("crate::util", "src/lib.rs", &file_index);
        assert_eq!(result, Some("src/util.rs".into()));
    }

    #[test]
    fn crate_direct_module_falls_back_to_mod_rs() {
        // crate::util where only src/util/mod.rs exists → src/util/mod.rs
        let file_index = idx(&["src/lib.rs", "src/util/mod.rs"]);
        let result = resolve_rust("crate::util", "src/lib.rs", &file_index);
        assert_eq!(result, Some("src/util/mod.rs".into()));
    }

    #[test]
    fn nonexistent_path_returns_none() {
        let file_index = idx(&["src/lib.rs"]);
        let result =
            resolve_rust("crate::nonexistent::thing", "src/lib.rs", &file_index);
        assert_eq!(result, None);
    }

    #[test]
    fn crate_root_alone_returns_none() {
        // "crate" or "crate::" should not resolve to src.rs or src/mod.rs
        let file_index = idx(&["src/lib.rs", "src/mod.rs"]);
        let result = resolve_rust("crate::", "src/lib.rs", &file_index);
        assert_eq!(result, None);
    }

    #[test]
    fn prefix_stripping_stops_before_crate_root() {
        // crate::x::y::z where nothing matches — should not resolve to src itself
        let file_index = idx(&["src/lib.rs", "src.rs"]);
        let result = resolve_rust("crate::x::y::z", "src/lib.rs", &file_index);
        assert_eq!(result, None);
    }

    #[test]
    fn existing_exact_match_preferred_over_stripped() {
        // crate::store::record where src/store/record.rs exists should NOT strip
        // to src/store.rs even if that also exists
        let file_index = idx(&[
            "src/lib.rs",
            "src/store.rs",
            "src/store/record.rs",
        ]);
        let result = resolve_rust("crate::store::record", "src/lib.rs", &file_index);
        assert_eq!(result, Some("src/store/record.rs".into()));
    }

    // ── Wildcard bare-keyword resolution ─────────────────────────────────

    #[test]
    fn super_wildcard_resolves_to_parent_module() {
        // use super::* from src/cli/review.rs → resolves to src/cli/mod.rs
        let file_index = idx(&["src/cli/review.rs", "src/cli/mod.rs"]);
        let imp = ImportStatement::new("super::*", ImportKind::Wildcard, 1);
        let result = RustResolver.resolve(&imp, "src/cli/review.rs", &file_index);
        assert_eq!(result, Some("src/cli/mod.rs".into()));
    }

    #[test]
    fn self_wildcard_resolves_to_current_module() {
        // use self::* from src/store/mod.rs → resolves to src/store/mod.rs itself
        let file_index = idx(&["src/store/mod.rs", "src/store/db.rs"]);
        let imp = ImportStatement::new("self::*", ImportKind::Wildcard, 1);
        let result = RustResolver.resolve(&imp, "src/store/mod.rs", &file_index);
        assert_eq!(result, Some("src/store/mod.rs".into()));
    }

    #[test]
    fn crate_wildcard_returns_none() {
        // use crate::* → no single file target for crate root
        let file_index = idx(&["src/lib.rs", "src/main.rs"]);
        let imp = ImportStatement::new("crate::*", ImportKind::Wildcard, 1);
        let result = RustResolver.resolve(&imp, "src/lib.rs", &file_index);
        assert_eq!(result, None);
    }
}
