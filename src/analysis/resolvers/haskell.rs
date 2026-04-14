//! Haskell import resolver.
//!
//! Converts dot-separated module names to slash-separated paths
//! (`MyLib.Utils` → `MyLib/Utils.hs`). Checks under `src/`, `app/`,
//! and the project root. Standard library modules are skipped.
//!
//! # Known limitations
//!
//! - Cabal and Stack multi-library layouts with custom `hs-source-dirs`
//!   are not detected — only `src/`, `app/`, and project root are
//!   searched
//! - Re-exported modules (`module X (module Y)`) are not followed
//! - Qualified imports (`import qualified Data.Map as Map`) still
//!   attempt resolution of `Data.Map` which is correctly skipped as
//!   stdlib, but local modules shadowing stdlib names would also be
//!   skipped
//! - Backpack module signatures (`.hsig` files) are not resolved
//! - CPP-guarded imports (`#ifdef`-controlled imports via Haskell's
//!   `{-# LANGUAGE CPP #-}`) are always counted
//! - Template Haskell splices that generate imports are invisible to
//!   tree-sitter
//!
//! These limitations mean Haskell projects using Backpack, custom
//! source directories, or heavy Template Haskell will have lower edge
//! counts. Standard Stack/Cabal projects with `src/` layout get good
//! coverage.

use super::{FileIndex, LanguageResolver};
use crate::analysis::parser::ImportStatement;
use crate::analysis::walker::Language;

pub struct HaskellResolver;

impl LanguageResolver for HaskellResolver {
    fn resolve(
        &self,
        import: &ImportStatement,
        _importing_file: &str,
        file_index: &FileIndex,
    ) -> Option<String> {
        resolve_haskell(&import.path, file_index)
    }

    fn language(&self) -> Language {
        Language::Haskell
    }

    fn name(&self) -> &'static str {
        "haskell"
    }
}

fn resolve_haskell(module_path: &str, file_index: &FileIndex) -> Option<String> {
    if is_haskell_stdlib(module_path) {
        return None;
    }

    // Convert dots to slashes: MyLib.Utils → MyLib/Utils
    let rel = module_path.replace('.', "/");

    // Try direct: MyLib/Utils.hs
    let direct = format!("{rel}.hs");
    if file_index.contains(&direct) {
        return Some(direct);
    }

    // Try under src/: src/MyLib/Utils.hs
    let src = format!("src/{rel}.hs");
    if file_index.contains(&src) {
        return Some(src);
    }

    // Try under app/: app/MyLib/Utils.hs
    let app = format!("app/{rel}.hs");
    if file_index.contains(&app) {
        return Some(app);
    }

    // Try literate Haskell: MyLib/Utils.lhs
    let lhs = format!("{rel}.lhs");
    if file_index.contains(&lhs) {
        return Some(lhs);
    }

    let src_lhs = format!("src/{rel}.lhs");
    if file_index.contains(&src_lhs) {
        return Some(src_lhs);
    }

    None
}

fn is_haskell_stdlib(module: &str) -> bool {
    let first = module.split('.').next().unwrap_or(module);
    matches!(
        first,
        "Data"
            | "Control"
            | "System"
            | "GHC"
            | "Prelude"
            | "Foreign"
            | "Numeric"
            | "Text"
            | "Debug"
            | "Unsafe"
            | "Type"
    )
}

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
    fn stdlib_skipped() {
        let file_index = idx(&["src/Main.hs"]);
        assert_eq!(
            HaskellResolver.resolve(&import("Data.List"), "src/Main.hs", &file_index),
            None
        );
        assert_eq!(
            HaskellResolver.resolve(&import("Control.Monad"), "src/Main.hs", &file_index),
            None
        );
        assert_eq!(
            HaskellResolver.resolve(&import("Prelude"), "src/Main.hs", &file_index),
            None
        );
    }

    #[test]
    fn local_module_resolves_under_src() {
        let file_index = idx(&["src/Main.hs", "src/MyLib/Utils.hs"]);
        let result = HaskellResolver.resolve(&import("MyLib.Utils"), "src/Main.hs", &file_index);
        assert_eq!(result, Some("src/MyLib/Utils.hs".into()));
    }

    #[test]
    fn local_module_resolves_at_root() {
        let file_index = idx(&["Main.hs", "Lib/Helper.hs"]);
        let result = HaskellResolver.resolve(&import("Lib.Helper"), "Main.hs", &file_index);
        assert_eq!(result, Some("Lib/Helper.hs".into()));
    }

    #[test]
    fn literate_haskell_resolves() {
        let file_index = idx(&["src/Main.hs", "src/MyLib/Doc.lhs"]);
        let result = HaskellResolver.resolve(&import("MyLib.Doc"), "src/Main.hs", &file_index);
        assert_eq!(result, Some("src/MyLib/Doc.lhs".into()));
    }

    #[test]
    fn nonexistent_returns_none() {
        let file_index = idx(&["src/Main.hs"]);
        assert_eq!(
            HaskellResolver.resolve(&import("Missing.Module"), "src/Main.hs", &file_index),
            None
        );
    }
}
