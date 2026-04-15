//! Haskell import resolver.
//!
//! Converts dot-separated module names to slash-separated paths
//! (`MyLib.Utils` → `MyLib/Utils.hs`). Checks under `src/`, `app/`,
//! and the project root. Standard library modules are skipped using an
//! explicit allowlist of GHC boot-package modules (base, containers,
//! bytestring, text, array, etc.).
//!
//! # Known limitations
//!
//! - Cabal and Stack multi-library layouts with custom `hs-source-dirs`
//!   are not detected — only `src/`, `app/`, and project root are
//!   searched
//! - Re-exported modules (`module X (module Y)`) are not followed
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

/// Check whether a Haskell module path belongs to the GHC standard library.
///
/// Uses an explicit allowlist of modules from GHC boot packages (base,
/// containers, bytestring, text, array, time, filepath, directory,
/// process, deepseq, pretty, parsec, stm, transformers, mtl).
///
/// Top-level namespaces that are exclusively stdlib-owned (`GHC`,
/// `Prelude`, `Foreign`, `Numeric`, `Debug`, `Unsafe`, `Type`) match
/// on the first segment alone.  For shared namespaces (`Data`,
/// `Control`, `System`, `Text`) we check the second segment against a
/// curated list so that third-party modules like `Data.Aeson` are NOT
/// classified as stdlib.
fn is_haskell_stdlib(module: &str) -> bool {
    let mut parts = module.splitn(3, '.');
    let first = parts.next().unwrap_or("");

    // Namespaces that are entirely GHC-owned.
    match first {
        "GHC" | "Prelude" | "Foreign" | "Numeric" | "Debug" | "Unsafe" | "Type" => return true,
        "Data" | "Control" | "System" | "Text" => {}
        _ => return false,
    }

    // For shared namespaces, match second segment against known stdlib modules.
    let second = match parts.next() {
        Some(s) => s,
        // Bare "Data" / "Control" etc. — not a real module import.
        None => return false,
    };

    match first {
        "Data" => matches!(
            second,
            // ── base ──
            "Bifoldable"
                | "Bifunctor"
                | "Bitraversable"
                | "Bits"
                | "Bool"
                | "Char"
                | "Coerce"
                | "Complex"
                | "Data"
                | "Dynamic"
                | "Either"
                | "Eq"
                | "Fixed"
                | "Foldable"
                | "Function"
                | "Functor"
                | "IORef"
                | "Int"
                | "Ix"
                | "Kind"
                | "List"
                | "Maybe"
                | "Monoid"
                | "Ord"
                | "Proxy"
                | "Ratio"
                | "STRef"
                | "Semigroup"
                | "String"
                | "Traversable"
                | "Tuple"
                | "Type"
                | "Typeable"
                | "Unique"
                | "Void"
                | "Version"
                | "Word"
                // ── containers ──
                | "Map"
                | "Set"
                | "IntMap"
                | "IntSet"
                | "Sequence"
                | "Tree"
                | "Graph"
                // ── bytestring ──
                | "ByteString"
                // ── text ──
                | "Text"
                // ── array ──
                | "Array"
                // ── time ──
                | "Time"
        ),
        "Control" => matches!(
            second,
            // ── base ──
            "Applicative"
                | "Arrow"
                | "Category"
                | "Concurrent"
                | "Exception"
                | "Monad"
                // ── deepseq ──
                | "DeepSeq"
        ),
        "System" => matches!(
            second,
            // ── base ──
            "CPUTime"
                | "Console"
                | "Environment"
                | "Exit"
                | "IO"
                | "Info"
                | "Mem"
                | "Posix"
                | "Timeout"
                // ── filepath ──
                | "FilePath"
                // ── directory ──
                | "Directory"
                // ── process ──
                | "Process"
                // ── random ──
                | "Random"
        ),
        "Text" => matches!(
            second,
            // ── base ──
            "ParserCombinators" | "Printf" | "Read" | "Show"
            // ── pretty ──
            | "PrettyPrint"
            // ── parsec ──
            | "Parsec"
            // ── regex-base ──
            | "Regex"
        ),
        _ => false,
    }
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

    // ── stdlib allowlist tests ─────────────────────────────────────────

    #[test]
    fn data_list_is_stdlib() {
        assert!(is_haskell_stdlib("Data.List"));
        assert!(is_haskell_stdlib("Data.List.NonEmpty"));
    }

    #[test]
    fn data_map_is_stdlib() {
        assert!(is_haskell_stdlib("Data.Map"));
        assert!(is_haskell_stdlib("Data.Map.Strict"));
    }

    #[test]
    fn data_aeson_is_not_stdlib() {
        assert!(!is_haskell_stdlib("Data.Aeson"));
        assert!(!is_haskell_stdlib("Data.Aeson.Types"));
    }

    #[test]
    fn data_aeson_types_is_not_stdlib() {
        // Covers sub-module paths too.
        assert!(!is_haskell_stdlib("Data.Aeson.Types.Internal"));
        assert!(!is_haskell_stdlib("Data.Aeson.Key"));
    }

    #[test]
    fn control_monad_is_stdlib() {
        assert!(is_haskell_stdlib("Control.Monad"));
        assert!(is_haskell_stdlib("Control.Monad.IO.Class"));
        assert!(is_haskell_stdlib("Control.Exception"));
    }

    #[test]
    fn user_module_is_not_stdlib() {
        assert!(!is_haskell_stdlib("MyApp.Foo"));
        assert!(!is_haskell_stdlib("Lib.Internal.Utils"));
        assert!(!is_haskell_stdlib("Network.HTTP"));
    }
}
