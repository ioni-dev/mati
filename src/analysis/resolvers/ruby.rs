//! Ruby import resolver.
//!
//! Resolves `require_relative` calls (classified as `ImportKind::Relative`
//! at parse time) relative to the importing file's directory. Plain `require`
//! calls (`ImportKind::Normal`) also try resolution against `lib/` — the
//! standard Ruby gem convention where `require 'sinatra/base'` maps to
//! `lib/sinatra/base.rb`.

use std::path::Path;

use super::{FileIndex, LanguageResolver};
use crate::analysis::parser::import::ImportKind;
use crate::analysis::parser::ImportStatement;
use crate::analysis::walker::Language;

pub struct RubyResolver;

impl LanguageResolver for RubyResolver {
    fn resolve(
        &self,
        import: &ImportStatement,
        importing_file: &str,
        file_index: &FileIndex,
    ) -> Option<String> {
        resolve_ruby(&import.path, importing_file, file_index, import.kind)
    }

    fn language(&self) -> Language {
        Language::Ruby
    }

    fn name(&self) -> &'static str {
        "ruby"
    }
}

fn resolve_ruby(
    require_path: &str,
    importing_file: &str,
    file_index: &FileIndex,
    kind: ImportKind,
) -> Option<String> {
    let parent = Path::new(importing_file)
        .parent()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();

    let resolved = if parent.is_empty() {
        require_path.to_string()
    } else {
        format!("{parent}/{require_path}")
    };

    // Try with .rb extension (relative to importing file)
    let with_rb = format!("{resolved}.rb");
    if file_index.contains(&with_rb) {
        return Some(with_rb);
    }

    // Try exact path (in case the extension is already included)
    if file_index.contains(&resolved) {
        return Some(resolved);
    }

    // For Normal requires (gem-style), also try lib/ prefix.
    // Standard Ruby gem layout: require 'sinatra/base' → lib/sinatra/base.rb
    if kind == ImportKind::Normal {
        let lib_rb = format!("lib/{require_path}.rb");
        if file_index.contains(&lib_rb) {
            return Some(lib_rb);
        }
        let lib_exact = format!("lib/{require_path}");
        if file_index.contains(&lib_exact) {
            return Some(lib_exact);
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

    fn import_relative(path: &str) -> ImportStatement {
        ImportStatement::new(path, ImportKind::Relative, 1)
    }

    fn import_normal(path: &str) -> ImportStatement {
        ImportStatement::new(path, ImportKind::Normal, 1)
    }

    #[test]
    fn require_relative_resolves() {
        let file_index = idx(&["lib/app.rb", "lib/helpers.rb"]);
        let result = RubyResolver.resolve(&import_relative("helpers"), "lib/app.rb", &file_index);
        assert_eq!(result, Some("lib/helpers.rb".into()));
    }

    #[test]
    fn require_relative_nested() {
        let file_index = idx(&["lib/app.rb", "lib/utils/format.rb"]);
        let result =
            RubyResolver.resolve(&import_relative("utils/format"), "lib/app.rb", &file_index);
        assert_eq!(result, Some("lib/utils/format.rb".into()));
    }

    #[test]
    fn require_normal_no_match() {
        // Plain require for a gem — won't match any local file
        let file_index = idx(&["lib/app.rb"]);
        let result = RubyResolver.resolve(&import_normal("json"), "lib/app.rb", &file_index);
        assert_eq!(result, None);
    }

    #[test]
    fn nonexistent_returns_none() {
        let file_index = idx(&["lib/app.rb"]);
        assert_eq!(
            RubyResolver.resolve(&import_relative("missing"), "lib/app.rb", &file_index),
            None
        );
    }

    // ── lib/ fallback for Normal requires ──────────────────────────────

    #[test]
    fn require_with_lib_prefix_resolves() {
        let file_index = idx(&["lib/sinatra/base.rb", "lib/sinatra.rb"]);
        let result = RubyResolver.resolve(
            &import_normal("sinatra/base"),
            "lib/sinatra.rb",
            &file_index,
        );
        assert_eq!(result, Some("lib/sinatra/base.rb".into()));
    }

    #[test]
    fn require_relative_unchanged() {
        // require_relative still resolves relative to importing file, not via lib/.
        let file_index = idx(&["test/test_helper.rb", "test/helpers.rb"]);
        let result = RubyResolver.resolve(
            &import_relative("helpers"),
            "test/test_helper.rb",
            &file_index,
        );
        assert_eq!(result, Some("test/helpers.rb".into()));
    }

    #[test]
    fn external_gem_require_returns_none() {
        // require 'json' (stdlib gem) — no lib/json.rb in the project.
        let file_index = idx(&["lib/app.rb"]);
        let result = RubyResolver.resolve(&import_normal("json"), "lib/app.rb", &file_index);
        assert_eq!(result, None);
    }

    #[test]
    fn nested_lib_path_resolves() {
        let file_index = idx(&[
            "lib/sinatra.rb",
            "lib/sinatra/main.rb",
            "lib/sinatra/base.rb",
        ]);
        let result = RubyResolver.resolve(
            &import_normal("sinatra/main"),
            "lib/sinatra.rb",
            &file_index,
        );
        assert_eq!(result, Some("lib/sinatra/main.rb".into()));
    }
}
