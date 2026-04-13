//! Ruby import resolver.
//!
//! Resolves `require_relative` calls (classified as `ImportKind::Relative`
//! at parse time) relative to the importing file's directory. Plain `require`
//! calls are `ImportKind::Normal` — they typically reference gems or stdlib
//! and won't match local files, so they naturally produce no edges.

use std::path::Path;

use super::{FileIndex, LanguageResolver};
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
        resolve_ruby(&import.path, importing_file, file_index)
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

    // Try with .rb extension
    let with_rb = format!("{resolved}.rb");
    if file_index.contains(&with_rb) {
        return Some(with_rb);
    }

    // Try exact path (in case the extension is already included)
    if file_index.contains(&resolved) {
        return Some(resolved);
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
}
