//! Ruby import resolver.
//!
//! Resolves three categories of Ruby imports:
//!
//! 1. **`require_relative`** (`ImportKind::Relative`) — resolves relative to the
//!    importing file's directory.
//! 2. **`require` / `require_dependency`** (`ImportKind::Normal`) — tries resolution
//!    relative to the importing file, then against every discovered `lib/` root
//!    (monorepo-aware: `lib/`, `core/lib/`, `api/lib/`, etc.).
//! 3. **Class inheritance / module inclusion** (`ImportKind::Inherits` /
//!    `ImportKind::Includes`) — resolved via Zeitwerk path conventions. A constant
//!    like `Foo::Bar` is converted to `foo/bar.rb` and searched across all
//!    discovered autoload roots (`app/models/`, `app/controllers/`, `lib/`, etc.).

use std::path::Path;

use super::{camel_to_snake, FileIndex, LanguageResolver};
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
        match import.kind {
            ImportKind::Inherits | ImportKind::Includes => {
                resolve_zeitwerk(&import.path, file_index)
            }
            ImportKind::Relative => resolve_relative(&import.path, importing_file, file_index),
            ImportKind::Normal => resolve_normal(&import.path, importing_file, file_index),
            _ => None,
        }
    }

    fn language(&self) -> Language {
        Language::Ruby
    }

    fn name(&self) -> &'static str {
        "ruby"
    }
}

// ── require_relative resolution ─────────────────────────────────────────────

fn resolve_relative(
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

    let with_rb = format!("{resolved}.rb");
    if file_index.contains(&with_rb) {
        return Some(with_rb);
    }
    if file_index.contains(&resolved) {
        return Some(resolved);
    }
    None
}

// ── require / require_dependency resolution ─────────────────────────────────

fn resolve_normal(
    require_path: &str,
    importing_file: &str,
    file_index: &FileIndex,
) -> Option<String> {
    // First try relative to importing file (same as require_relative behavior).
    if let Some(found) = resolve_relative(require_path, importing_file, file_index) {
        return Some(found);
    }

    // Try every discovered lib/ root (monorepo-aware).
    // E.g. require 'spree/core' → core/lib/spree/core.rb
    let lib_roots = file_index.ruby_lib_roots();
    for root in lib_roots {
        let lib_rb = format!("{root}{require_path}.rb");
        if file_index.contains(&lib_rb) {
            return Some(lib_rb);
        }
        let lib_exact = format!("{root}{require_path}");
        if file_index.contains(&lib_exact) {
            return Some(lib_exact);
        }
    }

    // Fallback: try bare lib/ even if not discovered (non-Ruby-dominant repos).
    if lib_roots.is_empty() || !lib_roots.contains(&"lib/".to_string()) {
        let lib_rb = format!("lib/{require_path}.rb");
        if file_index.contains(&lib_rb) {
            return Some(lib_rb);
        }
    }

    // Try autoload roots too — require_dependency 'app/services/foo' or
    // require 'discourse' might resolve against an autoload root.
    for root in file_index.ruby_autoload_roots() {
        let ar_rb = format!("{root}{require_path}.rb");
        if file_index.contains(&ar_rb) {
            return Some(ar_rb);
        }
    }

    None
}

// ── Zeitwerk constant-to-path resolution ────────────────────────────────────

/// Resolve a Ruby constant name (e.g. `"Foo::Bar::Baz"`) to a repo-relative
/// file path using Zeitwerk autoload conventions.
///
/// Zeitwerk convention: `Foo::Bar::Baz` lives at `<root>/foo/bar/baz.rb` under
/// any autoload root. Also checks the nested-folder variant
/// `<root>/foo/bar/baz/baz.rb` (less common but valid).
fn resolve_zeitwerk(constant: &str, file_index: &FileIndex) -> Option<String> {
    let parts: Vec<String> = constant.split("::").map(|p| camel_to_snake(p)).collect();
    let path_suffix = parts.join("/");

    // Search autoload roots first (app/models/, app/controllers/, etc.),
    // then lib/ roots.
    let all_roots = file_index
        .ruby_autoload_roots()
        .iter()
        .chain(file_index.ruby_lib_roots().iter());

    for root in all_roots {
        // Direct: <root>/foo/bar/baz.rb
        let direct_path = format!("{root}{path_suffix}.rb");
        if file_index.contains(&direct_path) {
            return Some(direct_path);
        }

        // Nested-folder: <root>/foo/bar/baz/baz.rb
        if let Some(last) = parts.last() {
            let nested_path = format!("{root}{path_suffix}/{last}.rb");
            if file_index.contains(&nested_path) {
                return Some(nested_path);
            }
        }
    }

    // For single-segment constants (e.g. "ApplicationController"), also try
    // a direct match without the autoload root prefix — the file might be at
    // the repo root or in a non-standard location.
    if !constant.contains("::") {
        let snake = camel_to_snake(constant);
        let direct = format!("{snake}.rb");
        if file_index.contains(&direct) {
            return Some(direct);
        }
    }

    None
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::parser::import::ImportKind;

    fn idx(paths: &[&str]) -> FileIndex {
        FileIndex::new(paths.iter().map(|s| s.to_string()))
    }

    fn idx_with_roots(paths: &[&str], autoload_roots: &[&str], lib_roots: &[&str]) -> FileIndex {
        let mut fi = FileIndex::new(paths.iter().map(|s| s.to_string()));
        fi.set_ruby_autoload_roots(autoload_roots.iter().map(|s| s.to_string()).collect());
        fi.set_ruby_lib_roots(lib_roots.iter().map(|s| s.to_string()).collect());
        fi
    }

    fn import_relative(path: &str) -> ImportStatement {
        ImportStatement::new(path, ImportKind::Relative, 1)
    }

    fn import_normal(path: &str) -> ImportStatement {
        ImportStatement::new(path, ImportKind::Normal, 1)
    }

    fn import_inherits(path: &str) -> ImportStatement {
        ImportStatement::new(path, ImportKind::Inherits, 1)
    }

    fn import_includes(path: &str) -> ImportStatement {
        ImportStatement::new(path, ImportKind::Includes, 1)
    }

    // ── Existing tests (require_relative / require) ───────────────────────

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

    // ── Zeitwerk resolution (Inherits + Includes) ─────────────────────────

    #[test]
    fn simple_class_inheritance_resolves_to_app_models() {
        let fi = idx_with_roots(
            &["app/models/user.rb", "app/models/application_record.rb"],
            &["app/models/"],
            &[],
        );
        let result = RubyResolver.resolve(
            &import_inherits("ApplicationRecord"),
            "app/models/user.rb",
            &fi,
        );
        assert_eq!(result, Some("app/models/application_record.rb".into()));
    }

    #[test]
    fn controller_inheritance_resolves() {
        let fi = idx_with_roots(
            &[
                "app/controllers/foos_controller.rb",
                "app/controllers/application_controller.rb",
            ],
            &["app/controllers/"],
            &[],
        );
        let result = RubyResolver.resolve(
            &import_inherits("ApplicationController"),
            "app/controllers/foos_controller.rb",
            &fi,
        );
        assert_eq!(
            result,
            Some("app/controllers/application_controller.rb".into())
        );
    }

    #[test]
    fn concern_inclusion_resolves_via_concerns_dir() {
        let fi = idx_with_roots(
            &["app/models/post.rb", "app/models/concerns/searchable.rb"],
            &["app/models/", "app/models/concerns/"],
            &[],
        );
        let result =
            RubyResolver.resolve(&import_includes("Searchable"), "app/models/post.rb", &fi);
        assert_eq!(result, Some("app/models/concerns/searchable.rb".into()));
    }

    #[test]
    fn namespaced_constant_resolves_via_nested_path() {
        let fi = idx_with_roots(
            &["app/models/my_app/bar.rb", "app/models/foo.rb"],
            &["app/models/"],
            &[],
        );
        let result = RubyResolver.resolve(&import_inherits("MyApp::Bar"), "app/models/foo.rb", &fi);
        assert_eq!(result, Some("app/models/my_app/bar.rb".into()));
    }

    #[test]
    fn monorepo_autoload_roots_detected() {
        // Solidus-style monorepo: core/app/models/spree/order.rb
        let fi = idx_with_roots(
            &[
                "core/app/models/spree/order.rb",
                "core/app/models/spree/product.rb",
                "core/app/models/spree/base.rb",
            ],
            &["core/app/models/"],
            &[],
        );
        let result = RubyResolver.resolve(
            &import_inherits("Spree::Base"),
            "core/app/models/spree/order.rb",
            &fi,
        );
        assert_eq!(result, Some("core/app/models/spree/base.rb".into()));
    }

    // ── P2: Monorepo lib/ fallback ────────────────────────────────────────

    #[test]
    fn monorepo_lib_require_resolves() {
        let fi = idx_with_roots(
            &["core/lib/spree/core.rb", "api/lib/spree/api.rb"],
            &[],
            &["core/lib/", "api/lib/"],
        );
        let result = RubyResolver.resolve(&import_normal("spree/core"), "core/lib/spree.rb", &fi);
        assert_eq!(result, Some("core/lib/spree/core.rb".into()));
    }

    #[test]
    fn repo_root_lib_still_works() {
        // Regression guard: sinatra-style require still resolves via lib/
        let fi = idx_with_roots(&["lib/sinatra/base.rb", "lib/sinatra.rb"], &[], &["lib/"]);
        let result = RubyResolver.resolve(&import_normal("sinatra/base"), "lib/sinatra.rb", &fi);
        assert_eq!(result, Some("lib/sinatra/base.rb".into()));
    }

    // ── P3: require_dependency resolves via autoload roots ────────────────

    #[test]
    fn require_dependency_resolves_via_autoload_roots() {
        let fi = idx_with_roots(&["app/services/foo.rb"], &["app/services/"], &[]);
        let result = RubyResolver.resolve(
            &import_normal("foo"),
            "app/controllers/bar_controller.rb",
            &fi,
        );
        assert_eq!(result, Some("app/services/foo.rb".into()));
    }
}
