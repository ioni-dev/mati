//! Go import resolver.
//!
//! Go imports use fully-qualified module paths (`fmt`, `net/http`,
//! `github.com/user/repo/pkg`). This resolver parses `go.mod` to find
//! the module path, then strips it from import paths to resolve internal
//! imports to repo-relative `.go` files.
//!
//! Resolution algorithm:
//! 1. Walk up from the importing file to find the nearest `go.mod`
//! 2. Read the `module` declaration to get the module path
//! 3. If the import starts with the module path, strip the prefix and
//!    resolve the remainder as a directory containing `.go` files
//! 4. Stdlib imports (single-segment) and third-party imports (different
//!    module path) return `None`

use super::{FileIndex, LanguageResolver};
use crate::analysis::parser::ImportStatement;
use crate::analysis::walker::Language;

pub struct GoResolver;

impl LanguageResolver for GoResolver {
    fn resolve(
        &self,
        import: &ImportStatement,
        importing_file: &str,
        file_index: &FileIndex,
    ) -> Option<String> {
        // Single-segment imports are stdlib (fmt, os, io, etc.)
        if !import.path.contains('/') {
            return None;
        }

        // Step 1: Find the nearest go.mod file by walking up from importing_file
        let module_path = self.find_module_path(importing_file, file_index)?;

        // Step 2: Check if the import starts with the module path
        let Some(relative) = import.path.strip_prefix(&module_path) else {
            return None; // external (stdlib, third-party, or unknown module)
        };
        // strip_prefix might leave a leading "/" or be empty for the root package
        let relative = relative.trim_start_matches('/');

        // Step 3: Resolve to any non-test .go file in the target directory
        let prefix = if relative.is_empty() {
            String::new()
        } else {
            format!("{relative}/")
        };
        let candidates = file_index.files_with_prefix(&prefix);
        candidates
            .into_iter()
            .find(|f| f.ends_with(".go") && !f.ends_with("_test.go"))
            .cloned()
    }

    fn language(&self) -> Language {
        Language::Go
    }

    fn name(&self) -> &'static str {
        "go"
    }
}

impl GoResolver {
    pub fn new() -> Self {
        Self
    }

    /// Walk up from the importing file's directory looking for go.mod,
    /// then read its module declaration. Returns None if no go.mod is
    /// found or it has no module line.
    fn find_module_path(&self, importing_file: &str, file_index: &FileIndex) -> Option<String> {
        use std::path::Path;
        let mut current = Path::new(importing_file).parent();
        while let Some(dir) = current {
            let candidate = if dir.as_os_str().is_empty() {
                "go.mod".to_string()
            } else {
                format!("{}/go.mod", dir.display())
            };
            if file_index.contains(&candidate) {
                if let Some(content) = file_index.read_file(&candidate) {
                    return Self::parse_module_line(&content);
                }
            }
            current = dir.parent();
        }
        None
    }

    /// Parse the module line from a go.mod file.
    /// Example: "module github.com/acme/project" -> "github.com/acme/project"
    fn parse_module_line(content: &str) -> Option<String> {
        for line in content.lines() {
            let trimmed = line.trim();
            if let Some(rest) = trimmed.strip_prefix("module ") {
                // Strip optional trailing comment
                let rest = rest.split("//").next().unwrap_or("");
                // Strip optional quotes (Go supports `module "foo"`)
                let rest = rest.trim().trim_matches('"');
                if !rest.is_empty() {
                    return Some(rest.to_string());
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::parser::import::ImportKind;
    use tempfile::TempDir;

    fn idx(paths: &[&str]) -> FileIndex {
        FileIndex::new(paths.iter().map(|s| s.to_string()))
    }

    fn import(path: &str) -> ImportStatement {
        ImportStatement::new(path, ImportKind::Normal, 1)
    }

    /// Create a go.mod file in a TempDir and return a FileIndex with root set.
    fn setup_go_project(
        dir: &TempDir,
        module_name: &str,
        files: &[&str],
    ) -> FileIndex {
        let go_mod_content = format!("module {module_name}\n\ngo 1.21\n");
        std::fs::write(dir.path().join("go.mod"), &go_mod_content).unwrap();

        // Create all the Go files
        for file in files {
            let path = dir.path().join(file);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(&path, "package main\n").unwrap();
        }

        let mut all_files: Vec<String> = vec!["go.mod".to_string()];
        all_files.extend(files.iter().map(|s| s.to_string()));
        FileIndex::new_with_root(dir.path().to_path_buf(), all_files)
    }

    // ── Preserved original tests ───────────────────────────────────────────

    #[test]
    fn stdlib_single_segment_skipped() {
        let file_index = idx(&["main.go"]);
        assert_eq!(
            GoResolver.resolve(&import("fmt"), "main.go", &file_index),
            None
        );
    }

    #[test]
    fn external_domain_skipped_without_gomod() {
        // Without go.mod readable, all multi-segment imports return None
        let file_index = idx(&["main.go"]);
        assert_eq!(
            GoResolver.resolve(&import("github.com/user/pkg"), "main.go", &file_index),
            None
        );
    }

    #[test]
    fn nonexistent_package_returns_none() {
        let file_index = idx(&["main.go"]);
        assert_eq!(
            GoResolver.resolve(&import("internal/missing"), "main.go", &file_index),
            None
        );
    }

    // ── go.mod parsing tests ───────────────────────────────────────────────

    #[test]
    fn parses_simple_gomod_module_line() {
        let content = "module github.com/acme/project\n\ngo 1.21\n";
        assert_eq!(
            GoResolver::parse_module_line(content),
            Some("github.com/acme/project".into())
        );
    }

    #[test]
    fn parses_gomod_with_comment_on_module_line() {
        let content = "module github.com/acme/project // my project\n\ngo 1.21\n";
        assert_eq!(
            GoResolver::parse_module_line(content),
            Some("github.com/acme/project".into())
        );
    }

    #[test]
    fn parses_gomod_with_require_block() {
        let content = "module github.com/acme/project\n\ngo 1.21\n\nrequire (\n\tgithub.com/pkg/errors v0.9.1\n)\n";
        assert_eq!(
            GoResolver::parse_module_line(content),
            Some("github.com/acme/project".into())
        );
    }

    #[test]
    fn parses_gomod_with_quoted_module() {
        let content = "module \"github.com/acme/project\"\n\ngo 1.21\n";
        assert_eq!(
            GoResolver::parse_module_line(content),
            Some("github.com/acme/project".into())
        );
    }

    // ── go.mod discovery tests ─────────────────────────────────────────────

    #[test]
    fn walks_up_from_nested_file_to_find_gomod() {
        let dir = TempDir::new().unwrap();
        let file_index = setup_go_project(
            &dir,
            "github.com/acme/project",
            &["cmd/server/main.go", "internal/auth/auth.go"],
        );

        let module = GoResolver
            .find_module_path("cmd/server/main.go", &file_index);
        assert_eq!(module, Some("github.com/acme/project".into()));
    }

    // ── Resolution with go.mod ─────────────────────────────────────────────

    #[test]
    fn resolves_internal_import_with_module_path_prefix() {
        let dir = TempDir::new().unwrap();
        let file_index = setup_go_project(
            &dir,
            "github.com/acme/project",
            &["main.go", "auth/auth.go", "auth/token.go"],
        );

        let result = GoResolver.resolve(
            &import("github.com/acme/project/auth"),
            "main.go",
            &file_index,
        );
        assert!(result.is_some(), "should resolve internal import");
        let resolved = result.unwrap();
        assert!(
            resolved.starts_with("auth/") && resolved.ends_with(".go"),
            "expected auth/*.go, got: {resolved}"
        );
    }

    #[test]
    fn rejects_stdlib_import() {
        let dir = TempDir::new().unwrap();
        let file_index = setup_go_project(
            &dir,
            "github.com/acme/project",
            &["main.go"],
        );
        assert_eq!(
            GoResolver.resolve(&import("net/http"), "main.go", &file_index),
            None,
            "stdlib multi-segment imports should not resolve"
        );
    }

    #[test]
    fn rejects_third_party_import() {
        let dir = TempDir::new().unwrap();
        let file_index = setup_go_project(
            &dir,
            "github.com/acme/project",
            &["main.go"],
        );
        assert_eq!(
            GoResolver.resolve(
                &import("github.com/other/library/pkg"),
                "main.go",
                &file_index,
            ),
            None,
            "third-party imports should not resolve"
        );
    }

    #[test]
    fn skips_test_go_files_in_package_resolution() {
        let dir = TempDir::new().unwrap();
        let go_mod = "module github.com/acme/project\n\ngo 1.21\n";
        std::fs::write(dir.path().join("go.mod"), go_mod).unwrap();

        // Only _test.go files in the package
        std::fs::create_dir_all(dir.path().join("auth")).unwrap();
        std::fs::write(dir.path().join("auth/auth_test.go"), "package auth\n").unwrap();

        let file_index = FileIndex::new_with_root(
            dir.path().to_path_buf(),
            vec![
                "go.mod".to_string(),
                "main.go".to_string(),
                "auth/auth_test.go".to_string(),
            ],
        );

        let result = GoResolver.resolve(
            &import("github.com/acme/project/auth"),
            "main.go",
            &file_index,
        );
        assert_eq!(result, None, "_test.go files should be skipped");
    }

    #[test]
    fn resolves_nested_package_import() {
        let dir = TempDir::new().unwrap();
        let file_index = setup_go_project(
            &dir,
            "github.com/acme/project",
            &["main.go", "internal/auth/handler.go", "internal/db/client.go"],
        );

        let result = GoResolver.resolve(
            &import("github.com/acme/project/internal/auth"),
            "main.go",
            &file_index,
        );
        assert_eq!(result, Some("internal/auth/handler.go".into()));

        let result = GoResolver.resolve(
            &import("github.com/acme/project/internal/db"),
            "main.go",
            &file_index,
        );
        assert_eq!(result, Some("internal/db/client.go".into()));
    }

    #[test]
    fn no_gomod_returns_none_for_all_multi_segment() {
        // Without go.mod in the index, nothing can resolve
        let file_index = idx(&["main.go", "internal/auth/auth.go"]);
        assert_eq!(
            GoResolver.resolve(&import("internal/auth"), "main.go", &file_index),
            None
        );
    }
}
