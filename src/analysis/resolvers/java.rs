//! Java import resolver.
//!
//! Converts dotted qualified names (`com.example.MyClass`) to filesystem paths
//! (`com/example/MyClass.java`). Also checks `src/main/java/` prefix for
//! Maven/Gradle project layouts.

use super::{FileIndex, LanguageResolver};
use crate::analysis::parser::ImportStatement;
use crate::analysis::walker::Language;

pub struct JavaResolver;

impl LanguageResolver for JavaResolver {
    fn resolve(
        &self,
        import: &ImportStatement,
        _importing_file: &str,
        file_index: &FileIndex,
    ) -> Option<String> {
        resolve_java(&import.path, file_index)
    }

    fn language(&self) -> Language {
        Language::Java
    }

    fn name(&self) -> &'static str {
        "java"
    }
}

fn resolve_java(import_path: &str, file_index: &FileIndex) -> Option<String> {
    // Skip standard library
    if is_java_stdlib(import_path) {
        return None;
    }

    // Strip wildcard suffix for directory-level imports
    let clean = import_path.trim_end_matches(".*");

    // Convert dots to slashes: com.example.Foo → com/example/Foo
    let rel = clean.replace('.', "/");

    // Try direct file: com/example/Foo.java
    let direct = format!("{rel}.java");
    if file_index.contains(&direct) {
        return Some(direct);
    }

    // Try Maven/Gradle layout: src/main/java/com/example/Foo.java
    let maven = format!("src/main/java/{rel}.java");
    if file_index.contains(&maven) {
        return Some(maven);
    }

    None
}

fn is_java_stdlib(path: &str) -> bool {
    path.starts_with("java.")
        || path.starts_with("javax.")
        || path.starts_with("sun.")
        || path.starts_with("com.sun.")
        || path.starts_with("jdk.")
}

/// Convert a dotted qualified name to a slash-separated path.
/// Reusable by Scala resolver.
pub(super) fn dotted_to_path(dotted: &str) -> String {
    dotted.replace('.', "/")
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
        let file_index = idx(&["Main.java"]);
        assert_eq!(
            JavaResolver.resolve(&import("java.util.List"), "Main.java", &file_index),
            None
        );
        assert_eq!(
            JavaResolver.resolve(&import("javax.swing.JFrame"), "Main.java", &file_index),
            None
        );
    }

    #[test]
    fn local_class_resolves() {
        let file_index = idx(&["com/example/Foo.java", "Main.java"]);
        let result = JavaResolver.resolve(&import("com.example.Foo"), "Main.java", &file_index);
        assert_eq!(result, Some("com/example/Foo.java".into()));
    }

    #[test]
    fn maven_layout_resolves() {
        let file_index = idx(&["src/main/java/com/example/Foo.java", "Main.java"]);
        let result = JavaResolver.resolve(&import("com.example.Foo"), "Main.java", &file_index);
        assert_eq!(result, Some("src/main/java/com/example/Foo.java".into()));
    }

    #[test]
    fn wildcard_import_resolves_to_directory_file() {
        let file_index = idx(&["com/example/Utils.java", "Main.java"]);
        // Wildcard stripped → tries com/example.java which doesn't exist
        let result = JavaResolver.resolve(&import("com.example.*"), "Main.java", &file_index);
        assert_eq!(result, None); // No directory-level resolution yet
    }

    #[test]
    fn nonexistent_returns_none() {
        let file_index = idx(&["Main.java"]);
        assert_eq!(
            JavaResolver.resolve(&import("com.example.Missing"), "Main.java", &file_index),
            None
        );
    }
}
