//! Java import resolver.
//!
//! Converts dotted qualified names (`com.example.MyClass`) to filesystem paths
//! (`com/example/MyClass.java`). Checks Maven/Gradle source roots
//! (`src/main/java/`, `src/test/java/`). Handles inner class and static member
//! imports by progressively stripping trailing segments until a `.java` file
//! matches.

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

/// Maven/Gradle source roots to search, in priority order.
const JAVA_SOURCE_ROOTS: &[&str] = &["", "src/main/java/", "src/test/java/"];

fn resolve_java(import_path: &str, file_index: &FileIndex) -> Option<String> {
    // Skip standard library and known external deps
    if is_java_stdlib(import_path) {
        return None;
    }

    // Strip wildcard suffix for directory-level imports
    let clean = import_path.trim_end_matches(".*");

    // Convert dots to slashes: com.example.Foo → com/example/Foo
    let rel = clean.replace('.', "/");

    // Try direct match against each source root
    for root in JAVA_SOURCE_ROOTS {
        let candidate = format!("{root}{rel}.java");
        if file_index.contains(&candidate) {
            return Some(candidate);
        }
    }

    // Inner class / static member stripping: progressively drop the last
    // segment and retry. E.g. org/jsoup/nodes/Document/OutputSettings
    // → try org/jsoup/nodes/Document.java (inner class OutputSettings).
    // Also handles static imports like Parser.NamespaceHtml → Parser.java.
    let mut segments: Vec<&str> = rel.split('/').collect();
    while segments.len() > 2 {
        segments.pop();
        let parent = segments.join("/");
        for root in JAVA_SOURCE_ROOTS {
            let candidate = format!("{root}{parent}.java");
            if file_index.contains(&candidate) {
                return Some(candidate);
            }
        }
    }

    None
}

fn is_java_stdlib(path: &str) -> bool {
    // JDK / Android platform
    path.starts_with("java.")
        || path.starts_with("javax.")
        || path.starts_with("jakarta.")
        || path.starts_with("sun.")
        || path.starts_with("com.sun.")
        || path.starts_with("jdk.")
        || path.starts_with("android.")
        // XML / W3C (shipped with JDK but separate namespace)
        || path.starts_with("org.w3c.")
        || path.starts_with("org.xml.")
        // Common test frameworks
        || path.starts_with("org.junit.")
        || path.starts_with("org.hamcrest.")
        || path.starts_with("org.mockito.")
        || path.starts_with("org.assertj.")
        // Common third-party libs (never project-local)
        || path.starts_with("org.jspecify.")
        || path.starts_with("org.slf4j.")
        || path.starts_with("org.apache.")
        || path.starts_with("org.springframework.")
        || path.starts_with("org.eclipse.")
        || path.starts_with("com.google.")
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

    // ── Inner class / static member stripping ─────────────────────────────

    #[test]
    fn inner_class_import_resolves_to_outer_file() {
        let file_index = idx(&["src/main/java/org/jsoup/nodes/Document.java"]);
        let result = JavaResolver.resolve(
            &import("org.jsoup.nodes.Document.OutputSettings"),
            "Foo.java",
            &file_index,
        );
        assert_eq!(
            result,
            Some("src/main/java/org/jsoup/nodes/Document.java".into())
        );
    }

    #[test]
    fn static_member_import_resolves_to_class_file() {
        let file_index = idx(&["src/main/java/org/jsoup/parser/Parser.java"]);
        let result = JavaResolver.resolve(
            &import("org.jsoup.parser.Parser.NamespaceHtml"),
            "Foo.java",
            &file_index,
        );
        assert_eq!(
            result,
            Some("src/main/java/org/jsoup/parser/Parser.java".into())
        );
    }

    #[test]
    fn deeply_nested_inner_class_resolves() {
        // Connection.Method.HEAD — three levels: file is Connection.java
        let file_index = idx(&["src/main/java/org/jsoup/Connection.java"]);
        let result = JavaResolver.resolve(
            &import("org.jsoup.Connection.Method.HEAD"),
            "Foo.java",
            &file_index,
        );
        assert_eq!(
            result,
            Some("src/main/java/org/jsoup/Connection.java".into())
        );
    }

    // ── Test source root ──────────────────────────────────────────────────

    #[test]
    fn test_source_root_resolves() {
        let file_index = idx(&["src/test/java/org/jsoup/TextUtil.java"]);
        let result = JavaResolver.resolve(
            &import("org.jsoup.TextUtil"),
            "src/test/java/org/jsoup/FooTest.java",
            &file_index,
        );
        assert_eq!(result, Some("src/test/java/org/jsoup/TextUtil.java".into()));
    }

    // ── External dep classification ───────────────────────────────────────

    #[test]
    fn org_junit_is_external() {
        let file_index = idx(&["Main.java"]);
        assert_eq!(
            JavaResolver.resolve(
                &import("org.junit.jupiter.api.Test"),
                "Main.java",
                &file_index
            ),
            None
        );
    }

    #[test]
    fn org_jspecify_is_external() {
        let file_index = idx(&["Main.java"]);
        assert_eq!(
            JavaResolver.resolve(
                &import("org.jspecify.annotations.Nullable"),
                "Main.java",
                &file_index
            ),
            None
        );
    }
}
