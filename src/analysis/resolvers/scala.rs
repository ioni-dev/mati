//! Scala import resolver.
//!
//! Resolves local Scala imports by converting dotted package paths to
//! filesystem paths, tried against the repo root and common source roots
//! (`src/main/scala/`). Reuses `dotted_to_path` from the Java resolver.
//!
//! # Known limitations
//!
//! - Package objects (`package.scala` files) are not resolved
//! - Selective imports `import com.acme.{Foo, Bar}` resolve to the
//!   package prefix, not individual members
//! - Akka framework classes are treated as external; local Akka
//!   subclasses will not produce edges
//! - sbt multi-project layouts beyond standard `src/main/scala/` are
//!   not detected
//! - Implicit imports from the `scala` package are not modeled
//! - Companion objects and type aliases are not distinguished from
//!   class files
//!
//! These limitations mean blast radius ranking and import-based
//! propagation will be less accurate for Scala projects with
//! non-standard build layouts. Edge counts on real Scala projects will
//! be lower than the parser's imports list would suggest.

use super::java::dotted_to_path;
use super::{FileIndex, LanguageResolver};
use crate::analysis::parser::ImportStatement;
use crate::analysis::walker::Language;

pub struct ScalaResolver;

impl LanguageResolver for ScalaResolver {
    fn resolve(
        &self,
        import: &ImportStatement,
        _importing_file: &str,
        file_index: &FileIndex,
    ) -> Option<String> {
        resolve_scala(&import.path, file_index)
    }

    fn language(&self) -> Language {
        Language::Scala
    }

    fn name(&self) -> &'static str {
        "scala"
    }
}

fn resolve_scala(import_path: &str, file_index: &FileIndex) -> Option<String> {
    if is_scala_stdlib(import_path) {
        return None;
    }

    // Strip Scala wildcard `._` and selective import braces
    let clean = import_path
        .split('{')
        .next()
        .unwrap_or(import_path)
        .trim_end_matches("._")
        .trim_end_matches('.');

    let rel = dotted_to_path(clean);

    // Try direct file: com/example/Foo.scala
    let direct = format!("{rel}.scala");
    if file_index.contains(&direct) {
        return Some(direct);
    }

    // Try sbt/Maven layout: src/main/scala/com/example/Foo.scala
    let sbt = format!("src/main/scala/{rel}.scala");
    if file_index.contains(&sbt) {
        return Some(sbt);
    }

    None
}

fn is_scala_stdlib(path: &str) -> bool {
    path.starts_with("scala.")
        || path.starts_with("java.")
        || path.starts_with("javax.")
        || path.starts_with("akka.")
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
        let file_index = idx(&["Main.scala"]);
        assert_eq!(
            ScalaResolver.resolve(
                &import("scala.collection.mutable"),
                "Main.scala",
                &file_index
            ),
            None
        );
    }

    #[test]
    fn local_class_resolves() {
        let file_index = idx(&["com/example/Utils.scala", "Main.scala"]);
        let result = ScalaResolver.resolve(&import("com.example.Utils"), "Main.scala", &file_index);
        assert_eq!(result, Some("com/example/Utils.scala".into()));
    }

    #[test]
    fn sbt_layout_resolves() {
        let file_index = idx(&["src/main/scala/com/example/Utils.scala", "Main.scala"]);
        let result = ScalaResolver.resolve(&import("com.example.Utils"), "Main.scala", &file_index);
        assert_eq!(
            result,
            Some("src/main/scala/com/example/Utils.scala".into())
        );
    }

    #[test]
    fn wildcard_stripped() {
        let file_index = idx(&["com/example.scala", "Main.scala"]);
        let result = ScalaResolver.resolve(&import("com.example._"), "Main.scala", &file_index);
        assert_eq!(result, Some("com/example.scala".into()));
    }

    #[test]
    fn nonexistent_returns_none() {
        let file_index = idx(&["Main.scala"]);
        assert_eq!(
            ScalaResolver.resolve(&import("com.example.Missing"), "Main.scala", &file_index),
            None
        );
    }
}
