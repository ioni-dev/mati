//! Scala import resolver.
//!
//! Resolves local Scala imports by converting dotted package paths to
//! filesystem paths, tried against the repo root, `src/main/scala/`,
//! and dynamically-discovered sbt source roots (for multi-project
//! layouts like `subproject/shared/src/main/scala/`).
//! Reuses `dotted_to_path` from the Java resolver.
//!
//! # Known limitations
//!
//! - Package objects (`package.scala` files) are not resolved
//! - Selective imports `import com.acme.{Foo, Bar}` resolve to the
//!   package prefix, not individual members
//! - Akka framework classes are treated as external; local Akka
//!   subclasses will not produce edges
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

    // Try discovered source roots (multi-project sbt layouts).
    // E.g. "zio-json/shared/src/main/scala/" + "zio/json/JsonDecoder.scala"
    for root in file_index.scala_source_roots() {
        let candidate = format!("{root}{rel}.scala");
        if file_index.contains(&candidate) {
            return Some(candidate);
        }
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

    // ── Multi-project sbt source root tests ────────────────────────────

    #[test]
    fn simple_src_main_scala_resolves() {
        // Flat layout already covered by sbt_layout_resolves above,
        // but verify the hardcoded path still works.
        let file_index = idx(&[
            "src/main/scala/foo/Bar.scala",
            "src/main/scala/foo/Main.scala",
        ]);
        let result = ScalaResolver.resolve(&import("foo.Bar"), "Main.scala", &file_index);
        assert_eq!(result, Some("src/main/scala/foo/Bar.scala".into()));
    }

    #[test]
    fn multi_project_subproject_resolves() {
        let mut file_index = idx(&[
            "myproject/src/main/scala/foo/Bar.scala",
            "myproject/src/main/scala/foo/Main.scala",
        ]);
        file_index.set_scala_source_roots(vec!["myproject/src/main/scala/".to_string()]);
        let result = ScalaResolver.resolve(&import("foo.Bar"), "Main.scala", &file_index);
        assert_eq!(
            result,
            Some("myproject/src/main/scala/foo/Bar.scala".into())
        );
    }

    #[test]
    fn shared_directory_resolves() {
        // The zio-json pattern: subproject/shared/src/main/scala/
        let mut file_index = idx(&[
            "zio-json/shared/src/main/scala/zio/json/JsonDecoder.scala",
            "zio-json/shared/src/main/scala/zio/json/JsonEncoder.scala",
        ]);
        file_index.set_scala_source_roots(vec!["zio-json/shared/src/main/scala/".to_string()]);
        let result = ScalaResolver.resolve(
            &import("zio.json.JsonDecoder"),
            "zio-json/shared/src/main/scala/zio/json/JsonEncoder.scala",
            &file_index,
        );
        assert_eq!(
            result,
            Some("zio-json/shared/src/main/scala/zio/json/JsonDecoder.scala".into())
        );
    }

    #[test]
    fn scala_version_specific_root_resolves() {
        let mut file_index = idx(&[
            "myproject/src/main/scala-2.13/foo/Compat.scala",
            "myproject/src/main/scala/foo/Main.scala",
        ]);
        file_index.set_scala_source_roots(vec![
            "myproject/src/main/scala-2.13/".to_string(),
            "myproject/src/main/scala/".to_string(),
        ]);
        let result = ScalaResolver.resolve(&import("foo.Compat"), "Main.scala", &file_index);
        assert_eq!(
            result,
            Some("myproject/src/main/scala-2.13/foo/Compat.scala".into())
        );
    }

    #[test]
    fn test_source_root_resolves() {
        let mut file_index = idx(&[
            "myproject/src/test/scala/foo/BarSpec.scala",
            "myproject/src/main/scala/foo/Bar.scala",
        ]);
        file_index.set_scala_source_roots(vec![
            "myproject/src/main/scala/".to_string(),
            "myproject/src/test/scala/".to_string(),
        ]);
        let result = ScalaResolver.resolve(&import("foo.BarSpec"), "Main.scala", &file_index);
        assert_eq!(
            result,
            Some("myproject/src/test/scala/foo/BarSpec.scala".into())
        );
    }

    #[test]
    fn cross_source_root_imports_resolve() {
        // Integration: imports from one source root resolve targets in another.
        let mut file_index = idx(&[
            "core/src/main/scala/com/acme/Model.scala",
            "web/src/main/scala/com/acme/Controller.scala",
        ]);
        file_index.set_scala_source_roots(vec![
            "core/src/main/scala/".to_string(),
            "web/src/main/scala/".to_string(),
        ]);
        // Controller imports Model across sub-projects.
        let result = ScalaResolver.resolve(
            &import("com.acme.Model"),
            "web/src/main/scala/com/acme/Controller.scala",
            &file_index,
        );
        assert_eq!(
            result,
            Some("core/src/main/scala/com/acme/Model.scala".into())
        );
    }
}
