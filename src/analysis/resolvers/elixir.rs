//! Elixir import resolver.
//!
//! Converts CamelCase module names to snake_case file paths under `lib/`.
//! Module names matching known Elixir/Erlang stdlib or common framework
//! prefixes are skipped (Phoenix, Ecto, Plug, etc.).

use super::{FileIndex, LanguageResolver};
use crate::analysis::parser::ImportStatement;
use crate::analysis::walker::Language;

pub struct ElixirResolver;

impl LanguageResolver for ElixirResolver {
    fn resolve(
        &self,
        import: &ImportStatement,
        _importing_file: &str,
        file_index: &FileIndex,
    ) -> Option<String> {
        resolve_elixir(&import.path, file_index)
    }

    fn language(&self) -> Language {
        Language::Elixir
    }

    fn name(&self) -> &'static str {
        "elixir"
    }
}

fn resolve_elixir(module_path: &str, file_index: &FileIndex) -> Option<String> {
    if is_elixir_stdlib(module_path) {
        return None;
    }

    // Convert MyApp.Router → my_app/router
    let segments: Vec<String> = module_path
        .split('.')
        .map(|seg| camel_to_snake(seg))
        .collect();
    let rel = segments.join("/");

    // Try under lib/: lib/my_app/router.ex
    let lib_ex = format!("lib/{rel}.ex");
    if file_index.contains(&lib_ex) {
        return Some(lib_ex);
    }

    // Try .exs (test/script files)
    let lib_exs = format!("lib/{rel}.exs");
    if file_index.contains(&lib_exs) {
        return Some(lib_exs);
    }

    // Try without lib/ prefix
    let direct_ex = format!("{rel}.ex");
    if file_index.contains(&direct_ex) {
        return Some(direct_ex);
    }

    None
}

fn is_elixir_stdlib(module: &str) -> bool {
    let first = module.split('.').next().unwrap_or(module);
    matches!(
        first,
        "Absinthe"
            | "Access"
            | "Agent"
            | "Application"
            | "Atom"
            | "Base"
            | "Bitwise"
            | "Broadway"
            | "Code"
            | "Collectable"
            | "Date"
            | "DateTime"
            | "DynamicSupervisor"
            | "Ecto"
            | "Enum"
            | "Enumerable"
            | "ETS"
            | "Exception"
            | "ExUnit"
            | "File"
            | "Finch"
            | "Float"
            | "Flow"
            | "GenServer"
            | "GenStage"
            | "HTTPoison"
            | "IEx"
            | "IO"
            | "Inspect"
            | "Integer"
            | "Jason"
            | "Kernel"
            | "Keyword"
            | "List"
            | "LiveBook"
            | "LiveView"
            | "Logger"
            | "Macro"
            | "Map"
            | "MapSet"
            | "Mix"
            | "Module"
            | "NaiveDateTime"
            | "Node"
            | "Oban"
            | "Path"
            | "Phoenix"
            | "Plug"
            | "Poison"
            | "Port"
            | "Process"
            | "Protocol"
            | "Range"
            | "Regex"
            | "Registry"
            | "Stream"
            | "String"
            | "Supervisor"
            | "System"
            | "Task"
            | "Time"
            | "Tuple"
            | "URI"
    )
}

/// Convert a CamelCase module segment to snake_case.
/// HTTPServer -> http_server
/// MyModule -> my_module
/// HTTP -> http
/// XMLParser -> xml_parser
fn camel_to_snake(s: &str) -> String {
    let mut result = String::with_capacity(s.len() + 4);
    let chars: Vec<char> = s.chars().collect();
    for (i, &c) in chars.iter().enumerate() {
        if c.is_uppercase() {
            // Insert underscore before uppercase letter if:
            // - it's not the first character, AND
            // - either the previous char is lowercase (MyModule -> my_module)
            //   or the next char is lowercase (HTTPServer -> http_server)
            if i > 0 {
                let prev_is_lower = chars[i - 1].is_lowercase();
                let next_is_lower = chars
                    .get(i + 1)
                    .map(|c| c.is_lowercase())
                    .unwrap_or(false);
                if prev_is_lower || next_is_lower {
                    result.push('_');
                }
            }
            result.push(c.to_ascii_lowercase());
        } else {
            result.push(c);
        }
    }
    result
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

    // ── camel_to_snake tests ───────────────────────────────────────────────

    #[test]
    fn camel_to_snake_simple() {
        assert_eq!(camel_to_snake("MyModule"), "my_module");
    }

    #[test]
    fn camel_to_snake_acronym_start() {
        assert_eq!(camel_to_snake("HTTPServer"), "http_server");
    }

    #[test]
    fn camel_to_snake_acronym_only() {
        assert_eq!(camel_to_snake("HTTP"), "http");
    }

    #[test]
    fn camel_to_snake_mixed() {
        assert_eq!(camel_to_snake("XMLParserV2"), "xml_parser_v2");
    }

    #[test]
    fn camel_to_snake_single_word() {
        assert_eq!(camel_to_snake("User"), "user");
    }

    #[test]
    fn camel_to_snake_my_app() {
        assert_eq!(camel_to_snake("MyApp"), "my_app");
    }

    #[test]
    fn camel_to_snake_router() {
        assert_eq!(camel_to_snake("Router"), "router");
    }

    // ── stdlib skip tests ──────────────────────────────────────────────────

    #[test]
    fn stdlib_skipped() {
        let file_index = idx(&["lib/my_app.ex"]);
        assert_eq!(
            ElixirResolver.resolve(&import("Enum"), "lib/my_app.ex", &file_index),
            None
        );
        assert_eq!(
            ElixirResolver.resolve(&import("GenServer"), "lib/my_app.ex", &file_index),
            None
        );
    }

    #[test]
    fn phoenix_skipped() {
        let file_index = idx(&["lib/my_app.ex"]);
        assert_eq!(
            ElixirResolver.resolve(&import("Phoenix.Router"), "lib/my_app.ex", &file_index),
            None
        );
    }

    #[test]
    fn ecto_skipped() {
        let file_index = idx(&["lib/my_app.ex"]);
        assert_eq!(
            ElixirResolver.resolve(&import("Ecto.Schema"), "lib/my_app.ex", &file_index),
            None
        );
    }

    #[test]
    fn plug_skipped() {
        let file_index = idx(&["lib/my_app.ex"]);
        assert_eq!(
            ElixirResolver.resolve(&import("Plug.Conn"), "lib/my_app.ex", &file_index),
            None
        );
    }

    #[test]
    fn absinthe_skipped() {
        let file_index = idx(&["lib/my_app.ex"]);
        assert_eq!(
            ElixirResolver.resolve(&import("Absinthe.Schema"), "lib/my_app.ex", &file_index),
            None
        );
    }

    #[test]
    fn broadway_skipped() {
        let file_index = idx(&["lib/my_app.ex"]);
        assert_eq!(
            ElixirResolver.resolve(&import("Broadway"), "lib/my_app.ex", &file_index),
            None
        );
    }

    #[test]
    fn oban_skipped() {
        let file_index = idx(&["lib/my_app.ex"]);
        assert_eq!(
            ElixirResolver.resolve(&import("Oban.Worker"), "lib/my_app.ex", &file_index),
            None
        );
    }

    #[test]
    fn ex_unit_skipped() {
        let file_index = idx(&["lib/my_app.ex"]);
        assert_eq!(
            ElixirResolver.resolve(&import("ExUnit.Case"), "lib/my_app.ex", &file_index),
            None
        );
    }

    #[test]
    fn mix_skipped() {
        let file_index = idx(&["lib/my_app.ex"]);
        assert_eq!(
            ElixirResolver.resolve(&import("Mix.Task"), "lib/my_app.ex", &file_index),
            None
        );
    }

    #[test]
    fn jason_skipped() {
        let file_index = idx(&["lib/my_app.ex"]);
        assert_eq!(
            ElixirResolver.resolve(&import("Jason"), "lib/my_app.ex", &file_index),
            None
        );
    }

    // ── Resolution tests ───────────────────────────────────────────────────

    #[test]
    fn local_module_resolves() {
        let file_index = idx(&["lib/my_app/router.ex"]);
        let result =
            ElixirResolver.resolve(&import("MyApp.Router"), "lib/my_app.ex", &file_index);
        assert_eq!(result, Some("lib/my_app/router.ex".into()));
    }

    #[test]
    fn single_segment_local_resolves() {
        let file_index = idx(&["lib/my_app.ex"]);
        let result = ElixirResolver.resolve(&import("MyApp"), "lib/other.ex", &file_index);
        assert_eq!(result, Some("lib/my_app.ex".into()));
    }

    #[test]
    fn acronym_module_resolves() {
        let file_index = idx(&["lib/my_app/http_server.ex"]);
        let result = ElixirResolver.resolve(
            &import("MyApp.HTTPServer"),
            "lib/my_app.ex",
            &file_index,
        );
        assert_eq!(result, Some("lib/my_app/http_server.ex".into()));
    }

    #[test]
    fn xml_parser_module_resolves() {
        let file_index = idx(&["lib/my_app/xml_parser.ex"]);
        let result = ElixirResolver.resolve(
            &import("MyApp.XMLParser"),
            "lib/my_app.ex",
            &file_index,
        );
        assert_eq!(result, Some("lib/my_app/xml_parser.ex".into()));
    }

    #[test]
    fn nonexistent_returns_none() {
        let file_index = idx(&["lib/my_app.ex"]);
        assert_eq!(
            ElixirResolver.resolve(&import("Missing.Module"), "lib/my_app.ex", &file_index),
            None
        );
    }
}
