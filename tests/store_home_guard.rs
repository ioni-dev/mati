use std::fs;
use std::path::{Path, PathBuf};

use tree_sitter::{Node, Parser};

struct Function {
    name: String,
    body: String,
}

fn store_open_without_isolation(path: &Path, source_text: &str) -> Option<String> {
    // Production code under `src/cli` opens stores legitimately, so only the
    // test module is in scope there. Integration test files are all test code.
    let source = if path.starts_with("src/cli") {
        test_module_source(source_text)?
    } else if path.starts_with("tests") {
        source_text.to_string()
    } else {
        return None;
    };

    let store_names = store_type_names(source_text);
    let functions = find_functions(&source);
    let mut visiting = vec![false; functions.len()];
    for (index, function) in functions.iter().enumerate() {
        if first_store_open(&function.body, &store_names).is_some()
            && !function_isolated(index, &functions, &store_names, &mut visiting)
        {
            return Some(function.name.clone());
        }
    }
    None
}

fn parse_rust(source: &str) -> tree_sitter::Tree {
    let language: tree_sitter::Language = tree_sitter_rust::LANGUAGE.into();
    let mut parser = Parser::new();
    parser
        .set_language(&language)
        .expect("load Rust grammar for store-home guard");
    parser
        .parse(source.as_bytes(), None)
        .expect("parse Rust source for store-home guard")
}

fn find_functions(source: &str) -> Vec<Function> {
    let tree = parse_rust(source);
    let mut functions = Vec::new();
    collect_functions(tree.root_node(), source, &mut functions);
    functions
}

fn store_type_names(source: &str) -> Vec<String> {
    let tree = parse_rust(source);
    let mut names = vec!["Store".to_string()];
    collect_store_type_names(tree.root_node(), source, &mut names);
    names.sort();
    names.dedup();
    names
}

fn collect_store_type_names(node: Node<'_>, source: &str, names: &mut Vec<String>) {
    if node.kind() == "use_declaration" {
        let declaration = node.utf8_text(source.as_bytes()).unwrap();
        if let Some((path, alias)) = declaration
            .trim()
            .trim_start_matches("use ")
            .trim_end_matches(';')
            .rsplit_once(" as ")
        {
            if path.ends_with("::Store") {
                names.push(alias.to_string());
            }
        }
    }

    if node.kind() == "type_item"
        && node
            .child_by_field_name("type")
            .and_then(|type_node| type_node.utf8_text(source.as_bytes()).ok())
            .is_some_and(|type_name| type_name.trim().ends_with("Store"))
    {
        if let Some(name) = node
            .child_by_field_name("name")
            .and_then(|name| name.utf8_text(source.as_bytes()).ok())
        {
            names.push(name.to_string());
        }
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_store_type_names(child, source, names);
    }
}

/// Body of `mod tests`, or `None` when the file has none. Found through the
/// syntax tree rather than a text split, so indentation and attribute
/// placement cannot hide it.
fn test_module_source(source: &str) -> Option<String> {
    let tree = parse_rust(source);
    find_test_module(tree.root_node(), source)
}

fn find_test_module(node: Node<'_>, source: &str) -> Option<String> {
    let is_tests_mod = node.kind() == "mod_item"
        && node
            .child_by_field_name("name")
            .and_then(|n| n.utf8_text(source.as_bytes()).ok())
            == Some("tests");
    if is_tests_mod {
        return node
            .child_by_field_name("body")
            .and_then(|body| body.utf8_text(source.as_bytes()).ok())
            .map(str::to_string);
    }

    let mut cursor = node.walk();
    let found = node
        .named_children(&mut cursor)
        .find_map(|child| find_test_module(child, source));
    found
}

fn collect_functions(node: Node<'_>, source: &str, functions: &mut Vec<Function>) {
    if node.kind() == "function_item" {
        let Some(name) = node.child_by_field_name("name") else {
            return;
        };
        let Some(body) = node.child_by_field_name("body") else {
            return;
        };
        functions.push(Function {
            name: name.utf8_text(source.as_bytes()).unwrap().to_string(),
            body: body.utf8_text(source.as_bytes()).unwrap().to_string(),
        });
        return;
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_functions(child, source, functions);
    }
}

fn first_store_open(body: &str, store_names: &[String]) -> Option<usize> {
    let direct = store_names
        .iter()
        .flat_map(|name| {
            [
                format!("{name}::open("),
                format!("{name}::open_and_rebuild("),
            ]
        })
        .filter_map(|needle| body.find(&needle))
        .min();
    direct.or_else(|| first_store_function_pointer(body, store_names))
}

fn first_store_function_pointer(body: &str, store_names: &[String]) -> Option<usize> {
    fn find_binding(node: Node<'_>, body: &str, store_names: &[String]) -> Option<usize> {
        if node.kind() == "let_declaration" {
            let pattern = node
                .child_by_field_name("pattern")
                .and_then(|pattern| pattern.utf8_text(body.as_bytes()).ok())
                .map(str::trim);
            let value = node
                .child_by_field_name("value")
                .and_then(|value| value.utf8_text(body.as_bytes()).ok())
                .map(str::trim);
            if let (Some(pattern), Some(value)) = (pattern, value) {
                let is_store_function = store_names.iter().any(|name| {
                    value == format!("{name}::open") || value == format!("{name}::open_and_rebuild")
                });
                if is_store_function && body[node.end_byte()..].contains(&format!("{pattern}(")) {
                    return Some(node.start_byte());
                }
            }
        }

        let mut cursor = node.walk();
        let found = node
            .named_children(&mut cursor)
            .find_map(|child| find_binding(child, body, store_names));
        found
    }

    let tree = parse_rust(body);
    find_binding(tree.root_node(), body, store_names)
}

fn function_isolated(
    index: usize,
    functions: &[Function],
    store_names: &[String],
    visiting: &mut [bool],
) -> bool {
    if visiting[index] {
        return false;
    }
    visiting[index] = true;

    let function = &functions[index];
    let store_position = first_store_open(&function.body, store_names);
    let isolation_position = ["common::isolate_mati_home", "ensure_test_home"]
        .iter()
        .filter_map(|needle| function.body.find(needle))
        .min();
    let direct = isolation_position
        .map(|position| store_position.is_none_or(|store| position < store))
        .unwrap_or(false);
    let via_helper = functions.iter().enumerate().any(|(helper_index, helper)| {
        let Some(call_position) = function.body.find(&format!("{}(", helper.name)) else {
            return false;
        };
        helper_index != index
            && store_position.is_none_or(|store| call_position < store)
            && function_isolated(helper_index, functions, store_names, visiting)
    });

    visiting[index] = false;
    direct || via_helper
}

fn rust_files_under(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory).expect("read guard directory") {
            let path = entry.expect("read guard entry").path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
                files.push(path);
            }
        }
    }
    files
}

#[test]
fn store_opening_tests_must_select_a_scratch_home() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));

    for directory in [root.join("tests"), root.join("src/cli")] {
        for path in rust_files_under(&directory) {
            if path == root.join("tests/store_home_guard.rs") {
                continue;
            }
            let source = fs::read_to_string(&path).expect("read Rust source");
            let relative = path.strip_prefix(root).expect("guard path under repo");
            if let Some(function) = store_open_without_isolation(relative, &source) {
                panic!(
                    "{} opens a store in {function} without isolating MATI_HOME",
                    path.display()
                );
            }
        }
    }
}

#[test]
fn source_guard_accepts_an_isolated_store_test() {
    let source = r#"
        #[tokio::test]
        async fn opens_store() {
            common::isolate_mati_home();
            let _ = Store::open(path).await;
        }
    "#;
    assert_eq!(
        store_open_without_isolation(Path::new("tests/synthetic.rs"), source),
        None
    );
}

#[test]
fn source_guard_rejects_a_store_test_without_isolation() {
    let source = r#"
        #[tokio::test]
        async fn opens_store() {
            let _ = Store::open(path).await;
        }
    "#;
    assert_eq!(
        store_open_without_isolation(Path::new("tests/synthetic.rs"), source),
        Some("opens_store".to_string())
    );
}

#[test]
fn source_guard_rejects_init_shape_when_a_second_test_forgets_isolation() {
    let source = r#"
        #[cfg(test)]
        mod tests {
            fn scratch_tree() {
                crate::cli::ensure_test_home();
            }

            #[tokio::test]
            async fn existing_test() {
                let dir = scratch_tree();
                let _ = Store::open(dir.path()).await;
            }

            #[tokio::test]
            async fn new_test_without_isolation() {
                let _ = Store::open(path).await;
            }
        }
    "#;
    assert_eq!(
        store_open_without_isolation(Path::new("src/cli/init.rs"), source),
        Some("new_test_without_isolation".to_string())
    );
}

#[test]
fn source_guard_rejects_open_and_rebuild_without_isolation() {
    let source = r#"
        #[tokio::test]
        async fn rebuilds_store() {
            let _ = Store::open_and_rebuild(path).await;
        }
    "#;
    assert_eq!(
        store_open_without_isolation(Path::new("tests/synthetic.rs"), source),
        Some("rebuilds_store".to_string())
    );
}

#[test]
fn source_guard_rejects_store_alias_without_isolation() {
    let source = r#"
        use mati_core::store::Store as S;

        #[tokio::test]
        async fn opens_store() {
            let _ = S::open(path).await;
        }
    "#;
    assert_eq!(
        store_open_without_isolation(Path::new("tests/synthetic.rs"), source),
        Some("opens_store".to_string())
    );
}

#[test]
fn source_guard_rejects_store_type_alias_without_isolation() {
    let source = r#"
        type Db = Store;

        #[tokio::test]
        async fn opens_store() {
            let _ = Db::open(path).await;
        }
    "#;
    assert_eq!(
        store_open_without_isolation(Path::new("tests/synthetic.rs"), source),
        Some("opens_store".to_string())
    );
}

#[test]
fn source_guard_rejects_store_function_pointer_without_isolation() {
    let source = r#"
        #[tokio::test]
        async fn opens_store() {
            let f = Store::open;
            let _ = f(path).await;
        }
    "#;
    assert_eq!(
        store_open_without_isolation(Path::new("tests/synthetic.rs"), source),
        Some("opens_store".to_string())
    );
}

#[tokio::test]
async fn store_open_without_mati_home_fails_in_a_test_process() {
    let previous_home = std::env::var_os("MATI_HOME");
    std::env::remove_var("MATI_HOME");

    let result = mati_core::store::Store::open(Path::new(env!("CARGO_MANIFEST_DIR"))).await;
    let error = result
        .err()
        .expect("Store::open must reject an unset MATI_HOME in tests")
        .to_string();

    if let Some(home) = previous_home {
        std::env::set_var("MATI_HOME", home);
    }

    assert!(error.contains("MATI_HOME"), "unexpected error: {error}");
}

#[test]
fn mati_subprocess_without_mati_home_fails_in_a_test_process() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_mati"))
        .arg("status")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .env_remove("MATI_HOME")
        .output()
        .expect("run mati without MATI_HOME");
    let output_text = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(
        !output.status.success(),
        "mati status unexpectedly succeeded"
    );
    assert!(
        output_text.contains("MATI_HOME"),
        "missing MATI_HOME failure in output: {output_text}"
    );
}
