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

    let functions = find_functions(&source);
    let mut visiting = vec![false; functions.len()];
    for (index, function) in functions.iter().enumerate() {
        if first_store_open(&function.body).is_some()
            && !function_isolated(index, &functions, &mut visiting)
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

fn first_store_open(body: &str) -> Option<usize> {
    ["Store::open(", "Store::open_and_rebuild("]
        .iter()
        .filter_map(|needle| body.find(needle))
        .min()
}

fn function_isolated(index: usize, functions: &[Function], visiting: &mut [bool]) -> bool {
    if visiting[index] {
        return false;
    }
    visiting[index] = true;

    let function = &functions[index];
    let store_position = first_store_open(&function.body);
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
            && function_isolated(helper_index, functions, visiting)
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
