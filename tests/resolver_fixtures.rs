//! Integration tests that exercise the resolver against real multi-file fixtures.
//!
//! These tests parse actual source files from `tests/fixtures/resolver/` and
//! verify that cross-file import resolution produces the correct edges.

use mati_core::analysis::parser::{parse_file, ImportKind};
use mati_core::analysis::resolvers::{FileIndex, ResolverRegistry};
use mati_core::analysis::walker::{Language, WalkedFile, Walker};

fn fixture_path(lang: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/resolver")
        .join(lang)
}

fn walk_fixture(lang: &str) -> Vec<WalkedFile> {
    Walker::new(fixture_path(lang)).walk().unwrap()
}

// ── Rust fixtures ───────────────────────────────────────────────────────────

#[test]
fn rust_fixture_resolves_crate_imports() {
    let files = walk_fixture("rust");
    let file_index = FileIndex::new(files.iter().map(|f| f.rel_path.clone()));
    let registry = ResolverRegistry::new();

    // Parse src/lib.rs — should have `use crate::store` and `use crate::store::helpers`
    let lib_file = files.iter().find(|f| f.rel_path == "src/lib.rs").unwrap();
    let analysis = parse_file(lib_file).unwrap();

    let resolved: Vec<String> = analysis
        .imports
        .iter()
        .filter_map(|imp| registry.resolve(imp, &lib_file.rel_path, Language::Rust, &file_index))
        .collect();

    assert!(
        resolved.contains(&"src/store/mod.rs".to_string()),
        "crate::store should resolve to src/store/mod.rs, got: {resolved:?}"
    );
}

#[test]
fn rust_fixture_resolves_self_import() {
    let files = walk_fixture("rust");
    let file_index = FileIndex::new(files.iter().map(|f| f.rel_path.clone()));
    let registry = ResolverRegistry::new();

    let mod_file = files
        .iter()
        .find(|f| f.rel_path == "src/store/mod.rs")
        .unwrap();
    let analysis = parse_file(mod_file).unwrap();

    let resolved: Vec<String> = analysis
        .imports
        .iter()
        .filter_map(|imp| registry.resolve(imp, &mod_file.rel_path, Language::Rust, &file_index))
        .collect();

    assert!(
        resolved.contains(&"src/store/helpers.rs".to_string()),
        "self::helpers should resolve, got: {resolved:?}"
    );
}

#[test]
fn rust_fixture_resolves_super_import() {
    let files = walk_fixture("rust");
    let file_index = FileIndex::new(files.iter().map(|f| f.rel_path.clone()));
    let registry = ResolverRegistry::new();

    let helpers_file = files
        .iter()
        .find(|f| f.rel_path == "src/store/helpers.rs")
        .unwrap();
    let analysis = parse_file(helpers_file).unwrap();

    // crate::store should resolve to src/store/mod.rs
    let resolved: Vec<String> = analysis
        .imports
        .iter()
        .filter_map(|imp| {
            registry.resolve(imp, &helpers_file.rel_path, Language::Rust, &file_index)
        })
        .collect();

    assert!(
        resolved.contains(&"src/store/mod.rs".to_string()),
        "crate::store should resolve to src/store/mod.rs, got: {resolved:?}"
    );
}

// ── Python fixtures ─────────────────────────────────────────────────────────

#[test]
fn python_fixture_resolves_absolute_import() {
    let files = walk_fixture("python");
    let file_index = FileIndex::new(files.iter().map(|f| f.rel_path.clone()));
    let registry = ResolverRegistry::new();

    let main_file = files
        .iter()
        .find(|f| f.rel_path == "app/main.py")
        .unwrap();
    let analysis = parse_file(main_file).unwrap();

    let resolved: Vec<String> = analysis
        .imports
        .iter()
        .filter_map(|imp| {
            registry.resolve(imp, &main_file.rel_path, Language::Python, &file_index)
        })
        .collect();

    assert!(
        resolved.contains(&"app/utils.py".to_string()),
        "app.utils should resolve to app/utils.py, got: {resolved:?}"
    );
}

#[test]
fn python_fixture_resolves_relative_import() {
    let files = walk_fixture("python");
    let file_index = FileIndex::new(files.iter().map(|f| f.rel_path.clone()));
    let registry = ResolverRegistry::new();

    let services_file = files
        .iter()
        .find(|f| f.rel_path == "app/services.py")
        .unwrap();
    let analysis = parse_file(services_file).unwrap();

    let resolved: Vec<String> = analysis
        .imports
        .iter()
        .filter_map(|imp| {
            registry.resolve(imp, &services_file.rel_path, Language::Python, &file_index)
        })
        .collect();

    assert!(
        resolved.contains(&"app/utils.py".to_string()),
        ".utils should resolve to app/utils.py, got: {resolved:?}"
    );
}

#[test]
fn python_fixture_resolves_package_init() {
    let files = walk_fixture("python");
    let file_index = FileIndex::new(files.iter().map(|f| f.rel_path.clone()));
    let registry = ResolverRegistry::new();

    // app/utils.py imports `..pkg` which should resolve to pkg/__init__.py
    let utils_file = files
        .iter()
        .find(|f| f.rel_path == "app/utils.py")
        .unwrap();
    let analysis = parse_file(utils_file).unwrap();

    let resolved: Vec<String> = analysis
        .imports
        .iter()
        .filter_map(|imp| {
            registry.resolve(imp, &utils_file.rel_path, Language::Python, &file_index)
        })
        .collect();

    assert!(
        resolved.contains(&"pkg/__init__.py".to_string()),
        "..pkg should resolve to pkg/__init__.py, got: {resolved:?}"
    );
}

// ── TypeScript fixtures ─────────────────────────────────────────────────────

#[test]
fn typescript_fixture_resolves_relative_import() {
    let files = walk_fixture("typescript");
    let file_index = FileIndex::new(files.iter().map(|f| f.rel_path.clone()));
    let registry = ResolverRegistry::new();

    let app_file = files
        .iter()
        .find(|f| f.rel_path == "src/app.ts")
        .unwrap();
    let analysis = parse_file(app_file).unwrap();

    let resolved: Vec<String> = analysis
        .imports
        .iter()
        .filter_map(|imp| {
            registry.resolve(imp, &app_file.rel_path, Language::TypeScript, &file_index)
        })
        .collect();

    assert!(
        resolved.contains(&"src/utils.ts".to_string()),
        "./utils should resolve to src/utils.ts, got: {resolved:?}"
    );
}

#[test]
fn typescript_fixture_resolves_index_import() {
    let files = walk_fixture("typescript");
    let file_index = FileIndex::new(files.iter().map(|f| f.rel_path.clone()));
    let registry = ResolverRegistry::new();

    let app_file = files
        .iter()
        .find(|f| f.rel_path == "src/app.ts")
        .unwrap();
    let analysis = parse_file(app_file).unwrap();

    let resolved: Vec<String> = analysis
        .imports
        .iter()
        .filter_map(|imp| {
            registry.resolve(imp, &app_file.rel_path, Language::TypeScript, &file_index)
        })
        .collect();

    assert!(
        resolved.contains(&"src/components/index.ts".to_string()),
        "./components should resolve to src/components/index.ts, got: {resolved:?}"
    );
}

#[test]
fn typescript_fixture_resolves_parent_dir_import() {
    let files = walk_fixture("typescript");
    let file_index = FileIndex::new(files.iter().map(|f| f.rel_path.clone()));
    let registry = ResolverRegistry::new();

    let button_file = files
        .iter()
        .find(|f| f.rel_path == "src/components/button.tsx")
        .unwrap();
    let analysis = parse_file(button_file).unwrap();

    let resolved: Vec<String> = analysis
        .imports
        .iter()
        .filter_map(|imp| {
            registry.resolve(imp, &button_file.rel_path, Language::TypeScript, &file_index)
        })
        .collect();

    assert!(
        resolved.contains(&"src/utils.ts".to_string()),
        "../utils should resolve to src/utils.ts, got: {resolved:?}"
    );
}

#[test]
fn typescript_fixture_skips_external_imports() {
    let files = walk_fixture("typescript");
    let file_index = FileIndex::new(files.iter().map(|f| f.rel_path.clone()));
    let registry = ResolverRegistry::new();

    let app_file = files
        .iter()
        .find(|f| f.rel_path == "src/app.ts")
        .unwrap();
    let analysis = parse_file(app_file).unwrap();

    // 'react' is an external import — should NOT be resolved
    let react_import = analysis.imports.iter().find(|i| i.path == "react").unwrap();
    assert_eq!(react_import.kind, ImportKind::External);
    assert_eq!(
        registry.resolve(react_import, &app_file.rel_path, Language::TypeScript, &file_index),
        None
    );
}
