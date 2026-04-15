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

fn fixture_sub_path(lang: &str, sub: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/resolver")
        .join(lang)
        .join(sub)
}

fn walk_fixture(lang: &str) -> Vec<WalkedFile> {
    Walker::new(fixture_path(lang)).walk().unwrap()
}

fn walk_fixture_sub(lang: &str, sub: &str) -> Vec<WalkedFile> {
    Walker::new(fixture_sub_path(lang, sub)).walk().unwrap()
}

/// Resolve all imports from a file and return the resolved repo-relative paths.
fn resolve_all(
    file: &WalkedFile,
    language: Language,
    registry: &ResolverRegistry,
    file_index: &FileIndex,
) -> Vec<String> {
    let analysis = parse_file(file).unwrap();
    analysis
        .imports
        .iter()
        .filter_map(|imp| registry.resolve(imp, &file.rel_path, language, file_index))
        .collect()
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

// ── Rust workspace fixture ──────────────────────────────────────────────────

#[test]
fn rust_workspace_fixture_resolves_crate_imports() {
    let root = fixture_sub_path("rust", "workspace_project");
    let files = walk_fixture_sub("rust", "workspace_project");
    let mut file_index = FileIndex::new_with_root(root.clone(), files.iter().map(|f| f.rel_path.clone()));
    let crate_roots = mati_core::analysis::edges::detect_rust_crate_roots(&root, &file_index);
    file_index.set_crate_roots(crate_roots);
    let registry = ResolverRegistry::new();

    // crates/foo/src/lib.rs has `use crate::helper` — should resolve within foo's crate
    let foo_lib = files
        .iter()
        .find(|f| f.rel_path == "crates/foo/src/lib.rs")
        .unwrap();
    let resolved = resolve_all(foo_lib, Language::Rust, &registry, &file_index);
    assert!(
        resolved.contains(&"crates/foo/src/helper.rs".to_string()),
        "crate::helper in foo should resolve to crates/foo/src/helper.rs, got: {resolved:?}"
    );
}

#[test]
fn rust_workspace_fixture_bar_resolves_independently() {
    let root = fixture_sub_path("rust", "workspace_project");
    let files = walk_fixture_sub("rust", "workspace_project");
    let mut file_index = FileIndex::new_with_root(root.clone(), files.iter().map(|f| f.rel_path.clone()));
    let crate_roots = mati_core::analysis::edges::detect_rust_crate_roots(&root, &file_index);
    file_index.set_crate_roots(crate_roots);
    let registry = ResolverRegistry::new();

    // crates/bar/src/lib.rs has `use crate::util` — should resolve within bar's crate
    let bar_lib = files
        .iter()
        .find(|f| f.rel_path == "crates/bar/src/lib.rs")
        .unwrap();
    let resolved = resolve_all(bar_lib, Language::Rust, &registry, &file_index);
    assert!(
        resolved.contains(&"crates/bar/src/util.rs".to_string()),
        "crate::util in bar should resolve to crates/bar/src/util.rs, got: {resolved:?}"
    );
}

#[test]
fn rust_workspace_fixture_produces_correct_edge_count() {
    use mati_core::analysis::edges::build_edges_with_root;
    use mati_core::analysis::parser::parse_file;

    let root = fixture_sub_path("rust", "workspace_project");
    let files = walk_fixture_sub("rust", "workspace_project");
    let analyses: Vec<_> = files.iter().map(|f| parse_file(f).unwrap()).collect();

    let result = build_edges_with_root(&files, &analyses, &[], Some(&root));

    // Intra-crate: foo/lib.rs → foo/helper.rs, bar/lib.rs → bar/util.rs = 2 edges
    // Cross-crate: bar/lib.rs → foo/lib.rs = 1 edge
    // Total: at least 3 edges
    assert!(
        result.edges.len() >= 3,
        "workspace should produce at least 3 import edges (2 intra + 1 cross), got {}",
        result.edges.len()
    );

    // Verify the cross-crate edge specifically
    let has_cross_crate = result.edges.iter().any(|(from, kind, to)| {
        from == "file:crates/bar/src/lib.rs"
            && *kind == mati_core::graph::EdgeKind::Imports
            && to == "file:crates/foo/src/lib.rs"
    });
    assert!(
        has_cross_crate,
        "expected cross-crate edge bar/lib.rs → foo/lib.rs, edges: {:?}",
        result.edges
    );

    assert_eq!(
        result.unresolved_imports, 0,
        "all workspace-internal imports should resolve"
    );
}

// ── Python fixtures ─────────────────────────────────────────────────────────

#[test]
fn python_fixture_resolves_absolute_import() {
    let files = walk_fixture("python");
    let file_index = FileIndex::new(files.iter().map(|f| f.rel_path.clone()));
    let registry = ResolverRegistry::new();

    let main_file = files.iter().find(|f| f.rel_path == "app/main.py").unwrap();
    let analysis = parse_file(main_file).unwrap();

    let resolved: Vec<String> = analysis
        .imports
        .iter()
        .filter_map(|imp| registry.resolve(imp, &main_file.rel_path, Language::Python, &file_index))
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
    let utils_file = files.iter().find(|f| f.rel_path == "app/utils.py").unwrap();
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

    let app_file = files.iter().find(|f| f.rel_path == "src/app.ts").unwrap();
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

    let app_file = files.iter().find(|f| f.rel_path == "src/app.ts").unwrap();
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
            registry.resolve(
                imp,
                &button_file.rel_path,
                Language::TypeScript,
                &file_index,
            )
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

    let app_file = files.iter().find(|f| f.rel_path == "src/app.ts").unwrap();
    let analysis = parse_file(app_file).unwrap();

    // 'react' is an external import — should NOT be resolved
    let react_import = analysis.imports.iter().find(|i| i.path == "react").unwrap();
    assert_eq!(react_import.kind, ImportKind::External);
    assert_eq!(
        registry.resolve(
            react_import,
            &app_file.rel_path,
            Language::TypeScript,
            &file_index
        ),
        None
    );
}

// ── Go fixtures ────────────────────────────────────────────────────────────

#[test]
fn go_fixture_resolves_internal_imports() {
    let root = fixture_sub_path("go", "simple_module");
    let files = walk_fixture_sub("go", "simple_module");
    let file_index = FileIndex::new_with_root(root, files.iter().map(|f| f.rel_path.clone()));
    let registry = ResolverRegistry::new();

    // main.go imports auth and db packages
    let main_file = files.iter().find(|f| f.rel_path == "main.go").unwrap();
    let resolved = resolve_all(main_file, Language::Go, &registry, &file_index);

    // Should resolve to at least one file in auth/ and one in db/
    assert!(
        resolved
            .iter()
            .any(|r| r.starts_with("auth/") && r.ends_with(".go")),
        "main.go should resolve auth import, got: {resolved:?}"
    );
    assert!(
        resolved
            .iter()
            .any(|r| r.starts_with("db/") && r.ends_with(".go")),
        "main.go should resolve db import, got: {resolved:?}"
    );
}

#[test]
fn go_fixture_cross_package_import() {
    let root = fixture_sub_path("go", "simple_module");
    let files = walk_fixture_sub("go", "simple_module");
    let file_index = FileIndex::new_with_root(root, files.iter().map(|f| f.rel_path.clone()));
    let registry = ResolverRegistry::new();

    // auth/user.go imports db
    let user_file = files.iter().find(|f| f.rel_path == "auth/user.go").unwrap();
    let resolved = resolve_all(user_file, Language::Go, &registry, &file_index);

    assert!(
        resolved.contains(&"db/client.go".to_string()),
        "auth/user.go should resolve db import, got: {resolved:?}"
    );
}

#[test]
fn go_fixture_skips_stdlib() {
    let root = fixture_sub_path("go", "simple_module");
    let files = walk_fixture_sub("go", "simple_module");
    let file_index = FileIndex::new_with_root(root, files.iter().map(|f| f.rel_path.clone()));
    let registry = ResolverRegistry::new();

    // main.go imports "fmt" which is stdlib — should not resolve
    let main_file = files.iter().find(|f| f.rel_path == "main.go").unwrap();
    let analysis = parse_file(main_file).unwrap();
    let fmt_import = analysis.imports.iter().find(|i| i.path == "fmt").unwrap();
    assert_eq!(
        registry.resolve(fmt_import, &main_file.rel_path, Language::Go, &file_index),
        None
    );
}

// ── Java fixtures ───────────────────────────────────���──────────────────────

#[test]
fn java_fixture_resolves_cross_package_imports() {
    let files = walk_fixture_sub("java", "simple_project");
    let file_index = FileIndex::new(files.iter().map(|f| f.rel_path.clone()));
    let registry = ResolverRegistry::new();

    // Main.java imports UserService and DbClient
    let main_file = files
        .iter()
        .find(|f| f.rel_path == "src/main/java/com/acme/app/Main.java")
        .unwrap();
    let resolved = resolve_all(main_file, Language::Java, &registry, &file_index);

    assert!(
        resolved.contains(&"src/main/java/com/acme/auth/UserService.java".to_string()),
        "Main should resolve UserService, got: {resolved:?}"
    );
    assert!(
        resolved.contains(&"src/main/java/com/acme/db/DbClient.java".to_string()),
        "Main should resolve DbClient, got: {resolved:?}"
    );
}

#[test]
fn java_fixture_transitive_import() {
    let files = walk_fixture_sub("java", "simple_project");
    let file_index = FileIndex::new(files.iter().map(|f| f.rel_path.clone()));
    let registry = ResolverRegistry::new();

    // UserService.java imports DbClient
    let user_file = files
        .iter()
        .find(|f| f.rel_path == "src/main/java/com/acme/auth/UserService.java")
        .unwrap();
    let resolved = resolve_all(user_file, Language::Java, &registry, &file_index);

    assert!(
        resolved.contains(&"src/main/java/com/acme/db/DbClient.java".to_string()),
        "UserService should resolve DbClient, got: {resolved:?}"
    );
}

// ── C fixtures ─────────────────────────────────────────────────────────────

#[test]
fn c_fixture_resolves_quoted_includes() {
    let files = walk_fixture_sub("c", "simple_project");
    let file_index = FileIndex::new(files.iter().map(|f| f.rel_path.clone()));
    let registry = ResolverRegistry::new();

    // main.c includes auth.h and db.h
    let main_file = files.iter().find(|f| f.rel_path == "main.c").unwrap();
    let resolved = resolve_all(main_file, Language::C, &registry, &file_index);

    assert!(
        resolved.contains(&"auth.h".to_string()),
        "main.c should resolve auth.h, got: {resolved:?}"
    );
    assert!(
        resolved.contains(&"db.h".to_string()),
        "main.c should resolve db.h, got: {resolved:?}"
    );
}

#[test]
fn c_fixture_header_includes_header() {
    let files = walk_fixture_sub("c", "simple_project");
    let file_index = FileIndex::new(files.iter().map(|f| f.rel_path.clone()));
    let registry = ResolverRegistry::new();

    // auth.h includes db.h
    let auth_h = files.iter().find(|f| f.rel_path == "auth.h").unwrap();
    let resolved = resolve_all(auth_h, Language::C, &registry, &file_index);

    assert!(
        resolved.contains(&"db.h".to_string()),
        "auth.h should resolve db.h, got: {resolved:?}"
    );
}

#[test]
fn c_fixture_source_includes_header() {
    let files = walk_fixture_sub("c", "simple_project");
    let file_index = FileIndex::new(files.iter().map(|f| f.rel_path.clone()));
    let registry = ResolverRegistry::new();

    // auth.c includes auth.h
    let auth_c = files.iter().find(|f| f.rel_path == "auth.c").unwrap();
    let resolved = resolve_all(auth_c, Language::C, &registry, &file_index);

    assert!(
        resolved.contains(&"auth.h".to_string()),
        "auth.c should resolve auth.h, got: {resolved:?}"
    );
}

// ── C++ fixtures ───────────────────────────────────────────────────────────

#[test]
fn cpp_fixture_resolves_quoted_includes() {
    let files = walk_fixture_sub("cpp", "simple_project");
    let file_index = FileIndex::new(files.iter().map(|f| f.rel_path.clone()));
    let registry = ResolverRegistry::new();

    // main.cpp includes auth.hpp and db.hpp
    let main_file = files.iter().find(|f| f.rel_path == "main.cpp").unwrap();
    let resolved = resolve_all(main_file, Language::Cpp, &registry, &file_index);

    assert!(
        resolved.contains(&"auth.hpp".to_string()),
        "main.cpp should resolve auth.hpp, got: {resolved:?}"
    );
    assert!(
        resolved.contains(&"db.hpp".to_string()),
        "main.cpp should resolve db.hpp, got: {resolved:?}"
    );
}

#[test]
fn cpp_fixture_header_chain() {
    let files = walk_fixture_sub("cpp", "simple_project");
    let file_index = FileIndex::new(files.iter().map(|f| f.rel_path.clone()));
    let registry = ResolverRegistry::new();

    // auth.hpp includes db.hpp
    let auth_hpp = files.iter().find(|f| f.rel_path == "auth.hpp").unwrap();
    let resolved = resolve_all(auth_hpp, Language::Cpp, &registry, &file_index);

    assert!(
        resolved.contains(&"db.hpp".to_string()),
        "auth.hpp should resolve db.hpp, got: {resolved:?}"
    );
}

#[test]
fn cpp_fixture_source_includes_header() {
    let files = walk_fixture_sub("cpp", "simple_project");
    let file_index = FileIndex::new(files.iter().map(|f| f.rel_path.clone()));
    let registry = ResolverRegistry::new();

    let auth_cpp = files.iter().find(|f| f.rel_path == "auth.cpp").unwrap();
    let resolved = resolve_all(auth_cpp, Language::Cpp, &registry, &file_index);

    assert!(
        resolved.contains(&"auth.hpp".to_string()),
        "auth.cpp should resolve auth.hpp, got: {resolved:?}"
    );
}

// ── Ruby fixtures ──────────────────────────────────────────────────────────

#[test]
fn ruby_fixture_resolves_require_relative() {
    let files = walk_fixture_sub("ruby", "simple_project");
    let file_index = FileIndex::new(files.iter().map(|f| f.rel_path.clone()));
    let registry = ResolverRegistry::new();

    // lib/main.rb requires auth and db
    let main_file = files.iter().find(|f| f.rel_path == "lib/main.rb").unwrap();
    let resolved = resolve_all(main_file, Language::Ruby, &registry, &file_index);

    assert!(
        resolved.contains(&"lib/auth.rb".to_string()),
        "main.rb should resolve auth, got: {resolved:?}"
    );
    assert!(
        resolved.contains(&"lib/db.rb".to_string()),
        "main.rb should resolve db, got: {resolved:?}"
    );
}

#[test]
fn ruby_fixture_transitive_require() {
    let files = walk_fixture_sub("ruby", "simple_project");
    let file_index = FileIndex::new(files.iter().map(|f| f.rel_path.clone()));
    let registry = ResolverRegistry::new();

    // lib/auth.rb requires db
    let auth_file = files.iter().find(|f| f.rel_path == "lib/auth.rb").unwrap();
    let resolved = resolve_all(auth_file, Language::Ruby, &registry, &file_index);

    assert!(
        resolved.contains(&"lib/db.rb".to_string()),
        "auth.rb should resolve db, got: {resolved:?}"
    );
}

// ── Scala fixtures ─────────────────────────────────────────────────────────

#[test]
fn scala_fixture_resolves_dotted_imports() {
    let files = walk_fixture_sub("scala", "simple_project");
    let file_index = FileIndex::new(files.iter().map(|f| f.rel_path.clone()));
    let registry = ResolverRegistry::new();

    let main_file = files
        .iter()
        .find(|f| f.rel_path == "src/main/scala/com/acme/Main.scala")
        .unwrap();
    let resolved = resolve_all(main_file, Language::Scala, &registry, &file_index);

    assert!(
        resolved.contains(&"src/main/scala/com/acme/auth/UserService.scala".to_string()),
        "Main should resolve UserService, got: {resolved:?}"
    );
    assert!(
        resolved.contains(&"src/main/scala/com/acme/db/DbClient.scala".to_string()),
        "Main should resolve DbClient, got: {resolved:?}"
    );
}

#[test]
fn scala_fixture_transitive_import() {
    let files = walk_fixture_sub("scala", "simple_project");
    let file_index = FileIndex::new(files.iter().map(|f| f.rel_path.clone()));
    let registry = ResolverRegistry::new();

    let user_file = files
        .iter()
        .find(|f| f.rel_path == "src/main/scala/com/acme/auth/UserService.scala")
        .unwrap();
    let resolved = resolve_all(user_file, Language::Scala, &registry, &file_index);

    assert!(
        resolved.contains(&"src/main/scala/com/acme/db/DbClient.scala".to_string()),
        "UserService should resolve DbClient, got: {resolved:?}"
    );
}

// ── Elixir fixtures ────────────────────────────────────────────────────────

#[test]
fn elixir_fixture_resolves_alias_imports() {
    let files = walk_fixture_sub("elixir", "simple_project");
    let file_index = FileIndex::new(files.iter().map(|f| f.rel_path.clone()));
    let registry = ResolverRegistry::new();

    let main_file = files
        .iter()
        .find(|f| f.rel_path == "lib/my_app.ex")
        .unwrap();
    let resolved = resolve_all(main_file, Language::Elixir, &registry, &file_index);

    assert!(
        resolved.contains(&"lib/my_app/auth/user_service.ex".to_string()),
        "my_app.ex should resolve UserService, got: {resolved:?}"
    );
    assert!(
        resolved.contains(&"lib/my_app/db/client.ex".to_string()),
        "my_app.ex should resolve Client, got: {resolved:?}"
    );
}

#[test]
fn elixir_fixture_transitive_alias() {
    let files = walk_fixture_sub("elixir", "simple_project");
    let file_index = FileIndex::new(files.iter().map(|f| f.rel_path.clone()));
    let registry = ResolverRegistry::new();

    let user_file = files
        .iter()
        .find(|f| f.rel_path == "lib/my_app/auth/user_service.ex")
        .unwrap();
    let resolved = resolve_all(user_file, Language::Elixir, &registry, &file_index);

    assert!(
        resolved.contains(&"lib/my_app/db/client.ex".to_string()),
        "user_service.ex should resolve Client, got: {resolved:?}"
    );
}

#[test]
fn elixir_fixture_acronym_modules_resolve() {
    let files = walk_fixture_sub("elixir", "acronym_project");
    let file_index = FileIndex::new(files.iter().map(|f| f.rel_path.clone()));
    let registry = ResolverRegistry::new();

    let main_file = files
        .iter()
        .find(|f| f.rel_path == "lib/my_app.ex")
        .unwrap();
    let resolved = resolve_all(main_file, Language::Elixir, &registry, &file_index);

    assert!(
        resolved.contains(&"lib/my_app/http_server.ex".to_string()),
        "my_app.ex should resolve HTTPServer → http_server.ex, got: {resolved:?}"
    );
    assert!(
        resolved.contains(&"lib/my_app/xml_parser.ex".to_string()),
        "my_app.ex should resolve XMLParser → xml_parser.ex, got: {resolved:?}"
    );
}

// ── Haskell fixtures ───────────────────────────────────────────────────────

#[test]
fn haskell_fixture_resolves_module_imports() {
    let files = walk_fixture_sub("haskell", "simple_project");
    let file_index = FileIndex::new(files.iter().map(|f| f.rel_path.clone()));
    let registry = ResolverRegistry::new();

    let main_file = files.iter().find(|f| f.rel_path == "src/Main.hs").unwrap();
    let resolved = resolve_all(main_file, Language::Haskell, &registry, &file_index);

    assert!(
        resolved.contains(&"src/MyApp/Auth/UserService.hs".to_string()),
        "Main should resolve UserService, got: {resolved:?}"
    );
    assert!(
        resolved.contains(&"src/MyApp/Db/Client.hs".to_string()),
        "Main should resolve Client, got: {resolved:?}"
    );
}

#[test]
fn haskell_fixture_transitive_import() {
    let files = walk_fixture_sub("haskell", "simple_project");
    let file_index = FileIndex::new(files.iter().map(|f| f.rel_path.clone()));
    let registry = ResolverRegistry::new();

    let user_file = files
        .iter()
        .find(|f| f.rel_path == "src/MyApp/Auth/UserService.hs")
        .unwrap();
    let resolved = resolve_all(user_file, Language::Haskell, &registry, &file_index);

    assert!(
        resolved.contains(&"src/MyApp/Db/Client.hs".to_string()),
        "UserService should resolve Client, got: {resolved:?}"
    );
}
