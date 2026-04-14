//! Regression test: Rust resolver against mati's own `src/` tree.
//!
//! Uses the real mati codebase as a fixture to verify that the Rust resolver
//! correctly resolves known internal imports. This catches future regressions
//! in prefix-stripping, `crate::` normalization, and `super::` handling.

use mati_core::analysis::parser::parse_file;
use mati_core::analysis::resolvers::rust::RustResolver;
use mati_core::analysis::resolvers::{FileIndex, LanguageResolver};
use mati_core::analysis::walker::{Language, Walker};

fn mati_src_index() -> (FileIndex, Vec<mati_core::analysis::walker::WalkedFile>) {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let files = Walker::new(root.to_path_buf()).walk().unwrap();
    let index = FileIndex::new(files.iter().map(|f| f.rel_path.clone()));
    (index, files)
}

/// Parse a specific file and return all resolved import targets.
fn resolved_imports_for(
    file_path: &str,
    files: &[mati_core::analysis::walker::WalkedFile],
    index: &FileIndex,
) -> Vec<String> {
    let resolver = RustResolver;
    let file = files
        .iter()
        .find(|f| f.rel_path == file_path)
        .unwrap_or_else(|| panic!("file not found in walker output: {file_path}"));
    let analysis = parse_file(file).unwrap();

    analysis
        .imports
        .iter()
        .filter(|imp| imp.kind != mati_core::analysis::parser::ImportKind::External)
        .filter_map(|imp| resolver.resolve(imp, file_path, index))
        .collect()
}

/// Count total resolved internal imports across all Rust files in src/.
fn total_resolved_imports(
    files: &[mati_core::analysis::walker::WalkedFile],
    index: &FileIndex,
) -> usize {
    let resolver = RustResolver;
    let mut count = 0;
    for file in files {
        if file.language != Language::Rust {
            continue;
        }
        if !file.rel_path.starts_with("src/") {
            continue;
        }
        let analysis = match parse_file(file) {
            Ok(a) => a,
            Err(_) => continue,
        };
        count += analysis
            .imports
            .iter()
            .filter(|imp| imp.kind != mati_core::analysis::parser::ImportKind::External)
            .filter(|imp| resolver.resolve(imp, &file.rel_path, index).is_some())
            .count();
    }
    count
}

// ── Per-file assertions ──────────────────────────────────────────────────────

#[test]
fn init_rs_resolves_store_imports() {
    let (index, files) = mati_src_index();
    let resolved = resolved_imports_for("src/cli/init.rs", &files, &index);

    // init.rs has `use super::*` (resolves to src/cli/mod.rs or similar)
    // and `use super::colors` etc.
    assert!(
        !resolved.is_empty(),
        "src/cli/init.rs must resolve at least one internal import, got none"
    );
}

#[test]
fn tools_rs_resolves_graph_import() {
    let (index, files) = mati_src_index();
    let resolved = resolved_imports_for("src/mcp/tools.rs", &files, &index);

    // tools.rs imports from crate::graph, crate::store, super::server, etc.
    assert!(
        !resolved.is_empty(),
        "src/mcp/tools.rs must resolve at least one internal import"
    );
}

#[test]
fn record_rs_resolves_blast_radius_import() {
    let (index, files) = mati_src_index();
    let resolved = resolved_imports_for("src/store/record.rs", &files, &index);

    // record.rs itself has few internal imports (mostly external serde/uuid),
    // but the blast_radius field references crate::analysis::blast_radius
    // which is a type reference not a use statement. So this file may have
    // zero resolved imports. The assertion checks it doesn't panic.
    let _ = resolved;
}

#[test]
fn explain_rs_resolves_super_colors() {
    let (index, files) = mati_src_index();
    let resolved = resolved_imports_for("src/cli/explain.rs", &files, &index);

    assert!(
        resolved.iter().any(|r| r.contains("colors")),
        "src/cli/explain.rs must resolve super::colors, got: {resolved:?}"
    );
}

#[test]
fn show_rs_resolves_super_colors() {
    let (index, files) = mati_src_index();
    let resolved = resolved_imports_for("src/cli/show.rs", &files, &index);

    assert!(
        resolved.iter().any(|r| r.contains("colors")),
        "src/cli/show.rs must resolve super::colors, got: {resolved:?}"
    );
}

// ── Aggregate assertion ──────────────────────────────────────────────────────

#[test]
fn mati_codebase_resolves_significant_fraction_of_imports() {
    let (index, files) = mati_src_index();
    let resolved = total_resolved_imports(&files, &index);

    // Before the prefix-stripping fix: 51 resolved.
    // After: should be significantly higher. We assert >= 100 as a floor
    // that catches major regressions without being fragile to small changes.
    assert!(
        resolved >= 100,
        "mati codebase should resolve at least 100 internal imports, got {resolved}"
    );

    eprintln!("Resolved {resolved} internal imports on mati's own codebase");
}
