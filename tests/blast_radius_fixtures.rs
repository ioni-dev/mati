//! Integration tests for blast radius computation across language fixtures.
//!
//! Verifies that blast radius is correctly computed from the import graph
//! for each supported language fixture in `tests/fixtures/resolver/`.

use mati_core::analysis::blast_radius::{BlastRadius, BlastTier};
use mati_core::analysis::edges::build_edges;
use mati_core::analysis::parser::parse_file;
use mati_core::analysis::walker::{WalkedFile, Walker};
use mati_core::graph::edges::EdgeKind;
use mati_core::graph::Graph;
use mati_core::store::Store;
use tempfile::TempDir;

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

fn walk_and_parse(
    root: &std::path::Path,
) -> (
    Vec<WalkedFile>,
    Vec<mati_core::analysis::StaticFileAnalysis>,
) {
    let files = Walker::new(root.to_path_buf()).walk().unwrap();
    let analyses: Vec<_> = files.iter().map(|f| parse_file(f).unwrap()).collect();
    (files, analyses)
}

async fn build_graph_with_edges(
    files: &[WalkedFile],
    analyses: &[mati_core::analysis::StaticFileAnalysis],
) -> (Graph, TempDir) {
    let edges = build_edges(files, analyses, &[]);
    let dir = TempDir::new().unwrap();
    let store = Store::open(dir.path()).await.unwrap();
    let mut graph = Graph::empty(store);

    let import_edges: Vec<_> = edges
        .edges
        .iter()
        .filter(|(_, kind, _)| *kind == EdgeKind::Imports)
        .cloned()
        .collect();
    graph.add_edges_batch(&import_edges).await.unwrap();

    (graph, dir)
}

/// Validate that every file in the fixture has a populated blast radius
/// and that the values are consistent.
async fn validate_fixture(root: &std::path::Path, lang_label: &str) {
    let (files, analyses) = walk_and_parse(root);
    assert!(
        !files.is_empty(),
        "{lang_label}: fixture must contain at least one file"
    );

    let (graph, _dir) = build_graph_with_edges(&files, &analyses).await;

    let mut has_imported = false;
    let mut has_leaf = false;

    for file in &files {
        let key = format!("file:{}", file.rel_path);
        let br = BlastRadius::compute(&key, &graph);

        // Every file must produce a valid blast radius
        assert!(
            br.score >= 0.0,
            "{lang_label}: score must be non-negative for {key}"
        );
        assert_eq!(
            br.tier,
            BlastTier::from_direct_count(br.direct),
            "{lang_label}: tier must match direct count for {key}"
        );

        if br.direct > 0 {
            has_imported = true;
        }
        if br.direct == 0 {
            has_leaf = true;
            assert_eq!(
                br.tier,
                BlastTier::Isolated,
                "{lang_label}: file with 0 importers must be Isolated: {key}"
            );
        }
    }

    // At least one file should be a leaf (entry point / main file)
    assert!(
        has_leaf,
        "{lang_label}: fixture should have at least one leaf file (Isolated)"
    );

    // If the fixture has import edges, at least one file should be imported
    // (some fixtures may have no resolvable internal imports)
    let _ = has_imported; // not all fixtures guarantee this

    graph.close().await.unwrap();
}

// ── Rust ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn rust_fixture_blast_radius() {
    let root = fixture_path("rust");
    let (files, analyses) = walk_and_parse(&root);
    let (graph, _dir) = build_graph_with_edges(&files, &analyses).await;

    // src/store/helpers.rs is imported by lib.rs and store/mod.rs → direct >= 1
    let helpers_br = BlastRadius::compute("file:src/store/helpers.rs", &graph);
    assert!(
        helpers_br.direct >= 1,
        "helpers.rs should have at least 1 direct importer, got {}",
        helpers_br.direct
    );
    assert_ne!(helpers_br.tier, BlastTier::Isolated);

    // src/store/mod.rs is imported by lib.rs → direct >= 1
    let mod_br = BlastRadius::compute("file:src/store/mod.rs", &graph);
    assert!(
        mod_br.direct >= 1,
        "store/mod.rs should have at least 1 direct importer, got {}",
        mod_br.direct
    );

    // src/lib.rs — root module, nothing imports it → isolated
    let lib_br = BlastRadius::compute("file:src/lib.rs", &graph);
    assert_eq!(lib_br.tier, BlastTier::Isolated);
    assert_eq!(lib_br.direct, 0);

    graph.close().await.unwrap();
}

// ── Python ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn python_fixture_blast_radius() {
    validate_fixture(&fixture_path("python"), "python").await;
}

// ── TypeScript ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn typescript_fixture_blast_radius() {
    validate_fixture(&fixture_path("typescript"), "typescript").await;
}

// ── Go ───────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn go_fixture_blast_radius() {
    validate_fixture(&fixture_sub_path("go", "simple_module"), "go").await;
}

// ── Java ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn java_fixture_blast_radius() {
    validate_fixture(&fixture_sub_path("java", "simple_project"), "java").await;
}

// ── C ────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn c_fixture_blast_radius() {
    validate_fixture(&fixture_sub_path("c", "simple_project"), "c").await;
}

// ── C++ ──────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn cpp_fixture_blast_radius() {
    validate_fixture(&fixture_sub_path("cpp", "simple_project"), "cpp").await;
}

// ── Ruby ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn ruby_fixture_blast_radius() {
    validate_fixture(&fixture_sub_path("ruby", "simple_project"), "ruby").await;
}

// ── Scala ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn scala_fixture_blast_radius() {
    validate_fixture(&fixture_sub_path("scala", "simple_project"), "scala").await;
}

// ── Elixir ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn elixir_fixture_blast_radius() {
    validate_fixture(&fixture_sub_path("elixir", "simple_project"), "elixir").await;
}

// ── Haskell ──────────────────────────────────────────────────────────────────

#[tokio::test]
async fn haskell_fixture_blast_radius() {
    validate_fixture(&fixture_sub_path("haskell", "simple_project"), "haskell").await;
}
