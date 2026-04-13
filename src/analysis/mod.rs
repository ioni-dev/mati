// Layer 0 — static analysis engine (M-06)
// Parallel file walker (ignore + rayon), tree-sitter parsing,
// git2 history mining, dependency parsing (Cargo.toml, package.json, go.mod)
// Target: <200ms on a 250-file Rust project

use std::collections::HashSet;

use crate::store::record::FileRecord;

pub mod claude_md;
pub mod deps;
pub mod edges;
pub mod git;
pub mod parser;
pub mod reparse;
pub mod resolvers;
pub mod walker;

pub use claude_md::{import_claude_md, ClaudeMdImport};
pub use deps::{
    dep_display_name_from_key, dep_record_key, parse_dep_key, parse_dependencies, DepEcosystem,
    DepEntry, DepSignals, DepVersion, ManifestKind,
};
pub use edges::{build_edges, build_edges_with_root, Layer0Edges};
pub use git::{mine_git_history, GitSignals};
pub use parser::{hash_and_parse_parallel, parse_file, parse_files_parallel, StaticFileAnalysis};
pub use walker::{Language, WalkedFile, Walker};

pub(crate) fn public_api_symbols(analysis: &StaticFileAnalysis) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut symbols =
        Vec::with_capacity(analysis.entry_points.len() + analysis.exported_types.len());

    for symbol in analysis
        .entry_points
        .iter()
        .chain(analysis.exported_types.iter())
    {
        if seen.insert(symbol.as_str()) {
            symbols.push(symbol.clone());
        }
    }

    symbols
}

/// Build one `FileRecord` from the parsed Layer 0 signals for a file.
///
/// If the parser extracted a module-level doc comment (`analysis.module_doc`),
/// it is used as the initial `purpose`. Records with a purpose are auto-promoted
/// to `additionalContext` quality in the caller (`init.rs`).
pub fn build_file_record(
    file: &WalkedFile,
    analysis: &StaticFileAnalysis,
    git: Option<&GitSignals>,
    hotspot_files: Option<&HashSet<String>>,
    last_modified_session: u64,
) -> FileRecord {
    let path = file.rel_path.clone();
    let (change_frequency, last_author, is_hotspot) = match git {
        Some(signals) => (
            signals.change_frequency.get(&path).copied().unwrap_or(0),
            signals.last_authors.get(&path).cloned(),
            hotspot_files
                .map(|hotspots| hotspots.contains(&path))
                .unwrap_or(false),
        ),
        None => (0, None, false),
    };

    let token_cost_estimate = (file.size_bytes / 4).min(u32::MAX as u64) as u32;
    let public_api = public_api_symbols(analysis);

    let mut fr = FileRecord::layer0_stub(
        path,
        public_api,
        analysis.imports.iter().map(|i| i.path.clone()).collect(),
        analysis.todos.clone(),
        analysis.unsafe_count,
        analysis.unwrap_count,
        change_frequency,
        last_author,
        is_hotspot,
        token_cost_estimate,
        last_modified_session,
    );

    // Propagate author-written doc comment to purpose — gives immediate
    // additionalContext value after `mati init` with no LLM calls.
    if let Some(doc) = &analysis.module_doc {
        fr.purpose = doc.clone();
    }

    fr.content_hash = analysis.content_hash.clone();
    fr.line_count = analysis.line_count;

    fr
}

/// Build layer-0 file records for a batch of parsed files.
pub fn build_file_records(
    files: &[WalkedFile],
    analyses: &[StaticFileAnalysis],
    git: Option<&GitSignals>,
    last_modified_session: u64,
) -> Vec<FileRecord> {
    assert_eq!(
        files.len(),
        analyses.len(),
        "build_file_records expects one analysis per walked file"
    );

    let hotspot_files = git.map(|signals| {
        signals
            .hotspot_files
            .iter()
            .cloned()
            .collect::<HashSet<_>>()
    });
    let hotspot_files = hotspot_files.as_ref();

    files
        .iter()
        .zip(analyses)
        .map(|(file, analysis)| {
            build_file_record(file, analysis, git, hotspot_files, last_modified_session)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::parser::{ImportKind, ImportStatement};
    use crate::store::record::TodoComment;

    #[test]
    fn build_file_record_uses_layer0_defaults_and_git_signals() {
        let analysis = StaticFileAnalysis {
            path: "src/lib.rs".to_string(),
            language: Language::Rust,
            entry_points: vec!["run".to_string()],
            exported_types: vec![],
            imports: vec![ImportStatement::new("crate::utils", ImportKind::Normal, 1)],
            todos: vec![TodoComment {
                text: "TODO: tighten docs".to_string(),
                line: 12,
                kind: crate::store::record::TodoKind::Todo,
            }],
            unsafe_count: 1,
            unwrap_count: 2,
            panic_count: 0,
            branch_count: 3,
            module_doc: None,
            content_hash: None,
            line_count: 0,
        };

        let mut git = GitSignals::empty();
        git.change_frequency.insert("src/lib.rs".to_string(), 9);
        git.last_authors
            .insert("src/lib.rs".to_string(), "ioni".to_string());
        git.hotspot_files.push("src/lib.rs".to_string());

        let file = WalkedFile {
            abs_path: std::path::PathBuf::from("/repo/src/lib.rs"),
            rel_path: "src/lib.rs".to_string(),
            language: Language::Rust,
            size_bytes: 400,
            mtime_secs: 0,
        };

        let hotspots = git.hotspot_files.iter().cloned().collect::<HashSet<_>>();

        let record = build_file_record(&file, &analysis, Some(&git), Some(&hotspots), 1234);

        assert_eq!(record.path, "src/lib.rs");
        assert!(record.purpose.is_empty());
        assert_eq!(record.entry_points, vec!["run".to_string()]);
        assert_eq!(record.imports, vec!["crate::utils".to_string()]);
        assert_eq!(record.todos.len(), 1);
        assert_eq!(record.unsafe_count, 1);
        assert_eq!(record.unwrap_count, 2);
        assert_eq!(record.change_frequency, 9);
        assert_eq!(record.last_author.as_deref(), Some("ioni"));
        assert!(record.is_hotspot);
        assert_eq!(record.token_cost_estimate, 100);
        assert_eq!(record.last_modified_session, 1234);
    }

    #[test]
    fn module_doc_propagates_to_purpose() {
        let analysis = StaticFileAnalysis {
            path: "src/auth.rs".to_string(),
            language: Language::Rust,
            entry_points: vec![],
            exported_types: vec![],
            imports: vec![],
            todos: vec![],
            unsafe_count: 0,
            unwrap_count: 0,
            panic_count: 0,
            branch_count: 0,
            module_doc: Some("Handles JWT authentication.".to_string()),
            content_hash: None,
            line_count: 0,
        };
        let file = WalkedFile {
            abs_path: std::path::PathBuf::from("/repo/src/auth.rs"),
            rel_path: "src/auth.rs".to_string(),
            language: Language::Rust,
            size_bytes: 100,
            mtime_secs: 0,
        };
        let record = build_file_record(&file, &analysis, None, None, 0);
        assert_eq!(record.purpose, "Handles JWT authentication.");
    }

    #[test]
    fn exported_types_are_folded_into_stored_api_surface() {
        let analysis = StaticFileAnalysis {
            path: "src/models.rs".to_string(),
            language: Language::Rust,
            entry_points: vec!["build".to_string()],
            exported_types: vec!["Widget".to_string(), "Widget".to_string()],
            imports: vec![],
            todos: vec![],
            unsafe_count: 0,
            unwrap_count: 0,
            panic_count: 0,
            branch_count: 0,
            module_doc: None,
            content_hash: None,
            line_count: 0,
        };
        let file = WalkedFile {
            abs_path: std::path::PathBuf::from("/repo/src/models.rs"),
            rel_path: "src/models.rs".to_string(),
            language: Language::Rust,
            size_bytes: 100,
            mtime_secs: 0,
        };

        let record = build_file_record(&file, &analysis, None, None, 0);
        assert_eq!(
            record.entry_points,
            vec!["build".to_string(), "Widget".to_string()]
        );
    }

    #[test]
    fn build_file_records_is_stable_for_missing_git_signals() {
        let files = vec![WalkedFile {
            abs_path: std::path::PathBuf::from("/repo/src/main.rs"),
            rel_path: "src/main.rs".to_string(),
            language: Language::Rust,
            size_bytes: 8,
            mtime_secs: 0,
        }];
        let analyses = vec![StaticFileAnalysis {
            path: "src/main.rs".to_string(),
            language: Language::Rust,
            entry_points: vec![],
            exported_types: vec![],
            imports: vec![],
            todos: vec![],
            unsafe_count: 0,
            unwrap_count: 0,
            panic_count: 0,
            branch_count: 0,
            module_doc: None,
            content_hash: None,
            line_count: 0,
        }];

        let records = build_file_records(&files, &analyses, None, 55);

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].path, "src/main.rs");
        assert_eq!(records[0].change_frequency, 0);
        assert!(records[0].last_author.is_none());
        assert!(!records[0].is_hotspot);
        assert_eq!(records[0].token_cost_estimate, 2);
    }
}
