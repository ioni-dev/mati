use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::time::Instant;

use anyhow::Result;
use clap::Args;
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use mati_core::analysis::{
    build_edges, build_file_records, import_claude_md, mine_git_history, parse_dependencies,
    parse_files_parallel, Walker,
};
use mati_core::graph::Graph;
use mati_core::scaffold::{install_hooks, write_claude_md_stub};
use mati_core::store::{
    Category, ConfidenceScore, Priority, QualityScore, Record, RecordLifecycle, RecordSource,
    RecordVersion, StalenessScore, Store, derive_slug,
};

#[derive(Args)]
pub struct InitArgs {
    /// Path to repository root (defaults to current directory)
    #[arg(short, long)]
    pub path: Option<PathBuf>,

    /// Skip hook installation into .claude/hooks/
    #[arg(long)]
    pub no_hooks: bool,

    /// Skip writing .claude/settings.json
    #[arg(long)]
    pub no_settings: bool,
}

pub async fn run(args: InitArgs) -> Result<()> {
    let root = match &args.path {
        Some(p) => p.clone(),
        None => std::env::current_dir()?,
    };
    let root = std::fs::canonicalize(&root)?;

    let slug = derive_slug(&root);
    let project_name = root
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "unknown".to_string());

    println!();
    println!("◈  mati — project: {}  (slug: {})", project_name, slug);
    println!();

    let total_start = Instant::now();
    let device_id = Uuid::new_v4();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // ── 1. Walk ──────────────────────────────────────────────────────────────
    let t = Instant::now();
    let walker = Walker::new(&root);
    let files = walker.walk()?;
    let total_file_count = files.len();
    println!(
        "  Scanning with ignore...              {:>4} files   {:>4}ms",
        total_file_count,
        t.elapsed().as_millis()
    );

    // Build walked_paths before consuming `files` (needed for git history).
    let walked_paths: HashSet<String> = files.iter().map(|f| f.rel_path.clone()).collect();

    // ── 2. Hash check — open store + compute hashes in parallel ──────────────
    let t = Instant::now();

    // Open the store early — needed to load stored hashes for incremental skip.
    let store = Store::open(&root).await?;

    // Compute SHA-256 of all file contents in parallel (I/O + CPU bound, rayon).
    // Borrows `files` — does not consume it (dep scanning needs all walked files).
    let current_hashes: HashMap<String, String> = files
        .par_iter()
        .filter_map(|f| {
            std::fs::read(&f.abs_path).ok().map(|bytes| {
                let digest = Sha256::digest(&bytes);
                let hash = hex::encode(digest);
                (f.rel_path.clone(), hash)
            })
        })
        .collect();

    // Load stored hashes from previous init (sessions tree, Eventual).
    let stored_hashes: HashMap<String, String> = store
        .scan_prefix("parse:hash:")
        .await?
        .into_iter()
        .map(|r| {
            let path = r.key.strip_prefix("parse:hash:").unwrap_or(&r.key).to_string();
            (path, r.value)
        })
        .collect();

    // Compute per-file parse decision without consuming `files`.
    // `files` must remain available for dep scanning (manifests are in the full walk).
    let needs_parse: Vec<bool> = files
        .iter()
        .map(|f| {
            match (current_hashes.get(&f.rel_path), stored_hashes.get(&f.rel_path)) {
                (Some(curr), Some(stored)) => curr != stored,
                _ => true, // new file or unreadable → must parse
            }
        })
        .collect();

    let parse_count = needs_parse.iter().filter(|&&p| p).count();
    let skipped_count = total_file_count - parse_count;

    // Clone only the files that need parsing — avoids cloning the full list.
    let files_to_parse: Vec<_> = files
        .iter()
        .zip(&needs_parse)
        .filter(|(_, &p)| p)
        .map(|(f, _)| f.clone())
        .collect();

    if skipped_count > 0 {
        println!(
            "  Hash check (incremental)...    {:>4} changed  {:>4} skipped  {:>3}ms",
            parse_count,
            skipped_count,
            t.elapsed().as_millis()
        );
    } else {
        println!(
            "  Hash check (first run)...      {:>4} to parse          {:>3}ms",
            parse_count,
            t.elapsed().as_millis()
        );
    }

    // ── 3. Parse (changed/new files only) ────────────────────────────────────
    let t = Instant::now();
    let analyses = parse_files_parallel(&files_to_parse);
    println!(
        "  Parsing with tree-sitter...    {:>4} files             {:>3}ms",
        parse_count,
        t.elapsed().as_millis()
    );

    // ── 4. Git history ───────────────────────────────────────────────────────
    let t = Instant::now();
    let git_signals = match mine_git_history(&root, &walked_paths) {
        Ok(g) => {
            println!(
                "  Mining git history...                              {:>4}ms",
                t.elapsed().as_millis()
            );
            Some(g)
        }
        Err(e) => {
            tracing::warn!("git history mining failed: {e}");
            println!(
                "  Mining git history...               (skipped)      {:>4}ms",
                t.elapsed().as_millis()
            );
            None
        }
    };

    // ── 5. Dependencies ──────────────────────────────────────────────────────
    // Always scan all walked files — manifest files (Cargo.toml, package.json,
    // go.mod) may be unchanged but are needed for correct dep records. On an
    // incremental run where no manifest changed, this is a fast no-op (<2ms).
    let t = Instant::now();
    let dep_signals = match parse_dependencies(&root, &files) {
        Ok(d) => {
            println!(
                "  Parsing dependencies...              {:>4} deps    {:>4}ms",
                d.deps.len(),
                t.elapsed().as_millis()
            );
            d
        }
        Err(e) => {
            tracing::warn!("dependency parsing failed: {e}");
            println!(
                "  Parsing dependencies...              (skipped)     {:>4}ms",
                t.elapsed().as_millis()
            );
            mati_core::analysis::DepSignals::empty()
        }
    };

    // ── 6. CLAUDE.md import ──────────────────────────────────────────────────
    let t = Instant::now();
    let claude_md_path = root.join("CLAUDE.md");
    let claude_import = match import_claude_md(&claude_md_path, device_id, 0) {
        Ok(imp) => {
            let section_count = imp.records.len();
            println!(
                "  Importing CLAUDE.md...               {:>4} sections {:>3}ms",
                section_count,
                t.elapsed().as_millis()
            );
            imp
        }
        Err(e) => {
            tracing::warn!("CLAUDE.md import failed: {e}");
            println!(
                "  Importing CLAUDE.md...               (skipped)     {:>4}ms",
                t.elapsed().as_millis()
            );
            mati_core::analysis::ClaudeMdImport { records: vec![] }
        }
    };

    // ── 7. Build file records (parsed files only) ────────────────────────────
    let file_records = build_file_records(&files_to_parse, &analyses, git_signals.as_ref(), now);

    // ── 8. Build edges (parsed files only) ───────────────────────────────────
    let t = Instant::now();
    let co_change_pairs: Vec<(String, String, u32)> = git_signals
        .as_ref()
        .map(|g| g.co_change_pairs.clone())
        .unwrap_or_default();
    let layer0_edges = build_edges(&files_to_parse, &analyses, &co_change_pairs);
    let edge_count = layer0_edges.edges.len();
    println!(
        "  Building graph edges...              {:>4} edges   {:>4}ms",
        edge_count,
        t.elapsed().as_millis()
    );

    // ── Prepare records for put_batch ────────────────────────────────────────
    let mut logical_clock: u64 = claude_import.records.len() as u64;

    // File records → Record structs (changed/new files only)
    let file_record_structs: Vec<Record> = file_records
        .iter()
        .enumerate()
        .map(|(i, fr)| {
            let key = format!("file:{}", fr.path);
            let mut rec = Record::layer0_file_stub(&key, device_id, logical_clock + i as u64, now);
            rec.value = serde_json::to_string(fr).unwrap_or_default();
            rec
        })
        .collect();
    logical_clock += file_record_structs.len() as u64;

    // Dep records → Record structs
    let dep_record_structs: Vec<Record> = dep_signals
        .deps
        .iter()
        .enumerate()
        .map(|(i, dep)| {
            let key = format!("dep:{}", dep.name);
            let mut rec =
                Record::layer0_file_stub(&key, device_id, logical_clock + i as u64, now);
            rec.category = Category::Dependency;
            rec.source = RecordSource::StaticAnalysis;
            rec.value = match &dep.version {
                mati_core::analysis::DepVersion::Declared(v) => {
                    format!("{} = \"{}\"", dep.name, v)
                }
                mati_core::analysis::DepVersion::Workspace => {
                    format!("{} (workspace)", dep.name)
                }
            };
            let manifest_tag = match dep.manifest {
                mati_core::analysis::ManifestKind::CargoToml => "manifest:cargo-toml",
                mati_core::analysis::ManifestKind::PackageJson => "manifest:package-json",
                mati_core::analysis::ManifestKind::GoMod => "manifest:go-mod",
            };
            rec.tags = vec![
                manifest_tag.to_string(),
                if dep.dev {
                    "dev-dep".to_string()
                } else {
                    "dep".to_string()
                },
            ];
            rec
        })
        .collect();

    // Parse-hash records — written for all changed/new files so re-init can
    // skip them when their content is unchanged. Stored in the sessions tree
    // (Eventual durability) — recomputable, not user-visible knowledge.
    let hash_record_structs: Vec<Record> = files_to_parse
        .iter()
        .filter_map(|f| {
            current_hashes.get(&f.rel_path).map(|h| {
                let key = format!("parse:hash:{}", f.rel_path);
                make_hash_record(&key, h, device_id, now)
            })
        })
        .collect();

    // Combine all records
    let all_records: Vec<Record> = claude_import
        .records
        .iter()
        .chain(file_record_structs.iter())
        .chain(dep_record_structs.iter())
        .chain(hash_record_structs.iter())
        .cloned()
        .collect();

    let all_pairs: Vec<(&str, &Record)> = all_records
        .iter()
        .map(|r| (r.key.as_str(), r))
        .collect();

    // ── 9. put_batch ─────────────────────────────────────────────────────────
    // Store was already opened above for hash loading. Reuse it.
    store.put_batch(&all_pairs).await?;

    // ── 9a. Seed stats snapshot (first run only) ──────────────────────────────
    // On incremental re-init, in-memory file_record_structs is incomplete
    // (only changed files). Skip seeding — mati stats will recompute from the
    // full store on next call.
    if skipped_count == 0 {
        let gotcha_recs: Vec<Record> = claude_import
            .records
            .iter()
            .filter(|r| r.key.starts_with("gotcha:"))
            .cloned()
            .collect();
        let decision_recs: Vec<Record> = claude_import
            .records
            .iter()
            .filter(|r| r.key.starts_with("decision:"))
            .cloned()
            .collect();
        if let Err(e) = super::stats::seed_snapshot(
            &store,
            &file_record_structs,
            &gotcha_recs,
            &decision_recs,
            &dep_record_structs,
            now,
        )
        .await
        {
            tracing::warn!("stats snapshot seed failed (non-fatal): {e}");
        }
    }

    // ── 10–11. Graph::load + add_edges_batch ─────────────────────────────────
    let mut graph = Graph::load(store).await?;
    graph.add_edges_batch(&layer0_edges.edges).await?;

    // ── 12. Scaffold: CLAUDE.md stub ─────────────────────────────────────────
    let t = Instant::now();
    match write_claude_md_stub(&root) {
        Ok(_) => println!(
            "  Writing .claude/CLAUDE.md stub...                   {:>3}ms",
            t.elapsed().as_millis()
        ),
        Err(e) => {
            tracing::warn!("CLAUDE.md stub write failed: {e}");
            println!(
                "  Writing .claude/CLAUDE.md stub...    (skipped)      {:>3}ms",
                t.elapsed().as_millis()
            );
        }
    }

    // ── 13. Scaffold: hooks ──────────────────────────────────────────────────
    if !args.no_hooks {
        let t = Instant::now();
        match install_hooks(&root) {
            Ok(_) => println!(
                "  Installing hooks into .claude/...                   {:>3}ms",
                t.elapsed().as_millis()
            ),
            Err(e) => {
                tracing::warn!("hook installation failed: {e}");
                println!(
                    "  Installing hooks into .claude/...    (skipped)      {:>3}ms",
                    t.elapsed().as_millis()
                );
            }
        }
    }

    // ── 14. Close ────────────────────────────────────────────────────────────
    graph.close().await?;

    // ── Summary ──────────────────────────────────────────────────────────────
    let gotcha_candidates: usize = analyses
        .iter()
        .map(|a| a.todos.len() + a.unsafe_count as usize + a.unwrap_count as usize)
        .sum();
    let hotspot_count = git_signals
        .as_ref()
        .map(|g| g.hotspot_files.len())
        .unwrap_or(0);

    println!();
    println!("  ─────────────────────────────────────────────");
    println!(
        "  file records:          {:>4}   ({} parsed, {} skipped)",
        total_file_count, parse_count, skipped_count
    );
    println!(
        "  gotcha candidates:     {:>4}   (TODOs, unsafe, unwrap — parsed files only)",
        gotcha_candidates
    );
    println!("  dep records:           {:>4}", dep_signals.deps.len());
    println!(
        "  graph edges:           {:>4}   (import + co-change)",
        edge_count
    );
    println!(
        "  imported from CLAUDE.md: {:>2}",
        claude_import.records.len()
    );
    println!("  hotspot files:         {:>4}", hotspot_count);
    println!("  ─────────────────────────────────────────────");
    println!();
    println!(
        "  Total: {}ms · 0 tokens · 0 Claude calls",
        total_start.elapsed().as_millis()
    );
    println!();

    Ok(())
}

/// Build a minimal sessions-tree Record to persist a file content hash.
///
/// Key format: `parse:hash:<rel_path>` (Eventual durability, sessions tree).
/// Value: SHA-256 hex string (64 chars). Not user-visible knowledge.
fn make_hash_record(key: &str, hash: &str, device_id: Uuid, now: u64) -> Record {
    Record {
        key: key.to_string(),
        value: hash.to_string(),
        category: Category::Analytics,
        priority: Priority::Normal,
        tags: vec![],
        created_at: now,
        updated_at: now,
        ref_url: None,
        staleness: StalenessScore::fresh(),
        lifecycle: RecordLifecycle::Active,
        version: RecordVersion {
            device_id,
            logical_clock: 1,
            wall_clock: now,
        },
        quality: QualityScore::layer0_default(),
        access_count: 0,
        last_accessed: 0,
        source: RecordSource::StaticAnalysis,
        confidence: ConfidenceScore::for_new_record(&RecordSource::StaticAnalysis),
        gap_analysis_score: 0.0,
    }
}
