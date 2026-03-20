use std::path::PathBuf;
use std::time::Instant;

use anyhow::Result;
use clap::Args;
use uuid::Uuid;

use mati_core::analysis::{
    build_edges, build_file_records, import_claude_md, mine_git_history, parse_dependencies,
    parse_files_parallel, Walker,
};
use mati_core::graph::Graph;
use mati_core::scaffold::{install_hooks, write_claude_md_stub};
use mati_core::store::{derive_slug, Category, Record, RecordSource, Store};

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
    let file_count = files.len();
    println!(
        "  Scanning with ignore...              {:>4} files   {:>4}ms",
        file_count,
        t.elapsed().as_millis()
    );

    // ── 2. Parse ─────────────────────────────────────────────────────────────
    let t = Instant::now();
    let analyses = parse_files_parallel(&files);
    println!(
        "  Parsing with tree-sitter...                      {:>4}ms",
        t.elapsed().as_millis()
    );

    // ── 3. Git history ───────────────────────────────────────────────────────
    let t = Instant::now();
    let walked_paths: std::collections::HashSet<String> =
        files.iter().map(|f| f.rel_path.clone()).collect();
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

    // ── 4. Dependencies ──────────────────────────────────────────────────────
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

    // ── 5. CLAUDE.md import ──────────────────────────────────────────────────
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

    // ── 6. Build file records ────────────────────────────────────────────────
    let file_records = build_file_records(&files, &analyses, git_signals.as_ref(), now);

    // ── 7. Build edges ───────────────────────────────────────────────────────
    let t = Instant::now();
    let co_change_pairs: Vec<(String, String, u32)> = git_signals
        .as_ref()
        .map(|g| g.co_change_pairs.clone())
        .unwrap_or_default();
    let layer0_edges = build_edges(&files, &analyses, &co_change_pairs);
    let edge_count = layer0_edges.edges.len();
    println!(
        "  Building graph edges...              {:>4} edges   {:>4}ms",
        edge_count,
        t.elapsed().as_millis()
    );

    // ── Prepare all records for put_batch ────────────────────────────────────
    let mut logical_clock: u64 = claude_import.records.len() as u64;

    // File records → Record structs
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

    // Combine all records
    let all_records: Vec<Record> = claude_import
        .records
        .iter()
        .chain(file_record_structs.iter())
        .chain(dep_record_structs.iter())
        .cloned()
        .collect();

    let all_pairs: Vec<(&str, &Record)> = all_records
        .iter()
        .map(|r| (r.key.as_str(), r))
        .collect();

    // ── 8–9. Store::open + put_batch ─────────────────────────────────────────
    let store = Store::open(&root).await?;
    store.put_batch(&all_pairs).await?;

    // ── 9a. Seed stats snapshot from in-memory records ────────────────────────
    // Data is already in memory — free to compute. Ensures `mati stats` after
    // init is O(1) (write-seq match) instead of triggering a full rescan.
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
        "  file records:          {:>4}   (stubs + entry points)",
        file_count
    );
    println!(
        "  gotcha candidates:     {:>4}   (TODOs, unsafe, unwrap)",
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
