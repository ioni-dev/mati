use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::time::Instant;

use anyhow::{Context, Result};
use clap::Args;
use uuid::Uuid;

use mati_core::analysis::{
    build_edges, build_file_records, hash_and_parse_parallel, import_claude_md, mine_git_history,
    parse_dependencies, Walker,
};
use mati_core::graph::Graph;
use mati_core::scaffold::{install_hooks, write_claude_md_stub};
use mati_core::store::{
    Category, ConfidenceScore, FileRecord, GotchaRecord, Priority, QualityScore, Record,
    RecordLifecycle, RecordSource, RecordVersion, StalenessScore, StalenessSignal, Store,
    derive_slug,
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

    // Guard: mati init needs exclusive store access. If the daemon is running it
    // holds the SurrealKV lock — attempting Store::open would hang or fail with a
    // cryptic error. Detect this early and give a clear remediation message.
    {
        use crate::cli::daemon::{daemon_result, mati_root_for, DaemonResult};
        let mati_root = mati_root_for(&root)?;
        match daemon_result(&mati_root, "ping", serde_json::json!({})).await {
            DaemonResult::Ok(_) => {
                anyhow::bail!(
                    "mati daemon is running and holds the store lock.\n\
                     Stop it first, then re-run init:\n\n  \
                     mati daemon stop\n"
                );
            }
            DaemonResult::Unresponsive => {
                anyhow::bail!(
                    "mati daemon socket exists but is not responding (may hold the store lock).\n\
                     Stop it first:\n\n  mati daemon stop\n"
                );
            }
            DaemonResult::NotRunning | DaemonResult::StaleSocket => {
                // Safe to proceed — no daemon holds the lock.
            }
        }
    }

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

    // ── 1. Walk + Store::open (concurrent) ───────────────────────────────────
    // Store::open has no internal await points — it is synchronous SurrealKV
    // startup (~65ms). Spawning it before the walk lets it run on a separate
    // tokio worker thread while the walk occupies the current one (~434ms).
    let store_task = {
        let root = root.clone();
        tokio::spawn(async move { Store::open(&root).await })
    };

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

    // ── 2. Load stored mtimes (plain file, not KV) ───────────────────────────
    // Await the store that was opened concurrently with the walk above.
    let store = store_task.await.context("Store::open task panicked")??;

    // mtime_index.json sits next to knowledge.db — plain file I/O is much
    // faster than storing a ~4MB blob in SurrealKV.
    let mtime_index_path = store.root.join("mtime_index.json");
    let stored_mtimes: HashMap<String, u64> = std::fs::read(&mtime_index_path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();

    // ── 3–5. Parse + Git + Deps (parallel) ───────────────────────────────────
    // Git and deps only need walk output — run all three concurrently.
    // Wall time = max(parse, git, deps) instead of their sum (~252ms saved).
    let (((hp, parse_ms), (git_result, git_ms)), (dep_result, dep_ms)) = rayon::join(
        || {
            rayon::join(
                || {
                    let t = Instant::now();
                    (hash_and_parse_parallel(&files, &stored_mtimes), t.elapsed().as_millis())
                },
                || {
                    let t = Instant::now();
                    (mine_git_history(&root, &walked_paths), t.elapsed().as_millis())
                },
            )
        },
        || {
            let t = Instant::now();
            (parse_dependencies(&root, &files), t.elapsed().as_millis())
        },
    );

    let files_to_parse = hp.parsed_files;
    let analyses = hp.analyses;
    let parse_count = hp.parse_count;
    let skipped_count = hp.skipped_count;

    if skipped_count > 0 {
        println!(
            "  Mtime+parse (incremental)...   {:>4} changed  {:>4} skipped  {:>3}ms",
            parse_count,
            skipped_count,
            parse_ms
        );
    } else {
        println!(
            "  Mtime+parse (first run)...     {:>4} files             {:>3}ms",
            parse_count,
            parse_ms
        );
    }

    let git_signals = match git_result {
        Ok(g) => {
            println!(
                "  Mining git history...                              {:>4}ms",
                git_ms
            );
            Some(g)
        }
        Err(e) => {
            tracing::warn!("git history mining failed: {e}");
            println!(
                "  Mining git history...               skipped — {}",
                format!("{e:#}")
            );
            None
        }
    };

    // Always scan all walked files — manifest files (Cargo.toml, package.json,
    // go.mod) may be unchanged but are needed for correct dep records. On an
    // incremental run where no manifest changed, this is a fast no-op (<2ms).
    let dep_signals = match dep_result {
        Ok(d) => {
            println!(
                "  Parsing dependencies...              {:>4} deps    {:>4}ms",
                d.deps.len(),
                dep_ms
            );
            d
        }
        Err(e) => {
            tracing::warn!("dependency parsing failed: {e}");
            println!(
                "  Parsing dependencies...              skipped — {}",
                format!("{e:#}")
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
                "  Importing CLAUDE.md...               skipped — {}",
                format!("{e:#}")
            );
            mati_core::analysis::ClaudeMdImport { records: vec![] }
        }
    };

    // ── 7. Build file records (parsed files only) ────────────────────────────
    let mut file_records = build_file_records(&files_to_parse, &analyses, git_signals.as_ref(), now);

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

    // ── 8a. Build co-change gotchas from git signals ─────────────────────────
    // logical_clock offset is computed inside build_cochange_gotchas, starting
    // after CLAUDE.md imports. We pass the current offset and advance after.
    let mut logical_clock: u64 = claude_import.records.len() as u64;

    let cochange_gotchas: Vec<CoChangeGotcha> = match &git_signals {
        Some(signals) => build_cochange_gotchas(signals, device_id, logical_clock, now),
        None => vec![],
    };
    let cochange_count = cochange_gotchas.len();
    logical_clock += cochange_count as u64;

    let revert_gotchas: Vec<RevertGotcha> = match &git_signals {
        Some(signals) => build_revert_gotchas(signals, &signals.change_frequency, device_id, logical_clock, now),
        None => vec![],
    };
    let revert_count = revert_gotchas.len();
    logical_clock += revert_count as u64;

    let ownership_gotchas: Vec<OwnershipGotcha> = match &git_signals {
        Some(signals) => build_ownership_gotchas(signals, device_id, logical_clock, now),
        None => vec![],
    };
    let ownership_count = ownership_gotchas.len();
    logical_clock += ownership_count as u64;

    // ── 8b. Link co-change gotchas to file records (cold init only) ──────────
    // On cold init all file records are in memory — we can update gotcha_keys
    // before serialising. On warm re-init, only changed files are in memory;
    // their gotcha_keys are updated here. Unchanged files retain their keys from
    // the previous cold init (accepted limitation — refreshed on next cold init).
    if skipped_count == 0 {
        // Build path → [gotcha_key] reverse index.
        let mut path_to_cochange_keys: HashMap<String, Vec<String>> = HashMap::new();
        for cg in &cochange_gotchas {
            path_to_cochange_keys
                .entry(cg.source_path.clone())
                .or_default()
                .push(cg.key.clone());
        }
        // Remove all stale co-change keys first (idempotent upsert on cold init).
        for fr in file_records.iter_mut() {
            fr.gotcha_keys.retain(|k| !k.starts_with("gotcha:cochange:"));
        }
        // Inject fresh keys.
        for fr in file_records.iter_mut() {
            if let Some(keys) = path_to_cochange_keys.get(&fr.path) {
                fr.gotcha_keys.extend(keys.iter().cloned());
            }
        }

        // Link revert gotcha stubs to file records.
        let mut path_to_revert_keys: HashMap<String, Vec<String>> = HashMap::new();
        for rg in &revert_gotchas {
            path_to_revert_keys
                .entry(rg.source_path.clone())
                .or_default()
                .push(rg.key.clone());
        }
        for fr in file_records.iter_mut() {
            fr.gotcha_keys.retain(|k| !k.starts_with("gotcha:revert:"));
        }
        for fr in file_records.iter_mut() {
            if let Some(keys) = path_to_revert_keys.get(&fr.path) {
                fr.gotcha_keys.extend(keys.iter().cloned());
            }
        }

        // Link ownership gotcha stubs to file records.
        let mut path_to_ownership_keys: HashMap<String, Vec<String>> = HashMap::new();
        for og in &ownership_gotchas {
            path_to_ownership_keys
                .entry(og.source_path.clone())
                .or_default()
                .push(og.key.clone());
        }
        for fr in file_records.iter_mut() {
            fr.gotcha_keys.retain(|k| !k.starts_with("gotcha:ownership:"));
        }
        for fr in file_records.iter_mut() {
            if let Some(keys) = path_to_ownership_keys.get(&fr.path) {
                fr.gotcha_keys.extend(keys.iter().cloned());
            }
        }
    }

    // ── P3: Content hash staleness detection ─────────────────────────────────
    // On incremental runs: compare each changed file's new content_hash against
    // the stored FileRecord. Files whose hash changed get LinesChangedPct; their
    // co-change partners (≥10% line delta) will be flagged after put_batch.
    // Cold init (skipped_count == 0): no existing records to compare — skip.
    let mut lines_changed: HashMap<String, f32> = HashMap::new(); // path → ratio
    if skipped_count > 0 {
        for fr in &file_records {
            let (Some(new_hash), true) = (&fr.content_hash, fr.line_count > 0) else {
                continue; // non-parseable or empty file
            };
            let key = format!("file:{}", fr.path);
            if let Ok(Some(existing)) = store.get(&key).await {
                if let Some(old_fr) = existing.payload_as::<FileRecord>() {
                    if let Some(old_hash) = &old_fr.content_hash {
                        if old_hash != new_hash && old_fr.line_count > 0 {
                            let delta = fr.line_count.abs_diff(old_fr.line_count);
                            let ratio = delta as f32 / old_fr.line_count as f32;
                            lines_changed.insert(fr.path.clone(), ratio);
                        }
                    }
                }
            }
        }
    }

    // ── Prepare records for put_batch ────────────────────────────────────────

    // File records → Record structs (changed/new files only)
    let file_record_structs: Vec<Record> = file_records
        .iter()
        .enumerate()
        .map(|(i, fr)| {
            let key = format!("file:{}", fr.path);
            let mut rec = Record::layer0_file_stub(&key, device_id, logical_clock + i as u64, now);
            rec.payload = serde_json::to_value(fr).ok();
            // Doc-comment records: promote to additionalContext quality so they
            // surface when Claude reads those files immediately after `mati init`.
            // confidence=0.45 puts them in the 0.3–0.6 additionalContext band;
            // quality=0.40 (Acceptable) passes the quality >= 0.4 gate.
            // The deny+inject path requires confirmed=true which file records
            // never get — so there is no risk of false-positive hard denies.
            if !fr.purpose.is_empty() {
                rec.value = fr.purpose.clone();
                rec.quality = QualityScore::doc_comment_default();
                rec.confidence.value = 0.45;
            }
            if let Some(&ratio) = lines_changed.get(&fr.path) {
                rec.staleness.signals.push(StalenessSignal::LinesChangedPct(ratio));
            }
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

    // Write updated mtime index as a plain file (not a KV record).
    // Plain file I/O avoids SurrealKV overhead for large blobs.
    {
        let mut merged = stored_mtimes;
        merged.extend(hp.new_mtimes);
        if let Ok(blob) = serde_json::to_string(&merged) {
            let _ = std::fs::write(&mtime_index_path, blob);
        }
    }
    let hash_record_structs: Vec<Record> = vec![];

    // Co-change gotcha records — extracted from Vec<CoChangeGotcha>.
    let cochange_record_structs: Vec<Record> =
        cochange_gotchas.into_iter().map(|cg| cg.record).collect();

    // Revert gotcha stub records — extracted from Vec<RevertGotcha>.
    let revert_record_structs: Vec<Record> =
        revert_gotchas.into_iter().map(|rg| rg.record).collect();

    // Ownership gotcha stub records — extracted from Vec<OwnershipGotcha>.
    let ownership_record_structs: Vec<Record> =
        ownership_gotchas.into_iter().map(|og| og.record).collect();

    // ── 8c. Tombstone stale co-change gotchas (cold init only) ───────────────
    // On cold init all git signals are fresh. Any gotcha:cochange:* key in the
    // store that is NOT in the new set represents a pair that fell below
    // threshold or was removed — delete it before writing the new batch.
    if skipped_count == 0 {
        let new_keys: HashSet<&str> = cochange_record_structs
            .iter()
            .map(|r| r.key.as_str())
            .collect();
        match store.scan_prefix("gotcha:cochange:").await {
            Ok(existing) => {
                for rec in existing {
                    if !new_keys.contains(rec.key.as_str()) {
                        if let Err(e) = store.delete(&rec.key).await {
                            tracing::warn!("failed to delete stale co-change gotcha {}: {e}", rec.key);
                        }
                    }
                }
            }
            Err(e) => tracing::warn!("co-change tombstone scan failed (non-fatal): {e}"),
        }

        // Tombstone stale revert gotchas.
        let new_revert_keys: HashSet<&str> = revert_record_structs
            .iter()
            .map(|r| r.key.as_str())
            .collect();
        match store.scan_prefix("gotcha:revert:").await {
            Ok(existing) => {
                for rec in existing {
                    if !new_revert_keys.contains(rec.key.as_str()) {
                        if let Err(e) = store.delete(&rec.key).await {
                            tracing::warn!("failed to delete stale revert gotcha {}: {e}", rec.key);
                        }
                    }
                }
            }
            Err(e) => tracing::warn!("revert tombstone scan failed (non-fatal): {e}"),
        }

        // Tombstone stale ownership gotchas.
        let new_ownership_keys: HashSet<&str> = ownership_record_structs
            .iter()
            .map(|r| r.key.as_str())
            .collect();
        match store.scan_prefix("gotcha:ownership:").await {
            Ok(existing) => {
                for rec in existing {
                    if !new_ownership_keys.contains(rec.key.as_str()) {
                        if let Err(e) = store.delete(&rec.key).await {
                            tracing::warn!("failed to delete stale ownership gotcha {}: {e}", rec.key);
                        }
                    }
                }
            }
            Err(e) => tracing::warn!("ownership tombstone scan failed (non-fatal): {e}"),
        }
    }

    // Combine all records
    let all_records: Vec<Record> = claude_import
        .records
        .iter()
        .chain(file_record_structs.iter())
        .chain(dep_record_structs.iter())
        .chain(hash_record_structs.iter())
        .chain(cochange_record_structs.iter())
        .chain(revert_record_structs.iter())
        .chain(ownership_record_structs.iter())
        .cloned()
        .collect();

    let all_pairs: Vec<(&str, &Record)> = all_records
        .iter()
        .map(|r| (r.key.as_str(), r))
        .collect();

    // ── 9. put_batch (KV only — tantivy indexed after graph ops) ─────────────
    // Separating KV write from search indexing lets us profile each cost and
    // keeps the fsync path clean. Search index is built from in-memory records
    // (no KV re-scan) immediately after graph writes complete.
    let t = Instant::now();
    store.put_batch_kv_only(&all_pairs).await?;
    println!(
        "  Writing store (KV)...          {:>4} recs    {:>4}ms",
        all_records.len(),
        t.elapsed().as_millis(),
    );

    // ── 9a. Implicit staleness — co-change partner propagation ───────────────
    // Files that changed ≥10% of their lines may have invalidated knowledge for
    // their co-change partners even though those partners weren't edited. Push
    // LinkedFileChanged onto each partner's existing record so `mati stale`
    // surfaces the implicit risk.
    {
        let significantly_changed: Vec<&str> = lines_changed
            .iter()
            .filter(|(_, &ratio)| ratio >= 0.10)
            .map(|(path, _)| path.as_str())
            .collect();

        if !significantly_changed.is_empty() {
            let changed_set: HashSet<&str> = significantly_changed.iter().copied().collect();
            // Build partner → [changed_paths] map from co_change_pairs.
            let mut to_flag: HashMap<String, Vec<String>> = HashMap::new();
            for (a, b, _) in &co_change_pairs {
                if changed_set.contains(a.as_str()) && !changed_set.contains(b.as_str()) {
                    to_flag.entry(b.clone()).or_default().push(a.clone());
                }
                if changed_set.contains(b.as_str()) && !changed_set.contains(a.as_str()) {
                    to_flag.entry(a.clone()).or_default().push(b.clone());
                }
            }
            for (partner_path, changed_paths) in to_flag {
                let key = format!("file:{}", partner_path);
                if let Ok(Some(mut rec)) = store.get(&key).await {
                    for changed_path in changed_paths {
                        let signal = StalenessSignal::LinkedFileChanged { path: changed_path };
                        if !rec.staleness.signals.contains(&signal) {
                            rec.staleness.signals.push(signal);
                        }
                    }
                    let _ = store.put(&key, &rec).await;
                }
            }
        }
    }

    // ── 9b. Seed stats + stale cache (first run only) ────────────────────────
    // On incremental re-init, in-memory record slices are incomplete
    // (only changed files). Skip seeding — mati stats/stale will recompute
    // from the full store on their next call.
    if skipped_count == 0 {
        let gotcha_recs: Vec<Record> = claude_import
            .records
            .iter()
            .filter(|r| r.key.starts_with("gotcha:"))
            .cloned()
            .chain(cochange_record_structs.iter().cloned())
            .chain(revert_record_structs.iter().cloned())
            .chain(ownership_record_structs.iter().cloned())
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
        if let Err(e) = super::stale::seed_stale_cache(&store, &all_records).await {
            tracing::warn!("stale cache seed failed (non-fatal): {e}");
        }
    }

    // ── 10–11. Graph::load + add_edges_batch ─────────────────────────────────
    // Warm re-init with no new edges: skip the 14k-key prefix scan entirely.
    // Graph::empty wraps the Store without touching SurrealKV — close() and
    // store() still work. Cold init (skipped_count == 0) always loads because
    // mark_search_stale is only called on cold paths and is a no-op concern.
    let t = Instant::now();
    let mut graph = if layer0_edges.edges.is_empty() && skipped_count > 0 {
        Graph::empty(store)
    } else {
        let mut g = Graph::load(store).await?;
        g.add_edges_batch(&layer0_edges.edges).await?;
        g
    };
    println!(
        "  Graph load+edges...                              {:>4}ms",
        t.elapsed().as_millis()
    );

    // ── 11a. Search index — deferred to first MCP server startup ─────────────
    // Cold init: tantivy costs ~400ms to index 27k records. CLI commands scan
    // KV directly and never need full-text search. Only the MCP server (via
    // open_and_rebuild) needs tantivy — defer the rebuild there.
    // Warm re-init: existing index is still valid; changed files are few and
    // CLI commands tolerate slight search staleness.
    if skipped_count == 0 {
        graph.store().mark_search_stale();
        println!("  Search index...                (deferred to first MCP server startup)");
    }

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
    println!(
        "  co-change gotchas:     {:>4}   (auto-generated from git history)",
        cochange_count
    );
    println!(
        "  revert stubs:          {:>4}   (confirmed=false, surface in mati review)",
        revert_count
    );
    println!(
        "  ownership stubs:       {:>4}   (confirmed=false, surface in mati review)",
        ownership_count
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

// ── Co-change gotcha generation ───────────────────────────────────────────────

/// One auto-generated gotcha derived from a co-change signal.
struct CoChangeGotcha {
    /// The store key: `gotcha:cochange:{source}|{target}`
    key: String,
    /// Repo-relative path of the file this gotcha attaches to.
    source_path: String,
    /// The fully-built Record, ready for `put_batch`.
    record: Record,
}

/// Derive directional co-change gotchas from git history signals.
///
/// For each `(a, b, count)` pair already filtered at `ratio >= CO_CHANGE_THRESHOLD`:
/// - Computes `ratio_a = count / freq_a` and `ratio_b = count / freq_b`.
/// - Creates a gotcha on file A if `ratio_a >= 0.70`, and one on file B if
///   `ratio_b >= 0.70`. Asymmetric pairs produce only the constrained direction.
///
/// The rule text uses per-file denominators so the numbers are always accurate
/// from the reader's perspective: "changed together in 47/60 commits (78%)".
///
/// Volume cap: at most 5 gotchas per source file, ordered by co-change count.
fn build_cochange_gotchas(
    signals: &mati_core::analysis::GitSignals,
    device_id: Uuid,
    logical_clock_start: u64,
    now: u64,
) -> Vec<CoChangeGotcha> {
    const THRESHOLD: f64 = 0.70;
    const STRONG_RATIO: f64 = 0.90;
    const STRONG_COUNT: u32 = 20;
    const MAX_PER_FILE: usize = 5;
    // At least 3 co-changes required before generating a gotcha.
    // Eliminates "1/1 (100%)" noise on young repos where every commit
    // touched multiple files — the signal has no statistical weight.
    const MIN_COUNT: u32 = 3;

    // Expand each unordered pair into up to two directed edges.
    // Each candidate: (source_path, target_path, count, ratio_from_source_pov)
    let mut candidates: Vec<(String, String, u32, f64)> = Vec::new();

    for (a, b, count) in &signals.co_change_pairs {
        let freq_a = match signals.change_frequency.get(a) {
            Some(&f) if f > 0 => f as f64,
            _ => continue,
        };
        let freq_b = match signals.change_frequency.get(b) {
            Some(&f) if f > 0 => f as f64,
            _ => continue,
        };
        let ratio_a = *count as f64 / freq_a;
        let ratio_b = *count as f64 / freq_b;

        if ratio_a >= THRESHOLD && *count >= MIN_COUNT {
            candidates.push((a.clone(), b.clone(), *count, ratio_a));
        }
        if ratio_b >= THRESHOLD && *count >= MIN_COUNT {
            candidates.push((b.clone(), a.clone(), *count, ratio_b));
        }
    }

    // Sort: group by source file, then descending count within each group
    // so the cap keeps the strongest signals per file.
    candidates.sort_by(|x, y| x.0.cmp(&y.0).then(y.2.cmp(&x.2)));

    let mut per_source_count: HashMap<String, usize> = HashMap::new();
    let mut clock_offset: u64 = 0;
    let mut result: Vec<CoChangeGotcha> = Vec::new();

    for (source, target, count, ratio) in candidates {
        let seen = per_source_count.entry(source.clone()).or_insert(0);
        if *seen >= MAX_PER_FILE {
            continue;
        }
        *seen += 1;

        let freq_source = signals.change_frequency.get(&source).copied().unwrap_or(1);
        let pct = (ratio * 100.0).round() as u32;

        let rule = format!(
            "Always check `{target}` when editing this file — changed together in {count}/{freq_source} commits ({pct}%).",
        );
        let reason = "Co-change signal from git history — modifying one without the other is a known source of bugs.".to_string();

        let (quality, conf_value, severity) = if ratio >= STRONG_RATIO && count >= STRONG_COUNT {
            (QualityScore::cochange_strong(), 0.65_f32, Priority::High)
        } else {
            (QualityScore::cochange_default(), 0.45_f32, Priority::Normal)
        };

        let gotcha = GotchaRecord {
            rule: rule.clone(),
            reason,
            severity: severity.clone(),
            affected_files: vec![source.clone()],
            ref_url: None,
            discovered_session: now,
            confirmed: true,
        };

        let key = format!("gotcha:cochange:{source}|{target}");
        let mut rec = Record::layer0_file_stub(
            &key,
            device_id,
            logical_clock_start + clock_offset,
            now,
        );
        rec.category = Category::Gotcha;
        rec.source = RecordSource::StaticAnalysis;
        rec.priority = severity;
        rec.value = rule;
        rec.quality = quality;
        rec.confidence.value = conf_value;
        rec.tags = vec!["co-change".to_string(), "auto-generated".to_string()];
        rec.payload = serde_json::to_value(&gotcha).ok();
        clock_offset += 1;

        result.push(CoChangeGotcha {
            key,
            source_path: source,
            record: rec,
        });
    }

    result
}

// ── Revert gotcha generation ──────────────────────────────────────────────────

/// One auto-generated gotcha stub derived from a revert signal.
struct RevertGotcha {
    /// The store key: `gotcha:revert:{path}`
    key: String,
    /// Repo-relative path of the file this gotcha attaches to.
    source_path: String,
    /// The fully-built Record, ready for `put_batch`.
    record: Record,
}

/// Derive revert-instability gotcha stubs from git history signals.
///
/// A `confirmed=false` stub is created for each file with a revert rate >=
/// `MIN_REVERT_RATE` AND at least `MIN_REVERTS` absolute revert commits.
/// The absolute floor prevents a single revert on a new file (e.g. 1/5 = 20%)
/// from triggering. These surface in `mati review` for developer confirmation.
fn build_revert_gotchas(
    signals: &mati_core::analysis::GitSignals,
    change_frequency: &std::collections::HashMap<String, u32>,
    device_id: Uuid,
    logical_clock_start: u64,
    now: u64,
) -> Vec<RevertGotcha> {
    const MIN_REVERTS: u32 = 2;
    const MIN_REVERT_RATE: f32 = 0.05;

    let mut candidates: Vec<(&String, u32, f32)> = signals
        .revert_counts
        .iter()
        .filter_map(|(path, &count)| {
            if count < MIN_REVERTS {
                return None;
            }
            let total = *change_frequency.get(path).unwrap_or(&0);
            if total == 0 {
                return None;
            }
            let rate = count as f32 / total as f32;
            if rate >= MIN_REVERT_RATE {
                Some((path, count, rate))
            } else {
                None
            }
        })
        .collect();

    // Highest rate first; break ties by count then alphabetically.
    candidates.sort_by(|a, b| {
        b.2.partial_cmp(&a.2)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| b.1.cmp(&a.1))
            .then_with(|| a.0.cmp(b.0))
    });

    let mut clock_offset: u64 = 0;
    let mut result: Vec<RevertGotcha> = Vec::new();

    for (path, count, rate) in candidates {
        let pct = (rate * 100.0).round() as u32;
        let rule = format!(
            "High revert rate ({pct}% of commits, {count} reverts) — this interface has been broken and undone repeatedly. Test carefully before touching.",
        );
        let reason =
            "Repeated reverts in git history indicate contested or fragile logic.".to_string();

        let gotcha = GotchaRecord {
            rule: rule.clone(),
            reason,
            severity: Priority::Normal,
            affected_files: vec![path.clone()],
            ref_url: None,
            discovered_session: now,
            confirmed: false,
        };

        let key = format!("gotcha:revert:{path}");
        let mut rec = Record::layer0_file_stub(
            &key,
            device_id,
            logical_clock_start + clock_offset,
            now,
        );
        rec.category = Category::Gotcha;
        rec.source = RecordSource::StaticAnalysis;
        rec.priority = Priority::Normal;
        rec.value = rule;
        rec.quality = QualityScore::cochange_default();
        rec.confidence.value = 0.35;
        rec.tags = vec!["revert".to_string(), "auto-generated".to_string()];
        rec.payload = serde_json::to_value(&gotcha).ok();
        clock_offset += 1;

        result.push(RevertGotcha {
            key,
            source_path: path.clone(),
            record: rec,
        });
    }

    result
}

// ── Ownership concentration gotcha generation ─────────────────────────────────

/// One auto-generated gotcha stub derived from an ownership concentration signal.
struct OwnershipGotcha {
    /// The store key: `gotcha:ownership:{path}`
    key: String,
    /// Repo-relative path of the file this gotcha attaches to.
    source_path: String,
    /// The fully-built Record, ready for `put_batch`.
    record: Record,
}

/// Derive ownership-concentration gotcha stubs from git history signals.
///
/// A `confirmed=false` stub is created for each hotspot file where a single
/// author contributed >= `CONCENTRATION_THRESHOLD` of all commits. This signals
/// a knowledge silo: if that person leaves, context for the file is lost.
fn build_ownership_gotchas(
    signals: &mati_core::analysis::GitSignals,
    device_id: Uuid,
    logical_clock_start: u64,
    now: u64,
) -> Vec<OwnershipGotcha> {
    // >80% of commits by one author — strong silo signal.
    const CONCENTRATION_THRESHOLD: f64 = 0.80;
    // Require at least 5 commits before flagging — avoids noise on new files.
    const MIN_COMMITS: u32 = 5;

    let hotspot_set: std::collections::HashSet<&String> =
        signals.hotspot_files.iter().collect();

    let mut candidates: Vec<(&String, String, u32, f64)> = Vec::new();

    for (path, author_counts) in &signals.author_commit_counts {
        // Only flag hotspot files — low-traffic files aren't a meaningful silo risk.
        if !hotspot_set.contains(path) {
            continue;
        }

        let total: u32 = author_counts.values().sum();
        if total < MIN_COMMITS {
            continue;
        }

        if let Some((top_author, &top_count)) =
            author_counts.iter().max_by_key(|(_, &c)| c)
        {
            let ratio = top_count as f64 / total as f64;
            if ratio >= CONCENTRATION_THRESHOLD {
                candidates.push((path, top_author.clone(), top_count, ratio));
            }
        }
    }

    // Highest concentration first; break ties alphabetically by path.
    candidates.sort_by(|a, b| {
        b.3.partial_cmp(&a.3)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.0.cmp(b.0))
    });

    let mut clock_offset: u64 = 0;
    let mut result: Vec<OwnershipGotcha> = Vec::new();

    for (path, top_author, top_count, ratio) in candidates {
        let total = signals
            .change_frequency
            .get(path)
            .copied()
            .unwrap_or(top_count);
        let pct = (ratio * 100.0).round() as u32;

        let rule = format!(
            "{pct}% of commits by {top_author} ({top_count}/{total}) — key person dependency on this hotspot file.",
        );
        let reason = "Single-author dominance on a high-traffic file is a knowledge silo risk — context may be lost if that person is unavailable.".to_string();

        let gotcha = GotchaRecord {
            rule: rule.clone(),
            reason,
            severity: Priority::Normal,
            affected_files: vec![path.clone()],
            ref_url: None,
            discovered_session: now,
            confirmed: false,
        };

        let key = format!("gotcha:ownership:{path}");
        let mut rec = Record::layer0_file_stub(
            &key,
            device_id,
            logical_clock_start + clock_offset,
            now,
        );
        rec.category = Category::Gotcha;
        rec.source = RecordSource::StaticAnalysis;
        rec.priority = Priority::Normal;
        rec.value = rule;
        rec.quality = QualityScore::cochange_default();
        rec.confidence.value = 0.40;
        rec.tags = vec!["ownership".to_string(), "auto-generated".to_string()];
        rec.payload = serde_json::to_value(&gotcha).ok();
        clock_offset += 1;

        result.push(OwnershipGotcha {
            key,
            source_path: path.clone(),
            record: rec,
        });
    }

    result
}

/// Build a minimal sessions-tree Record for a parse-cache blob.
///
/// Used for `parse:mtime_index` (JSON blob) — Eventual durability, sessions tree.
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
        payload: None,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use mati_core::analysis::GitSignals;

    fn make_signals(pairs: &[(&str, &str, u32)], freq: &[(&str, u32)]) -> GitSignals {
        let mut signals = GitSignals::empty();
        for (a, b, count) in pairs {
            signals.co_change_pairs.push((a.to_string(), b.to_string(), *count));
        }
        for (path, f) in freq {
            signals.change_frequency.insert(path.to_string(), *f);
        }
        signals
    }

    fn dummy() -> (Uuid, u64) {
        (Uuid::new_v4(), 0)
    }

    // ── Rule text format ──────────────────────────────────────────────────────

    #[test]
    fn rule_text_contains_ratio_and_pct() {
        let (dev, now) = dummy();
        let signals = make_signals(&[("a.rs", "b.rs", 9)], &[("a.rs", 10), ("b.rs", 10)]);
        let gotchas = build_cochange_gotchas(&signals, dev, 0, now);
        // Both symmetric → both get a gotcha.
        let ga = gotchas.iter().find(|g| g.source_path == "a.rs").unwrap();
        assert!(ga.record.value.contains("9/10"), "rule should contain 9/10");
        assert!(ga.record.value.contains("90%"), "rule should contain 90%");
        assert!(ga.record.value.contains("`b.rs`"), "rule should name the target");
    }

    // ── Directionality ────────────────────────────────────────────────────────

    #[test]
    fn symmetric_pair_produces_two_gotchas() {
        let (dev, now) = dummy();
        let signals = make_signals(&[("a.rs", "b.rs", 8)], &[("a.rs", 10), ("b.rs", 10)]);
        let gotchas = build_cochange_gotchas(&signals, dev, 0, now);
        assert_eq!(gotchas.len(), 2);
        assert!(gotchas.iter().any(|g| g.source_path == "a.rs"));
        assert!(gotchas.iter().any(|g| g.source_path == "b.rs"));
    }

    #[test]
    fn asymmetric_pair_only_constrained_file_gets_gotcha() {
        // a: 30 commits, b: 4 commits, pair: 4.
        // ratio_a = 4/30 = 13% (below 0.70) → no gotcha on a.
        // ratio_b = 4/4  = 100% (above 0.70) AND count=4 >= MIN_COUNT → gotcha on b only.
        let (dev, now) = dummy();
        let signals = make_signals(&[("a.rs", "b.rs", 4)], &[("a.rs", 30), ("b.rs", 4)]);
        let gotchas = build_cochange_gotchas(&signals, dev, 0, now);
        assert_eq!(gotchas.len(), 1);
        assert_eq!(gotchas[0].source_path, "b.rs");
        assert!(gotchas[0].record.value.contains("`a.rs`"));
        assert!(gotchas[0].record.value.contains("4/4"));
        assert!(gotchas[0].record.value.contains("100%"));
    }

    #[test]
    fn key_is_directional() {
        let (dev, now) = dummy();
        let signals = make_signals(&[("a.rs", "b.rs", 4)], &[("a.rs", 30), ("b.rs", 4)]);
        let gotchas = build_cochange_gotchas(&signals, dev, 0, now);
        assert_eq!(gotchas[0].key, "gotcha:cochange:b.rs|a.rs");
    }

    // ── Quality/confidence tiers ──────────────────────────────────────────────

    #[test]
    fn normal_signal_gets_additionalcontext_tier() {
        let (dev, now) = dummy();
        // ratio = 8/10 = 80%, count = 8 — strong ratio but count < 20, so normal tier.
        let signals = make_signals(&[("a.rs", "b.rs", 8)], &[("a.rs", 10), ("b.rs", 10)]);
        let gotchas = build_cochange_gotchas(&signals, dev, 0, now);
        let ga = gotchas.iter().find(|g| g.source_path == "a.rs").unwrap();
        assert!((ga.record.confidence.value - 0.45).abs() < 0.001);
        assert!((ga.record.quality.value - 0.40).abs() < 0.001);
    }

    #[test]
    fn strong_signal_gets_inject_tier() {
        let (dev, now) = dummy();
        // ratio = 95%, count = 21 — clears both strong thresholds.
        let signals = make_signals(&[("a.rs", "b.rs", 20)], &[("a.rs", 21), ("b.rs", 21)]);
        let gotchas = build_cochange_gotchas(&signals, dev, 0, now);
        let ga = gotchas.iter().find(|g| g.source_path == "a.rs").unwrap();
        assert!((ga.record.confidence.value - 0.65).abs() < 0.001);
        assert!((ga.record.quality.value - 0.60).abs() < 0.001);
    }

    // ── Volume cap ────────────────────────────────────────────────────────────

    #[test]
    fn volume_cap_is_five_per_source() {
        let (dev, now) = dummy();
        // hub.rs always co-changes with 7 other files — should be capped at 5.
        // All counts >= 3 to clear MIN_COUNT; ratios all = 1.0 (always together).
        let pairs: Vec<(&str, &str, u32)> = (0..7)
            .map(|i| ("hub.rs", Box::leak(format!("dep{i}.rs").into_boxed_str()) as &str, 10 - i as u32))
            .collect();
        let mut freqs: Vec<(&str, u32)> = vec![("hub.rs", 10)];
        for i in 0..7u32 {
            freqs.push((Box::leak(format!("dep{i}.rs").into_boxed_str()), 10 - i));
        }
        let signals = make_signals(&pairs, &freqs);
        let gotchas = build_cochange_gotchas(&signals, dev, 0, now);
        let hub_gotchas: Vec<_> = gotchas.iter().filter(|g| g.source_path == "hub.rs").collect();
        assert!(hub_gotchas.len() <= 5, "expected ≤ 5 gotchas for hub.rs, got {}", hub_gotchas.len());
    }

    // ── GotchaRecord payload ──────────────────────────────────────────────────

    #[test]
    fn payload_deserializes_as_gotcha_record() {
        let (dev, now) = dummy();
        let signals = make_signals(&[("a.rs", "b.rs", 8)], &[("a.rs", 10), ("b.rs", 10)]);
        let gotchas = build_cochange_gotchas(&signals, dev, 0, now);
        let ga = gotchas.iter().find(|g| g.source_path == "a.rs").unwrap();
        let gr: GotchaRecord = ga.record.payload_as().expect("payload should deserialize");
        assert!(gr.confirmed);
        assert!(gr.rule.contains("b.rs"));
        assert_eq!(gr.affected_files, vec!["a.rs"]);
    }

    // ── Empty / no git ────────────────────────────────────────────────────────

    #[test]
    fn empty_signals_produce_no_gotchas() {
        let (dev, now) = dummy();
        let signals = GitSignals::empty();
        let gotchas = build_cochange_gotchas(&signals, dev, 0, now);
        assert!(gotchas.is_empty());
    }
}
