use super::*;

pub async fn run(args: InitArgs) -> Result<()> {
    let requested = match &args.path {
        Some(p) => p.clone(),
        None => std::env::current_dir()?,
    };
    // `--path` names a repository, not a scope: resolve it through git the same
    // way the slug is derived, so a subdir walks up to its repo root. Canonicalize
    // first — it is what rejects a path that does not exist, which `slug_root`'s
    // non-git fallback silently tolerates.
    let requested = std::fs::canonicalize(&requested)?;
    let root = slug_root(&requested);

    let slug = derive_slug(&root);
    let project_name = root
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "unknown".to_string());

    println!();
    println!("◈  mati — project: {}  (slug: {})", project_name, slug);
    // A path inside a repo indexes the whole repo, not that path. Say so, so the
    // wider scope is never silent.
    if requested != root {
        println!(
            "   indexing repo root {}  (requested {})",
            root.display(),
            requested.display()
        );
    }
    println!();

    // Hooks that can never reach a daemon only fail open; refuse before writing them.
    if let Some(problem) =
        crate::cli::daemon::socket_path_problem(&crate::cli::daemon::mati_root_for(&root)?)
    {
        anyhow::bail!(problem);
    }

    // ── 0. Scaffold: agent hooks (no store access needed) ───────────────
    // Install hooks BEFORE any store operations so they succeed even when
    // the daemon holds the store lock. Hooks only write files to disk.
    let (claude_installed, codex_installed) = install_scaffold(&root, &args)?;

    // Guard: mati init needs exclusive store access. If the daemon is running it
    // holds the SurrealKV lock — attempting Store::open would hang or fail with a
    // cryptic error. Detect this early and give a clear remediation message.
    {
        use crate::cli::daemon::{daemon_result, mati_root_for, DaemonResult};
        let mati_root = mati_root_for(&root)?;
        match daemon_result(&mati_root, "ping", serde_json::json!({})).await {
            DaemonResult::Ok(_) => {
                // Check who owns the socket to give accurate remediation advice.
                let owner = crate::cli::daemon::read_pid_file(&mati_root)
                    .map(|(_, o)| o)
                    .unwrap_or_else(|| "unknown".to_string());
                let remedy = if owner == "mcp" {
                    "close your Claude Code / Codex session, then run `mati init`"
                } else {
                    "mati daemon stop && mati init"
                };
                // `--claude`/`--codex` asked for the scaffold, and it is written.
                if claude_installed || codex_installed {
                    println!("  Hook scaffold updated. Store not re-scanned: the mati daemon holds the lock.");
                    println!("  To re-scan: {remedy}");
                    println!();
                    return Ok(());
                }
                anyhow::bail!(
                    "mati daemon is running and holds the store lock.\nTo re-init: {remedy}\n"
                );
            }
            DaemonResult::Unresponsive | DaemonResult::PermissionDenied => {
                if claude_installed || codex_installed {
                    println!("  Hook scaffold updated successfully.");
                    println!();
                }
                anyhow::bail!(
                    "mati daemon socket exists but is not responding (may hold the store lock).\n\
                     Hook scaffold was updated. Stop the daemon first:\n\n  mati daemon stop\n"
                );
            }
            DaemonResult::NotRunning | DaemonResult::StaleSocket => {
                // No daemon socket — but a daemon may be starting (race window
                // between spawn and socket bind). Check the mati.starting sentinel.
                let starting = mati_root.join("mati.starting");
                if let Ok(content) = std::fs::read_to_string(&starting) {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    // Semantics must match try_claim_starting_sentinel:
                    //   - PID alive → always active (owner is running)
                    //   - PID dead + recent → stale (owner crashed, safe to proceed)
                    //   - No PID (legacy) → active only if recent
                    let active =
                        if let Some((_ts, pid)) = crate::cli::daemon::parse_sentinel(&content) {
                            mati_core::mcp::metadata::is_pid_alive(pid)
                        } else if let Ok(ts) = content.trim().parse::<u64>() {
                            now.saturating_sub(ts) < crate::cli::daemon::STARTING_STALE_SECS
                        } else {
                            false
                        };
                    if active {
                        if claude_installed || codex_installed {
                            println!("  Hook scaffold updated successfully.");
                            println!();
                        }
                        anyhow::bail!(
                            "a mati daemon is starting and may hold the store lock.\n\
                             Hook scaffold was updated. Wait a few seconds, then re-run:\n\n  mati init\n"
                        );
                    }
                }
            }
        }
    }

    let total_start = Instant::now();
    let device_id = mati_core::store::stable_device_id();
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
                    (
                        hash_and_parse_parallel(&files, &stored_mtimes),
                        t.elapsed().as_millis(),
                    )
                },
                || {
                    let t = Instant::now();
                    (
                        mine_git_history(&root, &walked_paths),
                        t.elapsed().as_millis(),
                    )
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
            parse_count, skipped_count, parse_ms
        );
    } else {
        println!(
            "  Mtime+parse (first run)...     {:>4} files             {:>3}ms",
            parse_count, parse_ms
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
            println!("  Mining git history...               skipped — {e:#}");
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
            println!("  Parsing dependencies...              skipped — {e:#}");
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
            println!("  Importing CLAUDE.md...               skipped — {e:#}");
            mati_core::analysis::ClaudeMdImport { records: vec![] }
        }
    };

    // ── 7. Build file records (parsed files only) ────────────────────────────
    let mut file_records =
        build_file_records(&files_to_parse, &analyses, git_signals.as_ref(), now);

    // ── 8. Build edges (parsed files only) ───────────────────────────────────
    let t = Instant::now();
    let co_change_pairs: Vec<(String, String, u32)> = git_signals
        .as_ref()
        .map(|g| g.co_change_pairs.clone())
        .unwrap_or_default();
    let mut layer0_edges = build_edges(&files_to_parse, &analyses, &co_change_pairs);
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
        Some(signals) => build_revert_gotchas(
            signals,
            &signals.change_frequency,
            device_id,
            logical_clock,
            now,
        ),
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

    // ── 8b. Link gotchas to file records ─────────────────────────────────────
    // Always runs for file records currently in memory (changed files on warm
    // re-init, all files on cold init). Unchanged files not in memory retain
    // their gotcha_keys from the previous init (they aren't overwritten here).
    {
        // Build path → [gotcha_key] reverse index.
        let mut path_to_cochange_keys: HashMap<String, Vec<String>> = HashMap::new();
        for cg in &cochange_gotchas {
            path_to_cochange_keys
                .entry(cg.source_path.clone())
                .or_default()
                .push(cg.key.clone());
        }
        // Remove all stale co-change keys first (idempotent upsert).
        for fr in file_records.iter_mut() {
            fr.gotcha_keys
                .retain(|k| !k.starts_with("gotcha:cochange:"));
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
            fr.gotcha_keys
                .retain(|k| !k.starts_with("gotcha:ownership:"));
        }
        for fr in file_records.iter_mut() {
            if let Some(keys) = path_to_ownership_keys.get(&fr.path) {
                fr.gotcha_keys.extend(keys.iter().cloned());
            }
        }
    }

    // One scan feeds both the rename migration and the §8c back-fill below —
    // the migration adds no store reads on the common (no-rename) path.
    let mut all_gotchas = store.scan_prefix("gotcha:").await.unwrap_or_default();

    // ── 8b-rename. Follow git renames onto developer gotchas ─────────────────
    // A gotcha binds to a file by the exact `affected_files` string, so a
    // `git mv` silently unbinds it: `file:<new>` is minted fresh with no
    // gotcha_keys and `file:<old>` is orphaned. Enforcement does not merely
    // lapse — `StalenessAnalyzer` sets `FileDeleted` on the orphan (the old
    // path no longer exists on disk) and `hooks::decide` treats that literal
    // signal, not the tombstone tier by itself, as its one enforcement
    // bypass. So the gate still degrades to an explicit allow here — because
    // the file is gone, not merely because its staleness crossed 0.9.
    //
    // Runs before §8c so the back-fill sees the re-keyed `affected_files` and
    // links the gotcha onto the `file:<new>` record this run is about to write.
    {
        let renames: &[(String, String)] = git_signals
            .as_ref()
            .map(|g| g.recent_renames.as_slice())
            .unwrap_or(&[]);
        let t = Instant::now();
        let applied = migrate_renamed_gotchas(&store, &root, renames, &mut all_gotchas).await;
        if !applied.is_empty() {
            println!(
                "  Following git renames...       {:>4} gotchas {:>4}ms",
                applied.len(),
                t.elapsed().as_millis()
            );
            for a in &applied {
                for (old, new) in &a.followed {
                    println!("    {old} → {new}  ({})", a.key);
                }
            }
            // `mati sandbox compile` reads `affected_files` live, but the L3
            // deny floor already materialized into settings.local.json still
            // names the old path — and the drift guard treats the vanished old
            // entry as a protection whose tag is gone, so the re-sync needs
            // --force. Say so rather than leaving a silently stale floor.
            if applied.iter().any(|a| a.sandbox_tagged) {
                println!(
                    "    note: a re-keyed gotcha is sandbox-tagged — run \
                     `mati sandbox compile --apply --force` to move the deny floor"
                );
            }
        }
    }

    // ── 8b-value. Repair values stored as "<rule> because Because <reason>" ──
    {
        let mut repaired = 0;
        for rec in all_gotchas.iter_mut() {
            // The write path forces `Active`; a tombstone must stay one.
            if !matches!(rec.lifecycle, RecordLifecycle::Active) {
                continue;
            }
            let Some(value) = mati_core::store::gotcha_ops::legacy_value_fix(rec) else {
                continue;
            };
            let files = rec
                .payload_as::<GotchaRecord>()
                .map(|g| g.affected_files)
                .unwrap_or_default();
            rec.value = value;
            rec.updated_at = now;
            rec.version.logical_clock += 1;
            rec.version.wall_clock = now;
            match mati_core::store::gotcha_ops::apply_gotcha_write(
                &store, &root, rec, &files, &files, false,
            )
            .await
            {
                Ok(()) => repaired += 1,
                Err(e) => tracing::warn!("init: value repair failed for {}: {e}", rec.key),
            }
        }
        if repaired > 0 {
            println!("  Repaired gotcha wording...     {repaired:>4} gotchas");
        }
    }

    // ── 8c. Back-fill developer-created gotcha keys ──────────────────────────
    // Auto-generated gotchas (cochange, revert, ownership) were handled above.
    // Developer-created gotchas added via `mati gotcha add` before the file
    // record existed were silently dropped by sync_gotcha_file_links (the file
    // record didn't exist at confirm time). Re-scan all non-auto gotcha records
    // and merge their affected_files into the file records being written now.
    {
        let mut path_to_manual_keys: HashMap<String, Vec<String>> = HashMap::new();
        for rec in &all_gotchas {
            if !matches!(rec.lifecycle, RecordLifecycle::Active) {
                continue;
            }
            if is_auto_gotcha(&rec.key) {
                continue;
            }
            if let Some(g) = rec.payload_as::<GotchaRecord>() {
                for file_path in &g.affected_files {
                    path_to_manual_keys
                        .entry(file_path.clone())
                        .or_default()
                        .push(rec.key.clone());
                }
            }
        }
        for fr in file_records.iter_mut() {
            if let Some(keys) = path_to_manual_keys.get(&fr.path) {
                for k in keys {
                    if !fr.gotcha_keys.contains(k) {
                        fr.gotcha_keys.push(k.clone());
                    }
                }
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
            // Files with linked co-change gotchas get at least Acceptable quality
            // even without a doc comment — co-change is objective git data (confirmed=true).
            // This ensures the pre-read hook surfaces additionalContext for coupled files
            // regardless of whether they have a module-level doc comment.
            if rec.quality.value < 0.40
                && fr
                    .gotcha_keys
                    .iter()
                    .any(|k| k.starts_with("gotcha:cochange:"))
            {
                rec.quality = QualityScore::doc_comment_default();
                if rec.confidence.value < 0.45 {
                    rec.confidence.value = 0.45;
                }
            }
            if let Some(&ratio) = lines_changed.get(&fr.path) {
                rec.staleness
                    .signals
                    .push(StalenessSignal::LinesChangedPct(ratio));
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
            let key = mati_core::analysis::dep_record_key(dep);
            let mut rec = Record::layer0_file_stub(&key, device_id, logical_clock + i as u64, now);
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
                format!("ecosystem:{}", dep.ecosystem.as_str()),
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
                            tracing::warn!(
                                "failed to delete stale co-change gotcha {}: {e}",
                                rec.key
                            );
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
                            tracing::warn!(
                                "failed to delete stale ownership gotcha {}: {e}",
                                rec.key
                            );
                        }
                    }
                }
            }
            Err(e) => tracing::warn!("ownership tombstone scan failed (non-fatal): {e}"),
        }

        let new_dep_keys: HashSet<&str> =
            dep_record_structs.iter().map(|r| r.key.as_str()).collect();
        match store.scan_prefix("dep:").await {
            Ok(existing) => {
                for key in stale_dependency_keys(&existing, &new_dep_keys) {
                    if let Err(e) = store.delete(&key).await {
                        tracing::warn!("failed to delete stale dependency record {}: {e}", key);
                    }
                }
            }
            Err(e) => tracing::warn!("dependency cleanup scan failed (non-fatal): {e}"),
        }
    }

    // ── 8c. CODEOWNERS ownership candidates (idea 2.2) ───────────────────────
    let repo_files: Vec<String> = file_record_structs
        .iter()
        .filter_map(|record| record.key.strip_prefix("file:").map(str::to_string))
        .collect();
    let codeowners_record_structs =
        build_codeowners_candidates(&root, &store, &repo_files, device_id, logical_clock, now)
            .await;

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
        .chain(codeowners_record_structs.iter())
        .cloned()
        .collect();

    let all_pairs: Vec<(&str, &Record)> = all_records.iter().map(|r| (r.key.as_str(), r)).collect();

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

    // ── 9a-pre. Patch gotcha_keys on skipped (unchanged) file records ────────
    // Incremental re-init only has changed files in memory. Skipped files that
    // are affected by new cochange/revert/ownership gotchas need their
    // gotcha_keys updated in the store directly.
    if skipped_count > 0 {
        let in_memory_paths: HashSet<String> =
            file_records.iter().map(|fr| fr.path.clone()).collect();

        // Build path -> [gotcha_key] for ALL auto-generated gotchas.
        // Include both in-memory records AND existing store records (from prior inits).
        let mut path_to_all_keys: HashMap<String, Vec<String>> = HashMap::new();
        for rec_vec in [
            &cochange_record_structs,
            &revert_record_structs,
            &ownership_record_structs,
        ] {
            for rec in rec_vec.iter() {
                if let Some(g) = rec.payload_as::<GotchaRecord>() {
                    for file_path in &g.affected_files {
                        path_to_all_keys
                            .entry(file_path.clone())
                            .or_default()
                            .push(rec.key.clone());
                    }
                }
            }
        }
        // Also scan store for gotchas from prior inits not in current batch.
        for prefix in &["gotcha:cochange:", "gotcha:revert:", "gotcha:ownership:"] {
            if let Ok(stored) = store.scan_prefix(prefix).await {
                for rec in &stored {
                    if !matches!(rec.lifecycle, RecordLifecycle::Active) {
                        continue;
                    }
                    if let Some(g) = rec.payload_as::<GotchaRecord>() {
                        for file_path in &g.affected_files {
                            let keys = path_to_all_keys.entry(file_path.clone()).or_default();
                            if !keys.contains(&rec.key) {
                                keys.push(rec.key.clone());
                            }
                        }
                    }
                }
            }
        }

        // For paths NOT in memory, load from store and patch gotcha_keys.
        let mut patched: Vec<(String, Record)> = Vec::new();
        for (path, gotcha_keys) in &path_to_all_keys {
            if in_memory_paths.contains(path) {
                continue; // Already handled by in-memory loop above.
            }
            let file_key = format!("file:{path}");
            if let Ok(Some(mut record)) = store.get(&file_key).await {
                if let Some(ref mut payload) = record.payload {
                    if let Some(obj) = payload.as_object_mut() {
                        let existing: Vec<String> = obj
                            .get("gotcha_keys")
                            .and_then(|v| serde_json::from_value(v.clone()).ok())
                            .unwrap_or_default();
                        let mut merged: Vec<String> = existing
                            .into_iter()
                            .filter(|k| {
                                !k.starts_with("gotcha:cochange:")
                                    && !k.starts_with("gotcha:revert:")
                                    && !k.starts_with("gotcha:ownership:")
                            })
                            .collect();
                        for k in gotcha_keys {
                            if !merged.contains(k) {
                                merged.push(k.clone());
                            }
                        }
                        obj.insert("gotcha_keys".to_string(), serde_json::json!(merged));
                    }
                }
                patched.push((file_key, record));
            }
        }
        if !patched.is_empty() {
            let pairs: Vec<(&str, &Record)> =
                patched.iter().map(|(k, r)| (k.as_str(), r)).collect();
            if let Err(e) = store.put_batch_kv_only(&pairs).await {
                tracing::warn!("init: skipped-file gotcha_keys patch failed: {e}");
            }
        }
    }

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

    // ── 9c. HasGotcha edges from all auto-generated gotchas ────────────────────
    // build_edges creates CoChanges + Imports edges but not HasGotcha. Generate
    // HasGotcha edges from affected_files in every gotcha record so the graph
    // traversal (mem_query graph mode, mem_bootstrap) sees them without repair.
    {
        let all_gotcha_recs = claude_import
            .records
            .iter()
            .filter(|r| r.key.starts_with("gotcha:"))
            .chain(cochange_record_structs.iter())
            .chain(revert_record_structs.iter())
            .chain(ownership_record_structs.iter());

        for rec in all_gotcha_recs {
            if !matches!(rec.lifecycle, RecordLifecycle::Active) {
                continue;
            }
            let affected = rec
                .payload_as::<GotchaRecord>()
                .map(|g| g.affected_files)
                .unwrap_or_default();
            for file_path in &affected {
                let file_key = format!("file:{file_path}");
                layer0_edges
                    .edges
                    .push((file_key, EdgeKind::HasGotcha, rec.key.clone()));
            }
        }
    }

    // ── 10–11. Graph::load + add_edges_batch ─────────────────────────────────
    // Warm re-init with no new edges: skip the 14k-key prefix scan entirely.
    // Graph::empty wraps the Store without touching SurrealKV — close() and
    // store() still work. Cold init (skipped_count == 0) always loads because
    // mark_search_stale is only called on cold paths and is a no-op concern.
    let t = Instant::now();
    let graph = if layer0_edges.edges.is_empty() && skipped_count > 0 {
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

    // ── 10a. Compute blast radius for all files ──────────────────────────────
    // Requires: graph loaded with Imports edges (Phase 10).
    // Patches file records in the store with blast radius scores.
    {
        let store_ref = graph.store();
        let t = Instant::now();
        let all_keys: Vec<String> = file_records
            .iter()
            .map(|fr| format!("file:{}", fr.path))
            .collect();
        let blast_map =
            mati_core::analysis::blast_radius::BlastRadius::compute_all(&graph, &all_keys);

        // Bulk read all file records in a single scan.
        let mut all_file_recs = store_ref.scan_prefix("file:").await.unwrap_or_default();
        let mut blast_count = 0u32;

        // In-memory mutation: patch each FileRecord with its blast radius.
        for record in all_file_recs.iter_mut() {
            if let Some(br) = blast_map.get(&record.key) {
                if let Some(mut fr) = record.payload_as::<FileRecord>() {
                    fr.blast_radius = Some(br.clone());
                    record.payload = serde_json::to_value(&fr).ok();
                    blast_count += 1;
                }
            }
        }

        // Bulk write all mutated records in a single batch transaction.
        let pairs: Vec<(&str, &Record)> =
            all_file_recs.iter().map(|r| (r.key.as_str(), r)).collect();
        let _ = store_ref.put_batch_kv_only(&pairs).await;

        println!(
            "  Blast radius...                {:>4} files   {:>4}ms",
            blast_count,
            t.elapsed().as_millis()
        );
    }

    // ── 10b. Compute and persist cluster index ─────────────────────────────
    // Requires: co_change_pairs from git mining (Phase 8a).
    // Writes: single "cluster:index" record.
    {
        let t = Instant::now();
        let cluster_index = mati_core::analysis::clusters::ClusterIndex::compute(
            &co_change_pairs,
            file_records.len() + skipped_count,
        );
        let cluster_count = cluster_index.total;
        let store_ref = graph.store();
        let now_ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let cluster_record = Record {
            key: "cluster:index".to_string(),
            value: format!(
                "{} clusters, {} clustered files",
                cluster_index.total, cluster_index.clustered_files
            ),
            payload: serde_json::to_value(&cluster_index).ok(),
            category: Category::Analytics,
            priority: Priority::Normal,
            tags: vec![],
            created_at: now_ts,
            updated_at: now_ts,
            ref_url: None,
            staleness: StalenessScore::fresh(),
            lifecycle: RecordLifecycle::Active,
            version: RecordVersion {
                device_id,
                logical_clock: 1,
                wall_clock: now_ts,
            },
            quality: QualityScore::layer0_default(),
            access_count: 0,
            last_accessed: 0,
            source: RecordSource::StaticAnalysis,
            confidence: ConfidenceScore::for_new_record(&RecordSource::StaticAnalysis),
            gap_analysis_score: 0.0,
        };
        let _ = store_ref.put("cluster:index", &cluster_record).await;

        // ── 10b-ii. Persist co-change pairs as source of truth ──────────────
        // Stored separately from CoChanges graph edges because edge values
        // are timestamps only (`src/graph/graph.rs:118-123`) — the count is
        // not recoverable from the persisted edge. `mati repair` (offline,
        // no git mining available) needs the raw pair counts to recompute
        // clusters correctly; without this record, repair has to fake
        // counts (`MIN_COCHANGE_COUNT`) which bypasses the cluster filter
        // and produces a giant single-component result (see DECISIONS.md
        // ADR-021).
        let pairs_payload = serde_json::json!({
            "pairs": &co_change_pairs,
            "total_files_at_init": file_records.len() + skipped_count,
        });
        let pairs_record = Record {
            key: "analytics:co_change_pairs".to_string(),
            value: format!(
                "{} pairs (source of truth for clustering)",
                co_change_pairs.len()
            ),
            payload: Some(pairs_payload),
            category: Category::Analytics,
            priority: Priority::Normal,
            tags: vec![],
            created_at: now_ts,
            updated_at: now_ts,
            ref_url: None,
            staleness: StalenessScore::fresh(),
            lifecycle: RecordLifecycle::Active,
            version: RecordVersion {
                device_id,
                logical_clock: 1,
                wall_clock: now_ts,
            },
            quality: QualityScore::layer0_default(),
            access_count: 0,
            last_accessed: 0,
            source: RecordSource::StaticAnalysis,
            confidence: ConfidenceScore::for_new_record(&RecordSource::StaticAnalysis),
            gap_analysis_score: 0.0,
        };
        let _ = store_ref
            .put("analytics:co_change_pairs", &pairs_record)
            .await;

        println!(
            "  Clusters...                    {:>4} found   {:>4}ms",
            cluster_count,
            t.elapsed().as_millis()
        );
    }

    // ── 10c. Compute propagated staleness ──────────────────────────────────
    // Requires: graph loaded with Imports edges (Phase 10), file records
    // with staleness values written to store (Phase 9).
    {
        let t = Instant::now();
        let store_ref = graph.store();
        let mut all_file_recs = store_ref.scan_prefix("file:").await.unwrap_or_default();
        let propagation =
            mati_core::analysis::propagation::compute_propagation(&all_file_recs, &graph);
        let mut prop_count = 0u32;

        // In-memory mutation: patch propagated staleness onto file records.
        for record in all_file_recs.iter_mut() {
            if let Some(prop) = propagation.get(&record.key) {
                if let Some(mut fr) = record.payload_as::<FileRecord>() {
                    fr.propagated_staleness = Some(prop.clone());
                    record.payload = serde_json::to_value(&fr).ok();
                    prop_count += 1;
                }
            }
        }

        // Bulk write all mutated records.
        if prop_count > 0 {
            let pairs: Vec<(&str, &Record)> =
                all_file_recs.iter().map(|r| (r.key.as_str(), r)).collect();
            let _ = store_ref.put_batch_kv_only(&pairs).await;
            println!(
                "  Staleness propagation...       {:>4} files   {:>4}ms",
                prop_count,
                t.elapsed().as_millis()
            );
        }
    }

    // ── 10d. Seed stats + stale cache (first run only) ───────────────────────
    // Must run after 10a/10c: those passes rewrite every file: record, bumping
    // write_seq. Seeding earlier stamps the caches with a stale write_seq, so
    // the very first `mati stats`/`mati stale` never validates the cache and
    // recomputes (dead cache in daemon mode). The blast-radius/propagation
    // patches don't affect what these caches store (purpose/hotspot/confidence
    // and staleness.tier), so the in-memory slices are still correct.
    // On incremental re-init, in-memory record slices are incomplete (only
    // changed files). Skip seeding — mati stats/stale will recompute instead.
    if skipped_count == 0 {
        let store_ref = graph.store();
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
            store_ref,
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
        if let Err(e) = super::stale::seed_stale_cache(store_ref, &root, &all_records).await {
            tracing::warn!("stale cache seed failed (non-fatal): {e}");
        }
    }

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

    // Read gotchas from the store, not this run's slices: an incremental
    // re-init holds only the changed files' records.
    let gated = match graph.store().scan_prefix("gotcha:").await {
        Ok(gotchas) => {
            let mut gated = super::gated_files(&gotchas);
            gated.retain(|p| root.join(p).exists());
            gated
        }
        Err(e) => {
            tracing::warn!("coverage scan failed (non-fatal): {e}");
            Default::default()
        }
    };

    // ── 12. Close ────────────────────────────────────────────────────────────
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
    let integration_label = match (claude_installed, codex_installed, args.no_hooks) {
        (_, _, true) => "MCP-only fallback (agent scaffolds skipped)".to_string(),
        (true, true, false) => "Claude + Codex".to_string(),
        (true, false, false) => "Claude".to_string(),
        (false, true, false) => "Codex".to_string(),
        (false, false, false) => "MCP-only fallback".to_string(),
    };
    println!("  integration:          {integration_label}");
    if claude_installed || codex_installed {
        let g = if std::io::stderr().is_terminal() {
            super::colors::GRAY
        } else {
            ""
        };
        let w = if std::io::stderr().is_terminal() {
            super::colors::WHITE
        } else {
            ""
        };
        let b = if std::io::stderr().is_terminal() {
            super::colors::BOLD
        } else {
            ""
        };
        let r = if std::io::stderr().is_terminal() {
            super::colors::RESET
        } else {
            ""
        };
        println!();
        println!("  {b}Enforcement{r}");
        if claude_installed {
            println!(
                "    {w}Claude:{r}  {g}file reads blocked until knowledge consulted (pre-read hook){r}"
            );
        }
        if codex_installed {
            println!(
                "    {w}Codex:{r}   {g}Bash reads blocked + gotchas injected on prompt submit{r}"
            );
        }
        println!("    {w}Both:{r}    {g}compliance tracking, edit capture, session analytics{r}");
    }
    println!();

    // ── Post-init insights ─────────────────────────────────────────────
    let use_color = std::io::stderr().is_terminal();
    let (blue, cyan, yellow, gray, white, bold, reset) = if use_color {
        (
            super::colors::BLUE,
            super::colors::CYAN,
            super::colors::YELLOW,
            super::colors::GRAY,
            super::colors::WHITE,
            super::colors::BOLD,
            super::colors::RESET,
        )
    } else {
        ("", "", "", "", "", "", "")
    };

    // Block 1: Enforcement coverage
    let ungated_hotspots = git_signals
        .as_ref()
        .map(|g| {
            g.hotspot_files
                .iter()
                .filter(|p| !gated.contains(*p))
                .count()
        })
        .unwrap_or(0);
    println!(
        "  {bold}Coverage:{reset}  {white}{}{reset}",
        super::coverage_line(gated.len(), total_file_count, ungated_hotspots)
    );

    // Block 2: Top hotspot files (filtered to code files for display)
    let hotspot_paths: &[String] = git_signals
        .as_ref()
        .map(|g| g.hotspot_files.as_slice())
        .unwrap_or(&[]);
    let code_hotspots: Vec<&String> = hotspot_paths.iter().filter(|p| is_code_file(p)).collect();
    // Fall back to unfiltered if filtering removes everything
    let display_hotspots: Vec<&String> = if code_hotspots.is_empty() {
        hotspot_paths.iter().collect()
    } else {
        code_hotspots
    };
    if !display_hotspots.is_empty() {
        println!();
        println!(
            "  {bold}Hotspot files{reset}  {gray}(highest risk — most changed in last 90 days){reset}"
        );
        for path in display_hotspots.iter().take(5) {
            println!("    {cyan}{path}{reset}");
        }
        if display_hotspots.len() > 5 {
            println!("    {gray}… and {} more{reset}", display_hotspots.len() - 5);
        }
    }

    // Block 3: Top co-change pairs (filtered to code-file pairs)
    let code_pairs: Vec<&(String, String, u32)> = co_change_pairs
        .iter()
        .filter(|(a, b, _)| is_code_file(a) && is_code_file(b))
        .collect();
    if !code_pairs.is_empty() {
        println!();
        println!(
            "  {bold}Co-change pairs{reset}  {gray}(files that always change together){reset}"
        );
        for (a, b, count) in code_pairs.iter().take(3) {
            let (freq_a, freq_b) = git_signals
                .as_ref()
                .map(|g| {
                    (
                        g.change_frequency
                            .get(a.as_str())
                            .copied()
                            .unwrap_or(1)
                            .max(1),
                        g.change_frequency
                            .get(b.as_str())
                            .copied()
                            .unwrap_or(1)
                            .max(1),
                    )
                })
                .unwrap_or((1, 1));
            let pct = ((*count as f64 / freq_a.min(freq_b) as f64) * 100.0)
                .round()
                .min(100.0) as u32;
            println!("    {cyan}{a}{reset}  ↔  {cyan}{b}{reset}  {gray}({pct}%){reset}");
        }
    }

    // Block 4: Review backlog
    // Only written records reach `mati review`. `gotcha_candidates` counts raw
    // scan signals (TODO, unsafe, unwrap) that are never persisted, so adding
    // it here promised a backlog 26x larger than the one review presents.
    let review_count = cochange_count + revert_count + ownership_count;
    if review_count > 0 {
        println!();
        println!(
            "  {bold}{yellow}Review backlog{reset}  {white}{review_count}{reset} {gray}candidates pending confirmation{reset}"
        );
        println!("    {gray}Run {white}mati review{gray} — confirmed gotchas block file reads until consulted{reset}");
        if hotspot_count > 0 {
            println!(
                "    {yellow}{hotspot_count} hotspot files have zero confirmed gotchas{reset}"
            );
        }
    }
    println!();

    // Block 5: Personalized next steps (column-aligned)
    println!("  {bold}{blue}Next steps{reset}");
    let top_file = display_hotspots.first().map(|s| s.as_str());
    let explain_cmd = if let Some(path) = top_file {
        format!("mati explain {path}")
    } else if total_file_count > 0 {
        "mati explain <file>".to_string()
    } else {
        String::new()
    };
    let review_cmd = "mati review".to_string();
    let status_cmd = "mati status".to_string();
    let hooks_cmd = "mati init --claude".to_string();
    let no_enforcement = !claude_installed && !codex_installed && !args.no_hooks;

    // Compute column width from the longest command + 2 spaces padding
    let col = explain_cmd
        .len()
        .max(review_cmd.len())
        .max(status_cmd.len())
        .max(hooks_cmd.len())
        + 2;

    if no_enforcement {
        println!(
            "    {white}{hooks_cmd:<col$}{reset}{yellow}← no hooks installed, so nothing is enforced (or --codex){reset}",
            col = col
        );
    }

    if !explain_cmd.is_empty() {
        let desc = if top_file.is_some() {
            "← start here (highest-risk file)"
        } else {
            "file briefing — gotchas and decisions before editing"
        };
        println!(
            "    {white}{explain_cmd:<col$}{reset}{gray}{desc}{reset}",
            col = col
        );
    }
    if review_count > 0 {
        let desc = format!("confirm {review_count} candidates for hook enforcement");
        println!(
            "    {white}{review_cmd:<col$}{reset}{gray}{desc}{reset}",
            col = col
        );
    }
    {
        let desc = "project knowledge dashboard";
        println!(
            "    {white}{status_cmd:<col$}{reset}{gray}{desc}{reset}",
            col = col
        );
    }
    println!();

    Ok(())
}
