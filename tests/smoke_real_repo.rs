//! Layer 2 real-repo smoke tests — full mati lifecycle against the project's own repository.
//!
//! These tests run against the mati codebase itself (via `CARGO_MANIFEST_DIR`),
//! using temp directories for all store state. They catch the class of bugs that
//! unit tests miss: performance timeouts, write amplification, staleness erasure,
//! and integration seams between walker/parser/store/graph/MCP layers.
//!
//! # Running
//!
//! Fast tests only (default `cargo test`):
//! ```sh
//! cargo test --test smoke_real_repo
//! ```
//!
//! Full suite including slow disk/git tests:
//! ```sh
//! cargo test --test smoke_real_repo -- --ignored
//! ```

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    use std::time::Instant;

    use tempfile::TempDir;

    use mati_core::analysis::walker::{Language, Walker};
    use mati_core::analysis::parser::parse_file;
    use mati_core::graph::{EdgeKind, Graph};
    use mati_core::health::staleness::{apply_reparse_staleness, ReparseDiff, StalenessAnalyzer};
    use mati_core::mcp::tools::assemble_context_packet;
    use mati_core::store::record::{
        Category, ConfidenceScore, GotchaRecord, Priority, QualityScore, QualityTier, Record,
        RecordLifecycle, RecordSource, RecordVersion, StalenessScore, StalenessTier,
    };
    use mati_core::store::Store;

    // ── Helpers ──────────────────────────────────────────────────────────────

    /// Project root — the mati repo itself. Resolved at compile time via
    /// CARGO_MANIFEST_DIR so tests work in CI regardless of cwd.
    fn project_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    }

    /// Create a fresh `Store` backed by a temporary directory.
    /// Returns both the store and the TempDir (caller must hold the TempDir
    /// to prevent cleanup while the store is in use).
    async fn temp_store() -> (Store, TempDir) {
        let dir = TempDir::new().expect("failed to create temp dir for store");
        let store = Store::open(dir.path())
            .await
            .expect("failed to open store at temp dir");
        (store, dir)
    }

    /// Construct a minimal `Record` for `file:<path>` keys, suitable for seeding.
    fn make_file_record(key: &str) -> Record {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Record {
            key: key.to_string(),
            value: String::new(),
            category: Category::File,
            priority: Priority::Normal,
            tags: vec![],
            created_at: now,
            updated_at: now,
            ref_url: None,
            staleness: StalenessScore {
                value: 0.0,
                tier: StalenessTier::Fresh,
                signals: vec![],
                computed_at: 0,
                last_record_sha: String::new(),
            },
            lifecycle: RecordLifecycle::Active,
            version: RecordVersion {
                device_id: uuid::Uuid::new_v4(),
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

    /// Construct a confirmed gotcha `Record` with quality >= 0.4 (Acceptable).
    fn make_confirmed_gotcha(key: &str, rule: &str, reason: &str, affected: &[&str]) -> Record {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let gotcha = GotchaRecord {
            rule: rule.to_string(),
            reason: reason.to_string(),
            severity: Priority::High,
            affected_files: affected.iter().map(|s| s.to_string()).collect(),
            ref_url: None,
            discovered_session: now,
            confirmed: true,
        };
        Record {
            key: key.to_string(),
            value: gotcha.rule.clone(),
            payload: serde_json::to_value(&gotcha).ok(),
            category: Category::Gotcha,
            priority: Priority::High,
            tags: vec!["test".to_string()],
            created_at: now,
            updated_at: now,
            ref_url: None,
            staleness: StalenessScore::fresh(),
            lifecycle: RecordLifecycle::Active,
            version: RecordVersion {
                device_id: uuid::Uuid::new_v4(),
                logical_clock: 1,
                wall_clock: now,
            },
            quality: QualityScore {
                value: 0.55,
                tier: QualityTier::Acceptable,
                signals: vec![],
                computed_at: now,
            },
            access_count: 0,
            last_accessed: 0,
            source: RecordSource::DeveloperManual,
            confidence: ConfidenceScore::for_new_record(&RecordSource::DeveloperManual),
            gap_analysis_score: 0.0,
        }
    }

    // ── Test 1: Store CRUD ──────────────────────────────────────────────────

    /// Proves Store CRUD works end-to-end: put, scan_prefix, get, close.
    #[tokio::test]
    async fn smoke_store_open_and_scan() {
        let (store, _dir) = temp_store().await;

        // Put 10 test records
        for i in 0..10 {
            let key = format!("file:src/test_{i}.rs");
            let record = make_file_record(&key);
            store
                .put(&key, &record)
                .await
                .expect(&format!("failed to put record {key}"));
        }

        // scan_prefix returns them
        let scanned = store
            .scan_prefix("file:")
            .await
            .expect("scan_prefix failed");
        assert!(
            scanned.len() >= 10,
            "expected at least 10 records from scan_prefix, got {}",
            scanned.len()
        );

        // get returns individual records
        let fetched = store
            .get("file:src/test_0.rs")
            .await
            .expect("get failed");
        assert!(
            fetched.is_some(),
            "expected to find file:src/test_0.rs via get"
        );
        let fetched = fetched.unwrap();
        assert_eq!(fetched.key, "file:src/test_0.rs");
        assert_eq!(fetched.category, Category::File);

        // close succeeds
        store.close().await.expect("store close failed");
    }

    // ── Test 2: Walker finds Rust files ─────────────────────────────────────

    /// Proves file walking works on a real codebase: finds .rs files, respects .gitignore.
    #[tokio::test]
    #[ignore] // touches disk extensively
    async fn smoke_walker_finds_rust_files() {
        let root = project_root();
        let walker = Walker::new(&root);
        let files = walker.walk().expect("walker failed on project root");

        let rust_files: Vec<_> = files
            .iter()
            .filter(|f| f.language == Language::Rust)
            .collect();

        assert!(
            rust_files.len() >= 20,
            "expected at least 20 .rs files in the mati project, found {}",
            rust_files.len()
        );

        // No files from target/ (respects .gitignore)
        let target_files: Vec<_> = files
            .iter()
            .filter(|f| f.rel_path.starts_with("target/"))
            .collect();
        assert!(
            target_files.is_empty(),
            "walker should not return files from target/, found {} files",
            target_files.len()
        );

        // All rel_paths are forward-slash separated and non-empty
        for f in &files {
            assert!(
                !f.rel_path.is_empty(),
                "walker produced a file with empty rel_path"
            );
            assert!(
                !f.rel_path.contains('\\'),
                "rel_path contains backslash: {}",
                f.rel_path
            );
        }
    }

    // ── Test 3: Parser parses real Rust files ───────────────────────────────

    /// Proves tree-sitter parsing works on real Rust code: no panics, produces
    /// structural signals.
    #[tokio::test]
    #[ignore] // touches disk extensively
    async fn smoke_parser_parses_real_rust_files() {
        let root = project_root();
        let walker = Walker::new(&root);
        let files = walker.walk().expect("walker failed");

        let rust_files: Vec<_> = files
            .into_iter()
            .filter(|f| f.language == Language::Rust)
            .take(5)
            .collect();

        assert!(
            !rust_files.is_empty(),
            "need at least 1 Rust file to test parser"
        );

        let mut any_has_entry_points = false;
        let mut any_has_imports = false;

        for file in &rust_files {
            let analysis = parse_file(file)
                .expect(&format!("parse_file panicked/errored on {}", file.rel_path));

            // Basic structural invariants
            assert_eq!(
                analysis.path, file.rel_path,
                "analysis path should match walked file rel_path"
            );

            if !analysis.entry_points.is_empty() {
                any_has_entry_points = true;
            }
            if !analysis.imports.is_empty() {
                any_has_imports = true;
            }
        }

        assert!(
            any_has_entry_points,
            "expected at least one Rust file to have entry_points > 0"
        );
        assert!(
            any_has_imports,
            "expected at least one Rust file to have imports > 0"
        );
    }

    // ── Test 4: StalenessAnalyzer completes within budget ───────────────────

    /// Proves the staleness analyzer establishes baselines efficiently on a real
    /// git repo, completing within the 3-second budget.
    ///
    /// Seeds records using real source file paths from the project so the
    /// revwalk and git_factor computation hit actual commits in the git history.
    #[tokio::test]
    #[ignore] // touches disk and git extensively
    async fn smoke_staleness_analyzer_completes_within_budget() {
        let (store, _dir) = temp_store().await;
        let root = project_root();

        // Collect real .rs paths from src/ relative to project root.
        fn collect_rs(dir: &std::path::Path, root: &std::path::Path, out: &mut Vec<String>) {
            let Ok(entries) = std::fs::read_dir(dir) else { return };
            for e in entries.flatten() {
                let p = e.path();
                if p.is_dir() {
                    collect_rs(&p, root, out);
                } else if p.extension().map_or(false, |x| x == "rs") {
                    if let Ok(rel) = p.strip_prefix(root) {
                        out.push(rel.to_string_lossy().into_owned());
                    }
                }
            }
        }
        let src_dir = root.join("src");
        let mut real_paths: Vec<String> = Vec::new();
        collect_rs(&src_dir, &root, &mut real_paths);

        assert!(
            !real_paths.is_empty(),
            "no .rs files found under src/ — project_root may be wrong"
        );

        for path in &real_paths {
            let key = format!("file:{path}");
            let record = make_file_record(&key);
            store.put(&key, &record).await.expect("failed to seed record");
        }

        let seeded = real_paths.len();

        let analyzer = StalenessAnalyzer::new(&root);
        let start = Instant::now();
        let report = analyzer
            .analyze_all(&store)
            .await
            .expect("analyze_all failed");
        let elapsed = start.elapsed();

        assert!(
            report.scanned >= seeded as u32,
            "expected at least {seeded} scanned, got {}",
            report.scanned
        );

        assert!(
            elapsed.as_secs() < 3,
            "analyze_all exceeded 3-second budget: took {:.2}s",
            elapsed.as_secs_f64()
        );

        // With real paths the git_factor computation runs revwalk for each
        // file — verify at least some records received a non-empty baseline SHA.
        let mut sha_count = 0u32;
        for path in &real_paths {
            let key = format!("file:{path}");
            if let Ok(Some(r)) = store.get(&key).await {
                if !r.staleness.last_record_sha.is_empty() {
                    sha_count += 1;
                }
            }
        }
        assert!(
            sha_count > 0,
            "expected at least one record to have a baseline SHA set, got 0"
        );

        store.close().await.expect("store close failed");
    }

    // ── Test 5: Staleness preserved after reparse ───────────────────────────

    /// Proves the reparse preservation fix works: staleness signals from
    /// reparse are not erased by a subsequent analyzer run within 24h.
    #[tokio::test]
    async fn smoke_staleness_preserved_after_reparse() {
        let (store, _dir) = temp_store().await;
        let root = project_root();

        // Seed a file record for a real .rs file in the project
        let key = "file:src/main.rs";
        let mut record = make_file_record(key);
        store
            .put(key, &record)
            .await
            .expect("failed to seed file record");

        // Run the staleness analyzer to set baselines
        let analyzer = StalenessAnalyzer::new(&root);
        analyzer
            .analyze_all(&store)
            .await
            .expect("first analyze_all failed");

        // Re-read the record after baseline establishment
        record = store
            .get(key)
            .await
            .expect("get after first analyze failed")
            .expect("record missing after first analyze");

        // Simulate a reparse with structural changes
        let diff = ReparseDiff {
            entry_points_added: vec!["new_function".to_string()],
            entry_points_removed: vec![],
            imports_added: vec!["crate::new_module".to_string()],
            imports_removed: vec![],
            todos_changed: true,
            unsafe_delta: 1,
            unwrap_delta: 0,
        };

        let signals = apply_reparse_staleness(&mut record, &diff);
        assert!(
            !signals.is_empty(),
            "reparse should have produced staleness signals"
        );

        let staleness_after_reparse = record.staleness.value;
        assert!(
            staleness_after_reparse > 0.0,
            "staleness should be > 0 after reparse with structural changes"
        );

        // Persist the reparse'd record
        record.updated_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        record.version.logical_clock += 1;
        store
            .put(key, &record)
            .await
            .expect("failed to persist reparse'd record");

        // Run analyzer again
        analyzer
            .analyze_all(&store)
            .await
            .expect("second analyze_all failed");

        // Re-read and verify staleness was NOT erased
        let record_after_second_analyze = store
            .get(key)
            .await
            .expect("get after second analyze failed")
            .expect("record missing after second analyze");

        assert!(
            record_after_second_analyze.staleness.value > 0.0,
            "staleness should NOT be reduced to 0.0 after re-analysis \
             (reparse signals preserved within 24h window). \
             Got value: {}",
            record_after_second_analyze.staleness.value
        );

        // The reparse signals should still be present in the signal list
        let has_reparse_signals = record_after_second_analyze
            .staleness
            .signals
            .iter()
            .any(|s| {
                matches!(
                    s,
                    mati_core::store::record::StalenessSignal::EntryPointsChanged(_)
                        | mati_core::store::record::StalenessSignal::ImportsChanged(_)
                        | mati_core::store::record::StalenessSignal::TodosChanged
                        | mati_core::store::record::StalenessSignal::UnsafeCountChanged(_)
                )
            });
        assert!(
            has_reparse_signals,
            "reparse-derived staleness signals should be preserved after re-analysis"
        );

        store.close().await.expect("store close failed");
    }

    // ── Test 6: Context packet assembly ─────────────────────────────────────

    /// Proves MCP context assembly works with real data structures: gotcha
    /// injection, token budget, and Vector B marker.
    #[tokio::test]
    async fn smoke_context_packet_assembly() {
        let (store, _dir) = temp_store().await;

        // Seed a file record
        let file_key = "file:src/lib.rs";
        let file_record = make_file_record(file_key);
        store
            .put(file_key, &file_record)
            .await
            .expect("failed to seed file record");

        // Seed a confirmed gotcha with quality >= 0.4
        let gotcha_key = "gotcha:no-unwrap-in-hooks";
        let gotcha = make_confirmed_gotcha(
            gotcha_key,
            "Never use .unwrap() in hook handlers",
            "Hook handlers run in the critical path; a panic crashes the entire session",
            &["src/lib.rs"],
        );
        store
            .put(gotcha_key, &gotcha)
            .await
            .expect("failed to seed gotcha record");

        // Build a Graph (takes ownership of store) and add HasGotcha edge.
        // After this, use graph.store() for all store access.
        let mut graph = Graph::load(store)
            .await
            .expect("Graph::load failed");
        graph
            .add_edge(file_key, EdgeKind::HasGotcha, gotcha_key)
            .await
            .expect("add_edge failed");

        // Assemble context packet via the store ref held by Graph
        let packet = assemble_context_packet(graph.store(), &graph, &["src/lib.rs".to_string()])
            .await
            .expect("assemble_context_packet failed");

        // Verify: injection_string contains the gotcha
        assert!(
            packet.injection_string.contains("unwrap"),
            "injection_string should contain the gotcha rule text. Got: {}",
            &packet.injection_string[..packet.injection_string.len().min(200)]
        );

        // Verify: token budget
        assert!(
            packet.token_estimate <= 2000,
            "token_estimate {} exceeds 2000 budget",
            packet.token_estimate
        );

        // Verify: Vector B marker
        assert!(
            packet.injection_string.contains("[mati]"),
            "injection_string should contain [mati] Vector B marker. Got: {}",
            &packet.injection_string[..packet.injection_string.len().min(200)]
        );

        graph.close().await.expect("graph close failed");
    }

    // ── Test 7: History tracks versions ─────────────────────────────────────

    /// Proves SurrealKV versioning works end-to-end: multiple writes produce
    /// retrievable version history.
    #[tokio::test]
    async fn smoke_history_tracks_versions() {
        let (store, _dir) = temp_store().await;

        let key = "file:src/versioned.rs";
        let mut record = make_file_record(key);

        // Write initial version
        store
            .put(key, &record)
            .await
            .expect("failed to put initial version");

        // Write 3 updates
        for i in 1..=3 {
            record.value = format!("version {i}");
            record.updated_at += 1;
            record.version.logical_clock += 1;
            store
                .put(key, &record)
                .await
                .expect(&format!("failed to put version {i}"));
        }

        // Retrieve history
        let history = store
            .history(key, 100)
            .expect("history retrieval failed");

        // SurrealKV should have at least 2 versions (write timing may coalesce
        // very fast writes, but 4 distinct puts should produce > 1 version)
        assert!(
            history.len() > 1,
            "expected > 1 history entries, got {}. \
             SurrealKV versioning may not be recording distinct writes.",
            history.len()
        );

        // Newest first ordering: first entry should have the highest timestamp
        if history.len() >= 2 {
            assert!(
                history[0].timestamp_ns >= history[1].timestamp_ns,
                "history should be newest-first. Got timestamps: {} then {}",
                history[0].timestamp_ns,
                history[1].timestamp_ns
            );
        }

        store.close().await.expect("store close failed");
    }

    // ── Test 8: git2 integration ────────────────────────────────────────────

    /// Proves git2 integration works with the real mati repo: HEAD exists,
    /// revwalk works, file blobs are accessible.
    #[tokio::test]
    #[ignore] // touches git extensively
    async fn smoke_git_history_accessible() {
        let root = project_root();

        let repo = git2::Repository::open(&root)
            .expect("failed to open git repository at project root");

        // HEAD exists
        let head = repo
            .head()
            .expect("HEAD ref not found — is the mati repo initialized?");
        assert!(
            head.is_branch() || head.target().is_some(),
            "HEAD should point to a branch or a commit"
        );

        // Revwalk: at least 5 commits
        let mut revwalk = repo.revwalk().expect("revwalk creation failed");
        revwalk
            .push_head()
            .expect("failed to push HEAD to revwalk");
        let commit_count = revwalk.take(100).filter(|r| r.is_ok()).count();
        assert!(
            commit_count >= 5,
            "expected at least 5 commits in the mati repo, found {}",
            commit_count
        );

        // Look up a known file's blob at HEAD
        let head_commit = repo
            .head()
            .expect("HEAD ref failed")
            .peel_to_commit()
            .expect("HEAD peel to commit failed");
        let tree = head_commit.tree().expect("HEAD commit tree failed");
        let entry = tree
            .get_path(Path::new("src/main.rs"))
            .expect("src/main.rs not found in HEAD tree");
        let blob_oid = entry.id();
        assert!(
            !blob_oid.is_zero(),
            "blob OID for src/main.rs should be non-zero"
        );
    }
}
