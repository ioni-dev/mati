use super::*;
use tempfile::TempDir;

/// Hygiene guard: unit tests must NEVER resolve `mati_home()` to the
/// developer's real `~/.mati`. Before this redirect, every `Store::open`
/// in the suite created a permanent `~/.mati/<slug>/` dir (thousands
/// accumulated). If this fails, the `cfg(test)` redirect in
/// `mati_home_opt` has regressed and the suite is polluting the real home.
#[test]
fn unit_tests_never_touch_real_mati_home() {
    let resolved = mati_home().expect("mati_home resolves under test");
    if let Some(real) = dirs::home_dir() {
        let real_mati = real.join(".mati");
        assert_ne!(
            resolved,
            real_mati,
            "unit test resolved to the REAL ~/.mati ({}); the cfg(test) \
                 redirect regressed — the suite is polluting the developer's home",
            real_mati.display()
        );
    }
    // An explicit MATI_HOME override must win over the auto-redirect.
    assert_eq!(
        std::env::var_os("MATI_HOME").map(PathBuf::from),
        Some(resolved),
        "under test, MATI_HOME is exported to the redirect dir so child \
             `mati` processes inherit the same root"
    );
}

/// Narrower than the guard above, and what let the real bug through:
/// `mati_home_opt` used to return an inherited `MATI_HOME` before reaching the
/// per-process redirect. An exported one then pointed every unit test at a
/// single shared store — not the real `~/.mati`, so the check above stayed
/// green while the suite quietly lost its isolation.
#[test]
fn the_unit_test_home_is_process_unique() {
    let resolved = mati_home().expect("mati_home resolves under test");
    let pid = std::process::id().to_string();
    let leaf = resolved
        .file_name()
        .map(|leaf| leaf.to_string_lossy().into_owned())
        .unwrap_or_default();
    assert!(
        leaf.contains(&pid),
        "MATI_HOME must end in a per-process leaf containing pid {pid}, got {}",
        resolved.display()
    );
}

// Helper: open a store backed by a temp directory (no real git repo needed)
fn temp_store() -> (Store, TempDir) {
    let dir = TempDir::new().unwrap();
    // Override slug derivation by constructing store path manually
    let root = dir.path().join("mati_test");
    std::fs::create_dir_all(&root).unwrap();
    let knowledge = open_knowledge_tree(root.join("knowledge.db")).unwrap();
    let sessions = open_sessions_tree(root.join("sessions.db")).unwrap();
    let search = OnceCell::new();
    let _ = search.set(Search::open(&root.join("search_index")).unwrap());
    let store = Store {
        knowledge,
        sessions,
        search,
        root: root.clone(),
        index_needs_rebuild: false,
    };
    (store, dir)
}

#[tokio::test]
async fn ping_roundtrip() {
    let (store, _dir) = temp_store();
    let latency = store.ping().await.unwrap();
    assert!(latency < 5_000_000, "ping took >5s: {latency}µs");
}

#[tokio::test]
async fn put_get_roundtrip() {
    use crate::store::record::{
        Category, ConfidenceScore, Priority, QualityScore, Record, RecordLifecycle, RecordSource,
        RecordVersion, StalenessScore,
    };
    use uuid::Uuid;

    let (store, _dir) = temp_store();

    let device_id = Uuid::new_v4();
    let record = Record {
        key: "gotcha:test-key".to_string(),
        value: "test value".to_string(),
        category: Category::Gotcha,
        priority: Priority::High,
        tags: vec!["test".to_string()],
        created_at: 0,
        updated_at: 0,
        ref_url: None,
        staleness: StalenessScore::fresh(),
        lifecycle: RecordLifecycle::Active,
        version: RecordVersion {
            device_id,
            logical_clock: 1,
            wall_clock: 0,
        },
        quality: QualityScore::layer0_default(),
        access_count: 0,
        last_accessed: 0,
        source: RecordSource::StaticAnalysis,
        confidence: ConfidenceScore::for_new_record(&RecordSource::StaticAnalysis),
        gap_analysis_score: 0.0,
        payload: None,
    };

    store.put("gotcha:test-key", &record).await.unwrap();
    let got = store.get("gotcha:test-key").await.unwrap();
    assert!(got.is_some());
    assert_eq!(got.unwrap().key, "gotcha:test-key");
}

#[tokio::test]
async fn put_delete_get_returns_none() {
    use crate::store::record::{
        Category, ConfidenceScore, Priority, QualityScore, Record, RecordLifecycle, RecordSource,
        RecordVersion, StalenessScore,
    };
    use uuid::Uuid;

    let (store, _dir) = temp_store();

    let device_id = Uuid::new_v4();
    let record = Record {
        key: "file:src/main.rs".to_string(),
        value: "entry point".to_string(),
        category: Category::File,
        priority: Priority::Normal,
        tags: vec![],
        created_at: 0,
        updated_at: 0,
        ref_url: None,
        staleness: StalenessScore::fresh(),
        lifecycle: RecordLifecycle::Active,
        version: RecordVersion {
            device_id,
            logical_clock: 1,
            wall_clock: 0,
        },
        quality: QualityScore::layer0_default(),
        access_count: 0,
        last_accessed: 0,
        source: RecordSource::StaticAnalysis,
        confidence: ConfidenceScore::for_new_record(&RecordSource::StaticAnalysis),
        gap_analysis_score: 0.0,
        payload: None,
    };

    store.put("file:src/main.rs", &record).await.unwrap();
    store.delete("file:src/main.rs").await.unwrap();
    let got = store.get("file:src/main.rs").await.unwrap();
    assert!(got.is_none());
}

#[tokio::test]
async fn scan_prefix_returns_matching_keys() {
    use crate::store::record::{
        Category, ConfidenceScore, Priority, QualityScore, Record, RecordLifecycle, RecordSource,
        RecordVersion, StalenessScore,
    };
    use uuid::Uuid;

    let (store, _dir) = temp_store();
    let device_id = Uuid::new_v4();

    let make_record = |key: &str| Record {
        key: key.to_string(),
        value: "v".to_string(),
        category: Category::Gotcha,
        priority: Priority::Normal,
        tags: vec![],
        created_at: 0,
        updated_at: 0,
        ref_url: None,
        staleness: StalenessScore::fresh(),
        lifecycle: RecordLifecycle::Active,
        version: RecordVersion {
            device_id,
            logical_clock: 1,
            wall_clock: 0,
        },
        quality: QualityScore::layer0_default(),
        access_count: 0,
        last_accessed: 0,
        source: RecordSource::StaticAnalysis,
        confidence: ConfidenceScore::for_new_record(&RecordSource::StaticAnalysis),
        gap_analysis_score: 0.0,
        payload: None,
    };

    store
        .put("gotcha:alpha", &make_record("gotcha:alpha"))
        .await
        .unwrap();
    store
        .put("gotcha:beta", &make_record("gotcha:beta"))
        .await
        .unwrap();
    store
        .put("gotcha:gamma", &make_record("gotcha:gamma"))
        .await
        .unwrap();
    store
        .put("file:src/main.rs", &make_record("file:src/main.rs"))
        .await
        .unwrap();

    let results = store.scan_prefix("gotcha:").await.unwrap();
    assert_eq!(results.len(), 3);
}

#[tokio::test]
async fn write_100_records_survive_reopen() {
    use crate::store::record::{
        Category, ConfidenceScore, Priority, QualityScore, Record, RecordLifecycle, RecordSource,
        RecordVersion, StalenessScore,
    };
    use uuid::Uuid;

    let dir = TempDir::new().unwrap();
    let root = dir.path().join("mati_test");
    std::fs::create_dir_all(&root).unwrap();
    let device_id = Uuid::new_v4();

    let make_record = |i: usize| {
        let key = format!("gotcha:item-{i:03}");
        Record {
            key: key.clone(),
            value: format!("value {i}"),
            category: Category::Gotcha,
            priority: Priority::Normal,
            tags: vec![],
            created_at: i as u64,
            updated_at: i as u64,
            ref_url: None,
            staleness: StalenessScore::fresh(),
            lifecycle: RecordLifecycle::Active,
            version: RecordVersion {
                device_id,
                logical_clock: i as u64,
                wall_clock: i as u64,
            },
            quality: QualityScore::layer0_default(),
            access_count: 0,
            last_accessed: 0,
            source: RecordSource::StaticAnalysis,
            confidence: ConfidenceScore::for_new_record(&RecordSource::StaticAnalysis),
            gap_analysis_score: 0.0,
            payload: None,
        }
    };

    // Write 100 records, then explicitly close to release LOCK.
    {
        let knowledge = open_knowledge_tree(root.join("knowledge.db")).unwrap();
        let sessions = open_sessions_tree(root.join("sessions.db")).unwrap();
        let search = OnceCell::new();
        let _ = search.set(Search::open(&root.join("search_index")).unwrap());
        let store = Store {
            knowledge,
            sessions,
            search,
            root: root.clone(),
            index_needs_rebuild: false,
        };
        for i in 0..100 {
            let r = make_record(i);
            store.put(&r.key, &r).await.unwrap();
        }
        store.close().await.unwrap();
    }

    // Reopen and verify all 100 are present.
    {
        let knowledge = open_knowledge_tree(root.join("knowledge.db")).unwrap();
        let sessions = open_sessions_tree(root.join("sessions.db")).unwrap();
        let search = OnceCell::new();
        let _ = search.set(Search::open(&root.join("search_index")).unwrap());
        let store = Store {
            knowledge,
            sessions,
            search,
            root: root.clone(),
            index_needs_rebuild: false,
        };
        let results = store.scan_prefix("gotcha:").await.unwrap();
        assert_eq!(
            results.len(),
            100,
            "expected 100 records after reopen, got {}",
            results.len()
        );
        store.close().await.unwrap();
    }
}

#[test]
fn slug_is_8_hex_chars() {
    let slug = derive_slug(Path::new("/some/repo"));
    assert_eq!(slug.len(), 8);
    assert!(slug.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn slug_is_deterministic() {
    let a = derive_slug(Path::new("/some/repo"));
    let b = derive_slug(Path::new("/some/repo"));
    assert_eq!(a, b);
}

#[test]
fn prefix_end_increments_last_byte() {
    // ':' is ASCII 58; incrementing gives ';' (59) → "gotcha;"
    assert_eq!(prefix_end("gotcha:"), "gotcha;");
    // All 0xff bytes — falls back to sentinel
    let all_ff = String::from_utf8(vec![0xff, 0xff]).unwrap_or_default();
    let end = prefix_end(&all_ff);
    assert_eq!(end, "\u{ffff}");
}

// ─── Shared helper ────────────────────────────────────────────────────────

fn make_record(key: &str) -> Record {
    use crate::store::record::{
        Category, ConfidenceScore, Priority, QualityScore, RecordLifecycle, RecordSource,
        RecordVersion, StalenessScore,
    };
    Record {
        key: key.to_string(),
        value: format!("value for {key}"),
        category: Category::Gotcha,
        priority: Priority::Normal,
        tags: vec![],
        created_at: 0,
        updated_at: 0,
        ref_url: None,
        staleness: StalenessScore::fresh(),
        lifecycle: RecordLifecycle::Active,
        version: RecordVersion {
            device_id: uuid::Uuid::new_v4(),
            logical_clock: 1,
            wall_clock: 0,
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

// ─── get / put / delete ────────────────────────────────────────────────────

#[tokio::test]
async fn get_never_written_key_returns_none() {
    let (store, _dir) = temp_store();
    assert!(store.get("gotcha:does-not-exist").await.unwrap().is_none());
}

#[tokio::test]
async fn put_twice_second_value_wins() {
    let (store, _dir) = temp_store();
    let mut r = make_record("gotcha:overwrite-me");
    store.put("gotcha:overwrite-me", &r).await.unwrap();
    r.value = "updated value".to_string();
    r.version.logical_clock = 2;
    store.put("gotcha:overwrite-me", &r).await.unwrap();
    let got = store.get("gotcha:overwrite-me").await.unwrap().unwrap();
    assert_eq!(got.value, "updated value", "second write must win");
    assert_eq!(got.version.logical_clock, 2);
}

#[tokio::test]
async fn delete_nonexistent_key_is_noop() {
    let (store, _dir) = temp_store();
    store.delete("gotcha:never-existed").await.unwrap();
    assert!(store.get("gotcha:never-existed").await.unwrap().is_none());
}

#[tokio::test]
async fn delete_does_not_remove_sibling_keys() {
    let (store, _dir) = temp_store();
    store
        .put("gotcha:keep", &make_record("gotcha:keep"))
        .await
        .unwrap();
    store
        .put("gotcha:remove", &make_record("gotcha:remove"))
        .await
        .unwrap();
    store.delete("gotcha:remove").await.unwrap();
    assert!(
        store.get("gotcha:keep").await.unwrap().is_some(),
        "sibling must survive"
    );
    assert!(store.get("gotcha:remove").await.unwrap().is_none());
}

// ─── scan_prefix isolation ─────────────────────────────────────────────────

#[tokio::test]
async fn scan_prefix_empty_result() {
    let (store, _dir) = temp_store();
    assert!(store.scan_prefix("gotcha:").await.unwrap().is_empty());
}

#[tokio::test]
async fn scan_prefix_does_not_spill_across_namespaces() {
    let (store, _dir) = temp_store();
    store
        .put("gotcha:alpha", &make_record("gotcha:alpha"))
        .await
        .unwrap();
    store
        .put("file:src/main.rs", &make_record("file:src/main.rs"))
        .await
        .unwrap();
    store
        .put("decision:arch", &make_record("decision:arch"))
        .await
        .unwrap();

    let gotcha = store.scan_prefix("gotcha:").await.unwrap();
    assert_eq!(gotcha.len(), 1);
    assert_eq!(gotcha[0].key, "gotcha:alpha");

    let file = store.scan_prefix("file:").await.unwrap();
    assert_eq!(file.len(), 1);
    assert_eq!(file[0].key, "file:src/main.rs");

    let decision = store.scan_prefix("decision:").await.unwrap();
    assert_eq!(decision.len(), 1);
    assert_eq!(decision[0].key, "decision:arch");
}

#[tokio::test]
async fn scan_prefix_values_match_stored_values() {
    let (store, _dir) = temp_store();
    for key in ["gotcha:alpha", "gotcha:beta", "gotcha:gamma"] {
        let mut r = make_record(key);
        r.value = format!("sentinel:{key}");
        store.put(key, &r).await.unwrap();
    }
    let mut results = store.scan_prefix("gotcha:").await.unwrap();
    results.sort_by(|a, b| a.key.cmp(&b.key));
    assert_eq!(results.len(), 3);
    for r in &results {
        assert_eq!(
            r.value,
            format!("sentinel:{}", r.key),
            "value mismatch for key '{}'",
            r.key
        );
    }
}

#[tokio::test]
async fn scan_prefix_excludes_adjacent_namespaces() {
    // prefix_end("gotcha:") == "gotcha;" — "decision:" and "file:" fall outside.
    let (store, _dir) = temp_store();
    store
        .put("gotcha:real", &make_record("gotcha:real"))
        .await
        .unwrap();
    store
        .put("decision:before", &make_record("decision:before"))
        .await
        .unwrap();
    store
        .put("file:after", &make_record("file:after"))
        .await
        .unwrap();

    let results = store.scan_prefix("gotcha:").await.unwrap();
    assert_eq!(results.len(), 1, "only gotcha: keys should appear");
    assert_eq!(results[0].key, "gotcha:real");
}

// ─── cross-tree isolation ──────────────────────────────────────────────────

#[tokio::test]
async fn knowledge_and_session_trees_are_isolated() {
    let (store, _dir) = temp_store();
    store
        .put("gotcha:in-knowledge", &make_record("gotcha:in-knowledge"))
        .await
        .unwrap();
    store
        .put("session:12345", &make_record("session:12345"))
        .await
        .unwrap();

    let gotcha_results = store.scan_prefix("gotcha:").await.unwrap();
    let session_results = store.scan_prefix("session:").await.unwrap();

    assert_eq!(gotcha_results.len(), 1);
    assert_eq!(gotcha_results[0].key, "gotcha:in-knowledge");
    assert_eq!(session_results.len(), 1);
    assert_eq!(session_results[0].key, "session:12345");
    assert!(
        gotcha_results
            .iter()
            .all(|r| !r.key.starts_with("session:")),
        "session records must not appear in gotcha: scan"
    );
    assert!(
        session_results
            .iter()
            .all(|r| !r.key.starts_with("gotcha:")),
        "gotcha records must not appear in session: scan"
    );
}

// ─── corrupt record tolerance ──────────────────────────────────────────────

#[tokio::test]
async fn scan_prefix_skips_corrupt_records_and_returns_valid_ones() {
    let (store, _dir) = temp_store();
    store
        .put("gotcha:good", &make_record("gotcha:good"))
        .await
        .unwrap();

    // Inject garbage bytes directly — simulates disk corruption or schema mismatch.
    {
        let mut txn = store.knowledge.begin().unwrap();
        txn.set_durability(SkvDurability::Immediate);
        txn.set(b"gotcha:corrupted", b"not valid json {{{").unwrap();
        txn.commit().await.unwrap();
    }

    let results = store.scan_prefix("gotcha:").await.unwrap();
    assert_eq!(results.len(), 1, "corrupt record must be silently skipped");
    assert_eq!(results[0].key, "gotcha:good");
}

#[tokio::test]
async fn scan_prefix_all_corrupt_returns_empty_not_panic() {
    let (store, _dir) = temp_store();
    {
        let mut txn = store.knowledge.begin().unwrap();
        txn.set_durability(SkvDurability::Immediate);
        txn.set(b"gotcha:bad1", b"null").unwrap();
        txn.set(b"gotcha:bad2", b"{\"x\":1}").unwrap(); // valid JSON, wrong shape
        txn.commit().await.unwrap();
    }
    let results = store.scan_prefix("gotcha:").await.unwrap();
    assert_eq!(
        results.len(),
        0,
        "all corrupt — must return empty, not panic"
    );
}

// ─── ping ──────────────────────────────────────────────────────────────────

#[tokio::test]
async fn ping_multiple_calls_all_succeed() {
    let (store, _dir) = temp_store();
    for i in 0..10 {
        let latency = store
            .ping()
            .await
            .unwrap_or_else(|e| panic!("ping #{i} failed: {e}"));
        assert!(latency < 5_000_000, "ping #{i} took >5 s: {latency} µs");
    }
}

// ─── slug derivation ───────────────────────────────────────────────────────

#[test]
fn slug_differs_for_different_paths() {
    let a = derive_slug(Path::new("/repo/project-alpha"));
    let b = derive_slug(Path::new("/repo/project-beta"));
    assert_ne!(a, b, "distinct paths must produce distinct slugs");
}

/// Pins the property that matters most: this repo's own slug must not move.
/// A slug change silently strands the existing store — `mati status` goes
/// empty with no explanation. This repo's slug is `7b63ddee` =
/// SHA-256(`https://github.com/ioni-dev/mati.git`)[..4], and its `.git` is a
/// real directory (the common case, not a gitlink). If this fails, the slug
/// algorithm moved and the change must stop here, not land.
#[test]
fn this_repos_own_slug_is_pinned() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    assert_eq!(derive_slug(manifest_dir), "7b63ddee");
}

/// A real repo (not a hand-rolled `.git/config`) with a real remote, set via
/// `git2` the way `git remote add` would.
fn init_repo_with_remote(dir: &Path, url: &str) {
    let repo = git2::Repository::init(dir).unwrap();
    repo.remote("origin", url).unwrap();
}

#[test]
fn slug_uses_remote_url_not_local_path() {
    // Verify the slug is actually derived from the URL, not the filesystem path.
    // We know the algorithm: first 8 hex chars of SHA-256(url).
    let url = "https://github.com/example/mati.git";
    let expected_slug = {
        let digest = Sha256::digest(url.as_bytes());
        hex::encode(&digest[..4])
    };

    let dir = tempfile::TempDir::new().unwrap();
    init_repo_with_remote(dir.path(), url);

    let actual_slug = derive_slug(dir.path());
    assert_eq!(
        actual_slug, expected_slug,
        "slug must equal SHA-256(remote URL)[0..4] hex"
    );

    // Also verify the path-derived slug for the same dir would differ
    // (i.e., the URL was actually preferred over the path).
    let path_slug = {
        let input = dir.path().to_string_lossy().into_owned();
        let digest = Sha256::digest(input.as_bytes());
        hex::encode(&digest[..4])
    };
    assert_ne!(
        actual_slug, path_slug,
        "URL slug must differ from the path slug for the same directory"
    );
}

#[test]
fn slug_is_stable_for_identical_remote_urls() {
    let make_repo = |url: &str| {
        let dir = tempfile::TempDir::new().unwrap();
        init_repo_with_remote(dir.path(), url);
        (derive_slug(dir.path()), dir)
    };
    let (slug_a, _dir_a) = make_repo("https://github.com/example/same-repo.git");
    let (slug_b, _dir_b) = make_repo("https://github.com/example/same-repo.git");
    assert_eq!(
        slug_a, slug_b,
        "same remote URL must always produce the same slug"
    );
}

#[test]
fn slug_differs_for_different_remote_urls() {
    let make_repo = |url: &str| {
        let dir = tempfile::TempDir::new().unwrap();
        init_repo_with_remote(dir.path(), url);
        (derive_slug(dir.path()), dir)
    };
    let (slug_a, _dir_a) = make_repo("https://github.com/org/repo-alpha.git");
    let (slug_b, _dir_b) = make_repo("https://github.com/org/repo-beta.git");
    assert_ne!(
        slug_a, slug_b,
        "different remote URLs must produce different slugs"
    );
}

#[test]
fn slug_of_a_real_repo_without_a_remote_hashes_the_same_workdir_slug_root_returns() {
    let dir = tempfile::TempDir::new().unwrap();
    git2::Repository::init(dir.path()).unwrap();

    let root = slug_root(dir.path());
    let expected = {
        let input = root.to_string_lossy().into_owned();
        let digest = Sha256::digest(input.as_bytes());
        hex::encode(&digest[..4])
    };
    assert_eq!(
        derive_slug(dir.path()),
        expected,
        "the no-remote fallback must hash exactly what slug_root returns"
    );
}

/// A `.git` that is itself a symlink: verified against `git2` 0.21 (not
/// assumed), `repo.workdir()` resolves fully through it — it returns the
/// symlink's target directory, not the directory the repo was accessed
/// from. libgit2 exposes no un-resolved alternative, so hashing
/// `workdir()` (per the fix's design) ends up hashing the TARGET here, and
/// a repo reached through a symlinked `.git` shares its slug with the
/// target's own directory. That is arguably correct (one underlying git
/// storage location, one identity) even though it means the "keeps its
/// current slug" framing does not hold for this specific shape — flagged
/// in the change that introduced this test, not silently assumed.
#[cfg(unix)]
#[test]
fn slug_of_a_repo_whose_git_is_a_symlink_matches_the_targets_own_slug() {
    let workdir = tempfile::TempDir::new().unwrap();
    let elsewhere = tempfile::TempDir::new().unwrap();
    git2::Repository::init(elsewhere.path()).unwrap();

    std::os::unix::fs::symlink(elsewhere.path().join(".git"), workdir.path().join(".git")).unwrap();

    assert_eq!(
        derive_slug(workdir.path()),
        derive_slug(elsewhere.path()),
        "workdir() resolves through a symlinked .git to the target, so both \
         access paths must hash to the same slug"
    );
    // And neither leaks unrelated git-internal layout: the shared slug is
    // exactly the hash of the (resolved) workdir, matching slug_root.
    assert_eq!(
        derive_slug(workdir.path()),
        derive_slug(&slug_root(workdir.path()))
    );
}

fn run_git(dir: &Path, args: &[&str]) {
    let status = std::process::Command::new("git")
        .args(args)
        .current_dir(dir)
        .status()
        .expect("run git");
    assert!(status.success(), "git {args:?} failed in {dir:?}");
}

/// A git repo with a remote and one commit, ready for `git worktree add`.
fn temp_repo_with_remote_for_worktrees(url: &str) -> TempDir {
    let dir = TempDir::new().expect("tempdir");
    run_git(dir.path(), &["init", "-q"]);
    run_git(dir.path(), &["config", "user.email", "t@t.com"]);
    run_git(dir.path(), &["config", "user.name", "t"]);
    run_git(dir.path(), &["remote", "add", "origin", url]);
    std::fs::write(dir.path().join("file.txt"), "hello").expect("write");
    run_git(dir.path(), &["add", "-A"]);
    run_git(dir.path(), &["commit", "-q", "-m", "init"]);
    dir
}

/// Linked worktrees share history (and `commondir`), so they must share a
/// slug — and therefore a store — while each still resolves record paths
/// against its own physical checkout.
#[test]
fn slug_is_shared_by_an_external_linked_worktree() {
    let main = temp_repo_with_remote_for_worktrees("https://github.com/example/wt-repo.git");
    let sibling_parent = TempDir::new().expect("tempdir");
    let wt_path = sibling_parent.path().join("wt");
    run_git(
        main.path(),
        &[
            "worktree",
            "add",
            wt_path.to_str().unwrap(),
            "-b",
            "wt-branch",
        ],
    );

    assert_eq!(
        derive_slug(main.path()),
        derive_slug(&wt_path),
        "a linked worktree must share the main checkout's slug"
    );
    assert_ne!(
        slug_root(main.path()),
        slug_root(&wt_path),
        "but each worktree still resolves record paths against its own workdir"
    );
}

/// The nested case: a worktree living inside the main checkout's own
/// directory tree (e.g. `.worktrees/<branch>`). Must share the slug for the
/// same reason as the external case above.
#[test]
fn slug_is_shared_by_a_worktree_nested_inside_the_main_checkout() {
    let main = temp_repo_with_remote_for_worktrees("https://github.com/example/nested-wt.git");
    let nested = main.path().join(".worktrees").join("wt");
    run_git(
        main.path(),
        &[
            "worktree",
            "add",
            nested.to_str().unwrap(),
            "-b",
            "nested-branch",
        ],
    );

    assert_eq!(derive_slug(main.path()), derive_slug(&nested));
}

/// A bare repo has no working tree. `slug_root` must fall back to the bare
/// repo's OWN location and never walk past it into an enclosing repo — a
/// bare clone nested under an unrelated working repo must not inherit that
/// repo's slug or store.
#[test]
fn slug_root_of_a_bare_repo_falls_back_to_its_own_path_not_an_ancestor() {
    let parent = TempDir::new().unwrap();
    init_repo_with_remote(parent.path(), "https://github.com/example/parent.git");

    let bare = parent.path().join("bare.git");
    git2::Repository::init_bare(&bare).unwrap();

    assert_eq!(
        slug_root(&bare),
        std::fs::canonicalize(&bare).unwrap(),
        "a bare repo's slug_root must be its own location"
    );
    assert_ne!(
        derive_slug(&bare),
        derive_slug(parent.path()),
        "a bare repo without its own remote must not collide with an \
         enclosing repo's slug"
    );
}

/// A bare mirror with its own remote gets the same slug a working clone of
/// that remote would — the bare/non-bare distinction only matters for
/// `slug_root` (no working tree to resolve paths against).
#[test]
fn slug_of_a_bare_repo_with_a_remote_hashes_the_remote() {
    let dir = TempDir::new().unwrap();
    let url = "https://github.com/example/bare-mirror.git";
    git2::Repository::init_bare(dir.path()).unwrap();
    let mut cfg = git2::Config::open(&dir.path().join("config")).unwrap();
    cfg.set_str("remote.origin.url", url).unwrap();

    let expected = {
        let digest = Sha256::digest(url.as_bytes());
        hex::encode(&digest[..4])
    };
    assert_eq!(derive_slug(dir.path()), expected);
}

// ─── prefix_end edge cases ─────────────────────────────────────────────────

#[test]
fn prefix_end_empty_prefix_returns_sentinel() {
    // No bytes to increment → sentinel covers the whole keyspace.
    assert_eq!(prefix_end(""), "\u{ffff}");
}

#[test]
fn prefix_end_single_ascii_char() {
    assert_eq!(prefix_end("a"), "b"); // 0x61 → 0x62
    assert_eq!(prefix_end("z"), "{"); // 0x7a → 0x7b
}

#[test]
fn prefix_end_known_namespace_boundaries() {
    // ':' (0x3a) + 1 = ';' (0x3b) for every namespace prefix.
    assert_eq!(prefix_end("gotcha:"), "gotcha;");
    assert_eq!(prefix_end("file:"), "file;");
    assert_eq!(prefix_end("decision:"), "decision;");
    assert_eq!(prefix_end("session:"), "session;");
}

// ─── delete + scan interaction ─────────────────────────────────────────────

#[tokio::test]
async fn delete_then_scan_excludes_deleted_key() {
    // Phantom-record regression: delete a key, then scan — must not return it.
    let (store, _dir) = temp_store();
    for key in ["gotcha:a", "gotcha:b", "gotcha:c", "gotcha:d"] {
        store.put(key, &make_record(key)).await.unwrap();
    }
    store.delete("gotcha:b").await.unwrap();
    store.delete("gotcha:d").await.unwrap();

    let results = store.scan_prefix("gotcha:").await.unwrap();
    assert_eq!(results.len(), 2, "deleted keys must not appear in scan");
    let keys: Vec<_> = results.iter().map(|r| r.key.as_str()).collect();
    assert!(keys.contains(&"gotcha:a"), "gotcha:a must survive");
    assert!(keys.contains(&"gotcha:c"), "gotcha:c must survive");
    assert!(!keys.contains(&"gotcha:b"), "gotcha:b must be gone");
    assert!(!keys.contains(&"gotcha:d"), "gotcha:d must be gone");
}

// ─── overwrite + scan deduplication ──────────────────────────────────────

#[tokio::test]
async fn overwrite_does_not_create_duplicate_in_scan() {
    // If SurrealKV MVCC versioning misbehaves, an overwrite could produce
    // two versions both visible under the same key during a range scan.
    let (store, _dir) = temp_store();
    let mut r = make_record("gotcha:dedup-me");
    store.put("gotcha:dedup-me", &r).await.unwrap();
    r.value = "v2".to_string();
    r.version.logical_clock = 2;
    store.put("gotcha:dedup-me", &r).await.unwrap();
    r.value = "v3".to_string();
    r.version.logical_clock = 3;
    store.put("gotcha:dedup-me", &r).await.unwrap();

    let results = store.scan_prefix("gotcha:").await.unwrap();
    assert_eq!(
        results.len(),
        1,
        "3 overwrites of the same key must yield 1 result in scan"
    );
    assert_eq!(results[0].value, "v3", "scan must return the latest value");
    assert_eq!(results[0].version.logical_clock, 3);
}

// ─── full field integrity through the store ────────────────────────────────

#[tokio::test]
async fn put_get_preserves_all_record_fields() {
    use crate::store::record::{
        Category, ConfidenceScore, Priority, QualityScore, QualitySignal, QualityTier, Record,
        RecordLifecycle, RecordSource, RecordVersion, StalenessScore, StalenessSignal,
        StalenessTier,
    };

    let (store, _dir) = temp_store();
    let device_id = uuid::Uuid::new_v4();

    // Construct a fully-populated record — every non-default field set.
    let written = Record {
        key: "gotcha:full-fields".to_string(),
        value: "Never hold a write txn across an await point.".to_string(),
        category: Category::Gotcha,
        priority: Priority::Critical,
        tags: vec![
            "async".to_string(),
            "tokio".to_string(),
            "surrealkv".to_string(),
        ],
        created_at: 1_710_520_800,
        updated_at: 1_710_520_900,
        ref_url: Some("https://github.com/example/issue/99".to_string()),
        staleness: StalenessScore {
            value: 0.42,
            tier: StalenessTier::Stale,
            signals: vec![
                StalenessSignal::NotAccessedDays(45),
                StalenessSignal::LinesChangedPct(0.3),
            ],
            computed_at: 1_710_520_800,
            last_record_sha: "abc123def456".to_string(),
        },
        lifecycle: RecordLifecycle::Active,
        version: RecordVersion {
            device_id,
            logical_clock: 7,
            wall_clock: 1_710_520_900,
        },
        quality: QualityScore {
            value: 0.78,
            tier: QualityTier::Good,
            signals: vec![
                QualitySignal::HasImperativeVerb,
                QualitySignal::HasCausality,
            ],
            computed_at: 1_710_520_800,
        },
        access_count: 12,
        last_accessed: 1_710_520_888,
        source: RecordSource::DeveloperManual,
        confidence: ConfidenceScore {
            value: 0.75,
            confirmation_count: 3,
            contributor_count: 2,
            last_challenged: Some(1_710_500_000),
            challenge_count: 1,
        },
        gap_analysis_score: 0.31,
        payload: None,
    };

    store.put("gotcha:full-fields", &written).await.unwrap();
    let read = store.get("gotcha:full-fields").await.unwrap().unwrap();

    // Verify every field survives the store round-trip.
    assert_eq!(read.key, written.key);
    assert_eq!(read.value, written.value);
    assert_eq!(read.category, written.category);
    assert_eq!(read.priority, written.priority);
    assert_eq!(read.tags, written.tags);
    assert_eq!(read.created_at, written.created_at);
    assert_eq!(read.updated_at, written.updated_at);
    assert_eq!(read.ref_url, written.ref_url);
    assert_eq!(read.staleness.tier, written.staleness.tier);
    assert_eq!(
        read.staleness.last_record_sha,
        written.staleness.last_record_sha
    );
    assert_eq!(read.staleness.signals.len(), 2);
    assert_eq!(read.lifecycle, written.lifecycle);
    assert_eq!(read.version.device_id, written.version.device_id);
    assert_eq!(read.version.logical_clock, written.version.logical_clock);
    assert_eq!(read.version.wall_clock, written.version.wall_clock);
    assert_eq!(read.quality.tier, written.quality.tier);
    assert_eq!(read.quality.signals.len(), 2);
    assert_eq!(read.access_count, written.access_count);
    assert_eq!(read.last_accessed, written.last_accessed);
    assert_eq!(read.source, written.source);
    assert_eq!(
        read.confidence.confirmation_count,
        written.confidence.confirmation_count
    );
    assert_eq!(
        read.confidence.contributor_count,
        written.confidence.contributor_count
    );
    assert_eq!(
        read.confidence.last_challenged,
        written.confidence.last_challenged
    );
    assert_eq!(
        read.confidence.challenge_count,
        written.confidence.challenge_count
    );
    assert!((read.gap_analysis_score - written.gap_analysis_score).abs() < f32::EPSILON);
}

// ─── Eventual durability persistence ──────────────────────────────────────

#[tokio::test]
async fn eventual_keys_survive_clean_close_and_reopen() {
    // The existing reopen test only exercises Immediate (gotcha:) keys.
    // This verifies that session: (Eventual) data also persists after close().
    let dir = tempfile::TempDir::new().unwrap();
    let root = dir.path().join("mati_test");
    std::fs::create_dir_all(&root).unwrap();

    {
        let knowledge = open_knowledge_tree(root.join("knowledge.db")).unwrap();
        let sessions = open_sessions_tree(root.join("sessions.db")).unwrap();
        let search = OnceCell::new();
        let _ = search.set(Search::open(&root.join("search_index")).unwrap());
        let store = Store {
            knowledge,
            sessions,
            search,
            root: root.clone(),
            index_needs_rebuild: false,
        };
        for i in 0..10 {
            let key = format!("session:{i:04}");
            store.put(&key, &make_record(&key)).await.unwrap();
        }
        store.close().await.unwrap(); // must fsync/flush sessions tree on clean close
    }

    {
        let knowledge = open_knowledge_tree(root.join("knowledge.db")).unwrap();
        let sessions = open_sessions_tree(root.join("sessions.db")).unwrap();
        let search = OnceCell::new();
        let _ = search.set(Search::open(&root.join("search_index")).unwrap());
        let store = Store {
            knowledge,
            sessions,
            search,
            root: root.clone(),
            index_needs_rebuild: false,
        };
        let results = store.scan_prefix("session:").await.unwrap();
        assert_eq!(
            results.len(),
            10,
            "Eventual session records must survive a clean close+reopen"
        );
        store.close().await.unwrap();
    }
}

// ─── corruption tolerance: corrupt record in the middle ───────────────────

#[tokio::test]
async fn scan_prefix_corrupt_in_middle_does_not_stop_iteration() {
    // Regression: if scan stops early on corruption rather than skipping,
    // valid records after the corrupt one would silently vanish.
    let (store, _dir) = temp_store();

    store
        .put("gotcha:aaa", &make_record("gotcha:aaa"))
        .await
        .unwrap(); // before corrupt
    store
        .put("gotcha:zzz", &make_record("gotcha:zzz"))
        .await
        .unwrap(); // after corrupt

    // Inject corruption lexicographically between the two valid records.
    {
        let mut txn = store.knowledge.begin().unwrap();
        txn.set_durability(SkvDurability::Immediate);
        txn.set(b"gotcha:mmm", b"not json").unwrap();
        txn.commit().await.unwrap();
    }

    let results = store.scan_prefix("gotcha:").await.unwrap();
    assert_eq!(
        results.len(),
        2,
        "corruption in the middle must not truncate the scan"
    );
    let keys: Vec<_> = results.iter().map(|r| r.key.as_str()).collect();
    assert!(
        keys.contains(&"gotcha:aaa"),
        "record before corruption must be returned"
    );
    assert!(
        keys.contains(&"gotcha:zzz"),
        "record after corruption must be returned"
    );
}

// ─── tombstoned lifecycle through the store ───────────────────────────────

#[tokio::test]
async fn tombstoned_record_survives_store_round_trip() {
    use crate::store::record::{RecordLifecycle, TombstoneReason};
    let (store, _dir) = temp_store();
    let mut r = make_record("file:src/deleted.rs");
    r.lifecycle = RecordLifecycle::Tombstoned {
        reason: TombstoneReason::FileDeleted,
        at: 1_710_520_800,
    };
    store.put("file:src/deleted.rs", &r).await.unwrap();
    let got = store.get("file:src/deleted.rs").await.unwrap().unwrap();
    match got.lifecycle {
        RecordLifecycle::Tombstoned { reason, at } => {
            assert_eq!(reason, TombstoneReason::FileDeleted);
            assert_eq!(at, 1_710_520_800);
        }
        other => panic!("expected Tombstoned, got {other:?}"),
    }
}

#[tokio::test]
async fn superseded_record_survives_store_round_trip() {
    use crate::store::record::RecordLifecycle;
    let (store, _dir) = temp_store();
    let mut r = make_record("gotcha:old-rule");
    r.lifecycle = RecordLifecycle::Superseded {
        by_key: "gotcha:new-rule".to_string(),
    };
    store.put("gotcha:old-rule", &r).await.unwrap();
    let got = store.get("gotcha:old-rule").await.unwrap().unwrap();
    match got.lifecycle {
        RecordLifecycle::Superseded { by_key } => {
            assert_eq!(by_key, "gotcha:new-rule");
        }
        other => panic!("expected Superseded, got {other:?}"),
    }
}

// ─── slug: error-recovery path ────────────────────────────────────────────

#[test]
fn slug_with_git_config_but_no_url_line_falls_back_to_path() {
    let dir = tempfile::TempDir::new().unwrap();
    let git_dir = dir.path().join(".git");
    std::fs::create_dir_all(&git_dir).unwrap();
    // A hand-rolled `.git/config` with no HEAD/objects/refs is not a repo
    // git2 recognizes at all (confirmed: even the `git` CLI refuses it) — so
    // this hits the same "no repo found" fallback as no `.git` whatsoever,
    // not the "repo found, no remote" branch (see the real-repo variant of
    // this test above).
    std::fs::write(
        git_dir.join("config"),
        "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n",
    )
    .unwrap();

    let slug = derive_slug(dir.path());
    let expected = {
        let canon = std::fs::canonicalize(dir.path()).unwrap();
        let input = canon.to_string_lossy().into_owned();
        let digest = Sha256::digest(input.as_bytes());
        hex::encode(&digest[..4])
    };
    assert_eq!(
        slug, expected,
        "an unrecognizable .git must fall back to the canonicalized path hash"
    );
}

#[test]
fn slug_with_no_git_dir_falls_back_to_path() {
    let dir = tempfile::TempDir::new().unwrap();
    // Completely fresh dir, no .git at all.
    let slug = derive_slug(dir.path());
    let expected = {
        let canon = std::fs::canonicalize(dir.path()).unwrap();
        let input = canon.to_string_lossy().into_owned();
        let digest = Sha256::digest(input.as_bytes());
        hex::encode(&digest[..4])
    };
    assert_eq!(slug, expected);
}

/// The on-disk shape of a submodule (and of a linked worktree): `.git` is a
/// FILE containing `gitdir: <path>`, not a directory. Mirrors
/// `health::staleness::tests::make_gitlink_child`.
fn make_gitlink_child(parent: &Path) -> PathBuf {
    git2::Repository::init(parent).unwrap();
    let child = parent.join("sub");
    std::fs::create_dir_all(&child).unwrap();

    let child_git = git2::Repository::init(&child).unwrap().path().to_path_buf();
    let moved = parent.join(".git").join("modules").join("sub");
    std::fs::create_dir_all(moved.parent().unwrap()).unwrap();
    std::fs::rename(&child_git, &moved).unwrap();
    std::fs::write(child.join(".git"), format!("gitdir: {}\n", moved.display())).unwrap();

    let mut cfg = git2::Config::open(&moved.join("config")).unwrap();
    cfg.set_str("core.worktree", child.to_str().unwrap())
        .unwrap();
    child
}

/// This is the bug this fix removes: a `.git` FILE (submodule / linked
/// worktree shape) used to walk past the gitlink to the parent's real
/// `.git/config`, so the child's slug and `slug_root` silently named the
/// PARENT repo. `git2::Repository::discover` resolves the gitlink correctly
/// — the child now gets its own root.
#[test]
fn slug_root_of_a_gitlink_child_is_the_child_itself() {
    let dir = TempDir::new().unwrap();
    let child = make_gitlink_child(dir.path());

    assert_eq!(
        slug_root(&child),
        std::fs::canonicalize(&child).unwrap(),
        "slug_root must resolve to the child's own workdir, not the parent's"
    );
}

/// A submodule's private `.git/modules/<name>/config` carries its own
/// remote, distinct from the parent's, so it gets its OWN slug — the fix
/// for the `file:*` key collision: a submodule's `file:src/lib.rs` and the
/// parent's must never land in the same store.
#[test]
fn slug_differs_for_a_submodule_with_its_own_remote() {
    let dir = TempDir::new().unwrap();
    let child = make_gitlink_child(dir.path());

    let mut parent_cfg = git2::Config::open(&dir.path().join(".git").join("config")).unwrap();
    parent_cfg
        .set_str("remote.origin.url", "https://github.com/example/parent.git")
        .unwrap();

    let mut child_cfg = git2::Config::open(
        &dir.path()
            .join(".git")
            .join("modules")
            .join("sub")
            .join("config"),
    )
    .unwrap();
    child_cfg
        .set_str(
            "remote.origin.url",
            "https://github.com/example/child-submodule.git",
        )
        .unwrap();

    assert_ne!(
        derive_slug(dir.path()),
        derive_slug(&child),
        "a submodule with its own remote must get its own slug, not the parent's"
    );
}

// ─── prefix_end: invalid UTF-8 after increment ────────────────────────────

#[test]
fn prefix_end_0x7f_byte_increments_to_0x80_which_is_invalid_utf8() {
    // 0x7f (DEL) + 1 = 0x80, which is an invalid lone UTF-8 byte.
    // from_utf8 will fail → must return the sentinel "\u{ffff}", not panic.
    let input = String::from_utf8(vec![0x61, 0x7f]).unwrap(); // "a\x7f"
    let result = prefix_end(&input);
    // 0x7f increments to 0x80 — invalid UTF-8 → sentinel fallback
    assert_eq!(
        result, "\u{ffff}",
        "increment of 0x7f produces invalid UTF-8; must fall back to sentinel"
    );
}

#[test]
fn prefix_end_0xfe_byte_increments_to_0xff_still_invalid_utf8() {
    // Similarly, 0xfe → 0xff is also invalid UTF-8.
    let input = unsafe { String::from_utf8_unchecked(vec![0x61, 0xfe]) };
    let result = prefix_end(&input);
    assert_eq!(result, "\u{ffff}");
}

// ─── put_batch ────────────────────────────────────────────────────────────

#[tokio::test]
async fn put_batch_empty_is_noop() {
    let (store, _dir) = temp_store();
    store.put_batch(&[]).await.unwrap();
    assert!(store.scan_prefix("gotcha:").await.unwrap().is_empty());
}

#[tokio::test]
async fn put_batch_single_record_readable() {
    let (store, _dir) = temp_store();
    let r = make_record("gotcha:batch-single");
    store
        .put_batch(&[("gotcha:batch-single", &r)])
        .await
        .unwrap();
    let got = store.get("gotcha:batch-single").await.unwrap().unwrap();
    assert_eq!(got.key, "gotcha:batch-single");
    assert_eq!(got.value, r.value);
}

#[tokio::test]
async fn put_batch_all_records_readable() {
    let (store, _dir) = temp_store();
    let records: Vec<Record> = (0..10)
        .map(|i| make_record(&format!("gotcha:b{i}")))
        .collect();
    let pairs: Vec<(&str, &Record)> = records.iter().map(|r| (r.key.as_str(), r)).collect();
    store.put_batch(&pairs).await.unwrap();
    let results = store.scan_prefix("gotcha:b").await.unwrap();
    assert_eq!(results.len(), 10);
}

#[tokio::test]
async fn put_batch_mixed_durability_both_trees_written() {
    let (store, _dir) = temp_store();
    let immediate = make_record("gotcha:imm");
    let eventual = make_record("session:evt");
    store
        .put_batch(&[("gotcha:imm", &immediate), ("session:evt", &eventual)])
        .await
        .unwrap();
    assert!(store.get("gotcha:imm").await.unwrap().is_some());
    assert!(store.get("session:evt").await.unwrap().is_some());
}

#[tokio::test]
async fn put_batch_matches_sequential_put_for_same_records() {
    let (store_a, _dir_a) = temp_store();
    let (store_b, _dir_b) = temp_store();
    let records: Vec<Record> = (0..20)
        .map(|i| make_record(&format!("file:src/mod{i}.rs")))
        .collect();

    // Sequential puts.
    for r in &records {
        store_a.put(&r.key, r).await.unwrap();
    }
    // Batch put.
    let pairs: Vec<(&str, &Record)> = records.iter().map(|r| (r.key.as_str(), r)).collect();
    store_b.put_batch(&pairs).await.unwrap();

    let a = {
        let mut v = store_a.scan_prefix("file:").await.unwrap();
        v.sort_by(|x, y| x.key.cmp(&y.key));
        v
    };
    let b = {
        let mut v = store_b.scan_prefix("file:").await.unwrap();
        v.sort_by(|x, y| x.key.cmp(&y.key));
        v
    };
    assert_eq!(a.len(), b.len());
    for (ra, rb) in a.iter().zip(b.iter()) {
        assert_eq!(ra.key, rb.key);
        assert_eq!(ra.value, rb.value);
    }
}

/// 1,200-record batch must be measurably faster than 1,200 sequential puts.
/// This test guards against the batch accidentally falling back to N fsyncs.
///
/// Ignored by default (~60s). Run with: `cargo test --lib put_batch_1200 -- --ignored`
#[tokio::test]
#[ignore]
async fn put_batch_1200_faster_than_sequential() {
    use std::time::Instant;

    let (store_seq, _dir_seq) = temp_store();
    let (store_bat, _dir_bat) = temp_store();
    let records: Vec<Record> = (0..1200)
        .map(|i| make_record(&format!("file:src/f{i}.rs")))
        .collect();

    // Sequential baseline.
    let seq_start = Instant::now();
    for r in &records {
        store_seq.put(&r.key, r).await.unwrap();
    }
    let seq_ms = seq_start.elapsed().as_millis();

    // Batch.
    let pairs: Vec<(&str, &Record)> = records.iter().map(|r| (r.key.as_str(), r)).collect();
    let bat_start = Instant::now();
    store_bat.put_batch(&pairs).await.unwrap();
    let bat_ms = bat_start.elapsed().as_millis();

    // Batch must be strictly faster (at least 2× in any environment).
    assert!(
        bat_ms < seq_ms,
        "put_batch ({bat_ms}ms) was not faster than sequential puts ({seq_ms}ms)"
    );

    // Verify all records landed correctly.
    let results = store_bat.scan_prefix("file:").await.unwrap();
    assert_eq!(results.len(), 1200);
}

// ─── search (M-05-C / M-05-F) ─────────────────────────────────────────────

#[tokio::test]
async fn search_returns_matching_records() {
    let (store, _dir) = temp_store();
    let mut r = make_record("gotcha:async-race");
    r.value = "never use inference inside async context".to_string();
    store.put(&r.key, &r).await.unwrap();

    let results = store.search("inference", 10).await.unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].key, "gotcha:async-race");
}

#[tokio::test]
async fn search_empty_and_whitespace_query_returns_empty() {
    let (store, _dir) = temp_store();
    let r = make_record("gotcha:foo");
    store.put(&r.key, &r).await.unwrap();
    for blank in ["", "  ", "\t", "\n"] {
        assert!(
            store.search(blank, 10).await.unwrap().is_empty(),
            "blank query {blank:?} must return empty"
        );
    }
}

#[tokio::test]
async fn search_no_match_returns_empty() {
    let (store, _dir) = temp_store();
    let r = make_record("gotcha:foo");
    store.put(&r.key, &r).await.unwrap();
    assert!(store
        .search("absolutely_no_match_xyzzy99", 10)
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn search_malformed_query_returns_partial_not_error() {
    // Malformed queries must not propagate Err — lenient parse returns
    // best-effort results.
    let (store, _dir) = temp_store();
    let mut r = make_record("gotcha:async-race");
    r.value = "tokio runtime inference race condition".to_string();
    store.put(&r.key, &r).await.unwrap();
    // "tokio AND" has a trailing operator — must not error
    let result = store.search("tokio AND", 10).await;
    assert!(result.is_ok(), "malformed query must not return Err");
}

#[tokio::test]
async fn search_limit_caps_results() {
    let (store, _dir) = temp_store();
    for i in 0..10 {
        let mut r = make_record(&format!("gotcha:item-{i:02}"));
        r.value = "tokio runtime executor gotcha performance".to_string();
        store.put(&r.key, &r).await.unwrap();
    }
    assert_eq!(store.search("tokio", 1).await.unwrap().len(), 1);
    assert_eq!(store.search("tokio", 5).await.unwrap().len(), 5);
    assert_eq!(store.search("tokio", 10).await.unwrap().len(), 10);
    // limit > total docs must return all docs, not panic or error
    assert_eq!(store.search("tokio", 999).await.unwrap().len(), 10);
}

#[tokio::test]
async fn search_deleted_record_not_returned() {
    // Delete should evict the tantivy entry too, not just rely on
    // post-filtering missing keys after a search hit.
    let (store, _dir) = temp_store();
    let mut r = make_record("gotcha:deleted");
    r.value = "this_unique_sentinel_deleted_record".to_string();
    store.put(&r.key, &r).await.unwrap();

    // Confirm it is searchable before deletion
    assert_eq!(
        store
            .search("this_unique_sentinel_deleted_record", 10)
            .await
            .unwrap()
            .len(),
        1
    );

    // Delete from SurrealKV (tantivy index still has the entry)
    store.delete("gotcha:deleted").await.unwrap();

    // Must return empty — the index hit is silently skipped
    let results = store
        .search("this_unique_sentinel_deleted_record", 10)
        .await
        .unwrap();
    assert!(
        results.is_empty(),
        "deleted record must not appear in search results"
    );
}

#[tokio::test]
async fn search_delete_does_not_consume_top_k_slot() {
    let (store, _dir) = temp_store();

    let mut deleted = make_record("gotcha:deleted-slot");
    deleted.value = "shared_sentinel_term".to_string();
    store.put(&deleted.key, &deleted).await.unwrap();

    let mut live = make_record("gotcha:live-slot");
    live.value = "shared_sentinel_term".to_string();
    store.put(&live.key, &live).await.unwrap();

    store.delete(&deleted.key).await.unwrap();

    let results = store.search("shared_sentinel_term", 1).await.unwrap();
    assert_eq!(
        results.len(),
        1,
        "live hit should still fill the top-k slot"
    );
    assert_eq!(results[0].key, "gotcha:live-slot");
}

#[tokio::test]
async fn search_returns_full_record_from_surrealkv_not_tantivy_stored_fields() {
    // Tantivy only stores 6 fields. The full Record (tags, confidence,
    // staleness, etc.) must come from SurrealKV via the key lookup.
    let (store, _dir) = temp_store();
    let mut r = make_record("gotcha:full-record-check");
    r.value = "sentinel_fullrecord_uniqueterm_xqz".to_string();
    r.tags = vec!["production".to_string(), "critical-path".to_string()];
    store.put(&r.key, &r).await.unwrap();

    let results = store
        .search("sentinel_fullrecord_uniqueterm_xqz", 10)
        .await
        .unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(
        results[0].tags,
        vec!["production", "critical-path"],
        "full tags must come from SurrealKV, not tantivy stored fields"
    );
}

/// M-05-F: 20 records total, 5 contain a unique sentinel term.
/// Query must return exactly those 5 with no false positives.
#[tokio::test]
async fn search_m05f_20_records_returns_exactly_correct_5() {
    let (store, _dir) = temp_store();

    // 15 records with unrelated, varied content — must not appear in results
    for i in 0..15 {
        let mut r = make_record(&format!("gotcha:noise-{i:02}"));
        r.value = format!("background noise record about rayon and petgraph item {i}");
        store.put(&r.key, &r).await.unwrap();
    }

    // 5 target records containing the unique sentinel term
    let mut target_keys = Vec::new();
    for i in 0..5 {
        let mut r = make_record(&format!("gotcha:target-{i}"));
        r.value = format!("sentinel_m05f_unique record index {i} with extra text");
        store.put(&r.key, &r).await.unwrap();
        target_keys.push(r.key.clone());
    }

    let results = store.search("sentinel_m05f_unique", 20).await.unwrap();
    let result_keys: Vec<&str> = results.iter().map(|r| r.key.as_str()).collect();

    assert_eq!(
        results.len(),
        5,
        "expected exactly 5 results, got {}: {:?}",
        results.len(),
        result_keys
    );

    for k in &target_keys {
        assert!(
            result_keys.contains(&k.as_str()),
            "target key '{k}' missing from results"
        );
    }

    // No noise records leaked in
    for r in &results {
        assert!(
            r.key.starts_with("gotcha:target-"),
            "noise record '{}' must not appear in results",
            r.key
        );
    }
}

/// Worst-case Store volume: 5,000 records at realistic mati project scale
/// (2,000-file codebase × 2-3 record types). All writes use put_batch
/// (2 fsyncs total: 1 SurrealKV + 1 tantivy) matching how Layer 0 works.
/// Proves BM25 returns exactly 20 targets from 4,980 noise records and
/// that limit enforcement and full-record retrieval both hold at this scale.
#[tokio::test]
async fn search_5k_records_zero_false_positives_limit_and_full_record_correct() {
    let (store, _dir) = temp_store();

    // 4,980 noise records — single put_batch call (2 fsyncs total)
    let noise: Vec<Record> = (0..4_980_usize)
        .map(|i| {
            let mut r = make_record(&format!("file:src/module_{i:04}.rs"));
            r.value = format!(
                "module {i} handles initialization routing configuration management dispatch"
            );
            r
        })
        .collect();
    let noise_pairs: Vec<(&str, &Record)> = noise.iter().map(|r| (r.key.as_str(), r)).collect();
    store.put_batch(&noise_pairs).await.unwrap();

    // 20 target records with unique sentinel + a meaningful tag we can
    // verify came from SurrealKV (not tantivy stored fields)
    let targets: Vec<Record> = (0..20_usize)
        .map(|i| {
            let mut r = make_record(&format!("gotcha:target-{i:02}"));
            r.value = format!("zqx_sentinel_5k_proof unique term record {i}");
            r.tags = vec!["verified-from-surrealkv".to_string()];
            r
        })
        .collect();
    let target_pairs: Vec<(&str, &Record)> = targets.iter().map(|r| (r.key.as_str(), r)).collect();
    store.put_batch(&target_pairs).await.unwrap();

    // ── correctness at limit=100 ─────────────────────────────────────────

    let results = store.search("zqx_sentinel_5k_proof", 100).await.unwrap();
    assert_eq!(
        results.len(),
        20,
        "expected 20 hits from 5,000 records, got {}",
        results.len()
    );

    let result_keys: Vec<&str> = results.iter().map(|r| r.key.as_str()).collect();
    let target_keys: Vec<&str> = targets.iter().map(|r| r.key.as_str()).collect();

    // All 20 targets present
    for k in &target_keys {
        assert!(result_keys.contains(k), "missing target: {k}");
    }
    // Zero noise leaked through
    for r in &results {
        assert!(
            r.key.starts_with("gotcha:target-"),
            "noise record '{}' must not appear in results",
            r.key
        );
    }

    // Full record came from SurrealKV — tantivy doesn't store tags
    for r in &results {
        assert_eq!(
            r.tags,
            vec!["verified-from-surrealkv"],
            "tags must be fetched from SurrealKV, key: {}",
            r.key
        );
    }

    // ── limit enforcement at scale ────────────────────────────────────────

    let limited = store.search("zqx_sentinel_5k_proof", 5).await.unwrap();
    assert_eq!(limited.len(), 5, "limit=5 must cap results at scale");

    // Over-limit returns exactly the matching set
    let over = store.search("zqx_sentinel_5k_proof", 999).await.unwrap();
    assert_eq!(
        over.len(),
        20,
        "limit > match count must return all 20 matches, not panic"
    );

    // ── ensure noise records are NOT findable by sentinel term ────────────

    // Pick a random noise record key, search by a term from its value
    // that does NOT appear in sentinel records
    let noise_only_results = store.search("zqx_sentinel_5k_proof", 100).await.unwrap();
    for r in &noise_only_results {
        assert!(
            !r.key.starts_with("file:src/module_"),
            "noise module record should not match sentinel query: {}",
            r.key
        );
    }
}

// ─── M-05-D: index rebuild ────────────────────────────────────────────────

// Helper: make_record with a custom value (needed to control searchable content).
fn make_record_v(key: &str, value: &str) -> Record {
    let mut r = make_record(key);
    r.value = value.to_string();
    r
}

// Helper: open a fresh store over an existing data directory (bypasses slug
// derivation so tests can point at a tempdir directly).
fn reopen_store(root: &std::path::Path) -> Store {
    let knowledge = open_knowledge_tree(root.join("knowledge.db")).unwrap();
    let sessions = open_sessions_tree(root.join("sessions.db")).unwrap();
    let search = OnceCell::new();
    let _ = search.set(Search::open(&root.join("search_index")).unwrap());
    Store {
        knowledge,
        sessions,
        search,
        root: root.to_path_buf(),
        index_needs_rebuild: false,
    }
}

async fn reopen_store_open_and_rebuild_like(root: &std::path::Path) -> Store {
    let knowledge = open_knowledge_tree(root.join("knowledge.db")).unwrap();
    let sessions = open_sessions_tree(root.join("sessions.db")).unwrap();
    let mut store = Store {
        knowledge,
        sessions,
        search: OnceCell::new(),
        root: root.to_path_buf(),
        index_needs_rebuild: false,
    };

    let search_path = store.root.join("search_index");
    let stale_marker = store.root.join(SEARCH_STALE_MARKER);
    let has_stale_marker = stale_marker.exists();
    let has_sync_pending = store.root.join(SEARCH_SYNC_PENDING).exists();

    if (has_stale_marker || has_sync_pending) && search_path.exists() {
        std::fs::remove_dir_all(&search_path).unwrap();
    }

    match Search::open(&search_path) {
        Ok(s) => {
            let _ = store.search.set(s);
        }
        Err(_) => {
            if search_path.exists() {
                std::fs::remove_dir_all(&search_path).unwrap();
            }
            let _ = store.search.set(Search::open(&search_path).unwrap());
            store.index_needs_rebuild = true;
        }
    }

    if has_stale_marker || has_sync_pending {
        store.index_needs_rebuild = true;
    }

    if store.index_needs_rebuild {
        store.rebuild_search_index().await.unwrap();
        let _ = std::fs::remove_file(store.root.join(SEARCH_SYNC_PENDING));
        if has_stale_marker {
            let _ = std::fs::remove_file(&stale_marker);
        }
    }

    store
}

/// Write records, close, delete search_index/, reopen with a fresh empty
/// index, call rebuild_search_index — all records must be searchable again.
#[tokio::test]
async fn rebuild_search_index_after_missing_index_restores_search() {
    let (store, _dir) = temp_store();
    let root = store.root.clone();

    // Write 10 records with a unique sentinel term in their values
    let records: Vec<Record> = (0..10)
        .map(|i| {
            make_record_v(
                &format!("gotcha:rebuild-miss-{i:02}"),
                "xq_rebuild_missing_sentinel unique term",
            )
        })
        .collect();
    let pairs: Vec<(&str, &Record)> = records.iter().map(|r| (r.key.as_str(), r)).collect();
    store.put_batch(&pairs).await.unwrap();
    store.close().await.unwrap();

    // Simulate missing index (deleted by user, first run after migration, etc.)
    std::fs::remove_dir_all(root.join("search_index")).unwrap();

    // Reopen with fresh empty index, then rebuild
    let store2 = reopen_store(&root);
    assert!(
        !store2.index_needs_rebuild(),
        "reopen_store sets flag=false; we test rebuild directly"
    );

    let committed = store2.rebuild_search_index().await.unwrap();
    assert_eq!(committed, 10, "rebuild must commit all 10 records");

    let results = store2
        .search("xq_rebuild_missing_sentinel", 20)
        .await
        .unwrap();
    assert_eq!(
        results.len(),
        10,
        "all records must be findable after rebuild"
    );
}

/// Corrupt meta.json → Store-level open logic must wipe and flag rebuild.
/// After rebuild_search_index the record is searchable again.
#[tokio::test]
async fn rebuild_search_index_after_corrupt_index_restores_search() {
    let (store, _dir) = temp_store();
    let root = store.root.clone();

    let r = make_record_v(
        "gotcha:rebuild-corrupt",
        "xq_rebuild_corrupt_sentinel unique",
    );
    store.put("gotcha:rebuild-corrupt", &r).await.unwrap();
    store.close().await.unwrap();

    // Corrupt the index by overwriting meta.json with garbage
    std::fs::write(
        root.join("search_index").join("meta.json"),
        b"not valid json {{{{",
    )
    .unwrap();

    // Replicate the Store::open_and_rebuild recovery path: Search::open fails → wipe → reopen
    let knowledge = open_knowledge_tree(root.join("knowledge.db")).unwrap();
    let sessions = open_sessions_tree(root.join("sessions.db")).unwrap();
    let search_path = root.join("search_index");
    let (search_cell, needs_rebuild) = {
        let cell = OnceCell::new();
        match Search::open(&search_path) {
            Ok(s) => {
                let _ = cell.set(s);
                (cell, false)
            }
            Err(_) => {
                std::fs::remove_dir_all(&search_path).unwrap();
                let _ = cell.set(Search::open(&search_path).unwrap());
                (cell, true)
            }
        }
    };
    let store2 = Store {
        knowledge,
        sessions,
        search: search_cell,
        root: root.clone(),
        index_needs_rebuild: needs_rebuild,
    };

    assert!(
        store2.index_needs_rebuild(),
        "corrupt meta.json must trigger rebuild flag"
    );

    store2.rebuild_search_index().await.unwrap();

    let results = store2
        .search("xq_rebuild_corrupt_sentinel", 10)
        .await
        .unwrap();
    assert_eq!(
        results.len(),
        1,
        "record must be searchable after rebuild from corrupt state"
    );
    assert_eq!(results[0].key, "gotcha:rebuild-corrupt");
}

/// rebuild_search_index returns the exact number of records it committed.
#[tokio::test]
async fn rebuild_search_index_returns_committed_count() {
    let (store, _dir) = temp_store();
    let root = store.root.clone();

    let records: Vec<Record> = (0..7)
        .map(|i| make_record(&format!("file:src/mod_{i}.rs")))
        .collect();
    let pairs: Vec<(&str, &Record)> = records.iter().map(|r| (r.key.as_str(), r)).collect();
    store.put_batch(&pairs).await.unwrap();
    store.close().await.unwrap();

    // Fresh empty index — simulates post-corrupt open
    std::fs::remove_dir_all(root.join("search_index")).unwrap();
    let store2 = reopen_store(&root);
    let committed = store2.rebuild_search_index().await.unwrap();
    assert_eq!(
        committed, 7,
        "committed count must equal number of records in SurrealKV"
    );
}

#[tokio::test]
async fn open_and_rebuild_like_wipes_stale_index_when_sync_pending_exists() {
    let (store, _dir) = temp_store();
    let root = store.root.clone();

    let deleted = make_record_v("gotcha:deleted-after-crash", "shared_crash_sentinel");
    let live = make_record_v("gotcha:live-after-crash", "shared_crash_sentinel");

    store.put(&deleted.key, &deleted).await.unwrap();
    store.put(&live.key, &live).await.unwrap();
    store.delete(&deleted.key).await.unwrap();

    // Simulate a stale tantivy entry surviving a crash window.
    store.ensure_search().unwrap().add_record(&deleted).unwrap();
    std::fs::write(root.join(SEARCH_SYNC_PENDING), b"").unwrap();
    store.close().await.unwrap();

    let reopened = reopen_store_open_and_rebuild_like(&root).await;
    let results = reopened.search("shared_crash_sentinel", 1).await.unwrap();
    assert_eq!(
        results.len(),
        1,
        "live record should fill top-k after rebuild"
    );
    assert_eq!(results[0].key, "gotcha:live-after-crash");
    assert!(
        !root.join(SEARCH_SYNC_PENDING).exists(),
        "successful rebuild should clear sync-pending marker"
    );
}

#[tokio::test]
async fn put_leaves_sync_pending_when_search_cannot_initialize() {
    let dir = TempDir::new().unwrap();
    let root = dir.path().join("mati_test");
    std::fs::create_dir_all(&root).unwrap();
    let knowledge = open_knowledge_tree(root.join("knowledge.db")).unwrap();
    let sessions = open_sessions_tree(root.join("sessions.db")).unwrap();
    std::fs::write(root.join("search_index"), b"not a directory").unwrap();

    let store = Store {
        knowledge,
        sessions,
        search: OnceCell::new(),
        root: root.clone(),
        index_needs_rebuild: false,
    };

    let record = make_record("gotcha:search-sync-failure");
    store.put(&record.key, &record).await.unwrap();

    assert!(
        root.join(SEARCH_SYNC_PENDING).exists(),
        "failed search sync must leave the crash-fence marker in place"
    );
}

/// Calling rebuild_search_index twice must not panic; query deduplication
/// in query_keys ensures each key appears exactly once in results.
#[tokio::test]
async fn rebuild_search_index_twice_is_safe() {
    let (store, _dir) = temp_store();
    let r = make_record_v("gotcha:idempotent", "xq_rebuild_idempotent_sentinel unique");
    store.put("gotcha:idempotent", &r).await.unwrap();

    store.rebuild_search_index().await.unwrap();
    store.rebuild_search_index().await.unwrap();

    let results = store
        .search("xq_rebuild_idempotent_sentinel", 10)
        .await
        .unwrap();
    assert_eq!(
        results.len(),
        1,
        "dedup must collapse duplicate tantivy entries to one result"
    );
}

/// Normal open (healthy index) must not set index_needs_rebuild.
#[tokio::test]
async fn open_healthy_index_does_not_set_rebuild_flag() {
    let (store, _dir) = temp_store();
    assert!(!store.index_needs_rebuild());
}

// ─── history (M-14) ──────────────────────────────────────────────────────

#[tokio::test]
async fn history_empty_key_returns_error() {
    let (store, _dir) = temp_store();
    let result = store.history("", 0);
    assert!(result.is_err(), "empty key must be rejected");
}

#[tokio::test]
async fn history_single_version() {
    let (store, _dir) = temp_store();
    store
        .put("gotcha:single", &make_record("gotcha:single"))
        .await
        .unwrap();

    let entries = store.history("gotcha:single", 0).unwrap();
    assert!(!entries.is_empty(), "must return at least one version");
    assert!(!entries[0].is_tombstone);
    assert!(entries[0].record.is_some());
    assert_eq!(entries[0].record.as_ref().unwrap().key, "gotcha:single");
}

#[tokio::test]
async fn history_multiple_versions_newest_first() {
    let (store, _dir) = temp_store();
    let mut r = make_record("gotcha:multi");
    r.value = "v1".to_string();
    store.put("gotcha:multi", &r).await.unwrap();
    r.value = "v2".to_string();
    r.version.logical_clock = 2;
    store.put("gotcha:multi", &r).await.unwrap();
    r.value = "v3".to_string();
    r.version.logical_clock = 3;
    store.put("gotcha:multi", &r).await.unwrap();

    let entries = store.history("gotcha:multi", 0).unwrap();
    assert!(
        entries.len() >= 3,
        "expected >=3 versions, got {}",
        entries.len()
    );

    // Newest first: timestamps must be non-increasing
    for pair in entries.windows(2) {
        assert!(
            pair[0].timestamp_ns >= pair[1].timestamp_ns,
            "history must be newest-first: {} >= {}",
            pair[0].timestamp_ns,
            pair[1].timestamp_ns,
        );
    }

    // Newest entry should have the latest value
    let newest = entries[0].record.as_ref().unwrap();
    assert_eq!(newest.value, "v3");
}

#[tokio::test]
async fn history_includes_tombstones() {
    let (store, _dir) = temp_store();
    store
        .put("gotcha:tomb", &make_record("gotcha:tomb"))
        .await
        .unwrap();

    // Use soft_delete (not hard delete) so SurrealKV retains the tombstone
    // marker in the version history. Store::delete is a hard delete that
    // erases all versions completely — the history API surfaces soft-delete
    // tombstones from lifecycle transitions.
    {
        let mut txn = store.knowledge.begin_with_mode(Mode::WriteOnly).unwrap();
        txn.set_durability(SkvDurability::Immediate);
        txn.soft_delete(b"gotcha:tomb").unwrap();
        txn.commit().await.unwrap();
    }

    let entries = store.history("gotcha:tomb", 0).unwrap();
    assert!(
        entries.len() >= 2,
        "must have create + soft-delete, got {}",
        entries.len()
    );
    // At least one tombstone must exist
    assert!(
        entries.iter().any(|e| e.is_tombstone),
        "tombstone must be present in history",
    );
}

#[tokio::test]
async fn history_no_key_spill() {
    let (store, _dir) = temp_store();
    store
        .put("gotcha:alpha", &make_record("gotcha:alpha"))
        .await
        .unwrap();
    store
        .put(
            "gotcha:alpha-extended",
            &make_record("gotcha:alpha-extended"),
        )
        .await
        .unwrap();
    store
        .put("gotcha:beta", &make_record("gotcha:beta"))
        .await
        .unwrap();

    let entries = store.history("gotcha:alpha", 0).unwrap();
    for e in &entries {
        if let Some(ref rec) = e.record {
            assert_eq!(
                rec.key, "gotcha:alpha",
                "spilled into adjacent key: {}",
                rec.key
            );
        }
    }
}

#[tokio::test]
async fn history_limit() {
    let (store, _dir) = temp_store();
    let mut r = make_record("gotcha:limited");
    for i in 0..5 {
        r.value = format!("v{i}");
        r.version.logical_clock = i as u64;
        store.put("gotcha:limited", &r).await.unwrap();
    }

    let entries = store.history("gotcha:limited", 2).unwrap();
    assert!(
        entries.len() <= 2,
        "limit=2 but got {} entries",
        entries.len()
    );
}

#[tokio::test]
async fn history_since_filters_old_versions() {
    let (store, _dir) = temp_store();
    let mut r = make_record("gotcha:since");
    r.value = "old".to_string();
    store.put("gotcha:since", &r).await.unwrap();

    // Capture a "since" timestamp between writes — use nanosecond
    // granularity so we can convert to seconds.
    let since_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    r.value = "new".to_string();
    r.version.logical_clock = 2;
    store.put("gotcha:since", &r).await.unwrap();

    let entries = store.history_since("gotcha:since", since_secs, 0).unwrap();
    // Should contain at least the "new" version
    assert!(
        !entries.is_empty(),
        "since filter should include the recent write",
    );
    // Verify all returned timestamps are >= since_secs
    for e in &entries {
        assert!(
            e.timestamp_secs >= since_secs.saturating_sub(1),
            "entry ts {} is before since {}",
            e.timestamp_secs,
            since_secs,
        );
    }
}

#[tokio::test]
async fn records_since_with_dep() {
    let (store, _dir) = temp_store();

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let old_ts = now.saturating_sub(3600);

    let mut old_rec = make_record("gotcha:old");
    old_rec.updated_at = old_ts;
    store.put("gotcha:old", &old_rec).await.unwrap();

    let mut new_gotcha = make_record("gotcha:new");
    new_gotcha.updated_at = now;
    store.put("gotcha:new", &new_gotcha).await.unwrap();

    let mut dep_rec = make_record("dep:cargo:serde");
    dep_rec.category = crate::store::record::Category::Dependency;
    dep_rec.updated_at = now;
    store.put("dep:cargo:serde", &dep_rec).await.unwrap();

    let since = now.saturating_sub(60);
    let results = store.records_since(since, 0).await.unwrap();
    let keys: Vec<&str> = results.iter().map(|r| r.key.as_str()).collect();

    assert!(keys.contains(&"gotcha:new"), "new gotcha should appear");
    assert!(
        keys.contains(&"dep:cargo:serde"),
        "dep record should appear"
    );
    assert!(
        !keys.contains(&"gotcha:old"),
        "old gotcha should be excluded"
    );

    // Verify newest-first ordering
    for pair in results.windows(2) {
        assert!(
            pair[0].updated_at >= pair[1].updated_at,
            "results must be newest-first",
        );
    }
}

#[tokio::test]
async fn records_since_respects_limit() {
    let (store, _dir) = temp_store();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    for i in 0..10 {
        let mut r = make_record(&format!("gotcha:lim-{i:02}"));
        r.updated_at = now;
        store.put(&r.key, &r).await.unwrap();
    }

    let results = store.records_since(now.saturating_sub(1), 3).await.unwrap();
    assert_eq!(results.len(), 3, "limit=3 should cap at 3");
}

#[test]
fn history_entry_timestamp_conversion() {
    let entry = HistoryEntry {
        timestamp_secs: 1_710_520_800,
        timestamp_ns: 1_710_520_800_000_000_000,
        record: None,
        is_tombstone: false,
    };
    assert_eq!(entry.timestamp_secs, entry.timestamp_ns / 1_000_000_000);
}

// ─── lock_error_hint ──────────────────────────────────────────────────

#[test]
fn lock_error_hint_rewrites_real_lock_contention_error() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("knowledge.db");
    std::fs::create_dir_all(&db_path).unwrap();

    // Write a fake LOCK file with a PID
    std::fs::write(db_path.join("LOCK"), "12345\n").unwrap();

    let err = anyhow::anyhow!("Database at /foo/LOCK is already locked by another process");
    let result = lock_error_hint(err, &db_path);
    let msg = format!("{result}");
    assert!(
        msg.contains("another mati process holds the lock"),
        "should rewrite lock error, got: {msg}"
    );
    assert!(
        msg.contains("PID: 12345"),
        "should include holder PID, got: {msg}"
    );
}

#[test]
fn lock_error_hint_passes_through_non_lock_errors() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("knowledge.db");
    std::fs::create_dir_all(&db_path).unwrap();

    // LOCK file exists (as it always does after first use)
    std::fs::write(db_path.join("LOCK"), "99999\n").unwrap();

    let err = anyhow::anyhow!("WAL segment corrupt at offset 1234");
    let result = lock_error_hint(err, &db_path);
    let msg = format!("{result}");
    assert!(
        msg.contains("WAL segment corrupt"),
        "non-lock errors must pass through unchanged, got: {msg}"
    );
    assert!(
        !msg.contains("another mati process"),
        "non-lock errors must NOT be rewritten to lock errors, got: {msg}"
    );
}

// ── Transaction tree-routing invariant tests ───────────────────────

#[tokio::test]
async fn transact_knowledge_rejects_sessions_key() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).await.unwrap();

    // "session:foo" routes to Eventual (sessions tree).
    let ops = vec![KnowledgeWriteOp::PutRaw {
        key: "session:foo",
        value: b"data",
    }];
    let err = store.transact_knowledge(&ops).await.unwrap_err();
    assert!(
        err.to_string().contains("routes to sessions tree"),
        "wrong-tree key must be rejected: {err}"
    );
}

#[tokio::test]
async fn transact_sessions_raw_rejects_knowledge_key() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).await.unwrap();

    // "gotcha:foo" routes to Immediate (knowledge tree).
    let entries: Vec<(&str, &[u8])> = vec![("gotcha:foo", b"data")];
    let err = store.transact_sessions_raw(&entries).await.unwrap_err();
    assert!(
        err.to_string().contains("routes to knowledge tree"),
        "wrong-tree key must be rejected: {err}"
    );
}

#[tokio::test]
async fn transact_knowledge_accepts_valid_knowledge_keys() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).await.unwrap();

    let ops = vec![
        KnowledgeWriteOp::PutRaw {
            key: "gotcha:test",
            value: b"data1",
        },
        KnowledgeWriteOp::PutRaw {
            key: "audit:knowledge:123",
            value: b"data2",
        },
    ];
    store
        .transact_knowledge(&ops)
        .await
        .expect("valid knowledge keys must succeed");
}

#[tokio::test]
async fn transact_sessions_raw_accepts_valid_session_keys() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).await.unwrap();

    let entries: Vec<(&str, &[u8])> = vec![
        ("session:consulted:file:foo", b"data1"),
        ("audit:session:123", b"data2"),
        ("analytics:hit_2026-04-09", b"data3"),
    ];
    store
        .transact_sessions_raw(&entries)
        .await
        .expect("valid session keys must succeed");
}
