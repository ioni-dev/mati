//! `mati seal` — the Tier 2 command surface.
//!
//! Arms and disarms the read floor whose mode bit, manifest and receipt lift
//! live in `mati_core::seal`. `add` tags the file's confirmed gotchas
//! `consult-to-read`, records the original mode, then chmods `000`; `clear` is
//! rung 1 of the restore ladder and never opens the store.
//!
//! Selector is the `consult-to-read` tag, never `crown-jewel`: reads work under
//! `crown-jewel` by design, and overloading it would change that silently.

use anyhow::{bail, Context, Result};
use clap::{Args, Subcommand};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use mati_core::seal::{
    manifest_path, read_manifest, restore_one, write_manifest, Manifest, SealedFile, RESTORE_NOTE,
    SEALED_MODE, TAG_CONSULT_TO_READ,
};
use mati_core::store::{GotchaRecord, Record, RecordLifecycle};

use super::proxy::StoreProxy;
use super::sandbox::{
    add_tags, blast_radius, normalize_rel, remove_tags, repo_root_for, resolve_under_repo,
};

#[derive(Args, Debug)]
pub struct SealArgs {
    #[command(subcommand)]
    pub command: SealCommand,
}

#[derive(Subcommand, Debug)]
pub enum SealCommand {
    /// Seal a file: tag its confirmed gotcha, record the mode, then chmod 000.
    Add(FileArgs),
    /// Unseal one file: restore its mode and drop the tag.
    Remove(FileArgs),
    /// List sealed files and the modes they will be restored to.
    List,
    /// Restore every sealed file from the manifest. Does not open the store.
    Clear,
}

#[derive(Args, Debug)]
pub struct FileArgs {
    /// Repo-relative file path (must already have a confirmed gotcha).
    pub file: String,
    /// Confirm when the gotcha also covers other files (the tag is per-gotcha).
    #[arg(long)]
    pub yes: bool,
}

pub async fn run(args: SealArgs) -> Result<()> {
    match args.command {
        SealCommand::Add(a) => run_seal(a, true).await,
        SealCommand::Remove(a) => run_seal(a, false).await,
        SealCommand::List => run_list(),
        SealCommand::Clear => run_clear(),
    }
}

// ── seal / unseal ───────────────────────────────────────────────────────────

async fn run_seal(args: FileArgs, add: bool) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let repo_root = repo_root_for(&cwd)?;
    let rel = normalize_rel(&args.file);

    let (abs, meta) = seal_target(&repo_root, &rel)?;

    let store = StoreProxy::open(&cwd).await?;
    let matched = confirmed_gotchas_for(&store, &rel).await?;
    // Only `add` needs a gotcha to tag. Requiring one to unseal would strand a
    // file whose gotcha was tombstoned after it was sealed.
    if add && matched.is_empty() {
        bail!(
            "no confirmed gotcha covers `{rel}` — add one first:\n  \
             mati gotcha add {rel} -r \"<rule>\"   then   mati gotcha confirm <key>"
        );
    }
    let verb = if add { "seal" } else { "unseal" };
    for r in &matched {
        if let Some(g) = r.payload_as::<GotchaRecord>() {
            let others = blast_radius(&rel, &g.affected_files);
            if !others.is_empty() && !args.yes {
                eprintln!("`{}` also covers: {}", r.key, others.join(", "));
                bail!("the consult-to-read tag is per-gotcha, so this would {verb} those too — re-run with --yes to confirm, or split the gotcha");
            }
        }
    }

    let mpath = manifest_path(&repo_root)?;
    let mut manifest = read_manifest(&mpath);
    let key = abs.to_string_lossy().to_string();
    let mode = meta.permissions().mode() & 0o7777;
    let row = manifest_row(&manifest, &key, mode);
    let n = tag_gotchas(&store, &matched, add).await?;

    if add {
        match row {
            // Re-recording would store 000 as the original and lose the real one.
            ManifestRow::Recorded(f) => {
                println!("`{rel}` was already sealed (original mode {}).", f.mode)
            }
            ManifestRow::AtFloorUnrecorded => bail!(
                "`{rel}` is already mode 000 but is not in the manifest, so mati cannot know \
                 its original mode — run `chmod u+rw {rel}` first, then seal it"
            ),
            ManifestRow::Absent => {
                manifest.files.push(SealedFile {
                    path: key.clone(),
                    mode: format!("{mode:o}"),
                    ..Default::default()
                });
                // Write-ahead: the record must survive a crash during the chmod.
                write_manifest(&mpath, &manifest)?;
            }
        }
        // `reseal` hashes while the file is still readable, chmods, then reads
        // ctime and writes the stamp the post-Bash sweep compares against. The
        // write-ahead row above is what a crash inside it falls back to.
        let store_root = mpath.parent().unwrap_or(&mpath).to_path_buf();
        if !mati_core::seal::reseal(&store_root, &repo_root, &rel) {
            std::fs::set_permissions(&abs, std::fs::Permissions::from_mode(SEALED_MODE))
                .with_context(|| format!("cannot chmod {}", abs.display()))?;
        }
        println!("Sealed `{rel}` at mode 000 ({n} gotcha(s) tagged {TAG_CONSULT_TO_READ}).");
        println!("  Your editor, language server and build cannot read it either.");
        println!("  Undo: mati seal remove {rel}   |   all: mati seal clear");
        // The mode bit is a floor the sweep repairs after the fact. Claude
        // Code compiles `denyWrite` to `(deny file-write* …)`, so the same path
        // under `mati sandbox protect` cannot be chmod'd or unlinked at all —
        // verified 2026-08-31 with a control. It needs `sandbox.enabled`, which
        // mati never writes, so this is a pointer and not a default.
        println!("  With Claude Code's sandbox on, `mati sandbox protect {rel}` also");
        println!("  prevents the chmod instead of repairing it afterwards.");
    } else {
        match row {
            ManifestRow::Recorded(f) => {
                restore_one(&f)?;
                manifest.files.retain(|x| x.path != key);
                write_manifest(&mpath, &manifest)?;
                println!(
                    "Unsealed `{rel}` to mode {} ({n} gotcha(s) untagged).",
                    f.mode
                );
            }
            // A file at mode 000 with no row is the state a deleted manifest
            // leaves behind, and "was not sealed" is a lie the developer will
            // act on. mati cannot know the original mode, so it does what rung
            // 3 does: restore owner read/write and say so.
            ManifestRow::AtFloorUnrecorded => {
                std::fs::set_permissions(&abs, std::fs::Permissions::from_mode(0o600))
                    .with_context(|| format!("cannot chmod {}", abs.display()))?;
                println!("`{rel}` is mode 000 but has no manifest row, so mati cannot know its");
                println!("original mode. Restored owner read/write (600) — the same under-restore");
                println!("`chmod -R u+rwX` performs. ({n} gotcha(s) untagged.)");
                println!("  `git checkout -- {rel}` recovers the executable bit if it had one.");
            }
            ManifestRow::Absent => println!("`{rel}` was not sealed ({n} gotcha(s) untagged)."),
        }
    }
    Ok(())
}

/// Resolve `rel` to the file `seal` may chmod, or explain why it may not.
///
/// The two refusals are the ones that cost a session: `chmod 000` under `.git`
/// takes git away, and on a directory takes the whole subtree.
fn seal_target(repo_root: &Path, rel: &str) -> Result<(PathBuf, std::fs::Metadata)> {
    let abs = resolve_under_repo(repo_root, rel).with_context(|| {
        format!(
            "`{rel}` does not resolve to a path under {}",
            repo_root.display()
        )
    })?;
    if abs.components().any(|c| c.as_os_str() == ".git") {
        bail!(
            "refusing to seal `{rel}`: an unreadable path under .git removes git from the session"
        );
    }
    let meta = std::fs::metadata(&abs).with_context(|| format!("cannot stat {}", abs.display()))?;
    if !meta.is_file() {
        bail!("`{rel}` is not a regular file");
    }
    Ok((abs, meta))
}

/// What the manifest knows about one path.
enum ManifestRow {
    Recorded(SealedFile),
    /// At mode 000 with no row — the state a deleted manifest leaves behind.
    /// The original mode is unrecoverable, so `add` refuses and `remove`
    /// under-restores rather than either one inventing a mode.
    AtFloorUnrecorded,
    Absent,
}

fn manifest_row(manifest: &Manifest, key: &str, live_mode: u32) -> ManifestRow {
    match manifest.find(key) {
        Some(f) => ManifestRow::Recorded(f.clone()),
        None if live_mode == SEALED_MODE => ManifestRow::AtFloorUnrecorded,
        None => ManifestRow::Absent,
    }
}

/// Confirmed, active gotchas naming `rel`. Unconfirmed records are Layer 0
/// stubs and tombstoned ones are retracted; neither may arm a read floor.
fn covers(r: &Record, rel: &str) -> bool {
    matches!(r.lifecycle, RecordLifecycle::Active)
        && r.payload_as::<GotchaRecord>()
            .map(|g| g.confirmed && g.affected_files.iter().any(|af| normalize_rel(af) == rel))
            .unwrap_or(false)
}

async fn confirmed_gotchas_for(store: &StoreProxy, rel: &str) -> Result<Vec<Record>> {
    Ok(store
        .scan_prefix("gotcha:")
        .await?
        .into_iter()
        .filter(|r| covers(r, rel))
        .collect())
}

async fn tag_gotchas(store: &StoreProxy, matched: &[Record], add: bool) -> Result<usize> {
    let mut n = 0;
    for r in matched {
        if let Some(mut rec) = store.get(&r.key).await? {
            if add {
                add_tags(&mut rec.tags, &[TAG_CONSULT_TO_READ]);
            } else {
                remove_tags(&mut rec.tags, &[TAG_CONSULT_TO_READ]);
            }
            store.put(&r.key, &rec).await?;
            n += 1;
        }
    }
    Ok(n)
}

// ── list / clear ────────────────────────────────────────────────────────────

fn run_list() -> Result<()> {
    let repo_root = repo_root_for(&std::env::current_dir()?)?;
    let mpath = manifest_path(&repo_root)?;
    let manifest = read_manifest(&mpath);
    if manifest.files.is_empty() {
        println!("Nothing sealed.");
        return Ok(());
    }
    println!("{}", mpath.display());
    for f in &manifest.files {
        let live = std::fs::metadata(&f.path)
            .map(|m| format!("{:o}", m.permissions().mode() & 0o7777))
            .unwrap_or_else(|_| "missing".to_string());
        println!("  {}  restores to {}  (now {live})", f.path, f.mode);
    }
    println!("\n{RESTORE_NOTE}");
    Ok(())
}

/// Rung 1 of the restore ladder. Deliberately store-free: the cases this exists
/// for include a daemon wedged on the store lock.
fn run_clear() -> Result<()> {
    clear_sealed(&repo_root_for(&std::env::current_dir()?)?)
}

fn clear_sealed(repo_root: &Path) -> Result<()> {
    let mpath = manifest_path(repo_root)?;
    let mut manifest = read_manifest(&mpath);
    if manifest.files.is_empty() {
        println!("Nothing sealed.");
        // An empty manifest and a deleted one are indistinguishable here, and
        // `clear` never opens the store, so it cannot tell them apart. Name
        // rung 3 rather than let a stranded file look like a clean tree.
        println!(
            "  If a file is still unreadable, mati has no record of it — \
             `chmod -R u+rwX {}` restores owner access.",
            repo_root.display()
        );
        return Ok(());
    }

    let mut failed: Vec<String> = Vec::new();
    for f in &manifest.files {
        if let Err(e) = restore_one(f) {
            eprintln!("could not restore {}: {e}", f.path);
            failed.push(f.path.clone());
        }
    }
    let restored = manifest.files.len() - failed.len();
    manifest.files.retain(|f| failed.contains(&f.path));
    write_manifest(&mpath, &manifest)?;

    println!("Restored {restored} file(s).");
    if !failed.is_empty() {
        bail!(
            "{} file(s) still sealed — `chmod -R u+rwX {}` restores owner access without mati",
            failed.len(),
            repo_root.display()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mati_core::store::{
        Category, ConfidenceScore, Priority, QualityScore, RecordSource, RecordVersion,
        StalenessScore, TombstoneReason,
    };

    /// A canonical tempdir. `resolve_under_repo` canonicalizes the target and
    /// compares with `starts_with`, so an uncanonicalized root (macOS hands out
    /// `/var/...` for `/private/var/...`) would fail every containment check.
    fn repo() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    fn root_of(dir: &tempfile::TempDir) -> PathBuf {
        std::fs::canonicalize(dir.path()).unwrap()
    }

    fn write_file(root: &Path, rel: &str, mode: u32) -> PathBuf {
        let abs = root.join(rel);
        std::fs::create_dir_all(abs.parent().unwrap()).unwrap();
        std::fs::write(&abs, b"x").unwrap();
        std::fs::set_permissions(&abs, std::fs::Permissions::from_mode(mode)).unwrap();
        abs
    }

    fn mode_of(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o7777
    }

    fn sealed(path: &Path, mode: &str) -> SealedFile {
        SealedFile {
            path: path.to_string_lossy().to_string(),
            mode: mode.to_string(),
            ..Default::default()
        }
    }

    /// `Manifest::restore` is private to `mati_core`, so build one field by
    /// field rather than with struct-update syntax.
    fn manifest_of(files: Vec<SealedFile>) -> Manifest {
        let mut m = Manifest::default();
        m.files = files;
        m
    }

    fn gotcha(files: &[&str], confirmed: bool, lifecycle: RecordLifecycle) -> Record {
        let payload = GotchaRecord {
            rule: "Consult before reading".into(),
            reason: "because the file is under a read floor".into(),
            severity: Priority::High,
            affected_files: files.iter().map(|s| s.to_string()).collect(),
            ref_url: None,
            discovered_session: 1_000_000,
            confirmed,
            confirmed_content: Default::default(),
        };
        Record {
            key: "gotcha:sealed".into(),
            value: payload.rule.clone(),
            payload: serde_json::to_value(&payload).ok(),
            category: Category::Gotcha,
            priority: Priority::High,
            tags: vec![],
            created_at: 1_000_000,
            updated_at: 1_000_000,
            ref_url: None,
            staleness: StalenessScore::fresh(),
            lifecycle,
            version: RecordVersion {
                device_id: uuid::Uuid::new_v4(),
                logical_clock: 1,
                wall_clock: 1_000_000,
            },
            quality: QualityScore::layer0_default(),
            access_count: 0,
            last_accessed: 0,
            source: RecordSource::DeveloperManual,
            confidence: ConfidenceScore::for_new_record(&RecordSource::DeveloperManual),
            gap_analysis_score: 0.0,
        }
    }

    // ── seal_target: what `add` may chmod ───────────────────────────────────

    #[test]
    fn a_regular_file_under_the_repo_resolves_with_its_live_mode() {
        let dir = repo();
        let root = root_of(&dir);
        let abs = write_file(&root, "src/gated.rs", 0o644);
        let (resolved, meta) = seal_target(&root, "src/gated.rs").unwrap();
        assert_eq!(resolved, abs);
        assert_eq!(meta.permissions().mode() & 0o7777, 0o644);
    }

    #[test]
    fn sealing_anything_under_dot_git_is_refused() {
        let dir = repo();
        let root = root_of(&dir);
        write_file(&root, ".git/config", 0o644);
        let err = seal_target(&root, ".git/config").unwrap_err().to_string();
        assert!(err.contains(".git"), "{err}");
    }

    #[test]
    fn sealing_a_directory_is_refused() {
        let dir = repo();
        let root = root_of(&dir);
        write_file(&root, "src/gated.rs", 0o644);
        let err = seal_target(&root, "src").unwrap_err().to_string();
        assert!(err.contains("not a regular file"), "{err}");
    }

    #[test]
    fn a_path_escaping_the_repo_is_refused() {
        let dir = repo();
        let root = root_of(&dir);
        let sibling = repo();
        let outside = write_file(&root_of(&sibling), "secret.rs", 0o644);
        // `..` out of the repo and back down into a sibling tempdir. Sealing it
        // would chmod 000 a path mati was never pointed at.
        let rel = format!(
            "../{}/secret.rs",
            root_of(&sibling).file_name().unwrap().to_string_lossy()
        );
        assert!(outside.exists());
        let err = seal_target(&root, &rel).unwrap_err().to_string();
        assert!(err.contains("does not resolve to a path under"), "{err}");
    }

    #[test]
    fn a_missing_file_is_refused_before_any_chmod() {
        // `resolve_under_repo` tolerates a non-existent leaf, so the refusal
        // has to come from the stat, not from containment.
        let dir = repo();
        let err = seal_target(&root_of(&dir), "src/gone.rs")
            .unwrap_err()
            .to_string();
        assert!(err.contains("cannot stat"), "{err}");
    }

    // ── manifest_row: the original mode must never be overwritten ───────────

    #[test]
    fn a_recorded_row_wins_even_when_the_file_already_sits_at_the_floor() {
        // The mode-loss case: a re-seal of an already-sealed file must report
        // the recorded 644, never re-record the live 000 as "original".
        let m = manifest_of(vec![sealed(Path::new("/repo/a.rs"), "644")]);
        match manifest_row(&m, "/repo/a.rs", SEALED_MODE) {
            ManifestRow::Recorded(f) => assert_eq!(f.mode, "644"),
            _ => panic!("a recorded row must take precedence over the live mode"),
        }
    }

    #[test]
    fn no_row_at_mode_000_is_unrecorded_rather_than_absent() {
        let m = manifest_of(vec![]);
        assert!(matches!(
            manifest_row(&m, "/repo/a.rs", SEALED_MODE),
            ManifestRow::AtFloorUnrecorded
        ));
    }

    #[test]
    fn no_row_on_a_readable_file_is_absent() {
        let m = manifest_of(vec![sealed(Path::new("/repo/other.rs"), "600")]);
        assert!(matches!(
            manifest_row(&m, "/repo/a.rs", 0o644),
            ManifestRow::Absent
        ));
    }

    // ── covers: only a confirmed, active gotcha may arm a floor ─────────────

    #[test]
    fn a_confirmed_active_gotcha_covers_its_file() {
        assert!(covers(
            &gotcha(&["src/gated.rs"], true, RecordLifecycle::Active),
            "src/gated.rs"
        ));
    }

    #[test]
    fn unconfirmed_and_tombstoned_gotchas_cover_nothing() {
        let stub = gotcha(&["src/gated.rs"], false, RecordLifecycle::Active);
        assert!(!covers(&stub, "src/gated.rs"));
        let dead = gotcha(
            &["src/gated.rs"],
            true,
            RecordLifecycle::Tombstoned {
                reason: TombstoneReason::FileDeleted,
                at: 1,
            },
        );
        assert!(!covers(&dead, "src/gated.rs"));
        let superseded = gotcha(
            &["src/gated.rs"],
            true,
            RecordLifecycle::Superseded {
                by_key: "gotcha:newer".into(),
            },
        );
        assert!(!covers(&superseded, "src/gated.rs"));
    }

    #[test]
    fn affected_files_are_normalized_before_they_are_matched() {
        // A gotcha stored with a `./` prefix must still match the normalized
        // target; without normalization `seal add` refuses every such file.
        let g = gotcha(&["./src/gated.rs"], true, RecordLifecycle::Active);
        assert!(covers(&g, "src/gated.rs"));
        assert!(!covers(&g, "src/other.rs"));
    }

    // ── clear_sealed: rung 1 of the restore ladder ─────────────────────────

    #[test]
    fn clear_restores_every_row_and_empties_the_manifest() {
        crate::cli::ensure_test_home();
        let dir = repo();
        let root = root_of(&dir);
        let a = write_file(&root, "a.rs", SEALED_MODE);
        let b = write_file(&root, "b.rs", SEALED_MODE);
        let mpath = manifest_path(&root).unwrap();
        write_manifest(
            &mpath,
            &manifest_of(vec![sealed(&a, "644"), sealed(&b, "600")]),
        )
        .unwrap();

        clear_sealed(&root).unwrap();

        assert_eq!(mode_of(&a), 0o644);
        assert_eq!(mode_of(&b), 0o600);
        assert!(read_manifest(&mpath).files.is_empty());
    }

    #[test]
    fn clear_keeps_only_the_rows_it_could_not_restore() {
        crate::cli::ensure_test_home();
        let dir = repo();
        let root = root_of(&dir);
        // `restore_one` fails on a row whose mode is not octal, and only for a
        // file that still exists.
        let bad = write_file(&root, "bad.rs", SEALED_MODE);
        let good = write_file(&root, "good.rs", SEALED_MODE);
        let mpath = manifest_path(&root).unwrap();
        write_manifest(
            &mpath,
            &manifest_of(vec![sealed(&bad, "zz"), sealed(&good, "644")]),
        )
        .unwrap();

        assert!(
            clear_sealed(&root).is_err(),
            "a stranded file must not exit 0"
        );

        // The failure must not stop the sweep: `good` comes after `bad`.
        assert_eq!(mode_of(&good), 0o644);
        assert_eq!(mode_of(&bad), SEALED_MODE);
        let kept = read_manifest(&mpath).files;
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].path, bad.to_string_lossy());
    }

    #[test]
    fn clear_with_nothing_sealed_writes_no_manifest() {
        crate::cli::ensure_test_home();
        let dir = repo();
        let root = root_of(&dir);
        let mpath = manifest_path(&root).unwrap();

        clear_sealed(&root).unwrap();

        assert!(
            !mpath.exists(),
            "a no-op clear must not create a manifest at {}",
            mpath.display()
        );
    }
}
