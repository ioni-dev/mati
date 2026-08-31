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

use mati_core::seal::{
    manifest_path, read_manifest, restore_one, write_manifest, SealedFile, RESTORE_NOTE,
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

    let abs = resolve_under_repo(&repo_root, &rel).with_context(|| {
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
    let n = tag_gotchas(&store, &matched, add).await?;

    if add {
        let mode = meta.permissions().mode() & 0o7777;
        match manifest.find(&key) {
            // Re-recording would store 000 as the original and lose the real one.
            Some(f) => println!("`{rel}` was already sealed (original mode {}).", f.mode),
            None if mode == SEALED_MODE => bail!(
                "`{rel}` is already mode 000 but is not in the manifest, so mati cannot know \
                 its original mode — run `chmod u+rw {rel}` first, then seal it"
            ),
            None => {
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
        match manifest.find(&key).cloned() {
            Some(f) => {
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
            None if meta.permissions().mode() & 0o7777 == SEALED_MODE => {
                std::fs::set_permissions(&abs, std::fs::Permissions::from_mode(0o600))
                    .with_context(|| format!("cannot chmod {}", abs.display()))?;
                println!("`{rel}` is mode 000 but has no manifest row, so mati cannot know its");
                println!("original mode. Restored owner read/write (600) — the same under-restore");
                println!("`chmod -R u+rwX` performs. ({n} gotcha(s) untagged.)");
                println!("  `git checkout -- {rel}` recovers the executable bit if it had one.");
            }
            None => println!("`{rel}` was not sealed ({n} gotcha(s) untagged)."),
        }
    }
    Ok(())
}

async fn confirmed_gotchas_for(store: &StoreProxy, rel: &str) -> Result<Vec<Record>> {
    Ok(store
        .scan_prefix("gotcha:")
        .await?
        .into_iter()
        .filter(|r| {
            matches!(r.lifecycle, RecordLifecycle::Active)
                && r.payload_as::<GotchaRecord>()
                    .map(|g| {
                        g.confirmed && g.affected_files.iter().any(|af| normalize_rel(af) == rel)
                    })
                    .unwrap_or(false)
        })
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
    let repo_root = repo_root_for(&std::env::current_dir()?)?;
    let mpath = manifest_path(&repo_root)?;
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
