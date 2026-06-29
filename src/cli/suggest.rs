//! `mati suggest` (idea 2.2) — onboarding import.
//!
//! Scans artifacts that already exist in a repo (CODEOWNERS, load-bearing /
//! security marker comments) and proposes `confirmed: false` gotcha
//! **candidates** that surface in `mati review` for approval — turning the
//! blank-slate "confirm your gotchas" step into "here are N candidates we
//! found." Re-runnable and idempotent: it never overwrites a record that
//! already exists, so prior confirmations/edits are safe.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use clap::Args;

use mati_core::analysis::onboarding;
use mati_core::analysis::walker::Walker;
use mati_core::store::record::Record;

use crate::cli::proxy::StoreProxy;

/// Standard CODEOWNERS locations, in precedence order.
const CODEOWNERS_LOCATIONS: &[&str] = &[
    "CODEOWNERS",
    ".github/CODEOWNERS",
    "docs/CODEOWNERS",
    ".gitlab/CODEOWNERS",
];

/// Skip files larger than this when scanning for markers (generated/binary).
const MAX_SCAN_FILE_BYTES: u64 = 512 * 1024;

#[derive(Args)]
#[command(
    long_about = "Propose gotcha candidates from existing repo artifacts (CODEOWNERS, \
                  load-bearing/security marker comments). Candidates are unconfirmed and \
                  surface in `mati review` for approval. Re-runnable; never overwrites \
                  existing records."
)]
pub struct SuggestArgs {
    /// Repository root (defaults to the current directory)
    #[arg(short, long)]
    pub path: Option<PathBuf>,

    /// Show what would be proposed without writing anything
    #[arg(long)]
    pub dry_run: bool,
}

pub async fn run(args: SuggestArgs) -> Result<()> {
    let root = match args.path {
        Some(p) => p,
        None => std::env::current_dir()?,
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let device_id = uuid::Uuid::new_v4();

    let codeowners = read_codeowners(&root);
    let files = read_text_files(&root);
    let candidates = onboarding::build_candidates(codeowners.as_deref(), &files, device_id, 1, now);

    if candidates.is_empty() {
        println!(
            "No onboarding candidates found (scanned CODEOWNERS + load-bearing/security markers)."
        );
        return Ok(());
    }

    if args.dry_run {
        println!("Would propose {} candidate(s):", candidates.len());
        for c in &candidates {
            println!("  {}\n      {}", c.key, c.value);
        }
        return Ok(());
    }

    let proxy = StoreProxy::open(&root).await?;
    let outcome = write_candidates(&proxy, &candidates).await;
    let (written, skipped) = proxy.close_with_result(outcome).await?;

    if written == 0 {
        println!("All {skipped} candidate(s) already present — nothing new to propose.");
    } else {
        let tail = if skipped > 0 {
            format!(" ({skipped} already present)")
        } else {
            String::new()
        };
        println!("Proposed {written} new candidate(s){tail} — run `mati review` to approve.");
    }
    Ok(())
}

/// Write candidates that don't already exist. Returns `(written, skipped)`.
/// Skipping existing keys means a re-run never clobbers a confirmation or edit.
async fn write_candidates(proxy: &StoreProxy, candidates: &[Record]) -> Result<(usize, usize)> {
    let mut written = 0;
    let mut skipped = 0;
    for rec in candidates {
        if proxy.get(&rec.key).await?.is_some() {
            skipped += 1;
            continue;
        }
        proxy.put(&rec.key, rec).await?;
        written += 1;
    }
    Ok((written, skipped))
}

/// Read the first existing CODEOWNERS file under the repo root.
fn read_codeowners(root: &Path) -> Option<String> {
    CODEOWNERS_LOCATIONS
        .iter()
        .find_map(|loc| std::fs::read_to_string(root.join(loc)).ok())
}

/// Walk the repo (ignore-aware) and read UTF-8 text files small enough to scan.
fn read_text_files(root: &Path) -> Vec<(String, String)> {
    let Ok(files) = Walker::new(root).walk() else {
        return Vec::new();
    };
    files
        .into_iter()
        .filter(|f| f.size_bytes <= MAX_SCAN_FILE_BYTES)
        .filter_map(|f| std::fs::read_to_string(&f.abs_path).ok().map(|c| (f.rel_path, c)))
        .collect()
}
