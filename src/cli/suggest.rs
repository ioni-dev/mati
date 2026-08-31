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
use mati_core::store::record::{GotchaRecord, Record, RecordLifecycle};
use mati_core::store::repair::RepairReader;
use uuid::Uuid;

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
    let device_id = mati_core::store::stable_device_id();

    let proxy = StoreProxy::open(&root).await?;
    let outcome = suggest(&proxy, &root, device_id, now, args.dry_run).await;
    let report = proxy.close_with_result(outcome).await?;

    print!("{report}");
    Ok(())
}

/// Everything between opening the store and closing it, so `run` has exactly
/// one close and nothing is printed before the write is durable.
async fn suggest(
    proxy: &StoreProxy,
    root: &Path,
    device_id: Uuid,
    now: u64,
    dry_run: bool,
) -> Result<Report> {
    let Plan {
        candidates,
        governed_note,
    } = plan(proxy, root, device_id, now).await?;

    if candidates.is_empty() {
        return Ok(Report::Nothing);
    }
    if dry_run {
        return Ok(Report::DryRun {
            candidates,
            governed_note,
        });
    }
    let (written, skipped) = write_candidates(proxy, &candidates).await?;
    Ok(Report::Written {
        written,
        skipped,
        governed_note,
    })
}

/// What the run has to say once its store is closed.
#[derive(Debug)]
enum Report {
    Nothing,
    DryRun {
        candidates: Vec<Record>,
        governed_note: String,
    },
    Written {
        written: usize,
        skipped: usize,
        governed_note: String,
    },
}

impl std::fmt::Display for Report {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Report::Nothing => writeln!(
                f,
                "No onboarding candidates found (scanned CODEOWNERS + load-bearing/security markers)."
            ),
            Report::DryRun {
                candidates,
                governed_note,
            } => {
                writeln!(
                    f,
                    "Would propose {} candidate(s):{governed_note}",
                    candidates.len()
                )?;
                for c in candidates {
                    writeln!(f, "  {}\n      {}", c.key, c.value)?;
                }
                Ok(())
            }
            Report::Written {
                written: 0,
                skipped,
                governed_note,
            } => writeln!(
                f,
                "All {skipped} candidate(s) already present — nothing new to propose.{governed_note}"
            ),
            Report::Written {
                written,
                skipped,
                governed_note,
            } => {
                let tail = if *skipped > 0 {
                    format!(" ({skipped} already present)")
                } else {
                    String::new()
                };
                writeln!(
                    f,
                    "Proposed {written} new candidate(s){tail}{governed_note} — run `mati review` to approve."
                )
            }
        }
    }
}

/// What a `suggest` run would propose, and what it skipped to get there.
#[derive(Debug)]
struct Plan {
    candidates: Vec<Record>,
    governed_note: String,
}

/// Read the governed set, then build candidates from everything it does not cover.
///
/// Fails closed: if the gotcha scan errors, the governed set is unknown, and an
/// empty one would mint candidates quoting files the read gate is denying — the
/// hole this filter exists to close. So no candidate is built at all.
async fn plan(reader: &impl RepairReader, root: &Path, device_id: Uuid, now: u64) -> Result<Plan> {
    let governed = governed_files(reader).await?;
    let codeowners = read_codeowners(root);
    let scanned = read_text_files(root);
    let scanned_count = scanned.len();
    let files: Vec<(String, String)> = scanned
        .into_iter()
        .filter(|(rel, _)| !governed.contains(rel))
        .collect();
    // Count what the filter actually removed, not the size of the governed set:
    // a confirmed gotcha can name a path that no longer exists, and reporting
    // that as a skip overstates what the filter did.
    let skipped_governed = scanned_count - files.len();
    Ok(Plan {
        candidates: onboarding::build_candidates(codeowners.as_deref(), &files, device_id, 1, now),
        governed_note: if skipped_governed == 0 {
            String::new()
        } else {
            format!(" ({skipped_governed} governed file(s) skipped)")
        },
    })
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

/// Repo-relative paths already covered by a confirmed gotcha.
///
/// `suggest` proposes onboarding candidates for files mati does not yet know
/// about, so a file that already carries a confirmed gotcha has nothing left
/// to onboard. Skipping it also keeps `suggest` from minting a record that
/// quotes a marker line out of a file the read gate is currently denying:
/// `mati show` prints record content without minting a receipt, so an
/// on-demand mint from ungated bytes would be a disclosure channel around the
/// gate. Reproduced 2026-08-31 before this filter existed.
async fn governed_files(reader: &impl RepairReader) -> Result<std::collections::HashSet<String>> {
    Ok(reader
        .scan_prefix("gotcha:")
        .await?
        .into_iter()
        .filter(|r| matches!(r.lifecycle, RecordLifecycle::Active))
        .filter_map(|r| r.payload_as::<GotchaRecord>())
        .filter(|g| g.confirmed)
        .flat_map(|g| g.affected_files)
        .collect())
}

/// Read the first existing CODEOWNERS file under the repo root.
pub(crate) fn read_codeowners(root: &Path) -> Option<String> {
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
        .filter_map(|f| {
            std::fs::read_to_string(&f.abs_path)
                .ok()
                .map(|c| (f.rel_path, c))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::anyhow;

    /// A reader whose gotcha scan fails. Models the store being unreachable or
    /// the scan erroring after the proxy opened.
    struct FailingReader;

    impl RepairReader for FailingReader {
        async fn get(&self, _key: &str) -> Result<Option<Record>> {
            Err(anyhow!("store unavailable"))
        }
        async fn scan_prefix(&self, _prefix: &str) -> Result<Vec<Record>> {
            Err(anyhow!("store unavailable"))
        }
        async fn scan_keys(&self, _prefix: &str) -> Result<Vec<String>> {
            Err(anyhow!("store unavailable"))
        }
    }

    /// A reader holding no gotchas at all, so nothing is governed.
    struct EmptyReader;

    impl RepairReader for EmptyReader {
        async fn get(&self, _key: &str) -> Result<Option<Record>> {
            Ok(None)
        }
        async fn scan_prefix(&self, _prefix: &str) -> Result<Vec<Record>> {
            Ok(Vec::new())
        }
        async fn scan_keys(&self, _prefix: &str) -> Result<Vec<String>> {
            Ok(Vec::new())
        }
    }

    /// A repo whose markers a working scan would turn into candidates.
    fn repo_with_markers() -> tempfile::TempDir {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            tmp.path().join("main.rs"),
            "fn main() {\n    // SECURITY: validate the token before use\n}\n",
        )
        .unwrap();
        tmp
    }

    /// The control: the same repo yields a candidate when the scan succeeds.
    /// Without this, the failing case below could pass for the wrong reason.
    #[tokio::test]
    async fn plan_builds_candidates_when_the_scan_succeeds() {
        let tmp = repo_with_markers();
        let out = plan(&EmptyReader, tmp.path(), Uuid::nil(), 0)
            .await
            .expect("plan should succeed");
        assert_eq!(out.candidates.len(), 1, "control must produce a candidate");
        assert!(out.governed_note.is_empty(), "nothing was skipped");
    }

    /// The report strings `tests/suggest_cli.rs` asserts on. Rendering is the
    /// only branching left in `run`, so it is the only part left to test there.
    #[tokio::test]
    async fn report_renders_every_branch() {
        let tmp = repo_with_markers();
        let out = plan(&EmptyReader, tmp.path(), Uuid::nil(), 0)
            .await
            .expect("plan should succeed");

        assert_eq!(
            Report::Nothing.to_string(),
            "No onboarding candidates found (scanned CODEOWNERS + load-bearing/security markers).\n"
        );

        let dry = Report::DryRun {
            candidates: out.candidates,
            governed_note: " (1 governed file(s) skipped)".into(),
        }
        .to_string();
        assert!(
            dry.starts_with("Would propose 1 candidate(s): (1 governed file(s) skipped)\n"),
            "got: {dry}"
        );
        assert!(dry.contains("marker:main.rs:2"), "got: {dry}");

        assert_eq!(
            Report::Written {
                written: 1,
                skipped: 0,
                governed_note: String::new(),
            }
            .to_string(),
            "Proposed 1 new candidate(s) — run `mati review` to approve.\n"
        );
        assert_eq!(
            Report::Written {
                written: 1,
                skipped: 2,
                governed_note: " (1 governed file(s) skipped)".into(),
            }
            .to_string(),
            "Proposed 1 new candidate(s) (2 already present) (1 governed file(s) skipped) \
             — run `mati review` to approve.\n"
        );
        assert_eq!(
            Report::Written {
                written: 0,
                skipped: 1,
                governed_note: String::new(),
            }
            .to_string(),
            "All 1 candidate(s) already present — nothing new to propose.\n"
        );
    }

    /// Fail closed: an unreadable governed set must abort, not fall back to an
    /// empty one. An empty set would mint candidates quoting files the read gate
    /// is denying, which is the disclosure hole this filter closes.
    #[tokio::test]
    async fn plan_fails_closed_when_the_gotcha_scan_errors() {
        let tmp = repo_with_markers();
        let err = plan(&FailingReader, tmp.path(), Uuid::nil(), 0)
            .await
            .expect_err("a failed gotcha scan must not yield a plan");
        assert!(
            err.to_string().contains("store unavailable"),
            "the scan error should propagate verbatim; got: {err}"
        );
    }
}
