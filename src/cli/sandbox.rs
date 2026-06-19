//! `mati sandbox` — L3 sandbox floor (Plane 3).
//!
//! Compiles confirmed, explicitly-tagged "crown-jewel" gotchas into Claude Code
//! `sandbox.filesystem` deny rules — an OS-level (Seatbelt / bubblewrap) floor
//! that blocks the agent's shell and every subprocess it spawns from reading or
//! writing those files. This closes the shell / symlink bypass that the dynamic
//! hook gate (L1) cannot reach: for a crown-jewel file the shell path is denied
//! at the OS level, leaving the consultation-gated Read/Edit tools as the only
//! way the agent can touch it. See `MATI-SOTA-ARCHITECTURE.md` (L3).
//!
//! Invariant: the generator is OSS — enforcement mechanisms are identical in
//! both tiers (README). Enterprise only adds managed-settings org push around it.
//!
//! Safety: this is the highest-risk layer (it mutates security config), so it is
//! explicit-tag-only (never severity-derived), **preview-default** (this command
//! only reports what it would write; mutation lands behind a later `--apply`),
//! and reversible.

use anyhow::Result;
use clap::{Args, Subcommand};
use std::collections::BTreeSet;

use mati_core::store::GotchaRecord;

use super::proxy::StoreProxy;

/// Tag → shell-deny mapping. Explicit opt-in only; severity is never used.
///
/// - `crown-jewel`: the shell / subprocess path cannot WRITE the file (protect
///   critical logic from out-of-gate modification). Reads still work.
/// - `sandbox-deny-read`: additionally, the shell cannot READ the file (secrets
///   / exfiltration protection).
const TAG_DENY_WRITE: &str = "crown-jewel";
const TAG_DENY_READ: &str = "sandbox-deny-read";

#[derive(Args, Debug)]
pub struct SandboxArgs {
    #[command(subcommand)]
    pub command: SandboxCommand,
}

#[derive(Subcommand, Debug)]
pub enum SandboxCommand {
    /// Preview the sandbox deny rules compiled from crown-jewel gotchas.
    Compile,
}

/// The sandbox filesystem deny rules compiled from gotchas. Paths are
/// project-root-relative (`./`-prefixed) and therefore portable across machines.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct SandboxRules {
    pub deny_read: BTreeSet<String>,
    pub deny_write: BTreeSet<String>,
}

impl SandboxRules {
    pub fn is_empty(&self) -> bool {
        self.deny_read.is_empty() && self.deny_write.is_empty()
    }
}

/// Pure mapping: confirmed + explicitly-tagged gotchas → sandbox deny entries.
///
/// Each item is `(tags, confirmed, affected_files)`. Unconfirmed gotchas and
/// gotchas carrying no sandbox tag contribute nothing — enforcement is
/// explicit-tag-only, never derived from severity.
pub fn compile_rules<'a>(
    gotchas: impl Iterator<Item = (&'a [String], bool, &'a [String])>,
) -> SandboxRules {
    let mut rules = SandboxRules::default();
    for (tags, confirmed, files) in gotchas {
        if !confirmed {
            continue;
        }
        let deny_write = tags.iter().any(|t| t == TAG_DENY_WRITE);
        let deny_read = tags.iter().any(|t| t == TAG_DENY_READ);
        if !deny_write && !deny_read {
            continue;
        }
        for f in files {
            let entry = normalize_sandbox_path(f);
            if entry.is_empty() {
                continue;
            }
            if deny_write {
                rules.deny_write.insert(entry.clone());
            }
            if deny_read {
                rules.deny_read.insert(entry);
            }
        }
    }
    rules
}

/// Normalize a repo-relative path to a project-root-relative sandbox entry:
/// forward slashes, collapse any leading `./` or `/`, then `./`-prefix.
///
/// Claude Code resolves `./` against the project root and canonicalizes the
/// path before building the OS profile; Seatbelt then matches the canonical
/// (symlink-resolved) path, so a symlink to a denied file cannot bypass the
/// floor (verified live against `sandbox-exec`, 2026-06-19).
fn normalize_sandbox_path(repo_rel: &str) -> String {
    let p = repo_rel.replace('\\', "/");
    let p = p.trim_start_matches("./").trim_start_matches('/');
    if p.is_empty() {
        return String::new();
    }
    format!("./{p}")
}

pub async fn run(args: SandboxArgs) -> Result<()> {
    match args.command {
        SandboxCommand::Compile => run_compile().await,
    }
}

async fn run_compile() -> Result<()> {
    let cwd = std::env::current_dir()?;
    let store = StoreProxy::open(&cwd).await?;
    let records = store.scan_prefix("gotcha:").await?;

    let items: Vec<(Vec<String>, bool, Vec<String>)> = records
        .iter()
        .map(|r| {
            let (confirmed, files) = match r.payload_as::<GotchaRecord>() {
                Some(gr) => (gr.confirmed, gr.affected_files),
                None => (false, Vec::new()),
            };
            (r.tags.clone(), confirmed, files)
        })
        .collect();

    let rules = compile_rules(
        items
            .iter()
            .map(|(t, c, f)| (t.as_slice(), *c, f.as_slice())),
    );

    print_preview(&rules);
    Ok(())
}

fn print_preview(rules: &SandboxRules) {
    if rules.is_empty() {
        println!("No crown-jewel gotchas found.");
        println!(
            "Tag a confirmed gotcha with `{TAG_DENY_WRITE}` (deny shell writes) or \
             `{TAG_DENY_READ}` (deny shell reads) to compile a sandbox floor."
        );
        return;
    }

    println!("Sandbox floor preview (Plane 3 / L3) — preview only, nothing written.");
    println!("Would add to .claude/settings.json under \"sandbox\" → \"filesystem\":\n");

    if !rules.deny_write.is_empty() {
        println!("  denyWrite (shell / subprocess cannot modify):");
        for p in &rules.deny_write {
            println!("    {p}");
        }
    }
    if !rules.deny_read.is_empty() {
        println!("  denyRead (shell / subprocess cannot read):");
        for p in &rules.deny_read {
            println!("    {p}");
        }
    }
    println!(
        "\nThese are OS-level (Seatbelt / bubblewrap) and cover every subprocess. The agent\n\
         can still reach these files through the consultation-gated Read/Edit tools (L1).\n\
         Requires the Claude Code sandbox to be enabled (`/sandbox` or sandbox.enabled).\n\
         Writing them (`mati sandbox compile --apply`) lands in the next step."
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn compile_maps_crown_jewel_to_deny_write() {
        let tags = s(&["crown-jewel"]);
        let files = s(&["src/payments/fraud.rs"]);
        let rules = compile_rules([(tags.as_slice(), true, files.as_slice())].into_iter());
        assert!(rules.deny_write.contains("./src/payments/fraud.rs"));
        assert!(rules.deny_read.is_empty());
    }

    #[test]
    fn compile_maps_deny_read_tag() {
        let tags = s(&["sandbox-deny-read"]);
        let files = s(&[".env.production"]);
        let rules = compile_rules([(tags.as_slice(), true, files.as_slice())].into_iter());
        assert!(rules.deny_read.contains("./.env.production"));
        assert!(rules.deny_write.is_empty());
    }

    #[test]
    fn both_tags_compose_on_one_file() {
        let tags = s(&["crown-jewel", "sandbox-deny-read"]);
        let files = s(&["secrets/key.pem"]);
        let rules = compile_rules([(tags.as_slice(), true, files.as_slice())].into_iter());
        assert!(rules.deny_write.contains("./secrets/key.pem"));
        assert!(rules.deny_read.contains("./secrets/key.pem"));
    }

    #[test]
    fn unconfirmed_gotchas_are_ignored() {
        let tags = s(&["crown-jewel"]);
        let files = s(&["src/x.rs"]);
        let rules = compile_rules([(tags.as_slice(), false, files.as_slice())].into_iter());
        assert!(rules.is_empty(), "unconfirmed gotchas must never gate");
    }

    #[test]
    fn untagged_gotchas_contribute_nothing() {
        let tags = s(&["enriched", "depth:deep"]);
        let files = s(&["src/x.rs"]);
        let rules = compile_rules([(tags.as_slice(), true, files.as_slice())].into_iter());
        assert!(
            rules.is_empty(),
            "explicit-tag-only: no sandbox tag -> no rule"
        );
    }

    #[test]
    fn paths_normalize_and_dedupe() {
        let tags = s(&["crown-jewel"]);
        let a = s(&["./src/x.rs"]);
        let b = s(&["src/x.rs"]);
        let rules = compile_rules(
            [
                (tags.as_slice(), true, a.as_slice()),
                (tags.as_slice(), true, b.as_slice()),
            ]
            .into_iter(),
        );
        assert_eq!(rules.deny_write.len(), 1, "./x and x are the same entry");
        assert!(rules.deny_write.contains("./src/x.rs"));
    }
}
