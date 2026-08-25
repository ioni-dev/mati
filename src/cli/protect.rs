//! `mati protect` — break-glass protection for a repo path.
//!
//! Sugar over `mati policy add`: authors a `policy:protect-<slug>` whose
//! `target_path_glob` gates any `tool=path` action (edits, and `rm`/`mv`/
//! `rmdir`/`shred` deletes and moves) against the glob, plus the
//! `decision:protect-<slug>` record the agent consults to unlock one. The
//! policy is authored at `shadow` so it observes without denying; `--enable`
//! promotes it to `enforce`.
//!
//! Determinism boundary: exact for edits and literal-path deletes/moves;
//! best-effort for shell bypasses (variable expansion, process substitution),
//! the same ~2-5% miss the read gate carries.

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use clap::Args;
use slugify::slugify;

use mati_core::mcp::protocol::PolicyWriteOp;
use mati_core::store::{
    Category, ConfidenceScore, PolicyFreshness, PolicyMode, PolicyRecord, PolicyRequires,
    PolicyStage, PolicyTrigger, Priority, QualityScore, ReceiptSource, Record, RecordLifecycle,
    RecordSource, RecordVersion, StalenessScore,
};

use crate::cli::proxy::StoreProxy;

#[derive(Args)]
pub struct ProtectArgs {
    /// Repo-relative glob to protect (e.g. `src/migrations/**`).
    glob: String,
    /// Why the path is protected. Stored in the decision record the agent
    /// consults to unlock an edit or delete.
    #[arg(long)]
    reason: Option<String>,
    /// Warn instead of deny (advisory `steer`). Default is `block`.
    #[arg(long)]
    steer: bool,
    /// Author at `enforce` for immediate protection. Default is `shadow`,
    /// which observes and logs would-block hits without denying.
    #[arg(long)]
    enable: bool,
    /// Seconds a consultation stays fresh before another is required.
    #[arg(long, default_value_t = 900)]
    ttl: u64,
}

pub async fn run(args: ProtectArgs) -> Result<()> {
    let glob = args.glob.trim();
    if glob.is_empty() {
        anyhow::bail!("protect glob cannot be empty");
    }
    let slug = slugify!(glob);
    if slug.is_empty() {
        anyhow::bail!("could not derive a policy slug from glob '{glob}'");
    }

    let target_glob = protect_glob(glob);
    let decision_key = format!("decision:protect-{slug}");
    let policy_key = format!("policy:protect-{slug}");
    let mode = if args.steer {
        PolicyMode::Steer
    } else {
        PolicyMode::Block
    };
    let stage = if args.enable {
        PolicyStage::Enforce
    } else {
        PolicyStage::Shadow
    };

    let reason = args.reason.unwrap_or_else(|| {
        format!(
            "{glob} is protected; consult this record before editing or deleting a matching path."
        )
    });
    let decision = decision_record(&decision_key, glob, &reason);

    let policy = PolicyRecord {
        name: format!("Protect {glob}"),
        rule: format!("Consult {decision_key} before editing or deleting {glob}."),
        reason: reason.clone(),
        scope: "repo".into(),
        mode,
        trigger: PolicyTrigger {
            tool: Some("path".into()),
            host_glob: None,
            target_path_glob: Some(target_glob.clone()),
            command_glob: None,
        },
        deny_if: None,
        requires: PolicyRequires {
            key: decision_key.clone(),
            via: vec![ReceiptSource::MemGet],
            freshness: PolicyFreshness {
                ttl_secs: args.ttl,
                fingerprint: false,
            },
        },
        stage,
        severity: Priority::High,
        created_by: "developer".into(),
    };
    mati_core::store::policy_ops::validate_trigger(&policy.trigger)?;

    let cwd = std::env::current_dir()?;
    let proxy = StoreProxy::open(&cwd).await?;
    // Decision first: it is the policy's `requires.key`, so it must back the
    // policy before the author-time backing check runs.
    proxy.put(&decision_key, &decision).await?;
    for warning in mati_core::store::policy_ops::author_warnings(&policy, true) {
        eprintln!("{warning}");
    }
    // Upsert: re-running `mati protect` on the same target updates it (e.g.
    // promoting shadow → enforce via `--enable`) rather than erroring.
    let op = if proxy.get(&policy_key).await?.is_some() {
        PolicyWriteOp::Edit
    } else {
        PolicyWriteOp::Create
    };
    let result = proxy.policy_write(op, &policy_key, Some(&policy)).await;
    proxy.close_with_result(result).await?;

    let stage_label = format!("{stage:?}").to_ascii_lowercase();
    let mode_label = format!("{mode:?}").to_ascii_lowercase();
    println!("Protected {glob}  (glob: {target_glob})");
    println!("  {policy_key} ({mode_label}, {stage_label})");
    println!("  {decision_key} authored (consult to unlock)");
    if matches!(stage, PolicyStage::Shadow) {
        println!("Run `mati protect {glob} --enable` to enforce, or `mati policy stage protect-{slug} enforce`.");
    }
    Ok(())
}

/// Build the trigger glob so protecting a directory also gates deleting the
/// directory itself, not just its contents. A plain path or a `<base>/**`
/// pattern expands to `{<base>,<base>/**}`, which matches the node and its
/// subtree without catching a sibling (`src/migrations` protects
/// `src/migrations/x` and `rm -rf src/migrations`, but not `src/migrationsX`).
/// A glob with its own metacharacters elsewhere is used verbatim.
fn protect_glob(input: &str) -> String {
    let trimmed = input.trim_end_matches('/');
    let base = trimmed.strip_suffix("/**").unwrap_or(trimmed);
    if base.contains(['*', '?', '[', ']', '{', '}']) {
        return input.to_string();
    }
    format!("{{{base},{base}/**}}")
}

pub(crate) fn decision_record(key: &str, glob: &str, reason: &str) -> Record {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    Record {
        key: key.to_string(),
        value: format!("Protected path: {glob}\n\n{reason}"),
        category: Category::Decision,
        priority: Priority::High,
        tags: vec!["protect".into()],
        created_at: now,
        updated_at: now,
        ref_url: None,
        staleness: StalenessScore::fresh(),
        lifecycle: RecordLifecycle::Active,
        version: RecordVersion {
            device_id: mati_core::store::stable_device_id(),
            logical_clock: 1,
            wall_clock: now,
        },
        quality: QualityScore::layer0_default(),
        access_count: 0,
        last_accessed: 0,
        source: RecordSource::DeveloperManual,
        confidence: ConfidenceScore::for_new_record(&RecordSource::DeveloperManual),
        gap_analysis_score: 0.0,
        payload: None,
    }
}

#[cfg(test)]
mod tests {
    use super::protect_glob;

    #[test]
    fn plain_path_covers_node_and_subtree() {
        assert_eq!(
            protect_glob("src/migrations"),
            "{src/migrations,src/migrations/**}"
        );
    }

    #[test]
    fn trailing_slash_and_star_star_normalize_to_same_glob() {
        let expected = "{src/migrations,src/migrations/**}";
        assert_eq!(protect_glob("src/migrations/"), expected);
        assert_eq!(protect_glob("src/migrations/**"), expected);
    }

    #[test]
    fn explicit_glob_is_verbatim() {
        assert_eq!(protect_glob("src/**/*.sql"), "src/**/*.sql");
    }
}
