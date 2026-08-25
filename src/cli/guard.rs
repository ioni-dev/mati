//! `mati guard` — break-glass protection for a command pattern.
//!
//! The command counterpart to `mati protect` (which guards paths). It authors a
//! `policy:guard-<slug>` whose `command_glob` gates a pathless destructive verb
//! (`dd`, `terraform destroy`, `git reset --hard`) plus the backing
//! `decision:guard-<slug>` the agent consults to unlock one. Authored at
//! `shadow`; `--enable` promotes it to `enforce`.
//!
//! `command_glob` is lexical and best-effort: it matches the normalized command
//! tokens, so quoting, variable expansion, and aliases slip past it. A block on
//! it is a tripwire backed by the audit chain, never a guarantee.

use anyhow::Result;
use clap::Args;
use slugify::slugify;

use mati_core::mcp::protocol::PolicyWriteOp;
use mati_core::store::{
    PolicyFreshness, PolicyMode, PolicyRecord, PolicyRequires, PolicyStage, PolicyTrigger,
    Priority, ReceiptSource,
};

use crate::cli::protect::decision_record;
use crate::cli::proxy::StoreProxy;

#[derive(Args)]
pub struct GuardArgs {
    /// Glob matched against the normalized command (e.g. `dd *`,
    /// `terraform destroy*`, `git reset --hard*`).
    glob: String,
    /// Why the command is guarded. Stored in the decision record the agent
    /// consults to unlock it.
    #[arg(long)]
    reason: Option<String>,
    /// Warn instead of deny (advisory `steer`). Default is `block`.
    #[arg(long)]
    steer: bool,
    /// Author at `enforce` for immediate guarding. Default is `shadow`, which
    /// observes and logs would-block hits without denying.
    #[arg(long)]
    enable: bool,
    /// Seconds a consultation stays fresh before another is required.
    #[arg(long, default_value_t = 900)]
    ttl: u64,
}

pub async fn run(args: GuardArgs) -> Result<()> {
    let glob = args.glob.trim();
    if glob.is_empty() {
        anyhow::bail!("guard glob cannot be empty");
    }
    let slug = slugify!(glob);
    if slug.is_empty() {
        anyhow::bail!("could not derive a policy slug from glob '{glob}'");
    }

    let decision_key = format!("decision:guard-{slug}");
    let policy_key = format!("policy:guard-{slug}");
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
        format!("`{glob}` is guarded; consult this record before running a matching command.")
    });
    let decision = decision_record(&decision_key, glob, &reason);

    let policy = PolicyRecord {
        name: format!("Guard {glob}"),
        rule: format!("Consult {decision_key} before running `{glob}`."),
        reason: reason.clone(),
        scope: "repo".into(),
        mode,
        trigger: PolicyTrigger {
            tool: None,
            host_glob: None,
            target_path_glob: None,
            command_glob: Some(glob.to_string()),
        },
        deny_if: None,
        require: None,
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
    // Upsert: re-running `mati guard` on the same pattern updates it (e.g.
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
    println!("Guarded `{glob}`");
    println!("  {policy_key} ({mode_label}, {stage_label})");
    println!("  {decision_key} authored (consult to unlock)");
    if matches!(stage, PolicyStage::Shadow) {
        println!("Run `mati guard '{glob}' --enable` to enforce, or `mati policy stage guard-{slug} enforce`.");
    }
    Ok(())
}
