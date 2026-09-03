//! `mati policy` — author local policies and verify signed policy-floor bundles.
//!
//! Verification only; authoring/signing bundles is mati-cloud's licensed
//! feature. Like `cosign verify`, it checks a bundle against a trusted key:
//! one supplied with `--key` (verify against a key you trust), or this build's
//! embedded trust anchor (empty in the OSS core, so a real bundle is rejected
//! until an Enterprise build supplies a key). Pure + offline.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use clap::{Args, Subcommand};
use slugify::slugify;

use mati_core::hooks::decide::{normalize_action, Action};
use mati_core::policy::{self, PolicyBundle, TrustedKey};
use mati_core::store::observability;
use mati_core::store::{
    PolicyMode, PolicyRecord, PolicyRequires, PolicyStage, PolicyTrigger, Priority, RecordLifecycle,
};
// Re-exported so `crate::cli::policy::{ActivityState, POLICY_ACTIVITY_*}` still
// resolves for `doctor.rs`, which consumes the same activity report.
pub(crate) use mati_core::store::observability::{
    ActivityReport, ActivityState, POLICY_ACTIVITY_DEFAULT_DAYS, POLICY_ACTIVITY_GRACE_DAYS,
};

use crate::cli::proxy::StoreProxy;

#[derive(Args)]
pub struct PolicyArgs {
    #[command(subcommand)]
    command: PolicyCommand,
}

#[derive(Subcommand)]
enum PolicyCommand {
    /// Add a local repository policy (stored under `policy:<slug>`).
    #[command(
        long_about = "Add a local, developer-authored policy. New policies are off by default; pass --shadow to observe or --enable for deliberate human activation."
    )]
    Add(AddArgs),
    /// Edit selected fields of an existing local policy.
    Edit(EditArgs),
    /// List active local policies.
    List {
        /// Emit JSON instead of a table.
        #[arg(long)]
        json: bool,
    },
    /// Show consultation receipts and which policies they satisfy.
    Receipts {
        #[arg(long)]
        json: bool,
    },
    /// Show bounded shadow observations, optionally for one policy.
    Observations {
        slug: Option<String>,
        #[arg(long)]
        json: bool,
    },
    #[command(
        long_about = "Report retained activity for active policies. Activity is an under-count by design: when a satisfied block policy co-occurs with a different deny, its allow-after-receipt trace is dropped to preserve the enforcement chain. A quiet result is therefore safe in direction, but use `mati policy test` before deleting a rule."
    )]
    /// Report retained activity for active policies.
    Activity {
        slug: Option<String>,
        #[arg(long)]
        json: bool,
        /// Look back this many days (enforcement retention bounds older claims).
        #[arg(long, default_value_t = 30)]
        since: u64,
    },
    /// Show one local policy.
    Show(PolicyKeyArgs),
    /// Enable one local policy.
    Enable(PolicyKeyArgs),
    /// Disable one local policy.
    Disable(PolicyKeyArgs),
    /// Set a policy rollout stage.
    Stage { key: String, stage: String },
    /// Tombstone one local policy.
    Delete(PolicyKeyArgs),
    /// Test local policy predicates against a command or path without writing.
    Test(TestArgs),
    /// Verify a signed policy-floor bundle's Ed25519 signature.
    Verify(VerifyArgs),
}

#[derive(Args)]
struct PolicyKeyArgs {
    /// Policy key (`policy:<slug>`) or slug.
    key: String,
}

#[derive(Args)]
struct AddArgs {
    /// Slug used to form `policy:<slug>`.
    slug: String,
    #[arg(long)]
    name: String,
    #[arg(long)]
    rule: String,
    #[arg(long)]
    reason: String,
    /// Repo-relative glob(s), or "repo".
    #[arg(long, default_value = "repo")]
    scope: String,
    /// steer or block.
    #[arg(long, default_value = "steer")]
    mode: String,
    /// JSON object such as {"tool":"db_client","host_glob":"*prod*"}.
    /// At least one predicate is required — an empty trigger would match
    /// every governed action.
    #[arg(long, default_value = "{}")]
    trigger: String,
    /// JSON object with key, via, and freshness.ttl_secs.
    #[arg(
        long,
        default_value = "{\"key\":\"\",\"via\":[],\"freshness\":{\"ttl_secs\":900}}"
    )]
    requires: String,
    /// low, normal, high, or critical.
    #[arg(long, default_value = "normal")]
    severity: String,
    #[arg(long, default_value = "developer")]
    created_by: String,
    /// Content-deny predicate: deny when the command's argv matches this glob,
    /// independent of any consult gate. Lexical tripwire (quoting, `-f file`,
    /// heredocs, and aliases bypass it), never a guarantee.
    #[arg(long)]
    deny_if_command_glob: Option<String>,
    /// Content-deny predicate on the path: deny when any of `target_path ∪
    /// files` matches this glob (edits, path-verb bash, db `-f` file args),
    /// independent of any consult gate. Lexical path match; sees the requested
    /// path, not file contents.
    #[arg(long, conflicts_with = "deny_if_command_glob")]
    deny_if_path_glob: Option<String>,
    /// Require predicate: deny UNLESS the command's argv matches this glob (the
    /// polarity mirror of `--deny-if-command-glob`). Lexical tripwire.
    #[arg(long)]
    require_command_glob: Option<String>,
    /// Require predicate on the path: deny UNLESS any of `target_path ∪ files`
    /// matches this glob — an allowlist (e.g. `src/**` denies edits outside
    /// `src/`). Lexical path match; sees the requested path, not file contents.
    #[arg(long, conflicts_with = "require_command_glob")]
    require_path_glob: Option<String>,
    /// Mint a CommandObserved receipt named `--mints-key` when an observed
    /// command's argv matches this glob (workflow ordering, e.g. a test runner
    /// minting `tests-ran`). Attests ATTEMPTED, not passed — prefer a full-suite
    /// glob. Requires `--mints-key`.
    #[arg(long, requires = "mints_key")]
    mints_command_glob: Option<String>,
    /// Receipt key the `--mints-command-glob` emitter writes. A separate policy
    /// sets `requires.key` to this to gate on it.
    #[arg(long)]
    mints_key: Option<String>,
    /// Enable immediately (otherwise the new policy is inert).
    #[arg(long)]
    enable: bool,
    /// Create in shadow stage for safe observation.
    #[arg(long, conflicts_with = "enable")]
    shadow: bool,
}

#[derive(Args)]
struct EditArgs {
    /// Policy key (`policy:<slug>`) or slug.
    key: String,
    #[arg(long)]
    name: Option<String>,
    #[arg(long)]
    rule: Option<String>,
    #[arg(long)]
    reason: Option<String>,
    #[arg(long)]
    scope: Option<String>,
    #[arg(long)]
    mode: Option<String>,
    #[arg(long)]
    trigger: Option<String>,
    #[arg(long)]
    requires: Option<String>,
    #[arg(long)]
    severity: Option<String>,
}

#[derive(Args)]
struct TestArgs {
    /// Bash command to normalize and test.
    #[arg(long)]
    command: Option<String>,
    /// File path to normalize and test.
    #[arg(long)]
    path: Option<String>,
    /// Ad-hoc trigger JSON to compile and test without reading or writing the store.
    #[arg(long)]
    trigger: Option<String>,
    /// Emit JSON instead of human output.
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
pub struct VerifyArgs {
    /// Path to the bundle JSON file.
    bundle: PathBuf,
    /// Base64 Ed25519 public key (32 bytes) to trust for this verification,
    /// trusted under the bundle's own key_id. Omit to use this build's embedded
    /// trust anchor (empty in the OSS core).
    #[arg(long)]
    key: Option<String>,
    /// Emit a JSON result instead of human output.
    #[arg(long)]
    json: bool,
}

pub async fn run(args: PolicyArgs) -> Result<()> {
    match args.command {
        PolicyCommand::Add(a) => add(a).await,
        PolicyCommand::Edit(a) => edit(a).await,
        PolicyCommand::List { json } => list(json).await,
        PolicyCommand::Receipts { json } => receipts(json).await,
        PolicyCommand::Observations { slug, json } => observations(slug.as_deref(), json).await,
        PolicyCommand::Activity { slug, json, since } => {
            activity(slug.as_deref(), json, since).await
        }
        PolicyCommand::Show(a) => show(&normalize_key(&a.key)).await,
        PolicyCommand::Enable(a) => set_enabled(&normalize_key(&a.key), true).await,
        PolicyCommand::Disable(a) => set_enabled(&normalize_key(&a.key), false).await,
        PolicyCommand::Stage { key, stage } => {
            set_stage(&normalize_key(&key), parse_stage(&stage)?).await
        }
        PolicyCommand::Delete(a) => delete(&normalize_key(&a.key)).await,
        PolicyCommand::Test(a) => test_policies(a).await,
        PolicyCommand::Verify(a) => verify(a),
    }
}

fn normalize_key(key: &str) -> String {
    if key.starts_with("policy:") {
        key.to_string()
    } else {
        format!("policy:{key}")
    }
}

fn parse_mode(value: &str) -> Result<PolicyMode> {
    match value.trim().to_ascii_lowercase().as_str() {
        "steer" => Ok(PolicyMode::Steer),
        "block" => Ok(PolicyMode::Block),
        other => anyhow::bail!("invalid policy mode '{other}'; expected steer or block"),
    }
}

/// Parse `--trigger` JSON and validate it before anything compiles or stores it.
///
/// `PolicyTrigger` rejects unknown fields, so a misspelled key fails here rather
/// than deserializing into the all-`None` trigger that matches everything;
/// `validate_trigger` then rejects a genuinely empty one.
fn parse_trigger(json: &str) -> Result<PolicyTrigger> {
    let trigger = serde_json::from_str::<PolicyTrigger>(json).context("parsing --trigger JSON")?;
    mati_core::store::policy_ops::validate_trigger(&trigger)?;
    Ok(trigger)
}

fn parse_priority(value: &str) -> Result<Priority> {
    match value.trim().to_ascii_lowercase().as_str() {
        "low" => Ok(Priority::Low),
        "normal" => Ok(Priority::Normal),
        "high" => Ok(Priority::High),
        "critical" | "crit" => Ok(Priority::Critical),
        other => {
            anyhow::bail!("invalid severity '{other}'; expected low, normal, high, or critical")
        }
    }
}

/// Reject a `--requires via` list naming a receipt source this binary does not
/// know. serde silently coerces an unknown string to `ReceiptSource::Unknown`,
/// which no `via` check accepts — the policy is then authored dead on arrival,
/// and on Codex a block gate degrades to a silent steer. Catch the typo at
/// authoring time; loading a policy written by a newer mati still tolerates
/// Unknown, so this validation lives here, not in the deserializer.
fn validate_requires_via(requires_json: &str) -> Result<()> {
    const KNOWN: &[&str] = &[
        "mem_get",
        "hook_context",
        "command_observed",
        "db_introspection",
    ];
    let value: serde_json::Value =
        serde_json::from_str(requires_json).context("parsing --requires JSON")?;
    let Some(via) = value.get("via").and_then(|v| v.as_array()) else {
        return Ok(());
    };
    for item in via {
        let Some(source) = item.as_str() else {
            continue;
        };
        if !KNOWN.contains(&source) {
            let hint = if source.starts_with("command") {
                " Did you mean 'command_observed'?"
            } else {
                ""
            };
            anyhow::bail!(
                "--requires via has an unrecognized receipt source '{source}'. \
                 Valid sources: {}.{hint}",
                KNOWN.join(", ")
            );
        }
    }
    Ok(())
}

async fn add(args: AddArgs) -> Result<()> {
    let slug = slugify!(&args.slug);
    if slug.is_empty() {
        anyhow::bail!("policy slug cannot be empty");
    }
    validate_requires_via(&args.requires)?;
    let policy = PolicyRecord {
        name: args.name,
        rule: args.rule,
        reason: args.reason,
        scope: args.scope,
        mode: parse_mode(&args.mode)?,
        trigger: parse_trigger(&args.trigger)?,
        deny_if: args
            .deny_if_command_glob
            .map(mati_core::store::ActionPredicate::CommandGlob)
            .or_else(|| {
                args.deny_if_path_glob
                    .map(mati_core::store::ActionPredicate::PathGlob)
            }),
        require: args
            .require_command_glob
            .map(mati_core::store::ActionPredicate::CommandGlob)
            .or_else(|| {
                args.require_path_glob
                    .map(mati_core::store::ActionPredicate::PathGlob)
            }),
        mints: match (args.mints_command_glob, args.mints_key) {
            (Some(on_command_glob), Some(key)) => Some(mati_core::store::ReceiptEmitter {
                on_command_glob,
                key,
            }),
            (None, None) => None,
            _ => anyhow::bail!("--mints-command-glob and --mints-key must be given together"),
        },
        requires: serde_json::from_str::<PolicyRequires>(&args.requires)
            .context("parsing --requires JSON")?,
        stage: if args.enable {
            PolicyStage::Enforce
        } else if args.shadow {
            PolicyStage::Shadow
        } else {
            PolicyStage::Off
        },
        severity: parse_priority(&args.severity)?,
        created_by: args.created_by,
    };
    let key = format!("policy:{slug}");
    let cwd = std::env::current_dir()?;
    let proxy = StoreProxy::open(&cwd).await?;
    let has_backing = has_backing_record(&proxy, &policy.requires.key).await?;
    for warning in mati_core::store::policy_ops::author_warnings(&policy, has_backing) {
        eprintln!("{warning}");
    }
    let result = proxy
        .policy_write(
            mati_core::mcp::protocol::PolicyWriteOp::Create,
            &key,
            Some(&policy),
        )
        .await;
    proxy.close_with_result(result).await?;
    println!("Created {key}");
    Ok(())
}

async fn edit(args: EditArgs) -> Result<()> {
    let key = normalize_key(&args.key);
    let cwd = std::env::current_dir()?;
    let proxy = StoreProxy::open(&cwd).await?;
    let record = proxy
        .get(&key)
        .await?
        .ok_or_else(|| anyhow::anyhow!("no record found for '{key}'"))?;
    let mut policy = record
        .payload_as::<PolicyRecord>()
        .ok_or_else(|| anyhow::anyhow!("'{key}' is not a policy record"))?;

    if let Some(value) = args.name {
        policy.name = value;
    }
    if let Some(value) = args.rule {
        policy.rule = value;
    }
    if let Some(value) = args.reason {
        policy.reason = value;
    }
    if let Some(value) = args.scope {
        policy.scope = value;
    }
    if let Some(value) = args.mode {
        policy.mode = parse_mode(&value)?;
    }
    if let Some(value) = args.trigger {
        policy.trigger = parse_trigger(&value)?;
    }
    if let Some(value) = args.requires {
        validate_requires_via(&value)?;
        policy.requires =
            serde_json::from_str::<PolicyRequires>(&value).context("parsing --requires JSON")?;
    }
    if let Some(value) = args.severity {
        policy.severity = parse_priority(&value)?;
    }

    let has_backing = has_backing_record(&proxy, &policy.requires.key).await?;
    for warning in mati_core::store::policy_ops::author_warnings(&policy, has_backing) {
        eprintln!("{warning}");
    }
    let result = proxy
        .policy_write(
            mati_core::mcp::protocol::PolicyWriteOp::Edit,
            &key,
            Some(&policy),
        )
        .await;
    proxy.close_with_result(result).await?;
    println!("Edited {key}");
    Ok(())
}

async fn list(json_output: bool) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let proxy = StoreProxy::open(&cwd).await?;
    let records = proxy
        .scan_prefix("policy:")
        .await?
        .into_iter()
        .filter_map(|record| {
            if record.payload_as::<PolicyRecord>().is_none() {
                eprintln!(
                    "warning: skipping policy {} with invalid payload",
                    record.key
                );
                return None;
            }
            matches!(record.lifecycle, mati_core::store::RecordLifecycle::Active).then_some(record)
        })
        .collect::<Vec<_>>();
    if json_output {
        println!("{}", serde_json::to_string_pretty(&records)?);
    } else if records.is_empty() {
        println!("No local policies found.");
    } else {
        for record in records {
            let policy = record
                .payload_as::<PolicyRecord>()
                .expect("validated policy payload");
            println!(
                "{}\t{}\t{}\t{:?}",
                record.key,
                format!("{:?}", policy.stage).to_ascii_lowercase(),
                policy.name,
                policy.mode
            );
        }
    }
    proxy.close().await
}

async fn show(key: &str) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let proxy = StoreProxy::open(&cwd).await?;
    let record = proxy
        .get(key)
        .await?
        .ok_or_else(|| anyhow::anyhow!("no record found for '{key}'"))?;
    let policy = record
        .payload_as::<PolicyRecord>()
        .ok_or_else(|| anyhow::anyhow!("'{key}' is not a policy record"))?;
    println!("{}", serde_json::to_string_pretty(&policy)?);
    proxy.close().await
}

async fn set_enabled(key: &str, enabled: bool) -> Result<()> {
    set_stage(
        key,
        if enabled {
            PolicyStage::Enforce
        } else {
            PolicyStage::Off
        },
    )
    .await
}

fn parse_stage(value: &str) -> Result<PolicyStage> {
    match value.trim().to_ascii_lowercase().as_str() {
        "off" => Ok(PolicyStage::Off),
        "shadow" => Ok(PolicyStage::Shadow),
        "enforce" => Ok(PolicyStage::Enforce),
        other => anyhow::bail!("invalid policy stage '{other}'; expected off, shadow, or enforce"),
    }
}

async fn set_stage(key: &str, stage: PolicyStage) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let proxy = StoreProxy::open(&cwd).await?;
    let record = proxy
        .get(key)
        .await?
        .ok_or_else(|| anyhow::anyhow!("no record found for '{key}'"))?;
    let mut policy = record
        .payload_as::<PolicyRecord>()
        .ok_or_else(|| anyhow::anyhow!("'{key}' is not a policy record"))?;
    policy.stage = stage;
    if stage == PolicyStage::Enforce {
        let has_backing = has_backing_record(&proxy, &policy.requires.key).await?;
        for warning in mati_core::store::policy_ops::author_warnings(&policy, has_backing) {
            eprintln!("{warning}");
        }
    }
    let result = proxy
        .policy_write(
            mati_core::mcp::protocol::PolicyWriteOp::Stage,
            key,
            Some(&policy),
        )
        .await;
    proxy.close_with_result(result).await?;
    println!("Set {} stage to {:?}", key, stage);
    Ok(())
}

/// Answer "why is this policy still blocking?" without a store dump.
///
/// A block policy is unlocked by a `session:consulted:*` receipt, and nothing
/// could read those: diagnosing a policy that would not unlock meant inferring
/// receipt state from whether a later command was denied. This reports the
/// receipt each policy is waiting on, its age against that policy's TTL, and
/// the resulting verdict.
///
/// Receipt keys are `session:consulted:<key>` or `session:consulted:<actor>:<key>`
/// and the consulted key contains colons of its own, so the actor cannot be
/// split out reliably. Matching runs from the policy side instead: a receipt
/// belongs to a policy when its key ends with the policy's `requires.key`.
async fn receipts(json_output: bool) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let proxy = StoreProxy::open(&cwd).await?;
    let now = mati_core::store::session::now_secs();

    let receipt_keys = proxy.scan_keys("session:consulted:").await?;
    let mut ages: Vec<(String, u64, bool)> = Vec::new();
    for key in &receipt_keys {
        let Some(record) = proxy.get(key).await? else {
            continue;
        };
        let fingerprinted = record
            .payload
            .as_ref()
            .and_then(|p| p.get("fingerprint"))
            .is_some_and(|v| !v.is_null());
        ages.push((
            key.clone(),
            now.saturating_sub(record.updated_at),
            fingerprinted,
        ));
    }

    let mut claimed: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut report = Vec::new();
    for record in proxy.scan_prefix("policy:").await? {
        if !matches!(record.lifecycle, RecordLifecycle::Active) {
            continue;
        }
        let Some(policy) = record.payload_as::<PolicyRecord>() else {
            continue;
        };
        if matches!(policy.stage, PolicyStage::Off) || policy.requires.key.is_empty() {
            continue;
        }
        let ttl = policy.requires.freshness.ttl_secs;
        let suffix = format!(":{}", policy.requires.key);
        let mut found = Vec::new();
        for (key, age, fingerprinted) in &ages {
            if !key.ends_with(&suffix) {
                continue;
            }
            claimed.insert(key.clone());
            let scope = key
                .strip_prefix("session:consulted:")
                .and_then(|rest| rest.strip_suffix(&policy.requires.key))
                .map(|actor| actor.trim_end_matches(':'))
                .filter(|actor| !actor.is_empty())
                .unwrap_or("global")
                .to_string();
            found.push(serde_json::json!({
                "scope": scope,
                "age_secs": age,
                "valid": *age <= ttl,
                "expires_in_secs": ttl.saturating_sub(*age),
                "fingerprinted": fingerprinted,
            }));
        }
        // A receipt is actor-scoped: the gate reads the global receipt for the
        // main thread and an agent's own receipt for a subagent. So there is no
        // single "satisfied" answer, only the set of scopes that currently pass.
        let satisfied_for: Vec<String> = found
            .iter()
            .filter(|r| r["valid"] == serde_json::Value::Bool(true))
            .filter_map(|r| r["scope"].as_str().map(str::to_string))
            .collect();
        report.push(serde_json::json!({
            "policy": record.key,
            "stage": format!("{:?}", policy.stage).to_ascii_lowercase(),
            "mode": format!("{:?}", policy.mode).to_ascii_lowercase(),
            "requires_key": policy.requires.key,
            "ttl_secs": ttl,
            // A fingerprinted policy also requires the consulted record's
            // content to be unchanged, which this report does not compute, so
            // its verdict is a TTL upper bound rather than the final answer.
            "fingerprint_required": policy.requires.freshness.fingerprint,
            "receipts": found,
            "satisfied_for": satisfied_for,
        }));
    }

    let orphans: Vec<_> = ages
        .iter()
        .filter(|(key, _, _)| !claimed.contains(key))
        .map(|(key, age, _)| serde_json::json!({"key": key, "age_secs": age}))
        .collect();

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "policies": report,
                "unmatched_receipts": orphans,
            }))?
        );
    } else if report.is_empty() && orphans.is_empty() {
        println!("No receipts and no policies awaiting one.");
    } else {
        for entry in &report {
            let scopes = entry["satisfied_for"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default();
            let verdict = if entry["mode"] == "steer" {
                "steer (no receipt needed)".to_string()
            } else if scopes.is_empty() {
                "BLOCKS every actor".to_string()
            } else {
                format!("satisfied for: {scopes}")
            };
            println!(
                "{}\t{}\t{}",
                entry["policy"].as_str().unwrap_or(""),
                entry["stage"].as_str().unwrap_or(""),
                verdict
            );
            if entry["fingerprint_required"] == serde_json::Value::Bool(true) {
                println!("  note     fingerprint required; verdict below is TTL only");
            }
            println!(
                "  requires {} (ttl {}s)",
                entry["requires_key"].as_str().unwrap_or(""),
                entry["ttl_secs"]
            );
            let found = entry["receipts"]
                .as_array()
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            if found.is_empty() {
                println!("  receipt  none");
            }
            for r in found {
                println!(
                    "  receipt  {}\tage {}s\t{}{}",
                    r["scope"].as_str().unwrap_or(""),
                    r["age_secs"],
                    if r["valid"] == serde_json::Value::Bool(true) {
                        format!("valid, {}s left", r["expires_in_secs"])
                    } else {
                        "expired".to_string()
                    },
                    if r["fingerprinted"] == serde_json::Value::Bool(true) {
                        "\tfingerprinted"
                    } else {
                        ""
                    }
                );
            }
        }
        if !orphans.is_empty() {
            println!("\nReceipts no active policy requires:");
            for o in &orphans {
                println!(
                    "  {}\tage {}s",
                    o["key"].as_str().unwrap_or(""),
                    o["age_secs"]
                );
            }
        }
    }
    proxy.close().await
}

async fn observations(slug: Option<&str>, json_output: bool) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let proxy = StoreProxy::open(&cwd).await?;
    let shadow_records = proxy.scan_prefix("analytics:policy_shadow_").await?;
    let observations = observability::assemble_shadow_observations(&shadow_records, slug);
    if json_output {
        println!("{}", serde_json::to_string_pretty(&observations)?);
    } else if observations.is_empty() {
        println!("No shadow observations found.");
    } else {
        for (policy_key, policy) in observations {
            println!("{policy_key}\tcount={}", policy.count);
            for observation in policy.observations {
                println!(
                    "  {}\twould={:?}\t{}",
                    observation.timestamp,
                    observation.would,
                    serde_json::to_string(&observation.action)?
                );
            }
        }
    }
    proxy.close().await
}

/// Aggregate policy traces on read. There is intentionally no per-policy
/// index: policy records remain rebuildable and `mati repair` stays complete.
///
/// The aggregation math lives in [`observability::assemble_activity_report`];
/// this wrapper only fetches the record sets through the daemon-backed proxy so
/// the CLI and the `mem_query` telemetry modes cannot drift.
pub(crate) async fn collect_policy_activity(
    proxy: &StoreProxy,
    days: u64,
) -> Result<ActivityReport> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let window_start = observability::window_start_secs(now, days);
    let enforcement = proxy
        .scan_enforcement_events_since_ms(
            window_start.saturating_mul(1000),
            now.saturating_mul(1000),
        )
        .await?;
    let policy_records = proxy.scan_prefix("policy:").await?;
    let shadow_records = proxy.scan_prefix("analytics:policy_shadow_").await?;
    let steer_records = proxy.scan_prefix("analytics:policy_steer_").await?;
    Ok(observability::assemble_activity_report(
        now,
        days,
        &policy_records,
        &enforcement,
        &shadow_records,
        &steer_records,
        None,
    ))
}

async fn activity(slug: Option<&str>, json_output: bool, days: u64) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let proxy = StoreProxy::open(&cwd).await?;
    let mut report = collect_policy_activity(&proxy, days).await?;
    if let Some(slug) = slug {
        let key = normalize_key(slug);
        report.policies.retain(|policy| policy.policy == key);
    }
    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("Policy activity — last {} days", report.window_days);
        if report.retention_limited {
            println!(
                "  note: {}",
                report
                    .retention_note
                    .as_deref()
                    .unwrap_or("retained enforcement history may be incomplete")
            );
        }
        for policy in &report.policies {
            let sources = if policy.sources.is_empty() {
                "-".to_string()
            } else {
                policy.sources.join(",")
            };
            match policy.state {
                ActivityState::Fired => println!(
                    "{}\tfired\tcount={}\tlast={}\tsources={}",
                    policy.policy,
                    policy.count,
                    policy.last_fired_at.unwrap_or(0),
                    sources
                ),
                ActivityState::NoActivity => println!(
                    "{}\tno activity in {} days\tsources={}",
                    policy.policy, policy.window_days, sources
                ),
                ActivityState::NotMeasurable => {
                    println!("{}\tnot measurable\tno adapter trace", policy.policy)
                }
            }
        }
        if report.policies.is_empty() {
            println!("No active policies found.");
        }
    }
    proxy.close().await
}

async fn delete(key: &str) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let proxy = StoreProxy::open(&cwd).await?;
    let result = proxy
        .policy_write(mati_core::mcp::protocol::PolicyWriteOp::Delete, key, None)
        .await;
    proxy.close_with_result(result).await?;
    println!("Deleted {key} (tombstoned)");
    Ok(())
}

async fn test_policies(args: TestArgs) -> Result<()> {
    if args.command.is_none() && args.path.is_none() {
        anyhow::bail!("provide --command or --path");
    }
    let action = normalize_action(args.command.as_deref(), args.path.as_deref());
    if let Some(trigger_json) = args.trigger {
        let trigger = parse_trigger(&trigger_json)?;
        let policy = PolicyRecord {
            mints: None,
            name: "ad-hoc".into(),
            rule: "ad-hoc trigger".into(),
            reason: "ad-hoc trigger evaluation".into(),
            scope: "repo".into(),
            mode: PolicyMode::Steer,
            trigger,
            deny_if: None,
            require: None,
            requires: serde_json::from_str(r#"{"key":"","via":[],"freshness":{"ttl_secs":900}}"#)?,
            stage: PolicyStage::Enforce,
            severity: Priority::Normal,
            created_by: "ad-hoc".into(),
        };
        let matcher = mati_core::hooks::policy_match::PolicyMatcherSet::from_policies([(
            "policy:ad-hoc".into(),
            policy,
        )])?;
        let matched = !matcher.matches(&action).is_empty();
        println!(
            "{}",
            render_ad_hoc_test_output(&action, matched, args.json)?
        );
        return Ok(());
    }
    let cwd = std::env::current_dir()?;
    let proxy = StoreProxy::open(&cwd).await?;
    let matches = proxy.policy_evaluate(&action, None).await?;
    let mut unbacked = Vec::new();
    for matched in &matches {
        if matched
            .via
            .contains(&mati_core::store::ReceiptSource::MemGet)
            && !has_backing_record(&proxy, &matched.requires_key).await?
        {
            unbacked.push(matched.requires_key.clone());
        }
    }
    let output = render_test_output_with_warnings(&action, &matches, &unbacked, args.json)?;
    proxy.close().await?;
    println!("{output}");
    Ok(())
}

fn render_ad_hoc_test_output(action: &Action, matched: bool, json_output: bool) -> Result<String> {
    if json_output {
        return Ok(serde_json::to_string_pretty(&serde_json::json!({
            "action": action,
            "matched": matched,
            "persisted": false,
        }))?);
    }
    Ok(format!(
        "Action: tool={} matched={matched} (persisted=false)",
        action.tool
    ))
}

fn render_test_output_with_warnings(
    action: &Action,
    matches: &[mati_core::mcp::protocol::PolicyVerdict],
    unbacked_requires: &[String],
    json_output: bool,
) -> Result<String> {
    if json_output {
        return Ok(serde_json::to_string_pretty(&serde_json::json!({
            "action": action,
            "matches": matches,
            "unbacked_requires": unbacked_requires,
        }))?);
    }

    let host = action.host.as_deref().unwrap_or("-");
    let files = if action.files.is_empty() {
        "-".to_string()
    } else {
        action.files.join(",")
    };
    let mut output = format!(
        "Action: tool={} host={} files={}\n",
        action.tool, host, files
    );
    if matches.is_empty() {
        output.push_str("No matching policies.");
    } else {
        output.push_str("Matching policies:\n");
        for matched in matches {
            let mode = match matched.mode {
                PolicyMode::Steer => "steer",
                PolicyMode::Block => "block",
            };
            let status = if matched.mode == PolicyMode::Block {
                if matched.satisfied {
                    "satisfied"
                } else {
                    "would-block"
                }
            } else {
                "advisory"
            };
            output.push_str(&format!(
                "  {} [{}; {}] {}\n",
                matched.key, mode, status, matched.rule
            ));
            if unbacked_requires
                .iter()
                .any(|key| key == &matched.requires_key)
            {
                output.push_str(&format!(
                    "  {}\n",
                    unbacked_requires_warning(&matched.requires_key)
                ));
            }
        }
        output.pop();
    }
    Ok(output)
}

async fn has_backing_record(proxy: &StoreProxy, key: &str) -> Result<bool> {
    Ok(proxy
        .get(key)
        .await?
        .is_some_and(|record| !matches!(record.lifecycle, RecordLifecycle::Tombstoned { .. })))
}

fn unbacked_requires_warning(key: &str) -> String {
    format!(
        "warning: requires.key '{key}' has no backing record; a mem_get on it would mint a receipt without the agent learning anything. Store a record at that key (e.g. the schema doc) so consultation is substantive."
    )
}

fn verify(args: VerifyArgs) -> Result<()> {
    let text = std::fs::read_to_string(&args.bundle)
        .with_context(|| format!("reading bundle {}", args.bundle.display()))?;
    let bundle: PolicyBundle = serde_json::from_str(&text).context("parsing bundle JSON")?;

    // Trust anchor: an explicit --key (trusted under the bundle's key_id), else
    // this build's embedded keys (empty in the OSS core).
    let trusted: Vec<TrustedKey> = match &args.key {
        Some(b64) => {
            let raw = B64.decode(b64.trim()).context("decoding --key base64")?;
            let public_key: [u8; 32] = raw
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("--key must be a 32-byte Ed25519 public key"))?;
            vec![TrustedKey {
                key_id: bundle.key_id.clone(),
                public_key,
            }]
        }
        None => policy::default_trusted_keys(),
    };

    let result = policy::verify_bundle(&bundle, &trusted);

    if args.json {
        let json = match &result {
            Ok(v) => serde_json::json!({
                "verified": true,
                "org_id": v.org_id,
                "bundle_id": v.bundle_id,
                "rules": v.rules.len(),
            }),
            Err(e) => serde_json::json!({ "verified": false, "error": e.to_string() }),
        };
        println!("{}", serde_json::to_string_pretty(&json)?);
    } else {
        match &result {
            Ok(v) => {
                println!(
                    "✓ verified: org={} bundle={} ({} rule(s))",
                    v.org_id,
                    v.bundle_id,
                    v.rules.len()
                );
                for r in &v.rules {
                    println!("    [{}] {} → {}", r.level, r.target, r.id);
                }
            }
            Err(e) => eprintln!("✗ verification failed: {e}"),
        }
    }

    if result.is_err() {
        std::process::exit(1);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mati_core::hooks::policy_match::PolicyMatcherSet;

    #[test]
    fn policy_keys_accept_slugs_and_full_keys() {
        assert_eq!(normalize_key("query-safety"), "policy:query-safety");
        assert_eq!(normalize_key("policy:query-safety"), "policy:query-safety");
    }

    /// `.claude/CLAUDE.md` mandates `mati policy test --trigger` as the dry run
    /// before authoring. A typo used to compile into a match-everything trigger
    /// and report `matched=true`, so the dry run endorsed the misconfiguration
    /// it exists to catch.
    #[test]
    fn trigger_parse_rejects_typos_and_empty_predicates() {
        let typo = parse_trigger(r#"{"tooool":"db_client"}"#).unwrap_err();
        assert!(typo.to_string().contains("parsing --trigger JSON"));
        let empty = parse_trigger("{}").unwrap_err();
        assert!(empty.to_string().contains("no predicate"));

        let ok = parse_trigger(r#"{"tool":"db_client","host_glob":"*prod*"}"#).unwrap();
        assert_eq!(ok.tool.as_deref(), Some("db_client"));
    }

    #[test]
    fn policy_cli_parses_structured_authoring_fields() {
        let trigger: PolicyTrigger =
            serde_json::from_str(r#"{"tool":"db_client","host_glob":"*prod*"}"#).unwrap();
        let requires: PolicyRequires = serde_json::from_str(
            r#"{"key":"schema:orders","via":["mem_get"],"freshness":{"ttl_secs":900}}"#,
        )
        .unwrap();
        assert_eq!(trigger.tool.as_deref(), Some("db_client"));
        assert_eq!(requires.freshness.ttl_secs, 900);
        assert!(!requires.freshness.fingerprint);
    }

    #[test]
    fn policy_test_output_reports_human_match_and_mode() {
        let policy = PolicyRecord {
            deny_if: None,
            require: None,
            mints: None,
            name: "Production query safety".into(),
            rule: "Consult the schema first.".into(),
            reason: "Production schemas drift because deployments change.".into(),
            scope: "repo".into(),
            mode: PolicyMode::Block,
            trigger: PolicyTrigger {
                tool: Some("db_client".into()),
                host_glob: Some("*prod*".into()),
                target_path_glob: None,
                command_glob: None,
            },
            requires: serde_json::from_str(
                r#"{"key":"schema:orders","via":["mem_get"],"freshness":{"ttl_secs":900}}"#,
            )
            .unwrap(),
            stage: PolicyStage::Enforce,
            severity: Priority::High,
            created_by: "test".into(),
        };
        let set = PolicyMatcherSet::from_policies([("policy:prod".into(), policy)]).unwrap();
        let action = normalize_action(Some("psql -h db.prod.internal -c select"), None);
        let matches = set
            .matches(&action)
            .into_iter()
            .map(|matched| mati_core::mcp::protocol::PolicyVerdict {
                content: mati_core::store::ContentOutcome::None,
                require_content: mati_core::store::ContentOutcome::None,
                key: matched.key.to_string(),
                stage: matched.policy.stage,
                mode: matched.policy.mode,
                rule: matched.policy.rule.clone(),
                reason: matched.policy.reason.clone(),
                severity: matched.policy.severity.clone(),
                requires_key: matched.policy.requires.key.clone(),
                via: matched.policy.requires.via.clone(),
                satisfied: false,
                strict: false,
            })
            .collect::<Vec<_>>();
        let output = render_test_output_with_warnings(&action, &matches, &[], false).unwrap();
        assert!(output.contains("policy:prod [block; would-block] Consult the schema first."));
    }

    #[test]
    fn policy_test_output_json_contains_action_and_matches() {
        let action = normalize_action(Some("ls -la"), None);
        let output = render_test_output_with_warnings(&action, &[], &[], true).unwrap();
        let json: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(json["action"]["tool"], "unknown");
        assert!(json["matches"].as_array().unwrap().is_empty());
    }

    #[test]
    fn policy_test_output_surfaces_unbacked_memget_requirement() {
        let action = normalize_action(Some("psql -h db.prod.internal -c select"), None);
        let matched = mati_core::mcp::protocol::PolicyVerdict {
            content: mati_core::store::ContentOutcome::None,
            require_content: mati_core::store::ContentOutcome::None,
            key: "policy:prod".into(),
            stage: PolicyStage::Enforce,
            mode: PolicyMode::Block,
            rule: "Consult first.".into(),
            reason: "Because production changes.".into(),
            severity: Priority::High,
            requires_key: "schema:missing".into(),
            via: vec![mati_core::store::ReceiptSource::MemGet],
            satisfied: false,
            strict: true,
        };
        let output = render_test_output_with_warnings(
            &action,
            &[matched],
            &["schema:missing".into()],
            false,
        )
        .unwrap();
        assert!(output.contains("warning: requires.key 'schema:missing'"));
    }

    #[test]
    fn unbacked_requirement_warning_has_substantiveness_guidance() {
        let warning = unbacked_requires_warning("schema:orders");
        assert!(warning.contains("without the agent learning anything"));
        assert!(warning.contains("Store a record at that key"));
    }

    #[test]
    fn fingerprint_warning_requires_memget_source() {
        let policy = PolicyRequires {
            key: "schema:orders".into(),
            via: vec![mati_core::store::ReceiptSource::DbIntrospection],
            freshness: mati_core::store::PolicyFreshness {
                ttl_secs: 900,
                fingerprint: true,
            },
        };
        assert!(!policy
            .via
            .contains(&mati_core::store::ReceiptSource::MemGet));
        assert!(policy.freshness.fingerprint);
    }

    #[test]
    fn ad_hoc_test_output_is_explicitly_non_persistent() {
        let action = normalize_action(Some("psql -c select"), None);
        let output = render_ad_hoc_test_output(&action, true, false).unwrap();
        assert!(output.contains("matched=true"));
        assert!(output.contains("persisted=false"));

        let json = render_ad_hoc_test_output(&action, false, true).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["matched"], false);
        assert_eq!(value["persisted"], false);
    }

    #[test]
    fn validate_requires_via_rejects_unknown_source_with_hint() {
        // 'command' is the common typo for 'command_observed'; serde would coerce
        // it to ReceiptSource::Unknown and author a dead policy. Reject at add time.
        let err = validate_requires_via(
            r#"{"key":"tests-ran","via":["command"],"freshness":{"ttl_secs":900}}"#,
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("unrecognized receipt source 'command'"),
            "{err}"
        );
        assert!(err.contains("command_observed"), "expected the hint: {err}");
    }

    #[test]
    fn validate_requires_via_accepts_known_and_empty() {
        validate_requires_via(
            r#"{"key":"k","via":["command_observed","mem_get"],"freshness":{"ttl_secs":900}}"#,
        )
        .unwrap();
        validate_requires_via(r#"{"key":"","via":[],"freshness":{"ttl_secs":900}}"#).unwrap();
    }
}
