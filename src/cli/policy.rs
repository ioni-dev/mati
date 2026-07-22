//! `mati policy` — author local policies and verify signed policy-floor bundles.
//!
//! Verification only; authoring/signing bundles is mati-cloud's licensed
//! feature. Like `cosign verify`, it checks a bundle against a trusted key:
//! one supplied with `--key` (verify against a key you trust), or this build's
//! embedded trust anchor (empty in the OSS core, so a real bundle is rejected
//! until an Enterprise build supplies a key). Pure + offline.

use std::path::PathBuf;

use anyhow::{Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use clap::{Args, Subcommand};
use slugify::slugify;

use mati_core::hooks::decide::{normalize_action, Action};
use mati_core::hooks::policy_match::{MatchedPolicy, PolicyMatcherSet};
use mati_core::policy::{self, PolicyBundle, TrustedKey};
use mati_core::store::{PolicyMode, PolicyRecord, PolicyRequires, PolicyTrigger, Priority};

use crate::cli::proxy::StoreProxy;

#[derive(Args)]
pub struct PolicyArgs {
    #[command(subcommand)]
    command: PolicyCommand,
}

#[derive(Subcommand)]
enum PolicyCommand {
    /// Add a local repository policy (stored under policy:<slug>).
    #[command(
        long_about = "Add a local, developer-authored policy. This authors data in the local mati store; it does not verify a signed policy-floor bundle."
    )]
    Add(AddArgs),
    /// List active local policies.
    List {
        /// Emit JSON instead of a table.
        #[arg(long)]
        json: bool,
    },
    /// Show one local policy.
    Show(PolicyKeyArgs),
    /// Enable one local policy.
    Enable(PolicyKeyArgs),
    /// Disable one local policy.
    Disable(PolicyKeyArgs),
    /// Tombstone one local policy.
    Delete(PolicyKeyArgs),
    /// Test local policy predicates against a command or path without writing.
    Test(TestArgs),
    /// Verify a signed policy-floor bundle's Ed25519 signature.
    Verify(VerifyArgs),
}

#[derive(Args)]
struct PolicyKeyArgs {
    /// Policy key (policy:<slug>) or slug.
    key: String,
}

#[derive(Args)]
struct AddArgs {
    /// Slug used to form policy:<slug>.
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
}

#[derive(Args)]
struct TestArgs {
    /// Bash command to normalize and test.
    #[arg(long)]
    command: Option<String>,
    /// File path to normalize and test.
    #[arg(long)]
    path: Option<String>,
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
        PolicyCommand::List { json } => list(json).await,
        PolicyCommand::Show(a) => show(&normalize_key(&a.key)).await,
        PolicyCommand::Enable(a) => set_enabled(&normalize_key(&a.key), true).await,
        PolicyCommand::Disable(a) => set_enabled(&normalize_key(&a.key), false).await,
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

fn direct_store(proxy: &StoreProxy) -> Result<&mati_core::store::Store> {
    proxy.direct_store().ok_or_else(|| {
        anyhow::anyhow!(
        "local policy mutations need direct store access, but a daemon currently holds the store. \
         Stop it first with `mati daemon stop`, then retry \
         (daemon-mode policy authoring lands in a later milestone)."
    )
    })
}

async fn add(args: AddArgs) -> Result<()> {
    let slug = slugify!(&args.slug);
    if slug.is_empty() {
        anyhow::bail!("policy slug cannot be empty");
    }
    let policy = PolicyRecord {
        name: args.name,
        rule: args.rule,
        reason: args.reason,
        scope: args.scope,
        mode: parse_mode(&args.mode)?,
        trigger: serde_json::from_str::<PolicyTrigger>(&args.trigger)
            .context("parsing --trigger JSON")?,
        requires: serde_json::from_str::<PolicyRequires>(&args.requires)
            .context("parsing --requires JSON")?,
        enabled: true,
        severity: parse_priority(&args.severity)?,
        created_by: args.created_by,
    };
    let key = format!("policy:{slug}");
    let cwd = std::env::current_dir()?;
    let proxy = StoreProxy::open(&cwd).await?;
    // Keep all policy:* writes centralized in store::policy_ops.
    let result = match direct_store(&proxy) {
        Ok(store) => mati_core::store::policy_ops::create(store, &key, &policy).await,
        Err(error) => Err(error),
    };
    proxy.close_with_result(result).await?;
    println!("Created {key}");
    Ok(())
}

async fn list(json_output: bool) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let proxy = StoreProxy::open(&cwd).await?;
    let records = proxy
        .scan_prefix("policy:")
        .await?
        .into_iter()
        .filter(|record| matches!(record.lifecycle, mati_core::store::RecordLifecycle::Active))
        .collect::<Vec<_>>();
    if json_output {
        println!("{}", serde_json::to_string_pretty(&records)?);
    } else if records.is_empty() {
        println!("No local policies found.");
    } else {
        for record in records {
            let policy = record.payload_as::<PolicyRecord>().ok_or_else(|| {
                anyhow::anyhow!("invalid PolicyRecord payload for {}", record.key)
            })?;
            println!(
                "{}\t{}\t{}\t{:?}",
                record.key,
                if policy.enabled {
                    "enabled"
                } else {
                    "disabled"
                },
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
    let cwd = std::env::current_dir()?;
    let proxy = StoreProxy::open(&cwd).await?;
    let result = match direct_store(&proxy) {
        Ok(store) => mati_core::store::policy_ops::set_enabled(store, key, enabled).await,
        Err(error) => Err(error),
    };
    proxy.close_with_result(result).await?;
    println!("{} {}", if enabled { "Enabled" } else { "Disabled" }, key);
    Ok(())
}

async fn delete(key: &str) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let proxy = StoreProxy::open(&cwd).await?;
    let result = match direct_store(&proxy) {
        Ok(store) => mati_core::store::policy_ops::delete(store, key).await,
        Err(error) => Err(error),
    };
    proxy.close_with_result(result).await?;
    println!("Deleted {key} (tombstoned)");
    Ok(())
}

async fn test_policies(args: TestArgs) -> Result<()> {
    if args.command.is_none() && args.path.is_none() {
        anyhow::bail!("provide --command or --path");
    }
    let action = normalize_action(args.command.as_deref(), args.path.as_deref());
    let cwd = std::env::current_dir()?;
    let proxy = StoreProxy::open(&cwd).await?;
    let records = proxy
        .scan_prefix("policy:")
        .await?
        .into_iter()
        .filter(|record| {
            matches!(record.lifecycle, mati_core::store::RecordLifecycle::Active)
                && record
                    .payload_as::<PolicyRecord>()
                    .is_some_and(|policy| policy.enabled)
        })
        .collect::<Vec<_>>();
    let matcher = PolicyMatcherSet::from_records(&records).context("compiling local policies")?;
    let matches = matcher.matches(&action);
    let output = render_test_output(&action, &matches, args.json)?;
    proxy.close().await?;
    println!("{output}");
    Ok(())
}

fn render_test_output(
    action: &Action,
    matches: &[MatchedPolicy<'_>],
    json_output: bool,
) -> Result<String> {
    if json_output {
        let matched = matches
            .iter()
            .map(|matched| {
                serde_json::json!({
                    "key": matched.key,
                    "name": matched.policy.name,
                    "mode": matched.policy.mode,
                })
            })
            .collect::<Vec<_>>();
        return Ok(serde_json::to_string_pretty(&serde_json::json!({
            "action": action,
            "matches": matched,
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
            let mode = match matched.policy.mode {
                PolicyMode::Steer => "steer",
                PolicyMode::Block => "block",
            };
            output.push_str(&format!(
                "  {} [{}] {}\n",
                matched.key, mode, matched.policy.name
            ));
        }
        output.pop();
    }
    Ok(output)
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

    #[test]
    fn policy_keys_accept_slugs_and_full_keys() {
        assert_eq!(normalize_key("query-safety"), "policy:query-safety");
        assert_eq!(normalize_key("policy:query-safety"), "policy:query-safety");
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
    }

    #[test]
    fn policy_test_output_reports_human_match_and_mode() {
        let policy = PolicyRecord {
            name: "Production query safety".into(),
            rule: "Consult the schema first.".into(),
            reason: "Production schemas drift because deployments change.".into(),
            scope: "repo".into(),
            mode: PolicyMode::Block,
            trigger: PolicyTrigger {
                tool: Some("db_client".into()),
                host_glob: Some("*prod*".into()),
                target_path_glob: None,
            },
            requires: serde_json::from_str(
                r#"{"key":"schema:orders","via":["mem_get"],"freshness":{"ttl_secs":900}}"#,
            )
            .unwrap(),
            enabled: true,
            severity: Priority::High,
            created_by: "test".into(),
        };
        let set = PolicyMatcherSet::from_policies([("policy:prod".into(), policy)]).unwrap();
        let action = normalize_action(Some("psql -h db.prod.internal -c select"), None);
        let matches = set.matches(&action);
        let output = render_test_output(&action, &matches, false).unwrap();
        assert!(output.contains("policy:prod [block] Production query safety"));
    }

    #[test]
    fn policy_test_output_json_contains_action_and_matches() {
        let action = normalize_action(Some("ls -la"), None);
        let set = PolicyMatcherSet::from_policies(Vec::<(String, PolicyRecord)>::new()).unwrap();
        let output = render_test_output(&action, &set.matches(&action), true).unwrap();
        let json: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(json["action"]["tool"], "unknown");
        assert!(json["matches"].as_array().unwrap().is_empty());
    }
}
