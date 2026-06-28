//! `mati policy verify` — verify a signed policy-floor bundle (idea 1.3).
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

use mati_core::policy::{self, PolicyBundle, TrustedKey};

#[derive(Args)]
pub struct PolicyArgs {
    #[command(subcommand)]
    command: PolicyCommand,
}

#[derive(Subcommand)]
enum PolicyCommand {
    /// Verify a signed policy-floor bundle's Ed25519 signature.
    Verify(VerifyArgs),
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
        PolicyCommand::Verify(a) => verify(a),
    }
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
