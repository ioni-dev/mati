//! Signed policy-floor bundle verification (idea 1.3 — control plane).
//!
//! A *policy floor* is a set of org rules a repo inherits and may strengthen
//! but never weaken. The core's role is narrow and INERT by itself: given a
//! bundle and trusted public keys, verify the Ed25519 signature over the
//! canonical payload and return the rules. It does NOT author or sign bundles
//! — that is mati-cloud's licensed responsibility. The open-core boundary is
//! exactly the trust anchor: the OSS build ships NO trusted signer key (see
//! [`default_trusted_keys`]), so no bundle verifies and the floor is dormant
//! until an Enterprise build (or an explicit caller) supplies a key.
//!
//! Pure: no I/O, no network — the verify path stays inside mati's zero-network
//! invariant. Mirrors the frozen-canonical + Ed25519 envelope convention used
//! by mati-cloud's `mati_license`.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

/// The accepted on-wire bundle format version.
pub const POLICY_FORMAT_VERSION: u32 = 1;

/// On-wire policy bundle: a signed payload of floor rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyBundle {
    /// Frozen on-wire format version. `1` for the layout below.
    pub policy_format_version: u32,
    /// Signature algorithm. Only `"ed25519"` is accepted.
    pub alg: String,
    /// Identifies which trusted key signed this bundle (no key fallback).
    pub key_id: String,
    /// Who issued the bundle (e.g. the org id). Informational.
    pub issuer: String,
    pub payload: PolicyPayload,
    /// Base64 (standard) Ed25519 signature over the canonical payload bytes.
    pub signature: String,
}

/// The signed content: org identity + the floor rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyPayload {
    pub org_id: String,
    pub bundle_id: String,
    /// ISO-8601 issue timestamp (informational; expiry handling is a follow-up).
    pub issued_at: String,
    pub rules: Vec<PolicyRule>,
}

/// A single non-weakenable floor rule. How `hook-decide` honors it is wired in
/// a follow-up; this defines the verified shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    pub id: String,
    /// Repo-relative path or glob the rule applies to.
    pub target: String,
    /// Floor level: `"deny"` (hard block) or `"advisory"` (inject context).
    pub level: String,
    pub reason: String,
}

/// A trusted signer: a key id and its Ed25519 public key.
#[derive(Debug, Clone)]
pub struct TrustedKey {
    pub key_id: String,
    pub public_key: [u8; 32],
}

/// Trusted policy signers embedded in THIS build. **Empty in the OSS core**, so
/// no bundle verifies and the floor is dormant — the open-core boundary. An
/// Enterprise build supplies its vendor/org key(s) here; a caller may also pass
/// its own to [`verify_bundle`] (e.g. `mati policy verify --key`).
pub fn default_trusted_keys() -> Vec<TrustedKey> {
    Vec::new()
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PolicyError {
    #[error("unsupported policy_format_version {0} (expected {POLICY_FORMAT_VERSION})")]
    UnsupportedVersion(u32),
    #[error("unsupported signature algorithm {0:?} (expected \"ed25519\")")]
    UnsupportedAlg(String),
    #[error("no trusted key matches key_id {0:?}")]
    UnknownKey(String),
    #[error("policy bundle signature verification failed (corrupt, tampered, or wrong key)")]
    SignatureInvalid,
}

/// A bundle whose signature verified against a trusted key. Holds the rules the
/// caller may honor as a floor.
#[derive(Debug, Clone)]
pub struct VerifiedBundle {
    pub org_id: String,
    pub bundle_id: String,
    pub rules: Vec<PolicyRule>,
}

/// Canonical bytes of a payload for signing/verification. Field order is FROZEN
/// for `policy_format_version` 1 — changing it invalidates every existing
/// signature. Re-serializes through an explicit-order struct rather than
/// trusting the incoming JSON's field/key order.
fn canonical_payload_bytes(payload: &PolicyPayload) -> Vec<u8> {
    #[derive(Serialize)]
    struct CanonicalRule<'a> {
        id: &'a str,
        target: &'a str,
        level: &'a str,
        reason: &'a str,
    }
    #[derive(Serialize)]
    struct Canonical<'a> {
        org_id: &'a str,
        bundle_id: &'a str,
        issued_at: &'a str,
        rules: Vec<CanonicalRule<'a>>,
    }
    let canonical = Canonical {
        org_id: &payload.org_id,
        bundle_id: &payload.bundle_id,
        issued_at: &payload.issued_at,
        rules: payload
            .rules
            .iter()
            .map(|r| CanonicalRule {
                id: &r.id,
                target: &r.target,
                level: &r.level,
                reason: &r.reason,
            })
            .collect(),
    };
    serde_json::to_vec(&canonical).expect("canonical serialization cannot fail")
}

/// Verify a policy bundle against trusted keys.
///
/// The signature MUST verify against the exact key named by `key_id` — there is
/// NO fallback to other trusted keys, so a bundle signed with key A never
/// verifies against key B even if both are trusted. Returns the verified rules,
/// or a [`PolicyError`] describing the rejection. Pure + offline.
pub fn verify_bundle(
    bundle: &PolicyBundle,
    trusted_keys: &[TrustedKey],
) -> Result<VerifiedBundle, PolicyError> {
    if bundle.policy_format_version != POLICY_FORMAT_VERSION {
        return Err(PolicyError::UnsupportedVersion(
            bundle.policy_format_version,
        ));
    }
    if bundle.alg != "ed25519" {
        return Err(PolicyError::UnsupportedAlg(bundle.alg.clone()));
    }

    let trusted = trusted_keys
        .iter()
        .find(|k| k.key_id == bundle.key_id)
        .ok_or_else(|| PolicyError::UnknownKey(bundle.key_id.clone()))?;

    let verifying =
        VerifyingKey::from_bytes(&trusted.public_key).map_err(|_| PolicyError::SignatureInvalid)?;

    let sig_bytes = B64
        .decode(bundle.signature.as_bytes())
        .map_err(|_| PolicyError::SignatureInvalid)?;
    let sig_arr: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| PolicyError::SignatureInvalid)?;
    let signature = Signature::from_bytes(&sig_arr);

    let canonical = canonical_payload_bytes(&bundle.payload);
    verifying
        .verify(&canonical, &signature)
        .map_err(|_| PolicyError::SignatureInvalid)?;

    Ok(VerifiedBundle {
        org_id: bundle.payload.org_id.clone(),
        bundle_id: bundle.payload.bundle_id.clone(),
        rules: bundle.payload.rules.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    const TEST_SEED: [u8; 32] = [7u8; 32];

    fn test_key() -> (SigningKey, TrustedKey) {
        let sk = SigningKey::from_bytes(&TEST_SEED);
        let public_key = sk.verifying_key().to_bytes();
        (
            sk,
            TrustedKey {
                key_id: "test-key-1".into(),
                public_key,
            },
        )
    }

    fn sample_payload() -> PolicyPayload {
        PolicyPayload {
            org_id: "acme".into(),
            bundle_id: "b-001".into(),
            issued_at: "2026-06-28T00:00:00Z".into(),
            rules: vec![PolicyRule {
                id: "PHI-1".into(),
                target: "src/payments/**".into(),
                level: "deny".into(),
                reason: "PHI files require consultation".into(),
            }],
        }
    }

    fn sign_with(sk: &SigningKey, key_id: &str, payload: PolicyPayload) -> PolicyBundle {
        let sig = sk.sign(&canonical_payload_bytes(&payload));
        PolicyBundle {
            policy_format_version: POLICY_FORMAT_VERSION,
            alg: "ed25519".into(),
            key_id: key_id.to_string(),
            issuer: "acme".into(),
            payload,
            signature: B64.encode(sig.to_bytes()),
        }
    }

    #[test]
    fn accepts_a_correctly_signed_bundle() {
        let (sk, trusted) = test_key();
        let bundle = sign_with(&sk, &trusted.key_id, sample_payload());
        let verified = verify_bundle(&bundle, &[trusted]).expect("should verify");
        assert_eq!(verified.org_id, "acme");
        assert_eq!(verified.rules.len(), 1);
        assert_eq!(verified.rules[0].id, "PHI-1");
        assert_eq!(verified.rules[0].level, "deny");
    }

    #[test]
    fn rejects_a_tampered_payload() {
        // The whole point of a floor: weakening a rule after signing must fail.
        let (sk, trusted) = test_key();
        let mut bundle = sign_with(&sk, &trusted.key_id, sample_payload());
        bundle.payload.rules[0].level = "advisory".into(); // weaken deny -> advisory
        assert!(matches!(
            verify_bundle(&bundle, &[trusted]),
            Err(PolicyError::SignatureInvalid)
        ));
    }

    #[test]
    fn rejects_an_unknown_key_id() {
        let (sk, trusted) = test_key();
        let bundle = sign_with(&sk, "some-other-key", sample_payload());
        assert!(matches!(
            verify_bundle(&bundle, &[trusted]),
            Err(PolicyError::UnknownKey(_))
        ));
    }

    #[test]
    fn rejects_a_signature_from_an_untrusted_key() {
        // Attacker signs with their own key but claims the trusted key_id.
        let (_sk, trusted) = test_key();
        let attacker = SigningKey::from_bytes(&[9u8; 32]);
        let payload = sample_payload();
        let sig = attacker.sign(&canonical_payload_bytes(&payload));
        let bundle = PolicyBundle {
            policy_format_version: POLICY_FORMAT_VERSION,
            alg: "ed25519".into(),
            key_id: trusted.key_id.clone(),
            issuer: "acme".into(),
            payload,
            signature: B64.encode(sig.to_bytes()),
        };
        assert!(matches!(
            verify_bundle(&bundle, &[trusted]),
            Err(PolicyError::SignatureInvalid)
        ));
    }

    #[test]
    fn rejects_bad_version_and_alg() {
        let (sk, trusted) = test_key();
        let mut v = sign_with(&sk, &trusted.key_id, sample_payload());
        v.policy_format_version = 999;
        assert!(matches!(
            verify_bundle(&v, std::slice::from_ref(&trusted)),
            Err(PolicyError::UnsupportedVersion(999))
        ));

        let mut a = sign_with(&sk, &trusted.key_id, sample_payload());
        a.alg = "rsa".into();
        assert!(matches!(
            verify_bundle(&a, &[trusted]),
            Err(PolicyError::UnsupportedAlg(_))
        ));
    }

    #[test]
    fn oss_core_trusts_no_keys_so_floor_is_dormant() {
        // Open-core gate: with the default (empty) trust anchor, even a
        // perfectly-signed bundle is rejected — the mechanism is inert until an
        // Enterprise build (or explicit caller) supplies a trusted key.
        let (sk, trusted) = test_key();
        let bundle = sign_with(&sk, &trusted.key_id, sample_payload());
        assert!(matches!(
            verify_bundle(&bundle, &default_trusted_keys()),
            Err(PolicyError::UnknownKey(_))
        ));
    }
}
