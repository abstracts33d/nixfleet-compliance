//! Shared sign / verify primitives for on-disk compliance evidence.
//!
//! The on-disk signature is over the JCS-canonical bytes (RFC 8785) of
//! `evidence.json`, signed with the host's existing SSH ed25519 key
//! (`/etc/ssh/ssh_host_ed25519_key` by default). An auditor in possession
//! of the host's SSH public key can verify the chain offline with the
//! `nixfleet-compliance-verify` binary or - equivalently - by replicating
//! the JCS canonicalisation and running `ed25519` verification themselves.
//!
//! When `nixfleet-compliance` is paired with the `nixfleet` agent, the
//! agent additionally signs a bounded wire-summary (`ComplianceFailureSignedPayload`
//! and friends) using the *same* SSH host key and posts that to the
//! control plane. The two signatures cover different things and coexist;
//! the wire path bounds payload size, the on-disk path keeps the full
//! evidence verifiable from a single host without CP access.

use anyhow::{bail, Context, Result};
use base64::Engine as _;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde_json::Value;
use std::fs;
use std::path::Path;

/// Default location of the SSH host signing key on NixOS.
pub const DEFAULT_HOST_KEY: &str = "/etc/ssh/ssh_host_ed25519_key";

/// Read an OpenSSH ed25519 *private* key from disk and return a signing key.
pub fn load_signing_key(path: &Path) -> Result<SigningKey> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("read SSH host key at {}", path.display()))?;
    let private = ssh_key::PrivateKey::from_openssh(&raw)
        .with_context(|| format!("parse OpenSSH key at {}", path.display()))?;

    // FOOTGUN: OpenSSH stores 64 bytes (seed + pubkey); dalek wants only the 32-byte seed.
    // Same shape as nixfleet/crates/nixfleet-agent/src/evidence_signer.rs.
    let seed = match private.key_data() {
        ssh_key::private::KeypairData::Ed25519(kp) => kp.private.to_bytes(),
        other => bail!(
            "SSH host key at {} is not ed25519 (algorithm: {:?})",
            path.display(),
            other.algorithm()
        ),
    };
    Ok(SigningKey::from_bytes(&seed))
}

/// Read an OpenSSH ed25519 *public* key from disk and return a verifying key.
pub fn load_verifying_key(path: &Path) -> Result<VerifyingKey> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("read SSH public key at {}", path.display()))?;
    let public = ssh_key::PublicKey::from_openssh(raw.trim())
        .with_context(|| format!("parse OpenSSH pubkey at {}", path.display()))?;
    let bytes = match public.key_data() {
        ssh_key::public::KeyData::Ed25519(k) => k.0,
        other => bail!(
            "SSH public key at {} is not ed25519 (algorithm: {:?})",
            path.display(),
            other.algorithm()
        ),
    };
    VerifyingKey::from_bytes(&bytes).context("invalid ed25519 public key bytes")
}

/// JCS-canonicalise the input JSON (RFC 8785) and return the canonical bytes.
/// This is what gets signed; an auditor reproducing the recipe MUST canonicalise
/// before verifying.
pub fn canonicalise(evidence_json: &Path) -> Result<Vec<u8>> {
    let raw = fs::read_to_string(evidence_json)
        .with_context(|| format!("read {}", evidence_json.display()))?;
    let value: Value =
        serde_json::from_str(&raw).context("evidence.json is not valid JSON")?;
    serde_jcs::to_vec(&value).context("JCS canonicalisation failed")
}

/// Sign the JCS-canonical bytes of `evidence_json` with `signing_key`.
/// Returns a base64-encoded 64-byte ed25519 signature (standard alphabet).
pub fn sign_evidence(evidence_json: &Path, signing_key: &SigningKey) -> Result<String> {
    let canonical = canonicalise(evidence_json)?;
    let sig = signing_key.sign(&canonical);
    Ok(base64::engine::general_purpose::STANDARD.encode(sig.to_bytes()))
}

/// Verify the signature in `signature_b64` against the JCS-canonical bytes of
/// `evidence_json` using `verifying_key`. Returns Ok(()) on success, Err on
/// any failure (decode, length, cryptographic).
pub fn verify_evidence(
    evidence_json: &Path,
    signature_b64: &str,
    verifying_key: &VerifyingKey,
) -> Result<()> {
    let canonical = canonicalise(evidence_json)?;
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(signature_b64.trim())
        .context("decode base64 signature")?;
    let sig_arr: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .context("signature must be 64 bytes")?;
    let signature = Signature::from_bytes(&sig_arr);
    verifying_key
        .verify(&canonical, &signature)
        .context("ed25519 verification failed")
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::RngCore;
    use std::io::Write;

    fn write_test_key(dir: &Path) -> (std::path::PathBuf, std::path::PathBuf) {
        let mut seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        let sk = SigningKey::from_bytes(&seed);

        // Private key (OpenSSH)
        let kp = ssh_key::private::Ed25519Keypair {
            public: ssh_key::public::Ed25519PublicKey(sk.verifying_key().to_bytes()),
            private: ssh_key::private::Ed25519PrivateKey::from_bytes(&sk.to_bytes()),
        };
        let priv_data = ssh_key::PrivateKey::new(
            ssh_key::private::KeypairData::Ed25519(kp.clone()),
            "test-host",
        )
        .expect("ssh PrivateKey::new");
        let priv_pem = priv_data
            .to_openssh(ssh_key::LineEnding::LF)
            .expect("to_openssh");
        let priv_path = dir.join("ssh_host_ed25519_key");
        fs::write(&priv_path, priv_pem.as_bytes()).expect("write priv");

        // Public key (OpenSSH, single-line)
        let pub_path = dir.join("ssh_host_ed25519_key.pub");
        let pub_str = priv_data
            .public_key()
            .to_openssh()
            .expect("pubkey to_openssh");
        fs::write(&pub_path, pub_str.as_bytes()).expect("write pub");

        (priv_path, pub_path)
    }

    fn write_test_evidence(dir: &Path, content: &str) -> std::path::PathBuf {
        let path = dir.join("evidence.json");
        let mut f = fs::File::create(&path).expect("create evidence");
        f.write_all(content.as_bytes()).expect("write evidence");
        path
    }

    #[test]
    fn sign_then_verify_round_trips() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (priv_path, pub_path) = write_test_key(dir.path());
        let evidence_path = write_test_evidence(
            dir.path(),
            r#"{"host":"bastion","timestamp":"2026-05-14T00:00:00Z","controls":[]}"#,
        );

        let sk = load_signing_key(&priv_path).expect("load priv");
        let sig = sign_evidence(&evidence_path, &sk).expect("sign");

        let vk = load_verifying_key(&pub_path).expect("load pub");
        verify_evidence(&evidence_path, &sig, &vk).expect("verify");
    }

    #[test]
    fn verify_fails_when_evidence_tampered() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (priv_path, pub_path) = write_test_key(dir.path());
        let evidence_path = write_test_evidence(
            dir.path(),
            r#"{"host":"bastion","timestamp":"2026-05-14T00:00:00Z","controls":[]}"#,
        );

        let sk = load_signing_key(&priv_path).expect("load priv");
        let sig = sign_evidence(&evidence_path, &sk).expect("sign");

        // Replace evidence with semantically-different content
        fs::write(
            &evidence_path,
            r#"{"host":"attacker","timestamp":"2026-05-14T00:00:00Z","controls":[]}"#,
        )
        .expect("rewrite evidence");

        let vk = load_verifying_key(&pub_path).expect("load pub");
        let err = verify_evidence(&evidence_path, &sig, &vk).unwrap_err();
        assert!(err.to_string().contains("verification failed"));
    }

    #[test]
    fn canonicalisation_is_key_order_insensitive() {
        let dir = tempfile::tempdir().expect("tempdir");
        let a = write_test_evidence(dir.path(), r#"{"a":1,"b":2}"#);
        let b_path = dir.path().join("b.json");
        fs::write(&b_path, r#"{"b":2,"a":1}"#).expect("write b");

        let canon_a = canonicalise(&a).expect("canon a");
        let canon_b = canonicalise(&b_path).expect("canon b");
        assert_eq!(canon_a, canon_b);
    }

    #[test]
    fn non_ed25519_private_key_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let bogus = dir.path().join("not_a_key");
        fs::write(&bogus, "not an openssh key").expect("write bogus");
        let err = load_signing_key(&bogus).unwrap_err();
        let chain: String = format!("{:?}", err);
        assert!(
            chain.contains("parse OpenSSH key") || chain.contains("ed25519"),
            "unexpected error: {}",
            chain
        );
    }
}
