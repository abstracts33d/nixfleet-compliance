//! nixfleet-compliance-verify -- offline-verify `evidence.json` against its
//! signature using the host's SSH ed25519 *public* key.
//!
//! The auditor's tool. Exit code:
//!   0 -- signature verifies; prints host, collected-at, pass/fail counts.
//!   1 -- usage error.
//!   2 -- verification failure.

use anyhow::{Context, Result};
use serde_json::Value;
use std::path::PathBuf;

fn print_usage_and_exit(code: i32) -> ! {
    eprintln!(
        "usage: nixfleet-compliance-verify \\
    --evidence <evidence.json> \\
    --signature <evidence.json.sig> \\
    --pubkey <ssh_host_ed25519_key.pub>

Verifies that <evidence.json> is signed by the operator of <pubkey>.
Reproduces the JCS canonicalisation (RFC 8785) and runs ed25519 verification.

Exits 0 on success, 2 on signature failure, 1 on usage error."
    );
    std::process::exit(code);
}

fn main() {
    if let Err(e) = run() {
        eprintln!("FAIL  {:#}", e);
        std::process::exit(2);
    }
}

fn run() -> Result<()> {
    let mut evidence: Option<PathBuf> = None;
    let mut sig_path: Option<PathBuf> = None;
    let mut pubkey: Option<PathBuf> = None;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--evidence" => evidence = Some(args.next().map(PathBuf::from).unwrap_or_else(|| print_usage_and_exit(1))),
            "--signature" => sig_path = Some(args.next().map(PathBuf::from).unwrap_or_else(|| print_usage_and_exit(1))),
            "--pubkey" => pubkey = Some(args.next().map(PathBuf::from).unwrap_or_else(|| print_usage_and_exit(1))),
            "-h" | "--help" => print_usage_and_exit(0),
            other => {
                eprintln!("unknown argument: {}", other);
                print_usage_and_exit(1);
            }
        }
    }

    let evidence = evidence.unwrap_or_else(|| print_usage_and_exit(1));
    let sig_path = sig_path.unwrap_or_else(|| print_usage_and_exit(1));
    let pubkey = pubkey.unwrap_or_else(|| print_usage_and_exit(1));

    let sig_b64 = std::fs::read_to_string(&sig_path)
        .with_context(|| format!("read {}", sig_path.display()))?;
    let verifying_key = nixfleet_compliance_tools::load_verifying_key(&pubkey)
        .context("load pubkey")?;

    nixfleet_compliance_tools::verify_evidence(&evidence, sig_b64.trim(), &verifying_key)
        .context("signature verification")?;

    // Pull out a few fields for a useful success summary.
    let raw = std::fs::read_to_string(&evidence)
        .with_context(|| format!("read {}", evidence.display()))?;
    let value: Value = serde_json::from_str(&raw).context("parse evidence.json")?;
    let host = value.get("host").and_then(Value::as_str).unwrap_or("?");
    let ts = value.get("timestamp").and_then(Value::as_str).unwrap_or("?");
    let controls = value
        .get("controls")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let total = controls.len();
    let compliant = controls
        .iter()
        .filter(|c| c.get("status").and_then(Value::as_str) == Some("compliant"))
        .count();
    let failed = controls
        .iter()
        .filter(|c| c.get("status").and_then(Value::as_str) == Some("non-compliant"))
        .count();
    let errors = controls
        .iter()
        .filter(|c| c.get("status").and_then(Value::as_str) == Some("error"))
        .count();

    println!("OK  signature verifies");
    println!("    host:       {}", host);
    println!("    collected:  {}", ts);
    println!(
        "    controls:   {} total -- {} compliant, {} non-compliant, {} error",
        total, compliant, failed, errors
    );
    Ok(())
}
