//! nixfleet-compliance-sign - sign `evidence.json` with the host's SSH ed25519 key.
//!
//! Called by the evidence collector after `probe-runner.sh` writes the JSON.
//! Produces `<evidence>.sig`: a single-line base64-encoded 64-byte ed25519
//! signature over the JCS-canonical bytes of the evidence.

use anyhow::{Context, Result};
use std::path::PathBuf;

fn print_usage_and_exit(code: i32) -> ! {
    eprintln!(
        "usage: nixfleet-compliance-sign \\
    --evidence <evidence.json> \\
    --host-key <ssh_host_ed25519_key> \\
    --out <evidence.json.sig>

Signs the JCS-canonical bytes of <evidence.json> using <ssh_host_ed25519_key>
and writes a base64-encoded 64-byte ed25519 signature to <out>."
    );
    std::process::exit(code);
}

fn main() -> Result<()> {
    let mut evidence: Option<PathBuf> = None;
    let mut host_key: Option<PathBuf> = None;
    let mut out: Option<PathBuf> = None;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--evidence" => evidence = Some(args.next().map(PathBuf::from).unwrap_or_else(|| print_usage_and_exit(2))),
            "--host-key" => host_key = Some(args.next().map(PathBuf::from).unwrap_or_else(|| print_usage_and_exit(2))),
            "--out" => out = Some(args.next().map(PathBuf::from).unwrap_or_else(|| print_usage_and_exit(2))),
            "-h" | "--help" => print_usage_and_exit(0),
            other => {
                eprintln!("unknown argument: {}", other);
                print_usage_and_exit(2);
            }
        }
    }

    let evidence = evidence.unwrap_or_else(|| print_usage_and_exit(2));
    let host_key = host_key.unwrap_or_else(|| {
        PathBuf::from(nixfleet_compliance_tools::DEFAULT_HOST_KEY)
    });
    let out = out.unwrap_or_else(|| print_usage_and_exit(2));

    let signing_key = nixfleet_compliance_tools::load_signing_key(&host_key)
        .context("load host signing key")?;
    let sig_b64 = nixfleet_compliance_tools::sign_evidence(&evidence, &signing_key)
        .context("sign evidence")?;

    // Single line + trailing newline. Easy to cat/inspect.
    std::fs::write(&out, format!("{}\n", sig_b64))
        .with_context(|| format!("write {}", out.display()))?;

    Ok(())
}
