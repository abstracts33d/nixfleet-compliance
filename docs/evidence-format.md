# Evidence format

The evidence collector writes three files to `/var/lib/nixfleet-compliance/`:

| File | What it is |
|------|------------|
| `evidence.json` | JSON record: host, timestamp, per-control status, framework articles, per-rule checks |
| `evidence.json.sig` | base64 ed25519 signature over the JCS-canonical bytes of `evidence.json` (RFC 8785) |
| `evidence.host.pub` | OpenSSH-format ed25519 public key - the key the auditor verifies against |

An auditor with `evidence.host.pub` can verify the chain offline using `nixfleet-compliance-verify` (ships with the module). No network access, no control plane, no trust in the operator.

## Format

`evidence.json` is the canonical wire artifact. **This document is the authoritative spec**; emitters (`probe-runner.sh`) and consumers (this repo's `compliance-check` + `nixfleet-compliance-verify`, the `nixfleet-agent` evidence probe runner) all conform. The fixture at [`evidence-format-fixture.json`](./evidence-format-fixture.json) is a hand-crafted reference instance exercising every field; consumer round-trip tests reference it.

```json
{
  "schemaVersion": 1,
  "hostname": "water-plant-01",
  "collectedAt": "2026-04-05T10:00:00Z",
  "controls": [
    {
      "controlId": "baseline-hardening",
      "passed": true,
      "frameworkArticles": {
        "nis2":     ["21(a)", "21(g)"],
        "iso27001": ["A.8.9", "A.8.8"]
      },
      "details": {
        "BH-03": {"compliant": true, "checks_passed": 5,  "checks_total": 5},
        "BH-06": {"compliant": true, "checks_passed": 20, "checks_total": 20}
      },
      "schema": "anssi-bp028/v1"
    }
  ]
}
```

Top-level fields:

- `schemaVersion` (`u32`, required) — wire-format version. Bumped on field removal or semantic change; additive fields keep this constant. Current: `1`.
- `hostname` (`string`, required) — emitting host.
- `collectedAt` (RFC 3339 UTC, required) — collector run timestamp.
- `controls` (array, required) — one entry per evaluated control. Order is preserved by the producer; consumers MAY rely on stable ordering within a single collection but not across collections.

Per-control entry:

- `controlId` (`string`, required) — capability-named slug (e.g. `access-control`, `secure-boot`). Matches the `controlId` parameter of `lib/mkTypedControl.nix`. Stable across framework presets; one control maps to multiple framework articles.
- `passed` (`bool`, required) — control-level aggregate. `true` iff every check in `details` passed. Probe-runner errors set `passed: false` and the failure context lands in `details.error`.
- `frameworkArticles` (`object<string, string[]>`, optional, default `{}`) — framework → article-IDs map. Empty is legal (synthetic always-fail probe, framework-less smoke probe). One control typically covers multiple articles across multiple frameworks.
- `details` (`object`, optional) — free-form per-rule probe output. Operator/auditor-facing detail; consumers MUST NOT use this for gating decisions (the gate reads `passed`). Schema-aware tools may decode this per the `schema` hint.
- `schema` (`string`, optional) — typed-control schema hint, e.g. `"anssi-bp028/v1"`. Set when the producer used the typed-control pipeline (`lib/mkTypedControl.nix`). Auditor tools apply schema-specific decoders to `details`.

## Versioning policy

`schemaVersion` is the handshake. Additive changes (new optional fields) leave the version constant — emitters set the new field, consumers using `serde(default)` ignore it. Breaking changes (field removal, semantic change, type change) bump the version and require coordinated release of all consumers.

Standalone operators emit `schemaVersion: 1`. NixFleet consumers reject any other value with a clear migration error pointing at the producer.

The v0.2 retag supersedes the unreleased pre-v0.2.0 emit shape (`host`/`timestamp`/`status` enum string, no `schemaVersion` field). No production deployment ran the broken integration end-to-end; no migration path is preserved.

## JCS canonicalisation

The on-disk JSON is collector-formatted (pretty-printed, human-readable). The signature is not over the on-disk bytes directly - it is over the **JCS-canonical** form (RFC 8785: sorted keys, compact form, no trailing newline). The verifier re-canonicalises before checking.

Canonicalisation matters because the signature attests to a specific byte sequence. Two semantically equivalent JSON documents (different key order, different whitespace) produce different signatures; the auditor verifying a signed file must reproduce the exact byte sequence the signer signed. JCS removes that ambiguity by defining a single canonical form.

The same JCS implementation (the [`serde_jcs`](https://crates.io/crates/serde_jcs) Rust crate, RFC 8785-conformant) is used by `nixfleet-compliance-sign` and `nixfleet-compliance-verify`. The agent in `nixfleet` uses the same crate for its wire-payload signing.

## Signing

`nixfleet-compliance-sign` is invoked by the collector after `evidence.json` is written. It:

1. Reads `evidence.json`, parses as JSON.
2. JCS-canonicalises the parsed value.
3. Loads the OpenSSH ed25519 private key from `/etc/ssh/ssh_host_ed25519_key` (configurable via `compliance.evidence.sign.hostKeyPath`).
4. Signs the canonical bytes with ed25519 -> 64-byte signature.
5. base64-encodes the signature, writes a single line to `evidence.json.sig`.

The host SSH key is intentionally reused: every NixOS host already has one, the public half is already discoverable via `ssh-keyscan`, and the agent in `nixfleet` uses the same key for its over-the-wire compliance reports. One identity, two signatures (file + wire), one verification path.

Signing is best-effort: a missing or non-ed25519 host key logs a warning but does not fail the collector. In that case `evidence.json` is still written; only the auditor chain is unavailable for that collection.

## Verifying offline

The collector publishes the host pubkey alongside the evidence (default `compliance.evidence.sign.publishPubkey = true`), so a self-contained verification bundle is the three files: `evidence.json`, `evidence.json.sig`, `evidence.host.pub`.

```sh
nixfleet-compliance-verify \
  --evidence /var/lib/nixfleet-compliance/evidence.json \
  --signature /var/lib/nixfleet-compliance/evidence.json.sig \
  --pubkey /var/lib/nixfleet-compliance/evidence.host.pub
```

Output on success:

```
OK  signature verifies
    host:       water-plant-01
    collected:  2026-04-05T10:00:00Z
    controls:   16 total -- 15 compliant, 1 non-compliant, 0 error
```

Exit code 0 = signature verifies, 2 = verification failure, 1 = usage error.

The auditor does not need to trust the control plane, the operator, or NixFleet itself. The signature binds the evidence to the SSH host key; the public half is published next to the evidence and is also independently obtainable from the host (`ssh-keyscan -t ed25519 <hostname>`). The v0.3 trajectory anchors the SSH host key to a TPM measurement chain (see [RFC-0004 in nixfleet](https://github.com/arcanesys/nixfleet/blob/main/docs/rfcs/0004-hardware-rooted-trust.md)) - at which point the chain becomes hardware-rooted, not just software-rooted.

## Reproducing verification by hand

The verifier is small - about 100 lines of Rust around the `ed25519-dalek`, `ssh-key`, and `serde_jcs` crates. Anyone uncomfortable trusting the binary can reproduce the recipe directly:

```sh
# 1. Read + parse evidence.json
# 2. JCS-canonicalise per RFC 8785 (sorted keys, compact, no trailing whitespace)
# 3. ed25519-verify the result against the public half of /etc/ssh/ssh_host_ed25519_key
```

The signing binary's source is at [`tools/src/bin/sign.rs`](https://github.com/arcanesys/nixfleet-compliance/blob/main/tools/src/bin/sign.rs) and the verifier at [`tools/src/bin/verify.rs`](https://github.com/arcanesys/nixfleet-compliance/blob/main/tools/src/bin/verify.rs). Both use the shared library at [`tools/src/lib.rs`](https://github.com/arcanesys/nixfleet-compliance/blob/main/tools/src/lib.rs). Round-trip + tamper-detection are exercised by unit tests in the same lib and by the VM test at [`tests/vm-evidence.nix`](https://github.com/arcanesys/nixfleet-compliance/blob/main/tests/vm-evidence.nix).

## Integration with NixFleet

When `nixfleet-compliance` is paired with the `nixfleet` agent, the agent additionally signs bounded **wire-summary** payloads (`ComplianceFailureSignedPayload`, `RuntimeGateErrorSignedPayload`) and posts them to the control plane. The wire signing uses the **same** SSH host key as the on-disk signing, but signs different content: a bounded summary plus a SHA-256 of the relevant evidence snippet. The two signing paths coexist and the auditor benefits from both:

- **On-disk** (`evidence.json.sig`): proof the full file as collected on the host has not been tampered with.
- **Wire-summary** (stored in the CP's audit log): proof the host posted a specific summary at a specific time, with the snippet hash linking to the on-disk file.

The on-disk signature stands alone for standalone-mode operators (no fleet). The wire signature additionally gates rollout-wave promotion in the CP. They are independent failure modes; one being broken does not falsify the other.
