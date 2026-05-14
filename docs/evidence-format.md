# Evidence format

Every probe output is a JSON record signed by the host key, written to `/var/lib/nixfleet-compliance/evidence.json`. This page documents the format, the signing discipline, and how to verify the evidence chain offline.

## Format

```json
{
  "host": "water-plant-01",
  "timestamp": "2026-04-05T10:00:00Z",
  "controls": [
    {
      "control": "baseline-hardening",
      "status": "compliant",
      "framework_articles": {
        "nis2":     ["21(a)", "21(g)"],
        "iso27001": ["A.8.9", "A.8.8"]
      },
      "checks": {
        "BH-03": {"compliant": true, "checks_passed": 5,  "checks_total": 5},
        "BH-06": {"compliant": true, "checks_passed": 20, "checks_total": 20}
      }
    }
  ],
  "overall": "16/16 controls compliant"
}
```

Each control entry carries:

- `control` - slug identifying the control (matches the module name).
- `status` - `compliant` | `non-compliant` | `error`.
- `framework_articles` - the regulatory anchors each framework preset maps this control to. The auditor's hook.
- `checks` - per-rule breakdown of the control's predicates / probes.

## JCS canonicalisation

Outputs are canonicalised at the producer using JCS (RFC 8785): sorted keys, compact form, no trailing newline. In shell terms: `jq -cSj`.

Canonicalisation matters because the signature attests to a specific byte sequence. Two semantically equivalent JSON documents (different key order, different whitespace) produce different signatures; the auditor verifying a signed file must reproduce the exact byte sequence the signer signed. JCS removes that ambiguity by defining a single canonical form.

## Signing

Each evidence record is signed with the host's signing key (separate from any control-plane keys). The signature wraps the JCS-canonicalised payload. The control plane verifies signatures before counting an event toward the gate, so a compromised mTLS cert cannot forge a passing report - the agent's mTLS posture is independent of the evidence-signing key.

Signature status (`ok` / `mismatch` / `malformed`) is part of the gate predicate. A `mismatch` is treated identically to a `non-compliant` status: the wave is blocked, rollback triggers, the operator investigates.

## Verifying offline

An auditor handed a hostname, a date range, and the host's public signing key can verify the evidence chain entirely offline:

```sh
# Read the file
cat /var/lib/nixfleet-compliance/evidence.json

# Re-canonicalise the payload
jq -cSj '.payload' < evidence.json > payload.jcs

# Verify the signature against the host pubkey
openssl dgst -sha256 -verify host.pub -signature evidence.sig payload.jcs
```

The auditor does not need to trust the control plane, the operator, or NixFleet itself. The signature binds the evidence to the host key; the host key binds to a hardware anchor in v0.3 (see [RFC-0004 in nixfleet](https://github.com/arcanesys/nixfleet/blob/main/docs/rfcs/0004-hardware-rooted-trust.md)). The chain is auditor-verifiable from the public side alone.

## Integration with NixFleet

When integrated with NixFleet (the orchestration framework), every `ReportEvent` carrying probe output - `ComplianceFailure`, `RuntimeGateError`, activation evidence variants - is signed at the host and signature-verified at the control plane before counting toward gate decisions. The control plane never forges or aggregates compliance signatures; it routes signed events from agents.

This separation is what makes "compliance proof" structurally different from "compliance assertion": the proof is a property of the host that the control plane only routes, never produces. Compromise the control plane and you delay the audit chain - you cannot fake it.
