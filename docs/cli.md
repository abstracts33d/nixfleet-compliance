# Compliance CLIs

Two binaries ship with the module. Both are installed when `compliance.check.enable = true`.

| Binary | Purpose | Who runs it |
|--------|---------|-------------|
| `compliance-check` | Read evidence locally; render pass/fail table; verify signature when sig + pubkey are present | Operator, daily |
| `nixfleet-compliance-verify` | Offline-verify the evidence chain from `evidence.json` + `evidence.json.sig` + `evidence.host.pub` | Auditor; also called internally by `compliance-check` |

## `compliance-check`

| Command | Who can run it | What it does |
|---|---|---|
| `compliance-check` | any user | Reads persisted `/var/lib/nixfleet-compliance/evidence.json`, prints a coloured pass/fail table, warns if the evidence is stale (>2h by default), runs signature verification if `evidence.json.sig` + `evidence.host.pub` are present. |
| `compliance-check --live` | root | Re-executes runtime probes inline, prints the live result. Does not write evidence (and therefore does not sign); for that, run `systemctl start compliance-evidence-collector`. |
| `compliance-check --help` | any user | Usage + environment info. |

### Output

```
$ compliance-check
NixFleet Compliance Check
=========================
Host: water-plant-01
Evidence collected: 2026-04-17T14:30:00+00:00 (0h27m ago)
Signature: OK (verified against /var/lib/nixfleet-compliance/evidence.host.pub)

  PASS  baselineHardening          (nis2, anssi, iso27001)
  PASS  auditLogging               (nis2, anssi, iso27001)
  PASS  accessControl              (nis2, iso27001, dora)
  FAIL  encryptionAtRest           (nis2, iso27001)

─────────────────────────────────
Total: 16  Pass: 15  Fail: 1
```

Signature line is one of:

- `Signature: OK (verified against <pubkey path>)` - the chain is valid.
- `Signature: FAIL -- <details>` - the chain is broken. The trailing line explicitly warns the operator not to hand the evidence to an auditor.
- `Signature: not verified (evidence.json.sig or evidence.host.pub absent)` - signing was disabled or failed; the JSON is still useful for operations, but the auditor chain is unavailable for this collection.

### Environment

| Variable | Default | Effect |
|---|---|---|
| `VERBOSE` | unset | When `1`, print the full `checks` body for every FAIL - the per-rule breakdown the gate uses to decide. |

## `nixfleet-compliance-verify`

The auditor's tool. Takes the three published files and runs ed25519 verification against the JCS-canonical bytes (RFC 8785). No NixOS dependency; can be run from any system with the binary on PATH.

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
    collected:  2026-04-17T14:30:00+00:00
    controls:   16 total -- 15 compliant, 1 non-compliant, 0 error
```

Exit codes:

- `0` - signature verifies.
- `1` - usage error (missing argument, unknown flag).
- `2` - verification failure (corrupt signature, tampered evidence, wrong pubkey).

The auditor's verification bundle is a directory containing exactly these three files. The hostname appears in `evidence.json`; the pubkey can be independently cross-checked against the host via `ssh-keyscan -t ed25519 <hostname>`. No CP access required.

See [evidence-format](evidence-format.md) for the on-disk shape and the cryptographic discipline. See [governance](governance.md) for how `enforce`-mode channels turn signature failures into rollout-blocking events (integrated with the `nixfleet` agent).

## Common workflows

- **"Is this host compliant right now?"** -> `compliance-check`. Reads the latest collected evidence (typically <1h old on essential entities, <24h on important).
- **"Has it drifted since the last collection?"** -> `sudo compliance-check --live`. Re-runs all probes inline. Slower (executes every probe) but reflects current state, not collected state. Note: `--live` does not sign - the signature only lives on the persisted file.
- **"What's actually failing?"** -> `VERBOSE=1 compliance-check`. Prints the full check-level breakdown for every FAIL.
- **"Refresh the evidence file now"** -> `sudo systemctl start compliance-evidence-collector`. The collector runs hourly (essential) / daily (important) by default; manual start runs it immediately. A successful manual start also re-signs the new file.
- **"Hand evidence to an auditor"** -> copy `/var/lib/nixfleet-compliance/{evidence.json,evidence.json.sig,evidence.host.pub}` and tell the auditor to run `nixfleet-compliance-verify` (or replicate the recipe in their own tooling).

## Operator hygiene

`compliance-check` is the daily diagnostic. The evidence file it reads is the same file the auditor will be handed. Discrepancies between the CLI output and what the auditor expects to see are almost always either:

- The CLI was run on an outdated evidence file (check the timestamp printed in the header).
- `--live` and persisted evidence diverge - i.e. drift between collection runs.
- A signature failure was ignored - `compliance-check` is loud about this; don't ship evidence with a failed signature.

If `--live` consistently differs from persisted evidence, the collector schedule is too sparse for your drift rate - increase frequency in `compliance.governance` or investigate why drift is happening between collections.
