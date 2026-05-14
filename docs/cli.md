# compliance-check CLI

A small CLI for reading and re-running compliance evidence on a host. Installed automatically when the module is enabled; no additional setup needed.

## Subcommands

| Command | Who can run it | What it does |
|---|---|---|
| `compliance-check` | any user | Reads persisted `/var/lib/nixfleet-compliance/evidence.json`, prints a coloured pass/fail table, warns if the evidence is stale (>2h by default). |
| `compliance-check --live` | root | Re-executes runtime probes inline, prints the live result. Does not write evidence; for that, run `systemctl start compliance-evidence-collector`. |
| `compliance-check --help` | any user | Usage + environment info. |

## Output

```
$ compliance-check
NixFleet Compliance Check
=========================
Host: water-plant-01
Date: 2026-04-17T14:30:00+00:00

  PASS  baselineHardening          (nis2, anssi, iso27001)
  PASS  auditLogging               (nis2, anssi, iso27001)
  PASS  accessControl              (nis2, iso27001, dora)
  FAIL  encryptionAtRest           (nis2, iso27001)

Total: 16  Pass: 15  Fail: 1
```

The right-column tags show which framework presets each control is mapped to - the same mapping that lands in the `framework_articles` field of the signed evidence record. See [evidence-format](evidence-format.md) for the on-disk shape.

## Environment

| Variable | Default | Effect |
|---|---|---|
| `VERBOSE` | unset | When `1`, print the full `checks` body for every FAIL - the per-rule breakdown the gate uses to decide. |

## Common workflows

- **"Is this host compliant right now?"** -> `compliance-check`. Reads the latest collected evidence (typically <1h old on essential entities, <24h on important).
- **"Has it drifted since the last collection?"** -> `sudo compliance-check --live`. Re-runs all probes inline. Slower (executes every probe) but reflects current state, not collected state.
- **"What's actually failing?"** -> `VERBOSE=1 compliance-check`. Prints the full check-level breakdown for every FAIL.
- **"Refresh the evidence file now"** -> `sudo systemctl start compliance-evidence-collector`. The collector runs hourly (essential) / daily (important) by default; manual start runs it immediately.

## Operator hygiene

`compliance-check` is the daily diagnostic. The evidence file it reads is the same file the auditor will be handed. Discrepancies between the CLI output and what the auditor expects to see are almost always either:

- The CLI was run on an outdated evidence file (check the timestamp printed in the header).
- `--live` and persisted evidence diverge - i.e. drift between collection runs.

If `--live` consistently differs from persisted evidence, the collector schedule is too sparse for your drift rate - increase frequency in `compliance.governance` or investigate why drift is happening between collections.
