# nixfleet-compliance

Regulatory compliance controls for NixOS infrastructure. MIT licensed.

## Structure

```
controls/       # NixOS modules — each enforces a technical measure + produces evidence
evidence/       # Evidence collection layer — probes, collector, schema
frameworks/     # Regulatory framework presets — NIS2, DORA, ISO 27001 (future)
lib/            # Helpers — mkProbe
tests/          # Eval + VM tests
docs/           # Compliance mapping docs (ANSSI attachments)
```

## Commands

```sh
nix develop                        # dev shell (alejandra, jq)
nix fmt                            # format all Nix files
nix flake check --no-build         # eval tests (instant)
```

## Architecture

- **Controls** are self-activating NixOS modules (`lib.mkIf cfg.enable`).
- Each control has two jobs: ENFORCE (NixOS config) and PROVE (evidence probe).
- **Framework modules** (e.g., nis2.nix) are policy presets that activate controls with framework-specific defaults.
- **Evidence collector** runs probes on a timer, aggregates into `/var/lib/nixfleet-compliance/evidence.json`.
- Controls are standalone NixOS modules — they read standard NixOS options, no build-time dependency on nixfleet.

## Consuming

```nix
# In a fleet repo's flake.nix:
inputs.compliance.url = "github:your-org/nixfleet-compliance";

# In mkHost or nixosSystem:
modules = [
  compliance.nixosModules.nis2
  { compliance.frameworks.nis2.enable = true; }
];
```

## Conventions

- Controls are `_`-prefixed (same pattern as nixfleet scopes)
- Evidence probes produce JSON to stdout
- Options live under `compliance.controls.<name>` and `compliance.frameworks.<name>`
- Evidence options live under `compliance.evidence`
