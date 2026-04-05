# NixFleet Compliance

Regulatory compliance controls for NixOS infrastructure. Enforce security measures and produce cryptographic evidence — all as declarative NixOS modules.

## What is this?

NixFleet Compliance provides:
- **Technical controls** as NixOS modules — enforce security at the infrastructure layer
- **Evidence probes** — each control proves it is active with machine-readable JSON
- **Framework presets** — enable NIS2 (or DORA, ISO 27001, ...) with one line

## Quick Start

```nix
# flake.nix
{
  inputs.compliance.url = "github:your-org/nixfleet-compliance";

  outputs = {compliance, ...}: {
    nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
      modules = [
        compliance.nixosModules.nis2
        {
          compliance.frameworks.nis2 = {
            enable = true;
            entityType = "essential";  # or "important"
          };
        }
      ];
    };
  };
}
```

This enables all Phase 1 controls with NIS2-appropriate defaults:
- **Supply chain** — SBOM generation, flake.lock integrity, reproducibility attestation
- **Asset inventory** — host, service, and network inventory from NixOS config
- **Encryption at rest** — LUKS verification, encrypted swap, tmpfs on /tmp
- **Access control** — SSH key-only auth, root login disabled, idle timeout

Evidence is collected hourly (essential) or daily (important) and written to `/var/lib/nixfleet-compliance/evidence.json`.

## Individual Controls

Don't want a full framework? Pick specific controls:

```nix
modules = [
  compliance.nixosModules.controls.supply-chain
  compliance.nixosModules.controls.access-control
  {
    compliance.controls.supplyChain.enable = true;
    compliance.controls.accessControl = {
      enable = true;
      idleTimeoutMinutes = 15;
    };
  }
];
```

## Evidence

Each control produces evidence proving compliance:

```json
{
  "host": "water-plant-01",
  "timestamp": "2026-04-05T10:00:00Z",
  "controls": [
    {
      "control": "supply-chain",
      "status": "compliant",
      "checks": {
        "sbom_generated": true,
        "closure_package_count": 847,
        "inputs_fresh": true
      }
    }
  ],
  "overall": "4/4 controls compliant"
}
```

## Frameworks

| Framework | Status | Controls |
|-----------|--------|----------|
| NIS2 | Phase 1 (4 controls) | supply-chain, asset-inventory, encryption-at-rest, access-control |
| DORA | Planned | — |
| ISO 27001 | Planned | — |
| HDS | Planned | — |
| SecNumCloud | Planned | — |

## Works With

- **NixFleet** — designed to complement nixfleet's mkHost and scopes
- **Vanilla NixOS** — works on any NixOS system (no nixfleet dependency required)
- **nixos-anywhere** — deploy compliance-enabled hosts from scratch

## License

MIT. See [LICENSE](LICENSE).
