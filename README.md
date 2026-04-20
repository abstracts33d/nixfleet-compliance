# NixFleet Compliance

[![CI](https://github.com/arcanesys/nixfleet-compliance/actions/workflows/ci.yml/badge.svg)](https://github.com/arcanesys/nixfleet-compliance/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE-MIT)
[![v0.1.0](https://img.shields.io/github/v/tag/arcanesys/nixfleet-compliance?label=version)](https://github.com/arcanesys/nixfleet-compliance/releases/tag/v0.1.0)

Regulatory compliance controls for NixOS infrastructure. Enforce security measures and produce cryptographic evidence - all as declarative NixOS modules.

Works with [NixFleet](https://github.com/arcanesys/nixfleet) or standalone on any NixOS system.

## Quick Start

```nix
# flake.nix
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    compliance.url = "github:arcanesys/nixfleet-compliance";
  };

  outputs = {nixpkgs, compliance, ...}: {
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

This enables all 12 NIS2 controls with appropriate defaults:
- **Baseline hardening** - 10 rules ported from ANSSI R7-R14 (IOMMU, kernel sysctls, IPv4/IPv6, filesystem)
- **Audit logging** - journald persistence + auditd with execve tracking (ANSSI R33)
- **Supply chain** - SBOM generation, flake.lock integrity, reproducibility attestation
- **Asset inventory** - host, service, and network inventory from NixOS config
- **Encryption** - LUKS verification, encrypted swap, TLS certificate inventory
- **Access control** - SSH key-only auth, root login disabled, idle timeout
- **And more** - backup retention, incident response, disaster recovery, vulnerability management, authentication, encryption in transit

Evidence is collected hourly (essential) or daily (important) and written to `/var/lib/nixfleet-compliance/evidence.json`.

## What's Included

- **16 technical controls** as NixOS modules (access control, encryption, audit logging, supply chain, baseline hardening, backup, incident response, disaster recovery, and more)
- **4 framework presets** that activate the right controls with appropriate defaults
- **Evidence probes** - each control generates JSON compliance proof collected hourly or daily
- **Governance engine** - fleet-wide enforcement levels, host-type scoping, per-rule exceptions with mandatory rationale
- **`compliance-check` CLI** - run all probes and get colored pass/fail output per control

## Supported Frameworks

| Framework | Controls | Scope | Regulatory context |
|-----------|----------|-------|--------------------|
| **NIS2** | 12 | EU critical infrastructure | Directive 2022/2555 - covers essential and important entities with tiered audit schedules |
| **DORA** | 9 | Financial sector | Regulation 2022/2554 - ICT risk management for credit institutions, investment firms, crypto-asset providers |
| **ISO 27001** | 14 | Cross-sector certification | ISO/IEC 27001:2022 Annex A - full and partial certification scope |
| **ANSSI BP-028** | 7 | French hardening | BP-028 v2.0 (Feb 2024) - 4 levels (minimal/intermediary/reinforced/high), 3 categories (base/client/server) |

Each framework preset sets governance defaults appropriate to the entity type or level. For example, NIS2 essential entities get hourly audits, 15-minute idle timeout, and MFA required, while important entities get daily audits with relaxed thresholds.

## Individual Controls

Don't need a full framework? Pick specific controls:

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

## Governance

Fleet-wide policy knobs that all controls respect:

```nix
compliance.governance = {
  enforceMode = "enforce";  # or "report" (probes only, no config changes)
  level = "strict";          # minimal | standard | strict | paranoid
  hostType = "server";       # server | workstation | appliance
  exceptions."BH-07".rationale = "IPv6 required for internal mesh";
};
```

## CLI

Run `compliance-check` on any compliant host:

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

Run with `VERBOSE=1` for detailed JSON output per control.

## Evidence

Each control produces evidence proving compliance:

```json
{
  "host": "water-plant-01",
  "timestamp": "2026-04-05T10:00:00Z",
  "controls": [
    {
      "control": "baseline-hardening",
      "status": "compliant",
      "framework_articles": {
        "nis2": ["21(a)", "21(g)"],
        "iso27001": ["A.8.9", "A.8.8"]
      },
      "checks": {
        "BH-03": {"compliant": true, "checks_passed": 5, "checks_total": 5},
        "BH-06": {"compliant": true, "checks_passed": 19, "checks_total": 19}
      }
    }
  ],
  "overall": "16/16 controls compliant"
}
```

## Framework Mappings

Detailed article-by-article regulatory mappings are in the [docs/](docs/) directory:

- [NIS2 Article 21 mapping](docs/nis2-mapping.md) - 10 sub-articles mapped to controls
- [ISO 27001 Annex A mapping](docs/iso27001-mapping.md) - 14 Annex A controls covered
- [DORA Chapter III mapping](docs/dora-mapping.md) - Articles 8, 9, 12, 17 mapped to controls
- [ANSSI BP-028 mapping](docs/anssi-mapping.md) - R7-R14 hardening rules + additional controls

## Documentation

Full documentation (architecture, control reference, governance, evidence layer) is available at [arcanesys.github.io/nixfleet](https://arcanesys.github.io/nixfleet).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT. See [LICENSE-MIT](LICENSE-MIT).
