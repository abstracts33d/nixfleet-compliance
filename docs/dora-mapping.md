# DORA Compliance Mapping

## Overview

This document maps DORA (Digital Operational Resilience Act - Regulation 2022/2554) requirements
to technical controls implemented as NixOS modules. DORA applies to financial entities: credit
institutions, investment firms, insurance, payment services, and crypto-asset service providers.

## Regulatory Reference

- **Regulation:** Regulation (EU) 2022/2554 of the European Parliament and of the Council of 14 December 2022 on digital operational resilience for the financial sector (DORA)
- **Published:** 27 December 2022 (Official Journal of the European Union, L 333)
- **Full text (EUR-Lex):** <https://eur-lex.europa.eu/eli/reg/2022/2554/oj>
- **Application date:** 17 January 2025

## Article Mapping

| Article | Requirement | Control Module | Enforcement | Evidence |
|---------|------------|----------------|-------------|----------|
| Art. 8 | ICT asset management | `_asset-inventory` | Host, service, and network inventory from NixOS config | Hostname, NixOS version, interfaces, services, service count |
| Art. 8 | Change and patch management | `_change-management` | Configuration tracking, rollback readiness, system age | Config audit status, rollback capability, change log |
| Art. 8 | Vulnerability and patch management | `_vulnerability-mgmt` | CVE scanning, nixpkgs staleness, deployment gates | CVE results, nixpkgs age, time-to-patch, blockOnCritical |
| Art. 9 | ICT access control | `_access-control` | SSH key-only auth, root login disabled, idle timeout | Auth method, privileged users, SSH key inventory |
| Art. 9 | Authentication | `_authentication` | PAM MFA, SSH certificates, service accounts | MFA status, cert authority, service account inventory |
| Art. 9 | Network segmentation | `_network-segmentation` | Firewall status, VLAN/bridge interfaces | Firewall enabled, VLAN/bridge count, rules count |
| Art. 12 | Backup and recovery | `_backup-retention` | Retention policy, restore testing schedule | Backup age, restore test status, retention compliance |
| Art. 12 | Business continuity and DR | `_disaster-recovery` | Minimum generations, RTO targets, recovery testing | Generations kept, RTO target, last recovery test |
| Art. 17 | ICT incident management | `_incident-response` | Alert rules, log retention, rollback readiness | Alert retention, rollback generations, last test |

## Critical Provider Differentiation

DORA Art. 31 designates certain ICT third-party service providers as "critical". Critical providers face enhanced oversight from a lead overseer.

| Parameter | Critical Provider | Standard |
|-----------|-------------------|----------|
| Evidence collection | Hourly (continuous) | Daily |
| SSH idle timeout | 15 minutes | 30 minutes |
| MFA required | Yes | No |
| Backup retention | 730 days | 365 days |
| Backup verification | Daily | Weekly |
| System age limit | 14 days | 30 days |
| DR generations | 10 | 5 |
| RTO target | 4 hours | 24 hours |
| DR testing | Monthly | Quarterly |
| Rollback testing | Weekly | Monthly |
| CVE scanning | Daily | Weekly |
| Nixpkgs staleness | 14 days | 30 days |
| Block on critical CVE | Yes | No |

## Usage

```nix
modules = [
  compliance.nixosModules.dora
  {
    compliance.frameworks.dora = {
      enable = true;
      criticalProvider = true;  # or false (default)
    };
  }
];
```

## NixOS Advantages for DORA

### Art. 8 - ICT Asset Management

NixOS flakes provide a complete, declarative asset inventory. Every host, service, and package
is enumerated in the configuration. There is no shadow IT - if it's not declared, it doesn't run.

### Art. 12 - Business Continuity

NixOS generations provide instant rollback. Each generation is a complete, bootable system snapshot.
The `_disaster-recovery` control verifies that enough generations are retained and that recovery
has been tested within the required interval.

### Art. 8 - Change Management

Every configuration change produces a new generation with a traceable link to the Nix expression
that produced it. `nix flake metadata` shows the exact git commit, and `nvd diff` shows the
package-level diff between generations.
