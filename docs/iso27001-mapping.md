# ISO 27001 Compliance Mapping

## Overview

This document maps ISO/IEC 27001:2022 Annex A controls to technical controls implemented
as NixOS modules. Covers 14 of 16 available controls mapped to Annex A (2022 numbering).

## Regulatory Reference

- **Standard:** ISO/IEC 27001:2022 - Information security, cybersecurity and privacy protection - Information security management systems - Requirements
- **Published:** October 2022
- **Official page:** <https://www.iso.org/standard/27001>
- **Annex A control reference:** <https://www.isms.online/iso-27001/annex-a/>

> **Note:** ISO 27001:2022 reorganized Annex A from 14 domains (A.5-A.18) in the 2013 version
> into 4 themes: Organizational (A.5), People (A.6), Physical (A.7), and Technological (A.8).
> All references below use the 2022 numbering.

## Annex A Mapping

| Annex A Control | Title | Control Module | Enforcement | Evidence |
|-----------------|-------|----------------|-------------|----------|
| A.5.9 | Inventory of information and other associated assets | `_asset-inventory` | Host, service, and network inventory from NixOS config | Hostname, NixOS version, interfaces, services |
| A.5.19, A.5.21 | Supplier relationships / ICT supply chain | `_supply-chain` | SBOM generation, flake.lock integrity, input provenance | SBOM status, package count, input freshness |
| A.5.24, A.5.26 | Incident management / Response to incidents | `_incident-response` | Alert rules, log retention, rollback readiness | Alert retention, rollback generations, last test |
| A.5.29, A.5.30 | Information security during disruption / ICT readiness | `_disaster-recovery` | Minimum generations, RTO targets, recovery testing | Generations kept, RTO target, last recovery test |
| A.8.2, A.8.3 | Privileged access rights / Information access restriction | `_access-control` | SSH key-only auth, root login disabled, idle timeout | Auth method, privileged users, SSH keys |
| A.8.5 | Secure authentication | `_authentication` | PAM MFA, SSH certificates, service accounts | MFA status, cert authority, service account inventory |
| A.8.8 | Management of technical vulnerabilities | `_vulnerability-mgmt` | CVE scanning, nixpkgs staleness, deployment gates | CVE results, nixpkgs age, blockOnCritical |
| A.8.9, A.8.8 | Configuration management / Technical vulnerabilities | `_baseline-hardening` | Kernel hardening, sysctl, service blocklist | Hardening score, deviation list |
| A.8.13 | Information backup | `_backup-retention` | Retention policy, restore testing schedule | Backup age, restore test status, retention compliance |
| A.8.15, A.8.16 | Logging / Monitoring activities | `_audit-logging` | Journal retention, auditd config | Retention days, auditd status |
| A.8.20, A.8.24 | Networks security / Use of cryptography | `_encryption-in-transit` | TLS version enforcement, cert expiry monitoring | Min TLS version, cert expiry days, certs expiring |
| A.8.24 | Use of cryptography | `_encryption-at-rest` | LUKS verification, encrypted swap, tmpfs on /tmp | Partition encryption, swap status, /tmp mount |
| A.8.24 | Use of cryptography (key management) | `_key-management` | Key rotation policy, key storage, key inventory | Rotation status, storage encryption, key count |
| A.8.32 | Change management | `_change-management` | Configuration tracking, rollback readiness | Config audit, rollback capability, change log |

## Certification Scope Differentiation

The `certificationScope` option adjusts strictness. "Full" targets formal certification evidence; "partial" is a pre-certification posture.

| Parameter | Full | Partial |
|-----------|------|---------|
| Evidence collection | Hourly (continuous) | Daily |
| SSH idle timeout | 15 minutes | 30 minutes |
| MFA required | Yes | No |
| Backup retention | 730 days | 365 days |
| Backup verification | Daily | Weekly |
| Log retention | 730 days | 365 days |
| System age limit | 14 days | 30 days |
| Key rotation | 365 days | 730 days |
| Input staleness | 14 days | 30 days |
| DR generations | 10 | 5 |
| RTO target | 4 hours | 24 hours |
| DR testing | Monthly | Quarterly |
| Rollback testing | Weekly | Monthly |
| Baseline hardening | strict | standard |
| CVE scanning | Daily | Weekly |
| Cert expiry warning | 30 days | 60 days |
| Block on critical CVE | Yes | No |

## Usage

```nix
modules = [
  compliance.nixosModules.iso27001
  {
    compliance.frameworks.iso27001 = {
      enable = true;
      certificationScope = "full";  # or "partial" (default)
    };
  }
];
```

## NixOS Advantages for ISO 27001

### A.5.19/A.5.21 - Supplier Relationships / ICT Supply Chain

The Nix closure is a complete, cryptographically verifiable software bill of materials.
`flake.lock` pins every input to a specific git commit. SBOM generation covers the entire
dependency tree - there are no untracked dependencies.

### A.8.32 - Change Management

Every NixOS generation is an immutable, traceable configuration state. `nvd diff` produces
a human-readable diff between generations. Rollback to any previous generation is instant
via `nixos-rebuild switch --rollback` or boot menu selection.

### A.8.24 - Use of Cryptography

The `_encryption-at-rest` control verifies LUKS at the block device level, not just configuration.
The probe reads `/proc/crypto` and `lsblk` to produce evidence that matches the physical state,
not just the declared intent.

### A.5.9 - Inventory of Information and Other Associated Assets

NixOS configurations declare the complete system state. The `_asset-inventory` probe enumerates
running services, network interfaces, and packages from the live system and compares against
the declared configuration. Undeclared services are flagged.
