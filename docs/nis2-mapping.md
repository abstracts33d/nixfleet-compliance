# NIS2 Compliance Mapping — NixFleet Compliance Framework

## Overview

This document maps NIS2 Directive (2022/2555) Article 21 requirements to technical controls
implemented as NixOS modules. Each control enforces a measure at the infrastructure layer
and produces machine-readable evidence of compliance.

## Article 21 — Cybersecurity Risk-Management Measures

| Article | Requirement | Control Module | Enforcement | Evidence |
|---------|------------|----------------|-------------|----------|
| 21(a) | Risk analysis, IS security policy | `_baseline-hardening` (Phase 2) | Kernel hardening, sysctl, service blocklist, filesystem permissions | Hardening score, deviation list |
| 21(b) | Incident handling | `_incident-response` (Phase 3) | Alert rules, log retention, rollback readiness | Alert status, rollback generations, last test |
| 21(c) | Business continuity, backup, DR | `_backup-retention` + `_disaster-recovery` (Phase 2-3) | Retention policy, restore testing, RTO measurement | Backup status, retention compliance, RTO metrics |
| 21(d) | **Supply chain security** | **`_supply-chain` (Phase 1)** | **Flake.lock pinning, SBOM generation, reproducibility attestation** | **Complete SBOM, build hash, input provenance** |
| 21(e) | Vulnerability handling | `_vulnerability-mgmt` (Phase 3) | CVE scanning, patch staleness, deployment gates | CVE results, nixpkgs age, time-to-patch |
| 21(f) | Effectiveness assessment | Built into evidence layer | Every control self-reports via probes | Per-control status, framework compliance % |
| 21(g) | Cyber hygiene | `_baseline-hardening` (Phase 2) | Password policy, session timeout, login banner | Included in hardening score |
| 21(h) | **Cryptography/encryption** | **`_encryption-at-rest` (Phase 1)** + `_encryption-in-transit` (Phase 2) | **LUKS verification, swap encryption, tmpfs** + TLS enforcement, cert monitoring | **Partition encryption status, swap status** + TLS config |
| 21(i) | **Access control, asset mgmt** | **`_access-control` + `_asset-inventory` (Phase 1)** | **SSH key-only, root disabled, sudo restrictions** + host/service/network inventory | **Auth method, privileged users, SSH keys** + complete host inventory |
| 21(j) | MFA, secure comms | `_authentication` (Phase 3) | PAM MFA, SSH certificates, service accounts | MFA status, cert authority, service account inventory |

**Bold** = Phase 1 (available now). All others in development roadmap.

## The NixOS Advantage

### Art. 21(d) — Supply Chain (headline capability)

Traditional infrastructure tools manage state but cannot *prove* it. NixOS is uniquely positioned:

- **Declarative**: The flake defines the entire system — every package, every service, every dependency
- **Immutable**: Built artifacts are read-only in `/nix/store`, content-addressed by hash
- **Deterministic**: Same inputs produce same outputs — builds are reproducible
- **Auditable**: `nix path-info --json --recursive` produces a complete dependency graph

This enables:
- **Cryptographic proof of supply chain**: every artifact has a known hash, traceable to source
- **Software Bill of Materials (SBOM)**: generated from the Nix closure, exhaustive
- **Reproducibility attestation**: build twice, compare hashes — mathematical proof
- **Input provenance**: flake.lock pins every input to a specific git commit

No other infrastructure framework can produce this level of supply chain evidence.

### Art. 21(i) — Asset Inventory

The NixOS flake IS the asset inventory:
- `nix flake show` lists every host
- Each host's configuration declares its exact service set
- Network interfaces, systemd services, and packages are all declared
- There is no shadow IT — if it's not in the flake, it doesn't exist

### General

- **Configuration IS policy**: An auditor can read the Nix expression and know exactly what's enforced
- **Rollback is native**: `nixos-rebuild switch --rollback` provides instant disaster recovery
- **No drift**: The running system matches the declared configuration — always

## Evidence Format

Each control produces evidence as JSON:

```json
{
  "host": "water-plant-01",
  "timestamp": "2026-04-05T10:00:00Z",
  "controls": [
    {
      "control": "supply-chain",
      "status": "compliant",
      "framework_articles": {"nis2": ["21(d)"]},
      "checks": {
        "has_configuration_revision": true,
        "sbom_generated": true,
        "closure_package_count": 847,
        "inputs_fresh": true
      }
    }
  ],
  "overall": "4/4 controls compliant"
}
```

## Entity Type Differentiation

NIS2 distinguishes essential and important entities with different strictness:

| Parameter | Essential | Important |
|-----------|-----------|-----------|
| Evidence collection | Hourly (continuous) | Daily |
| SSH idle timeout | 15 minutes | 30 minutes |
| Input staleness warning | 14 days | 30 days |
| Backup retention (Phase 2) | 730 days | 365 days |
| Rollback testing (Phase 3) | Weekly | Monthly |
| CVE scan (Phase 3) | Daily | Weekly |
| MFA required (Phase 3) | Yes | Optional |
