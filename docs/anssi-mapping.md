# ANSSI Compliance Mapping

## Overview

This document maps ANSSI BP-028 v2.0 recommendations to technical controls implemented
as NixOS modules. The guide targets GNU/Linux system hardening across 4 compliance levels.

## Regulatory Reference

- **Guide:** Recommandations de sécurité relatives à un système GNU/Linux (ANSSI-BP-028 v2.0)
- **Published:** February 2024 (revision of the October 2022 edition)
- **Official page (FR):** <https://cyber.gouv.fr/publications/recommandations-de-securite-relatives-un-systeme-gnulinux>
- **Official page (EN):** <https://cyber.gouv.fr/en/publications/configuration-recommendations-gnulinux-system>

## Recommendation Mapping

| Recommendation | Title | Control Module | Enforcement | Evidence |
|----------------|-------|----------------|-------------|----------|
| R7 | Activating the IOMMU | `_baseline-hardening` (BH-01) | `iommu=force` kernel parameter | IOMMU presence in boot params |
| R8 | Configuring memory options | `_baseline-hardening` (BH-02) | L1TF, Meltdown, Spectre, MDS, slab hardening boot params | Memory hardening params present |
| R9 | Configuring kernel options | `_baseline-hardening` (BH-03) | dmesg_restrict, kptr_restrict, ASLR, SysRq, BPF, panic_on_oops | Sysctl hardening score |
| R10 | Disabling kernel modules loading | `_baseline-hardening` (BH-04) | `kernel.modules_disabled = 1` | Module loading status |
| R11 | Yama LSM configuration | `_baseline-hardening` (BH-05) | `kernel.yama.ptrace_scope = 1` | Ptrace scope setting |
| R12 | IPv4 configuration options | `_baseline-hardening` (BH-06) | BPF JIT, forwarding, ICMP redirects, ARP filtering, rp_filter, SYN cookies | IPv4 sysctl compliance |
| R13 | Disabling IPv6 | `_baseline-hardening` (BH-07) | `net.ipv6.conf.all.disable_ipv6 = 1` | IPv6 disabled status |
| R14 | File system configuration | `_baseline-hardening` (BH-08) | suid_dumpable, protected FIFOs/symlinks/hardlinks | Filesystem sysctl compliance |
| R33 | Auditd enforcement | `_audit-logging` (AL-02) | auditd enabled with execve tracking, log rotation | Auditd status, rule count |

## Additional Controls

The ANSSI framework also enables these controls without specific ANSSI recommendation numbers:

| Control Module | Purpose | Rationale |
|----------------|---------|-----------|
| `_access-control` | SSH key-only auth, root login disabled, idle timeout | General hardening best practice aligned with ANSSI guidance |
| `_encryption-at-rest` | LUKS verification, encrypted swap | Data protection aligned with ANSSI encryption recommendations |
| `_authentication` | PAM MFA, SSH certificates | Authentication hardening |
| `_secure-boot` | UEFI Secure Boot verification | Boot chain integrity |
| `_network-segmentation` | Firewall status, VLAN/bridge interfaces (server only) | Network isolation for servers |

## Compliance Levels

ANSSI defines 4 compliance levels with increasing strictness:

| Level | Governance Mapping | Description |
|-------|-------------------|-------------|
| minimal | `minimal` | Basic hygiene - essential rules only |
| intermediary | `standard` | Standard production hardening (default) |
| reinforced | `strict` | Aggressive hardening for sensitive systems |
| high | `paranoid` | Maximum security (may break workloads) |

Rules are filtered by severity: `minimal` enables only minimal-severity rules, `intermediary`
enables minimal + standard, `reinforced` adds strict, and `high` enables all including paranoid rules.

## System Categories

| Category | Host Type | Description |
|----------|-----------|-------------|
| base | server | Rules that apply to all systems |
| client | workstation | Workstation-specific rules |
| server | server | Server-specific rules (enables network segmentation) |

## Usage

```nix
modules = [
  compliance.nixosModules.anssi
  {
    compliance.frameworks.anssi = {
      enable = true;
      level = "reinforced";   # minimal | intermediary | reinforced | high
      category = "server";    # base | client | server
      exceptions = {
        "BH-07".rationale = "IPv6 required for internal mesh networking";
      };
    };
  }
];
```

## NixOS Advantages for ANSSI BP-028

### R7-R14 - Kernel and System Hardening

NixOS enforces kernel parameters declaratively. Unlike imperative hardening scripts that may
drift or be overridden, NixOS rebuilds the system from the declared configuration on every
activation. Sysctl values cannot drift because they are set from the Nix store on boot.

### R33 - Audit Logging

The `_audit-logging` control configures auditd with execve tracking rules declaratively.
The NixOS module generates audit rules from Nix expressions, ensuring the rule set matches
the declared configuration. Log persistence is enforced via journald configuration.

### Exception Management

The governance engine allows per-rule exceptions with mandatory rationale. For example,
R10 (disable kernel module loading) may need an exception on hosts that load modules at
runtime. The exception is recorded in the compliance report with its justification.
