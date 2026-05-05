# NixFleet Compliance

[![CI](https://github.com/arcanesys/nixfleet-compliance/actions/workflows/ci.yml/badge.svg)](https://github.com/arcanesys/nixfleet-compliance/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE-MIT)
[![Latest tag](https://img.shields.io/github/v/tag/arcanesys/nixfleet-compliance?label=version&sort=semver)](https://github.com/arcanesys/nixfleet-compliance/releases)

Compliance controls for NixOS that **gate releases** instead of just observing them. Static predicates fail the build before a non-compliant closure can ship; runtime probes produce signed evidence and block wave promotion when they fail. Works with [NixFleet](https://github.com/arcanesys/nixfleet) for fleet-wide enforcement, or standalone on any NixOS host for local hardening and evidence collection.

## Who this is for

You are an RSSI or DSI under **NIS2** (Loi Résilience, transposition deadline 2027), **DORA** (applicable since 2025), **ISO 27001**, or **ANSSI BP-028**. You've been told "compliance as code" means installing another scanner. You don't want another scanner. You want an auditor-grade evidence chain you can produce on demand without trusting your scanner vendor.

**You don't need a fleet yet.** This module runs standalone on any NixOS host - one hardened bastion, one DMZ gateway, one SCADA jumpbox is enough to start producing signed evidence. NixFleet (the orchestration framework) becomes useful once you have several such hosts; until then, `nixfleet-compliance` standalone closes the audit point.

## Scanner vs. gate

A scanner tells you what's broken after the fact. This module:

1. **Refuses to build** non-compliant closures on `enforce`-mode channels. An SSH-password-auth host can't even produce a signable artifact for an ANSSI BP-028 channel.
2. **Signs every probe output** with the host key - JCS-canonicalized, schema-versioned. An auditor handed a hostname and a date can verify the chain without trusting the control plane.
3. **Blocks rollout waves** on runtime failure when integrated with NixFleet. A probe failure on wave 0 prevents wave 1 from promoting and triggers per-host rollback.

The module produces compliance proof, but the proof is a side-effect of the gate. The gate is the point.

## Coverage

- **4 framework presets** - NIS2 (essential / important), DORA, ISO 27001, ANSSI BP-028 (4 levels) - activate the right controls with defaults appropriate to the regulatory profile.
- **16 production controls** across access, encryption, audit, supply chain, baseline hardening, backup, incident response, disaster recovery, key management, network segmentation, secure boot, asset inventory, change management, vulnerability management, authentication, and agent egress. Plus one synthetic always-fail control (opt-in) for testing the rollback path end-to-end.
- **Article-level coverage** of **CRA** (Cyber Resilience Act) and **SecNumCloud** on individual controls where those frameworks apply (e.g. secure boot, supply chain, key management, network segmentation).
- **Governance engine** - per-channel mode (`disabled` / `permissive` / `enforce`), fleet-wide hardening level, host-type scoping, per-rule exceptions with mandatory rationale.
- **`compliance-check` CLI** - read the latest signed evidence as any user, or re-run probes live (root, `--live`).

## See it work

[nixfleet-demo](https://github.com/arcanesys/nixfleet-demo) ships with the NIS2 preset enabled on its control-plane host. Boot the 4-VM fleet, exercise the runtime gate, and inspect signed evidence locally.

## Pilot

We deliver auditor-ready evidence packets - NIS2, DORA, ISO 27001, or ANSSI BP-028 - as part of our free 12-week pilots for regulated operators. Pilot scope can start at **one hardened host** (this module standalone, no fleet needed) or **one regulated zone** (5 to 15 hosts, full NixFleet orchestration, migration from Ansible / Puppet / Chef in scope). Both yield the same M3 deliverable: a signed evidence chain your auditor can verify without trusting us.

Scope, deliverables, and what we ask for in return: <https://arcanesys.fr/en/pilot>.

Contact: <contact@arcanesys.fr>

## Documentation

- Framework mappings: [NIS2](docs/nis2-mapping.md) · [DORA](docs/dora-mapping.md) · [ISO 27001](docs/iso27001-mapping.md) · [ANSSI BP-028](docs/anssi-mapping.md)
- Typed controls explainer: [`docs/typed-controls.md`](docs/typed-controls.md)
- Synthetic control runbook: [`docs/synthetic-control-runbook.md`](docs/synthetic-control-runbook.md)
- Full docs: [arcanesys.github.io/nixfleet](https://arcanesys.github.io/nixfleet)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT. See [LICENSE-MIT](LICENSE-MIT).
