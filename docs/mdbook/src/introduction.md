# NixFleet Compliance

Compliance controls for NixOS that **gate releases** instead of just observing them. Static predicates fail the build before a non-compliant closure can ship; runtime probes produce signed evidence and block wave promotion when they fail.

This documentation covers:

- **Concepts** — what makes this a gate, not a scanner; how typed controls work; how governance escalates from `permissive` to `enforce`.
- **Reference** — the evidence format your auditor reads; the `compliance-check` CLI you read every day.
- **Frameworks** — article-by-article mappings for the four supported presets: NIS2, DORA, ISO 27001, ANSSI BP-028.
- **Runbooks** — operational procedures, starting with the synthetic always-fail control used to test the rollback path.

This module works standalone on any NixOS host — one hardened bastion is enough to start producing signed evidence. For fleet-wide enforcement (multiple hosts, wave promotion, automated rollback), pair with [nixfleet](https://github.com/arcanesys/nixfleet).

For the project README and the pilot offer, see [github.com/arcanesys/nixfleet-compliance](https://github.com/arcanesys/nixfleet-compliance).
