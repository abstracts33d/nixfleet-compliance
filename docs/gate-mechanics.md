# Scanner vs. gate

A scanner observes drift after it happens. A gate refuses drift before it ships. NixFleet Compliance is a gate.

This page covers the two layers — static (build-time) and runtime (post-activation) — and how they interact with NixFleet's wave-promotion engine.

## Two layers, one discipline

Every control declares its `type`:

- **`static`** — pure function of NixOS configuration. Evaluated at build time. Examples: secure-boot enabler declared, audit service enabled, kernel sysctl values present in config.
- **`runtime`** — JSON-emitting probe wrapped in a systemd unit. Evaluated post-activation. Examples: `sshd -T` reports password auth disabled, `auditctl` shows execve tracking active, a service is responding on its declared port.
- **`both`** — declares both projections. Static catches misconfigurations before deploy; runtime catches drift, manual changes, or kernel-level state the config can't fully prove.

The discriminator lives in [`lib/mkTypedControl.nix`](https://github.com/arcanesys/nixfleet-compliance/blob/main/lib/mkTypedControl.nix). Static predicates are pure functions returning `{ passed, evidence }`; runtime probes are JCS-disciplined `mkProbe` invocations producing JSON the collector signs with the host SSH ed25519 key (see [evidence-format](evidence-format.md)). See [typed controls migration notes](typed-controls.md) for the schema-versioning and breaking-changes lineage.

## Static gate

When a host is declared on a channel with `compliance.mode = "enforce"`, NixFleet's `mkFleet` extracts every control with `type ∈ {static, both}`, evaluates each static predicate, and **throws** on any failure. The build fails. Nothing is signed. Nothing ships.

On `permissive` channels the same predicates run as warnings. On `disabled` channels they are skipped entirely. See [governance](governance.md) for the mode-escalation path.

The static gate's job is to fail loud and early — before any non-compliant closure can reach a host. An SSH-password-auth host cannot produce a signable artifact for an ANSSI BP-028 enforce channel; the build itself rejects the configuration.

## Runtime gate

After activation, the agent runs all `runtime` and `both` probes. On `enforce` channels, any failure causes the agent to:

1. Post a signed `ComplianceFailure` (or `RuntimeGateError`) report to the control plane.
2. Trigger local rollback to the previous generation.
3. Post `RollbackTriggered`.

The control plane aggregates outstanding compliance failures by rollout. The reconciler emits `Action::WaveBlocked` for the next wave when any host in earlier waves has unresolved failures, and the dispatch path holds further hosts until the failures are resolved by replacement (a new clean rollout supersedes the failed one).

The runtime gate's job is to catch what static predicates can't: drift introduced by an operator's manual `nixos-rebuild`, a kernel module that loaded differently than expected, an external service that's no longer responding.

## Why both layers exist

Static gates are cheap (build-time pure functions) but limited — they prove the config, not the running system. Runtime gates are expensive (probes execute on every host) but ground-truth — they prove the running state. Declaring a control `type = "both"` gets you both proofs, and the gate fails on the earlier one.

The intended discipline:

- Express every property that *can* be derived from config as a static predicate. Cheaper failures, faster feedback.
- Add a runtime probe whenever (a) a property cannot be fully proven from config, or (b) drift between the config and the running system is a real operational risk.
- Use `type = "both"` when the two projections give different information — for instance, a static predicate confirms the secure-boot module is enabled in the config, and a runtime probe confirms the boot actually completed in secure mode.
