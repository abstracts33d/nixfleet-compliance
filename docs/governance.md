# Governance

The governance engine encodes who decides which controls run, how strictly, with what exceptions, and how that decision rolls out across channels.

## Mode

```nix
compliance.channels.prod.mode = "enforce";  # disabled | permissive | enforce
```

`mode` controls gate behaviour per channel:

- **`disabled`** — controls produce no evidence and no gating. Useful for greenfield channels before any compliance work has landed.
- **`permissive`** — controls produce evidence; failures surface in logs and the CLI but don't block builds or rollouts. Used for onboarding existing fleets without disrupting service.
- **`enforce`** — failures fail the build (static) and block wave promotion + trigger rollback (runtime). The production posture.

## Escalation path

The intended adoption progression per channel:

```
disabled → static-permissive → static-enforce → runtime-permissive → runtime-enforce
```

Each step is reversible. The progression lets an operator land NixFleet Compliance without forcing every existing config to be compliant on day one — they accept evidence collection first, then tighten one stage at a time as the fleet catches up.

## Level and host type

```nix
compliance.governance = {
  level    = "strict";       # minimal | standard | strict | paranoid
  hostType = "server";       # server | workstation | appliance
};
```

`level` sets the default strictness of any control that has tiered thresholds (audit-log retention, password complexity, idle timeout, etc.). `hostType` selects the right baseline — a workstation needs different sysctls than a server, an appliance needs neither.

Framework presets set these by default. Override explicitly when a host's role demands a non-default profile.

## Per-rule exceptions

```nix
compliance.governance.exceptions = {
  "BH-07" = {
    rationale = "IPv6 required for internal mesh — review 2027-Q1";
  };
  "NS-03" = {
    rationale = "Legacy SCADA protocol on segment, ANSSI waiver ref ANSSI-XXX/2026";
  };
};
```

The `rationale` field is **mandatory** for every exception. Empty-string rationales fail the build. The intent is that an auditor reading the fleet config can see every deviation from policy and its justification inline — no separate "exceptions register" to keep in sync with the implementation.

Exceptions are scoped via standard NixOS module composition: declare them in a per-host module and they apply only to that host.

## Choosing where to start

**For a new fleet operating under NIS2 / DORA / ANSSI:**

1. Start every channel at `permissive`.
2. Enable the framework preset for the host's regulatory regime.
3. Let the evidence collector run for a week. Read the failures.
4. Fix the failures (preferred) or document them as exceptions with rationale.
5. When the channel reports zero unjustified failures, switch to `enforce`.

**For an existing fleet being brought under compliance:**

1. Start `disabled` on every channel.
2. Enable the preset on one host in `permissive` mode to surface the gap.
3. Triage the gap; fix or document an exception for each control.
4. Roll the preset to the rest of the channel in `permissive`.
5. Switch to `enforce` per channel as each one converges.

The goal is observable progress, not green dashboards on day one. The framework rewards honesty — `permissive` with rationale-bearing exceptions is closer to compliance than `enforce` with everything green and no exceptions documented.

## Individual controls without a preset

Skip the framework preset and pick controls à la carte when the regulatory profile doesn't match any single preset, or when adopting incrementally:

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

Useful when:

- The host is under a non-standard regime (sector-specific overlay on top of NIS2).
- You're adopting controls one at a time to limit blast radius.
- You're standing up a compliance-only NixOS host as a wedge into a larger Ansible-managed fleet (the host produces evidence; the rest of the fleet stays where it is).
