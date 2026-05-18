# Migration: v0.1 → v0.2 (capability vs policy split)

This guide walks the L1 (NixOS module) ↔ L2/L3 (`fleet.nix`) pairing that
`nixfleet-compliance` v0.2 makes explicit. The two layers were always
distinct, but v0.1 conflated their declaration sites; v0.2 separates them
cleanly. No control logic changes — this is a config-surface migration.

## TL;DR

| Old (v0.1) | New (v0.2) |
|---|---|
| One place: `services.nixfleet-compliance.*` on the host's NixOS, sometimes also referenced from `fleet.nix` | Two places: NixOS module enables the *capability* (collector + controls); `fleet.nix` enables the *policy* (probe consumption + mode + per-control exemptions) |
| Channel mode lived in `compliance.channels.<ch>.mode` | Channel-shorthand `nixfleet.channels.<ch>.compliance.frameworks` + per-scope `mode` refinements (fleet / tag / channel / host) |
| Per-control exception was `compliance.governance.exceptions.<id>.rationale = "..."` (NixOS-module side only) | Same NixOS exception still works for L1 evaluation; v0.2 adds L2-side `controlOverrides.<id> = { mode; reason; }` for *runtime* gating that doesn't require touching the host's closure |
| `mode = "disabled"` was implicit (omit the framework from the channel) | `mode = "disabled"` is now an explicit per-framework value — Aether/Darwin and similar exceptions ride next to the host declaration, not as a probe-shadow workaround |

## What is L1 vs L2/L3

| Layer | Declaration site | What it does | Survives a `fleet.nix` rebuild? |
|---|---|---|---|
| **L1 (capability)** | `services.nixfleet-compliance.*` on each host's NixOS configuration | Turns on the `compliance-evidence-collector` systemd unit, materialises the per-control `probeDescriptor` scripts, writes evidence to `/var/lib/nixfleet-compliance/evidence.json` | Yes — independent of `fleet.nix` |
| **L2 (channel-scope policy)** | `nixfleet.channels.<ch>.compliance.frameworks` in `fleet.nix` | Synthesises `evidence-<framework>` probes into each channel-member's `health-checks.json`; agent consumes them | Yes — re-synthesised on every fleet rebuild |
| **L3 (refinement policy)** | `nixfleet.compliance` / `tags.<t>.compliance` / `hosts.<h>.compliance` in `fleet.nix` | Refines L2: framework-level `mode` (enforce / observe / disabled), `reason`, per-control `controlOverrides` | Yes — re-synthesised on every fleet rebuild |

L1 is the host saying "I can produce evidence for X." L2 is the fleet
saying "the agent should consume X's evidence." L3 is the fleet
refining "but on these hosts/tags, treat it like this."

Conflating L1 and L2 produces two failure modes:

1. **L2 without L1** — fleet declares the framework, agent probes for
   `/var/lib/nixfleet-compliance/evidence.json`, the file doesn't exist
   because the collector isn't enabled. Probe reports `Fail`.
2. **L1 without L2** — host runs the collector, evidence file is
   produced and rotates on disk, no agent reads it, no gate effect.
   Cost: disk write, zero benefit.

v0.2 keeps L1 and L2 deliberately decoupled (no auto-coupling): the
operator opts into both explicitly. This is the same pattern as
`programs.zsh.enable` (capability) vs an operator's actual decision to
log into the host with zsh (policy) — declaring one doesn't imply the
other.

## Migration steps

### Step 1 — Audit your existing v0.1 declarations

```bash
# What's enabled at L1 (per host)?
nix eval ".#nixosConfigurations.<host>.config.compliance.controls" --apply 'lib.filterAttrs (n: c: c.enable or false)' --json

# What did fleet.nix used to say about compliance?
grep -A3 'compliance' fleet.nix
```

For most pre-v0.2 fleets the existing fleet.nix declared something like:

```nix
# Pre-v0.2 (DEPRECATED — see step 2)
channels.stable.compliance = {
  mode = "enforce";
  frameworks = ["nis2-essential"];
};
```

That declaration is still valid in v0.2 (no breaking change) but it
*only* establishes channel-scope policy. The host-scope NixOS module
configuration (L1) still has to be present separately.

### Step 2 — Confirm L1 capability is enabled per host

For each host in the channel, ensure the NixOS module config includes
the controls the framework requires. The two most common controls are:

```nix
# host's NixOS config
{
  services.nixfleet-compliance.enable = true;

  compliance.controls.encryptionAtRest.enable = true;
  compliance.controls.authentication = {
    enable = true;
    mfaRequired = true;  # set false during onboarding; tighten later
  };

  compliance.governance = {
    primaryFramework = "nis2-essential";
    level = "standard";        # minimal | standard | strict | paranoid
    hostType = "server";       # server | workstation | appliance
  };
}
```

Verify the collector unit is active after rebuild:

```bash
systemctl status compliance-evidence-collector.service
ls -la /var/lib/nixfleet-compliance/evidence.json
```

If the file doesn't appear within the collector's interval, L1 is
incomplete — fix this before adding L2/L3 policy.

### Step 3 — L2: declare the channel-shorthand

```nix
# fleet.nix
{
  nixfleet.channels.stable = {
    rolloutPolicy = "...";
    signingIntervalMinutes = 60;
    freshnessWindow = 180;

    # v0.2: same shape as before; `mode` here only sets the default
    # for bare-string entries below (an explicit `{name; mode;}` per
    # entry overrides this default).
    compliance = {
      mode = "enforce";
      frameworks = ["nis2-essential"];
    };
  };
}
```

This synthesises `healthChecks.evidence-nis2-essential` into every host
on `stable`. No change for operators already using the v0.1 shorthand;
the field shape is preserved.

### Step 4 — L3: pin per-host / per-tag / per-fleet refinements

Three concrete patterns the v0.2 surface unblocks:

#### Pattern A — Per-host disable (e.g. Aether/Darwin)

A single host that *cannot* produce evidence (Darwin developer host,
sealed appliance, etc.) needs the probe deactivated without removing
the host from the channel.

```nix
# fleet.nix
nixfleet.hosts.aether.compliance.frameworks.nis2-essential = {
  mode = "disabled";
  reason = "Darwin developer host: no NixOS compliance collector available";
};
```

The synthesised `evidence-nis2-essential` probe is emitted with
`mode = "disabled"`; the agent's probe-runner worker skips it. The
`reason` is surfaced in operator-facing tooling.

In v0.1 this required carving a probe-shadow under
`nixfleet.hosts.aether.healthChecks` — an L4 workaround. v0.2 lets the
declaration live next to the host as a one-liner.

#### Pattern B — Tag-scoped enforcement bump

A subset of hosts (e.g. anything tagged `audit`) must always enforce,
even during an observe-mode rollout window:

```nix
# fleet.nix
nixfleet.compliance.frameworks.nis2-essential = {
  mode = "observe";
  reason = "Q2 audit-window rollout: observe mode while collectors stabilise";
};

nixfleet.tags.audit.compliance.frameworks.nis2-essential = {
  mode = "enforce";
  reason = "Audit-tagged hosts: always-enforce";
};
```

Precedence is `fleet < tag < channel < host` (most-specific non-null
wins). An `audit`-tagged host on a channel that uses the bare-string
shorthand (`frameworks = ["nis2-essential"]`) ends up at `enforce`; an
untagged host ends up at the fleet's `observe`.

#### Pattern C — Per-control override (v0.2 `controlOverrides`)

A specific control needs a different runtime mode without changing the
framework-level mode or touching the host's L1 governance exceptions:

```nix
# fleet.nix
nixfleet.hosts.legacy-egress.compliance.frameworks.nis2-essential.controlOverrides = {
  "agent-egress-exemption" = {
    mode = "observe";
    reason = "Phase-out window for legacy egress policy on this host only";
  };
};
```

This is **not** the same as `compliance.governance.exceptions.<id>` on
the host's NixOS module:

| Surface | When evaluated | Effect |
|---|---|---|
| `compliance.governance.exceptions.<id>.rationale` (L1) | Static, at NixOS build time | Disables the *rule* — the L1 control's `check` script doesn't probe that rule at all. Evidence file does not report it. |
| `controlOverrides.<id> = { mode = "observe"; reason; }` (L3) | Runtime, in the agent's per-control evaluation | The L1 evidence still reports the rule (passed or failed); the agent's gate treats it as `observe` (records but doesn't gate) instead of `enforce`. |

Use L1 exceptions for "this rule does not apply to this host's
hardware/topology." Use L3 `controlOverrides` for "this rule applies
but we're accepting failures during a transition window."

### Step 5 — BH-06 / BH-07 (baseline hardening) special case

The two most commonly-exempted ANSSI baseline-hardening rules are
network-related:

- `BH-06` — IPv4 sysctl tightening (R12). Fails on hosts that
  legitimately need looser settings (BPF JIT for eBPF observability,
  forwarding for routers, etc.).
- `BH-07` — IPv6 disable (R13). Fails on hosts that legitimately need
  IPv6 (internal mesh, dual-stack peers).

In v0.1 the only path was `compliance.governance.exceptions.BH-07`
in the host's NixOS module — which *disables the rule's `enable`
attribute entirely* and therefore drops the rule from the evidence
file's `BH-07` entry.

In v0.2 the operator has both surfaces and should pick deliberately:

```nix
# L1 path — rule is truly N/A for this host's role
# (host's NixOS config)
compliance.governance.exceptions = {
  "BH-07" = {
    rationale = "Internal mesh requires IPv6 - review 2027-Q1";
  };
};
```

```nix
# L3 path — rule applies but accept failures during transition
# (fleet.nix)
nixfleet.hosts.mesh-router.compliance.frameworks."anssi-bp028".controlOverrides = {
  "BH-07" = {
    mode = "observe";
    reason = "IPv6 required for internal mesh; tracking re-enablement under TICKET-1234";
  };
};
```

Rule of thumb: if the answer to "should this rule produce evidence at
all on this host?" is "no, it's structurally inapplicable," use the L1
exception. If the answer is "yes, but we accept the failure for now,"
use the L3 `controlOverrides`.

### Step 6 — Verify the resolved health-checks

After rebuild + push, inspect the per-host effective probe set:

```bash
nix eval ".#fleet.resolved.effectiveHealthChecks.<host>.evidence-nis2-essential" --json
```

Expected shape:

```json
{
  "kind": "evidence",
  "framework": "nis2-essential",
  "mode": "enforce",                   // or "observe" | "disabled"
  "controlOverrides": {
    "agent-egress-exemption": {
      "mode": "observe",
      "reason": "Phase-out window for legacy egress policy on this host only"
    }
  },
  "evidencePath": "/var/lib/nixfleet-compliance/evidence.json",
  ...
}
```

Confirm:
- `mode` matches your most-specific declaration
- `controlOverrides` contains every refinement from every scope
- `framework` matches what L1 is producing

If `mode = "enforce"` but the L1 evidence file isn't present on the
host (step 2 incomplete), the agent will report `Fail` on every
poll cycle. That is the expected failure mode for L2-without-L1; fix
L1 first.

## What's deliberately not changing

- L1 module surfaces (`compliance.controls.*`, `compliance.governance.*`,
  `services.nixfleet-compliance.*`) are unchanged. Existing host configs
  rebuild as-is.
- Channel-scope `compliance.frameworks` list shorthand (bare strings or
  `{name; mode; controlOverrides;}` entries) is unchanged. Existing
  fleet.nix declarations rebuild as-is.
- Evidence file schema is unchanged for collector consumers; v0.2
  adds the canonical `schemaVersion = 1` document, but earlier
  schemaVersion-0 evidence emits with the same shape under the same
  field names where they overlap.

The migration is additive: L1 still works, L2 channel-shorthand still
works, L3 refinement attrsets are new and optional.

## See also

- `docs/governance.md` — L1 governance engine (modes, levels, host
  types, exceptions)
- `docs/evidence-format.md` — canonical evidence-file schema (v0.2
  `schemaVersion = 1`)
- `nixfleet/docs/rfcs/0010-multi-scope-health-probes.md` §3.6 — the
  capability-vs-policy split as documented in the consumer repo
- `nixfleet/docs/rfcs/0010-multi-scope-health-probes.md` §3.7 — the
  full scope hierarchy and merge semantics
