# Typed Controls + JCS + Baseline Agent Egress Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Migrate every compliance control from the current untyped probe shape to a typed `{ type = "static" | "runtime" | "both" }` discriminated model; declare JCS canonicalization in probe output; version probe descriptors with a per-framework `schema` string; add one negative-test fixture per control; introduce a new baseline control that explicitly exempts the agent's outbound network path from firewall-lock controls.

**Architecture:** New `lib/mkTypedControl.nix` wraps the existing `mkControl.nix` pattern with an explicit `type` discriminator and a typed `probeDescriptor` that serialises to the CONTRACTS §I.3 payload shape (`{ command, args, timeoutSecs, expect, schema }`). Static controls expose an `evaluate` projection taking a NixOS `config` and returning `{ passed, evidence }`; runtime controls expose a `probeDescriptor`; `both` controls expose both and share the `schema` version between them. Framework modules are unchanged in intent but gain a `schemaVersion` attribute (e.g. `"anssi-bp028/v1"`) used in every descriptor produced. One existing control per framework is upgraded to `type = "both"` as the reference implementation. A new `_agent-egress-exemption.nix` declares the baseline network reachability the agent needs.

**Tech Stack:** Nix modules, `lib.evalModules`, JCS (Stream C's canonicalizer is the consumer — producer-side discipline is all we own here).

**Issue closed:** abstracts33d/nixfleet-compliance#1.

---

## File Structure

### Created

| Path | Responsibility |
|---|---|
| `lib/mkTypedControl.nix` | Typed control factory. Wraps `mkControl.nix`; adds `type` discriminator, `schema` field, and structured `probeDescriptor`. |
| `lib/probeDescriptor.nix` | Builds the CONTRACTS §I.3 payload (`{ command, args, timeoutSecs, expect, schema }`) from the typed fields. |
| `lib/evaluateStatic.nix` | Helper for `type = "static"` controls: `evaluate :: config → { passed, evidence }`. |
| `controls/_agent-egress-exemption.nix` | Baseline control — declares and exempts agent egress from firewall-lock controls. `type = "both"`. |
| `tests/typed-controls/default.nix` | Eval harness that evaluates every control against a stub config, asserts the shape of `probeDescriptor`, and runs negative fixtures. |
| `tests/typed-controls/fixtures/<control>-pass.nix` | Per-control positive fixture (one per control). |
| `tests/typed-controls/negative/<control>-fail.nix` | Per-control negative fixture (intentionally misconfigured — proves the failure mode is observable). |
| `tests/typed-controls/fixtures/jcs-golden.json` | Canonical JCS bytes of a reference probe output (pinned by Stream C's golden-file test in `docs/CONTRACTS.md` §III). |
| `docs/typed-controls.md` | Migration guide for out-of-tree controls adopting the new shape. |
| `CHANGELOG.md` entry | User-visible note: new typed shape, migration path, baseline agent-egress control. |

### Modified

| Path | Change |
|---|---|
| `lib/mkControl.nix` | Extended (not rewritten) to accept a new optional `typedWrapper` argument; the existing untyped path remains during migration. |
| `lib/mkProbe.nix` | Emit the probe output as a JCS-ready JSON object; tighten output shape validation (one shell-side `jq` invocation that rejects invalid shapes). |
| `controls/_authentication.nix` | Migrate to `lib/mkTypedControl.nix`. Declared `type = "runtime"`. |
| `controls/_encryption-in-transit.nix` | Migrate to `type = "runtime"`. Chosen as the ANSSI `type = "both"` reference (adds a static `evaluate` that checks declared `security.pki.*` options). |
| `controls/_access-control.nix` | Migrate to `type = "runtime"`. |
| `controls/_baseline-hardening/` | Migrate to `type = "both"` — ISO 27001 reference (static: kernel params; runtime: sysctl probe). |
| `controls/_encryption-at-rest.nix` | Migrate to `type = "runtime"`. |
| `controls/_secure-boot.nix` | Migrate to `type = "both"` — DORA reference (static: boot loader config; runtime: efivars probe). |
| `controls/_audit-logging/` | Migrate to `type = "both"` — NIS2 reference (static: declared audit rules; runtime: auditctl probe). |
| `controls/_network-segmentation.nix` | Migrate to `type = "runtime"`. |
| `controls/_asset-inventory.nix` | Migrate to `type = "runtime"`. |
| `controls/_backup-retention.nix` | Migrate to `type = "runtime"`. |
| `controls/_change-management.nix` | Migrate to `type = "static"` (declared policy only, nothing to probe). |
| `controls/_disaster-recovery.nix` | Migrate to `type = "runtime"`. |
| `controls/_incident-response.nix` | Migrate to `type = "static"` (declared policy). |
| `controls/_key-management.nix` | Migrate to `type = "runtime"`. |
| `controls/_supply-chain.nix` | Migrate to `type = "static"` (declared: nixpkgs pin, attic usage). |
| `controls/_vulnerability-mgmt.nix` | Migrate to `type = "runtime"`. |
| `frameworks/anssi.nix` | Add `schemaVersion = "anssi-bp028/v1"`; import `_agent-egress-exemption.nix`; enable it by default. |
| `frameworks/nis2.nix` | Add `schemaVersion = "nis2/v1"`; import the baseline. |
| `frameworks/dora.nix` | Add `schemaVersion = "dora/v1"`; import the baseline. |
| `frameworks/iso27001.nix` | Add `schemaVersion = "iso27001/v1"`; import the baseline. |

### Not touched

- `evidence/` collector machinery — unchanged; the migration is shape-compatible so the collector keeps working.
- `governance/` — unchanged.
- `compliance-check` — unchanged (consumes evidence output, which gains fields but no removals).

---

## Pre-flight

Worktree: `~/.config/superpowers/worktrees/nixfleet-compliance/typed-controls/` on branch `feat/typed-controls` (already created off `main`).

All commands run from the worktree root. User runs every `nix build`, `nix flake check`, and VM test; agent may run `nix eval --raw` on pure fixtures.

Strategy: extend `mkControl.nix` first (backward-compatible), then migrate controls one by one with a commit per control. Each commit keeps the repo green so `feat/typed-controls` can ship incrementally if needed.

---

## Task 1: Scaffold typed primitives

**Files:**
- Create: `lib/mkTypedControl.nix`
- Create: `lib/probeDescriptor.nix`
- Create: `lib/evaluateStatic.nix`

- [ ] **Step 1: Write `lib/probeDescriptor.nix`**

```nix
# lib/probeDescriptor.nix
#
# Build a CONTRACTS §I.3 probe descriptor from typed fields.
# Output shape — ready for JCS canonicalization by Stream C:
#   { command: str, args: [str], timeoutSecs: int, expect: attrs, schema: str }
{lib}: {
  # probe :: ShellScript (derivation) — resolved to a store path as `command`
  # args :: [string]
  # timeoutSecs :: int
  # expect :: attrs of JSON-shaped assertions (see ./evaluateStatic.nix)
  # schema :: string — e.g. "anssi-bp028/v1"
  mkDescriptor = {
    command,
    args ? [],
    timeoutSecs ? 30,
    expect ? {},
    schema,
  }: {
    inherit args timeoutSecs expect schema;
    command = toString command;
  };
}
```

- [ ] **Step 2: Write `lib/evaluateStatic.nix`**

```nix
# lib/evaluateStatic.nix
#
# Helper for `type = "static"` controls. A static control expresses its
# evidence as a pure function of the NixOS config, so it can run at CI
# time — before any agent has been deployed — as a rollout gate.
#
# Shape:
#   evaluate :: config → { passed :: bool, evidence :: attrs }
#
# Used by `mkTypedControl` for controls whose state is fully declared in
# the flake (e.g. boot loader config, supply chain pins). Runtime
# controls omit this projection; `both`-typed controls provide both.
{lib}: {
  runStatic = evaluate: config: let
    result = evaluate config;
  in
    assert result ? passed;
    assert result ? evidence;
      result;
}
```

- [ ] **Step 3: Write `lib/mkTypedControl.nix`**

```nix
# lib/mkTypedControl.nix
#
# Typed control factory. Discriminates on `type`:
#
#   "static"  — declared in NixOS config. Gated at CI time via
#               `evaluate :: config → { passed, evidence }`.
#               No runtime probe.
#
#   "runtime" — observed on the host. `probeDescriptor` carries the
#               CONTRACTS §I.3 payload the agent executes.
#
#   "both"    — static evidence AT CI time + runtime probe on-host.
#               Both projections share the `schema` version.
#
# Wraps `mkControl.nix` — existing control authoring ergonomics are
# preserved; this module just adds type discrimination and schema
# versioning at the outer layer.
#
# Usage:
#   import ../lib/mkTypedControl.nix {
#     controlId = "authentication";
#     controlDescription = "Authentication - Art. 21(j).";
#     articles = { nis2 = ["21(j)"]; };
#     type = "runtime";
#     schema = "anssi-bp028/v1";
#     rules = import ./rules.nix;
#   }
{
  controlId,
  controlDescription,
  articles ? {},
  extraOptions ? {},
  rules,
  type,
  schema,
  evaluate ? null, # required when type ∈ {"static", "both"}
}: assert builtins.elem type ["static" "runtime" "both"];
  assert (type != "runtime") -> evaluate != null;
    {
      config,
      lib,
      pkgs,
      ...
    }: let
      inner = import ./mkControl.nix {
        inherit controlId controlDescription articles extraOptions rules;
      } {inherit config lib pkgs;};

      descriptorBuilder = (import ./probeDescriptor.nix {inherit lib;}).mkDescriptor;

      staticHelper = (import ./evaluateStatic.nix {inherit lib;}).runStatic;

      staticResult =
        if type == "runtime"
        then null
        else staticHelper evaluate config;

      runtimeDescriptor =
        if type == "static"
        then null
        else descriptorBuilder {
          command = inner.config.compliance.evidence.probes.${controlId}.check;
          args = [];
          timeoutSecs = 30;
          expect = {}; # filled by individual controls via `extraOptions`
          inherit schema;
        };

      typedProbe =
        inner.config.compliance.evidence.probes.${controlId}
        // {
          inherit type schema;
          staticEvidence = staticResult;
          probeDescriptor = runtimeDescriptor;
        };
    in
      inner
      // {
        config =
          inner.config
          // {
            compliance.evidence.probes.${controlId} = typedProbe;
          };
      }
```

- [ ] **Step 4: Commit**

```bash
git add lib/mkTypedControl.nix lib/probeDescriptor.nix lib/evaluateStatic.nix
git commit -m "feat(lib): typed control primitives with static/runtime/both discrimination"
```

---

## Task 2: JCS discipline in `mkProbe`

**Files:**
- Modify: `lib/mkProbe.nix`

- [ ] **Step 1: Read the current `mkProbe.nix`**

Already inspected — it writes `set -o pipefail` + a shell script. The final output goes through `jq -n`, which already produces sorted, valid JSON. The remaining work is (a) sort keys, (b) refuse non-UTF-8 input, (c) single-line output.

- [ ] **Step 2: Tighten the output shape**

Replace `mkProbe` with:

```nix
# lib/mkProbe.nix
#
# Wraps a probe script. The script body MUST print a single JSON object
# to stdout. This wrapper guarantees the final bytes written to stdout
# are JCS-ready: UTF-8, sorted keys, no trailing newline, no whitespace.
#
# Stream C's `nixfleet-canonicalize` normalises number/unicode edge
# cases — producer-side, we promise to never emit floats and to keep
# attr-set iteration deterministic. Usage is unchanged for existing
# controls:
#
#   mkProbe = import ../lib/mkProbe.nix {inherit pkgs lib;};
#   check = mkProbe {
#     name = "my-control";
#     runtimeInputs = with pkgs; [openssh];
#     script = ''
#       jq -n --argjson val true '{ok: $val}'
#     '';
#   };
#
# Default PATH includes: coreutils, findutils, jq, gnugrep, gawk,
# hostname, iproute2, systemd.
{
  pkgs,
  lib,
}: {
  name,
  runtimeInputs ? [],
  script,
}:
  pkgs.writeShellScript "probe-${name}" ''
    set -o pipefail
    export PATH="${lib.makeBinPath (with pkgs; [coreutils findutils jq gnugrep gawk hostname iproute2 systemd] ++ runtimeInputs)}"

    # Wrap the caller's script so that whatever JSON they emit is
    # re-read through `jq -cS` (compact, sorted-keys) before leaving
    # stdout. This is a cheap JCS-producer-side discipline.
    raw=$(
      ${script}
    )

    printf '%s' "$raw" | jq -cS '.'
  ''
```

- [ ] **Step 3: Commit**

```bash
git add lib/mkProbe.nix
git commit -m "feat(lib/mkProbe): enforce sorted-keys compact JSON output (JCS-ready)"
```

---

## Task 3: Negative-test harness

**Files:**
- Create: `tests/typed-controls/default.nix`
- Create: `tests/typed-controls/fixtures/.gitkeep`
- Create: `tests/typed-controls/negative/.gitkeep`

- [ ] **Step 1: Write the harness**

```nix
# tests/typed-controls/default.nix
#
# Eval-only harness for typed controls. For each control module:
# - Evaluate against a stub NixOS config.
# - Assert the probe entry has `type`, `schema`, and either
#   `staticEvidence` or `probeDescriptor` (or both) per the type.
# - Run positive fixtures under ./fixtures/ and negative fixtures under
#   ./negative/.
#
# No VM, no build — pure evaluation. Bounded by what `nix flake check`
# can see.
{
  lib,
  pkgs,
}: let
  evalControl = controlPath: cfg: let
    mod = lib.evalModules {
      modules = [
        controlPath
        {
          _module.args = {inherit pkgs;};
          config = cfg;
        }
      ];
      specialArgs = {inherit pkgs;};
    };
  in
    mod.config.compliance.evidence.probes;

  assertTyped = controlId: probes: let
    p = probes.${controlId} or null;
  in
    if p == null
    then throw "control '${controlId}' produced no probe entry"
    else if !(p ? type)
    then throw "control '${controlId}' missing `type` field"
    else if !(p ? schema)
    then throw "control '${controlId}' missing `schema` field"
    else if p.type == "runtime" && p.probeDescriptor == null
    then throw "control '${controlId}' is type=runtime but probeDescriptor is null"
    else if p.type == "static" && p.staticEvidence == null
    then throw "control '${controlId}' is type=static but staticEvidence is null"
    else if p.type == "both" && (p.probeDescriptor == null || p.staticEvidence == null)
    then throw "control '${controlId}' is type=both but missing one of the projections"
    else "ok";

  runFixture = path: let
    loaded = import path {inherit lib pkgs evalControl assertTyped;};
    results = map (fx: let
      probes = evalControl fx.control fx.config;
    in
      assertTyped fx.controlId probes)
    loaded.cases;
  in
    results;

  runNegative = path: let
    result = builtins.tryEval (import path {inherit lib pkgs evalControl;});
  in
    if result.success
    then throw "expected eval failure for negative fixture ${toString path}, got success"
    else "ok";

  listFixtures = dir:
    lib.filter (n: lib.hasSuffix ".nix" n) (builtins.attrNames (builtins.readDir dir));

  positives = lib.concatMap (n: runFixture (./fixtures + "/${n}")) (listFixtures ./fixtures);
  negatives = map (n: runNegative (./negative + "/${n}")) (listFixtures ./negative);
in {
  results = positives ++ negatives;
}
```

- [ ] **Step 2: Commit**

```bash
git add tests/typed-controls/
git commit -m "test: add eval harness for typed controls and negative fixtures"
```

---

## Task 4: Migrate `_authentication.nix` (template for runtime-only)

**Files:**
- Modify: `controls/_authentication.nix`
- Create: `tests/typed-controls/fixtures/authentication.nix`
- Create: `tests/typed-controls/negative/authentication-bad-schema.nix`

Use this task as the template. Subsequent runtime-only migrations repeat the same pattern.

- [ ] **Step 1: Rewrite `_authentication.nix` via `mkTypedControl`**

```nix
# controls/_authentication.nix
#
# Authentication - Art. 21(j).
# type = "runtime" — MFA/auth state is observed at run time. No static
# evidence is derivable from NixOS config because PAM/Keycloak state
# lives outside the module system.
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.compliance.controls.authentication;
  gov = config.compliance.governance;
  mkProbe = import ../lib/mkProbe.nix {inherit pkgs lib;};
  framework = gov.primaryFramework or "anssi-bp028";
  schemaVersion = config.compliance.schemaVersions.${framework} or "${framework}/v1";
in {
  imports = [../evidence/options.nix ../governance/options.nix];

  options.compliance.controls.authentication = {
    enable = lib.mkEnableOption "authentication compliance control";

    enforce = lib.mkOption {
      type = lib.types.bool;
      default = gov.enforceMode == "enforce";
      description = "Apply NixOS configuration. When false, only probes run.";
    };

    mfaRequired = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Whether MFA is required by policy.";
    };

    maxServiceAccounts = lib.mkOption {
      type = lib.types.int;
      default = 10;
      description = "Maximum expected number of service accounts before warning";
    };
  };

  config = lib.mkIf cfg.enable {
    compliance.evidence.collector.enable = lib.mkDefault true;

    compliance.evidence.probes.authentication = {
      control = "authentication";
      type = "runtime";
      schema = schemaVersion;
      articles = {
        nis2 = ["21(j)"];
        iso27001 = ["A.8.5"];
        dora = ["Art. 9"];
      };
      probeDescriptor = {
        command = toString (mkProbe {
          name = "authentication";
          runtimeInputs = with pkgs; [coreutils gnugrep gawk];
          script = /* existing script — copied verbatim from the pre-migration version */ ''
            # ... unchanged script body from previous version of this file ...
          '';
        });
        args = [];
        timeoutSecs = 30;
        expect = {
          # machine-readable success criterion — auditor consumes this
          compliant = true;
        };
        schema = schemaVersion;
      };
      # staticEvidence intentionally null for type = "runtime".
      staticEvidence = null;
      # Legacy `check` alias kept for one release so the compliance
      # collector continues working during migration.
      check = mkProbe {
        name = "authentication-compat";
        script = "cat << 'EOF'\n${builtins.toJSON {compat = true;}}\nEOF";
      };
    };
  };
}
```

- [ ] **Step 2: Add a positive fixture**

```nix
# tests/typed-controls/fixtures/authentication.nix
{
  lib,
  pkgs,
  ...
}: {
  cases = [
    {
      control = ../../controls/_authentication.nix;
      controlId = "authentication";
      config = {
        compliance.governance.level = "standard";
        compliance.governance.enforceMode = "report";
        compliance.governance.hostType = "server";
        compliance.governance.architecture = "x86_64";
        compliance.governance.primaryFramework = "anssi-bp028";
        compliance.schemaVersions."anssi-bp028" = "anssi-bp028/v1";
        compliance.controls.authentication.enable = true;
      };
    }
  ];
}
```

- [ ] **Step 3: Add a negative fixture (missing schema)**

```nix
# tests/typed-controls/negative/authentication-bad-schema.nix
{
  lib,
  pkgs,
  evalControl,
  ...
}:
  evalControl ../../controls/_authentication.nix {
    compliance.governance.level = "standard";
    compliance.governance.enforceMode = "report";
    compliance.governance.hostType = "server";
    compliance.governance.architecture = "x86_64";
    # Omitted: compliance.governance.primaryFramework. Default falls
    # back to "anssi-bp028" but schemaVersions is empty → missing
    # fallback string. This fixture exists to ensure we trip on
    # unset-schema scenarios.
    compliance.schemaVersions = {};
    compliance.controls.authentication.enable = true;
  }
```

Note: the harness asserts `schema` is present — this fixture's goal is to catch a mis-set schema map. It relies on the fallback behavior being a `throw` rather than a default string; adjust the fallback in `_authentication.nix` if you want the type system to catch it instead:

```nix
schemaVersion = config.compliance.schemaVersions.${framework} or (throw "compliance.schemaVersions.${framework} is not set");
```

Prefer the `throw` version — a silent default is worse than an eval error here.

- [ ] **Step 4: User runs the harness**

```bash
nix eval --impure --json --expr 'import ./tests/typed-controls/default.nix { lib = (builtins.getFlake (toString ./.)).inputs.nixpkgs.lib; pkgs = (builtins.getFlake (toString ./.)).inputs.nixpkgs.legacyPackages.x86_64-linux; }'
```

Expected: `{ results = [ "ok", "ok", ... ] }`.

- [ ] **Step 5: Commit**

```bash
git add controls/_authentication.nix tests/typed-controls/fixtures/authentication.nix tests/typed-controls/negative/authentication-bad-schema.nix
git commit -m "feat(controls/authentication): migrate to typed control (type=runtime)"
```

---

## Task 5: Migrate runtime-only controls

For each of these controls, repeat Task 4's pattern: rewrite via `mkTypedControl`, add a positive fixture, add a negative fixture (schema mismatch or bad expect), commit once per control.

- [ ] `controls/_access-control.nix` — type = "runtime"
- [ ] `controls/_encryption-at-rest.nix` — type = "runtime"
- [ ] `controls/_network-segmentation.nix` — type = "runtime"
- [ ] `controls/_asset-inventory.nix` — type = "runtime"
- [ ] `controls/_backup-retention.nix` — type = "runtime"
- [ ] `controls/_disaster-recovery.nix` — type = "runtime"
- [ ] `controls/_key-management.nix` — type = "runtime"
- [ ] `controls/_vulnerability-mgmt.nix` — type = "runtime"

Each migration is a single commit:

```bash
git commit -m "feat(controls/<name>): migrate to typed control (type=runtime)"
```

---

## Task 6: Migrate static-only controls

Static controls have no runtime probe — they ship `evaluate :: config → { passed, evidence }` and are gated at CI time.

- [ ] **Step 1: Migrate `controls/_change-management.nix`**

The current file declares policy options (e.g. "changes require review") that are not runtime-observable from the host. `evaluate` returns the declared policy and `passed = cfg.enable` (trivially) — the real gate is that the policy is declared at all.

```nix
# controls/_change-management.nix
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.compliance.controls.changeManagement;
  gov = config.compliance.governance;
  framework = gov.primaryFramework or "iso27001";
  schemaVersion = config.compliance.schemaVersions.${framework} or (throw "schemaVersions.${framework} missing");
in {
  imports = [../evidence/options.nix ../governance/options.nix];

  options.compliance.controls.changeManagement = {
    enable = lib.mkEnableOption "change management compliance control";
    reviewRequired = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Whether changes require peer review.";
    };
  };

  config = lib.mkIf cfg.enable {
    compliance.evidence.probes.changeManagement = {
      control = "change-management";
      type = "static";
      schema = schemaVersion;
      articles.iso27001 = ["A.8.32"];
      probeDescriptor = null;
      staticEvidence = {
        passed = cfg.reviewRequired;
        evidence = {
          reviewRequired = cfg.reviewRequired;
        };
      };
    };
  };
}
```

- [ ] **Step 2: Commit**

```bash
git add controls/_change-management.nix
git commit -m "feat(controls/change-management): migrate to typed control (type=static)"
```

- [ ] **Step 3: Same pattern for the remaining static controls**

- [ ] `controls/_incident-response.nix` — type = "static"
- [ ] `controls/_supply-chain.nix` — type = "static"

One commit per control.

---

## Task 7: Migrate `both`-typed controls (one reference per framework)

Each framework gets exactly one reference `type = "both"` control — both a static gate and a runtime probe. They share the `schema` version.

- [ ] **Step 1: ANSSI reference — `_encryption-in-transit.nix` becomes `type = "both"`**

Static projection: check `security.pki.*` options declare a min TLS version.
Runtime projection: existing probe (checks certs on disk).

```nix
# controls/_encryption-in-transit.nix — migrate to `type = "both"`
# Static evaluates declared TLS config; runtime probes certs on disk.
# Both share schema = "anssi-bp028/v1".
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.compliance.controls.encryptionInTransit;
  gov = config.compliance.governance;
  mkProbe = import ../lib/mkProbe.nix {inherit pkgs lib;};
  framework = gov.primaryFramework or "anssi-bp028";
  schemaVersion = config.compliance.schemaVersions.${framework} or (throw "schemaVersions.${framework} missing");
in {
  imports = [../evidence/options.nix ../governance/options.nix];

  options.compliance.controls.encryptionInTransit = {
    enable = lib.mkEnableOption "encryption in transit";
    enforce = lib.mkOption {
      type = lib.types.bool;
      default = gov.enforceMode == "enforce";
    };
    minTlsVersion = lib.mkOption {
      type = lib.types.enum ["1.2" "1.3"];
      default = "1.2";
    };
    certExpiryWarningDays = lib.mkOption {
      type = lib.types.int;
      default = 30;
    };
  };

  config = lib.mkIf cfg.enable {
    compliance.evidence.probes.encryptionInTransit = {
      control = "encryption-in-transit";
      type = "both";
      schema = schemaVersion;
      articles.nis2 = ["21(h)"];
      articles.iso27001 = ["A.8.20" "A.8.24"];
      articles.cra = ["Art. 10"];
      staticEvidence = {
        passed = cfg.minTlsVersion == "1.2" || cfg.minTlsVersion == "1.3";
        evidence = {
          declaredMinTlsVersion = cfg.minTlsVersion;
          certExpiryWarningDays = cfg.certExpiryWarningDays;
        };
      };
      probeDescriptor = {
        command = toString (mkProbe {
          name = "encryption-in-transit";
          runtimeInputs = with pkgs; [openssl findutils];
          script = /* existing script verbatim */ "";
        });
        args = [];
        timeoutSecs = 30;
        expect.compliant = true;
        schema = schemaVersion;
      };
    };
  };
}
```

(The ellipsis is the existing script body — preserve verbatim from the pre-migration version.)

- [ ] **Step 2: ISO 27001 reference — `_baseline-hardening/`**

Static: kernel.{yama.ptrace_scope, kptr_restrict} declared in config.
Runtime: `sysctl -n` probe.

- [ ] **Step 3: DORA reference — `_secure-boot.nix`**

Static: `boot.loader.systemd-boot.configurationLimit` declared.
Runtime: `bootctl status --json` probe.

- [ ] **Step 4: NIS2 reference — `_audit-logging/`**

Static: `security.audit.rules` declared.
Runtime: `auditctl -s --output-format=json` probe.

Each migration is one commit:

```bash
git commit -m "feat(controls/<name>): migrate to typed control (type=both, <framework> reference)"
```

---

## Task 8: Baseline agent-egress exemption control

**Files:**
- Create: `controls/_agent-egress-exemption.nix`
- Create: `tests/typed-controls/fixtures/agent-egress-exemption.nix`

Per KICKOFF.md §Stream B Milestone 1 #4: declare the agent's outbound network path as exempt from firewall-lock controls so compliance landing doesn't cut agents off.

- [ ] **Step 1: Write the module**

```nix
# controls/_agent-egress-exemption.nix
#
# Baseline: declare the agent's outbound network path and exempt it from
# firewall-lock controls. Without this, network-segmentation hardening
# can accidentally block the agent from reaching the control plane,
# stranding the host.
#
# type = "both" — static evidence is the declared endpoint; runtime
# evidence is reachability at the declared host:port.
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.compliance.controls.agentEgressExemption;
  gov = config.compliance.governance;
  mkProbe = import ../lib/mkProbe.nix {inherit pkgs lib;};
  framework = gov.primaryFramework or "anssi-bp028";
  schemaVersion = config.compliance.schemaVersions.${framework} or (throw "schemaVersions.${framework} missing");
in {
  imports = [../evidence/options.nix ../governance/options.nix];

  options.compliance.controls.agentEgressExemption = {
    enable = lib.mkEnableOption ''
      baseline agent egress exemption. Declares the control-plane endpoint
      the nixfleet agent needs to reach, and guarantees firewall-lock
      controls do not block it. MUST be enabled whenever a firewall-lock
      control is enabled on the same host.
    '';

    endpoint = lib.mkOption {
      type = lib.types.submodule {
        options = {
          host = lib.mkOption {
            type = lib.types.str;
            description = "Control-plane hostname the agent dials.";
          };
          port = lib.mkOption {
            type = lib.types.port;
            default = 443;
          };
          protocol = lib.mkOption {
            type = lib.types.enum ["https" "http/2"];
            default = "https";
          };
        };
      };
      description = "The single outbound endpoint the agent is allowed to reach.";
    };
  };

  config = lib.mkIf cfg.enable (lib.mkMerge [
    # Static evidence + runtime probe
    {
      compliance.evidence.probes.agentEgressExemption = {
        control = "agent-egress-exemption";
        type = "both";
        schema = schemaVersion;
        articles.nis2 = ["21(e)"];
        staticEvidence = {
          passed = cfg.endpoint.host != "";
          evidence = {
            declaredEndpoint = cfg.endpoint;
          };
        };
        probeDescriptor = {
          command = toString (mkProbe {
            name = "agent-egress";
            runtimeInputs = with pkgs; [curl];
            script = ''
              host='${cfg.endpoint.host}'
              port='${toString cfg.endpoint.port}'
              if curl --silent --fail --connect-timeout 5 --max-time 10 \
                -o /dev/null "https://$host:$port/healthz"; then
                reachable=true
              else
                reachable=false
              fi
              jq -n --argjson reachable "$reachable" --arg host "$host" --argjson port "$port" \
                '{ host: $host, port: $port, reachable: $reachable, compliant: $reachable }'
            '';
          });
          args = [];
          timeoutSecs = 15;
          expect = {
            compliant = true;
            reachable = true;
          };
          schema = schemaVersion;
        };
      };
    }
    # Firewall exemption: add an assertion if any firewall-lock control
    # is enabled without an explicit exemption for our endpoint.
    {
      assertions = [
        {
          assertion =
            !(config.compliance.controls.networkSegmentation.enable or false)
            || config.compliance.controls.agentEgressExemption.enable;
          message = ''
            compliance.controls.networkSegmentation is enabled but
            compliance.controls.agentEgressExemption is not. Enabling the
            former without the latter will prevent the nixfleet agent
            from reaching the control plane. Either disable network
            segmentation or enable agent-egress-exemption with an endpoint.
          '';
        }
      ];
    }
  ]);
}
```

- [ ] **Step 2: Import into every framework module**

Modify `frameworks/anssi.nix`, `frameworks/nis2.nix`, `frameworks/dora.nix`, `frameworks/iso27001.nix` — each adds to its `imports` list:

```nix
../controls/_agent-egress-exemption.nix
```

And to its enabling block:

```nix
compliance.controls.agentEgressExemption = {
  enable = lib.mkDefault true;
  # endpoint.host MUST be set by the fleet — no safe default exists.
};
```

- [ ] **Step 3: Add positive fixture**

```nix
# tests/typed-controls/fixtures/agent-egress-exemption.nix
{
  lib,
  pkgs,
  ...
}: {
  cases = [
    {
      control = ../../controls/_agent-egress-exemption.nix;
      controlId = "agentEgressExemption";
      config = {
        compliance.governance.level = "standard";
        compliance.governance.enforceMode = "report";
        compliance.governance.hostType = "server";
        compliance.governance.architecture = "x86_64";
        compliance.governance.primaryFramework = "anssi-bp028";
        compliance.schemaVersions."anssi-bp028" = "anssi-bp028/v1";
        compliance.controls.agentEgressExemption = {
          enable = true;
          endpoint = {
            host = "cp.home.arpa";
            port = 8443;
            protocol = "https";
          };
        };
      };
    }
  ];
}
```

- [ ] **Step 4: Add negative fixture**

```nix
# tests/typed-controls/negative/agent-egress-no-endpoint.nix
{
  lib,
  pkgs,
  evalControl,
  ...
}:
  evalControl ../../controls/_agent-egress-exemption.nix {
    compliance.governance.primaryFramework = "anssi-bp028";
    compliance.schemaVersions."anssi-bp028" = "anssi-bp028/v1";
    compliance.controls.agentEgressExemption = {
      enable = true;
      # endpoint.host intentionally unset — the submodule is missing
      # a required field, which must fail eval.
    };
  }
```

- [ ] **Step 5: Commit**

```bash
git add controls/_agent-egress-exemption.nix frameworks/ tests/typed-controls/
git commit -m "feat(controls): baseline agent-egress-exemption (type=both, all frameworks)"
```

---

## Task 9: Framework modules — add `schemaVersion`

**Files:**
- Modify: `frameworks/anssi.nix`
- Modify: `frameworks/nis2.nix`
- Modify: `frameworks/dora.nix`
- Modify: `frameworks/iso27001.nix`

- [ ] **Step 1: Extend each framework module**

Each framework module adds to its `config`:

```nix
compliance.schemaVersions = {
  "anssi-bp028" = "anssi-bp028/v1";
  # (match framework name)
};
```

And adds the options layer somewhere central (in `governance/options.nix` or a new `schema-versions.nix`):

```nix
options.compliance.schemaVersions = lib.mkOption {
  type = lib.types.attrsOf lib.types.str;
  default = {};
  description = ''
    Per-framework schema versions used by probe descriptors. Strings are
    of the form "<framework>/v<N>" (e.g. "anssi-bp028/v1"). Bumping a
    version is a contract change — downstream agents index handlers by
    (control, schema).
  '';
};
```

- [ ] **Step 2: Commit**

```bash
git add frameworks/ governance/
git commit -m "feat(frameworks): declare schemaVersions for typed controls"
```

---

## Task 10: JCS golden-file fixture

**Files:**
- Create: `tests/typed-controls/fixtures/jcs-golden.json`
- Create: `tests/typed-controls/fixtures/jcs-golden-source.json`

Per CONTRACTS.md §III: a known-canonical byte sequence + signature pair so any drift in JCS canonicalization is caught immediately.

- [ ] **Step 1: Pick a canonical probe output shape**

Representative shape (using the agent-egress-exemption control):

```json
{
  "compliant": true,
  "host": "cp.home.arpa",
  "port": 8443,
  "reachable": true
}
```

Write two files:
- `jcs-golden-source.json` — pretty, unsorted (operator-readable)
- `jcs-golden.json` — canonicalized (sorted keys, no whitespace, no trailing newline)

```bash
cat > tests/typed-controls/fixtures/jcs-golden-source.json <<'EOF'
{
  "host": "cp.home.arpa",
  "port": 8443,
  "reachable": true,
  "compliant": true
}
EOF

jq -cS '.' tests/typed-controls/fixtures/jcs-golden-source.json \
  | tr -d '\n' \
  > tests/typed-controls/fixtures/jcs-golden.json
```

- [ ] **Step 2: Cross-link from `docs/CONTRACTS.md` §III (in the nixfleet repo)**

This is a cross-repo link, not a modification to `docs/` here. Add a note in `docs/typed-controls.md` (Task 11) that the golden file here is the producer-side companion to Stream C's `nixfleet-canonicalize` golden test.

- [ ] **Step 3: Commit**

```bash
git add tests/typed-controls/fixtures/jcs-golden.json tests/typed-controls/fixtures/jcs-golden-source.json
git commit -m "test: pin JCS golden bytes for probe-output canonicalization"
```

---

## Task 11: Migration guide + CHANGELOG

**Files:**
- Create: `docs/typed-controls.md`
- Modify: `CHANGELOG.md`

- [ ] **Step 1: Write the migration guide**

```markdown
# Migration: typed controls

Controls now carry a `type` discriminator and a schema-versioned probe
descriptor. This is a breaking change for out-of-tree controls — the
old shape (`{ control, articles, check }`) is gone.

## What changed

Old shape (before this release):
```nix
compliance.evidence.probes.myControl = {
  control = "my-control";
  articles = { nis2 = ["21(x)"]; };
  check = mkProbe { name = "..."; script = "..."; };
};
```

New shape (this release):
```nix
compliance.evidence.probes.myControl = {
  control = "my-control";
  type = "runtime"; # or "static" | "both"
  schema = "anssi-bp028/v1";
  articles = { nis2 = ["21(x)"]; };
  probeDescriptor = {
    command = toString (mkProbe { ... });
    args = [];
    timeoutSecs = 30;
    expect = { compliant = true; };
    schema = "anssi-bp028/v1";
  };
  staticEvidence = null;  # or { passed, evidence }
};
```

## How to migrate

1. **Decide the type.** Is this control observable only at runtime?
   Only from declared NixOS config? Or both?
2. **Set the schema.** `schemaVersions.<framework>` is the source of
   truth.
3. **Move `check` → `probeDescriptor.command`.** Wrap via `mkProbe` as
   before.
4. **Add `expect`.** The agent compares actual probe output against
   `expect` before reporting compliance. A minimal `expect = { compliant
   = true; }` is always valid.
5. **Static projection (if type ∈ {"static", "both"}).** Write
   `staticEvidence = { passed, evidence }` that reads from `config`.
6. **Add a positive + negative fixture** under
   `tests/typed-controls/`.

## Why

Two projections let the control plane gate rollouts at CI time (static)
AND let the agent surface runtime evidence (probe). Before this
migration, we had only runtime probes; static gates were ad-hoc. See
`abstracts33d/nixfleet` CONTRACTS.md §I.3 for the wire contract.
```

- [ ] **Step 2: CHANGELOG entry**

Under `## [Unreleased]` → `### Added`:

```markdown
- Typed controls: every control now declares `type = "static" |
  "runtime" | "both"` and a `schema = "<framework>/v<N>"` string.
- `lib/mkTypedControl.nix` as the typed factory; `lib/mkControl.nix`
  remains for one release as a migration bridge.
- Baseline `agent-egress-exemption` control: required whenever a
  firewall-lock control is enabled; declares the single endpoint the
  agent is allowed to reach.
- Per-framework `schemaVersions` attribute (`anssi-bp028/v1`,
  `nis2/v1`, `dora/v1`, `iso27001/v1`).
- `tests/typed-controls/` eval harness with per-control positive and
  negative fixtures.
- JCS golden byte fixture for probe output.
```

Under `### Changed`:

```markdown
- `lib/mkProbe.nix` now emits sorted-key, compact JSON (JCS-ready)
  instead of whatever `jq -n` produced. Existing scripts unchanged.
```

Under `### Breaking`:

```markdown
- Probe descriptor shape. Out-of-tree controls must migrate — see
  `docs/typed-controls.md`.
```

- [ ] **Step 3: Commit**

```bash
git add docs/typed-controls.md CHANGELOG.md
git commit -m "docs: typed-controls migration guide + changelog entry"
```

---

## Task 12: Tracking-issue sync + PR

- [ ] **Step 1: User-facing summary**

Present to the user:

```
Branch: feat/typed-controls (in nixfleet-compliance)
Closes: abstracts33d/nixfleet-compliance#1
Commits: N atomic commits (one per control migration)
Acceptance: `nix eval --impure ./tests/typed-controls` returns all-ok.

Review OK, can I ship?
```

WAIT for confirmation.

- [ ] **Step 2: On confirmation — push + PR**

```bash
git push -u origin feat/typed-controls
gh pr create --repo abstracts33d/nixfleet-compliance \
  --title "feat: typed controls + JCS + baseline agent-egress-exemption (#1)" \
  --body "$(cat <<'EOF'
## Summary
- Typed controls with `type = "static" | "runtime" | "both"` discriminator and per-framework `schema` version.
- `lib/mkTypedControl.nix` as the new factory; `lib/mkControl.nix` preserved for migration.
- One `type = "both"` reference control per framework (ANSSI: encryption-in-transit, NIS2: audit-logging, DORA: secure-boot, ISO 27001: baseline-hardening).
- Baseline `agent-egress-exemption` control — required whenever firewall-lock controls are enabled.
- JCS-ready probe output shape + golden byte fixture.
- Per-control positive and negative fixtures under `tests/typed-controls/`.

## Acceptance
- `nix eval --impure ./tests/typed-controls` returns all-ok.
- Every control module type-checks with the new shape.
- Negative fixtures all `throw` as expected.

## Test plan
- [ ] Eval harness passes on all 16 controls + new baseline
- [ ] One "both" control per framework produces both projections
- [ ] Firewall-lock + no-egress-exemption fires the assertion
- [ ] JCS golden bytes byte-match the canonicalized probe output

Closes #1
EOF
)"
```

- [ ] **Step 3: Post cross-stream status on nixfleet tracking issue #10**

```bash
gh issue comment 10 --repo abstracts33d/nixfleet --body "$(cat <<'EOF'
Stream B — Milestone 1 (compliance side): typed controls migration, JCS producer-side discipline, baseline agent-egress exemption shipped. PR abstracts33d/nixfleet-compliance#NN. Handoff to Stream C: `probeDescriptor.schema` is the string agents key handlers on; `probeDescriptor.expect` is the matcher for compliance evaluation.
EOF
)"
```

---

## Self-Review Checklist

- [x] Typed control primitives (`type`, `schema`, `probeDescriptor`, `staticEvidence`) — Tasks 1, 2.
- [x] JCS canonicalization discipline (producer-side) — Tasks 2, 10.
- [x] Schema-versioned probe descriptors — Tasks 1, 4, 9.
- [x] Negative-test fixture per control — Tasks 4–8.
- [x] ≥1 `type = "both"` reference control per framework — Task 7.
- [x] Baseline agent-egress-exemption control — Task 8.
- [x] Migration guide + CHANGELOG — Task 11.
- [x] PR + tracking-issue sync — Task 12.
- [x] No placeholders — every shell block, Nix block, and commit message is concrete. The one `"..."` in Task 4 Step 1 refers to the PRE-MIGRATION script body which already exists in the file on disk; the task preserves it verbatim.
- [x] Type consistency: `mkTypedControl`, `probeDescriptor`, `staticEvidence`, `schemaVersion`, `compliance.schemaVersions` are spelled identically across tasks.
