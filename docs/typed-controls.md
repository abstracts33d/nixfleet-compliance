# Migration: typed controls

Controls now carry a `type` discriminator and a schema-versioned probe
descriptor. This is a breaking change for out-of-tree controls — the
old shape (`{ control, articles, check }`) is extended with new
required fields for controls that want to participate in the typed
evidence pipeline.

## What changed

Old shape (pre-migration):

    compliance.evidence.probes.myControl = {
      control = "my-control";
      articles = { nis2 = ["21(x)"]; };
      check = mkProbe { name = "..."; script = "..."; };
    };

New shape (this release):

    compliance.evidence.probes.myControl = {
      control = "my-control";
      type = "runtime"; # or "static" | "both"
      schema = "anssi-bp028/v1";
      articles = { nis2 = ["21(x)"]; };
      check = mkProbe { ... };                # kept for backward compat
      probeDescriptor = {
        command = toString (mkProbe { ... });
        args = [];
        timeoutSecs = 30;
        expect = { compliant = true; };
        schema = "anssi-bp028/v1";
      };
      staticEvidence = null;                  # or { passed, evidence }
    };

## How to migrate

1. **Decide the type.**
   - `runtime` — evidence is observed on the host at runtime.
   - `static` — evidence is derivable from `config` at CI time.
   - `both` — static gate at CI + runtime probe on-host.

2. **Declare schema versions.** Set `compliance.schemaVersions.<framework> = "<framework>/v1"` for each framework your control claims articles in. This is the string the agent uses to route probe handlers.

3. **Move `check` into a `probeScript` let-binding.** Keep the `check = probeScript` attribute for evidence-collector backward compatibility. Reference `probeScript` from the new `probeDescriptor.command` field.

4. **Declare `expect`.** Agents compare actual probe output against `expect` before reporting compliance. Minimal `expect = { compliant = true; }` is always valid.

5. **Static projection (if type ∈ {"static", "both"}).** Compute `staticEvidence = { passed, evidence }` from `config` reads. Static evidence runs at CI time before any host is deployed.

6. **Add fixtures.** Positive under `tests/typed-controls/fixtures/<control>.nix`, negative under `tests/typed-controls/negative/<control>-<failure-mode>.nix`.

## Why

Two projections let the control plane gate rollouts at CI time (static) AND let the agent surface runtime evidence (probe). Before this migration, only runtime probes existed; static gates were ad-hoc. The wire contract for the `probeDescriptor` payload lives in [`abstracts33d/nixfleet` CONTRACTS.md §I.3](https://github.com/abstracts33d/nixfleet/blob/main/docs/CONTRACTS.md).

## JCS canonicalization

`lib/mkProbe.nix` emits sorted-key, compact JSON (JCS-ready) via `jq -cSj`. The canonical byte sequence for probe-output reference is pinned at `tests/typed-controls/fixtures/_jcs-golden.json` (69 bytes, no trailing newline).

## Baseline: agent egress exemption

If you enable a firewall-lock control (e.g. `networkSegmentation`), you MUST also enable `agentEgressExemption` with a declared `endpoint.host`. An assertion enforces this, and forgetting it will strand the agent.

## Breaking changes in this release

- Probe submodule in `evidence/options.nix` gains `type`, `schema`, `staticEvidence`, `probeDescriptor` fields (all `nullOr ... default = null`; existing controls keep working).
- New top-level option `compliance.schemaVersions`.
- New governance option `compliance.governance.primaryFramework` (default `"anssi-bp028"`).
- `mkProbe.nix` emits compact sorted-key JSON instead of whatever `jq -n` produced.
