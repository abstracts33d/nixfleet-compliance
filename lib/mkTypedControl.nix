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
}:
assert builtins.elem type ["static" "runtime" "both"];
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
      else
        descriptorBuilder {
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
