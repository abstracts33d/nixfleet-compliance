# lib/mkTypedControl.nix
#
# Typed control factory. Discriminates on `type`:
#
#   "static"  - declared in NixOS config. Gated at CI time via
#               `evaluate :: config -> { passed, evidence }`.
#               No runtime probe.
#
#   "runtime" - observed on the host. `probeDescriptor` carries the
#               CONTRACTS §I.3 payload the agent executes.
#
#   "both"    - static evidence AT CI time + runtime probe on-host.
#               Both projections share the `schema` version.
#
# Composes with `mkControl.nix` via module imports. Reading
# `config.compliance.evidence.probes.${controlId}.check` works
# because the module system merges both contributions before
# attribute access is resolved.
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
  expect ? {},
  timeoutSecs ? 30,
}:
assert builtins.elem type ["static" "runtime" "both"];
assert (type != "runtime") -> evaluate != null;
  {
    config,
    lib,
    pkgs,
    ...
  }: let
    cfg = config.compliance.controls.${controlId};
    descriptorBuilder = (import ./probeDescriptor.nix {}).mkDescriptor;
    staticHelper = (import ./evaluateStatic.nix {}).runStatic;

    staticResult =
      if type == "runtime"
      then null
      else staticHelper evaluate config;

    runtimeDescriptor =
      if type == "static"
      then null
      else
        descriptorBuilder {
          command = config.compliance.evidence.probes.${controlId}.check;
          args = [];
          inherit timeoutSecs expect schema;
        };
  in {
    imports = [
      (import ./mkControl.nix {
        inherit controlId controlDescription articles extraOptions rules;
      })
    ];

    config = lib.mkIf cfg.enable {
      compliance.evidence.probes.${controlId} = {
        inherit type schema;
        staticEvidence = staticResult;
        probeDescriptor = runtimeDescriptor;
      };
    };
  }
