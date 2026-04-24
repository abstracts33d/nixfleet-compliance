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
        {config = cfg;}
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
    lib.filter
    (n: lib.hasSuffix ".nix" n && !(lib.hasPrefix "_" n))
    (builtins.attrNames (builtins.readDir dir));

  positives = lib.concatMap (n: runFixture (./fixtures + "/${n}")) (listFixtures ./fixtures);
  negatives = map (n: runNegative (./negative + "/${n}")) (listFixtures ./negative);
in {
  results = positives ++ negatives;
}
