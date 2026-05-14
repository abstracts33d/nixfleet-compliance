# lib/evaluateStatic.nix
#
# Helper for `type = "static"` controls. A static control expresses its
# evidence as a pure function of the NixOS config, so it can run at CI
# time -- before any agent has been deployed -- as a rollout gate.
#
# Shape:
#   evaluate :: config -> { passed :: bool, evidence :: attrs }
#
# Used by `mkTypedControl` for controls whose state is fully declared in
# the flake (e.g. boot loader config, supply chain pins). Runtime
# controls omit this projection; `both`-typed controls provide both.
{}: {
  runStatic = evaluate: config: let
    result = evaluate config;
  in
    assert result ? passed;
    assert result ? evidence; result;
}
