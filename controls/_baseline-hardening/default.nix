# controls/_baseline-hardening/default.nix
#
# Baseline hardening - Art. 21(a)(g).
# Uses mkControl with fine-grained rules implementing ANSSI R7-R14.
#
# Typed control: type="both" (reference "both"-type control for ISO
# 27001). The `mkControl` DSL generates per-rule options and the
# aggregated `check` probe; the sibling `typed-augment.nix` adds the
# typed fields (`type`, `schema`, `staticEvidence`, `probeDescriptor`)
# via module composition.
{
  imports = [
    (import ../../lib/mkControl.nix {
      controlId = "baselineHardening";
      controlName = "baseline-hardening";
      controlDescription = "baseline hardening compliance control (NIS2 Art. 21(a)(g))";
      articles = {
        nis2 = ["21(a)" "21(g)"];
        iso27001 = ["A.8.9" "A.8.8"];
      };
      rules = import ./rules.nix;
    })
    ./typed-augment.nix
  ];
}
