# controls/_baseline-hardening/default.nix
#
# Baseline hardening - Art. 21(a)(g).
# Uses mkControl with fine-grained rules implementing ANSSI R7-R14.
import ../../lib/mkControl.nix {
  controlId = "baselineHardening";
  controlDescription = "baseline hardening compliance control (NIS2 Art. 21(a)(g))";
  articles = {
    nis2 = ["21(a)" "21(g)"];
    iso27001 = ["A.8.9" "A.8.8"];
  };
  rules = import ./rules.nix;
}
