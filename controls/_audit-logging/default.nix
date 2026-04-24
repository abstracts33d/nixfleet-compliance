# controls/_audit-logging/default.nix
#
# Audit logging - Art. 21(b)(f).
# Uses mkControl with journald + auditd rules, plus control-level retention/forwarding options.
{
  config,
  lib,
  pkgs,
  ...
}: let
  mkControlMod = import ../../lib/mkControl.nix {
    controlId = "auditLogging";
    controlName = "audit-logging";
    controlDescription = "audit logging compliance control (NIS2 Art. 21(b)(f))";
    articles = {
      nis2 = ["21(b)" "21(f)"];
      iso27001 = ["A.8.15" "A.8.16"];
    };
    rules = import ./rules.nix;
  };
in {
  imports = [mkControlMod ./typed-augment.nix];

  options.compliance.controls.auditLogging = {
    retentionDays = lib.mkOption {
      type = lib.types.int;
      default = 365;
      description = "Log retention period in days";
    };

    forwardTo = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "Remote syslog endpoint for log forwarding";
    };

    adminEmail = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "Email for auditd disk space alerts (ANSSI R33)";
    };
  };
}
