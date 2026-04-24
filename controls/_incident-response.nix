# controls/_incident-response.nix
#
# Incident response - NIS2 Art. 21(b), ISO 27001 A.5.24/A.5.26, DORA Art. 17.
# No enforcement: incident response tooling is fleet-specific.
#
# Typed control: type="static". Declared policy (rollback cadence, alert
# retention) is evaluated at CI time (staticEvidence); no runtime probe is
# needed. A no-op `check` script is retained for backward compatibility
# with the evidence collector.
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.compliance.controls.incidentResponse;
  gov = config.compliance.governance;
  framework = gov.primaryFramework or "nis2";
  schemaVersion =
    config.compliance.schemaVersions.${framework}
    or (throw "compliance.schemaVersions.${framework} is not set");
in {
  imports = [../evidence/options.nix ../governance/options.nix];

  options.compliance.controls.incidentResponse = {
    enable = lib.mkEnableOption "incident response compliance control (NIS2 Art. 21(b))";

    enforce = lib.mkOption {
      type = lib.types.bool;
      default = gov.enforceMode == "enforce";
      description = "Apply NixOS configuration. When false, only probes run.";
    };

    rollbackTestInterval = lib.mkOption {
      type = lib.types.str;
      default = "monthly";
      description = "Systemd calendar expression for rollback test scheduling (informational)";
    };

    alertRetentionDays = lib.mkOption {
      type = lib.types.int;
      default = 365;
      description = "Required alert/log retention period in days";
    };
  };

  config = lib.mkIf cfg.enable {
    compliance.evidence.collector.enable = lib.mkDefault true;

    compliance.evidence.probes.incidentResponse = {
      control = "incident-response";
      type = "static";
      schema = schemaVersion;
      articles = {
        nis2 = ["21(b)"];
        iso27001 = ["A.5.24" "A.5.26"];
        dora = ["Art. 17"];
      };
      probeDescriptor = null;
      staticEvidence = {
        passed = cfg.enable;
        evidence = {
          rollbackTestInterval = cfg.rollbackTestInterval;
          alertRetentionDays = cfg.alertRetentionDays;
        };
      };
      check = pkgs.writeShellScript "noop-incident-response" ''
        jq -n '{compliant: true}'
      '';
    };
  };
}
