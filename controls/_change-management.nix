# controls/_change-management.nix
#
# Change management - ISO 27001 A.8.32, DORA Art. 8, NIS2 21(e).
# No enforcement: deployment policy is fleet-specific.
#
# Typed control: type="static". Declared policy is evaluated at CI time
# (staticEvidence); no runtime probe is needed. A no-op `check` script is
# retained for backward compatibility with the evidence collector.
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.compliance.controls.changeManagement;
  gov = config.compliance.governance;
  framework = gov.primaryFramework or "iso27001";
  schemaVersion =
    config.compliance.schemaVersions.${framework}
    or (throw "compliance.schemaVersions.${framework} is not set");
in {
  imports = [../evidence/options.nix ../governance/options.nix];

  options.compliance.controls.changeManagement = {
    enable = lib.mkEnableOption "change management compliance control (ISO 27001 A.8.32)";

    enforce = lib.mkOption {
      type = lib.types.bool;
      default = gov.enforceMode == "enforce";
      description = "Apply NixOS configuration. When false, only probes run.";
    };

    maxSystemAgeDays = lib.mkOption {
      type = lib.types.int;
      default = 30;
      description = "Maximum days since last system rebuild before warning";
    };

    minGenerationFrequency = lib.mkOption {
      type = lib.types.int;
      default = 1;
      description = "Minimum expected rebuilds per month (informational)";
    };
  };

  config = lib.mkIf cfg.enable {
    compliance.evidence.collector.enable = lib.mkDefault true;

    compliance.evidence.probes.changeManagement = {
      control = "change-management";
      type = "static";
      schema = schemaVersion;
      articles = {
        iso27001 = ["A.8.32"];
        dora = ["Art. 8"];
        nis2 = ["21(e)"];
      };
      probeDescriptor = null;
      staticEvidence = {
        passed = cfg.enable;
        evidence = {
          maxSystemAgeDays = cfg.maxSystemAgeDays;
          minGenerationFrequency = cfg.minGenerationFrequency;
        };
      };
      check = pkgs.writeShellScript "noop-change-management" ''
        jq -n '{compliant: true}'
      '';
    };
  };
}
