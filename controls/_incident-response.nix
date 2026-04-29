# controls/_incident-response.nix
#
# Incident response - NIS2 Art. 21(b), ISO 27001 A.5.24/A.5.26, DORA Art. 17.
# No enforcement: incident response tooling is fleet-specific.
#
# Typed control: type="static". Predicate inspects whether the host has
# rollback infrastructure (bootloader retains previous generations) and
# the operator's declared alert retention is non-trivial. The previous
# predicate `passed = cfg.enable` was tautological - see issue #11.
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

  # Rollback headroom - bootloader retains ≥1 previous generation so
  # an operator can revert if a deploy goes bad. This is the
  # incident-response-flavoured read of "we kept a known-good state
  # for recovery". Mirrors the analogous check in change-management
  # (#11) - the two controls are different framing on the same
  # underlying property.
  configurationLimit = config.boot.loader.systemd-boot.configurationLimit or 0;
  hasRollbackInfrastructure = configurationLimit >= 1;
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
        # Predicate: rollback infrastructure present AND non-trivial
        # alert retention declared. The previous tautology `cfg.enable`
        # made the control a no-op - see issue #11.
        passed = hasRollbackInfrastructure && cfg.alertRetentionDays > 0;
        evidence = {
          hasRollbackInfrastructure = hasRollbackInfrastructure;
          configurationLimit = configurationLimit;
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
