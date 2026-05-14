# controls/_change-management.nix
#
# Change management - ISO 27001 A.8.32, DORA Art. 8, NIS2 21(e).
# No enforcement: deployment policy is fleet-specific.
#
# Typed control: type="static". Predicate inspects whether the host
# was built from a tracked source revision and has enough rollback
# headroom to satisfy a "could reproduce a previous state on demand"
# read of change-management. The previous predicate `passed = cfg.enable`
# was tautological -- see issue #11.
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

  # `system.configurationRevision` is non-null whenever the host was
  # built from a known git rev (NixOS exposes the revision via the
  # flake's `self.shortRev`/`self.rev`). nixfleet's CI sets it on
  # every build. Empty/null means we can't prove the running config
  # came from a reviewed commit -- which IS the property
  # change-management is meant to assert.
  configurationRevision = config.system.configurationRevision or null;
  hasTrackedRevision = configurationRevision != null && configurationRevision != "";

  # Bootloader configurationLimit gives rollback headroom -- the
  # operator can revert to N previous generations without rebuilding.
  # Used by change-management *and* disasterRecovery (#7); keeping a
  # local read here so the predicate is self-contained.
  # Same null-coercion as _disaster-recovery.nix (#14): NixOS option
  # default is null; `or 0` doesn't fire on null, so `null >= 1` throws.
  rawSdBoot = config.boot.loader.systemd-boot.configurationLimit or null;
  rawGrub = config.boot.loader.grub.configurationLimit or null;
  configurationLimit =
    if rawSdBoot != null
    then rawSdBoot
    else if rawGrub != null
    then rawGrub
    else 0;
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
        # Predicate: host was built from a tracked source revision
        # AND has rollback headroom (≥1 previous generation
        # retained). The previous tautology `cfg.enable` made the
        # control a no-op -- see issue #11.
        passed = hasTrackedRevision && configurationLimit >= 1;
        evidence = {
          hasTrackedRevision = hasTrackedRevision;
          configurationLimit = configurationLimit;
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
