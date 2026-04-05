# frameworks/nis2.nix
#
# NIS2 Directive (2022/2555) compliance framework.
# Activates controls with NIS2-specific defaults.
# Differentiates between "essential" and "important" entity types.
{
  config,
  lib,
  ...
}: let
  cfg = config.compliance.frameworks.nis2;
  isEssential = cfg.entityType == "essential";
in {
  imports = [
    ../controls/_supply-chain.nix
    ../controls/_asset-inventory.nix
    ../controls/_encryption-at-rest.nix
    ../controls/_access-control.nix
  ];

  options.compliance.frameworks.nis2 = {
    enable = lib.mkEnableOption "NIS2 directive compliance (Directive 2022/2555)";

    entityType = lib.mkOption {
      type = lib.types.enum ["essential" "important"];
      default = "important";
      description = ''
        NIS2 entity classification.
        Essential: energy, transport, banking, health, water, digital infra,
                   ICT service management, public admin, space.
        Important: postal, waste, chemicals, food, manufacturing, digital
                   providers, research.
        Essential entities face stricter audit obligations.
      '';
    };

    auditCycle = lib.mkOption {
      type = lib.types.str;
      default =
        if isEssential
        then "hourly"
        else "*-*-* 06:00:00";
      description = ''
        Systemd calendar expression for evidence collection frequency.
        Essential: hourly (continuous monitoring).
        Important: daily at 06:00 (periodic assessment).
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    compliance.controls = {
      supplyChain = {
        enable = true;
        sbomGeneration = true;
        inputStalenessWarningDays =
          if isEssential
          then 14
          else 30;
      };

      assetInventory.enable = true;

      encryptionAtRest = {
        enable = true;
        requireEncryptedSwap = true;
        requireTmpOnTmpfs = true;
      };

      accessControl = {
        enable = true;
        passwordAuthDisabled = true;
        rootLoginDisabled = true;
        idleTimeoutMinutes =
          if isEssential
          then 15
          else 30;
      };
    };

    compliance.evidence.collector.interval = lib.mkDefault cfg.auditCycle;
  };
}
