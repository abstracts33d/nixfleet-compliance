# controls/_change-management.nix
#
# Change management — ISO 27001 A.12.1, DORA Art. 8.
# No enforcement: deployment policy is fleet-specific.
# Verifies: system age, rebuild freshness, generation frequency,
# NixOS version, last rebuild timestamp.
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.compliance.controls.changeManagement;
  mkProbe = import ../lib/mkProbe.nix {inherit pkgs lib;};
in {
  imports = [../evidence/options.nix];

  options.compliance.controls.changeManagement = {
    enable = lib.mkEnableOption "change management compliance control (ISO 27001 A.12.1)";

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
      articles = {
        iso27001 = ["A.12.1"];
        dora = ["Art. 8"];
        nis2 = ["21(e)"];
      };
      check = mkProbe {
        name = "change-management";
        runtimeInputs = with pkgs; [coreutils findutils];
        script = ''
          system_epoch=$(stat -c '%Y' /run/current-system 2>/dev/null || echo "0")
          now=$(date +%s)
          system_age_days=$(( (now - system_epoch) / 86400 ))

          system_fresh=$([ "$system_age_days" -le ${toString cfg.maxSystemAgeDays} ] 2>/dev/null && echo "true" || echo "false")

          generations_last_30_days=$(find /nix/var/nix/profiles/ -name 'system-*-link' -mtime -30 2>/dev/null | wc -l)

          current_nixos_version=$(cat /run/current-system/nixos-version 2>/dev/null || echo "unknown")

          last_rebuild_timestamp=$(date -d "@$system_epoch" --iso-8601=seconds 2>/dev/null || echo "unknown")

          jq -n \
            --argjson system_age_days "$system_age_days" \
            --argjson system_fresh "$system_fresh" \
            --argjson generations_last_30_days "$generations_last_30_days" \
            --arg current_nixos_version "$current_nixos_version" \
            --arg last_rebuild_timestamp "$last_rebuild_timestamp" \
            '{
              system_age_days: $system_age_days,
              system_fresh: $system_fresh,
              generations_last_30_days: $generations_last_30_days,
              current_nixos_version: $current_nixos_version,
              last_rebuild_timestamp: $last_rebuild_timestamp
            }'
        '';
      };
    };
  };
}
