# controls/_disaster-recovery.nix
#
# Disaster recovery — Art. 21(c).
# Enforces: nix keep-outputs for generation retention.
# Verifies: generation count against minimum, generation ages,
# system uptime, RTO target.
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.compliance.controls.disasterRecovery;
  mkProbe = import ../lib/mkProbe.nix {inherit pkgs lib;};
in {
  imports = [../evidence/options.nix];

  options.compliance.controls.disasterRecovery = {
    enable = lib.mkEnableOption "disaster recovery compliance control (NIS2 Art. 21(c))";

    minGenerations = lib.mkOption {
      type = lib.types.int;
      default = 5;
      description = "Minimum number of boot generations to keep";
    };

    rtoTarget = lib.mkOption {
      type = lib.types.str;
      default = "24h";
      description = "Target recovery time objective (informational)";
    };

    testInterval = lib.mkOption {
      type = lib.types.str;
      default = "quarterly";
      description = "Disaster recovery test interval (informational)";
    };
  };

  config = lib.mkIf cfg.enable {
    nix.settings.keep-outputs = lib.mkDefault true;

    compliance.evidence.collector.enable = lib.mkDefault true;

    compliance.evidence.probes.disasterRecovery = {
      control = "disaster-recovery";
      articles = {
        nis2 = ["21(c)"];
        iso27001 = ["A.17"];
        dora = ["Art. 12"];
      };
      check = mkProbe {
        name = "disaster-recovery";
        runtimeInputs = with pkgs; [coreutils];
        script = ''
          generations_count=$(ls /nix/var/nix/profiles/system-*-link 2>/dev/null | wc -l)

          meets_min_generations=$([ "$generations_count" -ge ${toString cfg.minGenerations} ] 2>/dev/null && echo "true" || echo "false")

          newest_generation_age_hours="unknown"
          newest_link=$(ls -1t /nix/var/nix/profiles/system-*-link 2>/dev/null | head -1)
          if [ -n "$newest_link" ]; then
            newest_epoch=$(stat -c '%Y' "$newest_link")
            now=$(date +%s)
            newest_generation_age_hours=$(( (now - newest_epoch) / 3600 ))
          fi

          oldest_generation_age_days="unknown"
          oldest_link=$(ls -1t /nix/var/nix/profiles/system-*-link 2>/dev/null | tail -1)
          if [ -n "$oldest_link" ]; then
            oldest_epoch=$(stat -c '%Y' "$oldest_link")
            now=$(date +%s)
            oldest_generation_age_days=$(( (now - oldest_epoch) / 86400 ))
          fi

          rto_target="${cfg.rtoTarget}"

          system_uptime_hours=$(awk '{printf "%.0f", $1/3600}' /proc/uptime 2>/dev/null || echo "unknown")

          jq -n \
            --argjson generations_count "$generations_count" \
            --argjson meets_min_generations "$meets_min_generations" \
            --arg newest_generation_age_hours "$newest_generation_age_hours" \
            --arg oldest_generation_age_days "$oldest_generation_age_days" \
            --arg rto_target "$rto_target" \
            --arg system_uptime_hours "$system_uptime_hours" \
            '{
              generations_count: $generations_count,
              meets_min_generations: $meets_min_generations,
              newest_generation_age_hours: $newest_generation_age_hours,
              oldest_generation_age_days: $oldest_generation_age_days,
              rto_target: $rto_target,
              system_uptime_hours: $system_uptime_hours
            }'
        '';
      };
    };
  };
}
