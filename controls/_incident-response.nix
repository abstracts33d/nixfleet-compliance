# controls/_incident-response.nix
#
# Incident response — Art. 21(b).
# No enforcement: incident response tooling is fleet-specific.
# Verifies: rollback readiness (boot generations), journal availability,
# generation age for log retention assessment.
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.compliance.controls.incidentResponse;
  mkProbe = import ../lib/mkProbe.nix {inherit pkgs lib;};
in {
  imports = [../evidence/options.nix];

  options.compliance.controls.incidentResponse = {
    enable = lib.mkEnableOption "incident response compliance control (NIS2 Art. 21(b))";

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
      articles = {
        nis2 = ["21(b)"];
        iso27001 = ["A.16"];
        dora = ["Art. 17"];
      };
      check = mkProbe {
        name = "incident-response";
        runtimeInputs = with pkgs; [coreutils];
        script = ''
          nixos_generations_available=$(ls /nix/var/nix/profiles/system-*-link 2>/dev/null | wc -l)

          current_generation=$(basename $(readlink /nix/var/nix/profiles/system) | grep -oP '\d+' || echo "unknown")

          oldest_generation_days="unknown"
          oldest_link=$(ls -1t /nix/var/nix/profiles/system-*-link 2>/dev/null | tail -1)
          if [ -n "$oldest_link" ]; then
            oldest_epoch=$(stat -c '%Y' "$oldest_link")
            now=$(date +%s)
            oldest_generation_days=$(( (now - oldest_epoch) / 86400 ))
          fi

          rollback_available=$([ "$nixos_generations_available" -gt 1 ] 2>/dev/null && echo "true" || echo "false")

          journal_available=$(journalctl -n 1 --no-pager >/dev/null 2>&1 && echo "true" || echo "false")

          jq -n \
            --argjson nixos_generations_available "$nixos_generations_available" \
            --arg current_generation "$current_generation" \
            --arg oldest_generation_days "$oldest_generation_days" \
            --argjson rollback_available "$rollback_available" \
            --argjson journal_available "$journal_available" \
            '{
              nixos_generations_available: $nixos_generations_available,
              current_generation: $current_generation,
              oldest_generation_days: $oldest_generation_days,
              rollback_available: $rollback_available,
              journal_available: $journal_available
            }'
        '';
      };
    };
  };
}
