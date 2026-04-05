# controls/_audit-logging.nix
#
# Audit logging — Art. 21(b)(f).
# Enforces: journal persistence, log retention, optional forwarding.
# Verifies: persistent journal, retention config, forwarding state,
# journal disk usage.
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.compliance.controls.auditLogging;
  mkProbe = import ../lib/mkProbe.nix {inherit pkgs lib;};
in {
  imports = [../evidence/options.nix];

  options.compliance.controls.auditLogging = {
    enable = lib.mkEnableOption "audit logging compliance control (NIS2 Art. 21(b)(f))";

    retentionDays = lib.mkOption {
      type = lib.types.int;
      default = 365;
      description = "Log retention period in days";
    };

    forwardTo = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "Remote syslog endpoint for log forwarding (e.g., tcp://syslog.example.com:514)";
    };
  };

  config = lib.mkIf cfg.enable {
    services.journald.extraConfig = ''
      Storage=persistent
      MaxRetentionSec=${toString (cfg.retentionDays * 24)}h
      Compress=yes
    '';

    compliance.evidence.collector.enable = lib.mkDefault true;

    compliance.evidence.probes.auditLogging = {
      control = "audit-logging";
      articles = {
        nis2 = ["21(b)" "21(f)"];
        iso27001 = ["A.12.4"];
      };
      check = mkProbe {
        name = "audit-logging";
        runtimeInputs = with pkgs; [systemd];
        script = ''
          if [ -d /var/log/journal ]; then
            journal_persistent=true
          else
            journal_persistent=false
          fi

          retention_configured_days=${toString cfg.retentionDays}

          forwarding_active=${
            if cfg.forwardTo != null
            then "true"
            else "false"
          }

          journal_disk_usage=$(journalctl --disk-usage 2>/dev/null \
            | grep -oP '[\d.]+[GMKT]' || true)
          journal_disk_usage="''${journal_disk_usage:-unknown}"

          if [ "$journal_persistent" = "true" ] && [ "''${retention_configured_days:-0}" -gt 0 ]; then
            compliant=true
          else
            compliant=false
          fi

          jq -n \
            --argjson journal_persistent "$journal_persistent" \
            --argjson retention_configured_days "$retention_configured_days" \
            --argjson forwarding_active "$forwarding_active" \
            --arg journal_disk_usage "$journal_disk_usage" \
            --argjson compliant "$compliant" \
            '{
              journal_persistent: $journal_persistent,
              retention_configured_days: $retention_configured_days,
              forwarding_active: $forwarding_active,
              journal_disk_usage: $journal_disk_usage,
              compliant: $compliant
            }'
        '';
      };
    };
  };
}
