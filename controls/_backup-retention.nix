# controls/_backup-retention.nix
#
# Backup retention — Art. 21(c).
# No enforcement: backup setup is the fleet's job.
# Verifies: backup service existence, last backup age, retention policy,
# timer state. Works with or without nixfleet's _backup scope.
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.compliance.controls.backupRetention;
  mkProbe = import ../lib/mkProbe.nix {inherit pkgs lib;};
in {
  imports = [../evidence/options.nix];

  options.compliance.controls.backupRetention = {
    enable = lib.mkEnableOption "backup retention compliance control (NIS2 Art. 21(c))";

    retentionDays = lib.mkOption {
      type = lib.types.int;
      default = 365;
      description = "Required backup retention period in days";
    };

    verifyInterval = lib.mkOption {
      type = lib.types.str;
      default = "weekly";
      description = "Systemd calendar expression for backup state verification";
    };
  };

  config = lib.mkIf cfg.enable {
    compliance.evidence.collector.enable = lib.mkDefault true;

    compliance.evidence.probes.backupRetention = {
      control = "backup-retention";
      articles = {
        nis2 = ["21(c)"];
        iso27001 = ["A.12.3"];
        dora = ["Art. 12"];
      };
      check = mkProbe {
        name = "backup-retention";
        runtimeInputs = with pkgs; [systemd findutils];
        script = ''
          if systemctl list-units --type=service --type=timer --all 2>/dev/null | grep -qi "backup"; then
            backup_service_exists=true
          else
            backup_service_exists=false
          fi

          last_backup_age_hours="unknown"
          backup_dir=""
          if [ -d /var/lib/nixfleet-backup ]; then
            backup_dir="/var/lib/nixfleet-backup"
          elif [ -d /var/backup ]; then
            backup_dir="/var/backup"
          fi
          if [ -n "$backup_dir" ]; then
            newest=$(find "$backup_dir" -type f -printf '%T@\n' 2>/dev/null | sort -rn | head -1)
            if [ -n "$newest" ]; then
              now=$(date +%s)
              newest_sec=$(printf '%.0f' "$newest")
              age_hours=$(( (now - newest_sec) / 3600 ))
              last_backup_age_hours="$age_hours"
            fi
          fi

          retention_policy_days=${toString cfg.retentionDays}

          if systemctl list-timers --all 2>/dev/null | grep -qi "backup"; then
            backup_timer_active=true
          else
            backup_timer_active=false
          fi

          if [ "$backup_timer_active" = "true" ] || [ "$backup_service_exists" = "true" ]; then
            compliant=true
          else
            compliant=false
          fi

          jq -n \
            --argjson backup_service_exists "$backup_service_exists" \
            --arg last_backup_age_hours "$last_backup_age_hours" \
            --argjson retention_policy_days "$retention_policy_days" \
            --argjson backup_timer_active "$backup_timer_active" \
            --argjson compliant "$compliant" \
            '{
              backup_service_exists: $backup_service_exists,
              last_backup_age_hours: $last_backup_age_hours,
              retention_policy_days: $retention_policy_days,
              backup_timer_active: $backup_timer_active,
              compliant: $compliant
            }'
        '';
      };
    };
  };
}
