# controls/_backup-retention.nix
#
# Backup retention - Art. 21(c).
# No enforcement: backup setup is the fleet's job.
# Verifies: backup service existence, last backup age, retention policy,
# timer state. Works with or without nixfleet's _backup scope.
#
# Typed control: type="runtime". Emits a CONTRACTS §I.3 probeDescriptor
# alongside the legacy `check` script for evidence collector backward
# compatibility.
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.compliance.controls.backupRetention;
  gov = config.compliance.governance;
  mkProbe = import ../lib/mkProbe.nix {inherit pkgs lib;};
  framework = gov.primaryFramework or "anssi-bp028";
  schemaVersion =
    config.compliance.schemaVersions.${framework}
    or (throw "compliance.schemaVersions.${framework} is not set");

  # Static predicate inputs — mirror the runtime probe's first
  # gate (`backup_timer_active || backup_service_exists`). The
  # runtime probe greps systemd units for "backup" via
  # `systemctl list-units`. Statically we widen the search to
  # cover the typical NixOS backup flavors that ship custom unit
  # names without a literal "backup" substring (e.g. restic-server,
  # borgbackup-* jobs, etc.) — the runtime probe should follow.
  serviceNames = builtins.attrNames (config.systemd.services or {});
  timerNames = builtins.attrNames (config.systemd.timers or {});
  allUnitNames = serviceNames ++ timerNames;
  hasBackupShapedUnit = lib.any (
    n: let
      lower = lib.toLower n;
    in
      lib.hasInfix "backup" lower
      || lib.hasInfix "restic" lower
      || lib.hasInfix "borg" lower
  )
  allUnitNames;
  # Native NixOS option signals — accepted as additional positive
  # evidence even if no service/timer matches the name heuristic
  # (e.g. an operator using a wholly-custom backup mechanism that
  # happens to flip these flags on without touching unit names).
  resticBackupsConfigured =
    (config.services.restic.backups or {}) != {};
  borgJobsConfigured =
    (config.services.borgbackup.jobs or {}) != {};
  backupIntentDeclared =
    hasBackupShapedUnit
    || resticBackupsConfigured
    || borgJobsConfigured;

  probeScript = mkProbe {
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
      max_backup_age_hours="${toString cfg.maxBackupAgeHours}"

      if systemctl list-timers --all 2>/dev/null | grep -qi "backup"; then
        backup_timer_active=true
      else
        backup_timer_active=false
      fi

      if [ "$backup_timer_active" = "true" ] || [ "$backup_service_exists" = "true" ]; then
        if [ "$last_backup_age_hours" = "unknown" ]; then
          # Timer/service exists but no backup files found - not compliant
          compliant=false
        elif [ "''${last_backup_age_hours:-0}" -gt "$max_backup_age_hours" ]; then
          compliant=false
        else
          compliant=true
        fi
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
in {
  imports = [../evidence/options.nix ../governance/options.nix];

  options.compliance.controls.backupRetention = {
    enable = lib.mkEnableOption "backup retention compliance control (NIS2 Art. 21(c))";
    enforce = lib.mkOption {
      type = lib.types.bool;
      default = gov.enforceMode == "enforce";
      description = "Apply NixOS configuration. When false, only probes run.";
    };

    retentionDays = lib.mkOption {
      type = lib.types.int;
      default = 365;
      description = "Required backup retention period in days";
    };

    maxBackupAgeHours = lib.mkOption {
      type = lib.types.int;
      default = 48;
      description = "Maximum hours since last backup before marking non-compliant";
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
      type = "both";
      schema = schemaVersion;
      articles = {
        nis2 = ["21(c)"];
        iso27001 = ["A.8.13"];
        dora = ["Art. 12"];
      };
      check = probeScript;
      staticEvidence = {
        # Predicate: some declared backup mechanism is wired on this
        # host. Mirrors the runtime probe's `backup_timer_active ||
        # backup_service_exists` first gate, but widened to recognise
        # the common NixOS backup flavors (restic, borg) by name OR
        # by typed-options presence. Backup *freshness* (last backup
        # ≤ maxBackupAgeHours) is intentionally NOT in the static
        # predicate — it's a fact about the world, runtime probe's
        # job. The previous `null` static gave operators no eval-
        # time signal that they'd forgotten to wire backups at all
        # — see issue #11.
        passed = backupIntentDeclared;
        evidence = {
          hasBackupShapedUnit = hasBackupShapedUnit;
          resticBackupsConfigured = resticBackupsConfigured;
          borgJobsConfigured = borgJobsConfigured;
          retentionDays = cfg.retentionDays;
          maxBackupAgeHours = cfg.maxBackupAgeHours;
          verifyInterval = cfg.verifyInterval;
        };
      };
      probeDescriptor = {
        command = toString probeScript;
        args = [];
        timeoutSecs = 30;
        expect = {compliant = true;};
        schema = schemaVersion;
      };
    };
  };
}
