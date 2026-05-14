# controls/_backup-retention.nix
#
# Backup retention - Art. 21(c). No enforcement: backup wiring is the
# consumer's job. Topology-aware: hosts that *receive* backups
# (services.restic.server.enable, services.borgbackup.repos) are
# attested as compliant by definition -- clients attest data freshness
# via their probes. Clients query their backup-shaped service unit's
# last `Result=success` + `InactiveEnterTimestamp` instead of looking
# for archive files in /var/lib/nixfleet-backup (which holds only the
# restic cache on a centralized push setup).
#
# Typed control: type="both". Emits a CONTRACTS §I.3 probeDescriptor
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

  serviceNames = builtins.attrNames (config.systemd.services or {});
  timerNames = builtins.attrNames (config.systemd.timers or {});
  allUnitNames = serviceNames ++ timerNames;

  # Server-side unit shapes: a host *receiving* backups. Detect by name
  # because consumers wire restic-rest-server / borgbackup-repo via custom
  # modules as often as via the upstream NixOS options, and the typed
  # options miss the custom path.
  isBackupServerUnit = n: let
    lower = lib.toLower n;
  in
    lib.hasInfix "rest-server" lower
    || lib.hasInfix "server-prune" lower
    || lib.hasInfix "borgbackup-repo" lower;

  # Init / one-shot units that are NOT recurring backups; excluded so the
  # client-unit list doesn't pick up something like `restic-repo-init`
  # (runs once at provisioning, then dormant).
  isBackupInitUnit = n: let
    lower = lib.toLower n;
  in
    lib.hasSuffix "-init" lower
    || lib.hasInfix "-init-" lower
    || lib.hasSuffix "-bootstrap" lower
    || lib.hasInfix "-bootstrap-" lower;

  isBackupy = n: let
    lower = lib.toLower n;
  in
    lib.hasInfix "backup" lower
    || lib.hasInfix "restic" lower
    || lib.hasInfix "borg" lower;

  # Topology: server detection covers both the upstream typed options
  # AND any declared server-shaped unit (custom modules count too).
  isBackupServer =
    (config.services.restic.server.enable or false)
    || ((config.services.borgbackup.repos or {}) != {})
    || lib.any isBackupServerUnit allUnitNames;

  isClientBackupName = n:
    isBackupy n
    && !(isBackupServerUnit n)
    && !(isBackupInitUnit n);

  hasBackupShapedUnit = lib.any isBackupy allUnitNames;
  clientBackupUnits = lib.filter isClientBackupName serviceNames;

  resticBackupsConfigured =
    (config.services.restic.backups or {}) != {};
  borgJobsConfigured =
    (config.services.borgbackup.jobs or {}) != {};
  backupIntentDeclared =
    isBackupServer
    || hasBackupShapedUnit
    || resticBackupsConfigured
    || borgJobsConfigured;

  # The probe inspects systemd unit state directly -- `Result=success`
  # plus `InactiveEnterTimestamp` for oneshots -- instead of grovelling
  # for backup files in `/var/lib/nixfleet-backup`. The old approach
  # broke on every centralized topology: clients hold a restic cache
  # (no archives), servers hold archives under a different path. Unit
  # state is the source of truth about whether the last run succeeded.
  clientUnitList = lib.concatStringsSep " " clientBackupUnits;

  probeScript = mkProbe {
    name = "backup-retention";
    runtimeInputs = with pkgs; [systemd coreutils];
    script = ''
      retention_policy_days=${toString cfg.retentionDays}
      max_backup_age_hours="${toString cfg.maxBackupAgeHours}"
      is_server="${
        if isBackupServer
        then "true"
        else "false"
      }"

      if [ "$is_server" = "true" ]; then
        # Backup destination -- clients attest data freshness via their probes.
        jq -n \
          --argjson compliant true \
          --argjson retention_policy_days "$retention_policy_days" \
          '{compliant: $compliant, role: "server", retention_policy_days: $retention_policy_days}'
        exit 0
      fi

      # Client path: pick the first declared backup-shaped service and
      # check its last-run state. Empty list = no client backup wired.
      declared_units="${clientUnitList}"
      service_unit=""
      for u in $declared_units; do
        case "$u" in
          *.service) service_unit="$u"; break ;;
          *) service_unit="$u.service"; break ;;
        esac
      done

      if [ -z "$service_unit" ]; then
        jq -n \
          --argjson compliant false \
          --argjson retention_policy_days "$retention_policy_days" \
          '{compliant: $compliant, role: "client", reason: "no backup-shaped service unit declared"}'
        exit 0
      fi

      result=$(systemctl show "$service_unit" --property=Result --value 2>/dev/null)
      inactive_ts=$(systemctl show "$service_unit" --property=InactiveEnterTimestamp --value 2>/dev/null)

      # Fall back to the timer's last-trigger when the service hasn't run
      # since boot -- `Result` is "success" by default for an inactive unit
      # and `InactiveEnterTimestamp` is empty until the unit has actually
      # finished a run. On a freshly-rebooted host this would otherwise
      # mis-report "result=success but InactiveEnterTimestamp unparseable".
      last_run_age_hours="unknown"
      ts_source=""
      if [ -n "$inactive_ts" ]; then
        ts_epoch=$(date -d "$inactive_ts" +%s 2>/dev/null || echo 0)
        if [ "$ts_epoch" -gt 0 ]; then
          now_epoch=$(date +%s)
          last_run_age_hours=$(( (now_epoch - ts_epoch) / 3600 ))
          ts_source="service.InactiveEnterTimestamp"
        fi
      fi
      if [ "$last_run_age_hours" = "unknown" ]; then
        timer_unit="''${service_unit%.service}.timer"
        last_trigger=$(systemctl show "$timer_unit" --property=LastTriggerUSec --value 2>/dev/null)
        if [ -n "$last_trigger" ] && [ "$last_trigger" != "0" ] && [ "$last_trigger" != "n/a" ]; then
          ts_epoch=$(date -d "$last_trigger" +%s 2>/dev/null || echo 0)
          if [ "$ts_epoch" -gt 0 ]; then
            now_epoch=$(date +%s)
            last_run_age_hours=$(( (now_epoch - ts_epoch) / 3600 ))
            ts_source="timer.LastTriggerUSec"
          fi
        fi
      fi

      compliant=false
      reason=""
      if [ "$result" = "success" ]; then
        if [ "$last_run_age_hours" = "unknown" ]; then
          reason="no recorded run since boot (service.InactiveEnterTimestamp + timer.LastTriggerUSec both empty)"
        elif [ "$last_run_age_hours" -gt "$max_backup_age_hours" ]; then
          reason="last run $last_run_age_hours h ago > $max_backup_age_hours h (source: $ts_source)"
        else
          compliant=true
        fi
      elif [ -z "$result" ] || [ "$result" = "" ]; then
        reason="unit $service_unit not present at runtime"
      else
        reason="last run Result=$result"
      fi

      jq -n \
        --arg unit "$service_unit" \
        --arg result "$result" \
        --arg last_run_age_hours "$last_run_age_hours" \
        --arg ts_source "$ts_source" \
        --argjson retention_policy_days "$retention_policy_days" \
        --argjson compliant "$compliant" \
        --arg reason "$reason" \
        '{compliant: $compliant, role: "client", unit: $unit, result: $result, last_run_age_hours: $last_run_age_hours, ts_source: $ts_source, retention_policy_days: $retention_policy_days, reason: $reason}'
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
        # Predicate: a backup mechanism is declared -- as a destination
        # (server) or as a client. Freshness is the runtime probe's
        # concern; the static gate just catches "operator forgot to
        # wire backups at all" (issue #11).
        passed = backupIntentDeclared;
        evidence = {
          isBackupServer = isBackupServer;
          hasBackupShapedUnit = hasBackupShapedUnit;
          clientBackupUnits = clientBackupUnits;
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
