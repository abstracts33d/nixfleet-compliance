# controls/_disaster-recovery.nix
#
# Disaster recovery - Art. 21(c).
# Enforces: nix keep-outputs for generation retention.
# Verifies: generation count against minimum, generation ages,
# system uptime, RTO target.
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
  cfg = config.compliance.controls.disasterRecovery;
  gov = config.compliance.governance;
  mkProbe = import ../lib/mkProbe.nix {inherit pkgs lib;};
  framework = gov.primaryFramework or "anssi-bp028";
  schemaVersion =
    config.compliance.schemaVersions.${framework}
    or (throw "compliance.schemaVersions.${framework} is not set");

  probeScript = mkProbe {
    name = "disaster-recovery";
    runtimeInputs = with pkgs; [coreutils];
    script = ''
      generations_count=$(find /nix/var/nix/profiles -maxdepth 1 -name 'system-*-link' 2>/dev/null | wc -l)
      generations_count="''${generations_count:-0}"
      # Count the active system as at least 1 generation
      if [ "$generations_count" -eq 0 ] && [ -e /run/current-system ]; then
        generations_count=1
      fi

      if [ "$generations_count" -ge ${toString cfg.minGenerations} ] 2>/dev/null; then
        meets_min_generations=true
      else
        meets_min_generations=false
      fi

      newest_generation_age_hours="unknown"
      newest_link=$(find /nix/var/nix/profiles -maxdepth 1 -name 'system-*-link' -printf '%T@ %p\n' 2>/dev/null | sort -rn | head -1 | awk '{print $2}')
      if [ -n "$newest_link" ]; then
        newest_epoch=$(stat -c '%Y' "$newest_link" 2>/dev/null || echo "0")
        now=$(date +%s)
        newest_generation_age_hours=$(( (now - newest_epoch) / 3600 ))
      fi

      oldest_generation_age_days="unknown"
      oldest_link=$(find /nix/var/nix/profiles -maxdepth 1 -name 'system-*-link' -printf '%T@ %p\n' 2>/dev/null | sort -n | head -1 | awk '{print $2}')
      if [ -n "$oldest_link" ]; then
        oldest_epoch=$(stat -c '%Y' "$oldest_link" 2>/dev/null || echo "0")
        now=$(date +%s)
        oldest_generation_age_days=$(( (now - oldest_epoch) / 86400 ))
      fi

      rto_target="${cfg.rtoTarget}"

      system_uptime_hours=$(awk '{printf "%.0f", $1/3600}' /proc/uptime 2>/dev/null || echo "unknown")

      compliant=$meets_min_generations

      jq -n \
        --argjson generations_count "$generations_count" \
        --argjson meets_min_generations "$meets_min_generations" \
        --arg newest_generation_age_hours "$newest_generation_age_hours" \
        --arg oldest_generation_age_days "$oldest_generation_age_days" \
        --arg rto_target "$rto_target" \
        --arg system_uptime_hours "$system_uptime_hours" \
        --argjson compliant "$compliant" \
        '{
          generations_count: $generations_count,
          meets_min_generations: $meets_min_generations,
          newest_generation_age_hours: $newest_generation_age_hours,
          oldest_generation_age_days: $oldest_generation_age_days,
          rto_target: $rto_target,
          system_uptime_hours: $system_uptime_hours,
          compliant: $compliant
        }'
    '';
  };
in {
  imports = [../evidence/options.nix ../governance/options.nix];

  options.compliance.controls.disasterRecovery = {
    enable = lib.mkEnableOption "disaster recovery compliance control (NIS2 Art. 21(c))";

    enforce = lib.mkOption {
      type = lib.types.bool;
      default = gov.enforceMode == "enforce";
      description = "Apply NixOS configuration. When false, only probes run.";
    };

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
    nix.settings.keep-outputs = lib.mkIf cfg.enforce (lib.mkDefault true);

    compliance.evidence.collector.enable = lib.mkDefault true;

    compliance.evidence.probes.disasterRecovery = {
      control = "disaster-recovery";
      type = "both";
      schema = schemaVersion;
      articles = {
        nis2 = ["21(c)"];
        iso27001 = ["A.5.29" "A.5.30"];
        dora = ["Art. 12"];
      };
      check = probeScript;
      # Predicate: bootloader retains ≥ minGenerations previous
      # generations for recovery. Was `null` (no static gate) - issue
      # #11 audit. Runtime probe verifies actual on-disk generation
      # presence; static check verifies the *config* allows it.
      staticEvidence = let
        rawSdBoot = config.boot.loader.systemd-boot.configurationLimit or null;
        rawGrub = config.boot.loader.grub.configurationLimit or null;
        # Use whichever bootloader is actively configured. systemd-boot wins
        # if both are set (NixOS asserts that at most one is enabled).
        configurationLimit =
          if rawSdBoot != null
          then rawSdBoot
          else if rawGrub != null
          then rawGrub
          else 0;
      in {
        passed = configurationLimit >= cfg.minGenerations;
        evidence = {
          configurationLimit = configurationLimit;
          minGenerations = cfg.minGenerations;
          rtoTarget = cfg.rtoTarget;
          testInterval = cfg.testInterval;
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
