# controls/_key-management.nix
#
# Key management - SecNumCloud, ISO 27001 A.10.
# No enforcement: key provisioning is fleet-specific.
# Verifies: SSH host key inventory with age/algorithm, TPM presence,
# LUKS key slots, rotation policy compliance.
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
  cfg = config.compliance.controls.keyManagement;
  gov = config.compliance.governance;
  mkProbe = import ../lib/mkProbe.nix {inherit pkgs lib;};
  framework = gov.primaryFramework or "anssi-bp028";
  schemaVersion =
    config.compliance.schemaVersions.${framework}
    or (throw "compliance.schemaVersions.${framework} is not set");

  probeScript = mkProbe {
    name = "key-management";
    runtimeInputs = with pkgs; [openssh cryptsetup coreutils];
    script = ''
      ssh_host_keys="[]"
      oldest_key_age_days=0
      now=$(date +%s)

      key_entries=""
      for pub in /etc/ssh/ssh_host_*_key.pub; do
        [ -f "$pub" ] || continue
        algorithm=$(ssh-keygen -l -f "$pub" 2>/dev/null | awk '{print $4}' | tr -d '()' || true)
        algorithm="''${algorithm:-unknown}"
        key_epoch=$(stat -c '%Y' "$pub" 2>/dev/null || echo "$now")
        age_days=$(( (now - key_epoch) / 86400 ))
        if [ "$age_days" -gt "$oldest_key_age_days" ]; then
          oldest_key_age_days=$age_days
        fi
        entry=$(jq -n \
          --arg algorithm "$algorithm" \
          --arg path "$pub" \
          --argjson age_days "$age_days" \
          '{algorithm: $algorithm, path: $path, age_days: $age_days}')
        if [ -n "$key_entries" ]; then
          key_entries="$key_entries,$entry"
        else
          key_entries="$entry"
        fi
      done
      ssh_host_keys="[$key_entries]"

      has_tpm="false"
      if [ -e /dev/tpm0 ] || [ -d /sys/class/tpm/tpm0 ]; then
        has_tpm="true"
      fi

      luks_key_slots="0"
      if command -v cryptsetup >/dev/null 2>&1; then
        root_device=$(lsblk -no PKNAME "$(findmnt -n -o SOURCE / 2>/dev/null)" 2>/dev/null || true)
        if [ -n "$root_device" ]; then
          luks_key_slots=$(cryptsetup luksDump "/dev/$root_device" 2>/dev/null | grep -c 'Key Slot' || true)
          luks_key_slots="''${luks_key_slots:-0}"
        fi
      fi

      key_count=$(echo "$ssh_host_keys" | jq 'length')
      key_count="''${key_count:-0}"

      if [ "$key_count" -eq 0 ]; then
        # No SSH host keys at all - cannot be compliant
        keys_within_rotation_policy=false
      elif [ "$oldest_key_age_days" -le ${toString cfg.maxKeyAgeDays} ] 2>/dev/null; then
        keys_within_rotation_policy=true
      else
        keys_within_rotation_policy=false
      fi

      compliant=$keys_within_rotation_policy

      jq -n \
        --argjson compliant "$compliant" \
        --argjson ssh_host_keys "$ssh_host_keys" \
        --argjson has_tpm "$has_tpm" \
        --argjson luks_key_slots "$luks_key_slots" \
        --argjson oldest_key_age_days "$oldest_key_age_days" \
        --argjson keys_within_rotation_policy "$keys_within_rotation_policy" \
        '{
          compliant: $compliant,
          ssh_host_keys: $ssh_host_keys,
          has_tpm: $has_tpm,
          luks_key_slots: $luks_key_slots,
          oldest_key_age_days: $oldest_key_age_days,
          keys_within_rotation_policy: $keys_within_rotation_policy
        }'
    '';
  };
in {
  imports = [../evidence/options.nix ../governance/options.nix];

  options.compliance.controls.keyManagement = {
    enable = lib.mkEnableOption "key management compliance control (SecNumCloud, ISO 27001 A.10)";
    enforce = lib.mkOption {
      type = lib.types.bool;
      default = gov.enforceMode == "enforce";
      description = "Apply NixOS configuration. When false, only probes run.";
    };

    maxKeyAgeDays = lib.mkOption {
      type = lib.types.int;
      default = 365;
      description = "Maximum days before SSH host keys should be rotated";
    };

    requiredAlgorithms = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = ["ed25519"];
      description = "Expected SSH host key algorithms";
    };
  };

  config = lib.mkIf cfg.enable {
    compliance.evidence.collector.enable = lib.mkDefault true;

    compliance.evidence.probes.keyManagement = {
      control = "key-management";
      type = "runtime";
      schema = schemaVersion;
      articles = {
        secnumcloud = ["key-mgmt"];
        iso27001 = ["A.8.24"];
        nis2 = ["21(h)"];
      };
      check = probeScript;
      staticEvidence = null;
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
