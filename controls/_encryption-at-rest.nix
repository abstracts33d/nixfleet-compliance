# controls/_encryption-at-rest.nix
#
# Encryption at rest control - Art. 21(h).
# Verifies: LUKS partitions, encrypted swap, tmpfs on /tmp.
#
# Does NOT provision encryption (disko handles that).
# This control VERIFIES the runtime state matches expectations.
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
  cfg = config.compliance.controls.encryptionAtRest;
  gov = config.compliance.governance;
  mkProbe = import ../lib/mkProbe.nix {inherit pkgs lib;};
  framework = gov.primaryFramework or "anssi-bp028";
  schemaVersion =
    config.compliance.schemaVersions.${framework}
    or (throw "compliance.schemaVersions.${framework} is not set");

  probeScript = mkProbe {
    name = "encryption-at-rest";
    runtimeInputs = with pkgs; [cryptsetup util-linux];
    script = ''
      luks_devices=$(lsblk -J -o NAME,TYPE,FSTYPE 2>/dev/null \
        | jq '[.blockdevices[] | recurse(.children[]?) | select(.type == "crypt")]' \
        || true)
      luks_devices="''${luks_devices:-[]}"
      luks_count=$(echo "$luks_devices" | jq 'length')
      luks_count="''${luks_count:-0}"

      swap_lines=$(swapon --show=NAME,TYPE --noheadings 2>/dev/null || echo "")
      if [ -z "$swap_lines" ]; then
        swap_encrypted=true
        swap_status="none"
      else
        swap_encrypted=true
        swap_status="present"
        while IFS= read -r line; do
          swap_dev=$(echo "$line" | awk '{print $1}')
          if ! cryptsetup status "$swap_dev" >/dev/null 2>&1; then
            parent=$(lsblk -no PKNAME "$swap_dev" 2>/dev/null || echo "")
            if ! cryptsetup status "/dev/mapper/$parent" >/dev/null 2>&1; then
              swap_encrypted=false
            fi
          fi
        done <<< "$swap_lines"
      fi

      tmp_mount=$(findmnt -n -o FSTYPE /tmp 2>/dev/null || true)
      tmp_mount="''${tmp_mount:-}"
      if [ "$tmp_mount" = "tmpfs" ]; then
        tmp_is_tmpfs=true
      else
        tmp_is_tmpfs=false
      fi

      require_encrypted_swap="${
        if cfg.requireEncryptedSwap
        then "true"
        else "false"
      }"
      require_tmp_tmpfs="${
        if cfg.requireTmpOnTmpfs
        then "true"
        else "false"
      }"

      compliant=true
      # LUKS is always required for encryption-at-rest
      if [ "''${luks_count:-0}" -eq 0 ]; then
        compliant=false
      fi
      # Only require encrypted swap when the option says so
      if [ "$require_encrypted_swap" = "true" ] && [ "$swap_encrypted" != "true" ]; then
        compliant=false
      fi
      # Only require tmpfs on /tmp when the option says so
      if [ "$require_tmp_tmpfs" = "true" ] && [ "$tmp_is_tmpfs" != "true" ]; then
        compliant=false
      fi

      jq -n \
        --argjson luks_count "$luks_count" \
        --argjson swap_encrypted "$swap_encrypted" \
        --arg swap_status "$swap_status" \
        --argjson tmp_is_tmpfs "$tmp_is_tmpfs" \
        --argjson compliant "$compliant" \
        '{
          luks_device_count: $luks_count,
          swap_encrypted: $swap_encrypted,
          swap_status: $swap_status,
          tmp_on_tmpfs: $tmp_is_tmpfs,
          compliant: $compliant
        }'
    '';
  };
in {
  imports = [../evidence/options.nix ../governance/options.nix];

  options.compliance.controls.encryptionAtRest = {
    enable = lib.mkEnableOption "encryption at rest compliance control (NIS2 Art. 21(h))";

    enforce = lib.mkOption {
      type = lib.types.bool;
      default = gov.enforceMode == "enforce";
      description = "Apply NixOS configuration. When false, only probes run.";
    };

    requireEncryptedSwap = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Require swap to be encrypted or absent";
    };

    requireTmpOnTmpfs = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Require /tmp to be a tmpfs mount";
    };
  };

  config = lib.mkIf cfg.enable {
    boot.tmp.useTmpfs = lib.mkIf (cfg.enforce && cfg.requireTmpOnTmpfs) (lib.mkDefault true);

    compliance.evidence.collector.enable = lib.mkDefault true;

    compliance.evidence.probes.encryptionAtRest = {
      control = "encryption-at-rest";
      type = "runtime";
      schema = schemaVersion;
      articles = {
        nis2 = ["21(h)"];
        iso27001 = ["A.8.24"];
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
