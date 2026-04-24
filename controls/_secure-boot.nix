# controls/_secure-boot.nix
#
# Secure boot - CRA Art. 10, SecNumCloud.
# No enforcement: secure boot setup is via lanzaboote, handled by fleet.
# Verifies: EFI support, secure boot status, boot loader detection,
# signed unified kernel images.
#
# Typed control: type="both". Declared policy and boot-loader selection
# are evaluated at CI time (staticEvidence); a runtime probe inspects
# bootctl/EFI state. The legacy `check` script is retained for backward
# compatibility with the evidence collector.
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.compliance.controls.secureBoot;
  gov = config.compliance.governance;
  mkProbe = import ../lib/mkProbe.nix {inherit pkgs lib;};
  framework = gov.primaryFramework or "dora";
  schemaVersion =
    config.compliance.schemaVersions.${framework}
    or (throw "compliance.schemaVersions.${framework} is not set");

  systemdBootEnabled = config.boot.loader.systemd-boot.enable or false;
  grubEnabled = config.boot.loader.grub.enable or false;
  declaredBootLoader =
    if systemdBootEnabled
    then "systemd-boot"
    else if grubEnabled
    then "grub"
    else "unknown";
  configurationLimit = config.boot.loader.systemd-boot.configurationLimit or null;

  probeScript = mkProbe {
    name = "secure-boot";
    runtimeInputs = with pkgs; [systemd];
    script = ''
      require_secure_boot="${
        if cfg.requireSecureBoot
        then "true"
        else "false"
      }"

      efi_supported="false"
      if [ -d /sys/firmware/efi ]; then
        efi_supported="true"
      fi

      secure_boot_active="false"
      if [ "$efi_supported" = "true" ]; then
        if bootctl status 2>/dev/null | grep -q "Secure Boot: enabled"; then
          secure_boot_active="true"
        fi
      fi

      boot_loader="unknown"
      if command -v bootctl >/dev/null 2>&1; then
        boot_loader=$(bootctl status 2>/dev/null | head -1 || true)
        boot_loader="''${boot_loader:-unknown}"
      fi

      signed_entries_exist="false"
      if ls /boot/EFI/Linux/*.efi >/dev/null 2>&1; then
        signed_entries_exist="true"
      fi

      if [ "$require_secure_boot" = "true" ]; then
        if [ "$secure_boot_active" = "true" ]; then
          compliant=true
        else
          compliant=false
        fi
      else
        # Secure boot not required - report EFI state but always pass
        compliant=true
      fi

      jq -n \
        --argjson compliant "$compliant" \
        --argjson efi_supported "$efi_supported" \
        --argjson secure_boot_active "$secure_boot_active" \
        --arg boot_loader "$boot_loader" \
        --argjson signed_entries_exist "$signed_entries_exist" \
        '{
          compliant: $compliant,
          efi_supported: $efi_supported,
          secure_boot_active: $secure_boot_active,
          boot_loader: $boot_loader,
          signed_entries_exist: $signed_entries_exist
        }'
    '';
  };
in {
  imports = [../evidence/options.nix ../governance/options.nix];

  options.compliance.controls.secureBoot = {
    enable = lib.mkEnableOption "secure boot compliance control (CRA Art. 10)";

    enforce = lib.mkOption {
      type = lib.types.bool;
      default = gov.enforceMode == "enforce";
      description = "Apply NixOS configuration. When false, only probes run.";
    };

    requireSecureBoot = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Whether secure boot is required by policy (informational - don't enforce, just report)";
    };
  };

  config = lib.mkIf cfg.enable {
    compliance.evidence.collector.enable = lib.mkDefault true;

    compliance.evidence.probes.secureBoot = {
      control = "secure-boot";
      type = "both";
      schema = schemaVersion;
      articles = {
        cra = ["Art. 10"];
        secnumcloud = ["boot"];
        nis2 = ["21(a)"];
      };
      check = probeScript;
      staticEvidence = {
        passed = systemdBootEnabled || grubEnabled;
        evidence = {
          bootLoader = declaredBootLoader;
          configurationLimit = configurationLimit;
          requireSecureBoot = cfg.requireSecureBoot;
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
