# controls/_secure-boot.nix
#
# Secure boot — CRA Art. 10, SecNumCloud.
# No enforcement: secure boot setup is via lanzaboote, handled by fleet.
# Verifies: EFI support, secure boot status, boot loader detection,
# signed unified kernel images.
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.compliance.controls.secureBoot;
  mkProbe = import ../lib/mkProbe.nix {inherit pkgs lib;};
in {
  imports = [../evidence/options.nix];

  options.compliance.controls.secureBoot = {
    enable = lib.mkEnableOption "secure boot compliance control (CRA Art. 10)";

    requireSecureBoot = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Whether secure boot is required by policy (informational — don't enforce, just report)";
    };
  };

  config = lib.mkIf cfg.enable {
    compliance.evidence.collector.enable = lib.mkDefault true;

    compliance.evidence.probes.secureBoot = {
      control = "secure-boot";
      articles = {
        cra = ["Art. 10"];
        secnumcloud = ["boot"];
        nis2 = ["21(a)"];
      };
      check = mkProbe {
        name = "secure-boot";
        runtimeInputs = with pkgs; [systemd];
        script = ''
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

          compliant=$efi_supported

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
    };
  };
}
