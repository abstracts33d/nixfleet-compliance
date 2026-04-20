# controls/_asset-inventory.nix
#
# Asset inventory control - Art. 21(i).
# Reports: hostname, platform, network interfaces, enabled services,
# last config apply timestamp.
#
# NixOS advantage: the flake IS the inventory. This control just reads it.
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.compliance.controls.assetInventory;
  gov = config.compliance.governance;
  mkProbe = import ../lib/mkProbe.nix {inherit pkgs lib;};
in {
  imports = [../evidence/options.nix ../governance/options.nix];

  options.compliance.controls.assetInventory = {
    enable = lib.mkEnableOption "asset inventory compliance control (NIS2 Art. 21(i))";
    enforce = lib.mkOption {
      type = lib.types.bool;
      default = gov.enforceMode == "enforce";
      description = "Apply NixOS configuration. When false, only probes run.";
    };
  };

  config = lib.mkIf cfg.enable {
    compliance.evidence.collector.enable = lib.mkDefault true;

    compliance.evidence.probes.assetInventory = {
      control = "asset-inventory";
      articles = {
        nis2 = ["21(i)"];
        iso27001 = ["A.5.9"];
        dora = ["Art. 8"];
      };
      check = mkProbe {
        name = "asset-inventory";
        runtimeInputs = with pkgs; [systemd];
        script = ''
          host=$(hostname)

          interfaces=$(ip -j link show 2>/dev/null \
            | jq '[.[] | select(.ifname != "lo") | {name: .ifname, state: .operstate}]' \
            || true)
          interfaces="''${interfaces:-[]}"

          services=$(systemctl list-units --type=service --state=running --no-pager --plain \
            | grep '\.service' \
            | awk '{print $1}' \
            | jq -R -s 'split("\n") | map(select(length > 0))' \
            || true)
          services="''${services:-[]}"

          service_count=$(echo "$services" | jq 'length')
          service_count="''${service_count:-0}"

          last_config_apply=""
          if [ -L /run/current-system ]; then
            profile_time=$(stat -c %Y /run/current-system 2>/dev/null || echo "0")
            last_config_apply=$(date -u -d "@$profile_time" +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || echo "unknown")
          fi

          nixos_version=$(cat /run/current-system/nixos-version 2>/dev/null || echo "unknown")

          # Inventory is only meaningful if we can identify the host and it has
          # a NixOS profile (proves the machine is managed via flake).
          if [ -n "$host" ] && [ -L /run/current-system ] && [ "$nixos_version" != "unknown" ]; then
            compliant=true
          else
            compliant=false
          fi

          jq -n \
            --arg host "$host" \
            --argjson interfaces "$interfaces" \
            --argjson services "$services" \
            --argjson service_count "$service_count" \
            --arg last_config_apply "$last_config_apply" \
            --arg nixos_version "$nixos_version" \
            --argjson compliant "$compliant" \
            '{
              host_registered: true,
              hostname: $host,
              nixos_version: $nixos_version,
              network_interfaces: $interfaces,
              running_services: $services,
              service_count: $service_count,
              last_config_apply: $last_config_apply,
              compliant: $compliant
            }'
        '';
      };
    };
  };
}
