# controls/_network-segmentation.nix
#
# Network segmentation — DORA Art. 9, SecNumCloud.
# No enforcement: network topology is fleet-specific.
# Verifies: firewall status, VLAN interfaces, bridge interfaces,
# firewall rule count, interface inventory.
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.compliance.controls.networkSegmentation;
  mkProbe = import ../lib/mkProbe.nix {inherit pkgs lib;};
in {
  imports = [../evidence/options.nix];

  options.compliance.controls.networkSegmentation = {
    enable = lib.mkEnableOption "network segmentation compliance control (DORA Art. 9)";

    expectedVlans = lib.mkOption {
      type = lib.types.listOf lib.types.int;
      default = [];
      description = "VLANs expected to be configured on this host";
    };

    requireFirewall = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Whether a firewall is required by policy";
    };
  };

  config = lib.mkIf cfg.enable {
    compliance.evidence.collector.enable = lib.mkDefault true;

    compliance.evidence.probes.networkSegmentation = {
      control = "network-segmentation";
      articles = {
        dora = ["Art. 9"];
        secnumcloud = ["network"];
        nis2 = ["21(a)"];
      };
      check = mkProbe {
        name = "network-segmentation";
        runtimeInputs = with pkgs; [iproute2 nftables jq];
        script = ''
          firewall_enabled=$(systemctl is-active nftables.service 2>/dev/null || systemctl is-active firewalld.service 2>/dev/null)
          if [ "$firewall_enabled" = "active" ]; then
            firewall_enabled="true"
          else
            firewall_enabled="false"
          fi

          vlan_interfaces=$(ip -j link show type vlan 2>/dev/null | jq '[.[].ifname]' || echo "[]")

          bridge_interfaces=$(ip -j link show type bridge 2>/dev/null | jq '[.[].ifname]' || echo "[]")

          firewall_rules_count=$(nft list ruleset 2>/dev/null | grep -c 'rule' || echo "0")

          interface_count=$(ip -j link show 2>/dev/null | jq '[.[] | select(.ifname != "lo")] | length' || echo "0")

          jq -n \
            --argjson firewall_enabled "$firewall_enabled" \
            --argjson vlan_interfaces "$vlan_interfaces" \
            --argjson bridge_interfaces "$bridge_interfaces" \
            --argjson firewall_rules_count "$firewall_rules_count" \
            --argjson interface_count "$interface_count" \
            '{
              firewall_enabled: $firewall_enabled,
              vlan_interfaces: $vlan_interfaces,
              bridge_interfaces: $bridge_interfaces,
              firewall_rules_count: $firewall_rules_count,
              interface_count: $interface_count
            }'
        '';
      };
    };
  };
}
