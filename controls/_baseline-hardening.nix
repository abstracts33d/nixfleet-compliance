# controls/_baseline-hardening.nix
#
# Baseline hardening — Art. 21(a)(g).
# Enforces: kernel hardening sysctls, module blocklist (strict mode).
# Verifies: dmesg_restrict, kptr_restrict, syncookies, rp_filter,
# redirect settings, hardening score.
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.compliance.controls.baselineHardening;
  mkProbe = import ../lib/mkProbe.nix {inherit pkgs lib;};
  isStrict = cfg.level == "strict";
in {
  imports = [../evidence/options.nix];

  options.compliance.controls.baselineHardening = {
    enable = lib.mkEnableOption "baseline hardening compliance control (NIS2 Art. 21(a)(g))";

    level = lib.mkOption {
      type = lib.types.enum ["strict" "standard"];
      default = "standard";
      description = "Hardening level. Strict adds kernel module blocklist.";
    };
  };

  config = lib.mkIf cfg.enable {
    boot.kernel.sysctl = {
      "kernel.dmesg_restrict" = lib.mkDefault 1;
      "kernel.kptr_restrict" = lib.mkForce 2;
      "net.ipv4.conf.all.rp_filter" = lib.mkDefault 1;
      "net.ipv4.conf.default.rp_filter" = lib.mkDefault 1;
      "net.ipv4.conf.all.accept_redirects" = lib.mkDefault 0;
      "net.ipv4.conf.default.accept_redirects" = lib.mkDefault 0;
      "net.ipv6.conf.all.accept_redirects" = lib.mkDefault 0;
      "net.ipv6.conf.default.accept_redirects" = lib.mkDefault 0;
      "net.ipv4.conf.all.send_redirects" = lib.mkDefault 0;
      "net.ipv4.conf.default.send_redirects" = lib.mkDefault 0;
      "net.ipv4.tcp_syncookies" = lib.mkDefault 1;
      "kernel.unprivileged_bpf_disabled" = lib.mkDefault 1;
    };

    boot.blacklistedKernelModules = lib.mkIf isStrict [
      "usb-storage"
      "firewire-core"
      "thunderbolt"
    ];

    compliance.evidence.collector.enable = lib.mkDefault true;

    compliance.evidence.probes.baselineHardening = {
      control = "baseline-hardening";
      articles = {
        nis2 = ["21(a)" "21(g)"];
        iso27001 = ["A.8" "A.12"];
      };
      check = mkProbe {
        name = "baseline-hardening";
        script = ''
          read_sysctl() {
            cat "/proc/sys/$1" 2>/dev/null || echo "unknown"
          }

          dmesg_val=$(read_sysctl kernel/dmesg_restrict)
          if [ "$dmesg_val" = "1" ]; then
            dmesg_restrict=true
          else
            dmesg_restrict=false
          fi

          kptr_val=$(read_sysctl kernel/kptr_restrict)
          if [ "$kptr_val" -ge 2 ] 2>/dev/null; then
            kptr_restrict=true
          else
            kptr_restrict=false
          fi

          syncookies_val=$(read_sysctl net/ipv4/tcp_syncookies)
          if [ "$syncookies_val" = "1" ]; then
            syncookies=true
          else
            syncookies=false
          fi

          rp_filter_val=$(read_sysctl net/ipv4/conf/all/rp_filter)
          if [ "$rp_filter_val" = "1" ]; then
            rp_filter=true
          else
            rp_filter=false
          fi

          accept_redirects_val=$(read_sysctl net/ipv4/conf/all/accept_redirects)
          if [ "$accept_redirects_val" = "0" ]; then
            accept_redirects_disabled=true
          else
            accept_redirects_disabled=false
          fi

          send_redirects_val=$(read_sysctl net/ipv4/conf/all/send_redirects)
          if [ "$send_redirects_val" = "0" ]; then
            send_redirects_disabled=true
          else
            send_redirects_disabled=false
          fi

          total=6
          passed=0
          for val in "$dmesg_restrict" "$kptr_restrict" "$syncookies" "$rp_filter" "$accept_redirects_disabled" "$send_redirects_disabled"; do
            [ "$val" = "true" ] && passed=$((passed + 1))
          done
          score=$(awk "BEGIN {printf \"%.2f\", $passed / $total}")

          hardening_score="$score"
          if [ "$hardening_score" = "1.00" ]; then
            compliant=true
          else
            compliant=false
          fi

          jq -n \
            --argjson dmesg_restrict "$dmesg_restrict" \
            --argjson kptr_restrict "$kptr_restrict" \
            --argjson syncookies "$syncookies" \
            --argjson rp_filter "$rp_filter" \
            --argjson accept_redirects_disabled "$accept_redirects_disabled" \
            --argjson send_redirects_disabled "$send_redirects_disabled" \
            --arg hardening_score "$score" \
            --argjson compliant "$compliant" \
            '{
              dmesg_restrict: $dmesg_restrict,
              kptr_restrict: $kptr_restrict,
              syncookies: $syncookies,
              rp_filter: $rp_filter,
              accept_redirects_disabled: $accept_redirects_disabled,
              send_redirects_disabled: $send_redirects_disabled,
              hardening_score: $hardening_score,
              compliant: $compliant
            }'
        '';
      };
    };
  };
}
