# controls/_authentication.nix
#
# Authentication — Art. 21(j).
# No enforcement: MFA/auth config is fleet-specific via PAM, Keycloak, etc.
# Verifies: MFA policy, PAM modules, SSH certificate auth,
# system account inventory.
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.compliance.controls.authentication;
  mkProbe = import ../lib/mkProbe.nix {inherit pkgs lib;};
in {
  imports = [../evidence/options.nix];

  options.compliance.controls.authentication = {
    enable = lib.mkEnableOption "authentication compliance control (NIS2 Art. 21(j))";

    mfaRequired = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Whether MFA is required by policy (informational — actual MFA config is fleet-specific)";
    };

    maxServiceAccounts = lib.mkOption {
      type = lib.types.int;
      default = 10;
      description = "Maximum expected number of service accounts before warning";
    };
  };

  config = lib.mkIf cfg.enable {
    compliance.evidence.collector.enable = lib.mkDefault true;

    compliance.evidence.probes.authentication = {
      control = "authentication";
      articles = {
        nis2 = ["21(j)"];
        iso27001 = ["A.9"];
        dora = ["Art. 9"];
      };
      check = mkProbe {
        name = "authentication";
        runtimeInputs = with pkgs; [coreutils gnugrep gawk];
        script = ''
          mfa_policy_required="${
            if cfg.mfaRequired
            then "true"
            else "false"
          }"

          pam_modules_loaded=$(grep -oP 'pam_\w+' /etc/pam.d/sshd 2>/dev/null \
            | sort -u | jq -R -s 'split("\n") | map(select(length > 0))' \
            || true)
          pam_modules_loaded="''${pam_modules_loaded:-[]}"

          if ls /etc/ssh/ssh_host_*_key-cert.pub >/dev/null 2>&1; then
            ssh_cert_auth_available=true
          else
            ssh_cert_auth_available=false
          fi

          system_accounts=$(awk -F: '$3 >= 1000 && $3 < 65534 && $1 !~ /^nixbld/ {print $1}' /etc/passwd 2>/dev/null \
            | jq -R -s 'split("\n") | map(select(length > 0))' \
            || true)
          system_accounts="''${system_accounts:-[]}"

          system_account_count=$(echo "$system_accounts" | jq 'length')
          system_account_count="''${system_account_count:-0}"

          if [ "$system_account_count" -gt ${toString cfg.maxServiceAccounts} ] 2>/dev/null; then
            service_accounts_over_threshold=true
          else
            service_accounts_over_threshold=false
          fi

          if [ "$mfa_policy_required" = "false" ]; then
            compliant=true
          else
            # MFA required — check if any MFA PAM module is present
            has_mfa=$(echo "$pam_modules_loaded" | jq 'map(select(test("u2f|google|duo|oath"))) | length > 0' 2>/dev/null || echo "false")
            if [ "$has_mfa" = "true" ]; then
              compliant=true
            else
              compliant=false
            fi
          fi

          jq -n \
            --argjson mfa_policy_required "$mfa_policy_required" \
            --argjson pam_modules_loaded "$pam_modules_loaded" \
            --argjson ssh_cert_auth_available "$ssh_cert_auth_available" \
            --argjson system_accounts "$system_accounts" \
            --argjson system_account_count "$system_account_count" \
            --argjson service_accounts_over_threshold "$service_accounts_over_threshold" \
            --argjson compliant "$compliant" \
            '{
              mfa_policy_required: $mfa_policy_required,
              pam_modules_loaded: $pam_modules_loaded,
              ssh_cert_auth_available: $ssh_cert_auth_available,
              system_accounts: $system_accounts,
              system_account_count: $system_account_count,
              service_accounts_over_threshold: $service_accounts_over_threshold,
              compliant: $compliant
            }'
        '';
      };
    };
  };
}
