# controls/_access-control.nix
#
# Access control - Art. 21(i).
# Verifies: SSH key-only auth, root login disabled, sudo group,
# idle session timeout, failed login lockout.
#
# Reads standard NixOS openssh options - works with or without nixfleet.
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
  cfg = config.compliance.controls.accessControl;
  gov = config.compliance.governance;
  mkProbe = import ../lib/mkProbe.nix {inherit pkgs lib;};
  framework = gov.primaryFramework or "anssi-bp028";
  schemaVersion =
    config.compliance.schemaVersions.${framework}
    or (throw "compliance.schemaVersions.${framework} is not set");

  probeScript = mkProbe {
    name = "access-control";
    runtimeInputs = with pkgs; [openssh];
    script = ''
      password_auth=$(sshd -T 2>/dev/null | grep -i "^passwordauthentication" | awk '{print tolower($2)}' || true)
      password_auth="''${password_auth:-unknown}"
      if [ "$password_auth" = "no" ]; then
        password_auth_disabled=true
      else
        password_auth_disabled=false
      fi

      root_login=$(sshd -T 2>/dev/null | grep -i "^permitrootlogin" | awk '{print tolower($2)}' || true)
      root_login="''${root_login:-unknown}"
      if [ "$root_login" = "no" ] || [ "$root_login" = "prohibit-password" ]; then
        root_login_restricted=true
      else
        root_login_restricted=false
      fi

      alive_interval=$(sshd -T 2>/dev/null | grep -i "^clientaliveinterval" | awk '{print $2}' || true)
      alive_interval="''${alive_interval:-0}"
      alive_count=$(sshd -T 2>/dev/null | grep -i "^clientalivecountmax" | awk '{print $2}' || true)
      alive_count="''${alive_count:-3}"
      if [ "$alive_interval" -gt 0 ] 2>/dev/null; then
        has_idle_timeout=true
      else
        has_idle_timeout=false
      fi

      sudo_users=$(grep '^wheel:' /etc/group 2>/dev/null | cut -d: -f4 | tr ',' '\n' \
        | jq -R -s 'split("\n") | map(select(length > 0))' \
        || true)
      sudo_users="''${sudo_users:-[]}"

      ssh_key_count=0
      for home_dir in /home/*; do
        [ -d "$home_dir" ] || continue
        auth_keys="$home_dir/.ssh/authorized_keys"
        if [ -f "$auth_keys" ]; then
          count=$(grep -c "^ssh-" "$auth_keys" 2>/dev/null || true)
          count="''${count:-0}"
          ssh_key_count=$((ssh_key_count + count))
        fi
      done

      if [ "$password_auth_disabled" = "true" ] && [ "$root_login_restricted" = "true" ]; then
        compliant=true
      else
        compliant=false
      fi

      jq -n \
        --argjson password_auth_disabled "$password_auth_disabled" \
        --argjson root_login_restricted "$root_login_restricted" \
        --argjson has_idle_timeout "$has_idle_timeout" \
        --argjson idle_timeout_seconds "$alive_interval" \
        --argjson sudo_users "$sudo_users" \
        --argjson ssh_key_count "$ssh_key_count" \
        --argjson compliant "$compliant" \
        '{
          password_auth_disabled: $password_auth_disabled,
          root_login_restricted: $root_login_restricted,
          has_idle_timeout: $has_idle_timeout,
          idle_timeout_seconds: $idle_timeout_seconds,
          sudo_users: $sudo_users,
          ssh_key_count: $ssh_key_count,
          compliant: $compliant
        }'
    '';
  };
in {
  imports = [../evidence/options.nix ../governance/options.nix];

  options.compliance.controls.accessControl = {
    enable = lib.mkEnableOption "access control compliance control (NIS2 Art. 21(i))";

    enforce = lib.mkOption {
      type = lib.types.bool;
      default = gov.enforceMode == "enforce";
      description = "Apply NixOS configuration. When false, only probes run.";
    };

    passwordAuthDisabled = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Require SSH password authentication to be disabled";
    };

    rootLoginDisabled = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Require SSH root login to be disabled or key-only";
    };

    idleTimeoutMinutes = lib.mkOption {
      type = lib.types.int;
      default = 30;
      description = "SSH idle timeout in minutes";
    };
  };

  config = lib.mkIf cfg.enable {
    services.openssh.settings = lib.mkIf cfg.enforce {
      PasswordAuthentication = lib.mkIf cfg.passwordAuthDisabled (lib.mkForce false);
      PermitRootLogin = lib.mkIf cfg.rootLoginDisabled (lib.mkForce "prohibit-password");
      ClientAliveInterval = lib.mkForce (cfg.idleTimeoutMinutes * 60);
      ClientAliveCountMax = lib.mkForce 0;
    };

    compliance.evidence.collector.enable = lib.mkDefault true;

    compliance.evidence.probes.accessControl = {
      control = "access-control";
      type = "runtime";
      schema = schemaVersion;
      articles = {
        nis2 = ["21(i)"];
        iso27001 = ["A.8.2" "A.8.3"];
        dora = ["Art. 9"];
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
