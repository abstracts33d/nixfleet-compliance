# controls/_authentication.nix
#
# Authentication - Art. 21(j).
# Module wires nothing on its own — MFA/auth config is fleet-specific
# (PAM stacks, Keycloak, U2F hardware, etc.). Verifies: MFA policy,
# PAM modules, SSH certificate auth, system account inventory.
#
# Typed control: type="both". Static predicate mirrors the runtime
# probe's compliance condition exactly:
#
#   - When `mfaRequired = false` the runtime probe shorts to
#     `compliant=true`; the static predicate does the same.
#   - When `mfaRequired = true` the runtime probe expects a known
#     MFA PAM module (u2f / google / duo / oath) loaded at sshd time;
#     the static predicate looks for the equivalent declaratively-
#     wired NixOS options on `security.pam.services.sshd`.
#
# Best-effort declarative detection — operators using non-NixOS-native
# MFA stacks (e.g. raw `text =` PAM bodies sourcing custom modules)
# may need to set `mfaRequired = false` and rely on the runtime probe
# alone. The runtime probe is the source of truth; the static predicate
# is the "catch operator overrides at fleet-eval time" defense-in-depth
# layer.
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.compliance.controls.authentication;
  gov = config.compliance.governance;
  mkProbe = import ../lib/mkProbe.nix {inherit pkgs lib;};
  framework = gov.primaryFramework or "anssi-bp028";
  schemaVersion =
    config.compliance.schemaVersions.${framework}
    or (throw "compliance.schemaVersions.${framework} is not set");

  # Static predicate inputs — mirror the runtime probe's MFA check.
  # The runtime probe greps `pam_(u2f|google|duo|oath)` from
  # `/etc/pam.d/sshd`; declaratively, NixOS exposes these as typed
  # options on `security.pam.services.sshd` (googleAuthenticator,
  # u2fAuth) plus a free-form `text` field that picks up other
  # modules. Best-effort coverage:
  pamSshd = config.security.pam.services.sshd or {};
  pamSshdText = pamSshd.text or "";
  declarativeMfaPresent =
    (pamSshd.googleAuthenticator.enable or false)
    || (pamSshd.u2fAuth or false)
    || (lib.hasInfix "pam_u2f" pamSshdText)
    || (lib.hasInfix "pam_google_authenticator" pamSshdText)
    || (lib.hasInfix "pam_oath" pamSshdText)
    || (lib.hasInfix "pam_duo" pamSshdText);

  probeScript = mkProbe {
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
        # MFA required - check if any MFA PAM module is present
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
in {
  imports = [../evidence/options.nix ../governance/options.nix];

  options.compliance.controls.authentication = {
    enable = lib.mkEnableOption "authentication compliance control (NIS2 Art. 21(j))";

    enforce = lib.mkOption {
      type = lib.types.bool;
      default = gov.enforceMode == "enforce";
      description = "Apply NixOS configuration. When false, only probes run.";
    };

    mfaRequired = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Whether MFA is required by policy (informational - actual MFA config is fleet-specific)";
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
      type = "both";
      schema = schemaVersion;
      articles = {
        nis2 = ["21(j)"];
        iso27001 = ["A.8.5"];
        dora = ["Art. 9"];
      };
      check = probeScript;
      # Static predicate mirrors the runtime probe's `compliant`
      # condition (lines 60-69 of the probe script). When mfaRequired
      # is false the predicate passes unconditionally (matching the
      # runtime short-circuit). When true, declarativeMfaPresent must
      # be true — i.e. some known MFA-enabling NixOS option is wired
      # on `security.pam.services.sshd`. Static FAIL surfaces operator
      # overrides like `mfaRequired = lib.mkForce true` without any
      # MFA stack at fleet-eval time, before deploy.
      staticEvidence = {
        passed = (!cfg.mfaRequired) || declarativeMfaPresent;
        evidence = {
          mfaRequired = cfg.mfaRequired;
          declarativeMfaPresent = declarativeMfaPresent;
          maxServiceAccounts = cfg.maxServiceAccounts;
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
