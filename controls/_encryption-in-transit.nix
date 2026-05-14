# controls/_encryption-in-transit.nix
#
# Encryption in transit - Art. 21(h).
# No direct TLS enforcement (that's per-service).
# Verifies: TLS minimum version policy, certificate inventory,
# expiring certificates, SSH host key presence.
#
# Typed control: type="both". Static predicate inspects the same
# NixOS options the runtime probe later verifies on disk: sshd is
# enabled with an ed25519 host key declared (the runtime probe
# checks `/etc/ssh/ssh_host_ed25519_key.pub` exists), AND the
# operator's declared `minTlsVersion` is in the modern set (the
# enum constraint already ensures this, but explicit is better
# than implicit). Cert-expiry is left to runtime -- it's a fact
# about the world, not the config. The previous predicate
# `builtins.elem cfg.minTlsVersion ["1.2" "1.3"]` was tautological
# given the option's enum type -- see issue #11.
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.compliance.controls.encryptionInTransit;
  gov = config.compliance.governance;
  mkProbe = import ../lib/mkProbe.nix {inherit pkgs lib;};
  framework = gov.primaryFramework or "anssi-bp028";
  schemaVersion =
    config.compliance.schemaVersions.${framework}
    or (throw "compliance.schemaVersions.${framework} is not set");

  # Static predicate inputs -- mirror the runtime probe's
  # `ssh_host_key_exists` check. NixOS will generate any host key
  # declared in `services.openssh.hostKeys`; ed25519 is the modern
  # default. The probe greps for the .pub at runtime; statically we
  # check the type is in the declared set.
  sshdEnabled = config.services.openssh.enable or false;
  declaredHostKeyTypes =
    map (k: k.type) (config.services.openssh.hostKeys or []);
  sshEd25519HostKeyDeclared =
    sshdEnabled && (builtins.elem "ed25519" declaredHostKeyTypes);

  probeScript = mkProbe {
    name = "encryption-in-transit";
    runtimeInputs = with pkgs; [openssl findutils];
    script = ''
      tls_min_version="${cfg.minTlsVersion}"

      cert_count=0
      for dir in /etc/ssl/certs /var/lib/acme; do
        if [ -d "$dir" ]; then
          count=$(find "$dir" -type f \( -name "*.pem" -o -name "*.crt" \) 2>/dev/null | wc -l)
          cert_count=$((cert_count + count))
        fi
      done

      expiring_certs="[]"
      warning_days=${toString cfg.certExpiryWarningDays}
      if [ -d /var/lib/acme ]; then
        for cert_file in /var/lib/acme/*/cert.pem; do
          [ -f "$cert_file" ] || continue
          end_date=$(openssl x509 -enddate -noout -in "$cert_file" 2>/dev/null \
            | sed 's/notAfter=//' || continue)
          end_epoch=$(date -d "$end_date" +%s 2>/dev/null || continue)
          now_epoch=$(date +%s)
          days_left=$(( (end_epoch - now_epoch) / 86400 ))
          if [ "$days_left" -le "$warning_days" ]; then
            domain=$(basename "$(dirname "$cert_file")")
            expiring_certs=$(echo "$expiring_certs" | jq \
              --arg d "$domain" --argjson dl "$days_left" \
              '. + [{domain: $d, days_left: $dl}]')
          fi
        done
      fi

      if [ -f /etc/ssh/ssh_host_ed25519_key.pub ]; then
        ssh_host_key_exists=true
      else
        ssh_host_key_exists=false
      fi

      expiring_count=$(echo "$expiring_certs" | jq 'length' 2>/dev/null || echo "0")
      if [ "$ssh_host_key_exists" = "true" ] && [ "''${expiring_count:-0}" -eq 0 ]; then
        compliant=true
      else
        compliant=false
      fi

      jq -n \
        --arg tls_min_version "$tls_min_version" \
        --argjson cert_files_found "$cert_count" \
        --argjson certs_expiring_soon "$expiring_certs" \
        --argjson ssh_host_key_exists "$ssh_host_key_exists" \
        --argjson compliant "$compliant" \
        '{
          tls_min_version: $tls_min_version,
          cert_files_found: $cert_files_found,
          certs_expiring_soon: $certs_expiring_soon,
          ssh_host_key_exists: $ssh_host_key_exists,
          compliant: $compliant
        }'
    '';
  };
in {
  imports = [../evidence/options.nix ../governance/options.nix];

  options.compliance.controls.encryptionInTransit = {
    enable = lib.mkEnableOption "encryption in transit compliance control (NIS2 Art. 21(h))";

    enforce = lib.mkOption {
      type = lib.types.bool;
      default = gov.enforceMode == "enforce";
      description = "Apply NixOS configuration. When false, only probes run.";
    };

    minTlsVersion = lib.mkOption {
      type = lib.types.enum ["1.2" "1.3"];
      default = "1.2";
      description = "Minimum acceptable TLS version";
    };

    certExpiryWarningDays = lib.mkOption {
      type = lib.types.int;
      default = 30;
      description = "Days before certificate expiry to raise a warning";
    };
  };

  config = lib.mkIf cfg.enable {
    compliance.evidence.collector.enable = lib.mkDefault true;

    compliance.evidence.probes.encryptionInTransit = {
      control = "encryption-in-transit";
      type = "both";
      schema = schemaVersion;
      articles = {
        nis2 = ["21(h)"];
        iso27001 = ["A.8.20" "A.8.24"];
        cra = ["Art. 10"];
      };
      check = probeScript;
      staticEvidence = {
        # Predicate: sshd enabled with an ed25519 host key declared
        # (mirrors the runtime probe's first compliance clause), AND
        # the declared minTlsVersion is in the modern set. The
        # previous predicate `builtins.elem cfg.minTlsVersion
        # ["1.2" "1.3"]` was tautological given the option type
        # enum -- see issue #11.
        passed =
          sshEd25519HostKeyDeclared
          && (cfg.minTlsVersion == "1.2" || cfg.minTlsVersion == "1.3");
        evidence = {
          declaredMinTlsVersion = cfg.minTlsVersion;
          certExpiryWarningDays = cfg.certExpiryWarningDays;
          sshdEnabled = sshdEnabled;
          sshEd25519HostKeyDeclared = sshEd25519HostKeyDeclared;
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
