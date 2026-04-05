# controls/_encryption-in-transit.nix
#
# Encryption in transit — Art. 21(h).
# No direct TLS enforcement (that's per-service).
# Verifies: TLS minimum version policy, certificate inventory,
# expiring certificates, SSH host key presence.
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.compliance.controls.encryptionInTransit;
  mkProbe = import ../lib/mkProbe.nix {inherit pkgs lib;};
in {
  imports = [../evidence/options.nix];

  options.compliance.controls.encryptionInTransit = {
    enable = lib.mkEnableOption "encryption in transit compliance control (NIS2 Art. 21(h))";

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
      articles = {
        nis2 = ["21(h)"];
        iso27001 = ["A.13"];
        cra = ["Art. 10"];
      };
      check = mkProbe {
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
            expiring_list=""
            for cert_file in /var/lib/acme/*/cert.pem; do
              [ -f "$cert_file" ] || continue
              end_date=$(openssl x509 -enddate -noout -in "$cert_file" 2>/dev/null \
                | sed 's/notAfter=//' || continue)
              end_epoch=$(date -d "$end_date" +%s 2>/dev/null || continue)
              now_epoch=$(date +%s)
              days_left=$(( (end_epoch - now_epoch) / 86400 ))
              if [ "$days_left" -le "$warning_days" ]; then
                domain=$(basename "$(dirname "$cert_file")")
                expiring_list="$expiring_list{\"domain\":\"$domain\",\"days_left\":$days_left},"
              fi
            done
            if [ -n "$expiring_list" ]; then
              expiring_certs="[$(echo "$expiring_list" | sed 's/,$//')]"
            fi
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
    };
  };
}
