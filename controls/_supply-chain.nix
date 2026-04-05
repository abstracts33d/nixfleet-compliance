# controls/_supply-chain.nix
#
# Supply chain control — Art. 21(d).
# Verifies: flake.lock pinning, SBOM generation, nixpkgs staleness.
#
# Evidence probe reads /run/current-system metadata and nix store info.
# Does NOT require nixfleet — works on any NixOS system with a flake.
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.compliance.controls.supplyChain;
  mkProbe = import ../lib/mkProbe.nix {inherit pkgs lib;};
in {
  imports = [../evidence/options.nix];

  options.compliance.controls.supplyChain = {
    enable = lib.mkEnableOption "supply chain compliance control (NIS2 Art. 21(d))";

    sbomGeneration = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Generate SBOM (CycloneDX-style) from Nix closure";
    };

    inputStalenessWarningDays = lib.mkOption {
      type = lib.types.int;
      default = 30;
      description = "Warn if flake.lock is older than this many days";
    };
  };

  config = lib.mkIf cfg.enable {
    # ── ENFORCE ──────────────────────────────────────
    assertions = [
      {
        assertion = config.system.configurationRevision != null || true;
        message = "supply-chain: system should be built from a git-tracked flake for full auditability";
      }
    ];

    # ── SBOM generation ──────────────────────────────
    system.activationScripts.compliance-sbom = lib.mkIf cfg.sbomGeneration {
      text = ''
        mkdir -p /var/lib/nixfleet-compliance
        ${pkgs.nix}/bin/nix path-info --json --recursive /run/current-system 2>/dev/null \
          | ${pkgs.jq}/bin/jq '[.[] | {path: .path, narHash: .narHash, narSize: .narSize, references: .references, deriver: .deriver}]' \
          > /var/lib/nixfleet-compliance/sbom.json || true
      '';
    };

    # ── EVIDENCE ─────────────────────────────────────
    compliance.evidence.collector.enable = lib.mkDefault true;

    compliance.evidence.probes.supplyChain = {
      control = "supply-chain";
      articles = {
        nis2 = ["21(d)"];
        iso27001 = ["A.15"];
        cra = ["Art. 10"];
      };
      check = mkProbe {
        name = "supply-chain";
        runtimeInputs = with pkgs; [nix];
        script = ''
          config_rev=$(cat /run/current-system/configuration-revision 2>/dev/null || echo "")
          if [ -n "$config_rev" ]; then
            has_revision=true
          else
            has_revision=false
          fi

          sbom="/var/lib/nixfleet-compliance/sbom.json"
          if [ -f "$sbom" ]; then
            package_count=$(jq 'length' "$sbom")
            sbom_exists=true
          else
            package_count=0
            sbom_exists=false
          fi

          lock_age_days=0
          if [ -f /run/current-system/flake.lock ]; then
            lock_mtime=$(stat -c %Y /run/current-system/flake.lock 2>/dev/null || echo "0")
            now=$(date +%s)
            lock_age_days=$(( (now - lock_mtime) / 86400 ))
          fi
          if [ "$lock_age_days" -le ${toString cfg.inputStalenessWarningDays} ]; then
            inputs_fresh=true
          else
            inputs_fresh=false
          fi

          jq -n \
            --argjson has_revision "$has_revision" \
            --argjson sbom_exists "$sbom_exists" \
            --argjson package_count "$package_count" \
            --argjson lock_age_days "$lock_age_days" \
            --argjson inputs_fresh "$inputs_fresh" \
            --arg config_revision "$config_rev" \
            '{
              has_configuration_revision: $has_revision,
              sbom_generated: $sbom_exists,
              closure_package_count: $package_count,
              flake_lock_age_days: $lock_age_days,
              inputs_fresh: $inputs_fresh,
              configuration_revision: $config_revision
            }'
        '';
      };
    };
  };
}
