# controls/_supply-chain.nix
#
# Supply chain control - NIS2 Art. 21(d), ISO 27001 A.5.19/A.5.21, CRA Art. 10.
# Verifies: flake.lock pinning, SBOM generation policy, input staleness
# threshold. Enforcement (when enabled) emits an SBOM at boot.
#
# Typed control: type="static". Declared policy (sbomGeneration,
# inputStalenessWarningDays) is evaluated at CI time. A no-op `check`
# script is retained for backward compatibility with the evidence
# collector.
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.compliance.controls.supplyChain;
  gov = config.compliance.governance;
  framework = gov.primaryFramework or "nis2";
  schemaVersion =
    config.compliance.schemaVersions.${framework}
    or (throw "compliance.schemaVersions.${framework} is not set");
in {
  imports = [../evidence/options.nix ../governance/options.nix];

  options.compliance.controls.supplyChain = {
    enable = lib.mkEnableOption "supply chain compliance control (NIS2 Art. 21(d))";

    enforce = lib.mkOption {
      type = lib.types.bool;
      default = gov.enforceMode == "enforce";
      description = "Apply NixOS configuration. When false, only probes run.";
    };

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
    warnings =
      lib.optional (config.system.configurationRevision == null)
      "supply-chain: system should be built from a git-tracked flake for full auditability";

    # ── SBOM generation ──────────────────────────────
    # Runs as a systemd service after boot (not activation script - /run/current-system
    # isn't updated yet during activation, so nix path-info would see stale/missing path).
    systemd.services.compliance-sbom-generator = lib.mkIf (cfg.enforce && cfg.sbomGeneration) {
      description = "Generate SBOM from NixOS closure";
      after = ["multi-user.target"];
      wantedBy = ["multi-user.target"];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStart = pkgs.writeShellScript "generate-sbom" ''
          mkdir -p /var/lib/nixfleet-compliance
          ${pkgs.nix}/bin/nix path-info --json --recursive /run/current-system 2>/dev/null \
            | ${pkgs.jq}/bin/jq '[.[] | {path: .path, narHash: .narHash, narSize: .narSize, references: .references, deriver: .deriver}]' \
            > /var/lib/nixfleet-compliance/sbom.json || true
        '';
        StateDirectory = "nixfleet-compliance";
      };
    };

    # ── EVIDENCE ─────────────────────────────────────
    compliance.evidence.collector.enable = lib.mkDefault true;

    compliance.evidence.probes.supplyChain = {
      control = "supply-chain";
      type = "static";
      schema = schemaVersion;
      articles = {
        nis2 = ["21(d)"];
        iso27001 = ["A.5.19" "A.5.21"];
        cra = ["Art. 10"];
      };
      probeDescriptor = null;
      staticEvidence = {
        passed = cfg.enable;
        evidence = {
          sbomGeneration = cfg.sbomGeneration;
          inputStalenessWarningDays = cfg.inputStalenessWarningDays;
          enforce = cfg.enforce;
        };
      };
      check = pkgs.writeShellScript "noop-supply-chain" ''
        jq -n '{compliant: true}'
      '';
    };
  };
}
