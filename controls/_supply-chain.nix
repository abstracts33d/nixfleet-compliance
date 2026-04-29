# controls/_supply-chain.nix
#
# Supply chain control - NIS2 Art. 21(d), ISO 27001 A.5.19/A.5.21, CRA Art. 10.
# Verifies: flake.lock pinning, SBOM generation policy, input staleness
# threshold. Enforcement (when enabled) emits an SBOM at boot.
#
# Typed control: type="both". Declared policy (sbomGeneration,
# inputStalenessWarningDays) is evaluated at CI time via staticEvidence.
# A runtime probe captures flake.lock age, SBOM file existence, and
# configuration-revision from the running system.
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.compliance.controls.supplyChain;
  gov = config.compliance.governance;
  mkProbe = import ../lib/mkProbe.nix {inherit pkgs lib;};
  framework = gov.primaryFramework or "nis2";
  schemaVersion =
    config.compliance.schemaVersions.${framework}
    or (throw "compliance.schemaVersions.${framework} is not set");

  # Static predicate inputs — mirror what the runtime probe verifies.
  # The runtime probe gates on:
  #   1. flake_lock_days ≤ inputStalenessWarningDays (a fact about the
  #      world — the deployed flake.lock's mtime; can't be checked
  #      statically).
  #   2. If sbomGeneration: the SBOM file exists.
  #
  # For (2) we can statically verify the SBOM-generator systemd
  # service is wired (it writes the file at boot). For (1) we can
  # only verify the threshold is non-trivial; the actual age check
  # lives at runtime where it belongs.
  sbomServiceWired =
    config.systemd.services ? compliance-sbom-generator
    && config.systemd.services.compliance-sbom-generator.enable or false;
  sbomRequirementSatisfiedStatically =
    (!cfg.sbomGeneration) || sbomServiceWired;
  stalenessThresholdReasonable = cfg.inputStalenessWarningDays > 0;

  probeScript = mkProbe {
    name = "supply-chain";
    runtimeInputs = with pkgs; [coreutils findutils gnugrep jq];
    script = ''
      # flake.lock age
      flake_lock_days=null
      if [ -f /run/current-system/flake.lock ]; then
        lock_mtime=$(stat -c %Y /run/current-system/flake.lock 2>/dev/null || echo 0)
        now=$(date +%s)
        if [ "$lock_mtime" -gt 0 ]; then
          flake_lock_days=$(( (now - lock_mtime) / 86400 ))
        fi
      fi

      # SBOM file existence
      sbom_present=false
      sbom_mtime_days=null
      if [ -f /var/lib/nixfleet-compliance/sbom.json ]; then
        sbom_present=true
        sbom_mtime=$(stat -c %Y /var/lib/nixfleet-compliance/sbom.json 2>/dev/null || echo 0)
        now=$(date +%s)
        if [ "$sbom_mtime" -gt 0 ]; then
          sbom_mtime_days=$(( (now - sbom_mtime) / 86400 ))
        fi
      fi

      # configuration-revision
      config_revision=null
      if [ -f /run/current-system/configuration-revision ]; then
        config_revision=$(cat /run/current-system/configuration-revision 2>/dev/null || echo null)
        config_revision="\"$config_revision\""
      fi

      # Compliance gate
      warn_days=${toString cfg.inputStalenessWarningDays}
      sbom_required=${
        if cfg.sbomGeneration
        then "true"
        else "false"
      }
      compliant=true
      if [ "$flake_lock_days" != "null" ] && [ "$flake_lock_days" -gt "$warn_days" ]; then
        compliant=false
      fi
      if [ "$sbom_required" = "true" ] && [ "$sbom_present" != "true" ]; then
        compliant=false
      fi

      jq -n \
        --argjson flake_lock_days "$flake_lock_days" \
        --argjson sbom_present "$sbom_present" \
        --argjson sbom_mtime_days "$sbom_mtime_days" \
        --argjson config_revision "$config_revision" \
        --argjson compliant "$compliant" \
        '{
          flake_lock_days: $flake_lock_days,
          sbom_present: $sbom_present,
          sbom_mtime_days: $sbom_mtime_days,
          config_revision: $config_revision,
          compliant: $compliant
        }'
    '';
  };
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
      type = "both";
      schema = schemaVersion;
      articles = {
        nis2 = ["21(d)"];
        iso27001 = ["A.5.19" "A.5.21"];
        cra = ["Art. 10"];
      };
      check = probeScript;
      staticEvidence = {
        # Predicate: SBOM generation is wired when required (matches
        # the runtime probe's `sbom_required → sbom_present` clause)
        # AND the staleness threshold is non-trivial. The previous
        # `passed = cfg.enable` was tautological — see issue #11.
        # flake.lock age is a runtime fact and stays in the runtime
        # probe.
        passed = sbomRequirementSatisfiedStatically && stalenessThresholdReasonable;
        evidence = {
          sbomGeneration = cfg.sbomGeneration;
          sbomServiceWired = sbomServiceWired;
          inputStalenessWarningDays = cfg.inputStalenessWarningDays;
          enforce = cfg.enforce;
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
