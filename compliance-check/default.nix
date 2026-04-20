# compliance-check/default.nix
#
# CLI compliance checker - runs all evidence probes and prints
# colored results. Installed as `compliance-check` in system PATH.
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.compliance.check;
  probes = config.compliance.evidence.probes;
  probeNames = lib.attrNames probes;

  checkScript = pkgs.writeShellScriptBin "compliance-check" ''
    set -o pipefail
    export PATH="${lib.makeBinPath (with pkgs; [coreutils findutils jq gnugrep gnused gawk hostname systemd])}"

    echo "NixFleet Compliance Check"
    echo "========================="
    echo "Host: $(hostname)"
    echo "Date: $(date -Iseconds)"
    echo ""

    total=0
    passed=0
    failed=0
    errors=0

    ${lib.concatMapStringsSep "\n" (name: let
        probe = probes.${name};
      in ''
        total=$((total + 1))
        if result=$("${probe.check}" 2>/dev/null); then
          compliant=$(echo "$result" | jq -r 'if has("compliant") then .compliant else true end')
          if [ "$compliant" = "true" ]; then
            printf "\033[32m  PASS\033[0m  %-30s %s\n" "${name}" "(${lib.concatStringsSep ", " (lib.attrNames (probe.articles or {}))})"
            passed=$((passed + 1))
          else
            printf "\033[31m  FAIL\033[0m  %-30s %s\n" "${name}" "(${lib.concatStringsSep ", " (lib.attrNames (probe.articles or {}))})"
            if [ "''${VERBOSE:-}" = "1" ]; then
              echo "$result" | jq -C '.' 2>/dev/null | sed 's/^/         /'
            fi
            failed=$((failed + 1))
          fi
        else
          printf "\033[33m  ERR \033[0m  %-30s %s\n" "${name}" "probe execution failed"
          errors=$((errors + 1))
        fi
      '')
      probeNames}

    echo ""
    echo "─────────────────────────────────"
    printf "Total: %d  " "$total"
    printf "\033[32mPass: %d\033[0m  " "$passed"
    printf "\033[31mFail: %d\033[0m  " "$failed"
    if [ "$errors" -gt 0 ]; then
      printf "\033[33mError: %d\033[0m" "$errors"
    fi
    echo ""

    if [ "$failed" -gt 0 ] || [ "$errors" -gt 0 ]; then
      echo ""
      echo "Tip: run with VERBOSE=1 for detailed probe output"
      exit 1
    fi
  '';
in {
  imports = [../evidence/options.nix];

  options.compliance.check = {
    enable = lib.mkEnableOption "compliance-check CLI tool";
  };

  config = lib.mkIf cfg.enable {
    environment.systemPackages = [checkScript];
  };
}
