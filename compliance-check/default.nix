# compliance-check/default.nix
#
# CLI compliance reader. Reads the persisted evidence.json the
# `compliance-evidence-collector` systemd service writes (as root,
# every NixOS activation + on the configurable interval).
#
# Closes abstracts33d/nixfleet-compliance#12. The previous shape
# re-executed probes inline as the calling user - produced false
# negatives whenever a probe needed root (sshd -T host key read,
# auditctl -l, root-only filesystem reads). The collector solves
# the privilege problem by running probes as root in a systemd
# unit; this CLI is a presentation layer over the resulting JSON.
#
# Modes:
# - default (any user): read JSON, format table, show timestamp/age.
#   Stale (older than `cfg.staleAfterSecs`) -> warning + non-zero exit.
#   Missing -> clear error pointing at the collector.
# - `--live` (root only): re-execute probes inline, ad-hoc. Useful
#   for development or "force a fresh run" without `systemctl start`.
#   Refuses with clear error when run as non-root.
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.compliance.check;
  probes = config.compliance.evidence.probes;
  collectorOutputDir = config.compliance.evidence.collector.outputDir;
  evidencePath = "${collectorOutputDir}/evidence.json";
  probeNames = lib.attrNames probes;

  # Inline-execution branch (`--live`). Mirrors the legacy script -
  # runs each probe directly. Refuses with a clear error when
  # invoked as non-root, since probes need privileged operations to
  # produce accurate output. Never silently reports false negatives.
  liveScriptBody = ''
    if [ "$(id -u)" -ne 0 ]; then
      echo "compliance-check --live needs root for accurate probe results." >&2
      echo "" >&2
      echo "Probes call privileged operations (sshd -T, auditctl, root-only" >&2
      echo "filesystem reads). Without root the probes silently fail and" >&2
      echo "report false negatives. Re-run via 'sudo compliance-check --live'." >&2
      exit 2
    fi

    echo "NixFleet Compliance Check (--live, ad-hoc inline execution)"
    echo "==========================================================="
    echo "Host: $(hostname)"
    echo "Date: $(date -Iseconds)"
    echo ""

    total=0
    passed=0
    failed=0
    errors=0

    ${lib.concatMapStringsSep "\n" (name: let
        probe = probes.${name};
        display = probe.control or name;
      in ''
        total=$((total + 1))
        if result=$("${probe.check}" 2>/dev/null); then
          compliant=$(echo "$result" | jq -r 'if has("compliant") then .compliant else true end')
          if [ "$compliant" = "true" ]; then
            printf "\033[32m  PASS\033[0m  %-30s %s\n" "${display}" "(${lib.concatStringsSep ", " (lib.attrNames (probe.articles or {}))})"
            passed=$((passed + 1))
          else
            printf "\033[31m  FAIL\033[0m  %-30s %s\n" "${display}" "(${lib.concatStringsSep ", " (lib.attrNames (probe.articles or {}))})"
            if [ "''${VERBOSE:-}" = "1" ]; then
              echo "$result" | jq -C '.' 2>/dev/null | sed 's/^/         /'
            fi
            failed=$((failed + 1))
          fi
        else
          printf "\033[33m  ERR \033[0m  %-30s %s\n" "${display}" "probe execution failed"
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

  # Reader branch (default, runs as any user). Reads evidence.json
  # the collector wrote, formats the same table compliance-check has
  # always produced. Staleness detection prevents operators from
  # staring at hour-old data after a config change without
  # realizing it.
  readerScriptBody = ''
    EVIDENCE="${evidencePath}"
    STALE_AFTER_SECS=${toString cfg.staleAfterSecs}

    if [ ! -f "$EVIDENCE" ]; then
      echo "compliance-check: evidence file missing." >&2
      echo "  Path: $EVIDENCE" >&2
      echo "" >&2
      echo "The compliance-evidence-collector service hasn't run yet, or" >&2
      echo "its output directory is misconfigured. To populate evidence:" >&2
      echo "" >&2
      echo "    sudo systemctl start compliance-evidence-collector" >&2
      echo "" >&2
      echo "On a freshly-deployed host this normally happens at activation" >&2
      echo "time (see compliance.evidence.collector.* options)." >&2
      exit 2
    fi

    if [ ! -r "$EVIDENCE" ]; then
      echo "compliance-check: evidence file unreadable by current user." >&2
      echo "  Path: $EVIDENCE" >&2
      echo "  Mode: $(stat -c '%a %U:%G' "$EVIDENCE" 2>/dev/null || echo unknown)" >&2
      echo "" >&2
      echo "Expected: 0644 root:root. The collector should set this - if" >&2
      echo "it's wrong, restart the service:" >&2
      echo "" >&2
      echo "    sudo systemctl start compliance-evidence-collector" >&2
      exit 2
    fi

    # Staleness check.
    timestamp=$(jq -r '.timestamp // empty' < "$EVIDENCE" 2>/dev/null || echo "")
    if [ -z "$timestamp" ]; then
      echo "compliance-check: evidence file has no timestamp - corrupt or pre-#12." >&2
      echo "Re-run the collector: sudo systemctl start compliance-evidence-collector" >&2
      exit 2
    fi
    evidence_epoch=$(date -d "$timestamp" +%s 2>/dev/null || echo 0)
    now_epoch=$(date +%s)
    age_secs=$((now_epoch - evidence_epoch))

    is_stale=false
    if [ "$age_secs" -gt "$STALE_AFTER_SECS" ]; then
      is_stale=true
    fi

    # Header
    host=$(jq -r '.host // "unknown"' < "$EVIDENCE")
    echo "NixFleet Compliance Check"
    echo "========================="
    echo "Host: $host"
    echo "Evidence collected: $timestamp ($(printf '%dh%02dm ago' $((age_secs / 3600)) $(((age_secs % 3600) / 60))))"
    if [ "$is_stale" = "true" ]; then
      printf "\033[33mWARNING: evidence older than %ds - collector may have stalled. Re-run:\033[0m\n" "$STALE_AFTER_SECS"
      echo "    sudo systemctl start compliance-evidence-collector"
    fi
    echo ""

    # Render the same per-control table compliance-check always has,
    # sourced from JSON. controls[*].framework_articles is an attrset
    # of {framework: [article-ids]}; we list the framework keys
    # alphabetically (matches the legacy `articles | keys` output).
    total=0
    passed=0
    failed=0
    errors=0

    while IFS=$'\t' read -r control status frameworks; do
      [ -z "$control" ] && continue
      total=$((total + 1))
      case "$status" in
        compliant)
          printf "\033[32m  PASS\033[0m  %-30s (%s)\n" "$control" "$frameworks"
          passed=$((passed + 1))
          ;;
        non-compliant)
          printf "\033[31m  FAIL\033[0m  %-30s (%s)\n" "$control" "$frameworks"
          failed=$((failed + 1))
          if [ "''${VERBOSE:-}" = "1" ]; then
            jq --arg c "$control" '.controls[] | select(.control == $c) | .checks' "$EVIDENCE" 2>/dev/null \
              | jq -C '.' 2>/dev/null | sed 's/^/         /'
          fi
          ;;
        error)
          printf "\033[33m  ERR \033[0m  %-30s (%s) probe execution failed\n" "$control" "$frameworks"
          errors=$((errors + 1))
          if [ "''${VERBOSE:-}" = "1" ]; then
            jq --arg c "$control" '.controls[] | select(.control == $c) | .checks' "$EVIDENCE" 2>/dev/null \
              | jq -C '.' 2>/dev/null | sed 's/^/         /'
          fi
          ;;
        *)
          printf "\033[35m  ?   \033[0m  %-30s (%s) unknown status: %s\n" "$control" "$frameworks" "$status"
          ;;
      esac
    done < <(jq -r '.controls[] | [.control, .status, (.framework_articles | keys | sort | join(", "))] | @tsv' < "$EVIDENCE")

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
      echo "Tip: '--live' re-runs probes inline (root only); useful when"
      echo "     evidence.json may be stale relative to a recent activation."
      exit 1
    fi
    if [ "$is_stale" = "true" ]; then
      exit 1
    fi
  '';

  checkScript = pkgs.writeShellScriptBin "compliance-check" ''
    set -o pipefail
    export PATH="${lib.makeBinPath (with pkgs; [coreutils findutils jq gnugrep gnused gawk hostname systemd])}"

    case "''${1:-}" in
      --live)
        shift
        ${liveScriptBody}
        ;;
      -h|--help)
        cat <<EOF
    compliance-check - read NixFleet compliance evidence

    Usage:
      compliance-check          Read persisted evidence.json (any user)
      compliance-check --live   Re-execute probes inline (root only)
      compliance-check --help   Show this help

    Environment:
      VERBOSE=1                 Print probe checks/evidence for FAILs

    Evidence file: ${evidencePath}
    Refresh:       sudo systemctl start compliance-evidence-collector
    EOF
        exit 0
        ;;
      ?*)
        echo "compliance-check: unknown argument '$1'" >&2
        echo "See 'compliance-check --help'" >&2
        exit 64
        ;;
      *)
        ${readerScriptBody}
        ;;
    esac
  '';
in {
  imports = [../evidence/options.nix];

  options.compliance.check = {
    enable = lib.mkEnableOption "compliance-check CLI tool";

    staleAfterSecs = lib.mkOption {
      type = lib.types.int;
      default = 7200;
      description = ''
        Maximum age of `evidence.json` (seconds) before
        `compliance-check` warns that the data is stale and exits
        non-zero. Default 2h matches the collector's default
        "hourly" interval with one tick of slack. Set higher if
        you intentionally run the collector less frequently;
        lower if you need fresher data guaranteed.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    environment.systemPackages = [checkScript];
  };
}
