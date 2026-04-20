# governance/report.nix
#
# Builds a compliance report with per-control status and exclusion reasoning.
# Produces system.build.complianceReport (eval-time attrset) and
# system.build.complianceReportDocument (JSON file).
{
  config,
  lib,
  pkgs,
  ...
}: let
  gov = config.compliance.governance;
  controls = config.compliance.controls;

  # Helper: read an attribute with fallback
  getOr = attr: default: set:
    if lib.hasAttr attr set
    then set.${attr}
    else default;

  # Collect metadata from controls that have it (mkControl-based)
  controlMetas = lib.filterAttrs (_: c: c ? _meta) controls;

  # Build report for mkControl-based controls (have _meta with rule details)
  mkControlReports =
    lib.mapAttrs (name: ctrl: {
      enabled = ctrl.enable;
      enforced = getOr "enforce" false ctrl;
      ruleCount = getOr "ruleCount" 0 ctrl._meta;
      enabledRuleCount = getOr "enabledRuleCount" 0 ctrl._meta;
      exclusions = getOr "exclusions" {} ctrl._meta;
      articles = getOr "articles" {} ctrl._meta;
    })
    controlMetas;

  # Build report for simple controls (no _meta)
  simpleControls = lib.filterAttrs (_: c: !(c ? _meta) && (c ? enable)) controls;
  simpleControlReports =
    lib.mapAttrs (name: ctrl: {
      enabled = ctrl.enable;
      enforced = getOr "enforce" false ctrl;
    })
    simpleControls;

  complianceReport = {
    "org.nixfleet.compliance.v1" = {
      hostname = config.networking.hostName or "unknown";
      domain = config.networking.domain or null;
      governance = {
        inherit (gov) enforceMode level hostType;
        excludeCount = builtins.length gov.excludes;
        exceptionCount = builtins.length (lib.attrNames gov.exceptions);
      };
      controls = mkControlReports // simpleControlReports;
      exceptions = lib.mapAttrs (_: e: e.rationale) gov.exceptions;
    };
  };
in {
  imports = [./options.nix];

  config = {
    system.build.complianceReport = complianceReport;
    system.build.complianceReportDocument =
      pkgs.writers.writeJSON "compliance-report.json" complianceReport;
  };
}
