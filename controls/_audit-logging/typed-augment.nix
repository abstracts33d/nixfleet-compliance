# controls/_audit-logging/typed-augment.nix
#
# Typed-controls projection for audit-logging. The main module at
# `default.nix` uses `mkControl` + `rules.nix` to generate per-rule options
# and an aggregated `check` probe. We keep that DSL intact and ADD the
# typed fields (`type`, `schema`, `staticEvidence`, `probeDescriptor`)
# via module composition: the module system merges this attrset into the
# probe entry declared by the rules engine.
#
# Assigned framework: NIS2 (reference "both"-type control for nis2).
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.compliance.controls.auditLogging;
  gov = config.compliance.governance;
  framework = gov.primaryFramework or "nis2";
  schemaVersion =
    config.compliance.schemaVersions.${framework}
    or (throw "compliance.schemaVersions.${framework} is not set");

  auditdEnabled = config.services.auditd.enable or false;
  rulesDeclared = config.security.audit.rules or [];
  auditEnabled = config.security.audit.enable or false;

  # Declaration intent: control enabled + at least one rule opted in.
  # Runtime-effective state (auditdEnabled etc.) stays in `evidence` as
  # informational for auditors; the runtime `probeDescriptor` is the
  # source of truth for "is the policy actually live on this host".
  enabledRuleCount = builtins.length (lib.filter (n: cfg.rules.${n}.enable or false) (builtins.attrNames cfg.rules));
in {
  imports = [../../evidence/options.nix ../../governance/options.nix];

  config = lib.mkIf cfg.enable {
    compliance.evidence.probes.auditLogging = {
      type = "both";
      schema = schemaVersion;
      staticEvidence = {
        passed = cfg.enable && enabledRuleCount > 0;
        evidence = {
          enabledRuleCount = enabledRuleCount;
          auditdEnabled = auditdEnabled;
          auditEnabled = auditEnabled;
          rulesDeclared = rulesDeclared;
          retentionDays = cfg.retentionDays;
          forwardTo = cfg.forwardTo;
          adminEmail = cfg.adminEmail;
        };
      };
      probeDescriptor = {
        command = toString config.compliance.evidence.probes.auditLogging.check;
        args = [];
        timeoutSecs = 30;
        expect = {compliant = true;};
        schema = schemaVersion;
      };
    };
  };
}
