# controls/_audit-logging/typed-augment.nix
#
# Typed-controls projection for audit-logging. The main module at
# `default.nix` uses `mkControl` + `rules.nix` to generate per-rule options
# and an aggregated `check` probe. We keep that DSL intact and ADD the
# typed fields (`type`, `schema`, `staticEvidence`, `probeDescriptor`)
# via module composition: the module system merges this attrset into the
# probe entry declared by the rules engine.
#
# Static predicate inspects the actual NixOS audit options the runtime
# probe (AL-02 in rules.nix) verifies via `systemctl is-active auditd`
# + `auditctl -l`. AL-02's `config = {...}` already self-configures
# these on enable, so the predicate passes when the rule is enabled
# AND fails to a useful diagnostic if an operator override breaks it.
# The previous `cfg.enable && enabledRuleCount > 0` counted the
# module's internal rule attrset (always > 0 once enabled at strict
# severity), making the gate vacuous on any framework-enabled fleet
# — see issue #11.
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

  # Static predicate inputs — mirror what AL-02's runtime probe
  # checks (`systemctl is-active auditd` + `auditctl -l > 0`).
  # NixOS exposes the audit daemon at `security.auditd.enable`
  # (NOT `services.auditd.*` — easy typo to make).
  auditdEnabled = config.security.auditd.enable or false;
  auditEnabled = config.security.audit.enable or false;
  rulesDeclared = config.security.audit.rules or [];
  hasDeclaredRules = rulesDeclared != [];

  # Internal rule-slot count, kept as informational evidence so
  # operators can correlate "did mkControl think this rule should
  # be enabled?" with "did NixOS actually wire auditd?".
  enabledRuleCount = builtins.length (lib.filter (n: cfg.rules.${n}.enable or false) (builtins.attrNames cfg.rules));
in {
  imports = [../../evidence/options.nix ../../governance/options.nix];

  config = lib.mkIf cfg.enable {
    compliance.evidence.probes.auditLogging = {
      type = "both";
      schema = schemaVersion;
      staticEvidence = {
        # Predicate: NixOS audit subsystem actually wired (auditd
        # service enabled, audit subsystem on, at least one rule
        # declared). Mirrors AL-02's runtime compliance condition.
        passed = auditdEnabled && auditEnabled && hasDeclaredRules;
        evidence = {
          auditdEnabled = auditdEnabled;
          auditEnabled = auditEnabled;
          declaredRulesCount = builtins.length rulesDeclared;
          enabledRuleCount = enabledRuleCount;
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
