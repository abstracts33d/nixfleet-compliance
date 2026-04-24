# controls/_baseline-hardening/typed-augment.nix
#
# Typed-controls projection for baseline-hardening. The main module at
# `default.nix` imports `mkControl` with `rules.nix` to generate
# per-rule options (ANSSI R7-R14 sysctls, kernel params, module
# blocklist) and an aggregated `check` probe. We keep that DSL intact
# and ADD the typed fields (`type`, `schema`, `staticEvidence`,
# `probeDescriptor`) via module composition.
#
# Assigned framework: ISO 27001 (reference "both"-type control for
# iso27001).
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.compliance.controls.baselineHardening;
  gov = config.compliance.governance;
  framework = gov.primaryFramework or "iso27001";
  schemaVersion =
    config.compliance.schemaVersions.${framework}
    or (throw "compliance.schemaVersions.${framework} is not set");

  sysctl = config.boot.kernel.sysctl or {};
  ptraceScope = sysctl."kernel.yama.ptrace_scope" or null;
  kptrRestrict = sysctl."kernel.kptr_restrict" or null;
  dmesgRestrict = sysctl."kernel.dmesg_restrict" or null;
  randomizeVaSpace = sysctl."kernel.randomize_va_space" or null;
  modulesDisabled = sysctl."kernel.modules_disabled" or null;
  suidDumpable = sysctl."fs.suid_dumpable" or null;
  protectedSymlinks = sysctl."fs.protected_symlinks" or null;
  protectedHardlinks = sysctl."fs.protected_hardlinks" or null;

  blacklistedModules = config.boot.blacklistedKernelModules or [];

  # Static pass signal: core Yama/kptr declarations are present.
  corePassed = (ptraceScope != null) && (kptrRestrict != null);
in {
  imports = [../../evidence/options.nix ../../governance/options.nix];

  config = lib.mkIf cfg.enable {
    compliance.evidence.probes.baselineHardening = {
      type = "both";
      schema = schemaVersion;
      staticEvidence = {
        passed = corePassed;
        evidence = {
          ptraceScope = ptraceScope;
          kptrRestrict = kptrRestrict;
          dmesgRestrict = dmesgRestrict;
          randomizeVaSpace = randomizeVaSpace;
          modulesDisabled = modulesDisabled;
          suidDumpable = suidDumpable;
          protectedSymlinks = protectedSymlinks;
          protectedHardlinks = protectedHardlinks;
          blacklistedModules = blacklistedModules;
        };
      };
      probeDescriptor = {
        command = toString config.compliance.evidence.probes.baselineHardening.check;
        args = [];
        timeoutSecs = 30;
        expect = {compliant = true;};
        schema = schemaVersion;
      };
    };
  };
}
