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

  enabledRuleCount = builtins.length (lib.filter (n: cfg.rules.${n}.enable or false) (builtins.attrNames cfg.rules));

  # Static predicate inputs -- inspect that the *essential* hardening
  # sysctls are set to safe values. Mirrors what the per-rule runtime
  # probes verify via `sysctl -a | grep`. Rules already self-configure
  # these via their `config = {...}` blocks; predicate just confirms
  # the merged NixOS config produces the expected values.
  #
  # "Essential" here is a curated subset -- the sysctls every NIS2/
  # ANSSI-aligned NixOS host should have set, regardless of host type.
  # Optional ones (kernel.modules_disabled -- breaks dynamic loading;
  # kernel.yama.ptrace_scope = 2 -- breaks gdb attach) are reported in
  # evidence but not gating, since they're often relaxed for
  # workstations or development servers.
  # Helper: treat null as 0 for the >= comparison. Nix's `or`
  # operator only works in attribute-access context, not on plain
  # variables, so an explicit if/else here.
  intOr0 = x:
    if x == null
    then 0
    else x;
  hardenedKptrRestrict = intOr0 kptrRestrict >= 1;
  hardenedDmesgRestrict = intOr0 dmesgRestrict >= 1;
  hardenedAslr = intOr0 randomizeVaSpace >= 2;
  hardenedSymlinks = intOr0 protectedSymlinks >= 1;
  hardenedHardlinks = intOr0 protectedHardlinks >= 1;
in {
  imports = [../../evidence/options.nix ../../governance/options.nix];

  config = lib.mkIf cfg.enable {
    compliance.evidence.probes.baselineHardening = {
      type = "both";
      schema = schemaVersion;
      staticEvidence = {
        # Predicate: essential hardening sysctls all set to safe
        # values (kptr_restrict ≥ 1, dmesg_restrict ≥ 1,
        # randomize_va_space = 2, protected_{sym,hard}links = 1).
        # The previous `cfg.enable && enabledRuleCount > 0` counted
        # the module's internal rule attrset (always > 0 once
        # enabled at strict severity), making the gate vacuous on
        # any framework-enabled fleet -- see issue #11.
        passed =
          hardenedKptrRestrict
          && hardenedDmesgRestrict
          && hardenedAslr
          && hardenedSymlinks
          && hardenedHardlinks;
        evidence = {
          enabledRuleCount = enabledRuleCount;
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
