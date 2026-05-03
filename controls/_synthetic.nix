# controls/_synthetic.nix
#
# Always-fail control for testing the agent's enforce-mode rollback
# path end-to-end without depending on a real compliance gap.
# Opt-in only: not imported by any framework. Operators set
# `compliance.controls.synthetic.alwaysFail.enable = true` on a
# throwaway host, flip the channel to enforce, observe the agent
# log + rollback, then disable.
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.compliance.controls.synthetic;
  gov = config.compliance.governance;
  mkProbe = import ../lib/mkProbe.nix {inherit pkgs lib;};
  framework = gov.primaryFramework or "anssi-bp028";
  schemaVersion =
    config.compliance.schemaVersions.${framework}
    or (throw "compliance.schemaVersions.${framework} is not set");

  probeScript = mkProbe {
    name = "synthetic-always-fail";
    runtimeInputs = [];
    script = ''
      jq -n '{compliant: false, reason: "synthetic always-fail control — operator-enabled for enforce-path verification"}'
    '';
  };
in {
  imports = [../evidence/options.nix ../governance/options.nix];

  options.compliance.controls.synthetic = {
    alwaysFail = {
      enable = lib.mkEnableOption "synthetic always-fail control (test rig for enforce-mode rollback)";
    };
  };

  config = lib.mkIf cfg.alwaysFail.enable {
    compliance.evidence.collector.enable = lib.mkDefault true;

    compliance.evidence.probes.syntheticAlwaysFail = {
      control = "synthetic-always-fail";
      type = "runtime";
      schema = schemaVersion;
      articles = {};
      check = probeScript;
      staticEvidence = {
        # Static gate also fails so a CI signing run rejects the artifact
        # before it reaches a host. Defence-in-depth: an operator who
        # forgets to disable this and pushes for real gets blocked twice.
        passed = false;
        evidence.synthetic = true;
      };
      probeDescriptor = {
        command = toString probeScript;
        args = [];
        timeoutSecs = 10;
        expect = {compliant = true;};
        schema = schemaVersion;
      };
    };
  };
}
