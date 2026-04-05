# tests/eval.nix
#
# Eval tests for compliance modules.
# Run via: nix flake check --no-build
{inputs, ...}: {
  perSystem = {
    pkgs,
    lib,
    system,
    ...
  }:
    lib.optionalAttrs (system == "x86_64-linux") {
      checks = let
        fleet = import ./fleet.nix {
          inherit pkgs lib;
          nixpkgs = inputs.nixpkgs;
        };

        mkEvalCheck = name: assertions:
          pkgs.runCommand "eval-test-${name}" {} (
            lib.concatStringsSep "\n" (
              map (a:
                if a.check
                then ''echo "PASS: ${a.msg}"''
                else ''echo "FAIL: ${a.msg}" >&2; exit 1'')
              assertions
            )
            + "\ntouch $out\n"
          );
      in {
        eval-nis2-enables-controls = mkEvalCheck "nis2-enables-controls" [
          {
            check = fleet.nis2Essential.compliance.controls.supplyChain.enable;
            msg = "NIS2 essential enables supply-chain control";
          }
          {
            check = fleet.nis2Essential.compliance.controls.assetInventory.enable;
            msg = "NIS2 essential enables asset-inventory control";
          }
          {
            check = fleet.nis2Essential.compliance.controls.encryptionAtRest.enable;
            msg = "NIS2 essential enables encryption-at-rest control";
          }
          {
            check = fleet.nis2Essential.compliance.controls.accessControl.enable;
            msg = "NIS2 essential enables access-control control";
          }
        ];

        eval-nis2-entity-differentiation = mkEvalCheck "nis2-entity-diff" [
          {
            check = fleet.nis2Essential.compliance.controls.accessControl.idleTimeoutMinutes == 15;
            msg = "Essential entity: idle timeout is 15 minutes";
          }
          {
            check = fleet.nis2Important.compliance.controls.accessControl.idleTimeoutMinutes == 30;
            msg = "Important entity: idle timeout is 30 minutes";
          }
          {
            check = fleet.nis2Essential.compliance.controls.supplyChain.inputStalenessWarningDays == 14;
            msg = "Essential entity: staleness warning is 14 days";
          }
          {
            check = fleet.nis2Important.compliance.controls.supplyChain.inputStalenessWarningDays == 30;
            msg = "Important entity: staleness warning is 30 days";
          }
        ];

        eval-controls-standalone = mkEvalCheck "controls-standalone" [
          {
            check = fleet.controlsOnly.compliance.controls.supplyChain.enable;
            msg = "Supply chain control works standalone";
          }
          {
            check = fleet.controlsOnly.compliance.controls.accessControl.enable;
            msg = "Access control works standalone";
          }
        ];

        eval-disabled-no-controls = mkEvalCheck "disabled-no-controls" [
          {
            check = !fleet.disabled.compliance.controls.supplyChain.enable;
            msg = "Disabled NIS2 does not enable supply-chain";
          }
          {
            check = !fleet.disabled.compliance.controls.accessControl.enable;
            msg = "Disabled NIS2 does not enable access-control";
          }
        ];

        eval-evidence-collector = mkEvalCheck "evidence-collector" [
          {
            check = fleet.nis2Essential.compliance.evidence.collector.enable;
            msg = "Evidence collector enabled when NIS2 is active";
          }
          {
            check = !fleet.disabled.compliance.evidence.collector.enable;
            msg = "Evidence collector disabled when NIS2 is inactive";
          }
        ];
      };
    };
}
