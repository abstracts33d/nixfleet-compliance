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

        eval-phase2-controls-enabled = mkEvalCheck "phase2-controls-enabled" [
          {
            check = fleet.nis2Essential.compliance.controls.baselineHardening.enable;
            msg = "NIS2 essential enables baseline-hardening";
          }
          {
            check = fleet.nis2Essential.compliance.controls.auditLogging.enable;
            msg = "NIS2 essential enables audit-logging";
          }
          {
            check = fleet.nis2Essential.compliance.controls.backupRetention.enable;
            msg = "NIS2 essential enables backup-retention";
          }
          {
            check = fleet.nis2Essential.compliance.controls.encryptionInTransit.enable;
            msg = "NIS2 essential enables encryption-in-transit";
          }
        ];

        eval-phase2-entity-differentiation = mkEvalCheck "phase2-entity-diff" [
          {
            check = fleet.nis2Essential.compliance.controls.baselineHardening.level == "strict";
            msg = "Essential entity: hardening level is strict";
          }
          {
            check = fleet.nis2Important.compliance.controls.baselineHardening.level == "standard";
            msg = "Important entity: hardening level is standard";
          }
          {
            check = fleet.nis2Essential.compliance.controls.auditLogging.retentionDays == 730;
            msg = "Essential entity: audit retention is 730 days";
          }
          {
            check = fleet.nis2Important.compliance.controls.auditLogging.retentionDays == 365;
            msg = "Important entity: audit retention is 365 days";
          }
        ];

        eval-phase3-controls-enabled = mkEvalCheck "phase3-controls-enabled" [
          {
            check = fleet.nis2Essential.compliance.controls.incidentResponse.enable;
            msg = "NIS2 essential enables incident-response";
          }
          {
            check = fleet.nis2Essential.compliance.controls.disasterRecovery.enable;
            msg = "NIS2 essential enables disaster-recovery";
          }
          {
            check = fleet.nis2Essential.compliance.controls.vulnerabilityMgmt.enable;
            msg = "NIS2 essential enables vulnerability-mgmt";
          }
          {
            check = fleet.nis2Essential.compliance.controls.authentication.enable;
            msg = "NIS2 essential enables authentication";
          }
        ];

        eval-phase3-entity-differentiation = mkEvalCheck "phase3-entity-diff" [
          {
            check = fleet.nis2Essential.compliance.controls.disasterRecovery.minGenerations == 10;
            msg = "Essential entity: min generations is 10";
          }
          {
            check = fleet.nis2Important.compliance.controls.disasterRecovery.minGenerations == 5;
            msg = "Important entity: min generations is 5";
          }
          {
            check = fleet.nis2Essential.compliance.controls.vulnerabilityMgmt.blockOnCritical == true;
            msg = "Essential entity: block on critical CVEs";
          }
          {
            check = fleet.nis2Important.compliance.controls.vulnerabilityMgmt.blockOnCritical == false;
            msg = "Important entity: don't block on critical CVEs";
          }
          {
            check = fleet.nis2Essential.compliance.controls.authentication.mfaRequired == true;
            msg = "Essential entity: MFA required";
          }
          {
            check = fleet.nis2Important.compliance.controls.authentication.mfaRequired == false;
            msg = "Important entity: MFA not required";
          }
        ];

        eval-future-controls-standalone = mkEvalCheck "future-controls-standalone" [
          {
            check = fleet.futureControls.compliance.controls.networkSegmentation.enable;
            msg = "Network segmentation control works standalone";
          }
          {
            check = fleet.futureControls.compliance.controls.changeManagement.enable;
            msg = "Change management control works standalone";
          }
          {
            check = fleet.futureControls.compliance.controls.keyManagement.enable;
            msg = "Key management control works standalone";
          }
          {
            check = fleet.futureControls.compliance.controls.secureBoot.enable;
            msg = "Secure boot control works standalone";
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
