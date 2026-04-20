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

        eval-nis2-hardening-controls = mkEvalCheck "nis2-hardening-controls" [
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

        eval-nis2-governance-differentiation = mkEvalCheck "nis2-governance-diff" [
          {
            check = fleet.nis2Essential.compliance.governance.level == "strict";
            msg = "Essential entity: governance level is strict";
          }
          {
            check = fleet.nis2Important.compliance.governance.level == "standard";
            msg = "Important entity: governance level is standard";
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

        eval-nis2-response-controls = mkEvalCheck "nis2-response-controls" [
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

        eval-nis2-response-differentiation = mkEvalCheck "nis2-response-diff" [
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

        eval-policy-controls-standalone = mkEvalCheck "policy-controls-standalone" [
          {
            check = fleet.policyControls.compliance.controls.networkSegmentation.enable;
            msg = "Network segmentation control works standalone";
          }
          {
            check = fleet.policyControls.compliance.controls.changeManagement.enable;
            msg = "Change management control works standalone";
          }
          {
            check = fleet.policyControls.compliance.controls.keyManagement.enable;
            msg = "Key management control works standalone";
          }
          {
            check = fleet.policyControls.compliance.controls.secureBoot.enable;
            msg = "Secure boot control works standalone";
          }
        ];

        # DORA framework tests
        eval-dora-enables-controls = mkEvalCheck "dora-enables-controls" [
          {
            check = fleet.doraCritical.compliance.controls.accessControl.enable;
            msg = "DORA enables access-control";
          }
          {
            check = fleet.doraCritical.compliance.controls.assetInventory.enable;
            msg = "DORA enables asset-inventory";
          }
          {
            check = fleet.doraCritical.compliance.controls.networkSegmentation.enable;
            msg = "DORA enables network-segmentation";
          }
          {
            check = fleet.doraCritical.compliance.controls.incidentResponse.enable;
            msg = "DORA enables incident-response";
          }
          {
            check = fleet.doraCritical.compliance.controls.changeManagement.enable;
            msg = "DORA enables change-management";
          }
        ];

        eval-dora-critical-differentiation = mkEvalCheck "dora-critical-diff" [
          {
            check = fleet.doraCritical.compliance.controls.accessControl.idleTimeoutMinutes == 15;
            msg = "Critical provider: idle timeout is 15 minutes";
          }
          {
            check = fleet.doraStandard.compliance.controls.accessControl.idleTimeoutMinutes == 30;
            msg = "Standard entity: idle timeout is 30 minutes";
          }
          {
            check = fleet.doraCritical.compliance.controls.vulnerabilityMgmt.blockOnCritical == true;
            msg = "Critical provider: block on critical CVEs";
          }
          {
            check = fleet.doraStandard.compliance.controls.vulnerabilityMgmt.blockOnCritical == false;
            msg = "Standard entity: don't block on critical CVEs";
          }
          {
            check = fleet.doraCritical.compliance.controls.authentication.mfaRequired == true;
            msg = "Critical provider: MFA required";
          }
        ];

        # ISO 27001 framework tests
        eval-iso27001-enables-controls = mkEvalCheck "iso27001-enables-controls" [
          {
            check = fleet.iso27001Full.compliance.controls.supplyChain.enable;
            msg = "ISO 27001 enables supply-chain (A.15)";
          }
          {
            check = fleet.iso27001Full.compliance.controls.encryptionAtRest.enable;
            msg = "ISO 27001 enables encryption-at-rest (A.10)";
          }
          {
            check = fleet.iso27001Full.compliance.controls.keyManagement.enable;
            msg = "ISO 27001 enables key-management (A.10)";
          }
          {
            check = fleet.iso27001Full.compliance.controls.auditLogging.enable;
            msg = "ISO 27001 enables audit-logging (A.12.4)";
          }
          {
            check = fleet.iso27001Full.compliance.controls.changeManagement.enable;
            msg = "ISO 27001 enables change-management (A.12.1)";
          }
          {
            check = fleet.iso27001Full.compliance.controls.baselineHardening.enable;
            msg = "ISO 27001 enables baseline-hardening (A.8)";
          }
        ];

        eval-iso27001-scope-differentiation = mkEvalCheck "iso27001-scope-diff" [
          {
            check = fleet.iso27001Full.compliance.governance.level == "strict";
            msg = "Full scope: governance level is strict";
          }
          {
            check = fleet.iso27001Partial.compliance.governance.level == "standard";
            msg = "Partial scope: governance level is standard";
          }
          {
            check = fleet.iso27001Full.compliance.controls.keyManagement.maxKeyAgeDays == 365;
            msg = "Full scope: key rotation is 365 days";
          }
          {
            check = fleet.iso27001Partial.compliance.controls.keyManagement.maxKeyAgeDays == 730;
            msg = "Partial scope: key rotation is 730 days";
          }
          {
            check = fleet.iso27001Full.compliance.controls.vulnerabilityMgmt.blockOnCritical == true;
            msg = "Full scope: block on critical CVEs";
          }
          {
            check = fleet.iso27001Partial.compliance.controls.vulnerabilityMgmt.blockOnCritical == false;
            msg = "Partial scope: don't block on critical CVEs";
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

        # ANSSI framework tests
        eval-anssi-enables-controls = mkEvalCheck "anssi-enables-controls" [
          {
            check = fleet.anssiIntermediary.compliance.controls.baselineHardening.enable;
            msg = "ANSSI intermediary enables baseline-hardening";
          }
          {
            check = fleet.anssiIntermediary.compliance.controls.auditLogging.enable;
            msg = "ANSSI intermediary enables audit-logging";
          }
          {
            check = fleet.anssiIntermediary.compliance.controls.accessControl.enable;
            msg = "ANSSI intermediary enables access-control";
          }
          {
            check = fleet.anssiIntermediary.compliance.governance.level == "standard";
            msg = "ANSSI intermediary maps to governance level standard";
          }
        ];

        eval-anssi-level-differentiation = mkEvalCheck "anssi-level-diff" [
          {
            check = fleet.anssiReinforced.compliance.governance.level == "strict";
            msg = "ANSSI reinforced maps to governance level strict";
          }
          {
            check = fleet.anssiIntermediary.compliance.governance.level == "standard";
            msg = "ANSSI intermediary maps to governance level standard";
          }
        ];

        # Governance tests
        eval-governance-report-mode = mkEvalCheck "governance-report-mode" [
          {
            check = fleet.reportOnly.compliance.governance.enforceMode == "report";
            msg = "Report-only mode: enforceMode is report";
          }
          {
            check = !fleet.reportOnly.compliance.controls.baselineHardening.enforce;
            msg = "Report-only mode: baseline-hardening enforce is false";
          }
          {
            check = fleet.reportOnly.compliance.controls.baselineHardening.enable;
            msg = "Report-only mode: baseline-hardening is still enabled (probes run)";
          }
        ];

        eval-governance-exceptions = mkEvalCheck "governance-exceptions" [
          {
            check = !(fleet.withExceptions.compliance.controls.baselineHardening.rules."BH-07".enable);
            msg = "Exception: BH-07 (disable-ipv6) is disabled via exception";
          }
          {
            check = fleet.withExceptions.compliance.controls.baselineHardening.rules."BH-03".enable;
            msg = "Non-excepted rule BH-03 (kernel sysctls) is still enabled";
          }
        ];

        eval-governance-architecture = mkEvalCheck "governance-architecture" [
          {
            check = !(fleet.aarch64Simulated.compliance.controls.baselineHardening.rules."BH-01".enable);
            msg = "aarch64: BH-01 (IOMMU) is disabled (x86_64-only)";
          }
          {
            check = !(fleet.aarch64Simulated.compliance.controls.baselineHardening.rules."BH-02".enable);
            msg = "aarch64: BH-02 (memory boot) is disabled (x86_64-only)";
          }
          {
            check = fleet.aarch64Simulated.compliance.controls.baselineHardening.rules."BH-03".enable;
            msg = "aarch64: BH-03 (kernel sysctls) is still enabled (arch-independent)";
          }
        ];

        # Multi-framework priority tests
        eval-multi-framework-priority = mkEvalCheck "multi-framework-priority" [
          {
            check = fleet.multiFrameworkNis2Anssi.compliance.governance.level == "strict";
            msg = "NIS2 essential (strict/70) wins over ANSSI intermediary (standard/80)";
          }
          {
            check = fleet.multiFrameworkNis2Anssi.compliance.governance.hostType == "server";
            msg = "Multi-framework: hostType uses governance default (frameworks don't set it)";
          }
          {
            check = fleet.multiFrameworkNis2Anssi.compliance.controls.auditLogging.retentionDays == 730;
            msg = "Multi-framework: NIS2 essential retention (730) wins over ANSSI (365)";
          }
          {
            check = fleet.multiFrameworkNis2Anssi.compliance.controls.accessControl.enable;
            msg = "Multi-framework: access control enabled";
          }
          {
            check = fleet.multiFrameworkNis2Anssi.compliance.controls.secureBoot.enable;
            msg = "Multi-framework: ANSSI-only controls (secureBoot) still enabled";
          }
        ];

        eval-compliance-check = mkEvalCheck "compliance-check" [
          {
            check = fleet.nis2Essential.compliance.check.enable;
            msg = "NIS2 framework enables compliance-check CLI";
          }
          {
            check = fleet.anssiIntermediary.compliance.check.enable;
            msg = "ANSSI framework enables compliance-check CLI";
          }
        ];
      };
    };
}
