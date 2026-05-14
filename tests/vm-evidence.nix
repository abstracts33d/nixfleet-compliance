# tests/vm-evidence.nix
#
# VM test: boot a NixOS host with NIS2 compliance enabled,
# run the evidence collector, verify output is valid JSON
# with expected structure.
{inputs, ...}: {
  perSystem = {
    pkgs,
    lib,
    system,
    ...
  }:
    lib.optionalAttrs (system == "x86_64-linux") {
      checks = {
        vm-compliance-evidence = pkgs.testers.nixosTest {
          name = "compliance-evidence";

          nodes.compliant = {
            config,
            pkgs,
            lib,
            ...
          }: {
            imports = [
              ../frameworks/nis2.nix
            ];

            # Enable NIS2 compliance
            compliance.frameworks.nis2 = {
              enable = true;
              entityType = "essential";
            };

            # Minimal system config for VM test
            services.openssh.enable = true;
            environment.systemPackages = [pkgs.jq];

            # Test user
            users.users.testuser = {
              isNormalUser = true;
              extraGroups = ["wheel"];
              password = "test";
            };
          };

          testScript = ''
            compliant.start()
            compliant.wait_for_unit("multi-user.target")

            # Verify evidence collector timer exists
            compliant.succeed("systemctl list-timers | grep compliance-evidence-collector")

            # Run the evidence collector manually (don't wait for timer)
            compliant.succeed("systemctl start compliance-evidence-collector.service")

            # Check evidence.json exists and is valid JSON
            compliant.succeed("test -f /var/lib/nixfleet-compliance/evidence.json")
            compliant.succeed("jq '.' /var/lib/nixfleet-compliance/evidence.json")

            # === Signed-evidence chain ===
            # Run these early so they're exercised regardless of whether
            # any later probe-specific assertion is flaky in the VM env.
            # The collector signs evidence.json with the host SSH ed25519
            # key and publishes the pubkey alongside.
            compliant.succeed("test -f /var/lib/nixfleet-compliance/evidence.json.sig")
            compliant.succeed("test -f /var/lib/nixfleet-compliance/evidence.host.pub")

            # Signature file is a single base64 line (64-byte ed25519 sig = 88 chars + newline)
            compliant.succeed(
              "test \"$(wc -c < /var/lib/nixfleet-compliance/evidence.json.sig)\" -lt 200"
            )

            # Verify the chain end-to-end with the auditor's tool
            compliant.succeed(
              "nixfleet-compliance-verify "
              "--evidence /var/lib/nixfleet-compliance/evidence.json "
              "--signature /var/lib/nixfleet-compliance/evidence.json.sig "
              "--pubkey /var/lib/nixfleet-compliance/evidence.host.pub"
            )

            # Tamper test: rewrite evidence.json after signing, verify fails
            compliant.succeed(
              "cp /var/lib/nixfleet-compliance/evidence.json /tmp/evidence.bak && "
              "cp /var/lib/nixfleet-compliance/evidence.json.sig /tmp/evidence.sig.bak"
            )
            compliant.succeed(
              "jq '.host = \"attacker\"' /var/lib/nixfleet-compliance/evidence.json "
              "> /tmp/evidence.tampered && "
              "install -m 0644 /tmp/evidence.tampered /var/lib/nixfleet-compliance/evidence.json"
            )
            compliant.fail(
              "nixfleet-compliance-verify "
              "--evidence /var/lib/nixfleet-compliance/evidence.json "
              "--signature /var/lib/nixfleet-compliance/evidence.json.sig "
              "--pubkey /var/lib/nixfleet-compliance/evidence.host.pub"
            )
            # Restore for the remaining assertions to operate on the
            # real (signed-and-verified) evidence.
            compliant.succeed(
              "install -m 0644 /tmp/evidence.bak /var/lib/nixfleet-compliance/evidence.json"
            )

            # Verify evidence structure
            evidence = compliant.succeed("cat /var/lib/nixfleet-compliance/evidence.json")

            # Check all 12 controls are present
            compliant.succeed("jq -e '.controls | length >= 12' /var/lib/nixfleet-compliance/evidence.json")

            # Check supply-chain control exists in evidence
            compliant.succeed(
              "jq -e '.controls[] | select(.control == \"supply-chain\")' "
              "/var/lib/nixfleet-compliance/evidence.json"
            )

            # Check access-control control exists in evidence
            compliant.succeed(
              "jq -e '.controls[] | select(.control == \"access-control\")' "
              "/var/lib/nixfleet-compliance/evidence.json"
            )

            # Check asset-inventory control exists in evidence
            compliant.succeed(
              "jq -e '.controls[] | select(.control == \"asset-inventory\")' "
              "/var/lib/nixfleet-compliance/evidence.json"
            )

            # Check encryption-at-rest control exists in evidence
            compliant.succeed(
              "jq -e '.controls[] | select(.control == \"encryption-at-rest\")' "
              "/var/lib/nixfleet-compliance/evidence.json"
            )

            # Verify overall field
            compliant.succeed(
              "jq -e '.overall' /var/lib/nixfleet-compliance/evidence.json"
            )

            # Check SBOM was generated (supply-chain module)
            # Note: SBOM may be empty in VM test (nix path-info needs full store metadata)
            # so we only check the file exists and is valid JSON, not that it's non-empty
            compliant.succeed("test -f /var/lib/nixfleet-compliance/sbom.json")
            compliant.succeed("jq '.' /var/lib/nixfleet-compliance/sbom.json")

            # Verify SSH hardening from access-control
            compliant.succeed("grep -q 'PasswordAuthentication no' /etc/ssh/sshd_config")

            # Verify incident-response probe reports compliant on the
            # bastion (NixOS rollback infrastructure present by default).
            # Previous assertion checked .checks.nixos_generations_available
            # >= 1, but the probe was refactored (issue #11) to a noop that
            # emits `{compliant: true}` -- the rollback property is captured
            # statically in staticEvidence, not at runtime.
            compliant.succeed(
              "jq -e '.controls[] | select(.control == \"incident-response\") | "
              ".status == \"compliant\"' "
              "/var/lib/nixfleet-compliance/evidence.json"
            )

            # Verify auditd probe detects the service as active
            compliant.succeed(
              "jq -e '.controls[] | select(.control == \"audit-logging\") | "
              ".checks.rules.\"AL-02\".auditd_active == true' "
              "/var/lib/nixfleet-compliance/evidence.json"
            )
          '';
        };
      };
    };
}
