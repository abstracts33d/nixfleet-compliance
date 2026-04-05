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
            compliant.succeed("test -f /var/lib/nixfleet-compliance/sbom.json")
            compliant.succeed("jq '.' /var/lib/nixfleet-compliance/sbom.json")
            compliant.succeed("jq -e 'length > 0' /var/lib/nixfleet-compliance/sbom.json")

            # Verify SSH hardening from access-control
            compliant.succeed("grep -q 'PasswordAuthentication no' /etc/ssh/sshd_config")
          '';
        };
      };
    };
}
