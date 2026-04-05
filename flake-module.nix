# Compliance framework exports.
# Each control is available individually or via framework presets.
{lib, ...}: {
  flake = {
    nixosModules = {
      # Framework presets (enable a full framework with one import)
      nis2 = ./frameworks/nis2.nix;

      # Individual controls (pick what you need)
      controls = {
        supply-chain = ./controls/_supply-chain.nix;
        asset-inventory = ./controls/_asset-inventory.nix;
        encryption-at-rest = ./controls/_encryption-at-rest.nix;
        access-control = ./controls/_access-control.nix;
        baseline-hardening = ./controls/_baseline-hardening.nix;
        audit-logging = ./controls/_audit-logging.nix;
        backup-retention = ./controls/_backup-retention.nix;
        encryption-in-transit = ./controls/_encryption-in-transit.nix;
        incident-response = ./controls/_incident-response.nix;
        disaster-recovery = ./controls/_disaster-recovery.nix;
        vulnerability-mgmt = ./controls/_vulnerability-mgmt.nix;
        authentication = ./controls/_authentication.nix;
        network-segmentation = ./controls/_network-segmentation.nix;
        change-management = ./controls/_change-management.nix;
        key-management = ./controls/_key-management.nix;
        secure-boot = ./controls/_secure-boot.nix;
      };

      # Evidence layer (auto-included by controls, also importable standalone)
      evidence = ./evidence/options.nix;
    };
  };
}
