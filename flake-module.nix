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
      };

      # Evidence layer (auto-included by controls, also importable standalone)
      evidence = ./evidence/options.nix;
    };
  };
}
