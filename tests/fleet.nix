# tests/fleet.nix
#
# Test host configurations for eval tests.
# These are minimal NixOS configs with compliance modules enabled.
{
  pkgs,
  lib,
  nixpkgs,
  ...
}: let
  mkTestHost = {modules ? []}:
    (nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules =
        [
          {
            boot.loader.grub.device = "nodev";
            fileSystems."/" = {
              device = "/dev/sda1";
              fsType = "ext4";
            };
            system.stateVersion = "24.11";
            services.openssh.enable = lib.mkDefault true;
          }
        ]
        ++ modules;
    })
    .config;
in {
  nis2Essential = mkTestHost {
    modules = [
      ../frameworks/nis2.nix
      {
        compliance.frameworks.nis2 = {
          enable = true;
          entityType = "essential";
        };
      }
    ];
  };

  nis2Important = mkTestHost {
    modules = [
      ../frameworks/nis2.nix
      {
        compliance.frameworks.nis2 = {
          enable = true;
          entityType = "important";
        };
      }
    ];
  };

  controlsOnly = mkTestHost {
    modules = [
      ../controls/_supply-chain.nix
      ../controls/_access-control.nix
      {
        compliance.controls.supplyChain.enable = true;
        compliance.controls.accessControl.enable = true;
      }
    ];
  };

  futureControls = mkTestHost {
    modules = [
      ../controls/_network-segmentation.nix
      ../controls/_change-management.nix
      ../controls/_key-management.nix
      ../controls/_secure-boot.nix
      {
        compliance.controls.networkSegmentation.enable = true;
        compliance.controls.changeManagement.enable = true;
        compliance.controls.keyManagement.enable = true;
        compliance.controls.secureBoot.enable = true;
      }
    ];
  };

  disabled = mkTestHost {
    modules = [
      ../frameworks/nis2.nix
    ];
  };
}
