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

  policyControls = mkTestHost {
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

  # DORA framework presets
  doraCritical = mkTestHost {
    modules = [
      ../frameworks/dora.nix
      {
        compliance.frameworks.dora = {
          enable = true;
          criticalProvider = true;
        };
      }
    ];
  };

  doraStandard = mkTestHost {
    modules = [
      ../frameworks/dora.nix
      {compliance.frameworks.dora.enable = true;}
    ];
  };

  # ISO 27001 framework presets
  iso27001Full = mkTestHost {
    modules = [
      ../frameworks/iso27001.nix
      {
        compliance.frameworks.iso27001 = {
          enable = true;
          certificationScope = "full";
        };
      }
    ];
  };

  iso27001Partial = mkTestHost {
    modules = [
      ../frameworks/iso27001.nix
      {
        compliance.frameworks.iso27001 = {
          enable = true;
          certificationScope = "partial";
        };
      }
    ];
  };

  disabled = mkTestHost {
    modules = [
      ../frameworks/nis2.nix
    ];
  };

  # ANSSI framework presets
  anssiIntermediary = mkTestHost {
    modules = [
      ../frameworks/anssi.nix
      {
        compliance.frameworks.anssi = {
          enable = true;
          level = "intermediary";
          category = "server";
        };
      }
    ];
  };

  anssiReinforced = mkTestHost {
    modules = [
      ../frameworks/anssi.nix
      {
        compliance.frameworks.anssi = {
          enable = true;
          level = "reinforced";
          category = "server";
        };
      }
    ];
  };

  # Governance: report-only mode
  reportOnly = mkTestHost {
    modules = [
      ../frameworks/nis2.nix
      {
        compliance.frameworks.nis2 = {
          enable = true;
          entityType = "essential";
        };
        compliance.governance.enforceMode = "report";
      }
    ];
  };

  # Governance: with exceptions
  withExceptions = mkTestHost {
    modules = [
      ../frameworks/anssi.nix
      {
        compliance.frameworks.anssi = {
          enable = true;
          level = "reinforced";
          exceptions = {
            "BH-07".rationale = "IPv6 required for internal mesh";
          };
        };
      }
    ];
  };

  # Multi-framework: NIS2 essential (strict) + ANSSI intermediary (standard)
  # NIS2 strict (priority 70) should win over ANSSI standard (priority 80)
  multiFrameworkNis2Anssi = mkTestHost {
    modules = [
      ../frameworks/nis2.nix
      ../frameworks/anssi.nix
      {
        compliance.frameworks.nis2 = {
          enable = true;
          entityType = "essential";
        };
        compliance.frameworks.anssi = {
          enable = true;
          level = "intermediary";
          category = "server";
        };
      }
    ];
  };

  # Governance: architecture filtering (simulated aarch64)
  aarch64Simulated = mkTestHost {
    modules = [
      ../frameworks/anssi.nix
      {
        compliance.frameworks.anssi = {
          enable = true;
          level = "reinforced";
          category = "server";
        };
        # Override architecture to simulate aarch64 on x86 eval
        compliance.governance.architecture = "aarch64";
      }
    ];
  };
}
