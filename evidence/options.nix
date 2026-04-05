# evidence/options.nix
#
# Declares compliance.evidence.* options.
# Controls register probes via compliance.evidence.probes.<name>.
# The collector module (collector.nix) consumes these.
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.compliance.evidence;

  probeType = lib.types.submodule {
    options = {
      control = lib.mkOption {
        type = lib.types.str;
        description = "Control identifier (e.g., 'supply-chain')";
      };
      articles = lib.mkOption {
        type = lib.types.attrsOf (lib.types.listOf lib.types.str);
        default = {};
        description = ''
          Framework article references.
          Example: { nis2 = ["21(d)"]; iso27001 = ["A.15"]; }
        '';
      };
      check = lib.mkOption {
        type = lib.types.package;
        description = ''
          Executable (usually a shell script) that prints a JSON object to stdout.
          The JSON must contain a "checks" key with control-specific verification results.
          Exit code 0 = probe ran successfully (regardless of compliance status).
          Non-zero exit = probe failed to run (collector marks as "error").
        '';
      };
    };
  };
in {
  imports = [./collector.nix];

  options.compliance.evidence = {
    probes = lib.mkOption {
      type = lib.types.attrsOf probeType;
      default = {};
      description = "Registered evidence probes. Controls add entries here.";
    };

    collector = {
      enable = lib.mkEnableOption "compliance evidence collector";

      interval = lib.mkOption {
        type = lib.types.str;
        default = "hourly";
        description = "Systemd calendar expression for evidence collection frequency";
      };

      outputDir = lib.mkOption {
        type = lib.types.str;
        default = "/var/lib/nixfleet-compliance";
        description = "Directory where evidence.json is written";
      };
    };
  };
}
