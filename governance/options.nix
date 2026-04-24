# governance/options.nix
#
# Fleet-wide compliance governance policy.
# Controls read these options to determine enforcement behavior.
# Framework presets (nis2.nix, anssi.nix) set defaults here.
{
  config,
  lib,
  ...
}: let
  cfg = config.compliance.governance;
in {
  options.compliance.governance = {
    enforceMode = lib.mkOption {
      type = lib.types.enum ["report" "enforce"];
      default = "enforce";
      description = ''
        Global enforcement mode.
        - "report": controls only run probes, no NixOS config applied.
        - "enforce": controls apply NixOS config AND run probes.
        Individual controls can override this via their own `enforce` option.
      '';
    };

    level = lib.mkOption {
      type = lib.types.enum ["minimal" "standard" "strict" "paranoid"];
      default = "standard";
      description = ''
        Severity threshold for rule activation.
        Rules with severity above this level are auto-disabled.
        - minimal: only critical rules
        - standard: baseline hardening (default)
        - strict: aggressive hardening (may break some workloads)
        - paranoid: all rules enabled (ANSSI "reinforced"+"high" equivalent)
      '';
    };

    hostType = lib.mkOption {
      type = lib.types.enum ["server" "workstation" "appliance"];
      default = "server";
      description = ''
        Host classification. Rules can scope themselves to specific host types.
        - server: production infrastructure (default)
        - workstation: developer/admin machines
        - appliance: embedded/single-purpose devices
      '';
    };

    excludes = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [];
      description = ''
        Tag-based rule exclusions.
        Rules tagged with any of these strings are auto-disabled.
        Example: ["no-ipv6" "disable-kernel-module-loading"]
      '';
    };

    architecture = lib.mkOption {
      type = lib.types.str;
      default = "x86_64";
      description = ''
        Host CPU architecture using Nix platform naming (e.g., "x86_64", "aarch64"),
        not Linux kernel naming. Rules can scope themselves to specific architectures.
        Set automatically by frameworks via parsed.cpu.name, or override for cross-compilation.
      '';
    };

    primaryFramework = lib.mkOption {
      type = lib.types.str;
      default = "anssi-bp028";
      description = ''
        Primary compliance framework. Used by typed controls to look up
        the schema version in `compliance.schemaVersions.<framework>`.
      '';
    };

    exceptions = lib.mkOption {
      type = lib.types.attrsOf (lib.types.submodule {
        options.rationale = lib.mkOption {
          type = lib.types.str;
          description = "Mandatory explanation for why this rule is excepted";
        };
      });
      default = {};
      description = ''
        Per-rule exceptions with mandatory rationale.
        Keys are rule IDs (e.g., "BH-07"). The rationale is included
        in the compliance report for audit purposes.
        Example: { "BH-07".rationale = "IPv6 required for internal mesh"; }
      '';
    };
  };

  options.compliance.schemaVersions = lib.mkOption {
    type = lib.types.attrsOf lib.types.str;
    default = {};
    description = ''
      Per-framework schema versions for typed-control evidence payloads.
      Example: { "anssi-bp028" = "anssi-bp028/v1"; }
    '';
  };
}
