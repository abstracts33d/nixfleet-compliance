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
      type = lib.mkOption {
        type = lib.types.nullOr (lib.types.enum ["static" "runtime" "both"]);
        default = null;
        description = ''
          Typed-control discriminator. When set, the probe also publishes
          a typed projection (staticEvidence and/or probeDescriptor) in
          addition to the legacy `check` script. Null means this probe
          predates the typed controls migration.
        '';
      };
      schema = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        description = ''
          Schema version for the typed projection (e.g. "anssi-bp028/v1").
          Pulled from `compliance.schemaVersions.<framework>`.
        '';
      };
      staticEvidence = lib.mkOption {
        type = lib.types.nullOr lib.types.attrs;
        default = null;
        description = ''
          Result of the static evaluator at CI time. Null for type="runtime".
        '';
      };
      probeDescriptor = lib.mkOption {
        type = lib.types.nullOr lib.types.attrs;
        default = null;
        description = ''
          CONTRACTS §I.3 probe descriptor the agent executes on-host.
          Null for type="static".
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

    # On-disk signing of evidence.json. Signs the JCS-canonical bytes
    # of the evidence file using the host's SSH ed25519 key. An auditor
    # with the host's SSH public key can verify the chain offline using
    # `nixfleet-compliance-verify`.
    #
    # Independent of the wire-summary signing the nixfleet agent performs:
    # both reuse the same SSH host key and coexist (different payloads).
    sign = {
      enable = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = ''
          Sign evidence.json with the host's SSH ed25519 key after every
          collection. Produces `evidence.json.sig` (base64-encoded
          ed25519 signature over the JCS-canonical bytes) next to
          `evidence.json` in the collector output directory.

          Default true so the auditor chain works out of the box. Set
          false on hosts that don't have an ed25519 SSH host key or
          where signing is handled elsewhere.
        '';
      };

      hostKeyPath = lib.mkOption {
        type = lib.types.str;
        default = "/etc/ssh/ssh_host_ed25519_key";
        description = ''
          Path to the SSH ed25519 private key used to sign evidence.
          Must be readable by root (the collector runs as root). The
          corresponding public key (with `.pub` suffix) is what the
          auditor uses to verify.
        '';
      };

      publishPubkey = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = ''
          Copy `<hostKeyPath>.pub` into the collector output directory
          as `evidence.host.pub`. Default true so the auditor receives
          a self-contained directory: evidence.json + evidence.json.sig
          + evidence.host.pub is all they need to verify offline.
        '';
      };
    };
  };
}
