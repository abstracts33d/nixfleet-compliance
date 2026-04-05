# evidence/collector.nix
#
# Systemd service + timer that runs evidence probes.
# Imported by evidence/options.nix when collector is enabled.
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.compliance.evidence;

  # Build a directory of probe scripts + metadata
  probeDir = pkgs.linkFarm "compliance-probes" (
    lib.flatten (
      lib.mapAttrsToList (name: probe: [
        {
          name = "probe-${probe.control}";
          path = probe.check;
        }
        {
          name = "probe-${probe.control}.meta";
          path = pkgs.writeText "probe-${probe.control}.meta" (builtins.toJSON {
            control = probe.control;
            articles = probe.articles;
          });
        }
      ])
      cfg.probes
    )
  );

  runner = pkgs.writeShellApplication {
    name = "compliance-probe-runner";
    runtimeInputs = with pkgs; [coreutils jq gnugrep hostname gawk];
    text = builtins.readFile ./probe-runner.sh;
  };
in {
  config = lib.mkIf cfg.collector.enable {
    systemd.services.compliance-evidence-collector = {
      description = "NixFleet Compliance Evidence Collector";
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${runner}/bin/compliance-probe-runner ${cfg.collector.outputDir} ${probeDir}";
        StateDirectory = "nixfleet-compliance";
        # Hardening
        NoNewPrivileges = true;
        ProtectHome = true;
        PrivateTmp = true;
      };
    };

    systemd.timers.compliance-evidence-collector = {
      description = "Run compliance evidence collection on schedule";
      wantedBy = ["timers.target"];
      timerConfig = {
        OnCalendar = cfg.collector.interval;
        Persistent = true;
        RandomizedDelaySec = "5min";
      };
    };
  };
}
