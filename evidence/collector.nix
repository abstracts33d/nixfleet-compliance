# evidence/collector.nix
#
# Systemd service + timer that runs evidence probes.
# Imported by evidence/options.nix when collector is enabled.
{
  config,
  lib,
  options,
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

  # Impermanence detection: the environment.persistence option only exists
  # when the impermanence NixOS module is imported (via nixfleet's mkHost or manually).
  # We check `options` to see if the option is declared, then check hostSpec for the flag.
  # This must use `options ? X.Y` (not hasAttr on config) to avoid triggering evaluation.
  hasImpermanence = options ? environment.persistence;
  hasHostSpec = options ? hostSpec.isImpermanent;
  isImpermanent = hasImpermanence && hasHostSpec && config.hostSpec.isImpermanent;
in {
  config = lib.mkIf cfg.collector.enable (
    lib.mkMerge [
      {
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
      }

      # Impermanence: persist evidence across reboots.
      # Only activates when the impermanence module is loaded AND hostSpec.isImpermanent is true.
      # Uses lib.optionalAttrs (not lib.mkIf) to avoid creating the option definition at all
      # when the impermanence module isn't present — NixOS rejects undefined option paths
      # even under a false mkIf.
      (lib.optionalAttrs isImpermanent {
        environment.persistence."/persist".directories = [cfg.collector.outputDir];
      })
    ]
  );
}
