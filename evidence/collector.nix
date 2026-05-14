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

  # Compiled from tools/ (Rust): produces nixfleet-compliance-sign +
  # nixfleet-compliance-verify. Signs the JCS-canonical bytes of
  # evidence.json with the host SSH ed25519 key after every collection.
  tools = pkgs.callPackage ../tools {};

  signBinArg =
    if cfg.sign.enable
    then "${tools}/bin/nixfleet-compliance-sign"
    else "";
  publishPubkeyArg =
    if cfg.sign.publishPubkey
    then "1"
    else "0";
in {
  config = lib.mkIf cfg.collector.enable {
    systemd.services.compliance-evidence-collector = {
      description = "NixFleet Compliance Evidence Collector";
      # Run after every NixOS activation so freshly-deployed hosts
      # have evidence without waiting for the next timer tick.
      # Combined with the timer below, this gives "always within one
      # collector interval of fresh", with deploys getting immediate
      # coverage. `wantedBy = multi-user.target` also makes the
      # service start on every boot.
      wantedBy = ["multi-user.target"];
      # When signing is enabled, the collector needs the SSH host key
      # to exist. sshd.service generates it via ssh-keygen -A at startup;
      # ordering ourselves after sshd means the keys are on disk before
      # we try to sign. Harmless when sshd is disabled (After-deps that
      # don't exist or aren't started are silently ignored by systemd).
      after = lib.optionals cfg.sign.enable ["sshd.service"];
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${runner}/bin/compliance-probe-runner ${cfg.collector.outputDir} ${probeDir} ${signBinArg} ${cfg.sign.hostKeyPath} ${publishPubkeyArg}";
        StateDirectory = "nixfleet-compliance";
        # 0755 so any user can read evidence.json. The probe runner
        # writes the file mode 0644 (see probe-runner.sh). Operator
        # CLIs (compliance-check, future audit tools) read the file
        # without privilege; only the collector itself writes.
        StateDirectoryMode = "0755";
        # Hardening - probes are read-only system inspectors.
        # They need to see real system state (mounts, sysctls, services).
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ReadWritePaths = [cfg.collector.outputDir];
        ProtectControlGroups = true;
        LockPersonality = true;
        RestrictRealtime = true;
        MemoryDenyWriteExecute = true;
        # NOT set (probes need these):
        # PrivateTmp - encryption-at-rest probe must see real /tmp mount
        # ProtectKernelTunables - probes read /proc/sys/* for sysctl values
        # ProtectKernelModules - nft needs netlink access
        # RestrictNamespaces - some probes may need mount namespace visibility
        # ProtectHome - access-control probe reads /home/*/.ssh/authorized_keys
        # The signing helper also reads /etc/ssh/ssh_host_ed25519_key
        # which is mode 0600 root:root -- accessible because the collector
        # runs as root.
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
