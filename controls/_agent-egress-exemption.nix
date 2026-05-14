# controls/_agent-egress-exemption.nix
#
# Baseline: declare the agent's outbound network path and exempt it from
# firewall-lock controls. Without this, network-segmentation hardening
# can accidentally block the agent from reaching the control plane,
# stranding the host.
#
# type = "both" -- static evidence is the declared endpoint; runtime
# evidence is reachability at the declared host:port.
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.compliance.controls.agentEgressExemption;
  gov = config.compliance.governance;
  mkProbe = import ../lib/mkProbe.nix {inherit pkgs lib;};
  framework = gov.primaryFramework or "anssi-bp028";
  schemaVersion =
    config.compliance.schemaVersions.${framework}
    or (throw "compliance.schemaVersions.${framework} is not set");

  probeScript = mkProbe {
    name = "agent-egress";
    runtimeInputs = with pkgs; [curl];
    script = ''
      host='${cfg.endpoint.host}'
      port='${toString cfg.endpoint.port}'
      if curl --silent --fail --connect-timeout 5 --max-time 10 \
        -o /dev/null "https://$host:$port/healthz"; then
        reachable=true
      else
        reachable=false
      fi
      jq -n --argjson reachable "$reachable" --arg host "$host" --argjson port "$port" \
        '{ host: $host, port: $port, reachable: $reachable, compliant: $reachable }'
    '';
  };
in {
  imports = [../evidence/options.nix ../governance/options.nix];

  options.compliance.controls.agentEgressExemption = {
    enable = lib.mkEnableOption ''
      baseline agent egress exemption. Declares the control-plane endpoint
      the nixfleet agent needs to reach, and guarantees firewall-lock
      controls do not block it. MUST be enabled whenever a firewall-lock
      control is enabled on the same host.
    '';

    endpoint = lib.mkOption {
      type = lib.types.submodule {
        options = {
          host = lib.mkOption {
            type = lib.types.str;
            description = "Control-plane hostname the agent dials.";
          };
          port = lib.mkOption {
            type = lib.types.port;
            default = 443;
          };
          protocol = lib.mkOption {
            type = lib.types.enum ["https" "http/2"];
            default = "https";
          };
        };
      };
      description = "The single outbound endpoint the agent is allowed to reach.";
    };
  };

  config = lib.mkIf cfg.enable (lib.mkMerge [
    {
      compliance.evidence.probes.agentEgressExemption = {
        control = "agent-egress-exemption";
        type = "both";
        schema = schemaVersion;
        articles.nis2 = ["21(e)"];
        check = probeScript;
        staticEvidence = {
          passed = cfg.endpoint.host != "";
          evidence = {
            declaredEndpoint = cfg.endpoint;
          };
        };
        probeDescriptor = {
          command = toString probeScript;
          args = [];
          timeoutSecs = 15;
          expect = {
            compliant = true;
            reachable = true;
          };
          schema = schemaVersion;
        };
      };
    }
    {
      assertions = [
        {
          assertion =
            !(config.compliance.controls.networkSegmentation.enable or false)
            || config.compliance.controls.agentEgressExemption.enable;
          message = ''
            compliance.controls.networkSegmentation is enabled but
            compliance.controls.agentEgressExemption is not. Enabling the
            former without the latter will prevent the nixfleet agent
            from reaching the control plane. Either disable network
            segmentation or enable agent-egress-exemption with an endpoint.
          '';
        }
      ];
    }
  ]);
}
