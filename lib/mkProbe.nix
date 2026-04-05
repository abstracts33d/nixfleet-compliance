# lib/mkProbe.nix
#
# mkProbe: wraps a probe script with common boilerplate.
# Handles: set -euo pipefail, PATH with common tools, jq validation.
#
# Usage in a control module:
#   mkProbe = import ../lib/mkProbe.nix {inherit pkgs lib;};
#   check = mkProbe {
#     name = "access-control";
#     runtimeInputs = with pkgs; [openssh];
#     script = ''
#       password_auth_disabled=$(...)
#       jq -n --argjson val "$password_auth_disabled" '{password_auth_disabled: $val}'
#     '';
#   };
#
# The script body MUST print a valid JSON object to stdout.
# Default PATH includes: coreutils, jq, gnugrep, gawk, hostname, iproute2.
{
  pkgs,
  lib,
}: {
  name,
  runtimeInputs ? [],
  script,
}:
  pkgs.writeShellScript "probe-${name}" ''
    set -euo pipefail
    export PATH="${lib.makeBinPath (with pkgs; [coreutils jq gnugrep gawk hostname iproute2] ++ runtimeInputs)}"

    ${script}
  ''
