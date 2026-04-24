# lib/mkProbe.nix
#
# Wraps a probe script. The script body MUST print a single JSON object
# to stdout. This wrapper guarantees the final bytes written to stdout
# are JCS-ready: UTF-8, sorted keys, no trailing newline, no whitespace.
#
# Stream C's `nixfleet-canonicalize` normalises number/unicode edge
# cases - producer-side, we promise to never emit floats and to keep
# attr-set iteration deterministic. Usage is unchanged for existing
# controls:
#
#   mkProbe = import ../lib/mkProbe.nix {inherit pkgs lib;};
#   check = mkProbe {
#     name = "my-control";
#     runtimeInputs = with pkgs; [openssh];
#     script = ''
#       jq -n --argjson val true '{ok: $val}'
#     '';
#   };
#
# Default PATH includes: coreutils, findutils, jq, gnugrep, gawk,
# hostname, iproute2, systemd.
{
  pkgs,
  lib,
}: {
  name,
  runtimeInputs ? [],
  script,
}:
pkgs.writeShellScript "probe-${name}" ''
  set -o pipefail
  export PATH="${lib.makeBinPath (with pkgs; [coreutils findutils jq gnugrep gawk hostname iproute2 systemd] ++ runtimeInputs)}"

  # Wrap the caller's script so that whatever JSON they emit is
  # re-read through `jq -cS` (compact, sorted-keys) before leaving
  # stdout. This is a cheap JCS-producer-side discipline.
  raw=$(
    ${script}
  )

  printf '%s' "$raw" | jq -cS '.'
''
