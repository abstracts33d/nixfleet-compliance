# lib/mkProbe.nix
#
# Wraps a probe script. The script body MUST print a single JSON object
# to stdout. This wrapper guarantees the final bytes written to stdout
# are JCS-ready: UTF-8, sorted keys, no trailing newline, no whitespace.
#
# Stream C's `nixfleet-canonicalize` normalises number/unicode edge
# cases -- producer-side, we promise to never emit floats and to keep
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
  # re-read through `jq -cSj` (compact, sorted-keys, no trailing
  # separator) before leaving stdout. This is a cheap JCS-producer-
  # side discipline. If the caller's script produced no output,
  # fail loudly rather than silently emitting an empty probe payload.
  raw=$(
    ${script}
  )

  if [ -z "$raw" ]; then
    echo "probe-${name}: script produced no output" >&2
    exit 1
  fi

  printf '%s' "$raw" | jq -cSj '.'
''
