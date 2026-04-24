# lib/probeDescriptor.nix
#
# Build a CONTRACTS §I.3 probe descriptor from typed fields.
# Output shape - ready for JCS canonicalization by Stream C:
#   { command: str, args: [str], timeoutSecs: int, expect: attrs, schema: str }
{lib}: {
  # probe :: ShellScript (derivation) - resolved to a store path as `command`
  # args :: [string]
  # timeoutSecs :: int
  # expect :: attrs of JSON-shaped assertions (see ./evaluateStatic.nix)
  # schema :: string - e.g. "anssi-bp028/v1"
  mkDescriptor = {
    command,
    args ? [],
    timeoutSecs ? 30,
    expect ? {},
    schema,
  }: {
    inherit args timeoutSecs expect schema;
    command = toString command;
  };
}
