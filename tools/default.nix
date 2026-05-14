# Builds the nixfleet-compliance-{sign,verify} binaries from tools/.
#
# Exposed as packages.nixfleet-compliance-tools (perSystem). Consumed by:
#   - evidence/collector.nix  -- signs evidence.json after every collection
#   - compliance-check        -- optionally verifies signatures on read
#   - the auditor             -- runs nixfleet-compliance-verify offline
{pkgs, ...}:
pkgs.rustPlatform.buildRustPackage {
  pname = "nixfleet-compliance-tools";
  version = "0.2.0";

  src = ./.;

  cargoLock = {
    lockFile = ./Cargo.lock;
  };

  # No tests at Nix build time; cargo test is exercised in CI + locally.
  doCheck = false;

  meta = {
    description = "Sign + verify on-disk compliance evidence using the host's SSH ed25519 key";
    homepage = "https://github.com/arcanesys/nixfleet-compliance";
    license = pkgs.lib.licenses.mit;
    mainProgram = "nixfleet-compliance-verify";
  };
}
