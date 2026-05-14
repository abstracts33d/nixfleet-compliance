{
  description = "NixFleet Compliance - regulatory compliance controls for NixOS infrastructure (MIT)";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    flake-parts.url = "github:hercules-ci/flake-parts";
    treefmt-nix = {
      url = "github:numtide/treefmt-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = inputs:
    inputs.flake-parts.lib.mkFlake {inherit inputs;} {
      systems = ["x86_64-linux" "aarch64-linux"];

      imports = [
        ./flake-module.nix
        ./tests/eval.nix
        ./tests/vm-evidence.nix
      ];

      perSystem = {
        pkgs,
        system,
        ...
      }: {
        formatter = pkgs.alejandra;

        packages.nixfleet-compliance-tools = pkgs.callPackage ./tools {};

        devShells.default = pkgs.mkShell {
          packages = with pkgs; [alejandra jq cargo rustc rustfmt clippy];
        };
      };
    };
}
