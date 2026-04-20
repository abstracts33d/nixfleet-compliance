# Contributing to NixFleet Compliance

Thank you for your interest in contributing!

## Development Setup

**Prerequisites:**
- [Nix](https://nixos.org/download) with flakes enabled (`experimental-features = nix-command flakes`)

**Getting started:**
```sh
git clone https://github.com/arcanesys/nixfleet-compliance.git
cd nixfleet-compliance
nix develop  # enters the dev shell with alejandra and jq
```

## Running Checks

```sh
nix fmt                       # format all Nix files
nix flake check --no-build    # run eval tests without building derivations
```

## Adding a New Control

1. Create `controls/_<control-name>.nix` following the ENFORCE/PROVE pattern
2. Import `../evidence/options.nix`
3. Define a `compliance.controls.<name>.enable` option
4. **ENFORCE section:** NixOS configuration that enforces the control
5. **PROVE section:** Register `compliance.evidence.probes.<name>` with a `mkProbe` script that produces machine-readable evidence
6. Add eval tests in `tests/eval.nix`
7. Map to regulatory articles in the `articles` attribute

See any existing control in `controls/` for a working example.

## Adding a Framework Preset

1. Create `frameworks/<name>.nix`
2. Enable the relevant controls with appropriate defaults
3. Add eval tests to verify the preset enables the expected controls

## Commit Conventions

Use [conventional commits](https://www.conventionalcommits.org/):

- `feat:` - new control or framework
- `fix:` - bug fix
- `docs:` - documentation only
- `chore:` - maintenance, dependencies
- `test:` - test additions or fixes

## Pull Requests

1. Fork and create a feature branch
2. Ensure `nix fmt` and `nix flake check --no-build` pass
3. Open a PR against main
4. Maintainer reviews and merges

## License

By submitting a pull request, you agree to license your contribution under the [MIT License](LICENSE-MIT).
