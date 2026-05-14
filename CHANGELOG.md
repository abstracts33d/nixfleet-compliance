# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/). Versioning: [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.2.0] - 2026-05-15

### Fixed

- `_disaster-recovery.nix`: coerce nullable `boot.loader.systemd-boot.configurationLimit` (and `grub.configurationLimit`) to `0` before comparing with `cfg.minGenerations`. The `or 0` fallback only fires when an attribute is missing, not when it is present-but-null, so hosts that left the option unset triggered `cannot compare null with an integer` during eval. When neither bootloader sets a limit, the static probe now returns `passed = false` with `evidence.configurationLimit = 0` instead of crashing. (#14)

### Added

- Typed controls: every control now declares `type = "static" | "runtime" | "both"` and a `schema = "<framework>/v<N>"` string.
- `lib/mkTypedControl.nix` - typed control factory composing via `imports` with `lib/mkControl.nix`. Provides `expect` / `timeoutSecs` as factory parameters, threaded into the `probeDescriptor`.
- `lib/probeDescriptor.nix`, `lib/evaluateStatic.nix` - helpers for building CONTRACTS §I.3 descriptors and static evidence projections.
- Baseline `agent-egress-exemption` control (type=both): required whenever a firewall-lock control is enabled on the same host; declares the single endpoint the agent is allowed to reach.
- Per-framework `schemaVersions` attribute (e.g. `"anssi-bp028/v1"`, `"nis2/v1"`, `"dora/v1"`, `"iso27001/v1"`).
- New governance option `primaryFramework` with default `"anssi-bp028"`.
- `tests/typed-controls/` eval harness with positive + negative fixture scaffolding.
- JCS golden byte fixture (`tests/typed-controls/fixtures/_jcs-golden.json`, 69 bytes, no trailing newline).
- `docs/typed-controls.md` migration guide.

### Changed

- `lib/mkProbe.nix` now wraps caller output through `jq -cSj` (compact, sorted-keys, no trailing newline) for JCS-producer-side discipline. Also guards empty-raw output with a loud error rather than silently succeeding.
- Every existing control (authentication, access-control, encryption-at-rest, encryption-in-transit, network-segmentation, asset-inventory, backup-retention, disaster-recovery, key-management, vulnerability-mgmt, secure-boot, audit-logging, baseline-hardening, change-management, incident-response, supply-chain) migrated to the typed shape. Per-control type: see the migration grid in the PR description.

### Breaking

- Out-of-tree controls: the probe descriptor shape is extended. Existing controls keep working because new fields default to `null`, but controls that want to participate in the typed evidence pipeline MUST declare `type`, `schema`, and the appropriate projection. See `docs/typed-controls.md` for migration.
- `compliance.schemaVersions.<framework>` is now consumed by typed controls. Each shipped framework sets its own value via `lib.mkDefault` (`anssi-bp028/v1`, `nis2/v1`, `dora/v1`, `iso27001/v1`); override per-fleet only when pinning a non-default revision. Out-of-tree frameworks that don't set a value still fail eval on the corresponding control module with a clear error.

## [0.1.0] - 2026-04-19

Initial release.

[Unreleased]: https://github.com/arcanesys/nixfleet-compliance/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/arcanesys/nixfleet-compliance/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/arcanesys/nixfleet-compliance/releases/tag/v0.1.0
