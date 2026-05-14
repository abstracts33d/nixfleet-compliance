# NixFleet Compliance documentation

The doc tree splits by audience and lifecycle.

## Concepts

| File | Topic |
|------|-------|
| [gate-mechanics.md](gate-mechanics.md) | Scanner vs. gate; static layer; runtime layer; why both exist |
| [typed-controls.md](typed-controls.md) | Typed-control schema, migration notes, JCS canonicalisation, framework defaults |
| [governance.md](governance.md) | Mode escalation path, level + hostType, exceptions with rationale, adoption patterns |

## Reference

| File | Topic |
|------|-------|
| [evidence-format.md](evidence-format.md) | Signed evidence JSON shape, JCS discipline, offline verification recipe |
| [cli.md](cli.md) | `compliance-check` + `nixfleet-compliance-verify` subcommands, environment, workflows |

## Frameworks

| File | Topic |
|------|-------|
| [nis2-mapping.md](nis2-mapping.md) | NIS2 Directive 2022/2555 - Article 21 mapping by control |
| [dora-mapping.md](dora-mapping.md) | DORA Regulation 2022/2554 - Chapter III mapping |
| [iso27001-mapping.md](iso27001-mapping.md) | ISO/IEC 27001:2022 - Annex A mapping |
| [anssi-mapping.md](anssi-mapping.md) | ANSSI BP-028 v2.0 - 4 hardening levels, 3 host categories |

## Runbooks

| File | Topic |
|------|-------|
| [synthetic-control-runbook.md](synthetic-control-runbook.md) | Always-fail control for exercising the rollback path end-to-end |

## Composed view (mdbook)

The same content as a browseable book lives under [mdbook/](mdbook/). The wrapper files under `mdbook/src/` are 1-line `{{#include}}` shims that pull from the canonical sources above - no duplication. Configuration in [mdbook/book.toml](mdbook/book.toml); table of contents in [mdbook/src/SUMMARY.md](mdbook/src/SUMMARY.md).

## Top-level meta-files

| File | What it is |
|------|-----------|
| [../README.md](../README.md) | User-facing project README |
| [../CHANGELOG.md](../CHANGELOG.md) | Release notes |
| [../CONTRIBUTING.md](../CONTRIBUTING.md) | Contributor guide |
| [../LICENSE-MIT](../LICENSE-MIT) | MIT licence |
