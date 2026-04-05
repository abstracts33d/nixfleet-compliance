# TODO

## Phase 4 — Enterprise (nixfleet-enterprise repo)

- [ ] Fleet evidence aggregation endpoint in control plane
- [ ] Compliance dashboard (web UI)
- [ ] Audit-ready PDF/JSON report generation
- [ ] Gap analysis engine ("to comply with X, enable Y on hosts Z")
- [ ] Historical compliance tracking (trends over time)

## Additional Framework Mappings

- [ ] `dora.nix` — EU Digital Operational Resilience Act (financial sector)
- [ ] `iso27001.nix` — ISO/IEC 27001:2022 (cross-sector certification)
- [ ] `hds.nix` — Hébergeur de Données de Santé (French health data)
- [ ] `secnumcloud.nix` — ANSSI SecNumCloud qualification
- [ ] `cra.nix` — EU Cyber Resilience Act (products with digital elements)

## Future Controls (identified gaps)

- [x] `_network-segmentation` — VLAN/firewall zone verification (DORA Art. 9, SecNumCloud)
- [ ] `_data-classification` — data sensitivity labeling (HDS, GDPR) — deferred: needs application-layer schema
- [x] `_change-management` — deployment frequency tracking (ISO 27001 A.12.1)
- [x] `_key-management` — key inventory, rotation tracking, TPM detection (SecNumCloud)
- [ ] `_data-residency` — geographic constraints on data (GDPR, HDS) — deferred: needs application-layer context
- [x] `_secure-boot` — verified boot chain attestation (CRA Art. 10)

## Evidence Layer Evolution

- [ ] Evidence signing (host key signs evidence.json for tamper detection)
- [ ] Agent transport (evidence flows through nixfleet-agent → CP)
- [ ] Multi-framework comparison ("95% NIS2, 80% DORA, 60% ISO 27001")
- [ ] Continuous attestation (real-time compliance stream)
