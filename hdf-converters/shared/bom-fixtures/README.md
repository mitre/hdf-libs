# Shared BOM parser fixtures

Real, unmodified BOM documents used by the shared `bom/` parser tests in **both**
languages (`shared/typescript/bom` and `shared/go/bom`) — a single copy so the
TS↔Go parity tests run against identical bytes (per ADR-0001 Phase 2 / kirq.2).

| File | Format | Source (provenance) |
|------|--------|---------------------|
| `cyclonedx-sbom.json` | CycloneDX 1.6 SBOM | OWASP Juice Shop SBOM (same real sample as `converters/cyclonedx-to-hdf/fixtures/input/juice-shop-sbom-minimal.json`) |
| `spdx-sbom.json` | SPDX 2.3 SBOM | SPDX `spdx-examples` repo — `presentations/OSS-NA-2023/SPDXVersion2.3/03-SBOMwDependency.json` (SPDX Tools v1.1.5 Java SBOM) |
| `cyclonedx-mlbom.json` | CycloneDX 1.6 ML-BOM | CycloneDX `specification` repo — `tools/src/test/resources/1.6/valid-machine-learning-1.6.json` (machine-learning-model + modelCard) |

Do not fabricate or hand-edit these — they are the tested contract for the parser.
Replace only with newer real samples from the same authoritative sources.
