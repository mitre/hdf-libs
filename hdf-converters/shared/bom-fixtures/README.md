# Shared BOM parser fixtures

Real BOM documents used by the shared `bom/` parser tests in **both** languages
(`shared/typescript/bom` and `shared/go/bom`) — a single copy so the TS↔Go
parity tests run against identical bytes (per ADR-0001 Phase 2 / kirq.2). The
CycloneDX-ML set is additionally consumed by the hdf-cli `system create` tests
(`hdf-cli/cmd/hdf/cmd/system_create_test.go`) via `shared.GetBOMFixturesDir()`.

| File | Format | Source (provenance) |
|------|--------|---------------------|
| `cyclonedx-sbom.json` | CycloneDX 1.6 SBOM | OWASP Juice Shop SBOM (same real sample as `converters/cyclonedx-to-hdf/fixtures/input/juice-shop-sbom-minimal.json`) |
| `spdx-sbom.json` | SPDX 2.3 SBOM | SPDX `spdx-examples` repo — `presentations/OSS-NA-2023/SPDXVersion2.3/03-SBOMwDependency.json` (SPDX Tools v1.1.5 Java SBOM) |
| `cyclonedx-mlbom.json` | CycloneDX 1.6 ML-BOM | CycloneDX `specification` repo — `tools/src/test/resources/1.6/valid-machine-learning-1.6.json` (machine-learning-model + modelCard) |
| `cyclonedx-mlbom-1.5.json` | CycloneDX 1.5 ML-BOM | CycloneDX `specification` repo — `tools/src/test/resources/1.5/valid-machine-learning-*.json` |
| `cyclonedx-mlbom-1.7.json` | CycloneDX 1.7 ML-BOM | CycloneDX `specification` repo — `tools/src/test/resources/1.7/valid-machine-learning-*.json` |
| `cyclonedx-mlbom-considerations-1.6.json` | CycloneDX 1.6 ML-BOM | CycloneDX `specification` repo — `tools/src/test/resources/1.6/valid-machine-learning-*.json` (a modelCard variant carrying only `considerations`, no `modelParameters` — a `Llama-2-7b` model card) |
| `cyclonedx-mlbom-sparse.json` | CycloneDX 1.6 ML-BOM | Real subset — trimmed from `cyclonedx-mlbom.json` to `bomFormat`+`specVersion`+a single machine-learning-model component (name/version/bom-ref) whose modelCard is stripped of `modelParameters`/`architecture`, to exercise partial-fidelity (parser must produce `ai-model` with a minimal/empty model extension and never fabricate `parameterCount`/`serializationFormat`/`modelArchitecture`). All retained values are copied verbatim from the source — no invented data. |
| `spdx-ai-model-1.json` | SPDX 3.0 AI/Dataset (JSON-LD) | SPDX `spdx-examples` repo — AI/Dataset profile example `ai/example01` (SimpleHTR handwriting recognition). Carries 2 `ai_AIPackage` (word-model, line-model) + 1 `dataset_DatasetPackage` (IAMdataset), with trainedOn/testedOn relationships. |
| `spdx-ai-model-2.json` | SPDX 3.0 AI/Dataset (JSON-LD) | SPDX `spdx-examples` repo — AI/Dataset profile example `ai/example02` (sentiment-demo SBOM). Carries 1 `ai_AIPackage` + 1 `dataset_DatasetPackage`. |
| `spdx-ai-dataset-1.json` | SPDX 3.0 AI/Dataset (JSON-LD) | SPDX `spdx-examples` repo — Dataset profile example `dataset/example01` (Our World in Data CO2 dataset). Carries 0 `ai_AIPackage` + 1 `dataset_DatasetPackage`. |
| `cyclonedx-format-casing-vectors.json` | Detection vector table (not a BOM) | Written for hdf-libs-52n0c.46. NOT captured output and not a document: a list of `bomFormat` values with whether the CycloneDX detectors must claim each, read by BOTH language suites so the two cannot drift on casing. Nothing is asserted about any real SBOM's content. |
| `spdx3-context-vectors.json` | Detection vector table (not a BOM) | Written for hdf-libs-52n0c.11. NOT captured output and not a document: `@context` values — string, array and inline-object forms — with whether each names an SPDX 3 vocabulary for ROUTING, read by BOTH language suites so the two cannot drift. Nothing is asserted about any real SBOM's content. |

The two `*-vectors.json` tables are consumed by the bom detector tests in BOTH languages (`shared/go/bom/bom_test.go`, `shared/typescript/bom/bom.test.ts`) and by nothing else. They assert nothing about any document's content. The SPDX-3 table's own `comment` states which of its rows are evidence and which merely illustrate; this file does not restate it, because the two drifted apart once already.

Consumers: shared bom parser tests (`shared/typescript/bom`, `shared/go/bom`)
and the hdf-cli `system create` AI-BOM tests. The three `spdx-ai-*` fixtures are
additionally consumed by the hdf-cli `system create` SPDX-3 tests.

Do not fabricate or hand-edit these — they are the tested contract for the parser.
Replace only with newer real samples from the same authoritative sources (the
`sparse` fixture may only be re-derived by trimming a real fixture, never by
adding invented fields).
