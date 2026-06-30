# ADR-0001: Generalized BOM/Manifest Representation in HDF

**Date:** 2026-06-30
**Status:** proposed
**Deciders:** Will Dower

## Context

HDF must represent AI Bills of Materials (model and dataset inventory/provenance) to support AI supply-chain evidence (CISA/G7 "SBOM for AI", NSA ML supply-chain guidance, EU AI Act, OWASP LLM Top 10). An initial proposal (`dev-docs/proposed-issues-ai-and-evidence.md`) suggested a new native `hdf-ai-bom` document type plus a dozen related issues. That does not generalize: if every new manifest kind (AI-BOM today; HBOM, SaaSBOM, CBOM, dataset manifests tomorrow) gets its own document schema, the schema surface multiplies and drifts. HDF already ships partial, SBOM-specific support (`sbom`/`sbomRef`/`sbomFormat` on `Base_Component`; the `sbom` evidence-package `Content_Type`; purl-keyed `Package_Diff`), which this decision generalizes. The governing constraint is HDF's existing pattern: one `hdf-results` schema plus a converter per scanner — we never mint a new results schema per scanner.

## Decision

**Represent all manifests — SBOM, AI-BOM, and future kinds — through one extensible shape attached to the HDF component primitive, discriminated by a `bomType` field; do not create a new document type per manifest kind.** A new manifest kind is added by (a) a `bomType`/`format` value and (b) a converter that normalizes the source format — mirroring the scanner→converter pattern.

Concretely:

1. **AI-BOM is a peer of SBOM, not a new document type.** Extend the existing SBOM touchpoints (`Base_Component`, `hdf-system`, `hdf-results`, evidence-package content reference, `hdf-comparison`) to handle BOMs generically.
2. **Generalize the component field:** replace `sbom`/`sbomRef`/`sbomFormat` on `Base_Component` with a multi-valued `boms[]`.
3. **Two carriage shapes:** *passthrough* (reference/embed of the native manifest, opaque) and *normalized* (converted into HDF's queryable BOM shape). A converter turns the native manifest into the normalized shape.
4. **Three-tier field placement** (the core discipline). The placement test for any field is "how many `bomType`s use it?":
   - **Component root** (`Base_Component`): generic identity (`name`, `version`, `componentId`, `externalIds`, `owner`, `labels`) + the `boms[]` field. *No BOM-type-specific fields, ever.*
   - **Shared BOM base** (every `bomType`): `bomType`, `format`, carriage (`ref?`/`document?`), `hashes[]`, `uniqueId`, `license`. *Only fields shared by ≥2 bomTypes.* Identity is **inherited** from the host component, not re-owned.
   - **Type-specific extension** (per `bomType`): the manifest's distinctive content. A field used by exactly one bomType lives here.
5. **`aiModel` becomes a thin component type** (`type` enum + `Component` oneOf), adding only identity/correlation fields (parallel to `Host_Component`'s `hostname`/`ip`); all model detail lives in the BOM payload.
6. **Model vs dataset are distinct `bomType`s on a shared base.** `bomType` is an open enum: `sbom | ai-model | dataset | …`.
7. **Field set aligned to the CISA/G7 "SBOM for AI" minimum elements** (the interoperability target). AI fields are optional (standards-correct; only the EU AI Act makes a subset binding for high-risk/GPAI). `adaptationType` adopts Hugging Face's `finetune | adapter | quantized | merge` (the only typed lineage enum in the ecosystem). `parameterCount` and `serializationFormat` are first-class **within the ai-model extension** (never at root). Structural disagreements normalize to the most expressive (superset) shape with a free-text fallback (bias → CycloneDX structured object + prose fallback; energy → CycloneDX per-activity array).
8. **No backward compatibility** — clean replacement of the SBOM trio (rapid-iteration phase; community expects breaking schema changes).
9. **Dual TypeScript + Go parity is an invariant** — every schema type, parser, and converter exists in both languages; no TS-only helpers.

## Alternatives Considered

### Alternative A: Native `hdf-ai-bom` document type (the original proposal)
A dedicated top-level schema document for AI-BOMs, with a content-type reference and rich `AI_Model_Component` fields.
- **Pros:** Direct mapping of CISA minimum elements; self-contained; matches the source doc.
- **Cons:** Doesn't generalize — every future manifest kind needs its own document; SBOM itself was never given a native document, so this is asymmetric; bloats the component with bespoke model fields.
- **Why rejected:** Violates the one-representation principle and the scanner→converter analogy that governs HDF.

### Alternative B: A new schema document per manifest kind (hdf-ai-bom, hdf-hbom, hdf-cbom, …)
Generalize the *document-per-type* approach across all future manifests.
- **Pros:** Each document is precisely tailored.
- **Cons:** Unbounded schema growth and drift; N validators, N converters-to-documents, N diff paths; exactly the maintenance burden HDF's converter model exists to avoid.
- **Why rejected:** The central anti-pattern this ADR prevents.

### Alternative C: Rich `AI_Model_Component` with bespoke model fields on the component
Put `serializationFormat`, `baseModelRef`, `adaptationType`, etc. directly on the component (per the source doc).
- **Pros:** Fields queryable at the component level without opening a payload.
- **Cons:** The component primitive bloats once per manifest type (HBOM wants hardware fields, SaaSBOM wants service fields…); duplicates inventory between component and BOM.
- **Why rejected:** Replaced by thin component + typed BOM payload; resolved by the three-tier test.

### Alternative D: TS-only shared BOM parser
Per a sub-agent's suggestion, implement the shared BOM parser only in TypeScript and let Go converters hand-roll.
- **Pros:** Half the parser maintenance.
- **Cons:** Breaks TS/Go parity; forks normalization logic across every Go converter — the "fork shared utilities" anti-pattern.
- **Why rejected:** Parity is a project invariant (we don't assume the consumer's language).

### Alternative E: Do Nothing
Keep SBOM-only support; reference AI-BOMs as opaque external files with no normalization.
- **Pros:** Zero schema work.
- **Cons:** No queryable/assessable AI inventory; can't diff models, can't assess against AI baselines, can't compute coverage; fails the AI supply-chain evidence requirement that motivates this work.
- **Why rejected:** The problem is real and load-bearing for the AI-evidence roadmap (epic `hdf-libs-kirq`).

## Consequences

**What becomes easier:**
- One mechanism for all manifests; a new kind costs a `bomType`/`format` value + a converter, never a new document schema.
- AI-specific concerns are quarantined in the `ai-model` extension; the component primitive and shared BOM base stay manifest-agnostic and stable.
- Reuses existing primitives (`Checksum`, `Integrity`, `Generator`, purl/cpe identity) and the converter→normalize pattern; small converter blast radius (only `cyclonedx-to-hdf` emits the SBOM fields today).
- Aligns to the CISA/G7 interoperability target; absorbs CycloneDX ML-BOM, SPDX AI/Dataset, HF cards, and Croissant via converters.

**What becomes harder:**
- Breaking change to the shipped `sbom`/`sbomRef`/`sbomFormat` shape; downstream consumers must migrate.
- Dual-language maintenance for the new `bom/` module and converters.
- The normalized ai-model payload is large.

**Risks:**
- *Payload sprawl* → mitigated by making all AI fields optional and leaning on passthrough when normalization isn't needed.
- *Breaking-change disruption* → acceptable in the current rapid-iteration phase; communicated via CHANGELOG and schema `$id` version bump.
- *Identity correlation gaps for AI artifacts* (purl-only diff) → tracked as an open question; generalize `Package_Diff` identity beyond purl.

## Implementation Plan

### Quality Standards (inherited by every card)
- **Framework-first / existing patterns:** follow the existing converter pattern (dual TS+Go + shared fixtures), the `shared/checklist/` and `shared/vex/` precedents for format-specific shared helpers, and the `fingerprint.ts` detector registry. Reuse `hdf-utilities` primitives (`parseJSON`, `parsePurl`, `parseCpe`, `sha256`/`hashObject`, `parseTimestamp`); **add no new hdf-utilities primitives**.
- **DRY from design:** the shared `bom/` module (normalized model + `parseBom`/`buildBom`) is built first (Phase 2) and consumed by all converters (Phase 3); `cyclonedx-to-hdf` adopts it rather than keeping its own emission.
- **Test strategy:** schema changes → `hdf-schema/test` validation; parser → dual-language unit tests against shared fixtures; converters → fixture-based TS+Go tests with schema-validated expected output; real fixtures only (no fabricated BOMs — see CLAUDE.md Fixture Integrity).
- **Security by design:** every converter calls `ValidateJSONSize`/`validateInputSize` as first op; serialization-format inventory surfaces pickle (RCE) vs safetensors; no secrets.
- **Parity:** TS + Go for every type, parser, and converter — verified by parity tests.
- **Timestamps:** canonical trimmed-UTC RFC3339 via the shared helpers (per `hdf-timestamp-canonical-utc`).

### Shared Abstractions (built before consumers)
| Shared need | Used by | Card it as |
|---|---|---|
| `primitives/bom.schema.json` (shared base + `ai-model`/`dataset`/`sbom` extensions) | all consuming schemas + converters | Phase 1 foundation |
| `hdf-converters/shared/{ts,go}/bom/` (normalized model, `parseBom`/`buildBom`, fingerprints) | all BOM converters | Phase 2 foundation |

### Scope

**IN scope:**
- Generalized `boms[]` on `Base_Component` replacing the SBOM trio; shared BOM base + `ai-model`/`dataset`/`sbom` extensions; `aiModel` component type.
- Evidence-package `Content_Type` generalization; `hdf-comparison` diff generalization beyond purl-only.
- Dual-language shared `bom/` parser module.
- Update `cyclonedx-to-hdf`; add `cyclonedx-mlbom-to-hdf` and `spdx-ai-to-hdf` converters.

**OUT of scope:**
- Model/build signing & provenance (OpenSSF Model Signing, Sigstore, SLSA/in-toto) and OCI model packaging — future `bomType`s/converters at most.
- The deferred siblings: `hdf-libs-9zig`, `hdf-libs-gccd`, `hdf-libs-vqic`, `hdf-libs-gxxb`, `hdf-libs-bsfr`.
- Adversarial-evaluation baselines and enterprise portfolio aggregation.

### Phases

#### Phase 1: Schema — generalized BOM + aiModel component (unblocked — start here)
**Files:**
- Create: `hdf-schema/src/schemas/primitives/bom.schema.json` (shared base + `ai-model`/`dataset`/`sbom` extensions, `bomType`/`format`/carriage discriminators)
- Modify: `hdf-schema/src/schemas/primitives/component.schema.json` (replace `sbom`/`sbomRef`/`sbomFormat` with `boms[]`; add `aiModel` to the `type` enum + `AI_Model_Component` to the `Component` oneOf); `hdf-schema/src/schemas/hdf-evidence-package.schema.json` (generalize `Content_Type`); `hdf-schema/src/schemas/primitives/comparison.schema.json` (generalize `Package_Diff` identity)
- Test: `hdf-schema/test/` (bom + component + evidence-package validation, incl. examples per the schema-examples convention)

**Acceptance criteria:**
- [ ] `boms[]` validates with `bomType` discriminator; `ai-model`/`dataset`/`sbom` extensions validate; passthrough (`ref`) and normalized (`document`) both validate
- [ ] `aiModel` component validates via the oneOf; `sbom`/`sbomRef`/`sbomFormat` removed
- [ ] AI-specific fields (`parameterCount`, `serializationFormat`, etc.) live only in the `ai-model` extension; `adaptationType` enum = `finetune|adapter|quantized|merge`
- [ ] `pnpm build:schemas` regenerates bundled schemas + `hdf-validators/go/schemas/`; TS + Go types regenerate

**Verification:** `cd hdf-schema && pnpm build && pnpm test`

#### Phase 2: Shared dual-language BOM parser (blocked by Phase 1)
**Files:**
- Create: `hdf-converters/shared/typescript/bom/{model,cyclonedx,spdx,ml-bom,normalize,fingerprints}.ts` and Go peers `hdf-converters/shared/go/bom/*.go`
- Test: matching `*_test.ts` / `*_test.go` against shared fixtures

**Acceptance criteria:**
- [ ] `parseBom()` detects + parses CycloneDX / SPDX / ML-BOM; `buildBom()` emits the normalized shape
- [ ] Reuses `hdf-utilities` primitives only (no new primitives there)
- [ ] TS and Go produce equivalent output on shared fixtures; fingerprints registered with the detector
- [ ] >90% coverage both languages

**Verification:** `cd hdf-converters && pnpm test:ts && go test ./shared/...`

#### Phase 3: Converters (blocked by Phase 2)
**Files:**
- Modify: `hdf-converters/converters/cyclonedx-to-hdf/{typescript,go}/converter.*` + `fixtures/expected/*` (emit `boms[]` via `buildBom()`)
- Create: `hdf-converters/converters/cyclonedx-mlbom-to-hdf/` and `spdx-ai-to-hdf/` (TS+Go+fixtures); CLI wrappers + `registerHDFConverter()` entries
- Test: per-converter TS + Go tests

**Acceptance criteria:**
- [ ] `cyclonedx-to-hdf` emits the generalized `boms[]` shape; expected fixtures schema-valid
- [ ] New converters emit `ai-model` BOMs (partial-fidelity pattern; unmapped native fields carried opaquely or dropped with a logged warning)
- [ ] CLI registration; `hdf convert` spot-checks pass
- [ ] TS + Go parity per converter

**Verification:** `cd hdf-converters && pnpm test && go test ./converters/...` + `hdf convert <ml-bom> -o out.json`

### Verification Strategy
- End-to-end: convert a real CycloneDX ML-BOM and a real SPDX AI file → assert the emitted `boms[]` validates against the bundled schema and round-trips through `parseBom`/`buildBom`.
- Edge cases: a component with multiple BOMs (SBOM + ai-model); passthrough-only (no normalized payload); a model referencing a dataset BOM; pickle vs safetensors serialization surfaced correctly.
- Parity: every parser/converter has a TS↔Go fixture-equivalence test.
- Security: oversized-input guard fires; no fabricated fixtures (real ML-BOM/SPDX-AI sources or schema-validated).

## References

- Source proposal: `dev-docs/proposed-issues-ai-and-evidence.md` (superseded re: the native-document approach)
- Tracking epic: `hdf-libs-kirq`; CVE-ecosystem sibling: `hdf-libs-5pg9`
- **Format survey (2026-06-30):** CycloneDX ML-BOM 1.7 (ECMA-424); SPDX 3.0.1 AI + Dataset profiles (note: only SPDX 2.2.1 is ISO/IEC 5962); Hugging Face model cards (de-facto input); MLCommons Croissant 1.1 (datasets); Google Model Card Toolkit (archived 2024 — ancestral to CycloneDX); **CISA/G7 "SBOM for AI — Minimum Elements" (May–Jun 2026, the interoperability target)**; out-of-scope adjacents: OpenSSF Model Signing/Sigstore, OCI model packaging (ModelPack/KitOps/Ollama).
- Survey findings shaping the field set: no native `parameterCount` in CDX/SPDX (EU AI Act binding for GPAI); energy modeling disagrees (CDX per-activity is the superset); bias structured in CDX, free-text elsewhere; HF owns typed lineage (`base_model_relation`); serialization format is security-critical yet under-modeled by the BOM specs.
