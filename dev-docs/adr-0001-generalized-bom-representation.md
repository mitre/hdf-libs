# ADR-0001: Generalized BOM/Manifest Representation in HDF

**Date:** 2026-06-30
**Status:** accepted
**Deciders:** Will Dower
**Revision:** 2026-06-30 — incorporated the cross-BOM-type survey: carriage/normalization framing, system-level BOM subject, `bomType` coverage tiers, and shared-base field semantics (see Decision §2, §3, §4, §6, §10 and Alternative F).
**Revision:** 2026-07-01 — model/dataset symmetry + subject-vs-document integrity. `dataset` is promoted to a first-class subject (a thin `dataset` component type plus lineage/derivation in its extension, symmetric with `aiModel`); artifact/subject integrity is separated from BOM-document integrity and unified onto `Base_Component.integrity` (absorbing the ad-hoc `Container_Image.digest` / `Artifact.checksum`). Both changes tighten the internal consistency of the initial cut and align with the prevailing direction of the broader AIBOM discussion on identity, integrity, and provenance minimums (see References). See Decision §4, §5, §11; implementation cards `hdf-libs-kirq.6` (symmetry) and `hdf-libs-kirq.7` (unified integrity).

## Context

HDF must represent AI Bills of Materials (model and dataset inventory/provenance) to support AI supply-chain evidence (CISA/G7 "SBOM for AI", NSA ML supply-chain guidance, EU AI Act, OWASP LLM Top 10). An initial proposal (`dev-docs/proposed-issues-ai-and-evidence.md`) suggested a new native `hdf-ai-bom` document type plus a dozen related issues. That does not generalize: if every new manifest kind (AI-BOM today; HBOM, SaaSBOM, CBOM, dataset manifests tomorrow) gets its own document schema, the schema surface multiplies and drifts. HDF already ships partial, SBOM-specific support (`sbom`/`sbomRef`/`sbomFormat` on `Base_Component`; the `sbom` evidence-package `Content_Type`; purl-keyed `Package_Diff`), which this decision generalizes. The governing constraint is HDF's existing pattern: one `hdf-results` schema plus a converter per scanner — we never mint a new results schema per scanner.

## Decision

**Represent all manifests — SBOM, AI-BOM, and future kinds — through one extensible `Bom` shape attached to a *BOM subject* (a component or a system boundary), discriminated by a `bomType` field; do not create a new document type per manifest kind.** A new manifest kind is added by (a) a `bomType`/`format` value and (b) a converter that normalizes the source format — mirroring the scanner→converter pattern.

Concretely:

1. **AI-BOM is a peer of SBOM, not a new document type.** Extend the existing SBOM touchpoints (`Base_Component`, `hdf-system`, `hdf-results`, evidence-package content reference, `hdf-comparison`) to handle BOMs generically.
2. **Generalize as a shared `Bom` primitive** (`primitives/bom.schema.json`) with a multi-valued `boms[]` attachment used, unmodified, at **two subjects:** on `Base_Component` (replacing `sbom`/`sbomRef`/`sbomFormat`) and on `hdf-system` (a system-scoped `boms[]`). Component-scoped BOMs (SBOM, AI-model) attach at the component; system-scoped BOMs (SaaSBOM, KBOM, OBOM) attach at the system boundary.
3. **Two co-equal shapes, available to *every* `bomType`:** *passthrough* (reference/embed of the native manifest, carried opaquely) and *normalized* (converted into HDF's queryable shape). Neither is second-class — passthrough is the universal escape hatch (always available, no normalization required); normalized is a target for every type, built incrementally. **A normalized type-extension may be relational** — a typed `nodes[]` + reference-based `edges[]` graph (exactly how CycloneDX already encodes SaaSBOM services/data-flows and CBOM `implements`/`uses` in JSON) — so no BOM type is inexpressible in HDF's own fields. We sequence *when* each type gets a normalized extension by effort; we never foreclose *whether* it can have one.
4. **Three-tier field placement** (the core discipline). The placement test for any field is "how many `bomType`s use it?":
   - **Component root** (`Base_Component`): generic identity (`name`, `version`, `componentId`, `externalIds`, `owner`, `labels`) + the `boms[]` field. *No BOM-type-specific fields, ever.*
   - **Shared BOM base** (every `bomType`): *required* — `bomType`, `format`, carriage (`ref?`/`document?`); *optional, with defined semantics* — `hashes[]` (**integrity of the carried BOM *document*** — the referenced/embedded manifest file — **not** the subject artifact; subject/artifact integrity is a generic component property, see §11), `uniqueId`, `license` (**optional/nullable** — meaningless for CBOM algorithms and often HBOM parts; per-node licenses live in the extension). *Only fields shared by ≥2 bomTypes.* Subject identity **and subject integrity** are **inherited** from the host component/system (§11), not re-owned by the BOM.
   - **Type-specific extension** (per `bomType`): the manifest's distinctive content, which **may be a typed graph** (`nodes[]` + reference-based `edges[]`) for relational BOMs (CBOM, SaaSBOM). A field used by exactly one bomType lives here.
5. **`aiModel` and `dataset` are symmetric thin component types** (`type` enum + `Component` oneOf), each adding only identity/correlation fields (parallel to `Host_Component`'s `hostname`/`ip`); all model/dataset detail lives in the BOM payload. Model and dataset are treated as co-equal first-class subjects — both get identity (component), integrity (§11), governance, and lineage: `aiModel`↔`ai-model` extension (`baseModelRef`/`adaptationType`) and `dataset`↔`dataset` extension (`baseDatasetRefs`/derivation). `ai-model.datasetRefs` references dataset `componentId`s rather than duplicating dataset detail (cf. §10). *(Symmetry added 2026-07-01; the initial cut shipped `aiModel` as a full subject but `dataset` as a bomType only — an internal-consistency gap corrected here. Co-equal model/dataset treatment is the prevailing direction across AIBOM discussions.)*
6. **`bomType` is an open, reserved enum.** Model vs dataset are distinct `bomType`s on the shared base. Reserve CycloneDX-aligned values now to avoid a breaking widening later: `sbom`, `ai-model`, `dataset`, `hbom`, `cbom`, `saasbom`, `obom`, `mbom`, `kbom` (extensible via pattern/registry). Coverage tiers: **normalize now** — `sbom`, `ai-model`, `dataset`; **reserve + passthrough now, normalize later** — `hbom`, `cbom`, `saasbom`, `obom`, `mbom`, `kbom`; **excluded (not BOMs)** — VEX, VDR, and SPDX's SecurityProfile (vulnerability *assertions*, already handled via converters/amendments; `format: spdx` must not imply a BOM when the payload is a SecurityProfile).
7. **Field set aligned to the CISA/G7 "SBOM for AI" minimum elements** (the interoperability target). AI fields are optional (standards-correct; only the EU AI Act makes a subset binding for high-risk/GPAI). `adaptationType` adopts Hugging Face's `finetune | adapter | quantized | merge` (the only typed lineage enum in the ecosystem). `parameterCount` and `serializationFormat` are first-class **within the ai-model extension** (never at root). Structural disagreements normalize to the most expressive (superset) shape with a free-text fallback (bias → CycloneDX structured object + prose fallback; energy → CycloneDX per-activity array).
8. **No backward compatibility** — clean replacement of the SBOM trio (rapid-iteration phase; community expects breaking schema changes).
9. **Dual TypeScript + Go parity is an invariant** — every schema type, parser, and converter exists in both languages; no TS-only helpers.
10. **System-scoped relational BOMs reference `hdf-system`, they do not duplicate it.** SaaSBOM's services + data-flows overlap `hdf-system`'s existing `components[]` + data-flow graph; a normalized SaaSBOM/KBOM aligns with or references those first-class entities rather than re-inventing a parallel graph inside a BOM payload. This — not expressibility — is the real constraint on relational BOMs.
11. **Artifact integrity is a generic subject property, unified on `Base_Component.integrity`.** The integrity of a *subject artifact* (model weights, dataset archive, container image layers, package bytes) is distinct from the integrity of a *BOM document* (`Bom.hashes[]`, §4). Because it applies to every component kind — not just BOMs — it lives on the component, expressed once as `Base_Component.integrity` (an array of `Checksum` supporting multi-file/sharded artifacts). This closes the model/dataset weight-hash gap (artifact integrity is a widely-cited AIBOM minimum element) and **unifies** the three ad-hoc integrity shapes HDF carried before (`Container_Image_Component.digest`, `Artifact_Component.checksum`, and none-elsewhere), which are absorbed into the single field. Deliberately the *wider* refactor over a per-BOM-type integrity field: it costs a broader change (including reconciling `Hash_Algorithm` with the old digest pattern's BLAKE3) but removes standing schema debt. Adopted 2026-07-01.

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

### Alternative F: Two-class model — some BOMs normalizable, relational ones carriage-only
Make SBOM/AI-BOM first-class (normalized) but declare relational BOMs (SaaSBOM, CBOM) expressible only as opaque passthrough references.
- **Pros:** Avoids the effort of modeling graphs in HDF's own fields.
- **Cons:** Directed graphs *are* expressible as `nodes[]` + `edges[]` field sets — CycloneDX itself encodes SaaSBOM data-flows and CBOM `implements`/`uses` this way in JSON — so the restriction is artificial; it would permanently relegate crypto-agility (CBOM) and attack-surface (SaaSBOM) inventory to un-queryable blobs.
- **Why rejected:** Every `bomType` is a normalization target (relational extensions are allowed); passthrough is a universal interim, not a second tier. We sequence normalization by effort, we do not foreclose it. The genuine constraint that remains is Decision §10 (don't duplicate `hdf-system`), which is about avoiding redundancy, not about expressibility.

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
- Shared `Bom` primitive + generalized `boms[]` on **both** `Base_Component` (replacing the SBOM trio) and `hdf-system`; shared BOM base + `ai-model`/`dataset`/`sbom` normalized extensions; `aiModel` component type.
- Reserve the full `bomType` enum now (`sbom, ai-model, dataset, hbom, cbom, saasbom, obom, mbom, kbom`, extensible) — passthrough works immediately for the reserved-but-not-yet-normalized types.
- Evidence-package `Content_Type` generalization; `hdf-comparison` diff generalization beyond purl-only.
- Dual-language shared `bom/` parser module.
- Update `cyclonedx-to-hdf`; add `cyclonedx-mlbom-to-hdf` and `spdx-ai-to-hdf` converters.

**OUT of scope:**
- **Normalized** extensions for `hbom`/`cbom`/`saasbom`/`obom`/`mbom`/`kbom` — reserved + passthrough-capable now; each normalized shape (with its converter) is a later PR, and SaaSBOM/CBOM must honor the Decision §10 anti-duplication guardrail.
- Model/build signing & provenance (OpenSSF Model Signing, Sigstore, SLSA/in-toto) and OCI model packaging — future `bomType`s/converters at most.
- The deferred siblings: `hdf-libs-9zig`, `hdf-libs-gccd`, `hdf-libs-vqic`, `hdf-libs-gxxb`, `hdf-libs-bsfr`.
- Adversarial-evaluation baselines and enterprise portfolio aggregation.

### Phases

#### Phase 1: Schema — generalized BOM + aiModel component (unblocked — start here)
**Files:**
- Create: `hdf-schema/src/schemas/primitives/bom.schema.json` (shared `Bom` base + `ai-model`/`dataset`/`sbom` normalized extensions; reserved `bomType` enum; `format`/carriage discriminators; `hashes`=artifact-integrity and `license` optional/nullable semantics)
- Modify: `hdf-schema/src/schemas/primitives/component.schema.json` (replace `sbom`/`sbomRef`/`sbomFormat` with `boms[]`; add `aiModel` to the `type` enum + `AI_Model_Component` to the `Component` oneOf); `hdf-schema/src/schemas/hdf-system.schema.json` (add system-scoped `boms[]`); `hdf-schema/src/schemas/hdf-evidence-package.schema.json` (generalize `Content_Type`); `hdf-schema/src/schemas/primitives/comparison.schema.json` (generalize `Package_Diff` identity)
- Test: `hdf-schema/test/` (bom + component + evidence-package validation, incl. examples per the schema-examples convention)

**Acceptance criteria:**
- [ ] `boms[]` validates on **both** `Base_Component` and `hdf-system`; `bomType` accepts every reserved value; passthrough (`ref`/`document`) validates for **every** reserved type; `ai-model`/`dataset`/`sbom` normalized extensions validate
- [ ] `aiModel` component validates via the oneOf; `sbom`/`sbomRef`/`sbomFormat` removed
- [ ] AI-specific fields (`parameterCount`, `serializationFormat`, etc.) live only in the `ai-model` extension; `adaptationType` enum = `finetune|adapter|quantized|merge`
- [ ] `pnpm build:schemas` regenerates bundled schemas + `hdf-validators/go/schemas/`; TS + Go types regenerate

**Verification:** `cd hdf-schema && pnpm build && pnpm test`

#### Phase 1 refinements (post-`kirq.1`, before Phase 2) — added 2026-07-01
Two schema refinements land on the settled Phase 1 shape before the parser is built, so Phase 2 targets the final schema:
- **`kirq.6` — model/dataset symmetry (§5):** add a thin `dataset` component type; give the `dataset` extension lineage (`baseDatasetRefs`) + a derivation enum; document `ai-model.datasetRefs` as `componentId` references; clarify `Bom.hashes[]` as BOM-document integrity.
- **`kirq.7` — unified subject integrity (§11):** add `Base_Component.integrity` (`Checksum[]`); remove `Container_Image_Component.digest` and `Artifact_Component.checksum`; reconcile `Hash_Algorithm` with the old digest pattern's BLAKE3. Assess the digest/checksum consumer blast radius at card start (the `kirq.1 → kirq.4/kirq.5` pattern).

Dependency chain: `kirq.6 → kirq.7 → kirq.2`.

#### Phase 3 refinement: cross-standard AI/dataset field coverage (`kirq.8`) — added 2026-07-02
Building the SPDX-3 AI/dataset path (`kirq.3.3`) surfaced that the normalized `ai-model`/`dataset` extensions were shaped almost entirely by CycloneDX-ML, so SPDX-3's richer AI/governance vocabulary had no first-class home. This refinement widens the two extensions **before** `kirq.3.3` builds, so the SPDX-3 normalizer targets the final shape.

**Two layers, kept distinct.** *Carriage* is already a superset: both extensions are `additionalProperties: true` and every `Bom` carries its raw source element via `document`, so no source field is ever lost regardless of what is named. This refinement is only about the *contract* layer — which fields become named, validated, documented, queryable, and part of the generated TS/Go/Python types.

**Inclusion rule (decided).** Promote a field to the contract iff it is either (a) cleanly present in **both** SPDX-3 **and** CycloneDX-ML (the intersection — high cross-standard confidence), **or** (b) a **CISA/G7 "SBOM for AI" minimum element** not already covered elsewhere in the HDF component/BOM model. CISA's set is authoritative and *bounded* (it is a curated minimum, not the mechanical union of every format's fields), which gives a principled, stable inclusion rule without the maintenance tail and institutionalized lossy mappings of a full union. Everything outside this rule stays passthrough.

**CISA/G7 minimum-element coverage (Models + Dataset clusters).** Already covered: model/dataset name·identifier·version (component + `modelId`/`datasetId`), hash value+algorithm (`Base_Component.integrity`), architecture (`modelArchitecture`), parameter count (`parameterCount`), RLHF/fine-tuning (`adaptationType`), license (`Bom.license`), producer (`owner`), external references (`externalIds`), dataset intended-use·sensitivity·dependency (`intendedUse`/`dataClassification`/`baseDatasetRefs`), dataset format (`datasetFormat`). Deliberately **not** promoted (covered elsewhere or low query value; carried via passthrough if a converter has them): model timestamp (document/tool timestamp), parametric/non-parametric flag, model size in bytes (`parameterCount`+`serializationFormat` suffice).

**Promoted fields (intersection + uncovered CISA gaps):**

- `AI_Model_Extension` (+5, all optional):
  - `learningApproach` — string, free-text (SPDX `ai_typeOfModel` ∩ CDX `modelParameters.approach.type` ∩ G7 "learning type").
  - `task` — string, free-text (CDX `modelParameters.task`; SPDX `ai_domain` is domain-level/adjacent — noted; G7 intended-application).
  - `performanceMetrics` — `array<{name, value}>`, free-text values (SPDX `ai_metric` ∩ CDX `quantitativeAnalysis.performanceMetrics` ∩ G7 KPI cluster).
  - `hyperparameters` — `array<{name, value}>` (CISA "Model properties: hyper-parameters"; SPDX `ai_hyperparameter`). **Not** `parameterCount` — see traps.
  - `inputOutput` — `object{ dataTypes?, modality?, contextLength?, tokenizer? }`, all optional (CISA "Model input-output properties"; CDX `inputs[].format`/`outputs[].format`).
- `Dataset_Extension` (+3, all optional):
  - `modality` — string|array (CISA "Dataset content: modality"; resolves SPDX `dataset_datasetType`, which is content-kind, **not** physical format — kept distinct from `datasetFormat`).
  - `provenance` — string, free-text (CISA "Dataset provenance"; SPDX `dataset_dataCollectionProcess`).
  - `statisticalProperties` — string, free-text (CISA "Dataset statistical properties"; `recordCount` remains the one structured stat).

**Traps (carried from the field audit).** SPDX `ai_hyperparameter` is a *list of training hyper-parameters* (28 `{key,value}` entries in the real fixture), never the model's trainable-parameter count → maps to `hyperparameters`, never `parameterCount`. SPDX `dataset_datasetSize` has unlabeled, inconsistent units across real fixtures (`2689` rows-ish vs `117553` bytes-ish) → not promoted, not auto-mapped to `recordCount`. Array→scalar SPDX fields (`ai_typeOfModel`, `ai_domain`) must pick one value and carry the source via `document`, never silently truncate.

**Symmetry requirement.** A promoted field is cross-standard by construction, so `kirq.3.2`'s CycloneDX-ML normalizer must populate the same new fields it can source (`learningApproach`, `task`, `performanceMetrics`, `inputOutput`) — not just the SPDX-3 path. Passthrough-only otherwise.

Dependency: `kirq.8` blocks `kirq.3.3`.

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
- **`kirq.8` field-coverage source:** CISA/G7, *Software Bill of Materials for AI — Minimum Elements*, https://www.cisa.gov/resources-tools/resources/software-bill-materials-ai-minimum-elements (Models + Dataset Properties clusters used as the baseline the promoted `ai-model`/`dataset` fields must cover).
- **Supporting reading — AIBOM field maturity:** Allan Friedman & Nick Leiserson, "Driving AI Transparency: Supply- and Demand-Based Paths Toward AIBOM," Institute for Security and Technology, June 2026, https://securityandtechnology.org/virtual-library/policy-memo/driving-ai-transparency/. One of several ongoing public discussions of AIBOM minimum elements, consistent with our own reading that AIBOM remains early/in-flux and that identity, integrity, lineage, and provenance dominate proposed minimums. HDF does **not** adopt its recommendations verbatim — the normative field set stays anchored to CISA/G7 and CycloneDX/SPDX; the memo's provenance cluster (supplier/origin/creator/supporting-documentation, data origin/country/processing-history) is intentionally out of scope this pass.
