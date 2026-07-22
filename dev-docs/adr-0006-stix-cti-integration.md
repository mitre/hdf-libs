# ADR-0006: STIX 2.1 CTI integration — generalized external references + `stix-to-hdf`

- **Status:** Proposed
- **Date:** 2026-07-22
- **Branch:** `feat/cti`
- **Related:** ADR-0001 (generalized BOM representation — the passthrough + partial-fidelity precedent this extends); bead `hdf-libs-avp2` (broader ref-migration follow-up)

## Context

We want HDF to interface with the STIX/TAXII cyber-threat-intelligence (CTI) ecosystem. This ADR covers **STIX-the-format** only — representing and ingesting STIX content, and referencing it from HDF documents. **TAXII** (the live transport/fetch protocol) is explicitly deferred to a future PR; nothing here requires pulling data over the wire.

Two forces converge on the same design surface:

1. **CTI reference need.** Consumers want to attach CTI — an external STIX bundle or object — to HDF documents at multiple levels: a system's threat environment, a specific finding, or an override's justification.

2. **Reference proliferation.** A survey of `hdf-schema/src/schemas/` found ~21 distinct external-reference constructs. Exactly one is a general-purpose reference (`Reference`, `primitives/common.schema.json:118-173`, an `anyOf` of `{ref | url | uri}`), and it is deployed in a single place (`Requirement_Core.refs[]`). Four others are discriminated-polymorphic (`Bom.ref` by `bomType`, `Content_Reference` by `type`, `External_Evidence_Reference` by `format`, `Evidence` `type:"url"`). The rest (~15) are type-locked (`systemRef`, `planRef`, `Remediation.uri`, component URLs, lineage refs, comparison sources, …). There is **no single "reference any external artifact URI, even one with no dedicated category" primitive.**

STIX itself already solved the generic-reference problem. Its `external_references` common property — present on every object — is `{source_name (required), external_id?, url?, description?, hashes?}` with the rule "`source_name` plus at least one of `external_id`/`url`/`description`." Its `source_name` + `external_id` shape (cite something by its id in a named system *without* needing a URL — e.g. `cve`/`CVE-2021-44228`, `mitre-att&ck`/`T1059`) is strictly more expressive than HDF's current `Reference`.

**Domain-direction reality.** HDF is *defensive assessment* data ("did this system pass its controls?"); STIX is *threat* data ("what are adversaries doing?"). HDF is naturally a CTI **consumer**, not a producer. A STIX `vulnerability` object is minimal (`{name, external_references:[cve]}`) and carries **no pass/fail status or impact** — so a naive "STIX vulnerability → HDF results finding" would *fabricate* status, violating the project's long-standing no-fabrication rule. The genuinely high-fidelity, non-fabricating map is STIX **exploitation/observation signals** (`sighting`, `indicator`, `report` referencing a CVE-bearing `vulnerability`) → HDF **amendments** (a threat-driven `riskAdjustment`), directly analogous to the existing VEX importers.

**Constraints inherited from the repo:** no fabricated data (real fixtures only); canonical trimmed-UTC RFC3339 timestamps; dual Go + TS converter parity enforced by the snapshot harness + ground-truth anchors; schema changes require the full regen/propagate chain and a version bump.

## Decision

Three coupled decisions:

### 1. Introduce a generalized `External_Reference` primitive (STIX-shaped)
In `primitives/common.schema.json`, modeled on STIX `external_references`:

- `sourceName` — **required**, open string (plus the `x-` custom convention already used for `bomType`); names the external system (`cve`, `mitre-att&ck`, `stix`, `taxii`, or any vendor label). Deliberately **not** a closed enum — that is the future-proofing.
- at least **one of** `externalId`, `url` (format `uri`), or `description` is required.
- optional `checksum` (reuse the HDF `Checksum` primitive — *not* STIX's `hashes`, to stay in HDF conventions) and `mediaType`.
- optional **`addedBy` (`Identity`) + `addedAt` (timestamp)** — lightweight attribution so "who attached this context, and when" is answerable *without* the override machinery (see decision 3). Deliberately flat: no chaining, superseding, or disposition — a reference overrides nothing, so it needs none of that.

It **coexists** with the existing narrow `Reference`; migrating the other scattered refs onto it is **out of scope** here (bead `avp2`). The CTI use case is this primitive's proving ground.

### 2. Wire `externalReferences[]` broadly — err toward more carriers, not fewer
Add an optional `externalReferences: External_Reference[]` at every level where an artifact reference is plausibly useful — the primitive is generic and future-proofing is the goal, so over-provision rather than under-provision:
- **hdf-system** (root + system-level threat environment),
- **hdf-results** root, **`Evaluated_Baseline`**, and **`Evaluated_Requirement`** (per-finding CTI enrichment / correlation),
- **hdf-baseline** root and **`Requirement_Core`** (so references travel with the requirement definition itself),
- **`Standalone_Override`** in hdf-amendments (the STIX source behind an actionable override),
- other document roots (plan, evidence-package, comparison) where it reads naturally.

This is a deliberately wide surface. Consequence: the schema wiring is a **large lift** even though each addition is small and additive.

### 3. Add a `stix-to-hdf` converter that emits **HDF Amendments**
STIX bundle → amendment overrides, restricted to the non-fabricating slice:
- For each CVE-bearing `vulnerability` that carries an exploitation/observation signal (is the `sighting_of_ref` of a `sighting`, or referenced by an `indicator`/`report` conveying active exploitation), emit **one override keyed by the CVE `requirementId`**, typed `riskAdjustment`, whose justification is the STIX context, with `externalReferences[]` pointing back to the source STIX and a **passthrough** of the raw STIX object(s).
- **Never fabricate** status/impact for STIX objects that do not carry it. Objects with no assessment meaning (`threat-actor`, `campaign`, plain `identity`/`location`, …) are carried as reference + passthrough, not turned into overrides.
- **Partial-fidelity + passthrough** (the ADR-0001 pattern): normalize the clean fields; preserve the raw STIX losslessly.

### Principle: two CTI channels, split by whether the result changes
The dividing line is **does this CTI change the computed result (status/impact)?**

- **Actionable CTI → an override** (`riskAdjustment`). It mutates the result, so it belongs in the override system and inherits its temporal-graph resolution — who added what, when, superseding chains, disposition/effectiveStatus — for free. It carries an `externalReferences[]` back to its STIX source.
- **Informational CTI → an `External_Reference`** on the requirement/baseline/etc. It changes nothing, so it is **inert to the override resolver by design** and must *not* be modeled as an "override" (which would be a semantic lie — it overrides nothing). Attribution ("who/when") is served by the flat optional `addedBy`/`addedAt` on the reference.

We explicitly **do not** extend the override machinery (chaining, superseding, disposition resolution) to informational context, and we do not build a parallel one. That machinery exists *because* overrides mutate results; context does not, so it needs only lightweight attribution. This keeps the heavyweight system reserved for things that actually override, and avoids rebuilding it for a second set of fields.

## Alternatives Considered

### Alternative A — Bespoke `stixRef`/`cti` field per document
- **Pros:** smallest change; no new primitive.
- **Cons:** adds a 22nd special-cased reference; perpetuates exactly the proliferation we want to stop; no future-proofing for the next artifact kind.
- **Why rejected:** STIX's own design demonstrates a generic primitive is the right answer; a bespoke field is the anti-pattern.

### Alternative B — Generalized primitive as its own schema PR *first*, STIX consumes it later
- **Pros:** cleanest scope isolation; the primitive is reviewed alone.
- **Cons:** sequences/blocks the CTI work behind a schema PR; two regen/propagate cycles; designing the primitive with no real consumer risks getting its shape wrong.
- **Why rejected:** the CTI use case is the best validation of the primitive's shape. We couple the *primitive* to this PR but defer the *migration* of existing refs (that split is bead `avp2`).

### Alternative C — `stix-to-hdf` emits Results (vulnerability findings)
- **Pros:** intuitive ("a STIX vulnerability is a finding").
- **Cons:** STIX vulnerability objects have no status/impact → fabrication; semantically wrong (threat intel is not an assessment result).
- **Why rejected:** violates no-fabrication; amendments are the honest target. (A thin `notReviewed` vulnerability inventory was considered and judged low-value versus the passthrough+reference it would duplicate.)

### Alternative D — Define rich native CTI shapes in HDF + `hdf-to-stix` export
- **Pros:** rich bidirectional CTI.
- **Cons:** scope mismatch — a compliance format authoring adversary intelligence; large schema burden; most STIX objects have no assessment meaning and would be empty/fabricated on export.
- **Why rejected:** HDF should *consume/reference* CTI, not originate it. One bounded export *is* coherent and non-fabricating — **vulnerability posture**: each CVE-bearing finding → a STIX `vulnerability` + a `sighting` on the assessed system's `infrastructure`/`identity` ("we observed this vuln here"). Recorded here as **future work**, not built now.

### Alternative E — A "context-only" override type for informational CTI
- **Pros:** informational CTI would reuse the override document, resolver, and provenance UI.
- **Cons:** it is not an override — no status/impact changes — so it would be a semantic lie that pollutes disposition/effectiveStatus resolution; and to keep it *out* of that resolution we would end up duplicating the temporal-graph machinery for a second set of fields.
- **Why rejected:** the informational/actionable split (decision 3) routes context to `External_Reference` with flat `addedBy`/`addedAt` attribution instead — same "who/when" answer, none of the override-resolver baggage, no parallel system to build.

### Do-Nothing
- Consumers hand-roll CTI links in free-text/tags; no interoperability; the generic-reference gap and ref proliferation both grow.
- **Why rejected:** misses the interop goal and leaves a known gap the team already wants closed.

## Consequences

**What becomes easier**
- CTI attaches to HDF through one principled, STIX-aligned reference instead of ad-hoc fields.
- A generic `External_Reference` future-proofs "reference any artifact" and gives `avp2` a target to consolidate onto.
- `stix-to-hdf` yields real threat-driven amendments, reusing the VEX/amendment machinery, snapshot harness, and anchors already in place.

**What becomes harder**
- One more converter pair to keep in Go/TS lockstep.
- A schema change touching **many carriers** (system, results root/baseline/requirement, baseline root/requirement, override, other doc roots) → full regen/propagate chain + version bump. Each addition is small and additive, but the breadth makes Phase 1 a **large lift** and a wide review surface.
- Passthrough of raw STIX inflates amendment documents.

**Risks + mitigations**
- *STIX↔HDF semantic mismatch yields low-value overrides* → the normalizer is restricted to the exploitation/CVE slice; everything else is reference + passthrough, never a fabricated override.
- *Passthrough size blowup* → passthrough is optional and size-validated (`ValidateJSONSize` first, existing limits).
- *STIX 2.2 shape churn* → `sourceName` is open and the primitive is additive; no closed enum to migrate.
- *Primitive scope creep into a repo-wide ref refactor* → migration of existing refs is explicitly deferred to `avp2`; this PR wires only CTI carriers.

## Implementation Plan

### Scope
**IN:** `External_Reference` primitive (incl. optional `addedBy`/`addedAt`); `externalReferences[]` wired broadly (hdf-system root, hdf-results root + `Evaluated_Baseline` + `Evaluated_Requirement`, hdf-baseline root + `Requirement_Core`, `Standalone_Override`, and other doc roots as fitting); `stix-to-hdf` → amendments (Go + TS) with fingerprint + CLI integration; real STIX-bundle fixtures; schema regen/propagate + examples + validator tests; docs + CHANGELOG.

**OUT:** TAXII fetch; `hdf-to-stix` export; migrating the existing ~20 refs onto `External_Reference` (`avp2`); any Results-output normalization; native rich-CTI schema shapes.

### Quality Standards (inherited by every card)
- Dual Go + TS parity, wired into the shared snapshot harness with an output-count ground-truth anchor (the machinery landed on `main`).
- No fabrication; canonical trimmed-UTC timestamps via the shared parse/serialize helpers; `ValidateJSONSize` as the first converter operation.
- **Real fixtures only** — STIX bundles sourced from the OASIS STIX 2.1 example corpus / public CTI, provenance documented; never fabricated.
- `examples` on every new/`$def` touched; schema regen/propagate run in full and committed together.

### Shared Abstractions (built first)
- The `External_Reference` primitive — the schema and both converters depend on it; land it before wiring.
- A STIX-bundle detect/parse helper in `shared/go` + `shared/typescript` — consumed by both the fingerprint and the converter (no fork).

### Phases
- **Phase 1 — Schema.** `External_Reference` primitive + `externalReferences[]` wiring + full regen/propagate + examples + validator (Go + TS) tests. *AC:* a doc using `externalReferences[]` validates; a malformed one (no `sourceName`, or `sourceName` with none of id/url/description) is rejected. *Verify:* `hdf-schema` build+test, validators Go+TS.
- **Phase 2 — `stix-to-hdf` converter (Go + TS).** Bundle → amendments over the exploitation/CVE slice + passthrough; snapshot goldens; anchor (emitted override count == independently-counted CVE-bearing exploitation objects in the bundle). *AC:* real STIX fixture → expected overrides; non-exploitation objects produce no fabricated overrides. *Verify:* converter Go+TS snapshot + anchor; golangci-lint/eslint/tsc clean.
- **Phase 3 — CLI + fingerprint.** Register `stix` fingerprint (detect `{type:"bundle", objects:[…]}`) and CLI wiring; auto-detect test. *AC:* `hdf convert <bundle>` auto-detects STIX and emits valid amendments. *Verify:* CLI convert+validate live.
- **Phase 4 — Docs + release hygiene.** `site/docs` CTI/STIX guide; CHANGELOG; live verification with a real STIX bundle pasted in notes.

### Verification Strategy
Per phase: schema `pnpm test` + validators (Go+TS); converter Go+TS snapshot + ground-truth anchor; live `hdf convert … && hdf validate …` against a real STIX bundle; `golangci-lint` + `pnpm lint` clean. The AC-verify gate runs before any card closes.

## Future Work (recorded, not scheduled)
- **`hdf-to-stix` vulnerability-posture export** — CVE-bearing findings → STIX `vulnerability` + `sighting` on the assessed system (`infrastructure`/`identity`). Non-fabricating, fits the existing bidirectional-converter pattern. Build only if a consumer materializes.
- **TAXII fetch command** — an `hdf` subcommand to pull a TAXII 2.1 collection and feed `stix-to-hdf`. Separate PR.
- **`avp2`** — migrate the existing scattered external references onto `External_Reference`.
