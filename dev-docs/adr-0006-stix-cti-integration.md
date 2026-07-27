# ADR-0006: STIX 2.1 CTI integration — generalized external references + `stix-to-hdf`

- **Status:** Proposed
- **Date:** 2026-07-22
- **Revised:** 2026-07-26 — incorporates the PR #162 design review (aaronlippold): the CVSS Exploit-Maturity bridge for honest risk recomputation, the converter honesty-boundary split, and `External_Reference` refinements (open `rel`, `anyOf`, `href`, URN note).
- **Branch:** `feat/cti`
- **Related:** ADR-0001 (generalized BOM representation — the passthrough + partial-fidelity precedent this extends); bead `hdf-libs-avp2` (broader ref-migration follow-up); PR #162 (design review)

## Context

We want HDF to interface with the STIX/TAXII cyber-threat-intelligence (CTI) ecosystem. This ADR covers **STIX-the-format** only — representing and ingesting STIX content, and referencing it from HDF documents. **TAXII** (the live transport/fetch protocol) is explicitly deferred to a future PR; nothing here requires pulling data over the wire.

Two forces converge on the same design surface:

1. **CTI reference need.** Consumers want to attach CTI — an external STIX bundle or object — to HDF documents at multiple levels: a system's threat environment, a specific finding, or an override's justification.

2. **Reference proliferation.** A survey of `hdf-schema/src/schemas/` found ~21 distinct external-reference constructs. Exactly one is a general-purpose reference (`Reference`, `primitives/common.schema.json:118-173`, an `anyOf` of `{ref | url | uri}`), and it is deployed in a single place (`Requirement_Core.refs[]`). Four others are discriminated-polymorphic (`Bom.ref` by `bomType`, `Content_Reference` by `type`, `External_Evidence_Reference` by `format`, `Evidence` `type:"url"`). The rest (~15) are type-locked (`systemRef`, `planRef`, `Remediation.uri`, component URLs, lineage refs, comparison sources, …). There is **no single "reference any external artifact URI, even one with no dedicated category" primitive.**

STIX itself already solved the generic-reference problem. Its `external_references` common property — present on every object — is `{source_name (required), external_id?, url?, description?, hashes?}` with the rule "`source_name` plus at least one of `external_id`/`url`/`description`." Its `source_name` + `external_id` shape (cite something by its id in a named system *without* needing a URL — e.g. `cve`/`CVE-2021-44228`, `mitre-att&ck`/`T1059`) is strictly more expressive than HDF's current `Reference`.

**Domain-direction reality.** HDF is *defensive assessment* data ("did this system pass its controls?"); STIX is *threat* data ("what are adversaries doing?"). HDF is naturally a CTI **consumer**, not a producer. A STIX `vulnerability` object is minimal (`{name, external_references:[cve]}`) and carries **no pass/fail status or impact** — so a naive "STIX vulnerability → HDF results finding" would *fabricate* status, violating the project's long-standing no-fabrication rule.

**The honest bridge: CVSS Exploit Maturity.** STIX 2.1 has exactly one native numeric — `confidence` (0–100, Common Properties §3.2) — and it measures *certainty of the assertion, not severity of the threat*. "Actively exploited" is expressed structurally (a `sighting`/`indicator`/`relationship:exploits` graph carrying only `count` and `confidence`), never a magnitude. So a direct "STIX → impact number" **is** fabrication. But that exploitation signal is exactly the semantic of one CVSS metric: **Exploit Maturity** (`E:A` "Attacked" in CVSS 4.0; `E:H`/`E:F` in 3.1). Applying `E:A` to a finding's existing vendor **Base vector** deterministically recomputes a Threat score *via the published CVSS algorithm* — a number that is **computed, not invented**. HDF already ships the carriers for this: the `Cvss` primitive models Base/Threat groups with `baseVector` + `threatVector` + `computedScore`, `Evaluated_Requirement` carries `cvss`/`kev`/`epss`, and `Standalone_Override` already has a `cvss` field with the soft rule `impact.value ≈ computedScore / 10.0` ("makes Threat enrichment auditable").

**Two operations, not one — and only one can be a standalone converter.** Ingesting STIX *as reference/context* is a blind `bundle → amendments` transform that needs nothing but the bundle. *Adjusting a finding's risk from exploitation intel* is different: it needs the finding's **Base vector**, which STIX never carries — so it is inherently an **enrichment/correlation over an existing results doc**, not a convert-time operation. A standalone `stix-to-hdf` converter therefore **cannot** honestly emit a `riskAdjustment` impact (it has no base vector, and `riskAdjustment` requires `impact`). The honest split: the converter emits `External_Reference` + passthrough unconditionally; the `E:A` risk recomputation is authored later, at correlation against real findings, where the base vector exists. Map exploitation to CVSS `E:A` **specifically** — never to `Kev` (CISA catalog) or `Epss` (FIRST model), which would be fabrication unless the STIX *source* is literally that feed.

**Constraints inherited from the repo:** no fabricated data (real fixtures only); canonical trimmed-UTC RFC3339 timestamps; dual Go + TS converter parity enforced by the snapshot harness + ground-truth anchors; schema changes require the full regen/propagate chain and a version bump.

## Decision

Four coupled decisions:

### 1. Introduce a generalized `External_Reference` primitive (STIX-shaped)
In `primitives/common.schema.json`, modeled on STIX `external_references` and cross-checked against OSCAL `link`, OCSF `enrichment`, ECS `threat.enrichments`, and the URI RFCs:

- `sourceName` — **required**, open string (plus the `x-` custom convention already used for `bomType`); names the external system (`cve`, `mitre-att&ck`, `stix`, `taxii`, or any vendor label). Deliberately **not** a closed enum — that is the future-proofing.
- **`anyOf`** `externalId`, `href`, or `description` — at least one required, but **any combination is allowed** (RFC 3986 §1.1.3 and STIX's own examples carry an id *and* a locator together; the only hard rule is "not neither"). Explicitly **not** `oneOf`.
- `href` (format **`uri-reference`**, not `uri`) is the locator — so a bare `#fragment`/`#uuid` internal reference is expressible (the OSCAL `#uuid` pattern), which also serves the future `avp2` consolidation. (`url` was the earlier name; `href` + `uri-reference` supersedes it.)
- optional open **`rel`** relationship token — the one field ≥2 peer standards carry that a plain reference otherwise omits (OSCAL `rel` `allow-other="yes"`; RFC 8288 extension relations). Ship a documented starter vocabulary (`reference`, `definition`, `evidence`, `investigate`, `canonical`) but keep it **open** (distinguishes "definition" vs "live pivot" vs "evidence" vs "canonical").
- optional `checksum` (reuse the HDF `Checksum` primitive — *not* STIX's `hashes`, to stay in HDF conventions) and `mediaType`. These apply meaningfully **only to retrievable (`href`) refs**; note as much.
- optional **`addedBy` (`Identity`) + `addedAt` (timestamp)** — lightweight attribution so "who attached this context, and when" is answerable *without* the override machinery (see the channel-split principle). Deliberately flat: no chaining, superseding, or disposition — a reference overrides nothing, so it needs none of that.

**URN equivalence (note in the primitive):** `sourceName` + `externalId` **is** a URN — `urn:<sourceName>:<externalId>` (RFC 8141) — so the by-identity (`cve`/`CVE-2021-44228`) and by-location (`href`) forms stay interconvertible.

It stays **one-tier** (no OSCAL-style two-tier back-matter `resource` model, which would be speculative here). It **coexists** with the existing narrow `Reference`; migrating the other scattered refs onto it is **out of scope** here (bead `avp2`). The CTI use case is this primitive's proving ground.

### 2. Wire `externalReferences[]` broadly — err toward more carriers, not fewer
Add an optional `externalReferences: External_Reference[]` at every level where an artifact reference is plausibly useful — the primitive is generic and future-proofing is the goal, so over-provision rather than under-provision:
- **hdf-system** (root + system-level threat environment),
- **hdf-results** root, **`Evaluated_Baseline`**, and **`Evaluated_Requirement`** (per-finding CTI enrichment / correlation),
- **hdf-baseline** root and **`Requirement_Core`** (so references travel with the requirement definition itself),
- **`Standalone_Override`** in hdf-amendments (the STIX source behind an actionable override),
- other document roots (plan, evidence-package, comparison) where it reads naturally.

This is a deliberately wide surface. Consequence: the schema wiring is a **large lift** even though each addition is small and additive.

### 3. Add a `stix-to-hdf` converter that emits **HDF Amendments** (reference + passthrough only)
A standalone converter sees only the bundle — never a finding's Base vector — so it **cannot** honestly emit a `riskAdjustment` impact (see Context). It therefore emits the non-fabricating slice unconditionally:
- For each STIX object, emit a document-level record carrying `externalReferences[]` back to the source STIX (`sourceName: "stix"`, `externalId` = the STIX id, `rel: "reference"`/`"investigate"`) plus a **passthrough** of the raw object. CVE-bearing `vulnerability` objects that carry an exploitation signal (are the `sighting_of_ref` of a `sighting`, or referenced by an `indicator`/`report`) additionally record the CVE and the exploitation fact — as context the correlation step (decision 4) can act on.
- **Emit no `impact` and no `riskAdjustment` at convert time.** The converter has no base vector to recompute from; any impact here would be fabrication. (Schema note: `riskAdjustment` *requires* `impact`, which is precisely why it cannot be authored here.)
- **Never fabricate** status/impact. Objects with no assessment meaning (`threat-actor`, `campaign`, plain `identity`/`location`, …) are carried as reference + passthrough only.
- **Partial-fidelity + passthrough** (the ADR-0001 pattern): normalize the clean fields; preserve the raw STIX losslessly.

### 4. CVSS recomputation at correlation — the `E:A` `riskAdjustment` (enrichment, not convert)
The honest risk adjustment is authored where the Base vector exists: an **enrichment pass over a results doc** that has CVE findings. Given a STIX-derived exploitation signal for a CVE:
- Match the signal to a finding **by CVE**; read that finding's `cvss[].baseVector`.
- Apply CVSS Exploit Maturity `E:A` (version-aware: `E:H`/`E:F` for a 3.1 base) and recompute the Threat/`computedScore` **via the published CVSS algorithm**.
- Emit a `riskAdjustment` `Standalone_Override` whose `cvss` block records `threatVector` + recomputed `computedScore`, with `impact.value = computedScore / 10.0` and `externalReferences[]` back to the STIX source. HDF's existing override resolver then surfaces the adjusted `effectiveImpact` for free.
- **Guardrails:** recompute only when a Base vector is present (else emit nothing — no fabrication); map exploitation to `E:A` only, never `Kev`/`Epss` unless the STIX source *is* that catalog/feed.

This needs one new shared capability: a **CVSS scoring engine** in `hdf-utilities`. Today it can only *parse* and *validate* vectors (`parseCvssVector`/`validateCvssVector`, Go + TS); it cannot *compute* a Base+Threat score. That engine is the single missing piece and is independently useful (any Threat/Environmental recompute, not just STIX).

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

### Alternative F — `stix-to-hdf` emits the `E:A` `riskAdjustment` (with recomputed CVSS) at convert time
- **Pros:** one command produces the risk-adjusted amendment directly; no separate enrichment step.
- **Cons:** the converter has only the STIX bundle, which carries **no CVSS Base vector** — so it cannot recompute a score, and `riskAdjustment` *requires* `impact`. It would have to either fabricate a number or emit nothing. Correlating "this CVE" to "this finding's base vector" is inherently a merge over a results doc the converter does not have.
- **Why rejected:** it collapses two operations that must stay separate (decisions 3 and 4). The converter stays non-fabricating (refs + passthrough); the recomputation is an enrichment pass where the base vector actually exists.

### Alternative G — a CVSS scoring dependency (npm/Go module) instead of an in-repo engine
- **Pros:** no formula to implement/maintain.
- **Cons:** adds a runtime dependency to the low-level `hdf-utilities` layer (which today is testify-only on the Go side); parity across Go + TS would hinge on two third-party libraries agreeing byte-for-byte; the CVSS 3.1/4.0 formulas are published and stable.
- **Why rejected:** a small, tested, dual-language scorer keeps `hdf-utilities` dependency-light and guarantees Go/TS parity via shared fixtures — consistent with how the repo already treats CVSS parse/validate.

### Do-Nothing
- Consumers hand-roll CTI links in free-text/tags; no interoperability; the generic-reference gap and ref proliferation both grow. Exploitation intel never reaches the risk score.
- **Why rejected:** misses the interop goal and leaves a known gap the team already wants closed.

## Consequences

**What becomes easier**
- CTI attaches to HDF through one principled, STIX-aligned reference instead of ad-hoc fields.
- A generic `External_Reference` future-proofs "reference any artifact" and gives `avp2` a target to consolidate onto.
- `stix-to-hdf` yields real threat-context amendments, reusing the VEX/amendment machinery, snapshot harness, and anchors already in place.
- **Exploitation intel reaches the risk score, honestly.** Applying a STIX-derived amendment to a CVE-bearing results doc yields an auditable, CVSS-algorithm-computed threat score — no hand-set impacts, no fabrication.
- **A reusable CVSS scoring engine** lands in `hdf-utilities` — useful for any Threat/Environmental recompute, not just STIX (e.g. VEX enrichment, environmental tailoring).

**What becomes harder**
- One more converter pair to keep in Go/TS lockstep, **plus** a CVSS scorer and an amendment-apply enrichment path — more dual-language surface.
- A schema change touching **many carriers** (system, results root/baseline/requirement, baseline root/requirement, override, other doc roots) → full regen/propagate chain + version bump. Each addition is small and additive, but the breadth makes the schema phase a **large lift** and a wide review surface.
- Implementing the CVSS 3.1/4.0 formulas correctly in two languages (with shared fixtures to guarantee parity) is exacting work.
- Passthrough of raw STIX inflates amendment documents.

**Risks + mitigations**
- *STIX↔HDF semantic mismatch yields low-value overrides* → the standalone converter emits **no** overrides, only refs + passthrough; the risk adjustment is a deliberate correlation step over the exploitation/CVE slice.
- *CVSS scorer disagrees with authoritative calculators* → validate against the published CVSS spec test vectors (NVD/FIRST reference vectors) as fixtures, Go + TS byte-identical.
- *Recompute attempted with no Base vector* → guardrail emits nothing (the finding keeps its base impact); never fabricate.
- *Mis-mapping exploitation to KEV/EPSS* → map only to CVSS `E:A`; `Kev`/`Epss` targets require the STIX source to be that catalog/feed.
- *Passthrough size blowup* → passthrough is optional and size-validated (`ValidateJSONSize` first, existing limits).
- *STIX 2.2 shape churn* → `sourceName` is open and the primitive is additive; no closed enum to migrate.
- *Primitive scope creep into a repo-wide ref refactor* → migration of existing refs is explicitly deferred to `avp2`; this PR wires only CTI carriers.

## Implementation Plan

### Scope
**IN:** `External_Reference` primitive (open `rel`, `anyOf` id/href/description, `href` as `uri-reference`, optional `checksum`/`mediaType`/`addedBy`/`addedAt`, URN note); `externalReferences[]` wired broadly (hdf-system root, hdf-results root + `Evaluated_Baseline` + `Evaluated_Requirement`, hdf-baseline root + `Requirement_Core`, `Standalone_Override`, and other doc roots as fitting); `stix-to-hdf` → amendments (Go + TS, **refs + passthrough only, no fabricated impact**) with fingerprint + CLI integration; a **CVSS scoring engine** in `hdf-utilities` (Base+Threat compute, Go + TS); an **amendment-apply CVSS-recompute enrichment** that authors the `E:A` `riskAdjustment` against a CVE-bearing results doc; real STIX-bundle + CVSS-spec-vector fixtures; schema regen/propagate + examples + validator tests; docs + CHANGELOG.

**OUT:** TAXII fetch; `hdf-to-stix` export; migrating the existing ~20 refs onto `External_Reference` (`avp2`); any Results-output normalization; native rich-CTI schema shapes; CVSS **Environmental** tailoring beyond what the Threat recompute needs (the engine may support it, but STIX drives only Threat/`E`).

### Quality Standards (inherited by every card)
- Dual Go + TS parity, wired into the shared snapshot harness with an output-count ground-truth anchor (the machinery landed on `main`).
- No fabrication; canonical trimmed-UTC timestamps via the shared parse/serialize helpers; `ValidateJSONSize` as the first converter operation.
- **Real fixtures only** — STIX bundles sourced from the OASIS STIX 2.1 example corpus / public CTI, provenance documented; never fabricated.
- `examples` on every new/`$def` touched; schema regen/propagate run in full and committed together.

### Shared Abstractions (built first)
- The `External_Reference` primitive — the schema and both converters depend on it; land it before wiring.
- A STIX-bundle detect/parse helper in `shared/go` + `shared/typescript` — consumed by both the fingerprint and the converter (no fork).
- The **CVSS scoring engine** in `hdf-utilities` (Go + TS) — extends the existing parse/validate with Base+Threat computation; consumed by the enrichment step, and independently by any future recompute. Built and tested against published CVSS spec vectors before the enrichment consumes it.

### Phases
Phases 1–3 (STIX-format ingestion) and phase 4 (CVSS engine) are independent; phase 5 depends on 4 (and, for the override carrier, on 1).
- **Phase 1 — Schema.** `External_Reference` primitive (open `rel`, `anyOf` id/href/description, `href` `uri-reference`, URN note) + `externalReferences[]` wiring + full regen/propagate + examples + validator (Go + TS) tests. *AC:* a doc using `externalReferences[]` validates; a malformed one (no `sourceName`, or `sourceName` with none of id/href/description) is rejected; an id+href-together ref validates (`anyOf`, not `oneOf`). *Verify:* `hdf-schema` build+test, validators Go+TS.
- **Phase 2 — `stix-to-hdf` converter (Go + TS).** Bundle → amendments as **`External_Reference` + passthrough only** (no `impact`, no `riskAdjustment`); snapshot goldens; anchor (emitted record count == independently-counted STIX objects in the bundle). *AC:* real STIX fixture → refs + passthrough; **no** override carries a fabricated impact; non-exploitation objects are carried as reference only. *Verify:* converter Go+TS snapshot + anchor; golangci-lint/eslint/tsc clean.
- **Phase 3 — CLI + fingerprint.** Register `stix` fingerprint (detect `{type:"bundle", objects:[…]}`) and CLI wiring; auto-detect test. *AC:* `hdf convert <bundle>` auto-detects STIX and emits valid amendments. *Verify:* CLI convert+validate live.
- **Phase 4 — CVSS scoring engine (`hdf-utilities`, Go + TS).** Add Base+Threat score computation (version-aware 3.1 + 4.0) alongside the existing parse/validate; dual-language parity via shared fixtures. *AC:* computes published CVSS spec test vectors (NVD/FIRST reference vectors) exactly, Go == TS; `E:A` applied to a known Base vector yields the spec's threat score. *Verify:* Go + TS unit tests against spec vectors; parity fixture.
- **Phase 5 — Amendment-apply CVSS recompute (enrichment).** Extend the amendment-apply path: match a STIX-derived exploitation amendment to a finding by CVE, read `cvss[].baseVector`, apply `E:A`, recompute via the phase-4 engine, emit a `riskAdjustment` with the `cvss` block + `impact.value = computedScore/10.0`; existing resolver surfaces `effectiveImpact`. *AC:* applying the amendment to a CVE-bearing results fixture yields the spec-correct adjusted impact; a finding with no Base vector is left unchanged (no fabrication); KEV/EPSS never asserted from generic exploitation. *Verify:* Go + TS over a real results+amendment fixture; live `hdf` apply + `validate`.
- **Phase 6 — Docs + release hygiene.** `site/docs` CTI/STIX guide (incl. the CVSS `E:A` bridge and the convert-vs-enrich split); CHANGELOG; live verification with a real STIX bundle + a recompute example pasted in notes.

### Verification Strategy
Per phase: schema `pnpm test` + validators (Go+TS); converter Go+TS snapshot + ground-truth anchor; CVSS engine against published spec vectors with Go==TS parity; enrichment over a real results+amendment fixture; live `hdf convert/apply … && hdf validate …`; `golangci-lint` + `pnpm lint` clean. The AC-verify gate runs before any card closes.

## Future Work (recorded, not scheduled)
- **`hdf-to-stix` vulnerability-posture export** — CVE-bearing findings → STIX `vulnerability` + `sighting` on the assessed system (`infrastructure`/`identity`). Non-fabricating, fits the existing bidirectional-converter pattern. Build only if a consumer materializes.
- **TAXII fetch command** — an `hdf` subcommand to pull a TAXII 2.1 collection and feed `stix-to-hdf`. Separate PR.
- **`avp2`** — migrate the existing scattered external references onto `External_Reference`.

## References
- **STIX 2.1** (OASIS) — Common Properties §3.2 (`confidence` is certainty, not severity), Vulnerability §4.19 (no native score; CVE via `external_references`), `external-reference` §2.5 (`source_name` + at-least-one rule).
- **CVSS** (FIRST) — v3.1 and v4.0 specifications: Exploit Maturity / Threat metric group and the score-computation formulas; NVD/FIRST published reference vectors (the scoring-engine test fixtures).
- **OSCAL** (NIST) — `link` (`rel` with `allow-other="yes"`) and `back-matter/resource` (the two-tier model we deliberately do *not* adopt).
- **OCSF** `enrichment` (`provider`/`src_url`/`data`); **ECS** `threat.enrichments` / `*.reference`.
- **RFC 3986** (URI reference, incl. `#fragment`), **RFC 8141** (URN — `urn:<sourceName>:<externalId>`), **RFC 8288** (Web Linking `rel`), **RFC 6838** (media types).
- **Internal:** ADR-0001 (BOM passthrough + partial-fidelity precedent); `hdf-schema/src/schemas/primitives/cvss.schema.json` (Base/Threat/`computedScore`); `primitives/amendments.schema.json` (`Standalone_Override.cvss`, `impact.value ≈ computedScore/10.0`); PR #162 design review.
