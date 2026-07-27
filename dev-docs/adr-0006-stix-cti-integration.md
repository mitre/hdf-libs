# ADR-0006: STIX 2.1 CTI integration — generalized external references + enrichment

- **Status:** Proposed
- **Date:** 2026-07-22
- **Revised:** 2026-07-26 — incorporates the PR #162 design review (aaronlippold): the CVSS Exploit-Maturity bridge for honest risk recomputation, the converter honesty-boundary split, and `External_Reference` refinements (open `rel`, `anyOf`, `href`, URN note).
- **Revised:** 2026-07-27 — design pivot after implementing Phase 1. STIX ingestion is modeled as an **enrichment pass over a results doc** (`hdf enrich <results> <source>`), **not** a standalone `stix-to-hdf` → Amendments converter: HDF Amendments has no non-fabricating carrier for inert context (`overrides[]` is required and non-empty; the only `externalReferences[]` carrier is inside `Standalone_Override`, which forces a `requirementId` + status/impact; no lossless-passthrough field exists). `External_Reference` is generalized into an **enrichment envelope** (optional lossless `document` + open `kind`); informational CTI lands inline on the results doc via the `externalReferences[]` carriers already wired in Phase 1, and the `E:A` risk adjustment lands as an inline `Status_Override` in the same pass. A standalone `hdf-enrichment` **document** type is deferred until a second detached-merge consumer exists.
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

**Two operations, both enrichment over a results doc — not a standalone converter.** The obvious shape — "`stix-to-hdf` converts a bundle to an HDF document" — does not survive contact with the schema. A standalone bundle has no findings to bind to, and **HDF Amendments has no non-fabricating carrier for inert context**: its root requires a non-empty `overrides[]`, the only `externalReferences[]` carrier is *inside* `Standalone_Override`, and that override forces a `requirementId` (a STIX `threat-actor` points at no requirement), a `reason`, an `expiresAt`, and — for every type but `operationalRequirement` — a fabricated `status`/`impact`; there is also no lossless-passthrough field anywhere in an amendments document. Forcing STIX context through amendments therefore *requires* fabrication, which the no-fabrication rule forbids.

The honest model is **enrichment**: both STIX operations are correlations over an existing results doc, keyed by CVE. (1) *Informational context* — attach the STIX object to the matching finding (by CVE), or, for non-CVE objects (`threat-actor`, `campaign`, plain `identity`/`location`), to the results root — as an `externalReferences[]` entry that changes nothing. (2) *Risk adjustment from exploitation intel* — read the matched finding's **Base vector** (which STIX never carries), apply CVSS `E:A`, and recompute the Threat score. Both need real findings, so both are enrichment over a results doc, not a convert-time transform. The command is `hdf enrich <results> <source>` (positional parity with `hdf convert`; `--from` as the optional format assertion). Its input is the raw STIX bundle and its output is the enriched results doc — so **no new HDF document type is introduced.** Map exploitation to CVSS `E:A` **specifically** — never to `Kev` (CISA catalog) or `Epss` (FIRST model), which would be fabrication unless the STIX *source* is literally that feed.

**Enrichment is a general concept, and STIX is one payload of it.** The unifying notion is *inert, third-party, post-hoc context attached to a finding* — distinct from the requirement's own `description`/`check`/`fix` (authoritative, ships with the baseline) and from an override (which changes status/impact). Beyond STIX threat-intel, the same envelope fits human triage annotations and the non-scoring slice of exploitation feeds (EPSS/KEV *as context*). It does **not** fit a STIG's Vuln Discussion — that is authoritative requirement metadata already homed in `descriptions[]` (`xccdf-results-to-hdf`, `extractVulnDiscussion`), not a third-party overlay. Because the kinds are heterogeneous, HDF models only the **envelope** (`sourceName`/`kind`/`rel`/`href`/`externalId`/`checksum`/`addedBy`/`addedAt` + an optional lossless `document`); each payload — STIX object, EPSS record, annotation — rides in `document` untouched. STIX itself is a poor *universal* enrichment container (it would distort annotations/EPSS into threat-intel shapes), so it is **one payload kind, not the schema** — which is exactly why we generalize `External_Reference` rather than mint a STIX-shaped type or a second document that duplicates STIX.

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
- optional **`document` + open `kind`** *(added in the 2026-07-27 revision; the Phase-1 primitive shipped without them)* — `document` is a lossless embedded copy of the referenced artifact (the raw STIX object, an EPSS record, an advisory) as an arbitrary object (`additionalProperties: true`); `kind` is an open token (`threat-intel`, `annotation`, `exploitation`, `advisory`, …) classifying the payload. These turn the primitive into the general **enrichment envelope**: `href`/`externalId` point at the artifact, `document` embeds a copy, and `checksum` ties them (the hash of the referent). Lossless embedding and external reference **compose** — one entry may carry both — and HDF stays payload-agnostic: it models the envelope; the STIX/EPSS/advisory content lives untouched in `document`.

**URN equivalence (note in the primitive):** `sourceName` + `externalId` **is** a URN — `urn:<sourceName>:<externalId>` (RFC 8141) — so the by-identity (`cve`/`CVE-2021-44228`) and by-location (`href`) forms stay interconvertible.

It stays **one-tier** (no OSCAL-style two-tier back-matter `resource` model, which would be speculative here). It **coexists** with the existing narrow `Reference`; migrating the other scattered refs onto it is **out of scope** here (bead `avp2`). The CTI use case is this primitive's proving ground.

### 2. Wire `externalReferences[]` broadly — err toward more carriers, not fewer
Add an optional `externalReferences: External_Reference[]` at every level where an artifact reference is plausibly useful — the primitive is generic and future-proofing is the goal, so over-provision rather than under-provision:
- **hdf-system** (root + system-level threat environment),
- **hdf-results** root, **`Evaluated_Baseline`**, and **`Evaluated_Requirement`** (per-finding CTI enrichment / correlation),
- **hdf-baseline** root and **`Requirement_Core`** (so references travel with the requirement definition itself),
- **`Standalone_Override`** in hdf-amendments and the inline **`Status_Override`** on `Evaluated_Requirement.overrides[]` (the STIX source behind an actionable override — the inline carrier is the 2026-07-27 addition, since the `E:A` recompute writes an inline override, not a detached amendment),
- other document roots (plan, evidence-package, comparison) where it reads naturally.

This is a deliberately wide surface. Consequence: the schema wiring is a **large lift** even though each addition is small and additive.

### 3. Ingest STIX as an **enrichment pass over a results doc** — not a standalone converter
STIX integration is `hdf enrich <results> <source>` (positional parity with `hdf convert`; `--from stix` optional, auto-detected from `{type:"bundle", objects:[…]}`). Input is a raw STIX bundle; output is the enriched results doc. No new HDF document type, and no Amendments (which cannot carry inert context without fabrication — see Context).

The **informational** pass changes nothing about status/impact:
- For each STIX object, resolve its CVE (via the object's own `external_references`). If the CVE matches a finding's `requirementId`, append an `externalReferences[]` entry to **that finding** (`Evaluated_Requirement.externalReferences[]`, wired in Phase 1); otherwise — a non-CVE object (`threat-actor`, `campaign`, plain `identity`/`location`), or a CVE with no matching finding — append it to the **results root** `externalReferences[]`.
- Each entry carries `sourceName: "stix"`, `kind: "threat-intel"`, `externalId` = the STIX id, `rel: "reference"`/`"investigate"`, and the raw object losslessly in `document`. `ValidateJSONSize` is the first operation. The pass is a **structural overlay** — the results doc is manipulated as generic JSON and only `externalReferences[]` is appended — so every pre-existing field, including the results' own timestamp strings, round-trips verbatim; it never re-parses or reformats timestamps (so no timestamp helper is needed, and Go↔TS stay byte-compatible on the shared golden).
- **Never fabricate** status/impact. The informational pass authors **no** overrides at all.
- **Partial-fidelity + passthrough** (the ADR-0001 pattern): normalize the clean envelope fields; preserve the raw STIX losslessly in `document`.

The **standalone, target-less** case (a bundle of pure context, or `hdf enrich` with no findings to match) degrades to "file the bundle as bundle-wide context on the results root" — the weak secondary path; the value is in the CVE-matched per-finding enrichment.

### 4. CVSS recomputation — the `E:A` risk adjustment, in the same enrichment pass
The score-changing slice runs in the same pass, but because it **mutates impact** it is a deliberate, opt-in action — not an automatic side effect of attaching context. For a CVE-matched finding whose STIX object carries an exploitation signal (it is the `sighting_of_ref` of a `sighting`, or referenced by an `indicator`/`report`) **and** that has a `cvss[].baseVector`:
- Apply CVSS Exploit Maturity `E:A` (version-aware: `E:H`/`E:F` for a 3.1 base) and recompute the Threat/`computedScore` **via the published CVSS algorithm**.
- Author a `riskAdjustment` **inline override** on the finding (`Evaluated_Requirement.overrides[]`, a `Status_Override`) whose `cvss` block records `threatVector` + recomputed `computedScore`, with `impact.value = computedScore / 10.0` and an `externalReferences[]` entry back to the STIX source. HDF's existing resolver then surfaces the adjusted `effectiveImpact` for free — everything stays in the one enriched results doc.
- **Guardrails:** recompute only when a Base vector is present (else author nothing — no fabrication); map exploitation to `E:A` only, never `Kev`/`Epss` unless the STIX source *is* that catalog/feed.

This needs two small schema follow-ons (the Phase-1b increment): the `document`/`kind` envelope fields on `External_Reference`, and `externalReferences[]` on the inline `Status_Override` (Phase 1 wired only the detached `Standalone_Override`). And one new shared capability: a **CVSS scoring engine** in `hdf-utilities`. Today it can only *parse*/*validate* vectors (`parseCvssVector`/`validateCvssVector`, Go + TS); it cannot *compute* a Base+Threat score. That engine is the single missing piece and is independently useful (any Threat/Environmental recompute, not just STIX). *(Open implementation details for the phase card: the exact CLI surface for opting into recompute — a flag on `hdf enrich` vs. a distinct subcommand — and the required override `expiresAt`/review horizon, since exploitation state is time-bound.)*

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
- **Why rejected:** violates no-fabrication. Note the enrichment model (decision 3) *writes into* a results doc but **does not fabricate findings** — it attaches context to findings that already exist and, at most, authors an auditable `E:A` override on them. Manufacturing new `notReviewed` findings from bare STIX vulnerability objects remains rejected.

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

### Alternative H — `stix-to-hdf` converter emitting HDF Amendments for informational context (the original decision 3)
- **Pros:** one bundle → one document; reuses the VEX/amendment converter machinery, snapshot harness, and anchors already in place.
- **Cons:** HDF Amendments has **no non-fabricating carrier for inert context** — `overrides[]` is required and non-empty, the only `externalReferences[]` carrier is inside `Standalone_Override`, and that override forces `requirementId` + status/impact (or the semantically-wrong `operationalRequirement`); there is no lossless-passthrough field. Every pure-context STIX object (`threat-actor`, `campaign`, …) would require fabricating override fields.
- **Why rejected:** it forces fabrication to satisfy the schema — discovered while implementing Phase 1. Informational context belongs on the `externalReferences[]` carriers already wired onto results/requirement/baseline, populated by the enrichment pass (decision 3), which changes nothing and needs no override scaffolding.

### Alternative I — Add a standalone `hdf-enrichment` document type now
- **Pros:** a detached, mergeable enrichment file symmetric with hdf-amendments; a clean home if enrichment is produced out-of-band and applied later.
- **Cons:** an 8th document type is a permanent maintenance and interop commitment; STIX ingestion needs only the enrichment *pass* (raw bundle in → enriched results out), with no detached HDF file in the loop; no second detached-merge consumer exists yet.
- **Why rejected (deferred):** by the same strict inclusion bar used for `hdf-fixtures` and schema additions, we do not mint a document type speculatively. Deferred to Future Work; revisit when a concrete second consumer (a CTI/annotation platform emitting enrichment files) materializes.

### Alternative J — A rich native `enrichments[]` shape (or a STIX-shaped schema)
- **Pros:** strongly-typed enrichment payloads; queryable without reaching into a passthrough blob.
- **Cons:** the enrichment kinds are heterogeneous (threat-intel, human annotation, exploitation-likelihood, advisory); normalizing each into native HDF shapes either duplicates STIX/EPSS/etc. field-for-field or distorts them. A STIX-shaped type in particular would just re-implement STIX with no benefit and no coverage of the non-threat kinds.
- **Why rejected:** HDF models only the **envelope** (`External_Reference` + `document`/`kind`); each payload rides in `document` untouched. This generalizes across kinds without duplicating any source ontology.

### Do-Nothing
- Consumers hand-roll CTI links in free-text/tags; no interoperability; the generic-reference gap and ref proliferation both grow. Exploitation intel never reaches the risk score.
- **Why rejected:** misses the interop goal and leaves a known gap the team already wants closed.

## Consequences

**What becomes easier**
- CTI attaches to HDF through one principled, STIX-aligned reference instead of ad-hoc fields.
- A generic `External_Reference` future-proofs "reference any artifact" and gives `avp2` a target to consolidate onto.
- `hdf enrich` yields real per-finding threat context (CVE-matched) with lossless STIX passthrough, on the `externalReferences[]` carriers already shipped in Phase 1 — reusing the snapshot harness and ground-truth anchors already in place.
- **Exploitation intel reaches the risk score, honestly.** The same pass, opted into, applies `E:A` to a CVE-bearing finding's Base vector and authors an inline `riskAdjustment` — an auditable, CVSS-algorithm-computed threat score, no hand-set impacts, no fabrication.
- **A general enrichment envelope, not a STIX silo.** `External_Reference` + `document`/`kind` carries any inert third-party context (threat-intel, annotations, EPSS-as-context) without duplicating those source ontologies — STIX is just its first consumer.
- **A reusable CVSS scoring engine** lands in `hdf-utilities` — useful for any Threat/Environmental recompute, not just STIX (e.g. VEX enrichment, environmental tailoring).

**What becomes harder**
- An `hdf enrich` pass to keep in Go/TS lockstep, **plus** a CVSS scorer — more dual-language surface. (No new converter *or* document type, which is the payoff of the enrichment model.)
- A schema change touching **many carriers** (system, results root/baseline/requirement, baseline root/requirement, override, other doc roots) → full regen/propagate chain + version bump. Each addition is small and additive, but the breadth makes the schema phase a **large lift** and a wide review surface.
- Implementing the CVSS 3.1/4.0 formulas correctly in two languages (with shared fixtures to guarantee parity) is exacting work.
- Passthrough of raw STIX in `document` inflates the enriched results document; it is optional and size-validated (`ValidateJSONSize` first, existing limits).

**Risks + mitigations**
- *STIX↔HDF semantic mismatch yields low-value overrides* → the informational pass authors **no** overrides, only `externalReferences[]`; the risk adjustment is a deliberate, opt-in correlation step over the exploitation/CVE slice.
- *CVSS scorer disagrees with authoritative calculators* → validate against the published CVSS spec test vectors (NVD/FIRST reference vectors) as fixtures, Go + TS byte-identical.
- *Recompute attempted with no Base vector* → guardrail emits nothing (the finding keeps its base impact); never fabricate.
- *Mis-mapping exploitation to KEV/EPSS* → map only to CVSS `E:A`; `Kev`/`Epss` targets require the STIX source to be that catalog/feed.
- *Passthrough size blowup* → passthrough is optional and size-validated (`ValidateJSONSize` first, existing limits).
- *STIX 2.2 shape churn* → `sourceName` is open and the primitive is additive; no closed enum to migrate.
- *Primitive scope creep into a repo-wide ref refactor* → migration of existing refs is explicitly deferred to `avp2`; this PR wires only CTI carriers.

## Implementation Plan

### Scope
**IN:** the `External_Reference` primitive + broad `externalReferences[]` wiring **(Phase 1, shipped — commit `ef74450`)**; an envelope extension (optional lossless `document` + open `kind`) plus `externalReferences[]` on the inline `Status_Override`; an `hdf enrich <results> <source>` pass (Go + TS) that attaches STIX objects to CVE-matched findings (else the results root) as `externalReferences[]` with lossless `document`, **authoring no overrides**; STIX source fingerprint + CLI `hdf enrich` integration; a **CVSS scoring engine** in `hdf-utilities` (Base+Threat compute, Go + TS); the opt-in **`E:A` recompute** in the enrich pass that authors an inline `riskAdjustment` against a CVE-bearing finding with a Base vector; real STIX-bundle + CVSS-spec-vector fixtures; schema regen/propagate + examples + validator tests; docs + CHANGELOG.

**OUT:** a standalone `stix-to-hdf` converter or `hdf-enrichment` document type (deferred — Alternatives H/I); TAXII fetch; `hdf-to-stix` export; migrating the existing ~20 refs onto `External_Reference` (`avp2`); fabricating findings from bare STIX; native rich-CTI schema shapes; CVSS **Environmental** tailoring beyond what the Threat recompute needs (the engine may support it, but STIX drives only Threat/`E`).

### Quality Standards (inherited by every card)
- Dual Go + TS parity, wired into the shared snapshot harness with an output-count ground-truth anchor (the machinery landed on `main`).
- No fabrication; canonical trimmed-UTC timestamps via the shared parse/serialize helpers; `ValidateJSONSize` as the first converter operation.
- **Real fixtures only** — STIX bundles sourced from the OASIS STIX 2.1 example corpus / public CTI, provenance documented; never fabricated.
- `examples` on every new/`$def` touched; schema regen/propagate run in full and committed together.

### Shared Abstractions (built first)
- The `External_Reference` primitive **(shipped in Phase 1)** + its envelope extension (`document`/`kind`) — the schema, the enrich pass, and any future enrichment source depend on it; land the extension before the pass consumes it.
- A STIX-bundle detect/parse helper in `shared/go` + `shared/typescript` — consumed by both the source fingerprint and the enrich pass (no fork).
- The **CVSS scoring engine** in `hdf-utilities` (Go + TS) — extends the existing parse/validate with Base+Threat computation; consumed by the `E:A` recompute, and independently by any future recompute. Built and tested against published CVSS spec vectors before the recompute consumes it.

### Phases
Phase 1 shipped. Phases 1b→2→3 (STIX enrichment) and phase 4 (CVSS engine) are independent; phase 5 depends on 4 and on the 1b carriers.
- **Phase 1 — Schema. [DONE — bead `hdf-libs-ne8q.1`, commit `ef74450`.]** `External_Reference` primitive (open `rel`, `anyOf` id/href/description, `href` `uri-reference`, URN note) + broad `externalReferences[]` wiring (roots + `Evaluated_Requirement`/`Requirement_Core`/`Evaluated_Baseline`/`Standalone_Override`) + full regen/propagate + examples + validator (Go + TS) tests. AC-verified 7/7.
- **Phase 1b — Envelope + inline-override wiring.** Add optional `document` (lossless, `additionalProperties: true`) + open `kind` to `External_Reference`; add `externalReferences[]` to the inline `Status_Override`; regen/propagate + examples + validator tests. *AC:* a ref with an embedded `document` + `kind` validates; a `Status_Override` carrying `externalReferences[]` validates; malformed envelope rejected. *Verify:* `hdf-schema` build+test, validators Go+TS.
- **Phase 2 — `hdf enrich` pass core (Go + TS).** `enrich(results, stixBundle)` → results with STIX objects attached as `externalReferences[]` (CVE-match → the finding; else → results root), each with lossless `document` + `kind: "threat-intel"`; **authors no overrides**; `ValidateJSONSize` first. Snapshot goldens + ground-truth anchor (emitted ref count == matched + unmatched objects). *AC:* real STIX fixture → CVE-matched refs land on the right findings, non-CVE objects on the root; zero overrides authored; raw object preserved losslessly in `document`. *Verify:* Go+TS snapshot + anchor; golangci-lint/eslint/tsc clean.
- **Phase 3 — CLI + source fingerprint.** `hdf enrich <results> <source>` (positional parity with `convert`; `--from stix` optional) + STIX bundle fingerprint (detect `{type:"bundle", objects:[…]}`); auto-detect test. *AC:* `hdf enrich results.json bundle.json` auto-detects STIX and emits a schema-valid enriched results doc. *Verify:* live `hdf enrich … && hdf validate …`.
- **Phase 4 — CVSS scoring engine (`hdf-utilities`, Go + TS).** Add Base+Threat score computation (version-aware 3.1 + 4.0) alongside the existing parse/validate; dual-language parity via shared fixtures. *AC:* computes published CVSS spec test vectors (NVD/FIRST reference vectors) exactly, Go == TS; `E:A` applied to a known Base vector yields the spec's threat score. *Verify:* Go + TS unit tests against spec vectors; parity fixture.
- **Phase 5 — `E:A` recompute in the enrich pass (opt-in).** Depends on 4 and the 1b carriers. For a CVE-matched finding with an exploitation signal **and** a `cvss[].baseVector`: apply `E:A`, recompute via the phase-4 engine, author an inline `riskAdjustment` `Status_Override` with the `cvss` block + `impact.value = computedScore/10.0` + `externalReferences[]` back to STIX; existing resolver surfaces `effectiveImpact`. *AC:* enriching a CVE-bearing results fixture with `--recompute` (or the chosen opt-in surface) yields the spec-correct adjusted impact; a finding with no Base vector is left unchanged (no fabrication); KEV/EPSS never asserted from generic exploitation. *Verify:* Go + TS over a real results+bundle fixture; live `hdf enrich --recompute … && hdf validate …`. *(Decision point: opt-in surface = flag vs. subcommand; required override `expiresAt`/review horizon.)*
- **Phase 6 — Docs + release hygiene.** `site/docs` CTI/STIX guide (incl. the enrichment model, the CVSS `E:A` bridge, and the context-vs-score-change split); CHANGELOG; live verification with a real STIX bundle + a recompute example pasted in notes.

### Verification Strategy
Per phase: schema `pnpm test` + validators (Go+TS); enrich-pass Go+TS snapshot + ground-truth anchor; CVSS engine against published spec vectors with Go==TS parity; recompute over a real results+bundle fixture; live `hdf enrich … && hdf validate …`; `golangci-lint` + `pnpm lint` clean. The AC-verify gate runs before any card closes.

## Future Work (recorded, not scheduled)
- **`hdf-to-stix` vulnerability-posture export** — CVE-bearing findings → STIX `vulnerability` + `sighting` on the assessed system (`infrastructure`/`identity`). Non-fabricating, fits the existing bidirectional-converter pattern. Build only if a consumer materializes.
- **TAXII fetch command** — an `hdf` subcommand to pull a TAXII 2.1 collection and feed `hdf enrich`. Separate PR.
- **Standalone `hdf-enrichment` document type** — a detached, mergeable enrichment file (symmetric with hdf-amendments) for enrichment produced out-of-band and applied later. Deferred (Alternative I); build when a second detached-merge consumer materializes.
- **Additional enrichment sources** — human triage annotations and EPSS/KEV-as-context are natural second consumers of the `External_Reference` envelope (`kind: "annotation"`/`"exploitation"`), validating the generalization beyond STIX.
- **`avp2`** — migrate the existing scattered external references onto `External_Reference`.

## References
- **STIX 2.1** (OASIS) — Common Properties §3.2 (`confidence` is certainty, not severity), Vulnerability §4.19 (no native score; CVE via `external_references`), `external-reference` §2.5 (`source_name` + at-least-one rule).
- **CVSS** (FIRST) — v3.1 and v4.0 specifications: Exploit Maturity / Threat metric group and the score-computation formulas; NVD/FIRST published reference vectors (the scoring-engine test fixtures).
- **OSCAL** (NIST) — `link` (`rel` with `allow-other="yes"`) and `back-matter/resource` (the two-tier model we deliberately do *not* adopt).
- **OCSF** `enrichment` (`provider`/`src_url`/`data`); **ECS** `threat.enrichments` / `*.reference`.
- **RFC 3986** (URI reference, incl. `#fragment`), **RFC 8141** (URN — `urn:<sourceName>:<externalId>`), **RFC 8288** (Web Linking `rel`), **RFC 6838** (media types).
- **Internal:** ADR-0001 (BOM passthrough + partial-fidelity precedent); `hdf-schema/src/schemas/primitives/cvss.schema.json` (Base/Threat/`computedScore`); `primitives/amendments.schema.json` (`Standalone_Override.cvss`, `impact.value ≈ computedScore/10.0`); PR #162 design review.
