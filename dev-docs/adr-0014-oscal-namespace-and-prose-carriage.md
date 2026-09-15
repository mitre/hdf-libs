# ADR-0014: OSCAL extension namespace, prose carriage, and identity

- **Status:** Accepted (owner, 2026-09-14)
- **Date:** 2026-09-14
- **Deciders:** Will Dower (owner ruling 2026-09-04 on §1–§3; identity section §4 and the review decisions below by owner decision 2026-09-14)
- **Revision:** 2026-09-14 (owner review) — §1.1 cites NIST's extension guidance for the namespace pattern and commits to publishing the vocabulary at the namespace URI (`gxeb.13`); §3 scopes carriage to SAR because HDF is a normalization format and gains no OSCAL-specific schema fields, so foreign POA&M props are a stated loss (§3.6); §4.5 replaces the shape-regex control test with roster confirmation through a fixed `nistExists` (`gxeb.12`) and skips findings with an empty target; §4.6 defines the full POA&M field round-trip contract; Alternative H records the rejected schema field. Owner answers to the review's open questions are folded in: foreign SAR baseline names are always uuid-qualified (§4.5); values OSCAL cannot hold are normalized with the exact value in `remarks` (§1.7); pre-ADR documents are read through a one-release fallback (§1.4).
- **Epic/cards:** `hdf-libs-gxeb` — this ADR is `gxeb.1`; implemented by `gxeb.2`–`gxeb.13` and the OSCAL cards moved under the epic. Related cards outside the epic: `hdf-libs-sjo52` (NIST id parser consolidation), `hdf-libs-w5u5r` (NIST catalog data drift).
- **Relates to:** [ADR-0006](adr-0006-stix-cti-integration.md) (the `External_Reference` primitive §4 reuses for foreign POA&M item identity); [ADR-0002](adr-0002-hdf-to-ecs-export.md) (OSCAL keeps finding status and risk response as distinct axes — unchanged here).

## Context

hdf-libs exports HDF to two OSCAL document types — Assessment Results (`hdf-to-oscal-sar`) and Plan of Action and Milestones (`hdf-to-oscal-poam`) — and imports all seven OSCAL types (`oscal-to-hdf`). Both exporters declare `oscal-version` 1.1.2 and are validated against the vendored NIST 1.1.2 and 1.2.3 schemas. Three problems in how they use the OSCAL model are independent of schema validity; one research card (`hdf-libs-qd4m`) and one survey established them:

- **Every prop we invent claims NIST's namespace.** OSCAL qualifies a prop `name` with `ns`, and a prop with no `ns` belongs to the default NIST namespace (`http://csrc.nist.gov/ns/oscal`). The SAR exporter emits 18 prop names of our own (`applicability`, `baseline-version`, `cci`, `check`, `control-type`, `cvss-base-score`, `cvss-base-vector`, `cwe`, `epss-percentile`, `epss-score`, `fix`, `hdf-requirement-id`, `kev`, `kev-due-date`, `nist`, `rationale`, `reference`, `verification-method`). The POA&M exporter emits 13 (`amendment-id`, `baseline-ref`, `captured-by`, `completed-at`, `completed-by`, `component-ref`, `external-id`, `impact-override`, `justification`, `milestone-status`, `mime-type`, `override-type`, `source-name`), plus FedRAMP's `impacted-control-id` and label props whose names come from HDF data. None sets `ns`. Checked against the NIST 1.2.3 metaschema allowed-value vocabularies (metadata, assessment-common, assessment-results, poam, control-common, implementation-common, ssp), none of the 31 names is NIST-defined for props — so each silently asserts NIST semantics NIST never defined, and each can collide with vocabulary NIST adds later. `impacted-control-id` is FedRAMP vocabulary emitted outside FedRAMP's namespace. `qd4m` found every surveyed producer namespaces its extensions (FedRAMP `https://fedramp.gov/ns/oscal`, compliance-trestle per-tool namespaces, Lula `docs.lula.dev/oscal/ns`).
- **Prose rides in props, where nothing reads it.** The SAR exporter carries a requirement's `check` and `rationale` text (and `fix` when no risk is emitted) as finding props whose `value` is a one-line preview and whose `remarks` holds the full text. OSCAL's `StringDatatype` forbids line breaks in a prop value, which forced that shape. `qd4m` found it contradicted by the model ("remarks SHOULD not be used to store arbitrary data"), without precedent in any surveyed producer, and invisible in practice: the only real AR renderer (EasyDynamics oscal-viewer) renders no finding props and drops prop remarks, FedRAMP validation never reads prop remarks, and our own importer reads neither.
- **Identity does not survive conversion.** OSCAL guarantees uniqueness only for `uuid` values, never for `title`. A 2026-09-14 survey of every OSCAL reader and exporter found identifiers built from titles or lossy text (each reproduced through the `hdf` CLI except the SSP defect, which is confirmed from the reader's code). The SAR reader extracts a control id from `target-id` with a shape regex (`^([a-z]{2}-\d+(?:\.\d+)?)`, keeping only the matched prefix) and then cuts every id at its first `_` whether or not the regex matched, so `SV-230221r858734_rule` and `SV-230221r991589_rule` both become `SV-230221` and every `xccdf_org…` id becomes `XCCDF`, merging distinct requirements; it never reads back the `hdf-requirement-id` prop its own exporter writes. SAR baselines are named from result titles, so same-title results collide; two FedRAMP POA&M items (`V-1`, `V-2`) on one control become indistinguishable overrides; SSP components carry only their title and no `componentId`; id-less catalog groups all receive the group id `""`. Round-tripping the seven `Standalone_Override` schema examples through POA&M returns only `requirementId`, `reason`, `expiresAt` and `milestones` intact: `type` comes back as `poam`, `baselineRef` is dropped, `appliedBy` is replaced by the converter's identity, every `appliedAt` collapses to the document's `last-modified`, `notApplicable` comes back `passed`, and `impact`, `justification`, `evidence`, `inheritedFrom` and `affectedPackages` are lost. PR #330 already applied the governing rule once, qualifying component-definition requirement ids as `<component-uuid>/<control>`.

Forces: HDF is a normalization format, so schema fields that serve one source format are a high bar; exporters mint fresh random UUIDs on every conversion (`GenerateUUID` / `crypto.randomUUID`), so OSCAL uuids in HDF-produced documents are not stable across exports; HDF requirement `tags` accept arbitrary keys and 42 of 47 importers already carry native metadata there, while `Standalone_Override` has no extension slot (`unevaluatedProperties: false`); HDF amendments already model external identity through `externalReferences` (ADR-0006); NIST offers no upstream relief — `qd4m` found OSCAL v2 has no active work, and single-line `StringDatatype` is structural; Go and TypeScript implementations must stay at parity.

## Decision

**Namespace every prop HDF invents, move prose to the model's real prose homes, carry foreign SAR props through HDF, and derive identity only from uuids, roster-confirmed control ids, and HDF-namespaced props — never from titles — with a full field round-trip contract for POA&M.**

### §1 The HDF OSCAL extension namespace

1. **The namespace URI is `https://mitre.github.io/hdf-libs/ns/oscal`.** NIST's OSCAL extension tutorial defines `ns` as an RFC 3986 URI "managed by a given organization or individual" and recommends a URI based on a domain the organization controls (its worked example is `http://example.com/ns/oscal`). NIST's own default namespace (`http://csrc.nist.gov/ns/oscal`) and FedRAMP's (`https://fedramp.gov/ns/oscal`) follow the same `<origin>/ns/oscal` shape; it is common rather than universal (Lula uses `docs.lula.dev/oscal/ns`). Ours uses the origin that already publishes the HDF schemas (`https://mitre.github.io/hdf-libs/schemas/…`). The URI is an identifier and never changes, even if the site moves. The docs site publishes the vocabulary at that URI, generated from the §1.5 table (`gxeb.13`).
2. **Scope: every prop HDF invents, in every OSCAL document any hdf-libs exporter emits** — today `hdf-to-oscal-sar` and `hdf-to-oscal-poam`, and any future OSCAL exporter.
3. **Third-party vocabulary keeps its owner's namespace, matched exactly.** A prop or facet defined by NIST keeps NIST's default namespace (e.g. the resource `type` prop with value `evidence`, which the NIST metadata metaschema defines as "the resource represents evidence"). A prop defined by FedRAMP carries `https://fedramp.gov/ns/oscal` (e.g. `impacted-control-id`, `POAM-ID`, as in the FedRAMP POA&M template fixture). Owner URIs are compared byte-for-byte: the SAR exporter's FedRAMP impact facet uses system `https://fedramp.gov`, which matches neither URI the NIST metaschema registers for that facet (`http://fedramp.gov`, `http://fedramp.gov/ns/oscal`), and is corrected to one of those two in `gxeb.3`.
4. **Importers match HDF props by name and namespace**, using the existing `ExtractPropValue(props, name, ns)` / `extractPropValue(props, name, ns)` with a non-empty `ns`, through the `gxeb.3` read helpers. A prop with the right name in another namespace is foreign (§3). **Pre-ADR documents:** for one minor release after the first release that stamps namespaces, the read helpers also accept a prop with no `ns` whose name is a `legacy` row of the §1.5 table, as that row's prop. A legacy-matched prop is consumed where the importer maps it and is never carried (§3). The release notes announce the fallback and the release that removes it; the following minor release removes it.
5. **One vocabulary table, read by both languages.** The table is `hdf-converters/converters/oscal-to-hdf/go/oscal-vocabulary.json`: the Go `oscal` package embeds it (`go:embed` cannot reach a parent directory, and both exporters already import that package), and `hdf-converters/converters/oscal-to-hdf/typescript/vocabulary.ts` imports it (`resolveJsonModule` is on and the package's TypeScript `rootDir` covers the file). It holds the namespace URI and one row per prop with: `name`, `ns`, the OSCAL objects it attaches to, its meaning, its value format, the HDF field it carries, and `legacy` (true exactly for the 32 names pre-ADR exporters emitted without `ns`: the 31 HDF names in the Context inventory plus `impacted-control-id`). Pre-ADR label props are not covered, because their names come from HDF data rather than the table; pre-ADR labels were never read back, so this is no regression. Rows cover every HDF prop in §2–§4.6 and every third-party prop an exporter emits or an importer consumes (`impacted-control-id` with FedRAMP's namespace; the resource `type` prop with NIST's). "Recognised third-party props" in §3.1 means exactly the table's third-party rows. A test in each language asserts that every prop an exporter emits on every fixture and adversarial-corpus input is a row with that row's namespace. The site generator (`gxeb.13`) reads the same file. Two hand-kept copies are not permitted.
6. **Naming rule.** Prop names this ADR adds carry no `hdf-` prefix — the namespace already qualifies them (`baseline-name`, `override-status`, `amendments-name`, `identity-identifier`). `hdf-requirement-id` keeps its shipped name, because renaming it would break the §1.4 fallback and consumers already matching it. Every name is an OSCAL `TokenDatatype`.
7. **Values OSCAL cannot hold.** These rules apply to every HDF prop the exporters emit; the helpers in `gxeb.3` implement them once per language, pinned by a shared case table both languages read (`hdf-converters/shared/oscal-string-cases.json`).
   1. *Normalization.* A prop `value` must be an OSCAL `StringDatatype` (non-empty, no leading or trailing whitespace, no line terminator). The exporter writes the normalized form of the HDF value: replace each maximal run of line terminators (CR, LF, U+2028, U+2029) with one space, then remove leading and trailing whitespace, with whitespace as ECMAScript `\s` defines it (the schema pattern's definition, so Go and TypeScript agree). A whitespace-only value normalizes to `_`.
   2. *Exact value.* When the normalized form differs from the HDF value, the prop's `remarks` holds the exact HDF value. Importers read an HDF prop's `remarks` when present and its `value` otherwise. This applies only to HDF props; a third-party prop's `remarks` belongs to its owner.
   3. *Empty strings.* A required HDF string field that is empty is carried by omitting its prop, and the importer returns it empty (§4.4). An optional HDF string field that is present but empty — including a label key or value — is carried by the prop `empty-field` on the same object, whose value names the HDF field; the importer returns it present and empty.
   4. *OSCAL-required values HDF lacks.* Where OSCAL requires a value that HDF does not have, the exporter writes display fallback text and the prop `absent-field` on the same object, whose value names the HDF field; the importer leaves that field absent and never reads the fallback text as HDF data.

   Single-line OSCAL fields that are not props (titles, `markup-line`) are display text: `gxeb.10` applies rule 1 to them, and every HDF value the §4.6 contract must return exactly has a separate exact home listed there.

### §2 Prose homes (ratified verdicts)

| HDF content | OSCAL home | Verdict |
|---|---|---|
| `fix` description | `risk.remediations[]` with `lifecycle: "recommendation"` and the text as `description` (already emitted) | **KEEP.** Model-exact ("recommended or actual plan for addressing the risk"; lifecycle `recommendation` "such as from an assessor or tool"); the FedRAMP rev5 SAR template states the convention; fully rendered by oscal-viewer; round-trips through our importer. |
| `fix` when no risk is emitted (impact 0) | the related observation's `relevant-evidence[]`, shape as for `check` | **REVISE.** The current preview-prop fallback shares the `check` defects. |
| `code` | back-matter `resource` with `base64` (`media-type: text/plain`), linked from the finding with `rel: "code"`; the resource gains prop `type` = `evidence` (NIST namespace) | **KEEP, refined.** Model-documented mechanism, reaffirmed upstream (OSCAL #2240 withdrawn 2026-06, "Base64 conversion is very reasonable for now"); FedRAMP validates base64-or-rlink evidence resources. `rel="code"` is a permitted locally-defined relation; only `rel="reference"` participates in the back-matter index constraint. |
| `rationale` description | `finding.target.description` (markup-multiline) | **REVISE.** The model's exact home: "the assessor's conclusions regarding the degree to which an objective is satisfied". Also fixes today's incoherence — the importer reads observation descriptions back as rationale while the exporter writes rationale to props. |
| `check` description | the finding's related observation `relevant-evidence[]` entry `{ description: <single-line preview>, remarks: <full text> }` | **REVISE.** Observation evidence is where real documents carry procedure prose, and is surfaced by oscal-viewer and Lula. The model-pure alternative (Activity/Step) is rejected — Alternative D. |

The `check`, `rationale` and `fix` preview props are removed, not namespaced. This is a consumer-visible output change, ratified by the owner on 2026-09-04.

### §3 Foreign-prop carriage through HDF (SAR)

1. **What is carried:** every prop on an OSCAL SAR object that maps to an HDF requirement — `finding`, its related `observation`s and `risk`s — that the importer does not consume into a first-class HDF field. HDF-namespaced props, and legacy-matched props during the §1.4 window, are consumed, never carried. Recognised third-party props (the §1.5 third-party rows) that the importer maps are consumed and also carried, so re-export reproduces them exactly.
2. **Where:** the reserved requirement tag **`oscal-props`**. HDF requirement `tags` accept arbitrary keys and are where 42 of 47 importers already carry native metadata; no converter uses this key today. It is a converter convention, not an HDF schema field (owner decision: HDF is a normalization format and gains no OSCAL-specific schema fields — Alternative H). Its shape is pinned by the JSON Schema `hdf-converters/shared/oscal-props.schema.json`, which both languages' tests validate every emitted tag against.
3. **Shape** — one entry per OSCAL prop, preserving source order:

   ```json
   "oscal-props": [
     { "on": "risk", "name": "priority", "value": "high", "ns": "https://fedramp.gov/ns/oscal" },
     { "on": "finding", "name": "scanner-rule", "value": "R-12", "ns": "https://example.org/ns/oscal", "class": "scanner", "group": "g1", "uuid": "6a5b…", "remarks": "…" }
   ]
   ```

   `on` (required) is the OSCAL object the prop was attached to: `finding`, `observation` or `risk`. `name` and `value` are required and verbatim. `ns`, `class`, `group`, `uuid` and `remarks` are present exactly when the source prop has them. The entry mirrors all seven members of OSCAL's property plus `on`, because carriage that drops a member, or forgets which object held the prop, is not lossless.
4. **Re-emission:** the SAR exporter emits its own props on each object first, then the carried entries for that object in carried order, skipping an entry whose `(ns, name, value)` it has already emitted on that object (an absent `ns` compares equal to the NIST default namespace). Placement:
   - `on: "finding"` entries go on the requirement's finding.
   - `on: "observation"` entries go on the requirement's first observation, including entries that came from several source observations.
   - `on: "risk"` entries go on the one risk the exporter emits for the requirement, including entries that came from several source risks.
   - When the exporter emits no object of that kind for the requirement (for example no risk, because the requirement's impact is 0), those entries are not re-emitted and stay in the HDF tag unchanged.
5. **Convergence contract:** OSCAL → HDF → OSCAL → HDF → OSCAL is stable: the second export equals the first after masking the volatile uuids and timestamps the golden harness already masks.
6. **POA&M: foreign props are not carried — a stated loss.** POA&M import produces HDF amendments, and `Standalone_Override` has no extension slot. The evidence does not justify adding one for OSCAL alone: of the other amendments importers, the three inspected (OpenVEX, CSAF VEX, CycloneDX VEX) use their native statement fields rather than dropping them — OpenVEX and CycloneDX VEX map `justification` to its override field and fold statement and analysis text into `reason`, and CSAF VEX reads its flags, remediations, notes and threats. Foreign POA&M documents therefore lose their own extension props on import. HDF-produced POA&Ms are unaffected: every HDF field round-trips through §4.6. A format-neutral override-level slot remains a possible future change if VEX round-trip fidelity work needs one.

### §4 Identity

1. **No OSCAL reader derives an HDF identifier from a title** — nor from `name`, `description`, `remarks`, prose, or a kebab-cased title. A title may appear in an identifier only as a readable prefix to a uuid that makes it unique (§4.5 SAR baseline names). HDF identifiers here are requirement ids, baseline names, requirement group ids, `componentId`, and the identity and scope of an override.
2. **Permitted sources, in order of precedence:**
   1. an **HDF-namespaced identity prop** (§4.3), whose value is used exactly (§1.7);
   2. a **roster-confirmed control reference** — an OSCAL control-id, objective or statement target, or a namespace-matched third-party control prop such as FedRAMP `impacted-control-id`, used as a NIST control only when the parsed control passes `nistExists` at a supported revision (§4.5);
   3. the **source identifier verbatim** — never truncated, re-cased, or cut at a separator;
   4. an **OSCAL `uuid`** — as `componentId` for OSCAL components, or to qualify an identifier that would otherwise collide, as PR #330 did (`<component-uuid>/<control>`).
3. **HDF-produced OSCAL carries HDF identity in HDF-namespaced props.** `hdf-requirement-id` on SAR `finding`s (already emitted, gains `ns`) and on POA&M `risk`s (new); `baseline-name` on SAR `result`s (new); override identity and scope on POA&M `risk`s per §4.6. Importers read each back into its HDF field; for HDF-produced documents these props take precedence over every other source. OSCAL `uuid`s in HDF-produced documents are never read back as HDF identity, because exporters regenerate them on every conversion. A POA&M risk is HDF-produced when it carries `override-type` in the HDF namespace (or, during the §1.4 window, without `ns`); `type` is required on every override, so every HDF-produced risk carries it.
4. **Absence is carried as absence.** An HDF value that is empty or absent is represented by omitting its HDF prop (or by `empty-field`, §1.7.3), and the importer returns it empty or absent. No importer substitutes a placeholder title (the POA&M `"Unidentified requirement"` title is display text only), the literal `unknown`, a POA&M tracking number, a generated sentence, or a uuid. Where OSCAL requires display text that HDF lacks, the exporter follows §1.7.4. An identity value that is not a valid `StringDatatype` follows §1.7.1–§1.7.2.
5. **Foreign documents keep object identity without inventing requirement ids.**
   - *SAR requirement ids:* a requirement id comes from `hdf-requirement-id`; else, when the finding's target parses under OSCAL control-id grammar (`<control>[.<enhancement>][_obj…|_smt…]`) to a control that `nistExists` confirms at a supported revision, from that NIST control (objectives and statements group under it, as today); else from the target-id verbatim. Distinct unconfirmed target ids never merge. A finding whose `target-id` is empty is invalid OSCAL and is skipped with a warning naming the finding; no requirement is named `unknown`. `nistExists` is fixed to accept every common NIST spelling and gains a Go peer (`gxeb.12`); the shape regex is no longer the test.
   - *SAR baseline names:* a baseline name comes from the result's `baseline-name`; else it is `<kebab-title>--<result-uuid>`, where `<kebab-title>` is the result title kebab-cased as today, and it is the bare result uuid when that kebab-cased title is empty. Foreign result uuids are fixed in the source document, so the name is stable across imports; SARs exported before this ADR carry no `baseline-name` and take the same form.
   - *POA&M:* an override's `requirementId` comes from `hdf-requirement-id`, else FedRAMP `impacted-control-id` (namespace-matched, roster-confirmed), else it is empty. `POAM-ID` is a tracking number, never a `requirementId`. Each override records the item it came from in its existing `externalReferences` (ADR-0006) as `{ "sourceName": "x-oscal-poam-item", "href": "#<poam-item-uuid>", "externalId": "<POAM-ID>" }`, with `externalId` present only when the item has a `POAM-ID`. No schema change. Risks that are not HDF-produced (§4.3) keep today's status mapping.
   - *SSP:* every HDF component gets `componentId` = the OSCAL component `uuid`.
   - *Catalog/profile:* an id-less group gets no identifier derived from its title; its representation is decided on `gxeb.11`.
6. **POA&M field round-trip contract.** HDF amendments → OSCAL POA&M → HDF returns every field below exactly. Every OSCAL home listed was checked against the OSCAL 1.2.3 POA&M schema. "Today" is the measured behaviour before this ADR. Props named here carry the HDF namespace unless stated; every prop value follows §1.7; numbers are formatted by the shared exporter number rule (`exportmap.FloatToken` and its TypeScript peer, pinned by `hdf-converters/shared/export-number-cases.json`). The pre-ADR props `completed-by` and `captured-by` are no longer emitted: task `responsible-roles` and observation `origins` replace them.

   **Override fields**

   | HDF field | OSCAL home | Today |
   |---|---|---|
   | `requirementId` | risk prop `hdf-requirement-id`, omitted when empty (§4.4); plus FedRAMP-namespace `impacted-control-id` (lowercase control form) only when the id is a roster-confirmed NIST control | exact only when control-shaped; otherwise case-folded |
   | `type` | risk prop `override-type` | lost (read back as `poam`) |
   | `status` | risk `status`: `closed` for `passed` and `notApplicable`, otherwise `open`, and `open` when `status` is absent; plus risk prop `override-status` (exact) only when `status` is present | `notApplicable` → `passed` |
   | `impact` | risk prop `impact-override` | lost |
   | `reason` | poam-item `description` | exact |
   | `justification` | risk prop `justification` | lost |
   | `baselineRef` | risk prop `baseline-ref` | lost |
   | `componentRef` | risk prop `component-ref` | lost |
   | `inheritedFrom` | risk prop `inherited-from` | not exported |
   | `appliedAt` | risk `risk-log.entries[]` entry `title: "Override applied"`, `start` | collapses to `metadata.last-modified` |
   | `appliedBy` | that entry's `logged-by[].party-uuid` → metadata `party` (Identity below) | replaced by the converter's identity |
   | `expiresAt` | risk `deadline` (plus the existing "Scheduled review" risk-log entry) | exact |
   | `milestones[]` | one risk `remediations[]` entry per milestone (`lifecycle: "planned"`) with one `tasks[]` entry: `description` → remediation `description` (exact; remediation and task `title` are display text); `estimatedCompletion` → task `timing.within-date-range` `start` and `end`; `status` → task prop `milestone-status`; `completedAt` → task prop `completed-at`; `completedBy` → task `responsible-roles[]` entry (`role-id: "completed-by"`, defined in metadata `roles`) whose `party-uuids` name the party | exact for the measured example; `completedBy` carries identifier only |
   | `evidence[]` | one `observation` per item, listed in the poam-item's `related-observations` (rows below) | exported, not read back |
   | `cvss` | one risk `characterizations[]` entry whose `facets[]` all use `system` = `http://www.first.org/cvss/v<version>`, one facet per present `Cvss` field, named as emitted today: `cvss_version`, `source`, `base_vector`, `base_score`, `base_severity`, `threat_vector`, `threat_score`, `environmental_vector`, `environmental_score`, `supplemental_vector`, `computed_score`, `computed_severity`; scores use the shared number rule, strings and severities are verbatim (§1.7 applies to facet values as to props) | exported, not read back |
   | `externalReferences[]` | one back-matter `resource` per reference, attached to its override by a risk `links[]` entry `rel: "reference"`, `href: "#<resource-uuid>"` (rows below) | exported but unattached; lost |
   | `affectedPackages[]` | risk props `affected-package-name`, `affected-package-version`, `affected-package-ecosystem`, `affected-package-cpe`, `affected-package-purl`, `affected-package-fixed-in-version`; every prop of one package carries `group: "package-<n>"`, where `n` is the package's 1-based position in source order | not exported |
   | `signature`, `previousChecksum` | **excluded** — a signature covers the original HDF bytes and the checksum chain covers document order, neither of which survives a format change; the importer re-chains overrides (`ChainOverrides` already runs on import) and does not carry signatures | — |

   **Evidence fields** (on the evidence item's `observation`)

   | HDF field | OSCAL home |
   |---|---|
   | `type` | observation `types[]` (single entry) |
   | `data` | when `type` is `url`, or `type` is `screenshot` or `file` and `data` is an absolute URI (RFC 3986, with a scheme): `relevant-evidence[0].href` = `data`. Otherwise: a back-matter `resource` whose `base64.value` is `data` when `encoding` is exactly `base64` and the base64 encoding of `data`'s UTF-8 bytes otherwise, with `base64.media-type` = `mimeType` when present, linked from the observation by `links[]` entry `rel: "evidence"`, `href: "#<resource-uuid>"`. The importer reads `relevant-evidence[0].href` when present and the linked resource otherwise, decoding unless `encoding` is `base64`. |
   | `description` | observation `description` (exact); when absent, the fallback text `Supporting evidence` plus `absent-field` = `description` |
   | `mimeType` | observation prop `mime-type` |
   | `encoding` | observation prop `evidence-encoding` |
   | `size` | observation prop `evidence-size` |
   | `capturedAt` | observation `collected`; when absent, the override's `appliedAt` plus `absent-field` = `capturedAt` |
   | `capturedBy` | observation `origins[].actors[]` entry (`type: "party"`, `actor-uuid`) naming the party |
   | — | observation `methods` is `["EXAMINE"]` and `relevant-evidence[0].description` is display text; neither is read back |

   **External reference fields** (on the reference's back-matter `resource`)

   | HDF field | OSCAL home |
   |---|---|
   | `sourceName` | resource prop `source-name` |
   | `externalId` | resource prop `external-id` |
   | `href` | resource `rlinks[0].href` |
   | `description` | resource `description` (exact) |
   | `rel` | resource prop `reference-rel` |
   | `mediaType` | resource prop `reference-media-type` |
   | `checksum` | resource props `checksum-algorithm` and `checksum-value` |
   | `addedBy` | resource prop `added-by` whose value is the uuid of the metadata party (Identity below) |
   | `addedAt` | resource prop `added-at` |
   | `kind` | resource prop `reference-kind` |
   | `document` | resource `base64` (`media-type: application/json`, `value` = the base64 encoding of the object serialized as JSON with object keys sorted) |

   Resource `title` stays display text, as today.

   **Identity** (override `appliedBy`, milestone `completedBy`, evidence `capturedBy`, reference `addedBy`, document `appliedBy` and `approvedBy`): one metadata `party` per distinct (`identifier`, `type`, `description`) triple, carrying props `identity-identifier` and `identity-type`, with `description` in the party `remarks` (exact). Party `name` and `type` stay display text.

   **Document fields**

   | HDF field | OSCAL home | Today |
   |---|---|---|
   | `name` | metadata `title` (display) plus metadata prop `amendments-name` (exact) | kebab-cased from the title |
   | `amendmentId` | metadata prop `amendment-id` | not read back |
   | `description` | metadata `remarks` (exact) | not read back |
   | `systemRef` | `import-ssp.href`; when absent, `#` (OSCAL requires `import-ssp`) plus metadata prop `absent-field` = `systemRef` | an absent `systemRef` comes back as `#` |
   | `appliedBy` | `responsible-parties` `prepared-by` → party | comes back with the party's uuid as its identifier and type `simple` |
   | `approvedBy` | `responsible-parties` `approved-by` → party | not read back |
   | `labels` | per label, metadata props `label-key` and `label-value`, both with `class: "amendment-label"` and `group: "label-<n>"`, where `n` is the label's 1-based position in sorted key order; an empty key or value follows §1.7.3. This replaces the pre-ADR one-prop-per-label encoding. | not read back |
   | `version` | metadata `version` | read back |
   | `integrity`, `signature`, `generator` | **excluded** — integrity is recomputed on import, signatures do not survive a format change, and the importer stamps its own generator | — |

## Alternatives Considered

### Alternative A: Keep the interim prop mapping (status quo)
`check`, `rationale` and the `fix` fallback stay as finding props with a preview `value` and full-text `remarks`; props stay un-namespaced.
- **Pros:** no output change; already schema-valid on 1.1.2 and 1.2.3.
- **Cons:** model-contradicted ("remarks SHOULD not be used to store arbitrary data"; props are documented for sort and filter tokens); no producer precedent at full-text scale; unrendered by the only AR viewer and unread by FedRAMP validation and by our own importer; un-namespaced names claim NIST semantics.
- **Why rejected:** the `qd4m` research refuted it on each axis with citations; the owner ruled to revise on 2026-09-04.

### Alternative B: Namespace per exporter or per document type
e.g. `…/ns/oscal/sar` and `…/ns/oscal/poam`.
- **Pros:** narrower vocabularies.
- **Cons:** the same props cross document types (`hdf-requirement-id` on SAR findings and POA&M risks), so one meaning would carry two namespaces and importers would match both.
- **Why rejected:** one HDF vocabulary, one namespace, one table (§1.5).

### Alternative C: Register vocabulary in NIST's default namespace upstream
Propose our prop names to NIST so they are legitimately un-namespaced.
- **Pros:** first-class names.
- **Cons:** most names are HDF-specific; `qd4m` found no active OSCAL model work to receive them.
- **Why rejected:** NIST's extension guidance directs organizations to define their own names in their own namespace; every surveyed producer does.

### Alternative D: Carry `check` text in an Activity/Step (`local-definitions`)
The model-pure home for "an assessment test or examination procedure".
- **Pros:** exact semantics.
- **Cons:** considerably heavier structure; no consumer renders it; per-requirement activities multiply document size.
- **Why rejected:** observation `relevant-evidence` is where real documents carry procedure prose and what real viewers show (§2).

### Alternative E: Identity from uuid-qualified titles in HDF-produced documents
Title POA&M items and name results `<uuid>/<control>`, as PR #330 did for imported component definitions.
- **Pros:** uses OSCAL's one guaranteed-unique value; titles become distinct.
- **Cons:** exporter uuids are regenerated on every conversion, so titles would change on every export; a uuid-qualified requirement id no longer matches the results requirement an amendment targets, which breaks `hdf amend apply`; the original HDF identifier is still not carried, so a round trip still cannot recover it.
- **Why rejected:** uuid qualification is right for *imported* objects with no other identity (§4.2.4, §4.5) — the #330 case — and wrong for carrying HDF identity out and back, which needs the exact value in a prop (§4.3).

### Alternative F: Carry foreign props in document-level `passthrough`
Store the source document's props wholesale at HDF document level.
- **Pros:** trivially lossless for the document.
- **Cons:** loses which requirement and which OSCAL object each prop belonged to, so re-export cannot place props; conflates with the attribution work on `passthrough` (`hdf-libs-3ysxe`).
- **Why rejected:** carriage must be object-local to re-emit correctly (§3.3–§3.4).

### Alternative G: Keep the shape regex as the NIST-control test
Treat any target whose prefix matches `^[a-z]{2}-\d+` as a NIST control, as the SAR reader does today.
- **Pros:** no data dependency; current output unchanged.
- **Cons:** any two-letters-dash-digits token is misread as a NIST control — the STIG id `sv-230221r858734_rule` becomes `SV-230221` — and distinct requirements merge silently.
- **Why rejected:** roster confirmation against NIST catalog data answers the actual question; the regex answers a different one (§4.5).

### Alternative H: A typed HDF schema field for carried OSCAL props
Add a carried-property array to requirements and to `Standalone_Override`, validated by the HDF schema.
- **Pros:** schema validation and documentation of the carriage shape; a home for foreign POA&M props.
- **Cons:** an HDF normalization-format field that serves one source format; requirements already have a general slot (`tags`, used by 42 of 47 importers); the inspected VEX amendments importers already use their native statement fields, so an override slot would mainly keep that structure separate rather than recover lost data; a schema change sets the release tier.
- **Why rejected:** owner decision 2026-09-14 — OSCAL, though critical, does not warrant format-specific schema fields; SAR carriage uses `tags` with a converter-side JSON Schema, and foreign POA&M props are a stated loss (§3.6).

### Alternative I: Do nothing
- **Pros:** zero work, zero output churn.
- **Cons:** invented props keep claiming NIST semantics and risk collision; prose stays invisible to every real consumer; foreign props are silently dropped on import; identity keeps collapsing on every round trip, merging distinct requirements and baselines and pairing them wrongly in hdf-diff; `hdf amend apply` keeps applying unscoped overrides to every baseline.
- **Why rejected:** the survey found identity-losing defects in the POA&M, SAR, SSP and catalog (and therefore profile) import paths and in both HDF → OSCAL → HDF round trips; they are correctness bugs, not style.

## Consequences

**What becomes easier:**
- Consumers can tell HDF vocabulary from NIST and FedRAMP vocabulary by `ns`, look up our props on the published vocabulary page, and filter or ignore them.
- HDF → POA&M → HDF returns every amendments field in §4.6 exactly, apart from the stated integrity exclusions; HDF → SAR → HDF returns requirement ids and baseline names exactly; hdf-diff and `hdf amend apply` keep working on round-tripped documents.
- Foreign SAR documents survive a trip through HDF with their extension props, so HDF can sit in an OSCAL assessment pipeline without stripping third-party extensions.
- Prose lands where the only real AR viewer and FedRAMP reviewers look.
- New exporters and importers get one rule set and one vocabulary table instead of rediscovering conventions.

**What becomes harder:**
- Output changes for every consumer: props gain `ns`, three preview props disappear, `impacted-control-id` moves to FedRAMP's namespace and is emitted only for roster-confirmed controls, the `completed-by` and `captured-by` props give way to roles and origins, labels become key/value prop pairs, POA&M documents gain risk-log entries, parties with identity props, observation props and attached references, SSP components gain `componentId`, and imported SAR baseline names gain a uuid suffix and some requirement ids change. Goldens regenerate deliberately.
- The SAR importer must track which OSCAL object each carried prop came from and dedupe on re-emission (§3.4).
- The vocabulary table is a maintained contract; adding an HDF prop means adding a row, which also updates the published page.
- Grouping SAR findings under NIST controls now depends on NIST catalog data currency.

**Risks:**
- *A consumer matches our props by name only and relied on them sitting in the default namespace.* Mitigation: existing names do not change, only `ns` is added; release-note the change and publish every prop and namespace on the vocabulary page.
- *Documents exported before this ADR carry HDF props without `ns`.* Mitigation: the one-release fallback (§1.4), release-noted with its removal release.
- *During the fallback window, a foreign SAR prop with no `ns` whose name is a legacy row is read as ours instead of carried.* Mitigation: the window is one minor release and limited to the 32 legacy names; after it, such a prop is carried (§3.1).
- *Carried props grow requirement tags.* Mitigation: carriage is bounded by the source document; no new data is invented.
- *Stale NIST catalog data fails to confirm a genuine control.* The Rev 5 crosswalk roster predates controls such as `IA-13`, `SA-24` and `SI-2(7)` that the Rev 5 description table already contains; `nistExists` consults the description table. Mitigation: confirmation uses the more current table, and reconciling the two is tracked on `hdf-libs-w5u5r`. An unconfirmed genuine control keeps its verbatim id rather than merging with anything.
- *Fixing `nistExists` changes a published function's answers.* Mitigation: every input that returns true today still does; only previously unrecognised spellings change, and the change is release-noted (`gxeb.12`).
- *Foreign POA&M extension props are lost on import.* Mitigation: stated in the importer and in release notes (§3.6); HDF-produced POA&Ms are unaffected.

## Implementation Plan

### Quality Standards (inherited by every card)
- **Parity:** every change lands in Go and TypeScript together; cross-language parity is asserted on contents through the existing golden normalization, not bytes.
- **Single vocabulary:** the §1.5 table is the only place an HDF prop name or the namespace URI is spelled; exporters, importers, tests and the vocabulary page read it.
- **Shared rules, shared cases:** §1.7 normalization and the §4.6 round trip are asserted from shared case tables both languages read, never two hand-kept copies.
- **Schema gates:** every exporter change validates against the vendored OSCAL 1.1.2 and 1.2.3 schemas, including the adversarial corpus.
- **Round-trip tests assert fields, not counts:** every §4.6 field, requirement id and baseline name is compared exactly after masking volatile uuids and timestamps.
- **TDD and fixtures:** failing test first; real or schema-validated fixtures only; >90% coverage on changed code.

### Shared Abstractions (built before consumers)

| Shared need | Used by | Card |
|---|---|---|
| Vocabulary table + per-language emit/read helpers implementing §1.4 (namespace match, legacy fallback) and §1.7 (normalization, exact `remarks`, `empty-field`, `absent-field`) | every exporter and importer card; the vocabulary page | `gxeb.3` |
| `oscal-props` JSON Schema + carriage read/write helpers | SAR importer and exporter | `gxeb.4` |
| `nistExists` accepting every common NIST spelling, with a Go peer | POA&M exporter (`gxeb.5`), SAR (`gxeb.6`) and foreign POA&M (`gxeb.7`) roster confirmation | `gxeb.12` |

### Scope
**IN scope:** namespace stamping on both exporters and the published vocabulary page; SAR prose relocation; foreign-prop carriage for SAR requirement-mapped objects; the full POA&M field contract (§4.6); SAR identity read-back, roster-confirmed control grouping and baseline naming; foreign POA&M item identity; SSP `componentId`; the no-title-identifier rule across all OSCAL importers; the `nistExists` fix.

**OUT of scope:** HDF schema changes (none — Alternative H); carrying foreign props on POA&M documents (§3.6) and on non-requirement SAR objects; changing the declared `oscal-version`; consolidating the repo's NIST id parsers onto one normalizer (`hdf-libs-sjo52`); reconciling NIST description tables with crosswalk rosters (`hdf-libs-w5u5r`); converter input-size plumbing (`pr:input-limits`).

### Phases

Unless a phase names another, the converter verification command is:
`cd hdf-converters && go test ./converters/oscal-to-hdf/... ./converters/hdf-to-oscal-sar/... ./converters/hdf-to-oscal-poam/... && ../node_modules/.bin/vitest run converters/oscal-to-hdf converters/hdf-to-oscal-sar converters/hdf-to-oscal-poam && ../node_modules/.bin/tsc --noEmit -p tsconfig.json && golangci-lint run ./converters/oscal-to-hdf/... ./converters/hdf-to-oscal-sar/... ./converters/hdf-to-oscal-poam/...`

#### Phase 1: Decision (unblocked — start here)
**Card:** `gxeb.1`.
**Files:** Create `dev-docs/adr-0014-oscal-namespace-and-prose-carriage.md`.
**Acceptance criteria:**
- [ ] Every decision the later phases need is made in the ADR, with no open questions; every OSCAL home in §4.6 is named exactly.
- [ ] ADR accepted by the owner, including §1.4, §1.7, §3.6, §4.5 and §4.6.
**Verification:** owner review; `grep -c '^## ' dev-docs/adr-0014-oscal-namespace-and-prose-carriage.md` prints 6.

#### Phase 2: Prose relocation (blocked by Phase 1)
**Card:** `gxeb.2`.
**Files:** Modify `hdf-converters/converters/hdf-to-oscal-sar/go/converter.go`, `hdf-converters/converters/hdf-to-oscal-sar/typescript/converter.ts`, `hdf-converters/converters/oscal-to-hdf/go/converter_sar.go`, `hdf-converters/converters/oscal-to-hdf/typescript/converter-sar.ts`, SAR goldens under `hdf-converters/converters/hdf-to-oscal-sar/fixtures/expected/`. Test: `hdf-converters/converters/hdf-to-oscal-sar/go/converter_test.go`, `hdf-converters/converters/hdf-to-oscal-sar/typescript/converter.test.ts`, the `oscal-to-hdf` SAR tests.
**Acceptance criteria:**
- [ ] `rationale`, `check`, `fix` and `code` land in the §2 homes; the three preview props are gone.
- [ ] The importer reads rationale from `finding.target.description`.
**Verification:** the converter command above.

#### Phase 3: Namespace, vocabulary and publication (blocked by Phase 1; after Phase 2 so removed props are not stamped)
**Cards:** `gxeb.3`, then `gxeb.13`.
**Files (`gxeb.3`):** Create `hdf-converters/converters/oscal-to-hdf/go/oscal-vocabulary.json`, `hdf-converters/converters/oscal-to-hdf/go/vocabulary.go` and `vocabulary_test.go`, `hdf-converters/converters/oscal-to-hdf/typescript/vocabulary.ts` and `vocabulary.test.ts`, `hdf-converters/shared/oscal-string-cases.json`. Modify both exporters (`hdf-converters/converters/hdf-to-oscal-{sar,poam}/go/converter.go`, `…/typescript/converter.ts`) and their goldens.
**Files (`gxeb.13`):** Create `site/generate-oscal-vocabulary.mjs` (writes `site/ns/oscal.md`, served at `/hdf-libs/ns/oscal`) and `site/test/generate-oscal-vocabulary.test.mjs`. Modify `site/package.json` (`generate` runs the new generator) and `.gitignore` (`site/ns/`, as for the other generated pages).
**Acceptance criteria:**
- [ ] The table has the §1.5 columns and rows; every emitted prop on every fixture and adversarial-corpus input is a row with that row's namespace, enforced by a test in each language.
- [ ] The read helpers match name and namespace, apply the §1.4 legacy fallback only to `legacy` rows, and prefer `remarks` (§1.7.2); the emit helpers implement §1.7.1–§1.7.4; both pass every row of `oscal-string-cases.json` in Go and TypeScript.
- [ ] `impacted-control-id` carries `https://fedramp.gov/ns/oscal`; the FedRAMP impact facet system is one of the two URIs the NIST metaschema registers.
- [ ] The page at the namespace path is generated from the table and a test fails when they disagree.
**Verification:** the converter command above; `cd site && pnpm generate && pnpm test:ts`.

#### Phase 4: SAR carriage (blocked by Phases 2 and 3)
**Card:** `gxeb.4`.
**Files:** Create `hdf-converters/shared/oscal-props.schema.json` and the carriage helpers beside the vocabulary helpers (`hdf-converters/converters/oscal-to-hdf/go/carriage.go`, `hdf-converters/converters/oscal-to-hdf/typescript/carriage.ts`, with tests). Modify `hdf-converters/converters/oscal-to-hdf/go/converter_sar.go`, `hdf-converters/converters/oscal-to-hdf/typescript/converter-sar.ts`, `hdf-converters/converters/hdf-to-oscal-sar/go/converter.go`, `hdf-converters/converters/hdf-to-oscal-sar/typescript/converter.ts`. Test: a convergence fixture derived from `hdf-converters/converters/oscal-to-hdf/fixtures/input/sar-fedramp.json`.
**Acceptance criteria:**
- [ ] `oscal-props` matches §3.3 exactly and validates against the JSON Schema in both languages.
- [ ] Re-emission follows every §3.4 placement rule, each with its own test.
- [ ] The §3.5 convergence test passes.
**Verification:** the converter command above.

#### Phase 5: Identity and round trips (blocked by Phase 3; `gxeb.5`, `gxeb.6` and `gxeb.7` also by `gxeb.12`)
**Cards and files:**
- `gxeb.12` — Create `hdf-mappings/src/nist/normalize.ts`, `hdf-mappings/go/nist/exists.go`, `hdf-mappings/go/nist/exists_test.go`, and the shared case table `hdf-mappings/go/nist/testdata/nist-id-spelling-cases.json`. Move the canonical NIST description tables from `hdf-mappings/src/data/` to `hdf-mappings/go/nist/`, where the Go peer embeds them and TypeScript imports them (the `hdf-mappings/go/checkov/` precedent — no second copy). Modify `hdf-mappings/src/nist/index.ts`, `hdf-mappings/src/index.ts`, and `hdf-mappings/scripts/generate-nist-descriptions.mjs` (writes the moved tables, still guarded by `mappings:descriptions:check`). Test: `hdf-mappings/test/nist.test.ts`. Verification: `cd hdf-mappings && pnpm test && go test ./go/nist/... && pnpm type-check && pnpm mappings:descriptions:check`.
- `gxeb.5` — Modify `hdf-converters/converters/hdf-to-oscal-poam/go/converter.go`, `hdf-converters/converters/hdf-to-oscal-poam/typescript/converter.ts`, `hdf-converters/converters/oscal-to-hdf/go/converter_poam.go`, `hdf-converters/converters/oscal-to-hdf/typescript/converter-poam.ts`, POA&M goldens. Create the shared round-trip case table `hdf-converters/shared/oscal-poam-roundtrip-cases.json`. Test: `hdf-converters/converters/hdf-to-oscal-poam/go/converter_test.go`, `hdf-converters/converters/hdf-to-oscal-poam/typescript/converter.test.ts`, `hdf-converters/converters/oscal-to-hdf/go/converter_poam_test.go`. (`oscal-to-hdf` TypeScript tests for every document type live in `hdf-converters/converters/oscal-to-hdf/typescript/converter.test.ts`; "TypeScript peer" below means that file.)
- `gxeb.6` — Modify `hdf-converters/converters/oscal-to-hdf/go/converter_sar.go`, `hdf-converters/converters/oscal-to-hdf/go/shared.go`, `hdf-converters/converters/oscal-to-hdf/typescript/converter-sar.ts`, `hdf-converters/converters/oscal-to-hdf/typescript/shared.ts`. Test: `hdf-converters/converters/oscal-to-hdf/go/converter_sar_test.go`, `hdf-converters/converters/hdf-to-oscal-sar/go/converter_test.go` and their TypeScript peers.
- `gxeb.8` — Modify the same SAR importer files plus `hdf-converters/converters/hdf-to-oscal-sar/go/converter.go` and `hdf-converters/converters/hdf-to-oscal-sar/typescript/converter.ts` (emit `baseline-name`). Test: as `gxeb.6`.
- `gxeb.7` (after `gxeb.5`) — Modify `hdf-converters/converters/oscal-to-hdf/go/converter_poam.go`, `hdf-converters/converters/oscal-to-hdf/typescript/converter-poam.ts`. Test: `hdf-converters/converters/oscal-to-hdf/go/converter_poam_test.go` and its TypeScript peer; `poam-fedramp.json` goldens.
- `gxeb.9` — Modify `hdf-converters/converters/oscal-to-hdf/go/converter_ssp.go`, `hdf-converters/converters/oscal-to-hdf/typescript/converter-ssp.ts`. Test: `hdf-converters/converters/oscal-to-hdf/go/converter_ssp_test.go` and its TypeScript peer.
- `gxeb.11` — Modify `hdf-converters/converters/oscal-to-hdf/go/converter_catalog.go`, `hdf-converters/converters/oscal-to-hdf/typescript/converter-catalog.ts`. Test: `hdf-converters/converters/oscal-to-hdf/go/converter_catalog_test.go`, `converter_profile_test.go` and their TypeScript peers.

**Acceptance criteria:**
- [ ] `gxeb.12`: `nistExists` returns true for every spelling in the shared case table at each supported revision, and every input that returns true today still does, in Go and TypeScript.
- [ ] `gxeb.5`: HDF → POA&M → HDF returns every §4.6 field exactly over the seven `Standalone_Override` schema examples plus the edge cases in Verification Strategy; the exclusions are the only differences.
- [ ] `gxeb.6`: HDF → SAR → HDF returns every requirement id exactly; foreign targets group only under roster-confirmed controls; empty targets are skipped with a warning.
- [ ] `gxeb.8`: HDF → SAR → HDF returns every baseline name exactly; foreign results are named per §4.5.
- [ ] `gxeb.7`: distinct FedRAMP POA&M items stay distinct overrides carrying their `x-oscal-poam-item` reference; `POAM-ID` is never a `requirementId`.
- [ ] `gxeb.9`: every imported SSP component's `componentId` is its OSCAL uuid.
- [ ] `gxeb.11`: no id-less group receives an identifier derived from its title, and no two groups share an empty id.
- [ ] No importer derives an identifier from a title or treats a shape-regex match as a NIST control.
**Verification:** the converter command above for the converter cards; the `gxeb.12` command above.

#### Phase 6: Conformance and harness (independent of Phases 2–5 unless noted)
**Cards and files:**
- `gxeb.10` (after `gxeb.3`, whose §1.7.1 helper it reuses) — Modify both exporters' Go and TypeScript converters. Test: `hdf-converters/converters/hdf-to-oscal-{sar,poam}/go/schema_validation_test.go` and `…/typescript/schema-validation.test.ts`.
- `hdf-libs-o0qu` — Modify `hdf-converters/converters/hdf-to-oscal-sar/typescript/converter.ts`, `…/typescript/schema-validation.test.ts`, `…/go/schema_validation_test.go`.
- `hdf-libs-mw2l` — Create realistic-prose inputs under `hdf-converters/converters/{hdf-to-oscal-poam,hdf-to-cyclonedx-vex,hdf-to-openvex,hdf-to-csaf-vex,hdf-to-xccdf}/fixtures/input/`; Modify those converters' schema-validation tests.
- `hdf-libs-gjll8` — Modify `hdf-schema/src/schemas/primitives/amendments.schema.json` (`requirementId` `minLength: 1`) and regenerate build outputs. After it lands an empty `requirementId` is invalid HDF; §4.4 still governs documents that carry one.
- `hdf-libs-xtgg` — Modify `hdf-converters/registry/convert/registry.go`, `hdf-converters/registry/convert/converter_oscal.go`. Test: `hdf-converters/registry/all/all_test.go`.
- `hdf-libs-3ysxe` — Modify `hdf-converters/shared/go/hdfversion/hdf_version.go`, `hdf-converters/converters/hdf-to-oscal-sar/go/converter.go`, `hdf-converters/converters/oscal-to-hdf/go/converter_sar.go`, with their tests.

**Acceptance criteria:**
- [ ] `gxeb.10`: no exporter writes a line terminator into a single-line OSCAL field; the 1.2.3 schema gate passes on inputs with multi-line titles.
- [ ] `hdf-libs-o0qu`: the SAR metadata literal is typed and both languages use the shared schema-validation harness.
- [ ] `hdf-libs-mw2l`: each listed exporter validates realistic-prose fixtures in the languages it ships, with schema provenance recorded.
- [ ] `hdf-libs-gjll8`: the amendments schema rejects an empty `requirementId` in `hdf-schema` and `hdf-validators` tests.
- [ ] `hdf-libs-xtgg`: every auto-detected OSCAL format name resolves to a registered converter, guarded by a registry test.
- [ ] `hdf-libs-3ysxe`: `target`, `passthrough` and `components` survive HDF → SAR → HDF.
**Verification:** the converter command above for `gxeb.10`, `o0qu` and `3ysxe`; each other card's own command (`hdf-libs-mw2l`: its converters' `go test` and `vitest run`; `hdf-libs-gjll8`: `cd hdf-schema && pnpm test`, then `cd hdf-validators && go test ./... && pnpm test:ts`; `hdf-libs-xtgg`: `cd hdf-converters && go test ./registry/... ./converters/oscal-to-hdf/...`, then `cd hdf-cli && go test ./cmd/hdf/cmd/`).

### Verification Strategy
- **Schema:** both exporters validate on OSCAL 1.1.2 and 1.2.3 for fixtures and the adversarial corpus.
- **Round trip:** HDF → POA&M → HDF over the seven `Standalone_Override` schema examples plus identity edge cases asserts every §4.6 field; HDF → SAR → HDF asserts requirement ids and baseline names; OSCAL → HDF → OSCAL convergence for carried SAR props (§3.5).
- **Vocabulary guard:** a test fails if an exporter emits a prop not in the table or with the wrong namespace, and if the published page disagrees with the table.
- **Real documents:** FedRAMP-shaped fixtures (`poam-fedramp.json`, `sar-fedramp.json`) import with identity preserved; the SAR fixture's props are carried.
- **Edge cases:** empty and whitespace-only identifiers (§4.4, §1.7); values with line breaks and leading or trailing whitespace (§1.7); present-but-empty optional strings and label keys and values (§1.7.3); evidence with no `description` or `capturedAt`, with `encoding: "base64"`, and with URI and non-URI `data` for each evidence `type` (§4.6); overrides with no status; empty `target-id`; same-title results and components; distinct ids sharing a control-like prefix (`sv-…`, `xccdf_…`); props with every optional member set; absent `systemRef`; a pre-ADR SAR and POA&M read through the §1.4 fallback.

## References
- NIST, "Extending OSCAL Models with Props and Links" (pages.nist.gov/OSCAL, learn/tutorials/general/extension) — namespace definition, default namespace, organization-controlled URIs.
- `hdf-libs-qd4m` research findings (2026-09-03): NIST OSCAL model reference quotes; producers surveyed (compliance-trestle, FedRAMP rev5 SAR template and extensions registry, usnistgov/oscal-content, oscal-compass/compliance-to-policy, Lula); consumers surveyed (EasyDynamics oscal-react-library and oscal-viewer, trestle, FedRAMP Schematron SAR rules, oscal-cli, oscal-xslt, Lula TUI); upstream issues usnistgov/OSCAL #2211, #2240, #1058, #1059, #884, #2007.
- 2026-09-14 OSCAL round-trip survey and reproductions, recorded on `hdf-libs-gxeb.5` through `hdf-libs-gxeb.13`, `hdf-libs-sjo52` and `hdf-libs-w5u5r`.
- NIST OSCAL v1.2.3 release (published 2026-08-07): JSON schemas vendored under `hdf-converters/converters/hdf-to-oscal-{sar,poam}/schemas/` on the 1.2.x conformance branch; metaschema allowed-value vocabularies under `src/metaschema/`.
- PR #330 — component-definition requirement ids qualified with the component uuid.
