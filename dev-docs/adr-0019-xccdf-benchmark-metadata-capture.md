# ADR-0019: The XCCDF benchmark converter carries every benchmark and rule field, checked against the XSD

- **Status:** Proposed
- **Date:** 2026-10-28
- **Revised:** 2026-10-28 — after a code-level review that opened both XSDs, ran both parsers on the CIS fixture and
  read the HDF spec: benchmark-level facts move under `extensions.passthrough` (the closed `extensions` of ADR-0017);
  the XSD walk is described as it really is (no `benchmarkType`, an extension chain plus `element ref`, 347 union
  paths) and card 3 is split; the CIS shape is corrected (safeguard-level groups, URI→URN rule, level derivation,
  `complex-check`); `cis_controls` is a list of URNs with the safeguard catalog at benchmark level, so the InSpec
  generator's tag rendering keeps parity; the DISA sub-element names are reconciled with the CKL vocabulary;
  `rationale`/`warning` are dropped from scope because main already carries them; the fixture plan says which fields
  no real DISA fixture fills.
- **Deciders:** Aaron Lippold
- **Branch:** `feat/xccdf-benchmark-metadata` (off `origin/main` at `6fbb858c`)
- **Issue:** hdf-libs #499
- **Numbering:** 0019 because 0018 (hardening playbook generation, the first consumer of the fields this ADR adds)
  is claimed on the unmerged `feat/ansible-playbook-generator` branch.
- **Relates to:** [ADR-0017](adr-0017-raw-source-artifact-carriage-and-requirement-rollup.md) §1 — `extensions` is
  closed; `extensions.passthrough` is the catch-all, keys flat, producers outside this repository namespace by tool;
  the `xccdf-results-to-hdf` converter's benchmark path (`ConvertXccdfBenchmarkToHDF` / `convertXccdfBenchmarkToHdf`);
  `hdf generate inspec-profile` and `hdf generate upgrade`, which read the Baseline it produces; the CKL converters in
  `hdf-converters/shared/{go,typescript}/checklist/`, which already write `extensions.passthrough.releaseInfo` and
  `tags.cklMetadata`; the fixture policy in `CLAUDE.md` and the `/fixtures` skill.

## Context

An HDF Baseline is the collection point for everything a benchmark says. Consumers differ in what they read: the
InSpec profile generator writes every tag it is given, a hardening generator needs the benchmark's "documentable" and
"responsibility" markers, a delta report needs the release, checklist export needs the release string verbatim. The
converter cannot know which consumer will come next, so its job is to carry what the file says and let each consumer
choose.

The XCCDF benchmark path does not do that today. Both parsers pull a fixed, hand-picked set of fields out of
hand-written structures — Go `encoding/xml` structs (`converter.go:41` `Benchmark` names `id`, `status`, `title`,
`description`, `version`, `platform`, `Group`, `Rule`, `TestResult` and nothing else; `:110` `Rule` names `id`,
`selected`, `severity`, `weight`, `version`, `title`, `description`, `rationale`, `warning`, `fixtext`, `ident`,
`check`, `reference`) and a `fast-xml-parser` object in TypeScript — and silently drop everything the structs do not
name. The vendored `xccdf_1.2.xsd` is used only to validate `hdf-to-xccdf` *output*; nothing on the input side checks
that the parse is complete. Every missing field has therefore been found one at a time, by a consumer that needed it:

- `hdf-libs-nhia` (P0): nested `Group`s were not traversed, dropping about 99% of the rules in SCAP Security Guide
  content.
- `hdf-libs-s7xc`: `Group.Rule` was a single element, dropping rules when a group had more than one.
- `hdf-libs-7vp0.5`: refs and descriptions were dropped on the results path.
- The results path emits `legacy_id` and `cce` (`buildTags`, `converter.go:1497-1531`); the benchmark path
  (`buildBaselineTags`, `:979-1016`) emits neither. The benchmark path emits `check_id` and `fix_id`; the results
  path does not.
- Of the DISA `<description>` body's eleven labelled sub-elements (`VulnDiscussion`, `FalsePositives`,
  `FalseNegatives`, `Documentable`, `Mitigations`, `SeverityOverrideGuidance`, `PotentialImpacts`,
  `ThirdPartyTools`, `MitigationControl`, `Responsibility`, `IAControls`), only `VulnDiscussion` survives
  (`extractVulnDiscussion`, `:1474`).
- The latest, found while designing the hardening generator (ADR-0018): DISA's release and benchmark date live in
  `<plain-text id="release-info">Release: 9 Benchmark Date: 01 Jul 2026</plain-text>` beside `<version>2</version>`.
  The converter reads only `<version>` (`:880`), so RHEL 9 V2R5 and V2R9 both become a Baseline with
  `version: "2"`, `hdf generate inspec-profile` writes `version: '2'` into `inspec.yml`, and nothing downstream can
  tell the releases apart. The CKL converters already carry this string as `extensions.passthrough.releaseInfo`
  (`shared/go/checklist/to_hdf.go:247`), so the key exists and the XCCDF path never fills it.
- In XCCDF 1.2 DISA input, `gid` and `rid` arrive in their qualified form (`xccdf_mil.disa.stig_group_V-204393`),
  which the converter copies into the tags unchanged (`:998,1010`); consumers keying on `V-…` then miss.

**CIS input drops more.** A real CIS benchmark (`CIS_Google_Chrome_Benchmark_v2.1.0-xccdf.xml`, XCCDF 1.2, in
`mitre/cis-bench` `tests/fixtures/xccdf/official/cis/`) puts the level in `Profile` membership (two profiles,
`Level 1 (L1) - …` selecting 72 of 93 rules and `Level 2 (L2) - …` selecting all 93), the CIS Controls v7/v8
safeguards in `ident` elements whose `system` is the framework URI and whose `cc7:controlURI` / `cc8:controlURI`
attribute is the control URI, and again in `metadata/controls:cis_controls/framework/safeguard` (title and URN) with
the implementation groups (as attributes, `ig2="true"`), asset type and security function **inside each safeguard**,
differing by framework (rule 1.4's security function is Protect under v8 and Detect under v7). Scored-ness is
`Rule/@role` (`full` / `unscored`); reference links are `ident system="URL"`; and 70 of the 93 rules carry their check
only inside `complex-check`, which the converter does not read, so CIS rules lose their check today. None of that
reaches the Baseline.

**Prior art reads the whole file.** `stig-parser` (PyPI, `pkeech/stig_parser`, MIT) keeps the raw release string and
splits out release and benchmark date, and carries all ten DISA sub-elements, writing `releaseinfo` back into the CKL
it produces. SAF CLI's `generate inspec_profile` (`mitre/saf`, Apache-2.0, `src/commands/generate/inspec_profile.ts:266-285`)
parses `release-info` into `profileVersion` (`2.9.0`), `benchmarkVersion` (`Version 2 Release 9 (V2R9)`) and
`benchmarkDate`. `mitre/cis-bench` (Apache-2.0) generates its XCCDF 1.1.4 and 1.2 models from the XSDs with `xsdata`
(`.xsdata.xml`, `src/cis_bench/models/xccdf/`), so every element the schema allows has a field by construction, and
its `docs/design/xccdf-mapping-design.md` records how CIS Controls land in `ident` and `metadata`.

**What the two parsers do with namespaces** (measured on the CIS fixture): Go `encoding/xml` matches an attribute
tag written without a namespace (`xml:"controlURI,attr"`) to `cc7:controlURI` and `cc8:controlURI` alike;
`parseXmlWithArrays` forces `removeNSPrefix: true` (`hdf-utilities/src/xml/index.ts:26`), so TypeScript sees plain
`controlURI` and can never test a namespace URI. The framework therefore has to come from the ident's `system`
attribute in both languages, and Go must match local names the way TS is forced to. In TS, a `framework` with one
`safeguard` arrives as an object and with two as an array, and an empty `cis_controls` arrives as `""`, unless those
element names are in the parser's array list.

**What the two XSDs actually define** (walked with the built-in parsers in both languages, identical output):
there is no `benchmarkType`; `Benchmark` has an anonymous type inside its global element (1.1.4 line 132, 1.2
line 47). Neither schema uses `xs:group` or substitution groups. What a walker must resolve is `xs:element ref=` to
global elements (`status`, `Profile`, `model`, `Value`), the extension chain `itemType → selectableItemType →
ruleType | groupType`, `ref="xml:lang"` attributes, `xs:any` / `xs:anyAttribute`, and the `complex-check` cycle.
With `TestResult`, `Value` and the Profile subtree cut off there are 248 paths in 1.1.4 and 277 in 1.2; with
`Profile` included (decision 2 needs it) 303 and 342, 347 in the union. Five paths exist only in 1.1.4 (deprecated
platform elements and a `dc`/`sccf` metadata wildcard); 34 only in 1.2, among them `Rule/metadata`, `Group/metadata`,
`Rule/ident/@*` (where `cc7`/`cc8` live), `dc-status`, `check/@negate` and `sub/@use`. NIST's published 1.1.4 XSD
has CRLF line endings; the copy in `cis-bench` is LF but otherwise identical.

**Constraints.** `extensions` is closed (ADR-0017 §1; `extensions.schema.json:94`): only `passthrough` and
`rawSourceArtifacts`, so every benchmark-level fact goes under `extensions.passthrough`, flat, as the CKL path does.
Tags are an open object with no registry; existing keys are snake_case. The InSpec generator emits every tag
(`control_stub.go:82-91`) and renders a list of objects as `map[…]` in Go and `[object Object]` in TS, so a tag value
is a string, a boolean, or a list of strings, never a list of objects. Go and TypeScript stay in parity with
byte-identical goldens (ADR-0001 §9). Fixtures are real files trimmed by whole-element drops with provenance, never
fabricated (`CLAUDE.md`, Fixture Integrity). DISA ships XCCDF 1.1; CIS ships 1.2; both must work. No new runtime
dependency is justified for XML parsing: `encoding/xml` and `fast-xml-parser` already parse these files; what is
missing is coverage, not capability.

## Decision

### 1. The benchmark path carries everything the file says

Every element and attribute the XCCDF schemas define under `Benchmark`, `Group` and `Rule` (the union of 1.1.4 and
1.2), plus the DISA description sub-elements and the CIS `metadata` structure that live inside otherwise-opaque text
or `xs:any` content, is either mapped to a Baseline field or explicitly listed as not carried, with a reason.
Consumers decide what to read; the converter does not decide for them.

### 2. Where each field lands

Three targets, chosen by shape, following what the Baseline already does.

**Benchmark-level facts → `extensions.passthrough`** (flat keys, beside the CKL path's `releaseInfo`, `stigid`,
`uuid`, `displayName`, `referenceIdentifier`, `classification`):

| Source | Key |
|---|---|
| `plain-text[@id="release-info"]` | `releaseInfo` (verbatim, the CKL key), `benchmarkRelease` (`"9"`), `benchmarkDate` (`"01 Jul 2026"`) |
| `status`, `status/@date` | `benchmarkStatus`, `benchmarkStatusDate` (Baseline `status` is HDF lifecycle, not XCCDF status) |
| `notice` | `notices[]` (`id`, `text`) |
| `reference/dc:publisher`, `reference/dc:source` | `publisher`, `source` |
| `platform/@idref` | `platforms[]` (CPE names; `supports[]` is the modeled home for a named OS and release, and mapping CPE names into it is later work) |
| `Profile` | `profiles[]` (`id`, `title`, `selectedRuleIds[]`, revision-free ids) |
| `plain-text[@id="generator"]`, `plain-text[@id="conventionsVersion"]` | `generatorVersion`, `conventionsVersion` |
| `metadata/controls:cis_controls/framework/safeguard` (every rule, merged) | `cisSafeguards[]`: `{ framework, urn, title, implementationGroups[], assetType, securityFunction }`, deduplicated on `urn` |

`benchmarkRelease` rather than `release`, because `supports[].release` already means the OS release. `release-info`
is located by `id`, never by position (DISA emits `generator` and `conventionsVersion` siblings in no guaranteed
order); the text is split on `Benchmark Date: ` and `Release: ` is stripped, as `stig-parser` does, which handles
`Release: 3.5` as well as `Release: 9`. A missing or unparseable element leaves the keys out; it is not an error.
The safeguard catalog sits at benchmark level because a safeguard's title, groups, asset type and security function
are properties of the safeguard, repeated in every rule that cites it; rules carry only the URNs.

**Per-rule single values and identifiers → `tags`** (beside the existing `gid`, `rid`, `stig_id`, `severity`,
`cci`, `gtitle`, `nist`, `fix_id`, `check_id`). Values are strings, booleans or lists of strings, so the InSpec
generator renders them identically in both languages:

| Source | Tag | Type |
|---|---|---|
| `ident[@system=".../legacy"]` | `legacy_id` (as the results path already does) | list |
| `ident[@system=".../cce"]` | `cce` | string |
| `Rule/@weight` | `weight` | string |
| `Rule/@role` | `role` | string |
| `description/Documentable` | `documentable` | boolean (`true`/`false` parsed; the existing `hdf-fixtures` Baseline already carries it as a boolean) |
| `description/FalsePositives`, `FalseNegatives`, `Mitigations`, `SeverityOverrideGuidance`, `PotentialImpacts`, `ThirdPartyTools`, `MitigationControl`, `Responsibility`, `IAControls` | `false_positives`, `false_negatives`, `mitigations`, `severity_override_guidance`, `potential_impacts`, `third_party_tools`, `mitigation_control`, `responsibility`, `ia_controls` | string |
| `Profile` membership | `cis_level` | list: the level label of every profile that selects the rule, from the profile title's `Level N` (`["L1","L2"]` for an L1 rule, since the L2 profile selects everything) |
| `ident[@system=<cc7 or cc8 framework URI>]/@controlURI` and `metadata/…/safeguard/@urn` | `cis_controls` | list of URNs; a control URI `…/20-cc/v8.0/control/9/subcontrol/3` is converted to `urn:cisecurity.org:controls:8.0:9:3` and the two sources are deduplicated on that URN; framework from `@system`, never from the prefix |

Tags because that is where every per-rule identifier and marker already lives, where the InSpec generator reads,
and where `hdf query --tag` can filter. An empty sub-element produces no tag. The names are the snake_case of the
DISA element names (`mitigation_control`, singular, as `MitigationControl` is). The CKL path carries the same facts
under `tags.cklMetadata` with the CKL field names (`False_Positives`, `Mitigation_Control`, `Potential_Impact`,
`Security_Override_Guidance`, …) and `legacy_ids` (plural); those are the checklist's own field names, kept for the
CKL round trip, and this ADR does not change them. The crosswalk between the two vocabularies is recorded in the
docs page (card 10); teaching the CKL exporter to read the XCCDF names is a separate card when checklist export from
a benchmark-sourced Baseline is wanted.

`gid` and `rid` are normalised to `V-…` and `SV-…r…_rule` by stripping DISA's `xccdf_mil.disa.stig_group_` and
`xccdf_mil.disa.stig_rule_` prefixes only; CIS ids (`xccdf_org.cisecurity.benchmarks_rule_…`) are left as they are.
The benchmark path reads a rule's check from `check` or, when the rule has only a `complex-check`, from the first
`check` inside it, so `check_id` and the check text arrive for CIS rules.

**Per-rule prose → `descriptions`.** Already carried on the benchmark path: `default` (from `VulnDiscussion`),
`check`, `fix`, `rationale`, `warning` (`buildBaselineDescriptions`, `converter.go:931-975`). Nothing is added.
**Reference links → `refs`:** `ident system="URL"` joins the `reference` elements already carried.

### 3. An XSD-driven completeness test keeps it that way

A test in each language fails when the schemas allow something the converter neither maps nor explicitly skips:

1. NIST's `xccdf-1.1.4.xsd` is vendored, byte for byte (CRLF; `.gitattributes` already marks schemas `-text`),
   beside the existing `xccdf_1.2.xsd` under `hdf-to-xccdf/schemas/`, with provenance.
2. One shared allowlist, `hdf-converters/converters/xccdf-results-to-hdf/fixtures/xccdf-coverage.json`, read by both
   suites. Keys are prefix-free local-name paths in the walker's output form (`Rule/check/check-content-ref/@href`,
   `Rule/ident/@*`, `Rule/metadata/*`), never type names, because inherited fields repeat under `Group`, `Rule` and
   `Value` and map to different targets. Each maps to
   `{ "target": "passthrough.benchmarkRelease" | "tags.cce" | "descriptions.rationale" | "refs" | "skip", "reason": "…" }`;
   a `skip` without a reason fails. Subtree rows (`Benchmark/TestResult/**`, `Benchmark/Value/**`) keep the file
   near a hundred rows rather than 350. A `vendor` section lists by hand the paths the schemas do not define: the ten
   DISA sub-elements inside `Rule/description`, and the CIS `Rule/metadata/cis_controls/framework/safeguard/…` tree.
3. The walker parses each XSD as XML with the language's own parser (no XSD library; about 110 lines of Go with
   `,any` nodes, about 50 of TypeScript), resolves `xs:element ref=`, the `itemType → selectableItemType →
   ruleType | groupType` extension chain, `xs:any` / `xs:anyAttribute` and the `complex-check` cycle, and emits the
   **union** of the 1.1.4 and 1.2 path sets (347 paths with `Profile`). It asserts each path is in the allowlist, and
   that each allowlist path outside `vendor` is defined by at least one schema, so the allowlist cannot drift.
4. For every non-`skip` target, a fixture that carries the source element must produce a non-empty value at the
   target in both languages. This is what turns "we mapped it" into "it arrives". Where no real fixture carries a
   source element, the row says so (`"fixture": "none: <reason>"`) and the arrival assertion is skipped for that row
   only, visibly.

The test is the decision's enforcement: the next XCCDF field someone forgets fails CI instead of surfacing in a
consumer a year later.

### 4. The InSpec profile generator uses the release

`hdf generate inspec-profile` writes `version: '<version>.<benchmarkRelease>.0'` into `inspec.yml` when
`extensions.passthrough.benchmarkRelease` is present (SAF CLI's `profileVersion` shape, so a profile generated here
matches one generated there), and the current `version: '<version>'` otherwise. No other consumer changes in this
ADR; ADR-0018 reads the new fields.

### 5. Fixtures are the real files, and the record says what they do not carry

DISA RHEL 9 V2R9 Manual XCCDF (1.1), downloaded from DISA's STIG library, and the CIS Google Chrome Benchmark v2.1.0
(1.2) from `mitre/cis-bench` `tests/fixtures/xccdf/official/cis/`, both trimmed by whole-element drops to the size
guideline, with provenance recording the source, sha256 as retrieved, retrieval date and the elements dropped. The
CIS file is trimmed with its `Profile` `select` lists so every kept rule keeps its level. They stay in the converter's
`fixtures/input` as its tested contract; ADR-0018 promotes the converted Baselines to `hdf-fixtures` when its
generators become the second consumer.

In RHEL 9 V2R5 (and Ubuntu 24.04 V1R1) every DISA sub-element except `Documentable` (always `false`) is empty in
every rule. Card 2 checks V2R9 and, if it is the same, the nine prose sub-element rows record `fixture: none` with
that reason rather than a fabricated value; the converter still carries them for the STIGs that fill them.

## Prior Art

| Candidate | Version / license (read from the repo) | What it offers | Verdict |
|---|---|---|---|
| `pkeech/stig_parser` (PyPI `stig-parser`) | master, MIT | `convert_xccdf`: raw `ReleaseInfo` + `Release` + `BenchmarkDate`; all ten DISA sub-elements; CAT mapping; `_Manual-xccdf.xml` extraction from the DISA zip; writes `releaseinfo` to CKL | **REFERENCE** — the parse rule and the field list are adopted; Python, no code to import. Locates `plain-text` by position (`[0]`), which this ADR does not copy. |
| `mitre/saf` `generate inspec_profile` | main, Apache-2.0 | `release-info` parse by `split(':')`; `profileVersion` `<v>.<r>.0`, `benchmarkVersion`, `benchmarkDate`, `inspecTitle` | **REFERENCE** — the `profileVersion` shape is adopted for `inspec.yml` so profiles from both tools agree; the split-on-colon parse is replaced by split-on-`Benchmark Date: `. |
| `mitre/cis-bench` | main, Apache-2.0 | XCCDF 1.1.4 and 1.2 dataclasses generated from the XSDs with `xsdata` (MIT); CIS → XCCDF field mapping design; real DISA and CIS fixtures | **REFERENCE** for the CIS field locations and the CIS fixture; **REJECT** as an approach (generated types, Alternative A). |
| `ansible-lockdown/Benchmark-Generator` (`mitre/benchmark-generator`) | 2020-08-18, MIT | lxml parse keyed on group id | **REJECT** — reads none of the fields in question. |
| Go XSD code generators (`xuri/xgen`, `droyo/go-xml`) and TS (`cxsd`) | various, BSD/MIT | Generate parse types from an XSD | **REJECT** — two schemas × two languages of generated code for a problem that is coverage, not capability; see Alternative A. |

No dependency is adopted; the footprint change is zero in both `go.mod` and `package.json`.

## Alternatives Considered

### A: Generate the parse types from the XSDs, as `cis-bench` does

- **Pros:** complete by construction; the schema is the source of truth.
- **Cons:** two XSD versions (1.1.4, 1.2) × two languages of generated code to maintain; generated Go/TS types for
  XCCDF's `xs:any` and mixed-content elements are awkward and still do not reach the DISA sub-elements, which are
  text inside `description`, or the CIS `controls:*` metadata, which is `xs:any`; a large diff for a converter that
  already parses everything it is pointed at.
- **Why rejected:** the problem is that nobody is told when a field is missing, not that the parser cannot read it.
  The completeness test gives the "schema is the source of truth" property with no generated code and also covers the
  vendor-specific content the schema does not define.

### B: Keep adding fields as consumers ask for them

- **Why rejected:** that is the current practice, and the Context lists what it cost. Each gap is cheap to fix and
  expensive to find.

### C: Carry the DISA sub-elements as labelled descriptions instead of tags

- **Pros:** `descriptions` is free-form prose; some sub-elements are paragraphs.
- **Why rejected:** they are markers and short fields a consumer filters on (`documentable`, `responsibility`), the
  InSpec generator reads tags, `hdf query --tag` filters tags, and the CKL path already keeps the same facts in tags.
  A long value in a tag is still a string.

### D: Reuse the CKL path's `cklMetadata` vocabulary for the DISA sub-elements

- **Pros:** one vocabulary; the CKL exporter would read benchmark-sourced Baselines unchanged.
- **Why rejected:** `cklMetadata` nests checklist field names (`False_Positives`, `Mitigation_Control`) under one
  tag as a round-trip bag for fields CKL has and HDF does not model; they are the checklist's names, not the
  benchmark's, and a nested object is not a tag a profile or a query filters on. The XCCDF names are first-class
  tags; the crosswalk is documented, and the exporter learns to read both when that export is wanted.

### E: Carry the CIS safeguard objects on each rule's `cis_controls` tag

- **Pros:** everything about a rule's controls in one place.
- **Why rejected:** a list of objects in a tag renders as `map[…]` / `[object Object]` in the generated InSpec
  controls, breaking Go/TS parity and the profile; and the safeguard's title, groups and functions are facts about
  the safeguard, repeated in every rule. Rules carry URNs; the catalog sits once at benchmark level.

### F: Parse `release-info` in the consumers that need it

- **Why rejected:** three consumers (profile generator, upgrade, checklist export) would each parse the same string,
  and the CKL path already has the key. Parse once, at collection.

### G: Do nothing

- **Why rejected:** ADR-0018's release check and disposition hints cannot be built, and the next consumer finds the
  next gap.

## Consequences

**What becomes easier:**

- Any consumer can tell two releases of one benchmark apart, filter rules by DISA or CIS marker, read CIS levels and
  controls, and resolve a safeguard URN to its title and groups, without touching XML.
- A profile generated by `hdf` and one generated by SAF CLI carry the same version string.
- The next missing XCCDF field is a CI failure with a named path, not a consumer bug.

**What becomes harder:**

- The three existing benchmark-path goldens (`benchmark-minimal-1.1`, `benchmark-minimal-1.2`,
  `benchmark-ssg-nested-groups`) change, plus the two new ones. Nothing else compares a benchmark Baseline byte for
  byte: `hdf-fixtures/baseline/` holds static files, the CLI tests assert by `Contains` and schema, the generator and
  MCP goldens have no XCCDF input.
- The allowlist is one more file to update when a field is added — which is the point.
- The passthrough and tag keys become a contract: `benchmarkRelease`, `benchmarkDate`, `cisSafeguards`,
  `cis_level`, `cis_controls`, the ten sub-element names. They are chosen here; renaming later is a breaking change
  for consumers.
- Two vocabularies for the DISA sub-elements exist until the CKL exporter reads both.

**Risks:**

- **The two parsers diverge on namespaced content.** Mitigation: framework from `@system` in both; Go matches local
  names; the TS parser call lists `framework`, `safeguard`, `notice`, `plain-text`, `metadata`, `Profile`, `select`
  as array tags; the CIS card asserts both outputs against one golden, and the completeness test's arrival assertion
  catches an empty value in either language.
- **Trimming the CIS fixture breaks a `Profile` `select` reference.** Mitigation: trim rules and their `select` lines
  together; the `cis_level` arrival assertion fails if a kept rule lost its profile.
- **Oversized fixtures.** The full RHEL 9 manual is 1.4 MB and the Chrome benchmark 460 KB. Mitigation: whole-element
  trimming to the guideline, keeping at least one rule that carries each source element.
- **No real DISA fixture fills the prose sub-elements.** Mitigation: decision 5's `fixture: none` rows; the converter
  carries them regardless, and the row flips to a fixture the day a STIG that fills them is added.

## Open Questions

None. The key names in decision 2 are this ADR's choice; no prior convention exists for the CIS and benchmark-level
keys, the DISA sub-element names follow the snake_case of the element names, and `documentable` is a boolean because
the existing `hdf-fixtures` Baseline already carries it that way.

## Implementation Plan

### Scope

**IN scope:**

- Every target in decision 2, on the benchmark path, in Go and TypeScript, with byte-identical goldens.
- `gid`/`rid` normalisation for DISA XCCDF 1.2 input; `complex-check` on the benchmark path.
- The completeness test of decision 3, with `xccdf-1.1.4.xsd` vendored and the shared allowlist.
- The two fixtures of decision 5 with provenance.
- `inspec.yml` version from the release (decision 4).
- The converter's page under `site/docs/`, including the CKL crosswalk, and the spec line that still says a Baseline
  carries no `extensions` (`hdf-specification.md:245`).

**OUT of scope:**

- Reading the Manual XCCDF out of a DISA zip (its own issue).
- CIS Controls as a mapping family in `hdf-mappings` (the catalog carries the URNs and titles; a crosswalk to NIST
  is later work).
- Mapping CPE platform names into `supports[]`.
- Teaching the CKL exporter to read the XCCDF tag names (its own card, when wanted).
- Filling `verificationMethod` or `applicability` from the new tags (consumers decide; ADR-0018 says why).
- Any change to the results path beyond fields it was also missing.
- Generated parse types (Alternative A).

### Quality Standards (inherited by every card)

- **Framework-first:** XML parsing only through the existing `encoding/xml` structs and `parseXmlWithArrays`
  (`fast-xml-parser`); no new dependency in either language. Passthrough written through the same `setIfNotEmpty` /
  `setIf` pattern the CKL path uses, under `extensions.passthrough`, flat. CCI → NIST untouched.
- **Existing patterns:** tag building extends `buildBaselineTags` / the TS `ruleToBaselineRequirement` tag object;
  the fixture procedure is the `/fixtures` skill, including `provenance.txt` and goldens for every new input; tag
  values are strings, booleans or lists of strings, never objects.
- **Go/TS parity:** every card lands both languages; goldens byte-identical; the completeness test reads one shared
  allowlist and the walker's path output is identical in both languages.
- **Tests:** TDD; >90% coverage; the completeness test and the arrival assertions are the spec; no time-dependent
  assertions.
- **Security:** `ValidateXMLInput` stays the first call on every input; no new file I/O in the converter.
- **Docs:** `site/docs/` only.

### Shared Abstractions (built first)

| Shared need | Used by | Card |
|---|---|---|
| `xccdf-1.1.4.xsd` vendored with provenance | completeness test | 1 |
| RHEL 9 V2R9 and CIS Chrome fixtures, trimmed, with provenance and goldens | every card's tests | 2 |
| The allowlist file and the XSD walker, both languages | completeness test; every field card adds its rows | 3 |
| The arrival assertion over the allowlist | every field card | 4 |

### Cards

Ten cards under one epic. Each is one TDD loop and one review (1–5 story points), inherits the Quality Standards,
and points its `Prior art checked` section at this ADR's Prior Art table. Go and TypeScript land in the same card.
Total: 27 story points.

| # | Card | sp | Blocked by |
|---|---|---|---|
| 1 | Vendor `xccdf-1.1.4.xsd` with provenance | 1 | — |
| 2 | Add the RHEL 9 V2R9 and CIS Chrome benchmark fixtures | 3 | — |
| 3 | Add the XSD walker and the allowlist, with every current field mapped and every gap listed as `skip` | 5 | 1 |
| 4 | Add the arrival assertion over the allowlist | 3 | 2, 3 |
| 5 | Carry benchmark-level facts into `extensions.passthrough`, including the release parse | 3 | 4 |
| 6 | Carry `legacy_id`, `cce`, `weight`, `role`; normalise DISA `gid`/`rid`; read `complex-check` | 3 | 4 |
| 7 | Carry the ten DISA description sub-elements as tags | 3 | 4 |
| 8 | Carry the CIS level, control URNs, safeguard catalog and URL refs | 3 | 4 |
| 9 | `inspec.yml` version from the release | 1 | 5 |
| 10 | Regenerate the goldens, write the docs page with the CKL crosswalk, fix the spec line | 2 | 5–8 |

**Card 1: Vendor `xccdf-1.1.4.xsd`.**
- Files: `hdf-converters/converters/hdf-to-xccdf/schemas/xccdf-1.1.4.xsd`, that directory's provenance record
- ACs: the file is NIST's published 1.1.4 schema byte for byte (CRLF kept; sha256 and URL recorded); the existing 1.2
  schema and its tests are unchanged.

**Card 2: Add the benchmark fixtures.**
- Files: `hdf-converters/converters/xccdf-results-to-hdf/fixtures/input/U_RHEL_9_STIG_V2R9_Manual-xccdf.xml`,
  `fixtures/input/CIS_Google_Chrome_Benchmark_v2.1.0-xccdf.xml`, their `expected/*.hdf.json` goldens,
  `fixtures/provenance.txt`
- ACs: provenance records source URL, sha256 as retrieved, retrieval date and the whole elements dropped; each trimmed
  file keeps at least one rule carrying every source element of decision 2 that the file fills (for CIS: a rule in
  each level, a rule with `cc7` and `cc8` idents, an `unscored` rule, a `complex-check`-only rule, a URL ident); the
  CIS `Profile` `select` lists reference only kept rules; the provenance states, per DISA sub-element, whether V2R9
  fills it anywhere; both convert and validate; Go and TS goldens identical.
- Verification: `cd hdf-converters && go test ./converters/xccdf-results-to-hdf/... && pnpm test:ts -- xccdf`

**Card 3: The XSD walker and the allowlist.**
- Files: `hdf-converters/converters/xccdf-results-to-hdf/fixtures/xccdf-coverage.json`,
  `go/coverage_test.go`, `typescript/coverage.test.ts`
- ACs: the walker reads both XSDs with the built-in parser, resolves `xs:element ref=`, the `itemType →
  selectableItemType → ruleType | groupType` chain, `xs:any` / `xs:anyAttribute` and the `complex-check` cycle, and
  emits the union path set, identical in Go and TS (347 paths with `Profile`); every path is in the allowlist or the
  test names the missing one; every allowlist path outside `vendor` is defined by at least one schema or the test
  names it; subtree rows cover `TestResult` and `Value`; the `vendor` section lists the DISA sub-elements and the
  CIS safeguard tree; at this card every field the converter already carries is mapped and every gap of decision 2 is
  `skip` with reason "card N".

**Card 4: The arrival assertion.**
- Files: as card 3
- ACs: for every non-`skip` row without `fixture: none`, the named fixture converts to a Baseline whose target is
  non-empty, in both languages; a row with `fixture: none` is reported as skipped by name; deleting a row or adding a
  fake one fails the test.

**Card 5: Benchmark-level passthrough.**
- Files: `go/converter.go` (`Benchmark` struct gains `plain-text`, `status/@date`, `notice`, `reference/dc:*`,
  `Profile`; `convertBenchmarkToBaseline` writes `extensions.passthrough`), `typescript/converter.ts` (array tags
  added to the parser call), their tests, goldens, the allowlist rows
- ACs: every key of decision 2's first table except `cisSafeguards` on both fixtures; the release parse handles
  `Release: 9`, `Release: 3.5`, a missing element and garbage (no keys, no error); `profiles[].selectedRuleIds`
  lists revision-free ids; the document validates against the schema (`passthrough` only); Go and TS goldens
  identical; the rows flip from `skip` to their targets and cards 3–4's tests pass.

**Card 6: Identifier tags, normalisation, `complex-check`.**
- Files: as card 5
- ACs: `legacy_id` from the legacy ident system exactly as the results path; `cce`; `weight`; `role`; DISA
  `xccdf_mil.disa.stig_` prefixes stripped from `gid` and `rid` (tested on the qualified ids in `stig-rhel7.xml`,
  whose benchmark half exercises the same function) and CIS ids untouched; `check_id` and check text read from the
  first `check` inside `complex-check` when a rule has no direct `check`; goldens and allowlist updated.

**Card 7: DISA description sub-elements.**
- Files: as card 5 (`extractVulnDiscussion` generalised to all eleven labels)
- ACs: each non-empty sub-element becomes its tag; `documentable` is a boolean; empty ones produce no tag;
  `VulnDiscussion` still feeds the `default` description; HTML stripped the way `default` is; every row either arrives
  from the V2R9 fixture or carries `fixture: none` with the reason from card 2's provenance; goldens and allowlist
  updated.

**Card 8: CIS level, control URNs, safeguard catalog, URL refs.**
- Files: as card 5
- ACs: `cis_level` from `Profile` membership by title (`["L1","L2"]` for an L1 rule); `cis_controls` as URNs from
  both the ident attributes (framework from `@system`, URI converted to URN) and the safeguard elements, deduplicated,
  sorted; `extensions.passthrough.cisSafeguards[]` with title, implementation groups (from the `igN` attributes),
  asset type and security function per framework, deduplicated on URN, sorted; `ident system="URL"` into `refs`;
  identical between the two parsers on the Chrome fixture; no CIS key on the DISA fixture; goldens and allowlist
  updated.

**Card 9: `inspec.yml` version from the release.**
- Files: `hdf-generators/go/generator.go`, `hdf-generators/src/inspec-yml.ts`, their tests
- ACs: `version: '2.9.0'` from the V2R9 Baseline; `version: '2'` when `benchmarkRelease` is absent; Go and TS
  identical.

**Card 10: Goldens, docs, spec line.**
- Files: the three existing benchmark-path goldens, `site/docs/` converter page,
  `site/docs/specification/hdf-specification.md:245`
- ACs: `pnpm check` and `pnpm test:go` green across the workspace; the docs page lists every passthrough key, tag
  and description label the benchmark path emits with the allowlist as its source, and the crosswalk to the CKL
  path's `cklMetadata` and `legacy_ids` names; the spec no longer says a Baseline carries no `extensions`; no emoji.

### Verification Strategy

- Both fixtures through both converters: every target of decision 2 present with the expected value; Go and TS
  goldens byte-identical.
- The completeness test green with zero unexplained `skip`s and every `fixture: none` row named; deleting one
  allowlist row fails it; adding a fake row fails it.
- V2R5 (from the ADR-0018 fixture work, or the `cis-bench` copy) and V2R9 Baselines differ in
  `extensions.passthrough.benchmarkRelease`; `hdf generate inspec-profile` on V2R9 writes `version: '2.9.0'`, and
  every generated control's tags render identically in Go and TS.
- Full workspace `pnpm check` and `pnpm test:go` after the golden regeneration; CI green on every module.
