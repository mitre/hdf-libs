# ADR-0024: The XCCDF benchmark converter carries every benchmark and rule field, checked against the XSD

- **Status:** Proposed
- **Date:** 2026-10-28
- **Revised:** 2026-10-28 — after a code-level review that opened both XSDs, ran both parsers on the CIS fixture and
  read the HDF spec: benchmark-level facts move under `extensions.passthrough` (the closed `extensions` of ADR-0017);
  the XSD walk is described as it really is (no `benchmarkType`, an extension chain plus `element ref`, 347 union
  paths as then estimated; the walker as built pins 628) and card 3 is split; the CIS shape is corrected (safeguard-level groups, URI→URN rule, level derivation,
  `complex-check`); `cis_controls` is a list of URNs with the safeguard catalog at benchmark level, so the InSpec
  generator's tag rendering keeps parity (the URN list was replaced on 2026-11-20, see decision 6); the DISA sub-element names are reconciled with the CKL vocabulary;
  `rationale`/`warning` are dropped from scope because main already carries them; the fixture plan says which fields
  no real DISA fixture fills.
- **Revised:** 2026-10-29 — after the corpus card exposed that the benchmark path applies the DISA STIG tag set to
  every file it reads: decision 6 adds identification of shape, version and benchmark family as the first step, the
  per-family contract (DISA STIG, CIS, SSG) that every field mapping and both generators follow, and the rule that no
  tag is ever emitted empty; decision 2's CIS rows are replaced by the family contract (the installed CIS vocabulary,
  not URNs); decision 4 becomes the generator's profile style per family; inline check content with child elements
  is carried; SSG is a supported family with its own corpus card; cards 11–14 are added and cards 6 and 8 re-scoped.
- **Decided:** 2026-11-20 — the owner decided or confirmed all 17 gaps of `adr-0024-gap-register.md`, each against
  measured evidence recorded there; decision 6 below is written to those decisions. The `hdf-libs` maintainer
  reviews the set and may change it.
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
`Rule/@role` (`full` / `unscored`); reference links are `ident system="URL"`; and 33 of the 93 rules carry their check
only inside `complex-check` (59 have a direct `check` and one has neither; `fixtures/provenance.txt`), which the converter does not read, so CIS rules lose their check today. None of that
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
`Profile` included (decision 2 needs it) 303 and 342, 347 in the union. Those were the 2026-10-28 estimates; the
walker as built pins 628 union paths (`fixtures/xccdf-coverage.json`). Five paths exist only in 1.1.4 (deprecated
platform elements and a `dc`/`sccf` metadata wildcard); 34 only in 1.2, among them `Rule/metadata`, `Group/metadata`,
`Rule/ident/@*` (where `cc7`/`cc8` live), `dc-status`, `check/@negate` and `sub/@use`. NIST's published 1.1.4 XSD
has CRLF line endings; the copy in `cis-bench` is LF but otherwise identical.

**Constraints.** `extensions` is closed (ADR-0017 §1; `extensions.schema.json:94`): only `passthrough` and
`rawSourceArtifacts`, so every benchmark-level fact goes under `extensions.passthrough`, flat, as the CKL path does.
Tags are an open object with no registry; existing keys are snake_case. The InSpec generator emits every tag
(`control_stub.go:82-91`) and renders a list of objects as `map[…]` in Go and `[object Object]` in TS, so a tag value
is a string, a boolean, or a list of strings, never a list of objects. One exception was decided on 2026-11-20:
`cis_controls` is a one-element list holding a map, the form the published CIS baselines write, and both generators
are taught to render a map as a Ruby hash (decision 6). Go and TypeScript stay in parity with
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
are properties of the safeguard, repeated in every rule that cites it; rules carry the control ids per framework
version in `cis_controls` (decision 6).

**Per-rule single values and identifiers → `tags`** (beside the existing `gid`, `rid`, `stig_id`, `severity`,
`cci`, `gtitle`, `nist`, `fix_id`, `check_id`). Values are strings, booleans or lists of strings, so the InSpec
generator renders them identically in both languages; `cis_controls` is the one exception (decision 6):

| Source | Tag | Type |
|---|---|---|
| `ident[@system=".../legacy"]` | `legacy_id` (as the results path already does) | list |
| `ident[@system=".../cce"]` | `cce` | string |
| `Rule/@weight` | `weight` | string |
| `Rule/@role` | `role` | string |
| `description/Documentable` | `documentable` | boolean (`true`/`false` parsed; the existing `hdf-fixtures` Baseline already carries it as a boolean) |
| `description/FalsePositives`, `FalseNegatives`, `Mitigations`, `SeverityOverrideGuidance`, `PotentialImpacts`, `ThirdPartyTools`, `MitigationControl`, `Responsibility`, `IAControls` | `false_positives`, `false_negatives`, `mitigations`, `severity_override_guidance`, `potential_impacts`, `third_party_tools`, `mitigation_control`, `responsibility`, `ia_controls` | string; `responsibility` is a list, because DISA repeats the element; `SecurityOverrideGuidance`, DISA's 2009 to 2012 spelling, also feeds `severity_override_guidance` |
| CIS rule id, `Profile` membership, `@role`, the `cc`/`controls` idents and safeguards | `cis_id`, `cis_level`, `cis_profiles`, `assessment_status`, `cis_controls` | the CIS family row of decision 6; these replace the URN list and the `["L1","L2"]` form of the 2026-10-28 revision, which no existing profile uses |

Tags because that is where every per-rule identifier and marker already lives, where the InSpec generator reads,
and where `hdf query --tag` can filter. An empty source produces no tag, ever: not an empty string, not an empty
list (the benchmark path emitted `stig_id: ""` and `nist: []` on every CIS and SSG rule before decision 6; one
exception stands until its open question in decision 6 is answered: a DISA rule with no CCI carries `nist: []`). The names are the snake_case of the
DISA element names (`mitigation_control`, singular, as `MitigationControl` is). The CKL path carries the same facts
under `tags.cklMetadata` with the CKL field names (`False_Positives`, `Mitigation_Control`, `Potential_Impact`,
`Security_Override_Guidance`, …) and `legacy_ids` (plural); those are the checklist's own field names, kept for the
CKL round trip, and this ADR does not change them. The crosswalk between the two vocabularies is recorded in the
docs page (card 10); teaching the CKL exporter to read the XCCDF names is a separate card when checklist export from
a benchmark-sourced Baseline is wanted.

`gid` and `rid` are normalised to `V-…` and `SV-…r…_rule` by stripping DISA's `xccdf_mil.disa.stig_group_` and
`xccdf_mil.disa.stig_rule_` prefixes only; CIS ids (`xccdf_org.cisecurity.benchmarks_rule_…`) are left as they are.
The benchmark path reads a rule's check from `check` or, when the rule has only a `complex-check`, from the first
`check` inside it. The check text is the descendant text of `check-content` in document order, markup stripped, the
same way the prose fields read XHTML children: CIS content of 2006–2016 puts the audit command inside
`ecl:shell-command` children and the element's own text is empty. `check_id` is a DISA fact (DISA puts `C-…_chk`
in `check/@system`); on other families `@system` is the check language and is not a tag.

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
   **union** of the 1.1.4 and 1.2 path sets (628 paths as built, pinned in `fixtures/xccdf-coverage.json`). It asserts each path is in the allowlist, and
   that each allowlist path outside `vendor` is defined by at least one schema, so the allowlist cannot drift.
4. For every non-`skip` target, a fixture that carries the source element must produce a non-empty value at the
   target in both languages. This is what turns "we mapped it" into "it arrives". Where no real fixture carries a
   source element, the row says so (`"fixture": "none: <reason>"`) and the arrival assertion is skipped for that row
   only, visibly.

The test is the decision's enforcement: the next XCCDF field someone forgets fails CI instead of surfacing in a
consumer a year later.

### 4. The InSpec profile generator renders a profile style per family

`hdf generate inspec-profile` reads `extensions.passthrough.benchmarkFamily` (decision 6) and renders the family's
row: the control id (`SV-257777` for DISA; `<slug>-cis-1.1.1` for CIS; the rule short name for SSG), the
`inspec.yml` `name` (the family's slug rule, never the raw benchmark id: the CIS id is 80 characters), the
`version` (`<version>.<benchmarkRelease>.0` for DISA, SAF CLI's `profileVersion` shape; the benchmark's own version
string for CIS and SSG), the description labels, and the tags, which it still writes as given because decision 6
makes them right per family. A Baseline with no family renders the generic style and the generator says so. Before
this revision one STIG-shaped template rendered every family: a CIS control came out as
`control 'xccdf_org.cisecurity.benchmarks_rule_1.1.1_L1_Ensure_…'` with `tag stig_id: ''` and `tag nist: []`.
ADR-0018 reads the same family and row for its playbooks.

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

The corpus is one real file per measured deviation, not per feature (card 11 of the 2026-10-29 revision): the
2026-10-29 sweeps measured the DISA and CIS libraries (the gap register's finding F2 gives the corrected counts), and
`fixtures/README.md` is the register that says what every input is there to prove. For SSG the repository holds one
fixture, whose origin was never established. Three SSG builds turned up in the CIS sweep's downloads, misfiled as
CIS (finding F2), and on 2026-11-20 six builds were measured, four of them from the published release v0.1.82.
Card 13 adds real SSG builds as fixtures before the SSG family row is implemented.

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
  the safeguard, repeated in every rule. The catalog sits once at benchmark level. (Revised 2026-11-20: rules carry
  `cis_controls` as the published one-element list holding a version-to-ids map, and the generators learn to render
  it; the safeguard objects still do not go on the rule, so this alternative stays rejected.)

### F: Parse `release-info` in the consumers that need it

- **Why rejected:** three consumers (profile generator, upgrade, checklist export) would each parse the same string,
  and the CKL path already has the key. Parse once, at collection.

### G: Do nothing

- **Why rejected:** ADR-0018's release check and disposition hints cannot be built, and the next consumer finds the
  next gap.

### 6. The parser identifies the document first, and every mapping follows the family

An XCCDF file has three facts a consumer cannot guess and the converter decided none of them before this revision:
its **shape** (benchmark, benchmark with results, ARF; the data stream of a separate card), its **version** (1.1 or
1.2) and its **family**, the publisher whose conventions it follows. Shape was already decided in code and never
recorded; version was handled by ignoring namespaces; family was never decided, so the DISA STIG tag set ran on
every rule of every file (`buildBaselineTags` is commented "STIG-specific tags"): a CIS or SSG rule got
`stig_id: ""`, `nist: []`, a `check_id` holding the OVAL system URL, and no identity of its own, and the InSpec
generator wrote all of it into a profile.

**Identification runs first, once, in both parsers, and is recorded.** Under `extensions.passthrough`:
`documentShape` (`benchmark` | `results` | `arf`), `xccdfVersion` (`1.1` | `1.2`), `benchmarkFamily`
(`disa-stig` | `cis` | `ssg` | `unknown`). The fingerprint reports the same three in its label once they exist.
The signals, measured on the 2026-10-29 corpora:

| Family | Signal | Measured |
|---|---|---|
| `disa-stig` | `plain-text[@id="release-info"]` present and the description bodies carry `VulnDiscussion` | 2,548 of 2,548 DISA files, 2009–2026; `xccdf_mil.disa.stig_` id prefix on 1.2 content as a third signal |
| `cis` | Benchmark id starts `xccdf_org.cisecurity.benchmarks_` or `cis_`, or a `cisecurity.org` namespace is used | 433 of 433 real CIS files, 2006–2026 (two further files in that sweep are synthetic test data) |
| `ssg` | Benchmark id starts `xccdf_org.ssgproject.content_`, or `version/@update` is a `github.com/ComplianceAsCode` URL | 6 of 6 builds measured 2026-11-20: four at v0.1.82 carry both signals; two 0.1.58 builds (ids `UBUNTU-XENIAL`, `UBUNTU_20-04`) carry `@update` alone |
| `unknown` | none of the above | the hand-made minimal fixtures |

No CIS or SSG file carries a DISA signal; the detector asserts exactly one family or `unknown`, never a guess.

**The family row.** Every per-rule mapping, the generators and ADR-0018's identity read one row. The generic part
applies to every family: `gid`, `gtitle`, `rid` (the XCCDF ids as published, DISA 1.2 prefixes stripped), `severity`
(the rule's own `low`, `medium` or `high`; medium, with impact 0.5, when the file gives none or says `unknown`),
`profiles` (the ids of the profiles that select the rule), `default`/`rationale`/`fix`/`check`/`warning`
descriptions when the text exists. The family part is:

| | DISA STIG | CIS | SSG |
|---|---|---|---|
| Stable key | SV number, revision-free (`SV-257777`) | benchmark slug, `-cis-`, recommendation number (`google-chrome-cis-1.1.11`; the number is parsed from the rule id as SAF CLI's `--idType cis` does); a rule whose id carries no number (all 29 rules of the 2007 ESX 3.5 benchmark) keeps its published id | rule short name (`accounts_password_minlen_login_defs`, after `_rule_`) |
| InSpec control id | `SV-257777` | `<slug>-cis-1.1.11`, the form MITRE's CIS baselines use (`aws-foundations-cis-1.1`, `microsoft-sql-server-2017-cis-1.1`); `<slug>` is the benchmark title with the leading `CIS ` and trailing ` Benchmark` removed, kebab-cased (`google-chrome`) | the short name |
| Identity tags | `stig_id`, `cci`, `nist` (from CCIs), `check_id`, `fix_id`, `legacy_id`, `cce`, `weight`, `role` | `cis_id` (`1.1.11`, the name MITRE's CIS baselines use), `cis_level` (`Level 1`, the lowest level whose profile selects the rule; Level 3 exists), `cis_profiles` (every selecting profile's title, keeping the Server/Workstation axis), `assessment_status` (`Automated` for `role="full"`, `Manual` for `unscored`), `cis_controls` (`[{ "8": ["5.4"], "7": ["4.1"] }]`, a one-element list holding the framework version to ids map, the form MITRE's CIS baselines write, from the ident `controlURI`s and the safeguards; the InSpec generators are taught to render a map as a Ruby hash; the catalog stays in `passthrough.cisSafeguards`), `cci` and `nist` from the CIS Controls to CCI mapping (card 15), `cce` when present | `cce`, and from `reference` by framework (cross-references to other publishers' ids, including the `stig_id` of the DISA rule an SSG rule implements): `nist` (the ids as SSG publishes them, 800-53 Revision 4, translated to the selected revision on output), `srg`, `stig_id` (a list: a rule can implement several DISA rules), `stig_rule_id` (the DISA requirement id of each, the `SV-` reference with its revision removed, `SV-258134`, which is that requirement's own id in a DISA Baseline; the `V-` reference carries the same digits and gets no tag), `cis_controls`, `cis_id` (a list of the CIS benchmark numbers the rule cites) and `cci` when the file cites one; every reference, these and those of every other framework (ISO 27001, ISA 62443, COBIT, CSF, HIPAA, NERC CIP, PCI DSS, ANSSI, BSI, ISM, NIAP, CJIS), stays in `refs` with its text and address, as the converter already writes them, so no second copy is kept; frameworks are matched by a table of URL patterns because the hrefs change between releases |
| Descriptions | `default` from `VulnDiscussion`, `check`, `fix`; the ten sub-elements as tags | `default`, `rationale`, `fix`; `check` when inline content exists (the six CIS fixtures carry no separate audit, default-value or impact elements) | `default`, `rationale`, `warning`; `fix` is the shell `fix` script, because SSG publishes no `fixtext` (0 of 1,540 RHEL 9 rules), and the scripts for the other systems (Ansible and six smaller ones, about 5 MB in the RHEL 9 build) are not carried yet: where they live is deferred until the hardening generator needs them |
| Severity model | `high`/`medium`/`low` → impact 0.7/0.5/0.3, CAT I/II/III | none in the file: `severity` medium and impact 0.5, the convention MITRE's CIS baselines use | `high`/`medium`/`low` as DISA; `unknown` (3% to 7% of rules in v0.1.82) becomes medium and 0.5, which is DISA's own rating for the four `unknown` rules in RHEL 9's STIG profile |
| `inspec.yml` | `name` kebab of the benchmark id, `version` `<version>.<release>.0` | `name` the benchmark slug with `-cis` (`google-chrome-cis`), `version` as published (`2.1.0`) | `name` the id after `_benchmark_`, `version` as published |
| Ansible (ADR-0018) | `cat1`–`cat3`, toggles `<role>_sv_NNNNNN` | `level1`–`level3`, toggles `<role>_rule_1_1_11`; upgrade matching needs the title tier because CIS renumbers sections between versions | the short name as key (proposed); decided with the ADR-0018 work |

**One builder, one table.** The family table is data: `hdf-converters/shared/xccdf-families.json`, loaded by both
parsers and the InSpec generator, with a schema and a test that every row is exercised by a fixture. One
rule-identity builder per language, keyed by family, serves the benchmark path and the results path, so a CIS rule
gets the same tags whether it arrives as a benchmark or inside scan results; this replaces the two builders
(`buildBaselineTags` and `buildTags`) and changes the results path, which earlier revisions left out of scope.
Tools that assume a DISA STIG keep accepting any family: the CKL, CKLB and XCCDF exporters already do, and
`hdf generate upgrade --id-type cis`, which overwrites each id with the raw `rid`, is changed to keep the id the
converter wrote.

`cci` and `nist` on CIS rules come from `mitre/cis-cci-mappings`, the validated CIS Controls (v7, v8, v8.1)
safeguard-to-CCI crosswalk (472 mappings, every v8 safeguard covered, each with a primary CCI, supporting CCIs,
confidence and the NIST control), vendored into `hdf-mappings` as a family beside CCI, CWE and the others (card 15)
and resolved per safeguard in `cis_controls`, for every Controls version the crosswalk covers, the results merged,
deduplicated and sorted (the placeholder safeguard `0.0` is skipped): `cci` from the crosswalk's primary CCI, `nist`
from the crosswalk's own validated `nist_control`, both exposed by `hdf-mappings` as CIS-to-CCI and CIS-to-NIST lookups. The existing
CCI-to-NIST table is a test cross-check on the crosswalk, not the source. A safeguard the crosswalk does not cover
(one v7 sentinel) contributes nothing, so the tags are absent, never empty. The DISA family keeps every tag it
has today. One DISA value changes: a rule with no CCI that carries DoD Instruction 8500.2 IA controls (the manuals
of 2009 to 2015 and a few still published) gets `nist` from DoD CIO's 2014 crosswalk of those controls to SP 800-53
Revision 4, vendored into `hdf-mappings`, and no `cci`, because DoD assigned none (register gap 18). A DISA rule
with neither carries `nist: []` today; the proposal is to leave the tag out, as every other converter does for
an unmapped requirement. The CIS and SSG
rows are chosen to match the profiles already in use (MITRE's CIS baselines, SAF CLI's `--idType cis`), so the
upgrade matcher meets prior work that looks like its own output.

## Consequences

**What becomes easier:**

- Any consumer can tell two releases of one benchmark apart, filter rules by DISA or CIS marker, read CIS levels and
  controls, and resolve a safeguard URN to its title and groups, without touching XML.
- A profile generated by `hdf` and one generated by SAF CLI carry the same version string.
- The next missing XCCDF field is a CI failure with a named path, not a consumer bug.

**What becomes harder:**

- Every benchmark-path golden under `fixtures/expected/` changes: the three that existed when this was first written
  (`benchmark-minimal-1.1`, `benchmark-minimal-1.2`, `benchmark-ssg-nested-groups`) and the DISA and CIS goldens
  added since. Nothing else compares a benchmark Baseline byte for
  byte: `hdf-fixtures/baseline/` holds static files, the CLI tests assert by `Contains` and schema, the generator and
  MCP goldens have no XCCDF input.
- The allowlist is one more file to update when a field is added — which is the point.
- The passthrough and tag keys become a contract: `benchmarkRelease`, `benchmarkDate`, `cisSafeguards`,
  `documentShape`, `xccdfVersion`, `benchmarkFamily`, the CIS family tags of decision 6, the ten sub-element names.
  They are chosen here; renaming later is a breaking change for consumers.
- Every CIS and SSG golden changes shape once decision 6 lands (the STIG tags leave, the family tags arrive); the
  DISA goldens do not. The generated CIS profile changes completely, which is the point.
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

- Settled 2026-11-20: the CIS slug is the benchmark title without the leading `CIS ` and trailing ` Benchmark`,
  kebab-cased (`google-chrome`); it never includes `-cis` itself. A requirement id is `<slug>-cis-<number>` and the
  `inspec.yml` name is `<slug>-cis`.
- Settled 2026-11-20 and 2026-11-21: SSG references become the tags `nist`, `srg`, `stig_id`, `stig_rule_id`,
  `cis_controls`, `cis_id` and, when cited, `cci`; every reference stays in `refs`. The CIS benchmark number on an SSG
  rule uses the name a CIS rule uses for its own, `cis_id`, as a list (404 of 1,540 RHEL 9 rules cite one; 4 cite more
  than one). The `SV-` reference becomes `stig_rule_id` without its revision; the `V-` reference is the same digits on
  1,352 of 1,352 rules measured and gets no tag. SSG's 800-53 ids are written as published (`CM-6(a)`); the existing
  revision translation and id normaliser already read them. The XCCDF severity `info` is `informational`, impact 0.0,
  as the converter and the shared severity table already have it.
- Proposed 2026-11-21 by the author, not yet decided by the owner; the maintainer may change them: the `cis_controls`
  key is the major version as a string (`"6"`, `"7"`, `"8"`; the fixtures write only 6.1, 7.0 and 8.0, and the
  crosswalk's v8 and v8.1 files agree on all 150 safeguards); a DISA rule with neither a CCI nor an IA control has no
  `nist` tag (28 fixture rules; across the repository's other converters an unmapped requirement has the tag absent
  on 37 and empty on none); the SSG key for the Ansible generator is decided with the ADR-0018 work.
- Deferred 2026-11-21: where SSG's `fix` scripts for systems other than the shell live. A requirement has no
  `extensions` member, the scripts total about 5 MB in one build, and nothing reads them yet.
- Settled 2026-11-20, for now: a CIS rule's `cci` tag holds the primary CCI only; the supporting CCIs stay in the
  vendored data and the `hdf-mappings` lookup.

The key names in decision 2 otherwise remain this ADR's choice; the DISA sub-element names follow the snake_case of
the element names, and `documentable` is a boolean because the existing `hdf-fixtures` Baseline already carries it
that way.

## Implementation Plan

### Scope

**IN scope:**

- Every target in decision 2, on the benchmark path, in Go and TypeScript, with byte-identical goldens.
- `gid`/`rid` normalisation for DISA XCCDF 1.2 input; `complex-check` on the benchmark path.
- The completeness test of decision 3, with `xccdf-1.1.4.xsd` vendored and the shared allowlist.
- The two fixtures of decision 5 with provenance.
- `inspec.yml` version from the release (decision 4), and the generator's profile style per family (decisions 4 and 6).
- Identification of shape, version and family, recorded in the Baseline, and the per-family contract (decision 6).
- The SSG corpus and family row (decision 6, card 13).
- The CIS Controls to CCI crosswalk as an `hdf-mappings` family, and `cci`/`nist` on CIS rules from it (card 15).
- The converter's page under `site/docs/`, including the CKL crosswalk, and the spec line that still says a Baseline
  carries no `extensions` (`hdf-specification.md:320`).

**OUT of scope:**

- Reading the Manual XCCDF out of a DISA zip (its own issue).
- Mapping CPE platform names into `supports[]`.
- Teaching the CKL exporter to read the XCCDF tag names (its own card, when wanted).
- Filling `verificationMethod` or `applicability` from the new tags (consumers decide; ADR-0018 says why).
- Any change to the results path beyond fields it was also missing and the shared rule-identity builder of
  decision 6.
- Generated parse types (Alternative A).

### Quality Standards (inherited by every card)

- **Framework-first:** XML parsing only through the existing `encoding/xml` structs and `parseXmlWithArrays`
  (`fast-xml-parser`); no new dependency in either language. Passthrough written through the same `setIfNotEmpty` /
  `setIf` pattern the CKL path uses, under `extensions.passthrough`, flat. CCI → NIST untouched.
- **Existing patterns:** tag building moves from `buildBaselineTags` / the TS `ruleToBaselineRequirement` tag object
  into the shared family-keyed builder of decision 6;
  the fixture procedure is the `/fixtures` skill, including `provenance.txt` and goldens for every new input; tag
  values are strings, booleans or lists of strings, never objects, except `cis_controls` (decision 6).
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

Cards under one epic. Each is one TDD loop and one review (1–5 story points), inherits the Quality Standards,
and points its `Prior art checked` section at this ADR's Prior Art table. Go and TypeScript land in the same card.
The first ten cards totalled 27 story points; cards 11 to 15 were added on 2026-10-29. The board holds the current
set and sizes.

| # | Card | sp | Blocked by |
|---|---|---|---|
| 1 | Vendor `xccdf-1.1.4.xsd` with provenance | 1 | — |
| 2 | Add the RHEL 9 V2R9 and CIS Chrome benchmark fixtures | 3 | — |
| 3 | Add the XSD walker and the allowlist, with every current field mapped and every gap listed as `skip` | 5 | 1 |
| 4 | Add the arrival assertion over the allowlist | 3 | 2, 3 |
| 5 | Carry benchmark-level facts into `extensions.passthrough`, including the release parse | 3 | 4 |
| 6 | Carry `legacy_id`, `cce`, `weight`, `role`; normalise DISA `gid`/`rid`; read `complex-check` | 3 | 4, 12 |
| 7 | Carry the ten DISA description sub-elements as tags | 3 | 4 |
| 8 | Carry the CIS family row: `cis_id`, level, profiles, `cis_controls`, safeguard catalog and URL refs | 3 | 4, 12 |
| 9 | `inspec.yml` version from the release | 1 | 5 |
| 10 | Regenerate the goldens, write the docs page with the CKL crosswalk, fix the spec line | 2 | 5–8 |
| 11 | One real fixture per measured DISA and CIS deviation, with the register (added 2026-10-29; done) | 5 | 2 |
| 12 | Identify shape, version and family; record them; scope every tag to the family; carry check-content descendants; no empty tags (decision 6) | 5 | 4, 11 |
| 13 | The SSG corpus: real `ssg-*-xccdf.xml` builds per measured deviation, the SSG family row decided from them | 3 | 11 |
| 14 | The InSpec generator renders the profile style per family (decision 4) | 3 | 12 |
| 15 | Vendor `mitre/cis-cci-mappings` (v7, v8, v8.1) into `hdf-mappings` with provenance; `cci` and `nist` on CIS rules from `cis_controls` through it | 3 | 8 |

Cards 6 and 8 are re-scoped by this revision: card 6 emits its DISA tags only on the `disa-stig` family; card 8
emits the CIS family row of decision 6 (not URNs, not `["L1","L2"]`), and both depend on card 12. Card 10 documents
the families. Card 12 comes before 6 and 8; the vendor schemas of the later vendor-schema card are derived per family.

On the board (epic `hdf-libs-lrgu7`) the cards above are: 1 `lrgu7.1`, 2 `lrgu7.2`, 3 `lrgu7.11`, 4 `lrgu7.12`,
5 `lrgu7.13`, 6 `lrgu7.14`, 7 `lrgu7.15`, 8 `lrgu7.16`, 9 `lrgu7.17`, 10 `lrgu7.18`, 11 `lrgu7.21`. Cards 1 to 5, 7,
9 and 11 are done. The identification part of card 12 is `lrgu7.24`; the rest of card 12 and cards 13 to 15 are
created by `lrgu7.23` from the decided register. Two board cards have no number here: `lrgu7.19` (prose inside XHTML
children, done) and `lrgu7.20` (vendor schemas for the DISA and CIS vocabularies).

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
  emits the union path set, identical in Go and TS (628 paths as built, pinned in `fixtures/xccdf-coverage.json`); every path is in the allowlist or the
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

**Card 8: The CIS family row (re-scoped 2026-10-29).**
- Files: as card 5
- ACs: on `cis` Baselines only: `cis_id`, `cis_level` (lowest selecting level, `Level 1`–`Level 3`),
  `cis_profiles`, `assessment_status` from `@role`, `cis_controls` as a one-element list holding the
  framework-version-to-ids map from both the
  ident `controlURI`s and the safeguards, deduplicated, sorted; `extensions.passthrough.cisSafeguards[]` with title,
  implementation groups (from the `igN` attributes), asset type and security function per framework, deduplicated on
  urn, sorted; `ident system="URL"` into `refs`; no STIG tag and no empty tag on any CIS rule; identical between the
  two parsers on every CIS fixture; no CIS key on the DISA fixtures; goldens and allowlist updated.

**Card 12: Identification and the family-scoped tag set.**
- Files: `go/converter.go`, `typescript/converter.ts` (a `identifyBenchmark` step before the benchmark path's tag
  builder; the fingerprint label), `go/fingerprint.go`, `typescript/fingerprint.ts`, their tests, goldens, the
  allowlist (rows keyed by family where a target is family-specific)
- ACs: every fixture in `fixtures/input` is identified with the family and version its register row states and the
  three keys are in its Baseline; the DISA tag set appears only on `disa-stig` Baselines and every DISA golden is
  unchanged apart from the three keys; no CIS or SSG rule carries `check_id`, `fix_id`, an empty `nist`, or a `stig_id` taken from `Rule/version` (an SSG
  rule's `stig_id` comes only from its DISA `reference`, decision 6);
  check text arrives for the ESX 3.5 rules from the `ecl:` children; a file with no signal is `unknown` with the
  generic tags only and a warning; Go and TS identical.

**Card 13: The SSG corpus and family row.**
- Files: `fixtures/input/<ssg builds>`, goldens, `provenance.txt`, `README.md`, the allowlist
- ACs: real ComplianceAsCode build products (`ssg-<product>-xccdf.xml`, at least the oldest and newest release the
  project publishes and one data-stream-derived file), trimmed by whole elements with provenance; the SSG shapes
  measured (references by framework, profiles, `cce`, severity, nested Groups) and recorded in the register; the SSG
  row of decision 6 filled in from them, with the owner's yes on the tag names.

**Card 15: CIS Controls to CCI, and NIST on CIS rules.**
- Files: `hdf-mappings/src/data/cis-cci-mapping-v{7,8,8.1}.json` with their schema and a provenance record (source
  repository, commit, sha256 as retrieved), `hdf-mappings/src/cis/`, `hdf-mappings/go/cis/`, their tests, the
  converter's CIS family row, goldens, the allowlist rows for `cci` and `nist` on CIS fixtures
- ACs: `CISToCCI(version, safeguard)` (primary, supporting available) and `CISToNIST(version, safeguard)` (the
  crosswalk's `nist_control`) in both languages, byte-identical results from one shared vector table; a test
  cross-checks every entry's primary CCI against the existing CCI-to-NIST table and records the disagreements; a CIS
  fixture rule with safeguards 5.4 (v8) and 4.1 (v7) carries `cci` and `nist` in its golden; an unmapped safeguard
  yields no tag; the `hdf-mappings` README table gains the two rows.

**Card 14: The generator's profile style per family.**
- Files: `hdf-generators/go/`, `hdf-generators/src/`, their tests, the generator docs
- ACs: control ids, `inspec.yml` `name` and `version`, and description labels follow the family row; a CIS profile
  generated from the Chrome fixture has `control 'google-chrome-cis-1.1.1'` with the CIS tags and no STIG tag; a DISA
  profile is unchanged; an `unknown` Baseline renders the generic style with a notice; a map-valued tag
  (`cis_controls`) is written as a Ruby hash in both languages; `inspec check` passes on each generated profile; Go
  and TS byte-identical.

**Card 9: `inspec.yml` version from the release.**
- Files: `hdf-generators/go/generator.go`, `hdf-generators/src/inspec-yml.ts`, their tests
- ACs: `version: '2.9.0'` from the V2R9 Baseline; `version: '2'` when `benchmarkRelease` is absent; Go and TS
  identical.

**Card 10: Goldens, docs, spec line.**
- Files: the three existing benchmark-path goldens, `site/docs/` converter page,
  `site/docs/specification/hdf-specification.md:320`
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
