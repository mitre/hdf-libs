# ADR-0024 gap register — identification and the per-family contract

Working register for the 2026-10-29 reshaping of ADR-0024 (decision 6). Every gap below must be covered by a
card on the `hdf-libs-lrgu7` epic or recorded here as deliberately deferred, before implementation continues.
Gaps 1 to 17 were decided or confirmed by the owner on 2026-11-20, and gap 18 was found and decided the same day, each against the evidence quoted in its row; the
`hdf-libs` maintainer reviews the set and may change it. "Covered by" is filled in by `hdf-libs-lrgu7.23`; "Status" is `open`, `decided` (with the decision), or
`deferred` (with the owner's reason). The three design artifacts at the end are decided here and
then move into ADR-0024 and the shared vector files the cards create.

## A. Gaps

### Identification and identity

| # | Gap | Decision needed | Status | Covered by |
|---|---|---|---|---|
| 1 | **One identifier, one owner.** Shape, version and family are decided in three places that share no code: the registry fingerprint (root element only), `parseRoot` plus the `TestResult` check, and nothing for family. | A single `identify(input) → {shape, version, family}` in the converter package per language, called by the fingerprint label, the CLI "Detected:" line, the MCP convert tool and both conversion paths, with its cases in one shared JSON vector. | decided 2026-11-20: one `identify` function per language in the converter package, called by the converter, the auto-detect fingerprint label, the CLI's `Detected:` line and the MCP convert tool; cases in one shared JSON file | `lrgu7.24`, `lrgu7.26` |
| 2 | **Signal precedence.** `benchmark-minimal-*` carry `VulnDiscussion` but no `release-info`; the SCAP component carries both plus the 1.2 id prefix; SSG 1.1 builds carry none of the SSG id prefixes. | Which signals are necessary, which sufficient, when the answer is `unknown`; measured on every fixture and the corpus before coding (artifact 1). | decided 2026-10-29: artifact 1 as drafted (DISA needs both signals; synthetic minimal fixtures are `unknown`; a two-family match is an error) | `lrgu7.24` |
| 3 | **What `requirement.id` is, per family.** DISA: the SV number. CIS today: the 80-character rule id; contract says `<benchmark>-1.1.11`. SSG: the short name. `hdf diff`, the upgrade matcher, `hdf query`, the MCP tools and ADR-0018's toggles all key on it. | Change the Baseline id for CIS and SSG (downstream follows), or keep the raw id and derive the display form in the generator (every consumer re-derives). Proposal: change the id; check `hdf-diff` and `hdf-engine` first. | decided 2026-11-20: the id changes per family: DISA the SV number; CIS `<slug>-cis-<number>` (`google-chrome-cis-1.1.11`), and a CIS rule whose id carries no number (0 of 29 ESX 3.5 rules has one) keeps its published id; SSG the short name. The full XCCDF id stays in `tags.rid` | `lrgu7.29`; consumers `lrgu7.44`, `lrgu7.45` |
| 4 | **Key and slug derivation in one place.** Benchmark slug (`inspec.yml` name, CIS control prefix), recommendation number from the rule id, SV number from `rid`, SSG short name. | Four functions, one shared vector file, called by the converter when it sets `Baseline.name` and `requirement.id`; never re-implemented in a generator. | decided 2026-11-20: derivation lives in the converter, one shared case file; the CIS slug is the title without the leading `CIS ` and trailing ` Benchmark`, kebab-cased (`google-chrome`), and never includes `-cis` itself; a requirement id is `<slug>-cis-<number>` and the `inspec.yml` name is `<slug>-cis` (two of three published MITRE CIS baselines checked name controls `<product>-cis-<number>`) | `lrgu7.29` |

### The per-family contract

| # | Gap | Decision needed | Status | Covered by |
|---|---|---|---|---|
| 5 | **Two tag builders that already disagree.** The results path's `buildTags` and the benchmark path's `buildBaselineTags` duplicate CCI, NIST, `stig_id`, `legacy_id`, `cce` and diverge on all of them. Results of a CIS scan are family-blind too. | One rule-identity builder keyed by family, used by both paths; a CIS results fixture to prove it (the results fixtures are all DISA). | decided 2026-11-20: one rule-identity builder per language, keyed by family, used by the benchmark and the results path; a real CIS scan-results fixture is found to prove it | `lrgu7.27` (benchmark path), `lrgu7.42` (results path), `lrgu7.41` (the CIS results fixture) |
| 6 | **The contract as data.** The family table (tag names, sources, descriptions, severity model) should be one shared JSON document both languages load, as the allowlist and the group-id cases already are. | Its schema; the allowlist gains a family dimension (a row's target may differ per family) and the arrival assertion runs per family fixture. | decided 2026-11-20: one shared `xccdf-families.json`, loaded by both converters and the InSpec generator, with a schema and a test that every row is exercised by a fixture | `lrgu7.27`, `lrgu7.28` |
| 7 | **Description structure per family.** CIS packs description, audit, remediation, default value and impact into prose; SSG has `warning` and references; DISA has the eleven sub-elements. | Which labels each family emits and from where, checked against the corpus; check-content descendant text reuses the existing inner-XML prose reader. | decided 2026-11-20: the generic labels `default`, `rationale`, `fix`, `check`, `warning`, each only when non-empty; check text from `check-content` descendants and from the first check inside a `complex-check`; for SSG the shell `fix` script is the `fix` description (1,328 of 1,540 RHEL 9 rules carry `fix` elements, 0 carry `fixtext`). Deferred 2026-11-21: the scripts for the other systems are not carried yet; a requirement has no `extensions` member, they total about 5 MB in the RHEL 9 build (Ansible 4.8 MB), and nothing reads them until the hardening generator exists | `lrgu7.33`, `lrgu7.40`; the other systems' scripts deferred |
| 8 | **Severity and impact.** `SeverityToImpact(severity, 0.5)` in `hdf-utilities` fabricates 0.5 for a rule with no severity; SSG builds also carry `severity="unknown"`, a legal XCCDF value (`info` is another). | Where the family severity model lives; what `impact` means for CIS and for `unknown`/`info`; whether a `severity` tag is ever written when the source has none; the generator renders what it is given. | decided 2026-11-20: a rule with no usable severity gets `severity` medium and impact 0.5: every CIS rule (the convention in MITRE's published CIS baselines) and an SSG rule marked `unknown` (DISA rates the four `unknown` rules in RHEL 9's STIG profile medium). `low`/`medium`/`high` pass through. `info` → `informational`, 0.0 (decided 2026-11-21: what the converter and the shared severity table already do; no real rule carries `info`, the v0.1.82 builds have it only on profile `refine-rule` lines, which are not applied) | `lrgu7.30` |
| 9 | **Profiles and levels, generic first.** DISA has `MAC-1_Classified`… profiles, SSG has `stig`, `cis_level1_server`, `anssi_*`, CIS has levels. | A generic "profiles that select this rule" tag for every family, with `cis_level` and friends as CIS sugar on top. | decided 2026-11-20: `tags.profiles` (profile ids) on every family; for CIS `cis_level` is the lowest selecting level as the string `Level 1` to `Level 3`, and `cis_profiles` lists every selecting profile's title | `lrgu7.31`, `lrgu7.16` |

### Mappings, parity mechanics, consumers, corpus

| # | Gap | Decision needed | Status | Covered by |
|---|---|---|---|---|
| 10 | **The CIS family in `hdf-mappings`.** `mitre/cis-cci-mappings` (v7, v8, v8.1; 472 entries; primary and supporting CCIs; `nist_control`). | Vendoring with provenance; CIS-to-CCI and CIS-to-NIST lookups in both languages from one vector table; which CIS version wins when a rule carries v7 and v8 ids; primary versus supporting CCIs (proposal: primary); the CCI-to-NIST table as a test cross-check, not the source. | decided 2026-11-20: vendor `mitre/cis-cci-mappings` at a pinned commit with provenance (the owner is its author; no releases, last commit 2026-02-12); `cci` holds the primary CCI only, for now; every covered Controls version the rule cites is looked up and merged, deduplicated and sorted; the placeholder safeguard `0.0` is skipped; a rule citing only v6 or none gets no `cci` tag and the default `nist` of `CM-6` (decided 2026-11-23); each safeguard is looked up in the mapping file for the exact Controls version the file states (decided 2026-11-23) | `lrgu7.34`, `lrgu7.35` |
| 11 | **Shared vectors, listed up front.** | Identification cases, key and slug cases, severity cases, family-table cases, CIS-to-CCI cases: one JSON file each, read by both suites (artifact 3). | confirmed 2026-11-20: the five case files of artifact 3, as the decisions above define them | identify cases `lrgu7.24`; key cases `lrgu7.29`; severity cases `lrgu7.30`; family table `lrgu7.27`; CIS-to-CCI cases `lrgu7.34` |
| 12 | **Consumers that assume DISA.** The CKL path (reads `stig_id`, writes `cklMetadata`), the XCCDF exporter (writes `Rule/version` from `stig_id`), `hdf generate upgrade`'s id types, ADR-0018's identity. | For each: refuse, pass through, or map, for a CIS or SSG Baseline, so none emits a STIG-shaped artifact from a CIS source. | decided 2026-11-20: pass through: the CKL, CKLB and XCCDF exporters keep accepting any family (they already do), proven by a CIS and an SSG baseline in each exporter's tests; `hdf generate upgrade --id-type cis`, which overwrites the id with the raw `rid`, is changed to keep the id the converter wrote | `lrgu7.43`, `lrgu7.44` |
| 13 | **The generator's profile style.** Control id, `inspec.yml`, description labels, tag rendering per family; parity by generating from one golden in both languages; the Ansible side reads the same row. | Decided in principle (ADR decision 4, card 14); the slug rule is an open question. | decided 2026-11-20: per-family profile style as artifact 2; the slug rule is gap 4's; both InSpec generators learn to render a map-valued tag as a Ruby hash (`formatTag` writes a map as `map[...]` today), which `cis_controls` needs | `lrgu7.36`, `lrgu7.37` |
| 14 | **The corpus has holes.** No SSG build products in `fixtures/input` (three exist in the sweep downloads, see finding F2), no results of a CIS scan, no CIS benchmark with a Level 3 profile, no data-stream fixture until 48zyh. | Measure each family before implementing its row, as `.21` did for DISA and CIS. | confirmed 2026-11-20: each family is measured on real files before its row is built. Still to find: results of a CIS scan, a CIS benchmark with a Level 3 profile. SSG: release v0.1.82 (sha512 verified) was measured and replaces the fixture whose origin was never established. The data stream waits on 48zyh | `lrgu7.25`, `lrgu7.41`; the data stream waits on 48zyh |
| 15 | **Docs and the spec.** | The site page listing every key, tag and label per family; the spec line about `extensions`. | confirmed 2026-11-20: covered by `hdf-libs-lrgu7.18` | `lrgu7.18` |
| 16 | **SSG identification signals.** The SSG 1.1 builds in the sweep (`ssg-ubuntu1604/1804/2004-xccdf.xml`, ComplianceAsCode 0.1.58) have Benchmark ids `UBUNTU-XENIAL`, `UBUNTU-BIONIC`, `UBUNTU_20-04`, bare rule ids (`prefer_64bit_os`) and no `xccdf_org.ssgproject.content_` prefix anywhere. | SSG signals beyond the id prefix: `version/@update` pointing at `github.com/ComplianceAsCode/content`, `style="SCAP_1.1"`, profile ids (`stig`, `cis_level1_server`, `anssi_*`, `standard`), the `reference` href set (ISO 27001, ISA 62443, COBIT, CIS Controls). Measured on the SSG corpus (card 13). | measured 2026-11-20, confirms artifact 1 unchanged: `version/@update` is a `github.com/ComplianceAsCode` URL in 6 of 6 builds; the id prefix is on the four v0.1.82 builds and absent on the two 0.1.58 builds | `lrgu7.25`, `lrgu7.24` |
| 17 | **SSG references as cross-family identity.** SSG rules carry thousands of `reference` elements keyed by `href` (CIS Controls, ISO, ISA, COBIT; NIST and STIG ids in newer builds) and no `ident` in these builds. | How references land (tags by framework, `refs`, or passthrough), decided from the measured corpus; this is where an SSG rule's STIG and CIS cross-references come from. | decided 2026-11-20: the references existing HDF consumers read become tags under the names already in use (`nist`, `srg`, `stig_id`, `cis_controls`, `cis_id`, `cci`) plus one new name, `stig_rule_id`; frameworks are matched by a table of URL patterns (24 distinct hrefs in RHEL 9 v0.1.82, and they change between releases). Decided 2026-11-21 on the v0.1.82 builds: the CIS benchmark number is `cis_id` as a list (RHEL 9: 404 of 1,540 rules cite one, 400 one number, 3 two, 1 seven); the `SV-` reference becomes `stig_rule_id` with the revision removed, the DISA requirement's own id in a DISA Baseline, and the `V-` reference gets no tag (same digits as the SV on 1,352 of 1,352 rules across four builds; the three always appear together); 800-53 ids are written as published; a CCI the file cites becomes `cci` (0 of 4,826 rules in the four v0.1.82 builds cite one; the 0.1.58 builds are measured when their fixture lands). Corrected 2026-11-21: every `reference` already lands in the requirement's `refs` with its text and address, so the other frameworks need no `passthrough.references`; that copy is dropped | `lrgu7.38` (recorded), `lrgu7.39` (cards the row) |
| 18 | **DISA rules with no CCI.** 67 rules in five DISA fixtures have no CCI ident and get `nist: []`: the 2009 to 2015 manuals and the Multifunction Device STIG still in DISA's library (1 CCI in 22 rules). 39 of them carry DoD Instruction 8500.2 IA controls (`DCBP-1`) in `IAControls`. | Whether those rules can carry a real `nist` value, and from what source. | decided 2026-11-20: a DISA rule with no CCI gets `nist` from its IA controls through DoD CIO's "DoDI 8500.2 - NIST SP 800-53 Rev 4 Crosswalk" (2014-12-22, 157 IA controls; the CCI list holds no 8500.2 reference), vendored into `hdf-mappings` and converted to JSON; no `cci` tag is derived, because DoD assigned none and a control ties to between 2 and 88 CCIs; values are stored at Revision 4 and translated on output; five malformed values are corrected (`CA-(2)` is CA-2(2); `SC-12-(2)(4)`, `SC-12-(2)(5)` and `SC-12-(4)(5)` are the SC-12 enhancements named). A rule with a CCI keeps the `nist` its CCIs give. Decided 2026-11-23: the 28 rules with neither get `nist: ["CM-6"]`, the repository's existing default for a configuration check with no specific mapping, and the same default applies to a rule of any family with no NIST mapping | `lrgu7.46`, `lrgu7.47` |

## B. Findings log

- **F1 (2026-10-29).** The benchmark path applies the DISA STIG tag set to every family: CIS and SSG rules get `stig_id: ""`, `nist: []`, `check_id` = the OVAL system URL; the InSpec generator writes all of it. Root cause: no family identification anywhere. Four "findings" from the `.21` review were this one defect.
- **F2 (2026-10-29).** Three real SSG builds were in the CIS sweep's downloads (ts-inspec-objects test data), misfiled as CIS by their directory; they are XCCDF 1.1 with ids `UBUNTU-XENIAL` etc. The earlier "433 of 435 CIS files carry the cis prefix" claim counted them as CIS; the correct count is 433 of 433 real CIS files, plus two synthetic test files, plus three SSG builds and five DISA files in the same sweep. The DISA signals (`release-info`, `VulnDiscussion`) appear in 2,548 of 2,548 DISA files and in no CIS or SSG file.
- **F3 (2026-10-29).** Four DISA pre-release manuals (`V1R0.x`) use product-prefixed rule ids (`RHEL-N-N_rule`) rather than `SV-`; they still carry `release-info` and `VulnDiscussion`. `SV-` ids are a confirming signal, not a necessary one.
- **F4 (2026-10-29).** The `check-content/*` allowlist skip (card `.11`) drops the audit command of 2006–2016 CIS content (`ecl:shell-command` children). Reversed by ADR decision 2.
- **F6 (2026-11-20).** The four findings handed over by the `lrgu7.21` review each belong to a gap: impact 0.5 on a
  rule with no severity is gap 8; the baseline name built from the prefixed Benchmark id is gap 4; ESX `ecl` check
  content not carried is F4 and gap 7; empty `stig_id` and `nist` tags are F1, owned by gaps 5 and 6 (the
  family-keyed builder and table). Cards: impact 0.5 `lrgu7.30`; baseline name `lrgu7.29`; `ecl` check content
  `lrgu7.33`; empty `stig_id` and `nist` on CIS and SSG rules `lrgu7.27`.
- **F7 (2026-11-20).** Both InSpec generators write a map-valued tag as Go's or JavaScript's default text
  (`map[8:[5.4]]`), which is not valid Ruby; `cis_controls` in the published form needs them fixed (gap 13).
- **F8 (2026-11-20).** CIS files cite a placeholder safeguard `0.0` (5 of 6 Visual Studio Code GPO rules); it maps
  to nothing and is skipped. Chrome v1.2.0 cites only Controls v6.1, which the crosswalk does not cover.
- **F9 (2026-11-20).** On the 31 fixture rules that cite Controls v7 and v8, the two versions' CCIs are the same on
  8 (5 of them only the placeholder), overlap on 3 and share nothing on 20. One identically titled safeguard
  ("Maintain and Enforce Network-Based URL Filters", v7 7.4 and v8 9.3) maps to SC-7 in v7 and SI-7 in v8.
- **F10 (2026-11-20).** `hdf generate upgrade --id-type cis` replaces each id with the raw `rid` (gap 12).
- **F11 (2026-11-20).** SSG publishes no `fixtext`; its remediation is `fix` scripts per system, dropped today
  (gap 7). SSG severities in v0.1.82: `unknown` on 120 of 1,701 RHEL 8 rules, 54 of 1,540 RHEL 9, 34 of 1,073
  RHEL 10, 33 of 938 OL 9, 44 of 946 SLE 15, 22 of 639 Ubuntu 22.04; inside the STIG profile 2, 4, 4, 4, 0 and 1.
- **F12 (2026-11-20).** Every DISA fixture rule that has a CCI has a filled `nist`; the 67 with `nist: []` have no CCI in
  the published file. Across the 43 converters with goldens, `nist` is filled on 5,243 requirements, absent on 37 and
  empty on 201, all 201 from this converter. The original crosswalk spreadsheet (sha256 `fb96bd3d…2a4187`) matches a
  public copy on 157 of 157 entries; 40 values need a stated clean-up rule and all 32 IA control codes in the
  fixtures are covered (gap 18).
- **F5 (2026-10-29).** `mitre/cis-cci-mappings` was listed as "later work" in ADR-0024's out-of-scope list; it is the source of `cci` and `nist` on CIS rules and is now card 15.

## C. Artifact 1 — identification rules (signed off 2026-10-29)

Decided once, in order; the first rule that matches wins; a file that matches none is `unknown`.

**Shape** (from the root element and the `TestResult` child, as the code already does):
`data-stream-collection` → not read (48zyh); `asset-report-collection` → `arf`; `Benchmark` with a `TestResult` → `results`; `Benchmark` without → `benchmark`; anything else → not XCCDF.

**Version:** the `Benchmark` element's namespace, `…/xccdf/1.1` → `1.1`, `…/xccdf/1.2` → `1.2`; recorded, never used to choose a parser.

**Family:**

| Order | Family | Rule | Coverage (2026-10-29 corpora) |
|---|---|---|---|
| 1 | `disa-stig` | `plain-text[@id="release-info"]` present **and** at least one rule description carries `<VulnDiscussion>` | 2,548 / 2,548 DISA files (2009–2026, every library, the SCAP benchmark components, the pre-release manuals); 0 CIS, 0 SSG |
| 2 | `cis` | Benchmark id starts `xccdf_org.cisecurity.benchmarks_` or `cis_`, **or** a `cisecurity.org` namespace (`20-cc`, `controls`, `check`, `notes`, `ae`) is used by an element | 433 / 433 real CIS files, 2006–2026 |
| 3 | `ssg` | Benchmark id starts `xccdf_org.ssgproject.content_`, **or** `version/@update` is a `github.com/ComplianceAsCode` URL | 6 of 6 builds measured 2026-11-20: four at v0.1.82 by both signals, two 0.1.58 builds by `@update` alone |
| 4 | `unknown` | none of the above | `benchmark-minimal-1.1/1.2`, `minimal`, `empty`, `arf-minimal` (synthetic; `VulnDiscussion` alone is not enough) |

Confirming signals, recorded but not decisive: `SV-…_rule` ids and `xccdf_mil.disa.stig_` prefixes (DISA);
`Level N` profile titles and `cis_controls` metadata (CIS); profile ids `stig`, `cis_level1_server`, `anssi_*` and
the reference href set (SSG). A file matching two families' rules is an error the detector reports, not a guess;
none was found.

Recorded in `extensions.passthrough` as `documentShape`, `xccdfVersion`, `benchmarkFamily`.

## D. Artifact 2 — the family table (decided 2026-11-20)

Becomes `hdf-converters/shared/xccdf-families.json`, loaded by both parsers and by the InSpec generator; one
document, one schema, read-only at runtime. The rules below are what the JSON encodes; the code holds no family
knowledge outside it except the handful of derivation functions of artifact 3.

**Facts from the sources that the table rests on.** XCCDF `severity` is one of `unknown`, `info`, `low`, `medium`,
`high` (both XSDs); HDF `severity` is `critical`, `high`, `medium`, `low`, `informational`, and `impact` is required
on every Baseline requirement. XCCDF `role` is `full`, `unscored`, `unchecked`. The upgrade and diff matcher pairs
requirements by exact id first, then mapped id, CCI, SRG and fuzzy title, so a per-family `requirement.id` is matched
by string equality within a family and by the title tier across renumberings. `hdf query` resolves an id against
`stig_id`, `gid`, `gtitle` and `id`.

**Generic row, every family** (what XCCDF itself defines, under the tag names this repo already uses):

| Field | Source | Rule |
|---|---|---|
| `requirement.id` | per family key, below | never the raw 80-character CIS id |
| `tags.rid`, `tags.gid`, `tags.gtitle` | `Rule/@id`, enclosing `Group/@id`, `Group/title` | the repo's established names for the XCCDF rule id, group id and group title (every golden and `hdf query` read them); kept on every family, as published, DISA 1.2 prefixes stripped; `gid`/`gtitle` absent when there is no Group |
| `tags.severity` | `Rule/@severity` | `low`/`medium`/`high` as is; `unknown` or absent → `medium` (decided for CIS, where the file gives none, and for a rule marked `unknown`; the owner chose it as one rule for every family); `info` → `informational` |
| `impact` | `tags.severity` | 0.3 / 0.5 / 0.7, `informational` → 0.0; no usable severity → 0.5 with `severity` medium, the convention in MITRE's CIS baselines and DISA's rating for the SSG rules checked |
| `tags.profiles` | the `Profile`s whose `select` names the rule or its Group | list of profile ids, document order; every family |
| `descriptions` | `description` → `default` (DISA: the `VulnDiscussion` body); `rationale`; `fixtext` → `fix`; `check-content` descendant text → `check`; `warning` | a label only when the text is non-empty |
| `refs` | `reference` (href + text), `ident[@system="URL"]` | every family |
| `tags.nist` | per family, below | never empty and never absent: a rule with no mapping gets `["CM-6"]` |
| `tags.cce` | `ident` with a CCE system | when present |
| passthrough | `documentShape`, `xccdfVersion`, `benchmarkFamily` plus the benchmark facts of decision 2 | every family |

**Family rows:**

| | `disa-stig` | `cis` | `ssg` | `unknown` |
|---|---|---|---|---|
| Stable key | SV number from `rid` (`SV-257777`) | `<slug>-cis-<ref>`: `<slug>` = benchmark title minus leading `CIS ` and trailing ` Benchmark`, kebab (`google-chrome`), and never includes `-cis` itself; ref = the recommendation number parsed from the rule id (`_rule_1.1.11_` → `1.1.11`), giving `google-chrome-cis-1.1.11`; a rule whose id carries no number keeps its published id | the rule short name (`disable_prelink`; after `_rule_` when the id is prefixed) | `rid` as published |
| Identity tags (on top of the generic row) | `stig_id` (`Rule/version`), `cci`, `nist` (CCI table), `check_id` (`check/@system`), `fix_id`, `legacy_id`, `weight`, `role`, `documentable` and the ten sub-elements; these are DISA facts read from the DISA elements (`Rule/version`, `check/@system`, `fixref`) and are read that way on no other family; an SSG rule gets `stig_id` only as a cross-reference, from its DISA `reference` | `cis_id`, `cis_level` (`Level N`, lowest among selecting profile titles), `cis_profiles` (those titles), `assessment_status` (`full` → `Automated`; `unscored`, `unchecked` → `Manual`), `cis_controls` (`[{"8.0": ["5.4"], "7.0": ["4.1"]}]`, keyed by the exact Controls version the file states, the form in MITRE's CIS baselines, from `controlURI` systems and safeguards), `cci` and `nist` from the crosswalk (every covered CIS Controls version the rule cites, merged; primary CCI; placeholder `0.0` skipped) | from `reference` by a table of URL patterns per framework: `nist` (800-53, as published), `srg`, `stig_id` (list), `stig_rule_id` (list; the `SV-` reference without its revision), `cis_controls` (`cisecurity.org/controls`), `cis_id` (list; `cisecurity.org/benchmark/…`) and `cci` when cited; the remaining frameworks (800-171, CSF, ISO 27001, ISA 62443, COBIT, HIPAA, PCI, NERC, CJIS, ANSSI, BSI, ISM, NIAP) stay in `refs`, where every reference already is | none |
| `description` meaning | DISA body split into `VulnDiscussion` and the sub-elements | prose; audit text is in `check-content` when inline | prose; the shell `fix` script is the `fix` description, and the `fix` elements for the other systems (`ansible`, `kickstart`, `kubernetes`, `puppet`, `anaconda`, `blueprint`, `bootc`) are not carried yet (deferred) | prose |
| `inspec.yml` | `name` kebab of the benchmark id; `version` `<version>.<benchmarkRelease>.0` | `name` the slug with `-cis` (`google-chrome-cis`); `version` as published | `name` the id after `_benchmark_` or the id itself; `version` as published | `name` kebab of the id; `version` as published |
| Ansible (ADR-0018) | `cat1`–`cat3`; `<role>_sv_NNNNNN` | `level1`–`level3`; `<role>_rule_1_1_11` | key the short name: `<role>_<short name>`, lowercased, any other character as `_`; switches by severity, `<role>_high`, `<role>_medium`, `<role>_low` (decided 2026-11-23) | not generated |

**Decisions this artifact takes (each is a gap row above):**

- Gap 3: `requirement.id` changes per family. The matcher and `hdf query` keep working by string equality;
  `hdf query`'s id resolution gains `cis_id`.
- Gap 5: one identity builder, keyed by `benchmarkFamily`, for the benchmark and results paths; the results path's
  extra fields (`legacy_id`, `cce`) move into the generic and DISA rows.
- Row 2 correction (2026-10-29): `gid`, `rid`, `gtitle` stay on every family; they are this repo's names, not
  new ones; `stig_id`, `check_id`, `fix_id` are read from the DISA elements on DISA files only (an SSG rule's `stig_id` comes from its DISA `reference`, gap 17). One tag name is new: `stig_rule_id` (gap 17).
- Gap 8: the severity rule in the generic row; a rule with no usable severity gets `severity` medium and `impact`
  0.5.
- Gap 9: `tags.profiles` is generic; `cis_level` and `cis_profiles` are the CIS reading of it.
- Gap 17: SSG references become tags for the frameworks HDF consumers already read (`nist`, `srg`, `stig_id`,
  `stig_rule_id`, `cis_controls`, `cis_id`, and `cci` when cited); every reference stays in `refs`.
- Decided 2026-11-23: the `cis_controls` key is the exact Controls version the file states; a rule with no NIST
  mapping gets `CM-6`; SSG rules in generated Ansible are keyed on the short name and grouped by severity.
- Not changed by this artifact: the ten DISA sub-element tags, the benchmark-level passthrough keys, the results path's
  status handling.

## E. Artifact 3 — shared vectors (confirmed 2026-11-20)

One JSON file each, read by the Go and TypeScript suites, beside the existing `xccdf-group-id-cases.json`:

| Vector | Cases | Consumed by |
|---|---|---|
| `xccdf-identify-cases.json` | every fixture plus minimal synthetic heads: expected shape, version, family | `identify` in both parsers, the fingerprint |
| `xccdf-key-cases.json` | SV from `rid`, recommendation number from CIS rule ids (SAF's regex cases), SSG short names, benchmark slugs from titles | key and slug derivation |
| `xccdf-severity-cases.json` | `high`/`medium`/`low`/`unknown`/`info`/absent per family → impact and tag | severity model |
| `xccdf-families.json` | the family table itself | both tag builders, the generator |
| `cis-cci-cases.json` | safeguard → primary CCI, NIST control, per CIS version; unmapped sentinel | `hdf-mappings` CIS family |
