# xccdf-results-to-hdf fixtures — register

One row per file in `input/`, saying what the file is here to prove. The
facts behind each row (source path, trim, validation, what the full file
holds) are in `provenance.txt`; the goldens in `expected/` are generated, not
sourced (`go test ./converters/xccdf-results-to-hdf/... -run TestSnapshots -update`).

Every input is read by the golden tests in both languages (Go `TestSnapshots`,
TypeScript `snapshot.test.ts`) and must have a golden or a `no-golden.txt` line.
"Read by" lists what else reads it: `coverage` is the arrival assertion over
`xccdf-coverage.json` (Go `coverage_test.go`, TS `coverage.test.ts`), which
names the fixture that proves each mapped field; `converter` is a targeted
assertion in `go/converter_test.go` and `typescript/converter.test.ts`;
`cli` is `hdf-cli/cmd/hdf/cmd/converter_xccdf_test.go` or another CLI test.

`sha256` is of the source bytes as retrieved (the zip member, or the mirror
file at the commit named in `provenance.txt`); for a trimmed fixture the
fixture's own hash is in `provenance.txt`. Rows marked `(fixture)` have no
retrieval record, so the hash is of the file itself.

## DISA STIG benchmarks

| Fixture | Format | Era / date | Source | sha256 | Proves | Read by |
|---|---|---|---|---|---|---|
| `U_AntiSpywareGeneral_V4R1_Manual-xccdf.xml` | XCCDF 1.1 benchmark | 2009-12-03, Release 1 | DISA STIG Library Oct 2015 (Wayback capture) | `9a608191…` | The original 2009 vocabulary: ten description sub-elements, no `IAControls`, the severity guidance spelled `SecurityOverrideGuidance` (empty), undated `status`, no `ident`, no `weight`; a `notice` id that is not an NCName | snapshots |
| `U_ISA2006Policy_V1R2_Manual-xccdf.xml` | XCCDF 1.1 benchmark | 2010-06-25, Release 2 | DISA STIG Library Oct 2015 (Wayback capture) | `ca883bf9…` | The 2010 vocabulary: `IAControls` added (filled) while the old guidance spelling remains; a Benchmark id with parentheses, not an NCName | snapshots |
| `U_Mac_10.5_V1R2_STIG_Manual-XCCDF.xml` | XCCDF 1.1 benchmark | 2011-07-29, Release 2 (draft) | DISA STIG Library Oct 2015 (Wayback capture); trimmed to 9 rules | `e35d1911…` | The one release that fills `SecurityOverrideGuidance` (2 rules); one Group holding two Rule revisions of the same `SV-` id | coverage, converter |
| `U_Microsoft_IE8_V1R19_Manual-xccdf.xml` | XCCDF 1.1 benchmark | 2015-07-24, Release 19 (sunset) | DISA STIG Library Oct 2015 (Wayback capture); trimmed to 9 rules | `5f30ad35…` | The one DISA Manual STIG with a Benchmark `Value` (bound by `check-export`) and a Benchmark `platform`; filled `ThirdPartyTools` and `PotentialImpacts`; a CCE ident and an ident labelled `cve.mitre.org` carrying a CCE; repeated `Responsibility` | coverage, converter |
| `U_SLES_V11_for_System_z_STIG_V1R12_Manual-xccdf.xml` | XCCDF 1.1 benchmark | 2018-10-26, Release 12 (sunset, still served) | dl.dod.cyber.mil zip; trimmed to 16 rules | `be232286…` | The filled prose sub-elements (`FalsePositives`, `Mitigations`, `SeverityOverrideGuidance`, `MitigationControl`, `IAControls`, repeated `Responsibility`), `Documentable` true; CCE idents beside CCIs; all CRLF | coverage, converter |
| `U_zOS_IBM_Health_Checker_for_ACF2_V6R3_STIG_Manual-xccdf.xml` | XCCDF 1.1 benchmark | 2022-11-23, Release 3 | DISA SRG-STIG Library April 2025 zip | `15142a60…` | The post-2020 renumbering: `cyber.mil/legacy` idents (`SV-` and `V-`) beside the `cyber.mil/cci` ident; `generator` and `conventionsVersion` plain-text; smallest such file | snapshots |
| `U_RHEL_8_V1R12_STIG_SCAP_1-2_Benchmark-xccdf.xml` | XCCDF 1.2 benchmark (SCAP 1.2 data-stream component) | 2024-01-24, Release 1.12 | dl.dod.cyber.mil SCAP 1.2 benchmark zip; the `xccdf:Benchmark` component of its data stream, trimmed to 6 rules | `2f1b0ce6…` | DISA's SCAP benchmark shape: `xccdf:` prefix, `style="SCAP_1.2"`, `xccdf_mil.disa.stig_` id prefixes on benchmark, groups, rules and profiles, OVAL checks, a non-integer release; the data-stream wrapper itself is not read | coverage |
| `U_Multifunction_Device_and_Network_Printers_STIG_V2R15_Manual-xccdf.xml` | XCCDF 1.1 benchmark | 2025-01-30, Release 15 | dl.dod.cyber.mil zip, untrimmed | `29c57d09…` | Pretty-printed DISA XML (whitespace between tags); filled `PotentialImpacts`, `Responsibility`, `IAControls`; a duplicate Rule id as published; rules with no ident | coverage, converter |
| `U_RHEL_9_STIG_V2R9_Manual-xccdf.xml` | XCCDF 1.1 benchmark | 2026-07-01, Release 9 | dl.dod.cyber.mil zip; trimmed to 7 rules | `c9124079…` | The current DISA shape: every benchmark-level element, nine Profiles, `generator`/`conventionsVersion`, CCI idents (one rule with six), CRLF inside two rules only, every description sub-element present and empty | coverage, converter, cli |

## CIS benchmarks

| Fixture | Format | Era / date | Source | sha256 | Proves | Read by |
|---|---|---|---|---|---|---|
| `CIS_VMware_ESX_3.5_Benchmark_v1.2.0.xml` | XCCDF 1.1 benchmark | 2007-04-26 | GitHub mirror nihalshah/cs460-attack-defend (CIS-CAT), untrimmed | `611710e4…` | The 2006–2016 CIS shape: `xccdf:`-prefixed 1.1, `cisecurity.org/check` checks with `ecl:shell-command` content, interactive `Value`s, `unscored` rules, no ident, no metadata, no severity; all CRLF | snapshots |
| `CIS_Google_Chrome_Benchmark_v1.2.0-xccdf.xml` | XCCDF 1.2 benchmark | 2017-06-27 | GitHub mirror ghcetraro/business_security (CIS-CAT), untrimmed | `8e7d2809…` | The 2017–2018 CIS shape: `cc` v6.1 only, every ident an empty element with `cc:controlURI`, no `metadata`, `complex-check` wrapping each OVAL check, a Benchmark `platform`, an XHTML default-namespace redeclaration in prose | snapshots |
| `CIS_Microsoft_SQL_Server_2016_Benchmark_v1.3.0-xccdf.xml` | XCCDF 1.2 benchmark | 2021-04-22 (draft) | GitHub mirror Hkurowski/CisCat (CIS-CAT); trimmed to 17 rules | `9febf0e4…` | The 2019–2021 CIS shape: `cc6` and `cc7` namespaces, no v8; URL idents with text beside empty `controlURI` idents; `metadata` holding `notes:notes` and XHTML rather than a controls tree; two Level 1 profiles | snapshots |
| `CIS_MongoDB_4_Benchmark_v1.0.0-xccdf.xml` | XCCDF 1.2 benchmark | 2021-07-21 (draft) | GitHub mirror Hkurowski/CisCat (CIS-CAT), untrimmed | `1f7a463a…` | Irregular `controls:cis_controls` trees: empty `cis_controls`, empty `asset_type`, `implementation_groups` without `ig` attributes, empty `security_function`, a `controls:control` child, a bare `br` and XHTML under `metadata`, `notes:notes`; cc6, cc7 and cc8 idents | snapshots |
| `CIS_Google_Chrome_Benchmark_v2.1.0-xccdf.xml` | XCCDF 1.2 benchmark | 2021-12-09 (draft) | mitre/cis-bench fixture; trimmed to 23 rules | `b834988b…` | The current CIS shape: Level 1/Level 2 profiles, `full` and `unscored` roles, direct and `complex-check` (one nested), cc7 and cc8 idents on some rules and none on others, URL idents, a `metadata` on every rule, Benchmark `platform` | coverage, converter, cli |
| `CIS_Visual_Studio_Code_GPO_Benchmark_v1.0.0-xccdf.xml` | XCCDF 1.2 benchmark | 2025-09-18 (interim) | GitHub mirror PanduKonala/Project-Anvil (CIS Assessor), untrimmed | `7cd3f28c…` | A 2025 benchmark with sparse safeguards: empty `asset_type`, attribute-less `implementation_groups` and empty `security_function` in five of six, `interim` status, cc7 and cc8 idents | snapshots |

## ComplianceAsCode / SCAP Security Guide

| Fixture | Format | Era / date | Source | sha256 | Proves | Read by |
|---|---|---|---|---|---|---|
| `benchmark-ssg-nested-groups.xml` | XCCDF 1.2 benchmark | SSG v0.1.81 | ComplianceAsCode build product `ssg-rhel8`, one nested Group subtree (origin not byte-matched) | `fa9bc97c…` (fixture) | Nested Groups with several Rules per Group; `check-content-ref` names with no inline content; SSG id prefixes | coverage, converter, cli |

## Results documents and minimal inputs

| Fixture | Format | Era / date | Source | sha256 | Proves | Read by |
|---|---|---|---|---|---|---|
| `xccdf-results-openscap-rhel7.xml` | XCCDF 1.2 results (Benchmark with TestResult) | OpenSCAP 1.2.17 run, RHEL 7 STIG 003.005 | heimdall2 sample, byte-identical | `6381256a…` (fixture) | A full OpenSCAP results document, untrimmed: every result/severity pair and the volume a parity run sees | snapshots |
| `xccdf-results-openscap-rhel8.xml` | XCCDF 1.2 results (Benchmark with TestResult) | OpenSCAP 1.3.5 run, RHEL 8 STIG 1.3 | heimdall2 sample; trimmed to 16 rule-results | `8fe9a78f…` (fixture) | The results path on OpenSCAP 1.3 output: `error` results, per-rule-result times, Groups and Rules kept consistent with the TestResult | converter |
| `xccdf-results-scc-rhel7.xml` | XCCDF 1.2 results (`cdf:` prefix) | SCC 5.4 run, RHEL 7 STIG 003.002 | heimdall2 sample, byte-identical | `9696e41f…` (fixture) | A full SCC results document, untrimmed; severity read from the rule-result | converter |
| `xccdf-results-scc-rhel8.xml` | XCCDF 1.2 results (`cdf:` prefix) | SCC 5.4.2 run, RHEL 8 STIG 1.2 | heimdall2 sample; trimmed to 12 rule-results | `41786fc5…` (fixture) | The results path on SCC output: six result/severity pairs, a pinned rule-result time, SCC's CPE `test-system` | converter |
| `stig-rhel7.xml` | XCCDF 1.2 results | OpenSCAP 1.2.17 run, RHEL 7 STIG 003.005 | origin not established | `117c4b88…` (fixture) | The small results anchor: one requirement per rule-result, CCI to NIST, status mapping, target, duration, `controlType` | converter, cli |
| `arf-minimal.xml` | ARF 1.1 holding XCCDF 1.2 results | OpenSCAP 1.3.5 ARF | origin not established | `335e09e9…` (fixture) | The ARF path: a Benchmark found inside `asset-report-collection`, `tool.version` from the ARF test-system | converter, cli |
| `benchmark-minimal-1.1.xml` | XCCDF 1.1 benchmark | Windows Server 2022 STIG fragment | origin not established | `7b0f8843…` (fixture) | The benchmark path on XCCDF 1.1 without a TestResult: `VulnDiscussion` to default description, check and fix text | converter, cli |
| `benchmark-minimal-1.2.xml` | XCCDF 1.2 benchmark | Windows Server 2022 STIG fragment | origin not established | `be54def7…` (fixture) | The same on XCCDF 1.2; the InSpec profile generator's input | converter, cli |
| `minimal.xml` | XCCDF 1.2 results | synthetic-looking two-rule results | origin not established | `38e72324…` (fixture) | Results without `version`, severity or NIST tags: id fallback to `idref`, default impact, no identifier tags | converter, cli |
| `empty.xml` | XCCDF 1.2 results, no rule-results | synthetic | built here | `aa400d90…` (fixture) | The nothing-to-convert path (no rule-results); exempt from the golden rule | converter |
