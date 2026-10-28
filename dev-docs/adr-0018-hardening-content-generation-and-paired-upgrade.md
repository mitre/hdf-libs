# ADR-0018: Hardening content generation from benchmarks, and one upgrade for validation and hardening

- **Status:** Proposed
- **Date:** 2026-10-26
- **Revised:** 2026-10-27 and 2026-10-28, after review against the code and against real DISA releases (RHEL 9
  V1R3, V2R4, V2R5, V2R8 and V2R9 converted and run through the upgrade matcher; the generated shape built for five
  platform rows and linted). The identity contract gained the bare stable key as the one match key, toggles keyed on
  the SV number always, and a record of the id type, platform and source release in the role; the placeholder became
  a `block` with a defined marker, a named placeholder task and a structured, author-only disposition; the status set
  gained `manual`, `not-applicable`, `withdrawn` and `orphan`; the pairing check compares state, not presence, and
  takes a `--profile`; the upgrade match moves out of the CLI into a library function in both languages that takes
  parsed Baselines, always matches on the SV number, matches it first, flags every pair whose keys differ, and reports
  withdrawn rules instead of dropping them silently; authored automation beats an upstream "manual" marker; the Junos
  row moves to `juniper.device`; the converter work moved out to hdf-libs issue #499, which this ADR now depends on;
  the card plan is 19 cards; a Phases section records what comes after the stubs.
- **Deciders:** Aaron Lippold
- **Depends on:** hdf-libs #499 — the XCCDF benchmark converter captures every benchmark and rule field (DISA and
  CIS) with an XSD-driven completeness test. This ADR's identity, release check and disposition hints read fields that
  #499 adds (`extensions.release`, `legacy_id`, normalised `gid`/`rid`, the DISA description sub-elements, the CIS
  level and controls).
- **Relates to:**
  - `hdf generate inspec-profile` (XCCDF benchmark → HDF Baseline → InSpec profile stubs) and `hdf generate upgrade`
    (smart-merge an existing baseline or profile onto a newer benchmark). This ADR adds hardening outputs beside the
    validation output and extends the upgrade to carry both.
  - The `xccdf-results-to-hdf` converter's benchmark path (`ConvertXccdfBenchmarkToHDF`), which every generator here
    reads through.
  - The requirement matching in `hdf-diff` (`matching.MatchRequirementsWithError` and its strategy chain, the port of
    SAF CLI's `generate:delta -M` requirement-first matcher with its optional fuzzy tiers), which the upgrade CLI calls
    today and which decision 5 moves behind a library function.

## Context

A security baseline has two halves: **validation** (does the system meet each requirement?) and **hardening** (make
it meet each requirement). hdf-libs generates the first half from a benchmark: `hdf generate inspec-profile` turns a
DISA STIG XCCDF into InSpec control stubs, and `hdf generate upgrade` moves an existing, filled-in profile onto the
next benchmark release, matching requirements by SRG/CCI semantics rather than exact ID, letting upstream win on
metadata and the author win on code. Nothing generates or upgrades the second half.

Teams that harden with Ansible start every role by hand from the benchmark, then re-do the bookkeeping by hand at every
DISA release (new SV revisions, renumbered or withdrawn rules, changed titles and fix text), separately from the
profile. The two drift: a control is upgraded and its hardening task is not, or a rule gains hardening with no control.

**The work is phased.** This ADR covers the first phase: generate the hardening *stubs* with the full requirement
identity, check them against the benchmark, and upgrade them together with the profile. Writing the remediation
inside each stub is the next phase (see Phases). Every phase-1 decision below is taken so that phase-2 content, once
written, survives every later release.

**Prior work outranks the benchmark.** A benchmark's "manual", "documentable" or "unscored" marker is the benchmark's
opinion of what can be automated, and teams routinely automate rules the benchmark calls manual, in InSpec and in
Ansible. So benchmark metadata is carried as information and never turned into a status, and an upgrade never lets an
upstream marker override authored automation.

**Prior art does not close the gap** (checked 2026-10-26 and 2026-10-27; licenses read from the repositories):

- `ansible-lockdown/Benchmark-Generator` (MIT; last commit 2020-08-18; MITRE fork `mitre/benchmark-generator`, no
  changes since): parses an XCCDF with lxml and writes `cat1.yml`…`cat3.yml` with an AUDIT/PATCH placeholder pair per
  rule. Its output no longer runs or lints: `always_run` was removed in Ansible 2.6, `command: true` placeholders with
  blanket `ignore_errors`, no FQCN; it keys on the group ID (`V-…`) only, drops the rule ID, STIG ID, CCIs, legacy IDs
  and the fix/check text; its sort result is discarded; a failed input exits 0. The per-rule skeleton idea is the part
  worth keeping, and it proves the generation itself is straightforward.
- `oscap xccdf generate fix --fix-type ansible` (OpenSCAP 1.4.6, LGPL-2.1) emits the `<fix>` elements whose system is
  `urn:xccdf:fix:script:ansible`. **DISA STIG XCCDFs carry none**: every `<fix>` is empty (all 445 in RHEL 9 V2R9, and
  none carries a `disruption` or `complexity` attribute); fix prose lives only in `<fixtext>`. Useful for
  ComplianceAsCode datastreams, not for DISA input.
- ComplianceAsCode/content (BSD-3-Clause) and the `RedHatOfficial/ansible-role-*` roles it publishes: hand-written or
  templated remediations per rule, with STIG profiles for RHEL, Ubuntu, SLE and Oracle Linux products; no network
  platform. Its `stigid@<product>` references key rules on the STIG ID across releases. Its `reboot` / `strategy` /
  `complexity` / `disruption` metadata is a good vocabulary, but no DISA input carries it. The published RHEL 9 role is
  one 64,665-line `tasks/main.yml` with uppercase toggle names that fail `var-naming`, STIG IDs as tags and toggles,
  and no SV/V identifiers.
- DISA "STIG for Ansible" packages (e.g. `U_RHEL_9_V2R9_STIG_Ansible.zip`, July 2026): one hand-written role per
  product, keyed by the revision-free SV number (`rhel9STIG_stigrule_279936_Manage`), covering 281 of 445 rules; no
  tags, no FQCN; a callback writes an XCCDF TestResult whose pass/fail is "changed". DISA states those results may
  differ from STIG compliance. No Cisco IOS XE package was found.
- `microsoft/PowerStig` (MIT; pushed 2026-09-18): turns DISA XCCDF into per-rule data with explicit `ManualRule` and
  `DocumentRule` types, exceptions and skip rules, and ships a new set each release. Precedent for the `manual` and
  `excepted` states of decision 4, with the difference that here those states are set by authors, not derived.
- ansible-lockdown's maintained STIG roles (MIT; RHEL9-STIG pushed 2026-10-21) are the current community convention
  for hand-maintained hardening: task names `<SEVERITY> | <STIG ID> | PATCH | <title>`, a toggle per rule named from
  the STIG ID (`rhel_09_211010`), tags carrying STIG ID, `CATn`, every CCI and SRG, the full `SV-…r…_rule` and
  `V-…`, NIST; PATCH-first (426 PATCH, 14 AUDIT, 5 WARN top-level tasks), with compliance auditing in a separate
  `-Audit` repository. Their Cisco roles were last pushed in 2022.
- `OpenSTIG-Ansible/cisco_ios-xe_router_ndm_stig` (Apache-2.0, pushed 2025-10-30): hand-written, some tasks merge nine
  rules, which breaks per-rule coverage.

No maintained tool turns a DISA XCCDF into a role skeleton that meets today's Ansible standards, and none keeps
hardening and validation in step across releases.

**What the input provides.** The input is DISA's *Manual* XCCDF (the SCAP benchmark carries only the automated subset
of rules), or a CIS XCCDF once CIS is in scope. The benchmark path of `xccdf-results-to-hdf` produces an HDF Baseline
whose requirement `id` is the revision-free SV number and whose `controlType` is derived from the NIST families. After
#499 the Baseline carries everything else the file says: at benchmark level `extensions.release`, `benchmarkDate`,
`releaseInfo`, the XCCDF status and date, notices, publisher, platforms and profiles; per rule the tags `gid`, `rid`
(normalised to `V-…` / `SV-…r…_rule` for XCCDF 1.2 input), `stig_id`, `severity`, `cci`, `gtitle`, `nist`,
`legacy_id`, `cce`, `fix_id`, `check_id`, `weight`, `role`, the ten DISA description sub-elements (`documentable`,
`responsibility`, `mitigations`, `severity_override_guidance`, …) and the CIS fields (`cis_level`, `cis_controls`,
`cis_implementation_groups`, …), with `check`, `fix`, `rationale` and `warning` as descriptions. Nothing here parses
XCCDF again, and nothing here is blocked on a field the converter does not carry.

**What the upgrade already does, measured on real releases** (RHEL 9 V1R3 → V2R4, V2R5 → V2R8 → V2R9, run
2026-10-27). The SV number held for 444 of 445 rules across V2R5 → V2R9; the span carried 126 revision bumps, 109
check-text and 70 fix-text edits, 10 retitles, 8 severity changes, 5 withdrawn rules and 1 added rule, and one
withdraw-and-replace (SV-274878 / RHEL-09-654096 removed in V2R6 as a duplicate, SV-279936 / RHEL-09-654097 added in
V2R7 with the same title). V1R3 → V2R4 carries two rules whose SV number held while the STIG ID changed
(SV-258234: RHEL-09-672010 → 215100; SV-258241: 672045 → 215105). Four defects in the current upgrade surfaced, and
each would misroute hardening content exactly as it misroutes InSpec code today:

- The strategy chain runs `srgDeterministic` and `srgCciTiebreak` before `exactId`. On V2R8 → V2R9 a one-character
  title edit made the CCI tiebreak rotate five rules into one another's slots (SV-258219 → SV-258218,
  SV-258220 → SV-258219, …), each at confidence 1.0 with the mismatch flag off, under a summary of "445 match,
  0 possible mismatch". All five SV numbers exist unchanged on both sides. 410 of the 445 rules sit in SRG groups
  holding more than one rule, so this is not a corner case. Matching the stable key first removes the rotation
  (cross-key pairs on V1R3 → V2R4 fall from 46 to 4, on V2R8 → V2R9 from 5 to 0) and makes nothing worse on the four
  pairs measured: 444 exact pairs, one cross-key pair (the withdraw-and-replace), four unmatched old rules.
- Even with the stable key matched first, the remaining SRG, CCI and fuzzy tiers still pair rules whose keys differ,
  and three of the four such pairs on V1R3 → V2R4 are unrelated rules (OpenSSL → SSH client ciphers by
  `srgCciTiebreak` at 1.00; tmux → Postfix by `vendorFuzzyTitle` at 0.88; session control → SELinux sudo by
  `cciMatch` at 0.80). The mismatch flag has per-strategy thresholds (0.5, 0.9, 0.8), never fires for
  `srgDeterministic` or for non-primary pairs, and so caught none of them. Nothing tells the author that content moved
  between unrelated rules.
- `--id-type` re-keys both inputs before matching (`remapBaselineIDs` overwrites every requirement's `id`), on JSON
  input too, although the help says it is ignored there. Under `--id-type version` the match runs on the STIG ID, the
  two STIG-ID-only changes above become cross-key pairs, every control is renamed and the SV-named files pruned.
- Rules withdrawn upstream are discarded before the link records are built, so they appear nowhere in the delta
  report, and the in-place profile write prunes their files. Of the five withdrawn V2R5 rules, three left no trace and
  two were paired to other rules. When several old rules match one new rule, the non-primary ones print a `related`
  line but their authored code is dropped silently. The report's own invariant check already prints `false` on
  V2R5 → V2R9 for that reason, and two identical runs produce differently ordered `delta.json` files.

Decision 5 fixes all of these, because the paired upgrade cannot be built on them as they stand.

**Current Ansible standards** the output must meet (2026-10-27): ansible-core 2.19 reaches end of life in
November 2026, 2.20 (end of life May 2027) and 2.21 are supported (controller Python 3.12–3.14), 2.22 is in release
candidate (controller Python 3.13–3.15). Red Hat's partner certification requires ansible-lint's `production` profile
(cumulative: `min`, `basic`, `moderate`, `safety`, `shared`, then `fqcn` and the production-only rules, several of
them planned but not yet implemented) and lists rules that may never be skipped (`no-changed-when`,
`risky-file-permissions`, `command-instead-of-*`, `risky-shell-pipe`, `no-handler`, `package-latest`, `unnamed-task` —
now an alias of `name[missing]` — and `meta-runtime[unsupported-version]`; `meta-no-info` is no longer a rule in
26.10.1). That certification is written for collections; this ADR ships a role inside a playbook project, so
`meta-runtime[unsupported-version]` (which reads only a collection's `meta/runtime.yml`) does not apply, and a role's
`min_ansible_version` is schema-checked as a quoted string and never enforced at run time. A custom `.yamllint` must
carry the settings ansible-lint requires (`comments.min-spaces-from-content: 1`, `comments-indentation: false`,
`braces` 0–1 spaces inside, `octal-values` forbidding implicit and explicit octals), or ansible-lint warns and disables
`--fix`. Facts about Ansible's runtime and linters that shape the generator, all tested on the generated shape: task
`name:` and `tags:` are Jinja-templated at run time, so benchmark text with `{{`, `{%` or `{#` inside a name fails
`name[template]` and `jinja[invalid]` at `production` (marking it `!unsafe` does not help); Ansible reads YAML 1.1, so
an unquoted `yes` or `on` becomes a boolean; a bare `when: <variable>` fails with "Conditionals must have a boolean
result" when the variable arrives as a string from `-e` or an INI inventory; `key-order[task]` requires
`name, when, tags, vars, block`; `document-start` requires `---`; `trailing-spaces` rejects verbatim text with
trailing blanks; `schema[meta]` requires `author`; and a block's `name` is not inherited by the tasks inside it (only
`when` and `tags` are).

**Any STIG, any platform.** The benchmark may be for an operating system, an application or a network device. On the
host side Ansible's built-in modules cover remediation. Network platforms each have a vendor collection with a
generic "config lines" module (`cisco.ios.ios_config`, `cisco.nxos.nxos_config`, `arista.eos.eos_config`,
`juniper.device.junos_config`, …) and a varying set of resource modules. The `junipernetworks.junos` collection is
deprecated (its `meta/runtime.yml` redirects to `juniper.device`, redirects removed after 2028-04-01; the `ansible` 14
package, shipped June 2026, no longer carries it), and `fqcn[canonical]` fails on its name at `production`. Taking
Cisco IOS XE as the measured example: `cisco.ios` 11.6.0 (GPL-3.0) has resource modules for logging, NTP, SNMP, ACLs,
interfaces, services and routes, plus non-resource modules such as `ios_banner` and `ios_user` that cover the banner
and local-account rules, but none for AAA, TACACS/RADIUS, `line con/vty`, `ip ssh`, `login block-for` or `archive`,
which most NDM STIG rules need; `ios_config` covers every rule as literal CLI lines, idempotent only for long-form
commands written as the device prints them. A config-lines task with an empty `lines:` list is a no-op at run time on
every platform, and ansible-lint does not validate module options (`skip_action_validation` is on and the `args` rule
skips action plugins), so lint passing says nothing about a row's options being valid.

## Decision

### 1. Generate hardening content from the same HDF Baseline as the profile

New generators in `hdf-generators` (Go and TypeScript, kept in parity like the profile generator) take an HDF
Baseline and build their output in memory, with no file I/O; the CLI writes it with `hdfutil.SafePath` and
`atomicfile.WriteFile`, as `generate inspec-profile` does. Input comes only through the existing converters
(XCCDF benchmark → Baseline); no XCCDF parser is added. DISA STIG input first; CIS XCCDF once the #499 fixture
converts and the CIS rows of the identity (see Phases) are decided.

### 2. One requirement identity, written into every artifact

Every generated artifact carries the same machine-readable identity per requirement, so artifacts can be matched to
each other and across releases without reading prose. This identity is a **contract**: once playbooks exist, it does
not change.

- **Stable key:** the revision-free rule number (`SV-215807`), the same key MITRE profiles, SAF CLI's default
  `--idType rule` and DISA's own Ansible packages use. **Matching always runs on it.** `--id-type rule|group|version`
  (three of the four values `generate upgrade` accepts; `cis` keys on the revisioned `rid` and is rejected here)
  changes only what block names and filenames show (V-ID or STIG ID), never the key the match or the toggles use.
  `generate inspec-profile` has no `--id-type` and always keys on the SV number.
- **Full identity in metadata:** `rid` with revision (`SV-215807r1186318_rule`), `gid` (`V-215807`), `stig_id`,
  severity, CCIs, SRG, NIST controls (from the Baseline's `tags.nist`), and legacy IDs. The revision changes every
  release, so it is never a key.
- **In a playbook the identity is the task block's tag set** (decision 3), and the **match key is one tag: the bare
  stable key** (`SV-215807`). The reader of decision 5 matches on that tag alone. Every other tag is carried for
  people and for `--tags` selection; CCI, SRG, CAT and NIST tags are shared across rules and are never used to match.
- **The role records how it was generated.** `meta/main.yml` carries, under a role-prefixed key, the id type, the
  platform row, and the source benchmark's release (`V2R9`, from the Baseline's `version` and `extensions.release`)
  and benchmark date. The reader and the validator read the id type from there rather than from a flag, and the
  upgrade refuses a playbook whose recorded id type or platform does not match the run.
- **Toggles key on the SV number always** (`<role>_sv_215807`), whatever `--id-type` names the blocks and files: an
  operator sets toggles in `group_vars`, outside anything the upgrade can rewrite, and the SV number is the key that
  held for 444 of 445 rules while two STIG IDs changed under it.
- **Tag normalisation:** tags are the value as DISA prints it where it has no spaces (`SV-215807`, `V-215807`,
  `CCI-000366`, `SRG-OS-000480-GPOS-00227`, `CAT2`, the full `rid`); NIST values carry spaces (`CM-6 b`,
  `AU-12.1 (iv)`), so a NIST tag is `NIST800-53R<rev>_` + the value with every run of whitespace removed
  (`NIST800-53R5_CM-6b`). `<rev>` comes from the same `hdf-mappings` revision setting the converter used
  (`nist.Revision()`, the CLI's `--nist-rev`), passed to the generator as an option, since the Baseline does not record
  it.
- **Benchmark metadata tags are carried, not interpreted.** The DISA description sub-elements and the CIS fields that
  #499 puts on the Baseline (`documentable`, `responsibility`, `mitigations`, `severity_override_guidance`,
  `cis_level`, `role`, …) are copied to the block as tags where they are single values, and into the comment block
  where they are prose. They inform an author or the validator's output; they never set a status or a disposition.
- **People see the STIG ID** in names, as both maintained Ansible ecosystems do.

### 3. One output: an Ansible playbook per benchmark, for any STIG, lint-clean at `production`

`hdf generate ansible-playbook` emits a runnable playbook project, the way hardening content is shipped and run
(`ansible-playbook site.yml`):

```
site.yml            # the playbook: applies the role to the inventory's hosts
roles/<name>/       # the generated role: tasks, defaults, argument specs, meta
requirements.yml    # collections the role needs (for example cisco.ios with --platform ios)
.ansible-lint
.yamllint
```

The reusable unit is the role; `site.yml` is the short entry point that runs it. The role is named after the
benchmark, snake-cased (e.g. `cisco_ios_xe_router_ndm_stig`), unless `--role-name` overrides it; the upgrade of
decision 5 keeps the existing role name. The role's `meta/main.yml` declares `min_ansible_version: "2.20"` (quoted:
unquoted it parses as 2.2), an `author`, Galaxy's exact platform names (`IOS`, `NXOS`, `Junos`, `eos`), and the
generation record of decision 2. Packaging as a Galaxy collection is future work. The role holds:

- One task file per rule, named by the stable key (`tasks/cat2/SV-215807.yml`), each starting with `---`, imported by
  `tasks/cat1|cat2|cat3/main.yml`. Each file holds **one `block`** with keys in the order `name, when, tags, vars,
  block`, named `<SEVERITY> | <STIG ID> | PATCH | <rule title>`, carrying the rule's toggle as
  `when: <role>_sv_215807 | bool` and the full tag set of decision 2. The block is the container authors fill in
  phase 2: a fix often takes several tasks (package, file, service), and tasks added inside the block inherit its
  toggle and tags, so the reader of decision 5 still sees one rule. The block's name is not inherited, so the
  generated block contains exactly one **placeholder task**, itself named `<SEVERITY> | <STIG ID> | PATCH | not
  implemented` (`ansible.builtin.debug` with a "not implemented" message), and the block carries the tag
  `placeholder`. The rule's check text and fix text, and any prose metadata tag, are carried as YAML comments above
  the block, verbatim except for wrapping to the line limit and the removal of trailing blanks, which
  `trailing-spaces` rejects.
- **Names are made template-safe.** Benchmark text placed in a `name:` has `{{`, `{%`, `{#` and their closing pairs
  neutralised by inserting an ASCII space between the two characters (`{ {`), which both linters accept and which stays
  visible in a diff. The verbatim title stays in the comment; identity lives in the tags, which the generator checks
  against the character set above.
- **No generated AUDIT tasks.** Validation is the InSpec profile generated from the same Baseline; the pairing report
  (decision 5) keeps the two in step. This matches the maintained community roles, which are PATCH-first with
  auditing kept separate, and DISA's own warning that "changed" is not compliance.
- A toggle per rule (`<role>_sv_215807`, role-prefixed and lowercase for `var-naming`) and category switches
  (`<role>_cat1`…`cat3`), all in `defaults/main.yml` and `meta/argument_specs.yml`. Each category's `import_tasks` is
  wrapped in a block that carries the category `when:`, because `import-task-no-when` is planned for `production`.
  No disruption switch is generated: DISA input carries no disruption data, and a switch that gates nothing is noise.
  Tags per block: the stable key, STIG ID, `CATn`, `V-…`, full `rid`, each CCI and SRG, NIST in the form of
  decision 2, the single-value metadata tags of decision 2, `patch`, and `placeholder` until filled.
  `--tags placeholder` therefore selects every unfilled rule. No `never` gating.
- **Disposition is author-only.** A block may carry one structured field,
  `vars: { <role>_disposition: { state, reason, reference } }`, where `state` is `excepted`, `manual` or
  `not-applicable`. It is the only machine-readable way to record that a rule will not get a technical fix, and it is
  written only by a person or by phase-2 authoring that looked at the rule. The generator never pre-fills it: a
  benchmark's `documentable`, `responsibility` or `role=unscored` says what the benchmark expects, and prior work
  routinely automates such rules. It lives in a `vars` field, never a comment, so the reader and the validator of
  decision 4 read it without parsing prose. Tested: a nested `vars` mapping on a block has no lint or argument-spec
  side effect.
- `.ansible-lint` (`profile: production`, `role-argument-spec` in `enable_list`, no skips from the certification list)
  and a `.yamllint` carrying the settings ansible-lint requires plus an explicit `line-length` (real rule titles run
  past 200 characters, and a bare `extends: default` would reset the limit to 80).

**Any STIG, any platform, one output.** Placeholders are platform-neutral by default (host and application STIGs).
For a network STIG, `--platform` selects a row of a small data table (not per-vendor code): the platform's
config-lines module, whether it takes `parents`, and which modules the platform's collection has for the "promote"
hint of decision 4. First rows: `ios` → `cisco.ios.ios_config` (parents: yes), `nxos` → `cisco.nxos.nxos_config`
(yes), `eos` → `arista.eos.eos_config` (yes), `junos` → `juniper.device.junos_config` (no `parents`; `set`/`delete`
lines; netconf). Each row's options are checked against the module's own argument spec in the table's tests, since
lint will not. Each rule's placeholder task is then a task of that module with an empty `lines:` list (and `parents:`
where the row allows it and the rule's fix text names a section), so filling in a rule's device configuration means
writing its lines into its task. The device configuration lives in the playbook; there is no separate config file to
keep in step. The generator never emits resource-module `state: overridden` or `replaced`. Adding a platform is a
table row.

Generated YAML is produced with a YAML library, not string templates: `gopkg.in/yaml.v3` in Go (the library the
repo's production modules already use) and `yaml` in TypeScript (today a development dependency of `hdf-openapi`; it
becomes a runtime dependency of `@mitre/hdf-generators`). Their defaults differ (quote style, line folding, key order,
comment spacing, untyped scalars), and pinning encoder options is not enough: both generators build an explicit node
tree with a style rule per scalar (every string tagged as a string, a fixed quote style, no folding, ordered keys, a
space after every `#`). One shared golden set, asserted by both suites, is what makes Go/TS byte parity a fact rather
than a hope.

### 4. Checking a playbook against its benchmark: `hdf validate ansible-playbook`

Creating and checking are separate commands, the way hdf already pairs `generate threshold` with `validate threshold`,
and the way Ansible keeps checking a playbook (`ansible-lint`, `--list-tasks`) apart from producing it.
`hdf validate ansible-playbook <dir> --baseline <file> [--profile <dir>]` reads a generated playbook with the reader
of decision 5 (the id type and platform come from the role's generation record) and reports per requirement:
identifiers, severity, one status, any `needs_review` tag left by an upgrade, the benchmark's own markers
(`documentable`, `role=unscored`, …) as information, and, for network platforms, whether the platform's collection
has a module covering the rule, so a person can promote it from the config-lines module. Statuses:

| status | meaning |
|---|---|
| `placeholder` | the block carries the `placeholder` tag and holds only the generated placeholder task |
| `implemented` | the `placeholder` tag is gone, or the block holds any task beyond the placeholder (for network rows, any non-empty `lines:`), and no disposition is declared |
| `excepted`, `manual`, `not-applicable` | the block declares that disposition; a declared disposition wins over the body |
| `withdrawn` | the block lives under `tasks/withdrawn/` (decision 5); its key is not expected in the Baseline |
| `missing` | the Baseline has the requirement; no block carries its key tag |
| `orphan` | a block outside `tasks/withdrawn/` carries a key tag that is not in the Baseline |

Exit status is non-zero when any requirement is `missing` or any block is `orphan`. A benchmark marker never changes
a status: a rule the benchmark calls manual with a filled block is `implemented`.

With `--profile`, the same run performs the **pairing check** of decision 5 without an upgrade.

### 5. One upgrade for validation and hardening, and a pairing check

**The match is a library function.** Today the upgrade CLI parses both inputs, remaps IDs, calls the `hdf-diff`
matcher and builds `LinkRecord`s inline, in Go only; `GenerateUpgrade` receives finished records and does no matching.
The sequence from two parsed Baselines to `LinkRecord`s (match, build records, flag, sort) moves into `hdf-generators`
as one function in Go and TypeScript, tested on the real releases of card 1, and the CLI calls it. Parsing, validation
and the InSpec shell-out stay in the CLI, so `hdf-generators` gains a dependency on `hdf-diff` and nothing else. The
changes that ride along, because the measured defects above would corrupt the paired upgrade:

- **The match runs on the SV number, and exact first.** `remapBaselineIDs` leaves the match; `--id-type` is applied to
  names and filenames after matching. The chain becomes `exactId` on the stable key, then the SRG/CCI tiers and the
  fuzzy tiers (the port of SAF CLI delta's optional fuzzy matching: token Jaccard and prefix-stripped Levenshtein on
  titles) only for keys present on one side.
- **Every cross-key pair is flagged.** A pair whose stable keys differ is a possible renumber and a possible
  misroute. `PotentialMismatch` becomes "the keys differ", for every strategy, score and relationship; the
  per-strategy thresholds go. The content is carried across, both the block and the control are tagged
  `needs_review` (one spelling in both artifacts; a hyphen is not a valid Ruby tag key), and the report lists the pair
  with its strategy and score. Whether a stronger matcher for that leftover set (a small language model over title,
  check and fix text, for example) earns its place is a question for phase 2, once there is real content to protect;
  the fuzzy tiers stay as the fallback until then.
- **Withdrawn rules are reported; merges are visible.** Unmatched current requirements enter the `LinkRecord`s and
  the delta report as `removed` (relationship `removed`, `newId` the empty string in both languages), counted by a new
  `Removed` field. The non-primary members of a merge stay `related` records, so "merged" is read off the records as
  one `newId` with several `oldId`s, and "split" as one `oldId` with several `newId`s; the report prints both. The
  `DeltaStatistics` invariants become: distinct `newId`s across non-`removed` records equal the upstream count;
  distinct `oldId`s plus `Removed` equal the current count. Records are sorted by `newId` then `oldId`, so two runs
  produce the same file. The profile keeps its existing behaviour (unmatched current dropped unless
  `--keep-unmatched`), now with a report line per rule and per dropped merge member.

**Both artifacts from one match.** `hdf generate upgrade` gains `--ansible-playbook <dir>` beside the profile it
already upgrades. `<current>` is the profile, the old benchmark or a Baseline, as today; the playbook is read back
beside it. The match is computed once and applied to the profile and the playbook in the same run, with the merge rule
per artifact:

- **Upstream wins on metadata:** names, the metadata tag set (every tag the benchmark converter emits: `rid`, `gid`,
  `stig_id`, `severity`, `cci`, `gtitle`, `nist`, `legacy_id` and the #499 fields), check/fix comments, category
  directory. Identity and metadata tags take upstream's value even under `--prefer current`, because a stale `rid`
  would break the next run's release check; this is a change for profiles too. On the playbook side the metadata set
  is card 2's tag list; author-added tags are the block's tags minus that list, and they are kept.
- **The author wins on content:** InSpec code; everything inside a block beyond the generated placeholder, including
  network `lines:`; the block's disposition; author-added tags. `placeholder` is recomputed from the block's body,
  never merged. **Authored automation beats an upstream marker:** when the new benchmark marks a rule manual,
  documentable or unscored and the current artifact automates it, the automation is kept and the report says
  "benchmark marks manual; authored automation kept", so nobody later "fixes" it back.

Before matching, the run checks that the profile and the playbook were generated from the same release: the
playbook's generation record against the profile's `inspec.yml` version (`<version>.<release>.0` after #499), and,
as the backstop for artifacts generated or edited before that, equality of the `rid` tag for every key present in
both the profile and the playbook's non-withdrawn blocks. On a mismatch the run stops and names the artifact that is
behind; that artifact is upgraded alone first (the profile with the existing command; the playbook by the same command
with the old benchmark as `<current>`). Per kind of release change:

- **Renumbered** (stable key changes): the block moves to its new file and key under the new identity, tagged
  `needs_review`; the delta report lists the old and new toggle names so operators update `group_vars`.
- **Severity changed:** the file moves between `catN/` directories; the report lists each move (read by joining the
  record to both Baselines), because the operator's category switch now covers a different set.
- **Withdrawn:** the block is moved under `tasks/withdrawn/` (not imported by any category `main.yml`), its toggle is
  kept in `defaults` and `argument_specs` defaulted to `false`, and it is listed in the report; `--keep-unmatched`
  leaves it in place instead. Authored content is never deleted by an upgrade, and the validator reports it as
  `withdrawn`, exit 0.
- **Split** (one `oldId`, several `newId`s): the old body is copied into every new block, each tagged `needs_review`
  and listed in the report.
- **Merged** (several `oldId`s, one `newId`): the primary's body is kept; the other bodies are appended inside the
  block as commented text, the block is tagged `needs_review`, and the report lists it.
- **New upstream rule:** a fresh placeholder block.
- A split or merge in which one rule keeps its SV number is seen by the exact-first chain as that rule plus a new or
  withdrawn one; the XCCDF carries no lineage that would say otherwise, and the report shows exactly that.
- `defaults/main.yml` and `meta/argument_specs.yml` are generated files and are rewritten (toggles, including those
  of withdrawn blocks); the generation record in `meta/main.yml` is updated to the new release. Authored variables
  belong in `vars/`, inventory or `group_vars`, which the upgrade never touches. `handlers/`, `templates/` and `files/`
  are never generated and never touched.

**The reader.** Upgrading a playbook requires reading it back. The reader parses each task file with the YAML library,
matches each block on the key tag of decision 2 only, and copies the authored body **out of the original bytes**: a
block's span runs from its own start position to the start of the next top-level node or the end of the file, and
both languages convert their native positions (line and column in Go, UTF-16 offsets in TypeScript) to byte offsets
before slicing, because parsing and re-emitting is not byte-for-byte (the `---` marker, blank lines and comment
spacing change). A block whose key tag is missing or unknown is reported, never guessed.

**The pairing check** is a column in the delta report and in `validate ansible-playbook --profile`: for every
requirement, the validation state (control stub or filled code, read from `controls/*.rb` by the anchored control-ID
pattern and the stub marker the profile generator already defines in both languages, no Ruby) beside the hardening
status of decision 4. It reports a requirement whose two halves disagree in kind: filled on one side and placeholder
on the other, or a disposition declared on one side only. Presence alone is never the test, because generation gives
every rule both halves. A rule the benchmark calls manual that the profile automates is the clearest case the column
exists for: it says the playbook can probably be automated too.

### 6. The generated output is checked by the real linters in CI

CI runs `ansible-lint --profile production --offline` and `yamllint` on playbooks generated from the committed
benchmark fixtures. ansible-lint, yamllint and the `ansible` 14.x package (which carries ansible-core 2.21 and the
Cisco and Arista collections; no supported `ansible` release ships the 2.20 floor) come from a hash-pinned requirements
file compiled for Python 3.12, the way the semgrep step installs semgrep, with Dependabot allowed to track them.
Network rows need their collections installed before linting, because `syntax-check[unknown-module]` cannot be skipped
and an online ansible-lint would install `requirements.yml` from Galaxy unpinned. `juniper.device`, which the `ansible`
package does not carry, is installed with `ansible-galaxy collection install --offline` from its Galaxy tarball checked
by sha256, resolving its `ansible.netcommon` dependency from the package. The generator and the CLI have no Python
dependency; Python is only in that CI step and on the machines that run the playbooks.

## Alternatives Considered

### A: Modernise `mitre/benchmark-generator` in Python as a standalone tool

Keep the fork, rewrite its parser and templates to current Ansible standards.

- **Pros:** closest to the original; Ansible users already have Python.
- **Cons:** a second XCCDF parser beside the converter hdf-libs already maintains and tests; no access to the
  upgrade's matching, so validation and hardening cannot be upgraded together; a separate release and CLI.
- **Why rejected:** decision 5 needs the profile and the playbook upgraded from one match, which only works inside
  hdf-libs. The fork stays credited as the origin of the per-rule skeleton idea.

### B: `oscap xccdf generate fix --fix-type ansible`

- **Why rejected:** DISA STIG XCCDFs contain no Ansible fix scripts, so it produces nothing for this input.

### C: Adopt ComplianceAsCode or the RedHatOfficial roles

- **Why rejected:** Linux-only content, no network platforms; the published roles do not lint clean at `production`
  and carry no SV/V identity. Their disruption/complexity/reboot vocabulary stays a reference for a later phase, once
  an input carries that data.

### D: Generate AUDIT and PATCH pairs per rule (Benchmark-Generator's model)

- **Pros:** one artifact both checks and fixes.
- **Cons:** duplicates the InSpec profile with weaker checks; "changed" is not compliance; the maintained roles moved
  away from it (14 AUDIT tasks against 426 PATCH).
- **Why rejected:** validation already has a generator and an upgrade path; the pairing check keeps the two in step.

### E: Generate resource-module tasks for network rules instead of the config-lines module

- **Pros:** structured data, idempotent, offline `rendered`/`parsed`.
- **Cons:** coverage varies by vendor and is thin for NDM areas (on IOS XE, nothing for AAA, lines, SSH, archive);
  `replaced`/`overridden` can lock an operator out.
- **Why rejected for the default:** the config-lines module covers every rule on every platform; the coverage report
  marks rules a person can promote to a resource module.

### F: A separate device configuration file per benchmark beside the playbook

One plain config file with a commented block per rule, applied by any tool.

- **Pros:** readable by people who do not use Ansible.
- **Cons:** a second artifact holding the same per-rule lines, with its own identity format, coverage and upgrade
  path, and its own drift from the playbook.
- **Why rejected:** the playbook's per-rule config-lines task already holds those lines, with the identity in its tags;
  one artifact is one thing to generate, cover and upgrade.

### G: Per-vendor generators (one for Cisco, one for Juniper, …)

- **Why rejected:** the only per-platform differences are the module name, `parents` support and which modules exist;
  a data table carries those, and every platform gets the same generator, coverage and upgrade. The Junos row's move
  from `junipernetworks.junos` to `juniper.device` during review was one table edit.

### H: Hand-written string templates for the YAML

- **Why rejected:** an Ansible role is far more YAML than `inspec.yml`, and quoting rules for titles, comments and
  check text are easy to get wrong; both languages already have a YAML library. The libraries' differing defaults are
  handled by building explicit node trees (decision 3), which is still the library doing the quoting.

### I: Key the toggles on the STIG ID, as ansible-lockdown does

- **Pros:** the convention operators know.
- **Why rejected:** the STIG ID is not the stable key, it changes between releases (two did on RHEL 9 V1R3 → V2R4 while
  their SV numbers held), and a toggle an operator set in `group_vars` goes stale without any warning from Ansible.
  The STIG ID stays visible in the block name.

### J: Never carry content across a cross-key pair; treat it as withdrawn plus new

- **Pros:** no misroute is ever possible.
- **Cons:** every real renumber becomes manual work, and the candidate pair is in the report anyway.
- **Why rejected for now:** carrying the content with a `needs_review` tag on both halves gives the author the same
  information with less to redo; the flag is unconditional, so nothing moves silently. Revisit if phase 2 shows
  reviewers ignoring the tag.

### K: Pre-fill `manual` / `not-applicable` from benchmark metadata

- **Pros:** fewer blocks for an author to look at on a fresh benchmark.
- **Why rejected:** the benchmark's marker is an opinion about automation that prior work contradicts all the time; a
  machine-set disposition would later be protected as "author content" and would hide rules worth automating. The
  markers are carried as tags and shown by the validator instead.

### L: Do nothing

Hardening keeps being written and upgraded by hand at every release, separately from validation. The drift described in
Context stays.

## Consequences

**What becomes easier:**

- Starting hardening for a new benchmark, any platform: one command gives a lint-clean playbook with every rule
  accounted for.
- A DISA release becomes one `hdf generate upgrade` run over the profile and the playbook, with authored content kept
  and one report of what changed, including the four defects the current profile upgrade has today.
- Seeing what is missing: coverage and pairing reports per requirement, with manual, not-applicable and withdrawn
  rules told apart from unfilled ones, and the benchmark's own markers beside them.

**What becomes harder:**

- `hdf-generators` gains a runtime YAML dependency in TypeScript and a direct one in Go, and a dependency on
  `hdf-diff` in both languages.
- CI gains a Python step (ansible-lint, yamllint, the `ansible` package) and a pinned collection install that must be
  kept current as Ansible's supported versions move; the requirements file is recompiled when the controller Python
  floor moves (2.22 needs 3.13), and the role's `min_ansible_version` needs a bump when 2.20 reaches end of life
  (May 2027).
- The identity format of decision 2 and the block shape of decision 3 become a contract: changing them later breaks
  upgrade of playbooks generated before the change.
- The upgrade's strategy order, its `--id-type` semantics, its `--prefer current` handling of identity tags and its
  reporting change for profiles too. That is a behaviour change for existing users, and a deliberate one: the measured
  misroute and the silent drops affect them today.
- This ADR waits on #499 for the converter fields it reads.

**Risks:**

- **The reader mis-matches a hand-edited block** (key tag removed or changed). Mitigation: match only on the key tag,
  report anything unmatched instead of guessing, never delete authored content on upgrade.
- **Authors put tasks outside the block.** Mitigation: the validator reports an orphan task file and the guide says
  where fixes go; the block is the whole point of the shape.
- **Authors ignore `needs_review`.** Mitigation: the validator shows it on every run, not only the upgrade report, and
  `--tags needs_review` selects those blocks.
- **ansible-lint rule churn** (rules planned but not yet implemented in `production`, such as `import-task-no-when`).
  Mitigation: pin the linter in the requirements file; generate in the shape the planned rules want; a lint failure on
  a pin bump is a generator fix, not a skip.
- **CIS input is untested here.** Mitigation: CIS stays out of phase 1; #499's CIS fixture and the identity rows in
  Phases are the gate.
- **The matcher change alters existing profile upgrades.** Mitigation: the release pairs of card 1 pin the rotation
  and the cross-key cases as regression tests, and the delta report shows every link's method and score.

## Open Questions

None open. Decided 2026-10-26: checking is `hdf validate ansible-playbook` (the `generate`/`validate threshold`
pattern); the role is named after the benchmark unless `--role-name` is given; one task file per rule. Decided
2026-10-27: the placeholder is a `block` with a named placeholder task; the match key is the bare stable-key tag;
toggles key on the SV number always and the role records its id type, platform and release; withdrawn rules are kept
under `tasks/withdrawn/` with a `withdrawn` status; every cross-key pair is flagged and carried with `needs_review`;
the Junos row uses `juniper.device`; the upgrade match becomes a library function over parsed Baselines with the stable
key matched first; the fixtures are two real RHEL 9 release pairs plus one Cisco IOS XE pair. Decided 2026-10-28: the
match always runs on the SV number regardless of `--id-type`; the disposition is author-only and benchmark markers are
carried as tags; authored automation beats an upstream manual marker on upgrade; the converter work lives in #499.

## Phases

**Phase 1 — this ADR.** Stubs with the full identity, `validate ansible-playbook`, the paired upgrade. Every rule gets
a block; no block gets a fix.

**Phase 2 — authoring, a later ADR.** Fill the blocks with remediation. Two inputs, in this order:

- **Prior work.** An existing profile or playbook for the same benchmark, an earlier release, or a sibling benchmark
  (RHEL 8 → RHEL 9; the CIS and the STIG benchmark for one platform) is matched to the new stubs with the same matcher
  (the SRG/CCI and cross-vendor tiers exist for exactly that), and what it automated is carried in as the starting
  point. The validator's "benchmark says manual, prior work automated it" cases are the first ones worth that
  treatment.
- **Model-assisted authoring** through the HDF MCP server (ADR-0007), rule by rule, from the fix text and the
  metadata already in the block's comment and tags, for what prior work does not cover. The same phase decides whether
  a model-backed matching tier for the leftover cross-key cases of decision 5 is worth adding.

Phase 1 decisions taken for phase 2's sake: the block as the container (several tasks per rule, one identity), the
bare stable-key tag (one thing to match on), the author-only structured disposition (manual and excepted rules are data,
not prose, and never machine-guessed), the `needs_review` tag (every uncertain move is visible), the benchmark
markers as tags (the authoring step sees what the benchmark expected), and the byte-preserving reader (authored content
comes back exactly as written).

**CIS.** The identity contract is DISA-shaped in two places: the stable key (SV number; for CIS it is the
recommendation number, `1.1.1`) and the category switches (`cat1`–`cat3`; for CIS, `cis_level` L1/L2). Both become a
row per benchmark family rather than a second design, decided when #499's CIS fixture converts and before any CIS
playbook is generated.

**Later.** Galaxy collection packaging; more platform rows; disruption and reboot metadata once an input carries it.

## Implementation Plan

### Scope

**IN scope:**

- Requirement identity and labels (decision 2), shared by the generator, the reader and the reports, reading the
  Baseline fields #499 provides.
- `hdf generate ansible-playbook` (Go + TS) for any STIG, with `--platform` for network STIGs;
  `hdf validate ansible-playbook` (Go + TS) with `--profile`.
- The `--platform` table with its first rows: none (host/application), `ios`, `nxos`, `eos`, `junos`.
- A reader for generated playbooks and a control-ID reader for InSpec profiles; the upgrade match as a library
  function over parsed Baselines in both languages, always on the SV number, exact first, every cross-key pair flagged,
  withdrawn rules reported, deterministic output; `hdf generate upgrade --ansible-playbook`; the pairing check in the
  delta report.
- CI lint of generated playbooks with pinned collections; the release-pair fixtures; a guide under `site/docs/guides/`
  and the updates to the existing upgrade guide.

**OUT of scope:**

- The converter changes (#499): `legacy_id`, normalised `gid`/`rid`, `extensions.release`, the DISA and CIS
  metadata, the completeness test.
- Writing remediation content for any rule (phase 2).
- Running playbooks against devices; generated AUDIT tasks; compliance results from Ansible runs.
- Deriving any disposition from benchmark metadata (alternative K).
- A model-backed matching tier (phase 2 decides).
- CIS benchmarks (see Phases).
- Adding platforms beyond the first table rows (a row each, later).
- Packaging generated content as a Galaxy collection, or publishing it to Galaxy or Automation Hub.

### Quality Standards (inherited by every card)

- **Framework-first:** input only through the existing XCCDF benchmark converter; YAML only through
  `gopkg.in/yaml.v3` / `yaml` node trees; file writes only through `hdfutil.SafePath` + `atomicfile.WriteFile`; NIST
  from the Baseline's `tags.nist`; matching only through `hdf-diff`.
- **Existing patterns:** generators are pure functions from an HDF Baseline to in-memory output, mirroring the shape
  of `GenerateInSpecProfile`; upgrade reuses `GenerateUpgrade`, `LinkRecord`s, `MergeRequirement` rules and
  `DeltaStatistics`; CLI commands follow `generate_inspec_profile.go` and `generate_upgrade.go`.
- **Go/TS parity:** the generator, the readers, the match function and the reports exist in both languages and are
  tested against the same fixtures; generated output is byte-identical between the two, asserted by one shared golden
  set under `hdf-generators/test/golden/ansible/`.
- **Tests:** TDD, including characterisation tests before any refactor of untested code; >90% coverage; golden
  outputs from real DISA benchmark fixtures (provenance per the `/fixtures` skill); every generated playbook passes
  `ansible-lint --profile production` and `yamllint` in CI; no time-dependent assertions.
- **Security:** generator output never executes anything; paths only through `SafePath`; benchmark text placed in
  names has its Jinja delimiters neutralised; benchmark text in comments is wrapped, never interpolated.
- **Docs:** one new guide page under `site/docs/guides/` plus the existing pages that change; no docs folders inside
  packages.

### Shared Abstractions (built first)

| Shared need | Used by | Phase |
|---|---|---|
| Real DISA release pairs: RHEL 9 V1R3 → V2R4 and V2R5 → V2R9, and two Cisco IOS XE Router NDM releases; XCCDF local to the converter, converted Baselines in `hdf-fixtures`, with provenance (V2R9 and the CIS fixture arrive with #499) | every phase's tests | 1 |
| Requirement identity: stable key, display key per `--id-type`, full identity, tag list including the metadata tags, NIST normalisation, toggle name, generation record | playbook generator, validator, reader, upgrade | 1 |
| `--platform` table: config-lines module, `parents` support, module coverage, checked against each module's argument spec | playbook generator, validator | 1 |
| YAML node emission with per-scalar style and one shared golden set | playbook generator, reader | 1 |

### Cards

Nineteen cards under one epic, grouped by phase, all after #499. Each card is sized for one TDD loop and one review
(2–3 story points), inherits the Quality Standards above, and points its `Prior art checked` section at this ADR's
Context. Go and TypeScript land in the same card. Total: 52 story points.

| # | Card | Phase | sp | Blocked by |
|---|---|---|---|---|
| 1 | Add the release-pair fixtures, Baselines promoted | 1 | 3 | #499 |
| 2 | Add the requirement identity and the generation record | 1 | 3 | 1 |
| 3 | Add the `--platform` table, checked against module argument specs | 1 | 2 | — |
| 4 | Add YAML node emission with a shared golden set | 1 | 3 | — |
| 5 | Generate the playbook project | 2 | 3 | 2, 3, 4 |
| 6 | Generate the per-rule placeholder blocks | 2 | 3 | 5 |
| 7 | Read a generated playbook back by its key tag, bodies by byte span | 3 | 3 | 6 |
| 8 | Read a profile's control IDs, filled state and `rid` tags | 3 | 2 | 1 |
| 9 | Check a playbook against its benchmark, with the pairing check | 3 | 3 | 7, 8 |
| 10 | Move the upgrade match into a library function over parsed Baselines, with characterisation tests | 4 | 3 | 1 |
| 11 | Match on the SV number, exact first; flag every cross-key pair; report removed rules; deterministic records | 4 | 3 | 10 |
| 12 | The merge rule and the same-release check for both artifacts | 4 | 3 | 7, 8, 11 |
| 13 | Apply one match to both artifacts: renumber, severity move, new | 4 | 3 | 12 |
| 14 | Apply one match to both artifacts: withdrawn, split, merged | 4 | 3 | 13 |
| 15 | Add the pairing check and the change lines to the delta report | 4 | 2 | 9, 14 |
| 16 | Add `hdf generate ansible-playbook` and `hdf validate ansible-playbook` | 5 | 3 | 9 |
| 17 | Add `hdf generate upgrade --ansible-playbook`, with the upgrade CLI tests | 5 | 3 | 15 |
| 18 | Lint generated playbooks in CI with pinned collections | 5 | 2 | 16 |
| 19 | Write the guide and update the existing pages | 5 | 2 | 16, 17 |

#### Phase 1: Shared foundation (cards 1–4; 3 and 4 start in parallel with #499)

**Card 1: Add the release-pair fixtures.** DISA RHEL 9 V1R3 and V2R4 (two STIG-ID-only changes and the cross-key
cases) and V2R5 (with #499's V2R9: the five-rule rotation, 8 severity changes, 5 withdrawn, 1 added, the
withdraw-and-replace), and two releases of DISA Cisco IOS XE Router NDM, as Manual XCCDF benchmark fixtures trimmed by
whole-element drops to the size guideline while keeping whole SRG groups, with provenance per the `/fixtures` skill.
The XCCDF files stay in the converter's `fixtures/input` as its tested contract; the converted Baselines (including
#499's V2R9) are promoted to `hdf-fixtures/baseline/` with a byte-identical pin to the converter golden, because the
generators, the match function and the CLI all load them.
- Files: `hdf-converters/converters/xccdf-results-to-hdf/fixtures/input/` and `expected/`, `provenance.txt`;
  `hdf-fixtures/baseline/`, `fixtures.go`, `src/index.ts`, the gate test, `README.md`
- ACs: provenance records the source URL, release, sha256 as retrieved, retrieval date and the whole elements
  dropped; every file converts through the benchmark converter (post-#499) to a Baseline that validates against the
  schema and carries `extensions.release`; the rotation still reproduces on V2R5 → V2R9 (the SRG groups involved are
  kept whole); each release pair keeps at least one withdrawn rule and one revision-only change, the RHEL 9 pairs keep
  a severity change and a STIG-ID-only change; every promoted Baseline is byte-identical to its converter golden.
- Verification: the converter's tests on the new fixtures in both languages; the `hdf-fixtures` gate.

**Card 2: Add the requirement identity and the generation record** (decision 2).
- Files: `hdf-generators/go/identity.go`, `hdf-generators/src/identity.ts`, their tests
- ACs: the stable key is the SV number; for each `--id-type` (`rule`, `group`, `version`) the display key and the
  filename of a fixture requirement match the benchmark; `cis` is rejected; the toggle name is `<role>_sv_<n>` under
  every id type; the full identity (`rid`, `gid`, `stig_id`, severity, CCIs, SRG, legacy IDs) and the tag list match,
  with the bare stable key present, NIST tags normalised from `tags.nist` with the revision passed as an option, and
  the single-value metadata tags copied; the generation record (id type, platform, release, benchmark date)
  round-trips; Go and TS agree.

**Card 3: Add the `--platform` table.**
- Files: `hdf-generators/go/platforms.go`, `hdf-generators/src/platforms.ts`, their tests
- ACs: rows none, `ios`, `nxos`, `eos`, `junos` (`juniper.device.junos_config`, no `parents`), each with config-lines
  module, `parents` support and module list; a test fixture of each module's argument spec (captured from the pinned
  collection, with provenance) confirms `lines: []` and, where claimed, `parents` are accepted and an unknown option
  is rejected; an unknown platform is an error listing the known ones.

**Card 4: Add YAML node emission with a shared golden set.**
- Files: `hdf-generators/go/yamlemit.go`, `hdf-generators/src/yaml-emit.ts`, their tests,
  `hdf-generators/test/golden/ansible/`; `hdf-generators/package.json` (`yaml`), `hdf-generators/go/go.mod`
  (`gopkg.in/yaml.v3` direct)
- ACs: both emitters build node trees with the style rule of decision 3 (every string tagged, fixed quote style, no
  folding, ordered keys, `---`, a space after `#`, no trailing blanks); comment blocks, wrapped check/fix text, titles
  with YAML-special characters, `yes`/`on`/numeric/empty strings and neutralised Jinja delimiters round-trip through
  each library's parser unchanged and lint clean; Go and TS emit identical bytes for every case in the golden set.

#### Phase 2: Playbook generator (cards 5–6)

**Card 5: Generate the playbook project** (decision 3, everything but the per-rule blocks).
- Files: `hdf-generators/go/ansible_playbook.go`, `hdf-generators/src/ansible-playbook.ts`, their tests
- ACs: `site.yml`; `roles/<name>/` named after the benchmark unless `--role-name` overrides it, with `meta/main.yml`
  (`min_ansible_version: "2.20"`, `author`, Galaxy platform names, the generation record), `defaults/main.yml` and
  `meta/argument_specs.yml` holding a toggle per rule and the category switches; `tasks/main.yml` with each category
  import wrapped in a block carrying its `when`; `requirements.yml` listing the platform's collection; `.ansible-lint`
  (`production`, `role-argument-spec`) and `.yamllint` with the required settings and an explicit `line-length`; every
  file starts with `---`; Go and TS output identical for both fixtures.

**Card 6: Generate the per-rule placeholder blocks.**
- Files: as card 5
- ACs: one task file per rule named by the stable key; one `block` in the order `name, when, tags, vars, block`,
  named `<SEVERITY> | <STIG ID> | PATCH | <rule title>` with Jinja delimiters neutralised, `when: <toggle> | bool`,
  the full tag set including the bare key, the metadata tags and `placeholder`, check and fix text and prose metadata
  as wrapped, right-trimmed comments above it; no disposition is ever emitted; a named `ansible.builtin.debug`
  placeholder task without `--platform`, the platform's config-lines task with empty `lines:` (and `parents:` where
  the row allows) with it; no `overridden`/`replaced`; both fixtures lint clean at `production`.

#### Phase 3: Readers and the check (cards 7–9)

**Card 7: Read a generated playbook back.**
- Files: `hdf-generators/go/playbook_reader.go`, `hdf-generators/src/playbook-reader.ts`, their tests
- ACs: the id type and platform are read from the generation record; every block is matched to its requirement by
  the key tag only; a block whose key tag is removed or unknown is reported, never guessed; the disposition is read
  from `vars`; author-added tags are returned as the block's tags minus the metadata set; authored bodies (every task
  beyond the placeholder, network `lines:` included) are returned byte for byte from the original file by the span rule
  of decision 5, with positions converted to byte offsets in both languages and a multi-byte title in the fixture;
  `tasks/withdrawn/` blocks are read with status `withdrawn`.

**Card 8: Read a profile's control IDs, filled state and `rid` tags.**
- Files: `hdf-generators/go/profile_reader.go`, `hdf-generators/src/profile-reader.ts`, their tests
- ACs: control IDs and `tag rid:` values read from `controls/*.rb` with the anchored control pattern the profile
  generator already defines in both languages, no Ruby; each control reported as stub (the generator's stub marker
  present) or filled; the `inspec.yml` version read; tested on a profile generated from the fixture with two controls
  filled.

**Card 9: Check a playbook against its benchmark** (decision 4).
- Files: `hdf-generators/go/playbook_coverage.go`, `hdf-generators/src/playbook-coverage.ts`, their tests
- ACs: every status of decision 4 on a generated playbook with some blocks filled, one of each disposition, one block
  withdrawn, one removed and one orphan; a declared disposition wins over the body; a benchmark marker never changes a
  status and is shown beside it; `needs_review` surfaced; promote hint per network rule; the pairing check against the
  profile of card 8 reports the disagreeing requirements and nothing else; both fixtures.

#### Phase 4: Paired upgrade (cards 10–15)

**Card 10: Move the upgrade match into a library function.**
- Files: `hdf-generators/go/upgrade_match.go`, `hdf-generators/src/upgrade-match.ts`, their tests;
  `hdf-generators/go/go.mod` and `package.json` (`hdf-diff`); `hdf-cli/cmd/hdf/cmd/generate_upgrade.go`,
  `generate_delta.go`, `generate_upgrade_test.go` (new)
- ACs: characterisation tests of the CLI's file-input path (XCCDF and Baseline inputs, no InSpec shell-out) are
  written and green before the refactor; match → `LinkRecord`s → mismatch flag is one function over two parsed
  Baselines with the CLI's current strategy chain and `--strategy` override, in Go and TS; parsing and validation stay
  in the CLI, which calls the function; on the RHEL 9 V2R5 → V2R9 fixture both languages produce the same records,
  rotation included (pinned as the regression the next card fixes).

**Card 11: Match on the SV number, exact first; flag every cross-key pair; report removed rules.**
- Files: as card 10, plus `hdf-generators/go/delta.go`, `delta_types.go`, `delta_report.go`, `src/delta.ts`,
  `delta-types.ts`, `delta-report.ts`
- ACs: `remapBaselineIDs` no longer runs before matching and `--id-type` affects only names and filenames (help text
  and strategy-order help updated); `exactId` on the SV number runs first and the SRG/CCI and fuzzy tiers see only
  keys present on one side; the rotation no longer occurs and the V1R3 → V2R4 STIG-ID-only changes match exactly;
  `PotentialMismatch` is "keys differ" for every strategy, score and relationship, and the V1R3 → V2R4 cross-key
  cases are all flagged; unmatched current requirements appear as `removed` records (`newId` empty in both
  languages, the TS type extended, the report printing them as removed) counted by `Removed`; the redefined
  `DeltaStatistics` invariants hold on V2R5 → V2R9; records are sorted by `newId` then `oldId` and two runs are
  byte-identical; the profile's drop/keep behaviour is unchanged.

**Card 12: The merge rule and the same-release check for both artifacts** (decision 5).
- Files: `hdf-generators/go/merge.go`, `src/merge.ts`, `hdf-generators/go/paired_upgrade.go`,
  `src/paired-upgrade.ts`, their tests
- ACs: the metadata tag set is named in code once and shared by both artifacts; identity and metadata tags take
  upstream under every `--prefer`; `placeholder` is recomputed and author-added tags are kept; an upstream manual,
  documentable or unscored marker never removes authored automation and is reported as kept; the same-release check
  compares the generation record with the profile's `inspec.yml` version and the per-key `rid` tags, stops a
  mismatched pair, names the artifact behind, and ignores `tasks/withdrawn/`; a second run on the same pair passes.

**Card 13: Apply one match to both artifacts: renumber, severity move, new.**
- Files: `hdf-generators/go/paired_upgrade.go`, `src/paired-upgrade.ts`, `delta.go`, `delta.ts`, their tests
- ACs: one match applied to both artifacts; a renumbered rule moves file, key and toggle with `needs_review` on both
  halves and the old and new toggle names recorded; a severity move changes the directory and is recorded from a join
  to both Baselines; a new rule gets a placeholder block; authored bodies and dispositions survive byte for byte;
  `defaults`, `argument_specs` and the generation record are rewritten, `vars/`, `handlers/`, `templates/`, `files/`
  untouched; on the real release pairs.

**Card 14: Apply one match to both artifacts: withdrawn, split, merged.**
- Files: as card 13
- ACs: a withdrawn block moves under `tasks/withdrawn/`, is not imported, keeps its toggle defaulted `false`, and is
  recorded (in place with `--keep-unmatched`); a split (one `oldId`, several `newId`s) copies the body into each new
  block with `needs_review`; a merge (several `oldId`s, one `newId`) keeps the primary's body, appends the others as
  commented text with `needs_review`; the profile side reports its dropped merge members; on the real release pairs.

**Card 15: Add the pairing check and the change lines to the delta report.**
- Files: `hdf-generators/go/delta_report.go`, `src/delta-report.ts`, their tests
- ACs: the report lists renamed toggles (old and new), category moves, withdrawn and removed rules, kept automation
  over an upstream marker, every `needs_review` block with its strategy and score, the split and merge groups, and
  the pairing column of decision 5; markdown and JSON forms agree; both languages.

#### Phase 5: CLI, CI and docs (cards 16–19)

**Card 16: Add the generate and validate commands.**
- Files: `hdf-cli/cmd/hdf/cmd/generate_ansible_playbook.go`, `validate_ansible_playbook.go`, `generate.go`,
  `validate.go`, their tests
- ACs: `hdf generate ansible-playbook` and `hdf validate ansible-playbook` (with `--profile`; non-zero exit on
  `missing` or `orphan`, zero on `withdrawn`) registered and documented in help; writes only through `SafePath` +
  `atomicfile`; `--id-type`, `--platform` and `--nist-rev` validated at the boundary.
- Verification: `cd hdf-cli && go test ./cmd/hdf/cmd/ -run 'Test(Generate|Validate)AnsiblePlaybook' -v`

**Card 17: Add `hdf generate upgrade --ansible-playbook`.**
- Files: `hdf-cli/cmd/hdf/cmd/generate_upgrade.go`, `generate_upgrade_test.go`
- ACs: `--ansible-playbook <dir>` runs the paired upgrade of cards 12–14 with `<current>` as the profile, the old
  benchmark or a Baseline, and writes both artifacts through `SafePath` + `atomicfile`; a recorded id type or
  platform that does not match the run is an error; the delta report of card 15 is written; the CLI tests cover the
  profile path and the paired path on the fixtures.
- Verification: `cd hdf-cli && go test ./cmd/hdf/cmd/ -run TestGenerateUpgrade -v`

**Card 18: Lint generated playbooks in CI** (decision 6).
- Files: `.github/requirements/ansible-lint.in`, `.github/requirements/ansible-lint.txt`, `.github/dependabot.yml`,
  `.github/workflows/ci.yml`
- ACs: CI builds the CLI, generates a playbook from each fixture (host, and `--platform ios`), installs the pinned
  `ansible` package from the hash-pinned requirements compiled for Python 3.12 and `juniper.device` from its
  sha256-checked tarball with `--offline`, and runs `ansible-lint --profile production --offline` and `yamllint`;
  Dependabot's `allow` list covers the new packages; a lint failure fails the build.

**Card 19: Write the guide.**
- Files: `site/docs/guides/generate-hardening.md`, `site/docs/guides/generate-upgrade.md`,
  `site/docs/packages/hdf-generators.md`, `site/docs/packages/hdf-cli.md`, the VitePress sidebar
- ACs: covers generate, validate, the block shape authors fill (tasks inside the block, named), the author-only
  disposition and the benchmark markers beside it, `needs_review`, `--profile`, and the paired upgrade with commands
  checked against the CLI, including the changed `--id-type` and `--prefer` semantics; no emoji; built by the site.

### Verification Strategy

- End to end: for a host STIG (RHEL 9 V2R5) and a network STIG (Cisco IOS XE Router NDM, `--platform ios`), generate a
  profile and a playbook; fill two rules on each side, one of them a rule the benchmark marks documentable, and declare
  one disposition; upgrade both onto the next real release; check filled content and dispositions survive byte for
  byte, the documentable rule's automation is kept and reported, metadata updates, the withdrawn rules land under
  `tasks/withdrawn/`, the severity moves and the withdraw-and-replace pair are in the report with `needs_review` on
  the latter, and the pairing column shows only the rules filled on one side.
- Cross-key: V1R3 → V2R4 with two rules filled; the two STIG-ID-only changes match exactly and keep their toggles under
  every `--id-type`; the four cross-key pairs are all flagged.
- Edge cases: a rule withdrawn upstream, then a second upgrade of the same pair (no orphan, no release-check stop); a
  rule whose SV revision changed only; a hand-edited block with its key tag removed (reported, not matched); a block
  with tasks added beside the placeholder; a toggle passed as a string from `-e`; titles with YAML-special characters,
  Jinja delimiters and multi-byte characters; a profile and playbook from different releases (stopped, with the
  artifact behind named); `--prefer current` followed by a second upgrade (no stale `rid`).
- Linters on every generated playbook in CI; Go/TS byte parity on every generated file; two identical upgrade runs
  produce identical reports.
