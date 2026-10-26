# ADR-0018: Hardening content generation from benchmarks, and one upgrade for validation and hardening

- **Status:** Proposed
- **Date:** 2026-10-26
- **Deciders:** Aaron Lippold
- **Relates to:**
  - `hdf generate inspec-profile` (XCCDF benchmark → HDF Baseline → InSpec profile stubs) and `hdf generate upgrade`
    (smart-merge an existing baseline or profile onto a newer benchmark). This ADR adds hardening outputs beside the
    validation output and extends the upgrade to carry both.
  - The `xccdf-results-to-hdf` converter's benchmark path (`ConvertXccdfBenchmarkToHDF`), which every generator here
    reads through.

## Context

A security baseline has two halves: **validation** (does the system meet each requirement?) and **hardening** (make
it meet each requirement). hdf-libs generates the first half from a benchmark: `hdf generate inspec-profile` turns a
DISA STIG XCCDF into InSpec control stubs, and `hdf generate upgrade` moves an existing, filled-in profile onto the
next benchmark release, matching requirements by SRG/CCI semantics rather than exact ID, letting upstream win on
metadata and the author win on code. Nothing generates or upgrades the second half.

Teams that harden with Ansible start every role by hand from the benchmark, then re-do the bookkeeping by hand at every
DISA release (new SV revisions, renumbered or withdrawn rules, changed titles and fix text), separately from the
profile. The two drift: a control is upgraded and its hardening task is not, or a rule gains hardening with no control.

**Prior art does not close the gap** (checked 2026-10-26; licenses read from the repositories):

- `ansible-lockdown/Benchmark-Generator` (MIT; last commit 2020-08-18; MITRE fork `mitre/benchmark-generator`, no
  changes since): parses an XCCDF with lxml and writes `cat1.yml`…`cat3.yml` with an AUDIT/PATCH placeholder pair per
  rule. Its output no longer runs or lints: `always_run` was removed in Ansible 2.6, `command: true` placeholders with
  blanket `ignore_errors`, no FQCN; it keys on the group ID (`V-…`) only, drops the rule ID, STIG ID, CCIs, legacy IDs
  and the fix/check text; its sort result is discarded; a failed input exits 0. The per-rule skeleton idea is the part
  worth keeping.
- `oscap xccdf generate fix --fix-type ansible` (OpenSCAP 1.4.6, LGPL-2.1) emits the `<fix>` elements whose system is
  `urn:xccdf:fix:script:ansible`. **DISA STIG XCCDFs carry none**: every `<fix>` is empty (e.g. all 42 in Cisco IOS XE
  Router NDM V3R7, all 445 in RHEL 9 V2R9); fix prose lives only in `<fixtext>`. Useful for ComplianceAsCode
  datastreams, not for DISA input.
- ComplianceAsCode/content (BSD-3-Clause) and the `RedHatOfficial/ansible-role-*` roles it publishes: hand-written or
  templated remediations per rule for RHEL products only; no Cisco product. Their `reboot` / `strategy` /
  `complexity` / `disruption` metadata is a good vocabulary. The published role is one 64,665-line `tasks/main.yml`
  with uppercase toggle names that fail `var-naming`, and no SV/V identifiers.
- DISA "STIG for Ansible" packages (e.g. `U_RHEL_9_V2R9_STIG_Ansible.zip`, July 2026): one hand-written role per
  product; tasks keyed by the revision-free SV number, no tags, no FQCN; a callback writes an XCCDF TestResult whose
  pass/fail is "changed". DISA states those results may differ from STIG compliance. No Cisco IOS XE package was
  found.
- ansible-lockdown's maintained STIG roles (MIT; RHEL9-STIG pushed 2026-10-21) are the current community convention
  for hand-maintained hardening: task names `<SEVERITY> | <STIG ID> | PATCH | <title>`, a toggle per rule, tags
  carrying STIG ID, `CATn`, every CCI and SRG, the full `SV-…r…_rule` and `V-…`, NIST; PATCH-first (413 PATCH, 14
  AUDIT, 5 WARN tasks), with compliance auditing in a separate `-Audit` repository. Their Cisco roles were last
  pushed in 2022.
- `OpenSTIG-Ansible/cisco_ios-xe_router_ndm_stig` (Apache-2.0, 2025): hand-written, some tasks merge nine rules,
  which breaks per-rule coverage.

No maintained tool turns a DISA XCCDF into a role skeleton that meets today's Ansible standards, and none keeps
hardening and validation in step across releases.

**What the input already provides.** The benchmark path of `xccdf-results-to-hdf` produces an HDF Baseline whose
requirements carry everything a generator needs: `gid` (V-ID), `rid` (`SV-…r…_rule`), `stig_id`, `severity`,
`cci`, `gtitle` (SRG), `legacy_id`, and `check` / `fix` descriptions. Nothing here parses XCCDF again.

**Current Ansible standards** the output must meet (2026-10-26): ansible-core 2.19 reaches end of life in
November 2026, 2.20 and 2.21 are supported (controller Python 3.12–3.14), 2.22 is in release candidate. Red Hat's
partner certification requires ansible-lint's `production` profile (cumulative: `basic`, `moderate`, `safety`,
`shared`, then `fqcn`) and lists rules that may never be skipped (`no-changed-when`, `risky-file-permissions`,
`command-instead-of-*`, `risky-shell-pipe`, `no-handler`, `package-latest`, `meta-no-info`, `unnamed-task`,
`meta-runtime[unsupported-version]`). ansible-lint 26.10.1's built-in supported-version list stops at 2.19, so a role
requiring 2.20 must declare `supported_ansible_also`. A custom `.yamllint` must carry the settings ansible-lint
requires or the linter refuses to run.

**Any STIG, any platform.** The benchmark may be for an operating system, an application or a network device. On the
host side Ansible's built-in modules cover remediation. Network platforms each have a vendor collection with a
generic "config lines" module (`cisco.ios.ios_config`, `cisco.nxos.nxos_config`, `arista.eos.eos_config`,
`junipernetworks.junos.junos_config`, …) and a varying set of resource modules. Taking Cisco IOS XE as the measured
example: `cisco.ios` 11.6.0 (GPL-3.0) has resource modules for logging, NTP, SNMP, ACLs, interfaces, services and
routes, but none for AAA, TACACS/RADIUS, `line con/vty`, `ip ssh`, `login block-for` or `archive`, which most NDM
STIG rules need; `ios_config` covers every rule as literal CLI lines, idempotent only for long-form commands written
as the device prints them.

## Decision

### 1. Generate hardening content from the same HDF Baseline as the profile

New generators in `hdf-generators` (Go and TypeScript, kept in parity like the profile generator) take an HDF
Baseline and build their output in memory, with no file I/O; the CLI writes it with `hdfutil.SafePath` and
`atomicfile.WriteFile`, as `generate inspec-profile` does. Input comes only through the existing converters
(XCCDF benchmark → Baseline); no XCCDF parser is added. DISA STIG input first; CIS XCCDF later, once a real CIS
XCCDF fixture shows the converter handles it.

### 2. One requirement identity, written into every artifact

Every generated artifact carries the same machine-readable identity per requirement, so artifacts can be matched to
each other and across releases without reading prose:

- **Stable key:** the revision-free rule number (`SV-215807`), the same key MITRE profiles and SAF CLI's default
  `--idType rule` use; `--id-type rule|group|version` (the values `generate upgrade` already accepts) selects V-ID or
  STIG ID instead for names and filenames.
- **Full identity in metadata:** `rid` with revision (`SV-215807r1186318_rule`), `gid` (`V-215807`), `stig_id`,
  severity, CCIs, SRG, NIST controls (from CCIs via `hdf-mappings`), and legacy IDs. The revision changes every
  release, so it is never a key.
- **People see the STIG ID** in names, as both maintained Ansible ecosystems do.

In a generated playbook the identity is the task's tag set (decision 3); the readers of decision 5 match on those tags.

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

The reusable unit is the role; `site.yml` is the short entry point that runs it. The role is named after the benchmark, snake-cased (e.g. `cisco_ios_xe_router_ndm_stig`), unless `--role-name` overrides it. The role's `meta/main.yml` declares
`min_ansible_version: "2.20"` (2.19 is end of life in November 2026). Packaging as a Galaxy collection is future work.
The role holds:

- One task file per rule, named by the stable key (`tasks/cat2/SV-215807.yml`), imported by `tasks/cat1|cat2|cat3/main.yml`;
  each holds one **PATCH placeholder** task, named
  `<SEVERITY> | <STIG ID> | PATCH | <rule title>`, using FQCN modules. A placeholder is an explicit
  "not implemented" warning task (no change, no failure), so an unfilled rule shows up in the coverage report instead
  of passing silently. The rule's check text and fix text are carried as YAML comments above the task.
- **No generated AUDIT tasks.** Validation is the InSpec profile generated from the same Baseline; the pairing report
  (decision 5) keeps the two in step. This matches the maintained community roles, which are PATCH-first with
  auditing kept separate, and DISA's own warning that "changed" is not compliance.
- A toggle per rule (`<role>_<stig_id_snake>: true`, role-prefixed and lowercase for `var-naming`), category switches
  (`<role>_cat1`…`cat3`), and a `<role>_disruption_high` switch; all in `defaults/main.yml` and
  `meta/argument_specs.yml`. Tags per task: STIG ID, `CATn`, `V-…`, full `rid`, each CCI and SRG, NIST in
  `NIST800-53R5_<control>` form, and `patch`. No `never` gating.
- `.ansible-lint` (`profile: production`, `role-argument-spec` enabled, no skips from the certification list, plus
  whatever supported-version setting the pinned ansible-lint needs for the declared minimum; ansible-lint 26.10.1's
  built-in list stops at 2.19) and a `.yamllint` with the settings ansible-lint requires.

**Any STIG, any platform, one output.** Placeholders are platform-neutral by default (host and application STIGs).
For a network STIG, `--platform` selects a row of a small data table (not per-vendor code): the platform's
config-lines module, whether it takes `parents`, and which resource modules the platform's collection has. First
rows: `ios` → `cisco.ios.ios_config`, `nxos` → `cisco.nxos.nxos_config`, `eos` → `arista.eos.eos_config`,
`junos` → `junipernetworks.junos.junos_config`. Each rule's placeholder is then a task of that module with an empty
`lines:` list (and `parents:` where the rule's fix text names a section), so filling in a rule's device configuration
means writing its lines into its task. The device configuration lives in the playbook; there is no separate config
file to keep in step. The generator never emits resource-module `state: overridden` or `replaced`. Adding a platform
is a table row.

Generated YAML is produced with a YAML library, not string templates: `go.yaml.in/yaml/v3` in Go (already in the
module graph) and `yaml` in TypeScript (already a workspace dependency of `hdf-openapi`).

### 4. Checking a playbook against its benchmark: `hdf validate ansible-playbook`

Creating and checking are separate commands, the way hdf already pairs `generate threshold` with `validate threshold`, and the way Ansible keeps checking a playbook (`ansible-lint`, `--list-tasks`) apart from producing it.
`hdf validate ansible-playbook <dir> --baseline <file>` reads a generated playbook and reports per requirement: identifiers, severity,
status (`implemented` / `placeholder` / `missing` / `excepted`), and, for network platforms, whether the platform's
collection has a resource module covering the rule (from the `--platform` table), so a person can promote it from the
config-lines module. A rule is `implemented` when its task is no longer the placeholder (for network platforms: its
`lines:` are filled in), and `excepted` when its task carries a documented reason it cannot be configured. Exit status
is non-zero when any requirement is `missing`.

### 5. One upgrade for validation and hardening, and a pairing check

`hdf generate upgrade` gains a hardening target beside the profile it already upgrades: `--ansible-playbook <dir>`.
The requirement match between current and upstream is computed **once** (the existing SRG/CCI matching and
`LinkRecord`s) and applied to the profile and the playbook in the same run, with the existing merge rule per artifact:
upstream wins on metadata (names, tags, identity, check/fix comments, toggle names), the author wins on content
(InSpec code, task bodies including network `lines:`). New requirements get placeholders; unmatched ones are reported,
or kept with `--keep-unmatched`. A rule renumbered between releases is renumbered identically in the profile and the
playbook.

The delta report gains a **pairing check**: requirements with validation but no hardening, and hardening with no
validation. The same check is available without an upgrade through `hdf validate ansible-playbook`.

Upgrading a playbook requires reading it back; the reader matches on the identity of decision 2 (task tags), never on
prose.

### 6. The generated output is checked by the real linters in CI

CI runs `ansible-lint --profile production` and `yamllint` on playbooks generated from the committed benchmark
fixtures, installing both from hash-pinned requirements files the way the semgrep step already does. The generator and
the CLI have no Python dependency; Python is only in that CI step and on the machines that run the playbooks.

## Alternatives Considered

### A: Modernise `mitre/benchmark-generator` in Python as a standalone tool

Keep the fork, rewrite its parser and templates to current Ansible standards.

- **Pros:** closest to the original; Ansible users already have Python.
- **Cons:** a second XCCDF parser beside the converter hdf-libs already maintains and tests; no access to
  `GenerateUpgrade`'s matching, so validation and hardening cannot be upgraded together; a separate release and CLI.
- **Why rejected:** decision 5 needs the profile and the playbook upgraded from one match, which only works inside
  hdf-libs. The fork stays credited as the origin of the per-rule skeleton idea.

### B: `oscap xccdf generate fix --fix-type ansible`

- **Why rejected:** DISA STIG XCCDFs contain no Ansible fix scripts, so it produces nothing for this input.

### C: Adopt ComplianceAsCode or the RedHatOfficial roles

- **Why rejected:** RHEL-only content, no network platforms; the published roles do not lint clean at `production`
  and carry no SV/V identity. Their disruption/complexity/reboot vocabulary is reused as a reference for the switches
  in decision 3.

### D: Generate AUDIT and PATCH pairs per rule (Benchmark-Generator's model)

- **Pros:** one artifact both checks and fixes.
- **Cons:** duplicates the InSpec profile with weaker checks; "changed" is not compliance; the maintained roles moved
  away from it (14 AUDIT tasks against 413 PATCH).
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

- **Why rejected:** the only per-platform differences are the module name, `parents` support and which resource
  modules exist; a data table carries those, and every platform gets the same generator, coverage and upgrade.

### H: Hand-written string templates for the YAML

- **Why rejected:** an Ansible role is far more YAML than `inspec.yml`, and quoting rules for titles, comments and
  check text are easy to get wrong; both languages already have the YAML library.

### I: Do nothing

Hardening keeps being written and upgraded by hand at every release, separately from validation. The drift described in
Context stays.

## Consequences

**What becomes easier:**

- Starting hardening for a new benchmark, any platform: one command gives a lint-clean playbook with every rule
  accounted for.
- A DISA release becomes one `hdf generate upgrade` run over the profile and the playbook, with authored content kept
  and one report of what changed.
- Seeing what is missing: coverage and pairing reports per requirement.

**What becomes harder:**

- `hdf-generators` gains a YAML dependency in TypeScript and a direct one in Go.
- CI gains a Python step (ansible-lint, yamllint) that must be kept current as Ansible's supported versions move;
  the role's `min_ansible_version` and the linter's version setting need a bump when 2.20 reaches end of life (May 2027).
- The identity format of decision 2 becomes a contract: changing the tags later breaks upgrade of playbooks generated
  before the change.

**Risks:**

- **The reader mis-matches a hand-edited task** (tags removed or changed). Mitigation: match only on the identity tags,
  report anything unmatched instead of guessing, never delete authored content on upgrade.
- **ansible-lint rule churn** (rules planned but not yet implemented in `production`). Mitigation: pin the linter in
  the requirements file; a lint failure on a pin bump is a generator fix, not a skip.
- **CIS input is untested.** Mitigation: CIS stays out of scope until a real CIS XCCDF fixture passes the converter.

## Open Questions

None open. Decided 2026-10-26: checking is `hdf validate ansible-playbook` (the `generate`/`validate threshold` pattern); the role is named after the benchmark unless `--role-name` is given; one task file per rule.

## Implementation Plan

### Scope

**IN scope:**

- Requirement identity and labels (decision 2), shared by the generator, the reader and the reports.
- `hdf generate ansible-playbook` (Go + TS) for any STIG, with `--platform` for network STIGs;
  `hdf validate ansible-playbook` (Go + TS).
- The `--platform` table with its first rows: none (host/application), `ios`, `nxos`, `eos`, `junos`.
- A reader for generated playbooks; `hdf generate upgrade --ansible-playbook`; the pairing check in the delta report.
- CI lint of generated playbooks; benchmark fixtures; a guide under `site/docs/guides/`.

**OUT of scope:**

- Writing remediation content for any rule (the generator emits placeholders).
- Running playbooks against devices; generated AUDIT tasks; compliance results from Ansible runs.
- CIS benchmarks (until a real CIS XCCDF fixture passes the converter).
- Adding platforms beyond the first table rows (a row each, later).
- Packaging generated content as a Galaxy collection, or publishing it to Galaxy or Automation Hub.

### Quality Standards (inherited by every card)

- **Framework-first:** input only through the existing XCCDF benchmark converter; YAML only through
  `go.yaml.in/yaml/v3` / `yaml`; file writes only through `hdfutil.SafePath` + `atomicfile.WriteFile`; CCI → NIST
  only through `hdf-mappings`.
- **Existing patterns:** generators are pure functions from an HDF Baseline to in-memory output, mirroring
  `GenerateInSpecProfile`; upgrade reuses `GenerateUpgrade`'s matching, `LinkRecord`s, `MergeRequirement` rules and
  `DeltaStatistics`; CLI commands follow `generate_inspec_profile.go` and `generate_upgrade.go`.
- **Go/TS parity:** the generator, the reader and the report exist in both languages and are tested against the same
  fixtures; output is byte-identical between the two.
- **Tests:** TDD; >90% coverage; golden outputs from real DISA benchmark fixtures (provenance per the `/fixtures`
  skill); every generated playbook passes `ansible-lint --profile production` and `yamllint` in CI; no time-dependent
  assertions.
- **Security:** generator output never executes anything; paths only through `SafePath`; benchmark text placed in
  comments and names is escaped by the YAML library, never interpolated into Jinja.
- **Docs:** one guide page under `site/docs/guides/`; no docs folders inside packages.

### Shared Abstractions (built first)

| Shared need | Used by | Phase |
|---|---|---|
| Requirement identity: stable key per `--id-type`, full identity, NIST from CCI, tag list | playbook generator, coverage, reader, upgrade | 1 |
| `--platform` table: config-lines module, `parents` support, resource-module coverage | playbook generator, coverage | 1 |
| YAML emission helpers on the YAML library (comments above tasks, safe scalars) | playbook generator, reader | 1 |
| Real DISA benchmark fixtures, one host STIG (RHEL 9) and one network STIG (Cisco IOS XE Router NDM), with provenance | every phase's tests | 1 |

### Cards

Twelve cards under one epic, grouped by phase. Each card is sized for one TDD loop and one review (2–3 story
points), inherits the Quality Standards above, and points its `Prior art checked` section at this ADR's Context.
Go and TypeScript land in the same card. Total: 31 story points.

| # | Card | Phase | sp | Blocked by |
|---|---|---|---|---|
| 1 | Add the benchmark fixtures | 1 | 2 | — |
| 2 | Add the requirement identity | 1 | 3 | 1 |
| 3 | Add the `--platform` table | 1 | 2 | — |
| 4 | Add YAML emission on the YAML libraries | 1 | 2 | — |
| 5 | Generate the playbook project | 2 | 3 | 2, 3, 4 |
| 6 | Generate the per-rule PATCH placeholder tasks | 2 | 3 | 5 |
| 7 | Check a playbook against its benchmark | 3 | 3 | 6 |
| 8 | Read a generated playbook back by its identity tags | 4 | 3 | 6 |
| 9 | Upgrade the profile and the playbook from one match | 4 | 3 | 7, 8 |
| 10 | Add the CLI commands | 5 | 3 | 7, 9 |
| 11 | Lint generated playbooks in CI | 5 | 2 | 10 |
| 12 | Write the guide | 5 | 2 | 10 |

#### Phase 1: Shared foundation (cards 1–4; 1, 3 and 4 start in parallel)

**Card 1: Add the benchmark fixtures.** One host STIG (DISA RHEL 9) and one network STIG (DISA Cisco IOS XE Router
NDM V3R7) as XCCDF benchmark fixtures, with provenance per the `/fixtures` skill; shared through `hdf-fixtures` only
if a second package loads them.
- Files: the fixture files, `provenance.txt`
- ACs: provenance records the source URL, release, sha256 as retrieved and retrieval date; both convert through the
  existing benchmark converter to a Baseline that validates against the schema.
- Verification: the converter's tests on the new fixtures in both languages.

**Card 2: Add the requirement identity** (decision 2).
- Files: `hdf-generators/go/identity.go`, `hdf-generators/src/identity.ts`, their tests
- ACs: for each `--id-type` (`rule`, `group`, `version`) the stable key of a fixture requirement matches the
  benchmark; the full identity (`rid`, `gid`, `stig_id`, severity, CCIs, SRG, legacy IDs) and the tag list match;
  NIST tags come from `hdf-mappings` per CCI in `NIST800-53R5_<control>` form; Go and TS agree.

**Card 3: Add the `--platform` table.**
- Files: `hdf-generators/go/platforms.go`, `hdf-generators/src/platforms.ts`, their tests
- ACs: rows none, `ios`, `nxos`, `eos`, `junos`, each with config-lines module, `parents` support and resource
  modules, checked against each collection's published docs; an unknown platform is an error listing the known ones.

**Card 4: Add YAML emission on the YAML libraries.**
- Files: `hdf-generators/go/yamlemit.go`, `hdf-generators/src/yaml-emit.ts`, their tests; `hdf-generators/package.json`
  (`yaml`), `hdf-generators/go/go.mod` (`go.yaml.in/yaml/v3` direct)
- ACs: comment blocks above a task, multi-line check/fix text, and YAML-special characters in titles round-trip
  through each library's parser unchanged; Go and TS emit identical bytes for the same input.

#### Phase 2: Playbook generator (cards 5–6)

**Card 5: Generate the playbook project** (decision 3, everything but the per-rule tasks).
- Files: `hdf-generators/go/ansible_playbook.go`, `hdf-generators/src/ansible-playbook.ts`, their tests
- ACs: `site.yml`; `roles/<name>/` named after the benchmark unless `--role-name` overrides it, with `meta/main.yml`
  (`min_ansible_version: "2.20"`), `defaults/main.yml` and `meta/argument_specs.yml` holding a toggle per rule and
  the category and disruption switches; `requirements.yml` listing the platform's collection; `.ansible-lint`
  (`production`, `role-argument-spec`) and `.yamllint`; Go and TS output identical for both fixtures.

**Card 6: Generate the per-rule PATCH placeholder tasks.**
- Files: as card 5
- ACs: one task file per rule named by the stable key, imported by the category's `main.yml`; task named
  `<SEVERITY> | <STIG ID> | PATCH | <rule title>`, tagged per decision 3, gated by its toggle, check and fix text as
  comments above it; platform-neutral "not implemented" placeholder without `--platform`, the platform's
  config-lines task with empty `lines:` (and `parents:` where it applies) with it; no `overridden`/`replaced`.

#### Phase 3: Playbook check (card 7)

**Card 7: Check a playbook against its benchmark** (decision 4).
- Files: `hdf-generators/go/playbook_coverage.go`, `hdf-generators/src/playbook-coverage.ts`, their tests
- ACs: per requirement `implemented` / `placeholder` / `missing` / `excepted` on a generated playbook with some rules
  filled, one excepted and one removed; resource-module hint per network rule; the pairing check against an InSpec
  profile generated from the same Baseline; both fixtures.

#### Phase 4: Paired upgrade (cards 8–9)

**Card 8: Read a generated playbook back by its identity tags.**
- Files: `hdf-generators/go/playbook_reader.go`, `hdf-generators/src/playbook-reader.ts`, their tests
- ACs: every task is matched to its requirement by its tags only; a task whose tags were removed or changed is
  reported as unmatched, never guessed; authored task bodies (including network `lines:`) are returned byte for byte.

**Card 9: Upgrade the profile and the playbook from one match** (decision 5).
- Files: `hdf-generators/go/delta.go`, `hdf-generators/go/delta_types.go`, `hdf-generators/src/delta.ts`,
  `hdf-generators/src/delta-types.ts`, their tests
- ACs: one `GenerateUpgrade` match applied to the profile and the playbook in one run; a renumbered rule is
  renumbered identically in both; authored content survives and metadata follows upstream; new rules get
  placeholders, unmatched ones are reported (or kept with `--keep-unmatched`), never deleted; the pairing check
  appears in the delta report. Tested on an old and a new release of one benchmark.

#### Phase 5: CLI, CI and docs (cards 10–12)

**Card 10: Add the CLI commands.**
- Files: `hdf-cli/cmd/hdf/cmd/generate_ansible_playbook.go`, `hdf-cli/cmd/hdf/cmd/validate_ansible_playbook.go`,
  `hdf-cli/cmd/hdf/cmd/generate_upgrade.go`, their tests
- ACs: `hdf generate ansible-playbook`, `hdf validate ansible-playbook` (non-zero exit on `missing`) and
  `hdf generate upgrade --ansible-playbook`; writes only through `SafePath` + `atomicfile`; `--id-type` and
  `--platform` validated at the boundary.
- Verification: `cd hdf-cli && go test ./cmd/hdf/cmd/ -run 'Test(Generate|Validate)' -v`

**Card 11: Lint generated playbooks in CI** (decision 6).
- Files: `.github/requirements/ansible-lint.txt`, `.github/workflows/ci.yml`
- ACs: CI generates a playbook from each fixture and runs `ansible-lint --profile production` and `yamllint` from
  hash-pinned requirements, the way the semgrep step installs semgrep; a lint failure fails the build.

**Card 12: Write the guide.**
- Files: `site/docs/guides/generate-hardening.md`
- ACs: covers generate, validate and upgrade with commands checked against the CLI; no emoji; built by the site.

### Verification Strategy

- End to end: for a host STIG (RHEL 9) and a network STIG (Cisco IOS XE Router NDM V3R7, `--platform ios`), generate a
  profile and a playbook; fill two rules; upgrade both onto a later release (or a fixture derived by whole-element
  drops); check filled content survives, metadata updates, and the pairing report is empty.
- Edge cases: a rule withdrawn upstream; a rule whose SV revision changed only; a hand-edited task with its tags
  removed (reported, not matched); a requirement with no fix text; titles with YAML-special characters.
- Linters on every generated playbook in CI; Go/TS byte parity on every generated file.
