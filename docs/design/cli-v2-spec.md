# HDF CLI v2 Design Spec

> **Note (v3.1.0):** This design spec has been largely implemented. See the CHANGELOG
> and current CLI help (`hdf --help`) for the authoritative command reference.

> Design review for the HDF CLI in the context of the full v2 schema ecosystem
> (7 document types, fingerprint auto-detection, labels, typed inputs, OSCAL alignment).

## Design Principles

1. **POSIX conventions** — flags for options, single positional arg for the input file
2. **Auto-detect by default** — the CLI should figure out what you gave it
3. **Explicit when ambiguous** — if auto-detect can't determine the format/type, require a flag
4. **Commands read like English** — `hdf convert --from nessus --to hdf scan.nessus`
5. **Consistent terminology** — requirements (not controls), baselines (not profiles)
6. **Consistent flags** — same flag name means the same thing everywhere
7. **Progressive disclosure** — simple usage first, advanced flags available

---

## Current State Audit

### Top-Level Commands (15)

| Command | Purpose | Doc types | Positionals | POSIX? | Issues |
|---------|---------|-----------|-------------|--------|--------|
| `validate` | Schema validation | All 7 | `<file>` | ✓ | `--type` already works |
| `info` | Summary display | All 7 (auto-detect) | `<file>` | ✓ | Good |
| `stats` | Aggregate statistics | results only | `<file>` | ✓ | Should it work on other types? |
| `list` | Enumerate items | results only | `<what> <file>` | ✗ | Two positionals, old terminology |
| `query` | Filter/search | results only | `<file>` | ✓ | Good, rich flags |
| `convert` | Format conversion | All ingest formats | `<src> to <dest> <input> [output]` | ✗ | Most non-POSIX command |
| `diff` | Compare documents | results (+ comparison) | `<old> <new>` | ✓ | Standard diff pattern |
| `amend` | Amendment workflow | amendments + results | Mixed | Partial | `apply` has 2 positionals |
| `evidence` | Evidence packages | evidence-package | Subcommands | ✓ | Already uses flags |
| `system` | System documents | system | Subcommands | ✓ | Only `info` subcommand |
| `plan` | Plan documents | plan | Subcommands | ✓ | `info` + `create` |
| `generate` | Template generation | baseline → InSpec | Subcommands | ✓ | OK |
| `fetch` | Live API fetch | Various APIs | Subcommands | ✓ | OK |
| `label` | Manage labels | results/baseline | `<file>` + args | Partial | |
| `version` | Version info | — | None | ✓ | OK |

### Problem Areas

1. **`convert`** — 4 positional args with a literal `to` keyword
2. **`list`** — 2 positionals, results-only, old terminology (controls/profiles)
3. **`amend apply`** — 2 positional files
4. **Noun-verb duplication** — `hdf system info` AND `hdf info` both show system info
5. **Terminology** — "controls" and "profiles" predate v2 naming
6. **Doc-type siloing** — `stats`, `list`, `query` only work on results

---

## Proposed Design

### Guiding Rule

> **One positional argument: the file.** Everything else is a flag.
>
> Exception: `hdf diff` takes two files (standard diff(1) convention).

### Command Restructure

#### Tier 1: Universal Commands (work on any HDF document)

These auto-detect the document type and adapt their output:

```
hdf validate <file> [--type <doc-type>]
hdf list <file> [--detail <section>] [flags]    (alias: hdf ls)
hdf query <file> [filter flags]
```

#### Tier 2: Two-File Commands

```
hdf diff <old> <new> [flags]
```

#### Tier 3: Workflow Commands (multi-input, create/modify)

```
hdf convert <file> [--from <format>] [--to <format>] [-o output]
hdf amend apply --results <file> --amendments <file> [-o output]
hdf amend create <results-file> [interactive]
hdf amend list <file>
hdf amend verify <file>
hdf evidence build --system <file> --results <file> [--amendments <file>] [-o output]
hdf evidence verify <file>
hdf evidence export <file> --format <format> [-o output]
```

#### Tier 4: Utility Commands

```
hdf label show <file>
hdf label set <file> key=value [key=value...]
hdf label remove <file> key [key...]
hdf generate inspec-profile <baseline-file> <output-dir>
hdf fetch <source> [source-specific flags]
hdf version
```

### Remove Noun-Verb Commands

Currently we have BOTH:
- `hdf info system.json` (auto-detects system, shows info)
- `hdf system info system.json` (explicit system subcommand)

**Decision:** Remove `hdf system info`, `hdf plan info`, `hdf evidence info`.
Keep `hdf info` as the universal entry point — it auto-detects.

Keep `hdf system create`, `hdf plan create`, `hdf amend create` because
these are write operations specific to a doc type, not read operations.

Keep `hdf evidence build`, `hdf evidence verify`, `hdf evidence export`
because these are multi-input workflows, not simple file reads.

So the noun commands become:
- `hdf system create` — create a system document
- `hdf plan create` — create a plan document
- `hdf amend` — amendment workflow (apply, create, list, verify)
- `hdf evidence` — evidence workflow (build, verify, export)

And the universal commands handle all reading:
- `hdf info <file>` — summary of any doc type
- `hdf list <file>` — enumerate contents of any doc type
- `hdf validate <file>` — validate any doc type

---

## Detailed Command Specs

### hdf convert

```
Usage:
  hdf convert <file> [--from <format>] [--to <format>] [-o <output>] [flags]

Flags:
  --from string    Source format (auto-detected if omitted)
  --to string      Target format (default: hdf)
  -o, --output     Output file (default: stdout)
  --catalog string Path to OSCAL catalog (for profile conversion)
  --labels strings Labels to apply to components (key=value pairs)

Behavior:
  - No --from: auto-detect via fingerprint registry
  - No --to: assume hdf
  - Confidence < 0.8 or ambiguous: error, suggest --from
  - Display detected format: "Detected: Nessus (confidence: 1.0)"
```

### hdf list (alias: hdf ls)

Replaces `hdf info`, `hdf stats`, and old `hdf list`. One command, progressive
detail via `--detail` flag.

```
Usage:
  hdf list <file> [--detail <section>] [flags]
  hdf ls <file> [--detail <section>] [flags]

Flags:
  --detail string     Expand a specific section to item-level detail
  --all-details       Expand all sections
  --status string     Filter by status (for requirements/overrides)
  --severity string   Filter by severity (for requirements)
  --expired           Show only expired items (for overrides)

Detail sections by document type:
  results:          requirements, baselines, components, inputs
  baseline:         requirements, groups
  system:           components, dataFlows
  plan:             assessments
  amendments:       overrides
  evidence-package: contents
```

#### Progressive detail model

```
No flags = summary (counts, status, metadata — no item-level data)
--detail <section> = expand one section to show individual items
--all-details = expand every section
```

#### Examples by document type

```bash
# Results — summary
$ hdf list results.json
  Document type: results
  Baselines (2): RHEL9-STIG (v1r1), PostgreSQL-STIG (v1r0)
  Requirements: 145 total — 120 passed, 15 failed, 10 not reviewed (82.8%)
    3 amended (2 waivers, 1 attestation)
  Components (3): web-01 [host], web-02 [host], db-01 [database]
  Duration: 45.5s

# Results — drill into requirements
$ hdf list results.json --detail requirements --status failed
  REQ-002  failed  0.9  RHEL9-STIG  Apply security patches  [poam: due 2026-07-01]
  REQ-015  failed  0.5  RHEL9-STIG  Disable unused services

# System — summary
$ hdf list system.json
  Document type: system
  Name: Enterprise Portal Production
  Authorization: authorized (moderate)
  Components: 2
  Data flows: 1

# System — drill into components
$ hdf list system.json --detail components
  WebTier       application  RHEL9-STIG  {labels.component: WebTier}
  DatabaseTier  database     PostgreSQL-15-STIG  {labels.component: DatabaseTier}

# Amendments — summary (shows counts, not individual overrides)
$ hdf list amendments.json
  Document type: amendments
  Name: Portal Q1 2026 Waivers
  Approved by: ao@agency.gov
  Overrides: 3 (2 waivers, 1 poam) — 1 expired

# Amendments — drill into overrides
$ hdf list amendments.json --detail overrides
  SV-257777  waiver  RHEL9-STIG  passed  expires 2026-06-30
  SV-258001  poam    RHEL9-STIG  failed  expires 2026-07-01
  SV-259000  waiver  RHEL9-STIG  passed  EXPIRED 2026-03-01

# Evidence — summary (counts, not contents)
$ hdf list evidence.json
  Document type: evidence-package
  Name: Enterprise Portal ATO Evidence - Q1 2026
  Prepared by: compliance@agency.gov (2026-03-31)
  Contents: 6 documents
  Completeness: 95.8% compliant
    ✓ All baselines assessed, ✓ All components covered
    0 expired waivers, 2 unresolved POA&Ms

# Evidence — drill into contents
$ hdf list evidence.json --detail contents
  hdf-system      portal-prod.hdf-system.json       sha256:aaa111
  hdf-baseline    rhel9-stig.hdf-baseline.json      sha256:bbb222
  hdf-plan        portal-monthly-scan.hdf-plan.json sha256:ccc333
  hdf-results     portal-scan-march.json            sha256:ddd444
  hdf-amendments  portal-waivers-q1.json            sha256:eee555
  hdf-comparison  portal-diff-feb-mar.json          sha256:fff666

# Baseline — summary
$ hdf list baseline.json
  Document type: baseline
  Name: RHEL9-STIG (v1r1)
  Maintainer: DISA
  Requirements: 250 (45 high, 150 medium, 55 low)
  Groups: 12

# Plan — summary
$ hdf list plan.json
  Document type: plan
  Name: Portal Monthly Assessment
  Type: automated
  System: portal-prod.hdf-system.json
  Assessments: 2
  Schedule: 0 2 1 * * (monthly)
```

#### Commands being retired

| Old command | Replaced by |
|-------------|-------------|
| `hdf info <file>` | `hdf list <file>` (default summary) |
| `hdf stats <file>` | `hdf list <file>` (summary includes stats) |
| `hdf list controls <file>` | `hdf list <file> --detail requirements` |
| `hdf list profiles <file>` | `hdf list <file> --detail baselines` |
| `hdf list components <file>` | `hdf list <file> --detail components` |
| `hdf system info <file>` | `hdf list <file>` (auto-detects system) |
| `hdf plan info <file>` | `hdf list <file>` (auto-detects plan) |
| `hdf evidence info <file>` | `hdf list <file>` (auto-detects evidence) |

### hdf query (expanded to all doc types)

Query is the power-user filter command with AND-logic flags.
Auto-detects document type and applies type-appropriate filters.

```
# Results / Baseline — filter requirements
hdf query results.json --status failed --severity high --nist AC-2
hdf query baseline.json --severity high --tag gtitle="Session Timeout"

# System — filter components
hdf query system.json --component-type database
hdf query system.json --baseline-ref RHEL9-STIG

# Amendments — filter overrides
hdf query amendments.json --override-type waiver
hdf query amendments.json --expired
hdf query amendments.json --requirement SV-257777

# Evidence — filter contents
hdf query evidence.json --content-type hdf-results
```

Type-specific filter flags:
  Results/Baseline:  --status, --severity, --impact, --nist, --cci,
                     --stig-id, --tag, --search, --baseline
  System:            --component-type, --baseline-ref, --label
  Amendments:        --override-type, --expired, --requirement, --baseline-ref
  Evidence:          --content-type, --has-checksum

### hdf diff (mostly unchanged)

Two positional files (standard diff convention). Flag for format:

```
hdf diff old.json new.json [--format json|markdown|table|csv]
hdf diff old.json new.json --system system.json --group-by labels.component
```

### hdf amend

```
hdf amend apply --results <file> --amendments <file> [-o output]
hdf amend create <results-file>              # interactive TUI
hdf amend list <file>                         # single file, positional OK
hdf amend verify <file> [--results <file>]    # verify chain against results
```

---

## Terminology

| Old | New | Where |
|-----|-----|-------|
| controls | requirements | list, query, stats, info, help text, output |
| profiles | baselines | list, info, help text, output |
| control | requirement | singular forms in messages |
| profile | baseline | singular forms in messages |

---

## Flag Consistency

| Flag | Meaning | Used by |
|------|---------|---------|
| `--type` / `-t` | Document type for validation | validate |
| `--detail` | Expand a section to item-level detail | list |
| `--all-details` | Expand all sections | list |
| `--format` / `-f` | Output format | diff, evidence export |
| `--output` / `-o` | Output file | convert, amend apply, evidence build |
| `--json` | JSON output mode | all commands (global) |
| `--status` / `-s` | Filter by status | list, query |
| `--from` | Source format | convert |
| `--to` | Target format | convert |
| `--results` | Results file input | amend apply, evidence build |
| `--amendments` | Amendments file input | amend apply, evidence build |
| `--system` | System file input | evidence build, diff |

---

## Auto-Detection Strategy

| Command | Detects what | How |
|---------|-------------|-----|
| `convert` | Input format (Nessus, SARIF, etc.) | Fingerprint registry |
| `validate` | Document type (results, system, etc.) | JSON structure fingerprinting |
| `info` | Document type | JSON structure fingerprinting |
| `list` | Document type + available item types | JSON structure fingerprinting |

Auto-detection displays what it found:
```
$ hdf convert scan.nessus
Detected: Nessus (confidence: 1.0)
Converting nessus → hdf...
```

---

## What's NOT Changing (structurally)

- `hdf query` — already POSIX, expanding filter flags per doc type but structure unchanged
- `hdf stats` — RETIRED, merged into `hdf list` summary output
- `hdf diff` — two positionals is diff(1) convention
- `hdf fetch` — already uses subcommands + flags
- `hdf generate` — already uses subcommands
- `hdf label` — already uses subcommands
- `hdf version` — trivial, no change needed

---

## Migration

This is pre-release software with no published users. Changes are breaking
but there is no backward-compatibility obligation. No deprecation period needed.

---

## Implementation Order

1. Terminology rename (controls→requirements, profiles→baselines) — foundation
2. `hdf convert` refactor — highest-impact POSIX fix
3. `hdf list` refactor — second-highest impact, expands to all doc types
4. `hdf amend apply` refactor — simple flag change
5. Remove noun-verb `info` duplicates (system info, plan info, evidence info)
6. Expand `hdf info` auto-detect to cover all doc types (if not already complete)
