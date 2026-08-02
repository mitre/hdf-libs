# hdf CLI

Command-line tool for validating, inspecting, querying, and converting Heimdall Data Format (HDF) files. Part of the [hdf-libs](https://github.com/mitre/hdf-libs) monorepo.

HDF (Heimdall Data Format) is a standardized JSON format for security assessment results. It normalizes outputs from vulnerability scanners, compliance checkers, configuration auditors, and cloud security tools into a unified schema that can be viewed in [Heimdall](https://github.com/mitre/heimdall2).

## Table of Contents

- [Installation](#installation)
- [Terminology](#terminology)
- [Commands](#commands)
  - [validate](#validate) -- Validate an HDF file against the schema
  - [list](#list) -- Summarize a document, or list items with `--detail`
  - [query](#query) -- Search and filter requirements
  - [diff](#diff) -- Compare two HDF documents
  - [events](#events) -- Derive, fold, and apply requirement-change events
  - [convert](#convert) -- Convert between formats
  - [system](#system) -- View and manage HDF system documents
  - [plan](#plan) -- View and manage HDF assessment plans
  - [amend](#amend) -- Apply, list, and verify amendments (waivers/attestations)
  - [enrich](#enrich) -- Attach external context (STIX CTI) to results
  - [evidence](#evidence) -- Build and inspect evidence packages
  - [label](#label) -- Add, remove, or show labels on components
  - [generate](#generate) -- Generate InSpec profiles, thresholds, and baseline upgrades
  - [fetch](#fetch) -- Fetch from live APIs
    - [fetch aws-config](#fetch-aws-config) -- AWS Config compliance data
    - [fetch aws-securityhub](#fetch-aws-securityhub) -- AWS Security Hub ASFF findings
    - [fetch defectdojo](#fetch-defectdojo) -- DefectDojo findings
    - [fetch gitlab](#fetch-gitlab) -- GitLab CI/CD security artifacts
    - [fetch sonarqube](#fetch-sonarqube) -- SonarQube issues
    - [fetch splunk](#fetch-splunk) -- Splunk HDF events
  - [version](#version) -- Print version information
- [Global Flags](#global-flags)
- [Supported Conversions](#supported-conversions)
  - [To HDF](#to-hdf)
  - [From HDF](#from-hdf)
- [Credential Handling](#credential-handling)
- [Development](#development)
- [License](#license)

## Installation

### Pre-built binaries (recommended)

Download the latest release for your platform from [GitHub Releases](https://github.com/mitre/hdf-libs/releases). Binaries are available for:

- macOS (amd64, arm64)
- Linux (amd64, arm64)
- Windows (amd64)

```bash
# Example: download and install on macOS (Apple Silicon)
curl -sL https://github.com/mitre/hdf-libs/releases/latest/download/hdf_darwin_arm64.tar.gz | tar xz
sudo mv hdf /usr/local/bin/

# Linux (amd64)
curl -sL https://github.com/mitre/hdf-libs/releases/latest/download/hdf_linux_amd64.tar.gz | tar xz
sudo mv hdf /usr/local/bin/
```

Archive naming: `hdf_<version>_<os>_<arch>.tar.gz` (e.g., `hdf_3.4.0_darwin_arm64.tar.gz`).

### Build from source

**Requirements:** Go 1.26+, pnpm

```bash
# From the hdf-libs monorepo root
pnpm install
pnpm build        # builds schema types first, then the hdf binary

# Or build only the CLI
cd hdf-cli
go build -o hdf ./cmd/hdf
```

The binary is written to `hdf-cli/hdf`. Add it to your PATH or invoke it directly.

> `go install …@latest` is not supported: the CLI's `go.mod` uses local `replace` directives, so it's distributed as pre-built release binaries (goreleaser) or built from source as above.

## Terminology

| Term | Definition |
|------|-----------|
| **HDF** | Heimdall Data Format -- a JSON schema for security assessment data |
| **HDF Results** | An assessed HDF file containing pass/fail results for each requirement |
| **HDF Baseline** | An unassessed HDF file defining security requirements without results |
| **Requirement** | A single security check or control (called "control" in InSpec terminology) |
| **Baseline/Profile** | A named collection of requirements (e.g., "RHEL 8 STIG") |

## Commands

### validate

Validate an HDF results or baseline file against the JSON schema. Returns exit code 0 on success, 1 on failure.

```
USAGE
  hdf validate <file> [flags]

FLAGS
  -t, --type string    Schema type (auto-detected if omitted): results, baseline, comparison, system, plan, amendments, evidence-package
  -q, --quiet          Suppress output on success (exit code only)

EXAMPLES
  hdf validate results.json
  hdf validate baseline.json --type baseline
  hdf validate --json results.json          # machine-readable validation output
  cat results.json | hdf validate -         # read from stdin
  curl -s https://example.com/scan.json | hdf validate
```

Example output:

```console
$ hdf validate results.json
✓ results.json is a valid HDF results file

$ echo '{"not":"hdf"}' | hdf validate -
✗ <stdin> — input not recognized as any HDF document type
  Use --type to specify: results, baseline, comparison, system, plan, amendments, evidence-package
```

### list

Summarize any HDF document, or expand a section to item-level detail with `--detail`. The default summary reports document counts and, for results, the status breakdown — this replaces the former `info` and `stats` commands.

```
USAGE
  hdf list <file> [file...] [--detail <section>] [flags]

DETAIL SECTIONS by document type
  results:           requirements, baselines, components
  baseline:          requirements, groups
  system:            components, interconnections
  plan:              assessments
  amendments:        overrides
  evidence-package:  contents

  Short aliases: r (requirements), b (baselines), t/c (components),
    g (groups), a (assessments), o (overrides)

FLAGS
  -s, --status string    Filter requirements by status: passed, failed, error, not_applicable, not_reviewed

EXAMPLES
  hdf list results.json                              # summary (counts + status breakdown)
  hdf list results.json --detail requirements        # list individual requirements
  hdf list results.json --detail requirements -s failed
  hdf list system.json --detail components           # list system components
  hdf list amendments.json --detail overrides        # list waivers/attestations
  hdf list results.json --json
```

Example output:

```console
$ hdf list results.json
Baselines:    5
Requirements: 1603
Components:   0

  ✓ passed          134
  ✗ failed          273
  ? not_reviewed    1196

$ hdf list results.json --detail requirements -s failed
Requirements: 273

ID         Status  Title
---------  ------  ------------------------------------------------------------
SV-257777  failed  RHEL 9 must be a vendor-supported release.
V-242387   failed  The Kubernetes Kubelet must have the read-only port flag ...
V-242391   failed  The Kubernetes Kubelet must have anonymous authentication...
V-242392   failed  The Kubernetes kubelet must enable explicit authorization.
```

### query

Search and filter controls by status, severity, framework mapping, tags, and free text. Multiple filters combine with AND logic.

```
USAGE
  hdf query <file> [flags]

FLAGS
  -s, --status string      Filter by status: passed, failed, error, not_applicable, not_reviewed
      --severity string    Filter by severity (repeatable, OR logic): critical, high, medium, low, informational
      --impact string      Filter by impact value (e.g., ">0.5", ">=0.7", "0.5")
      --cci string         Filter by CCI identifier (e.g., CCI-000366)
      --nist string        Filter by NIST control (e.g., AC-2, CM-6*)
      --id string          Filter by requirement ID, STIG ID, GID, or group title
  -t, --tag string         Filter by tag key:value (e.g., severity:high)
      --search string      Search in control title and description
  -p, --baseline string    Filter by profile name
  -c, --count              Show only the count of matching controls
  -l, --limit int          Limit number of results (0 = unlimited)

EXAMPLES
  hdf query results.json --status failed
  hdf query results.json --status failed --severity high
  hdf query results.json --nist "AC-2"
  hdf query results.json --cci CCI-000366
  hdf query results.json --id V-230221
  hdf query results.json --tag "severity:high"
  hdf query results.json --search "password policy"
  hdf query results.json --impact ">0.5" --status failed
  hdf query results.json --status failed --count
  hdf query results.json --limit 20 --status failed
```

Example output:

```console
$ hdf query results.json --status failed --limit 5
Found 5 matching requirement(s):

ID         Status  Severity  Title
---------  ------  --------  -------------------------------------------------------
SV-257777  failed  INFO      RHEL 9 must be a vendor-supported release.
V-242387   failed  HIGH      The Kubernetes Kubelet must have the read-only port ...
V-242391   failed  HIGH      The Kubernetes Kubelet must have anonymous authentic...
V-242392   failed  HIGH      The Kubernetes kubelet must enable explicit authoriz...

$ hdf query results.json --status failed --count
273
```

### diff

Compare two HDF documents and classify each requirement as fixed, regressed, unchanged, updated, new, or absent. Results documents are compared temporally; system documents by component drift. Document type is auto-detected.

```
USAGE
  hdf diff <old-file> <new-file> [flags]

FLAGS
  -f, --format string      Output format: table, json, markdown (default "table")
      --stat               Summary counts only (like git diff --stat)
      --regressed          Show only regressions (also --fixed, --new, --absent)
      --exit-code          POSIX diff exit codes: 0=identical, 1=differences, 2=error
      --detailed-exitcode  Nuanced codes: 10=fixes, 11=regressions, 12=mixed, 13=baseline, 14=drift
      --system string      System document for component-aware comparison
      --sbom               Treat inputs as CycloneDX/SPDX SBOM documents

EXAMPLES
  hdf diff old-scan.json new-scan.json
  hdf diff old-scan.json new-scan.json -f markdown
  hdf diff old-scan.json new-scan.json --regressed
  hdf diff old-scan.json new-scan.json --detailed-exitcode   # exit code encodes outcome
  hdf diff --sbom old.cdx.json new.cdx.json
```

Example output:

```console
$ hdf diff old-scan.json new-scan.json
HDF Comparison: old-scan.json → new-scan.json

ID       Title                          Old Status  New Status  State
-------  -----------------------------  ----------  ----------  ---------
REQ-001  Test Requirement               passed      failed      regressed
REQ-002  Audit logging must be enabled  -           passed      new

Summary: 0 fixed, 1 regressed, 1 new, 0 absent, 0 unchanged, 0 updated (2 total)
```

### events

Batch operations over the HDF requirement-change-event stream (continuous monitoring): `derive` emits one NDJSON `Requirement_Change_Event` per requirement whose effective posture moved between two same-target results documents; `fold` materializes an event batch into a `systemDrift` hdf-comparison; `apply` reassembles the reconciled hdf-results (seed + events), stamped with a `derivation` block so it never masquerades as scanner output.

Every invocation is stateless and deterministic: event identity is a UUIDv5 over the entity key + sequence + the next document's timestamp — identical inputs produce byte-identical events. Sequencing across repeated derive runs is the caller's job (`--start-sequence`); fold and apply read events from any number of batch-file arguments or stdin, in any order — the fold contract ((source, eventId) dedup, per-key sequence as the only ordering authority) makes multi-batch delivery order-independent. Chain anomalies (gaps, duplicate keys, unknown tombstones) are warnings on stderr, never silent and never fatal.

```
USAGE
  hdf events derive --prev <results.json> --next <results.json> [flags]
  hdf events fold   --seed <results.json> [events.ndjson ...] [flags]
  hdf events apply  --seed <results.json> [events.ndjson ...] [flags]

DERIVE FLAGS
      --system-ref string      System document reference for the entity key (required)
      --component-id string    Component UUID (default: the next document's sole component)
      --source string          Producer URI recorded in the envelope
      --start-sequence int     Sequence assigned to the first emitted event (default 1)
      --schema-ref string      Optional schemaRef URI stamped on every event
  -o, --output string          Output file (default: stdout)

FOLD / APPLY FLAGS
  -o, --output string          Output file (default: stdout)
      --seed-uri string        (apply) Seed URI for the derivation block (default: the --seed path)
      --source string          (apply) Stream source for the derivation block (default: first event's source)

EXAMPLES
  hdf events derive --prev monday.hdf.json --next tuesday.hdf.json \
    --system-ref prod.hdf-system.json --component-id 6e0f2a3b-9c01-4d5e-8f7a-1b2c3d4e5f60 \
    -o events.ndjson
  hdf events fold --seed monday.hdf.json events.ndjson -o drift.comparison.json
  hdf events apply --seed monday.hdf.json batch-1.ndjson batch-2.ndjson -o reconciled.hdf.json
  cat events.ndjson | hdf events apply --seed monday.hdf.json -o reconciled.hdf.json
```

A complete runnable example — a live container scanned with a MITRE SAF STIG baseline, driven through seed → drift → derive → apply → amendment → chaos → re-center — lives at [mitre/hdf-conmon-demo](https://github.com/mitre/hdf-conmon-demo).

Example loop (real output):

```console
$ hdf events derive --prev scan-before.json --next scan-after.json \
    --system-ref prod.hdf-system.json --component-id 6e0f2a3b-... -o events.ndjson
$ cut -c1-80 events.ndjson | head -2
{"after":{"descriptions":[{"data":"The system must disable root SSH login","labe
{"after":{"descriptions":[{"data":"The audit subsystem must be active","label":"
$ hdf events apply --seed scan-before.json events.ndjson -o reconciled.hdf.json
$ hdf validate reconciled.hdf.json
✓ reconciled.hdf.json is a valid HDF results file
```

### convert

Convert security assessment data between HDF and other formats. Supports auto-detection, explicit `--from`/`--to` flags, stdin, and stdout.

```
USAGE
  hdf convert <file> -o <output>                        # Auto-detect format
  hdf convert --from <source> <file> -o <output>        # Explicit source format
  hdf convert --from <source> --to <dest> <file> -o <output>  # Explicit both
  hdf convert <file>                                     # Auto-detect, stdout
  cat scan.json | hdf convert -                          # stdin

INPUT/OUTPUT
  <file>      File path or "-" for stdin
  -o <output> Output file path; defaults to stdout if omitted

EXAMPLES
  hdf convert scan.nessus -o results.json
  hdf convert --from nessus scan.nessus -o results.json
  hdf convert --from sarif findings.sarif -o results.json
  hdf convert --from gosec gosec-output.json -o results.json
  hdf convert --from grype grype-output.json -o results.json
  hdf convert --from snyk snyk-output.json -o results.json
  hdf convert --from trufflehog secrets.json -o results.json
  hdf convert --from xccdf xccdf-results.xml -o results.json
  hdf convert --from gitlab gl-sast-report.json -o results.json
  hdf convert --from junit test-results.xml -o results.json
  hdf convert --from zap zap-report.json -o results.json
  hdf convert --from legacyhdf old-scan.json -o new-scan.json
  hdf convert --from hdf --to csv results.json -o controls.csv
  hdf convert --from hdf --to xml results.json -o controls.xml
  cat scan.json | hdf convert --from sarif - -o output.json
```

Example output:

```console
$ hdf convert compliance.nessus -o results.json
Detected: Nessus 2 (confidence: 100%)

$ hdf validate results.json
✓ results.json is a valid HDF results file
```

On auto-detection the source format and a confidence score are reported; with an explicit `--from` the conversion runs silently and writes to `-o` (or stdout).

See [Supported Conversions](#supported-conversions) for the full list.

### system

View and manage HDF **system** documents — a system's authorization boundary, components, baselines, and interconnections.

```
USAGE
  hdf system <subcommand> <file> [flags]

SUBCOMMANDS
  create            Bootstrap a system document from a results file or SBOM
  info              Summarize a system document
  add-component     Add a component from an SBOM
  update-component  Update a component's SBOM reference
  set               Set/unset top-level fields

EXAMPLES
  hdf system create --from results.json --name "Portal Prod" -o portal.hdf-system.json
  hdf system info portal.hdf-system.json
  hdf system info portal.hdf-system.json --json
```

Example output:

```console
$ hdf system info portal-prod.hdf-system.json
System: Portal Prod
System ID: aaaaaaaa-1111-2222-3333-444444444444

Components (2):
  WebTier (application)
    Baselines: RHEL9-STIG
  DatabaseTier (application)
    Baselines: PostgreSQL-STIG
```

### plan

View and manage HDF **assessment plan** documents — which baselines run against which targets, with resolved inputs and scheduling.

```
USAGE
  hdf plan <subcommand> <file> [flags]

SUBCOMMANDS
  create   Create an assessment plan
  info     Summarize a plan document
  set      Set/unset top-level fields

EXAMPLES
  hdf plan info quarterly-plan.hdf-plan.json
  hdf plan info quarterly-plan.hdf-plan.json --json
```

Example output:

```console
$ hdf plan info quarterly-plan.hdf-plan.json
Plan: portal-prod-assessment-plan
ID: 4737569f-8bb5-49b1-8e3a-3586a88d092e
Type: automated
System: system.json

Assessments (2):
  1. Baseline: RHEL9-STIG
  2. Baseline: PostgreSQL-STIG
```

### amend

Apply, list, and verify HDF **amendments** — standalone waiver / attestation / POA&M documents that modify requirement compliance status in results.

```
USAGE
  hdf amend <subcommand> [flags]

SUBCOMMANDS
  apply    Merge amendments into a results file (sets effectiveStatus)
  create   Create waivers, attestations, and other amendments
  draft    Scaffold an incomplete amendments draft from a results file
  list     List amendments in an amendments file
  verify   Verify amendment validity, expiration, and chain integrity
  set      Set/unset top-level fields

EXAMPLES
  hdf amend apply --results results.json --amendments waivers.json -o merged.json
  hdf amend list waivers.json
  hdf amend verify waivers.json                     # expiration check
  hdf amend verify waivers.json results.json         # full chain verification
```

Example output:

```console
$ hdf amend list waivers.json
Amendments: Q1 Waivers
System: portal-prod.hdf-system.json

Amendments (1):
Requirement  Type    Status  Impact  Expires     Reason
-----------  ------  ------  ------  ----------  ---------------------
AC-1         waiver  passed          2099-12-31  Risk accepted per ATO

$ hdf amend verify waivers.json
Total amendments: 1
Valid:            1
Expired:         0

All amendments are valid.
```

### enrich

Overlay an **enrichment source** onto an HDF results document, attaching inert `externalReferences[]` to findings (matched by CVE) or to the results root. Enrichment is informational — it adds context and never changes a finding's status or impact. Positional parity with `convert`: `<results> <source>`, with `--from` as the optional format assertion.

```
USAGE
  hdf enrich <results> <source> [flags]

FLAGS
  --from string           Enrichment source format (auto-detected if omitted; e.g. stix)
  --recompute-cvss        Also author an E:H CVSS riskAdjustment on exploited, 3.1-base-vector findings
  -o, --output string     Output file (default: stdout)

EXAMPLES
  hdf enrich results.json log4shell-bundle.json -o enriched.json       # auto-detect STIX
  hdf enrich results.json feed.json --from stix -o enriched.json        # assert the format
  hdf enrich results.json bundle.json --recompute-cvss -o enriched.json # + CVSS E:H recompute
  hdf enrich results.json bundle.json                                   # write to stdout
```

Supported sources: **stix** (a STIX 2.1 bundle, `{type:"bundle", objects:[…]}`). A CVE-bearing STIX object attaches to the finding whose requirement ID is that CVE; everything else (non-CVE objects, and CVEs with no matching finding) attaches to the results root. Each reference carries the raw STIX object losslessly in `document`.

With **`--recompute-cvss`**, when a matched STIX object shows active exploitation (a sighting, a `targets`/`exploits` relationship, or an indicator/report reference) and the finding carries a CVSS **3.1** base vector, an inline `riskAdjustment` is authored: Exploit Maturity `E:H` is applied and the Threat score recomputed via the CVSS engine, with `impact.value = computedScore/10` and an `externalReferences[]` back to the STIX source. Findings with no base vector, or a CVSS **4.0** base vector, are left unchanged (no fabrication). Enrichment without `--recompute-cvss` never changes status or impact.

### evidence

Build and inspect HDF **evidence packages** — bundles of references to all HDF documents for audit, authorization, and compliance review.

```
USAGE
  hdf evidence <subcommand> <file> [flags]

SUBCOMMANDS
  build         Bundle HDF documents into an evidence package
  info          Summarize an evidence package (with per-document checksum status)
  verify        Verify an evidence package against its assessment plan
  export        Export package documents to another format
  set           Set/unset top-level fields
  add-evidence  Reference external native-format evidence (logs/telemetry) by uri + hash + format

EXAMPLES
  hdf evidence build --system system.json --results r1.json --results r2.json -o q1.hdf-evidence-package.json
  hdf evidence info q1.hdf-evidence-package.json
  hdf evidence verify q1.hdf-evidence-package.json
  hdf evidence add-evidence q1.hdf-evidence-package.json --uri logs/q1.ndjson --format ecs --collector elastic-agent
```

Example output:

```console
$ hdf evidence info q1-2026.hdf-evidence-package.json
Evidence Package: Portal Prod Q1 Evidence
System: system.json

Contents (4):
  hdf-system       system.json  ✓ checksum
  hdf-plan         plan.json  ✓ checksum
  hdf-results      rhel9-results.json  ✓ checksum
  hdf-results      postgres-results.json  ✓ checksum
```

### label

Add, remove, or show key=value labels on the components of an HDF document.

```
USAGE
  hdf label <subcommand> <file> [flags]

SUBCOMMANDS
  show     Display labels on all components
  set      Set labels on all components
  remove   Remove labels from all components

EXAMPLES
  hdf label show results.json
  hdf label set results.json system=Portal environment=production -o labeled.json
  hdf label remove results.json system environment -o cleaned.json
```

Example output:

```console
$ hdf label set results.json system=Portal environment=production -o labeled.json
Labels written to labeled.json

$ hdf label show labeled.json
Component: web01.example.com [host]
  environment = production
  system = Portal
```

### generate

Generate security templates and skeletons from HDF baselines, results, or XCCDF benchmarks.

```
USAGE
  hdf generate <subcommand> <file> [flags]

SUBCOMMANDS
  inspec-profile   Generate an InSpec profile from an HDF Baseline or XCCDF Benchmark
  threshold        Generate a compliance threshold template from HDF results
  upgrade          Upgrade a baseline with new upstream metadata, preserving customizations (alias: delta)

EXAMPLES
  hdf generate inspec-profile baseline.json my-profile/           # <input> <output-dir>
  hdf generate inspec-profile U_RHEL_9_STIG_xccdf.xml rhel9-stig/  # XCCDF auto-detected
  hdf generate threshold results.json -o threshold.yml
  hdf generate upgrade profile/ new-stig-xccdf.xml               # <current> <upstream>
```

Example output:

```console
$ hdf generate threshold results.json
compliance:
    min: 100
passed:
    high:
        min: 1
    total:
        min: 1
```

### fetch

Fetch security data from a live API and convert to HDF in a single step. No intermediate files needed.

All fetch subcommands support `--format raw` to skip HDF conversion and return the tool's native output, and `--output` / `-o` to write to a file instead of stdout.

Credentials are resolved from environment variables or tool-specific config files. See [Credential Handling](#credential-handling).

#### fetch aws-config

Fetch AWS Config compliance evaluation results and convert to HDF.

Credentials are resolved via the standard AWS credential chain: environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`), shared credentials file (`~/.aws/credentials`), or IAM instance role.

**Service-linked rules are excluded.** Config rules owned by an AWS service (`CreatedBy` set — Security Hub, conformance packs, Organizations) can't be read via the Config API by a customer principal, so they're skipped (a `WARNING: skipped N service-linked rule(s)` is printed to stderr). Fetch their findings through the owning service instead — e.g. `hdf fetch aws-securityhub` for Security Hub controls.

**Remediation surfaces as a `fix` description.** A customer-managed rule with an attached remediation configuration (SSM Automation document) gains a `fix` description in its HDF requirement describing the remediation.

```
USAGE
  hdf fetch aws-config [output] [flags]

FLAGS
  -r, --region string     (required) AWS region (e.g., us-east-1)
  -p, --profile string    AWS CLI named profile
      --format string     Output format: hdf or raw (default "hdf")
      --no-validate       Skip schema validation of converter output before writing
  -o, --output string     Output file path (default: stdout)

EXAMPLES
  hdf fetch aws-config --region us-east-1 output.json
  hdf fetch aws-config --region us-east-1 --profile my-audit-account output.json
  hdf fetch aws-config --region us-east-1 --format raw | jq '.ConfigRules | length'
  hdf fetch aws-config --region us-east-1 | jq '.baselines[0].requirements | length'
```

#### fetch aws-securityhub

Fetch ASFF findings from AWS Security Hub and convert to HDF via the `asff-to-hdf` converter. Use `--check` to verify credentials without downloading findings.

Credentials are resolved via the same AWS chain as `fetch aws-config` (env vars, `~/.aws/credentials` / `~/.aws/config`, IAM instance role, AssumeRole).

```
USAGE
  hdf fetch aws-securityhub [output] [flags]

FLAGS
  -r, --region string       (required) AWS region (e.g., us-east-1)
  -p, --profile string      AWS CLI named profile
      --format string       Output format: hdf or raw (default "hdf")
      --filter-json string  Path to a JSON file with an ASFF AwsSecurityFindingFilters object
      --no-validate         Skip schema validation of converter output before writing
  -o, --output string       Output file path (default: stdout)
      --check               Verify credentials only; skip findings download

EXAMPLES
  # Fetch all findings in a region
  hdf fetch aws-securityhub --region us-east-1 output.json

  # Use a named AWS CLI profile
  hdf fetch aws-securityhub --region us-east-1 --profile my-audit-account output.json

  # Save raw ASFF JSON instead of HDF
  hdf fetch aws-securityhub --region us-east-1 --format raw asff.json

  # Narrow the pull with a Security Hub filter (see "Filtering findings" below)
  hdf fetch aws-securityhub --region us-east-1 --filter-json failed-only.json output.json

  # Verify credentials only -- exits 0 on success, non-zero on auth failure
  hdf fetch aws-securityhub --region us-east-1 --check
```

##### Filtering findings

By default the fetch pulls every active finding, which on a busy account is a
lot. `--filter-json` narrows it: point it at a file containing a Security Hub
[`AwsSecurityFindingFilters`](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_AwsSecurityFindingFilters.html)
object, which is passed straight to the [`GetFindings`](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_GetFindings.html)
API. Each field is an array of matchers; **multiple values on one field OR
together, and different fields AND together**. String matchers take a
[`Comparison`](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_StringFilter.html)
(`EQUALS`, `NOT_EQUALS`, `PREFIX`, `PREFIX_NOT_EQUALS`, `CONTAINS`, `NOT_CONTAINS`)
and **values are case-sensitive**.

Only failed compliance findings (the common "what needs remediation" pull):

```json
{ "ComplianceStatus": [{ "Value": "FAILED", "Comparison": "EQUALS" }] }
```

Only critical and high severity (OR within the field):

```json
{ "SeverityLabel": [
    { "Value": "CRITICAL", "Comparison": "EQUALS" },
    { "Value": "HIGH", "Comparison": "EQUALS" }
] }
```

Active findings that are not resolved (AND across fields):

```json
{ "RecordState":    [{ "Value": "ACTIVE",   "Comparison": "EQUALS" }],
  "WorkflowStatus": [{ "Value": "RESOLVED", "Comparison": "NOT_EQUALS" }] }
```

Findings updated in the last 7 days — the continuous-monitoring incremental pull
(date fields take a `DateRange` in `DAYS` instead of a `Comparison`):

```json
{ "UpdatedAt": [{ "DateRange": { "Unit": "DAYS", "Value": 7 } }] }
```

Combined — failed criticals from the last 30 days:

```json
{ "ComplianceStatus": [{ "Value": "FAILED",   "Comparison": "EQUALS" }],
  "SeverityLabel":    [{ "Value": "CRITICAL", "Comparison": "EQUALS" }],
  "UpdatedAt":        [{ "DateRange": { "Unit": "DAYS", "Value": 30 } }] }
```

The [`AwsSecurityFindingFilters` reference](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_AwsSecurityFindingFilters.html)
lists every filterable field (product, account, standard, resource type, and
more) — `--filter-json` accepts any of them.

#### fetch defectdojo

Fetch findings from a DefectDojo instance and convert to HDF.

Token must be set via the `DEFECTDOJO_API_TOKEN` environment variable.

Findings are grouped into HDF baselines by their underlying scanner (test_type),
and risk-accepted findings carry a full HDF status override (who accepted the
risk, when, why, and when it expires) reconstructed from the finding's inline
risk-acceptance provenance.

```
USAGE
  hdf fetch defectdojo [output] [flags]

FLAGS
  -u, --url string            (required) DefectDojo instance URL
      --product-name string   Filter findings to a product by name
      --engagement string     Filter findings to an engagement by id
      --test string           Filter findings to a single test by id
      --format string         Output format: hdf or raw (default "hdf")
      --check                 Verify credentials only; skip findings download
      --no-validate           Skip schema validation of converter output before writing
  -o, --output string         Output file path (default: stdout)

EXAMPLES
  export DEFECTDOJO_API_TOKEN=<your-token>
  hdf fetch defectdojo --url https://defectdojo.example.com -o output.json
  hdf fetch defectdojo --url https://defectdojo.example.com --product-name "My App" -o output.json
  hdf fetch defectdojo --url https://defectdojo.example.com --check
```

#### fetch gitlab

Fetch a GitLab CI/CD security scan artifact (SAST, DAST, secret detection, etc.) and convert to HDF.

Token is resolved from: `GITLAB_TOKEN` env var, `GLAB_TOKEN` env var, or glab CLI config (`glab auth login`).

The `--scan-type` flag selects the default artifact filename:

| Scan Type | Default Artifact |
|-----------|-----------------|
| `sast` (default) | `gl-sast-report.json` |
| `dast` | `gl-dast-report.json` |
| `secret-detection` | `gl-secret-detection-report.json` |
| `dependency-scanning` | `gl-dependency-scanning-report.json` |
| `container-scanning` | `gl-container-scanning-report.json` |
| `api-fuzzing` | `gl-api-fuzzing-report.json` |

```
USAGE
  hdf fetch gitlab [output] [flags]

FLAGS
  -u, --url string              GitLab instance URL (default "https://gitlab.com")
      --project string          (required) Project ID or namespace/project path
      --ref string              Branch or tag name (default "main")
      --scan-type string        Scan type (default "sast")
      --artifact-path string    Override default artifact filename
      --job string              (required) CI job name that produced the artifact
      --format string           Output format: hdf or raw (default "hdf")
      --max-response-size int   Max response size in bytes (default 10MB, -1 for no limit)
  -o, --output string           Output file path (default: stdout)

EXAMPLES
  hdf fetch gitlab --project my-org/my-project --job semgrep-sast -o output.json
  hdf fetch gitlab --url http://gitlab.local:9090 --project 42 \
    --scan-type dast --ref develop --job dast -o output.json
  hdf fetch gitlab --project my-org/my-project --job secret_detection \
    --scan-type secret-detection --ref master -o secrets.json
  hdf fetch gitlab --project 42 --job semgrep-sast --format raw | jq '.vulnerabilities | length'
```

#### fetch sonarqube

Fetch SonarQube project issues and convert to HDF.

Token must be set via the `SONARQUBE_TOKEN` environment variable.

```
USAGE
  hdf fetch sonarqube [output] [flags]

FLAGS
  -u, --url string                (required) SonarQube server URL
      --project-key string        (required) SonarQube project key
      --branch string             Branch name
      --pull-request string       Pull request ID
      --organization string       SonarCloud organization key
      --sonarqube-version string  SonarQube server version (auto-detected if omitted; affects auth method)
      --format string             Output format: hdf or raw (default "hdf")
      --no-validate               Skip schema validation of converter output before writing
  -o, --output string             Output file path (default: stdout)

NOTE
  --branch and --pull-request are mutually exclusive.

EXAMPLES
  export SONARQUBE_TOKEN=squ_abc123
  hdf fetch sonarqube --url https://sonarqube.example.com --project-key my-project -o output.json
  hdf fetch sonarqube --url https://sonarqube.example.com --project-key my-project \
    --branch develop -o output.json
  hdf fetch sonarqube --url https://sonarqube.example.com --project-key my-project \
    --pull-request 42 -o output.json
```

#### fetch splunk

Fetch HDF evaluation events from a Splunk index and reassemble into an HDF results file.

Token must be set via the `SPLUNK_TOKEN` environment variable.

```
USAGE
  hdf fetch splunk [output] [flags]

FLAGS
  -u, --url string       (required) Splunk server URL
  -i, --index string     (required) Splunk index name
  -g, --guid string      (required) Evaluation GUID to fetch
      --no-validate      Skip schema validation of converter output before writing
  -o, --output string    Output file path (default: stdout)

EXAMPLES
  export SPLUNK_TOKEN=your-splunk-token
  hdf fetch splunk --url https://splunk.example.com --index hdf --guid abc123 -o output.json
  hdf fetch splunk --url https://splunk.example.com --index hdf --guid abc123 | jq .
```

### version

Print version, commit hash, build date, and Go version.

```
USAGE
  hdf version [flags]

EXAMPLES
  hdf version
  hdf version --json
```

## Global Flags

These flags apply to all commands.

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--json` | | `false` | Output in JSON format |
| `--debug` | `-d` | `false` | Enable debug output |
| `--fail-fast` | `-F` | `false` | Abort on first file that fails instead of continuing |
| `--max-size` | | `50` | Maximum input file size in MB |
| `--no-follow-symlinks` | | `false` | Refuse to read symlinked files |
| `--no-headers` | | `false` | Suppress column headers in table output |
| `--schema-dir` | | | Load schemas from a directory instead of the embedded copies |

## Supported Conversions

### To HDF

| Source Format | Aliases | Description |
|--------------|---------|-------------|
| `asff` | | AWS Security Finding Format — Security Hub / AWS-integrated tool findings (JSON) |
| `aws-config` | | AWS Config compliance evaluation results (JSON) |
| `burpsuite` | | PortSwigger BurpSuite web scanner (XML) |
| `checkov` | | Checkov IaC static analysis (JSON) |
| `ckl` | | DISA STIG Viewer checklist (`.ckl` XML) |
| `cklb` | | DISA STIG Viewer 3.x checklist (`.cklb` JSON) |
| `conveyor` | | Conveyor container security (JSON) |
| `csaf-vex` | | CSAF VEX advisory (csaf_vex profile) → HDF Amendments (JSON) |
| `cyclonedx` | | CycloneDX SBOM (JSON) — VEX-bearing BOMs auto-route to cyclonedx-vex |
| `cyclonedx-vex` | | CycloneDX BOM with VEX analysis statements → HDF Amendments (JSON) |
| `dbprotect` | | DbProtect database scanner (XML) |
| `defectdojo` | | DefectDojo findings export via API (JSON) |
| `deptrack` | `dependency-track` | Dependency-Track vulnerability audit (JSON) |
| `fortify` | | Micro Focus Fortify SAST (FVDL XML) |
| `gitlab` | `gitlab-sast`, `gitlab-dast` | GitLab CI/CD security scan reports (JSON) |
| `gosec` | | gosec Go security checker (JSON or SARIF) |
| `grype` | | Anchore Grype vulnerability scan (JSON) |
| `hipcheck` | | MITRE Hipcheck supply-chain risk report (`hc check --format json`) |
| `ionchannel` | | Ion Channel supply chain analysis (JSON) |
| `jfrog-xray` | `xray` | JFrog Xray SCA scan (JSON) |
| `junit` | | JUnit XML test results |
| `legacyhdf` | `inspec` | Legacy HDF (InSpec exec-json format) to current HDF |
| `msft-defender-cloud` | `defender-cloud` | Microsoft Defender for Cloud (JSON) |
| `msft-defender-devops` | `msdo` | Microsoft Defender for DevOps (SARIF) |
| `msft-defender-endpoint` | `defender-endpoint` | Microsoft Defender for Endpoint (JSON) |
| `msft-secure-score` | | Microsoft Secure Score (JSON) |
| `nessus` | | Tenable Nessus scan results (`.nessus` XML) |
| `netsparker` | `invicti` | Netsparker/Invicti web scanner (XML) |
| `neuvector` | | NeuVector container security (JSON) |
| `nikto` | | Nikto web server scanner (JSON) |
| `openvex` | | OpenVEX statements → HDF Amendments (JSON) |
| `oscal` | | OSCAL document (auto-detect type) |
| `oscal-sar` | `oscal-assessment-results` | OSCAL Assessment Results → HDF Results |
| `oscal-catalog` | | OSCAL Catalog → HDF Baseline |
| `oscal-component-definition` | | OSCAL Component Definition → HDF Baseline |
| `oscal-ssp` | | OSCAL System Security Plan → HDF System |
| `oscal-poam` | | OSCAL Plan of Action and Milestones → HDF Amendments |
| `prisma` | | Prisma Cloud/Twistlock container scan (JSON) |
| `sarif` | | SARIF 2.1.0 (Static Analysis Results Interchange Format) |
| `scoutsuite` | | NCC Group ScoutSuite cloud audit (JSON) |
| `snyk` | | Snyk vulnerability scan (JSON) |
| `sonarqube` | | SonarQube issues export (JSON) |
| `splunk` | | Splunk HDF events (JSON) |
| `trufflehog` | | TruffleHog secret scanner (JSON, NDJSON, or single object) |
| `twistlock` | | Palo Alto Twistlock container scan (JSON) |
| `veracode` | | Veracode SAST/DAST results (XML) |
| `xccdf` | `arf`, `xccdf-benchmark`, `xccdf-results` | XCCDF/ARF benchmark or results (XML) |
| `zap` | | OWASP ZAP web scanner (JSON) |

Auto-detection: `hdf convert <file>` identifies the input format automatically. Use `--from <format>` only when auto-detection fails or you want to force a specific parser.

### From HDF

| Source | Destination | Description |
|--------|-------------|-------------|
| `hdf` | `csv` | Export requirements to CSV spreadsheet |
| `hdf` | `ecs` | Export findings as Elastic Common Schema (ECS 9.4.0) NDJSON events |
| `hdf` | `splunk` | Export findings as Splunk HEC (CIM Vulnerabilities) NDJSON events |
| `hdf` | `ocsf` | Export findings as OCSF v1.8.0 Finding NDJSON (Compliance / Vulnerability Finding) |
| `hdf` | `asff` | Export findings as an AWS Security Finding Format `{"Findings":[...]}` envelope (Security Hub / BatchImportFindings) |
| `hdf` | `xml` | Export requirements to XML |
| `hdf` | `xccdf` | Export to XCCDF results XML |
| `hdf` | `ckl` | Export to DISA STIG Viewer checklist (`.ckl` XML) |
| `hdf` | `cklb` | Export to DISA STIG Viewer 3.x checklist (`.cklb` JSON) |
| `hdf` | `oscal-sar` | Export to OSCAL Assessment Results |
| `hdf-amendments` | `csaf-vex` | Export HDF Amendments as CSAF VEX advisory (partial-fidelity round-trip) |
| `hdf-amendments` | `openvex` | Export HDF Amendments as OpenVEX statements (partial-fidelity round-trip) |
| `hdf-amendments` | `cyclonedx-vex` | Export HDF Amendments as CycloneDX BOM with VEX analysis (partial-fidelity round-trip) |
| `hdf-amendments` | `oscal-poam` | Export to OSCAL Plan of Action and Milestones |

## Credential Handling

The `fetch` commands connect to live APIs. Credentials are **never** accepted as CLI flags to prevent exposure in shell history, process listings, and CI logs.

| Service | Environment Variable | Config File Fallback |
|---------|---------------------|---------------------|
| AWS Config | `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY` | `~/.aws/credentials` (via AWS SDK credential chain) |
| DefectDojo | `DEFECTDOJO_API_TOKEN` | None |
| GitLab | `GITLAB_TOKEN` or `GLAB_TOKEN` | glab CLI config (`glab auth login`) |
| SonarQube | `SONARQUBE_TOKEN` | None |
| Splunk | `SPLUNK_TOKEN` | None |

For GitLab, the glab CLI config is read from the platform's standard config directory:

| Platform | Config Path |
|----------|------------|
| Linux | `$XDG_CONFIG_HOME/glab-cli/config.yml` (default: `~/.config/glab-cli/`) |
| macOS | `~/Library/Application Support/glab-cli/config.yml` |
| Windows | `%LOCALAPPDATA%\glab-cli\config.yml` |

Override with the `GLAB_CONFIG_DIR` environment variable on any platform.

## Development

See the [monorepo root README](https://github.com/mitre/hdf-libs/blob/main/README.md) and [CLAUDE.md](https://github.com/mitre/hdf-libs/blob/main/hdf-cli/CLAUDE.md) for full architecture and contribution guidelines.

### Quick Reference

From the monorepo root:

```bash
pnpm build           # build everything (schema types + hdf binary)
pnpm test            # run all tests (Go + TypeScript)
pnpm lint            # run golangci-lint
```

From within `hdf-cli/` directly:

```bash
go build -o hdf ./cmd/hdf       # build the binary
go test ./... -v                 # run all Go tests
pnpm fmt                        # gofmt -s -w .
pnpm vet                        # go vet ./...
pnpm test:coverage              # coverage report (generates coverage.out)
```

### Adding a New Converter

See the [`/build-converter` skill documentation](https://github.com/mitre/hdf-libs/blob/main/hdf-cli/CLAUDE.md) for the full process. In brief:

1. Implement Go converter in `hdf-converters/converters/<name>/go/converter.go`
2. Implement TypeScript converter in `hdf-converters/converters/<name>/typescript/converter.ts`
3. Register CLI integration in `hdf-cli/cmd/hdf/cmd/converter_<name>.go`
4. Add tests for all three layers
5. Source real fixtures from tool output -- never fabricate test data

### Test Fixtures

Command tests (validate, query, list, etc.) load HDF fixtures from `../hdf-schema/test/fixtures/`. Converter tests load format-specific fixtures from `../hdf-converters/converters/{tool}/fixtures/`. Both skip gracefully if the fixture directories are absent.

## License

Apache 2.0 -- Approved for Public Release; Distribution Unlimited. Case Number 18-3678.

Copyright 2024-2026 The MITRE Corporation.
