# HDF Document Type Ecosystem

> **Status:** This is the HDF **design specification**. Implementation is tracked
> in beads epic `hdf-libs-15kg`. As of 2026-04-02, all 7 schemas exist (hdf-baseline,
> hdf-results, hdf-comparison, hdf-system, hdf-plan, hdf-amendments, hdf-evidence-package)
> and all Phase 0–4 work is complete (typed inputs, labels, rename, cross-references,
> all document type schemas with full type generation for TS/Go). Phase 5
> (ecosystem integration) is in progress.

## Overview

HDF (Heimdall Data Format) defines 7 document types that together cover the full
security assessment lifecycle: define requirements, describe systems, plan assessments,
execute scans, analyze changes, govern risk, and prove compliance.

Each document type has its own JSON Schema and serves a distinct purpose. They compose
via cross-references — not nesting — following OSCAL's principle of separating concerns
into independent, linkable documents.

## Document Types

| # | Document | Schema | Purpose | Created By | Consumed By |
|---|----------|--------|---------|------------|-------------|
| 1 | hdf-baseline | `hdf-baseline.schema.json` | Security requirements (what to check) | STIG authors, Vulcan, profile devs | Scanners, hdf-plan, Heimdall |
| 2 | hdf-results | `hdf-results.schema.json` | Assessment findings (what happened) | Scanners via converters | Heimdall, hdf-diff, CI/CD, auditors |
| 3 | hdf-comparison | `hdf-comparison.schema.json` | Structured diff (what changed) | `hdf diff` CLI, Heimdall | Security teams, CI/CD, dashboards |
| 4 | hdf-system | `hdf-system.schema.json` | System architecture & boundary (what is it) | Architects, CMDB, cloud discovery | hdf-plan, hdf-diff, Heimdall, OSCAL export |
| 5 | hdf-plan | `hdf-plan.schema.json` | Assessment plan / scan config (how to assess) | Security teams, CI/CD config | Scanner runners, audit trail |
| 6 | hdf-amendments | `hdf-amendments.schema.json` | Waivers, risk acceptance, manual verification | Assessors, authorizing officials | hdf-results (merge), auditors |
| 7 | hdf-evidence-package | `hdf-evidence-package.schema.json` | Verifiable audit bundle (prove it was done) | Compliance automation, Heimdall | 3PAO, IG, authorization officials |

## Lifecycle Flow

```
┌─────────────┐       ┌─────────────┐       ┌─────────────┐       ┌─────────────┐
│ hdf-baseline│──────>│ hdf-system  │──────>│  hdf-plan   │──────>│ hdf-results │
│ "what to    │       │ "what is    │       │ "how to     │       │ "what       │
│  check"     │       │  the system"│       │  assess it" │       │  happened"  │
└─────────────┘       └─────────────┘       └──────┬──────┘       └──────┬──────┘
                                                   │                     │
                                                   │              ┌──────┴──────┐
                                                   │              │hdf-comparison│
                                                   │              │"what changed"│
                                                   │              └──────┬──────┘
                                            ┌──────┴──────────┐         │
                                            │ hdf-amendments │         │
                                            │ "risk accepted" │         │
                                            └──────┬──────────┘         │
                                                   │                    │
                                            ┌──────┴────────────────────┴──┐
                                            │    hdf-evidence-package       │
                                            │  "audit-ready bundle"        │
                                            └──────────────────────────────┘
```

**Assessment data flows UP** (converters → results → comparison).
**System context flows DOWN** (system → plan → results).
**Governance flows SIDEWAYS** (amendments merge into results).

## Cross-Reference Map

```
hdf-baseline ←──── hdf-plan (which baselines to run)
     │                │
     ▼                ▼
hdf-system ◄───── hdf-plan (which components to scan)
     │                │
     ▼                ▼
hdf-results ◄──── hdf-plan (provenance: what config produced these results)
     │
     ├──── hdf-amendments (merge: apply waivers to results)
     │
     ├──── hdf-comparison (diff: compare two results)
     │
     └──── hdf-evidence-package (bundle: package everything for audit)
```

| Document | References | Referenced By |
|----------|-----------|---------------|
| hdf-baseline | Framework mappings (CCI, NIST), typed inputs | hdf-system, hdf-plan, hdf-results |
| hdf-system | hdf-baseline (component→baseline mapping), components (via label selectors) | hdf-plan, hdf-results, hdf-comparison, hdf-evidence |
| hdf-plan | hdf-baseline (which baselines), hdf-system (which components), resolved inputs | hdf-results (provenance) |
| hdf-results | hdf-baseline (evaluated), components (with labels), systemRef, planRef | hdf-comparison, hdf-amendments, hdf-evidence |
| hdf-comparison | Any two HDF docs of same type (source checksums), systemRef (boundary context) | hdf-evidence |
| hdf-amendments | hdf-baseline (requirements), hdf-system, Identity, Signature | hdf-results (merge), hdf-evidence |
| hdf-evidence | All other types (bundled by reference + checksum) | Auditors, authorization officials |

---

## Full Scenario: Enterprise Portal Lifecycle

### Phase 1: DEFINE — hdf-baseline

A STIG author creates a baseline with typed inputs:

```json
{
  "name": "RHEL9-STIG",
  "version": "V1R1",
  "inputs": [
    {
      "name": "max_concurrent_sessions",
      "type": "Numeric",
      "value": 3,
      "description": "Maximum concurrent sessions per user",
      "required": true
    },
    {
      "name": "approved_ciphers",
      "type": "Array",
      "value": ["aes-256-gcm", "aes-128-gcm"],
      "description": "Approved TLS cipher suites"
    }
  ],
  "requirements": [
    {
      "id": "SV-257777",
      "title": "RHEL 9 must limit concurrent sessions",
      "impact": 0.5,
      "tags": { "cci": ["CCI-000054"], "nist": ["AC-10"] },
      "descriptions": [
        { "label": "default", "data": "Limit concurrent sessions per user" },
        { "label": "check", "data": "Verify maxlogins in limits.conf" },
        { "label": "fix", "data": "Set maxlogins in /etc/security/limits.conf" }
      ]
    }
  ]
}
```

### Phase 2: DESCRIBE — hdf-system

A system architect defines the authorization boundary. Components use label selectors
(not hardcoded target names) so new servers are automatically included.

```json
{
  "name": "Enterprise Portal Production",
  "identifier": "SYS-2024-00142",
  "identifierScheme": "https://emass.mil",
  "authorizationStatus": "authorized",
  "authorizationDate": "2025-06-15T00:00:00Z",
  "categorizationLevel": "moderate",
  "boundaryDescription": "All resources in prod VPC (10.0.0.0/16)...",
  "components": [
    {
      "name": "WebTier",
      "type": "application",
      "description": "RHEL 9 web servers running the portal",
      "targetSelector": { "labels.component": "WebTier" },
      "baselineRefs": ["RHEL9-STIG", "DISA-Container-STIG"],
      "sbomRef": "https://artifacts.agency.gov/sbom/webtier-2026-03.cdx.json",
      "sbomFormat": "cyclonedx",
      "inputOverrides": [
        {
          "baselineRef": "RHEL9-STIG",
          "inputName": "max_concurrent_sessions",
          "value": 5,
          "justification": "Admin team needs 5 sessions for shift handoff",
          "approvedBy": { "type": "email", "identifier": "issm@agency.gov" }
        }
      ]
    },
    {
      "name": "DatabaseTier",
      "type": "database",
      "targetSelector": { "labels.component": "DatabaseTier" },
      "baselineRefs": ["PostgreSQL-15-STIG"]
    }
  ]
}
```

### Phase 3: PLAN — hdf-plan

The security team defines scan configuration. The plan resolves inputs from
baseline defaults + system overrides into final scanner parameters.

```json
{
  "name": "Portal Monthly Assessment",
  "type": "automated",
  "systemRef": "portal-prod.hdf-system.json",
  "assessments": [
    {
      "baselineRef": "RHEL9-STIG",
      "targetSelector": { "labels.component": "WebTier" },
      "inputs": {
        "max_concurrent_sessions": 5,
        "password_min_length": 15
      },
      "runner": {
        "name": "cinc-auditor",
        "version": "6.8.1"
      }
    }
  ],
  "schedule": {
    "cron": "0 2 1 * *",
    "notifyOnRegression": ["security-team@agency.gov"]
  }
}
```

### Phase 4: EXECUTE — hdf-results

The scanner produces results with labels on components and typed inputs on baselines.

```json
{
  "timestamp": "2026-03-14T02:00:00Z",
  "systemRef": "portal-prod.hdf-system.json",
  "planRef": "portal-monthly-scan.hdf-plan.json",
  "components": [
    {
      "type": "host",
      "name": "web-server-01",
      "labels": {
        "system": "Enterprise Portal Production",
        "component": "WebTier",
        "environment": "production",
        "region": "us-gov-west-1"
      }
    }
  ],
  "baselines": [
    {
      "name": "RHEL9-STIG",
      "version": "V1R1",
      "inputs": [
        { "name": "max_concurrent_sessions", "type": "Numeric", "value": 5 }
      ],
      "requirements": [
        {
          "id": "SV-257777",
          "results": [
            {
              "status": "failed",
              "codeDesc": "limits.conf maxlogins should cmp <= 5",
              "message": "expected maxlogins <= 5, got 7"
            }
          ]
        }
      ]
    }
  ]
}
```

### Phase 5: ANALYZE — hdf-comparison

The diff engine compares this month's scan against last month's.

```bash
# Basic comparison
hdf diff feb-scan.json mar-scan.json

# With system context — component-level breakdown
hdf diff --system portal-prod.hdf-system.json feb-scan.json mar-scan.json

# Group by any label
hdf diff --group-by labels.component feb-scan.json mar-scan.json

# CI/CD gate — nuanced exit codes
hdf diff --detailed-exitcode feb-scan.json mar-scan.json
# Exit 12 = mixed (fixes + regressions)
```

### Phase 6: GOVERN — hdf-amendments

An assessor creates a signed waiver with evidence.

```json
{
  "name": "Portal Q1 2026 Waivers",
  "systemRef": "portal-prod.hdf-system.json",
  "approvedBy": { "type": "email", "identifier": "ao@agency.gov" },
  "overrides": [
    {
      "type": "waiver",
      "requirementId": "SV-257777",
      "baselineRef": "RHEL9-STIG",
      "status": "passed",
      "reason": "Compensating control: session timeout set to 15 min",
      "expiresAt": "2026-06-30T00:00:00Z",
      "evidence": [
        {
          "type": "url",
          "data": "https://jira.agency.gov/CYBER-4521",
          "description": "ISSM approval with compensating control documentation"
        }
      ],
      "signature": {
        "type": "Ed25519Signature2020",
        "created": "2026-01-15T10:00:00Z",
        "creator": { "type": "email", "identifier": "ao@agency.gov" },
        "proofPurpose": "attestation",
        "signatureValue": "z3FXq7..."
      },
      "previousChecksum": { "algorithm": "sha256", "value": "abc123..." }
    }
  ]
}
```

**Merge operation:**
```bash
hdf amend apply portal-scan.json portal-waivers.json -o merged.json
```

### Phase 7: PROVE — hdf-evidence-package

Everything bundled for the auditor with integrity verification.

```json
{
  "name": "Enterprise Portal ATO Evidence - Q1 2026",
  "systemRef": "portal-prod.hdf-system.json",
  "preparedBy": { "type": "email", "identifier": "compliance@agency.gov" },
  "contents": [
    { "type": "hdf-system", "uri": "portal-prod.hdf-system.json", "checksum": {"algorithm":"sha256","value":"aaa..."} },
    { "type": "hdf-baseline", "uri": "rhel9-stig.hdf-baseline.json", "checksum": {"algorithm":"sha256","value":"bbb..."} },
    { "type": "hdf-plan", "uri": "portal-monthly-scan.hdf-plan.json", "checksum": {"algorithm":"sha256","value":"ccc..."} },
    { "type": "hdf-results", "uri": "portal-scan-merged.json", "checksum": {"algorithm":"sha256","value":"ddd..."} },
    { "type": "hdf-amendments", "uri": "portal-waivers-q1.json", "checksum": {"algorithm":"sha256","value":"eee..."} },
    { "type": "hdf-comparison", "uri": "portal-diff-feb-mar.json", "checksum": {"algorithm":"sha256","value":"fff..."} }
  ],
  "completenessCheck": {
    "allBaselinesAssessed": true,
    "allComponentsCovered": true,
    "expiredWaivers": 0,
    "unresolvedPoams": 2,
    "compliancePercent": 95.8,
    "sbomCoverage": { "componentsWithSbom": 3, "totalComponents": 5 }
  },
  "signature": { "type": "Ed25519Signature2020", "signatureValue": "z4GHyq8..." }
}
```

```bash
hdf evidence validate portal-evidence.json
# ✓ All baselines assessed
# ✓ All components covered
# ⚠ 2 unresolved POA&Ms
# Overall: 95.8% compliant

hdf evidence verify portal-evidence.json
# ✓ All checksums match
# ✓ Amendment signatures valid
# ✓ Amendment chain intact
```

---

## Typed Inputs — Bridging Governance and Automation

The typed Input primitive solves the gap between governance prose and scanner automation.

### The Problem

OSCAL and STIGs express requirements as prose: "The system must limit concurrent
sessions to 3 per user." Automated scanners need machine-readable expected values:
`max_concurrent_sessions: 3`. There is no standard way to connect these.

### The Solution: Input Chain

```
GOVERNANCE                    HDF SCHEMA                   AUTOMATION
───────────                   ──────────                   ──────────

SSP says:                     hdf-baseline:                InSpec profile:
"Max 3 sessions"              inputs: [{                   inputs:
                                name: max_sessions,          max_sessions: 3
                                type: Numeric,
                                value: 3
                              }]
        ↓
System tailors:               hdf-system:                  Plan resolves:
"We need 5"                   inputOverrides: [{           hdf-plan:
                                inputName: max_sessions,     inputs:
                                value: 5,                      max_sessions: 5
                                justification: "..."
                                approvedBy: ISSM
                              }]
        ↓
Scanner runs:                 hdf-results:                 InSpec exec:
"Found 7"                     inputs: [{                     --input max_sessions=5
                                name: max_sessions,
                                value: 5                   Result:
                              }]                             FAIL: got 7, expected <=5
        ↓
Diff detects:                 hdf-comparison:              CI/CD:
"Regression"                  parameterDrift: {              Exit code 11
                                expected: 5,
                                oldObserved: 5,
                                newObserved: 7
                              }
        ↓
Waiver applied:               hdf-amendments:             Merge:
"Risk accepted"               type: waiver,                  hdf amend apply
                              signature: { ... }
                              expiresAt: "2026-06-30"
```

Every step is typed, traceable, and auditable. An auditor can follow the chain from the
governance decision ("allow 5") through the scanner configuration ("configured with 5")
through the result ("found 7") through the risk acceptance ("waiver approved by AO").

### Rename: attributes → inputs

The `Evaluated_Baseline.attributes` field in hdf-results is renamed to `inputs` in v2.
This normalizes the legacy InSpec v3/v4 naming. InSpec itself renamed "attributes" to
"inputs" because "attributes" was ambiguous. Both schemas (baseline and results) now
use `inputs` consistently.

### Input Type Definition

```json
{
  "name": "max_concurrent_sessions",
  "type": "Numeric",
  "value": 3,
  "description": "Maximum concurrent sessions per user",
  "required": true,
  "sensitive": false,
  "operator": "le",
  "constraints": { "min": 1, "max": 100 }
}
```

Supported types: String, Numeric, Boolean, Array, Hash, Regexp.
Supported operators: eq, ne, lt, le, gt, ge, contains, matches, in, notIn.

---

## Labels — Flexible Grouping Without Hierarchy

### Design Decision

Four research agents analyzed adding system/sub-system hierarchy to the schema.
The conclusion: **labels are strictly more powerful than a fixed hierarchy**.

A hierarchy forces one grouping dimension. Labels support unlimited dimensions simultaneously.

### How Labels Work

Components and baselines carry optional `labels: Record<string, string>`:

```json
{
  "type": "host",
  "name": "web-01",
  "labels": {
    "system": "Portal-Prod",
    "component": "WebTier",
    "environment": "production",
    "region": "us-gov-west-1",
    "team": "platform-eng"
  }
}
```

The diff engine can group by any label:
```bash
hdf diff --group-by labels.system scan1.json scan2.json
hdf diff --group-by labels.component scan1.json scan2.json
hdf diff --group-by labels.team scan1.json scan2.json
```

### Well-Known Label Keys (documented convention, not enforced)

| Key | Description | Example Values |
|-----|-------------|----------------|
| `system` | Authorization boundary / ATO system | `"ACME-WebPortal"` |
| `component` | Logical component within a system | `"WebTier"`, `"DatabaseTier"` |
| `environment` | Deployment environment | `"production"`, `"staging"` |
| `region` | Geographic or cloud region | `"us-east-1"`, `"eu-west-1"` |
| `team` | Owning team | `"platform-engineering"` |
| `oscal-ssp` | URI to OSCAL SSP document | `"https://example.com/ssp.json"` |

### System Components Use Label Selectors

Components in hdf-system match assessed components by label values, not by name:

```json
{
  "name": "WebTier",
  "targetSelector": { "labels.component": "WebTier" },
  "baselineRefs": ["RHEL9-STIG"]
}
```

Adding a new server with `labels.component: "WebTier"` automatically includes it
in the WebTier component — no system document update needed.

---

## Generic Comparison — Any HDF Document Type

hdf-comparison is not limited to assessment results. It is a **generic structured diff
for any two HDF documents of the same type**. One comparison document contains one type
of diff.

### Comparison Modes

| Mode | Documents compared | Diff section | What it shows |
|------|-------------------|-------------|---------------|
| `temporal` | hdf-results vs hdf-results | `requirementDiffs[]` | Fixed, regressed, new, absent (implemented) |
| `baseline` | hdf-results vs hdf-results | `requirementDiffs[]` | Asymmetric — reference vs target (implemented) |
| `fleet` | hdf-results[] vs reference | `requirementDiffs[]` | N systems vs reference (implemented) |
| `multiSource` | hdf-results vs hdf-results | `requirementDiffs[]` | Different tools, same target (implemented) |
| `systemDrift` | hdf-system vs hdf-system | `componentDiffs[]` | Component/SBOM/boundary changes (planned) |
| `baselineEvolution` | hdf-baseline vs hdf-baseline | `requirementChanges[]` | Requirement changes between versions (planned) |

### Cross-Environment Comparison

Comparison is not just temporal (same system, two time points). It also covers:

- **Dev vs prod:** "Is production configured the same as what we tested in dev?"
- **Cross-system:** "How does System A's compliance compare to System B's?"
- **Pre/post migration:** "What changed after we moved from on-prem to cloud?"

These are same-mode comparisons (e.g., `temporal` or `fleet`) with different source
contexts. The comparison schema captures the context in `sources[].label` and the
top-level `systemRef` field.

### System-Level Comparison (systemDrift)

When comparing two hdf-system documents, the diff engine reports:

```
hdf diff old-system.json new-system.json

Component changes:
  + Added:    "APIGateway" (type: application)
  ~ Modified: "WebTier"
      baselineRefs: added "DISA-Container-STIG"
      SBOM changes (webtier.cdx.json):
        + Added:   pkg:npm/express@5.0.0
        - Removed: pkg:npm/express@4.18.2
        ~ Updated: pkg:deb/openssl@3.0.2 → 3.0.15
        CVE impact:
          - Resolved: CVE-2024-1234 (openssl patched)
          + New:      CVE-2026-5678 (express 5.0.0)
  ~ Modified: "DatabaseTier"
      baselineRefs: ["PostgreSQL-15-STIG"] → ["CockroachDB-STIG"]
  - Removed: "LegacyAuth" (decommissioned)

Authorization:
  ~ Status: conditionallyAuthorized → authorized
```

### SBOM Comparison

SBOM comparison is a sub-feature of system comparison. When both system documents
have components with `sbomRef`, the diff engine reads and parses the referenced
SBOM documents (CycloneDX and SPDX are both supported) to produce package-level diffs.

**Library adoption:**
- **Go:** `protobom` (OpenSSF, 320 stars) — unified CycloneDX + SPDX parsing with
  built-in diff primitives (`Node.Diff()`, `NodeList.Intersect()`, `NodeList.Union()`)
- **TypeScript:** Custom format-agnostic parser normalizing CycloneDX `components[]`
  and SPDX `packages[]` into a common model, indexed by PURL via `packageurl-js`

Full research: (archived)

The diff algorithm is format-agnostic once components are extracted: match by PURL,
compare versions, report added/removed/updated. Both CycloneDX and SPDX from day one.

### Baseline Evolution (baselineEvolution)

When comparing two hdf-baseline documents (e.g., STIG V1R1 vs V1R2), the diff shows:

- Requirements added (new controls in the update)
- Requirements removed (deprecated controls)
- Requirements modified (changed description, impact, tags, check/fix text)
- Input changes (default values modified)

### Schema Additions for Generic Comparison

The hdf-comparison schema gains:
- Top-level `systemRef` field (auditor needs system boundary context)
- Optional `componentDiffs[]` section (for system comparison)
- Optional `packageDiffs[]` section (for SBOM comparison within system diff)
- Optional `requirementChanges[]` section (for baseline comparison)
- New `comparisonMode` values: `systemDrift`, `baselineEvolution`

---

## Chain of Trust

The existing hdf-integrity design provides 5 trust levels. Attestations and waivers
build on this:

```
Level 0: No integrity (default)
Level 1: SHA-256 checksums (tamper detection)
Level 2: Amendment chain (previousChecksum creates linked list)
Level 3: Digital signatures (non-repudiation)
Level 4: External audit log (timestamp authority)
```

### Amendment Chain

```
Original scan results  ──checksum──→  Attestation   ──signature──→  Merged results
     (unsigned)              ↑           (signed)                    (verifiable)
                      previousChecksum
```

Each amendment entry carries:
- **Who**: Identity (email, username, system)
- **What**: requirementId, status change, evidence
- **When**: appliedAt, expiresAt (no permanent overrides)
- **Why**: reason (free text justification)
- **Proof**: evidence[] (screenshots, logs, URLs)
- **Signature**: digital signature by the authorizing official
- **Chain link**: previousChecksum linking to prior amendment

### Override Types

| Type | Meaning | Effect | Who |
|---------|---------|--------|-----|
| **attestation** | "I verified this manually" | Status → passed | Assessor |
| **waiver** | "I accept this risk" | Status → passed (risk remains) | Authorizing official |
| **falsePositive** | "Scanner incorrectly flagged this" | Status → passed or notApplicable | Assessor + AO |
| **riskAdjustment** | "Impact adjusted for context" | Impact score changed (FedRAMP Risk Adjustment) | AO |
| **operationalRequirement** | "Deviation required by operations" | Open risk (FedRAMP Operational Requirement) | System owner + AO |
| **inherited** | "Control provided by another system" | Status reflects inherited posture | System owner |
| **poam** | "We'll fix this by date X" | Status unchanged (tracks work) | System owner |

All seven use the same `hdf-amendments` document type with a `type` discriminator.

---

## CLI Command Tree

```
hdf
├── validate <file>               # Validate any HDF document against its schema
├── info <file>                   # Display summary of any HDF document
├── stats <results-file>          # Assessment statistics
├── list <type> <file>            # List requirements, baselines, components
├── query <results-file>          # Search/filter controls
├── convert <from> to <to>        # Convert between formats (30+ converters)
│
├── diff <old> <new>              # Compare any two HDF docs of same type (EXISTS)
│   ├── --system <file>           # System-aware comparison
│   ├── --group-by <label>        # Group by any label
│   ├── --detailed-exitcode       # Nuanced exit codes (10-14)
│   ├── --format json|md|table    # Output format
│   │   # Examples:
│   │   # hdf diff old-results.json new-results.json       (assessment diff)
│   │   # hdf diff old-system.json new-system.json         (system drift)
│   │   # hdf diff stig-v1r1.json stig-v1r2.json           (baseline evolution)
│   │   # hdf diff dev-results.json prod-results.json      (cross-environment)
│
├── system                        # System operations
│   ├── info <file>               # Show system architecture
│   ├── validate <file>           # Validate system document
│   ├── discover --aws|--k8s      # Auto-discover from cloud/k8s
│   └── export --format oscal     # Export to OSCAL SSP
│
├── plan                          # Assessment planning
│   ├── create --system <file>    # Generate plan from system definition
│   ├── validate <file>           # Validate plan against system
│   └── run <file>                # Execute the plan (run scans)
│
├── amend                         # Amendment management
│   ├── create <results-file>     # Create waiver/attestation/override
│   ├── apply <results> <amend>   # Merge amendments into results
│   ├── verify <file>             # Verify signatures and amendment chain
│   └── list <file>               # List active/expired overrides
│
├── evidence                      # Evidence packaging
│   ├── build --system --results  # Package everything for audit
│   ├── validate <file>           # Check completeness
│   ├── verify <file>             # Verify integrity chain
│   └── export --format oscal     # Export to OSCAL format
│
└── version                       # Print version info
```

---

## Heimdall Integration

How Heimdall consumes each document type:

```
Heimdall Dashboard
├── System View                   # Load hdf-system → see components, baselines
│   ├── Component compliance %    # Aggregate results by labels.component
│   ├── Authorization status      # From hdf-system
│   └── Drill down to controls    # From hdf-results
│
├── Comparison View               # Load hdf-comparison → see what changed
│   ├── Temporal trending         # Chain of comparisons over time
│   ├── Fleet comparison          # Systems side-by-side
│   └── Component breakdown       # Group by labels.component
│
├── Waiver Management             # Create/manage hdf-amendments documents
│   ├── Active waivers            # With expiration countdown
│   ├── Approval workflow         # Sign with hardware key
│   └── Merge into results        # Apply button
│
├── Evidence Export                # Generate hdf-evidence-package
│   ├── Completeness checker      # Are all baselines covered?
│   ├── Package builder           # Bundle with integrity
│   └── OSCAL export              # One-click OSCAL generation
│
└── Plan Management               # Create/execute hdf-plan
    ├── Scan scheduler            # Cron-based recurring plans
    ├── Input management          # Override baseline defaults per system
    └── Execution history         # Plan → results provenance
```

---

## Converter Impact

### Standard Converters (30+)

**One mandatory change:** The `attributes` → `inputs` rename (Phase 0.3) affects every
converter that sets `Evaluated_Baseline.attributes`. This is a mechanical field rename.

All other enrichment is additive and optional (progressive enrichment):

| Converter | Enrichment it can populate |
|-----------|--------------------------|
| All | (none required beyond the rename) |
| aws-config | `labels.account`, `labels.region` |
| nessus | `labels.hostgroup`, `labels.network` |
| k8s-bench | `labels.cluster`, `labels.namespace` |
| InSpec | Typed `inputs` (already has data in inspec.yml) |
| grype/trivy | `labels.image`, `labels.registry`, `component.sbomRef` |
| OSCAL AR import | `systemRef` (from OSCAL import-ssp) |

### OSCAL Converters (Multi-Document)

OSCAL converters are special — they produce **multiple HDF document types**, not just
hdf-results. Each OSCAL document type maps to a specific HDF document type:

| OSCAL Source | HDF Output | Notes |
|-------------|-----------|-------|
| System Security Plan (SSP) | **hdf-system** | System architecture, components, boundary |
| Assessment Results (SAR) | hdf-results | Assessment findings with labels + systemRef |
| Plan of Action & Milestones (POA&M) | **hdf-amendments** | Risk responses, waivers, remediation plans |
| Assessment Plan (SAP) | **hdf-plan** | Assessment scope, methodology, schedule |
| Catalog | hdf-baseline | Security requirements |
| Profile | hdf-baseline | Tailored requirements |

These converters cannot be implemented until the target schemas exist. They are
tracked under Phase 5 (hdf-libs-qcj7) with a converter alignment audit card
(hdf-libs-ccp0) to ensure all converters reflect current schema changes.

Reverse converters (HDF → OSCAL) are also needed for OSCAL export from Heimdall.

---

## Schema Organization

```
hdf-schema/src/schemas/
├── hdf-baseline.schema.json           (exists)
├── hdf-results.schema.json            (exists)
├── hdf-comparison.schema.json         (exists)
├── hdf-system.schema.json             (exists)
├── hdf-plan.schema.json               (exists)
├── hdf-amendments.schema.json         (exists)
├── hdf-evidence-package.schema.json   (exists)
└── primitives/
    ├── common.schema.json             (exists — Identity, Checksum, Signature, Evidence)
    ├── result.schema.json             (exists — ResultStatus, RequirementResult)
    ├── component.schema.json          (exists — 11 component types with labels)
    ├── data-flow.schema.json          (exists — Data_Flow, Direction)
    ├── extensions.schema.json         (exists — StatusOverride, POAM, Generator)
    ├── comparison.schema.json         (exists — RequirementDiff, Source)
    ├── system.schema.json             (exists — System, AuthorizationStatus)
    ├── plan.schema.json               (exists — Assessment, Schedule)
    ├── amendments.schema.json         (exists — Override types with signature support)
    ├── parameter.schema.json          (exists — Input/Parameter type definitions)
    ├── platform.schema.json           (exists)
    ├── runner.schema.json             (exists)
    └── statistics.schema.json         (exists)
```

## Shared Primitives

Existing primitives reused across document types:
- **Identity** — who performed an action (email, username, system)
- **Checksum** — SHA-256/384/512 integrity verification
- **Signature** — digital signatures (JWK, PEM, Ed25519, PKCS#11)
- **Evidence** — supporting artifacts (screenshots, logs, URLs)
- **Component** — assessed entities (11 polymorphic types)

New primitives:
- **Input** — typed parameter definition (name, type, value, operator, constraints)
- **Labels** — key-value metadata on components and baselines

---

## Design Principles

1. **Assessment-centric** — HDF models assessment data. Organizational/governance
   context lives in separate document types (hdf-system, hdf-amendments), not
   embedded in results.

2. **Labels over hierarchies** — Components and baselines carry key-value labels for
   flexible grouping. No fixed hierarchy imposed. Follows Kubernetes/AWS tagging patterns.

3. **Separate document types** — Following OSCAL's pattern of SSP vs AR, each concern
   gets its own document type. They compose via references, not nesting.

4. **Chain of trust** — Amendment chains (previousChecksum), digital signatures, and
   integrity verification enable tamper-evident audit trails across document types.

5. **Typed inputs** — Parameter definitions carry type information enabling automated
   validation of expected vs observed values. Bridges governance prose to automation.

6. **Backward compatible** — All new fields are optional. Documents without labels,
   systemRef, or typed inputs remain valid. Converters need zero changes.

7. **DRY with $ref** — All document types share primitives via JSON Schema $ref.
   Types defined once in primitives, referenced everywhere.

---

## Changes to Existing Schemas

### hdf-results.schema.json
- Rename `attributes` to `inputs` on Evaluated_Baseline (normalize legacy InSpec naming)
- Add optional `labels: Record<string, string>` to Component via component.schema.json
- Add optional `labels: Record<string, string>` to Evaluated_Baseline
- Add optional `systemRef: string` (URI to hdf-system document)
- Add optional `planRef: string` (URI to hdf-plan document)
- Use typed Input primitive for `inputs[]` (was unstructured `object`)

### hdf-baseline.schema.json
- Add optional `labels: Record<string, string>`
- Use typed Input primitive for `inputs[]` (was unstructured `object`)

### primitives/component.schema.json
- Add optional `labels` to Base_Component

### primitives/common.schema.json
- Add Input type definition (or new parameter.schema.json)

---

## OSCAL Alignment

| HDF Document | OSCAL Equivalent | Relationship |
|-------------|-----------------|--------------|
| hdf-baseline | Catalog + Profile | Convert from OSCAL |
| hdf-results | Assessment Results (AR) | Bidirectional convert |
| hdf-comparison | (none — HDF original) | Export summaries |
| hdf-system | SSP system-characteristics | Bidirectional convert |
| hdf-plan | Assessment Plan (SAP) | Bidirectional convert |
| hdf-amendments | POA&M risk-response | Bidirectional convert |
| hdf-evidence | (AR + POA&M bundle) | Export to OSCAL |

---

## Data Volume and Sizing

### Per-Document Sizes

| Document | Typical Size (raw) | Compressed (gzip) | Notes |
|----------|-------------------|-------------------|-------|
| hdf-baseline | 50–200 KB | 5–20 KB | 250–800 requirements × ~200B metadata each |
| hdf-results | 300–800 KB | 25–65 KB | 250–800 requirements × ~1 KB each (with results) |
| hdf-comparison | 600–1500 KB | 50–120 KB | Full before/after snapshots for all requirements |
| hdf-system | 5–20 KB | 1–3 KB | Components, dataFlows, boundary definition |
| hdf-plan | 3–10 KB | 0.5–2 KB | Assessment config, schedule, resolved inputs |
| hdf-amendments | 2–50 KB | 0.5–5 KB | Depends on number of overrides + embedded evidence |
| hdf-evidence-package | 1–5 KB | 0.3–1 KB | Metadata only (references with checksums, no embedded content) |

### Full Snapshots Sizing Rationale

The comparison document uses full `EvaluatedRequirement` before/after snapshots
(Terraform pattern), not patches. The size cost is negligible:

```
Typical STIG: 300 requirements × ~1 KB each = ~300 KB per scan
Full comparison (worst case — all 300 changed):
  300 × 2 sides × 1 KB  = ~600 KB
  + metadata/summary     = ~650 KB

With gzip (standard for HTTP and storage):
  ~650 KB × 0.08 (JSON compresses ~92%) = ~52 KB
```

52 KB gzipped — smaller than most JPEG images. Even uncompressed, 650 KB is trivial
for modern APIs, storage, dashboards, and CLI output.

### Enterprise Scale: 500 Systems, Monthly Scans

A mid-size federal agency with ~500 systems under continuous monitoring:

```
Per system per month:
  1 results file:          ~500 KB
  1 comparison file:      ~1000 KB
  1 amendment update:       ~10 KB  (quarterly, amortized)
  1 system doc update:      ~10 KB  (updated rarely)
  ─────────────────────────────────
  Total:                  ~1.5 MB raw / ~130 KB gzipped

Enterprise per month (500 systems):
  500 × 1.5 MB           = 750 MB raw / ~65 MB gzipped

Enterprise per year:
  750 MB × 12             = 9 GB raw / ~780 MB gzipped
  + evidence packages       ~2.5 MB  (500 quarterly bundles, negligible)
  + baselines               ~100 MB  (updated infrequently)
  ─────────────────────────────────────────────────────────
  Total annual raw:        ~9.1 GB
  Total annual compressed: ~880 MB
```

### Fleet Comparison Performance

```
Small fleet  (50 systems × 300 controls):     15K comparisons    → <1 second
Medium fleet (200 systems × 500 controls):   100K comparisons    → ~2 seconds
Large fleet  (500 systems × 800 controls):   400K comparisons    → ~5 seconds
                                             ~200 MB raw / ~16 MB gzipped
Enterprise   (1000+ systems × 800 controls): 800K+ comparisons   → streaming/chunked
```

Processing time estimates assume single-threaded sequential comparison. The Go CLI
can parallelize across cores for fleet mode. Streaming/chunked processing prevents
memory exhaustion at enterprise scale.

### Comparison to Existing Tools

| Tool | Scope | Storage per year (500 systems) |
|------|-------|-------------------------------|
| Heimdall2 database | Results only | ~2–5 GB |
| eMASS | Everything including docs | ~10–50 GB |
| HDF with full ecosystem | All 7 doc types, self-contained | ~9 GB raw / ~880 MB gzipped |
| OSCAL (full AR + SSP + POA&M) | Assessment + governance | ~15–30 GB (verbose XML/JSON) |

HDF is competitive on storage while providing richer document types. The high
compressibility of JSON (92% with gzip) means network transfer and cold storage
costs are minimal.

---

## Progressive Enrichment

HDF documents follow a principle of **progressive enrichment**: each layer of
context adds value when present but never blocks core functionality when absent.

| Enrichment Layer | When Present | When Absent |
|-----------------|-------------|-------------|
| Labels on components | Group by system/component/team/region | Flat list of components |
| systemRef on results | Provenance chain to system architecture | Results stand alone |
| planRef on results | Audit trail of scan configuration | Results stand alone |
| Typed inputs on baselines | Machine-readable expected values | Unstructured attributes |
| Signatures on overrides | Non-repudiation, chain of trust | Unsigned governance decisions |
| sbomRef on components | Full software supply chain traceability | Architecture without package details |

This means:
- A converter producing bare results with no labels works fine.
- A system doc with no sbomRefs works fine.
- An evidence package with partial coverage is informational, not invalid.
- The schema never rejects a document for missing enrichment.

Consumers (Heimdall, CLI, CI/CD) can check for enrichment levels and prompt users
to add more context ("3 of 5 components have SBOM coverage — consider running
your SBOM scanner on the remaining 2").

---

## What HDF Does NOT Define

- **Policy documents** — prose, belongs in GRC platforms (Archer, ServiceNow GRC)
- **Remediation playbooks** — Ansible/Terraform have their own formats; `remediation.uri` is sufficient
- **SBOM** — defer to CycloneDX/SPDX. HDF references SBOMs by URI (from hdf-system
  components and optionally from hdf-results components) but does not define its own SBOM
  format. Package-level data enters HDF through `tags.purl` on vulnerability findings
  (populated by SCA converters like Grype/Trivy) and through `sbomRef` fields pointing
  to external SBOM documents. See "Progressive Enrichment" — SBOM references are always
  optional.
- **VEX/Advisories** — defer to CSAF/OpenVEX
- **Trending/time-series** — query-time aggregation of hdf-comparison documents
- **Alerts** — integration concern (webhooks, PagerDuty, Slack)
- **Incident response** — STIX/TAXII, TheHive, MISP

HDF builds converters TO/FROM these standards, not competing schemas.

---

## AI Agent Integration (Future)

### TOON (Token-Oriented Object Notation)

TOON is a text-based format designed to reduce token consumption when passing structured
data to LLMs. Research found 30-60% token reduction for uniform tabular data.

- **Best fit:** The `requirementDiffs[]` array (uniform, tabular) — TOON's sweet spot
- **Poor fit:** Nested `before`/`after` snapshots — falls back to verbose encoding
- **npm package:** `@toon-format/toon` (MIT, v3.0 spec working draft)
- **Status:** Experimental. Add as optional output renderer when demand materializes.

### JSON-LD

JSON-LD would add `@context` to HDF documents, mapping fields to security ontology URIs
for semantic web discoverability. Deferred — adds complexity without immediate need.
HDF JSON Schema already serves as the tool-use spec for LLMs.

### MCP Server

An MCP (Model Context Protocol) server wrapping `hdf-diff` would let AI agents invoke
`diffHdf()` directly as a tool. The JSON Schema defines the function calling spec.
Combined with TOON output, this enables low-token-cost security assessment analysis
by AI agents. Create card when MCP ecosystem matures.

---

## Multi-Language Support (Future)

### Current

- **TypeScript** — npm packages for programmatic use (Heimdall, CI/CD integrations)
- **Go** — native CLI binary + reusable packages

### Planned / Considered

- **Python** — type definitions and runtime library for data science, ML-based security
  analytics, Jupyter notebook consumption of HDF data.
- **Ruby** — would serve the Chef/InSpec ecosystem natively. InSpec itself is Ruby.
  Could enable direct profile-to-baseline conversion without Node/Go.
- **Rust** — performance-critical CLI, WASM compilation for browser-based tools,
  memory-safe parsing of untrusted HDF documents.

No timeline set. Ruby, Python, and Rust would require manual implementation or new
generator backends.

---

## Key Design Documents

| Document | Purpose |
|----------|---------|
| `docs/architecture/hdf-readers-guide.md` | **Start here** — narrative guide with walkthroughs |
| `docs/architecture/hdf-document-ecosystem.md` | This file — full ecosystem vision |
| Design decisions | (archived) — 12 design decisions with research rationale |
| `docs/design/developer-guide.md` | Patterns for contributors (dual impl, testing, cross-platform) |
| `docs/plans/2026-03-14-hdf-ecosystem-plan.md` | Implementation plan with phase cards |
| SBOM library research | (archived) |
| Docs consistency review | (archived) |
| Memory audit | (archived) |

## Decision-to-Card Mapping

| Decision | Beads Card | Phase |
|----------|-----------|-------|
| D1: Labels over hierarchies | hdf-libs-pdf7 | Phase 0.2 |
| D5: Typed inputs | hdf-libs-hlvt | Phase 0.1 |
| D6: Seven document types | hdf-libs-15kg (epic) | All phases |
| D8: Dual TS+Go from day one | (all cards) | All phases |
| D9: Progressive enrichment | (all cards) | All phases |
| D10: Rename to hdf-amendments | hdf-libs-3qm7 | Phase 3 |
| D11: Generic comparison | hdf-libs-tvcs (system), hdf-libs-gz0p (baseline), hdf-libs-a96 (SBOM) | Phase 1+ |
| D12: SBOM library adoption | hdf-libs-a96, hdf-libs-b4lj | Phase 1 |
| Converter v2 alignment | hdf-libs-ccp0 | Phase 5 |
