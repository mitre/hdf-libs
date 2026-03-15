# HDF v2 Document Type Ecosystem

## Overview

HDF (Heimdall Data Format) v2 defines 7 document types that together cover the full
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
| 6 | hdf-attestation | `hdf-attestation.schema.json` | Waivers, risk acceptance, manual verification | Assessors, authorizing officials | hdf-results (merge), auditors |
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
                                            │ hdf-attestation │         │
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
**Governance flows SIDEWAYS** (attestation merges into results).

## Cross-Reference Map

```
hdf-baseline ←──── hdf-plan (which baselines to run)
     │                │
     ▼                ▼
hdf-system ◄───── hdf-plan (which components/targets to scan)
     │                │
     ▼                ▼
hdf-results ◄──── hdf-plan (provenance: what config produced these results)
     │
     ├──── hdf-attestation (merge: apply waivers to results)
     │
     ├──── hdf-comparison (diff: compare two results)
     │
     └──── hdf-evidence-package (bundle: package everything for audit)
```

| Document | References | Referenced By |
|----------|-----------|---------------|
| hdf-baseline | Framework mappings (CCI, NIST), typed inputs | hdf-system, hdf-plan, hdf-results |
| hdf-system | hdf-baseline (component→baseline mapping), targets (via label selectors) | hdf-plan, hdf-results, hdf-comparison, hdf-evidence |
| hdf-plan | hdf-baseline (which baselines), hdf-system (which targets), resolved inputs | hdf-results (provenance) |
| hdf-results | hdf-baseline (evaluated), targets (with labels), systemRef, planRef | hdf-comparison, hdf-attestation, hdf-evidence |
| hdf-comparison | hdf-results (source checksums), hdf-system (fleet mode) | hdf-evidence |
| hdf-attestation | hdf-baseline (requirements), hdf-system, Identity, Signature | hdf-results (merge), hdf-evidence |
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

The scanner produces results with labels on targets and typed inputs on baselines.

```json
{
  "timestamp": "2026-03-14T02:00:00Z",
  "systemRef": "portal-prod.hdf-system.json",
  "planRef": "portal-monthly-scan.hdf-plan.json",
  "targets": [
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

### Phase 6: GOVERN — hdf-attestation

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
hdf attest apply portal-scan.json portal-waivers.json -o merged.json
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
    { "type": "hdf-attestation", "uri": "portal-waivers-q1.json", "checksum": {"algorithm":"sha256","value":"eee..."} },
    { "type": "hdf-comparison", "uri": "portal-diff-feb-mar.json", "checksum": {"algorithm":"sha256","value":"fff..."} }
  ],
  "completenessCheck": {
    "allBaselinesAssessed": true,
    "allComponentsCovered": true,
    "expiredWaivers": 0,
    "compliancePercent": 95.8
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
# ✓ Attestation signature valid
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
Waiver applied:               hdf-attestation:             Merge:
"Risk accepted"               type: waiver,                  hdf attest apply
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

Targets and baselines carry optional `labels: Record<string, string>`:

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

Components in hdf-system match targets by label values, not by name:

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

### Attestation Chain

```
Original scan results  ──checksum──→  Attestation   ──signature──→  Merged results
     (unsigned)              ↑           (signed)                    (verifiable)
                      previousChecksum
```

Each attestation carries:
- **Who**: Identity (email, username, system)
- **What**: requirementId, status change, evidence
- **When**: appliedAt, expiresAt (no permanent overrides)
- **Why**: reason (free text justification)
- **Proof**: evidence[] (screenshots, logs, URLs)
- **Signature**: digital signature by the authorizing official
- **Chain link**: previousChecksum linking to prior amendment

### Attestation vs Waiver vs Exception

| Concept | Meaning | Effect | Who |
|---------|---------|--------|-----|
| **Attestation** | "I verified this manually" | Status → passed | Assessor |
| **Waiver** | "I accept this risk" | Status → passed (risk remains) | Authorizing official |
| **Exception** | "This doesn't apply" | Status → notApplicable | System owner + AO |
| **POA&M** | "We'll fix this by date X" | Status unchanged (tracks work) | System owner |

All four use the same `hdf-attestation` document type with a `type` discriminator.

---

## CLI Command Tree

```
hdf
├── validate <file>               # Validate any HDF document against its schema
├── info <file>                   # Display summary of any HDF document
├── stats <results-file>          # Assessment statistics
├── list <type> <file>            # List controls, profiles, targets
├── query <results-file>          # Search/filter controls
├── convert <from> to <to>        # Convert between formats (30+ converters)
│
├── diff <old> <new>              # Compare assessments (EXISTS)
│   ├── --system <file>           # System-aware comparison
│   ├── --group-by <label>        # Group by any label
│   ├── --detailed-exitcode       # Nuanced exit codes (10-14)
│   └── --format json|md|table    # Output format
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
├── attest                        # Attestation management
│   ├── create <results-file>     # Create waiver/attestation
│   ├── apply <results> <attest>  # Merge attestation into results
│   ├── verify <file>             # Verify signatures
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
├── System View                   # Load hdf-system → see components, targets, baselines
│   ├── Component compliance %    # Aggregate results by labels.component
│   ├── Authorization status      # From hdf-system
│   └── Drill down to controls    # From hdf-results
│
├── Comparison View               # Load hdf-comparison → see what changed
│   ├── Temporal trending         # Chain of comparisons over time
│   ├── Fleet comparison          # Systems side-by-side
│   └── Component breakdown       # Group by labels.component
│
├── Waiver Management             # Create/manage hdf-attestation documents
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

**Zero mandatory changes.** Converters produce hdf-results documents. They don't need
to know about systems, plans, or attestations. Additive label population is optional:

| Converter | Labels it can populate |
|-----------|----------------------|
| All | (none required) |
| aws-config | `labels.account`, `labels.region`, `labels.service` |
| nessus | `labels.hostgroup`, `labels.network` |
| k8s-bench | `labels.cluster`, `labels.namespace` |
| InSpec | Typed `inputs` (already has data in inspec.yml) |
| grype/trivy | `labels.image`, `labels.registry` |
| OSCAL AR import | `systemRef` (from OSCAL import-ssp) |

---

## Schema Organization

```
hdf-schema/src/schemas/
├── hdf-baseline.schema.json           (exists)
├── hdf-results.schema.json            (exists)
├── hdf-comparison.schema.json         (exists)
├── hdf-system.schema.json             (new)
├── hdf-plan.schema.json               (new)
├── hdf-attestation.schema.json        (new)
├── hdf-evidence-package.schema.json   (new)
└── primitives/
    ├── common.schema.json             (exists — Identity, Checksum, Signature, Evidence)
    ├── result.schema.json             (exists — ResultStatus, RequirementResult)
    ├── target.schema.json             (exists — 11 target types, adding labels)
    ├── extensions.schema.json         (exists — StatusOverride, POAM, Generator)
    ├── comparison.schema.json         (exists — RequirementDiff, Source)
    ├── system.schema.json             (new — System, Component, AuthorizationStatus)
    ├── plan.schema.json               (new — Assessment, Schedule)
    ├── attestation.schema.json        (new — Override types with signature support)
    ├── parameter.schema.json          (new — Input/Parameter type definitions)
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
- **Target** — assessed entities (11 polymorphic types)

New primitives for v2:
- **Input** — typed parameter definition (name, type, value, operator, constraints)
- **Labels** — key-value metadata on targets and baselines

---

## Design Principles

1. **Assessment-centric** — HDF models assessment data. Organizational/governance
   context lives in separate document types (hdf-system, hdf-attestation), not
   embedded in results.

2. **Labels over hierarchies** — Targets and baselines carry key-value labels for
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

## v2 Changes to Existing Schemas

### hdf-results.schema.json
- Rename `attributes` to `inputs` on Evaluated_Baseline (normalize legacy InSpec naming)
- Add optional `labels: Record<string, string>` to Target via target.schema.json
- Add optional `labels: Record<string, string>` to Evaluated_Baseline
- Add optional `systemRef: string` (URI to hdf-system document)
- Add optional `planRef: string` (URI to hdf-plan document)
- Use typed Input primitive for `inputs[]` (was unstructured `object`)

### hdf-baseline.schema.json
- Add optional `labels: Record<string, string>`
- Use typed Input primitive for `inputs[]` (was unstructured `object`)

### primitives/target.schema.json
- Add optional `labels` to Base_Target

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
| hdf-plan | Assessment Plan (SAP) | Convert from OSCAL |
| hdf-attestation | POA&M risk-response | Bidirectional convert |
| hdf-evidence | (AR + POA&M bundle) | Export to OSCAL |

---

## What HDF Does NOT Define

- **Policy documents** — prose, belongs in GRC platforms (Archer, ServiceNow GRC)
- **Remediation playbooks** — Ansible/Terraform have their own formats; `remediation.uri` is sufficient
- **SBOM** — defer to CycloneDX/SPDX, reference by URI from hdf-system components
- **VEX/Advisories** — defer to CSAF/OpenVEX
- **Trending/time-series** — query-time aggregation of hdf-comparison documents
- **Alerts** — integration concern (webhooks, PagerDuty, Slack)
- **Incident response** — STIX/TAXII, TheHive, MISP

HDF builds converters TO/FROM these standards, not competing schemas.
