# HDF: The Complete Picture

> A narrative guide to the Heimdall Data Format ecosystem — what it is, why it
> exists, and how all the pieces fit together. Read this first if you're new to HDF.

---

## The Problem

Security assessment is fragmented. An organization running 500 systems has:

- **30+ scanner tools** producing incompatible output formats (InSpec, Nessus, Trivy,
  OpenSCAP, AWS Config, Grype, SARIF tools, etc.)
- **No standard way to compare** assessments across time, tools, or environments
- **No structured link** between governance decisions ("we accept this risk") and
  scanner automation ("check if this value is ≤ 5")
- **No audit trail** connecting the scan results to the system architecture to the
  risk acceptance to the evidence package
- **No way to ask** "what changed?" at the system level — only at the individual
  scan level

HDF solves this with **7 document types** that together cover the full security
assessment lifecycle.

---

## The Seven Document Types

```
DEFINE          DESCRIBE         PLAN            EXECUTE
─────           ────────         ────            ───────
hdf-baseline    hdf-system       hdf-plan        hdf-results
"what to        "what is the     "how to         "what
 check"          system"          assess it"      happened"

                    ANALYZE              GOVERN            PROVE
                    ───────              ──────            ─────
                    hdf-comparison       hdf-amendments    hdf-evidence-package
                    "what changed"       "risk decisions"  "audit bundle"
```

Each document type has its own JSON Schema, its own CLI commands, and its own
purpose. They connect via cross-references — not nesting — following OSCAL's
principle of keeping concerns separate.

---

## Walkthrough 1: Monthly Compliance Scan

*The most common use case — scanning a system monthly and tracking changes.*

### Step 1: The baseline exists

A STIG author created an RHEL 9 baseline with typed inputs:

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
      "required": true,
      "operator": "le"
    }
  ],
  "requirements": [
    {
      "id": "SV-257777",
      "title": "RHEL 9 must limit concurrent sessions",
      "impact": 0.5,
      "tags": { "cci": ["CCI-000054"], "nist": ["AC-10"] }
    }
  ]
}
```

The `inputs` field is the bridge between governance prose ("max 3 sessions") and
scanner automation (`--input max_concurrent_sessions=3`). Without typed inputs,
this value lives in a sentence in the SSP that no machine can read.

### Step 2: The scanner runs

InSpec executes the baseline against a server, producing an hdf-results document:

```json
{
  "timestamp": "2026-03-14T02:00:00Z",
  "systemRef": "portal-prod.hdf-system.json",
  "components": [
    {
      "type": "host",
      "name": "web-server-01",
      "labels": {
        "system": "Enterprise Portal Production",
        "component": "WebTier",
        "environment": "production"
      }
    }
  ],
  "baselines": [
    {
      "name": "RHEL9-STIG",
      "inputs": [
        { "name": "max_concurrent_sessions", "type": "Numeric", "value": 5 }
      ],
      "requirements": [
        {
          "id": "SV-257777",
          "results": [
            {
              "status": "failed",
              "message": "expected maxlogins <= 5, got 7"
            }
          ]
        }
      ]
    }
  ]
}
```

Notice: the input value is `5`, not `3`. The system owner tailored the baseline
default (3) to allow 5 sessions. This is traceable through the input chain:
baseline default (3) → system override (5) → scan value (5) → observed (7) → FAIL.

### Step 3: Compare with last month

```bash
hdf diff feb-scan.json mar-scan.json --format table

  State       Count   Examples
  ─────       ─────   ────────
  fixed         12    SV-230387, SV-230401, ...
  regressed      3    SV-257777, SV-258001, SV-258042
  unchanged    498
  new            2    SV-260101, SV-260102
  absent         0

  Compliance: 94.2% → 93.1% (Δ -1.1%)

hdf diff --detailed-exitcode feb-scan.json mar-scan.json
# Exit code 12 (mixed fixes and regressions)
```

The comparison document captures the full before/after state of every requirement.
An auditor can drill into any requirement and see exactly what changed.

### Step 4: CI/CD gate

```bash
hdf diff --detailed-exitcode feb-scan.json mar-scan.json
case $? in
  0)  echo "No changes" ;;
  10) echo "Improvements only — safe to proceed" ;;
  11) echo "Regressions found — blocking deployment" ; exit 1 ;;
  12) echo "Mixed — needs human review" ;;
esac
```

GitLab CI supports `allow_failure: exit_codes: [10, 13, 14]` natively, letting
security improvements pass while blocking regressions.

---

## Walkthrough 2: System Architecture and Drift

*A system evolves over time. Components are added, technologies change, SBOMs update.*

### Step 1: Define the system

```json
{
  "name": "Enterprise Portal Production",
  "identifier": "SYS-2024-00142",
  "authorizationStatus": "authorized",
  "categorizationLevel": "moderate",
  "components": [
    {
      "name": "WebTier",
      "type": "application",
      "targetSelector": { "labels.component": "WebTier" },
      "baselineRefs": ["RHEL9-STIG"],
      "sbomRef": "https://artifacts.agency.gov/sbom/webtier-2026-02.cdx.json",
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

Key design points:
- **Label selectors** (`targetSelector`) match components by labels, not by name.
  Adding a new web server with `labels.component: "WebTier"` automatically includes
  it — no system doc update needed.
- **sbomRef** points to an external CycloneDX SBOM. This is optional (progressive
  enrichment) — the system doc works fine without it.
- **inputOverrides** tailor the baseline defaults per component. The ISSM approved
  raising `max_concurrent_sessions` from 3 to 5.

### Step 2: The system changes

A month later, the team adds an API Gateway, upgrades the web tier SBOM, and gets
full ATO:

```bash
hdf diff old-system.json new-system.json

Component changes:
  + Added:    "APIGateway" (type: application)
  ~ Modified: "WebTier"
      sbomRef: webtier-2026-02.cdx.json → webtier-2026-03.cdx.json
      SBOM changes:
        + Added:   pkg:npm/express@5.0.0
        - Removed: pkg:npm/express@4.18.2
        ~ Updated: pkg:deb/openssl@3.0.2 → 3.0.15
        CVE impact:
          - Resolved: CVE-2024-1234 (openssl patched)
          + New:      CVE-2026-5678 (express 5.0.0, no fix yet)

Authorization:
  ~ Status: conditionallyAuthorized → authorized
  ~ Date: 2025-06-15 → 2026-03-01
```

The diff engine reads both SBOMs (CycloneDX or SPDX — both supported), indexes
packages by PURL, and reports what changed. An auditor sees the complete picture:
architectural changes + software supply chain changes + authorization changes.

---

## Walkthrough 3: Cross-Environment Comparison

*Dev and prod should match. Do they?*

Comparison is not limited to the same system at different times. You can compare
any two systems or environments:

```bash
# Are dev and prod running the same config?
hdf diff dev-results.json prod-results.json

  State       Count
  ─────       ─────
  unchanged    487
  updated       28    # Different input values (dev uses relaxed thresholds)
  regressed      5    # Prod has failures that dev doesn't
  new            3    # Dev has controls not yet deployed to prod

# Group by component to find where the drift is
hdf diff --group-by labels.component dev-results.json prod-results.json

  Component     Fixed   Regressed   Unchanged
  ─────────     ─────   ─────────   ─────────
  WebTier         0         3          245
  DatabaseTier    0         2          242
  APIGateway      0         0          (not in prod yet)
```

This answers: "Is production configured the same as what we tested in dev?" If not,
the comparison shows exactly where the drift is, grouped by whatever label dimension
matters to you.

---

## Walkthrough 4: Amendments (Waivers, Attestations, Overrides)

*Governance decisions about findings — applied as formal amendments to the record.*

### Why "amendments"?

The document type is called `hdf-amendments` (not hdf-attestation) because it covers
seven subtypes aligned with FedRAMP deviation request categories:

| Subtype | Meaning | Effect on status |
|---------|---------|-----------------|
| **attestation** | "I verified this manually" | Status → passed |
| **waiver** | "I accept this risk" | Status → passed (risk remains) |
| **falsePositive** | "Scanner incorrectly flagged this" | Status → passed or notApplicable |
| **riskAdjustment** | "Impact adjusted for context" | Impact score changed |
| **operationalRequirement** | "Deviation required by operations" | Open risk |
| **inherited** | "Control provided by another system" | Status reflects inherited posture |
| **poam** | "We'll fix this by date X" | Status unchanged (tracks work) |

Each entry amends the assessment record. The amendment chain (`previousChecksum`)
creates a tamper-evident linked list of modifications.

### Creating an amendment

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

### Applying amendments

```bash
# Merge amendments into scan results
hdf amend apply portal-scan.json portal-waivers.json -o merged.json

# The merged results have:
# - SV-257777: effectiveStatus changed from "failed" to "passed" (waiver applied)
# - statusOverrides[] populated with the waiver entry
# - Amendment chain intact: previousChecksum links back to original results

# Verify the chain
hdf amend verify merged.json
# ✓ Signature valid (AO: ao@agency.gov)
# ✓ Amendment chain intact (2 links verified)
# ⚠ 1 waiver expires in 107 days (SV-257777, 2026-06-30)
```

The chain of trust:
```
Original results  ──checksum──→  Waiver document  ──signature──→  Merged results
   (unsigned)           ↑            (signed by AO)                (verifiable)
                  previousChecksum
```

---

## Walkthrough 5: Baseline Evolution

*DISA publishes a new STIG version. What changed?*

```bash
hdf diff rhel9-stig-v1r1.json rhel9-stig-v1r2.json

Requirement changes (V1R1 → V1R2):
  + Added:   5 new requirements
      SV-260101: "RHEL 9 must implement FIPS-validated cryptography"
      SV-260102: "RHEL 9 must disable USB storage"
      ...
  - Removed: 2 deprecated requirements
      SV-230210: (superseded by SV-260101)
      SV-230211: (merged into SV-257777)
  ~ Modified: 8 requirements
      SV-257777: impact changed 0.5 → 0.7
      SV-258001: fix text updated
      ...

  Input changes:
      max_concurrent_sessions: default 3 → 2 (tightened)
      password_min_length: default 15 → 20 (tightened)
```

This answers: "What do I need to update in my system to comply with the new STIG?"
Without this, organizations manually diff PDF documents or XCCDF XML — error-prone
and not machine-readable.

---

## Walkthrough 6: Evidence Package

*Bundle everything for the auditor.*

```bash
hdf evidence build \
  --system portal-prod.hdf-system.json \
  --results portal-scan-merged.json \
  --amendments portal-waivers-q1.json \
  --comparison portal-diff-feb-mar.json \
  -o portal-ato-evidence-q1-2026.json
```

The evidence package is metadata — it references documents by URI + checksum,
not embedded content:

```json
{
  "name": "Enterprise Portal ATO Evidence - Q1 2026",
  "systemRef": "portal-prod.hdf-system.json",
  "preparedBy": { "type": "email", "identifier": "compliance@agency.gov" },
  "contents": [
    { "type": "hdf-system", "uri": "portal-prod.hdf-system.json",
      "checksum": { "algorithm": "sha256", "value": "aaa..." } },
    { "type": "hdf-results", "uri": "portal-scan-merged.json",
      "checksum": { "algorithm": "sha256", "value": "ddd..." } },
    { "type": "hdf-amendments", "uri": "portal-waivers-q1.json",
      "checksum": { "algorithm": "sha256", "value": "eee..." } },
    { "type": "hdf-comparison", "uri": "portal-diff-feb-mar.json",
      "checksum": { "algorithm": "sha256", "value": "fff..." } },
    { "type": "sbom", "uri": "webtier-sbom.cdx.json", "format": "cyclonedx",
      "checksum": { "algorithm": "sha256", "value": "ggg..." } }
  ],
  "completenessCheck": {
    "allBaselinesAssessed": true,
    "allComponentsCovered": true,
    "expiredWaivers": 0,
    "unresolvedPoams": 2,
    "compliancePercent": 95.8,
    "sbomCoverage": { "componentsWithSbom": 3, "totalComponents": 5 }
  },
  "signature": { "type": "Ed25519Signature2020", "signatureValue": "z4GH..." }
}
```

```bash
hdf evidence validate portal-ato-evidence-q1-2026.json
# ✓ All baselines assessed
# ✓ All components covered (5/5)
# ✓ No expired waivers
# ⚠ 2 unresolved POA&Ms
# ℹ SBOM coverage: 3 of 5 components (60%)
# Overall: 95.8% compliant

hdf evidence verify portal-ato-evidence-q1-2026.json
# ✓ All checksums match
# ✓ Amendment signatures valid
# ✓ Amendment chain intact (3 links)
# ✓ Package signature valid
```

---

## Walkthrough 7: The Typed Input Chain

*The most important innovation in HDF — tracing a value from governance to automation.*

This is the full chain for one value (`max_concurrent_sessions`):

```
STEP 1: GOVERNANCE SAYS "3"
──────────────────────────────
hdf-baseline (RHEL9-STIG):
  inputs: [{ name: "max_concurrent_sessions", type: "Numeric", value: 3 }]

    The STIG default says max 3 sessions. This is the governance intent.

STEP 2: SYSTEM TAILORS TO "5"
──────────────────────────────
hdf-system (Enterprise Portal):
  components[WebTier].inputOverrides: [{
    inputName: "max_concurrent_sessions",
    value: 5,
    justification: "Admin team needs 5 for shift handoff",
    approvedBy: { identifier: "issm@agency.gov" }
  }]

    The ISSM approved raising the limit to 5 for this specific system.

STEP 3: PLAN RESOLVES TO "5"
──────────────────────────────
hdf-plan (Portal Monthly Assessment):
  assessments[0].inputs: { max_concurrent_sessions: 5 }

    The plan takes the baseline default (3), applies the system override (5),
    and produces the final scanner configuration.

STEP 4: SCANNER FINDS "7"
──────────────────────────────
hdf-results (March 2026 scan):
  inputs: [{ name: "max_concurrent_sessions", value: 5 }]
  requirements[SV-257777].results[0]:
    status: "failed"
    message: "expected maxlogins <= 5, got 7"

    The scan was configured with 5 (correct). The system has 7 (violation).

STEP 5: DIFF DETECTS REGRESSION
──────────────────────────────
hdf-comparison (Feb → Mar):
  requirementDiffs[SV-257777]:
    state: "regressed"
    oldEffectiveStatus: "passed"
    newEffectiveStatus: "failed"

    Last month it was 5 (passing). This month it's 7 (failing). Regression.

STEP 6: WAIVER APPLIED
──────────────────────────────
hdf-amendments (Q1 Waivers):
  overrides[0]:
    type: "waiver"
    requirementId: "SV-257777"
    status: "passed"
    reason: "Compensating control: session timeout 15 min"
    expiresAt: "2026-06-30"
    signature: { creator: "ao@agency.gov", ... }

    The AO accepted the risk with a compensating control. Expires June 30.
```

Every step is typed, traceable, and auditable. An auditor can follow the chain:
- **Why 5?** Because the ISSM approved an override from the baseline default of 3.
- **Why failed?** Because the system has 7 sessions, exceeding the approved limit of 5.
- **Why passed after amendment?** Because the AO signed a waiver with a compensating control.
- **When does the waiver expire?** June 30, 2026.

No other format provides this complete chain. OSCAL defines the governance concepts
but not the scanner configuration link. InSpec defines the scanner parameters but not
the governance provenance.

---

## How It All Connects: The Cross-Reference Map

```
hdf-baseline ←──── hdf-plan (which baselines to run)
     │                │
     ▼                ▼
hdf-system ◄───── hdf-plan (which components to scan)
     │                │
     ▼                ▼
hdf-results ◄──── hdf-plan (provenance: what config produced these results)
     │
     ├──── hdf-amendments (merge: apply governance decisions to results)
     │
     ├──── hdf-comparison (diff: compare any two HDF docs of same type)
     │
     └──── hdf-evidence-package (bundle: package everything for audit)
```

**Data flows UP:** converters → results → comparison
**System context flows DOWN:** system → plan → results
**Governance flows SIDEWAYS:** amendments merge into results

---

## Progressive Enrichment

Not every organization has every piece. HDF works at every level of maturity:

| Level | What you have | What works |
|-------|-------------|------------|
| 0 | Bare converter output | Scan results, basic compliance % |
| 1 | + Labels on components | Group by system/component/team/region |
| 2 | + systemRef / planRef | Provenance chain — "this scan came from this plan" |
| 3 | + Typed inputs | Governance tracing — "why is the threshold 5?" |
| 4 | + sbomRef | Software supply chain — "what packages does this run?" |
| 5 | + Signatures | Non-repudiation — "the AO signed this waiver" |
| 6 | + Evidence package | Audit-ready — "here's everything, verified" |

A converter producing bare results with no labels works fine. A system doc with
no SBOMs works fine. An evidence package with partial coverage is informational,
not invalid. The schema never rejects a document for missing enrichment.

---

## Data Volume at Enterprise Scale

For a mid-size federal agency with ~500 systems under continuous monitoring:

| Metric | Value |
|--------|-------|
| Per system per month | ~1.5 MB raw / ~130 KB gzipped |
| Enterprise per month | ~750 MB raw / ~65 MB gzipped |
| Enterprise per year | ~9 GB raw / ~880 MB gzipped |
| Fleet comparison (500 systems) | ~200 MB raw / ~16 MB gzipped |
| Fleet comparison processing | ~5 seconds (parallelizable) |

For comparison: Heimdall2 stores ~2-5 GB/year for results only. eMASS stores
~10-50 GB/year including all documentation. HDF provides richer document types
at comparable storage costs, with 92% gzip compressibility.

---

## CLI Command Tree

```
hdf
├── validate <file>                  # Validate any HDF document
├── info <file>                      # Display summary
├── convert <from> to <to>           # Convert between formats (30+ converters)
│
├── diff <old> <new>                 # Compare any two HDF docs of same type
│   ├── --system <file>              # System-aware comparison
│   ├── --group-by <label>           # Group by any label
│   ├── --detailed-exitcode          # 0/1/2 basic, 10-14 detailed
│   └── --format json|md|table       # Output format
│   # Works on: results, systems, baselines, plans
│
├── system                           # System architecture
│   ├── info / validate              # Inspect or validate
│   └── discover --aws|--k8s         # Auto-discover from cloud
│
├── plan                             # Assessment planning
│   ├── create --system <file>       # Generate from system definition
│   └── run <file>                   # Execute the plan (run scans)
│
├── amend                            # Governance decisions
│   ├── create <results>             # Create waiver/attestation/override
│   ├── apply <results> <amendments> # Merge into results
│   ├── verify <file>                # Verify signatures + chain
│   └── list <file>                  # List active/expired
│
└── evidence                         # Audit evidence
    ├── build --system --results     # Package everything
    ├── validate / verify            # Check completeness + integrity
    └── export --format oscal        # Export to OSCAL
```

---

## OSCAL Alignment

HDF documents map to OSCAL document types:

| HDF Document | OSCAL Equivalent | Direction |
|-------------|-----------------|-----------|
| hdf-baseline | Catalog + Profile | Convert from OSCAL |
| hdf-results | Assessment Results (AR) | Bidirectional |
| hdf-system | SSP system-characteristics | Bidirectional |
| hdf-plan | Assessment Plan (SAP) | Bidirectional |
| hdf-amendments | POA&M risk-response | Bidirectional |
| hdf-comparison | *(HDF original)* | Export summaries |
| hdf-evidence | AR + POA&M bundle | Export to OSCAL |

OSCAL converters are special — they produce **multiple HDF document types**, not
just results. An OSCAL SSP produces an hdf-system. An OSCAL POA&M produces
hdf-amendments. This is why the HDF ecosystem matters.

---

## What HDF Does NOT Define

HDF focuses on assessment data. It builds converters TO/FROM other standards,
not competing schemas:

- **SBOM** — defer to CycloneDX/SPDX (reference by URI via `sbomRef`)
- **Policy** — belongs in GRC platforms (Archer, ServiceNow GRC)
- **Remediation** — Ansible/Terraform have their own formats
- **VEX/Advisories** — defer to CSAF/OpenVEX
- **Incident response** — STIX/TAXII, TheHive, MISP
- **Trending** — query-time aggregation of comparison documents
- **Alerts** — integration concern (webhooks, PagerDuty, Slack)

---

## Implementation Status

> As of 2026-04-02. See `docs/plans/2026-03-14-hdf-ecosystem-plan.md` for the
> full implementation plan with beads card references.

| What | Status |
|------|--------|
| hdf-baseline schema | Complete |
| hdf-results schema | Complete |
| hdf-comparison schema | Complete |
| hdf-system schema | Complete |
| hdf-plan schema | Complete |
| hdf-amendments schema | Complete |
| hdf-evidence-package schema | Complete |
| Phase 0: typed inputs, labels, rename, refs | Complete |
| Phase 1: hdf-system | Complete |
| Phase 2: hdf-plan | Complete |
| Phase 3: hdf-amendments | Complete |
| Phase 4: hdf-evidence-package | Complete |
| hdf-diff TS library | Complete (380 tests, 100% coverage) |
| hdf-diff Go library | Complete (500+ tests, 98.4% coverage) |
| `hdf diff` CLI command | Complete (exit codes 0/1/2 + 10-14) |
| Validators + CLI for all 7 types | Complete |
| Phase 5: ecosystem integration | In progress |
| System-level comparison | Ready (unblocked) |
| Baseline comparison | Ready (unblocked) |
| SBOM comparison | Ready (unblocked) |

---

## Key Documents

| Document | What it covers |
|----------|---------------|
| [Architecture](hdf-document-ecosystem.md) | Full ecosystem vision, all 7 types, JSON examples |
| Design decisions | (archived) — 12 design decisions with research rationale |
| [Developer Guide](../design/developer-guide.md) | Contributor patterns, dual impl, testing |
| [Implementation Plan](../plans/2026-03-14-hdf-ecosystem-plan.md) | Phase-by-phase plan with beads cards |
| SBOM Research | (archived) — CycloneDX/SPDX library landscape |
