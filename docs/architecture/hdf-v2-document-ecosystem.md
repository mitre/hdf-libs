# HDF v2 Document Type Ecosystem

## Overview

HDF (Heimdall Data Format) v2 defines 7 document types that together cover the full
security assessment lifecycle: define requirements, describe systems, plan assessments,
execute scans, analyze changes, govern risk, and prove compliance.

## Document Types

| # | Document | Schema | Purpose |
|---|----------|--------|---------|
| 1 | hdf-baseline | `hdf-baseline.schema.json` | Security requirements (what to check) |
| 2 | hdf-results | `hdf-results.schema.json` | Assessment findings (what happened) |
| 3 | hdf-comparison | `hdf-comparison.schema.json` | Structured diff (what changed) |
| 4 | hdf-system | `hdf-system.schema.json` | System architecture & boundary (what is it) |
| 5 | hdf-plan | `hdf-plan.schema.json` | Assessment plan / scan config (how to assess) |
| 6 | hdf-attestation | `hdf-attestation.schema.json` | Waivers, risk acceptance, manual verification |
| 7 | hdf-evidence-package | `hdf-evidence-package.schema.json` | Verifiable audit bundle |

## Lifecycle Flow

```
DEFINE          DESCRIBE        PLAN            EXECUTE
hdf-baseline -> hdf-system   -> hdf-plan     -> hdf-results
"what to        "what is the    "how to          "what
 check"          system"         assess it"       happened"

ANALYZE         GOVERN          PROVE
hdf-comparison  hdf-attestation hdf-evidence-package
"what changed"  "risk accepted" "audit-ready bundle"
```

## Cross-Reference Map

| Document | References | Referenced By |
|----------|-----------|---------------|
| hdf-baseline | Framework mappings (CCI, NIST) | hdf-system, hdf-plan, hdf-results |
| hdf-system | hdf-baseline (component→baseline mapping) | hdf-plan, hdf-results, hdf-comparison, hdf-evidence |
| hdf-plan | hdf-baseline, hdf-system | hdf-results (provenance) |
| hdf-results | hdf-baseline, targets, systemRef, planRef | hdf-comparison, hdf-attestation, hdf-evidence |
| hdf-comparison | hdf-results (source checksums) | hdf-evidence |
| hdf-attestation | hdf-baseline (requirements), hdf-system | hdf-results (merge), hdf-evidence |
| hdf-evidence | All other types (bundled) | Auditors, authorization officials |

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
    ├── common.schema.json             (exists — Identity, Checksum, Signature, Evidence, etc.)
    ├── result.schema.json             (exists — ResultStatus, RequirementResult, etc.)
    ├── target.schema.json             (exists — 11 target types, adding labels)
    ├── extensions.schema.json         (exists — StatusOverride, POAM, Generator, etc.)
    ├── comparison.schema.json         (exists — RequirementDiff, Source, etc.)
    ├── system.schema.json             (new — System, Component, AuthorizationStatus, etc.)
    ├── plan.schema.json               (new — Assessment, Schedule, etc.)
    ├── attestation.schema.json        (new — Override types with signature support)
    ├── parameter.schema.json          (new — Input/Parameter type definitions)
    ├── platform.schema.json           (exists)
    ├── runner.schema.json             (exists)
    └── statistics.schema.json         (exists)
```

## Shared Primitives

These existing primitives are reused across document types:
- **Identity** — who performed an action (email, username, system)
- **Checksum** — SHA-256/384/512 integrity verification
- **Signature** — digital signatures (JWK, PEM, Ed25519, PKCS#11)
- **Evidence** — supporting artifacts (screenshots, logs, URLs)
- **Target** — assessed entities (11 polymorphic types)

New shared primitives for v2:
- **Input** — typed parameter definition (name, type, value, operator, constraints)
- **Label** — key-value metadata on targets and baselines

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

5. **Typed inputs** — Parameter definitions carry type information (Numeric, String,
   Boolean, Array) enabling automated validation of expected vs observed values.

6. **Backward compatible** — All new fields are optional. Documents without labels,
   systemRef, or typed inputs remain valid. Converters need zero changes.

7. **DRY with $ref** — All document types share primitives via JSON Schema $ref.
   Types defined once in primitives, referenced everywhere.

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

## What HDF Does NOT Define

- **Policy documents** — prose, belongs in GRC platforms
- **Remediation playbooks** — Ansible/Terraform have their own formats
- **SBOM** — defer to CycloneDX/SPDX, reference by URI
- **VEX/Advisories** — defer to CSAF/OpenVEX
- **Trending/time-series** — query-time aggregation of comparisons
- **Alerts** — integration concern (webhooks, PagerDuty)

HDF builds converters TO/FROM OSCAL, not competing schemas.

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
