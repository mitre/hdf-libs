# HDF v2 Document Ecosystem Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan.

**Goal:** Complete the HDF v2 document ecosystem — 7 document types covering the full
security assessment lifecycle, with typed inputs, labels, chain of trust, and OSCAL alignment.

**Architecture:** See `docs/architecture/hdf-v2-document-ecosystem.md` for full vision,
lifecycle diagrams, example JSON, CLI command tree, Heimdall integration, and design rationale.

**Key Design Decisions:** (see `docs/design/decisions.md` for full rationale)
- Labels over hierarchies (D1)
- Typed inputs bridging governance to automation (D5)
- Separate document types following OSCAL SSP/AR pattern (D6)
- Chain of trust via existing integrity primitives
- `attributes` → `inputs` rename (InSpec v3→v5 normalization)
- All document types: dual TS + Go implementation from day one (D8)
- Progressive enrichment — no optional field gates functionality (D9)
- Renamed hdf-attestation → **hdf-amendments** (D10)
- Generic comparison — hdf-comparison diffs any HDF doc type (D11)
- SBOM: both CycloneDX + SPDX from day one, adopt protobom (Go) (D12)

**Cards:** Epic `hdf-libs-15kg` with phase cards linked below.

---

## Implementation Status

> **Update this table as phases complete.**

| Phase | Card | Status | Notes |
|-------|------|--------|-------|
| 0.1 Typed inputs | hdf-libs-hlvt | NOT STARTED | Unblocked, start here |
| 0.2 Labels | hdf-libs-pdf7 | NOT STARTED | Unblocked (parallel with 0.1) |
| 0.3 Rename attributes→inputs | hdf-libs-fjfe | NOT STARTED | Blocked on 0.1 |
| 0.4 Cross-references | hdf-libs-5ef5 | NOT STARTED | Unblocked |
| 1 hdf-system | hdf-libs-b4lj | NOT STARTED | Blocked on 0.1 + 0.2 |
| 2 hdf-plan | hdf-libs-5sgt | NOT STARTED | Blocked on Phase 1 |
| 3 hdf-amendments | hdf-libs-3qm7 | NOT STARTED | Blocked on 0.1 |
| 4 hdf-evidence-package | hdf-libs-3cjk | NOT STARTED | Blocked on 1 + 2 + 3 |
| 5 Ecosystem integration | hdf-libs-qcj7 | NOT STARTED | Incremental after each phase |
| — System-level comparison | hdf-libs-tvcs | NOT STARTED | Blocked on Phase 1 |
| — Baseline comparison | hdf-libs-gz0p | NOT STARTED | Blocked on Phase 0.1 |
| — SBOM comparison | hdf-libs-a96 | NOT STARTED | Blocked on Phase 1 |
| — Converter v2 alignment | hdf-libs-ccp0 | NOT STARTED | Blocked on all Phase 0 |

**Already complete:**
- hdf-comparison schema (exists)
- hdf-diff TS library (380 tests, 100% coverage)
- hdf-diff Go library (500+ tests, 98.4% coverage)
- hdf diff CLI command (exit codes 0/1/2 + 10-14)
- v2 architecture doc, decisions doc, developer guide

---

## Phase 0: Foundation (v2 schema refinements)

**Card:** `hdf-libs-hlvt` (typed inputs), `hdf-libs-pdf7` (labels), `hdf-libs-fjfe` (rename), `hdf-libs-5ef5` (refs)

### 0.1 Add typed Input primitive

**Card:** `hdf-libs-hlvt`

Create `primitives/parameter.schema.json` with `Input` type definition.

**Architecture reference:** See `docs/architecture/hdf-v2-document-ecosystem.md` section
"Typed Inputs — Bridging Governance and Automation" for the full rationale and the
input chain diagram showing how values flow from baseline → system → plan → results → comparison.

Fields:
- `name` (string, required) — matches InSpec input name
- `type` (enum: String, Numeric, Boolean, Array, Hash, Regexp) — matches InSpec input types
- `value` (any, matching type) — the default or resolved value
- `description` (string) — human-readable purpose
- `required` (boolean) — whether the input must be provided
- `sensitive` (boolean) — whether the value should be masked in output
- `operator` (enum: eq, ne, lt, le, gt, ge, contains, matches, in, notIn) — comparison operator for validation
- `constraints` (object) — min, max, pattern, allowedValues

Implementation:
1. Create `hdf-schema/src/schemas/primitives/parameter.schema.json` with `$defs/Input`
2. Write 10+ validation tests
3. Add to type generation pipeline (TS/Go/Python)
4. Reference from hdf-baseline `inputs[]` and hdf-results `inputs[]`

### 0.2 Add labels to targets and baselines

**Card:** `hdf-libs-pdf7`

**Architecture reference:** See `docs/architecture/hdf-v2-document-ecosystem.md` section
"Labels — Flexible Grouping Without Hierarchy" for design rationale, well-known keys table,
and label selector pattern used by hdf-system components.

Add `labels: Record<string, string>` to:
- `Base_Target` in `primitives/target.schema.json`
- `Baseline_Metadata` in `primitives/common.schema.json`

Implementation:
1. Add `labels` property to both schemas
2. Write tests verifying labels are optional, accept string values, reject non-string values
3. Regenerate types
4. Document well-known label keys as convention (not enforced in schema)

### 0.3 Rename attributes to inputs in hdf-results

**Card:** `hdf-libs-fjfe`

**Rationale:** InSpec renamed "attributes" to "inputs" in v4/v5. The old name was ambiguous.
Both hdf-baseline and hdf-results should use `inputs` consistently. Since v2 is not released,
this is a free rename with no backward compatibility concern.

Implementation:
1. Rename field in `hdf-results.schema.json` (Evaluated_Baseline)
2. Use typed Input primitive for `inputs[]` items
3. Update all TS/Go/Python generated types
4. Update hdf-diff (TS + Go) — field name in before/after snapshots
5. Update hdf-cli commands that read attributes
6. Update all converters that produce `attributes`
7. Update all tests

### 0.4 Add document cross-references to hdf-results

**Card:** `hdf-libs-5ef5`

Add optional fields to HdfResults:
- `systemRef: string` (URI to hdf-system document)
- `planRef: string` (URI to hdf-plan document)

These create the provenance chain: "this scan was planned by X for system Y."

---

## Phase 1: hdf-system

**Card:** `hdf-libs-b4lj`

**Architecture reference:** See `docs/architecture/hdf-v2-document-ecosystem.md` section
"Phase 2: DESCRIBE — hdf-system" for full example JSON showing components with label
selectors and input overrides. See "Labels" section for targetSelector design.

### 1.1 Design primitives/system.schema.json

$defs:
- `Authorization_Status` enum — authorized, denied, pending, revoked, conditionallyAuthorized, underReview
- `Categorization_Level` enum — low, moderate, high (FIPS 199)
- `Component_Type` enum — application, database, network, infrastructure, service, policy, operatingSystem, container, cloudService, other
- `System` — name (required), identifier, identifierScheme, description, authorizationStatus, authorizationDate, categorizationLevel, boundaryDescription, components[], targetRefs[], interconnections[], extensions
- `Component` — name (required), type (required), description, targetSelector (label-based matching), baselineRefs[], inputOverrides[], sbomRef (optional URI to CycloneDX/SPDX), sbomFormat (optional: "cyclonedx" | "spdx"), extensions
- `InputOverride` — baselineRef, inputName, value, justification, approvedBy (Identity), approvedAt
- `Interconnection` — name, direction (inbound/outbound/bidirectional), description, systemRef

**Key design point:** Components use `targetSelector` (label-based matching like Kubernetes)
not hardcoded target name lists. This means adding a new server with the right labels
automatically includes it in the component — no system doc update needed.

### 1.2 Design hdf-system.schema.json

Top-level document. Required: `name`. Optional: everything else.
`$ref` to system primitives, common primitives (Identity, Checksum), target primitives.

### 1.3 Tests

30+ validation tests: minimal valid document, required fields, enum validation,
component structure, input overrides, interconnections, label selectors.

### 1.4 Type generation

Add hdf-system to TS/Go/Python type generation pipeline.
Both TS and Go types must be generated — dual implementation from day one.

### 1.5 CLI: hdf system commands (TS + Go)

- `hdf system info <file>` — display system architecture (components, targets, baselines)
- `hdf system validate <file>` — validate against schema

### 1.6 Integration with hdf-diff

- `hdf diff --system <file>` flag for system-aware comparison
- `hdf diff --group-by labels.<key>` for label-based grouping
- Component-level summary in comparison output (per-component compliance %)

---

## Phase 2: hdf-plan

**Card:** `hdf-libs-5sgt`

**Architecture reference:** See `docs/architecture/hdf-v2-document-ecosystem.md` section
"Phase 3: PLAN — hdf-plan" for example JSON showing how inputs are resolved from
baseline defaults + system overrides into final scanner parameters.

### 2.1 Design primitives/plan.schema.json

$defs:
- `Assessment` — baselineRef, targetSelector (label-based), inputs (resolved values), runner (name, version, containerImage)
- `Schedule` — cron, notifyOnRegression (email list), frequency
- `PlanType` enum — automated, manual, hybrid

The plan resolves the input chain:
1. Start with baseline default values (from hdf-baseline inputs[])
2. Apply system overrides (from hdf-system component inputOverrides[])
3. Result: the final scanner parameters (in hdf-plan assessment inputs)

### 2.2 Design hdf-plan.schema.json

Top-level: name (required), type, systemRef, assessments[] (required), schedule.
References hdf-baseline (which baselines to run), hdf-system (which targets to scan).

### 2.3 Tests

20+ validation tests.

### 2.4 Type generation (TS + Go)

### 2.5 CLI: hdf plan commands

- `hdf plan create --system <file>` — generate plan from system definition (auto-discovers baselines per component)
- `hdf plan validate <file>` — validate plan against system (all components covered? all baselines referenced?)
- `hdf plan run <file>` — execute the plan (future — requires scanner runner integration)

---

## Phase 3: hdf-amendments

**Card:** `hdf-libs-3qm7`

**Architecture reference:** See `docs/architecture/hdf-v2-document-ecosystem.md` sections
"Phase 6: GOVERN — hdf-amendments", "Chain of Trust", and "Attestation vs Waiver vs Exception"
for full design including signed waivers, amendment chains, and the merge operation.

### 3.1 Design primitives/amendments.schema.json

$defs:
- `Override_Type` enum — waiver, attestation, exception, poam (conceptually distinct, same structure)
- `Standalone_Override` — extends existing StatusOverride primitive with:
  - `requirementId` (which requirement this applies to)
  - `baselineRef` (which baseline)
  - `signature` (Signature — reuses existing primitive)
  - `previousChecksum` (Checksum — amendment chain link)

Reuses ALL existing primitives: Identity, Signature, Evidence, Checksum.
The standalone document wraps the same StatusOverride/POAM types that already exist inline
in hdf-results, but as a first-class signed document.

### 3.2 Design hdf-amendments.schema.json

Top-level: name (required), systemRef, appliedBy (Identity), approvedBy (Identity),
overrides[] (required), integrity (Integrity).

### 3.3 Tests

25+ validation tests including signature verification, amendment chain, expiration.

### 3.4 Type generation (TS + Go)

### 3.5 CLI: hdf amend commands

- `hdf amend create <results-file>` — interactively create waiver/attestation for failing controls
- `hdf amend apply <results> <amendments> -o <merged>` — merge amendments into results
- `hdf amend verify <file>` — verify digital signatures and amendment chain integrity
- `hdf amend list <file>` — list active/expired overrides with expiration dates

### 3.6 Merge operation

Implemented in hdf-utilities (TS) and pkg/diff or pkg/amend (Go).

The merge operation:
1. Load results document
2. Load amendments document
3. For each override in amendments document, apply to matching requirement in results
4. Set `effectiveStatus` based on the override
5. Add override to `statusOverrides[]` array
6. Compute `previousChecksum` linking to the pre-merge results checksum
7. Write merged results document

The amendment chain:
```
Original results (checksum A) → Attestation (previousChecksum: A) → Merged results (checksum B)
                                                                      ↑
                                                              Amendment chain verifiable
```

---

## Phase 4: hdf-evidence-package

**Card:** `hdf-libs-3cjk`

**Architecture reference:** See `docs/architecture/hdf-v2-document-ecosystem.md` section
"Phase 7: PROVE — hdf-evidence-package" for full example JSON and CLI usage.

### 4.1 Design hdf-evidence-package.schema.json

Top-level: name (required), systemRef, preparedBy (Identity), preparedAt (datetime),
contents[] (required), completenessCheck, signature (Signature).

Contents array: each entry is `{ type, label, uri, checksum }` referencing another HDF document.

CompletenessCheck: `{ allBaselinesAssessed, allComponentsCovered, expiredWaivers, unresolvedPoams, compliancePercent }`

### 4.2 Tests

20+ validation tests.

### 4.3 Type generation (TS + Go)

### 4.4 CLI: hdf evidence commands

- `hdf evidence build --system <file> --results <file> [--amendments <file>] [--comparison <file>] -o <package>` — bundle documents
- `hdf evidence validate <package>` — check completeness (all baselines assessed? all components covered?)
- `hdf evidence verify <package>` — verify all checksums + signatures in the chain
- `hdf evidence export --format oscal <package>` — export to OSCAL SAR + POA&M

---

## Phase 5: Ecosystem integration

**Card:** `hdf-libs-qcj7`

### 5.1 Converter label support

Update high-value converters to populate labels from source tool metadata.
Zero breaking changes — labels are additive and optional.

| Converter | Labels | Source of data |
|-----------|--------|---------------|
| aws-config | labels.account, labels.region, labels.service | AWS resource ARN |
| nessus | labels.hostgroup, labels.network | Nessus host properties |
| InSpec | typed inputs on baselines | inspec.yml inputs section |
| k8s-bench | labels.cluster, labels.namespace | K8s metadata |
| grype/trivy | labels.image, labels.registry | Container image ref |
| OSCAL AR | systemRef | OSCAL import-ssp reference |

### 5.2 OSCAL converters (bidirectional)

OSCAL converters produce multiple HDF document types. Each maps to a specific schema:

| OSCAL Source | HDF Output | Card |
|-------------|-----------|------|
| System Security Plan (SSP) | **hdf-system** | hdf-libs-eey (updated 2026-03-15) |
| Assessment Results (SAR) | hdf-results (with labels + systemRef) | hdf-libs-vwv |
| POA&M | **hdf-amendments** | hdf-libs-1vb (updated 2026-03-15) |
| Assessment Plan (SAP) | **hdf-plan** | hdf-libs-uej (updated 2026-03-15) |
| Catalog | hdf-baseline | hdf-libs-y03 |
| Profile | hdf-baseline | hdf-libs-g3i |

Reverse converters (HDF → OSCAL) also needed for export from Heimdall.

### 5.3 hdf-diff enhancements — generic comparison

**Card:** (new cards for system-level and baseline comparison)

Extend hdf-comparison to support any HDF document type:

- `systemDrift` mode: compare two hdf-system documents (componentDiffs[], SBOM diffs)
- `baselineEvolution` mode: compare two hdf-baseline documents (requirementChanges[])
- Add `systemRef` field to hdf-comparison schema
- Add `componentDiffs[]`, `packageDiffs[]`, `requirementChanges[]` optional sections
- Cross-environment comparison: dev vs prod, pre/post migration

SBOM comparison (sub-feature of systemDrift):
- Adopt `protobom` (Go) for unified CycloneDX + SPDX parsing with built-in diff
- Build custom TS parser normalizing both formats into common model via `packageurl-js`
- Both CycloneDX and SPDX supported from day one
- Full research: `docs/reviews/2026-03-15-sbom-library-research.md`

Existing enhancements (already planned):
- `--system <file>` — system-aware fleet comparison with component-level summary
- `--group-by labels.<key>` — group results by any label dimension
- Parameter drift detection — detect when expected values change between scans
- Component-level compliance percentage in comparison output

### 5.4 Converter v2 alignment audit

**Card:** `hdf-libs-ccp0`

Systematic review and update of ALL converters for v2 schema changes:
- `attributes` → `inputs` rename in every converter
- Populate progressive enrichment fields where source data exists
- Update OSCAL converter output types (SSP→hdf-system, POA&M→hdf-amendments, SAP→hdf-plan)
- Blocked on Phase 0 completion (schemas must exist first)

### 5.5 Documentation

- HDF v2 specification document (formal)
- Well-known label keys reference
- OSCAL alignment guide
- Migration guide from v1 (for tool authors)
- hdf-plan input resolution guide (baseline → system → plan → results chain)

---

## Implementation Pattern

**CRITICAL: Every phase follows this pattern for EACH document type:**

1. Design JSON Schema (primitives + top-level) — TDD with schema validation tests
2. Generate types (TS + Go + Python) — both languages from day one
3. Write TS library code — TDD, 95%+ coverage
4. Write Go library code — TDD, 95%+ coverage, side-by-side with TS
5. Write CLI commands (Go) — following existing cobra patterns
6. Differential testing — verify TS and Go produce identical output
7. Code review — security, DRY, maintainability, standards

Do NOT build TS first and Go later. Build both simultaneously to avoid the
parity gap that happened with hdf-diff (learned the hard way).

---

## Dependency Order

```
Phase 0 (foundation) — must be first
  ├── Phase 0.1 (typed inputs) ← START HERE, no blockers
  ├── Phase 0.2 (labels) ← depends on 0.1
  ├── Phase 0.3 (rename) ← depends on 0.1
  └── Phase 0.4 (refs) ← independent

Phase 0 complete
  ├── Phase 1 (hdf-system) ← depends on 0.1 + 0.2
  ├── Phase 3 (hdf-amendments) ← depends on 0.1 only (can parallel with Phase 1)
  ├── Baseline comparison ← depends on Phase 0 only
  └── Converter v2 alignment (hdf-libs-ccp0) ← depends on all Phase 0

Phase 1 complete
  ├── Phase 2 (hdf-plan) ← depends on Phase 1
  └── System-level comparison + SBOM diff ← depends on Phase 1

Phases 1 + 2 + 3 complete
  └── Phase 4 (hdf-evidence-package) ← depends on all three

All phases complete
  └── Phase 5 (ecosystem integration) ← can begin incrementally after each phase
       ├── OSCAL converters (need target schemas to exist)
       ├── Converter v2 alignment audit
       └── Documentation
```

Phases 1 and 3 can be parallelized (different document types, no shared code).
Phase 5 subtasks can begin as soon as their dependency is complete (e.g., converter
labels can start after Phase 0.2). System-level comparison and SBOM diff require
hdf-system to exist first. OSCAL converters require their target schemas to exist.
