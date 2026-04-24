# HDF Document Ecosystem Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan.

**Goal:** Complete the HDF document ecosystem — 7 document types covering the full
security assessment lifecycle, with typed inputs, labels, chain of trust, and OSCAL alignment.

**Architecture:** See `docs/architecture/hdf-document-ecosystem.md` for full vision,
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

> **Last updated: 2026-03-17**

| Phase | Card | Status | Notes |
|-------|------|--------|-------|
| 0.1 Typed inputs | hdf-libs-hlvt | ✅ COMPLETE | parameter.schema.json — Input, Input_Type, Comparison_Operator, Input_Constraints. 26 tests. |
| 0.2 Labels | hdf-libs-pdf7 | ✅ COMPLETE | labels: Record<string, string> on Base_Component + Baseline_Metadata. 16 tests. |
| 0.3 Rename attributes→inputs | hdf-libs-fjfe | ✅ COMPLETE | hdf-results uses `inputs[]` consistently. |
| 0.4 Cross-references | hdf-libs-5ef5 | ✅ COMPLETE | systemRef + planRef added to hdf-results. |
| 1 hdf-system | hdf-libs-b4lj | ✅ COMPLETE | system.schema.json + hdf-system.schema.json — Component, InputOverride, Data_Flow, TargetSelector, 3 enums. 34 tests. |
| 2 hdf-plan | hdf-libs-5sgt | ✅ COMPLETE | plan.schema.json + hdf-plan.schema.json — Assessment, Schedule, RunnerConfig, PlanType enum. 24 tests. |
| 3 hdf-amendments | hdf-libs-3qm7 | ✅ COMPLETE | amendments.schema.json + hdf-amendments.schema.json — StandaloneOverride, OverrideType enum (waiver/attestation/exception/poam). 26 tests. |
| 4 hdf-evidence-package | hdf-libs-3cjk | ✅ COMPLETE | hdf-evidence-package.schema.json — ContentReference, CompletenessCheck, SBOMCoverage, ContentType enum. 24 tests. |
| — Validators + CLI | — | ✅ COMPLETE | All 7 types validated via hdf-validators (TS + Go) and `hdf validate --type`. |
| 5 Ecosystem integration | hdf-libs-qcj7 | READY | All schema phases complete. Unblocked. |
| — System-level comparison | hdf-libs-tvcs | READY | Unblocked (hdf-system exists). |
| — Baseline comparison | hdf-libs-gz0p | READY | Unblocked (Input primitive exists). |
| — SBOM comparison | hdf-libs-a96 | READY | Unblocked (hdf-system exists). |
| — Converter v2 alignment | hdf-libs-ccp0 | READY | All Phase 0 deps closed. |

**Complete (pre-v2 schemas):**
- hdf-baseline + hdf-results schemas (original)
- hdf-comparison schema + hdf-diff TS/Go libraries (380+ / 500+ tests)
- hdf diff CLI command (exit codes 0/1/2 + 10-14)
- v2 architecture doc, decisions doc (12 decisions), developer guide

**Complete (v2 schemas, 2026-03-17):**
- All 7 document type schemas implemented with full type generation (TS/Go/Python)
- 12 primitive schemas (common, target, parameter, system, plan, amendments, comparison, extensions, platform, result, runner, statistics)
- 150 new schema validation tests across 6 test files
- hdf-validators updated for all types (TS + Go)
- CLI `hdf validate --type` supports all 7 types
- Go enum renames handled across 23 converter/parser files

---

## Phase 0: Foundation (schema refinements)

**Card:** `hdf-libs-hlvt` (typed inputs), `hdf-libs-pdf7` (labels), `hdf-libs-fjfe` (rename), `hdf-libs-5ef5` (refs)

### 0.1 Add typed Input primitive

**Card:** `hdf-libs-hlvt`

Create `primitives/parameter.schema.json` with `Input` type definition.

**Architecture reference:** See `docs/architecture/hdf-document-ecosystem.md` section
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

### 0.2 Add labels to components and baselines

**Card:** `hdf-libs-pdf7`

**Architecture reference:** See `docs/architecture/hdf-document-ecosystem.md` section
"Labels — Flexible Grouping Without Hierarchy" for design rationale, well-known keys table,
and label selector pattern used by hdf-system components.

Add `labels: Record<string, string>` to:
- `Base_Component` in `primitives/component.schema.json`
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

**Architecture reference:** See `docs/architecture/hdf-document-ecosystem.md` section
"Phase 2: DESCRIBE — hdf-system" for full example JSON showing components with label
selectors and input overrides. See "Labels" section for targetSelector design.

### 1.1 Design primitives/system.schema.json

$defs:
- `Authorization_Status` enum — authorized, denied, pending, revoked, conditionallyAuthorized, underReview
- `Categorization_Level` enum — low, moderate, high (FIPS 199)
- Component types come from the `Copyright` type — host, containerImage, containerInstance, containerPlatform, cloudAccount, cloudResource, repository, application, artifact, network, database
- `System` — name (required), identifier, identifierScheme, description, authorizationStatus, authorizationDate, categorizationLevel, boundaryDescription, components[], dataFlows[], controlDesignations[], extensions
- `Component` — name (required), type (from Copyright enum), description, componentId (UUID), targetSelector (label-based matching), baselineRefs[], inputOverrides[], sbomRef (optional URI to CycloneDX/SPDX), sbomFormat (optional: "cyclonedx" | "spdx"), extensions
- `InputOverride` — baselineRef, inputName, value, justification, approvedBy (Identity), approvedAt
- `Data_Flow` — from (UUID), to (UUID or external endpoint), protocol, port, direction (inbound/outbound/bidirectional), description

**Key design point:** Components use `targetSelector` (label-based matching like Kubernetes)
not hardcoded target name lists. This means adding a new server with the right labels
automatically includes it in the component — no system doc update needed.

### 1.2 Design hdf-system.schema.json

Top-level document. Required: `name`. Optional: everything else.
`$ref` to system primitives, common primitives (Identity, Checksum), target primitives.

### 1.3 Tests

30+ validation tests: minimal valid document, required fields, enum validation,
component structure, input overrides, dataFlows, label selectors.

### 1.4 Type generation

Add hdf-system to TS/Go/Python type generation pipeline.
Both TS and Go types must be generated — dual implementation from day one.

### 1.5 CLI: hdf system commands (TS + Go)

- `hdf system info <file>` — display system architecture (components, baselines)
- `hdf system validate <file>` — validate against schema

### 1.6 Integration with hdf-diff

- `hdf diff --system <file>` flag for system-aware comparison
- `hdf diff --group-by labels.<key>` for label-based grouping
- Component-level summary in comparison output (per-component compliance %)

---

## Phase 2: hdf-plan

**Card:** `hdf-libs-5sgt`

**Architecture reference:** See `docs/architecture/hdf-document-ecosystem.md` section
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
References hdf-baseline (which baselines to run), hdf-system (which components to scan).

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

**Architecture reference:** See `docs/architecture/hdf-document-ecosystem.md` sections
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

**Architecture reference:** See `docs/architecture/hdf-document-ecosystem.md` section
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
| aws-config | labels.account, labels.region | AWS resource ARN |
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

- HDF specification document (formal)
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
Phase 0 (foundation) ✅ COMPLETE
  ├── Phase 0.1 (typed inputs) ✅
  ├── Phase 0.2 (labels) ✅
  ├── Phase 0.3 (rename) ✅
  └── Phase 0.4 (refs) ✅

Phases 1–4 (schemas) ✅ COMPLETE
  ├── Phase 1 (hdf-system) ✅
  ├── Phase 2 (hdf-plan) ✅
  ├── Phase 3 (hdf-amendments) ✅
  └── Phase 4 (hdf-evidence-package) ✅

Phase 5 (ecosystem integration) ← CURRENT FOCUS
  All schema dependencies are satisfied. Work can proceed on all fronts:
  ├── Converter v2 alignment audit (hdf-libs-ccp0) ← READY
  ├── OSCAL bidirectional converters (SSP↔system, SAP↔plan, POA&M↔amendments)
  ├── Converter label population (aws-config, nessus, k8s, grype/trivy)
  ├── hdf-diff enhancements (systemDrift, baselineEvolution, SBOM diff)
  ├── CLI commands for new doc types (hdf system, hdf plan, hdf amend, hdf evidence)
  └── Documentation (v2 spec, migration guide, OSCAL alignment guide)
```

Phase 5 subtasks are independent and can be parallelized. The converter v2
alignment audit (ccp0) is the broadest task — it touches all 30+ converters.
OSCAL converters that produce new document types (SSP→hdf-system,
SAP→hdf-plan, POA&M→hdf-amendments) can be updated incrementally.
