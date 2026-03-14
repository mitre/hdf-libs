# HDF v2 Document Ecosystem Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan.

**Goal:** Complete the HDF v2 document ecosystem — 7 document types covering the full
security assessment lifecycle, with typed inputs, labels, chain of trust, and OSCAL alignment.

**Architecture:** See `docs/architecture/hdf-v2-document-ecosystem.md`

---

## Phase 0: Foundation (v2 schema refinements)

### 0.1 Add typed Input primitive
Create `primitives/parameter.schema.json` with `Input` type:
- name (string, required)
- type (enum: String, Numeric, Boolean, Array, Hash, Regexp)
- value (any, matching type)
- description (string)
- required (boolean)
- sensitive (boolean)
- operator (enum: eq, ne, lt, le, gt, ge, contains, matches, in, notIn)
- constraints (min, max, pattern, allowedValues)

### 0.2 Add labels to targets and baselines
Add `labels: Record<string, string>` to:
- `Base_Target` in `primitives/target.schema.json`
- `Baseline_Metadata` in `primitives/common.schema.json`

### 0.3 Rename attributes to inputs in hdf-results
Rename `Evaluated_Baseline.attributes` to `Evaluated_Baseline.inputs`
Use typed Input primitive for the array items.

### 0.4 Add document cross-references to hdf-results
Add optional fields to HdfResults:
- `systemRef: string` (URI to hdf-system)
- `planRef: string` (URI to hdf-plan)

### 0.5 Type generation + test updates
Regenerate TS/Go/Python types. Update all tests for renamed field.
Update hdf-diff and hdf-cli for the rename.

---

## Phase 1: hdf-system

### 1.1 Design primitives/system.schema.json
$defs:
- Authorization_Status enum (authorized, denied, pending, revoked, conditionallyAuthorized, underReview)
- Categorization_Level enum (low, moderate, high)
- Component_Type enum (application, database, network, infrastructure, service, policy, operatingSystem, container, cloudService, other)
- System (name, identifier, identifierScheme, description, authorizationStatus, authorizationDate, categorizationLevel, boundaryDescription, components[], targetRefs[], interconnections[], extensions)
- Component (name, type, description, targetSelector, baselineRefs[], inputOverrides[], extensions)
- InputOverride (baselineRef, inputName, value, justification, approvedBy, approvedAt)
- Interconnection (name, direction, description, systemRef)

### 1.2 Design hdf-system.schema.json
Top-level document. Required: name. Optional: everything else.
$ref to system primitives, common primitives (Identity, Checksum), target primitives.

### 1.3 Tests for hdf-system schema
Validation tests: minimal valid document, required fields, enum validation,
component structure, input overrides, interconnections.

### 1.4 Type generation
Add hdf-system to TS/Go/Python type generation pipeline.

### 1.5 CLI: hdf system commands
- `hdf system info <file>` — display system architecture
- `hdf system validate <file>` — validate against schema

### 1.6 Integration with hdf-diff
- `hdf diff --system <file>` flag for system-aware comparison
- `hdf diff --group-by labels.<key>` for label-based grouping
- Component-level summary in comparison output

---

## Phase 2: hdf-plan

### 2.1 Design primitives/plan.schema.json
$defs:
- Assessment (baselineRef, targetSelector, inputs, runner)
- Schedule (cron, notifyOnRegression)
- PlanType enum (automated, manual, hybrid)

### 2.2 Design hdf-plan.schema.json
Top-level: name, type, systemRef, assessments[], schedule.
References hdf-baseline (which baselines), hdf-system (which targets).

### 2.3 Tests

### 2.4 Type generation

### 2.5 CLI: hdf plan commands
- `hdf plan create --system <file>` — generate plan from system
- `hdf plan validate <file>` — validate plan against system
- `hdf plan run <file>` — execute the plan (future — requires runner integration)

---

## Phase 3: hdf-attestation

### 3.1 Design primitives/attestation.schema.json
$defs:
- Override_Type enum (waiver, attestation, exception)
- Standalone_Override (extends existing StatusOverride with: requirementId, baselineRef, signature, previousChecksum)

### 3.2 Design hdf-attestation.schema.json
Top-level: name, systemRef, appliedBy, approvedBy, overrides[], integrity.
Reuses existing Identity, Signature, Evidence, Checksum primitives.

### 3.3 Tests

### 3.4 Type generation

### 3.5 CLI: hdf attest commands
- `hdf attest create <results-file>` — create waiver/attestation
- `hdf attest apply <results> <attestation>` — merge into results
- `hdf attest verify <file>` — verify signatures and chain
- `hdf attest list <file>` — list active/expired overrides

### 3.6 Merge operation in hdf-utilities
Function: merge attestation document into results document.
Produces new results with statusOverrides applied and amendment chain intact.

---

## Phase 4: hdf-evidence-package

### 4.1 Design hdf-evidence-package.schema.json
Top-level: name, systemRef, preparedBy, preparedAt, contents[], completenessCheck, signature.
Contents reference other HDF documents by type + URI + checksum.

### 4.2 Tests

### 4.3 Type generation

### 4.4 CLI: hdf evidence commands
- `hdf evidence build` — package documents for audit
- `hdf evidence validate` — check completeness
- `hdf evidence verify` — verify integrity chain
- `hdf evidence export --format oscal` — export to OSCAL

---

## Phase 5: Ecosystem integration

### 5.1 Converter label support
Update high-value converters to populate labels from source tool metadata:
- aws-config: labels.account, labels.region
- nessus: labels.hostgroup
- InSpec: typed inputs (already has data in inspec.yml)
- k8s scanners: labels.cluster, labels.namespace

### 5.2 OSCAL converters
- oscal-ssp ↔ hdf-system (bidirectional)
- oscal-sar ↔ hdf-results (bidirectional)
- oscal-poam ↔ hdf-attestation (bidirectional)

### 5.3 hdf-diff enhancements
- System-aware fleet comparison
- Label-based grouping (--group-by)
- Parameter drift detection
- Component-level summary

### 5.4 Documentation
- HDF v2 specification document
- Well-known label keys reference
- OSCAL alignment guide
- Migration guide from v1

---

## Dependency Order

```
Phase 0 (foundation) — must be first
  ├── Phase 1 (hdf-system) — depends on labels + typed inputs
  ├── Phase 3 (hdf-attestation) — depends on existing primitives only
  │
  Phase 1 complete
  ├── Phase 2 (hdf-plan) — depends on hdf-system
  │
  Phases 1-3 complete
  └── Phase 4 (hdf-evidence) — depends on all other document types

  All phases complete
  └── Phase 5 (ecosystem integration)
```

Phases 1 and 3 can be parallelized.
Phase 2 depends on Phase 1.
Phase 4 depends on Phases 1-3.
Phase 5 can begin incrementally after each phase.
