# HDF-Diff Schema & Library Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Design and implement `hdf-diff` as a formal HDF document type with its own JSON schema — the industry's first standardized format for structured security assessment comparison.

**Architecture:** A new JSON Schema (`hdf-comparison.schema.json`) defines the document type. The `hdf-diff` TypeScript library produces documents conforming to this schema. The schema supports 4 comparison modes (temporal, baseline, fleet, multi-source), Terraform-inspired before/after snapshots with companion metadata maps, SARIF-compatible state vocabulary, and configurable matching strategies with confidence scores. The design borrows from Terraform's plan format (full snapshots, action reasons, drift separation), SARIF (baselineState, fingerprinting), Debezium (before/after envelope with provenance), and LSP (change annotations).

**Tech Stack:** JSON Schema 2020-12, TypeScript 5.6+, Vitest, json-diff-ts

---

## Table of Contents

1. [Research Summary](#1-research-summary)
2. [Schema Design](#2-schema-design)
3. [Comparison Modes](#3-comparison-modes)
4. [Matching Strategies](#4-matching-strategies)
5. [Implementation Tasks](#5-implementation-tasks)

---

## 1. Research Summary

### The Gap

No industry standard exists for representing structured diffs between security assessments. Research across 30+ tools and standards found:

- **SARIF** annotates results with `baselineState` (new/unchanged/updated/absent) but embeds comparison inline — no standalone diff document
- **RFC 6902 JSON Patch** is purely structural — no semantic awareness of security concepts
- **OSCAL** has no comparison format; NIST's `oscal-deep-diff` tool is schema-agnostic
- **Terraform plan** has the best-designed diff format but targets infrastructure, not security
- **No security tool** (Snyk, Grype, Trivy, DefectDojo, SonarQube, Tenable, Qualys) produces a standalone diff document with a public schema

### Design Patterns Adopted

| Source | Pattern | Application |
|--------|---------|-------------|
| Terraform | Full before/after snapshots (not patches) | Each requirement carries complete old + new state |
| Terraform | Companion boolean maps | `sensitive`, `unknown` markers mirroring value structure |
| Terraform | `resource_drift` vs `resource_changes` | Separate `drift` from `changes` arrays |
| Terraform | `action_reason` | `changeReasons[]` on each requirement diff |
| Terraform | Actions as arrays | Compound transitions: `["removed","added"]` for split/merge |
| Terraform | `format_version` | Schema versioning from day one |
| SARIF | `baselineState` vocabulary | Standard state enum compatible with SARIF consumers |
| SARIF | Fingerprinting (Appendix B) | Configurable matching with `matchStrategy` + `matchConfidence` |
| Debezium | Before/after envelope + source metadata | Per-change provenance |
| LSP | ChangeAnnotation | Explanation layer linked by annotation IDs |
| GumTree | Move as first-class operation | `moved` status for reorganized requirements |
| Git | Rename detection with similarity index | `matchConfidence: 0.86` for fuzzy matches |
| Automerge | Conflicts are data | Multi-scanner disagreements preserved, not resolved |
| Prisma | Desired vs actual with shadow verification | Golden baseline comparison mode |
| buf | Multiple compatibility tiers | Different detail levels for different stakeholders |

---

## 2. Schema Design

### 2.1 Top-Level Document: `hdf-comparison`

**Schema file layout (DRY with `$ref`):**

```
hdf-schema/src/schemas/
├── hdf-comparison.schema.json       ← NEW top-level document type
├── hdf-results.schema.json          ← existing (provides EvaluatedRequirement)
├── hdf-baseline.schema.json         ← existing
└── primitives/
    ├── comparison.schema.json       ← NEW ($defs for RequirementDiff, Source, etc.)
    ├── common.schema.json           ← existing ($ref for Checksum, Identity)
    ├── extensions.schema.json       ← existing ($ref for Generator, DataSource, Integrity)
    ├── target.schema.json           ← existing ($ref for Target in Source metadata)
    ├── result.schema.json           ← existing ($ref for ResultStatus enum)
    └── ...
```

**`$ref` dependency graph:**

```
hdf-comparison.schema.json
  ├── $ref primitives/comparison.schema.json
  │     ├── $defs/RequirementDiff
  │     │     ├── before/after: $ref hdf-results.schema.json#/$defs/Evaluated_Requirement
  │     │     └── state: $ref #/$defs/RequirementState
  │     ├── $defs/Source
  │     │     ├── checksum: $ref primitives/common.schema.json#/$defs/Checksum
  │     │     ├── dataSource: $ref primitives/extensions.schema.json#/$defs/DataSource
  │     │     └── targets: $ref primitives/target.schema.json#/$defs/Target
  │     ├── $defs/ComparisonSummary
  │     ├── $defs/FieldChange
  │     ├── $defs/MatchingConfig
  │     ├── $defs/BaselineDiff
  │     ├── $defs/ScannerConflict
  │     └── $defs/Annotation
  ├── $ref primitives/extensions.schema.json (Generator, Integrity)
  └── $ref primitives/common.schema.json (Checksum)
```

**Key DRY win:** `RequirementDiff.before` and `RequirementDiff.after` are `$ref` to the SAME `EvaluatedRequirement` definition that `hdf-results.schema.json` uses. Zero type duplication. When `EvaluatedRequirement` evolves (new fields, v2.1), the comparison schema automatically inherits the changes.

**Document structure:**

```
hdf-comparison.schema.json
├── formatVersion: "1.0.0"
├── comparisonMode: "temporal" | "baseline" | "fleet" | "multiSource"
├── timestamp: ISO 8601 (when comparison was performed)
├── generator: { name, version }
├── sources: Source[] (2+ source documents)
├── matching: MatchingConfig (how requirements were paired)
├── summary: ComparisonSummary
├── baselineDiffs: BaselineDiff[]
├── requirementDiffs: RequirementDiff[]
├── drift: RequirementDiff[] (external changes, separate from intentional)
├── annotations: { [id]: Annotation } (explanations linked to changes)
├── integrity: Integrity (optional, from hdf-schema)
└── extensions: object (tool-specific data)
```

### 2.2 Source Metadata

Every comparison references 2+ source documents with full provenance:

```typescript
interface Source {
  /** Role of this source in the comparison */
  role: "old" | "new" | "golden" | "reference" | "system";
  /** Human-readable label (e.g., "Production scan 2024-01-15") */
  label?: string;
  /** Path or URI to the source document */
  uri?: string;
  /** Original format before normalization */
  originalFormat?: "hdf-v2" | "inspec-v1" | "sarif" | "oscal-ar" | "xccdf";
  /** SHA-256 of the source document for integrity verification */
  checksum?: Checksum;
  /** When the source assessment was performed */
  assessmentTimestamp?: string;
  /** Scanner/tool that produced the source */
  dataSource?: DataSource;
  /** Target system(s) assessed */
  targets?: Target[];
  /** Baseline name and version from the source */
  baselineRef?: { name: string; version?: string };
}
```

### 2.3 Requirement State Vocabulary

Aligned with SARIF `baselineState` for interoperability, extended for security domain:

```typescript
/**
 * SARIF-compatible core states:
 *   new, unchanged, updated, absent
 *
 * Security-domain extensions:
 *   fixed, regressed, moved, split, merged
 */
type RequirementState =
  | "new"        // Present only in new source (SARIF: new)
  | "absent"     // Present only in old source (SARIF: absent)
  | "unchanged"  // Same effective status (SARIF: unchanged)
  | "updated"    // Status or fields changed (SARIF: updated)
  | "fixed"      // Was failing/error, now passing (updated subtype)
  | "regressed"  // Was passing, now failing/error (updated subtype)
  | "moved"      // Reorganized to different group/baseline, same content
  | "split"      // One old requirement became multiple new ones
  | "merged";    // Multiple old requirements became one new one
```

### 2.4 Change Reasons

Why did the status change? Multiple reasons can apply simultaneously:

```typescript
type ChangeReason =
  | "resultChanged"      // Test results differ
  | "overrideAdded"      // New waiver/attestation added
  | "overrideExpired"    // Override expired between assessments
  | "overrideRemoved"   // Override was removed
  | "overrideModified"  // Override was modified (e.g., extended)
  | "impactChanged"     // Impact/severity score changed
  | "baselineUpgraded"  // Baseline version changed
  | "controlMapped"     // Control ID changed via mapping table
  | "scannerChanged"    // Different scanner produced the result
  | "targetChanged"     // Different target system
  | "configChanged"     // Scanner configuration changed
  | "metadataChanged";  // Non-status metadata changed (tags, descriptions)
```

### 2.5 RequirementDiff (Terraform-Inspired)

Following Terraform's pattern: full before/after snapshots, not patches.

```typescript
interface RequirementDiff {
  /** Canonical requirement ID (from new source, or old if absent) */
  id: string;
  /** ID in old source (may differ for mapped/moved requirements) */
  oldId?: string;
  /** ID in new source */
  newId?: string;
  /** Human-readable title */
  title?: string;
  /** The comparison state */
  state: RequirementState;
  /** Why the state is what it is — empty for unchanged */
  changeReasons: ChangeReason[];

  // ── Terraform-style before/after (ALWAYS full snapshots) ──────
  //
  // These $ref EvaluatedRequirement from hdf-results.schema.json.
  // Full snapshots, never patches. The document is self-contained.
  // - null only when state = "new" (before) or state = "absent" (after)
  // - For state = "unchanged": before and after are both populated
  //   with identical content (redundant but unambiguous)

  /** Complete EvaluatedRequirement from old source. Null only when state = "new". */
  before: EvaluatedRequirement | null;
  /** Complete EvaluatedRequirement from new source. Null only when state = "absent". */
  after: EvaluatedRequirement | null;

  // ── Companion metadata maps (Terraform pattern) ───────────────

  /** Boolean map mirroring before: true at leaves containing sensitive values */
  beforeSensitive?: Record<string, unknown>;
  /** Boolean map mirroring after: true at leaves containing sensitive values */
  afterSensitive?: Record<string, unknown>;

  // ── Derived convenience fields (computed from before/after) ────
  // Redundant with snapshots but saves consumers from re-computing.

  /** Effective status in old source */
  oldEffectiveStatus?: string;
  /** Effective status in new source */
  newEffectiveStatus?: string;
  /** Impact in old source */
  oldImpact?: number;
  /** Impact in new source */
  newImpact?: number;

  // ── Matching metadata ─────────────────────────────────────────

  /** How this requirement was matched across sources */
  matchStrategy?: "exactId" | "mappedId" | "cciMatch" | "nistMatch" | "fuzzyTitle" | "fuzzyContent";
  /** Confidence score 0.0-1.0 (1.0 = exact match) */
  matchConfidence?: number;
  /** Whether a human confirmed/overrode this match */
  matchManual?: boolean;

  // ── Field-level changes (RFC 6902-inspired) ───────────────────
  // Computed convenience: derived from diffing before vs after.
  // Redundant with the snapshots but saves consumers from re-diffing.

  /** Specific field changes for machine consumption */
  fieldChanges: FieldChange[];

  // ── Annotations ───────────────────────────────────────────────

  /** IDs of annotations explaining this change */
  annotationIds?: string[];

  // ── Fleet mode ────────────────────────────────────────────────

  /** Index into sources[] identifying which system this diff belongs to (fleet mode) */
  sourceIndex?: number;

  // ── Multi-scanner (conflicts are data) ────────────────────────

  /** When multiple sources disagree, all results preserved */
  conflicts?: ScannerConflict[];
}
```

### 2.6 FieldChange (RFC 6902-Inspired)

```typescript
interface FieldChange {
  /** Operation type */
  op: "add" | "remove" | "replace";
  /** Dot-notation path to the changed field */
  path: string;
  /** Value in old source (undefined for add) */
  oldValue?: unknown;
  /** Value in new source (undefined for remove) */
  newValue?: unknown;
}
```

### 2.7 ComparisonSummary

```typescript
interface ComparisonSummary {
  /** Total unique requirements across all sources */
  total: number;

  // ── Counts by state ──
  new: number;
  absent: number;
  unchanged: number;
  updated: number;
  fixed: number;
  regressed: number;
  moved: number;

  // ── Aggregate metrics ──
  /** Compliance percentage in old source (0-100) */
  oldCompliancePercent?: number;
  /** Compliance percentage in new source (0-100) */
  newCompliancePercent?: number;
  /** Net change in compliance percentage */
  complianceDelta?: number;

  // ── By severity breakdown ──
  bySeverity?: {
    critical?: StateCounts;
    high?: StateCounts;
    medium?: StateCounts;
    low?: StateCounts;
  };

  // ── Matching quality ──
  matchedCount: number;
  unmatchedOldCount: number;
  unmatchedNewCount: number;
  averageMatchConfidence?: number;
}

interface StateCounts {
  fixed: number;
  regressed: number;
  new: number;
  absent: number;
  unchanged: number;
  updated: number;
}
```

### 2.8 BaselineDiff

```typescript
interface BaselineDiff {
  name: string;
  state: "new" | "absent" | "unchanged" | "updated";
  oldVersion?: string;
  newVersion?: string;
  /** Mapping table used for cross-version matching */
  mappingSource?: string;
}
```

### 2.9 ScannerConflict (Automerge-inspired)

For multi-scanner correlation where sources disagree:

```typescript
interface ScannerConflict {
  /** Which field has conflicting values */
  field: string;
  /** Each source's value for this field */
  values: {
    sourceIndex: number;
    sourceLabel: string;
    value: unknown;
  }[];
  /** Which value was chosen as canonical (if any) */
  resolvedIndex?: number;
  /** Resolution strategy */
  resolution?: "mostSevere" | "mostRecent" | "manual" | "unresolved";
}
```

### 2.10 Annotation (LSP-inspired)

```typescript
interface Annotation {
  /** Human-readable label */
  label: string;
  /** Detailed explanation */
  description?: string;
  /** Category of annotation */
  category?: "remediation" | "drift" | "waiver" | "baselineChange" | "scannerNote";
  /** Whether this change needs human confirmation */
  needsConfirmation?: boolean;
}
```

### 2.11 MatchingConfig

```typescript
interface MatchingConfig {
  /** Primary matching strategy */
  primaryStrategy: "exactId" | "mappedId" | "cciMatch" | "nistMatch" | "fuzzyTitle";
  /** Fallback strategies in priority order */
  fallbackStrategies?: string[];
  /** Minimum confidence for fuzzy matches (0.0-1.0) */
  minimumConfidence?: number;
  /** External mapping table URI (for STIG version transitions) */
  mappingTableUri?: string;
  /** Fields used for fingerprinting */
  fingerprintFields?: string[];
}
```

---

## 3. Comparison Modes

### 3.1 Temporal (default)

Two scans of the same system at different times. Symmetric comparison.

```json
{
  "comparisonMode": "temporal",
  "sources": [
    { "role": "old", "label": "January scan", "assessmentTimestamp": "2024-01-01T00:00:00Z" },
    { "role": "new", "label": "February scan", "assessmentTimestamp": "2024-02-01T00:00:00Z" }
  ]
}
```

### 3.2 Baseline

Current scan vs approved/authorized golden state. **Asymmetric** — deviations are attributed to the current scan.

```json
{
  "comparisonMode": "baseline",
  "sources": [
    { "role": "golden", "label": "Approved baseline (ATO 2024-01-01)", "uri": "golden-baseline.json" },
    { "role": "new", "label": "Current scan", "assessmentTimestamp": "2024-02-01T00:00:00Z" }
  ]
}
```

### 3.3 Fleet

Multiple systems against the same baseline. One reference, N systems.

```json
{
  "comparisonMode": "fleet",
  "sources": [
    { "role": "reference", "label": "Golden image" },
    { "role": "system", "label": "web-server-01", "targets": [{"type": "host", "name": "web-01"}] },
    { "role": "system", "label": "web-server-02", "targets": [{"type": "host", "name": "web-02"}] }
  ]
}
```

Fleet mode produces one `RequirementDiff` per requirement per system, with the `before` being the reference state.

### 3.4 Multi-Source

Same system scanned by different tools. Results correlated by CCI/NIST mapping.

```json
{
  "comparisonMode": "multiSource",
  "sources": [
    { "role": "old", "label": "InSpec STIG scan", "dataSource": {"name": "InSpec"} },
    { "role": "new", "label": "OpenSCAP scan", "dataSource": {"name": "OpenSCAP"} }
  ],
  "matching": {
    "primaryStrategy": "cciMatch",
    "fallbackStrategies": ["nistMatch", "fuzzyTitle"],
    "minimumConfidence": 0.7
  }
}
```

---

## 4. Matching Strategies

### 4.1 Exact ID Match (default)

Requirements share the same `id` field. Reliable for same-baseline comparisons.
Confidence: 1.0

### 4.2 Mapped ID Match

A mapping table translates IDs between baseline versions. DISA publishes these for STIG transitions (e.g., V1R1 → V1R2).
Confidence: 0.95-1.0 (depending on mapping source)

### 4.3 CCI Match

Requirements matched by CCI identifier in tags. Many-to-many possible — requires disambiguation.
Confidence: 0.7-0.9

### 4.4 NIST Match

Requirements matched by NIST 800-53 control family. Coarser than CCI — more ambiguity.
Confidence: 0.5-0.8

### 4.5 Fuzzy Title/Content Match

NLP-based similarity matching on title, description, or check content. Always requires human confirmation.
Confidence: 0.3-0.7

---

## 5. Implementation Tasks

### Task 1: JSON Schema for hdf-comparison

**Files:**
- Create: `hdf-schema/src/schemas/hdf-comparison.schema.json`
- Create: `hdf-schema/src/schemas/primitives/comparison.schema.json`
- Modify: `hdf-schema/src/schemas/primitives/common.schema.json` (if shared types needed)
- Test: `hdf-schema/test/hdf-comparison.test.ts`

**Step 1: Write the failing test**

Create `hdf-schema/test/hdf-comparison.test.ts` that:
- Loads the comparison schema
- Validates a minimal valid comparison document
- Validates a full comparison document with all fields
- Rejects documents missing required fields (`formatVersion`, `comparisonMode`, `sources`, `summary`, `requirementDiffs`)
- Rejects invalid `comparisonMode` values
- Rejects sources with invalid `role` values
- Rejects `requirementDiffs` with invalid `state` values

**Step 2: Run test to verify it fails**

```bash
cd hdf-schema && pnpm test
```

Expected: FAIL (schema file doesn't exist)

**Step 3: Write the JSON Schema**

Create `hdf-comparison.schema.json` following the patterns in `hdf-results.schema.json`:
- `$schema`: `https://json-schema.org/draft/2020-12/schema`
- `$id`: `https://mitre.github.io/hdf-libs/schemas/hdf-comparison/v1.0.0`
- `$ref` to shared primitive types where possible
- `unevaluatedProperties: false` for strict validation
- All types from Section 2 as `$defs`

**Step 4: Run test to verify it passes**

```bash
cd hdf-schema && pnpm test
```

Expected: PASS

**Step 5: Commit**

```bash
git add hdf-schema/src/schemas/hdf-comparison.schema.json
git add hdf-schema/src/schemas/primitives/comparison.schema.json
git add hdf-schema/test/hdf-comparison.test.ts
git commit -s -m "feat(hdf-schema): add hdf-comparison schema for structured assessment diffs

Defines the industry's first formal JSON schema for security assessment
comparison. Supports 4 comparison modes (temporal, baseline, fleet,
multiSource), Terraform-inspired before/after snapshots, SARIF-compatible
state vocabulary, configurable matching strategies with confidence scores,
and multi-scanner conflict preservation.

Authored by: Aaron Lippold<lippold@gmail.com>"
```

---

### Task 2: Generate TypeScript Types from Schema

**Files:**
- Modify: `hdf-schema/src/generate-types.ts` (add comparison type generation)
- Output: `hdf-schema/dist/ts/hdf-comparison.ts`
- Modify: `hdf-schema/package.json` (add `./hdf-comparison` export)

**Step 1: Add comparison schema to type generation**

Modify `generate-types.ts` to include `hdf-comparison.schema.json` alongside the existing results and baseline schemas.

**Step 2: Build and verify types generate**

```bash
cd hdf-schema && pnpm build
ls dist/ts/hdf-comparison.*
```

Expected: `hdf-comparison.ts`, `hdf-comparison.d.ts`

**Step 3: Add subpath export to package.json**

```json
"./hdf-comparison": {
  "import": "./dist/ts/hdf-comparison.js",
  "types": "./dist/ts/hdf-comparison.d.ts"
}
```

**Step 4: Run all hdf-schema tests**

```bash
cd hdf-schema && pnpm test
```

Expected: All existing tests still pass + new comparison tests pass

**Step 5: Commit**

```bash
git add hdf-schema/src/generate-types.ts hdf-schema/package.json
git commit -s -m "feat(hdf-schema): generate TypeScript types for hdf-comparison

Authored by: Aaron Lippold<lippold@gmail.com>"
```

---

### Task 3: Redesign hdf-diff Types to Match Schema

**Files:**
- Modify: `hdf-diff/src/types.ts`
- Modify: `hdf-diff/src/index.ts`
- Modify: `hdf-diff/package.json` (add `@mitre/hdf-schema` dependency)
- Test: Update all existing tests to use new type names

**Step 1: Update types.ts to align with schema**

Replace current types with schema-aligned versions:
- `HdfDiff` → `HdfComparison` (matches schema name)
- `DiffStatus` → `RequirementState` (matches SARIF vocabulary)
- `DiffSummary` → `ComparisonSummary` (with severity breakdown)
- Add `Source`, `MatchingConfig`, `ScannerConflict`, `Annotation`
- Add `before`/`after` full snapshots to `RequirementDiff`

**Step 2: Update all test files**

Replace old type names with new ones. Tests should still express the same expectations — just with updated field names/structure.

**Step 3: Run tests to verify they fail**

```bash
cd hdf-diff && pnpm test
```

Expected: FAIL (implementations don't match new types yet)

**Step 4: Update implementations**

Update `status.ts`, `diff.ts`, `summary.ts` to produce the new types.

**Step 5: Run tests**

```bash
cd hdf-diff && pnpm test
```

Expected: PASS

**Step 6: Commit**

```bash
git add hdf-diff/src/types.ts hdf-diff/src/index.ts hdf-diff/src/diff.ts
git add hdf-diff/src/status.ts hdf-diff/src/summary.ts
git add hdf-diff/test/
git commit -s -m "refactor(hdf-diff): align types with hdf-comparison schema

Renames types to match the formal schema: HdfDiff→HdfComparison,
DiffStatus→RequirementState, DiffSummary→ComparisonSummary. Adds
before/after full snapshots, Source metadata, MatchingConfig, and
SARIF-compatible state vocabulary.

Authored by: Aaron Lippold<lippold@gmail.com>"
```

---

### Task 4: Implement Comparison Modes

**Files:**
- Create: `hdf-diff/src/modes/temporal.ts`
- Create: `hdf-diff/src/modes/baseline.ts`
- Create: `hdf-diff/src/modes/fleet.ts`
- Create: `hdf-diff/src/modes/multi-source.ts`
- Modify: `hdf-diff/src/diff.ts` (dispatch to mode-specific logic)
- Test: `hdf-diff/test/modes/temporal.test.ts`
- Test: `hdf-diff/test/modes/baseline.test.ts`
- Test: `hdf-diff/test/modes/fleet.test.ts`
- Test: `hdf-diff/test/modes/multi-source.test.ts`

**Step 1: Write temporal mode tests** (this is the current behavior, extracted)

Temporal mode is symmetric: `role: "old"` + `role: "new"`. All existing tests should pass with the temporal mode.

**Step 2: Write baseline mode tests**

Baseline mode is asymmetric:
- `role: "golden"` is the approved state
- Deviations are always attributed to the `role: "new"` source
- Test: golden has 5 passing controls. New has 4 passing + 1 failing → state is "regressed" for the failing control, NOT "updated"
- Test: golden has a waiver for control X. New scan shows X failing without waiver → state shows waiver was not applied

**Step 3: Write fleet mode tests**

Fleet mode compares N systems against a reference:
- Test: reference has 3 controls all passing. System A has 2 passing + 1 failing. System B has all passing.
- Output: one comparison per system, each with its own summary
- Test: controls that fail on ALL systems should be flagged as "systemic"

**Step 4: Write multi-source mode tests**

Multi-source correlates different scanners:
- Test: InSpec scan has control "V-12345" with CCI "CCI-000366". OpenSCAP scan has rule "xccdf_rule_ssh_root_login" with same CCI.
- Matching by CCI should pair them
- If both say "passed" → unchanged. If they disagree → conflict preserved
- Test: conflict resolution strategies

**Step 5: Implement each mode, run tests after each**

Each mode shares the core matching/status logic but differs in:
- How sources are interpreted
- Symmetry of comparison
- How summary is computed
- How conflicts are handled

**Step 6: Commit after each mode passes**

---

### Task 5: Implement Matching Strategies

**Files:**
- Create: `hdf-diff/src/matching/exact-id.ts`
- Create: `hdf-diff/src/matching/mapped-id.ts`
- Create: `hdf-diff/src/matching/cci-match.ts`
- Create: `hdf-diff/src/matching/fuzzy-match.ts`
- Create: `hdf-diff/src/matching/index.ts` (strategy registry)
- Test: `hdf-diff/test/matching/` (one test file per strategy)

**Step 1: Extract exact ID matching** from current `diff.ts` into `exact-id.ts`

**Step 2: Write mapped ID tests**

Test with a mock mapping table: `{ "V-001-old": "V-001-new" }`. Verify controls are paired despite different IDs. Verify `matchStrategy: "mappedId"` and `matchConfidence: 0.95` on the diff.

**Step 3: Implement mapped ID matching**

Load mapping table (JSON object `{ oldId: newId }`), apply translations before exact matching.

**Step 4: Write CCI match tests**

Test: old control with `tags.cci: ["CCI-000366"]`, new control with same CCI but different ID. Should match with `matchStrategy: "cciMatch"`, `matchConfidence: 0.8`.

Test edge case: two new controls share the same CCI — should warn/annotate ambiguity.

**Step 5: Implement CCI matching**

Build CCI→requirementId index for each source. Match on CCI overlap.

**Step 6: Write fuzzy match tests**

Test: old control "Ensure SSH root login is disabled" vs new control "SSH root login must be disabled" — should match with confidence ~0.85.

Test: very different titles — should NOT match below minimum confidence threshold.

**Step 7: Implement fuzzy matching**

Use simple token-based Jaccard similarity (no external NLP deps for v1). Configurable threshold.

**Step 8: Commit after each strategy**

---

### Task 6: Drift vs Changes Separation (Terraform Pattern)

**Files:**
- Modify: `hdf-diff/src/diff.ts`
- Modify: `hdf-diff/src/types.ts`
- Test: `hdf-diff/test/drift.test.ts`

**Step 1: Write drift detection tests**

When comparing with a golden baseline:
- Requirements that changed status = `requirementDiffs` (intentional assessment)
- Requirements whose baseline metadata changed (tags, descriptions) but status is same = `drift` (environmental change)
- Test: control has same pass/fail but description text changed → appears in `drift`, not `requirementDiffs`
- Test: control has different status → appears in `requirementDiffs`, not `drift`

**Step 2: Implement drift separation logic**

In baseline mode, separate changes into two buckets:
- Status changes → `requirementDiffs`
- Metadata-only changes → `drift`

**Step 3: Run tests**

**Step 4: Commit**

---

### Task 7: Schema Validation of Output

**Files:**
- Modify: `hdf-diff/src/diff.ts` (validate output against schema)
- Modify: `hdf-diff/package.json` (add ajv dependency, reference hdf-schema)
- Test: `hdf-diff/test/schema-validation.test.ts`

**Step 1: Write validation test**

Every output of `diffHdf()` must validate against `hdf-comparison.schema.json`. Run diffHdf on all fixture combinations and validate each output.

**Step 2: Add optional schema validation**

```typescript
export interface DiffOptions {
  validateOutput?: boolean; // default: false (performance)
  // ...existing options
}
```

When enabled, validate the output document against the schema before returning. Throw on validation failure.

**Step 3: Run tests**

**Step 4: Commit**

---

### Task 8: Output Format Renderers

**Files:**
- Create: `hdf-diff/src/renderers/json.ts` (identity — the native format)
- Create: `hdf-diff/src/renderers/markdown.ts`
- Create: `hdf-diff/src/renderers/csv.ts`
- Create: `hdf-diff/src/renderers/sarif.ts`
- Create: `hdf-diff/src/renderers/terminal.ts`
- Test: `hdf-diff/test/renderers/` (one test file per renderer)

Renderers convert an `HdfComparison` document to other formats. They are pure functions: `(comparison: HdfComparison, options?) => string`.

**The canonical JSON document is always complete (full snapshots, all fields).** Detail levels are a **renderer concern** — renderers choose what to display, not what to store.

**Priority order:**
1. JSON (identity — serialize the full document as-is)
2. Markdown (for PR comments, reports)
3. Terminal (for CLI — colored, with summary line)
4. CSV (for Excel/spreadsheet analysis)
5. SARIF (for GitHub Code Scanning integration)

Each non-JSON renderer should support display detail levels:
- `"summary"` — counts only (e.g., "3 fixed, 1 regressed, 296 unchanged")
- `"control"` — per-control state, status, title (no field changes or snapshots)
- `"full"` — everything including field changes, before/after excerpts, annotations

---

### Task 9: CLI Integration (`hdf diff`)

**Files:**
- Create: `hdf-cli/cmd/hdf/cmd/diff.go`
- Create: `hdf-cli/pkg/diff/diff.go` (Go implementation or shim)
- Modify: `hdf-cli/cmd/hdf/cmd/root.go` (register diff command)
- Test: `hdf-cli/cmd/hdf/cmd/diff_test.go`

**CLI interface:**

```
hdf diff <old> <new> [flags]

Flags:
  --mode string         Comparison mode: temporal, baseline, fleet (default "temporal")
  --format string       Output format: json, markdown, csv, sarif, table (default "table")
  --detail string       Display detail for non-JSON formats: summary, control, full (default "control")
  --match string        Matching strategy: exactId, mappedId, cciMatch, fuzzyTitle (default "exactId")
  --mapping string      Path to ID mapping table (for --match=mappedId)
  --min-confidence float  Minimum match confidence for fuzzy strategies (default 0.7)
  --fixed              Show only fixed requirements
  --regressed          Show only regressions
  --new                Show only new requirements
  --severity string    Filter by severity: critical, high, medium, low
  --json               Shorthand for --format=json (always complete — full snapshots)
  -o, --output string  Write output to file instead of stdout
  --exit-code          Use exit codes: 0=no regressions, 1=regressions found, 2=error
```

Note: `--json` always outputs the complete `hdf-comparison` document with full before/after snapshots. The `--detail` flag only affects display formats (table, markdown, terminal). This follows the principle that the canonical document is always complete — renderers choose what to show.

**Exit codes for CI/CD:**
- 0 = comparison complete, no regressions
- 1 = comparison complete, regressions found (or thresholds violated)
- 2 = error (invalid input, parse failure, etc.)

**Step 1: Write Go test with fixture files**

**Step 2: Implement diff.go command**

For v1, the Go CLI can shell out to the TypeScript library via a bundled Node script, or implement core matching logic natively. Per the dual-implementation strategy (beads comment), native Go implementation with differential testing against TypeScript.

**Step 3: Run tests**

**Step 4: Commit**

---

### Task 10: Differential Testing (TS ↔ Go Parity)

**Files:**
- Create: `hdf-diff/test/differential/` (shared fixtures and expected outputs)
- Create: `hdf-cli/cmd/hdf/cmd/diff_differential_test.go`

Generate comparison documents from both TypeScript and Go implementations using identical inputs. Diff the outputs — they must be byte-identical (after key sorting).

This ensures the dual-implementation strategy (npm library + native CLI) maintains parity.

---

## Dependency Order

```
Task 1 (Schema)
  └→ Task 2 (Type Generation)
       └→ Task 3 (Redesign hdf-diff types)
            ├→ Task 4 (Comparison Modes) ─── can parallelize ──┐
            ├→ Task 5 (Matching Strategies) ─── can parallelize ┤
            └→ Task 6 (Drift Separation)                        │
                 └→ Task 7 (Schema Validation) ←────────────────┘
                      └→ Task 8 (Output Renderers) ─── can parallelize
                           └→ Task 9 (CLI Integration)
                                └→ Task 10 (Differential Testing)
```

Tasks 4, 5, 6 can be parallelized after Task 3.
Task 8 subtasks (each renderer) can be parallelized.
Tasks 9 and 10 are sequential and depend on everything above.

---

## Design Decisions (Resolved)

### 1. `before`/`after` carry FULL requirement snapshots — always

**Decision:** Full `EvaluatedRequirement` snapshots. No patches-only mode. No detail levels for the canonical document.

**Rationale:** Every well-designed diff format (Terraform, Debezium, Delta Lake, Review Board) uses full snapshots. The comparison document is a first-class audit artifact — it must be self-contained without requiring the original source documents. Size is negligible: 300 requirements × 2 sides × 1KB = ~600KB uncompressed, ~52KB gzipped.

**Schema rules:**
- `before`: full `$ref EvaluatedRequirement` or `null` (null only when `state = "new"`)
- `after`: full `$ref EvaluatedRequirement` or `null` (null only when `state = "absent"`)
- For `state = "unchanged"`: both `before` and `after` are populated with identical content. Redundant but unambiguous.
- `fieldChanges[]`: computed convenience derived from comparing `before` vs `after`. Redundant with the snapshots but saves consumers from re-diffing.

**Detail levels apply to renderers (markdown, terminal, CSV), not to the document itself.** The canonical JSON document is always complete. Renderers can choose what to display.

### 2. Fleet mode: one document with all systems

**Decision:** Single document. Each `RequirementDiff` gets a `sourceIndex` field referencing `sources[]`. Summary includes per-source breakdown.

**Rationale:** One comparison = one artifact to store/sign/transmit. Per-system extraction is just filtering by `sourceIndex`. Fleet comparisons are inherently about cross-system visibility.

### 3. Schema lives in `hdf-schema`

**Decision:** `hdf-comparison.schema.json` lives alongside `hdf-results.schema.json` and `hdf-baseline.schema.json` in the `hdf-schema` package.

**Rationale:** Single source of truth for all HDF document types. The comparison schema `$ref`s heavily into existing primitives (`EvaluatedRequirement`, `Checksum`, `Identity`, `Target`, etc.). Co-location is natural. Same pattern as existing document types.

### 4. N-way temporal: pairwise only in v1

**Decision:** v1 supports pairwise comparison only. Schema designed so pairwise diffs chain naturally (source checksums enable verification of chains). N-way trending is a presentation concern for v1.1.

**Rationale:** Pairwise is the atomic operation. The CLI can support `hdf trend scan1.json scan2.json scan3.json` as a convenience that internally chains pairwise diffs.

### 5. `split`/`merged`: enum values reserved, implementation deferred to v1.1

**Decision:** Include `"split"` and `"merged"` in the `RequirementState` enum now (forward compatibility). Do not implement matching logic for 1:N or N:1 in v1. If a mapping table has 1:N entries, treat as separate "absent" + "new" pairs with an annotation.

**Rationale:** Low real-world frequency. Most STIG transitions are 1:1 renames. Including the values now avoids a schema version bump later.
