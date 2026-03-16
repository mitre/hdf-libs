# HDF v2 Documentation Consistency Review

**Date:** 2026-03-15
**Reviewer:** Automated agent (docs-reviewer)
**Scope:** All 4 design docs + 3 schema files

---

## SUMMARY

**Overall Status:** 8 critical gaps, 14 accuracy issues, 2 cross-reference errors, 3 stale content markers. The documentation is aspirational and future-focused while actual implementation is in Phase 0 (foundation work).

---

## CRITICAL FINDINGS

### 1. PHASE MISMATCH: Documentation vs. Reality

**Finding:** The documentation describes a complete v2 ecosystem (7 document types, full implementation), but actual schemas only contain 3 of 7 planned document types.

**Details:**
- **Documentation claims** (hdf-v2-document-ecosystem.md):
  - All 7 schemas exist and are complete
  - Table on line 15-23 lists full "Created By / Consumed By" workflows
  - Phase 7 example JSON at line 302-327 shows fully-built hdf-evidence-package

- **Actual Implementation:**
  - Only 3 schemas exist: `hdf-results.schema.json`, `hdf-baseline.schema.json`, `hdf-comparison.schema.json`
  - Missing: `hdf-system.schema.json`, `hdf-plan.schema.json`, `hdf-attestation.schema.json`, `hdf-evidence-package.schema.json`
  - Missing primitives: `primitives/system.schema.json`, `primitives/plan.schema.json`, `primitives/attestation.schema.json`, `primitives/parameter.schema.json`

**Severity:** CRITICAL - Documentation reads as a completed specification when actual implementation is in Phase 0.

**Location:** hdf-v2-document-ecosystem.md, entire document; 2026-03-14-hdf-v2-ecosystem-plan.md, Phases 1-4

---

### 2. SCHEMA FIELD STATUS: Inputs vs. Attributes Inconsistency

**Finding:** Documentation claims the rename from `attributes` → `inputs` is complete, but actual schema still uses `attributes`.

**Details:**
- **Documentation claims** (hdf-v2-document-ecosystem.md, lines 395-403):
  - "The `Evaluated_Baseline.attributes` field in hdf-results is renamed to `inputs` in v2."
  - "Both schemas (baseline and results) now use `inputs` consistently."

- **Actual Schema** (hdf-results.schema.json, lines 125-133):
  ```json
  "attributes": {
    "type": "array",
    "items": { "type": "object", "additionalProperties": true },
    "description": "The input(s) or attribute(s) used in the run."
  }
  ```
  - Field is still named `attributes`, NOT `inputs`

- **hdf-baseline.schema.json** (line 31):
  - Uses `inputs` correctly in baseline

**Severity:** CRITICAL - Contradiction between spec and implementation; Phase 0.3 (rename task) is marked "Ready" in beads but not actually completed in schemas.

**Location:** hdf-v2-document-ecosystem.md, line 400; hdf-results.schema.json, line 125; decisions.md, line 72

---

### 3. TYPED INPUTS NOT IMPLEMENTED

**Finding:** Documentation extensively describes `Input` primitive with type definitions, but the primitive schema doesn't exist.

**Details:**
- **Documentation claims** (hdf-v2-document-ecosystem.md, lines 407-421):
  - Full `Input` type with fields: name, type (enum: String/Numeric/Boolean/Array/Hash/Regexp), value, description, required, sensitive, operator, constraints
  - Example usage in Phase 1 (lines 94-106)

- **Actual Implementation:**
  - `primitives/parameter.schema.json` does NOT exist
  - hdf-results.schema.json still has untyped `attributes: object[]` (line 127-129)
  - hdf-baseline.schema.json `inputs` field is undefined/untyped

- **Task Status** (beads: hdf-libs-hlvt, Phase 0.1):
  - Listed as "Ready" but schema doesn't exist
  - Blocks Phase 0.2, 0.3, Phase 1 (hdf-system depends on typed inputs)

**Severity:** CRITICAL - Core v2 design feature is not implemented. All downstream features depend on this.

**Location:** hdf-v2-document-ecosystem.md, lines 344-421; 2026-03-14-hdf-v2-ecosystem-plan.md, lines 28-51; decisions.md, Decision 5

---

### 4. LABELS NOT ADDED TO SCHEMAS

**Finding:** Documentation claims labels are added to targets and baselines, but schemas don't reflect this.

**Details:**
- **Documentation claims** (hdf-v2-document-ecosystem.md, lines 425-483):
  - "`labels: Record<string, string>` to Target" (line 437-450)
  - "`labels: Record<string, string>` to Baseline" (line 698)
  - Multiple examples using labels (lines 209-214, 438-450)

- **Actual Schema** (primitives/target.schema.json):
  - No `labels` field in Base_Target definition

- **hdf-baseline.schema.json**:
  - No `labels` field in Baseline_Metadata

- **hdf-results.schema.json**:
  - No `systemRef` or `planRef` fields (should be added per lines 699-700 of spec)

- **Task Status** (beads: hdf-libs-pdf7, Phase 0.2):
  - Listed as "Ready" but not implemented in schemas

**Severity:** CRITICAL - Labels are fundamental to the v2 design (fleet comparison, grouping).

**Location:** hdf-v2-document-ecosystem.md, lines 425-483, 698-700; 2026-03-14-hdf-v2-ecosystem-plan.md, lines 53-70

---

### 5. CROSS-REFERENCE ERROR: Missing Document Type References

**Finding:** The architecture doc references schemas that don't exist in planned structure.

**Details:**
- **hdf-v2-document-ecosystem.md, line 626-649** (Schema Organization):
  ```
  hdf-system.schema.json           (new)  ← DOESN'T EXIST
  hdf-plan.schema.json             (new)  ← DOESN'T EXIST
  hdf-attestation.schema.json       (new)  ← DOESN'T EXIST
  hdf-evidence-package.schema.json  (new)  ← DOESN'T EXIST
  primitives/system.schema.json     (new)  ← DOESN'T EXIST
  primitives/plan.schema.json       (new)  ← DOESN'T EXIST
  primitives/attestation.schema.json (new) ← DOESN'T EXIST
  primitives/parameter.schema.json  (new)  ← DOESN'T EXIST
  ```
  All marked "(new)" but none exist.

**Severity:** HIGH - Architectural diagram is fictional; no way to verify docs against actual schemas.

**Location:** hdf-v2-document-ecosystem.md, lines 626-649

---

### 6. INCONSISTENCY: hdf-results Field Names

**Finding:** Documentation examples use different field names than schema definitions.

**Details:**
- **Documentation (hdf-v2-document-ecosystem.md, lines 205-215)** shows a target with:
  ```json
  "labels": { "system": "...", "component": "..." }  ← Not in schema
  ```

- **Documentation (line 222)** shows evaluated baseline with:
  ```json
  "inputs": [{ "name": "...", "type": "Numeric", "value": 5 }]  ← Schema uses "attributes"
  ```

- **Actual hdf-results.schema.json** (line 125):
  - Field is `attributes`, not `inputs`
  - No `labels` field on targets

**Severity:** CRITICAL - Examples don't match schema; will confuse implementers.

**Location:** hdf-v2-document-ecosystem.md, lines 205-239

---

## ACCURACY ISSUES (Non-Critical)

### 7. Stale Cross-Reference in Architecture Doc

- **hdf-v2-document-ecosystem.md, line 916**: References `docs/plans/2026-03-13-hdf-diff-schema-design.md` — file doesn't exist at that path.
- **Line 917**: References `docs/plans/2026-03-14-hdf-v2-ecosystem-plan.md` — this file IS confirmed.

**Severity:** MEDIUM

---

### 8. Inconsistent Phase Numbering

The mapping between decision IDs and beads card IDs is implicit and scattered across multiple docs. No single table links Decision N → Card hdf-libs-XXXX.

**Severity:** MEDIUM

---

### 9. SBOM Reference Design Incomplete

Documentation describes sbomRef fields but no schema defines them. Expected — sbomRef is planned for hdf-system which doesn't exist yet.

**Severity:** LOW

---

### 10. Comparison Snapshot Claim vs. Reality

Feature is actually implemented (hdf-diff exists with full before/after). Documentation is correct here.

**Severity:** LOW (verified accurate)

---

### 11. Exit Code Implementation Claim

decisions.md says "Decided and implemented" which is correct — implemented in hdf-diff CLI. Could clarify this is a CLI feature, not a schema feature.

**Severity:** LOW

---

## GAPS (Missing Content)

### 12. No Decision-to-Card Mapping

Readers can't tell which decision maps to which beads card. Suggested mapping:
- Decision 1 (Labels) → Phase 0.2 (hdf-libs-pdf7)
- Decision 5 (Typed Inputs) → Phase 0.1 (hdf-libs-hlvt)
- Decision 6 (7 Doc Types) → Epic hdf-libs-15kg

---

### 13. Terminology: "hdf-comparison" vs. "hdf-diff"

"hdf-diff" is the CLI tool/library; "hdf-comparison" is the document type. Documentation is technically correct but uses both terms in ways that could confuse new readers.

---

## POSITIVE FINDINGS

- hdf-comparison schema is actually implemented and matches documented design
- Exit codes are correctly implemented in both TS and Go
- Existing primitives (common.schema.json, extensions.schema.json) match documentation
- Design decisions are well-researched (Decisions 1-9 all have rationale)
- Developer guide is accurate for hdf-diff patterns
- Progressive enrichment principle is clearly explained

---

## RECOMMENDED ACTIONS

### Immediate
1. Add status header to architecture doc: "This is the HDF v2 design specification. Implementation is tracked in beads epic hdf-libs-15kg."
2. Flag examples that show future state (inputs, labels, systemRef)
3. Fix broken cross-reference on line 916

### Medium Term
4. Add decision-to-card mapping table
5. Create status table showing which schemas exist vs. planned

---

## CROSS-REFERENCE VERIFICATION

| Document Type | Referenced In | Actual Status | Schema File |
|--|--|--|--|
| hdf-baseline | Architecture, Plan, Decisions | EXISTS | hdf-baseline.schema.json |
| hdf-results | Architecture, Plan, Decisions | EXISTS | hdf-results.schema.json |
| hdf-comparison | Architecture, Plan, Decisions | EXISTS | hdf-comparison.schema.json |
| hdf-system | Architecture, Plan, Phase 1 | NOT BUILT | missing |
| hdf-plan | Architecture, Plan, Phase 2 | NOT BUILT | missing |
| hdf-attestation | Architecture, Plan, Phase 3 | NOT BUILT | missing |
| hdf-evidence-package | Architecture, Plan, Phase 4 | NOT BUILT | missing |
