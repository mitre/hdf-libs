# Beads Memory Audit Report

**Date:** 2026-03-15
**Reviewer:** Automated agent (memory-reviewer)
**Scope:** All 16 beads memories verified against codebase

---

## Summary Table

| # | Memory ID | Verdict | Relevance |
|---|-----------|---------|-----------|
| 1 | `beads-init-force-warning` | ACCURATE | HIGH |
| 2 | `comparison-systemref-confirmed` | NEEDS UPDATE | MEDIUM |
| 3 | `dual-implementation-lesson` | ACCURATE | HIGH |
| 4 | `go-nil-slice-null` | ACCURATE | HIGH |
| 5 | `hdf-diff-exit-codes` | ACCURATE | HIGH |
| 6 | `hdf-diff-status` | ACCURATE | MEDIUM (will become STALE when PR merges) |
| 7 | `hdf-v2-ecosystem-decision` | ACCURATE | HIGH |
| 8 | `hdf-v2-new-schemas` | ACCURATE | HIGH |
| 9 | `hdf-v2-schema-changes` | ACCURATE | HIGH |
| 10 | `json-ld-research` | ACCURATE | LOW |
| 11 | `labels-vs-hierarchy-decision` | ACCURATE | HIGH |
| 12 | `mcp-server-concept` | ACCURATE | LOW |
| 13 | `multi-language-ports` | ACCURATE | MEDIUM |
| 14 | `progressive-enrichment-principle` | ACCURATE | HIGH |
| 15 | `sbom-integration-design` | ACCURATE | MEDIUM |
| 16 | `toon-format-research` | ACCURATE | LOW |

---

## Detailed Findings

### Memory 1: `beads-init-force-warning`

**Content**: DANGER: `bd init --force` overwrites issues.jsonl. This is how hdf-libs lost 154 issues (commit b9bb063, Feb 27).

**Verdict: ACCURATE**

Evidence: Operational warning about beads tool usage. The specific commit reference and date provide actionable context. This is a safety guardrail that prevents future data loss.

- Relevance: HIGH — prevents repeating a destructive mistake
- Completeness: Good
- Redundancy: Not duplicated elsewhere

---

### Memory 2: `comparison-systemref-confirmed`

**Content**: hdf-comparison schema will get a first-class optional `systemRef` field.

**Verdict: NEEDS UPDATE**

Evidence: The current `hdf-comparison.schema.json` does NOT have a `systemRef` field. The memory records a *design decision* as if it were a committed fact. It should clarify this is planned/unimplemented.

- Relevance: MEDIUM — useful for future implementation
- Completeness: Missing "not yet implemented" qualifier
- Redundancy: Overlaps with `hdf-v2-schema-changes` and the architecture doc

---

### Memory 3: `dual-implementation-lesson`

**Content**: During hdf-diff development, TypeScript was built first (380 tests, 100% coverage) then Go second. Lesson: build both simultaneously.

**Verdict: ACCURATE**

Evidence: Both implementations exist and are confirmed:
- `hdf-diff/` directory contains the TS library with 23 test files
- `hdf-cli/pkg/diff/` contains 9 Go packages
- PR #8 confirms this sequence and the test counts
- Genuine process insight useful for future library development

- Relevance: HIGH — guides development approach for remaining packages
- Completeness: Good
- Redundancy: Partially overlaps with `hdf-diff-status` but captures a different lesson

---

### Memory 4: `go-nil-slice-null`

**Content**: Go encoding/json serializes nil slices as JSON null, but HDF JSON Schema 2020-12 with unevaluatedProperties rejects null where array is expected.

**Verdict: ACCURATE**

Evidence: Commit `9e4a027` titled "feat(hdf-cli): add Go schema validation + integration tests, fix nil-slice serialization" directly confirms this was a real issue. The `hdf-cli/pkg/diff/normalize/` package exists. This is a technical gotcha that will recur whenever Go types are serialized to HDF-validated JSON.

- Relevance: HIGH — any Go implementation touching HDF schemas will hit this
- Completeness: Good
- Redundancy: None

---

### Memory 5: `hdf-diff-exit-codes`

**Content**: hdf diff CLI uses hybrid exit code scheme. Default: GNU diff compatible (0/1/2). Detailed: 10-14 range.

**Verdict: ACCURATE**

Evidence: Verified in both implementations:
- `hdf-diff/src/exit-codes.ts` defines exactly these constants
- `hdf-cli/cmd/hdf/cmd/diff.go` defines matching constants
- Values match: 0=identical, 1=differences, 2=error, 10=fixes, 11=regressions, 12=mixed, 13=baseline, 14=drift

- Relevance: HIGH — critical for CI/CD integration and scripting
- Completeness: Good
- Redundancy: Partially redundant with CLAUDE.md but more concise

---

### Memory 6: `hdf-diff-status`

**Content**: hdf-diff implementation complete. TS: 380 tests, 100% coverage. Go: 500+ tests, 98.4% coverage, 9 packages. PR #8 open.

**Verdict: ACCURATE**

Evidence:
- `hdf-diff/` directory exists with full source and test structure
- `hdf-cli/pkg/diff/` has exactly 9 packages confirmed
- 4 matching strategies and 4 renderers confirmed
- PR #8 confirmed open with correct title

- Relevance: MEDIUM — status snapshot; will become stale once PR merges
- Completeness: Good
- Redundancy: Overlaps significantly with PR #8 description

---

### Memory 7: `hdf-v2-ecosystem-decision`

**Content**: Decided on 7 document types for HDF v2.

**Verdict: ACCURATE**

Evidence: Architecture doc lists exactly these 7 document types. Currently 3 schemas exist (hdf-baseline, hdf-results, hdf-comparison). The other 4 do NOT exist yet — confirmed by filesystem checks. Memory correctly captures the architectural decision.

- Relevance: HIGH — foundational architectural decision
- Completeness: Good
- Redundancy: Redundant with architecture doc, but memories are more accessible across sessions

---

### Memory 8: `hdf-v2-new-schemas`

**Content**: Four new JSON schemas for v2: hdf-system, hdf-plan, hdf-attestation, hdf-evidence-package.

**Verdict: ACCURATE (as planned; not yet implemented)**

Evidence: None of the 4 schemas exist yet. The plan doc confirms these are planned. Memory accurately records the design intent.

- Relevance: HIGH — guides future implementation
- Completeness: Could note these are planned, not yet implemented
- Redundancy: Overlaps with memory #7 and the plan doc

---

### Memory 9: `hdf-v2-schema-changes`

**Content**: v2 changes to existing schemas: rename attributes→inputs, add labels, add systemRef/planRef.

**Verdict: ACCURATE (as planned; not yet implemented)**

Evidence: `hdf-results.schema.json` still uses `"attributes"` (line 125). `hdf-baseline.schema.json` already uses `"inputs"` (line 31), showing the naming inconsistency this change would resolve.

- Relevance: HIGH — critical migration detail
- Completeness: Good
- Redundancy: Partially covered by the plan doc

---

### Memory 10: `json-ld-research`

**Content**: JSON-LD considered for semantic web / AI agent interop. Deferred.

**Verdict: ACCURATE**

- Relevance: LOW — speculative/exploratory; no implementation planned near-term
- Completeness: Sufficient
- Redundancy: None

---

### Memory 11: `labels-vs-hierarchy-decision`

**Content**: Four research agents scored three approaches. Labels won over fixed hierarchy.

**Verdict: ACCURATE**

Evidence: Architecture doc has a "Labels" section. This was a real architectural decision with consequences visible in the schema design.

- Relevance: HIGH — foundational decision that shapes all v2 schemas
- Completeness: Good
- Redundancy: Partially covered by architecture doc

---

### Memory 12: `mcp-server-concept`

**Content**: Wrapping hdf-diff as an MCP tool for AI agent invocation.

**Verdict: ACCURATE**

- Relevance: LOW — speculative; no implementation planned
- Completeness: Sufficient
- Redundancy: None

---

### Memory 13: `multi-language-ports`

**Content**: User asked about Ruby, Python, Rust ports. Decision: not now.

**Verdict: ACCURATE**

- Relevance: MEDIUM — prevents re-asking the same question
- Completeness: Good
- Redundancy: Overlaps with CLAUDE.md

---

### Memory 14: `progressive-enrichment-principle`

**Content**: All HDF optional fields follow progressive enrichment — valid at any level of detail.

**Verdict: ACCURATE**

Evidence: Current schemas demonstrate this principle. Documented as Decision 9.

- Relevance: HIGH — fundamental design principle for all schema work
- Completeness: Good
- Redundancy: None

---

### Memory 15: `sbom-integration-design`

**Content**: SBOMs connect at 3 levels, all optional.

**Verdict: ACCURATE (as planned; not yet implemented)**

Evidence: No `sbomRef` field exists in current schemas. This is purely a design decision for future implementation.

- Relevance: MEDIUM — useful when implementing hdf-system
- Completeness: Good
- Redundancy: Likely covered in architecture doc

---

### Memory 16: `toon-format-research`

**Content**: TOON format for reducing token consumption in LLM interactions.

**Verdict: ACCURATE**

- Relevance: LOW — informational; no action planned
- Completeness: Sufficient
- Redundancy: None

---

## Recommendations

### Needs Update (1)
- `comparison-systemref-confirmed` — Should clarify systemRef is a planned addition, not yet in schema

### Watch for Staleness (1)
- `hdf-diff-status` — Will go stale when PR #8 merges

### Consider Removing (3 low-relevance)
- `json-ld-research` — No planned implementation
- `mcp-server-concept` — No planned implementation
- `toon-format-research` — No planned implementation

Note: Keeping these is defensible — they prevent re-researching the same questions.

### Redundancy Notes
- Memories #7, #8, #9 overlap (all about v2 ecosystem) but each captures a different facet
- Memory #13 overlaps with CLAUDE.md but adds the explicit "no Ruby/Python/Rust" decision
