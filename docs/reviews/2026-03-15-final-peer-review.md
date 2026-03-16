# Final Peer Review — Pre-Commit

**Date:** 2026-03-15
**Reviewers:** 3 specialist agents (dependency order, docs alignment, board alignment)

---

## Review 1: Dependency Order (Architecture Review)

**Verdict: Well-designed, one optimization, no circular deps.**

### Findings

1. **FALSE DEPENDENCY: Phase 0.2 (labels) does NOT depend on Phase 0.1 (typed inputs).**
   They touch different schema files (target.schema.json vs parameter.schema.json).
   Removing this false dep lets them run in parallel, shortening the critical path by
   one phase.

2. **Phase 0.4 (systemRef/planRef) positioning is acceptable** as independent at
   the schema level (URI strings don't need target schemas), but integration tests
   will be incomplete until Phases 1/2 land. Add a note to the card.

3. **Phase 3 before Phase 1 is acceptable.** hdf-amendments doesn't structurally
   depend on hdf-system. Component-scoped amendments (e.g., "waive for WebTier only")
   would be a future additive enhancement, not a rework.

4. **No circular dependencies.** Graph is a clean DAG.

5. **Baseline comparison (gz0p) could also depend on 0.2 (labels)** to detect label
   changes between baseline versions. Optional — can be a Phase 5 enhancement.

### Recommended Board Changes

| Change | Type | Impact |
|--------|------|--------|
| Remove pdf7 → hlvt dependency | Remove false dep | Shortens critical path |
| Add note to 5ef5: "integration tests deferred to Phase 1/2" | Documentation | Clarity |
| Add note to 3qm7: "component-scoped amendments deferred to post-Phase 1" | Documentation | Prevents rework |

---

## Review 2: Documentation Alignment (Technical Editor)

**Verdict: 10 stale name references, 6 factual inconsistencies, 6 naming standardization items.**

### Must Fix (stale names)

1. decisions.md line 233: Decision 6 table still says `hdf-attestation`
2. decisions.md line 290: Decision 8 lists `hdf-attestation` in future libraries
3. architecture doc line 397: typed input chain says `hdf attest apply`
4. plan doc line 19: self-referential "Renamed hdf-amendments → hdf-amendments"
5. plan doc line 259: CLI param `<attestation>` should be `<amendments>`
6. plan doc line 265: Go package `pkg/attest` should be `pkg/amend`
7. plan doc line 309: CLI flag `--attestation` should be `--amendments`
8. architecture doc line 600: section header "Attestation Chain" → "Amendment Chain"
9. architecture doc line 898: "1 attestation update" → "1 amendment update"
10. architecture doc line 346: "Attestation signature valid" → "Amendment signature valid"

### Should Fix (factual conflicts)

1. OSCAL hdf-plan direction: reader's guide says "Bidirectional", architecture doc says "Convert from OSCAL" — pick one
2. completenessCheck fields differ across 3 docs (unresolvedPoams, sbomCoverage)
3. Evidence package contents differ between reader's guide and architecture doc
4. Override_Type enum: plan doc lists 3 values, decisions doc lists 4 (missing `poam`)
5. Architecture doc system example missing `sbomRef` that reader's guide includes
6. Reader's guide target label says "Enterprise Portal" but system is "Enterprise Portal Production"

### Nice to Fix (naming consistency)

1. Standardize `hdf-evidence-package` vs `hdf-evidence` (6 locations use short form)
2. Exit code comment in reader's guide CLI tree is misleading

---

## Review 3: Board Alignment (Beads Audit)

**Verdict: 3 critical missing deps, 3 stale card descriptions, 1 structural issue.**

### Critical — Missing Dependencies

| Card | Should Depend On | Currently | Fix |
|------|-----------------|-----------|-----|
| hdf-libs-eey (oscal-ssp) | hdf-libs-b4lj (Phase 1) | NONE — shows as ready | Add dep |
| hdf-libs-1vb (oscal-poam) | hdf-libs-3qm7 (Phase 3) | NONE — shows as ready | Add dep |
| hdf-libs-uej (oscal-sap) | hdf-libs-5sgt (Phase 2) | NONE — shows as ready | Add dep |

These cards appear as "ready" when they cannot be implemented.

### Moderate — Stale Descriptions

1. hdf-libs-vwv (oscal-sar): not updated with v2 additions (labels, systemRef)
2. hdf-libs-y03 (oscal-catalog): not updated with typed inputs awareness
3. hdf-libs-g3i (oscal-profile): not updated with typed inputs awareness

### Moderate — Phase 5 Dependency Too Strict

Phase 5 (qcj7) depends only on Phase 4 (3cjk), blocking ALL incremental work.
The plan says subtasks can begin earlier. Consider splitting or relaxing.

### Minor

1. Epic (15kg) tracks children via text notes, not formal beads links
2. hdf-libs-3qm7 notes still reference old section name "Phase 6: GOVERN — hdf-attestation"
