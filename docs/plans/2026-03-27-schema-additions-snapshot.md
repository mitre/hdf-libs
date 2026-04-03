# HDF Schema Additions Plan — Snapshot 2026-03-27

Status as of commit 376d6af on dev branch.

## Context

The HDF Component Architecture epic (hdf-libs-w2br) elevates components to first-class schema types with stable identity, SBOM embedding, data flows, and control inheritance. This document captures the overall plan and rationale at a point-in-time for reference.

## Completed Work

### hdf-schema (foundation)
- JSON schemas for 7 document types: results, baseline, system, plan, amendments, comparison, evidence-package
- Primitive schemas: common, platform, target, runner, statistics, result, extensions, parameter, comparison, component, data-flow
- Multi-language type generation (TypeScript, Go, Python) via quicktype
- 756+ tests passing, 100% coverage

### Phase 3b: Control Inheritance (hdf-libs-bc27) — DONE
- `Control_Designation` type in system.schema.json: controlId, designation (common/system-specific/hybrid), providedBy (UUID), systemRef (URI), inheritedBy (UUID[]), description
- `controlDesignations[]` array on hdf-system document
- `inherited` added to Override_Type enum in amendments.schema.json
- `inheritedFrom` (UUID) field on Standalone_Override
- Maps to NIST SP 800-53 Appendix C designations and OSCAL SSP by-component provided/inherited
- 25 new tests, spec doc updated

## Active / Blocked Work

### Phase 1: hdf-component and hdf-data-flow schemas (hdf-libs-4dr9) — IN PROGRESS
- component.schema.json: Base_Component with componentId (UUID), externalIds, labels, sbom/sbomRef/sbomFormat, polymorphic oneOf union (host, containerImage, containerInstance, containerPlatform, cloudAccount, cloudResource, repository, application, artifact, network, database)
- data-flow.schema.json: from/to componentId, cross-system via {systemRef, componentId}, protocol, port, direction, description
- Schema files and tests written, CLI changes (hdf label --component-id, hdf convert --component-id) pending
- **Blocks**: Phase 2, Phase 3, Phase 4

### Phase 2: Migrate hdf-results targets[] to components[] (hdf-libs-bccx) — BLOCKED on Phase 1
- Replace targets[] with components[] using new hdf-component schema
- Components have stable componentId for cross-scan identity matching
- Backward compat: not needed (v2 hasn't shipped yet)

### Phase 3: Update hdf-system for hdf-component + hdf-data-flow (hdf-libs-qwur) — BLOCKED on Phase 1
- Replace simple Component type in hdf-system with full hdf-component schema
- Add dataFlows[] array using hdf-data-flow
- Remove old interconnections[] (replaced by dataFlows)
- Update system create CLI and tests

### Phase 4: SBOM embedding in hdf-component (hdf-libs-55v7) — BLOCKED on Phase 1
- Embed full CycloneDX/SPDX SBOM objects (not just refs)
- Conditional validation: CycloneDX requires bomFormat + specVersion, SPDX requires spdxVersion + SPDXID

### Phase 5: Update all converters for component-aware output (hdf-libs-dbpq) — BLOCKED on Phase 2
- All 30+ converters produce component-aware output instead of targets
- Both TypeScript and Go implementations

### Phase 6: Extend hdf-diff for component and SBOM diffing (hdf-libs-6zlr) — BLOCKED on Phase 3
- Component identity matching across scans
- SBOM package diffing (added/removed/changed packages)

### Phase 7: Update hdf-plan, hdf-amendments, hdf-evidence-package for componentRef (hdf-libs-cuds) — BLOCKED on Phase 5
- Assessments reference components by componentId
- Amendments can be scoped to a component
- Evidence package references component SBOMs
- NOTE: inherited amendment type already handled by Phase 3b

### Phase 8: Update specification and documentation (hdf-libs-xc9e) — BLOCKED on Phase 7 + bc27
- Full spec doc update for component, data-flow, control designation
- Cross-document reference diagram
- Converter guide and README updates

## Dependency Graph

```
Phase 1 (4dr9) ──┬──> Phase 2 (bccx) ──> Phase 5 (dbpq) ──> Phase 7 (cuds) ──> Phase 8 (xc9e)
                  ├──> Phase 3 (qwur) ──> Phase 6 (6zlr)
                  ├──> Phase 4 (55v7)
                  └──> Phase 3b (bc27) ✓ ──────────────────────────────────────────> Phase 8 (xc9e)
```

## Non-Epic Work (also open)

| ID | Pri | Title |
|----|-----|-------|
| f1d1 | P1 | Release prep: publish hdf-libs 2.0.0 |
| vfl7 | P1 | Update schema $id URLs to final hosting domain |
| wx56 | P1 | Set up CNAME for schema hosting domain |
| 7mkt | P2 | Source real Ion Channel fixture data |
| csbr | P2 | hdf system create: interactive TUI |
| q3zx | P2 | hdf evidence create: interactive TUI |
| sjlq | P2 | Verify contributor dev workflow after release config |
| xf5c | P2 | Manual CLI smoke test |
| h2ix | P3 | Add interactive query mode (hdf query --interactive) |
| kp12 | P3 | Add interactive evidence build wizard |
| t0t  | P3 | Integrate mutation testing into CI |
| zpjo | P3 | Source real fixtures for Defender Cloud and Endpoint converters |
| 02vl | P4 | hdf plan run: execute assessment plan (future) |

## Key Design Decisions

1. **Control inheritance is system-level, not component-level.** The same host might inherit SC-7 in System A (with a WAF) but need its own firewall in System B. Therefore controlDesignations live on the system document, not on individual components.

2. **`inherited` is an amendment type, not a result status.** A scanner flags a control as failing; an ISSM overrides it post-assessment because the control is provided elsewhere. This keeps the assessment truthful (the scanner saw what it saw) while documenting the architectural decision.

3. **Polymorphic component types via oneOf union.** Each component type (host, cloud, container, etc.) extends Base_Component with type-specific fields. The `type` field is the discriminator.

4. **SBOM embedding, not just references.** Components can carry full CycloneDX or SPDX documents inline for self-contained system descriptions. sbomRef remains for external references.

5. **Data flows replace interconnections.** The data-flow schema is more expressive (protocol, port, cross-system references) and works at the component level rather than the system boundary level.

6. **No backward compatibility shims.** HDF v2 hasn't shipped yet, so schema changes are clean additions/replacements without migration paths.

## OSCAL Alignment Summary

| HDF Concept | OSCAL Equivalent |
|-------------|-----------------|
| Control_Designation.providedBy | SSP by-components[].component-uuid (provided) |
| Control_Designation.systemRef | leveraged-authorizations |
| Control_Designation.designation | NIST 800-53 Appendix C |
| inherited amendment | SAR finding with implementation-status: inherited |
| controlDesignations[] | SSP control-implementations |
| Component.componentId | SSP component UUID |
| Data_Flow | SSP interconnection (but richer) |
