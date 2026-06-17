# OSCAL Alignment Guide

HDF and OSCAL are complementary formats. OSCAL (Open Security Controls Assessment Language) models the governance lifecycle -- catalogs, profiles, system security plans, assessment plans, and assessment results. HDF models the assessment data lifecycle -- baselines, results, comparisons, amendments, and evidence packages.

The HDF CLI provides bidirectional converters between OSCAL and HDF document types. This guide documents the mapping between the two ecosystems.

For full architecture details, see [hdf-document-ecosystem.md](../architecture/hdf-document-ecosystem.md), section "OSCAL Alignment."

## Bidirectional Mapping Table

| OSCAL Document | HDF Document | CLI (OSCAL to HDF) | CLI (HDF to OSCAL) | Notes |
|---|---|---|---|---|
| Catalog | Baseline | `hdf convert --from oscal-catalog` | -- | Controls become requirements |
| Profile | Baseline | `hdf convert --from oscal-profile --catalog <file>` | -- | Filtered + resolved controls |
| Component Definition | Baseline | `hdf convert --from oscal-component-definition` | -- | Implemented requirements |
| System Security Plan (SSP) | System | `hdf convert --from oscal-ssp` | -- | System boundary + components |
| Assessment Plan (SAP) | Plan | `hdf convert --from oscal-assessment-plan` | -- | Assessment schedule |
| Assessment Results (SAR) | Results | `hdf convert --from oscal-assessment-results` | `hdf convert --from hdf --to oscal-sar` | Findings map to requirements |
| POA&M | Amendments | `hdf convert --from oscal-poam` | `hdf convert --from hdf-amendments --to oscal-poam` | Remediation tracking |

### Auto-detection

The CLI can auto-detect any OSCAL document type and delegate to the correct converter:

```bash
hdf convert any-oscal-file.json -o output.json
```

This inspects the root JSON key (`catalog`, `profile`, `system-security-plan`, etc.) and routes to the matching converter. Profile auto-detection still requires the `--catalog` flag.

## Mapping Details by Document Type

### Catalog to Baseline

**CLI:** `hdf convert --from oscal-catalog catalog.json -o baseline.json`

Key field correspondences:
- OSCAL `group[].controls[]` map to HDF `requirements[]`
- OSCAL `group.id` / `group.title` map to HDF `groups[]` (RequirementGroup)
- Control `parts` with name `statement` map to the `default` description
- Control `parts` with name `guidance` map to the `rationale` description
- Control `parts` with name `assessment-objective` map to the `check` description
- OSCAL control IDs (e.g., `ac-1`) are normalized to NIST notation (e.g., `AC-1`) via `ControlIDToNistTag`

### Profile to Baseline

**CLI:** `hdf convert --from oscal-profile --catalog catalog.json profile.json -o baseline.json`

Key field correspondences:
- The profile's `imports[].include-controls` select which catalog controls to include
- The catalog is loaded separately via `--catalog` and used as the control source
- Selected controls are converted using the same logic as catalog conversion
- The resulting baseline contains only the controls referenced by the profile

The profile resolver also applies `modify.set-parameters` (parameter overrides) and `modify.alters` (part/prop adds and removes) before emitting the baseline. Multi-level profile chains (profile → profile → catalog) and `import-resource` references are not yet supported — those should be pre-resolved externally.

### Component Definition to Baseline

**CLI:** `hdf convert --from oscal-component-definition compdef.json -o baseline.json`

Key field correspondences:
- Each `component.control-implementations[].implemented-requirements[]` becomes an HDF requirement
- The component title is used as the baseline name
- Control descriptions from `implemented-requirements` populate HDF descriptions

### SSP to System

**CLI:** `hdf convert --from oscal-ssp ssp.json -o system.json`

Key field correspondences:
- OSCAL `system-characteristics.system-name` maps to HDF `name`
- OSCAL `system-characteristics.security-impact-level` (confidentiality, integrity, availability) maps to HDF `categorizationLevel` using the FIPS 199 high-water mark
- OSCAL `system-characteristics.status.state` maps to HDF `authorizationStatus` (`operational` maps to `authorized`, `under-development` to `pendingAuthorization`, `disposition` to `revoked`)
- OSCAL `system-characteristics.authorization-boundary.description` maps to HDF `boundaryDescription`
- OSCAL `system-implementation.components[]` map to HDF `components[]`, with `type` mapped from OSCAL values (`software`/`this-system`/`service` to `application`, `hardware` to `host`, `storage` to `artifact`, etc.)
- OSCAL `control-implementation.implemented-requirements[].by-components[]` are used to populate `baselineRefs` on each component

### Assessment Plan (SAP) to Plan

**CLI:** `hdf convert --from oscal-assessment-plan sap.json -o plan.json`

Key field correspondences:
- OSCAL `reviewed-controls.control-selections[]` and `control-objective-selections[]` map to HDF `assessments[]`
- OSCAL `import-ssp.href` maps to HDF `systemRef`
- OSCAL `assessment-subjects[]` map to HDF assessment `targetSelector`
- OSCAL `assessment-assets` is inspected for runner configuration metadata

### Assessment Results (SAR) to Results

**CLI:** `hdf convert --from oscal-assessment-results sar.json -o results.json`

Aliases: `oscal-sar` is accepted as an alias for `oscal-assessment-results`.

Key field correspondences:
- Each OSCAL `results[]` entry becomes an HDF `EvaluatedBaseline`
- OSCAL `findings[]` are grouped by control ID; all findings for the same control produce multiple `RequirementResult` entries on a single requirement
- Finding `target.status.state` maps to HDF `ResultStatus` (`satisfied` to `passed`, `not-satisfied` to `failed`, others to `notReviewed`)
- OSCAL `observations[]` provide the code description (methods and subjects)
- OSCAL `risks[]` provide the message text and determine impact severity via `ExtractRiskSeverity`
- OSCAL `import-ap.href` maps to HDF `planRef`
- OSCAL `results[].start` maps to `startTime` on each requirement result

### Results to SAR (reverse)

**CLI:** `hdf convert --from hdf --to oscal-sar results.json -o sar.json`

Key field correspondences:
- HDF `baselines[]` map to OSCAL `results[]`
- HDF `requirements[]` map to OSCAL `findings[]`
- HDF `ResultStatus` is reversed: `passed` to `satisfied`, `failed` to `not-satisfied`

### POA&M to Amendments

**CLI:** `hdf convert --from oscal-poam poam.json -o amendments.json`

`oscal-poam-to-hdf` emits an HDF **Amendments** document (top-level `overrides[]`), not Results — joining the VEX family (`openvex`, `csaf-vex`, `cyclonedx-vex`) as the second class of amendment-output converters. Consumer-attached remediation context is an amendment act, not a scan finding.

Key field correspondences:
- OSCAL `plan-of-action-and-milestones.poam-items[]` map to HDF `overrides[]`, each with `type: "poam"`
- OSCAL `import-ssp.href` maps to HDF `systemRef`
- OSCAL metadata `responsible-parties[role-id=prepared-by]` maps to HDF `appliedBy`
- OSCAL `risks[]` referenced by a `poam-item.related-risks[]` populate the override's `requirementId` (from `impacted-control-id` props) and `status` (`open`/`investigating` → `failed`, `closed`/`risk-accepted` → `passed`)
- OSCAL `risks[].remediations[lifecycle=planned]` map to HDF `Milestone[]` entries on the override (`description`, `status: "pending"`, `estimatedCompletion`)

### Amendments to POA&M (reverse)

**CLI:** `hdf convert --from hdf-amendments --to oscal-poam amendments.json -o poam.json`

Key field correspondences:
- HDF `overrides[]` map to OSCAL `poam-items[]`
- HDF `Milestone[]` entries on each override map to OSCAL remediation tasks
- HDF `appliedBy` populates OSCAL responsible-party entries

## Limitations

1. **Profile resolution is partial.** The converter handles `include-controls`, `exclude-controls`, `modify.set-parameters`, and `modify.alters` (adds/removes on parts and props), but does not resolve multi-level profile chains or `import-resource` references. For deeply chained profiles, resolve them using the OSCAL resolver tooling first.

2. **Field loss in some directions.** OSCAL documents often contain metadata (responsible parties, roles, locations, back-matter) that has no direct HDF equivalent. This metadata is not preserved in the OSCAL-to-HDF direction. Similarly, HDF fields like `effectiveStatus` and `statusOverrides` have no direct OSCAL SAR equivalent.

3. **Component definition is one-way.** There is no HDF-to-OSCAL component definition converter. Component definitions map to baselines (requirements extracted from implemented controls), but the reverse mapping is ambiguous.

4. **SSP conversion is one-way.** HDF system documents can be created from OSCAL SSPs, but the reverse (HDF system to OSCAL SSP) is not yet implemented. The SSP format contains extensive narrative content that cannot be synthesized from HDF system metadata alone.

## Future Work

- **ARF/XCCDF output converters** -- Export HDF results as SCAP Assessment Results Format (ARF) or XCCDF results for consumption by SCAP-compatible tools.
- **Full profile resolver** -- Handle `modify.alters` for complete profile resolution without external tooling.
- **HDF system to OSCAL SSP** -- Generate SSP system-characteristics from HDF system documents.
