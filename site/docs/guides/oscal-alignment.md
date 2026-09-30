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

Which mapping applies depends on who produced the POA&M. A `poam-item` whose
related risk carries an `override-type` prop in the HDF namespace is read as
HDF-produced and round-trips. The same prop with no namespace marks an export
from before the namespace existed and is read with the legacy rule. Anything
else takes the foreign-document mapping.

In every case:
- OSCAL `plan-of-action-and-milestones.poam-items[]` map to HDF `overrides[]`
- OSCAL `import-ssp.href` maps to HDF `systemRef`
- OSCAL metadata `responsible-parties[role-id=prepared-by]` maps to HDF `appliedBy`
- OSCAL `risks[].remediations[lifecycle=planned]` map to HDF `Milestone[]` entries on the override (`description`, `estimatedCompletion`, `status` defaulting to `pending`); an HDF-produced POA&M also restores each milestone's `title`, `status`, `completedAt` and `completedBy` from its task

**HDF-produced POA&M (round-trip).** Every override field returns from the prop
or object the exporter wrote it to — no field is derived from titles or UUIDs,
and an absent prop is an absent field:
- HDF-namespaced props restore `type` (`override-type`), `requirementId` (`hdf-requirement-id`), `status` (`override-status`), `impact` (`impact-override`), `justification`, `baselineRef`, `componentRef`, `inheritedFrom` and `affectedPackages`
- the risk's `risk-log` "Override applied" entry restores `appliedBy`; CVSS `characterizations` restore `cvss`; the item's related observations restore `evidence`; the risk's `links[rel=reference]` and their back-matter resources restore `externalReferences`

**Pre-namespace HDF export (legacy rule).** When the related risk's
`override-type` prop carries no namespace, `requirementId` is taken from the
risk's `impacted-control-id` prop alone — never from a title — and an item
without one is skipped with a warning. The un-namespaced spelling is a
one-release compatibility window.

**Foreign POA&M.** With no `override-type` prop at all, each item becomes an
override with `type: "poam"`; its `status` is `passed` when the related risk's
status is `closed` (or `satisfied`) and `failed` otherwise, which covers `open`,
`investigating` and every other OSCAL risk status.
`requirementId` comes from the risk's `impacted-control-id` prop, then the
item's `POAM-ID` prop, then the item title, and is `unknown` when none is
present.

### Amendments to POA&M (reverse)

**CLI:** `hdf convert --from hdf-amendments --to oscal-poam amendments.json -o poam.json`

The exporter writes everything the importer needs to return every override
field, so an HDF-produced POA&M read back through `oscal-poam-to-hdf`
round-trips:
- HDF `overrides[]` map to OSCAL `poam-items[]`, each with one related risk carrying the override's identity and disposition as HDF-namespaced props (`hdf-requirement-id`, `override-type`, `override-status`, `impact-override`, `justification`, `baseline-ref`, `component-ref`, `inherited-from`, and the `affectedPackages` entries)
- a `requirementId` that NIST defines also gets FedRAMP's `impacted-control-id` prop, so a FedRAMP consumer reads the control without the HDF vocabulary
- HDF `Milestone[]` entries on each override map to OSCAL remediation tasks
- HDF `appliedBy` populates OSCAL responsible-party entries and the risk's `risk-log` "Override applied" entry
- HDF `cvss` becomes a risk characterization; `evidence` and `externalReferences` become observations and risk links backed by back-matter resources

## Limitations

1. **Profile resolution is partial.** The converter handles `include-controls`, `exclude-controls`, `modify.set-parameters`, and `modify.alters` (adds/removes on parts and props), but does not resolve multi-level profile chains or `import-resource` references. For deeply chained profiles, resolve them using the OSCAL resolver tooling first.

2. **Field loss in some directions.** OSCAL documents often contain metadata (responsible parties, roles, locations, back-matter) that has no direct HDF equivalent; that metadata is not preserved in the OSCAL-to-HDF direction. Props are the exception: props on a SAR finding and its related observations and risks that HDF does not consume are carried through HDF and re-emitted on export (see below). Similarly, HDF fields like `effectiveStatus` and `statusOverrides` have no direct OSCAL SAR equivalent.

3. **Component definition is one-way.** There is no HDF-to-OSCAL component definition converter. Component definitions map to baselines (requirements extracted from implemented controls), but the reverse mapping is ambiguous.

4. **SSP conversion is one-way.** HDF system documents can be created from OSCAL SSPs, but the reverse (HDF system to OSCAL SSP) is not yet implemented. The SSP format contains extensive narrative content that cannot be synthesized from HDF system metadata alone.

## HDF extension namespace

Every property hdf-libs invents in the OSCAL it writes carries the namespace
`https://mitre.github.io/hdf-libs/ns/oscal`; properties defined by NIST or
FedRAMP keep their owner's namespace instead. The [vocabulary](/ns/oscal) is
published at that URI, with one row per property — the OSCAL objects it attaches
to, its meaning, and the HDF field it carries. It is generated from
`hdf-converters/converters/oscal-to-hdf/go/oscal-vocabulary.json`, the single
table the exporters, the importers and that page all read, so it cannot drift
from what the converters emit.

- Importers match HDF properties by name *and* namespace, so a familiar name in another namespace is treated as foreign.
- Foreign properties on a SAR finding and its related observations and risks are carried through HDF in the reserved `oscal-props` requirement tag — one entry per source property, recording the object it hung on (shape: `hdf-converters/shared/oscal-props.schema.json`).
- The SAR exporter re-emits each carried property after that object's own properties, skipping any already present: finding entries on the finding, observation entries on the requirement's first observation, risk entries on its risk. An entry whose object the exporter does not write for that requirement (a risk entry for a requirement whose impact is 0, for which no risk is written) is not re-emitted; it stays in the HDF tag unchanged.

## Future Work

- **ARF output converter** -- Export HDF results as SCAP Assessment Results Format (ARF) for consumption by SCAP-compatible tools. (XCCDF results already ship: `hdf convert --from hdf --to xccdf`.)
- **Full profile resolver** -- Resolve multi-level profile chains and `import-resource` references without external tooling.
- **HDF system to OSCAL SSP** -- Generate SSP system-characteristics from HDF system documents.
