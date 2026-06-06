# Heimdall Data Format (HDF) v3.2.0 Specification

**Version**: 3.2.0
**Schema**: JSON Schema draft 2020-12
**License**: Apache-2.0 | The MITRE Corporation

## Overview

HDF is a JSON format for representing security assessment data. It normalizes outputs from vulnerability scanners, compliance checkers, and configuration auditors into a unified data model. Seven document types cover the full assessment lifecycle.

| Document | Purpose | Key Fields |
|----------|---------|------------|
| **Results** | Assessment findings (pass/fail) | baselines, components, statistics |
| **Baseline** | Requirements sets (without findings attached) | requirements, groups, inputs |
| **System** | Description of system under assessment | components, dataFlows, controlDesignations |
| **Plan** | Assessment plan | assessments, schedule |
| **Amendments** | Status overrides (waivers, POAMs) | overrides |
| **Comparison** | Diff between assessments | requirementDiffs, summary |
| **Evidence Package** | Audit bundle | contents (references to other docs) |

Documents reference each other via URI strings: `systemRef`, `planRef`.

## Conventions

- All documents use `"unevaluatedProperties": false` — unknown fields are rejected.
- Date/time values use ISO 8601 (`2026-01-15T10:30:00Z`).
- UUIDs use RFC 4122 format.
- Checksums use `{algorithm, value}` pairs. Algorithms: `sha256`, `sha384`, `sha512`.
- `generator` (optional on all documents): `{name, version}` of the producing tool.
- `labels` (optional on most documents): `{key: value}` string map for flexible grouping. Well-known keys: `system`, `component`, `environment`, `region`, `team`.

### Cardinality invariants

Several arrays in the schema declare `minItems: 1`:

| Path | Constraint |
|------|------------|
| `Evaluated_Baseline.requirements` | minItems: 1 |
| `Evaluated_Requirement.results` | minItems: 1 |
| `Evaluated_Requirement.descriptions` | minItems: 1 (must include label `default`) |
| `Baseline.requirements` | minItems: 1 |
| `Baseline_Requirement.descriptions` | minItems: 1 (must include label `default`) |
| `Components` (system) | minItems: 1 |

**Rationale.** An HDF Results document records the outcome of an assessment. A baseline with zero requirements (or a requirement with zero results) is structurally meaningless — it implies the producer claims an assessment happened but recorded no work. The cardinality invariants force producers to commit to a non-empty record, and let consumers (Heimdall app, `hdf query`, dashboards, downstream OSCAL exporters) safely access `baselines[0]`, `requirements[0].results[0]`, and `requirements[0].descriptions[0]` without defensive null-checking. Empty arrays would also be semantically ambiguous: clean scan? filter excluded everything? truncated input? converter bug? An explicit record disambiguates. The constraint matches peer formats — OSCAL `AssessmentResult` and InSpec profiles have equivalent non-empty-collection guarantees.

**Migration note.** Legacy HDF (the InSpec-ExecJSON-shaped output that the original Heimdall2 mappers produced) did **not** enforce these cardinality invariants. A clean Heimdall2 scan emitted `profiles[0].controls: []` and the consumer was expected to tolerate empty arrays. The v3 schema deliberately tightened the contract: producers MUST emit non-empty arrays, and clean scans MUST synthesize a `passed` placeholder per the convention below. Consumers reading v3 HDF can rely on first-element access being safe; producers translating from legacy InSpec-shaped data MUST add synthesis at the converter boundary.

### Clean-scan convention: synthesize a `passed` placeholder

A direct consequence of the cardinality invariants: a scanner that runs cleanly (zero findings) still must produce at least one requirement and one result. Converters MUST synthesize a placeholder rather than emitting an empty array.

**Shape:**

| Field | Value |
|-------|-------|
| `id` | `<source>-no-findings` (kebab-case converter source name) — or `<sub-tool>-no-findings` for multi-baseline converters where each baseline represents a distinct sub-tool (e.g. SARIF per-run, MSDO per-scanner) |
| `title` | `"No findings reported"` |
| `impact` | `0` |
| `tags` | `{}` |
| `descriptions[0]` | `{label: "default", data: <codeDesc>}` |
| `results[0].status` | `passed` |
| `results[0].codeDesc` | `<Tool> <verb> <target> and reported zero <noun>.` (verb: `scanned` default, `analyzed` for SCA tools, `ran` for multi-tool wrappers; noun: `findings` default, `vulnerable components` for SCA/dependency/container-vuln tools) |
| `results[0].startTime` | scan timestamp from source, or current time if unavailable |

**Spec-backed semantics for `passed`.** This is not a "no information" placeholder — it is a positive assertion that the scan ran against in-scope inputs and detected nothing wrong. The framing aligns with: NIST SP 800-53A *Satisfied*, OSCAL `satisfied`, XCCDF `pass`, STIG *Not_a_Finding*, and SARIF v2.1.0 §3.7.2 ("an empty results array shall be interpreted to mean that the analysis tool did not detect any results").

**Distinguish from `notApplicable`.** Synthesize `notApplicable` (not `passed`) when the rule's applicability check itself didn't fire — e.g. a cloud-config rule with zero in-scope resources, where the rule never evaluated against anything. The two convey materially different audit positions: `passed` says "we checked and you're compliant"; `notApplicable` says "we didn't check this one." Producers SHOULD use whichever the source format's semantics support; consumers SHOULD treat them as distinct.

Reference helper implementations: `shared.BuildNoFindingsRequirement` (Go) and `buildNoFindingsRequirement` (TypeScript) in `hdf-converters/shared/`. Every in-tree converter that emits a `passed` placeholder for clean scans calls one of these.

---

## 1. Results

Assessment findings from running security checks against target systems.

**Schema ID**: `https://mitre.github.io/hdf-libs/schemas/hdf-results/v3.2.0`

### Top-Level Fields

A Results document is the primary output of HDF converters. It captures what was scanned (components), what was checked (baselines with requirements), and what happened (results with pass/fail status). The `tool` field identifies the original security tool; `generator` identifies the converter that produced the HDF file. Cross-document links (`systemRef`, `planRef`) connect results to the broader assessment context.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| baselines | Evaluated_Baseline[] | **yes** | Baselines evaluated with findings |
| components | Component[] | no | System components assessed |
| statistics | Statistics | no | Duration, result counts |
| timestamp | date-time | no | When assessment ran |
| tool | Tool | no | Security tool that produced scan data (`{name, version, format}`) |
| generator | Generator | no | Tool that produced this HDF file |
| runner | Runner | no | Execution environment (distinct from components) |
| integrity | Integrity | no | Cryptographic integrity metadata |
| systemRef | URI-reference | no | Link to System document |
| planRef | URI-reference | no | Link to Plan document |
| extensions | object | no | Tool-specific metadata |
| id | UUID | no | Unique assessment run identifier |
| remediation | Remediation | no | Reference to automated fix resources |

### Evaluated_Baseline

An evaluated baseline represents the results of a set of security tests that have been run against a target system, aligned back to a baseline. It contains the original baseline metadata (name, version, author information) plus the assessed requirements with their pass/fail results. For example, an Evaluated Baseline could represent a Security Content Automation Protocol (SCAP) benchmark after it is evaluated. In InSpec terms, an Evaluated Baseline is a profile after it has been executed against a target with `inspec exec` and produced results. HDF converters should produce one evaluated baseline per scan profile, scanner module, or logical grouping of checks in the source tool's output.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name | string | **yes** | Unique baseline name |
| requirements | Evaluated_Requirement[] | **yes** | Assessment findings; minItems: 1 |
| title | string | no | Human-readable title |
| version | string | no | Baseline version |
| description | string | no | Detailed description |
| maintainer | string | no | Maintainer name/contact |
| summary | string | no | e.g. STIG header |
| copyright | string | no | Copyright holder(s) |
| copyrightEmail | string | no | Copyright contact email |
| license | string | no | e.g. "Apache-2.0" |
| status | string | no | e.g. "loaded" |
| statusMessage | string | no | Explanation of status |
| groups | RequirementGroup[] | no | Logical groupings of requirements |
| inputs | Input[] | no | Typed parameters for execution |
| depends | Dependency[] | no | Baseline dependencies |
| supports | SupportedPlatform[] | no | Supported platform targets |
| checksum | Checksum | no | Baseline integrity hash |
| originalChecksum | Checksum | no | Immutable baseline definition hash |
| resultsChecksum | Checksum | no | Raw results hash (before amendments) |
| parentBaseline | string | no | Parent baseline name (overlay/wrapper) |
| labels | {string: string} | no | Key-value grouping metadata |
| extensions | object | no | Tool-specific metadata |

### Evaluated_Requirement

A single security requirement with test results. Each requirement maps to one testable security control — an InSpec control, a SonarQube rule, a Nessus plugin, or an OSCAL control objective. The `impact` score (0.0–1.0) indicates severity, `tags` carry framework mappings (NIST SP 800-53, CCI, CWE), and `results` holds the individual test executions. Multiple results occur when the same check runs against multiple resources or when findings are grouped by rule.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| id | string | **yes** | Requirement identifier, e.g. "SV-238196" |
| impact | number | **yes** | Severity score 0.0–1.0 |
| tags | {string: any} | **yes** | Metadata; common keys: `nist`, `cci`, `severity`, `cwe` |
| results | RequirementResult[] | **yes** | Test executions; minItems: 1 |
| descriptions | Description[] | **yes** | Must include label "default"; minItems: 1 |
| title | string | no | Human-readable title |
| code | string | no | Source code of the check |
| severity | Severity | no | Explicit severity rating |
| effectiveStatus | ResultStatus | no | Status after applying overrides |
| sourceLocation | SourceLocation | no | File path and line number |
| refs | Reference[] | no | External document references |
| statusOverrides | StatusOverride[] | no | Audit trail of status changes |
| poams | PoamElement[] | no | Remediation tracking (don't change status) |
| evidence | Evidence[] | no | Screenshots, logs, code samples |
| disposition | OverrideType | no | Override disposition applied to this requirement |
| effectiveImpact | number | no | Effective impact after overrides (0.0–1.0) |
| controlType | ControlType | no | NIST SP 800-53 / SP 800-53A categorization: `policy` \| `procedure` \| `technical` \| `management` \| `operational` *(v3.2.0)* |
| verificationMethod | VerificationMethod | no | How this requirement is verified: `automated` \| `manual-by-design` \| `manual-pending-automation` \| `hybrid`. Disambiguates the two cases that null `code` previously overloaded *(v3.2.0)* |
| applicability | Applicability | no | Within-baseline applicability: `required` \| `optional` \| `advisory`. Distinct from severity (risk weight) and status (lifecycle) *(v3.2.0)* |

### RequirementResult

A single test execution within a requirement. Each result records what was tested (`codeDesc`), when (`startTime`), how long it took (`runTime`), and the outcome (`status`). For failed tests, `message` explains the failure. For errors, `exception` and `backtrace` capture the fault. The `resource` and `resourceId` fields identify the specific system resource that was tested (e.g. a file, service, or package).

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| status | ResultStatus | **yes** | Test outcome |
| codeDesc | string | **yes** | Description of what was tested |
| startTime | date-time | **yes** | When test started |
| runTime | number | no | Execution time in seconds |
| message | string | no | Explanation of result |
| exception | string | no | Exception type if error occurred |
| resource | string | no | Resource type tested, e.g. "file", "service" |
| resourceId | string | no | Resource identifier, e.g. "/etc/passwd" |
| backtrace | string[] | no | Stack trace if exception occurred |

### Component

The system element that was assessed. Components are polymorphic — each has a `type` discriminator that determines which additional fields are available. All components share `name`, `type`, and optional fields for identity (`componentId`), external cross-references (`externalIds`), labels, SBOM embedding, and baseline references. Components in Results are typically populated with minimal fields by converters; components in System documents carry the full set including `componentId` for cross-document correlation.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name | string | **yes** | Human-readable component name |
| type | ComponentType | **yes** | Discriminator (see types below) |
| componentId | UUID | no | Stable identity for cross-document correlation |
| description | string | no | Component role or purpose |
| externalIds | {string: string} | no | External ID map (aws, azure, cmdb, emass) |
| labels | {string: string} | no | Key-value grouping metadata |
| sbom | object | no | Embedded CycloneDX or SPDX SBOM |
| sbomRef | URI-reference | no | Reference to external SBOM document |
| sbomFormat | "cyclonedx" \| "spdx" | no | SBOM format (required when sbom/sbomRef present) |
| baselineRefs | string[] | no | Names of baselines that apply |

**Type-specific fields:**

| Type | Extra Fields |
|------|-------------|
| host | fqdn, ipAddress, macAddress, osName, osVersion |
| containerImage | imageId, registry, repository, tag, digest |
| containerInstance | containerId, image, runtime |
| containerPlatform | platformType, clusterName, namespace, version |
| cloudAccount | provider, accountId, region |
| cloudResource | provider, resourceType, resourceId, arn, region |
| repository | url, branch, commit |
| application | url, version, environment |
| artifact | packageManager, packageName, version, checksum |
| network | cidr, gateway |
| database | engine, version, host, port |

---

## 2. Baseline

Security requirements without results (before assessment).

**Schema ID**: `https://mitre.github.io/hdf-libs/schemas/hdf-baseline/v3.2.0`

Shares most fields with Evaluated_Baseline but uses `Baseline_Requirement` (no results, no effectiveStatus) instead of `Evaluated_Requirement`.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name | string | **yes** | Unique baseline name |
| requirements | Baseline_Requirement[] | **yes** | Security requirements; minItems: 1 |
| groups | RequirementGroup[] | no | Logical groupings of requirements |
| inputs | Input[] | no | Typed parameters for execution |
| depends | Dependency[] | no | Baseline dependencies |
| checksum | Checksum | no | Baseline integrity hash |
| remediation | Remediation | no | Reference to automated fix resources |
| generator | Generator | no | Tool that produced this file |
| title | string | no | Human-readable title |
| version | string | no | Baseline version |
| description | string | no | Detailed description |
| maintainer | string | no | Maintainer name/contact |
| summary | string | no | e.g. STIG header |
| copyright | string | no | Copyright holder(s) |
| copyrightEmail | string | no | Copyright contact email |
| license | string | no | e.g. "Apache-2.0" |
| status | string | no | e.g. "loaded" |
| statusMessage | string | no | Explanation of status |
| supports | SupportedPlatform[] | no | Supported platform targets |
| labels | {string: string} | no | Key-value grouping metadata |

### Baseline_Requirement

A security requirement before assessment. Structurally identical to Evaluated_Requirement but without results, effectiveStatus, statusOverrides, poams, or evidence. Used to represent standalone baselines (STIG profiles, CIS benchmarks) and in OSCAL catalog/profile conversions where no assessment has occurred yet.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| id | string | **yes** | Requirement identifier |
| impact | number | **yes** | Severity score 0.0–1.0 |
| tags | {string: any} | **yes** | Metadata; common keys: `nist`, `cci`, `severity` |
| descriptions | Description[] | **yes** | Must include label "default"; minItems: 1 |
| title | string | no | Human-readable title |
| code | string | no | Source code of the check |
| severity | Severity | no | Explicit severity rating |
| sourceLocation | SourceLocation | no | File path and line number |
| refs | Reference[] | no | External document references |
| controlType | ControlType | no | NIST SP 800-53 / SP 800-53A categorization: `policy` \| `procedure` \| `technical` \| `management` \| `operational` *(v3.2.0)* |
| verificationMethod | VerificationMethod | no | How this requirement is verified: `automated` \| `manual-by-design` \| `manual-pending-automation` \| `hybrid` *(v3.2.0)* |
| applicability | Applicability | no | Within-baseline applicability: `required` \| `optional` \| `advisory` *(v3.2.0)* |

---

## 3. System

Describes a system under assessment. A system document defines the authorization boundary, including what components make up the system, its security categorization (FIPS 199), and its authorization status (ATO). This corresponds to a FedRAMP system or an OSCAL SSP's system characteristics. Results and amendments reference the system via `systemRef` to establish which system the assessment applies to.

**Schema ID**: `https://mitre.github.io/hdf-libs/schemas/hdf-system/v3.2.0`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name | string | **yes** | System name |
| components | Component[] | **yes** | System components |
| identifier | string | no | System identifier (e.g. FedRAMP ID) |
| identifierScheme | string | no | Identifier scheme (e.g. "fedramp") |
| description | string | no | System description |
| authorizationStatus | AuthorizationStatus | no | ATO status |
| authorizationDate | date | no | Date of authorization decision |
| categorizationLevel | CategorizationLevel | no | FIPS 199 categorization |
| boundaryDescription | string | no | System boundary narrative |
| controlDesignations | ControlDesignation[] | no | Control inheritance declarations |
| dataFlows | DataFlow[] | no | Data flows between components or external endpoints |
| labels | {string: string} | no | Key-value grouping metadata |
| checksum | Checksum | no | Document integrity hash |
| version | string | no | Document version |
| generator | Generator | no | Tool that produced this file |

### System Component

System components use the same polymorphic Component type as Results (see Section 1), with `componentId` required for stable cross-document references, data flow endpoints, and control designation binding.

### Data Flow

Describes a data flow between components within the system or to external endpoints. Used for authorization boundary diagrams and data flow documentation.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| from | UUID | **yes** | Source componentId |
| to | UUID or External_Endpoint | **yes** | Destination (local component or external) |
| protocol | string | no | Protocol (e.g. "HTTPS", "TCP") |
| port | integer | no | Port number (1–65535) |
| direction | Direction | no | inbound, outbound, or bidirectional |
| description | string | no | Flow description |
| labels | {string: string} | no | Key-value metadata |

### Control Designation

Declares a control's designation within the system — whether it is common (provided by another component or external system), system-specific (implemented locally), or hybrid (shared responsibility). This maps to NIST SP 800-53 Appendix C control designations and OSCAL SSP by-component provided/inherited semantics. When `providedBy` is set, the control is provided by a local component; when `systemRef` is set, the provider is in another system's authorization boundary. When neither is set, the provider is external with no formal HDF representation (e.g. a cloud provider's physical security).

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| controlId | string | **yes** | Control identifier (e.g. "SC-7", "AC-2 (1)") |
| designation | ControlDesignationType | **yes** | common, system-specific, or hybrid |
| description | string | **yes** | Justification for this designation |
| providedBy | UUID | no | componentId of local provider |
| systemRef | URI-reference | no | Reference to external system document |
| inheritedBy | UUID[] | no | componentIds that inherit (default: all) |

---

## 4. Plan

Assessment plan defining what to assess and how. A plan document describes the scope, methodology, and schedule for an upcoming security assessment. It references the system under test via `systemRef` and lists the individual assessments to be performed. This corresponds to an OSCAL SAP (Security Assessment Plan) or a FedRAMP test plan.

**Schema ID**: `https://mitre.github.io/hdf-libs/schemas/hdf-plan/v3.2.0`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name | string | **yes** | Plan name |
| assessments | Assessment[] | **yes** | Planned assessment activities |
| type | PlanType | no | Assessment methodology |
| description | string | no | Plan description |
| systemRef | URI-reference | no | Link to System document |
| schedule | Schedule | no | Assessment schedule |
| labels | {string: string} | no | Key-value grouping metadata |
| checksum | Checksum | no | Document integrity hash |
| version | string | no | Document version |
| generator | Generator | no | Tool that produced this file |

### Assessment

A single assessment within a plan — defines which baseline to run against which component.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| baselineRef | URI-reference | **yes** | Reference to baseline to evaluate |
| componentRef | UUID | no | componentId of target component (direct binding) |
| targetSelector | TargetSelector | no | Label selector for target matching |
| inputs | object | no | Resolved input values |
| runner | RunnerConfig | no | Runner/scanner configuration |
| description | string | no | Assessment purpose |

---

## 5. Amendments

Status overrides applied after assessment (waivers, attestations, POAMs).

**Schema ID**: `https://mitre.github.io/hdf-libs/schemas/hdf-amendments/v3.2.0`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name | string | **yes** | Amendment set name |
| overrides | Override[] | **yes** | Status overrides |
| description | string | no | Description of this amendment set |
| systemRef | URI-reference | no | Link to System document |
| appliedBy | Identity | no | Who applied the overrides |
| approvedBy | Identity | no | Who approved the overrides |
| labels | {string: string} | no | Key-value grouping metadata |
| checksum | Checksum | no | Document integrity hash |
| signature | Signature | no | Digital signature |
| version | string | no | Document version |
| generator | Generator | no | Tool that produced this file |

### Override

A deliberate change to an assessed requirement's compliance status. Waivers grant temporary acceptance of a known risk. Attestations assert manual verification of a requirement that cannot be automatically tested. POAMs track planned remediation with milestones. False positives mark findings confirmed as not applicable. Risk adjustments modify severity based on contextual analysis. Operational requirements document accepted deviations due to mission needs. Inherited overrides indicate that a control is provided by another component or system (typically overriding to notApplicable or passed). Each override records who authorized it, why, and when it expires. The `previousChecksum` field creates a tamper-evident chain linking each override to the document state at the time it was applied.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| requirementId | string | **yes** | ID of requirement being overridden |
| type | OverrideType | **yes** | Override category |
| status | ResultStatus | **yes** | New effective status |
| justification | string | **yes** | Reason for override |
| authority | Identity | no | Authorizing entity |
| expiration | date-time | no | When override expires |
| componentRef | UUID | no | Scopes override to a specific component |
| inheritedFrom | UUID | no | componentId of local control provider |
| previousChecksum | Checksum | no | Links to prior state (amendment chain) |

---

## 6. Comparison

Diff between two or more assessment documents. A comparison captures how compliance posture changed between scans, across environments, or between baseline versions. The `comparisonMode` indicates the type of analysis (temporal drift, fleet comparison, baseline evolution, etc.). Each requirement diff records whether a control is new, absent, fixed, regressed, or unchanged. Comparisons are produced by `hdf diff` and consumed by dashboards to show trend data.

**Schema ID**: `https://mitre.github.io/hdf-libs/schemas/hdf-comparison/v3.2.0`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| formatVersion | string | **yes** | Comparison format version |
| comparisonMode | ComparisonMode | **yes** | Type of comparison |
| sources | Source[] | **yes** | Documents being compared |
| summary | Summary | **yes** | Aggregate diff statistics |
| requirementDiffs | RequirementDiff[] | **yes** | Per-requirement diffs |
| timestamp | date-time | no | When comparison was generated |
| generator | Generator | no | Tool that produced this file |
| matching | MatchingConfig | no | How requirements were matched |
| baselineDiffs | BaselineDiff[] | no | Per-baseline diffs |
| componentDiffs | ComponentDiff[] | no | Per-component diffs |
| packageDiffs | PackageDiff[] | no | Per-package diffs |
| systemRef | URI-reference | no | Link to System document |
| drift | DriftAnalysis | no | Drift analysis metadata |
| annotations | Annotation[] | no | Human/tool annotations on diffs |
| integrity | Integrity | no | Cryptographic integrity metadata |
| extensions | object | no | Tool-specific metadata |

---

## 7. Evidence Package

Bundles references to assessment artifacts for audit and compliance submission. An evidence package collects results, baselines, amendments, system descriptions, and supporting materials (screenshots, logs, SBOMs) into a single auditable unit. This corresponds to a FedRAMP security package or an OSCAL POA&M submission bundle. The `completenessCheck` field validates that all expected artifacts are present.

**Schema ID**: `https://mitre.github.io/hdf-libs/schemas/hdf-evidence-package/v3.2.0`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name | string | **yes** | Package name |
| contents | ContentReference[] | **yes** | References to bundled artifacts |
| description | string | no | Package description |
| systemRef | URI-reference | no | Link to System document |
| preparedBy | Identity | no | Who prepared this package |
| preparedAt | date-time | no | When package was prepared |
| completenessCheck | CompletenessCheck | no | Validation of package contents |
| signature | Signature | no | Digital signature |
| labels | {string: string} | no | Key-value grouping metadata |
| checksum | Checksum | no | Document integrity hash |
| version | string | no | Document version |
| generator | Generator | no | Tool that produced this file |

### Content Reference

A reference to an HDF document or SBOM included in the evidence package.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| type | ContentType | **yes** | Document type |
| uri | URI-reference | **yes** | Document location |
| checksum | Checksum | no | Document integrity hash |
| description | string | no | Entry description |
| componentRef | UUID | no | componentId this content relates to |

---

## Enumerations

### ResultStatus
`passed` | `failed` | `notApplicable` | `notReviewed` | `error`

### Severity
`critical` | `high` | `medium` | `low` | `informational`

### Impact Mapping
Impact is a float 0.0 to 1.0. Conventional mapping to severity:

| Impact | Severity |
|--------|----------|
| 0.9 | critical |
| 0.7 | high |
| 0.5 | medium |
| 0.3 | low |
| 0.0 | informational / notApplicable |

### OverrideType
`waiver` | `attestation` | `poam` | `inherited` | `falsePositive` | `riskAdjustment` | `operationalRequirement`

### PlanType
`automated` | `manual` | `hybrid`

### ComparisonMode
`temporal` | `baseline` | `fleet` | `multiSource` | `baselineEvolution` | `systemDrift`

### RequirementState (comparison)
`new` | `absent` | `unchanged` | `updated` | `fixed` | `regressed` | `moved` | `split` | `merged`

### AuthorizationStatus
`authorized` | `denied` | `pendingAuthorization` | `conditionallyAuthorized` | `notYetRequested` | `revoked`

### CategorizationLevel
`low` | `moderate` | `high`

### ComponentType
`host` | `containerImage` | `containerInstance` | `containerPlatform` | `cloudAccount` | `cloudResource` | `repository` | `application` | `artifact` | `network` | `database`

### Direction (data flow)
`inbound` | `outbound` | `bidirectional`

### ControlDesignationType
`common` | `system-specific` | `hybrid`

### HashAlgorithm
`sha256` | `sha384` | `sha512`

---

## Shared Primitives

### Checksum
```json
{ "algorithm": "sha256", "value": "abc123..." }
```

### Generator
```json
{ "name": "sarif-to-hdf", "version": "1.0.0" }
```

### Tool
```json
{ "name": "Nessus", "version": "10.8.1", "format": "XML" }
```

### Identity
```json
{ "type": "simple", "identifier": "john.doe@example.com" }
```
Types: `simple`, `oidc`, `x509`, `saml`, `ssh`, `pgp`.

### Description
```json
{ "label": "default", "data": "The system must..." }
```
Labels: `default` (required), `check`, `fix`, `rationale` (conventional).

### RequirementGroup
```json
{ "id": "controls/ssh.rb", "title": "SSH Controls", "requirements": ["SV-1", "SV-2"] }
```

### Dependency
```json
{ "name": "os-baseline", "url": "https://...", "status": "loaded" }
```

### Input
Typed parameters for baseline execution.
```json
{
  "name": "max_sessions",
  "description": "Maximum concurrent sessions",
  "type": "Numeric",
  "value": 10,
  "constraints": { "operator": "le", "limit": 20 }
}
```
Input types: `String` | `Numeric` | `Boolean` | `Array` | `Hash` | `Regexp`.
Comparison operators: `eq` | `ne` | `lt` | `le` | `gt` | `ge` | `contains` | `matches` | `in` | `notIn`.

### SourceLocation
```json
{ "ref": "controls/ssh.rb", "line": 42 }
```

### SupportedPlatform
```json
{ "platformName": "ubuntu", "platformFamily": "debian", "release": "22.04" }
```

---

## Integrity Model

HDF supports 4 trust levels for tamper detection:

| Level | Mechanism | Fields |
|-------|-----------|--------|
| 0 | None | *(default)* |
| 1 | Checksums | `originalChecksum`, `resultsChecksum` on baselines |
| 2 | Amendment chain | `previousChecksum` on overrides |
| 3 | Digital signatures | `signature` on amendments, evidence packages |

### Checksum Flow
1. **originalChecksum**: SHA-256 of the baseline definition file (immutable)
2. **resultsChecksum**: SHA-256 of raw results before amendments
3. **previousChecksum**: Links each override to the prior state (chain)

---

## Cross-Document References

```
Plan ---- baselineRef ---------> Baseline
Plan ---- systemRef -----------> System
Plan ---- componentRef --------> Component (by UUID)
Results - planRef -------------> Plan
Results - systemRef -----------> System
Results - baselines[] ---------> Baseline (embedded, not referenced)
Results - components[] --------> Component (embedded)
Amendments - systemRef --------> System
Amendments - componentRef -----> Component (by UUID)
Amendments - inheritedFrom ----> Component (by UUID)
Evidence Package - systemRef --> System
Evidence Package - componentRef -> Component (by UUID, on Content_Reference)
System - dataFlows[].from/to --> Component (by UUID)
System - controlDesignations --> Component (by UUID, providedBy/inheritedBy)
```

All `*Ref` fields are URI-reference strings (relative path, absolute URI, or fragment identifier) unless noted as UUID. Component references use `componentId` (UUID) for local binding. The `baselines[]` and `components[]` relationships in Results are composition — they embed the data rather than referencing external documents.

---

## Schema Compliance

All schemas use JSON Schema draft 2020-12 with `"unevaluatedProperties": false` — documents containing unknown fields are invalid. Tool-specific data should go in the `extensions` field where available.

Schemas are published at `https://mitre.github.io/hdf-libs/schemas/` and distributed as bundled JSON files in the `hdf-schema` package.

## HDF Libraries

| Package | Language | Purpose |
|---------|----------|---------|
| `hdf-schema` | TS/Go | JSON schemas, generated types, validation helpers |
| `hdf-validators` | TS/Go | Validate documents against HDF schemas |
| `hdf-converters` | TS/Go | Convert 30+ security tool formats to/from HDF |
| `hdf-parsers` | TS/Go | Parse and flatten HDF documents |
| `hdf-mappings` | TS/Go | CCI, CWE, OWASP, NIST framework mappings |
| `hdf-generators` | TS/Go | Generate scanner profile stubs from HDF Baselines |
| `hdf-diff` | TS/Go | Compare HDF documents, produce Comparison documents |
| `hdf-extension-graph` | TS | Resolve baseline overlay/extension dependency chains |
| `hdf-utilities` | TS | Shared utilities: XML parsing, HTML stripping, hashing |
| `hdf-cli` | Go | CLI tool: `hdf validate`, `hdf convert`, `hdf query`, `hdf diff` |
