# HDF to eMASS crosswalk

What each part of an HDF evidence package corresponds to in eMASS, what has no counterpart in either direction, and which eMASS fields an operator must supply because HDF does not carry them.

Written against the eMASS REST API specification **v3.22**, read from `docs/eMASSRestOpenApi.yaml` in [`mitre/emass_client`](https://github.com/mitre/emass_client) (sha256 `4124a3c7926769e1f06a0a34480c51e670614b58295d515196dc13600ad65f37`). Every eMASS field below is named as that specification names it, in the schema it belongs to. Where a value cannot be derived from an evidence package it is marked **operator input** — see [Operator input](#operator-input).

## How to read this

eMASS groups each entity's fields into `*RequiredFields`, `*ConditionalFields`, `*OptionalFields` and `*ReadOnlyFields` schemas. A write must satisfy the required group and whichever conditionals apply; read-only fields are returned but never sent.

One property of the API shapes everything here: **eMASS reports when a record was created and never when it last changed.** `createdDate` exists on POA&M items and milestones; no `lastUpdate`, `lastModified`, `updatedDate` or `modifiedDate` appears anywhere in the specification, and `PoamReadOnlyFields` carries no timestamp at all. A client therefore cannot tell from eMASS alone whether a record has been edited since it was read. Conflict detection is layered to work without one.

## Identity: the join key

| HDF | eMASS | Notes |
|-----|-------|-------|
| `hdf-system.identifier` | `systemId` | The join. Documented in HDF as "System identifier from an authoritative source. Example: eMASS system ID". |
| `hdf-system.identifierScheme` | — | Must be `https://emass.mil` for the identifier to be read as an eMASS system id. |
| `components[].externalIds.emass` | `systemId` | Per-component alternative, written by `hdf label set --external-id emass=<id>`. |

A push never creates an eMASS system. If `identifier` resolves to no system the push fails and names the identifier.

## Test results

eMASS schema `TestResultsGet`. Write is a batch `POST` to `/api/systems/{systemId}/test-results` whose response reports a per-object outcome, so a partial success is normal and must be read per item.

**Natural key:** control acronym plus assessment procedure. **Write:** `POST` only; there is no update operation.

| HDF | eMASS field | Required | Notes |
|-----|-------------|----------|-------|
| `hdf-system.identifier` | `systemId` | Required | |
| `requirements[].tags.nist` | `control` | Read-only | eMASS derives it; sent implicitly via the assessment procedure. |
| `requirements[].tags.cci` | `cci` | Required | HDF carries CCI as a tag array, e.g. `["CCI-000068"]`. |
| — | `assessmentProcedure` | Required | **Operator input.** HDF names the requirement by its own id and by NIST control and CCI, not by an eMASS assessment procedure. |
| — | `testedBy` | Required | **Operator input.** Format is "Last Name, First Name"; a scanner result has no human tester. |
| `requirements[].results[].startTime` | `testDate` | Required | Unix time; HDF is RFC3339 and converts. |
| `requirements[].results[].codeDesc` | `description` | Required | 4000-character limit; HDF prose is unbounded and must be truncated. |
| `requirements[].effectiveStatus` | `complianceStatus` | Required | Mapped, see below. |

### Status mapping

eMASS `complianceStatus` admits exactly `Compliant`, `Non-Compliant` and `Not Applicable`. HDF's `effectiveStatus` has five values, so the mapping is lossy in one direction:

| HDF `effectiveStatus` | eMASS `complianceStatus` |
|-----------------------|--------------------------|
| `passed` | `Compliant` |
| `failed` | `Non-Compliant` |
| `notApplicable` | `Not Applicable` |
| `notReviewed` | no counterpart |
| `error` | no counterpart |

`notReviewed` and `error` have nowhere to go. Reporting either as `Non-Compliant` would assert a failing assessment that did not happen, and as `Not Applicable` would assert a scope decision nobody made. Requirements in those states are therefore **not pushed**, and the receipt records them as skipped with the reason.

## POA&M items

eMASS schemas `PoamRequiredFields`, `PoamConditionalFields`, `PoamOptionalFields`, `PoamReadOnlyFields`. HDF's counterpart is a `Standalone_Override` of POA&M type in an amendments document.

**Natural key:** no natural key exists. Correlating an HDF amendment to a pre-existing eMASS POA&M is an open problem; see [Unresolved](#unresolved). **Write:** `POST` to create, `PUT` to update.

| HDF | eMASS field | Group | Notes |
|-----|-------------|-------|-------|
| `statusOverrides[].status` | `status` | Required | eMASS admits `Ongoing`, `Risk Accepted`, `Completed`, `Not Applicable`, `Archived`. |
| `statusOverrides[].reason` | `vulnerabilityDescription` | Required | 2000-character limit. |
| `tool.name` + `statusOverrides[].requirementId` | `sourceIdentifyingVulnerability` | Required | 2000-character limit. |
| — | `pocOrganization` | Required | **Operator input.** |
| — | `resources` | Required | **Operator input.** |
| — | `identifiedInCFOAuditOrOtherReview` | Required | Defaults to `false` when unspecified. |
| `statusOverrides[].appliedBy.identifier` | `pocEmail` | Conditional | Only when the identity's `type` is `email`. |
| — | `pocFirstName`, `pocLastName`, `pocPhoneNumber` | Conditional | **Operator input.** HDF's `Identity` is `{identifier, type, description}` and carries no name parts or phone. |
| `statusOverrides[].milestones[].estimatedCompletion` | `scheduledCompletionDate` | Conditional | Required for ongoing and completed items. |
| `statusOverrides[].milestones[].completedAt` | `completionDate` | Conditional | Required for completed items. |
| `statusOverrides[].justification` | `comments` | Conditional | Required for completed and risk-accepted items. |
| — | the resourcing block | Conditional | **Operator input**, see below. |
| `statusOverrides[].requirementId` | `externalUid` | Optional | Gives eMASS a handle on the HDF requirement. |
| `requirements[].tags.nist` | `controlAcronym` | Optional | |
| `statusOverrides[].cvss` | `rawSeverity` | Optional | Derived from the CVSS base score. |
| `statusOverrides[].impact` | `impact` | Optional | eMASS uses a Very Low to Very High band, HDF a 0.0–1.0 score. |

### The resourcing block

`PoamConditionalFields` includes a funding model: `personnelResourcesFundedBaseHours`, `personnelResourcesCostCode`, `personnelResourcesUnfundedBaseHours`, `personnelResourcesNonfundingObstacle`, `personnelResourcesNonfundingObstacleOtherReason`, and four `nonPersonnelResources*` equivalents. The specification states that at least one must be completed.

HDF models none of it. It describes what an assessment found, not who owns remediating it or what that costs. All of these are **operator input**.

## Milestones

eMASS schema `MilestonesGet`, under `/api/systems/{systemId}/poam/{poamId}/milestones`.

**Natural key:** parent POA&M plus description. **Write:** `POST` to create, `PUT` to update.

| HDF | eMASS field | Required | Notes |
|-----|-------------|----------|-------|
| `statusOverrides[].milestones[].description` | `description` | Required | |
| `statusOverrides[].milestones[].estimatedCompletion` | `scheduledCompletionDate` | Required | Unix time. |
| `statusOverrides[].milestones[].status` | — | — | **No counterpart.** See below. |
| `statusOverrides[].milestones[].completedAt` | — | — | No counterpart on the milestone itself; reaches eMASS only as the parent POA&M's `completionDate`. |
| `statusOverrides[].milestones[].completedBy` | — | — | No counterpart. eMASS has `createdBy`, read-only, naming whoever created the milestone there. |
| `statusOverrides[].milestones[].title` | — | — | No counterpart; eMASS milestones have a description only. |

An eMASS milestone has no progress status. Its `reviewStatus` is read-only and belongs to the approval chain, not to the milestone's own completion. So HDF's `pending`/`inProgress`/`completed` does not survive the push, and a milestone's completion state is visible in eMASS only indirectly, through the parent POA&M.

## Artifacts

eMASS schemas `ArtifactsRequiredFields`, `ArtifactsOptionalFields`, `ArtifactsReadOnlyFields`. HDF's counterparts are the evidence package's `externalEvidence[]` and `contents[]`.

**Natural key:** `filename`. An upload whose filename matches an existing artifact updates it; an unmatched filename creates a new one, which makes this the one entity with genuine upsert semantics. **Write:** `POST` to add, `PUT` to update.

The upload is `multipart/form-data` carrying a zip archive, and `filename` names a file *inside* that archive — the specification says it "should match exactly one file within the provided zip file". So pushing artifacts means assembling a zip of the package's external evidence and naming each member, not posting files individually.

| HDF | eMASS field | Required | Notes |
|-----|-------------|----------|-------|
| `externalEvidence[].uri` basename | `filename` | Required | The natural key. |
| — | `isTemplate` | Required | Always `false` for pushed evidence. |
| — | `type` | Required | **Operator input.** "Artifact type options", with no enum in the specification; valid values are instance-defined. |
| — | `category` | Required | **Operator input.** Same, "Artifact category options". |
| `externalEvidence[].sourceName` | `name` | Optional | 100-character limit. |
| `externalEvidence[].description` | `description` | Optional | 10,000-character limit. |
| `requirements[].tags.nist` | `controls` | Optional | |
| `signature.signedAt` | `signedDate` | Optional | Unix time, when the package is signed. |
| `externalEvidence[].integrity` | — | — | **No counterpart.** eMASS computes `fileSize` and `mimeContentType` itself and stores no caller-supplied digest. |

## HDF with no eMASS counterpart

These are carried by an evidence package and have nowhere to go. A push records them in its receipt so the omission is visible, but eMASS will not hold them.

| HDF | Why there is no counterpart |
|-----|------------------------------|
| `integrity` | eMASS stores no package-level hash. It computes `fileSize` and `mimeContentType` per artifact and nothing across a submission. |
| `completenessCheck` | An eMASS system's completeness is its own workflow's concern, assessed in the Control Approval Chain rather than asserted by a submitter. |
| `signature` | Only the artifact `signedDate` survives; the signature itself has no field. |
| `contents[].checksum` | Per-document checksums have no eMASS equivalent. |
| `planRef` | eMASS has no assessment-plan reference on a system. |
| `milestones[].status`, `.completedBy`, `.title` | As above: eMASS milestones carry description and schedule only. |
| `effectiveStatus` of `notReviewed` or `error` | Outside eMASS's three-value compliance vocabulary. |
| `requirements[].results[]` beyond the first | eMASS records one test result per control and assessment procedure; a requirement with several results must be rolled up, and the roll-up is lossy. |

## Operator input

Fields eMASS requires, or conditionally requires, that an HDF evidence package cannot supply. In this epic they come from operator configuration rather than from the package.

**A POA&M pushed this way is therefore partly operator assertion, not assessment output.** That distinction matters to anyone reading the result in eMASS, so a push receipt marks operator-supplied values separately from package-derived ones. A reader who cannot tell the two apart cannot tell what the scan actually found.

| eMASS field | Entity | Why HDF cannot supply it |
|-------------|--------|---------------------------|
| `assessmentProcedure` | test result | HDF identifies requirements by its own id, NIST control and CCI, not by eMASS procedure. |
| `testedBy` | test result | A scanner result has no human tester. |
| `pocOrganization` | POA&M | HDF's `Identity` has no organization. |
| `resources` | POA&M | Programmatic, not assessment data. |
| `pocFirstName`, `pocLastName`, `pocPhoneNumber` | POA&M | HDF's `Identity` is a single identifier string with a type. |
| the resourcing block | POA&M | HDF models no funding or effort. |
| `type`, `category` | artifact | eMASS taxonomies with no enum in the specification. |

The durable fix for the POA&M entries is for HDF amendments to carry remediation ownership and resourcing as first-class fields, so a push derives them instead of an operator asserting them per system. That is a schema change tracked separately from this work, and it would retire most of this table.

## Unresolved

**Correlating an HDF amendment to a pre-existing eMASS POA&M on a first push.** Artifacts key on filename and test results on control plus assessment procedure, but a POA&M has no natural key. Once a push has run, its receipt records which eMASS id each amendment produced, so later pushes correlate from the receipt. The first push against a system that already holds POA&Ms has no such record. Writing `externalUid` from `requirementId` establishes the handle going forward but does not help with POA&Ms eMASS already had.
