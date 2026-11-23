# HDF to eMASS crosswalk

What each part of an HDF evidence package corresponds to in eMASS, what has no counterpart in either direction, and which eMASS fields an operator must supply because HDF does not carry them.

Written against the eMASS REST API specification **v3.22**, read from `docs/eMASSRestOpenApi.yaml` in [`mitre/emass_client`](https://github.com/mitre/emass_client) (sha256 `4124a3c7926769e1f06a0a34480c51e670614b58295d515196dc13600ad65f37`). Every eMASS field below is named as that specification names it, in the schema it belongs to. Where a value cannot be derived from an evidence package it is marked **operator input** — see [Operator input](#operator-input).

## How to read this

eMASS groups most entities' fields into `*RequiredFields`, `*ConditionalFields`, `*OptionalFields` and `*ReadOnlyFields` schemas, composed into the write body with `allOf`. A write must satisfy the required group and whichever conditionals apply; read-only fields are returned but never sent. POA&Ms, controls and the hardware and software baselines follow that pattern; artifacts follow it without a conditional group. Two entities depart from it. **Test results have no group schemas at all** — their requirements come from the `[Required]` markers inside `TestResultsGet` and from the write body's own `required` list. **Milestones have `MilestonesRequiredPost` and `MilestonesRequiredPut` but not the rest of the quartet**, and those two name their fields inside `properties.milestones.items.required` rather than at the schema root.

One property of the API shapes everything here: **no entity a push writes reports when it last changed.** `createdDate` exists on POA&M items and milestones only — artifacts, test results and controls carry no creation timestamp either — and none of them reports a modification timestamp. A client therefore cannot tell from eMASS alone whether one of those records has been edited since it was read, and conflict detection is layered to work without one.

The specification does carry one last-edit timestamp, on a surface a push does not write: `WorkflowInstanceGet.lastEditedDate` ("[Read-Only] Date the workflow was last acted on") and its companion `lastEditedBy`, returned by `GET /api/workflows/instances`. It describes a workflow instance — a package moving through approval — not the POA&M, artifact or test result inside it, so it cannot date a record a push would overwrite. It is worth knowing anyway: POA&M items lock while their package is in an active workflow, so a workflow instance's last-acted-on date is evidence about *why* a write may be refused, even though it cannot tell you whether a particular POA&M changed. `ControlsReadOnlyFields.modifiedByOverlays` is a related near-miss — it names what modified a control's values, not when — and so is `ArtifactsOptionalFields.lastReviewedDate`, which a caller supplies rather than eMASS maintaining.

## Identity: the join key

| HDF | eMASS | Notes |
|-----|-------|-------|
| `hdf-system.identifier` | `systemId` | The join. Documented in HDF as "System identifier from an authoritative source. Example: eMASS system ID, FedRAMP package ID." |
| `hdf-system.identifierScheme` | — | A push reads the identifier as an eMASS system id only when this is `https://emass.mil`. That is this tool's rule, not the specification's — HDF documents the value as an example, and eMASS never sees the field. |
| `components[].externalIds.emass` | `systemId` | Per-component alternative, written by `hdf label set --external-id emass=<id>`. |

A push never creates an eMASS system. If `identifier` resolves to no system the push fails and names the identifier.

## Test results

eMASS schema `TestResultsGet`. Write is a batch `POST` to `/api/systems/{systemId}/test-results` whose response reports a per-object outcome, so a partial success is normal and must be read per item.

**Natural key:** control acronym plus assessment procedure. **Write:** `POST` only; there is no update operation.

| HDF | eMASS field | Required | Notes |
|-----|-------------|----------|-------|
| `hdf-system.identifier` | `systemId` | Required | |
| `baselines[].requirements[].tags.nist` | `control` | Read-only | eMASS derives it; sent implicitly via the assessment procedure. |
| — | `cci` | Read-only on write | `TestResultsRequestPostBody` carries only `testedBy`, `testDate`, `description`, `complianceStatus` and `assessmentProcedure`. eMASS appears to derive `cci` from the assessment procedure — its artifact schema calls `ccis` the "CCI mapping for Assessment Procedures", though the test-result endpoint does not say so outright — and either way HDF's `baselines[].requirements[].tags.cci` cannot reach a test result even though it holds the data. |
| — | `assessmentProcedure` | Required | **Operator input.** HDF names the requirement by its own id and by NIST control and CCI, not by an eMASS assessment procedure. |
| `runner.operator.identifier` | `testedBy` | Required | Partly derivable. `runner.operator` is "the identity of the person or system responsible for executing the test" — a human auditor for a manual assessment, a tool or CI system otherwise. eMASS wants "Last Name, First Name", so an automated run still needs **operator input** to name a responsible person. 100-character limit. |
| `baselines[].requirements[].results[].startTime` | `testDate` | Required | Unix time; HDF is RFC3339 and converts. |
| `baselines[].requirements[].results[].codeDesc` | `description` | Required | 4000-character limit; HDF prose is unbounded and must be truncated. |
| `baselines[].requirements[].effectiveStatus` | `complianceStatus` | Required | Mapped, see below. |

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

Skipping is not the end of it. **On the surfaces a push writes there is no way to say that a prior answer is no longer backed by a scan.** A control's own `complianceStatus` is `[Read-only]` — eMASS derives it from the test results attached to the control — `TestResultsRequestPostBody` carries only the five fields above, `complianceStatus` admits only `Compliant`, `Non-Compliant` and `Not Applicable`, and there is no `DELETE` on `/test-results`. So if an earlier push recorded `Compliant` and the current package reports `notReviewed`, eMASS keeps showing `Compliant`.

eMASS does hold that vocabulary elsewhere, on a surface this crosswalk does not map. `ContainerScanRequestPostBody.benchmarks[].results[].status` admits `Not Reviewed` and `Not Checked` alongside `Pass` and `Fail`, keyed by a `ruleId` whose own example is `SV-230221r743913_rule` — the shape of an HDF requirement id from a STIG scan — and its sibling `ContainerScanRequestPostBody.benchmarks[].isBaseline` replaces every existing compliance result for that benchmark in one call, which is a retraction mechanism. That surface takes a container scanner's own output shape rather than a test result, and mapping it is the scan-ingestion work recorded as out of scope below. It is the reason the limitation is a property of the chosen surfaces and not of eMASS.

A push must not leave that silent. It reports the staleness on its own output — named in the dry-run diff, recorded in the receipt under its own skip reason, and written to stderr on a committing run so a CI log carries it even when the receipt is discarded. Nothing is written to eMASS: no field on the test-result or control surface can carry it, and the two ways to close the gap there — deleting the prior result, or moving the requirement onto the container-scan path — are both beyond what a push does.

## POA&M items

eMASS schemas `PoamRequiredFields`, `PoamConditionalFields`, `PoamOptionalFields`, `PoamReadOnlyFields`. HDF's counterpart is a `Standalone_Override` of POA&M type in an amendments document.

**Natural key:** no natural key exists. Correlating an HDF amendment to a pre-existing eMASS POA&M is an open problem; see [Unresolved](#unresolved). **Write:** `POST` to create, `PUT` to update.

| HDF | eMASS field | Group | Notes |
|-----|-------------|-------|-------|
| derived — see below | `status` | Required | eMASS admits `Ongoing`, `Risk Accepted`, `Completed`, `Not Applicable`, `Archived`. **Not** `overrides[].status`, which is a `Result_Status` (`passed`/`failed`/…) describing the requirement's posture, not the remediation's lifecycle. |
| `overrides[].reason` | `vulnerabilityDescription` | Required | 2000-character limit. |
| `tool.name` + `overrides[].requirementId` | `sourceIdentifyingVulnerability` | Required | 2000-character limit. |
| — | `pocOrganization` | Required | **Operator input.** 100-character limit. |
| — | `resources` | Required | **Operator input.** 250-character limit. |
| — | `identifiedInCFOAuditOrOtherReview` | Required | Defaults to `false` when unspecified. |
| `overrides[].appliedBy.identifier` | `pocEmail` | Conditional | eMASS requires it once `pocFirstName`, `pocLastName` or `pocPhoneNumber` has data — so supplying any of those operator-input fields makes this required. Usable only when the identity's `type` is `email`. |
| — | `pocFirstName`, `pocLastName`, `pocPhoneNumber` | Conditional | **Operator input.** HDF's `Identity` is `{identifier, type, description}` and carries no name parts or phone. 100 characters each; the phone field documents an `(area code) ***-****` format. |
| `overrides[].milestones[].estimatedCompletion` | `scheduledCompletionDate` | Conditional | Required for ongoing and completed items. |
| `overrides[].milestones[].completedAt` | `completionDate` | Conditional | Required for completed items. |
| `baselines[].requirements[].poams[].explanation` | `comments` | Conditional | Required for completed and risk-accepted items. HDF's `POAM` primitive requires `explanation`, "Detailed explanation of the plan, including what actions will be taken" — prose about the remediation, which is what this field wants. Use it when the requirement carries a POA&M; it is **operator input** only when none does. 2000-character limit. Do **not** write `overrides[].justification`, a VEX controlled-vocabulary enum (`component_not_present`, `vulnerable_code_not_in_execute_path`, …) that produces an unreadable comment, and do not reuse `reason`, which `vulnerabilityDescription` already carries. |
| — | the resourcing block | Conditional | **Operator input**, see below. |
| `overrides[].requirementId` | `externalUid` | Optional | Gives eMASS a handle on the HDF requirement. 100-character limit, against an unbounded HDF field — a long id truncates. |
| `baselines[].requirements[].tags.nist` | `controlAcronym` | Optional | |
| `baselines[].requirements[].severity` | `severity` | Conditional | Required for approved items — though `reviewStatus` (`Not Approved`/`Under Review`/`Approved`) is `[Read-only]`, so a push cannot put an item into that state and the condition never binds at create time. HDF's five-band `critical`/`high`/`medium`/`low`/`informational` maps onto eMASS's `Very High`/`High`/`Moderate`/`Low`/`Very Low`. |
| `overrides[].cvss.baseScore` | `rawSeverity` | Optional | **Lossy, and the thresholds are a decision this page does not make.** CVSS gives a 0.0–10.0 number; `rawSeverity` takes the same five prose bands as `severity`. CVSS v3.1's own qualitative ranges are the obvious source but there are four of them, not five, so a push must define the mapping explicitly rather than inherit one. |
| `overrides[].impact.value` | `impact` | Optional | eMASS uses a Very Low to Very High band, HDF a 0.0–1.0 score. |

### Deriving the POA&M status

eMASS's `status` is a remediation lifecycle; HDF has no single field for it. It is derived:

| eMASS `status` | derived from |
|----------------|--------------|
| `Risk Accepted` | `overrides[].type` is `riskAdjustment` or `operationalRequirement` |
| `Not Applicable` | `overrides[].type` is `falsePositive`, or `overrides[].status` is `notApplicable`. Note eMASS updates an item already in this status through test-result creation rather than the POA&M endpoint |
| `Completed` | every entry in `overrides[].milestones[]` has `status: completed` |
| `Ongoing` | any milestone is `pending` or `inProgress` |
| `Archived` | no HDF source — eMASS-side lifecycle state only |

`overrides[].type` admits `waiver`, `attestation`, `poam`, `inherited`, `falsePositive`, `riskAdjustment` and `operationalRequirement`; only some of those describe a remediation at all, so a push writes POA&Ms for the subset that does.

### Write rules that constrain the order

eMASS enforces business rules a push must honor, not just field requirements:

- A `Completed` or `Ongoing` POA&M **cannot be saved without milestones**, and `PoamRequestPostBody` composes `MilestonesRequiredPost` — so milestones go in the POA&M create, not only through the milestones endpoint.
- A `Risk Accepted` POA&M **cannot have** a `scheduledCompletionDate` or milestones.
- eMASS **cross-validates the milestone and POA&M dates**: while an item is `Not Approved` its milestone `scheduledCompletionDate` may not exceed the POA&M's own, and once `Approved` it may only be saved if the milestone date *does* exceed it. Both come from the same HDF source — `overrides[].milestones[].estimatedCompletion` feeds the milestone date and the POA&M's `scheduledCompletionDate` alike — so a push must not write the same value to both.
- A `Completed` item **cannot be saved with a `completionDate` in the future**, which constrains `overrides[].milestones[].completedAt` directly.
- An `Approved`, `Completed` **or** `Ongoing` POA&M cannot have its `scheduledCompletionDate` updated — `Ongoing` being the common case for an open finding, so this blocks re-scheduling the very items a re-push is most likely to touch. An archived item cannot be updated at all, and items in an active package are locked.
- A POA&M item **cannot be saved if its security control or assessment procedure is inherited**, which matters because HDF models inheritance directly as `overrides[].type: inherited` with `inheritedFrom`. Such an override must not be pushed as a POA&M.
- An item whose status is `Not Applicable` is updated **through test-result creation**, not through the POA&M endpoint.
- A `PUT` additionally requires `poamId` and `displayPoamId`; a milestone `PUT` requires `milestoneId`. Those come from the previous push's receipt, which is why correlation matters.
- **`isActive` is required on the milestones array of a POA&M `PUT`**, not on the milestones endpoint's own `PUT`. `MilestonesRequiredPut` names it inside `properties.milestones.items.required` and composes into `PoamRequestPutBody`, while `MilestonesRequestPutBody` — the body for `PUT /poams/{poamId}/milestones` — requires only `milestoneId`, `description` and `scheduledCompletionDate` and has no `isActive` at all. It is the field that keeps a re-push from duplicating milestones: the specification directs a client to include it set to `false` to avoid uploading duplicate or undesired milestones, and uses it to delete a milestone while updating a POA&M. It has no HDF source — nothing in an evidence package says a milestone should be removed — so it is **operator input**, and a push that omits it on a `PUT` is both invalid and the likeliest cause of milestone duplication. Its own description calls it `[Conditional]` while the schema lists it as required; treat the schema as binding.

### Instance-dependent requirements

Some eMASS instances require the Risk Analysis fields on a POA&M write: `severity`, `relevanceOfThreat`, `likelihood`, `impact`, `residualRiskLevel` and `mitigations`. Only `severity` and `impact` have an HDF source; the rest are **operator input** where an instance demands them. `identifiedInCFOAuditOrOtherReview` is likewise instance-dependent — required for VA, optional for Army and USCG — and absent from `PoamRequestPostBody.required`.

### The resourcing block

`PoamConditionalFields` includes a funding model: `personnelResourcesFundedBaseHours`, `personnelResourcesCostCode`, `personnelResourcesUnfundedBaseHours`, `personnelResourcesNonfundingObstacle`, `personnelResourcesNonfundingObstacleOtherReason`, and five `nonPersonnelResources*` equivalents (`FundedAmount`, `CostCode`, `UnfundedAmount`, `NonfundingObstacle`, `NonfundingObstacleOtherReason`). On a VA instance the specification requires at least one of four specifically — funded and unfunded personnel base hours, and funded and unfunded non-personnel amounts — so the cost-code and nonfunding-obstacle members do not satisfy it.

HDF models none of it. It describes what an assessment found, not who owns remediating it or what that costs. All of these are **operator input**.

## Milestones

eMASS schema `MilestonesGet`, under `/api/systems/{systemId}/poams/{poamId}/milestones`.

**Natural key:** parent POA&M plus description. **Write:** `POST` to create, `PUT` to update.

| HDF | eMASS field | Required | Notes |
|-----|-------------|----------|-------|
| `overrides[].milestones[].description` | `description` | Required | 2,000-character limit, against an unbounded HDF field. |
| `overrides[].milestones[].estimatedCompletion` | `scheduledCompletionDate` | Required | Unix time. |
| `overrides[].milestones[].status` | — | — | **No counterpart.** See below. |
| `overrides[].milestones[].completedAt` | — | — | No counterpart on the milestone itself; reaches eMASS only as the parent POA&M's `completionDate`. |
| `overrides[].milestones[].completedBy` | — | — | No counterpart. eMASS has `createdBy`, read-only, naming whoever created the milestone there. |
| `overrides[].milestones[].title` | — | — | No counterpart; eMASS milestones have a description only. |

An eMASS milestone has no progress status. Its `reviewStatus` is read-only and belongs to the approval chain, not to the milestone's own completion. So HDF's `pending`/`inProgress`/`completed` does not survive the push, and a milestone's completion state is visible in eMASS only indirectly, through the parent POA&M.

## Artifacts

eMASS schemas `ArtifactsRequiredFields`, `ArtifactsOptionalFields`, `ArtifactsReadOnlyFields`. HDF's counterpart is the evidence package's `externalEvidence[]` — the external files a package points at. Its `contents[]` is *not* a second source: those entries reference the package's own HDF documents rather than files to upload, and have no eMASS counterpart.

**Natural key:** `filename`. The `POST` description says an upload whose filename matches an existing artifact updates it and an unmatched filename creates a new one, which would make this the one entity with genuine upsert semantics. **The same endpoint's business rules contradict that**, stating an artifact version cannot be saved if an artifact with the same filename already exists and that filename uniqueness is enforced by the API for both methods. The specification does not resolve which governs, so an implementation must not rely on upsert until it is confirmed against a live instance — and a push that assumes it will either duplicate or fail on every re-push of the same evidence file. **Write:** the `POST` carries the file as `multipart/form-data`; a `PUT` updates the metadata, since the specification directs that "to update values other than the file itself, please submit a PUT request". The `PUT` replaces every field, so one that is omitted is nulled rather than left alone.

The upload is `multipart/form-data`, and the `isBulk` query parameter decides its shape. It **defaults to `false`**, where "an individual artifact file is expected"; set to `true`, "a .zip file is expected which can contain multiple artifact files". So a push may post files one at a time or batch them into an archive, and the choice is ours.

Note that `filename` means two different things. In the `POST` body it is the binary file being uploaded. On the metadata side — `ArtifactsRequiredFields` — it is the name used to match an existing artifact, and that is where the "should match exactly one file within the provided zip file" wording belongs.

| HDF | eMASS field | Required | Notes |
|-----|-------------|----------|-------|
| `externalEvidence[].uri` basename | `filename` | Required | The natural key. 1,000-character limit, and eMASS caps an artifact at 30MB. |
| — | `isTemplate` | Required | `false`. The specification sets this as a create-time default. |
| — | `type` | Required | The specification documents nine values — `Procedure`, `Diagram`, `Policy`, `Labor`, `Document`, `Image`, `Other`, `Scan Result`, `Auditor Report` — in the field's description rather than as a JSON `enum`, and notes an instance may add its own. `Other` is the documented create-time default, but **`Scan Result` is the honest value for an evidence package's scanner output** and is derivable from the converter that produced the document, so it is not operator input. |
| — | `category` | Required | Two documented values, `Implementation Guidance` and `Evidence`, again in prose and again instance-extensible. `Evidence` is both the documented default and the correct value here. |
| — | `name` | Optional | 100-character limit. **Operator input**, though rarely needed: `External_Evidence_Reference` has no display name (`sourceName` belongs to `External_Reference`, a different type), and the specification defaults `name` to `filename` on a `PUT`. A `POST` documents no default for it — "any values not specified below will be null" — so a create either supplies it or leaves it null. |
| `externalEvidence[].description` | `description` | Optional | 10,000-character limit. |
| `baselines[].requirements[].tags.nist` | `controls` | Optional | |
| `signature.created` | `signedDate` | Optional | Unix time, when the package is signed. |
| `externalEvidence[].checksum` | — | — | **No counterpart on an artifact.** eMASS computes `fileSize` and `mimeContentType` itself and accepts no digest here. It does accept one on the software baseline (`SwBaselineOptionalFields.cryptographicHash`), a surface this push does not write. |

## HDF with no eMASS counterpart

These are carried by an evidence package and have nowhere to go. A push records them in its receipt so the omission is visible, but eMASS will not hold them.

| HDF | Why there is no counterpart |
|-----|------------------------------|
| `integrity` | eMASS stores no package-level hash. It computes `fileSize` and `mimeContentType` per artifact and nothing across a submission. |
| `completenessCheck` | An eMASS system's completeness is its own workflow's concern, assessed in the Control Approval Chain rather than asserted by a submitter. |
| `signature` | Only the artifact `signedDate` survives; the signature itself has no field. |
| `planRef` | eMASS has no assessment-plan reference on a system. |
| `packageId`, `preparedAt`, `preparedBy` | Package-level provenance. eMASS records who submitted through its own workflow, not as submitted metadata. |
| `systemRef` | Superseded by `systemId` as the join; the HDF reference itself has no field. |
| `generator` | eMASS does not record which converter produced a submission. |
| `contents[].type`, `.uri`, `.componentRef`, `.checksum`, `.description` | Document references, the whole type. eMASS holds artifacts, not references to HDF documents, and has no per-document checksum. |
| `externalEvidence[].format`, `.mediaType`, `.formatVersion` | eMASS derives `mimeContentType` from the file extension itself. |
| `externalEvidence[].metadata.recordCount`, `.timeRange`, `.collector` | Telemetry-corpus description with no eMASS counterpart. |
| `tool`, `runner`, `statistics`, `derivation` | Scan provenance. Only `tool.name` reaches eMASS, inside `sourceIdentifyingVulnerability`, and only `runner.operator` inside `testedBy`. |
| `overrides[].cvss.baseVector`, `.baseSeverity`, `.version`, `.source`, `.computedScore`, `.computedSeverity`, `.threatScore`, `.threatVector`, `.environmentalScore`, `.environmentalVector`, `.supplementalVector` | Everything the CVSS object carries except `overrides[].cvss.baseScore`, which reaches eMASS as the `rawSeverity` band above. The vector, the version, who computed the score, and every threat or environmental adjustment have no eMASS field. |
| `baselines[].requirements[].cvss[]`, `.cwe[]`, `.epss`, `.kev` | Vulnerability enrichment. eMASS carries only a single `rawSeverity` string. |
| `baselines[].requirements[].disposition`, `.effectiveImpact`, `.effectiveChecksum` | Override-resolution results, computed HDF-side and not modeled by eMASS. |
| `baselines[].requirements[].descriptions[]` | Only a test result's single `description` reaches eMASS, truncated to 4000 characters, so the labeled description set collapses to one string. |
| `baselines[].requirements[].results[].message`, `.backtrace[]`, `.resource`, `.runTime`, `.rawSourceRecord` | Per-result detail. eMASS keeps one prose `description` per result. |
| `components[]` | See below. |
| `overrides[].appliedBy.type`, `.description` | Which kind of identity applied the override, and a note about it. Only the identifier reaches eMASS, as `pocEmail`, and only when the type is `email`; eMASS's POC fields are name and phone parts rather than a typed identity. |
| `overrides[].expiresAt` | **Required on every override, and eMASS's POA&M cannot hold it.** It time-boxes the acceptance; eMASS's `extensionDate` is read-only and its POA&M has no expiry a client can set. A push drops the one field saying when the acceptance stops being valid, so the receipt must carry it. |
| `overrides[].componentRef` | Scopes an override to a single component. eMASS's POA&M is system-wide, so a component-scoped amendment pushed as-is asserts more than the amendment did. `devicesAffected` is the nearest thing and is Navy only. |
| `overrides[].baselineRef`, `.affectedPackages[]`, `.externalReferences[]`, `.inheritedFrom` | Which baseline and packages an override applies to, and its outbound links. eMASS has no field for any of them. |
| `overrides[].appliedAt`, `.signature`, `.previousChecksum`, `.evidence[]` | Amendment provenance and the chain linking revisions. eMASS dates a submission itself and holds no signature or prior-version pointer. |
| `amendmentId`, `approvedBy`, `appliedBy` (amendments root) | Document identity and the approving authority. eMASS records approval through its own workflow, not as submitted data. |
| `name`, `description`, `version`, `labels`, `extensions` (amendments root) | Amendment-document identity and passthrough, as for the other two documents. eMASS's unit is the POA&M item, not the document that carried it. |
| `overrides[].milestones[].status`, `.completedBy`, `.title` | As above: eMASS milestones carry description and schedule only. |
| `effectiveStatus` of `notReviewed` or `error` | Outside eMASS's three-value compliance vocabulary. |
| `baselines[].maintainer`, `.license`, `.copyright`, `.copyrightEmail`, `.summary`, `.version`, `.name`, `.title`, `.description` | Baseline identity and provenance, largely inherited from the InSpec profile a scan ran. eMASS holds the control catalog itself and records no statement about the baseline that produced a result. |
| `baselines[].status`, `.statusMessage` | Whether the baseline itself loaded and ran. eMASS has no field for the health of the thing that produced a submission. |
| `baselines[].groups[]`, `.inputs[]`, `.depends[]`, `.supports[]`, `.parentBaseline` | Profile structure — control grouping, parameterization, profile dependencies, platform support and the overlay parent. eMASS models none of it; a push flattens the chain and sends only the resolved requirements. |
| `baselines[].resultsChecksum`, `.originalChecksum`, `.integrity` | Per-baseline integrity. Same as the package level: eMASS stores no caller-supplied digest on any surface a push writes. |
| `baselines[].labels`, `.extensions`, `.externalReferences[]` | Baseline-level labeling and passthrough. |
| `baselines[].requirements[].id`, `.externalReferences[]` | The HDF requirement's own identity and links. `externalUid` carries the id onto a POA&M, but a test result has no field for it. |
| `baselines[].requirements[].title`, `.code`, `.impact`, `.applicability`, `.controlType`, `.verificationMethod` | Requirement definition. eMASS holds the control catalog itself, so a push names a control rather than describing it. `impact` reaches eMASS only indirectly, as the `severity` band. |
| `baselines[].requirements[].affectedPackages[]`, `.refs[]`, `.sourceLocation` | Where a finding lives and what it affects. eMASS's nearest field is `PoamOptionalFields.devicesAffected`, a hostname list, which `components[]` supplies instead. |
| `baselines[].requirements[].statusOverrides[]` | The in-results override record. eMASS has no per-result adjudication trail; what a push sends is the resolved POA&M, and `disposition` above records the resolution. |
| `baselines[].requirements[].poams[].type`, `.appliedBy`, `.appliedAt`, `.expiresAt`, `.previousChecksum`, `.signature` | HDF's POA&M model beyond `baselines[].requirements[].poams[].explanation` and `.milestones[]`. eMASS's POA&M carries no amendment chain and no signature, and its dates are a scheduled and a completion date rather than an applied-at or an expiry — it does expose `createdDate`, `extensionDate` and `pendingExtensionDate`, all read-only. |
| `baselines[].requirements[].poams[].evidence[]`, `baselines[].requirements[].evidence[]`, `overrides[].evidence[]` | **Attached evidence, and the limit here is write access rather than absence.** `PoamReadOnlyFields.artifacts` lists "the filenames of any artifact files attached to the POA&M Item", so eMASS does model the attachment — but it is read-only there, and no artifact write field carries a `poamId` — `ArtifactsRequiredFields` and `ArtifactsOptionalFields` offer no POA&M association at all, only `controls` and `assessmentProcedures`, so a push cannot create the association from either side. HDF's `Evidence` primitive carries `data`, `mimeType`, `size` and `encoding`, which for a `code` or `log` entry is content that could instead be uploaded as an artifact against the control or assessment procedure. An entry whose `type` is `url` is a reference rather than content, and closer to `externalEvidence[]`. **This page does not take that option**: it would turn evidence embedded in a document into separate uploaded files with their own filenames and lifecycle, which is a design decision for the push, not a field mapping. |
| `baselines[].requirements[].results[].status`, `.exception`, `.resourceId` | Per-result detail. Only the rolled-up `complianceStatus` and one `description` reach a test result. |
| `timestamp`, `preAmendmentChecksum`, `externalReferences[]`, `extensions`, `id` (results root) | Document-level provenance and passthrough. eMASS dates a submission itself and holds no document identity. |
| `remediation` (results root) | "Reference to automated remediation resources for implementing security controls" — Ansible playbooks, Terraform. eMASS's POA&M records what *will* be done in prose, through `comments` and the milestone `description`, and has no field for a pointer to automation that does it. |
| `name`, `description`, `version`, `labels`, `externalReferences[]`, `extensions` (evidence-package root) | Package identity and metadata. eMASS's unit is the system, not the package. |
| `baselines[].requirements[].results[]` beyond the first | A test result carries one `description` and one `complianceStatus`, so a requirement with several results must be rolled up and the roll-up is lossy. eMASS **accumulates** test results rather than replacing them: `GET /test-results` takes a `latestOnly` parameter defaulting to `true`, "Indicates that only the latest test resultes are retrieved", which only makes sense if earlier results are retained. A re-push therefore appends, and this roll-up loss is permanent in the record. How eMASS picks "latest" among several written in one call is not stated and needs a live instance. |

## System inventory

HDF's `components[]` describes the hosts, images, cloud accounts and other targets an assessment ran against. eMASS has two surfaces that cover the same ground — `/api/systems/{systemId}/hw-baseline` and `/sw-baseline`, each with full `POST`/`PUT`/`DELETE` and its own required, conditional, optional and read-only groups — plus `PoamOptionalFields.devicesAffected`, "list any affected devices by hostname".

**Mapping the inventory is out of scope for this crosswalk.** Pushing an evidence package means pushing what the assessment found, and a hardware or software baseline is a statement about what the system *is*, maintained on its own cadence. Writing it from a scan's incidental component list would assert an inventory nobody curated. The one exception worth taking is `devicesAffected`, derivable from the components a requirement's results reference — though the specification marks it **Navy only**, so not every instance will accept it. Every one of the resourcing block's ten fields is likewise marked VA only.

## Write surfaces this crosswalk does not map

The specification exposes fourteen write paths. This page maps four — `POST /test-results`, `POST`/`PUT`/`DELETE /poams`, the milestone paths under a POA&M, and `/artifacts`. The other ten are recorded here so a reader checking the page against eMASS finds nothing silently unaccounted for.

| Path | Why it is not mapped |
|------|----------------------|
| `POST`/`PUT`/`DELETE /hw-baseline`, `/sw-baseline` | System inventory, above — a statement about what the system *is*. `SwBaselineOptionalFields.cryptographicHash` is worth noting as the one place eMASS accepts a caller-supplied digest, though on a surface this push does not write. |
| `POST /device-scan-results`, `/container-scan-results`, `/cloud-resource-results`, `/static-code-scans` | **The closest structural match in eMASS to an HDF results document**, and deliberately out of scope here. Each takes a scanner's own output shape rather than a POA&M or test result, and they line up with HDF `components[]` types — `containerImage` with the container path, `cloudAccount` with the cloud-resource path. Mapping them is a larger piece of work than this epic: it would make the push a scan-ingestion path as well as a compliance-record path, and the two have different idempotency and different audiences. Recorded as a candidate, not a gap. |
| `POST /approval/pac`, `/approval/cac` | Package and control approval — moving a package through its workflow, which is a human decision a tool should not take. |
| `PUT /controls` | **Not a push target, despite being the surface a compliance tool would reach for first.** A control's `complianceStatus` is `[Read-only]` — eMASS derives it from the attached test results — so the one field an assessment could speak to cannot be written. What `ControlsRequestPutBody` requires is `acronym`, `responsibleEntities`, `controlDesignation`, `estimatedCompletionDate` and `implementationNarrative`: authorization-package authoring, none of it carried by an evidence package. A push therefore moves a control's compliance by writing test results, never by writing the control. |
| `POST /api-key` | Client registration, not system data. |

## Operator input

Fields eMASS requires, or conditionally requires, that an HDF evidence package cannot supply. In this epic they come from operator configuration rather than from the package.

**A POA&M pushed this way is therefore partly operator assertion, not assessment output.** That distinction matters to anyone reading the result in eMASS, so a push receipt marks operator-supplied values separately from package-derived ones. A reader who cannot tell the two apart cannot tell what the scan actually found.

| eMASS field | Entity | Why HDF cannot supply it |
|-------------|--------|---------------------------|
| `assessmentProcedure` | test result | HDF identifies requirements by its own id, NIST control and CCI, not by eMASS procedure. |
| `testedBy` | test result | Partly derivable from `runner.operator`; an automated run still needs a responsible person named. |
| `name` | artifact | `External_Evidence_Reference` carries no display name. |
| `comments` | POA&M | Only when the requirement carries no `baselines[].requirements[].poams[]`. Where it does, `baselines[].requirements[].poams[].explanation` supplies this — see the POA&M table. |
| `relevanceOfThreat`, `likelihood`, `residualRiskLevel`, `mitigations` | POA&M | Risk-analysis fields some instances require; HDF models none of them. |
| `pocOrganization` | POA&M | HDF's `Identity` has no organization. |
| `resources` | POA&M | Programmatic, not assessment data. |
| `pocFirstName`, `pocLastName`, `pocPhoneNumber` | POA&M | HDF's `Identity` is a single identifier string with a type. |
| the resourcing block | POA&M | HDF models no funding or effort. |
| `isActive` | milestone | Required on a `PUT`; expresses an intent to retain or delete a milestone that an evidence package does not record. |

The durable fix for the POA&M entries is for HDF amendments to carry remediation ownership and resourcing as first-class fields, so a push derives them instead of an operator asserting them per system. That is a schema change tracked separately from this work, and it would retire most of this table.

## Unresolved

**Correlating an HDF amendment to a pre-existing eMASS POA&M on a first push.** Artifacts key on filename and test results on control plus assessment procedure, but a POA&M has no natural key. Once a push has run, its receipt records which eMASS id each amendment produced, so later pushes correlate from the receipt. The first push against a system that already holds POA&Ms has no such record. Writing `externalUid` from `requirementId` establishes the handle going forward but does not help with POA&Ms eMASS already had.
