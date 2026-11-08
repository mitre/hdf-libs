# HDF Status Determination

How hdf-libs determines the overall status of a control/requirement from its individual test results. This logic applies to all data sources (InSpec, SARIF, Nessus, XCCDF, etc.).

## Status Values

| Status | Meaning |
|---|---|
| `passed` | Control requirements are met |
| `failed` | One or more requirements are not met |
| `error` | A test execution error occurred |
| `notApplicable` | Control is not applicable to this target |
| `notReviewed` | Control was not evaluated (skipped, no results) |

### What a converter may claim

`passed` is the only status that makes an affirmative claim: this requirement was checked and met. Every exporter carries it as one — CKL `NotAFinding`, ASFF `PASSED`, XCCDF `pass`, ECS `success`, OSCAL-SAR `satisfied` — and `NotAFinding` is a compliance claim eMASS scores. So a converter may emit `passed` only where the **source** assessed the requirement.

That is not the same as forbidding a default branch. Some formats encode a pass as the absence of anything else, and reading them correctly means returning `passed` from the fall-through:

- JUnit: a `<testcase>` with no `<failure>`, `<error>` or `<skipped>` child passed. That is the format's own convention.
- A scanner that reports only violations: a clean run with no findings did assess the target and found nothing.
- A tool whose score encodes the verdict, where zero means "no finding" rather than "no data".

What is forbidden is a `passed` the converter invents because the source said nothing. The failure mode is a degenerate comparison of two empty values — this was `msft-secure-score-to-hdf`, where an unscored profile's `maxScore` decodes to 0 and the control's score is 0 too:

```go
// WRONG — an unscored control has maxScore 0, so this passes on 0 == 0
if cs.Score == maxScore {
    return hdf.Passed
}
```

Guard the unassessed case first and report `notReviewed`, which is what `scoutsuite-to-hdf` does:

```go
if checkedItems == 0 {
    return hdf.NotReviewed   // nothing was checked; that is not a pass
}
if flaggedItems == 0 {
    return hdf.Passed        // items were checked and none flagged
}
```

`conveyor-to-hdf` does the same for an absent score: its `Score` is a pointer, and a nil one yields `notReviewed` with the reason in the message rather than reaching the zero-means-clean comparison.

`notReviewed` is the honest substitute because it keeps the requirement in the compliance denominator: an unassessed requirement is outstanding work. `notApplicable` would be worse than wrong — it is excluded from the ratio entirely, so it flatters the number while asserting a scope decision nobody made. `error` claims a failure that did not happen.

The same rule governs a **derived** impact. Where a converter computes impact from a source field and that field is absent, do not let the arithmetic yield `0` — that asserts the requirement carries no risk, on the same missing evidence. Use the converter's unknown-severity default instead, as `msft-secure-score-to-hdf` does for a control with no matching profile and for one whose profile is unscored.

This applies to a derivation, not to a record the converter synthesizes itself. A placeholder requirement — `shared.BuildNoFindingsRequirement`'s clean-scan record, or `conveyor-to-hdf`'s stand-in for a service entry carrying no score — is informational by nature, and `impact: 0` describes the record honestly rather than making a claim about a control's risk.

## Precedence Order

When a control has multiple test results with different statuses, the overall status is determined by precedence (highest wins):

```
1. error          — any result errored → control is error
2. failed         — any result failed  → control is failed
3. passed         — any result passed  → control is passed
4. notApplicable  — only if all results are notApplicable
5. notReviewed    — only if nothing else matches (all skipped/notReviewed)
```

### Key Rules

- **`failed` + `passed` → `failed`**: One failure means the control fails
- **`passed` + `notReviewed` → `passed`**: A passing test proves the control works; a skipped test alongside it doesn't negate that
- **Impact does not affect status**: A status says what the assessment established; an impact says how much risk the requirement carries. The two are independent, so a requirement reports the same status at impact 0.0 as it would at 0.7. A source that conflates them — InSpec scores a control it considers inapplicable 0.0 and then reports no pass or fail for it — has that convention translated into an explicit `notApplicable` result by its importer, so the claim travels in `results[]` where every consumer can see it. See "Not Applicable is a result, not a score" below
- **A governing override outranks everything**: A non-expired `statusOverride` adjudicates uniformly — at any impact, over any roll-up, including `error`. See the effective-status ladder below
- **No results → `notReviewed`**: Nothing was established, at any impact

### The Effective-Status Ladder

The full effective-status computation combines the roll-up above with overrides in one fixed order:

```
1. governing override   — the most recent non-expired statusOverride's status
2. roll-up              — else the worst-wins roll-up (empty results → notReviewed)
```

`error` needs no rung of its own: it already outranks every other status in the worst-wins order, so an errored result reports `error` whatever else the requirement carries. That matches InSpec Enhanced Outcomes and Heimdall inspecjs, which both rank error above the Not Applicable determination.

The stored `effectiveStatus` field is **never an input** to this computation. The only sanctioned channel for a requirement's status to diverge from its results is a governing override; an unprovenanced stored value that contradicts the results — in either direction, optimistic (`passed` over failing results) or pessimistic (`error` over passing results) — is ignored and the ladder's answer wins. Source tools whose control-level verdict carries information the results array does not (for example a crashed tool that recorded only its passing sub-checks) must have that knowledge encoded into `results[]` by their converter — as a synthesized errored result — not smuggled through the stored field.

#### Checksum epochs

Requirement-change-event chains anchor their integrity in effective checksums, which hash the *resolved* effective status. When the ladder's semantics change (as in the change that introduced it), checksums computed by older binaries no longer match what a newer binary recomputes — a **checksum epoch**. A chain derived before an epoch boundary and verified after it reports `chainGap` warnings on the affected keys even though no events are missing. The warning text names both possible causes; the remedy for an epoch-crossing chain is to **re-derive it from a fresh rescan**, which re-anchors the chain under the current semantics. Event-chain verification deliberately does not accept old-epoch checksums — doing so would weaken the integrity claim for genuinely broken chains.

There have been two epochs. The first introduced this ladder. The second removed its `impact === 0 → notApplicable` rung, so an impact-0 requirement whose results establish nothing now resolves `notReviewed` where it previously resolved `notApplicable`, and any checksum over that requirement moves with it. In practice almost nothing is anchored on an affected status, and re-conversion from the original source — which supplies the explicit `notApplicable` result — settles both the status and the checksum together.

### Examples

| Results | Impact | Overall Status |
|---|---|---|
| `[passed]` | 0.7 | `passed` |
| `[failed]` | 0.7 | `failed` |
| `[passed, failed]` | 0.5 | `failed` |
| `[passed, notReviewed]` | 0.7 | `passed` |
| `[notReviewed]` | 0.5 | `notReviewed` |
| `[notReviewed]` | 0.0 | `notReviewed` |
| `[notReviewed, notApplicable]`† | 0.0 | `notApplicable` |
| `[passed, error]` | 0.5 | `error` |
| `[error]` | 0.0 | `error` |
| `[passed, error]` | 0.0 | `error` |
| `[]` (empty)*  | 0.0 | `notReviewed` |
| `[]` (empty)*  | 0.5 | `notReviewed` |

The impact column is there to show that it changes nothing: every row would read the same with any other value in it.

\* The v3 HDF schema enforces `results.minItems=1`, so empty results arrays should not appear in schema-valid HDF documents — converters synthesize a `passed` placeholder for clean scans (see `../specification/hdf-specification.md` § "Clean-scan convention"). The empty-results rows above remain a safety net for legacy HDF v2 (InSpec-ExecJSON-shaped) input that did not enforce the invariant.

† The shape an InSpec reader emits for a control scored 0.0: the scope claim is a result, so the roll-up reaches `notApplicable` without the ladder needing to know anything about InSpec.

## Where Status Is Computed

### effectiveStatus Field

The `effectiveStatus` field on `EvaluatedRequirement` carries the post-adjudication status a producer computed at write time. It is an **output cache, not an input**: the canonical `computeEffectiveStatus` never reads it — the ladder above computes from results, overrides, and impact alone, so a stale stored value (in either direction) cannot influence the answer. The field's correctness is a **write-path guarantee**: every producer (converters, the amendments-apply flow) must emit a value equal to what the ladder computes. External consumers that cannot run the computation — raw-JSON readers, dashboards, `jq` pipelines — may read the field directly and are relying on that write-path guarantee.

### Who resolves, and who deliberately does not

Every non-test read of a requirement's `impact`, `effectiveStatus` or `disposition` in this workspace was classified in one sweep, because the two defects found by hand before it (`hdf query` counting severity pre-adjudication while resolving status post-adjudication, and `hdf-to-csv` reporting a stored impact nothing accounted for) were both invisible to a passing test suite.

**The question is never "does this call the ladder". It is "which question is this reader answering".** A raw read is correct in about half these places. A reader is wrong only when its stated purpose is post-adjudication and its code is pre-adjudication.

| Reader | Reads | Why |
|---|---|---|
| `Filter` / `hdf query`, `hdf list`, MCP `hdf_query` | effective | Report a requirement's current posture; their status column already resolves overrides |
| `CountControlsByStatus`, `MapControlIDsByStatus`, MCP severity grouping | effective | Override-aware by contract; the injected status resolver is the giveaway |
| `CountControlsByStatusSeverity`, `MapControlIDs` | **raw, by design** | The documented no-override-awareness twins — that is their entire purpose |
| `hdf generate` control stubs (`hdf-generators`) | **raw, by design** | Generating a profile's declared impact, not reporting an assessment |
| `hdf-to-xccdf` severity | **raw, by design** | XCCDF severity describes the *rule*, not the outcome of running it |
| Checklist `resolveSeverity` (base severity) | **raw, by design** | CKL models base severity and `SEVERITY_OVERRIDE` separately; the base is the raw one |
| `hdf-diff` field comparisons, `hdf-extension-graph` modifications, `hdf-parsers` flatten | **raw, structural** | A differ reports that a *field* changed; the stored field is the subject, not a posture claim |
| `baselineAsResults` (MCP) | **raw, unavoidable** | A baseline document carries no results and no overrides |
| Reads of `statusOverrides[].impact.value` (`hdf-to-oscal-poam`, `hdf-to-cyclonedx-vex`, `hdf amend`) | n/a | The override's own field, not the requirement's |
| `hdf-diff` `ComputeEffectiveImpact` / `ComputeDisposition` | computes, then **falls back to the stored cache when a requirement carries no overrides** | Predates the shared ladder; feeds the effective checksum, so changing it is a checksum epoch |

| Exporters' disposition text and labels (`hdf-to-oscal-sar`, `hdf-to-ocsf`, `hdf-to-ecs`, CKL/CKLB) | resolved, with one fallback | Resolve from the overrides; fall back to the stored field only on a requirement carrying none at all — see the exception below |

Open defects found by the sweep are tracked rather than listed here, so this table does not rot into a bug list. The shape that recurs is an exporter trusting a stored `effective*`/`disposition` field.

**One exception, at the export boundary.** A requirement carrying **no overrides at all** still reports its stored `disposition` when exported (`RequirementDisposition`, `exportmap.Disposition` and their TypeScript twins). There the stored value is the only evidence the document holds — nothing can contradict it — and dropping it would lose the disposition of every document whose producer recorded the verdict without the override detail. An *expired* override still counts as the document carrying overrides, so it suppresses the fallback rather than triggering it.

`hdf query --disposition` deliberately does **not** take that fallback and reports nothing for such a requirement. The asymmetry is the point: a filter matching on an unprovenanced value selects requirements it cannot justify, where an export is only restating what it was handed. No other stored `effective*` field has an equivalent exception.

**Array order carries no meaning.** A reader must never take `statusOverrides[0]` as "the governing override": nothing sorts that array, and this repo's own writers **append**, so the newest override is last. The schema's description says so explicitly — order is not significant, and the governing override is resolved by `appliedAt`. Two shared helpers do it, `GoverningOverride` for typed requirements and `exportmap.GoverningOverride` for the generically-parsed exporters, both on the same `governingOverrideIndex` the three ladders use. One exception is deliberate: `sarif-to-hdf` picks the override whose status produced the rollup, because every override it creates carries the same run timestamp and so recency cannot tell them apart.

**A field is reachable three ways, and a sweep must cover all three:** dotted access (`req.Impact`), map index (`req["impact"]`), and an accessor helper taking the name as a string (`exportmap.GetStr(req, "disposition")`). Enumerate the codebase's own accessors before grepping; the third shape is invisible to patterns written for the first two.

### disposition Field

Disposition has a ladder too, and it is the shortest of the three:

```
1. the most recent non-expired statusOverride — whatever it carries → its type
```

There is **no eligibility filter**. Status requires an override carrying a status, impact one carrying an impact; disposition takes the latest non-expired override of any kind, which is the schema's own definition ("the type of the most recent non-expired override … governing this requirement") and the rule `hdf-diff` has always used to compute the effective checksum.

The consequence is worth stating plainly, because it looks like a contradiction and is not: **disposition may name a different override than the one that decided the status.** A requirement waived in June and risk-adjusted in January reports `effectiveStatus: passed` from the waiver and `disposition: riskAdjustment` from the adjustment. That is what per-field eligibility means — disposition answers "what is the most recent thing anyone did to this requirement", not "what set its status".

Filtering it required a status-carrying override until the change that introduced this section, which meant `--disposition riskAdjustment` could not match the shape a `riskAdjustment` normally has — one carrying an impact and no status. That shape is not hypothetical: `hdf enrich --recompute-cvss` authors exactly it, and appends it to whatever overrides a requirement already carries, so a waived finding that is later enriched acquires a newer impact-only override with no human deciding it.

**POA&Ms participate.** The schema defines disposition as "the type of the most recent non-expired override **or POAM** governing this requirement", and for a long time only the override half was implemented. The distinction that matters: a `poam`-TYPED entry in `statusOverrides[]` always resolved, because it went through the override path like any other type — that is what `hdf amend apply` and the OSCAL POA&M importer write. What never resolved was a `poams[]` entry, the schema's actual POA&M array, so `disposition` answered a narrower question than it appeared to. Overrides and POA&Ms are now resolved as **one ordered set**, not two tiers: the most recently applied non-expired entry governs, whichever kind it is. No new comparison was invented for this. `POAM` requires `[type, explanation, appliedBy, appliedAt, expiresAt]` and `Status_Override` requires `[type, reason, appliedBy, appliedAt, expiresAt]`, so the same `appliedAt` drives recency and the same `expiresAt` drives expiry, and the existing `governingOverrideIndex` simply receives a wider input set.

Expiry still outranks recency: a waiver applied more recently than a POA&M but already lapsed does not displace a plan still in force.

Two alternatives were considered and rejected, recorded here because the question will be asked again. **Overrides always outrank POA&Ms** — consult a plan only when no live override exists — on the reasoning that an override adjudicates while a plan only tracks. **POA&Ms always outrank** — a live plan means the finding is still being worked, whatever was decided about it. Both invent a tier the schema does not describe, and each has a case that reads wrong: under the second, a waiver filed after a plan could never take effect on disposition, which is exactly what an accepted risk superseding a remediation looks like.

A POA&M's **own kind is not representable** in this field. `disposition` is typed as `Override_Type` (`waiver`, `attestation`, `poam`, `inherited`, `falsePositive`, `riskAdjustment`, `operationalRequirement`), while a POA&M's `type` is one of `remediation`, `mitigation`, `riskAcceptance`, `vendorDependency` — none of them members. So every governing POA&M reports the flat value `poam`, and which of the four kinds it is cannot be read from disposition. Distinguishing them would mean widening `Override_Type`, which is a schema change.

**This moved the effective checksum.** `effectiveChecksum` hashes `{status, impact, disposition}`, so any requirement whose governing entry is now a POA&M — one carrying a live plan and either no override or only older or lapsed ones — hashes differently than it did before. That is a **checksum epoch**: stored checksums computed by an earlier version will not match a recomputation, and a continuous-monitoring consumer comparing across the boundary sees a one-time flip on those requirements. One further class moves with it: a requirement with no overrides, only lapsed plans, and a stored `disposition` field previously fell back to that cached value and now correctly resolves to none, because a lapsed entry governs nothing and a stored effective* field is an output cache rather than an input. A requirement carrying no `poams[]` entry at all is unaffected and hashes exactly as before.

### effectiveImpact Field

Impact has its own ladder, and it is much shorter than the status one:

```
1. governing impact override — the most recent non-expired statusOverride carrying an impact → its value
2. the requirement's own impact
```

The canonical implementation is `computeEffectiveImpact` in `@mitre/hdf-utilities` (`hdfutil.ComputeEffectiveImpact` in Go), and the stored `effectiveImpact` field is an **output cache under the same write-path guarantee** as `effectiveStatus` — never read as an input.

Eligibility is **per field**. The override that governs status and the override that governs impact need not be the same one: a waiver adjudicates status and says nothing about impact, so a newer waiver does not displace an older `riskAdjustment`'s re-score. Both selections run through one shared rule (`governingOverrideIndex`) with a different eligibility predicate, so they cannot disagree about expiry or recency.

The override's impact is optional rather than defaulted because **0 is a legitimate re-score** meaning "no longer applicable", which a default could not tell from "this override carries no impact".

Everything that asks a requirement's impact post-adjudication goes through this: the `impact` filter and the derived severity in `hdf query`, the override-aware compliance counts and control listings, and threshold rules. The documented no-override-awareness variants (`countControlsByStatusSeverity`, `mapControlIDs`) keep reading the requirement's own impact — that is their purpose. On the query surface, `--impact` is the effective score and `--raw-impact` the unadjusted one; there is no raw twin of `--status`, so the pair exists only where both scores answer different questions (for example, "an override may not move a critical below 0.7").

**Settled — impact never reaches the status.** A `riskAdjustment` re-scoring a finding to 0.0 leaves it `failed`, and so does an authored impact of 0.0 on a failing control. Neither the requirement's own impact nor an override's re-score is consulted when resolving status, so the two can never disagree.

The two fields answer different questions. A status asks **what did the assessment establish**; `effectiveImpact` asks **how much risk does this carry now** — a statement an assessor makes at adjudication time. An override carrying no `status` is not making a claim about what was established, so it cannot move the status; one that *does* carry a status is, and rung 1 lets it win. That is the same per-field eligibility as the rest of the ladder.

Three things hold the line:

- **The schema says so.** `Override_Type` defines `riskAdjustment` as *"impact score adjusted based on environmental context (FedRAMP Risk Adjustment); does not change pass/fail status, only impact via the impact field."* The disposition-branching table below gives it a typical `effectiveStatus` of `failed` and "stays open".
- **FedRAMP, the model the enum is aligned to, separates the same three acts.** A Risk Adjustment reduces the scanner-defined risk level of a vulnerability that *does exist*; the finding stays on the POA&M and closure depends on actual remediation, not on the adjustment being approved. A validated False Positive — the vulnerability "does not actually exist on the system" — moves to the Closed tab and is not an open risk. An Operational Requirement stays open and is periodically reassessed. There is no Risk Adjustment path to "not applicable"; that is what a False Positive is for.
- **Authority.** The schema names an Authorizing Official for `waiver` and names none for `riskAdjustment`. Since `notApplicable` leaves the compliance denominator (`CalculateCompliance` counts only passed+failed+skipped+error), letting an adjustment reach `notApplicable` would let an assessor raise a compliance score by scoring alone — doing by re-rating what the schema reserves for a signature.

#### Not Applicable is a result, not a score

An earlier version of this ladder carried a third rung, `impact === 0 → notApplicable`, and the measurement behind it was sound: across the fixture corpus roughly a quarter of all requirements carry impact 0, and the overwhelming majority of those roll up to `notReviewed` because InSpec supplies no pass or fail for an impact-0 control at all. Reporting them `notReviewed` asserts absence of evidence where the tool actually returned a verdict of "reviewed, not applicable", and drops them into the compliance denominator as skipped.

**The measurement was right about the data and wrong about the remedy.** "Impact 0 means not applicable" is one tool's convention, not an HDF rule. Most converters derive impact from the shared severity map, where 0.0 is the *informational* band — so the rung applied InSpec's reading to every format that had never agreed to it, and a clean scan, a never-run scan and a genuinely inapplicable control all collapsed to one status. It also made a severity score carry an adjudication, which is the overloading this document warns about everywhere else.

So the rung is gone, and the convention is translated where it is true: every reader of an InSpec control payload emits an explicit `notApplicable` result for a control scored 0.0 that reports nothing else. That is `legacyhdf-to-hdf` for exec JSON and legacy HDF, and `splunk-to-hdf` for the same controls read back out of Splunk — one run must produce one document whichever way it is read, so the translation lives in `shared` and both call it. The verdict is then ground truth in `results[]` rather than a special case in the ladder — the same treatment a control-level error gets, and for the same reason. Neither reader rewrites `impact`: that the source scored the control 0.0 is a fact about the source, and `tags.severity` already preserves the original STIG severity where the profile zeroed it.

Two consequences worth knowing. A document converted before this change carries impact 0 with a `notReviewed` roll-up and no translated result, so a consumer recomputing its status now reads `notReviewed` where the stored `effectiveStatus` says `notApplicable`; re-conversion from the original source is the remedy. And because a synthesized `notApplicable` ranks below `passed` and `failed` in worst-wins, the translation can never bury evidence that a check actually ran.

**If a zero-risk finding should not block a pipeline, bound the band, not the status.** A requirement adjusted to 0.0 reports `failed` with severity `informational`, so `failed.critical.max: 0` and `failed.high.max: 0` pass over it while it stays visible and counted — which is what an auditor asking "what did you decide, and why" needs to see.

### In hdf-libs

The single canonical implementation is `computeEffectiveStatus` in `@mitre/hdf-utilities` (mirrored in Go as `hdfutil.ComputeEffectiveStatus`). Everything else delegates to it:

- **hdf-converters**: converters that bake `effectiveStatus` at ingest (e.g. `legacyhdf-to-hdf` for v1 InSpec data) derive it through the canonical implementation.
- **hdf-cli** (`determineControlStatus` in `stats.go`): calls the canonical implementation and maps the result to display form via `SchemaStatusToDisplay`. The `threshold` and `mcp` paths inject the same computation as their status resolver.
- **@mitre/hdf-schema `helpers`** (`computeEffectiveStatus`): delegates to the canonical `@mitre/hdf-utilities` implementation — same ladder, same answers, overrides included.

### Schema Note

The HDF schema uses **camelCase** for status enum values (`notApplicable`, `notReviewed`). The CLI uses **snake_case** for display (`not_applicable`, `not_reviewed`). The `SchemaStatusToDisplay` function in the CLI handles this translation.

## Overrides

Security results data often has to distinguish between the original status of a requirement as tested (e.g. _the status the scanning tool originally reported_) versus contextualization applied to that status later (an _override, applied after the results are already collected_). Many source formats for HDF have some concept of an override for results. CVE data, for example, often includes the Base components of a [CVSS score](https://www.first.org/cvss/v4.0/specification-document#Base-Metrics) but assumes that the consumer of the scan will fill out the rest of the CVSS metrics to give a complete picture of the risk a CVE represents in-context for a given environment.

Many security functions also allow a failing requirement to be considered _waived_, meaning that while the result as-tested is still a failure, it does not represent a failure that the organization will fix at this time, usually due to a mitigating control or simple risk acceptance. A given requirement might have multiple overrides applied to it over time.

All of these nuances require that HDF has fields to represent both the original status of a requirement, and the effective status of that requirement after all overrides have been applied to it.

The precedence rules above answer one question — **did the requirement pass or fail as tested?** A waiver, false-positive determination, or risk acceptance answers a *different* question — **has that result been formally adjudicated?** These are two orthogonal axes, and HDF keeps them distinct:

1. **Verdict (the raw result).** The status rolled up from `results[]` by the precedence above. This is what the scan actually observed. An acceptance decision never rewrites it.
2. **Acceptance (the override).** A consumer-attached `statusOverride` records a governance decision about a raw failure. It is carried in `disposition`, `effectiveStatus`, `effectiveImpact`, `statusOverrides[]`, and `poams[]` — alongside, not instead of, the raw results.

> **A waiver does not make a control pass.** The raw verdict stays `failed`; the waiver is recorded on the separate acceptance axis. Collapsing the two — treating a waived failure as a genuine pass — is an audit-integrity anti-pattern: a reader of the verdict can no longer tell "genuinely compliant" from "failed but accepted," and actionable-failure counts silently drop as risks are accepted.

### effectiveStatus is the post-adjudication status, not the verdict

With **no override**, `effectiveStatus` is exactly the worst-wins roll-up of the raw results. An override is the *only* thing that makes the effective status differ from the roll-up. When they differ, `effectiveStatus` is the post-adjudication status and the raw roll-up (`worstOf(results[].status)`) is still available losslessly in `results[]`. Which one a consumer should key on depends on the question it is answering (see [disposition branching](#disposition-branching) and the [SIEM export guide](../guides/siem-export.md)).

### Disposition branching

Not every override suppresses the finding. The `disposition` — the type of the governing override or POA&M, whichever was most recently applied and is unexpired — determines whether the finding leaves the actionable set or merely gets re-scored:

| Disposition | Typical `effectiveStatus` | Still an open finding? | Meaning |
|---|---|---|---|
| `falsePositive` | `passed` / `notApplicable` | No — genuinely closed | The scanner was wrong; the check actually passes or does not apply |
| `waiver` | `passed` / `notApplicable` | Accepted out of the actionable set | Risk formally accepted by an Authorizing Official |
| `attestation` | `passed` / `notApplicable` | Accepted out of the actionable set | Manually verified compliant by an assessor |
| `riskAdjustment` | **`failed`** | **Yes — stays open** | Only the impact/severity is re-scored (environmental context); the finding remains |
| `operationalRequirement` | **`failed`** | **Yes — stays open** | Cannot be remediated (operational constraint); remains an accepted open risk |
| `poam` | **`failed`** | **Yes — stays open** | Remediation is tracked; status is unchanged until the work lands |

The dividing line is whether the override drives `effectiveStatus` to a **non-failing** value. `falsePositive`, `waiver`, and `attestation` do; `riskAdjustment`, `operationalRequirement`, and `poam` leave the finding failing and actionable.

### Standards alignment

The two-axis model is not an HDF invention — it mirrors how the governing frameworks separate assessment from risk response:

- **NIST SP 800-53A / RMF (SP 800-37):** control assessment (*Satisfied* vs *Other-Than-Satisfied*) and risk response (*accept / mitigate / transfer*) are distinct steps. Accepting a risk does not make the control Satisfied.
- **FedRAMP deviation requests:** a Risk Adjustment or Operational Requirement leaves the finding **Open** in the POA&M; only the risk rating or remediation obligation changes. A False Positive is the deviation that closes it.
- **OSCAL Assessment Results:** `finding.target.status` (the objective result) and `finding.associated-risk[].facet` (the risk response) are separate, independently-persisted axes — findings are not deleted by risk acceptance.
- **VEX:** `not_affected` records a vulnerability as *present but not exploitable* in context — the affected component still ships; the finding is contextualized, not erased.
- **GRC / SIEM tooling** (OCSF, AWS Security Hub, Rapid7, Sysdig): all model *Suppressed ≠ Resolved* — suppression is an acknowledgement axis separate from the finding's own state.

## Reference

This logic matches [InSpec Enhanced Outcomes](https://github.com/inspec/inspec/blob/main/lib/inspec/enhanced_outcomes.rb) (`Inspec::EnhancedOutcomes.determine_status`), which is the industry standard for security control status determination.
