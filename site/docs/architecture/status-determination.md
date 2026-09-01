# HDF Status Determination

How hdf-libs determines the overall status of a control/requirement from its individual test results. This logic applies to all data sources (InSpec, SARIF, Nessus, XCCDF, etc.).

## Status Values

| Status | Meaning |
|---|---|
| `passed` | Control requirements are met |
| `failed` | One or more requirements are not met |
| `error` | A test execution error occurred |
| `notApplicable` | Control is not applicable (impact 0.0 or explicitly scoped out) |
| `notReviewed` | Control was not evaluated (skipped, no results) |

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
- **`impact === 0` → `notApplicable`, except `error`**: A control with impact 0.0 is Not Applicable regardless of whether its tests passed, failed, or were skipped — but **not** when the roll-up is `error`. An execution error means the check never ran, so nothing was established about applicability; an errored control reports `error` even at impact 0.0. This matches InSpec Enhanced Outcomes and Heimdall inspecjs, which both rank error above the Not Applicable determination
- **A governing override outranks everything**: A non-expired `statusOverride` adjudicates uniformly — at any impact, over any roll-up, including `error` and including impact 0.0. See the effective-status ladder below
- **No results → `notReviewed`**: Unless impact is 0.0 (then `notApplicable`)

### The Effective-Status Ladder

The full effective-status computation combines the roll-up above with overrides and impact in one fixed order:

```
1. governing override   — the most recent non-expired statusOverride's status
2. error roll-up        — else if the result roll-up is error → error
3. impact 0             — else if impact === 0 → notApplicable
4. roll-up              — else the worst-wins roll-up (empty results → notReviewed)
```

The stored `effectiveStatus` field is **never an input** to this computation. The only sanctioned channel for a requirement's status to diverge from its results is a governing override; an unprovenanced stored value that contradicts the results — in either direction, optimistic (`passed` over failing results) or pessimistic (`error` over passing results) — is ignored and the ladder's answer wins. Source tools whose control-level verdict carries information the results array does not (for example a crashed tool that recorded only its passing sub-checks) must have that knowledge encoded into `results[]` by their converter — as a synthesized errored result — not smuggled through the stored field.

### Examples

| Results | Impact | Overall Status |
|---|---|---|
| `[passed]` | 0.7 | `passed` |
| `[failed]` | 0.7 | `failed` |
| `[passed, failed]` | 0.5 | `failed` |
| `[passed, notReviewed]` | 0.7 | `passed` |
| `[notReviewed]` | 0.5 | `notReviewed` |
| `[notReviewed]` | 0.0 | `notApplicable` |
| `[passed, error]` | 0.5 | `error` |
| `[error]` | 0.0 | `error` |
| `[passed, error]` | 0.0 | `error` |
| `[]` (empty)*  | 0.0 | `notApplicable` |
| `[]` (empty)*  | 0.5 | `notReviewed` |

\* The v3 HDF schema enforces `results.minItems=1`, so empty results arrays should not appear in schema-valid HDF documents — converters synthesize a `passed` placeholder for clean scans (see `../specification/hdf-specification.md` § "Clean-scan convention"). The empty-results rows above remain a safety net for legacy HDF v2 (InSpec-ExecJSON-shaped) input that did not enforce the invariant.

## Where Status Is Computed

### effectiveStatus Field

The `effectiveStatus` field on `EvaluatedRequirement` carries the post-adjudication status a producer computed at write time. It is an **output cache, not an input**: the canonical `computeEffectiveStatus` never reads it — the ladder above computes from results, overrides, and impact alone, so a stale stored value (in either direction) cannot influence the answer. The field's correctness is a **write-path guarantee**: every producer (converters, the amendments-apply flow) must emit a value equal to what the ladder computes. External consumers that cannot run the computation — raw-JSON readers, dashboards, `jq` pipelines — may read the field directly and are relying on that write-path guarantee.

### In hdf-libs

The single canonical implementation is `computeEffectiveStatus` in `@mitre/hdf-utilities` (mirrored in Go as `hdfutil.ComputeEffectiveStatus`). Everything else delegates to it:

- **hdf-converters**: converters that bake `effectiveStatus` at ingest (e.g. `legacyhdf-to-hdf` for v1 InSpec data) derive it through the canonical implementation.
- **hdf-cli** (`determineControlStatus` in `stats.go`): calls the canonical implementation and maps the result to display form via `SchemaStatusToDisplay`. The `threshold` and `mcp` paths inject the same computation as their status resolver.
- **@mitre/hdf-schema `helpers`** (`computeEffectiveStatus`): a documented back-compat variant that honors an already-set `effectiveStatus` first — unconditionally, including over an `error` roll-up, unlike the canonical implementation — and does not consult `statusOverrides`. Its impact-0/error ordering for the derivation path matches the canonical rule.

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

With **no override**, `effectiveStatus` equals the ladder's computation from the raw results — identical to the roll-up except where the ladder's fixed rules intervene (an `error` roll-up always reports `error`; a non-errored impact-0 requirement always reports `notApplicable`). An override is the *only* thing beyond those fixed rules that makes the effective status differ from the roll-up. When they differ, `effectiveStatus` is the post-adjudication status and the raw roll-up (`worstOf(results[].status)`) is still available losslessly in `results[]`. Which one a consumer should key on depends on the question it is answering (see [disposition branching](#disposition-branching) and the [SIEM export guide](../guides/siem-export.md)).

### Disposition branching

Not every override suppresses the finding. The `disposition` (the governing override's type) determines whether the finding leaves the actionable set or merely gets re-scored:

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
