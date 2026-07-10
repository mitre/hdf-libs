# HDF to SIEM Export

hdf-libs exports an HDF Results document to three SIEM-native event formats, one NDJSON event per evaluated requirement:

| Target | Format | CLI |
|---|---|---|
| Elastic | Elastic Common Schema (ECS 9.4.0) | `hdf convert --from hdf --to ecs` |
| Splunk | HEC envelope, normalized to the Common Information Model (CIM) | `hdf convert --from hdf --to splunk` |
| OCSF | Open Cybersecurity Schema Framework 1.8.0 Findings | `hdf convert --from hdf --to ocsf` |

All three share a mapping core and emit byte-identical output from the TypeScript and Go implementations. The design decisions live in ADR-0002 (ECS + OCSF) and ADR-0004 (Splunk CIM).

## The raw-primary status model

The exporters follow HDF's [two-axis status model](../architecture/status-determination.md#overrides): the **verdict** (did it pass or fail as tested) and the **acceptance** (has the failure been formally adjudicated) are separate, orthogonal fields.

Every exporter is **raw-primary**: the verdict field always carries the *raw* result. A waived or risk-accepted failure is still a failure — it is never rewritten to a pass — so a consumer reading the verdict can never mistake accepted risk for genuine compliance. Acceptance rides a separate suppression axis. A control is *suppressed* only when the raw result is failing **and** an override (waiver, false positive, attestation) drove the effective status non-failing. A `riskAdjustment`, `operationalRequirement`, or `poam` that leaves the finding failing is **not** suppressed — it stays actionable, only its impact is re-scored.

### Field mapping per exporter

| Axis | ECS | Splunk (CIM/HEC) | OCSF |
|---|---|---|---|
| **Verdict (raw)** | `event.outcome` (`success` / `failure` / `unknown`) | `hdf_status` (raw 5-value) | `compliance.status_id` (`1` Pass / `2` Warning / `3` Fail) |
| **Acceptance** | `hdf.suppressed` (boolean) | `suppressed` (boolean; in `event` and indexed `fields`) | base `status_id` (`1` New vs `3` Suppressed) |
| **Full override chain** | `hdf.status_overrides[]` | `hdf.status_overrides[]` | `unmapped.hdf_requirement` |

### The canonical "still actionable" query

To list open failures that have **not** been accepted out of the actionable set:

| Target | Query |
|---|---|
| ECS | `event.outcome:"failure" AND hdf.suppressed:false` |
| Splunk | `hdf_status=failed suppressed=false` |
| OCSF | `compliance.status_id = 3 AND status_id = 1` |

In each case a waived / false-positive / attested failure drops out on the suppression axis, while a genuine open failure **and** a risk-adjusted still-failing failure both remain. Every filter is on a normalized enum or boolean — never on free text.

For Splunk, the companion technology add-on (`Splunk_TA_hdf`) encodes this at the data-model layer: its finding eventtype tags failed/error/CVE events into the CIM Vulnerabilities model but excludes `suppressed=true`, so a waived control never enters the model while a risk-adjusted still-failing control does.

## Confidentiality boundary of the lossless blocks

Each event carries a **lossless** copy of the full original requirement so nothing is dropped:

- ECS and Splunk: the `hdf.*` block (status, overrides, cvss, results, descriptions, code, tags, poams, tool/generator metadata).
- OCSF: `unmapped.hdf_requirement` (OCSF's schema-sanctioned home for source data).

This block reproduces the source scan **verbatim**, including data that may be sensitive: result `message` values (observed configuration, file paths, command output), control `code`, free-text override `reason` fields (which may name individuals or email addresses), and tool metadata. **The exporters apply no redaction, masking, or field filtering** — losslessness is the design contract.

The practical boundary: the destination SIEM index inherits the sensitivity of the source scan data. Treat it accordingly.

- For CUI or classified assessments, classify the destination index (and its access controls) at the level of the source scan.
- If specific fields must be withheld from the SIEM, filter or redact the HDF document **before** export. The exporters will not do it for you — they are lossless by design.
- The promoted flat fields (the verdict, suppression, host, rule, and CVE scalars) are a projection *of* that same data, not an additional disclosure.

## See also

- [HDF Status Determination](../architecture/status-determination.md) — the two-axis verdict/acceptance model and its standards grounding.
- ADR-0002 (HDF to ECS / OCSF) and ADR-0004 (HDF to Splunk CIM) — the design records, including the cross-exporter raw-primary reconciliation.
