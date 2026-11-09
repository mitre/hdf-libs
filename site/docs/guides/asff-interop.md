# ASFF Interoperability

HDF interoperates with the [AWS Security Finding Format (ASFF)](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format.html) in both directions:

- **Import** — `asff-to-hdf` reads ASFF findings (Security Hub controls, Inspector, GuardDuty, Prowler, Trivy, and any other producer) into HDF Results.
- **Export** — `hdf-to-asff` writes HDF Results back out as an ASFF `{"Findings": [...]}` envelope, the shape `BatchImportFindings` accepts and `asff-to-hdf` reads back.

The two directions are **not symmetric**, and that is deliberate. ASFF is a finding-exchange format; HDF is a superset that also carries baseline/profile hierarchy, per-result detail, waiver/attestation data, and arbitrary tags. Export maps HDF onto standard ASFF fields and accepts a documented, lossy round-trip rather than smuggling HDF structure through non-standard channels.

## Why the export is lossy by design

heimdall2's original `hdf2asff` mapper made the round-trip lossless by encoding the entire HDF control into the ASFF `Types[]` field as escaped key/value strings (`Control/ID/...`, `Control/Waiver_Data/{json}`, `Tags/nist/[...]`, plus a `MITRE/SAF/<version>-hdf2asff` marker its own importer detected). `Types` is meant to be AWS's **finding-type taxonomy** (`namespace/category/classifier`), and overloading it as a serialization channel:

- pollutes the Security Hub console's type facets,
- degrades the Security Lake **ASFF → OCSF** transform (non-standard `Types` has no OCSF home), and
- produces findings that only round-trip through a matching custom importer.

`hdf-to-asff` does **not** do this. The three real ASFF consumers — the Security Hub console, EventBridge automations, and Security Lake/OCSF — all read standard fields and are actively harmed by the encoding hack, while the one consumer that wanted losslessness (reconstructing HDF from pushed findings) is not a workflow this project supports. Provenance that does not fit a standard field rides `ProductFields` (ASFF's official `string` map), never `Types`.

## Granularity

One ASFF finding is emitted **per HDF requirement** (`Evaluated_Requirement`), matching `hdf-to-ocsf` and the shared export harness. A requirement's results roll up to a single `Compliance.Status` via the shared status roll-up. This keeps the two AWS-ecosystem exports (`asff`, `ocsf`) aligned, which matters because Security Lake transcodes ASFF into OCSF downstream.

## Status mapping

`Compliance.Status` is the rolled-up requirement verdict — the governing status override when one applies, else the worst of `results[].status`. The one exception is suppression, described below:

| HDF status | ASFF `Compliance.Status` |
|---|---|
| `passed` | `PASSED` |
| `failed` | `FAILED` |
| `notApplicable` | `NOT_AVAILABLE` |
| `notReviewed` | `WARNING` |
| `error` | `WARNING` |

### Suppression is the exception

Security Hub keeps two axes orthogonal: `Compliance.Status` is the check result and `Workflow.Status` is the triage state. Suppressing a finding there records a decision about the finding; it does not rewrite the check.

So when a governing override drives a **failing** verdict non-failing — the acceptance shape — the export reports the **raw** verdict in `Compliance.Status` and puts the acceptance in `Workflow.Status: SUPPRESSED`. Reporting the roll-up instead would turn a failed check into `PASSED` and discard the verdict an importer needs to read back.

| HDF shape | `Compliance.Status` | `Workflow.Status` |
|---|---|---|
| `failed` result, governing waiver to `passed` | `FAILED` (raw) | `SUPPRESSED` |
| `passed` result, governing escalation to `failed` | `FAILED` (roll-up) | absent |
| `notApplicable` result, no override | `NOT_AVAILABLE` (roll-up) | absent |

The second and third rows are the narrow cases: an escalation and a scope claim are not acceptance decisions, so they report the roll-up like everything else.

Going the other way, `asff-to-hdf` reconstructs that shape: a finding with `Workflow.Status: SUPPRESSED` over a failing `Compliance.Status` keeps its `failed` result and gains a `waiver` status override, so the acceptance travels in `statusOverrides[]` rather than as an impact of 0. Two cases produce no override. A suppression over a finding that did not fail adjudicates nothing adverse — and `error`, which an unrecognized `Compliance.Status` maps to, is indeterminate rather than failing, so there is no verdict to accept. And because ASFF folds findings sharing a control id into one requirement, where an override governs the whole requirement, a suppressed finding sharing its id with an unsuppressed failing one yields no override either: waiving it would clear a live finding.

The acceptance axis is orthogonal: a raw-failing result an override drove non-failing (waiver / falsePositive / attestation) sets `Workflow.Status = SUPPRESSED`. A riskAdjustment / operationalRequirement / poam that leaves the requirement failing is **not** suppressed — it stays actionable.

`Severity` is derived from the requirement `impact` (0.0–1.0): `Label` from the canonical impact→severity bands, `Normalized` as `impact × 100`.

## Required fields ASFF has and HDF does not

ASFF requires `ProductArn`, `AwsAccountId`, and a `Region` that HDF has no native field for:

- **`AwsAccountId`** is recovered from a `cloudAccount` component when present — the clean reverse of `asff-to-hdf`'s `AwsAccountId → cloudAccount component` mapping. Absent that, a placeholder (`000000000000`) is emitted.
- **`ProductArn`** is a placeholder self-managed product ARN built from the recovered account.
- **`Region`** is a placeholder (`us-east-1`), emitted in the `ProductArn` and on each `Resource` (alongside `Partition: aws`); Security Hub ignores it on `BatchImportFindings` and auto-populates it on import.

These placeholders make the offline converter output structurally valid. When findings are pushed to a live Security Hub (a separate capability), the push path overrides `ProductArn`, `AwsAccountId`, and `Region` with the caller's registered product integration.

## Round-trip fidelity

`ASFF → HDF → ASFF` and `HDF → ASFF → HDF` are both partial. What survives:

| Field | HDF → ASFF → HDF | Notes |
|---|---|---|
| Control id | ✓ | `id` ↔ `GeneratorId` |
| Title | ✓ | truncated to 256 code points |
| Description | ✓ | truncated to 1024 code points |
| Status verdict | ✓ | via the status table above |
| Severity / impact | ✓ | quantized to the severity bands |
| Cloud account identity | ✓ | via the `cloudAccount` component |
| Fix guidance / ref URL | partial | first `fix` description + first ref → `Remediation.Recommendation` |
| Per-result detail | ✗ | rolled up to one finding + status |
| Baseline hierarchy, tags, waiver/attestation payloads | ✗ | `ProductFields` provenance only; not reconstructable |

There is **no blanket round-trip guarantee** — fidelity is per-format, documented, with intentional asymmetries.

## CLI

```bash
# Export: HDF Results → ASFF findings envelope
hdf convert --to asff results.json -o findings.asff.json

# Import: ASFF → HDF Results (auto-detected)
hdf convert findings.asff.json -o results.json
```

## See also

- [SIEM Export](./siem-export.md) — the shared HDF→X export model (OCSF, ECS, Splunk).
- [VEX Interoperability](./vex-interop.md) — the other documented per-format round-trip.
