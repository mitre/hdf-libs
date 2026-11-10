# HDF to SIEM Export

hdf-libs exports an HDF Results document to three SIEM-native event formats, one NDJSON event per evaluated requirement:

| Target | Format | CLI |
|---|---|---|
| Elastic | Elastic Common Schema (ECS 9.4.0) | `hdf convert --from hdf --to ecs` |
| Splunk | HEC envelope, normalized to the Common Information Model (CIM) | `hdf convert --from hdf --to splunk` |
| OCSF | Open Cybersecurity Schema Framework 1.8.0 Findings | `hdf convert --from hdf --to ocsf` |

All three share a mapping core and emit byte-identical output from the TypeScript and Go implementations.

## Status semantics by target

The exporters use HDF's [two-axis status model](../architecture/status-determination.md#overrides): the raw test verdict and the governing effective status are distinct. The shared status engine derives effective status from results and governing overrides; it does not trust the stored `effectiveStatus` cache.

ECS is **effective-primary**: `event.outcome` reflects that derived effective status, while `hdf.status` retains the raw verdict. Splunk is **raw-primary** in `hdf_status`. OCSF Compliance Findings are **raw-primary** in `compliance.status_id`; Vulnerability Findings have no `compliance` field. OCSF's separate `status_detail` carries the effective rollup.

Suppression means a governing override drove a raw-failing finding to a non-failing effective status. A risk adjustment, operational requirement or POA&M that leaves the finding failing does not suppress it. A waived failure can therefore have ECS `event.outcome=success` while its original failed result remains in `hdf.status` and the retained source; Splunk keeps `hdf_status=failed`, and OCSF Compliance Findings keep `compliance.status_id=3`.

| Field | ECS | Splunk (CIM/HEC) | OCSF |
|---|---|---|---|
| Native verdict | `event.outcome`: effective `success` / `failure` / `unknown` | `hdf_status`: raw five-value status | Compliance only: raw `compliance.status_id` (`1` Pass / `2` Warning / `3` Fail) |
| Acceptance | `hdf.suppressed` | `suppressed` in payload and indexed fields | Base `status_id`: `3` Suppressed or `1` New |
| Source override history | `hdf.status_overrides[]` | `hdf.status_overrides[]` | `unmapped.hdf_requirement.statusOverrides` |

### Actionable failure queries

| Target | Query |
|---|---|
| ECS | `event.outcome:"failure" AND hdf.suppressed:false` |
| Splunk | `hdf_status=failed suppressed=false` |
| OCSF Compliance Findings | `class_uid = 2003 AND compliance.status_id = 3 AND status_id = 1` |

These queries exclude suppressed findings and retain risk-adjusted findings that remain failing. The OCSF query applies to Compliance Findings, not Vulnerability Findings (`class_uid=2002`). For Splunk, the companion `Splunk_TA_hdf` tags failed/error/CVE findings for the CIM Vulnerabilities model while excluding `suppressed=true`. The integration suite verifies event types and tags; it does not install the separate CIM add-on or claim accelerated data-model verification.

## Source preservation and confidentiality

Standalone exporter output keeps its established native fields and legacy context. ECS and Splunk's `hdf.*` blocks are selected, renamed projections, not complete copies of every source member. OCSF's `unmapped.hdf_requirement` carries the parsed requirement, but does not by itself deliver the complete original assessment or its original bytes.

Use the explicit source-preserving bundle when complete evidence must survive export. The initial `legacy-additive/1` profile adds a complete requirement value at the following locations and retains the original HDF bytes once in `source.json`:

| Target | Preservation envelope |
|---|---|
| ECS | `hdf.source` |
| Splunk HEC | `event.hdf.source` |
| OCSF | `unmapped.hdf_source` |

The envelope identifies the source artifact and the occurrence's JSON Pointer. Retain the events, source, manifest and standard evidence-package inventory together. Verified resolution checks artifact checksums and agreement between the carried requirement and the original occurrence, then returns the exact original HDF source, including baseline integrity and embedded scanner evidence. It rejects missing or altered artifacts and mismatched records. It does not authenticate retained signatures or recompute native query fields.

This is recovery from retained source, not an inverse converter. The existing Splunk importer accepts a different header/profile/control format; it does not reverse these HEC events. An ECS reverse importer and a compact export profile are not provided. The additive profile deliberately retains existing duplicated fields for compatibility.

The preserved source inherits the assessment's sensitivity: result messages, code, override reasons and embedded scanner artifacts can contain sensitive information. Exporters do not redact or mask them. Provision both SIEM and retained-artifact access accordingly. If redaction is required, perform it before export and treat the redacted document as the new input; the bundle cannot recover material removed before that boundary.

See the [integration runbook](../contributing/siem-integration-testing.md#ingestion-and-preservation) for Elasticsearch's required mapping, Splunk's add-on, retrieval and size limits, and [converter bundle APIs](https://github.com/mitre/hdf-libs/tree/main/hdf-converters#preserve-siem-source-data) for library use.

## Projecting change events into interop vocabularies

`hdf events derive` emits one `Requirement_Change_Event` per requirement whose
effective posture moved between observations (state enum:
`new | absent | updated | fixed | regressed`); a complete runnable
walkthrough of the event loop lives at
[mitre/hdf-conmon-demo](https://github.com/mitre/hdf-conmon-demo). Consumers feeding OCSF activity
pipelines or SARIF baseline comparisons should use the following total
mappings rather than inventing their own. One rule frames both tables: a
steady-state control emits **no event**, so "unchanged" is the *absence* of an
event — never a mapped value.

### Event state to OCSF `activity_id`

Target: Compliance Finding (class 2003), OCSF 1.8.0
([schema.ocsf.io](https://schema.ocsf.io/1.8.0/classes/compliance_finding)).

| Event state | `activity_id` | Activity |
|---|---|---|
| `new` | `1` | Create |
| `updated` | `2` | Update |
| `fixed` | `2` | Update |
| `regressed` | `2` | Update |
| `absent` | `3` | Close |

Recompute `type_uid` alongside (`class_uid × 100 + activity_id`: `200301` /
`200302` / `200303`). The direction a plain Update cannot carry stays visible
in OCSF through `compliance.status_id` flipping (Pass ↔ Fail) and the
original event travels losslessly in `unmapped`.

`fixed` maps to Update, not Close: under the [OCSF raw-primary semantics](#status-semantics-by-target)
the control remains a tracked compliance finding whose verdict changed — only
`absent` (the requirement left the assessment scope) closes it. A
finding-lifecycle consumer that tracks *only failing* findings may reasonably
treat `fixed` as Close; that is a policy choice in the consumer, not the
default projection.

Note the batch exporter (`hdf convert --from hdf --to ocsf`) emits
`activity_id: 1` (Create) for every finding: a single document carries no
change context. The event stream is precisely what makes Update and Close
projectable.

### Event state to SARIF `baselineState`

Target: the closed four-value `baselineState` property
(`new | unchanged | updated | absent`), SARIF 2.1.0
[§3.27.24](https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/sarif-v2.1.0-errata01-os-complete.html#_Toc141790912).

| Event state | `baselineState` | Lossy? |
|---|---|---|
| `new` | `new` | no |
| `updated` | `updated` | no |
| `fixed` | `updated` | **yes** — direction lost |
| `regressed` | `updated` | **yes** — direction lost |
| `absent` | `absent` | no |

The loss is structural: `baselineState` records *that* a result changed, never
*which way*. `fixed` and `regressed` — opposite triage outcomes — collapse
into the same `updated`. HDF carries the direction SARIF cannot; a consumer
that needs it must keep the event `state` (or `changeReasons`) alongside the
projection.

`fixed` maps to `updated`, not `absent`, because HDF requirement rows persist
across status flips: like a SARIF run using `kind: pass`/`fail`, a control
that starts passing is still *present* in the current observation with a
changed result — it has not left the run. The alternative applies only to a
problems-only SARIF stream (failures are the sole results): there a `fixed`
control's result disappears (`absent`) and a `regressed` control's failure
first appears (`new`). Use that variant only when the consuming pipeline
genuinely reports failures alone, and say so where the projection is defined.

## See also

- [HDF Status Determination](../architecture/status-determination.md) — the two-axis verdict/acceptance model and its standards grounding.

## Export an archive for unattended handoff

Use `hdf convert results.json --to ecs --bundle -o export.zip` to deliver the finding events alongside the original HDF source, its manifest and a standard evidence-package inventory. `splunk` and `ocsf` are also supported targets.

Both this command and `hdf evidence bundle` default to `--output-access private`. Protection is established before archive bytes are written. Linux checks actual owner/mode permissions on ext2/3/4, XFS, Btrfs or tmpfs; macOS requires local APFS/HFS with ownership enabled and prevents inherited ACL grants; Windows requires persistent ACL support and a protected creator-only DACL. Unsupported storage, including OverlayFS, fails without falling back to broader access.

For agents running as different accounts, provision a shared directory and select inherited access explicitly:

```bash
hdf convert results.json --to ecs --bundle --output-access inherit -o shared/export.zip
hdf evidence bundle evidence-package.json --output-access inherit -o shared/evidence.zip
```

`inherit` uses the directory's native ACL policy and POSIX umask/default ACLs. It can expose evidence broadly, or still produce an owner-only file under a restrictive umask. The operator controls that directory policy. No prompt or environment variable is needed; same-account agents can use the private default.

`--overwrite` replaces an existing archive with the selected new-file access policy. A failure leaves the previous destination intact. The ordinary-user privacy guarantee excludes administrator privileges and requires a trusted destination directory. Neither mode encrypts data or transfers filesystem ACLs with ZIP contents. Across CI jobs, use the platform's authenticated artifact upload/download mechanism and establish access at the receiving destination.
