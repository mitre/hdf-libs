# ADR-0002: HDF → ECS export (`hdf-to-ecs`)

- **Status:** Proposed (pending implementation-feedback review)
- **Date:** 2026-07-05
- **Epic/cards:** `hdf-libs-wvc3` (HDF → SIEM exporters); this ADR is `wvc3.1`, implemented by `wvc3.2`.
- **Supersedes / relates to:** complements the carriage/import direction (`hdf-libs-8j9o`, external log evidence *into* HDF by reference). This is the opposite direction: HDF findings *out* to a SIEM.

## Context

A consumer wants HDF assessment results queryable **alongside other security telemetry** in an Elastic data lake. `hdf convert --from hdf --to ecs` should fan one HDF Results document into a stream of Elastic Common Schema (ECS) events.

The forces:

- **ECS is flat, wide, dot-notation**, optimized for indexing/searching in Elasticsearch. **HDF is a nested assessment document** (baselines → requirements → results; arrays of objects like `cvss[]`, `statusOverrides[]`, `descriptions[]`). Elasticsearch flattens arrays-of-objects lossily unless you declare expensive `nested` mappings, so HDF's nested structure does not "just work" as queryable data.
- **ECS has no native compliance pass/fail field.** `event.outcome` (`success|failure|unknown`) means "did the *producer/scan* run," not "did the *control* pass." Representing HDF's assessment verdict is the central design decision.
- HDF's `Result_Status` enum has **five values**: `passed, failed, notApplicable, notReviewed, error`. A binary pass/fail model is lossy against these.
- Consumers attach **overrides** (waivers, attestations, risk adjustments, false-positives) and POA&Ms. These are governance-critical: the first SIEM question is usually "show me failing controls that are *not* waived."
- Direction is **one-way** (HDF → SIEM). A SIEM event stream carries no assessment structure to recover, so there is no ECS → HDF path. (`hdf-libs-8j9o` covers referencing native log corpora *into* HDF, which is a different mechanism.)
- Repo invariants: **TypeScript ↔ Go output parity**, real fixtures only, `unevaluatedProperties`-strict schema, canonical UTC timestamps.

Prior verified ECS research (epic `wvc3` design notes + a fresh sourced pass) established: ECS 9.4.0 is current (SemVer, `github.com/elastic/ecs`); `vulnerability.*` and `threat.*` fieldsets model findings well; there is **no** core-ECS compliance-verdict or NIST/CCI fieldset; the `result.evaluation` field used by Elastic Security's CSPM UI is an **integration field, not in core `elastic/ecs`**; the Elasticsearch `_bulk` API requires LF-delimited, non-pretty-printed NDJSON.

## Decision

`hdf-to-ecs` emits **plain NDJSON — one ECS event object per `Evaluated_Requirement`** — with a **hybrid** shape: a flat, core-ECS-native *projection* for queryability, plus a complete, lossless **`hdf.*` block** carrying the canonical requirement record, with the hot filter fields promoted flat.

1. **Hybrid event structure.** Every event carries both:
   - **ECS-native fields** (`event.*`, `rule.*`, `vulnerability.*`, `threat.*`, `observer.*`, `host.*`, `related.*`) — the queryable projection that lets HDF findings sit alongside other security telemetry and light up ECS-aware views/detection rules.
   - **An `hdf.*` block** — the full requirement (status, overrides, cvss, results, descriptions, tags, poams) preserved losslessly, rooted in `hdf` so the shape is **identical regardless of the original source tool**.

2. **Pass/fail = core-ECS purist (data-lake-first).** `event.outcome` is derived from the (effective) status: `passed→success`, `failed→failure`, everything else `→unknown`. The lossless five-value status lives in `hdf.status`. We do **not** emit `result.evaluation` — it is not core ECS, and the data-lake target does not depend on Elastic Security's CSPM UI. (It can be added later as a derived field if a CSPM-UI consumer materializes.)

3. **Overrides are promoted and preserved.** When an override is present, `event.outcome` follows `effectiveStatus`; `hdf.effective_status`, `hdf.disposition`, and `hdf.overridden` are flat/queryable; the full `statusOverrides[]` and `poams[]` history rides in the `hdf` block.

4. **Plain NDJSON, ECS 9.4.0.** One event per line, LF-delimited, no pretty-print, trailing newline; `ecs.version` pinned to `"9.4.0"`. `_bulk` action/metadata framing (and index naming) is an *ingest* concern left to the consumer — not hardcoded here (a future `--bulk` flag could add it).

5. **NIST/CCI and ATT&CK** ride in the `hdf.*` block (`hdf.nist`, `hdf.cci`, `hdf.cwe`) and, where present in tags, project to core `threat.*` (ATT&CK) and `rule.reference`. ECS has no native control-catalog fieldset, so the authoritative mapping stays in `hdf.*`.

### Event mapping (per requirement)

Status roll-up: `effectiveStatus ?? worstOf(results[].status)`.

| ECS field | Source (HDF) |
|---|---|
| `@timestamp` | `results[0].startTime` ?? doc `timestamp` |
| `ecs.version` | `"9.4.0"` (constant) |
| `event.kind` | `"state"` |
| `event.category` | `["configuration"]` (+ `"vulnerability"` when CVE data present) |
| `event.type` | `["info"]` |
| `event.outcome` | map(status): passed→success, failed→failure, else→unknown |
| `event.id` | deterministic: component + baseline + requirement id |
| `event.dataset` / `event.module` | `"hdf.findings"` / `"hdf"` |
| `message` | requirement title + status |
| `observer.{name,product,version,type}` | `tool` (fallback `generator`); type=`"scanner"` |
| `host.{name,id,ip,mac,os.*}`, `related.{hosts,ip}` | target `component` (fqdn/name, componentId, ipAddress, macAddress, osName/osVersion) |
| `rule.{id,name,description,ruleset,version,reference}` | requirement id/title/default-description, baseline name/version, `refs[0].url` |
| `vulnerability.{id,enumeration,classification,score.base,score.version,severity,scanner.vendor,description}` | `cvss[]`/`cwe[]`/`affectedPackages[]` (present only for CVE findings) |
| `threat.{framework,tactic.*,technique.*}` | ATT&CK from `tags.mitre_attack`/`tags.attack` (best-effort) |
| `hdf.*` | **lossless:** `status`, `effective_status`, `effective_impact`, `impact`, `severity`, `disposition`, `overridden`, `baseline`, `control_id`, `nist`, `cci`, `cwe`, full `tags`, `cvss[]`, `epss`, `kev`, `affected_packages[]`, `descriptions[]`, `results[]`, `status_overrides[]`, `poams[]`, `code`, `refs[]`, `generator`, `tool`, `exporter_version` |

## Alternatives considered

- **Pure HDF-in-ECS-envelope** (drop the whole requirement under `hdf` inside a minimal envelope, no ECS-native fields). *Rejected:* Elasticsearch stores but cannot meaningfully query the nested arrays; findings would not light up ECS-aware views/detection rules/`related.*` pivots — defeating the reason to export to ECS at all (if only the JSON were wanted, one would store the HDF file directly). It is fully lossless but not *useful* in a SIEM.
- **Curated ECS only (lossy)** (map to flat ECS/`hdf.*` scalars, discard the original). *Rejected:* loses override history and full CVSS/result detail; the consumer requires lossless.
- **`result.evaluation` as the primary verdict** (Elastic CSPM convention). *Rejected here:* not core ECS (an Elastic-Security *integration* field); a data-lake-first target does not need the CSPM UI. Reconsider as a derived add-on if a CSPM-UI consumer appears.
- **`_bulk`-framed output with hardcoded index** *Rejected:* couples the exporter to Elasticsearch index naming; plain NDJSON is consumable by any ingest path (Filebeat/Logstash/`_bulk` helpers). Defer `--bulk` to a flag.
- **Splunk / Schema One now.** Deferred: Splunk is `wvc3.3`; the Schema One *profile* (`wvc3.4`) is blocked on its CAC/CUI-gated spec. Schema One is ECS-based, so it will be a profile delta on this exporter once the spec is in hand.

## Consequences

- **Easier:** HDF findings become first-class, queryable ECS events in a data lake — filterable by `event.outcome`, `rule.ruleset`, `vulnerability.severity`, and (for governance) `hdf.disposition`/`hdf.effective_status` — sitting alongside other telemetry. Lossless round-trip is preserved via the `hdf` block. Uniform event shape regardless of source tool.
- **Harder / caveats:** The custom `hdf.*` namespace is best served by a consumer-side index mapping / component template (to be documented) for optimal types; without it, ES applies dynamic mapping. One event per requirement means multi-result requirements roll up their status (the full `results[]` is still preserved in `hdf`). The mapping must be maintained at **TS↔Go parity**. `event.outcome=unknown` covers three distinct statuses (`notApplicable/notReviewed/error`); consumers needing to distinguish them query `hdf.status`.
- **Open follow-ons:** `wvc3.3` (Splunk HEC/CIM export), `wvc3.4` (Schema One profile — needs the gated spec), and a possible `--bulk` framing flag.

## Notes

- ADR location: this project keeps ADRs in `dev-docs/` as historical artifacts (not on the published site). The `wvc3.1` card text says "under `site/docs/architecture`" — superseded by that project convention.
