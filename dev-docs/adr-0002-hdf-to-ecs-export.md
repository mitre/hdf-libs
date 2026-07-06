# ADR-0002: HDF → ECS export (`hdf-to-ecs`)

- **Status:** Proposed (pending implementation-feedback review)
- **Date:** 2026-07-05
- **Deciders:** Will Dower
- **Epic/cards:** `hdf-libs-wvc3` (HDF → SIEM exporters); this ADR is `wvc3.1`, implemented by `wvc3.2`.
- **Relates to:** complements the carriage/import direction (`hdf-libs-8j9o`, external log evidence *into* HDF by reference) — this is the opposite direction, HDF findings *out* to a SIEM. See also **[ADR-0003](adr-0003-hdf-conmon-streaming.md)** — HDF CONMON streaming (deferred): this exporter's field projection is the deliberate first building block for any future streaming/delta-event work.

## Context

A consumer wants HDF assessment results queryable **alongside other security telemetry** in an Elastic data lake. `hdf convert --from hdf --to ecs` should fan one HDF Results document into a stream of Elastic Common Schema (ECS) events. The central problem is that HDF and ECS have fundamentally different shapes and ECS has no native concept of a compliance verdict, so the mapping is a genuine design decision rather than a mechanical field rename.

The forces at play:

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

## Alternatives Considered

### Alternative A: Pure HDF-in-ECS-envelope
Drop the whole requirement under `hdf` inside a minimal ECS envelope, with no ECS-native projected fields.
- **Pros:** Fully lossless; trivial to implement; nothing to map.
- **Cons:** Elasticsearch stores but cannot meaningfully query the nested arrays; findings would not light up ECS-aware views, detection rules, or `related.*` pivots.
- **Why rejected:** It defeats the reason to export to ECS at all — if only the JSON were wanted, one would store the HDF file directly. Lossless but not *useful* in a SIEM.

### Alternative B: Curated ECS only (lossy)
Map to flat ECS and `hdf.*` scalars and discard the original nested detail.
- **Pros:** Compact events; clean, fully-typed mappings.
- **Cons:** Loses override history and full CVSS/result detail.
- **Why rejected:** The consumer requires lossless; governance queries depend on the override and POA&M history that this would drop.

### Alternative C: `result.evaluation` as the primary verdict (Elastic CSPM convention)
Use Elastic Security's CSPM finding field as the compliance pass/fail.
- **Pros:** Lights up Elastic Security's CSPM UI out of the box.
- **Cons:** `result.evaluation` is an Elastic-Security *integration* field, not part of core `elastic/ecs`.
- **Why rejected here:** The target is a data lake, not the CSPM UI. Reconsider as a *derived add-on* if a CSPM-UI consumer appears — the hybrid shape already carries everything needed to synthesize it later.

### Alternative D: `_bulk`-framed output with hardcoded index
Emit Elasticsearch `_bulk` action/metadata lines interleaved with documents, with an index name baked in.
- **Pros:** Directly `curl`-able into the `_bulk` API with no wrapper.
- **Cons:** Couples the exporter to Elasticsearch index naming and to one ingest path.
- **Why rejected:** Plain NDJSON is consumable by *any* ingest path (Filebeat/Logstash/`_bulk` helpers). Defer `--bulk` framing to an optional flag rather than hardcoding it.

### Alternative E: Splunk / Schema One now
Build the Splunk (CIM/HEC) and/or Schema One targets in this cycle instead of ECS-first.
- **Pros:** Serves other stakeholders sooner.
- **Cons:** Splunk is a separate mapping (`wvc3.3`); the Schema One *profile* (`wvc3.4`) is blocked on a CAC/CUI-gated spec we do not hold.
- **Why rejected (sequenced later):** Schema One is ECS-based, so it becomes a profile delta on this exporter once its spec is in hand; ECS-first is the correct foundation.

### Alternative F: Make HDF a streaming/CONMON event format now
Emit per-result events over a message bus instead of a batch export.
- **Pros:** Directly targets fleet-scale continuous monitoring.
- **Cons:** Requires an owned event producer that does not exist yet and a schema design pass; different product line.
- **Why rejected (deferred, not declined):** This exporter's field projection is its prerequisite. Full reasoning in **[ADR-0003](adr-0003-hdf-conmon-streaming.md)**.

### Alternative G: Do Nothing
Leave HDF results outside the SIEM; consumers store raw HDF files.
- **Pros:** No new converter to maintain.
- **Cons:** HDF findings stay unqueryable next to other telemetry; the stakeholder need goes unmet.
- **Why rejected:** The queryability-alongside-telemetry need is real and is exactly what an ECS projection delivers.

## Consequences

**What becomes easier:**
- HDF findings become first-class, queryable ECS events in a data lake — filterable by `event.outcome`, `rule.ruleset`, `vulnerability.severity`, and (for governance) `hdf.disposition` / `hdf.effective_status` — sitting alongside other telemetry.
- Lossless round-trip is preserved via the `hdf` block, and the event shape is uniform regardless of source tool.
- The field projection is reusable as the substrate for later SIEM targets (Splunk, Schema One) and for the deferred streaming work (ADR-0003).

**What becomes harder:**
- The custom `hdf.*` namespace is best served by a consumer-side index mapping / component template (to be documented) for optimal types; without it, ES applies dynamic mapping.
- One event per requirement means multi-result requirements roll up their status (the full `results[]` is still preserved in `hdf`).
- The mapping must be maintained at **TS↔Go parity** — two implementations that must produce byte-identical output.

**Risks:**
- *`event.outcome=unknown` collapses three distinct statuses* (`notApplicable/notReviewed/error`). *Mitigation:* the lossless five-value status is always in `hdf.status`; consumers needing to distinguish them query that field.
- *ECS 9.4.0 drift* — a future ECS version changes a fieldset. *Mitigation:* `ecs.version` is pinned and asserted in fixtures, so a bump is a deliberate, tested change.
- *Dynamic mapping bloat* on `hdf.*` in an unconfigured index. *Mitigation:* document the recommended component template alongside the exporter.

## Implementation Plan

### Scope

**IN scope:**
- New converter `hdf-converters/converters/hdf-to-ecs/{go,typescript,fixtures}` — `ConvertHDFToECS(input, version) → NDJSON` (Go) and `convertHdfToEcs(input, version?) → NDJSON` (TS), at output parity.
- CLI wiring: `hdf-cli/cmd/hdf/cmd/converter_hdf_to_ecs.go` registering `RegisterConverter("hdf", "ecs", …)`, exposing `hdf convert --from hdf --to ecs`.
- Real fixtures covering a compliance doc (pass/fail/NA), a CVE doc (cvss/cwe/affectedPackages), and an override doc (`statusOverrides[]`/`effectiveStatus`); assertion-based tests in both languages.
- README + CHANGELOG updates.

**OUT of scope:**
- `_bulk` action-line framing / index naming (possible future `--bulk` flag).
- Splunk export (`wvc3.3`) and the Schema One profile (`wvc3.4`, blocked on the gated spec).
- Any streaming/delta-event work (ADR-0003).
- An ECS → HDF path (one-way by design).

### Phases

#### Phase 1: `hdf-to-ecs` exporter (`wvc3.2`) — unblocked once this ADR is accepted
**Files:**
- Create: `hdf-converters/converters/hdf-to-ecs/go/converter.go`, `.../typescript/converter.ts`, `.../typescript/index.ts`, `fixtures/input/*.json`, `fixtures/expected/*.ndjson`.
- Create: `hdf-cli/cmd/hdf/cmd/converter_hdf_to_ecs.go` (+ `_test.go`).
- Modify: `hdf-converters` TS barrel export; `hdf-cli/README.md` and `hdf-converters/README.md` conversion tables; `CHANGELOG.md`.
- Test: `.../go/converter_test.go`, `.../typescript/converter.test.ts`.

**Acceptance criteria:**
- [ ] Valid one-object-per-line NDJSON, LF-delimited, trailing newline; `ecs.version` = `"9.4.0"`.
- [ ] `event.outcome` mapping correct for each of the five statuses; lossless five-value in `hdf.status`.
- [ ] `vulnerability.*` populated for the CVE fixture, absent for pure-compliance.
- [ ] Override fixture yields `hdf.disposition` + `hdf.effective_status` + full `hdf.status_overrides`.
- [ ] TS and Go emit byte-identical output; empty/invalid input errors cleanly.
- [ ] All work via TDD; no regressions.

**Verification:** `cd hdf-converters && pnpm test:ts && go test ./...` && `cd hdf-cli && go test ./cmd/hdf/cmd/ && golangci-lint run` && root `pnpm lint`.

#### Phase 2: Follow-ons (separate cards, later)
Splunk (`wvc3.3`), Schema One profile (`wvc3.4`, blocked on spec), optional `--bulk` flag. Not part of this ADR's delivery.

### Verification Strategy
- **End-to-end:** build the CLI, run `hdf convert --from hdf --to ecs <real-results>.json -o out.ndjson`, confirm each line is standalone JSON (`while read l; do echo "$l" | jq -e . >/dev/null; done`), and spot-check `event.outcome`, `rule.*`, `vulnerability.*`, and a lossless `hdf` block including overrides. Confirm `hdf convert --help` lists `hdf → ecs`.
- **ECS conformance:** field names/values checked against the pinned ECS 9.4.0 reference in tests (no runtime Elasticsearch dependency).
- **Edge cases:** empty baselines, multi-result requirements (status roll-up), missing/unparseable source timestamps (fallback), and multi-component documents.

## Notes

- ADR location: this project keeps ADRs in `dev-docs/` as historical artifacts (not on the published site). The `wvc3.1` card text says "under `site/docs/architecture`" — superseded by that project convention.
