# ADR-0004: HDF → Splunk CIM export (`hdf-to-splunk`)

- **Status:** Accepted (owner-approved 2026-07-08; no team review required)
- **Date:** 2026-07-08
- **Deciders:** Will Dower
- **Epic/cards:** `hdf-libs-wvc3` (HDF → SIEM exporters); this is `wvc3.3`.
- **Relates to:** **[ADR-0002](adr-0002-hdf-to-ecs-export.md)** (HDF → ECS export — the parallel first target; this reuses its field-mapping core and mirrors its hybrid shape). See also **[ADR-0003](adr-0003-hdf-conmon-streaming.md)** (CONMON streaming, deferred).

## Context

A verified consumer wants HDF assessment results in Splunk, normalized to the **Common Information Model (CIM)** so findings sit in Splunk's data models (and light up Enterprise Security / risk-based alerting) alongside other security telemetry. This is the second SIEM export target after ECS (`hdf-to-ecs`, ADR-0002). The consumer precondition on the card ("confirm a committed consumer before building") is satisfied.

Authoritative research against the current Splunk CIM Add-on and HEC documentation established the forces that make this **not** a mechanical port of the ECS exporter:

- **There is no Compliance or Configuration CIM data model.** Confirmed by exhaustive enumeration of the CIM data-model set. Splunk's own compliance products (the App for PCI Compliance, SCAP add-ons) route assessment findings through the **Vulnerabilities** data model. So both CVE findings *and* failed configuration/STIG controls land in Vulnerabilities; there is no native "control passed/failed" model.
- **CIM has no pass/fail verdict field.** In the Vulnerabilities model an event's *existence* is the finding, so a **passed control produces no Vulnerabilities event**. Preserving full posture ("X of Y controls passed") requires emitting every result — including passes — into our own sourcetype with our own status field.
- **CIM field typing is strict and flat.** `cvss` is a single **number** (no array, no vector field); `severity` is an enum with exactly `critical | high | medium | low | informational`; `os` / `first_found` / `last_found` are **not** in the current Vulnerabilities model. CIM rows are flat and single-valued — nested arrays lose element correlation under auto-KV and risk Splunk's ~5,000-character search-time extraction cutoff.
- **CIM association is by search-time tags, not payload — an exporter cannot tag over the wire.** A data model only picks up events carrying its tags (Vulnerabilities requires `tag=vulnerability` **and** `tag=report`). Tags are applied *inside Splunk* by a technology add-on (TA): `eventtypes.conf` (keyed on `sourcetype`) → `tags.conf` → `props.conf` field aliases. There is no HEC field that assigns CIM tags. Every reputable integration (Qualys TA, Nessus CIM Mapper, Tenable) ships a companion TA; it is structurally required, not optional.
- **HEC envelope shape.** The HEC `/services/collector/event` endpoint takes per-event objects with `event` (may be a JSON object), `time` (epoch seconds with optional millis), `host`, `source`, `sourcetype`, `index`, and `fields` (a **flat** map of index-time fields). Batches are newline-delimited/concatenated objects (NDJSON is a valid subset) or a JSON array.
- **Repo invariants:** TypeScript ↔ Go byte-identical output parity; real fixtures only; canonical UTC timestamp handling via the repo's `parseTimestamp` helpers (never raw `new Date()` / `time.Parse`); `unevaluatedProperties`-strict schema (not directly relevant here — output is not HDF).

The central tension: "full CIM mapping" (which the consumer wants, over plain HEC passthrough) pulls toward flat, per-finding, TA-backed events — the opposite of the ECS exporter's rich, per-requirement, lossless-`hdf.*` shape. The design must satisfy CIM without discarding HDF's losslessness or forking the ECS exporter's mapping core.

## Decision

`hdf-to-splunk` emits **HEC-envelope NDJSON — one HEC event per `Evaluated_Requirement`** (parallel to `hdf-to-ecs`), in a **hybrid shape**: a flat, CIM-named scalar projection promoted to the top of the `event` payload (and mirrored into the HEC indexed `fields`), plus a complete lossless nested **`hdf.*` block**. It ships a **minimal companion TA (`Splunk_TA_hdf`)** that associates the `hdf:results` sourcetype with the Vulnerabilities CIM model and aliases the flat scalars to CIM field names.

1. **HEC-envelope NDJSON, one event per requirement.** Each output line is one HEC event object: `{ time, host, source, sourcetype, event, fields }`. `time` is epoch seconds converted from the requirement's `startTime` (RFC3339) via the repo's `parseTimestamp` helper (falling back to the document `timestamp`, then omitted so HEC stamps receive-time); `sourcetype` is the stable, namespaced `"hdf:results"` (the single contract the TA hangs off); `source` is `"hdf-exporter"`; `host` is the target component name/fqdn. Concatenated/NDJSON batch form (one object per line, LF-delimited, trailing newline).

2. **Hybrid event shape — flat CIM projection + lossless `hdf.*` block.** The `event` payload carries:
   - **Promoted flat CIM scalars** at top level: `signature` (requirement title, or rule id), `signature_id` (control id — SV-/CCI/rule id), `cvss` (single number = **max base score** across `cvss[]`; omitted/0 for pure-compliance), `severity` (mapped CIM enum), `dest` (target host), `dvc` (scanner host when known), `vendor_product` (tool name), `category` (CWE name / control family), `hdf_status` (the **raw** five-value verdict — CIM has no field for it), and `suppressed` (the boolean acceptance axis — see below).
   - The **hot CIM scalars mirrored into the HEC `fields`** key (index-time) — including `hdf_status` and `suppressed` — so the CIM-critical values are indexed and immune to the ~5,000-char extraction cutoff.
   - A nested lossless **`hdf` block** (full requirement: `status`, `suppressed`, `effective_status`, `disposition`, `overridden`, `cvss[]`, `results[]`, `descriptions[]`, `status_overrides[]`, `poams[]`, `tags`, `nist`, `cci`, `refs[]`, `code`, `generator`, `tool`, `exporter_version`) for drill-down. We do **not** ask CIM to normalize the nested arrays — they are drill-down only.

   **Raw-primary status (shared model).** `hdf_status` carries the **raw** verdict (a waived failure is still `failed`); `suppressed` is the separate acceptance axis — `true` iff the raw result is failing and an override drove the effective status non-failing (waiver / falsePositive / attestation). A `riskAdjustment` / `operationalRequirement` / `poam` that leaves the effective status failing is **not** suppressed and stays actionable. This is the same two-axis model the ECS and OCSF exporters use — see ADR-0002 **"Reconciliation: the raw-primary two-axis model"** for the standards grounding. Canonical "still actionable" query: `hdf_status=failed suppressed=false`.

3. **Vulnerabilities is the CIM home; passes stay for posture.** Failed compliance controls **and** CVE findings are the events the TA tags into the Vulnerabilities model (`tag=vulnerability tag=report`) — **except those with `suppressed=true`** (waived/false-positive/attested), which are adjudicated out of the actionable set. Passed / notApplicable / notReviewed controls emit to the *same* `hdf:results` sourcetype (carrying `hdf_status`) so posture reporting is complete, but are **not** vuln-tagged (they are not findings). The exporter emits uniformly; the **TA** performs the discrimination (its eventtype keys on `hdf_status`/CVE presence and excludes `suppressed=true`), keeping that policy in Splunk config, not baked into the exporter. A risk-adjusted still-failing control (`suppressed=false`) correctly stays in the model.

4. **Ship a minimal companion TA (`Splunk_TA_hdf`).** In-repo, a small Splunk add-on: `props.conf` (sourcetype recognition, JSON `KV_MODE`), `eventtypes.conf` (`[hdf_finding] search = sourcetype=hdf:results (hdf_status=failed OR hdf_status=error OR cve=*) NOT suppressed=true`), and `tags.conf` (`[eventtype=hdf_finding] vulnerability=enabled report=enabled`). This is the piece that makes the output genuinely CIM-live; without it the JSON is CIM-shaped but populates no data model.

   *Two refinements landed during implementation:* (a) the finding discriminator keys on **`cve=*`** rather than `cvss>0` — a `baseScore:0` CVE (e.g. `CVE-1999-0632`) is still a CVE finding and must tag into Vulnerabilities, which `cvss>0` would wrongly exclude; (b) **no `FIELDALIAS`/`EVAL` or `TIME_*` is needed** in `props.conf` because the exporter already emits CIM-native field names and the HEC envelope `time` supplies the timestamp — so the TA is pure sourcetype-config + tagging.

5. **Severity and CVSS mapping.** CIM `severity` from HDF `impact` (0.0–1.0): `≥0.9→critical`, `0.7–<0.9→high`, `0.4–<0.7→medium`, `0.1–<0.4→low`, else `informational` (also the value for notApplicable/informational). CIM `cvss` = the **maximum `baseScore`** across the requirement's `cvss[]`; the full `cvss[]` is preserved losslessly in the `hdf` block. When a source severity string is present it is normalized to the CIM enum rather than recomputed.

6. **Reuse the ECS mapping core (do not fork).** The generic-access helpers, status roll-up (`worstOfResults`), component/tool/timestamp extraction, and the baseline→requirement fan-out currently private to `hdf-to-ecs` are extracted into a shared `hdf-converters/shared` unit consumed by both exporters (TS + Go). Per "extend shared utilities, don't fork them," this is preferred over duplicating the logic; it entails a minimal, behavior-preserving refactor of the merged ECS exporter (covered by its existing golden tests).

### Event mapping (per requirement)

Status roll-up: raw = `worstOf(results[].status)` over the five-value enum; `hdf_status` carries the **raw** verdict. `suppressed = isFailing(raw) AND NOT isFailing(effectiveStatus ?? raw)`.

| HEC / CIM field | Source (HDF) |
|---|---|
| `time` (envelope) | `results[0].startTime` ?? doc `timestamp` → epoch (via `parseTimestamp`); omitted if unparseable |
| `host` (envelope) | target `component` fqdn ?? name |
| `source` (envelope) | `"hdf-exporter"` (constant) |
| `sourcetype` (envelope) | `"hdf:results"` (constant) |
| `fields` (envelope, indexed) | flat copy of `signature`, `signature_id`, `severity`, `cvss`, `dest`, `dvc`, `hdf_status`, `suppressed` |
| `event.signature` | requirement `title` (fallback `id`) |
| `event.signature_id` | requirement `id` (SV-/CCI/rule id) |
| `event.cve` | CVE id from `cvss[].source` when CVE-shaped |
| `event.cvss` | max `baseScore` across `cvss[]` (single number; omitted when none) |
| `event.severity` | map(`impact`)/normalized source severity → CIM enum |
| `event.dest` | target `component` name/ip |
| `event.dvc` | scanner host, when known |
| `event.vendor_product` | `tool.name` |
| `event.category` | `cwe` name / control family |
| `event.hdf_status` | **raw** five-value verdict |
| `event.suppressed` | acceptance axis (bool) — raw-failing driven non-failing |
| `event.hdf.*` | **lossless:** status (raw), suppressed, effective_status, disposition, overridden, impact, severity, baseline, control_id, nist, cci, cwe, full tags, cvss[], epss, kev, affected_packages[], descriptions[], results[], status_overrides[], poams[], code, refs[], generator, tool, exporter_version |

## Alternatives Considered

### Alternative A: CIM-flat, one event per finding (no nested block)
Emit one flat, single-valued CIM row per result/CVE; keep no nested detail in the event (full detail stays in the source HDF file).
- **Pros:** Purest CIM fit; exactly what auto-KV/data-model acceleration wants; dodges the 5,000-char cutoff by construction; matches how vendor TAs shape data.
- **Cons:** Diverges from the `hdf-to-ecs` hybrid shape (two different exporter philosophies to maintain); drops HDF's in-event losslessness; per-finding fan-out complicates posture roll-up.
- **Why rejected:** The consumer chose the hybrid shape for consistency with ECS and to keep events lossless. The companion TA bridges the flatness gap — promoting the CIM-critical scalars to top-level/indexed fields gives clean data-model population without discarding the nested detail.

### Alternative B: Plain HEC passthrough (no CIM mapping)
Wrap the ECS-style hybrid event in a HEC envelope and stop; no CIM field names, no TA.
- **Pros:** Minimal work; Splunk indexes and can search it.
- **Cons:** Populates no CIM data model; no ES/RBA integration; not "CIM-compatible" in any real sense.
- **Why rejected:** The consumer explicitly wants full CIM mapping, not raw indexing.

### Alternative C: Ship no companion TA (rely on payload field names alone)
Emit CIM-named fields and a stable sourcetype, and let correct field names carry the integration.
- **Pros:** No new artifact type in the repo.
- **Cons:** Structurally cannot work — data-model membership requires `tag=…`, which only a TA (eventtypes/tags .conf) can apply inside Splunk. Correct field names alone never enter an event into a data model.
- **Why rejected:** It would ship output that looks CIM-compliant but populates nothing. Tagging is impossible from the write side.

### Alternative D: Map compliance findings to the Change data model
Use CIM **Change** (`action`, `status=success|failure`) for control results.
- **Pros:** Change has a `status` field that superficially resembles pass/fail.
- **Cons:** Change models administrative *mutations*; its `status` means "did the change operation succeed," not "did the control pass." Semantically wrong for an assessment verdict.
- **Why rejected:** Misrepresents assessment results as change events. Change only fits if we later emit *remediation* actions. Failed findings belong in Vulnerabilities.

### Alternative E: Put the full `cvss[]` array (or a vector) in CIM `cvss`
Preserve all CVSS detail in the CIM field.
- **Pros:** Lossless in the CIM field.
- **Cons:** CIM `cvss` is a single number; there is no `cvss_vector` field in the model. An array won't normalize.
- **Why rejected:** Violates CIM typing. We map `cvss` to the max base score and keep the full `cvss[]` in the lossless `hdf` block.

### Alternative F: Do Nothing
Ship only ECS; tell the consumer to store raw HDF.
- **Pros:** No new exporter/TA to maintain.
- **Cons:** Leaves a verified consumer's need unmet; HDF findings never reach their Splunk data models.
- **Why rejected:** There is a committed consumer.

## Consequences

**What becomes easier:**
- HDF findings populate Splunk's Vulnerabilities model and feed Enterprise Security / risk-based alerting, sitting alongside other CIM-normalized telemetry, while full HDF detail (overrides, POA&Ms, all CVSS) stays available in the `hdf.*` block for drill-down.
- Posture reporting ("X of Y controls passed") is preserved via `hdf_status` on every event, which CIM itself cannot express.
- Extracting the shared mapping core makes ECS and Splunk two thin projections over one tested fan-out/roll-up engine, so a third target (e.g. OCSF/Schema One) is cheaper.

**What becomes harder:**
- A new artifact type enters the repo — Splunk `.conf` files (`Splunk_TA_hdf`) — with no Go/TS test harness; correctness is verified by fixture assertions plus documented `btool`/manual validation, and the TA must be version-checked against CIM releases.
- The exporter converts timestamps to epoch (HEC `time`), a departure from the ECS exporter's raw pass-through; it must use the repo's `parseTimestamp` helpers and stay at TS↔Go parity.
- Two exporters now share a core; a change to the core must preserve both golden suites.

**Risks:**
- *5,000-char extraction cutoff hides deep nested fields.* *Mitigation:* all CIM-critical scalars are promoted to the top of the payload and mirrored into indexed `fields`; only drill-down detail lives deep in `hdf.*`.
- *CIM drift* — a future CIM version renames/moves a Vulnerabilities field. *Mitigation:* the mapping and required tags are pinned and documented in the TA; a CIM bump is a deliberate, tested change.
- *TA misinstallation by the consumer* yields indexed-but-untagged events. *Mitigation:* ship the TA with clear install docs and a verification search (`| tstats … from datamodel=Vulnerabilities`); the stable `sourcetype` contract is the one thing that must never change.
- *`cvss` reduction to a single number is lossy in the CIM field.* *Mitigation:* lossless full `cvss[]` retained in `hdf.*`; the reduction is documented.
- *TS/Go epoch or float divergence.* *Mitigation:* shared golden fixtures asserted by both suites, as in ECS.

## Implementation Plan

Per our convention, this ADR is written **first and reviewed before any code** (same gate as ECS/`wvc3.1`). Phases below become `wvc3.3` implementation work once the ADR is approved.

### Scope

**IN scope:**
- New converter `hdf-converters/converters/hdf-to-splunk/{go,typescript,fixtures}` — `ConvertHDFToSplunk(input, version) → HEC NDJSON` (Go) and `convertHdfToSplunk(input, version?) → HEC NDJSON` (TS), byte-identical parity.
- Extraction of the shared fan-out / roll-up / access core from `hdf-to-ecs` into `hdf-converters/shared` (TS + Go), with the ECS exporter refactored onto it (no output change).
- A minimal companion TA `Splunk_TA_hdf` (props/eventtypes/tags .conf) + install/verify docs.
- CLI wiring: `converter_hdf_to_splunk.go` registering `RegisterConverter("hdf", "splunk", …)` → `hdf convert --from hdf --to splunk`.
- Real fixtures (compliance, CVE, override) + assertion tests both languages; README + CHANGELOG.

**OUT of scope:**
- Schema One export profile (`wvc3.4`, blocked on the gated spec) — may attach here or to ECS later.
- The Change/remediation model (only relevant if we emit remediation actions).
- Live HEC POST / a streaming daemon (ADR-0003); the exporter writes files consumed by the consumer's ingestion.
- OCSF.

### Phases

#### Phase 0: Extract the shared mapping core (refactor, no behavior change)
**Files:**
- Create: `hdf-converters/shared/{go,typescript}/hdfmap/*` (fan-out, `worstOfResults`, component/tool/timestamp/description/ref helpers, generic access).
- Modify: `hdf-to-ecs` go + ts to consume the shared core.
- Test: existing ECS golden suites must pass unchanged.

**Acceptance criteria:**
- [ ] ECS golden output byte-identical before/after (no fixture change).
- [ ] Shared helpers unit-tested in both languages.

**Verification:** `cd hdf-converters && pnpm test:ts && go test ./...` (ECS goldens green).

#### Phase 1: `hdf-to-splunk` exporter (blocked by Phase 0)
**Files:**
- Create: `hdf-converters/converters/hdf-to-splunk/{go/converter.go,typescript/converter.ts,typescript/index.ts}`, fixtures, expected `.ndjson`.
- Modify: `hdf-converters/src/index.ts` barrel.
- Test: `go/converter_test.go`, `typescript/converter.test.ts`.

**Acceptance criteria:**
- [ ] HEC-envelope NDJSON, one event/requirement, LF-delimited, trailing newline; `sourcetype=hdf:results`; `time` epoch (via `parseTimestamp`, fallback documented).
- [ ] Flat CIM scalars promoted + mirrored into indexed `fields`; lossless `hdf.*` block present.
- [ ] `cvss` = max base score (number); `severity` maps to the CIM enum for all impact bands; full `cvss[]` retained in `hdf.*`.
- [ ] `hdf_status` carries all five **raw** statuses losslessly; CVE fixture emits `cve` + `cvss`, compliance fixture omits `cvss`.
- [ ] Waiver fixture: `hdf_status=failed` + `suppressed=true` (event + indexed fields); riskAdjustment fixture: `hdf_status=failed` + `suppressed=false`; disposition/overridden preserved in both.
- [ ] TS and Go byte-identical; empty/invalid input errors cleanly.

**Verification:** `cd hdf-converters && pnpm test:ts && go test ./converters/hdf-to-splunk/...`.

#### Phase 2: Companion TA `Splunk_TA_hdf` (parallel to Phase 1)
**Files:**
- Create: `hdf-converters/converters/hdf-to-splunk/Splunk_TA_hdf/{default/props.conf,default/eventtypes.conf,default/tags.conf,metadata/default.meta,README}`.

**Acceptance criteria:**
- [ ] `eventtypes.conf` keys on `sourcetype=hdf:results` and **excludes `suppressed=true`** (`… NOT suppressed=true`); `tags.conf` applies `vulnerability`+`report` to the finding eventtype; `props.conf` aliases scalars to CIM names + sets time.
- [ ] Documented verify step (`| tstats count from datamodel=Vulnerabilities …`) and install instructions.
- [ ] `.conf` stanzas validated (btool/manual) and covered by a fixture-level assertion that the exporter's field names match the TA's aliases.

**Verification:** conf review + a test asserting exporter output field names ⊆ TA-aliased set.

#### Phase 3: CLI + docs (blocked by Phase 1)
**Files:**
- Create: `hdf-cli/cmd/hdf/cmd/converter_hdf_to_splunk.go` (+ `_test.go`).
- Modify: `hdf-cli/README.md`, `hdf-converters/README.md` conversion tables; `CHANGELOG.md`.

**Acceptance criteria:**
- [ ] `hdf convert --from hdf --to splunk <results> -o out.ndjson` works; auto-listed in `--help`.
- [ ] CLI round-trip test (registered, NDJSON, invalid, empty-baselines).

**Verification:** `cd hdf-cli && go test ./cmd/hdf/cmd/ && golangci-lint run` && root `pnpm lint`.

### Verification Strategy
- **End-to-end:** build the CLI, convert real fixtures, confirm each line is a standalone HEC object (`jq -e .event`), spot-check promoted CIM scalars, indexed `fields`, epoch `time`, and a lossless `hdf` block including overrides.
- **CIM conformance (offline):** assert field names/enum values against the pinned CIM Vulnerabilities reference in tests (no live Splunk needed); assert the exporter's emitted scalar names are exactly the set the TA aliases.
- **TA smoke (documented, manual):** install `Splunk_TA_hdf`, HEC-post a fixture, confirm `tstats … datamodel=Vulnerabilities` returns the failed/CVE events and not the passed ones.
- **Edge cases:** pure-compliance (no `cvss`), multi-CVSS (max selection), waiver (raw-failing → `suppressed=true`), riskAdjustment (raw-failing → `suppressed=false`), missing/unparseable timestamp (HEC `time` omitted), multi-component docs.

## Notes

- ADR location: `dev-docs/` per project convention (historical artifact, not the published site).
- The `Splunk_TA_hdf` add-on is the first non-Go/non-TS build artifact shipped from `hdf-converters`; its home (co-located under the converter vs. a top-level `packaging/` dir) is finalized in Phase 2.
