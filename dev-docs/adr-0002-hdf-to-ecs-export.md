# ADR-0002: HDF → ECS export (`hdf-to-ecs`)

- **Status:** Accepted (colleague-reviewed 2026-07-06, no changes requested)
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

2. **Pass/fail = raw-primary, core-ECS purist (data-lake-first).** `event.outcome` is derived from the **raw** verdict (`worstOf(results[].status)`): `passed→success`, `failed→failure`, everything else `→unknown`. A waived/risk-accepted failure is **still `failure`** — the verdict field is never rewritten by an acceptance decision, so no consumer can mistake an accepted risk for a genuine pass. The lossless five-value raw status lives in `hdf.status`. We do **not** emit `result.evaluation` — it is not core ECS, and the data-lake target does not depend on Elastic Security's CSPM UI. (It can be added later as a derived field if a CSPM-UI consumer materializes.) See **Reconciliation: the raw-primary two-axis model** for the standards grounding and cross-exporter contract.

3. **Acceptance is a separate axis, promoted and preserved.** `hdf.suppressed` (boolean) is the acceptance axis, orthogonal to `event.outcome`: `true` exactly when the raw result is failing **and** an override drove the effective status non-failing (waiver / falsePositive / attestation). A `riskAdjustment` / `operationalRequirement` / `poam` that leaves the effective status failing is **not** suppressed — it stays actionable, only its impact is re-scored. `hdf.effective_status`, `hdf.effective_impact`, `hdf.disposition`, and `hdf.overridden` are flat/queryable; the full `statusOverrides[]` and `poams[]` history rides in the `hdf` block. The canonical "still actionable" consumer query is **`event.outcome:"failure" AND hdf.suppressed:false`**.

4. **Plain NDJSON, ECS 9.4.0.** One event per line, LF-delimited, no pretty-print, trailing newline; `ecs.version` pinned to `"9.4.0"`. `_bulk` action/metadata framing (and index naming) is an *ingest* concern left to the consumer — not hardcoded here (a future `--bulk` flag could add it).

5. **NIST/CCI and ATT&CK** ride in the `hdf.*` block (`hdf.nist`, `hdf.cci`, `hdf.cwe`) and, where present in tags, project to core `threat.*` (ATT&CK) and `rule.reference`. ECS has no native control-catalog fieldset, so the authoritative mapping stays in `hdf.*`.

### Event mapping (per requirement)

Status roll-up: raw = `worstOf(results[].status)`; effective = `effectiveStatus ?? raw`; `suppressed = isFailing(raw) AND NOT isFailing(effective)` (only `failed` is failing; `error` is indeterminate).

| ECS field | Source (HDF) |
|---|---|
| `@timestamp` | `results[0].startTime` ?? doc `timestamp` |
| `ecs.version` | `"9.4.0"` (constant) |
| `event.kind` | `"state"` |
| `event.category` | `["configuration"]` (+ `"vulnerability"` when CVE data present) |
| `event.type` | `["info"]` |
| `event.outcome` | map(**raw** status): passed→success, failed→failure, else→unknown (a waived failure is still `failure`) |
| `event.id` | deterministic: component + baseline + requirement id |
| `event.dataset` / `event.module` | `"hdf.findings"` / `"hdf"` |
| `message` | requirement title + status |
| `observer.{name,product,version,type}` | `tool` (fallback `generator`); type=`"scanner"` |
| `host.{name,id,ip,mac,os.*}`, `related.{hosts,ip}` | target `component` (fqdn/name, componentId, ipAddress, macAddress, osName/osVersion) |
| `rule.{id,name,description,ruleset,version,reference}` | requirement id/title/default-description, baseline name/version, `refs[0].url` |
| `vulnerability.{id,enumeration,classification,score.base,score.version,severity,scanner.vendor,description}` | `cvss[]`/`cwe[]`/`affectedPackages[]` (present only for CVE findings) |
| `threat.{framework,tactic.*,technique.*}` | ATT&CK from `tags.mitre_attack`/`tags.attack` (best-effort) |
| `hdf.*` | **lossless:** `status` (raw), `suppressed`, `effective_status`, `effective_impact`, `impact`, `severity`, `disposition`, `overridden`, `baseline`, `control_id`, `nist`, `cci`, `cwe`, full `tags`, `cvss[]`, `epss`, `kev`, `affected_packages[]`, `descriptions[]`, `results[]`, `status_overrides[]`, `poams[]`, `code`, `refs[]`, `generator`, `tool`, `exporter_version` |

## Reconciliation: the raw-primary two-axis model (shared by all three exporters)

All three SIEM exporters — `hdf-to-ecs`, `hdf-to-splunk` (ADR-0004), and `hdf-to-ocsf` (addendum below) — implement **one** status model. This was made uniform after a pre-merge review found ECS/Splunk on effective-primary and OCSF on raw-primary; two research passes (internal HDF precedent + external standards) resolved decisively on **raw-primary**, and all three were aligned to it. It is an error for the exporters to diverge here.

**The two axes (orthogonal):**

1. **Verdict (raw)** — did the control pass or fail *as tested*? Always the raw `worstOf(results[].status)`. An acceptance decision (waiver, risk acceptance) **never** rewrites it. A waived failure is still a failure.
2. **Acceptance (`suppressed`)** — has a governance decision removed this raw failure from the actionable set? `suppressed = isFailing(raw) AND NOT isFailing(effective)`. True only for **waiver / falsePositive / attestation** (which drive the effective status non-failing). A **riskAdjustment / operationalRequirement / poam** leaves the effective status failing → **not** suppressed → still actionable, only its impact is re-scored.

**Why raw-primary (standards grounding):**

- **NIST SP 800-53A / RMF (SP 800-37):** control assessment (Satisfied / Other-Than-Satisfied) and risk response (accept / mitigate / transfer) are *separate steps*. Accepting a risk does not make the control Satisfied. Effective-primary collapses these two steps into one and loses the assessment result.
- **FedRAMP deviation requests:** a Risk Adjustment or Operational Requirement leaves the finding **Open** in the POA&M; only the risk rating or remediation obligation changes. False Positive is the one that closes it.
- **OSCAL Assessment Results:** `finding.target.status` (the objective result) and `finding.associated-risk[].facet` (the risk response) are distinct axes that persist independently — findings are not deleted by risk acceptance.
- **VEX:** `not_affected` records the product as *present but the vuln not exploitable* — the component still ships the affected package; the finding is contextualized, not erased.
- **OCSF / AWS Security Hub / Rapid7 / Sysdig:** all model *Suppressed ≠ Resolved* — suppression is an acknowledgement axis separate from the finding's own pass/fail/open state.

Effective-primary (rewriting the verdict to the post-acceptance status) is an **audit-integrity anti-pattern**: a reader of the verdict field cannot distinguish "genuinely passed" from "failed but accepted," and actionable-failure counts silently drop when risks are accepted.

**How each exporter carries the two axes (same model, native field per platform):**

| Axis | ECS | Splunk (CIM/HEC) | OCSF |
|---|---|---|---|
| **Verdict (raw)** | `event.outcome` (success/failure/unknown) | `hdf_status` (raw 5-value) | `compliance.status_id` (1/2/3) |
| **Acceptance** | `hdf.suppressed` (bool) | `suppressed` (bool, event + indexed fields) | base `status_id` (1 New vs 3 Suppressed) |
| **"Still actionable" query** | `event.outcome:"failure" AND hdf.suppressed:false` | `hdf_status=failed suppressed=false` | `compliance.status_id=3 AND status_id=1` |
| **Full lossless override chain** | `hdf.status_overrides[]` | `hdf.status_overrides[]` | `unmapped.hdf_requirement` |

The Splunk companion TA excludes `suppressed=true` from the CIM Vulnerabilities data model, so a waived control drops out while a risk-adjusted still-failing control stays in — the data-model equivalent of the query above.

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
- HDF findings become first-class, queryable ECS events in a data lake — filterable by `event.outcome`, `hdf.suppressed`, `rule.ruleset`, `vulnerability.severity`, and (for governance) `hdf.disposition` / `hdf.effective_status` — sitting alongside other telemetry. The actionable-failures view is `event.outcome:"failure" AND hdf.suppressed:false`.
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
- [ ] `event.outcome` maps the **raw** status for each of the five values; lossless five-value in `hdf.status`; `hdf.suppressed` is the acceptance axis.
- [ ] `vulnerability.*` populated for the CVE fixture, absent for pure-compliance.
- [ ] Waiver fixture → `event.outcome:"failure"` + `hdf.suppressed:true` + `hdf.disposition` + `hdf.effective_status` + full `hdf.status_overrides`; riskAdjustment fixture → `event.outcome:"failure"` + `hdf.suppressed:false` (still actionable).
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
- **Amended 2026-07-09** with the *Addendum: HDF → OCSF export* below (`wvc3.5`). Rather than mint a separate ADR per SIEM target, additional export targets that reuse this ADR's architecture (fan-out, shared `exportmap` core, NDJSON, TS↔Go byte-identical parity) are recorded as dated addenda here. (Splunk CIM export is the exception — its own ADR-0004 predates this convention.)

---

## Addendum: HDF → OCSF export (`hdf-to-ocsf`, `wvc3.5`) — 2026-07-09

### Context

The third SIEM-export target. Prompted by the finding that "Schema One" is a DoD program label with no field spec (see `wvc3.4` closure + bd memory `schema-one-is-a-program-not-a-schema`) — its only concrete, implementable meaning for security telemetry is **OCSF** (Open Cybersecurity Schema Framework), a real, versioned, field-defined standard. OCSF is also a materially *cleaner* fit than Splunk CIM (ADR-0004): where CIM has **no** compliance data model (forcing failed controls into Vulnerabilities), OCSF has native **Compliance Finding** *and* **Vulnerability Finding** classes under its Findings category, plus a schema-sanctioned lossless-carry container (`unmapped`). This exporter reuses this ADR's architecture wholesale (per-requirement fan-out, the shared `exportmap` core, NDJSON, TS↔Go byte-identical parity) — only the target field shaping is OCSF-specific.

Research pinned **OCSF v1.8.0** (2026-03-18, `github.com/ocsf/ocsf-schema`), verified against `schema.ocsf.io/1.8.0` and the raw dictionary.

### Decision

`hdf-to-ocsf` emits **plain NDJSON — one OCSF Finding object per `Evaluated_Requirement`**, each self-describing via its `class_uid`. Unlike ECS/Splunk (one hybrid event shape), OCSF is a *native* target: each requirement maps to a real OCSF finding class rather than a projection + lossless block.

1. **Two classes, discriminated by CVE data.** A requirement carrying `cvss[]` → **Vulnerability Finding** (`class_uid 2002`); otherwise → **Compliance Finding** (`class_uid 2003`). Both are `category_uid 2` (Findings). `activity_id = 1` (Create); `type_uid = class_uid*100 + activity_id` (→ `200201` / `200301`).

2. **Raw-primary verdict + lifecycle override axis (base fields only — no profile).** OCSF gives two orthogonal, first-class enum axes, and we use both with the *raw* result kept authoritative:
   - The **compliance verdict** rides on `compliance.status_id` (`1 Pass / 2 Warning / 3 Fail`), always reflecting the **raw** HDF result. A failed control **stays `Fail` even when waived** — the verdict is never rewritten to `Pass`, so no consumer can mistake a waiver for a genuine pass by reading the verdict field.
   - **Overrides** ride on the base finding `status_id` (lifecycle enum `1 New / 2 In Progress / 3 Suppressed / 4 Resolved / …`). This is the "is it still my problem?" axis. See the **Override representation** subsection for the exact encoding, the consumer query it enables, and OCSF's genuine limitations here.

   *Rejected: effective-primary* (`compliance.status_id = effectiveStatus`) — it masks a waived failure as `Pass` and forces a naive verdict-only consumer to over-count compliance. *Rejected: the `incident` profile's `verdict_id`* — it is the only first-class field for an override *reason*, but the profile's own definition is "attributes that add **incident handling semantics** to a Finding," so applying it to a routine compliance/evidence result mislabels it as an incident. Base fields only.

3. **HDF status → `compliance.status_id` mapping** (using only the confirmed enum `1 Pass / 2 Warning / 3 Fail`): `passed → 1 Pass`; `failed → 3 Fail`; `error` / `notApplicable` / `notReviewed → 2 Warning` (OCSF `2 Warning` = "did not yield a [pass/fail] result"). The sibling string `compliance.status` carries the **OCSF caption** of that enum (`Pass` / `Warning` / `Fail`) — OCSF's convention is that an enum's sibling string is the caption of the enum value, and emitting a non-caption string triggers a validator `attribute_enum_sibling_incorrect` warning on every event. The **exact** HDF status (which distinguishes `error` vs `notApplicable` vs `notReviewed`, all → `Warning`) is preserved verbatim in `unmapped.hdf_requirement.results[].status` / `.effectiveStatus`, so nothing is lost by collapsing them onto `Warning`. A Compliance Finding is emitted for **every** requirement (pass, fail, or in-between), so full posture survives natively — no custom sidecar needed (contrast CIM, ADR-0004). Note this keeps the actionable-failures query clean: only real failures are `status_id = 3`, so `notApplicable`/`notReviewed`/`error` never pollute a `compliance.status_id = 3` filter.

4. **Control/framework ids via `compliance.checks[]`.** Each HDF control mapping becomes a `check` object: `check.uid` = the control id (STIG `V-230234`, NIST `AC-17(2)`, `CCI-000068`) and `check.standards[]` = the framework(s). Only the **primary** (STIG-rule) check carries a `check.status_id` — HDF has a single per-requirement verdict, not a per-framework-id one, so the NIST/CCI framework checks carry the id + standards without a separate (fabricated) status. `compliance.control` (single string) carries the primary rule id and `compliance.standards[]` the framework list. This `checks[]` pattern is OCSF's intended mechanism for one finding to carry many framework control ids — a direct fit for HDF's `tags.nist`/`tags.cci`/STIG id arrays.

   **Class-routing limitation (CVE + framework tags).** `compliance.checks[]` is a **Compliance Finding (2003)** field — the OCSF v1.8.0 **Vulnerability Finding (2002)** class has no `compliance` object at all (verified against the schema server). So a requirement that carries *both* a CVE and NIST/CCI tags routes to a Vulnerability Finding and cannot use `compliance.checks[]`. Rather than bury the mapping in `unmapped` (opaque, not a query surface), the exporter surfaces it on **`finding_info.tags[]`** — OCSF's queryable `key_value_object` tag surface, present on both finding classes — as `{name:"nist", values:[…]}` / `{name:"cci", values:[…]}`. Compliance Findings keep the richer native `compliance.checks[]` (with per-check `status_id`); Vulnerability Findings expose the framework mapping via `finding_info.tags`. A cross-class "findings mapped to control X" query therefore checks `compliance.checks[].uid` OR `finding_info.tags`. (Alternatives considered and rejected: `enrichments[]` — heavier, and `finding_info.tags` is the more direct fit; dual-emitting a 2002 + a 2003 finding — breaks one-finding-per-requirement and double-counts in dashboards/`tstats`. The full requirement, including the raw tags, is preserved in `unmapped.hdf_requirement` regardless.)

5. **`severity_id` from HDF impact** (OCSF enum `0 Unknown, 1 Informational, 2 Low, 3 Medium, 4 High, 5 Critical, 6 Fatal, 99 Other`): `≥0.9 → 5 Critical`, `≥0.7 → 4 High`, `≥0.4 → 3 Medium`, `≥0.1 → 2 Low`, else `1 Informational`; no impact → normalize a source severity string, else `0 Unknown`.

6. **Vulnerability Finding payload.** `vulnerabilities[]` → one `vulnerability` with `cve.uid` (the CVE id from `cvss[].source`), `cve.cvss[]` mapping each HDF `cvss[]` entry 1:1 (`base_score` **Float**, `version` **required**, `vector_string`, `severity`), and `cve.related_cwes` (note `cve.cwe` is deprecated ≥v1.4.0). The `vulnerability` "exactly one of cve/cwe/advisory" constraint is satisfied by populating `cve`. **`base_score` is emitted as OCSF `float_t`** — always with a decimal point (`10.0`, not the integer `10`), since the OCSF validator rejects an integer-shaped token for a float field. This is rendered via the shared `exportmap.FloatToken` (Go `json.Number`) / `floatNumber` (TS `RawNumber`), byte-identical across languages. The ECS (`vulnerability.score.base`) and Splunk (`cvss`) exporters do **not** apply this — Elasticsearch coerces integer JSON to its float field mapping and Splunk does no index-time numeric typing, so a whole-number score there is not an error.

7. **Host and tool.** The target component → the top-level `device` object: `device.name`, `device.hostname` (HDF fqdn — OCSF v1.8.0 `device` has no `fqdn` field), `device.ip`, `device.uid` (componentId), and `device.os.{name, type_id, version}` (`os.type_id` classified from the OS string: Windows→100, Linux→200, macOS→300, else 0). `device.type_id` defaults to `0 Unknown`. The scanning tool → `metadata.product.{name, version, vendor_name}`; `metadata.version = "1.8.0"` (the OCSF schema version, **not** the tool version).

8. **Lossless carry via `unmapped`.** The full original HDF requirement is preserved under **`unmapped.hdf_requirement`** — `unmapped` is OCSF's schema-sanctioned, always-valid, *queryable* object for source data with no standard home. This replaces the ECS/Splunk `hdf.*` block with an OCSF-native mechanism; no extension/registry needed. (A first-class `hdf`-prefixed OCSF *extension* was considered and rejected as overkill — see below.)

9. **`time` = epoch milliseconds** (OCSF convention) from `results[0].startTime` via the canonical `parseTimestamp` (Go `.UnixMilli()` / TS `.getTime()`) — **note:** OCSF uses millis, unlike Splunk HEC's epoch *seconds* (ADR-0004). Integer millis keep Go/TS byte-identical.

10. **Plain NDJSON, one finding per line.** Each object self-identifies via `class_uid`, so mixing `2002`/`2003` lines is valid and consumer-disambiguable. The OCSF *bundle frame* (`{events:[…], count, …}`) and Amazon-Security-Lake Parquet (one class per object) are ingest concerns left to the consumer; a `--bundle` flag is a possible future add (mirrors ECS's deferred `--bulk`).

### Override representation

The exporter encodes HDF's **acceptance axis** onto the base finding `status_id` so a consumer can filter adjudicated vs. actionable findings **on normalized enums only — never on free text**. The axis is keyed on whether the override drove the *effective status* non-failing — **not** on the mere presence of an override. This is the crux: a `riskAdjustment` / `operationalRequirement` / `poam` is an *open* accepted risk that leaves the finding failing, so it must stay actionable. The contract (an invariant this exporter guarantees):

| HDF override state | effective status | `status_id` |
|---|---|---|
| no override | (raw) | `1 New` |
| waiver / falsePositive / attestation (raw-failing driven non-failing) | non-failing | `3 Suppressed` |
| riskAdjustment / operationalRequirement / poam (still failing) | failing | `1 New` |

Formally: `status_id = 3 Suppressed` iff `suppressed` (raw failing ∧ effective non-failing), else `1 New`. This is the same `Suppressed` axis the ECS/Splunk exporters use (see **Reconciliation**). (HDF overrides that leave a result failing are *open* accepted risks; a genuinely *remediated* control simply passes on the next scan as a raw `passed` with no override — so this exporter does not emit `4 Resolved`; that lifecycle value is left for a downstream OCSF workflow to set.)

Combined with the raw-primary `compliance.status_id`, this yields the **canonical consumer query for "open, actionable, not-accepted-as-closed compliance failures":**

```
class_uid = 2003 AND compliance.status_id = 3 (Fail) AND status_id = 1 (New)
```

A waived / false-positive / attested failure falls out on `status_id = 3 Suppressed`; a genuine open fail **and a risk-adjusted still-open fail** both pass through as `status_id = 1`. "Show me the accepted-as-closed failures" is `compliance.status_id = 3 AND status_id = 3`. For Vulnerability Findings (no `compliance.status_id` — the finding's existence is the problem) it reduces to `class_uid = 2002 AND status_id = 1`. Mental model: `status_id` = *has it been accepted out of my actionable set?*; `compliance.status_id` = *did it pass or fail?* — independent axes.

**Two honest limitations (documented, not worked around):**

1. **OCSF has no native compliance-waiver / risk-acceptance concept.** `status_id = 3 Suppressed` is defined as *"reviewed, determined to be benign or a false positive"* — a good fit for `falsePositive` and an acceptable one for a *waiver* / *attestation* (adjudicated out of the actionable set). It deliberately does **not** cover `riskAdjustment` / `operationalRequirement`: those leave the finding failing and *actionable*, so they stay `1 New` (only the impact/severity is re-scored), never Suppressed. `3 Suppressed` is the closest lifecycle state for "adjudicated, removed from the actionable set," and it makes the query above work. The **exact** override type, its justification, expiry, author, and the full multi-entry `statusOverrides[]` chain are preserved in `unmapped.hdf_requirement` (lossless) and the governing reason is additionally surfaced in `comment` (human-readable). No first-class OCSF field carries the override *type* without misusing the incident profile — so it deliberately lives in `comment` + `unmapped`, never gated behind free-text for the core actionable-vs-adjudicated filter.
2. **`status_id` is nominally consumer-set.** OCSF documents `status_id` as *"set by the consumer"* (the downstream triage field). This exporter pre-populates it from HDF's authoritative adjudication (HDF already carries the waivers), handing the consumer a correct initial triage state rather than making them re-derive it; a downstream workflow may still overwrite it. This producer-side pre-population is part of the documented mapping contract.

### Event mapping (per requirement)

| OCSF field | Source (HDF) | Class |
|---|---|---|
| `class_uid` / `category_uid` / `type_uid` / `activity_id` | constants (2002/2003, 2, computed, 1) | both |
| `time` | `results[0].startTime` → epoch **millis** (`parseTimestamp`) | both |
| `severity_id` | map(`impact`) → OCSF 0–6 | both |
| `metadata.product.{name,version,vendor_name}` / `metadata.version` | `tool`/`generator`; `"1.8.0"` | both |
| `finding_info.{uid,title,desc}` | requirement id / title / default description | both |
| `device.{name,hostname,ip,uid,os.*}` | target `component` (name/fqdn/ip/componentId/osName/osVersion) | both |
| `unmapped.hdf_requirement` | **the full original requirement (lossless)** | both |
| `status_id` (lifecycle) | `suppressed` (raw-failing driven non-failing) → `3 Suppressed`; else `1 New` | both |
| `compliance.status_id` + `compliance.status` | map(**raw** status) → 1/2/3 + OCSF caption (`Pass`/`Warning`/`Fail`) | Compliance (2003) |
| `compliance.control` / `compliance.standards[]` / `compliance.checks[]` | STIG id / frameworks / per-control `{uid,standards,status_id}` from tags | Compliance (2003) |
| `vulnerabilities[].cve.{uid,cvss[],related_cwes,references}` | `cvss[].source` + `cvss[]` 1:1 + `cwe` + refs | Vulnerability (2002) |

### Alternatives (OCSF-specific)

- **Reuse the ECS/Splunk `hdf.*` block for losslessness.** *Rejected:* OCSF provides `unmapped` — a schema-native, validation-safe container for exactly this. Using a bespoke `hdf.*` key would be non-idiomatic and risk validation friction.
- **`raw_data` (stringified requirement).** *Rejected:* it is a String — consumers must re-parse it and it isn't queryable; `unmapped` (object) is superior.
- **A first-class OCSF `hdf` extension/profile.** *Rejected (for now):* the "legitimate named attribute" route requires registering an extension UID and shipping an extension schema. Overkill for an exporter; `unmapped` is the standards-blessed pragmatic choice. Revisit only if a consumer must schema-validate the HDF payload's internal structure.
- **Force failed controls into Vulnerability Finding (the CIM approach).** *Rejected:* unnecessary in OCSF — Compliance Finding is a real class. Only genuine CVE findings become Vulnerability Findings.
- **Bundle-frame-only output.** *Rejected as default:* NDJSON is consistent with our other exporters and lake-friendly; the bundle frame is a future `--bundle` flag.

### Scope / plan (this is `wvc3.5`)

Same shape as the ECS/Splunk exporter cards: new `hdf-converters/converters/hdf-to-ocsf/{go,typescript,fixtures}` (`ConvertHDFToOCSF(input,version) → NDJSON`), reusing `exportmap`; CLI `converter_hdf_to_ocsf.go` registering `RegisterConverter("hdf","ocsf",…)`; real fixtures (the shared compliance/cve/override inputs); dual TS+Go byte-identical golden tests; README + CHANGELOG. Severity/OS-type/status helpers are OCSF-specific and unit-tested. **`notApplicable`/`notReviewed`/`error` convention (as implemented):** all three map to `compliance.status_id = 2 Warning`, with `compliance.status` carrying the OCSF caption `"Warning"` (see decision 3 above). The exact HDF status is preserved in `unmapped.hdf_requirement`. (No `0 Unknown` / `99 Other` compliance status is emitted — only `1`/`2`/`3`.)
