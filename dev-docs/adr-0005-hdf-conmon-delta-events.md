# ADR-0005: HDF continuous-monitoring delta-event stream — schema + kernel (speculative build)

- **Status:** Proposed — draft for review
- **Date:** 2026-07-22
- **Deciders:** Will Dower
- **Supersedes the deferral in:** **[ADR-0003](adr-0003-hdf-conmon-streaming.md)** (which recorded the target architecture but gated the build on an event producer existing). This ADR follows up on ADR-0003: we are now picking up the streaming direction and advancing it to ADR-0003's "Phase 2 — streaming design ADR + delta-event schema."
- **Builds on:** **[ADR-0002](adr-0002-hdf-to-ecs-export.md)** (HDF → ECS export) and the shipped `hdf-to-ocsf` exporter (native OCSF Compliance Finding, class 2003) — the SIEM *projection* substrate reused inside every event.

## Context

We are following up on ADR-0003 and now intend to **stream individual events in HDF to support cATO** (continuous Authority to Operate). This revisits ADR-0003's producer-availability gate: we will build the streaming **library kernel speculatively** — ahead of any production event producer — so the schema and the pure functions exist and are validated when a producer materializes.

What has and has not changed since ADR-0003 (2026-07-06):

- **Changed:** the decision to build now, not defer. The gate ("no producer exists, so don't build the pipe") is deliberately relaxed for the *library* pieces (schema + pure delta function), which are useful and testable without a producer.
- **Not changed:** we still do **not** own a producer that emits per-result or per-checksum events. We may build a **dead-simple, throwaway "hello-world" producer** purely to exercise the schema/function in tests — and, per ADR-0003's format-vs-transport boundary, **that producer lives outside hdf-libs** (a scratch project or SAF CLI), never in this repo.
- **Already shipped substrate:** the batch HDF → ECS export (ADR-0002) and `hdf-to-ocsf` (OCSF Compliance Finding 2003 + Vulnerability Finding 2002, `compliance.checks[]`/`status_id`, OCSF v1.8.0). So the "project posture into SIEM fields" half is done; this ADR is about the *event/delta* half.
- **Already-present delta vocabulary:** `hdf-comparison` has a **`systemDrift`** mode carrying a **`systemRef`**, `drift`, and per-entity diffs (`requirementDiffs`, `componentDiffs`, `packageDiffs`) with states `new | absent | unchanged | updated` (and `added | removed` for packages). The delta-event is therefore an *increment of something we already model*, not a new vocabulary.

ADR-0003 already settled the architecture (delta events, not a raw-result firehose; keyed last-value detection; the checksum heartbeat; the format-vs-transport split). This ADR does **not** relitigate that. It resolves the two questions ADR-0003 left open and this effort now forces:

1. **What is the delta anchored against, and where does the accumulated result live** in the HDF document ecosystem — an evidence package? a system? a new results snapshot?
2. **How does that fit the OSCAL ecosystem** HDF aligns with (SSP / SAR / POA&M / assessment observations), so a cATO consumer can reconcile a stream of deltas back into the governance artifacts an ATO actually consumes.

## Decision

**Build, speculatively and library-only: (a) an HDF delta-event schema expressed as a streaming profile of `hdf-comparison`, and (b) a pure, stateless `deltaFromPrevious(prevState, newResult) → DeltaEvent | null` function plus its inverse `foldDeltaIntoComparison`.** No runtime, no broker, no producer in this repo. Anchor and reconciliation are decided as follows.

### 1. The delta is anchored to a **system**, keyed by `(systemRef, componentId, requirementId)`

The stateful entity a cATO pipeline monitors is a **system's authorization boundary** — exactly what `hdf-system` (≈ OSCAL SSP) defines and what `hdf-comparison`'s `systemDrift` mode already diffs against via `systemRef`. So:

- A **delta-event is one `requirementDiff` (or `componentDiff`) of a `systemDrift` comparison**, carrying the `systemRef`, the component/requirement identity, the prior and new effective status/impact, a `drift` state (`new`/`updated`/`absent`/…), and the timestamp.
- The detection key is `(systemRef, componentId, requirementId)` → last-value `{ effectiveStatus, effectiveImpact, checksum }`. This is ADR-0003's keyed compaction made concrete against the system anchor.
- We **reuse the `hdf-comparison` diff vocabulary**; we do not invent a parallel set of change states.

### 2. The stream is a **signal, not a live-mutated document**

A delta-event stream does **not** mutate an `hdf-evidence-package`, `hdf-system`, or `hdf-results` document in place. Those remain the periodic, authoritative, human-reviewable snapshots that an ATO consumes. The stream is the *between-snapshots signal*. Reconciliation back into governance artifacts is an explicit, separable operation:

- **Materialize:** folding an accumulated window of delta-events yields a full `hdf-comparison` (systemDrift) document — the same shape we already produce in batch. hdf-libs owns the pure `foldDeltaIntoComparison`.
- **Snapshot:** applying deltas to a prior `hdf-results` yields the current posture as a fresh `hdf-results` (≈ an incremental SAR update).
- **Escalate (governance):** a sustained or repeat failure can drive an `hdf-amendments` (≈ POA&M) entry. Whether/when that happens is a *policy* decision for the consuming tool, not something the stream does automatically — hdf-libs provides the pure classification, not the trigger.

### 3. OSCAL fit

HDF aligns to OSCAL as: `hdf-system`≈SSP, `hdf-results`≈SAR (findings/observations), `hdf-amendments`≈POA&M, `hdf-baseline`≈catalog/profile. A cATO program in OSCAL terms is **continuous SAR + POA&M updates against a fixed SSP**. The HDF delta-event is therefore the **wire form of an incremental SAR observation/finding change** against an SSP-defined system, reconcilable into a SAR (`hdf-results`) and, on escalation, a POA&M (`hdf-amendments`). This positions the stream inside — not beside — the OSCAL story we already support: it is the streaming increment whose batch reconciliation is ordinary SAR/POA&M.

### 4. Format-vs-transport boundary (unchanged from ADR-0003, restated for scope)

- **hdf-libs owns (stateless, deterministic, TS↔Go parity, real fixtures):** the delta-event schema; `deltaFromPrevious`; `foldDeltaIntoComparison`; the ECS/OCSF projection (already shipped); and any finer-grained checksum needed to localize change.
- **hdf-libs does NOT own:** the producer, the state store, the stream processor, the message bus, keying/partitioning at runtime, and deployment topology. The optional throwaway test producer is a scratch/SAF artifact.

### 5. Enabling change: finer-grained change detection

`resultsChecksum` is per-baseline today, which cannot say *which control* moved. We will add a **per-requirement effective-fields checksum** (the minimal set: `effectiveStatus`, `effectiveImpact`, `disposition`) to `hdf-results` so a delta is localizable and a heartbeat can be per-control. Exact field set and algorithm are an open question for the schema phase (below).

## Worked example: continuous monitoring of a RHEL host

This walks a single RHEL 9 host from deploy to steady-state CONMON, to make the moving parts concrete. It also settles a common confusion: **almost nothing about the `hdf-system` document changes on a per-event basis — the *posture* updates continuously, the system *definition* does not.**

The pieces referenced below: the pure functions `deltaFromPrevious` / `foldDeltaIntoComparison` (hdf-libs, this ADR); the batch converters `inspec → hdf-results` and `hdf-to-ocsf`/`hdf-to-ecs` (already shipped); and an **external** producer + keyed last-value store (SAF / a scratch tool — not hdf-libs).

**Step 0 — Preconditions.** An `hdf-baseline` for the RHEL 9 STIG (the requirement catalog, ~370 rules) exists. The external test producer and a small keyed state store exist outside this repo.

**Step 1 — Deploy and enroll the host (authoring, one time).** Provision RHEL 9 host `web01`. Author (or append to) the **`hdf-system`** document for the authorization boundary — say a system named `AppTier` — adding `web01` as a `host` component with a stable `componentId` (UUID). This is the SSP-equivalent: the boundary, components, data flows, and control designations. **It is written deliberately and changes only when the boundary changes** (a component is enrolled, retired, or re-designated) — not when a scan result moves.

**Step 2 — Initial scan → the first snapshot.** Run the RHEL 9 STIG InSpec profile against `web01`; convert the InSpec JSON to **`hdf-results`** (the SAR-equivalent point-in-time snapshot), tied to `systemRef=AppTier` and `componentId=web01`. Say 370 requirements: 41 failed, the rest passed. This snapshot is authoritative and auditable as-is — the classic HDF artifact.

**Step 3 — Seed the last-value state.** The external reconciler ingests that initial `hdf-results` and populates the keyed store — one tiny row per control:

```
(AppTier, web01, RHEL-09-255065) → { effectiveStatus: failed, effectiveImpact: 0.5, checksum: 9f2a… }
(AppTier, web01, RHEL-09-211010) → { effectiveStatus: passed, effectiveImpact: 0.0, checksum: 1b7c… }
…
```

The `checksum` is the new per-requirement effective-fields checksum (Decision §5). There is now a baseline to delta against. No events yet.

**Step 4 — Steady state: re-evaluate and emit only what moved.** On a cadence (or on config-change triggers), the producer re-runs InSpec on `web01`. For each evaluated requirement it can emit either a full per-result event or just a per-requirement **checksum heartbeat** (a few bytes). The reconciler calls `deltaFromPrevious(prevState[key], newResult)`:

- **Unchanged** (checksum matches) → returns `null`, no event. This is the overwhelming majority every scan — the "still passing / still failing" noise never hits the stream.
- **Changed** → returns a **DeltaEvent**. Example: the FIPS SSH-cipher control `RHEL-09-255065` was remediated, `failed → passed`:

  ```json
  { "systemRef": "AppTier", "componentId": "web01",
    "requirementId": "RHEL-09-255065", "drift": "updated",
    "from": { "effectiveStatus": "failed", "effectiveImpact": 0.5 },
    "to":   { "effectiveStatus": "passed", "effectiveImpact": 0.0 },
    "priorChecksum": "9f2a…", "timestamp": "2026-07-22T14:03:11Z" }
  ```

  The reconciler updates the stored last-value for that key. That single event *is* one `requirementDiff` of a `systemDrift` `hdf-comparison` — the same vocabulary we already validate.

**Step 5 — Fan-out.** Each DeltaEvent goes two places:
- **SOC / SIEM:** projected through the shipped `hdf-to-ocsf` / `hdf-to-ecs` mapping (OCSF Compliance Finding, class 2003) so the drift shows up next to operational telemetry and is alertable.
- **Governance reconciler:** appended to the running window for `AppTier`.

**Step 6 — Materialize current posture (the "continually updating" part).** On demand or on a cadence, the reconciler **folds** the accumulated deltas over the initial snapshot — two pure, deterministic outputs, neither of which mutates a document in place:
- `foldDeltaIntoComparison(events, initialResults)` → a fresh **`hdf-comparison` (systemDrift)** for `AppTier`: exactly what drifted since the last snapshot (e.g. "3 controls improved, 1 regressed").
- applying the same deltas to the prior `hdf-results` → an updated **current-posture `hdf-results`** — the incremental SAR that answers "what is `web01`'s posture *right now*." A cATO dashboard reads this.

  What is **not** rewritten on each event: the `hdf-system` document. Its components and control designations are the stable boundary; the churn lives entirely in the results/comparison it *references*. The system doc is edited only in Step 8.

**Step 7 — Escalation (governance policy, external).** If `RHEL-09-255065` stays failed past a policy threshold (e.g. N hours, or a severity gate), the consuming tool — not the stream — emits an **`hdf-amendments`** / POA&M entry against `(AppTier, web01, RHEL-09-255065)`. hdf-libs supplies the classification in the event; the *trigger* is the consumer's policy. The cATO authorization view = folded posture + open POA&Ms against a fixed SSP — ordinary OSCAL continuous monitoring, fed by the stream.

**Step 8 — Boundary change.** When `web01` is decommissioned, the `hdf-system` document is updated to remove the component (a rare, deliberate edit), the reconciler drops its keys, and a `drift: "absent"` event marks the disappearance so downstream views stop expecting it.

**Why the loop holds together:** stable `componentId` + `requirementId` are the join keys across every scan; the per-requirement checksum decides what moved; `deltaFromPrevious` turns "moved" into an event; `foldDeltaIntoComparison` turns a window of events back into the batch artifacts governance already understands. Everything hdf-libs owns is a pure function over those keys — the state store, cadence, and transport are the external producer/reconciler's job.

## Alternatives Considered

### Alternative A: New standalone `hdf-conmon-event` document type
Define a brand-new event schema unrelated to `hdf-comparison`.
- **Pros:** Freedom to shape the envelope exactly for the wire.
- **Cons:** Duplicates the diff vocabulary (`new/absent/updated`, `systemRef`, drift) we already validate and generate; two things to version and keep in sync; consumers learn a second model.
- **Why rejected:** The delta *is* a single comparison entry; a streaming profile of `hdf-comparison` reuses the schema, the validators, and the batch↔stream reconciliation for free.

### Alternative B: Emit raw per-result events (the firehose)
Stream every evaluated requirement as it completes, each re-carrying metadata.
- **Pros:** No state anywhere.
- **Cons / Why rejected:** Already rejected in ADR-0003 (Alt C). It conflates lake ingestion (served by the batch exporter + lake) with the SOC delta signal, and re-carries metadata HDF exists to normalize. The requester confirmed they want the **delta-event stream**, not the firehose.

### Alternative C: Anchor the delta to an evidence package (mutate it live)
Treat the `hdf-evidence-package` as a living object the stream updates in place.
- **Pros:** One artifact reflects "current posture" at all times.
- **Cons:** Destroys the snapshot semantics that make HDF useful for accreditation (an evidence package is a point-in-time bundle an auditor signs off); creates write contention and an unauditable mutable record; conflates signal with artifact.
- **Why rejected:** Decision §2 — the stream is a signal; the authoritative artifacts stay periodic snapshots, reconciled from the stream on demand.

### Alternative D: Anchor to a baseline only (no system)
Key deltas on `(baseline, requirement)` without a system boundary.
- **Pros:** Simpler key.
- **Cons:** cATO is per-*system* continuous authorization; the same control on two systems drifts independently, and reconciliation targets a system's SAR/POA&M. A baseline-only key cannot place a delta on the right authorization boundary.
- **Why rejected:** The system is the unit of authorization; `systemDrift`/`systemRef` already encode it.

### Alternative E: Build the runtime/producer now, in hdf-libs
Ship a broker consumer + state store to make the stream "real" immediately.
- **Pros:** End-to-end demo in one repo.
- **Cons / Why rejected:** Violates the format-vs-transport boundary (ADR-0003 §4); a long-running stateful service is categorically different software from a stateless schema/converter library. The throwaway producer stays external.

### Alternative F: Do Nothing (keep ADR-0003 deferred)
Leave the gate in place; wait for a producer.
- **Pros:** No speculative work.
- **Cons:** Leaves the schema/function undesigned when a producer appears, forcing rushed design under delivery pressure — the exact failure ADR-0003's Phase 2 exists to avoid.
- **Why rejected:** We are now picking this direction up; building the library kernel speculatively is low-cost, testable without a producer, and de-risks the eventual runtime.

## Consequences

**What becomes easier:**
- A cATO consumer gets a concrete, validated event shape and a pure delta/fold pair to build a pipeline around, without waiting on schema design.
- Batch and stream stay reconcilable by construction: the event is a comparison entry; folding events reproduces a `hdf-comparison`, and the OCSF/ECS projection is the same one the batch exporter uses.
- The OSCAL story is coherent: deltas reconcile into SAR/POA&M against an SSP-defined system — nothing new for governance consumers to learn.

**What becomes harder:**
- More schema surface and versioning: a streaming profile of `hdf-comparison` plus a per-requirement checksum in `hdf-results` are new commitments to maintain at TS↔Go parity.
- The signal-vs-artifact boundary (Decision §2) must be actively defended against "just update the evidence package live" requests.
- Testing a producerless system: we must build/borrow a throwaway producer and synthetic event streams to exercise the kernel, and be honest that this validates the *library*, not a real pipeline.

**Risks:**
- *Delta-event envelope designed wrong* (granularity, identity fields). *Mitigation:* design the envelope in the schema phase against real `hdf-diff`/`hdf-comparison` fixtures and the throwaway producer's output; prototype `deltaFromPrevious` before freezing the schema.
- *Component identity is unstable across scans* (a component re-keys and every requirement looks "new"). *Mitigation:* reuse the existing component identity/matching rules from `hdf-comparison`'s `matching`; treat identity stability as an explicit precondition and test host-disappearance / re-key edge cases.
- *Per-requirement checksum picks the wrong field set* (misses a field that should trigger a delta, or churns on a volatile one). *Mitigation:* derive it from the same effective-status fields the exporter already treats as load-bearing; unit-test that each status/impact/disposition transition flips the checksum and nothing else does.
- *Scope creep pulls a runtime into hdf-libs.* *Mitigation:* Decision §4; the producer and processor are external by ADR.

## Implementation Plan

### Scope

**IN scope (hdf-libs, this effort):**
- A **delta-event schema** as a streaming profile of `hdf-comparison` (one diff entry + `systemRef` + prior/new effective state + `drift` + prior-checksum + timestamp), with validation and TS↔Go parity.
- Pure **`deltaFromPrevious(prevState, newEvaluatedRequirement) → DeltaEvent | null`** and **`foldDeltaIntoComparison(events[], base?) → hdf-comparison`**, stateless, TS↔Go parity, real fixtures.
- A **per-requirement effective-fields checksum** on `hdf-results` to localize change detection.
- Reuse of the existing ECS/OCSF projection inside the event (no new projection).

**OUT of scope (external — SAF CLI, a scratch project, or a consuming team):**
- The event **producer** (scanner fork/daemon emitting per-result/per-checksum events) — including the optional dead-simple "hello-world" test producer, which lives outside this repo.
- The stream-processor **runtime**, state store, keying/partitioning, and message bus (Kafka/Pulsar).
- Deployment topology and the governance **escalation policy** (when a sustained delta becomes a POA&M).

**Prior art for the (external) reconciler.** The reconciler is a well-trodden pattern — keyed last-value state + emit-on-change + a materialized current view — so it should start from known designs rather than a blank page: **AWS Config** keeps compliance state per `(resource, rule)` and emits a compliance-change notification when it flips, with a queryable current view (the closest domain analog — swap in `(system, component, requirement)`); **Wazuh / OSSEC File Integrity Monitoring** holds a baseline per file and emits only on change (the same delta-over-last-value shape in the security domain); and **Kafka Streams / ksqlDB** — a `KTable` *is* last-value-per-key over a log-compacted changelog, the likely engineering substrate and the concrete form of ADR-0003's "log-compacted topic + streams app" (Flink serves the heavier stateful cases). Elastic's `latest` transform plus Watcher is the ECS-stack equivalent. Whatever is built, it depends on hdf-libs (the schema + the pure `deltaFromPrevious` / `foldDeltaIntoComparison` functions) and supplies only the state, transport, and lifecycle around them.

### Phases (with acceptance + verification)

1. **Phase 1 — Per-requirement checksum in `hdf-results`.** Add the effective-fields checksum. *AC:* checksum present + deterministic + TS↔Go identical; flips on status/impact/disposition change, stable otherwise. *Verify:* unit tests over transition fixtures at parity; schema propagation (src → dist/go → validators embed → site).
2. **Phase 2 — Delta-event schema (streaming profile of `hdf-comparison`).** Define the envelope + examples. *AC:* validates; carries `systemRef` + identity + prior/new effective state + `drift` + prior-checksum + timestamp; a single event round-trips through `foldDeltaIntoComparison` into a valid `hdf-comparison`. *Verify:* schema tests; example fixtures validate; batch↔event round-trip.
3. **Phase 3 — Pure `deltaFromPrevious` + `foldDeltaIntoComparison`.** Implement + unit-test (TS↔Go parity) against real `hdf-diff`/`hdf-comparison` fixtures. *AC:* exact delta for each transition (passed→failed, failed→passed, appear/disappear, no-change→null); fold reconstructs the comparison. *Verify:* parity unit tests; ground-truth-anchor-style count checks; edge cases (first scan, host disappearance, baseline version change, new vulnerable BOM component).
4. **Phase 4a — In-process reference reconciler (external; the primary hands-on validation).** A broker-free tool (scratch project / SAF) that reads an event sequence from files or stdin, holds the keyed last-value map in memory, calls `deltaFromPrevious` / `applyDelta` / `foldDeltaIntoComparison`, and writes the resulting `hdf-comparison`. Zero infrastructure. This is the "throwaway test harness" the format-vs-transport boundary names: it dogfoods the hdf-libs API end-to-end and surfaces API-ergonomics problems before any runtime exists. *Goal:* the kernel consumes a real/synthetic event stream and folds to a valid comparison. *Note:* external to hdf-libs — it validates the library API but is not itself a repo deliverable. If the kernel cannot cleanly power this dead-simple reconciler, that is a signal to fix the kernel first.

5. **Phase 4b — Kafka reference implementation (optional demo — explicitly NOT in scope).** A log-compacted-topic + Streams-app rendering of the reconciler that demonstrates the true target topology (a `KTable` keyed on `(system, component, requirement)` as the last-value store). **This is definitely out of scope for hdf-libs — and out of scope for this PR and for the delta-event schema/kernel effort itself.** Treat it as a *neat reference implementation / demonstration artifact* for stakeholder pitches, **not** an acceptance criterion for the schema work. Pursue it only as a separately-scoped demo once Phases 1–3 land and 4a has proven the API; it teaches nothing about the kernel that 4a does not.

### Verification Strategy

- **Library-first:** everything in scope is verified by stateless unit tests at TS↔Go parity against real fixtures, before any producer or runtime exists. The producerless build is validated by synthetic + throwaway-producer event streams.
- **Reconciliation is the invariant:** the load-bearing property is that folding a stream of delta-events reproduces the same `hdf-comparison` a batch systemDrift diff would — tested directly.
- **Open questions to resolve in Phase 1–2, not assumed now:** exact per-requirement checksum field set + algorithm; the delta-event envelope's minimal identity fields; component-identity/matching reuse from `hdf-comparison`; and the escalation/reconciliation *policy* surface (explicitly deferred to the consuming tool, but its inputs must be present in the event).

## Notes

- ADR location: `dev-docs/` (historical artifacts; not on the published VitePress site).
- This ADR reopens and advances ADR-0003; ADR-0003's architecture (delta-not-firehose, format/transport split, keyed compaction, checksum heartbeat) stands and is cited rather than repeated.
- The OCSF Compliance Finding mapping (class 2003) is already shipped in `hdf-to-ocsf`; a formal upstream OCSF *profile/extension* (`profile.ohdf.*`) beyond the class mapping is a **separate, optional standards-track effort**, not part of this delta-event work.
