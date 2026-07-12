# ADR-0003: HDF continuous-monitoring streaming — design intent (deferred)

- **Status:** Proposed — **deferred, not declined** (design intent only; no implementation planned yet)
- **Date:** 2026-07-06
- **Deciders:** Will Dower
- **Relates to:** **[ADR-0002](adr-0002-hdf-to-ecs-export.md)** (the HDF → ECS/SIEM *export* mapping — the deliberate first building block for everything below); complements the carriage/import direction (`hdf-libs-8j9o`, external log evidence *into* HDF by reference).

## Context

Multiple stakeholders are asking whether HDF can support **continuous-monitoring (CONMON) workflows and continuous Authority to Operate (cATO)** — and, more broadly, whether the HDF/SAF ecosystem can integrate not just with the SIEM *data formats* (ECS, OCSF, Schema One) but with SIEM *architectures* overall: streaming ingestion, edge/source normalization, message buses, and live security data lakes. ADR-0002 answers the format question one direction at a time (a batch HDF → ECS export). This ADR addresses the larger architectural question standing behind those requests: **should HDF itself become a streaming, event-driven format** so that compliance and vulnerability posture can flow as a live security signal alongside operational telemetry?

The forces at play:

- **State vs. stream is a real and load-bearing distinction.** SIEM schemas are event-driven/dynamic ("what is happening right now"); HDF is assessment-driven/snapshot ("what is the exact posture at this instant"). That snapshot semantics is precisely what makes HDF useful for accreditation. Any streaming direction must *preserve* that semantics, not erase it.
- **Two genuinely different use cases.** Classic HDF serves governance: a program assembles an assessment package for GRC/RMF review and an ATO decision (batch, point-in-time, human-reviewed). CONMON streaming would serve operations: a SOC or cATO pipeline wants quasi-realtime notification that a host drifted out of compliance or that a newly-scanned BOM surfaced a component with a known vulnerability (delta, machine-triggered, high-volume). These have different consumers, latencies, and schemas.
- **The velocity is real at fleet scale.** For a single program the data is low-volume and batch is fine. For a datacenter under cATO the numbers change: ~5,000 hosts × hourly × (STIG ~370 + vuln ~500 + BOM ~1,000 items) ≈ **~240M items/day ≈ ~2,800 sustained items/sec**. That is data-lake tier; hourly monolithic file drops are the wrong architecture there.
- **We do not (yet) control the event producers.** Scanners (InSpec, Trivy, …) emit a report at the *end* of a run, not a result-at-a-time. A streaming pipeline needs a producer that emits discrete events; today none exists in the toolchain. This is a prerequisite, and one a consuming team could satisfy by building or forking a producer.
- **Repo invariants still apply** to anything that lands here: TypeScript ↔ Go parity, real fixtures, deterministic/stateless library code, canonical UTC timestamps.

## Decision

**Defer HDF CONMON streaming as a distinct future product line — record the design intent and target architecture now, but do not implement it yet and do not fold it into the ADR-0002 export work.** When it is picked up it gets its own epic and its own detailed implementation ADR. The batch export mapping (ADR-0002 / epic `wvc3`) is its deliberate, non-regretful first building block.

The reasoning, and the target architecture we would pursue when the prerequisites are met:

1. **The valuable event is a state-change delta, not a re-chunked result.** The signals stakeholders describe — "host X control V-230222 went passed→failed," "host Y's BOM now shows a component with a known CVE" — are deltas. The full-posture firehose (~2,800/sec) is mostly "still passing" noise no SOC alerts on; that volume is a *data-lake ingestion* concern (compact, queryable per-record events — what the ADR-0002 exporter already produces). The delta stream — dozens-to-hundreds of events/hour across the whole fleet — is small and genuinely event-shaped. The likely delta-event schema is therefore an **iteration of an HDF delta**, building on the existing `hdf-diff` engine and `hdf-comparison` document type, plus a change classification — not a metadata-re-carrying `hdf-results` fragment.

2. **Deltas are detected by keyed last-value state, not by hoarding and diffing whole documents.** The detection primitive is a compaction: `(host_id, control_id) → { status, impact, checksum_of_relevant_fields }`. An incoming event is compared to its stored last value and a delta is emitted only on change. This is standard stateful stream processing (log-compacted topic + streams app, Flink, or an edge processor); state is one tiny row per (host, control), trivial even at ~10M keys. Where that state physically lives — a stateful agent at the edge vs. a central processor teeing off the lake feed — is an **edge-vs-center bandwidth-vs-compute deployment tradeoff**, chosen per environment, *not* baked into the library.

3. **HDF's existing checksums give change detection for cheap.** `resultsChecksum` (per baseline), `originalChecksum`, and the root `integrity` mean a source can emit *just a checksum* as a heartbeat (a few bytes) and a collector holds last-checksum-per-(host, baseline), pulling/emitting a detailed delta only on mismatch — narrowing wire volume and diff scope to only what moved.

4. **Format vs. transport — the boundary of what this repo owns.**
   - **hdf-libs owns (library-shaped: stateless, deterministic, unit-testable):** the event schema(s) (result-event in, delta-event out); the ECS/OCSF field projection (the exporter); and a **pure `deltaFromPrevious(prevState, newResult) → DeltaEvent | null`** function factored out of `hdf-diff` — no I/O, no state, no broker. This is the kernel of the streaming story and is buildable independent of any infrastructure.
   - **hdf-libs does NOT own (infrastructure / consuming tool):** the state store, the stream-processor runtime, keying/partitioning, the message bus, and the deployment topology. A long-running broker consumer (backpressure, delivery guarantees, offset management) is categorically different software from a schema/converter library; it belongs in SAF CLI or a dedicated service that a consuming team builds or forks.

## Alternatives Considered

### Alternative A: Build CONMON streaming now
Design and ship the event schema, the delta function, and a streaming runtime in this cycle.
- **Pros:** Directly answers stakeholder requests; first-mover on compliance-as-telemetry.
- **Cons:** No upstream producer emits discrete events today, so the pipe would have nothing flowing into it; the delta-event schema shape is undecided and expensive to get wrong.
- **Why rejected:** Blocked on an external prerequisite (a producer) and on design work that must precede code. Revisit once a producer exists.

### Alternative B: Decline the idea entirely
Treat HDF as batch-only forever; SIEM integration stops at the ADR-0002 export.
- **Pros:** Keeps the library narrowly scoped; zero new surface.
- **Cons:** Discards a real, stakeholder-driven use case (fleet cATO); the velocity case is legitimate and the goal — posture queryable next to telemetry — is valuable.
- **Why rejected:** The objections to streaming are timing (producer) and scale-dependent (velocity), not merit. Declining throws away genuine value for the wrong reason.

### Alternative C: Chunk and emit every result as it completes
The naive stream model: the scanner emits each raw result the instant it evaluates, over a message bus, each event re-carrying its requirement metadata.
- **Pros:** Conceptually simple; no state anywhere in the pipeline.
- **Cons:** Conflates the lake-ingestion firehose with the SOC delta signal; re-carries heavy metadata per event, defeating HDF's normalization; produces a primarily-noise stream a SOC cannot alert on directly.
- **Why rejected:** The valuable event is a delta; a raw-result firehose is an export/ingestion concern already served by the batch exporter plus a lake.

### Alternative D: Per-host stateful agent hoarding prior scans + document diff
Each host stores scan N−1 and structurally diffs it against scan N locally, emitting deltas.
- **Pros:** Only deltas leave the host; naturally partitioned; minimal wire volume.
- **Cons:** Operationally heavy (a stateful agent on every host: attack surface, patching, state-loss failure modes); unnecessary, because detection is a keyed last-value compaction, not a whole-document diff.
- **Why rejected as a baked-in requirement:** It may still be a valid *deployment* at the edge, but that is the deployment's choice, not a library or architecture mandate.

### Alternative E: Full feed to the lake + central stateful delta processor (selected target)
Emit full posture to the data lake (wanted anyway for cATO queryability) and run a stateful processor that tees off that feed, holds last-value-per-key, and emits deltas.
- **Pros:** The "noise" firehose has an independent, wanted consumer (the lake); delta extraction is a cheap keyed operation; centralizes state off the hosts; reuses the exporter's per-record projection.
- **Cons:** Pays full-feed bandwidth (acceptable, since the lake needs it regardless); requires a central stream-processing tier.
- **Why selected (as the target, when built):** It matches how fleet-scale SIEM/lake pipelines already work and cleanly separates the library concern (schema + projection + pure delta function) from the infrastructure concern (state + transport).

### Alternative F: Bake the streaming daemon into hdf-libs
Ship the broker consumer/producer and state store as part of this repo.
- **Pros:** One-stop implementation.
- **Cons:** A long-running stateful service is categorically different from a schema/converter library; drags broker/runtime concerns and their operational + security profile into a repo that is otherwise batch and stateless.
- **Why rejected:** Violates the format-vs-transport boundary; the runtime belongs in a consuming tool.

### Alternative G: Do Nothing (status quo — export only)
Ship ADR-0002 and take no position on streaming.
- **Pros:** No new documents or commitments.
- **Cons:** Leaves recurring stakeholder questions unanswered and the reasoning undocumented, inviting the same debate to be re-litigated from scratch and risking an ad-hoc streaming design later.
- **Why rejected:** Recording the intent and target architecture now is cheap and prevents future churn; this ADR *is* the lightweight "do the thinking, defer the build" middle path.

## Consequences

**What becomes easier:**
- The ADR-0002 export work is confirmed as a shared substrate — non-regretful regardless of whether streaming is ever built, because its field projection lives inside every future event.
- The future design pass starts from a concrete architecture (delta events on `hdf-diff`/`hdf-comparison`, keyed last-value detection, checksum heartbeat, format/transport split) rather than a blank sheet.
- The library/infrastructure boundary is drawn in advance, so the eventual epic knows exactly what is in scope for this repo.

**What becomes harder:**
- Contributors must resist the pull to add streaming/runtime concerns to a batch, stateless library; the boundary in Decision §4 has to be actively defended.
- Two use cases (governance batch vs. operations stream) coexisting in one ecosystem means more schema surface and more careful versioning if/when the delta-event type lands.

**Risks:**
- *The delta-event schema is designed wrong* (raw-result vs. state-change; wrong granularity). *Mitigation:* defer schema design to a dedicated ADR with real producer output in hand; prototype the pure `deltaFromPrevious` function against `hdf-diff` fixtures before committing a schema.
- *Checksum granularity is too coarse* (per-baseline hides which control moved). *Mitigation:* treat per-control/per-result checksum granularity as an explicit open question for the design pass, not an assumption.
- *Scope creep pulls broker/runtime into hdf-libs. Mitigation:* Decision §4 names the split explicitly; the runtime target is SAF CLI or a separate service.

## Implementation Plan

This ADR is **deferred**: it defines intent and a target architecture, not a build. No epic or cards exist yet; they are created when the prerequisites below are met. The phasing is a sequencing sketch, not a card list.

### Scope

**IN scope (of the eventual product line):**
- An HDF streaming **event schema** — most likely a delta-event derived from `hdf-comparison`/`hdf-diff` — plus its validation, TS↔Go parity, and fixtures.
- A pure, stateless **`deltaFromPrevious(prevState, newResult) → DeltaEvent | null`** library function.
- The **ECS/OCSF projection** reused inside events (delivered first, as ADR-0002).
- Possibly finer-grained **checksums** on `hdf-results` to localize change detection.

**OUT of scope (belongs to a consuming tool / infrastructure, not hdf-libs):**
- The stream-processor runtime, state store, keying/partitioning, and message-bus (Kafka/Pulsar) plumbing.
- The event **producer** (scanner modification/fork that emits discrete events).
- Deployment topology (edge agent vs. central processor) and index/topic naming.

### Phases (sequencing sketch — no cards yet)

1. **Phase 1 — Export mapping (in flight as `wvc3`).** HDF → ECS/OCSF field projection. Prerequisite for every later phase; already scoped by ADR-0002.
2. **Phase 2 — Streaming design ADR + event schema.** With real producer output in hand: decide the delta-event shape (extend `hdf-comparison` vs. new type), checksum granularity, and the `deltaFromPrevious` contract. Blocked by Phase 1 and by an available producer.
3. **Phase 3 — Pure delta function + fixtures.** Implement and unit-test `deltaFromPrevious` (TS↔Go parity) against `hdf-diff` fixtures. Blocked by Phase 2.
4. **Phase 4 — Streaming runtime (NOT in this repo).** State store, stream processor, broker integration in SAF CLI or a dedicated service. Blocked by Phase 3 and out of hdf-libs scope.

### Verification Strategy

- **Prerequisites gate:** this ADR does not leave "deferred" until (1) an owned producer emits per-result (or per-checksum) events, (2) the ADR-0002 exporter has landed, and (3) a dedicated streaming epic + implementation ADR exist.
- **When built:** the `deltaFromPrevious` function is verified by unit tests asserting exact delta output for each status transition (passed→failed, failed→passed, appearance/disappearance, no-change→null) against real `hdf-diff` fixtures, at TS↔Go parity — before any runtime is written.
- **Edge cases to design for:** first-ever scan (no prior state), host disappearance, baseline version change between scans, and BOM-component additions that carry a new known-vulnerable component.

## Notes

- ADR location: this project keeps ADRs in `dev-docs/` as historical artifacts (not on the published VitePress site).
- This ADR supersedes the compressed streaming rationale currently held only in the `hdf-siem-export-wvc3` bd memory.
