# ADR-0005: HDF continuous-monitoring requirement-change-event stream — schema + kernel (speculative build)

- **Status:** Proposed — revision 2, incorporating design review feedback (PR #161)
- **Date:** 2026-07-22 (revised 2026-07-26)
- **Deciders:** Will Dower
- **Supersedes the deferral in:** **[ADR-0003](adr-0003-hdf-conmon-streaming.md)** (which recorded the target architecture but gated the build on an event producer existing). This ADR follows up on ADR-0003: we are now picking up the streaming direction and advancing it to ADR-0003's "Phase 2 — streaming design ADR + delta-event schema."
- **Builds on:** **[ADR-0002](adr-0002-hdf-to-ecs-export.md)** (HDF → ECS export) and the shipped `hdf-to-ocsf` exporter (native OCSF Compliance Finding, class 2003) — the SIEM *projection* substrate reused inside every event.

> **Naming note (revision 2):** this work was originally titled the "delta-event stream." The term "delta" is dropped throughout: it collides with `hdf-diff`'s existing `drift` concept (metadata-only changes), and `delta` already means "update an InSpec profile against a new benchmark release" to SAF CLI users (`saf generate delta`). The unit is now a **requirement-change event** (`Requirement_Change_Event`); the kernel functions are `changeEventFromPrevious`, `foldChangeEventsIntoComparison`, and `applyChangeEvents`.

## Context

We are following up on ADR-0003 and now intend to **stream individual change events in HDF to support cATO** (continuous Authority to Operate). This revisits ADR-0003's producer-availability gate: we will build the streaming **library kernel speculatively** — ahead of any production event producer — so the schema and the pure functions exist and are validated when a producer materializes.

**The gap is real, and this is gap-filling rather than reinvention.** OSCAL Assessment Results and POA&M are point-in-time snapshots by design; their only temporal machinery (`risk-log`, `assessment-log`) audits status *within* one result, never a cross-snapshot control-result change. SCAP/ARF (NIST IR 7694) is a provenance-only report container; ASR (IR 7848) is withdrawn; CAESARS (IR 7756/7800) delegates content to SCAP snapshots. A standardized assessment-result change event does not exist anywhere in the RMF/SCAP/OSCAL world — while NIST SP 800-137 (ISCM), SP 800-37r2 ongoing authorization, and the DoD cATO memo (Feb 2022) all describe consuming continuous change signals into a near-real-time posture view.

What has and has not changed since ADR-0003 (2026-07-06):

- **Changed:** the decision to build now, not defer. The gate ("no producer exists, so don't build the pipe") is deliberately relaxed for the *library* pieces (schema + pure functions), which are useful and testable without a producer.
- **Not changed:** we still do **not** own a producer that emits per-result or per-checksum events. We may build a **dead-simple, throwaway "hello-world" producer** purely to exercise the schema/functions in tests — and, per ADR-0003's format-vs-transport boundary, **that producer lives outside hdf-libs** (a scratch project or SAF CLI), never in this repo.
- **Already shipped substrate:** the batch HDF → ECS export (ADR-0002) and `hdf-to-ocsf` (OCSF Compliance Finding 2003 + Vulnerability Finding 2002, `compliance.checks[]`/`status_id`, OCSF v1.8.0). So the "project posture into SIEM fields" half is done; this ADR is about the *event* half.
- **Already-present change vocabulary:** `hdf-comparison` has a **`systemDrift`** mode carrying a **`systemRef`** and per-entity diffs (`requirementDiffs`, `componentDiffs`; `packageDiffs` is RESERVED and not currently emitted) with `Requirement_State` values `new | absent | unchanged | updated | fixed | regressed | moved | split | merged`. The change event reuses this vocabulary's producer-computable subset — we do not invent a parallel set.

ADR-0003 already settled the architecture (change events, not a raw-result firehose; keyed last-value detection; the checksum heartbeat; the format-vs-transport split). This ADR does **not** relitigate that. It resolves the questions ADR-0003 left open: what the event is anchored against, what shape it takes on the wire, how a stream reconciles back into governance artifacts, and how that fits OSCAL.

## Decision

**Build, speculatively and library-only: (a) a `Requirement_Change_Event` schema — a new document type that reuses the `hdf-comparison` vocabulary but is not a `Requirement_Diff`; and (b) three pure, stateless kernel functions: `changeEventFromPrevious(prevState, newRequirement) → Requirement_Change_Event | null`, `foldChangeEventsIntoComparison(events[], seedResults) → hdf-comparison`, and `applyChangeEvents(seedResults, events[]) → hdf-results`.** No runtime, no broker, no producer in this repo.

### 1. The event is anchored to a **system**, keyed by `(systemRef, componentId, requirementId)`

The stateful entity a cATO pipeline monitors is a **system's authorization boundary** — exactly what `hdf-system` (≈ OSCAL SSP) defines and what `hdf-comparison`'s `systemDrift` mode already diffs against via `systemRef`. The detection key is `(systemRef, componentId, requirementId)` → last-value `{ effectiveStatus, effectiveImpact, checksum }` — ADR-0003's keyed compaction made concrete against the system anchor. This entity key is durable across events; it is deliberately distinct from the per-event identity (§4). Precedent: OCSF's Compliance Finding formalizes the same split (`finding_info.uid` = durable finding vs `metadata.uid` = this event occurrence); SARIF splits `correlationGuid` (equivalence class) from `guid` (occurrence).

A requirement *renumbering* is emitted as `absent` + `new` under the two keys — never an in-place key mutation (Debezium's rule for primary-key changes). The batch comparison later reconciles the rename via its `oldId`/`newId` matching machinery.

### 2. The event is a **new type** — a projection of the comparison vocabulary, not a `Requirement_Diff`

An earlier draft claimed the event "is one `requirementDiff` of a `systemDrift` comparison." Design review showed that is not literally true, and making it true would be wrong in both directions:

- **`Requirement_Diff` is the batch/audit artifact.** Its required full `before`/`after` snapshots, `changeReasons`, and `fieldChanges` are the strict at-rest contract every `hdf-comparison` consumer relies on, and its matching machinery (`matchStrategy`, `matchConfidence`, `oldId`/`newId`) plus the states `moved`/`split`/`merged` are **outputs of cross-document identity resolution** — computable only with two full corpora in hand. A streaming producer watches one key and can never emit `split`.
- **The event needs transport identity** (`eventId`, `source`, `sequence`) that is meaningless in a document at rest — and `Requirement_Diff`'s `unevaluatedProperties: false` correctly forbids it.

So: a new `$def`, with `Requirement_Diff` left untouched. The event **reuses** the comparison vocabulary where it is producer-computable:

- `state` is the **producer-computable subset** of `Requirement_State`: `new | absent | updated | fixed | regressed`. The batch-only states (`moved`/`split`/`merged`) remain fold/batch enrichments. Note `fixed`/`regressed` carry direction that SARIF's closed 4-value `baselineState` lacks; the OCSF/ECS projection documents a mapping down to SARIF's 4 for external interop.
- `changeReasons` (optional) reuses the existing `Change_Reason` enum, again the producer-computable subset (`resultChanged`, `overrideAdded/Expired/Removed/Modified`, `impactChanged`, `configChanged`). An `overrideExpired` status flip is a different triage than a `resultChanged` one — the "why" at classification level.
- Field names match the schema (`state`, `before`, `after`) — not the earlier draft's `drift`/`from`/`to` — so the lift from event to `Requirement_Diff` at fold time is mechanical.

*Kernel signature elaboration (Phase 3, as implemented):* the headline sketch `changeEventFromPrevious(prevState, newResult)` gains two caller-supplied inputs. An **`EventInputs`** parameter injects the entire §4 envelope (the purity mandate forbids minting identity internally), including a `prevReferenceTimestamp` — the prior observation's time — without which `overrideExpired` is undetectable (expiry must cross the observation window). An optional **full prior requirement** operationalizes §3's "recoverable from the reconciler's materialized state": with it, `changeReasons` classification is complete (reusing the batch classifier filtered to the event vocabulary); without it, reasons degrade to what thin state proves (`impactChanged`). Two wire-vocabulary values — `configChanged` and `overrideModified` — are not currently emitted by this kernel (the batch classifier never produces them); they remain in the schema for producers with richer context.

### 3. Payload: full `after`, thin `before` — forced by the reassembly-parity invariant

Measured against real fixture requirements (median OpenSCAP RHEL8 requirement ≈ 1.6 KB; worst-case Nessus plugin_output-heavy requirement ≈ 408 KB):

| Candidate payload | Median event size |
|---|---|
| Effective-fields-only projection | ~400 B |
| Full `before` + full `after` (a literal `Requirement_Diff` payload) | ~3.7 KB (817 KB worst case) |
| **Thin `before` projection + full `after`** (chosen) | **~2.1 KB** |

- **`after`** is a full **`Evaluated_Requirement`**, required and non-null for every state except `absent` (where it is null by definition). This is not an optimization choice — it is forced by the reassembly-parity invariant (§6): an effective-fields-only event can flip a status but cannot reproduce the changed requirement's content (result messages, codeDesc, override state), so replay-reconstruction of `hdf-results` would be unachievable by construction. Since events fire only on change, essentially every event is content-bearing; there is no meaningful "thin tier." The full row is also *the point*: a responder opens a `regressed` event for the failing `results[]`, not for the enum. (Debezium's full-after-row CDC model, arrived at from the parity requirement.)
- **`before`** is a lightweight effective-fields projection (`{ effectiveStatus, effectiveImpact }`): enough for at-a-glance alerting without a lookup. The full prior state is recoverable from the reconciler's materialized state, and the `priorChecksum` chain (§4) covers integrity of that recovery.
- The stream's economy therefore comes from **sparsity in time** (only changed keys, only when they change), not payload thinness.
- Patches were considered and rejected as the wire form: RFC 6902 is order-dependent and non-idempotent; RFC 7386 cannot patch array elements or represent null — both fatal on a compacted, at-least-once stream. Full-state-carrying events with a derived `fieldChanges` hint (the `Requirement_Diff` split) remain the model at fold time.

### 4. Envelope: CloudEvents-style identity, ordering, and idempotency — every field grounded

The envelope answers the review's identity/ordering/idempotency finding. Fields, with their grounding (primary sources in References):

| Field | Type | Semantics | Grounding |
|---|---|---|---|
| `eventId` | string (uuid) | Identity of **this event occurrence**. Unique per `source`; `(source, eventId)` is the dedup key. UUIDv7 recommended (time-ordered), not required. | CloudEvents v1.0.2 normative: "Producers MUST ensure that `source` + `id` is unique"; consumers MAY treat identical `(source, id)` as duplicates. OCSF `metadata.uid`; SARIF `result.guid`. |
| `source` | uri-reference | The producer context (e.g. `inspec://web01/rhel9-stig`). | CloudEvents `source`. House `*Ref` style. |
| `sequence` | integer | **Monotonic per entity key** `(systemRef, componentId, requirementId)`. The only ordering authority. | **Documented divergence:** no envelope standard sequences per entity key (CloudEvents' `sequence` extension is non-normative, string-typed, per-source; ECS `event.sequence`/OCSF `metadata.sequence` are numeric with unspecified scope). Per-key monotonic sequence is event-sourcing aggregate-version practice (Young) and Kafka per-key ordering; CloudEvents itself directs per-subject sequencing to a custom extension. Numeric per ECS/OCSF. |
| `timestamp` | RFC 3339 (trimmed UTC, house rule) | **Occurrence time.** Never an ordering key. | ECS, OCSF, and Debezium all separate occurrence from processing time and none orders by wall clock. |
| `schemaRef` | uri | The versioned schema `$id` this event validates against. | CloudEvents `dataschema`; our hosted versioned `$id` URLs are already exactly this. |
| `systemRef` | uri-reference | The `hdf-system` document (authorization boundary). Resolves to the **latest version** of an evolving document. | House convention (same field on hdf-comparison/amendments/evidence-package/results). Resolve-to-latest semantics per STIX `*_ref`. |
| `componentId` | string (uuid) | Component within the system. | House convention (`componentId`/`componentRef`). |
| `requirementId` | string | Canonical requirement identifier (natural key, same as `Requirement_Diff.id`). | Kimball durable-key; renumber = `absent`+`new` per §1. |
| `priorChecksum` | Checksum object, nullable | Per-requirement effective-fields checksum (§8) of the state this event supersedes — the house `{algorithm, value}` Checksum shape, matching `effectiveChecksum`. Null at chain start (seed). | **Documented divergence:** no event standard has a hash chain. Grounded in AWS CloudTrail digest chaining (`previousDigestHashValue`, null at chain start) and RFC 6962/9162 transparency logs. See the honesty note below. |

**What the hash chain does and does not guarantee** (per the RFC 6962/9162 framing, written here so nobody oversells it): given a trusted head, a broken chain detects tampering, reordering, and mid-chain gaps — so the reconciler can mark a key's state *unverified* instead of confidently serving stale posture. It does **not** by itself prove completeness or prevent a split view. The out-of-band anchor that closes that gap is structural in this design: the periodic re-centering rescan (§7) plus the reconciled document's derivation block act as the signed checkpoint — CloudTrail's cadence-plus-digest pattern.

**Envelope as a shared primitive.** The envelope is entity-agnostic and is defined as a standalone `$def` (`Change_Event_Envelope`) composed into the event type via `allOf`. This is deliberate family design: the one anticipated sibling — **component change events** — would reuse it verbatim (hdf-comparison already models `componentDiffs` alongside `requirementDiffs`, and AWS Config streams exactly this pair: per-resource configuration changes beside per-rule×resource compliance changes; cloud-native autoscaled boundaries make component churn event-speed). No other HDF document type passes the event-speed filter: amendments surface through requirement events, baselines/plans/evidence packages change at notification speed, and comparisons are derived. A subtype discriminator was rejected as paying a generality tax before the second member exists.

**Fold-correctness contract (normative for `foldChangeEventsIntoComparison` and `applyChangeEvents`):** keyed last-value-wins by `sequence` per entity key; idempotent via `(source, eventId)` dedup; tombstone-aware (an `absent` event carries the thin `before` and `after: null` — the semantic record — distinct from any transport-level tombstone a compacted log needs, and distinct from `fixed`); total over the event-state enum; `timestamp` never participates in ordering. This satisfies both event-sourcing rebuild-by-replay and log-compaction semantics, and makes fold output invariant under duplicate delivery and reordering.

### 5. The stream is a **signal, not a live-mutated document**

A change-event stream does **not** mutate an `hdf-evidence-package`, `hdf-system`, or `hdf-results` document in place. Those remain the periodic, authoritative, human-reviewable snapshots that an ATO consumes. The stream is the *between-snapshots signal*. Reconciliation back into governance artifacts is an explicit, separable operation:

- **Materialize:** `foldChangeEventsIntoComparison(events, seedResults)` yields a full `hdf-comparison` (systemDrift) — the same shape we already produce in batch.
- **Reassemble:** `applyChangeEvents(seedResults, events)` yields the current posture as a fresh `hdf-results` — the **reconciled result set** (§7).
- **Escalate (governance):** a sustained or repeat failure can drive an `hdf-amendments` entry (the POA&M subset — see §9). Whether/when that happens is a *policy* decision for the consuming tool; hdf-libs provides the classification, not the trigger.

### 6. The reassembly-parity invariant and the producer contract

The load-bearing correctness property, stated exactly. Given seed scan A, a later rescan B of the same target, and the event stream derived between them:

> **`applyChangeEvents(A, derive(A→B)) ≡ B` at requirement level** — agreement on every requirement's identity, status, `effectiveStatus`/`effectiveImpact`, disposition/overrides, tags, and full `results[]` content.

Two residuals define the (small, fully documented) mask:

- **Changed requirements match exactly** — the last event for the key carried B's full row verbatim.
- **Unchanged requirements carry A's content**, differing from B only in per-run volatile fields (`results[].startTime`/`runTime`, run-varying message text). This is the *correct* semantic — the reconciled document honestly reports last observed state — and it is the entirety of the requirement-level mask.
- Document-level metadata (`generator`, document `timestamp`, `statistics.duration`, `resultsChecksum`) legitimately differs; parity is requirement-level, never byte-level.

A companion law ties stream to batch: `foldChangeEventsIntoComparison(derive(A→B), A)` produces the same `requirementDiffs` as the batch `diff(A, B)`, modulo the batch-only states (§2).

The invariant is conditional on the **producer contract**, which is part of this design, not an aspiration:

1. **Completeness:** every path that changes effective state emits an event — *including* override changes that occur without a scan (a waiver applied or expiring is a state change with no scanner involved). The `priorChecksum` chain exists precisely because completeness cannot be assumed: a gap is detectable, and detected gaps mark the key unverified until the next re-center.
2. **Order/dedup per the fold contract** (§4).

Both laws are directly testable across the existing fixture corpus (same-target pairs such as `scan-before`/`scan-after`, `ubuntu-22-vanilla`/`-hardened`), in both languages, plus property tests: duplicate delivery → identical output; shuffled delivery → identical output.

### 7. Reconciled result sets, lineage, and the re-centering loop

**Reconciled result set** (pinned term): an `hdf-results` document produced by `applyChangeEvents`, not by a scanner. It must be **unambiguously self-identifying — it never masquerades as a scan**:

- `generator` names the reconciler, not the scanning tool.
- A small optional **`derivation` block** on `hdf-results` (the `Derivation` def in the events primitive) records the lineage: the **`seed`** as an inline `{uri, checksum}` object with checksum **required** — pinning by content, the prevailing location-plus-expected-hash pattern of SRI / OCI descriptors / SPDX external document refs — plus the producer `source`, `throughSequence` (event watermark), `eventsApplied`, and `asOf`. Conceptually this is W3C PROV's qualified derivation (derived entity ← used entity + activity + generation time) / OpenLineage's dataset-version facet. The seed deliberately does **not** reuse `Content_Reference` (evidence-package-coupled: required `type` from its `Content_Type` enum) nor the ADR-0006 `External_Reference` proposal (checksum optional there; unlanded at decision time); consolidating HDF's reference shapes onto one primitive is tracked by bead `hdf-libs-avp2`, where the seed object is listed as a migration site.

**The re-centering loop.** Periodic full rescans are non-negotiable, and the rescan has three jobs:

1. **Drift check:** the reconciler diffs its materialized state against the rescan using the existing batch `diff()`. Agreement = the parity law holding in production; disagreement = missed or bad events, itself a first-class alertable signal. The test invariant doubles as a runtime health check.
2. **Re-seed:** the rescan becomes the new seed; per-key state resets; the sequence watermark advances. **Divergence is bounded by the rescan cadence** — the reconciled view can never be wrong for longer than one re-centering interval.
3. **Evidence:** the rescan is the artifact that enters the evidence package. The reconciled document is the freshest-available *view* between scans.

**Downstream precedence rule:** a full-scan document supersedes the reconciled view as of its scan time; between scans, the reconciled document with the highest `throughSequence` is the current posture. Dashboards read the reconciled view; evidence packages reference the scans (and optionally the event log as supporting record).

Cutover mechanics — what to do with events that arrive mid-rescan, watermark placement relative to scan start — are reconciler-runtime policy, external to hdf-libs (§10). hdf-libs owes the pure tools that make any policy implementable.

### 8. Enabling change: per-requirement effective-fields checksum

`resultsChecksum` is per-baseline today, which cannot say *which control* moved. We will add a **per-requirement effective-fields checksum** (minimal set: `effectiveStatus`, `effectiveImpact`, `disposition`) to `hdf-results` so change detection is localizable, a heartbeat can be per-control, and the `priorChecksum` chain has its link value. Exact field set and algorithm are resolved in the schema phase.

### 9. OSCAL fit

HDF aligns to OSCAL as: `hdf-system`≈SSP, `hdf-results`≈SAR (findings/observations), `hdf-baseline`≈catalog/profile. A cATO program in OSCAL terms is **continuous SAR + POA&M updates against a fixed SSP**. The requirement-change event is the **wire form of an incremental SAR observation/finding change** against an SSP-defined system, reconcilable into a SAR (`hdf-results`) and, on escalation, a POA&M entry. Since OSCAL has no delta type (see Context), "reconcile into snapshots on demand" is the entire OSCAL story — the stream sits inside, not beside, the alignment we already support.

*Scope note:* `hdf-amendments` spans waivers, attestations, false positives, risk adjustments, inherited controls, and POA&Ms — in OSCAL those scatter across POA&M `poam-items`, `risk` deviations, and the SAR `attestation` assembly. The escalation path here targets specifically the **POA&M subset** of amendments; "amendments ≈ POA&M" elsewhere in HDF docs is shorthand broader than strictly true.

### 10. Format-vs-transport boundary (unchanged from ADR-0003, restated for scope)

- **hdf-libs owns (stateless, deterministic, TS↔Go parity, real fixtures):** the `Requirement_Change_Event` schema; `changeEventFromPrevious`; `foldChangeEventsIntoComparison`; `applyChangeEvents`; the per-requirement checksum; the derivation-block schema; and the ECS/OCSF projection (already shipped).
- **hdf-libs does NOT own:** the producer, the state store, the stream processor, the message bus, keying/partitioning at runtime, re-centering cutover policy, escalation policy, and deployment topology. The optional throwaway test producer is a scratch/SAF artifact.

## Worked example: continuous monitoring of a RHEL host

This walks a single RHEL 9 host from deploy to steady-state CONMON. It also settles a common confusion: **almost nothing about the `hdf-system` document changes on a per-event basis — the *posture* updates continuously, the system *definition* does not.**

The pieces referenced below: the pure kernel functions (hdf-libs, this ADR); the batch converters `inspec → hdf-results` and `hdf-to-ocsf`/`hdf-to-ecs` (already shipped); and an **external** producer + keyed last-value store (SAF / a scratch tool — not hdf-libs).

**Step 0 — Preconditions.** An `hdf-baseline` for the RHEL 9 STIG (~370 rules) exists. The external test producer and a small keyed state store exist outside this repo.

**Step 1 — Deploy and enroll the host (authoring, one time).** Provision RHEL 9 host `web01`. Author (or append to) the **`hdf-system`** document for the authorization boundary — say a system named `AppTier` — adding `web01` as a `host` component with a stable `componentId` (UUID). This is the SSP-equivalent. **It is written deliberately and changes only when the boundary changes** — not when a scan result moves.

**Step 2 — Initial scan → the first snapshot.** Run the RHEL 9 STIG InSpec profile against `web01`; convert to **`hdf-results`** (the SAR-equivalent point-in-time snapshot), tied to `systemRef=AppTier` and `componentId=web01`. Say 370 requirements: 41 failed, the rest passed. This snapshot is authoritative and auditable as-is.

**Step 3 — Seed the last-value state.** The external reconciler ingests that initial `hdf-results` and populates the keyed store — one tiny row per control:

```
(AppTier, web01, RHEL-09-255065) → { effectiveStatus: failed, effectiveImpact: 0.5, checksum: 9f2a… }
(AppTier, web01, RHEL-09-211010) → { effectiveStatus: passed, effectiveImpact: 0.0, checksum: 1b7c… }
…
```

The `checksum` is the new per-requirement effective-fields checksum (§8). There is now a baseline to compare against. No events yet.

**Step 4 — Steady state: re-evaluate and emit only what moved.** On a cadence (or on config-change triggers), the producer re-runs InSpec on `web01`. For each evaluated requirement, `changeEventFromPrevious(prevState[key], newRequirement)`:

- **Unchanged** (checksum matches) → returns `null`, no event. This is the overwhelming majority every scan — "still passing / still failing" noise never hits the stream.
- **Changed** → returns a **`Requirement_Change_Event`**. Example: the FIPS SSH-cipher control `RHEL-09-255065` was remediated, failed → passed, so `state: "fixed"`:

  ```json
  {
    "eventId": "0190f6f2-1c4e-7c3a-9f2a-3b1d5e7a9c01",
    "source": "inspec://web01/rhel9-stig",
    "sequence": 412,
    "schemaRef": "https://mitre.github.io/hdf-libs/schemas/…/v…",
    "systemRef": "apptier.hdf-system.json",
    "componentId": "6e0f2a3b-…",
    "requirementId": "RHEL-09-255065",
    "state": "fixed",
    "changeReasons": ["resultChanged"],
    "before": { "effectiveStatus": "failed", "effectiveImpact": 0.5 },
    "after": { /* full Evaluated_Requirement: id, tags, descriptions, results[] with the passing check output, … */ },
    "priorChecksum": "9f2a…",
    "timestamp": "2026-07-22T14:03:11Z"
  }
  ```

  The reconciler dedups on `(source, eventId)`, orders on `sequence`, verifies `priorChecksum` against its stored state (chain intact), and updates the stored last-value for the key.

**Step 5 — Fan-out.** Each event goes two places:
- **SOC / SIEM:** projected through the shipped `hdf-to-ocsf` / `hdf-to-ecs` mapping (OCSF Compliance Finding, class 2003 — whose required `activity_id` Create/Update/Close maps naturally from `state`) so the change shows up next to operational telemetry and is alertable. The full `after` row means the alert carries the failing/passing check output — the "why" — not just an enum flip.
- **Governance reconciler:** appended to the running window for `AppTier`.

**Step 6 — Materialize current posture (the "continually updating" part).** On demand or on a cadence — two pure, deterministic outputs, neither of which mutates a document in place:
- `foldChangeEventsIntoComparison(events, seedResults)` → a fresh **`hdf-comparison` (systemDrift)** for `AppTier`: exactly what changed since the last snapshot ("3 controls fixed, 1 regressed").
- `applyChangeEvents(seedResults, events)` → the **reconciled result set**: an updated current-posture `hdf-results` answering "what is `web01`'s posture *right now*." Its `generator` names the reconciler and its derivation block pins the seed + event watermark (§7). A cATO dashboard reads this.

  What is **not** rewritten on each event: the `hdf-system` document. The churn lives entirely in the results/comparison it *references*. The system doc is edited only in Step 8.

**Step 7 — Escalation (governance policy, external).** If `RHEL-09-255065` stays failed past a policy threshold, the consuming tool — not the stream — emits an **`hdf-amendments`** POA&M entry against `(AppTier, web01, RHEL-09-255065)`. hdf-libs supplies the classification in the event; the *trigger* is the consumer's policy. The cATO authorization view = reconciled posture + open POA&Ms against a fixed SSP — ordinary OSCAL continuous monitoring, fed by the stream.

**Step 7a — Re-center (periodic).** On the re-centering cadence, a full rescan of `web01` arrives. The reconciler diffs it against its materialized state (drift check — disagreement is alertable), re-seeds the keyed store from it, advances the watermark, and the rescan enters the evidence package as primary evidence (§7).

**Step 8 — Boundary change.** When `web01` is decommissioned, the `hdf-system` document is updated to remove the component (a rare, deliberate edit), the reconciler drops its keys, and `state: "absent"` events (thin `before`, `after: null`) mark the disappearance so downstream views stop expecting it.

**Why the loop holds together:** stable `componentId` + `requirementId` are the join keys across every scan; the per-requirement checksum decides what moved; `changeEventFromPrevious` turns "moved" into an event; `foldChangeEventsIntoComparison` and `applyChangeEvents` turn a window of events back into the batch artifacts governance already understands. Everything hdf-libs owns is a pure function over those keys — the state store, cadence, and transport are the external producer/reconciler's job.

## Alternatives Considered

### Alternative A: The event **is** a `Requirement_Diff` (carry the full diff on the wire)
Make the "same vocabulary we already validate" claim literally true by streaming full `Requirement_Diff` objects.
- **Pros:** Reconciliation is identity; zero lift at fold time; one type.
- **Cons:** ~3.7 KB median / 817 KB worst-case events (two full snapshots) where one snapshot suffices; `unevaluatedProperties: false` forbids the required envelope fields, so the type must change anyway; the diff's matching machinery and batch-only states are dead weight a producer can never populate.
- **Why rejected:** The measured cost buys nothing — full `before` is recoverable from reconciler state — and the type still has to change to admit the envelope. See §2–§3.

### Alternative B: Relax `Requirement_Diff` into the event (one type, loosened)
Add optional envelope fields to `Requirement_Diff` and relax its required list so thin instances validate.
- **Pros:** Single type to version.
- **Cons:** Downgrades the at-rest contract for every existing `hdf-comparison` consumer (hdf-diff's severity filter reads `tags` out of `before`/`after`; the CLI renders the snapshots); pollutes a domain type with transport identity that is meaningless at rest; "required in a document, optional on the wire" is only expressible as two `$defs` anyway.
- **Why rejected:** Strictness of the batch artifact is load-bearing. The envelope/payload separation is the settled lesson of CloudEvents/CDC — merging them rebuilds the problem those standards solved.

### Alternative C: Effective-fields-only events (the ~400 B thin shape)
Stream only `{ state, before, after }` effective projections.
- **Pros:** Minimal wire cost; trivially cheap producers.
- **Cons:** Cannot reproduce changed requirement content, so `applyChangeEvents` reassembly is unachievable by construction — for `updated`, not just `new`; strips the evidence (`results[]`) that responders open the event for; since events fire only on change, essentially every real event is content-bearing and the thin tier serves no one.
- **Why rejected:** The reassembly-parity invariant (§6) is a requirement, not a nice-to-have; §3's measurements show the honest cost of parity is ~2.1 KB median.

### Alternative D: New standalone event vocabulary unrelated to `hdf-comparison`
Define a brand-new change vocabulary for the event.
- **Pros:** Freedom to shape everything for the wire.
- **Cons:** Duplicates `Requirement_State`/`Change_Reason` — which already extend SARIF's `baselineState` with the direction (`fixed`/`regressed`) SARIF itself lacks; two vocabularies to version; consumers learn a second model.
- **Why rejected:** The vocabulary is reused (§2); only the *type* is new, because the envelope and payload obligations genuinely differ.

### Alternative E: Emit raw per-result events (the firehose)
Stream every evaluated requirement as it completes.
- **Pros:** No state anywhere.
- **Cons / Why rejected:** Already rejected in ADR-0003 (Alt C). Conflates lake ingestion (served by the batch exporter) with the change signal, and re-carries metadata HDF exists to normalize.

### Alternative F: Anchor to an evidence package (mutate it live)
Treat `hdf-evidence-package` as a living object the stream updates in place.
- **Pros:** One artifact reflects current posture at all times.
- **Cons:** Destroys the snapshot semantics that make HDF useful for accreditation; unauditable mutable record; conflates signal with artifact.
- **Why rejected:** Decision §5 — the stream is a signal; authoritative artifacts stay periodic snapshots.

### Alternative G: Anchor to a baseline only (no system)
Key events on `(baseline, requirement)` without a system boundary.
- **Pros:** Simpler key.
- **Cons:** cATO is per-*system* continuous authorization; the same control on two systems changes independently; reconciliation targets a system's SAR/POA&M.
- **Why rejected:** The system is the unit of authorization; `systemDrift`/`systemRef` already encode it.

### Alternative H: Build the runtime/producer now, in hdf-libs
- **Pros:** End-to-end demo in one repo.
- **Cons / Why rejected:** Violates the format-vs-transport boundary (ADR-0003 §4); a long-running stateful service is categorically different software from a stateless schema/converter library.

### Alternative I: Do Nothing (keep ADR-0003 deferred)
- **Pros:** No speculative work.
- **Cons:** Leaves the schema/functions undesigned when a producer appears, forcing rushed design under delivery pressure — the exact failure ADR-0003's Phase 2 exists to avoid.
- **Why rejected:** Building the library kernel speculatively is low-cost, testable without a producer, and de-risks the eventual runtime.

## Consequences

**What becomes easier:**
- A cATO consumer gets a concrete, validated, standards-grounded event shape and three pure kernel functions to build a pipeline around, without waiting on schema design.
- Batch and stream stay reconcilable by *tested invariant*, not by construction-claims: the parity and fold–batch laws are the test suite, and they double as the production drift check.
- The reconciled result set has honest, machine-readable provenance; downstream precedence is a one-line rule.
- The OSCAL story is coherent: events reconcile into SAR/POA&M against an SSP-defined system.

**What becomes harder:**
- More schema surface at TS↔Go parity: `Requirement_Change_Event`, the per-requirement checksum, and the derivation block are new commitments.
- The signal-vs-artifact boundary must be actively defended against "just update the evidence package live" requests.
- Producer discipline is now a documented contract (completeness, sequencing) — real producers must be held to it, and the library can only detect violations (chain gaps), not prevent them.
- Testing a producerless system: synthetic + throwaway-producer streams validate the *library*, not a real pipeline.

**Risks:**
- *Envelope designed wrong despite grounding.* *Mitigation:* every field now traces to a primary source or a documented divergence; prototype `changeEventFromPrevious` against real fixtures before freezing.
- *Component identity unstable across scans* (a re-keyed component makes every requirement look `new`). *Mitigation:* reuse `hdf-comparison`'s component matching rules; treat identity stability as an explicit precondition; test host-disappearance/re-key edges.
- *Per-requirement checksum picks the wrong field set* (misses a change-worthy field or churns on a volatile one). *Mitigation:* derive from the effective fields the exporter already treats as load-bearing; unit-test that each status/impact/disposition transition flips it and nothing else does.
- *Producers violate the completeness contract* (out-of-band override changes never emit). *Mitigation:* the chain makes gaps detectable; the re-centering drift check catches what the chain cannot; document the contract prominently in the producer-facing docs.
- *Scope creep pulls a runtime into hdf-libs.* *Mitigation:* Decision §10.

## Implementation Plan

### Scope

**IN scope (hdf-libs, this effort):**
- The **`Requirement_Change_Event` schema** (envelope §4 + payload §3), with validation, examples, and TS↔Go parity.
- Pure **`changeEventFromPrevious`**, **`foldChangeEventsIntoComparison`**, and **`applyChangeEvents`**, stateless, TS↔Go parity, real fixtures.
- The **per-requirement effective-fields checksum** on `hdf-results` (§8).
- The **derivation block** on `hdf-results` for reconciled result sets (§7) — flagged schema addition, designed in the schema phase.
- **Thin batch CLI wrappers** — `hdf events derive | fold | apply` — over the three kernel functions. Each invocation is stateless and deterministic (state lives in user-supplied files), so they sit inside the repo's no-runtime invariant exactly as hdf-cli's other batch commands do. The loop/cadence/daemon around them remains external.
- Reuse of the existing ECS/OCSF projection (no new projection; document the `state` → OCSF `activity_id` and → SARIF `baselineState` mappings).

**OUT of scope (external — SAF CLI, a scratch project, or a consuming team):**
- The event **producer** — including the optional dead-simple "hello-world" test producer.
- The stream-processor **runtime**, state store, keying/partitioning, message bus, and re-centering cutover policy.
- Deployment topology and the governance **escalation policy**.

**Prior art for the (external) reconciler.** The reconciler is a well-trodden pattern — keyed last-value state + emit-on-change + a materialized current view: **AWS Config** keeps compliance state per `(resource, rule)` and emits a compliance-change notification when it flips (the closest domain analog — swap in `(system, component, requirement)`); **Wazuh / OSSEC FIM** holds a baseline per file and emits only on change; **Kafka Streams / ksqlDB** — a `KTable` *is* last-value-per-key over a log-compacted changelog, the likely engineering substrate (Flink for heavier stateful cases); Elastic's `latest` transform plus Watcher is the ECS-stack equivalent. Whatever is built depends on hdf-libs for the schema + pure functions and supplies only state, transport, and lifecycle.

### Phases (with acceptance + verification)

1. **Phase 1 — Per-requirement checksum in `hdf-results`.** Add the effective-fields checksum. *AC:* present + deterministic + TS↔Go identical; flips on status/impact/disposition change, stable otherwise. *Verify:* unit tests over transition fixtures at parity; schema propagation (src → dist/go → validators embed → site).
2. **Phase 2 — `Requirement_Change_Event` schema.** Define envelope + payload + examples; include the derivation-block design for `hdf-results`. *AC:* validates; carries the §4 envelope and §3 payload; `after` required-non-null except `absent` (conditional schema); examples cover each event state incl. chain start (null `priorChecksum`) and `absent`. *Verify:* schema tests; example fixtures validate; quicktype propagation clean.
3. **Phase 3 — Kernel functions.** Implement + unit-test all three at TS↔Go parity against real fixtures. *AC:* exact event for each transition (fixed, regressed, new, absent, updated, no-change→null); **the §6 parity law holds over same-target fixture pairs** with only the documented mask; the fold–batch law holds modulo batch-only states; duplicate and shuffled delivery produce identical output. *Verify:* parity unit tests; property tests (dedup/reorder); ground-truth-anchor-style count checks; edge cases (first scan, chain gap detected, host disappearance, baseline version change).
4. **Phase 4a — Batch CLI wrappers + external live-scan validation (the primary hands-on validation).** In-repo: `hdf events derive | fold | apply` batch subcommands wrapping the kernel (stateless per invocation; see Scope). External (scratch repo): a demo that drives a real container target through seed → deliberate drift → derive → fold/apply → a **live parity-law assertion** → the amendment path → chaos tests (replay/reorder/drop) → re-center, using real scans end to end. Zero infrastructure beyond a shell loop; it dogfoods the API and surfaces ergonomics problems before any runtime exists. If the kernel cannot cleanly power this dead-simple loop, fix the kernel first.
5. **Phase 4b — Kafka reference implementation (optional demo — explicitly NOT in scope).** A log-compacted-topic + Streams-app rendering of the reconciler (a `KTable` keyed on the entity key as the last-value store). **Definitely out of scope for hdf-libs — and out of scope for this PR and for the schema/kernel effort itself.** A *neat reference implementation* for stakeholder pitches, **not** an acceptance criterion. Pursue only as a separately-scoped demo once Phases 1–3 land and 4a has proven the API; it teaches nothing about the kernel that 4a does not.

### Verification Strategy

- **Library-first:** everything in scope is verified by stateless unit tests at TS↔Go parity against real fixtures, before any producer or runtime exists.
- **The parity and fold–batch laws are the invariants** (§6) — tested directly, over the fixture corpus, with the mask enumerated and justified key-by-key.
- **Open questions to resolve in Phases 1–2, not assumed now:** exact per-requirement checksum field set + algorithm; the derivation block's exact shape; component-identity/matching reuse from `hdf-comparison`; the escalation policy surface (deferred to the consuming tool, but its inputs must be present in the event); and **re-confirmation freshness** — a rescan that finds a still-failing control emits nothing under change semantics, yet evidence staleness is itself an ISCM signal (SP 800-137); whether that becomes a heartbeat event class, reconciler-side bookkeeping, or stays out of scope is deliberately not decided here.

## References

Standards and precedents grounding the envelope, payload, and lineage decisions (each verified against the primary source during design review):

- **CloudEvents v1.0.2** — `id`/`source` uniqueness and dedup semantics; `dataschema`; the `sequence` extension's non-normative status and per-source scope. <https://github.com/cloudevents/spec>
- **SARIF 2.1.0** — `baselineState` (§3.27.24) as the closed 4-value change-state HDF's `Requirement_State` extends; `guid`/`correlationGuid`/`fingerprints` identity split. <https://docs.oasis-open.org/sarif/sarif/v2.1.0/>
- **OCSF Compliance Finding (class 2003)** — `finding_info.uid` (durable entity) vs `metadata.uid` (event occurrence); required `activity_id` Create/Update/Close; `metadata.version`/`metadata.sequence`. <https://schema.ocsf.io>
- **ECS** — `event.id`/`event.sequence` ("make the exact ordering of events unambiguous, regardless of the timestamp precision"); occurrence-vs-pipeline timestamps. <https://www.elastic.co/docs/reference/ecs>
- **Debezium CDC** — full-after-row envelope; `source` block ordering fields vs `ts_ms`; tombstones; primary-key change as delete+create. <https://debezium.io/documentation>
- **Kafka log compaction / event sourcing** — per-key ordering, keyed compaction, rebuild-by-replay (Fowler; Young's aggregate-version sequencing). <https://kafka.apache.org/documentation/#compaction>
- **RFC 6902 / RFC 7386** — why the wire form is state-carrying, not a patch.
- **RFC 6962 / RFC 9162, AWS CloudTrail log-file integrity** — hash-chain guarantees and limits (tamper-evidence given a trusted head; completeness requires an out-of-band anchor); `previousDigestHashValue` chaining with null chain start.
- **W3C SRI / OCI descriptors / SPDX external document refs** — the location + expected-hash reference pattern behind `Content_Reference`.
- **W3C PROV-DM / OpenLineage** — qualified derivation and dataset-version pinning behind the derivation block.
- **NIST SP 800-137, SP 800-37r2, DoD cATO memo (Feb 2022)** — the demand framing: continuous change signals feeding a near-real-time authorization view.

## Notes

- ADR location: `dev-docs/` (historical artifacts; not on the published VitePress site).
- This ADR reopens and advances ADR-0003; ADR-0003's architecture (change-events-not-firehose, format/transport split, keyed compaction, checksum heartbeat) stands and is cited rather than repeated.
- Revision 2 (2026-07-26) incorporates the PR #161 design review: the event is a new type rather than a `Requirement_Diff` (Finding 1); the CloudEvents-style envelope and normative fold contract (Finding 2); `state`/`before`/`after` naming and the "delta" rename (Finding 3); plus the reassembly-parity invariant, the reconciled-result-set/lineage/re-centering design, and the standards grounding survey.
- The OCSF Compliance Finding mapping (class 2003) is already shipped in `hdf-to-ocsf`; a formal upstream OCSF *profile/extension* (`profile.ohdf.*`) beyond the class mapping is a **separate, optional standards-track effort**, not part of this work.
