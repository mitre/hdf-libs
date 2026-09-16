# ADR-0015: Backwards-compatible input normalization for legacy SAF-supplement shapes

Status: proposed
Date: 2026-09-15
Refs: GitHub #234; related #233, #235. This ADR covers only the input-normalization half of #234; the OSCAL-SAR components[] round-trip half is handled separately by bead hdf-libs-3ysxe under the OSCAL fidelity epic (gxeb), in its own PR.

## Context

`saf supplement target write` and the SAF `passthrough` convention stamp two
**top-level** keys onto an HDF results document:

- `target` — what was assessed, e.g. `{"id":"prod-account","type":"cloudAccount","boundary":"sparc"}`
- `passthrough` — provenance / original-scan carrier, e.g. `passthrough.audit`

These are a **HDF v2 (Heimdall ExecJSON)** convention. That schema is open
(`additionalProperties: true`), so the keys were valid there, and ~15 heimdall2
converters emit `passthrough` to carry a scan's native structure.

HDF **v3 deliberately re-homed both concepts** into typed, scoped carriers:

- **`components[]` is the documented successor to Target** — `component.schema.json`:
  *"Components are the successor to Targets, adding stable identity (componentId),
  external system cross-references, and manifest inventory."* `cloudAccount` is one
  of the component types. There is no top-level `target` in v3 by design.
- **`extensions`** (top-level) is *"Reserved for tool-specific data not defined in
  the HDF standard. Use this to preserve original tool output, auxiliary data,
  provenance"* — the direct heir to v2's `passthrough`. (Per-requirement raw lives
  in `code`; native manifests use BOM passthrough, ADR-0001.)

The v3 results schema sets **`unevaluatedProperties: false`**, so a document
carrying top-level `target`/`passthrough` is schema-invalid. `hdf convert`
silently drops them (issue #234): attribution — the thing the conversion pipeline
exists to feed — does not survive.

The user who hit this (issue #234) produced the document with **SAF's own CLI**.
That makes it our responsibility to remain backwards-compatible with SAF-supplement
output, not the user's responsibility to hand-edit their documents.

Issue #234 also reports a second, naming-independent defect: `components[]` is lost
through the **HDF → OSCAL-SAR → HDF** round trip (only the first component
survives). That is an OSCAL converter bug, not an input-normalization concern, and
is handled in a separate PR under the OSCAL fidelity epic (bead hdf-libs-3ysxe). It
is called out here only so the two halves of #234 stay legible; this ADR does not
own it. The two are independent in code (the round trip is testable against a pure
v3 multi-component document with no normalization); #234 closes at release once both
have shipped.

## Decision

**Absorb the legacy SAF-supplement shape with a backwards-compatible input
normalizer that rewrites the legacy top-level keys into v3-native carriers before
schema validation. Do NOT add `target`/`passthrough` to the v3 schema.**

- **Placement — all read paths.** The normalizer is a pre-validation byte transform
  in `hdf-parsers` `ParseResults`/`ParseBaseline`, a sibling to the existing
  `NormalizeTimestamps` (which already runs before the schema gate). Every command
  that parses HDF (convert, query, validate, list, …) therefore accepts a
  SAF-supplemented document; the document becomes valid v3 *before* the
  `unevaluatedProperties: false` gate rejects it.
- **Rewrite, don't preserve.** The raw legacy keys never reach a validated document.
  The normalizer detects top-level `target`/`passthrough` on an otherwise-v3-shaped
  results doc and rewrites them:
  - `target {id, type, boundary}` → a `components[]` entry: `type` → component `type`
    (validated against the component-type enum); `id` → the component `name`
    (required) and, for `cloudAccount`, `accountId`; **`boundary` → a `labels` entry
    (`labels.boundary`)** — a tag for now, a first-class field deferred (a possible
    later card). If an equivalent component already exists, merge (add the label)
    rather than duplicate.
  - `passthrough` → `extensions.passthrough` (namespaced so it does not collide with
    other extension data and stays recoverable); merge into any existing `extensions`.
- **Warn on normalize.** Emit a deprecation notice naming the v3-native shape, so
  users (and SAF) migrate.
- **Sunset eventually (no fixed date).** The shim is removable once the ecosystem has
  moved to v3-native shapes — possibly mooted when SAF CLI is rebuilt on hdf-libs.
  The deprecation warning is the migration signal.

## Alternatives Considered

### Alternative A: Add `target` and `passthrough` as first-class v3 schema fields
Add both as top-level properties, regenerate Go/TS types, propagate atomically.
**Rejected.** Re-adds concepts v3 intentionally replaced — `components[]` already
*is* Target's successor and `extensions` already *is* the provenance home — creating
"which do I use?" ambiguity. It is a schema change (minor version bump) and would
push ~15 converters to populate a redundant `passthrough` for consistency. Cost
*and* architectural regression, for zero capability v3 doesn't already have.

### Alternative B: Preserve the raw `target`/`passthrough` keys as untyped passthrough
Carry the keys verbatim around the typed convert path without a schema change.
**Rejected.** With `unevaluatedProperties: false`, the preserved document is still
schema-invalid — `hdf validate` would reject a document `hdf convert` faithfully
round-trips. Incoherent, and it perpetuates the v2-ism instead of migrating it.

### Alternative C: Fix it only upstream in SAF CLI (emit v3-native shapes)
Change `saf supplement target write` to write a component; tell users to upgrade.
**Rejected as the sole fix** (kept as a complementary follow-up). It strands every
document already produced by older SAF CLI and every user who has not upgraded, and
hdf-libs cannot control SAF's release cadence. hdf-libs must read what SAF has
historically emitted. (A SAF-CLI-side fix + this normalizer's sunset is the endgame.)

### Alternative D: Do nothing
**Rejected.** Silent attribution loss on SAF-produced documents is a data-integrity
failure in the pipeline the format exists to feed (issue #234).

## Consequences

- **Easier:** SAF-supplemented documents work across every hdf-libs command with no
  user action; attribution survives conversion and the OSCAL-SAR round trip; no
  schema/version churn; the migration path is explicit (the deprecation warning).
- **Harder / risks:** a normalization layer is a compatibility contract that must be
  maintained and eventually retired; the `target`→component mapping must be defined
  precisely per component type (only `cloudAccount` is exercised by #234 today — the
  normalizer validates `target.type` against the enum and warns on an unmapped type
  rather than guessing); `boundary`-as-label is a stopgap that may need promotion to
  a first-class field later.
- **Parity:** `hdf-parsers` is dual Go + TS; the normalizer ships in both languages
  and is pinned against a shared fixture, exactly like the timestamp normalizer.
- **No schema change**, so no `$id`/version movement and no generated-type regen.

## Implementation Plan

### Quality Standards (inherited by every card)
- **Framework/pattern-first:** the normalizer is a sibling to `NormalizeTimestamps`
  in `hdf-parsers` — a byte→byte transform applied before `validators.Validate*`.
  Follow that exact pattern; do not add a bespoke pre-parse hook elsewhere.
- **Go/TS parity:** implement in both `hdf-parsers` languages; pin behavior with a
  shared fixture pair (legacy-in / v3-out) both suites read, mirroring the
  timestamp-normalizer parity discipline. No language-only normalization.
- **TDD, >90% coverage, zero lint.** Table-driven tests for the mapping matrix.
- **Idempotent + narrow:** a document with no legacy keys passes through byte-identical;
  a document already carrying `components`/`extensions` is merged into, never clobbered.
- **No schema edits, no generated-type edits** (Anti-pattern: touching
  `hdf-schema` or `hdf.go` — this ADR's whole point is that the schema does not change).
- **Deprecation warning** surfaced through the existing lossy/notice UX, not a bespoke
  channel.

### Shared Abstractions (built before consumers)
| Shared need | Used by | Card as |
|---|---|---|
| `NormalizeSAFSupplement(input []byte) ([]byte, warnings)` in hdf-parsers (Go + TS) | ParseResults, ParseBaseline, all read paths | Phase 1 foundation card |
| Shared legacy-in/v3-out fixture pair | Go + TS normalizer tests | Phase 1 foundation card |

### Scope
- **IN:** detect + rewrite top-level `target`/`passthrough` on v3-results (and
  baseline where applicable) input, in Go and TS, before validation, on all read
  paths; deprecation warning.
- **OUT:** the components[] **OSCAL-SAR round-trip fix** (separate PR, OSCAL epic
  gxeb / bead 3ysxe — an independent converter bug); adding `target`/`passthrough` to
  the schema; promoting `boundary` to a first-class field (deferred); new `hdf`
  subcommands to read/write target/passthrough (that is #235 / bead wp8u7); HDF v1
  renumbering (#233); changing SAF CLI itself (complementary follow-up, tracked
  separately).
- **FUTURE:** first-class `boundary`; SAF CLI emitting v3-native shapes; sunset of
  this shim.

### Phases
1. **Foundation — the normalizer + shared fixtures (Go + TS).** `NormalizeSAFSupplement`:
   detect legacy keys, rewrite target→component (type-validated, `boundary`→label,
   dedup/merge) and passthrough→`extensions.passthrough` (merge), return warnings;
   byte-identical passthrough when no legacy keys; shared legacy-in/v3-out fixtures;
   table-driven parity tests. First failing test:
   `TestNormalizeSAFSupplement_TargetBecomesComponent`.
2. **Wire into all read paths.** Call the normalizer before validation in
   `ParseResults`/`ParseBaseline` (Go + TS); surface the deprecation warning through
   the CLI/MCP notice UX. Assert a SAF-supplemented doc now converts/queries/validates
   and that `target`/`passthrough` survive as component/extensions. Live CLI proof.

(The OSCAL-SAR components[] round-trip fix is intentionally NOT a phase here — it is a
separate PR under the OSCAL epic; see Scope → OUT and bead 3ysxe.)

### Verification Strategy
`cd hdf-parsers && go test ./go/... && pnpm test:ts` (normalizer + Go/TS parity);
`cd hdf-cli && go test ./cmd/hdf/cmd/ && go build ./... && golangci-lint run`; plus a
live CLI run on clem-field's #234 document shape confirming `target` normalizes to a
`cloudAccount` component and `passthrough` to `extensions.passthrough` (commands +
output pasted in the card).

## References
- GitHub #234 (source), #233, #235
- ADR-0001 (BOM passthrough — the established "carry native data opaquely" precedent)
- `hdf-schema/src/schemas/primitives/component.schema.json` ("successor to Targets")
- `hdf-schema/src/schemas/hdf-results.schema.json` (`unevaluatedProperties: false`; `extensions`)
- `hdf-parsers/go/parsers.go` (`ParseResults`, `NormalizeTimestamps` — the sibling pattern)
- bead hdf-libs-3ysxe (the OSCAL-SAR round-trip half of #234; separate PR, OSCAL epic gxeb)
