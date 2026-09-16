# ADR-0016: Source-artifact carriage — every converted document references its original, embedding optional

- **Status:** Proposed — **DRAFT, needs heavy refinement.** This records a direction and the evidence behind it, not a settled design. The Open Questions section is load-bearing: several of its answers could change the Decision. Do not card implementation from this draft until the open questions are resolved.
- **Date:** 2026-09-16
- **Deciders:** Will Dower (pending review)
- **Branch:** `feat/schema-greenfield` (may carry further schema adjustments)
- **Relates to:**
  - [ADR-0001](adr-0001-generalized-bom-representation.md) — BOM passthrough by reference (`ref`) or by embedding (`document`), the established "carry native data opaquely" precedent.
  - [ADR-0006](adr-0006-stix-cti-integration.md) — introduced the `External_Reference` primitive this ADR reuses.
  - [ADR-0007](adr-0007-hdf-mcp-server.md) — the MCP's size constraint and token budgets.
  - ADR-0014 (OSCAL namespace, prose carriage and identity; PR #352) — Alternative F rejected document-level passthrough for OSCAL props because carriage must be object-local.
  - ADR-0015 (SAF-supplement input normalization; PR #354) — maps legacy top-level `passthrough` to `extensions.passthrough`, and its Alternative A rejected a first-class `passthrough` schema field.

## Context

Heimdall's HDF v2 converters could attach an exact copy of the original tool output to the document (`passthrough`). HDF v3 split that idea without finishing it: `requirements[].code` carries the code or record a scanner ran, and the root `extensions` object invites "preserve original tool output" in its description, but no field is defined as *the entire original output*.

One of the original Heimdall developers has argued, in retrospect, that passthrough should have been a **requirement** of converters where feasible: having the source in the normalized document makes it trivial to reconstruct the original, and nobody has raised storage or transfer cost as a real concern. This ADR tests that proposal against measurements taken in this repository.

### What converters do today (measured 2026-09-15)

62 converter directories: 47 ingest (`*-to-hdf`), 14 export (`hdf-to-*`), and `hdf-passthrough` (which is only a fingerprint for input that is already HDF, not a carrier).

| Field | What it holds | Ingest converters populating it |
|---|---|---|
| `baselines[].requirements[].code` | code/record the scanner ran | 27 of 47 |
| `baselines[].requirements[].sourceLocation` | pointer (`ref`, `line`) — not content | 17 of 47 |
| root `extensions` | "use this to preserve original tool output" | **0** |
| `baselines[].extensions` | scan metadata | 3 (gosec, ionchannel, neuvector) |
| `baselines[].resultsChecksum` | SHA-256 of the raw input (via `inputChecksum` / `shared.InputChecksum`) | effectively all |

`code` has absorbed the passthrough role de facto: asff, trivy and nessus serialize the entire source record into it, per requirement. Nothing reconstructs source output from HDF, and the conversion fidelity harness asserts requirement counts only (`registry/convert/fidelity_check.go`: "Count fidelity only — the right count with the wrong severities still passes").

### The schema already models reference-versus-embed

- **`External_Reference`** (`primitives/common.schema.json`) has `href`, `checksum` (the HDF `Checksum` primitive), `mediaType`, an open `rel` token, an open `kind` token, and `document`: an "optional lossless embedded copy of the referenced artifact … preserved verbatim", which "composes with `href`/`externalId` … and `checksum` … a single entry can both point and embed." `externalReferences[]` exists at the root of results, plan, system, comparison and evidence-package documents.
- **`Bom`** (`primitives/bom.schema.json`) has `ref` (passthrough by reference) beside `document` (passthrough by embedding) — the same choice, already made for BOMs (ADR-0001).
- **`External_Evidence_Reference`** (`hdf-evidence-package.schema.json`): "The data stays canonical in its native format — HDF references it, never parses or transcodes it."

The one structural gap: `External_Reference.document` is `type: object`, so a non-JSON source (XML, CSV, plain text) cannot be embedded in it as-is.

### Cost of mandatory embedding (measured)

15 real fixture pairs, original embedded as a JSON string at the document root, both sides normalized with `jq -S`:

- **Median multiplier 2.32× raw, 1.99× gzipped.** Sample totals: 20.0 MB → 45.3 MB raw; 2.07 MB → 4.61 MB gzipped.
- The multiplier is `1 + input/hdf`, so it is worst where converters are most lossy — `sarif-to-hdf` 12.19×, `junit-to-hdf` 10.44×, `oscal-to-hdf` (NIST 800-53 catalog) 6.92× — and smallest where HDF already exceeds its source — `prisma-to-hdf` (CSV) 1.18×, `gitlab-to-hdf` 1.47×, `cyclonedx-to-hdf` 1.53×, `grype-to-hdf` 1.60×.
- The 5 MB legacy InSpec pair ADR-0007 cites (`hdf-fixtures/inspec/wrapper.json` → its HDF) costs **2.88× raw, 2.96× gzipped**.
- **Compression does not recover it.** gzip's 32 KB window is far smaller than these documents, so the embedded copy is not deduplicated against the HDF derived from it: its marginal compressed cost equals its standalone compressed size (nessus: 478,092 vs 478,276 bytes).
- JSON-string escaping adds 7–12% to embedded JSON sources and 1–3% to XML sources.

### Storage is not the binding constraint — the input ceilings are

Every gate is 50 MB: `hdfutil.DefaultMaxInputSize` (`hdf-utilities/go/size.go`), its TS peer, `DefaultMaxXMLSize`, the CLI file reader (`--max-size` default 50), and the MCP per-document read (`HDF_MCP_MAX_SIZE`). They gate *input*, so conversion itself is unaffected — but the enlarged HDF is input to the CLI loader, engine, validators, MCP and every `hdf-to-*` exporter. A source of roughly 25 MB, legal today, would convert and then fail to reload. **Mandatory embedding halves the usable budget of every round-trip pipeline.** No code path streams HDF: Go uses whole-buffer `json.Unmarshal` throughout, and TS uses `JSON.parse`.

### MCP and other resource-lite consumers

- **Context cost is low by construction.** No MCP tool returns a document body; handlers project named fields (`hdf_query`: `id, title, status, severity, impact`, plus `baseline, tags, descriptions` at full detail), and responses are capped at 2,000 / 10,000 tokens on serialized size. The precedent exists: raw findings already ride in `code`, which no read tool projects; `tools/payload_boundary_test.go` measures that 89 `code` blobs total ~149,735 tokens, within 4% of the whole raw file.
- **Memory and parse cost is not low.** The MCP document cache (`internal/mcp/loader`, 256 MB byte-bounded LRU) retains both raw bytes and parsed form, so capacity halves; documents over budget bypass it and their content-addressed handles stop resolving. `hdf-diff` parses every document twice — once into a generic `map[string]any` (which retains the blob) to detect legacy format, then typed. Anything carried under root `extensions` is retained in Go as an `interface{}` tree and re-marshalled by the MCP write tools.

## Decision (draft)

**Every converter records its source artifact by reference, with a checksum; embedding the artifact is opt-in. No new top-level schema field.**

1. **The carrier is one `External_Reference` entry in the document's root `externalReferences[]`, with `rel: "source"`.** `source` joins `rel`'s documented starter vocabulary. The entry carries:
   - `sourceName` — the tool (required by the primitive);
   - `checksum` — SHA-256 of the exact input bytes the converter read (the value `inputChecksum` already computes);
   - `mediaType` — the input's media type;
   - `href` — only when the caller supplies a meaningful location (see Open Question 4);
   - `document` — **only when embedding is requested** (see §3 and Open Question 2).
2. **Carriage by reference is required of converters by policy, not by schema.** Tools that emit HDF natively have no source artifact to reference, so a schema-level requirement would make valid native HDF invalid. The converter contract, its shared builder, and the converter test harness enforce it instead.
3. **Embedding is opt-in** (`hdf convert --embed-source`, and the equivalent builder option). Default output stays close to today's size. Embedding is the right choice when self-containment matters more than size — air-gapped transfer, evidence packages — and it is paid knowingly.
4. **Set centrally.** The reference is emitted by the shared builders (`BuildHDFResults` / `buildHdfResults`), which 39 of 47 Go ingest converters already call (~30 TS); the remaining converters that build documents by hand are updated individually.
5. **Restoration is a CLI capability, not a property of exporters.** `hdf restore` (name TBD) writes the embedded original back out and verifies it against `checksum`. A passthrough only helps when the target format *is* the source format: HDF produced from Nessus carries Nessus XML, which does nothing for `hdf-to-oscal-sar`. Exporters keep their real conversion logic.

## Open Questions (must be resolved before this ADR is accepted)

1. **Should this ADR supersede part of ADR-0015?** ADR-0015 (open, PR #354) rewrites legacy `passthrough` to `extensions.passthrough`. Adopting this ADR would create two homes for "original data." Options: point the ADR-0015 normalizer at a `rel: "source"` entry instead, or keep `extensions.passthrough` for legacy content only. Coordinate before PR #354 merges.
2. **What type does embedded content take?** `External_Reference.document` is object-only. XML, CSV and text sources cannot be embedded without either widening `document` (to `object | string`), adding a sibling `content` + `encoding` pair (text vs base64), or wrapping text in an object. This is the one change that forces a schema version bump.
3. **Is `resultsChecksum` the right place for the input hash today?** Converters store the raw-input SHA-256 there, but the schema describes it as "raw results before any amendments." For converters those are the same bytes; for native emitters they are not. Keep the overload, or make the `rel: "source"` checksum authoritative and define `resultsChecksum` separately?
4. **What goes in `href`?** A converter sees bytes, not locations. Absolute local paths leak machine and user details (this repo has been bitten by that in fixtures). Omit by default and set only from an explicit caller-supplied URI?
5. **What happens above the ceiling?** Options: refuse to embed when the result would exceed the reload limit; raise the loader limits for embedded documents; or introduce streaming/lazy parsing so `document` is skipped until asked for. Mandatory-reference with opt-in embedding contains the problem but does not remove it for users who opt in.
6. **Does document-level embedding make per-requirement raw `code` redundant?** asff, trivy and nessus already put whole source records in `code`. With `--embed-source`, are those duplicated a third time? Should `code` narrow to the check/query itself?
7. **Multi-input conversions.** Where a conversion consumes more than one artifact, is it one `rel: "source"` entry per input? Does order matter for restoration?
8. **Sensitivity.** Raw tool output routinely contains hostnames, internal addresses and configuration fragments (ADR-0007). Embedding widens exposure to every consumer of the document. Is any redaction or an explicit sensitivity marker required when embedding?
9. **Is the evidence bar met?** The colleague's argument rests on reconstruction being valuable. No current consumer reconstructs sources, and no user request for it is on record. This ADR should cite at least one concrete workflow that needs restoration before the embedding half ships.
10. **Object-local carriage still stands.** ADR-0014 Alternative F showed OSCAL props must be carried per object to re-export. A document-level source reference does not replace that; confirm the two coexist without either being treated as a substitute.

## Alternatives Considered

### Alternative A: Mandatory inline embedding for every converter (the original proposal)
Every converter embeds its full source in the document.
- **Pros:** every converted document is self-contained; restoration is always possible; simplest rule to state.
- **Cons:** measured median cost 2.32× raw and 1.99× gzipped, up to 12× for lossy converters; halves the usable 50 MB budget of every round-trip pipeline; halves the MCP document cache; retained twice over by `hdf-diff`'s generic parse; widens exposure of sensitive raw output by default; changes every converter's expected fixtures.
- **Why rejected (draft):** the guarantee it buys — a verifiable link to the original — is available by reference at near-zero cost, and the self-containment it adds can be opted into where it is actually wanted.

### Alternative B: A new first-class top-level field (`source` / `passthrough`)
Add a dedicated typed field to each document schema.
- **Pros:** discoverable; self-describing.
- **Cons:** duplicates `External_Reference`, which already carries href, checksum, media type and an embedded copy; creates the "which do I use?" ambiguity ADR-0015 Alternative A rejected for the same concept.
- **Why rejected (draft):** the primitive exists; a new `rel` token composes with it.

### Alternative C: Use `extensions.passthrough` for every converter (extend ADR-0015)
Converters write their source into the untyped root `extensions` object.
- **Pros:** no schema change at all; aligns with ADR-0015's legacy mapping.
- **Cons:** untyped — no checksum, media-type or reference contract; retained in Go as an `interface{}` tree; object-only, so text sources still need wrapping; invisible to schema validation.
- **Why rejected (draft):** it keeps the data but loses the verifiability that makes carriage worth doing. It may remain right for *legacy* passthrough content (Open Question 1).

### Alternative D: Reference only, never embed (sidecar files)
Store the original beside the HDF, content-addressed by checksum; HDF only references it.
- **Pros:** smallest documents; no ceiling pressure; mirrors the evidence-package "reference, never transcode" rule.
- **Cons:** loses self-containment for transfer and evidence packaging; restoration needs the sidecar to travel with the document.
- **Why not chosen (draft):** it is the Decision's default; the draft keeps embedding available as an opt-in rather than forbidding it.

### Alternative E: Standardize per-requirement raw carriage in `code`
Every converter serializes each source record into its requirement's `code`, as asff and trivy do.
- **Pros:** data sits beside the finding it produced; already practised by several converters.
- **Cons:** fragments the source and loses document-level structure, so the original cannot be restored; overloads a field defined as "the raw source code of the requirement"; the MCP already measures `code` blobs at ~1,607 tokens median each.
- **Why rejected (draft):** it cannot deliver restoration, which is the proposal's point.

### Alternative F: Do nothing
Keep `resultsChecksum` as the only link to the source; leave root `extensions` unused.
- **Pros:** no work, no churn.
- **Cons:** documents carry a hash of their input with no record of what the input was (tool, media type), so the hash cannot be acted on; `extensions`' "preserve original tool output" invitation stays unimplemented and inconsistently interpreted; converters keep inventing per-requirement carriage.
- **Why rejected (draft):** a single reference entry is cheap, and it turns an existing opaque hash into provenance.

## Consequences (draft)

**What becomes easier:**
- Every converted document names its source artifact and ties it to the exact input bytes by checksum.
- Restoring the original is a one-command operation for documents converted with embedding.
- The schema gains no new top-level concept; source carriage reuses `External_Reference`.

**What becomes harder:**
- Every converter's expected output gains a reference entry, so every golden regenerates — a large, deliberate, reviewable diff.
- The converter contract gains a policy rule that the schema cannot enforce; the test harness must.
- If Open Question 2 widens `document`, every consumer of `External_Reference` must handle a string payload.

**Risks:**
- *Opt-in embedding still hits the 50 MB reload ceiling.* Mitigation pending Open Question 5.
- *Embedded raw output exposes sensitive data more widely.* Mitigation pending Open Question 8.
- *Two homes for original data* (this ADR and ADR-0015's `extensions.passthrough`). Mitigation pending Open Question 1.
- *"We keep the original" becomes a reason to stop backfilling normalized fields.* Downstream consumers read normalized fields, not attached originals; the converter source-field fidelity epic (`hdf-libs-j5hz`) is unaffected by this ADR and must not be deprioritized because of it.

## Implementation Plan (provisional — re-plan after the open questions are answered)

### Quality Standards (inherited by every card)
- **Reuse, don't invent.** Source carriage uses `External_Reference`; no new top-level field.
- **Schema examples convention.** Any change to `External_Reference` updates its `examples` and the definition-level `$comment`; `hdf-schema/test/examples-valid.test.ts` must pass.
- **Go/TS parity.** Builder options, emitted entries and CLI behaviour match across languages, pinned by shared fixtures.
- **Real fixtures only; deliberate golden regeneration**, noted per converter.
- **No machine-local data** in `href`, fixtures or examples.
- **TDD, >90% coverage on changed code, zero lint warnings.**

### Shared Abstractions (built before consumers)
| Shared need | Used by | Card as |
|---|---|---|
| `rel: "source"` vocabulary + (possibly) text-capable embedded content on `External_Reference` | builders, CLI, MCP, restore | Phase 1 schema card |
| Builder option emitting the source reference (Go `BuildHDFResults`, TS `buildHdfResults`) | 39 Go / ~30 TS converters | Phase 2 foundation card |
| Converter-contract check that a converted document carries exactly one `rel: "source"` entry per input | converter test harness | Phase 2 foundation card |

### Scope
- **IN:** the `rel: "source"` convention; any `External_Reference` change Open Question 2 requires; builder support; all ingest converters; `--embed-source`; a restore command that verifies the checksum; documentation on the site.
- **OUT:** changing `code` semantics (Open Question 6 may create a follow-up); streaming parsers (Open Question 5 may create a follow-up); the ADR-0015 normalizer itself; object-local OSCAL prop carriage (ADR-0014).

### Phases
1. **Schema** — add `source` to `rel`'s documented vocabulary; resolve and implement embedded-content typing; examples and `$comment`; regenerate TS and Go types; `pnpm build:schemas`.
2. **Builders and contract** — source-reference option on both shared builders; converter-harness assertion.
3. **Converter sweep** — enable on the 39 builder-based converters; update the 8 hand-built converters in each language; regenerate goldens deliberately.
4. **CLI** — `hdf convert --embed-source`; restore command with checksum verification.
5. **Consumers** — confirm no MCP tool projects `document`; decide the ceiling policy; address `hdf-diff`'s retaining generic parse if embedding makes it material.
6. **Docs** — site pages for source carriage, embedding trade-offs, and restoration.

### Verification Strategy
- Every ingest converter's output validates and carries one `rel: "source"` entry whose checksum equals the SHA-256 of its fixture input.
- With embedding, restore produces bytes whose SHA-256 matches `checksum`, for a JSON, an XML and a CSV source.
- Default document sizes grow by no more than the reference entry; embedded sizes are re-measured against this ADR's figures.
- A document near the reload ceiling behaves as the Open Question 5 decision specifies.

## References
- Measurements behind the Context tables: session research, 2026-09-15 (fixture pairs under `hdf-converters/converters/*/fixtures/`; commands reproducible with `wc -c`, `gzip -9`, `jq -S`).
- `hdf-schema/src/schemas/primitives/common.schema.json` — `External_Reference`, `Checksum`, `Requirement_Core.code`, `Source_Location`.
- `hdf-schema/src/schemas/primitives/bom.schema.json` — `Bom.ref` / `Bom.document`.
- `hdf-schema/src/schemas/hdf-evidence-package.schema.json` — `External_Evidence_Reference`.
- `hdf-schema/src/schemas/hdf-results.schema.json` — root `extensions`, `externalReferences`, `baselines[].resultsChecksum`, `unevaluatedProperties: false`.
- `hdf-converters/shared/go/converterutil.go` / `hdf-converters/shared/typescript/converterutil.ts` — `BuildHDFResults` / `buildHdfResults`, `InputChecksum` / `inputChecksum`.
- `hdf-utilities/go/size.go` — `DefaultMaxInputSize`.
- `hdf-cli/internal/mcp/` — `tools/source.go`, `loader/loader.go`, `respond/respond.go`, `tools/payload_boundary_test.go`.
- `hdf-diff/go/normalize.go` — generic-then-typed double parse.
