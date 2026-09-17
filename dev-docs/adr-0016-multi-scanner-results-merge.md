# ADR-0016: Multi-scanner results merge — one baseline per tool, provenance, determinism, and the bridge to ADR-0012

- **Status:** Accepted — owner review 2026-09-16 (see §Owner decisions); implementation in progress
- **Date:** 2026-09-16
- **Deciders:** Will Dower
- **Revision:** 2026-09-16 — incorporated the owner review: the three open questions (well-known label keys, non-results inputs, `generator.version`) are settled in §Owner decisions and the corollary for converter `generator.version` is carded separately (`hdf-libs-v8xd9`); Status moved from Proposed to Accepted.
- **Revision:** 2026-09-16 (implementation, card `.3`) — the engine signature is `Merge(sources []MergeSource)` / `merge(sources)`: the `opts` parameter written in §1 had no v1 meaning (every rule is fixed by this ADR), and an empty options struct would be a placeholder, not a design; an option is added when a decision needs one. Provenance label keys are documented in `site/docs/guides/label-keys-reference.md` §Merge Provenance Keys. Warnings are typed (`duplicate-baseline-name`, `label-overwritten`) and a stale `toolVersion` label on a re-merged baseline is removed (with a warning) rather than kept, since it would describe the wrong tool. Two clarifications from the card `.3` review: (a) the engine API is typed on `hdf.HDFResults`, so the §1 rejection of a non-results input necessarily lives in the callers that load documents — the CLI (`.4`) and the MCP loader (`.5`) — not in `Merge` itself; (b) "verbatim" provenance is verbatim in value, not bytes: Go re-serializes each source `timestamp` through `time.Time` (RFC 3339 nano, trailing zeros trimmed) while TS carries the string through, so a `...:11.000Z` input reads `...:11Z` from Go. Parity is asserted on names, labels, counts and root values; byte-identical output across the two languages is not a goal (determinism is per language).
- **Branch:** `feat/multi-scanner-merge`
- **Epic/cards:** `hdf-libs-js1nv` (this ADR is card `.1`; implementation is `.2`–`.8`)
- **Numbering:** 0016 because 0008–0015 are claimed on unmerged branches — 0008–0013 on `docs/adr-0008-0009-openapi-and-db-schema` (ADR-0012, the data platform, is the one this ADR relates to most), 0014 on `feat/oscal-namespace-and-prose`, 0015 on `fix/saf-supplement-input-normalization`.
- **Relates to:** **[ADR-0007](adr-0007-hdf-mcp-server.md)** §Tool contract, §Known constraints ("cross-document query filtering (its own card)"), §Quality Standards (no new logic in `internal/mcp`; engines are dual TS+Go with parity per PR); **[ADR-0001](adr-0001-generalized-bom-representation.md)** §9 (dual TS/Go parity); the HDF specification §"Evaluated_Baseline" (`site/docs/specification/hdf-specification.md`); ADR-0012 (unmerged) §Context ("Cross-document questions — these are joins over stored data"); beads `hdf-libs-vqic` (evidence portfolio, deferred) and `hdf-libs-w913.32` (evidence rollup) stay separate.

## Context

An analyst's first question over a pipeline is cross-scanner: *how many failed requirements, per NIST family, across the SAST, DAST, vulnerability and compliance scans of one system?* Today the HDF MCP cannot answer it in one call, and often cannot answer it at all within a small model's tool budget:

- `hdf_query` and `hdf_compliance` take **one** `source`. `hdf_compliance` has `groupBy` (baseline | severity | nistFamily) for one document only.
- `hdf_aggregate` takes N sources but is a **fan-out counter**: it groups only by source path, has no `groupBy`, never returns rows, and accepts a narrower filter set than `hdf_query`. It answers "how many across all" and nothing with a second dimension.
- No tool joins or correlates across documents; the opt-in `fields[]` correlation keys on `hdf_query` exist so a *client* can join, one document per call.

The format already supports the shape that would fix this. The specification says an evaluated baseline is "a set of security tests … aligned back to a baseline" and that "HDF converters should produce one evaluated baseline per scan profile, scanner module, or logical grouping of checks in the source tool's output." `hdf-results.baselines[]` is an unconstrained array, and multi-baseline output is already normal: seven shipped expected fixtures carry more than one baseline (asff per AWS standard, conveyor, ionchannel, msft-defender-devops per sub-scanner, nessus, prisma, zap per site), and the SARIF converter emits one per run. And the engine's `Filter` already iterates every baseline, stamping each match with its baseline name.

Measured on the benchmark fixtures (hdf-mcp-demo, 2026-09-16): a hand-merged document of gosec + ZAP + grype (6 baselines, 120 requirements, 944 KB) validates as `hdf-results`, and on it

| question | call | answer | ≈tokens |
|---|---|---|---|
| high-or-above across all three tools | `hdf_query impact>=0.7 limit=1` | `total: 60` | 182 (the `hdf_aggregate` answer costs ≈750) |
| ZAP only | `hdf_query baseline="zap*" limit=1` | `total: 28` | 185 |
| per-tool rollup | `hdf_compliance groupBy=baseline` | 6 groups | 480 |
| **per NIST family across tools** | `hdf_compliance groupBy=nistFamily` | AC 2, RA 99, SA 97, SC 16, SI 5 | 404 |
| high findings with CWE across tools | `hdf_query impact>=0.7 fields=[cwe,affectedPackages]` | 19 rows/page | 2,015 |

The fourth row is a capability `hdf_aggregate` cannot provide at any cost. Nothing new in the read path was needed — only the document.

What is missing is the **operation**. No `hdf merge` exists in the CLI; no library function; no MCP tool. `hdf_aggregate` builds exactly this document in memory (`hdf-cli/internal/mcp/tools/aggregate.go:107,152`) and discards it inside a closure.

Two defects surface the moment a document carries several baselines, and both already bite shipped converter output:

1. **Same-named baselines silently collapse.** `partitionResults` (`compliance.go:236-242`) keys `groupBy=baseline` partitions by `b.Name`, last write wins. Verified: two same-named baselines carrying 99 requirements → ungrouped `hdf_compliance` reports 99, `groupBy=baseline` reports **one group of 10**. No error. The specification's field table describes `name` as "Unique baseline name" (and the generated Go type's comment says "must be unique"); nothing enforces it, and the shipped Prisma fixture has 16 baselines under one name (Nessus 3/1, Conveyor 4/1).
2. **Rows mis-join on (name, id).** `indexRequirements` (`query.go:397-411`) and `filterResultsToMatches` (`aggregate.go:173-194`) key requirements by `requirementKey(baselineName, id)`. Requirement IDs repeat within one baseline today (grype emits one requirement per package instance: `Grype/CVE-2022-48174` twice in the demo fixture), so full-verbosity and `fields[]` rows can carry another requirement's tags, descriptions and correlation keys.

Provenance has no per-baseline home. `tool` and `generator` are document-root singletons; `Evaluated_Baseline` has neither, and both objects are `unevaluatedProperties: false`. A merged document therefore says one `tool` for every scanner's rows unless a convention is chosen. `baselines[].labels` (`map[string]string`, well-known keys `system, component, environment, region, team`) and `baselines[].extensions` are the schema-legal carriers. No read tool surfaces root `tool`/`generator` today either (`inspect.go:367-368` projects only `{id, systemRef, planRef}`).

Finally, the project has already recorded where cross-document analysis is going. ADR-0007 puts cross-document query out of v1 scope; ADR-0012 (unmerged) states the case — "Everything is file-shaped. Five needs now exist that files cannot serve: 1. Cross-document questions … These are joins over stored data" — and answers with a PostgreSQL 3NF store, a data-access layer, `hdf-serve`, and `hdf_precedent`/`hdf_similar`. External practice agrees: every multi-scanner aggregator (DefectDojo, Dependency-Track, OCSF/Security Lake) ends with one normalized finding row per (tool, finding) in a store, treating the many-runs document (SARIF `runs[]`, HDF `baselines[]`) as interchange. This ADR must therefore be explicit that the merged document is the **interchange artifact** the store will import, not a query engine.

## Decision

### 1. `Merge` is an hdf-engine operation, Go + TS, parity in the same PR

`hdf-engine` gains `Merge(sources []MergeSource) (hdf.HDFResults, []MergeWarning, error)` (Go) and `merge(sources): {results, warnings}` (TS) — no options parameter, see the Revision bullet with identical semantics and a cross-language parity test on shared real fixtures (the loader/detect parity pattern). It is the single implementation consumed by the CLI (`hdf merge`) and by `hdf_aggregate`'s totals (§7: no MCP merge tool). Per ADR-0007 §Quality Standards, merge logic inside `hdf-cli/internal/mcp` or `hdf-cli/cmd` is a defect.

`MergeSource` is `{Name string; Doc hdf.HDFResults}` where `Name` is the source's basename (or a caller-supplied label) and is recorded, never used as a key. Inputs are results documents only; a baseline (non-results) document is rejected with an error naming its index and type (the wrap alternative is rejected in §Owner decisions 2).

### 2. Baseline naming: `<tool>/<original name>`

Every merged baseline is renamed `<tool>/<original name>`, where `<tool>` is, in order: the source document's root `tool.name` lower-cased and whitespace-trimmed; else `generator.name`; else `doc<N>` (N = 0-based source index). The original name is preserved verbatim after the slash.

Rationale: baseline **name is the key** everywhere — engine `Filter`'s `Baseline` glob, `groupBy=baseline`, `requirementKey`, `hdf diff`'s pairing, `--group-by`, amendment `baselineRef`. Prefixing is the only way to keep two scanners' same-named baselines distinct through every existing consumer without changing any of them, and it also disambiguates the shipped one-name-many-baselines converters (the 16 Prisma baselines become `prisma cloud/Prisma Cloud Scan` … still colliding *with each other* — see §6, which is why the index change is also required).

If two merged baselines would still collide after prefixing, `Merge` emits a `MergeWarning{Kind: "duplicate-baseline-name", Indices: [i, j], Name}` and keeps both. It never renames beyond the rule and never drops a baseline.

### 3. Per-baseline provenance lives in `baselines[].labels`

`Merge` writes three labels on every merged baseline:

| key | value | when |
|---|---|---|
| `tool` | the `<tool>` value of §2 | always |
| `toolVersion` | root `tool.version` of the source | when present |
| `sourceDocument` | `MergeSource.Name` | always |

Existing labels are preserved. A pre-existing `tool`/`toolVersion`/`sourceDocument` label is overwritten and a `MergeWarning{Kind: "label-overwritten"}` is emitted. `labels` is chosen over `extensions` because it is typed (`map[string]string`), already the grouping carrier Heimdall and `hdf diff --group-by` use, and is exactly what `hdf_compliance groupBy=tool` (§7) reads. These three keys are added to the well-known keys reference (`site/docs/guides/label-keys-reference.md`) in card `.3` (§Owner decisions 1).

Note the known gap this does not fix: `hdf label set` and `hdf_convert --labels` write component labels only (`hdf-cli/internal/hdfdoc/hdfdoc.go:30-33`); baseline labels are written by `Merge` itself. A follow-on could extend `hdf label set` to baselines; out of scope here.

### 4. The merged root

| field | value |
|---|---|
| `generator` | `{name: "hdf-merge", version: hdfengine.Version()}` — the engine version (`hdf-engine/go/engine.go`, lock-stepped with `package.json`), so the value is deterministic per library build and identical across Go and TS |
| `tool` | omitted — there is no single tool |
| `timestamp` | the latest input `timestamp` (deterministic); omitted if no input has one |
| `baselines` | every input's baselines, input order preserved, renamed per §2, labelled per §3 |
| `components` | union, keyed by `componentId`; entries without a `componentId` are all kept, in order |
| `extensions["hdf-merge"]` | `{version: <engine version>, sources: [{index, name, tool, generator, timestamp, runner}]}` — each input's root provenance verbatim, so nothing an input said about itself is lost |
| `runner`, `statistics`, `integrity`, `id`, `systemRef`, `planRef`, `derivation`, `remediation`, `externalReferences`, `preAmendmentChecksum` | omitted — each is a per-run or per-document fact that has no defined meaning for a union; the per-source values survive under `extensions["hdf-merge"].sources[]` |

Output is byte-reproducible for the same inputs in the same order (stable key order, canonical trimmed-UTC timestamps — the ADR-0007 determinism rule). Reordering inputs changes baseline order and `doc<N>` fallbacks and is therefore a different document by design.

### 5. Union semantics — no deduplication in v1

Requirements are appended as they are. Nothing is deduplicated, re-keyed, re-scored, or dropped. Two scanners reporting the same CVE on the same package produce two requirements, attributable by baseline. Cross-tool dedup is a real need with an established design space (DefectDojo's per-parser hash keys with an always-on `service` field; Dependency-Track's per-component correlation) and is **future work with its own ADR**; deciding it here would couple a mechanical operation to a policy question.

### 6. The engine `Match` gains indices; read tools key on indices, never names

`hdfengine.Match` gains `BaselineIndex int` and `Index int` (position within the baseline), populated by `Filter`, in Go and TS with parity. `partitionResults` (baseline mode), `indexRequirements`, and `filterResultsToMatches` key on `(BaselineIndex, Index)`; `groupRollup` gains an additive `baselineIndex` field so same-named groups are distinct rows. This is the fix for Context defects 1 and 2 and is correct independently of merging — it is carded as a P1 bug (`.2`) with no dependency on this ADR's acceptance, but the design is recorded here so that the merge and the fix share one rule: **a document is the input; read tools are correct on it as given** and never rename or dedupe at read time.

### 7. MCP reflection (per ADR-0007 §Known constraints: a per-change decision)

- **`hdf_merge` is NOT reflected into the MCP.** *(Owner decision at card `.5`, 2026-09-16, reversing the first draft.)* ADR-0007 §12's default holds: merge is a deterministic pipeline operation with no model judgment, exactly like `hdf enrich` and `hdf events`, which were kept out of the tool surface for that reason. The merged document is produced by `hdf merge` where the scans are produced — in the pipeline — and lands under `HDF_MCP_ROOT`, where every read tool already operates on it by `{path}`. Reflecting it was measured and rejected: an advertised tool costs its schema (534 tokens) on **every** agent turn of every default deployment whether or not a merge ever happens, the eleventh tool pushes the full `tools/list` past its 5,200-token budget (5,639), and with writes off by default the tool would mostly mint cache-only handles. The one capability given up — an agent handed N unmerged documents merging them itself — has no user story today; `hdf_aggregate` already answers the counts case across N documents. Revisit with a concrete agent-driven use case (the benchmark's ad-hoc arm would be the natural one); the engine `Merge` makes the tool a day's work when that day comes. The first draft's `hdf_merge` contract and its "handle without output" discussion are superseded by this bullet.
- **`hdf_aggregate` computes its totals through engine `Merge`** and deletes its private concatenation. Its contract (counts only, never rows) is unchanged.
- **`hdf_compliance groupBy` gains `tool` and `cwe`** (`.7`): `tool` groups by `baselines[].labels.tool` with `unlabeled` fallback; `cwe` by each `tags.cwe` value with `unmapped` fallback (multi-membership, the `nistFamily` pattern). Additive enum values (ADR-0007 §17). Grouping is added here and **not** to `hdf_aggregate`: the merged document plus one grouping surface is the design; a second grouping surface would recreate the overlapping-tools problem ADR-0007 §Tool surface warns about.
- **`hdf_inspect` surfaces provenance** (`.6`): results `metadata` gains `tool {name, version, format}` (each field only when present — `format` is the schema's third `Tool` field, the named source format a converter records, e.g. `SARIF`; an empty tool object projects to no key) and `generator {name, version}` when present; each baseline entry gains `labels` when non-empty. Absent values are omitted, never synthesized (the `statistics` rule at `inspect.go:160-165`).
- **`hdf_query`, `hdf_diff`, `hdf_validate`, `hdf_open`:** unchanged; they already operate on multi-baseline documents.

### 8. Relationship to ADR-0012

The merged document is the **interchange artifact** the ADR-0012 store imports (`hdf db import` of one file per system-scan instead of N), and the tool surface above is what the store will sit behind. It is **not** a query engine: it is a snapshot with no index, re-merged on every change, bounded by one document-size budget (`HDF_MCP_MAX_SIZE`, default 50 MB; engine `Load` validates size first). When ADR-0012 lands, `hdf merge` remains the way to produce the artifact and `hdf_aggregate`/`hdf_compliance` remain correct on it; anything row-returning across documents (joins on `affectedPackages`/purl, precedent, similarity) is the store's. If ADR-0012 merges mid-epic, the epic stops and reconciles rather than shipping two aggregation stories.

## Alternatives Considered

### A — Merge at read time inside `hdf_aggregate` (persist nothing)
- **Pros:** no new tool, no file.
- **Cons:** the merged view is un-addressable — no handle, so `hdf_query`/`hdf_compliance` cannot be pointed at it; every cross-tool question re-merges N documents; and the logic already lives in `internal/mcp`, which ADR-0007 §Quality Standards names a defect.
- **Why rejected:** cannot serve the one-call-on-one-document goal, and cements the adapter-owns-logic drift.

### B — A new document type (`hdf-portfolio` / `hdf-evidence-portfolio`)
- **Pros:** explicit multi-document semantics; a home for dedup policy and cross-references.
- **Cons:** a ninth schema, new validators in two languages, new `hdf_inspect`/`hdf_validate` branches, and every existing read tool would need to learn it; ADR-0007 §Scope puts "any change to the eight schemas" out of scope, and `hdf-libs-vqic` records this exact question as open and undesigned.
- **Why rejected (for now):** the existing results schema already sanctions one baseline per tool; a new type buys nothing the read surface needs today. Revisit with `vqic` if dedup or cross-references need a typed home.

### C — Skip the merge; wait for the ADR-0012 store
- **Pros:** one aggregation story.
- **Cons:** the store is on an unmerged branch with no delivery date; the benchmark's cross-tool questions and every pipeline user need the capability now; and the store needs an import artifact anyway.
- **Why rejected:** the merge is the store's input, not its competitor (§8).

### D — Deduplicate across tools in v1
- **Why rejected:** policy, not mechanics — §5. Would silently change compliance numbers depending on a hash-key choice no one has reviewed.

### E — Disambiguate colliding baseline names at read time (suffix `#i` inside the read tools)
- **Why rejected:** read tools would then report names that are not in the document; `hdf diff`, amendments `baselineRef`, and any external consumer would disagree with the MCP. Fix the key (§6), not the name.

### F — Store provenance in `baselines[].extensions` rather than `labels`
- **Why rejected:** `extensions` is untyped and unbounded; `labels` is typed, already the grouping carrier, and is what `groupBy=tool` reads. `extensions["hdf-merge"]` is used only at the root, for the verbatim per-source metadata that has no typed home.

## Consequences

- **Exporters that assume one tool per document will mislabel a merged document:** `hdf-to-xccdf` names the benchmark after `Baselines[0]`; the ECS/Splunk export map hoists root `tool` once and stamps it on every event (`hdf-converters/shared/go/exportmap/exportmap.go:392`); `hdf events apply` appends to the first baseline (it warns). These are carded under `hdf-libs-5gri` when the merge lands; until then a merged document should not be exported to those formats, and `hdf merge` says so in its help text.
- **Baseline-name uniqueness remains unenforced.** Enforcing "must be unique" in validators is a schema-governance decision (it would reject shipped converter output) and is not taken here; §6 makes the read surface correct under collision instead.
- **`hdf label set` cannot write baseline labels;** `Merge` writes them itself. Extending `hdf label set` is a small follow-on.
- **Size:** a merged STIG-plus-scanners document can approach the input ceiling; `Load` validates size first and `hdf merge` fails loudly. The store (ADR-0012) is the answer past that point.
- **Token budget:** no new tool joins `tools/list` (§7 — an eleventh tool would have pushed it to 5,639 against the 5,200 budget). `hdf_compliance` sits at 580 tokens and gains two enum words in card `.7` — measured there, with the description shortened rather than the ceiling raised if it exceeds.
- **The benchmark** (hdf-mcp-demo) gains a merged-document question (`.8`); results on it are not comparable to pre-merge runs (the ablation plan applies).

## Implementation Plan

Cards under `hdf-libs-js1nv`, in dependency order:

1. `.1` this ADR — owner acceptance gates everything below except `.2`.
2. `.2` (P1 bug, independent) engine `Match` indices + index-keyed read tools.
3. `.3` engine `Merge`, Go + TS + parity, real fixtures.
4. `.4` `hdf merge` CLI; `.5` `hdf_aggregate` computes its totals through engine `Merge` (rescoped — no MCP tool, see §7); `.6` `hdf_inspect` provenance.
5. `.7` `groupBy tool | cwe`; `.8` benchmark question (hdf-mcp-demo, needs `.4`).

Quality standards are ADR-0007's: framework-first, no new logic in `internal/mcp`, token bounding as an AC, real fixtures only, >90% coverage, `pnpm check` and `golangci-lint` clean, determinism asserted.

## Owner decisions (2026-09-16)

Accepted as drafted, with the three open questions settled:

1. **Well-known label keys.** `tool`, `toolVersion`, `sourceDocument` are added to `site/docs/guides/label-keys-reference.md` in card `.3`, alongside the code that writes them — `hdf_compliance groupBy=tool` reads `tool`, so it is a contract either way.
2. **Non-results inputs.** A `baseline` document among the inputs is **rejected** with an error naming its index and detected type. Wrapping it as all-`notReviewed` would fabricate a status for every requirement and move the compliance denominator (the ADR-0006 §3 no-fabrication rule).
3. **`generator.version`.** The **engine version** (`hdfengine.Version()`), for determinism per library build and Go/TS identity. Owner's corollary, recorded as a follow-on outside this epic: converters currently stamp `generator.version` from a build-time value (`"dev"` in every committed expected fixture), and should adopt the same library-version rule for the same reasons — carded separately.
