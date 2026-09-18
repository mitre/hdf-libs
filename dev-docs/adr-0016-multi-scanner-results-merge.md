# ADR-0016: Multi-source reads across scanner results — an in-memory Merge, one baseline per tool, provenance, determinism, and the bridge to ADR-0012

- **Status:** Accepted — owner review 2026-09-16 (see §Owner decisions); **redirected 2026-09-17** (see §Owner decisions 2026-09-17 and Alternative G); implementation in progress
- **Date:** 2026-09-16
- **Deciders:** Will Dower
- **Revision:** 2026-09-16 — incorporated the owner review: the three open questions (well-known label keys, non-results inputs, `generator.version`) are settled in §Owner decisions and the corollary for converter `generator.version` is carded separately (`hdf-libs-v8xd9`); Status moved from Proposed to Accepted.
- **Revision:** 2026-09-16 (implementation, card `.3`) — the engine signature is `Merge(sources []MergeSource)` / `merge(sources)`: the `opts` parameter written in §1 had no v1 meaning (every rule is fixed by this ADR), and an empty options struct would be a placeholder, not a design; an option is added when a decision needs one. Provenance label keys are documented in `site/docs/guides/label-keys-reference.md` §Merge Provenance Keys. Warnings are typed (`duplicate-baseline-name`, `label-overwritten`) and a stale `toolVersion` label on a re-merged baseline is removed (with a warning) rather than kept, since it would describe the wrong tool. Two clarifications from the card `.3` review: (a) the engine API is typed on `hdf.HDFResults`, so the §1 rejection of a non-results input necessarily lives in the callers that load documents — the MCP loader — not in `Merge` itself; (b) "verbatim" provenance is verbatim in value, not bytes: Go re-serializes each source `timestamp` through `time.Time` (RFC 3339 nano, trailing zeros trimmed) while TS carries the string through, so a `...:11.000Z` input reads `...:11Z` from Go. Parity is asserted on names, labels, counts and root values; byte-identical output across the two languages is not a goal (determinism is per language).
- **Revision:** 2026-09-17 (redirection, card `.9`) — **the merged document is no longer an artifact; there is no `hdf merge` CLI command.** The first draft's premise — that the MCP could not correlate across scanners until the data was one document — was wrong: `hdf_aggregate` already loads N sources and merges them in memory on every call. The real gap was narrower and is stated correctly in §Context now: `hdf_query` and `hdf_compliance` take one `source` *by interface*. The fix that follows is `sources[]` on those tools over the same in-memory `Merge` (card `.10`), not a file. A persisted merged document was also found to be actively harmful to gating (Alternative G). Engine `Merge`, the `<tool>/<original>` naming, the provenance labels, the `Match` indices and `hdf_inspect`'s provenance are unchanged: they are what multi-source reads run on. The CLI command built on this branch (card `.4`, commit 69799f2c) is reverted before release.
- **Branch:** `feat/multi-scanner-merge`
- **Epic/cards:** `hdf-libs-js1nv` (this ADR is card `.1`; implementation is `.2`–`.11`; `.4` withdrawn by `.9`)
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

The fourth row is a capability `hdf_aggregate` cannot provide at any cost. Nothing new in the read path was needed — only a multi-baseline *view* of the three documents.

**What is missing is the interface, not the data.** The first draft of this ADR read the measurement above as "the MCP needs one document" and designed a persisted merge. That was the human habit of thinking of a data set as one big file, not a property of the server: `hdf_aggregate` already builds exactly this multi-baseline view in memory on every call (`hdf-cli/internal/mcp/tools/aggregate.go`) and discards it. The server can load N documents from wherever they are — files today, a store later — and correlate across them; what it cannot do is *accept* N documents on the two tools that return rows and groupings, because their `source` field is singular. The gap is therefore closed by `sources[]` on `hdf_query` and `hdf_compliance` over one shared in-memory operation (§1, §7), and by nothing on disk (Alternative G).

Two defects surface the moment a document carries several baselines, and both already bite shipped converter output:

1. **Same-named baselines silently collapse.** `partitionResults` (`compliance.go:236-242`) keys `groupBy=baseline` partitions by `b.Name`, last write wins. Verified: two same-named baselines carrying 99 requirements → ungrouped `hdf_compliance` reports 99, `groupBy=baseline` reports **one group of 10**. No error. The specification's field table describes `name` as "Unique baseline name" (and the generated Go type's comment says "must be unique"); nothing enforces it, and the shipped Prisma fixture has 16 baselines under one name (Nessus 3/1, Conveyor 4/1).
2. **Rows mis-join on (name, id).** `indexRequirements` (`query.go:397-411`) and `filterResultsToMatches` (`aggregate.go:173-194`) key requirements by `requirementKey(baselineName, id)`. Requirement IDs repeat within one baseline today (grype emits one requirement per package instance: `Grype/CVE-2022-48174` twice in the demo fixture), so full-verbosity and `fields[]` rows can carry another requirement's tags, descriptions and correlation keys.

Provenance has no per-baseline home. `tool` and `generator` are document-root singletons; `Evaluated_Baseline` has neither, and both objects are `unevaluatedProperties: false`. A multi-source view therefore says one `tool` for every scanner's rows unless a convention is chosen. `baselines[].labels` (`map[string]string`, well-known keys `system, component, environment, region, team`) and `baselines[].extensions` are the schema-legal carriers. No read tool surfaced root `tool`/`generator` either before card `.6` (`inspect.go:367-368` projected only `{id, systemRef, planRef}`).

Finally, the project has already recorded where cross-document analysis is going. ADR-0007 puts cross-document query out of v1 scope; ADR-0012 (unmerged) states the case — "Everything is file-shaped. Five needs now exist that files cannot serve: 1. Cross-document questions … These are joins over stored data" — and answers with a PostgreSQL 3NF store, a data-access layer, `hdf-serve`, and `hdf_precedent`/`hdf_similar`. External practice agrees: every multi-scanner aggregator (DefectDojo, Dependency-Track, OCSF/Security Lake) ends with one normalized finding row per (tool, finding) in a store. This ADR is therefore explicit that the multi-source view is a **per-call read** over whatever the sources are — not a query engine and not an artifact the store imports (§8).

## Decision

### 1. `Merge` is an hdf-engine operation, Go + TS, parity in the same PR — consumed in memory

`hdf-engine` gains `Merge(sources []MergeSource) (hdf.HDFResults, []MergeWarning, error)` (Go) and `merge(sources): {results, warnings}` (TS) — no options parameter, see the Revision bullet — with identical semantics and a cross-language parity test on shared real fixtures (the loader/detect parity pattern). It is the single definition of "these documents combined", and it is consumed **in memory only**: by `hdf_aggregate`'s totals today and by `hdf_query`/`hdf_compliance` over `sources[]` (§7). No CLI command and no MCP tool persists or returns its output (§7, Alternative G). Per ADR-0007 §Quality Standards, merge logic inside `hdf-cli/internal/mcp` or `hdf-cli/cmd` is a defect.

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

Existing labels are preserved. A pre-existing `tool`/`toolVersion`/`sourceDocument` label is overwritten and a `MergeWarning{Kind: "label-overwritten"}` is emitted. `labels` is chosen over `extensions` because it is typed (`map[string]string`), already the grouping carrier Heimdall and `hdf diff --group-by` use, and is exactly what `hdf_compliance groupBy=tool` (§7) reads. These three keys are in the well-known keys reference (`site/docs/guides/label-keys-reference.md`) since card `.3` (§Owner decisions 1).

Note the known gap this does not fix: `hdf label set` and `hdf_convert --labels` write component labels only (`hdf-cli/internal/hdfdoc/hdfdoc.go:30-33`); baseline labels are written by `Merge` itself. A follow-on could extend `hdf label set` to baselines; out of scope here.

### 4. The merged view's root

The view `Merge` returns is a complete, schema-valid `hdf-results` value — it must be, because every read tool and the engine's `Filter` run on it unchanged — and its root is fixed so the view is deterministic per library build:

| field | value |
|---|---|
| `generator` | `{name: "hdf-merge", version: hdfengine.Version()}` — the engine version (`hdf-engine/go/engine.go`, lock-stepped with `package.json`), so the value is deterministic per library build and identical across Go and TS |
| `tool` | omitted — there is no single tool |
| `timestamp` | the latest input `timestamp` (deterministic); omitted if no input has one |
| `baselines` | every input's baselines, input order preserved, renamed per §2, labelled per §3 |
| `components` | union, keyed by `componentId`; entries without a `componentId` are all kept, in order |
| `extensions["hdf-merge"]` | `{version: <engine version>, sources: [{index, name, tool, generator, timestamp, runner}]}` — each input's root provenance verbatim, so nothing an input said about itself is lost |
| `runner`, `statistics`, `integrity`, `id`, `systemRef`, `planRef`, `derivation`, `remediation`, `externalReferences`, `preAmendmentChecksum` | omitted — each is a per-run or per-document fact that has no defined meaning for a union; the per-source values survive under `extensions["hdf-merge"].sources[]` |

Output is reproducible for the same inputs in the same order (stable key order, canonical trimmed-UTC timestamps — the ADR-0007 determinism rule). Reordering inputs changes baseline order and `doc<N>` fallbacks and is therefore a different view by design. Nothing in this project serializes the view to a file; the root shape matters because a caller of the engine API may, and because a re-merge of such a document must behave (the `hdf-merge` tool fallback and the `label-overwritten` warning cover it).

### 5. Union semantics — no deduplication in v1

Requirements are appended as they are. Nothing is deduplicated, re-keyed, re-scored, or dropped. Two scanners reporting the same CVE on the same package produce two requirements, attributable by baseline. Cross-tool dedup is a real need with an established design space (DefectDojo's per-parser hash keys with an always-on `service` field; Dependency-Track's per-component correlation) and is **future work with its own ADR**; deciding it here would couple a mechanical operation to a policy question.

### 6. The engine `Match` gains indices; read tools key on indices, never names

`hdfengine.Match` gains `BaselineIndex int` and `Index int` (position within the baseline), populated by `Filter`, in Go and TS with parity. `partitionResults` (baseline mode), `indexRequirements`, and `filterResultsToMatches` key on `(BaselineIndex, Index)`; `groupRollup` gains an additive `baselineIndex` field so same-named groups are distinct rows. This is the fix for Context defects 1 and 2 and is correct independently of merging — it is carded as a P1 bug (`.2`) with no dependency on this ADR's acceptance, but the design is recorded here so that the merge and the fix share one rule: **a document is the input; read tools are correct on it as given** and never rename or dedupe at read time.

### 7. No merge artifact — the read tools accept `sources[]`

- **There is no `hdf merge` CLI command and no `hdf_merge` MCP tool.** *(Owner decisions 2026-09-16 at card `.5` — no MCP tool — and 2026-09-17 at card `.9` — no CLI command; the latter reverses card `.4`.)* The first draft reflected ADR-0007 §12's deterministic-operation rule by making the merge a pipeline command whose output lands under `HDF_MCP_ROOT`. Alternative G records why that output is not wanted. The MCP-tool measurement stands and still argues against a tool: an advertised tool costs its schema (534 tokens) on **every** agent turn whether or not a merge ever happens, and an eleventh tool pushes `tools/list` past its 5,200-token budget (5,639).
- **`hdf_query` and `hdf_compliance` accept `sources[]`** (`.10`): a set of results documents (paths or handles), loaded and combined through engine `Merge` per call, exactly as `hdf_aggregate` does. Exactly one of `source` / `sources` is given; a one-element `sources` behaves as `source`. Rows carry the `<tool>/<original>` baseline name so a cross-tool question is one call over N files; `groupBy=baseline` returns one group per input baseline with its `baselineIndex`; a `threshold` applies over the view as it would over one document — a threshold *intended* for combined data is legitimate even though thresholds are used per tool today (owner, 2026-09-17), so the view is neither refused nor special-cased. Single-source calls are unchanged in shape; multi-source responses carry `sources: [{index, source}]` in place of `handle` — `source` is the path the caller passed, else the path its handle carries, else `sources[i]`. No per-member `handle` and no per-member `docType` (owner, 2026-09-17, on the token budget): a handle cost ~230 bytes per member on every response for something the caller already holds — measured on the benchmark's three-scanner set, the oracle responses were ~300 o200k tokens heavier per call than a single-document response — and a caller that wants one opens the member; the type never varies, and the envelope's `docType` says so once. `source` is no longer a schema-required property on the two tools, since exactly-one-of cannot be expressed to the schema reflector; the handler enforces it. The load-and-merge path is one shared helper for all three tools.
- **`hdf_aggregate` computes its totals through engine `Merge`** (`.5`) and deletes its private concatenation. Its contract (counts only, never rows) is unchanged. Once `hdf_compliance sources[] groupBy=baseline` exists it returns `hdf_aggregate`'s per-source counts and more; whether `hdf_aggregate` is then retired is an owner decision recorded at `.10`, not taken here.
- **`hdf_compliance groupBy` gains `tool` and `cwe`** (`.7`): `tool` groups by `baselines[].labels.tool` with `unlabeled` fallback; `cwe` by each value of the requirement's first-class `cwe[]` field — the schema's normalized correlation key, the one `hdf_query fields:[cwe]` reads, so the two tools agree about every row — normalized to its number, with `unmapped` fallback (multi-membership, the `nistFamily` pattern). *(Corrected 2026-09-17 from "`tags.cwe`": the field is `cwe[]`. Consequence found in review: the SARIF converter writes CWEs only to `tags.cwe` and never populates `cwe[]`, so SARIF-derived documents group as `unmapped` — a converter defect, carded separately, not a reason for the read tools to consult two fields.)* Additive enum values (ADR-0007 §17). Grouping is added here and **not** to `hdf_aggregate`: one multi-source view plus one grouping surface is the design; a second grouping surface would recreate the overlapping-tools problem ADR-0007 §Tool surface warns about.
- **`hdf_inspect` surfaces provenance** (`.6`): results `metadata` gains `tool {name, version, format}` (each field only when present — `format` is the schema's third `Tool` field, the named source format a converter records, e.g. `SARIF`; an empty tool object projects to no key) and `generator {name, version}` when present; each baseline entry gains `labels` when non-empty. Absent values are omitted, never synthesized (the `statistics` rule at `inspect.go:160-165`).
- **`hdf_diff`, `hdf_validate`, `hdf_open`:** unchanged; they already operate on multi-baseline documents.

### 8. Relationship to ADR-0012

`sources[]` is the seam the ADR-0012 store plugs into: today a source is `{path}` or `{handle}` under `HDF_MCP_ROOT`; with the store it is a stored document, and the view is built the same way. Nothing is imported "pre-merged" — the store ingests each scanner's document as produced, which is also what gating and amendments need (Alternative G). The in-memory view is **not** a query engine: it is rebuilt per call, has no index, and is bounded by N × the document-size budget (`HDF_MCP_MAX_SIZE`, default 50 MB; engine `Load` validates size first). Anything row-returning across documents that the view cannot answer by filtering and grouping (joins on `affectedPackages`/purl, precedent, similarity) is the store's. If ADR-0012 merges mid-epic, the epic stops and reconciles rather than shipping two aggregation stories.

## Alternatives Considered

### A — Merge at read time (persist nothing) — **adopted 2026-09-17**
- **Pros:** no new tool, no file, one definition of "combined" that every read tool shares.
- **Cons as first written:** the merged view is un-addressable (no handle, so `hdf_query`/`hdf_compliance` cannot be pointed at it); every cross-tool question re-merges N documents; and the logic lived in `internal/mcp`.
- **Why the cons do not hold:** `sources[]` *is* the address — the caller names the set, and the response names each member's handle; a per-call merge of the benchmark's three documents is milliseconds against a model turn measured in seconds, and is bounded by the same size budget as any load; and the logic is the engine's (§1), so `internal/mcp` holds none. The first draft rejected this alternative for the "one call on one document" goal; the goal was mis-stated — the goal is one call, and the call can take N documents.

### B — A new document type (`hdf-portfolio` / `hdf-evidence-portfolio`)
- **Pros:** explicit multi-document semantics; a home for dedup policy and cross-references.
- **Cons:** a ninth schema, new validators in two languages, new `hdf_inspect`/`hdf_validate` branches, and every existing read tool would need to learn it; ADR-0007 §Scope puts "any change to the eight schemas" out of scope, and `hdf-libs-vqic` records this exact question as open and undesigned.
- **Why rejected (for now):** the existing results schema already sanctions one baseline per tool; a new type buys nothing the read surface needs today. Revisit with `vqic` if dedup or cross-references need a typed home.

### C — Skip the merge; wait for the ADR-0012 store
- **Pros:** one aggregation story.
- **Cons:** the store is on an unmerged branch with no delivery date; the benchmark's cross-tool questions and every pipeline user need the capability now.
- **Why rejected:** the in-memory view is a few hundred lines in an engine that already exists and is the shape the store will serve later (§8); waiting buys nothing.

### D — Deduplicate across tools in v1
- **Why rejected:** policy, not mechanics — §5. Would silently change compliance numbers depending on a hash-key choice no one has reviewed.

### E — Disambiguate colliding baseline names at read time (suffix `#i` inside the read tools)
- **Why rejected:** read tools would then report names that are not in the document; `hdf diff`, amendments `baselineRef`, and any external consumer would disagree with the MCP. Fix the key (§6), not the name.

### F — Store provenance in `baselines[].extensions` rather than `labels`
- **Why rejected:** `extensions` is untyped and unbounded; `labels` is typed, already the grouping carrier, and is what `groupBy=tool` reads. `extensions["hdf-merge"]` is used only at the root, for the verbatim per-source metadata that has no typed home.

### G — Persist the merged document (`hdf merge <results>... -o <out>`) — **the first draft's decision, withdrawn 2026-09-17**
- **What it was:** a CLI command writing the §4 view to a file as a pipeline step, so the MCP would read "one document"; built as card `.4` (commit 69799f2c) and reverted by card `.9`.
- **Why withdrawn:**
  1. **It damages gating.** A `hdf validate` threshold is a verdict over one document's counts. A pipeline that must fail when *grype specifically* reports any failure writes a zero-failures threshold against grype's document; against a merged file the same threshold fails on ZAP's findings too, and there is no way to say "grype's baselines only". Every per-tool gate in use today is expressed per document, and a merged artifact cannot express any of them. (A threshold *intended* for combined data remains legitimate — it is simply written against the `sources[]` view, §7 — so this is a reason not to persist, not a ban on combined thresholds.)
  2. **It re-namespaces requirement ids.** Amendments key on requirement ids within a document; ids that were unambiguous per tool become one shared namespace in which `hdf amend` and `hdf diff` must be told which tool's `Grype/CVE-…` is meant.
  3. **The MCP never needed it.** `hdf_aggregate` proved the server merges N documents per call; the two tools that could not were limited by a singular `source` field, one line each.
  4. **It is a second artifact with one consumer.** Every pipeline would carry both the per-tool documents (for gating, amendment, export and the store) and the merged one (for the MCP), and keep them consistent.
- **What survives:** the engine operation, naming, labels and root shape it wrote (§1–§5) — as the definition of the in-memory view.

## Consequences

- **Exporters that assume one tool per document will mislabel a multi-tool document:** `hdf-to-xccdf` names the benchmark after `Baselines[0]`; the ECS/Splunk export map hoists root `tool` once and stamps it on every event (`hdf-converters/shared/go/exportmap/exportmap.go:392`); `hdf events apply` appends to the first baseline (it warns). No CLI path produces such a document any more, but multi-baseline converter output (Prisma, Nessus, ZAP per site) already has the same property; carded under `hdf-libs-5gri`.
- **Baseline-name uniqueness remains unenforced.** Enforcing "must be unique" in validators is a schema-governance decision (it would reject shipped converter output) and is not taken here; §6 makes the read surface correct under collision instead.
- **`hdf label set` cannot write baseline labels;** `Merge` writes them itself on the view. Extending `hdf label set` is a small follow-on.
- **Size and cost:** a multi-source call loads N documents, each within `HDF_MCP_MAX_SIZE`; the view is bounded by their sum and rebuilt per call. Measured 2026-09-17 on nine real converter outputs (InSpec ×4, grype, CycloneDX, NeuVector, ZAP, gosec — 12.5 MB, 12 baselines, 2,083 requirements): first call 228 ms (parse + schema-validate all nine, then resident in the loader's content-hash LRU, 29 MB parsed ≈ 2.3× the JSON); warm calls 9.6 ms, of which `Merge` is 18 µs (it appends baseline structs whose requirement slices are shared — O(baselines + components), not O(requirements)) and the rest is re-reading and hashing the members' bytes (~0.75 ms/MB, the one cost that scales with the set); a full warm `hdf_query` over the set is 11 ms against 2.5 ms for the largest single document, and 34 ms for 27 documents / 37 MB. Nothing of the view is retained between calls. Parse cost is paid once per document until LRU eviction (`HDF_MCP_CACHE_BYTES`, default 256 MB ≈ 110 MB of scanner JSON), so a set larger than the cache re-parses on every call — that, not merging, is the bound. Response size is bounded as today by `limit`/`page`. The store (ADR-0012) is the answer when N stops being small.
- **Token budget:** no new tool joins `tools/list` (§7). `sources[]` adds one field to `hdf_query` and `hdf_compliance`, measured in card `.10` against the 600-per-tool and 5,200-total budgets; `hdf_compliance` gains two `groupBy` enum words in `.7`, measured there.
- **The benchmark** (hdf-mcp-demo) carries three `multi-*` questions answered by one `hdf_query{sources:[…]}` call over the three converted documents (`.11`, revising `.8`'s merged-file version); results on them are not comparable to pre-epic runs (the ablation plan applies).

## Implementation Plan

Cards under `hdf-libs-js1nv`, in dependency order:

1. `.1` this ADR — owner acceptance gates everything below except `.2`.
2. `.2` (P1 bug, independent) engine `Match` indices + index-keyed read tools.
3. `.3` engine `Merge`, Go + TS + parity, real fixtures.
4. `.5` `hdf_aggregate` computes its totals through engine `Merge`; `.6` `hdf_inspect` provenance. (`.4`, the `hdf merge` CLI, was built and withdrawn — `.9`, Alternative G; `.8`, the benchmark's merged-file questions, is superseded by `.11`.)
5. `.9` withdraw the CLI and rewrite this ADR; `.10` `sources[]` on `hdf_query`/`hdf_compliance`; then `.7` `groupBy tool | cwe` and `.11` the benchmark's multi-source questions (hdf-mcp-demo).

Quality standards are ADR-0007's: framework-first, no new logic in `internal/mcp`, token bounding as an AC, real fixtures only, >90% coverage, `pnpm check` and `golangci-lint` clean, determinism asserted.

## Owner decisions (2026-09-16)

Accepted as drafted, with the three open questions settled:

1. **Well-known label keys.** `tool`, `toolVersion`, `sourceDocument` are added to `site/docs/guides/label-keys-reference.md` in card `.3`, alongside the code that writes them — `hdf_compliance groupBy=tool` reads `tool`, so it is a contract either way.
2. **Non-results inputs.** A `baseline` document among the inputs is **rejected** with an error naming its index and detected type. Wrapping it as all-`notReviewed` would fabricate a status for every requirement and move the compliance denominator (the ADR-0006 §3 no-fabrication rule).
3. **`generator.version`.** The **engine version** (`hdfengine.Version()`), for determinism per library build and Go/TS identity. Owner's corollary, recorded as a follow-on outside this epic: converters currently stamp `generator.version` from a build-time value (`"dev"` in every committed expected fixture), and should adopt the same library-version rule for the same reasons — carded separately.

## Owner decisions (2026-09-17)

Redirection after review of the shipped `.4`–`.8`:

1. **No merged artifact.** The `hdf merge` CLI command is withdrawn (Alternative G); engine `Merge` stays as the in-memory operation. "What actually matters is that the MCP can load all the relevant HDF data from wherever it came from — one file, many files, maybe a DB at some point — and see patterns and do analysis between disparate baselines and tool types."
2. **`sources[]` on the read tools** (`.10`) is the mechanism; `groupBy tool | cwe` (`.7`) follows it.
3. **Thresholds over a multi-source view are not banned.** A threshold intended for combined data may be wanted later; the view accepts one like any document. The gating argument in Alternative G is about persisting, not about combining.
4. **Benchmark question IDs** become `multi-*` (`.11`).
