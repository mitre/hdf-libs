# ADR-0008: OpenAPI 3.1 Components and a Generated Reference API for HDF

**Status:** Proposed
**Date:** 2026-09-01 (revision 4, after three rounds of independent multi-lens design review)
**Deciders:** Aaron Lippold (author); Will Dower (maintainer review — see "Reviewer challenge points")

> **How to review (~25 min):** read "Reviewer challenge points" first — those are the decisions we want challenged. Then Context (measured forces) → Decision §1–§3 → Alternatives C and D. §4–§6 are packaging. The Implementation Plan is card-shaped input for the project-card skill; skim Scope, the prerequisite cards, and Phase 1a. Reply per challenge letter rather than per line. Cross-ADR links: §6 ↔ ADR-0009 §1 (packaging); Phase 4 ↔ ADR-0009 Phase 6 (count fixes); both "Delivery" lines.

## Context

HDF's **eight** document types (results, baseline, system, plan, amendments, evidence-package, comparison, requirement-change-event) are published as JSON Schema 2020-12 bundles (`hdf-schema/dist/schemas/`, tracked copy in `hdf-validators/go/schemas/`, hosted at `https://mitre.github.io/hdf-libs/schemas/`), with generated TS/Go/Python types. There is no OpenAPI artifact, so anyone building an HTTP service over HDF — an `hdf serve` mode of the CLI, Heimdall-class viewers, SAF pipeline services, partner tooling — hand-translates the schemas and hand-invents an API, and both drift.

The HDF MCP server (ADR-0007) already defines a typed operation surface: nine tools (`hdf_open`, `hdf_inspect`, `hdf_query`, `hdf_compliance`, `hdf_diff`, `hdf_validate`, `hdf_convert`, `hdf_author`, `hdf_apply_amendment`), five resource families (`hdf://schema/{docType}`, `hdf://schema/{docType}/{def}{?view}`, `hdf://enum/{name}`, `hdf://catalog/converters`, `hdf://session/transcript`), and a closed 12-code error taxonomy (`hdf-cli/internal/mcp/mcperr`). `tools/list` returns both `inputSchema` and `outputSchema` for every tool, and the repo already byte-compares that output against a tracked golden (`hdf-cli/internal/mcp/evalharness/testdata/tools-list.golden.json`).

Forces established by the reviews (counts re-measured against the tracked embed):

- **The bundles are compound documents, not drop-in components.** The bundler (`@hyperjump/json-schema`, `definitionNamingStrategy: 'uri'`) embeds each primitive resource as a URL-keyed `$defs` entry carrying its own `$id`/`$schema`. Across the eight bundles: 115 named definitions plus 19 URL-keyed resource wrappers; 408 absolute `$ref`s and 348 local pointers that resolve against the enclosing resource's `$id`; the `hdf-results` resource is itself embedded inside comparison and change-event. Source has 129 definitions, 14 (`target`/`platform` primitives) unreferenced and never bundled. Zero same-name/different-definition collisions today. OpenAPI component keys must match `^[a-zA-Z0-9.\-_]+$`, and pointer-based codegens resolve by JSON pointer, not `$id`.
- **2020-12 features in play**: 282 `unevaluatedProperties` sites in the bundles (77 in source), 7 `if`, 3 boolean-`false` subschemas (`Bom` else-branches), 1 `dependentRequired`, `contains`+`const`, `type: [string, null]` enums, `$ref` with sibling `description`, 74 `$comment`, `examples` on 45 definitions and 7 roots. No `$dynamicRef`/`$anchor`/`patternProperties`/`prefixItems`. All OpenAPI-3.1-legal; tool support is uneven and must be measured.
- **The MCP schemas are not a complete contract source.** Go SDK `jsonschema` tags become descriptions only — enums appear as prose (`"passed|failed|..."`, `"concise (default) or full"`, `"schema, checksums, or completeness"`), never `enum` arrays; the full row/summary shapes for query, diff, compliance, inspect, and convert-batch live in unexported Go types (some built as `map[string]any` per docType or per mode×verbosity) or in `hdf-engine`; MCP inputs are filesystem-shaped (`source.path`, `output`, `outputDir`, `overwrite`, `directory`, `dryRun`); MCP pagination is token-budgeted `page`/`nextPage`/`notice`/`truncated`; write tools are gated by `HDF_MCP_ENABLE_WRITES` and return a success-shaped `writesDisabled` preview. A generator must handle each of these explicitly or it is hand-authoring in disguise.
- **The repo's validators do not enforce `unevaluatedProperties`** (draft-07 engines in both languages), so "validates with hdf-validators" is weaker than "conforms to the schema text". Conformance tests here must use a 2020-12 engine; the validator gap is carded under ADR-0009 §5.
- The schema `$id` embeds the schema version (`v3.5.0`) while the package is `3.5.1`; patch releases leave `$id` unchanged. The OpenAPI artifacts need their own version axis.
- The CLI/MCP boundary already enforces input gates (50 MB caps, symlink/regular-file checks, XML entity checks that today only scan the first 4 KB for `<!ENTITY`, `SafePath`, per-tool timeouts, output redaction). An HTTP boundary is strictly more hostile and must carry equivalent gates in the contract.

## Decision

Create a new workspace package **`@mitre/hdf-openapi`** — a leaf package that derives from `@mitre/hdf-schema` and from the CLI's MCP contract; nothing in the repo imports it.

### 1. Components document (generated)
`dist/hdf-components.oas.json` + `.yaml`, OpenAPI 3.1, `jsonSchemaDialect: https://json-schema.org/draft/2020-12/schema`, produced by an explicit transform over the eight bundles read from the tracked embed (`hdf-validators/go/schemas/`) — never a glob of the gitignored `dist/`, and hard-failing if the file set differs from the bundler's `MAIN_SCHEMAS`. Steps: **unwrap** the 19 URL-keyed resource wrappers (they are not components); **hoist** every named `$defs` entry to `#/components/schemas/<Name>`; **rewrite** `$ref`s resource-scoped (a local pointer is resolved against its enclosing resource's `$id` before rewriting — never a global string replace); **strip** embedded `$id`/`$schema`; **deduplicate** by deep-equality after stripping, recognizing the embedded `hdf-results` resource as the `HdfResults` root; **name** the eight roots (`HdfResults`, `HdfBaseline`, …); **pass through untouched** every 2020-12 feature listed in Context; retain `examples` and `$comment`. Guards: a same-name/different-definition collision fails the build; a count mismatch fails the build.

### 2. Reference API document (generated from the MCP contract)
`dist/hdf-api.oas.json` + `.yaml`, generated from one **MCP contract golden** plus one hand-authored **binding table**.

- **The golden.** The existing `tools-list.golden.json` is extended by the same Go test into a single `mcp-contract.golden.json` holding `tools/list`, `resources/list`, `resources/templates/list`, `mcperr.Codes`, and **reflected full shapes** (`fullShapes`) of exported Go types. The build syncs it into `hdf-openapi/src/` (validators-embed pattern); a CI step regenerates and fails on diff. Three prerequisite cards in `hdf-cli`/`hdf-utilities` precede Phase 2: **(a)** tool input schemas carry real `enum` arrays for `hdf_query.status`/`severity`, `hdf_compliance.groupBy`, `verbosity` (query/inspect/diff), `hdf_diff.mode`, `hdf_validate.mode`, `hdf_author.docType`, `hdf_convert.from` (sourced from the schema enums and the converter registry); **(b)** full shapes exported and reflected: the query concise/full rows, the four diff row types registered under `diff.temporal.concise|full` and `diff.component.concise|full`, the convert batch entry, per-docType open summaries (or listed as `absent` with reason), and `hdf-engine`'s `StatusCounts`/`ThresholdConfig`; **(c)** the XML helper is created for TS and hardened in Go to scan to the root element and reject any `<!DOCTYPE`, so the contract's rule cites a helper that satisfies it.
- **The binding table** (`src/bindings.yaml`) has a closed grammar: per tool — `method`, `path`, per-field `placement ∈ {path, query, body}`, `bodyRef: <components key | fullShapes key>` (name only), `drop: [{name, reason}]`, `enumFrom: <schema enum | registry>`, `items: <output field that becomes the envelope's items>`, `fullResponse: <fullShapes key or discriminated list of keys>`; `class` is derived from the tool's `readOnlyHint`, never hand-set (`hdf_diff` is read-only; its `output`/`overwrite` inputs are dropped, which is why the derived class is correct); per resource — `method`, `path`; one `synthetic` section for the ingest operation MCP lacks (document body → id), whose body is `bodyRef`-only (the eight roots as `oneOf`); an `absent: [{tool|resource|field, reason}]` allowlist (the session transcript; MCP-only fields; components with no Go type). The generator **hard-fails** on any input property whose description mentions `HDF_MCP_ROOT` or whose name is one of `path`, `output`, `outputDir`, `overwrite`, `directory`, `pattern`, `failFast`, `sources`, `dryRun` unless it is in `drop`. A **fixed rewrite map** applies to every operation: inputs `page` (int) → cursor `next`, `limit` count-based; outputs `handle` → `id`, `page`/`nextPage`/`notice`/`truncated`/`returned` → the envelope's `next` (or dropped), `total` kept, `writesDisabled` and `outputPath` stripped; the table's `items` key names the row array. Go nil semantics (`["null","array"]`) are normalized to non-null. The **no-fragment AC is mechanical**: every leaf in `bindings.yaml` is a scalar from the closed key set; any `type`, `properties`, `$ref`, `items` (as a schema), `oneOf`, or `allOf` key anywhere in the file fails the build.
- HTTP responses are the **canonical full shapes**; MCP payloads stay the token-budgeted subset (this inverts ADR-0007's framing for the HTTP surface only — reviewer challenge (c)).

### 3. Contract conventions (shared components applied to every operation)
- **Identity**: the wire id is a server-issued opaque `uuid` per ingest (matching ADR-0009's `documents.id`); `sha256` of the ingested bytes is exposed as `ETag` and as `integrity.sourceSha256`; `If-Match` gates write operations (on `hdf_apply_amendment` it gates the results target), so `412` is meaningful and maps `HANDLE_STALE`. Within one tenant, re-ingesting identical bytes returns the existing id (`200`); across tenants the same bytes are distinct documents. All lookups are tenant-scoped: an id owned elsewhere is a uniform `404`, never `403`/`409`. Ids are never filesystem paths.
- **Bodies and limits**: inline JSON or multipart for conversion inputs; every operation with a `requestBody` MUST declare `413` and `415` (custom Spectral rule, planted-omission test); the effective size cap is advertised on the catalog operation and defaults to the CLI's 50 MB; content-type allowlist; XML inputs MUST be rejected on any `<!DOCTYPE` before the root element; `from`/`to` are enums from the converter registry (`to` is CLI-only and listed in `absent` with reason as a synthetic addition).
- **Pagination**: HTTP envelope `{items, next, total?, limit}` with cursor `next` and a documented count-based `limit` maximum on query/diff; MCP's token budget never surfaces.
- **Load**: `429` and `503` with `Retry-After` on every operation. No `202`/status resource in this revision — no producer exists (ADR-0007 defers Tasks); future work with `hdf serve`.
- **Security**: one bearer scheme; a `security` requirement on **every** operation (Spectral `operation-security-defined`); write-class operations (`readOnlyHint: false`) additionally require the `hdf:write` scope. A write attempt without the scope is `403` with `type: about:blank` and the fixed title `writes-disabled` (distinguished from other 403s by title only) — MCP's success-shaped preview does not transfer to HTTP, and this is **not** a taxonomy extension.
- **Errors**: RFC 9457. Domain errors carry `type` URIs hosted on the site, mapped one-to-one onto the closed `mcperr` taxonomy: `DOCUMENT_NOT_FOUND`→404, `TOO_LARGE`→413, `SCHEMA_INVALID`→422 (+ `errors[]` of `{path,line,message}`), `HANDLE_STALE`→412, `NO_CONVERTER`/`AMBIGUOUS_FORMAT`/`WRONG_DOC_TYPE`→422, `CACHE_MISS`→404 (unpersisted authored document; distinguished from `DOCUMENT_NOT_FOUND` by `type`); intentionally absent: `OUTPUT_EXISTS`, `PATH_DENIED`, `WRITE_FAILED` (filesystem-only), `TRUNCATED` (dead in MCP too). Transport-level conditions (400 for the code-less `mcperr.Arg` class, 401, 403, 413, 415, 429, 503) use `about:blank`, so this ADR does not extend the closed taxonomy. `nextCall` is carried as an extension member after rewriting by the generator; a test asserts no `HDF_MCP_` substring or MCP tool name appears in any problem example; `detail` MUST NOT contain paths, host configuration, or raw upstream error strings.
- **Vocabulary**: HTTP uses the schema status vocabulary; the compliance component keeps the threshold vocabulary (`skipped`/`no_impact`) because it *is* the threshold contract, and says so.

### 4. Versioning and layout
Components inline into the API document at build (self-contained; no file refs). `info.version` of the components document is the schema `$id` version; the API document has its own semver from `1.0.0`; `info` carries `x-hdf-schema-version` and `x-hdf-mcp-golden-sha`. Rules: components minor → API minor; components major → API major; golden change → API bump. Site archive under `openapi/<name>/v<version>/`.

### 5. Tooling compatibility is measured
Redocly CLI **and** Spectral for lint; openapi-typescript **and** oapi-codegen for codegen; a tracked per-keyword honored/ignored baseline that CI diffs; published on the site. `REDOCLY_TELEMETRY=off`. Node floor ≥ 22.12 documented.

### 6. Packaging
Separate package (not inside `@mitre/hdf-schema`) so lint/codegen tooling never enters the schema package's dependency tree and release cadence decouples; ADR-0009 §1 adopts the same decision. Exports: `.` (TS: `components`, `apiSpec`, `validateExample`) plus explicit file subpaths; `files: ["dist"]`; `publint` + `attw` clean. Vendor extensions `x-hdf-mcp-tool` / `x-hdf-resource` on every generated operation.

## Reviewer challenge points

Will's review — and any agent review he runs — should specifically challenge or verify: (a) **generating the API from the MCP contract** versus deferring it to an `hdf serve` ADR (ADR-0003 precedent) — chosen because the typed source exists, at the cost of three prerequisite cards; (b) whether the **binding-table grammar** (closed key set, `bodyRef`/`fullResponse` by name only, mechanical no-fragment AC) keeps the table a mapping and not the API in disguise; (c) **HTTP as the canonical full shape**, inverting ADR-0007's token-budget framing; (d) the **opaque-uuid + ETag** identity model versus content-hash ids; (e) dropping `202`/async until a producer exists; (f) treating `writes-disabled` as an `about:blank` 403 rather than extending the closed taxonomy.

## Alternatives Considered

### A. Hand-authored OpenAPI components
Pros: no generator. Cons: drift across ~129 definitions; violates the generation rule. Why rejected: drift is the failure the architecture prevents.

### B. Hand-authored reference API (revision-1 draft)
Pros: design freedom. Cons: the reviews showed the drafted path list was neither one-to-one with MCP nor a defensible CLI subset, and non-document response shapes became a second hand-maintained contract. Why rejected: contradicts generation; rots without a server.

### C. Defer the reference API to an `hdf serve` ADR
Pros: ADR-0003 precedent. Cons: the typed MCP contract exists; generation is cheap once three small prerequisites land. Why rejected (narrowly) — challenge (a).

### D. Content-hash document ids
Pros: idempotent ingest. Cons: 412/409 lose meaning; cross-tenant existence oracle. Why rejected: opaque ids with sha256 as `ETag` give the integrity signal without the oracle — challenge (d).

### E. Ship inside `@mitre/hdf-schema`
Why rejected: dependency and release coupling on the ecosystem's most-consumed package.

### F. OpenAPI 3.0 with down-converted schemas
Why rejected: lossy (no `if`/`then`, `unevaluatedProperties`, type arrays).

### G. Components that `$ref` hosted schema URLs
Why rejected: network-dependent specs break air-gapped use, codegens, and CI determinism.

### H. Do nothing
Why rejected: no public issue asks for OpenAPI today (demand is anticipated by the `hdf serve` direction), but generated artifacts cost near nothing to maintain.

## Consequences

Easier: API builders `$ref` HDF types; MCP and HTTP share one operation vocabulary by construction; a measured compatibility table.

Harder: schema bumps gain a regeneration step; the API document is a new public contract with its own semver; three prerequisite cards; the golden and binding table are tracked artifacts with a CI diff gate.

Risks and mitigations: tool lag → measured baseline; components drift → semantic conformance with negatives; API drifts from MCP → build fails on unbound tools/resources, parity compares names/enums/shapes after the fixed rewrite map, golden regenerate-and-diff in CI; hand-authoring creeps in → mechanical no-fragment AC; later `$defs` collision → build fails; partial local `dist/` → tracked-embed input + count guard. Semantic drift with unchanged names (`limit: 0 = all`, impact comparison grammar) is **not** caught without a producer — `hdf serve` contract tests close it later.

## Implementation Plan

### Scope
IN: the package; components transform with guards; the extended golden and sync; API generator, binding grammar, conventions; lint/codegen matrices with tracked baseline; conformance, parity, example tests; site publication with archive; release/CI wiring; the three prerequisite cards.
OUT: any server; client SDKs; auth implementation; `202`/async; OpenAPI for non-HDF payloads.
Delivery: **two PRs** — PR A = Phases 1a, 1b, 4 (components + site); PR B = Phases 2–3 after the prerequisites land. Both ADRs land together in the design PR first.

### Quality Standards (inherited by every card)
- Generation only; the binding table obeys its closed grammar (mechanical AC).
- OpenAPI 3.1, 2020-12 dialect; Redocly **and** Spectral zero errors; `operation-security-defined` and the 413/415 rule enforced.
- Codegen matrix diffs against a tracked baseline; diffs fail.
- Every example validates with a 2020-12 engine; examples from hdf-fixtures or schema `examples`, never fabricated; `hdf-comparison` gets a root example (owned here).
- Three-artifact rule; `publint` + `attw`; TDD, >90% coverage on generator/test code; zero lint warnings; repo gauntlet.
- No commercial downstream consumers referenced anywhere.

### Shared Abstractions
| Shared need | Used by | Card it as |
|---|---|---|
| Schema→components transform + guards | 1a–4 | Phase 1a |
| Extended MCP contract golden + build sync + CI regenerate-and-diff | 2–3 | Prerequisite card (b) |
| Contract-convention components (identity/ETag, problem details + mapping, envelope, limits, security scopes, rewrite map) | every operation | Phase 2 |
| Validation harness (lints, codegen baseline, example validation, conformance with negatives, parity with planted drifts) | 1b–3 | Phase 1b |

### Phases (sp = agent-pace story points; "Depends on" feeds `bd dep add`)

**Prerequisite cards** (in `hdf-cli`/`hdf-utilities`; depends on: nothing). **(a) Enums on tool schemas — sp3.** Files: `hdf-cli/internal/mcp/tools/{query,compliance,inspect,diff,validate,author,convert}.go`. AC: [ ] each listed field carries a non-empty `enum` in `tools/list`. Verification: `cd hdf-cli && go test ./internal/mcp/...`. **(b) Exported shapes + one golden — sp5.** Files: `hdf-cli/internal/mcp/tools/{query,diff,convert,open}.go` (exports), `hdf-cli/internal/mcp/evalharness/testdata/mcp-contract.golden.json`, `evalharness_test.go`. AC: [ ] golden holds tools, resources, templates, 12 codes, and `fullShapes` for every listed type; open summaries per docType or `absent`. Verification: as (a). **(c) XML DOCTYPE hardening — sp2.** Files: `hdf-utilities/go/xml.go`, `hdf-utilities/src/xml/index.ts` (new), tests. AC: [ ] `<!DOCTYPE` anywhere before the root element rejected in both languages. Verification: `cd hdf-utilities && pnpm test && go test ./go/...`.

**Phase 1a — Scaffold + components transform (sp8; depends on: nothing).** Files: `hdf-openapi/{package.json,tsconfig.json,tsdown.config.ts,eslint.config.js}`, `src/generate-components.ts`, `test/components.test.ts`. AC: [ ] eight roots from the tracked embed, self-contained, zero `$id`/absolute refs, wrappers unwrapped; [ ] collision and count guards fail when planted; [ ] each Context-listed 2020-12 feature present unchanged (assertion per feature). Verification: `cd hdf-openapi && pnpm build && pnpm test && pnpm lint`.

**Phase 1b — Matrices + semantic conformance (sp5; depends on: 1a).** Files: `scripts/openapi-matrix.mjs`, `test/conformance.test.ts`, `test/baseline/keywords.json`. AC: [ ] Redocly + Spectral zero errors; [ ] codegen baseline tracked and diffed; [ ] conformance: each root and each definition extracted back to a standalone 2020-12 schema and validated with a 2020-12 engine — root examples and hdf-fixtures documents against roots, the 45 definition examples against their extracted definitions — asserting the same verdict as the source; negatives per root in five mutation classes (missing required, bad enum, extra key under `unevaluatedProperties: false`, `if`/`then` violation, boolean-`false` branch). Verification: `cd hdf-openapi && pnpm test && pnpm exec node scripts/openapi-matrix.mjs`.

**Phase 2 — API generator + bindings + conventions (sp13; depends on: 1b, prerequisites a–c).** Files: `src/generate-api.ts`, `src/bindings.yaml`, `src/conventions/*.yaml`, `scripts/sync-mcp-golden.mjs`, `test/api.test.ts`. AC: [ ] every tool, resource, and field bound, dropped, or allowlisted; [ ] generator hard-fails on an undropped filesystem field (planted `dryRun`); [ ] every operation has `security`; write ops carry `hdf:write` + the `writes-disabled` 403; every body op has 413/415; [ ] rewrite map applied (no `page`/`handle`/`writesDisabled`/`outputPath` in output); [ ] mcperr mapping complete (8 mapped, 4 absent with reasons); [ ] no-fragment AC (closed key set) green; [ ] both lints zero errors. Verification: `cd hdf-openapi && pnpm build && pnpm test && pnpm lint`.

**Phase 3 — Parity + contract tests (sp5; depends on: 2).** Files: `test/parity.test.ts`, `test/examples.test.ts`. AC: [ ] parity fails on eight planted drifts: unbound tool, stale binding, parameter, enum, resource, code, `fullShapes` field, `readOnlyHint` flip; [ ] all examples validate; [ ] no `HDF_MCP_` substring in any problem example. Verification: `cd hdf-openapi && pnpm test`.

**Phase 4 — Site, versioning, release/CI wiring (sp5; depends on: 1b).** Files: `site/generate-openapi-docs.mjs` + page (Redoc embed, downloads, compatibility table) + `site/public/openapi/<name>/v<version>/`; `.claude/commands/release.md` (package row; "7" → 8); `.github/workflows/{ci,release,pre-release}.yml` (build verify loop, artifact paths, `verify-packages` and publish `PACKAGES` arrays, pre-release smoke-import list); `CLAUDE.md` (document types → 8; component types → 13); memory `hdf-schema-change-propagation` (step 4; fix its "all 7"); `site/docs/contributing/developer-guide.md`; `hdf-schema/src/schemas/hdf-comparison.schema.json` (root example). AC: [ ] site renders both artifacts and the table; [ ] every enumeration includes the package; [ ] counts corrected in every listed file. Verification: `cd site && pnpm generate && pnpm build` and `pnpm check`.

Total ≈ sp36 + prerequisites sp10 (≈ 4–6 h agent-pace).

### Verification Strategy
Repo gauntlet every phase. Feature-level: both lints, codegen baseline diff, example validation, semantic conformance with negatives, parity with eight planted drifts, golden regenerate-and-diff in CI. Live test before close: render the API document in Redoc, generate a TS client with openapi-typescript against a real fixture, validate a fixture with a 2020-12 validator via the extracted component — outputs pasted in card notes.

## References
- OpenAPI 3.1.0 — https://spec.openapis.org/oas/v3.1.0; JSON Schema 2020-12 — https://json-schema.org/draft/2020-12; RFC 9457 — https://www.rfc-editor.org/rfc/rfc9457 (accessed 2026-09-01)
- Redocly CLI 2.49.x — https://redocly.com/docs/cli; Spectral 6.16.x — https://docs.stoplight.io/docs/spectral; openapi-typescript — https://openapi-ts.dev; oapi-codegen — https://github.com/oapi-codegen/oapi-codegen (accessed 2026-09-01)
- MCP Go SDK v1.7 and jsonschema-go v0.4 (tag → description; `Schema.Enum` settable) — https://github.com/modelcontextprotocol/go-sdk, https://github.com/google/jsonschema-go (accessed 2026-09-01)
- This repo: ADR-0007; `hdf-cli/internal/mcp/{mcperr,respond,resources,tools,evalharness}`; `hdf-schema/src/bundle-schemas.ts`; ADR-0009 §5 (validator-gap card)
