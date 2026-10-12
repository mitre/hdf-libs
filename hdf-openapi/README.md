# @mitre/hdf-openapi

OpenAPI 3.1 components for the Heimdall Data Format, generated from the HDF JSON Schema 2020-12 bundles.

> **Status:** both documents ship. `hdf-components.oas.json` carries the components generated from the
> schema bundles; `hdf-api.oas.json` is the reference API generated from the HDF MCP server's contract and a
> closed-grammar binding table (ADR-0008 §2), published alongside `problems.json`, the documentation for every
> RFC 9457 problem type it declares.

## Why this exists

HDF publishes eight document types as JSON Schema 2020-12 bundles. Anyone building an HTTP service over HDF previously hand-translated those schemas into OpenAPI and hand-invented an API to go with them — and both then drifted from the format they were meant to describe.

The bundles are not drop-in OpenAPI components. The bundler embeds each primitive as a URL-keyed resource carrying its own `$id`, so the eight bundles together hold 19 such resource wrappers and well over a hundred named definitions (the exact figure is `EXPECTED_DEFINITIONS` in `src/components.ts`, which the build refuses to disagree with), with hundreds of `$ref`s — some absolute, some local pointers that resolve against the enclosing resource rather than the file. OpenAPI component keys cannot be URLs, and pointer-based code generators resolve by JSON pointer, not by `$id`. Translating that by hand is both tedious and easy to get subtly wrong.

So this package generates the components instead. Nothing here is hand-authored — they come from the tracked
schema embed. The only thing in this repository that reads this package is the docs site, whose generators
publish both documents, their per-version archives and a page per problem type from `dist/`.

The reference API is generated the same way, from the MCP contract golden plus a closed-grammar binding table
mechanically prevented from containing API fragments (ADR-0008 §2). The shared components it applies to every
operation — identity and `ETag`, the problem details mapped onto the `mcperr` taxonomy, the pagination
envelope, limits, security scopes — are the one hand-authored input, and §2 fixes what they may contain.

## Installation

```bash
npm install @mitre/hdf-openapi
```

## Usage

### Read the components document

```ts
import components from '@mitre/hdf-openapi/hdf-components.oas.json' with { type: 'json' };

const results = components.components.schemas.HdfResults;
```

The generated document is the consumer surface. The transform that produces it is
also exported, but note that `EMBED_DIR` points at this repository's tracked schema
embed, which is **not** part of the published tarball (`files: ["dist"]`) — so the
call below works inside this repository and not from an installed copy:

```ts
// In-repo only: regenerating from the tracked embed.
import { buildComponentsDocument, loadBundles, EMBED_DIR } from '@mitre/hdf-openapi';

const doc = buildComponentsDocument(loadBundles(EMBED_DIR));
```

An installed consumer reads the generated artifact, or passes its own bundles to
`buildComponentsDocument`.

### The eight roots

Each HDF document type is a component named after it:

| Document type | Component |
|---|---|
| hdf-results | `HdfResults` |
| hdf-baseline | `HdfBaseline` |
| hdf-comparison | `HdfComparison` |
| hdf-system | `HdfSystem` |
| hdf-plan | `HdfPlan` |
| hdf-amendments | `HdfAmendments` |
| hdf-evidence-package | `HdfEvidencePackage` |
| hdf-requirement-change-event | `HdfRequirementChangeEvent` |

Every other definition is hoisted to `#/components/schemas/<Name>` under its own name, and every `$ref` is rewritten to a local component pointer.

## What the transform guarantees

- **2020-12 features pass through unchanged**, and a test asserts the complete keyword histogram of the output
  against an independent walk of the input, so a dropped keyword fails the build rather than surfacing in a
  downstream codegen. `unevaluatedProperties`, `if`/`then`/`else`, `dependentRequired`, boolean-`false`
  subschemas, `contains` + `const` and `type: [string, null]` enums are all left as the schemas define them. They are legal in OpenAPI 3.1, and tool support for them is measured rather than assumed.
- **Refs are resolved, not string-replaced.** A local `#/$defs/X` is resolved against the resource that encloses it, and the target's existence is checked in the scope the ref names. A global string replace would silently retarget refs inside an embedded primitive.
- **Duplicates collapse, conflicts fail.** The `hdf-results` resource is embedded inside comparison and change-event; identical definitions deduplicate, while a same-name definition with a different body fails the build rather than picking a winner.
- **The input is the tracked embed.** Generation reads `hdf-validators/go/schemas/`, the reviewed copy, never the gitignored `hdf-schema/dist/`. The file set must match the bundler's own list, so a document type that appeared or vanished fails the build.
- **`info.version` is the schema version** from the bundles' `$id`, not this package's version. The two move independently.

## Tooling compatibility is measured, not assumed

`test/baseline/keywords.json` records what real tooling actually does with the published document, and `pnpm run matrix` fails if any of it moves. Four things are tracked:

- **Which keywords the document uses**, with counts, so a schema change that introduces a keyword nothing in the matrix supports is a failing diff rather than a consumer's discovery.
- **Redocly at zero findings, every severity** — *and* the per-rule counts its waivers are absorbing, measured by re-running with every waiver stripped. A waiver can therefore never quietly grow to cover a new finding. Every waiver in `redocly.yaml` carries the reason it does not apply to a document schema, and because those counts mix suppressed false positives with any future genuine finding, movement in them needs human triage rather than a blind re-record.

- **Spectral at zero errors**, over the core `oas` ruleset loaded through Spectral's library rather than its CLI (`scripts/spectral-lint.mjs`). **The OWASP API Security ruleset is not loaded**, and that is measured rather than an oversight: the reasons, with the dates they were re-checked, live in `.spectral.mjs` beside the ruleset they explain. The short version is that every way of loading it carries either an unfixable advisory or a bundler that cannot import it, and the library packages used here carry neither of the offending dependencies at all.

- **Whether each generator can consume the document at all.** `openapi-typescript` can. **`oapi-codegen` 2.8.0 cannot:** its parser (kin-openapi) rejects a boolean subschema, which HDF uses to express the three-tier BOM rule (`properties: { model: false }` on a non-`ai-model` BOM). The refusal and its trigger are recorded rather than worked around, because the construct is a real constraint and dropping it would weaken the schema to suit one tool.
- **Per keyword, whether a generator's output depends on it** — measured differentially: generate from a probe schema carrying the keyword, generate again with that one keyword deleted, compare the bytes. Both generators honour the structural keywords (`$ref`, `properties`, `required`, `items`, `type`, `enum`, `allOf`/`anyOf`/`oneOf`, `format`) and **both discard every validation constraint**: `minimum`, `maximum`, `minLength`, `minItems`, `pattern`, `contains`, `not`, `dependentRequired`, `if`/`then`/`else` and `unevaluatedProperties`. Generated types are shape-only. Anything that must actually enforce the schema has to run a validator — which is why ADR-0008 §7 derives Zod from this document rather than trusting generated types.

None of that is optional. `pnpm test` re-measures the lints and openapi-typescript and fails on any drift from the baseline, and CI's `check-openapi-matrix` job installs the pinned `oapi-codegen` and runs the full matrix, so the Go half is gated too. The test also asserts that CI wiring still exists — an ungated baseline is the real hazard, so losing the job fails the suite rather than quietly going unmeasured.

`oapi-codegen` is a Go binary, not an npm dependency, which is why `pnpm test` measures only the half it can reach. To run the whole matrix locally:

```bash
go install github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.8.0
pnpm run matrix          # verify against the tracked baseline
pnpm run matrix:update   # re-record after a deliberate tooling or schema change
pnpm run lint:openapi    # Redocly alone
```

With the binary present, `pnpm test` upgrades itself to the full both-generator comparison; without it, the npm half runs and CI covers the rest.

Conformance is checked separately and more strictly than any linter manages: `test/conformance.test.ts` extracts **every component** back to a standalone 2020-12 schema and compiles each one, then validates every root example, every definition example and the `@mitre/hdf-fixtures` corpus with a **2020-12** engine. The counts are asserted in that test rather than quoted here, so they cannot rot in two places. This repository's own validators are draft-07 and ignore `unevaluatedProperties`, so they would accept documents the schema text rejects.

## Versioning

The components document's `info.version` tracks the schema `$id` version, read from the bundle rather than
from this package's version — the two axes are independent and have already diverged.

The reference API carries its own semver (`API_VERSION` in `src/generate-api.ts`), and ADR-0008 §4 says which
digit moves: a components minor is an API minor, a components major is an API major, a change to the MCP
golden bumps the API document. Because none of those covers a change to the binding table or the conventions
— where the breaking changes have in practice come from — `info` also carries `x-hdf-contract-digest` over the
whole document except `info` itself, and `test/baseline/contract.json` fails when that digest moves under an
unchanged version. The digest detects; the version still has to be bumped deliberately, because only a human
can say whether a change is breaking. Re-record with `pnpm run contract:update`, which is correct while a
version is unreleased and wrong once it has shipped.

## Design

`dev-docs/adr-0008-openapi-schema-and-reference-api.md`, in the [hdf-libs repository](https://github.com/mitre/hdf-libs), records the decisions, the alternatives considered, and the measured forces behind them. ADR-0012 puts this package in context: it stays in `hdf-libs` because it derives from this repository's schemas and MCP contract, and it is the contract the sibling platform repository implements.

## License

Apache-2.0. See [LICENSE.md](../LICENSE.md).
