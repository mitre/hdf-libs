# @mitre/hdf-openapi

OpenAPI 3.1 components for the Heimdall Data Format, generated from the HDF JSON Schema 2020-12 bundles.

> **Status:** the components document ships today. A second artifact — a *reference API* document generated
> from the HDF MCP server's contract — is designed but **not yet built**; see ADR-0008 §2. Nothing in this
> README describes behaviour that does not exist.

## Why this exists

HDF publishes eight document types as JSON Schema 2020-12 bundles. Anyone building an HTTP service over HDF previously hand-translated those schemas into OpenAPI and hand-invented an API to go with them — and both then drifted from the format they were meant to describe.

The bundles are not drop-in OpenAPI components. The bundler embeds each primitive as a URL-keyed resource carrying its own `$id`, so the eight bundles together hold 19 such resource wrappers and 115 named definitions, with hundreds of `$ref`s — some absolute, some local pointers that resolve against the enclosing resource rather than the file. OpenAPI component keys cannot be URLs, and pointer-based code generators resolve by JSON pointer, not by `$id`. Translating that by hand is both tedious and easy to get subtly wrong.

So this package generates the components instead. Nothing here is hand-authored — they come from the tracked
schema embed. Nothing in this repository imports this package: it is a leaf, published for consumers.

When the reference API document arrives it will be generated the same way, from the MCP contract golden plus
a closed-grammar binding table mechanically prevented from containing API fragments (ADR-0008 §2).

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

  **Spectral and the OWASP API Security ruleset are deferred to Phase 2.** ADR-0008 §5 still names both linters for this phase; correcting it is tracked as `hdf-libs-lx1oj.10`, not yet done. Two measurements drove that. Its CLI is the sole carrier of GHSA-vfj7-8cjw-p6xm, and that advisory is structurally unfixable: `braces` is frozen at 3.0.3 against a patched floor of 3.0.4 that was never published, every `fast-glob` depends on `micromatch`, every `micromatch` on `braces`, and every `spectral-cli` release pins `fast-glob ~3.2.12`. Loading the ruleset through Spectral's library instead — whose packages carry no `fast-glob` — fails because the bundler still ships rollup 2.80, which cannot import the OWASP ruleset's CommonJS build; making that work would mean hand-rolling ruleset loading, which is more risk than the advisory. And on a components document Spectral had little to say: of 746 findings, 735 were OWASP API4 request-surface rules that do not apply to stored documents, 9 were operation-less-document rules, one was `info-contact` (fixed), and exactly one was real — `array-items` on `Input_Constraints.allowedValues`, now carried by card `hdf-libs-ztq0b` rather than by any lint, since Redocly has no equivalent rule. The OWASP rules earn their keep against Phase 2's reference API document, where operations and security schemes exist.
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

Conformance is checked separately and more strictly than any linter manages: `test/conformance.test.ts` extracts **all 123 components** back to standalone 2020-12 schemas and compiles each one, then validates every root example, all 120 definition examples and the `@mitre/hdf-fixtures` corpus with a **2020-12** engine. This repository's own validators are draft-07 and ignore `unevaluatedProperties`, so they would accept documents the schema text rejects.

## Versioning

The components document's `info.version` tracks the schema `$id` version — currently 3.7.0, which happens to
equal this package's version and will not stay that way.

The planned rules for the reference API document, once it exists (ADR-0008 §4): it carries its own semver; a
components minor is an API minor; a components major is an API major; a change to the MCP golden bumps the API
document.

## Design

`dev-docs/adr-0008-openapi-schema-and-reference-api.md`, in the [hdf-libs repository](https://github.com/mitre/hdf-libs), records the decisions, the alternatives considered, and the measured forces behind them. ADR-0012 puts this package in context: it stays in `hdf-libs` because it derives from this repository's schemas and MCP contract, and it is the contract the sibling platform repository implements.

## License

Apache-2.0. See [LICENSE.md](../LICENSE.md).
