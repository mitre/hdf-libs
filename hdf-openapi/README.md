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
