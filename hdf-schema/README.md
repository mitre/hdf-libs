# @mitre/hdf-schema

JSON schemas and multi-language type definitions for **Heimdall Data Format (HDF)**.

## Overview

HDF is a standardized format for representing security assessment results. This package provides:

- **JSON Schemas** for validating HDF documents
- **Generated types** for TypeScript and Go

## Installation

```bash
npm install @mitre/hdf-schema
```

## Schema Types

Seven document types covering the full security assessment lifecycle:

### HDF Results (`hdf-results`)

Assessment findings from running security checks against target systems. The primary output of converters. Contains evaluated baselines with requirement results, components (hosts, containers, cloud resources), status overrides with disposition tracking, and statistics.

### HDF Baseline (`hdf-baseline`)

Security requirement definitions without results — the "what to check" document. Contains requirement metadata (title, descriptions, severity, impact), check/fix instructions, framework mappings (NIST, CCI), and dependency information.

### HDF System (`hdf-system`)

Authorization boundary definition. Describes a system's components (with polymorphic types: host, container, cloud account, application, etc.), data flows between components, and control designations (common/hybrid/system-specific).

### HDF Plan (`hdf-plan`)

Assessment plan linking baselines to system components. Defines what will be assessed, how, and by whom. References baselines, systems, and runner configurations.

### HDF Amendments (`hdf-amendments`)

Standalone amendment documents containing waivers, attestations, POA&Ms, and other overrides. Applied to results via `hdf amend apply` to track adjudication decisions (false positives, risk adjustments, operational requirements).

### HDF Evidence Package (`hdf-evidence-package`)

Bundles references to all documents needed for a compliance review — results, baselines, system, plan, and amendments — with checksums for integrity verification.

### HDF Comparison (`hdf-comparison`)

Output of the diff engine. Structural comparison between two or more HDF documents showing requirement-level changes, status transitions, and field diffs.

## Usage

### Importing Schemas

Schemas can be imported in two ways:

```typescript
// Named exports from the barrel (all schemas available)
import { hdfResultsSchema, hdfBaselineSchema, hdfSystemSchema } from '@mitre/hdf-schema';

// Sub-path imports (one schema per import, tree-shakeable)
import type { HdfResults } from '@mitre/hdf-schema/hdf-results';
import type { HdfBaseline } from '@mitre/hdf-schema/hdf-baseline';
import type { HdfSystem } from '@mitre/hdf-schema/hdf-system';
import type { HdfPlan } from '@mitre/hdf-schema/hdf-plan';
import type { HdfAmendments } from '@mitre/hdf-schema/hdf-amendments';
import type { HdfEvidencePackage } from '@mitre/hdf-schema/hdf-evidence-package';
import type { HdfComparison } from '@mitre/hdf-schema/hdf-comparison';
```

Helper functions (severity mapping, effective status computation):

```typescript
import { severityToImpact, impactToSeverity, computeEffectiveStatus } from '@mitre/hdf-schema/helpers';
```

### Validating Documents (TypeScript/JavaScript)

```typescript
import Ajv from 'ajv';
import { hdfResultsSchema } from '@mitre/hdf-schema';

const ajv = new Ajv({ strict: false });
const validate = ajv.compile(hdfResultsSchema);

const isValid = validate(myDocument);
if (!isValid) {
  console.error(validate.errors);
}
```

### Using Generated Types (TypeScript)

```typescript
import type { HdfResults, HdfBaseline } from '@mitre/hdf-schema';

function processResults(results: HdfResults) {
  for (const baseline of results.baselines) {
    for (const requirement of baseline.requirements) {
      console.log(`${requirement.id}: ${requirement.results[0]?.status}`);
    }
  }
}
```

### Using Generated Types (Go)

```go
import hdf "github.com/mitre/hdf-schema"

func main() {
    data := []byte(`{"baselines": [...]}`)
    results, err := hdf.UnmarshalHDFResults(data)
    if err != nil {
        panic(err)
    }
    for _, baseline := range results.Baselines {
        fmt.Printf("%s: %d requirements\n", baseline.Name, len(baseline.Requirements))
    }
}
```

## Schema Files

| File | Description |
|------|-------------|
| `src/schemas/hdf-results.schema.json` | Assessment findings (modular, uses $ref) |
| `src/schemas/hdf-baseline.schema.json` | Requirement definitions without results |
| `src/schemas/hdf-system.schema.json` | Authorization boundary, components, data flows |
| `src/schemas/hdf-plan.schema.json` | Assessment plan linking baselines to components |
| `src/schemas/hdf-amendments.schema.json` | Waivers, attestations, POA&Ms |
| `src/schemas/hdf-evidence-package.schema.json` | Bundle of references to all documents |
| `src/schemas/hdf-comparison.schema.json` | Differential analysis between assessments |
| `src/schemas/primitives/*.schema.json` | Shared type definitions |
| `dist/schemas/*.schema.json` | Bundled schemas (self-contained, all $refs inlined) |

### Modular vs Bundled Schemas

**Modular schemas** (`src/schemas/`) use `$ref` to reference shared definitions from primitive files. Use these if your validator supports `$ref` resolution.

**Bundled schemas** (`dist/schemas/`) have all references inlined. Use these for tools that don't support `$ref` or for simpler integration.

## Generated Types

After building, types are available in:

| Language | Location |
|----------|----------|
| TypeScript | `dist/ts/hdf-*.ts` (7 files, one per schema) |
| Go | `dist/go/hdf.go` (single file containing all types) |

## Development

```bash
# Install dependencies
pnpm install

# Run tests
pnpm test

# Build everything (schemas + types)
pnpm build

# Build only bundled schemas
pnpm build:schemas

# Build only generated types
pnpm build:types
```

## Versioning

This package has two version numbers that serve different purposes:

- **Package version** (`package.json` `version`): Follows npm semver. Bumped on every release — bug fixes, new helpers, type generation improvements, dependency updates. This is what consumers see in `npm install @mitre/hdf-schema@3.0.1`.

- **Schema version** (`$id` URL in each `.schema.json`): Identifies the schema structure itself. Only changes when the schema structure changes — new fields, removed fields, type changes, constraint changes. Example: `https://mitre.github.io/hdf-libs/schemas/hdf-results/v3.1.0`.

These versions are aligned at major boundaries (both are 3.x to signal this is the successor to the heimdall2 v2.x ecosystem) but can diverge at minor/patch levels. A package patch release (e.g., 3.0.1 → 3.0.2) that only fixes a converter bug or updates a helper function does not change the schema `$id`. A schema structural change (e.g., adding a new required field) bumps the schema version in the `$id` URL regardless of where the package version stands.

The `$id` URLs are also the canonical hosted location for each schema: `https://mitre.github.io/hdf-libs/schemas/`.

### JSON Schema dialect

All schemas use **JSON Schema draft/2020-12**.

### Hosted schema documentation

Interactive schema reference documentation is published at:
**<https://mitre.github.io/hdf-libs/schemas/>**

### What's new in v3.1.0

- **`disposition`** field on `EvaluatedRequirement` — the type of the governing override or POAM (e.g., `waiver`, `falsePositive`, `riskAdjustment`). Indicates why a requirement is in its current state.
- **`effectiveImpact`** field on `EvaluatedRequirement` — the computed impact score (0.0–1.0) after applying the most recent non-expired impact override.
- **`Impact_Override`** type on `Status_Override` and `Standalone_Override` — object with a `value` field (0.0–1.0). At least one of `status` or `impact` must be set (enforced via `anyOf`).
- **`Override_Type` expansion** — added `falsePositive`, `riskAdjustment`, `operationalRequirement`; removed `exception` (use `waiver` with `status: "notApplicable"` instead).
- **`vendorDependency`** added to POAM type enum.
- **Breaking:** The `./schemas/<name>.schema.json` sub-path export was removed. Use named imports from the barrel (`import { hdfResultsSchema } from '@mitre/hdf-schema'`) instead.
