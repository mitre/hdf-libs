# @mitre/hdf-schema

JSON schemas and multi-language type definitions for **Heimdall Data Format (HDF)**.

## Overview

HDF is a standardized format for representing security assessment results. This package provides:

- **JSON Schemas** for validating HDF documents
- **Generated types** for TypeScript, Go, and Python

## Installation

```bash
npm install @mitre/hdf-schema
```

## Schema Types

### HDF Results

Assessment results from running security checks against target systems. Contains:

- Target system information (hosts, containers, cloud accounts, etc.)
- Evaluated baselines with requirement results
- Pass/fail status for each check
- Statistics and timing data

### HDF Baseline

Security requirement definitions without results. Contains:

- Requirement metadata (title, description, severity)
- Check and fix instructions
- Framework mappings (NIST, CIS, etc.)
- Dependencies between requirements

## Usage

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

> Schemas have been available as named exports since v3.1.0. The legacy
> `import x from '@mitre/hdf-schema/schemas/<name>.schema.json'` sub-path
> form was removed in the same release; switch to named imports.

### Using Generated Types (TypeScript)

```typescript
import type { HdfResults, HdfBaseline } from '@mitre/hdf-schema';

function processResults(results: HdfResults) {
  for (const baseline of results.profiles) {
    for (const requirement of baseline.controls) {
      console.log(`${requirement.id}: ${requirement.results[0]?.status}`);
    }
  }
}
```

### Using Generated Types (Go)

```go
import "github.com/mitre/hdf-libs/hdf-schema/dist/go/hdf"

func main() {
    data := []byte(`{"platform": {...}, "profiles": [...]}`)
    results, err := hdf.UnmarshalHdfResults(data)
    if err != nil {
        panic(err)
    }
    fmt.Println(results.Version)
}
```

### Using Generated Types (Python)

```python
from hdf_results import HdfResults
import json

with open('results.json') as f:
    data = json.load(f)
    results = HdfResults.from_dict(data)
    print(results.version)
```

## Schema Files

| File | Description |
|------|-------------|
| `src/schemas/hdf-results.schema.json` | Results schema (modular, uses $ref) |
| `src/schemas/hdf-baseline.schema.json` | Baseline schema (modular, uses $ref) |
| `src/schemas/primitives/*.schema.json` | Shared type definitions |
| `dist/schemas/hdf-results.schema.json` | Bundled results schema (self-contained) |
| `dist/schemas/hdf-baseline.schema.json` | Bundled baseline schema (self-contained) |

### Modular vs Bundled Schemas

**Modular schemas** (`src/schemas/`) use `$ref` to reference shared definitions from primitive files. Use these if your validator supports `$ref` resolution.

**Bundled schemas** (`dist/schemas/`) have all references inlined. Use these for tools that don't support `$ref` or for simpler integration.

## Generated Types

After building, types are available in:

| Language | Location |
|----------|----------|
| TypeScript | `dist/ts/hdf-results.ts`, `dist/ts/hdf-baseline.ts` |
| Go | `dist/go/hdf_results.go`, `dist/go/hdf_baseline.go` |
| Python | `dist/python/hdf_results.py`, `dist/python/hdf_baseline.py` |

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

- **Schema version** (`$id` URL in each `.schema.json`): Identifies the schema structure itself. Only changes when the schema structure changes — new fields, removed fields, type changes, constraint changes. Example: `https://mitre.github.io/hdf-libs/schemas/hdf-results/v3.0.0`.

These versions are aligned at major boundaries (both are 3.x to signal this is the successor to the heimdall2 v2.x ecosystem) but can diverge at minor/patch levels. A package patch release (e.g., 3.0.1 → 3.0.2) that only fixes a converter bug or updates a helper function does not change the schema `$id`. A schema structural change (e.g., adding a new required field) bumps the schema version in the `$id` URL regardless of where the package version stands.

The `$id` URLs are also the canonical hosted location for each schema: `https://mitre.github.io/hdf-libs/schemas/`.

### JSON Schema dialect

All schemas use **JSON Schema draft/2020-12**.
