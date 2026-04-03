# @mitre/hdf-diff

Structured comparison of HDF evaluation results — tracks what changed, why, and by how much.

## What it does

Compares two HDF results documents and produces a structured diff showing:
- Requirements added, removed, or changed between evaluations
- Status transitions (passed→failed, failed→passed, etc.) with change reasons
- Field-level changes (impact, title, severity)
- Per-baseline and per-component compliance summaries
- SBOM (CycloneDX/SPDX) package-level diffs

Output formats: JSON, Markdown, CSV, terminal (ANSI-colored).

## Relationship to other packages

| Package | Relationship |
|---------|-------------|
| **hdf-schema** | Provides the `HDFResults` types that hdf-diff consumes |
| **hdf-validators** | Used to validate comparison output against the HDF comparison schema |
| **hdf-cli** | `hdf diff` command wraps this library for CLI use |
| **hdf-parsers** | Not used — hdf-diff operates on typed structs, not raw JSON |

## Installation

```bash
npm install @mitre/hdf-diff
```

## Usage

```typescript
import { diffHdf, render } from '@mitre/hdf-diff';

// Compare two evaluation results
const comparison = diffHdf(oldResults, newResults);

// Render as markdown
const md = render(comparison, { format: 'markdown', detail: 'full' });

// Render as JSON
const json = render(comparison, { format: 'json' });

// Check exit codes for CI
import { computeExitCode, EXIT_IDENTICAL } from '@mitre/hdf-diff';
const code = computeExitCode(comparison);
if (code !== EXIT_IDENTICAL) process.exit(code);
```

### Requirement matching

hdf-diff supports multiple strategies for matching requirements across evaluations:
- **Exact ID** (default) — match by requirement ID
- **Mapped ID** — match via a user-provided ID mapping
- **CCI match** — match by shared CCI identifiers
- **Fuzzy title** — Jaccard similarity on tokenized titles

```typescript
import { diffHdf, createFuzzyTitleStrategy } from '@mitre/hdf-diff';

const comparison = diffHdf(oldResults, newResults, {
  matchStrategy: createFuzzyTitleStrategy(0.8), // 80% similarity threshold
});
```

### SBOM comparison

```typescript
import { diffSboms } from '@mitre/hdf-diff';

const sbomDiff = diffSboms(oldSbom, newSbom);
// Shows packages added, removed, updated, or unchanged
```

## CLI usage

```bash
hdf diff old-results.json new-results.json
hdf diff old-results.json new-results.json --format markdown
hdf diff old-results.json new-results.json --json
hdf diff --sbom old-sbom.json new-sbom.json
```

## License

Apache-2.0 © MITRE Corporation
