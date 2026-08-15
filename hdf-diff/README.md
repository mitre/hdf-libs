# @mitre/hdf-diff

Structured comparison of HDF documents — tracks what changed, why, and by how much.

## What it does

Compares HDF documents (results, baselines, or system documents) and produces a structured diff:

- **Results comparison** (`diffHdf`) — requirements added, removed, or changed between evaluations; status transitions with change reasons; field-level changes (impact, severity, disposition, effectiveImpact); per-baseline compliance summaries
- **Baseline evolution** (`diffBaselines`) — track how a baseline's requirements change across versions (IDs added/removed, impact/severity/title changes)
- **System drift** (`diffSystems`) — compare two HDF system documents for component, data flow, and configuration changes
- **SBOM comparison** (`diffSboms`) — CycloneDX/SPDX package-level diffs (added, removed, updated)
- **Amendment operations** (Go only, `amend` subpackage) — merge overrides into results, verify amendment chains, compute effectiveStatus/effectiveImpact/disposition
- **Requirement change events** (`changeEventFromPrevious`, `applyChangeEvents`, `foldChangeEventsIntoComparison`) — the continuous-monitoring kernel (ADR-0005): derive a per-requirement change-event stream between two scans, fold a batch of events into a comparison, and replay events onto a seed to reassemble a reconciled results document (parity law: `applyChangeEvents(A, derive(A→B)) ≡ B` at requirement level). Dual Go + TS; wrapped by the `hdf events` CLI command group.

Additional capabilities:
- Multiple comparison modes: temporal, baseline, fleet, multi-source
- Format normalization: InSpec exec-json (legacy HDF v1) to current HDF
- Output formats: JSON, Markdown, CSV, terminal (ANSI-colored)
- CI exit codes: GNU diff-compatible (0/1/2) and detailed (10-14)

## Relationship to other packages

| Package | Relationship |
|---------|-------------|
| **hdf-schema** | Provides `HDFResults`, `HDFBaseline`, and system types that hdf-diff consumes |
| **hdf-validators** | Used to validate comparison output against the HDF comparison schema |
| **hdf-cli** | `hdf diff` and `hdf amend` commands wrap this library for CLI use |

## Installation

```bash
npm install @mitre/hdf-diff
```

## Usage

```typescript
import { diffHdf, diffBaselines, diffSystems, render } from '@mitre/hdf-diff';

// Compare two evaluation results (temporal mode)
const comparison = diffHdf(oldResults, newResults);

// Compare baseline evolution (track requirement changes across versions)
const baselineDiff = diffBaselines(oldBaseline, newBaseline);

// Compare system documents (component/data-flow drift)
const systemDiff = diffSystems(oldSystem, newSystem);

// Render as markdown, JSON, CSV, or terminal
const md = render(comparison, 'markdown', { detail: 'full' });
const json = render(comparison, 'json');

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
import { diffHdf } from '@mitre/hdf-diff';

const comparison = diffHdf(oldResults, newResults, {
  matchStrategy: 'fuzzyTitle',
  minConfidence: 0.8, // 80% similarity threshold
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
# Results comparison
hdf diff old-results.json new-results.json
hdf diff old-results.json new-results.json --format markdown
hdf diff old-results.json new-results.json --json

# System drift detection (auto-detected from document type)
hdf diff old-system.json new-system.json

# SBOM comparison
hdf diff --sbom old.cdx.json new.cdx.json

# Encode the security outcome in the exit code (10=fixes, 11=regressions, 12=mixed, 13=baseline change, 14=metadata drift only)
hdf diff old-results.json new-results.json --detailed-exitcode
```

Example output — a scan where one requirement regressed and one was added:

```console
$ hdf diff old-results.json new-results.json
HDF Comparison: old-results.json → new-results.json

ID       Title                          Old Status  New Status  State
-------  -----------------------------  ----------  ----------  ---------
REQ-001  Test Requirement               passed      failed      regressed
REQ-002  Audit logging must be enabled  -           passed      new

Summary: 0 fixed, 1 regressed, 1 new, 0 absent, 0 unchanged, 0 updated (2 total)
```

The same comparison with `--format markdown` renders a GitHub-friendly table; `--json` emits an HDF Comparison document (`formatVersion`, `summary`, `requirementDiffs[]`) suitable for CI gating.

## Go usage

The diff engine is also available as a Go module:

```go
import diff "github.com/mitre/hdf-libs/hdf-diff/go/v3"
```

See the [hdf-diff/go](https://github.com/mitre/hdf-libs/tree/main/hdf-diff/go) directory for the Go API.

## Schema documentation

The HDF Comparison schema that hdf-diff produces is documented at
<https://mitre.github.io/hdf-libs/schemas/>.

## License

Apache-2.0 © MITRE Corporation
