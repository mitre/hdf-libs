# @mitre/hdf-engine

Shared, schema-typed read-side engines for Heimdall Data Format (HDF) documents — document-type **detection**, requirement **query/filtering**, **compliance** rollups and threshold verdicts, the document **loader**, the **evidence-verify** core, and multi-document **merge**.

## Why this exists

Reading an HDF document correctly is harder than it looks. Deciding a requirement's effective status means resolving amendments and impact-zero rules; counting by severity means agreeing on what an absent severity derives to; detecting a document's type means fingerprinting keys that several types share. Each of those has exactly one right answer, and every consumer that reimplements it drifts from the others.

So the engines live here rather than in any one consumer. The `hdf` CLI and the HDF MCP server both delegate to this package, which is why they cannot disagree about the same document. It sits above `@mitre/hdf-schema` (types) and `@mitre/hdf-utilities` (schema-free primitives), and is a sibling to `@mitre/hdf-diff`, which owns diff, change events and amend.

Dual-language and kept at parity: TypeScript (`@mitre/hdf-engine`) and Go (`github.com/mitre/hdf-libs/hdf-engine/go/v3`).

## Installation

```bash
npm install @mitre/hdf-engine
```

```bash
go get github.com/mitre/hdf-libs/hdf-engine/go/v3
```

## Usage

### Detect a document's type

Returns the HDF document type, or an empty result when the bytes are not an HDF document:

```ts
import { detect } from '@mitre/hdf-engine';

const docType = detect(bytes); // 'results' | 'baseline' | 'system' | ...
```

```go
import hdfengine "github.com/mitre/hdf-libs/hdf-engine/go/v3"

docType := hdfengine.Detect(data) // "" when not an HDF document
```

### Query requirements

Filter a results document by status, severity, impact, control identifiers, tags or free text. Filters combine with AND; the values within one filter combine with OR:

```ts
import { filter } from '@mitre/hdf-engine';

const matches = filter(results, {
  status: ['failed'],
  severity: ['critical', 'high'],
});
```

```go
matches := hdfengine.Filter(ctx, results, hdfengine.Options{
    Status:   []string{"failed"},
    Severity: []string{"critical", "high"},
})
```

`Tag` matches `key=value` and accepts globs, which is how source-specific data reaches a query without this package knowing the vocabulary of every scanner.

### Roll up compliance

Counts are sliced by status and, within each status, by severity:

```ts
import { countControlsByStatusSeverity, calculateCompliance } from '@mitre/hdf-engine';

const counts = countControlsByStatusSeverity(results);
const pct = calculateCompliance(counts); // passed / (passed+failed+skipped+error) * 100
```

```go
counts := hdfengine.CountControlsByStatusSeverity(results)
pct := hdfengine.CalculateCompliance(counts)
```

`notApplicable` is excluded from the denominator: a requirement that does not apply is not evidence of compliance either way.

### Apply a threshold

A threshold is a policy of bounds over those counts. `validateThresholds` returns one message per breached bound, and an empty list when the document passes:

```ts
import { validateThresholds } from '@mitre/hdf-engine';

const violations = validateThresholds(config, counts, pct, controlMap);
```

```go
violations := hdfengine.ValidateThresholds(config, counts, pct, controlMap)
```

See the [thresholds guide](https://mitre.github.io/hdf-libs/docs/guides/thresholds-workflow) for the file format and how a pipeline gates on it.

### Merge several scans into one view

Combine several results documents into one multi-baseline document — one baseline
per input baseline, renamed `<tool>/<original>`, with each input's provenance kept
verbatim. The semantics are a union: no requirement is deduplicated, re-keyed or
dropped, and the same inputs in the same order always produce the same output.

```go
merged, warnings, err := hdfengine.Merge([]hdfengine.MergeSource{
    {Name: "nessus-scan", Doc: nessusResults},
    {Name: "checkov-scan", Doc: checkovResults},
})
```

The warnings report what the merge could not carry cleanly; they are advisory
rather than failures, so check them rather than assuming a clean pass.

Because `tool` and `generator` are document-root fields, a merged view cannot say
per baseline which scanner produced it — so the merge writes that provenance onto
each baseline's labels instead.

### Verify an evidence package

Parse a package, check the checksums of everything it references, and report whether the plan's baselines are covered:

```go
name, contents, err := hdfengine.ParseEvidencePackage(pkg)
results := hdfengine.VerifyChecksums(contents, fetch)
report := hdfengine.Completeness(planned, covered)
```

The `fetch` function is supplied by the caller, so this package never reads the filesystem or the network itself.

## API

### Detection

- `detect(data)` / `Detect(data)` — the document's type, empty when not HDF
- `KnownTypes()` (Go) — every type detection can return

### Query

- `filter(results, options)` / `Filter(ctx, results, opts)` — matching requirements
- `FilterOptions` / `Options` — `status`, `severity`, `impact`, `cci`, `nist`, `id`, `tag`, `search`, `baseline`, `limit`, `count`, and a `statusOf` hook to override how status is resolved
- `Match` — one result row

### Compliance

- `countControlsByStatusSeverity` / `CountControlsByStatusSeverity` — counts by status and severity
- `countControlsByStatus` / `CountControlsByStatus` — counts with a caller-supplied status resolver
- `calculateCompliance` / `CalculateCompliance` — the percentage
- `deriveSeverity` / `DeriveSeverity` — a requirement's severity, explicit or derived from impact
- `overallStatus` (TypeScript only) — the worst status across a requirement's results; the Go peer is internal to the package
- `mapControlIDs`, `mapControlIDsByStatus` / `MapControlIDs`, `MapControlIDsByStatus` — control id to status/severity
- `agentOverrideCount` / `AgentOverrideCount` — overrides attributed to an agent
- `validateThresholds` / `ValidateThresholds` — threshold verdicts
- `StatusCounts`, `SeverityCounts`, `ControlIDMapping`, `ThresholdConfig`, `ThresholdSeverity`, `ThresholdBound`, `ComplianceBound`

### Merge

- `merge` / `Merge` — combine results documents into one multi-baseline view; the Go form returns the document, warnings and an error, the TypeScript form a `MergeResult`
- `MergeSource` — one input: a results document plus the name it is recorded under

### Loader

- `load(data, maxSize)` / `Load(data, maxSize)` — parse and normalize input
- `detectFormat` (TypeScript only) — the detected input shape; `InputFormat` and `LoadResult` are the accompanying types

### Evidence

- `parseEvidencePackage` / `ParseEvidencePackage` — package name and contents
- `verifyChecksums` / `VerifyChecksums` — per-reference checksum status
- `plannedBaselineRefs`, `coveredBaselineNames`, `coveredBaselinesInPackage` — plan coverage inputs
- `agentOverridesInPackage` / `AgentOverridesInPackage` — agent-attributed overrides across a package
- `completeness` / `Completeness` — planned versus covered
- `ChecksumStatus`, `EvidenceContent`, `ChecksumResult`, `CompletenessResult`, `FetchFn` / `FetchFunc`

### Version

- `engineVersion` (TS) / `Version()` (Go) — the package version, used to stamp generated documents
