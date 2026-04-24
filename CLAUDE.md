# CLAUDE.md

Project context for Claude Code and human developers working in this repository.

## Quick Start

```bash
pnpm install          # Install all dependencies
pnpm build            # Build TS + Go
pnpm test             # Run all tests (TS + Go)
pnpm check            # Full CI gate: build + lint + test + security
pnpm lint             # ESLint (TS) + golangci-lint (Go)
pnpm security         # pnpm audit + govulncheck
```

## Monorepo Layout

pnpm workspace with 10 packages + a VitePress schema documentation site:

| Package | Purpose | Language |
|---------|---------|----------|
| `hdf-schema` | 7 JSON schemas + TS/Go/Python type generation | TS |
| `hdf-utilities` | XML, CSV, hash, string helpers | TS |
| `hdf-mappings` | CCI, NIST, CWE, OWASP control mappings | TS + Go |
| `hdf-validators` | Schema validation with embedded schemas | TS + Go |
| `hdf-parsers` | Parse and flatten HDF documents | TS + Go |
| `hdf-converters` | 33 security tool converters (dual TS + Go) | TS + Go |
| `hdf-generators` | Generate InSpec profiles from baselines | TS + Go |
| `hdf-diff` | Structural diff engine for assessments | TS |
| `hdf-extension-graph` | InSpec overlay/extension chain resolution | TS |
| `hdf-cli` | Go CLI wrapping all of the above | Go |
| `site/` | VitePress schema reference site for GitHub Pages | TS |

## Key Commands

### Per-package testing
```bash
cd hdf-converters && pnpm test:ts           # TS converter tests
cd hdf-converters && go test ./...           # Go converter tests
cd hdf-cli && go test ./cmd/hdf/cmd/ -run TestQuery -v  # Single CLI test
cd hdf-schema && pnpm test                  # Schema validation tests (rebuilds first)
```

### Go linting
```bash
cd hdf-cli && golangci-lint run             # 39 linters enabled
cd hdf-cli && golangci-lint run --fix       # Auto-fix
```

### Schema workflow
```bash
cd hdf-schema && pnpm build:schemas         # Bundle source → dist schemas
cd hdf-schema && pnpm build                 # Bundle + generate TS/Go/Python types
cp hdf-schema/dist/schemas/*.schema.json hdf-validators/go/schemas/  # Sync validators
```

### VitePress schema site
```bash
cd site && pnpm generate && pnpm exec vitepress dev  # Local preview
```

## Schema Architecture

7 document types, all JSON Schema 2020-12:

- **hdf-results** — Assessment findings (the primary converter output)
- **hdf-baseline** — Requirement definitions without results
- **hdf-system** — Authorization boundary, components, data flows, control designations
- **hdf-plan** — Assessment plan linking baselines to components
- **hdf-amendments** — Waivers, attestations, POA&Ms
- **hdf-evidence-package** — Bundle of references to all documents
- **hdf-comparison** — Differential analysis (v1.0.0; others are v2.0.0)

Source schemas: `hdf-schema/src/schemas/` (modular, with `primitives/` subdirectory)
Bundled schemas: `hdf-schema/dist/schemas/` (self-contained, all `$ref`s embedded)
Hosted at: `https://mitre.github.io/hdf-libs/schemas/`

### Key schema fields
- `components[]` — polymorphic array (11 types: host, containerImage, cloudAccount, etc.) with UUID `componentId`
- `tool` — source security tool metadata (name, version, format). Aligns with SARIF/OSCAL/CycloneDX.
- `generator` — converter that produced the HDF file (required: name + version)
- `integrity` — root-level hash + optional signature (Integrity type)
- `baselines[].resultsChecksum` / `originalChecksum` — per-baseline checksums (Checksum type)
- `disposition` — Override_Type of the governing non-expired override (waiver, falsePositive, riskAdjustment, etc.)
- `effectiveStatus` — Result_Status after overrides (passed, failed, notApplicable, notReviewed, error)
- `effectiveImpact` — impact score (0.0–1.0) after impact overrides

### Schema examples convention
When adding or modifying a `$defs` type in the schema source files, always add or update the `examples` array on the definition. Examples should:
- Use realistic data (real STIG IDs, plausible CVEs, genuine tool output patterns)
- Include a `$comment` field explaining what the example demonstrates
- Cover the key usage patterns and edge cases (e.g., both compliance-scan and CVE-scan false positives)
- Be valid against the schema — the bundler includes them in dist, and consumers see them in IDE tooltips

See `Evaluated_Requirement` in `hdf-results.schema.json` for the model to follow.

## Converter Pattern

Each converter exists in both TypeScript and Go with shared test fixtures:

```
hdf-converters/converters/<name>/
├── typescript/converter.ts      # TS implementation
├── typescript/converter.test.ts # TS tests
├── go/converter.go              # Go implementation
├── go/converter_test.go         # Go tests
├── fixtures/input/              # Source tool output (real data)
└── fixtures/expected/           # Expected HDF output (schema-validated)
```

### Shared helpers
- **Go**: `shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"` — `BuildHDFResults()`, `SeverityToImpact()`, `ValidateJSONSize()`, `LimitSliceWithWarning()`, `MapCWEToNIST()`
- **TS**: `converterutil.ts` — `buildHdfResults()`, `inputChecksum()`, `validateInputSize()`, `mapCWEToNIST()`, `limitArrayWithWarning()`

### CLI integration
Every converter registers in `hdf-cli/cmd/hdf/cmd/converter_registry.go` via `registerHDFConverter()`. CLI thin wrappers live in `converter_<name>.go`.

## Go Module Structure

Multiple Go modules in the monorepo with `replace` directives for local development. Replace directives are ignored by consumers (`go get`) — this is the standard pattern (OpenTelemetry, gRPC-Go).

`go install` does not work with replace directives — CLI is distributed as pre-built binaries via goreleaser.

## Pre-commit Hook

`.husky/pre-commit` runs `pnpm check` (build + lint + test + security). This is the full CI gate. If it fails, fix the issue — do not bypass with `--no-verify` unless batching commits with no code changes between them.

## Security Requirements

- All converters must call `ValidateJSONSize` / `ValidateXMLInput` as first operation
- XML converters must check for entity expansion (`ValidateXMLInput` handles this)
- File paths from JSON must be validated with `safePath()` (evidence_verify, generators)
- No secrets in code; test tokens annotated with `//nolint:gosec`

## Adding a New Converter

Use the `/build-converter` skill (`.claude/commands/build-converter.md`) — it walks through the full process: research → fixtures → TDD tests → Go + TS implementation → CLI integration → verification. This is the most common development task in this repo.

Quick reference: `hdf convert <file> -o <output>` (auto-detects format) or `hdf convert --from nessus <file> -o <output>`

## Fixture Integrity

Never fabricate fixture data. Every fixture must be real tool output, copied from heimdall2/SAF CLI, or validated against the format's official schema.
