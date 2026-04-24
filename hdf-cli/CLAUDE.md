# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`hdf-cli` is a Go CLI tool for working with Heimdall Data Format (HDF) files — a standardized format for security assessment results. It supports validation, conversion, querying, and display of HDF compliance data.

## Build & Development Commands

Build tasks are run via `pnpm`. The Go binary is the only artifact.

```bash
pnpm build           # Compile Go binary (go build -o hdf ./cmd/hdf)
pnpm build:release   # Build with version info embedded (git tag, commit, timestamp)
pnpm clean           # Remove binary and coverage files
```

Schema validation is provided by `hdf-validators/go` via `//go:embed` — no schema copying step is needed. The `go.mod` `replace` directive points at `../hdf-validators/go`.

## Testing

Test fixtures are loaded from `../hdf-schema/test/fixtures/` (sibling monorepo package). Tests skip gracefully if fixtures are missing.

```bash
pnpm test                  # go test ./...
pnpm test:verbose          # go test -v ./...
pnpm test:coverage         # Coverage analysis (generates coverage.out)

# Run a single test
go test -run TestQueryFoo ./cmd/hdf/cmd/

# Run a specific package
go test ./cmd/hdf/cmd/
```

## Linting & Quality Checks

```bash
pnpm fmt              # gofmt -s -w . (format in place)
pnpm fmt:check        # gofmt -l . (check without modifying)
pnpm lint             # golangci-lint run (39 linters enabled)
pnpm lint:fix         # golangci-lint run --fix
pnpm vet              # go vet ./...
pnpm security         # gosec + govulncheck + gitleaks
pnpm check            # fmt:check + lint + test + security (full local CI)
```

Linting thresholds (`.golangci.yml`): `gocyclo` min-complexity 20, `gocognit` min-complexity 40, `dupl` threshold 100 lines. Generated files (`hdf_results.go`, `hdf_baseline.go`) are excluded from most linters.

## Architecture

### Command Layer (`cmd/hdf/cmd/`)

Built on [Cobra](https://github.com/spf13/cobra). Each command is in its own file. The root command defines persistent flags (`--json`, `--no-color`, `--debug`, `--max-size`, `--no-follow-symlinks`, `--schema-dir`).

Commands: `validate`, `info`, `stats`, `list`, `query`, `version`, `convert`.

### Input Handling (`input.go`)

Security-gated pipeline for all file/stdin reading:
1. File size check (default 50MB, `--max-size`)
2. Symlink detection (`--no-follow-symlinks`)
3. Regular file validation
4. **Schema validation before JSON parsing** (gatekeeper pattern using `xeipuuv/gojsonschema`)
5. JSON decode + trailing garbage check

Both `parseHDFResults()` and `parseHDFBaseline()` follow this pipeline. Schema validation always runs first — never skip it.

### Converter System (`converter_registry.go`, `converter_*.go`)

Pluggable registry pattern:
```go
type Converter interface {
    Convert(input []byte) ([]byte, error)
    Name() string
}
// Registered by format pair (source → dest)
RegisterConverter(source, dest, converter)
GetConverter(source, dest) (Converter, error)
```

Converters are implemented in separate files (`converter_nessus.go`, `converter_sarif.go`, etc.) and registered in `init()` or at startup via `converter_registry.go`. When adding a new converter, register it in the registry and add a corresponding subcommand in `convert.go`.

Conversion error messages include suggestions (which sources support the target format, which targets the source supports) — preserve this UX pattern.

### Data Types

Go types are imported from `github.com/mitre/hdf-libs/hdf-schema/dist/go/v3` (quicktype-generated from the JSON schemas in `hdf-schema/dist/go/`). The CLI does not maintain its own copy of these types. The diff engine lives in `github.com/mitre/hdf-libs/hdf-diff/go/v3` (sibling monorepo package).

### Schema Validation (`hdf-validators/go`)

Schema validation is provided by the sibling `hdf-validators/go` package (imported as `validators`). Schemas are embedded at compile time via `//go:embed` inside that package. In dev mode (`--schema-dir`), `validators.SetSchemaDir()` redirects to disk. Do not add a local `pkg/schema/` package — it was removed as a duplicate.

### Query Engine (`query.go`)

Filters controls using AND logic across: `--status`, `--severity`, `--impact`, `--cci`, `--nist`, `--stig-id`, `--tag`, `--search`, `--profile`. `safematch.go` provides panic-safe regex matching used throughout the query layer.

## Monorepo Context

This package lives in the `hdf-libs` monorepo. Key sibling packages (referenced via `go.mod` `replace` directives):
- `../hdf-schema` — JSON schemas and generated Go types
- `../hdf-validators/go` — Validation service
- `../hdf-converters` — Core conversion logic (CLI wraps this)
- `../hdf-mappings/go` — Data mappings for converters
