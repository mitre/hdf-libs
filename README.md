# HDF Libraries

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/mitre/hdf-libs/badge)](https://scorecard.dev/viewer/?uri=github.com/mitre/hdf-libs)

**Heimdall Data Format (HDF)** is a standardized JSON schema for representing security assessment baselines and results across diverse tools and platforms.

## Overview

Security teams use many different tools—vulnerability scanners, compliance checkers, configuration auditors, cloud security posture managers—each producing results in its own format. HDF provides a common data model that normalizes these outputs, enabling:

- **Unified dashboards** across all security tools
- **Consistent metrics** regardless of data source
- **Interoperability** between security platforms
- **Historical analysis** with a stable schema

## Quick navigation

| I want to... | Start here |
|---|---|
| Convert or validate a security scan file | [hdf-cli →](./hdf-cli/README.md) |
| Use the HDF schema or types in my project | [hdf-schema →](./hdf-schema/README.md) |
| Contribute code or add a converter | [CONTRIBUTING.md →](./CONTRIBUTING.md) |
| Set up the development environment | [Development →](#development) |

## Packages

All libraries are available for both TypeScript (npm) and Go. See [Installation](#installation) for install commands.

| Package | Description |
|---------|-------------|
| [`hdf-schema`](./hdf-schema/README.md) | JSON schemas and generated TypeScript/Go types for all 8 HDF document types |
| [`hdf-converters`](./hdf-converters/README.md) | 40+ security tool format converters (Nessus, XCCDF, OSCAL, SARIF, Grype, etc.) |
| [`hdf-validators`](./hdf-validators/README.md) | Schema validation for all 8 HDF document types with embedded schemas |
| [`hdf-parsers`](./hdf-parsers/README.md) | Parse and flatten HDF documents |
| [`hdf-mappings`](./hdf-mappings/README.md) | CCI, NIST 800-53, CWE, OWASP, and tool-specific control mappings |
| [`hdf-utilities`](./hdf-utilities/README.md) | XML, CSV, JSON parsing, SHA-256/SHA-512 hashing, string helpers |
| [`hdf-generators`](./hdf-generators/README.md) | Generate InSpec profiles from HDF baselines or XCCDF benchmarks |
| [`hdf-diff`](./hdf-diff/README.md) | Structural diff engine for HDF results, baselines, and systems |
| [`hdf-engine`](./hdf-engine/README.md) | Schema-typed read-side engines — document detection, query/filtering, compliance rollups |
| [`hdf-extension-graph`](./hdf-extension-graph/README.md) | InSpec overlay/extension chain resolution |
| [`hdf-cli`](./hdf-cli/README.md) | Command-line tool wrapping all of the above — convert, validate, query, diff, amend |
| [`hdf-openapi`](./hdf-openapi/README.md) | OpenAPI 3.1 components generated from the schema bundles, with a measured tooling-compatibility matrix |
| [`hdf-fixtures`](./hdf-fixtures/README.md) | Shared real-world HDF test data, used by cross-package tests here and published so consumers can test against the same corpus |

## Schema Types

HDF defines eight document types (all JSON Schema 2020-12): seven assessment documents plus a continuous-monitoring change-event stream.

### HDF Results
Assessment results from running security checks against a target system. Contains:
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

### HDF System
Authorization boundary definition for a system. Contains:
- Components (hosts, cloud accounts, container images, etc.)
- Data flows between components
- Control designations (common, hybrid, system-specific)

### HDF Plan
Assessment plan linking baselines to system components. Defines which baselines apply to which parts of the system and under what schedule.

### HDF Amendments
Waivers, attestations, and plans of action & milestones (POA&Ms). Captures risk acceptance decisions and remediation timelines.

### HDF Evidence Package
Bundle of references to all related HDF documents for a complete assessment record. Links results, baselines, system definitions, plans, and amendments.

### HDF Comparison
Differential analysis between HDF documents (results, baselines, or systems). Produced by the hdf-diff library.

### HDF Requirement Change Event
A continuous-monitoring stream of per-requirement change events (`new`, `absent`, `updated`, `fixed`, `regressed`) derived between two results scans. Each event carries the full after-state and a thin before-state, chained by per-key sequence so a reconciled results document can be replayed from a seed. Produced by `hdf events derive` and the hdf-diff kernel.

All schemas are at v3.8.0.

## Installation

Install only the packages you need. Each package is published independently to npm and as a Go module.

| Package | npm | Go |
|---------|-----|----|
| **Schema** — HDF document types and JSON schemas | `npm install @mitre/hdf-schema` | `go get github.com/mitre/hdf-libs/hdf-schema/dist/go/v3` |
| **Converters** — 40+ security tool format converters | `npm install @mitre/hdf-converters@stable` | `go get github.com/mitre/hdf-libs/hdf-converters/v3` |
| **Validators** — schema validation with embedded schemas | `npm install @mitre/hdf-validators` | `go get github.com/mitre/hdf-libs/hdf-validators/go/v3` |
| **Parsers** — parse and flatten HDF documents | `npm install @mitre/hdf-parsers` | `go get github.com/mitre/hdf-libs/hdf-parsers/go/v3` |
| **Mappings** — CCI, NIST, CWE, OWASP control mappings | `npm install @mitre/hdf-mappings` | `go get github.com/mitre/hdf-libs/hdf-mappings/go/v3` |
| **Utilities** — XML, CSV, hash, string helpers | `npm install @mitre/hdf-utilities` | `go get github.com/mitre/hdf-libs/hdf-utilities/go/v3` |
| **Generators** — InSpec profile generation from baselines | `npm install @mitre/hdf-generators` | `go get github.com/mitre/hdf-libs/hdf-generators/go/v3` |
| **Diff** — structural diff engine for assessments | `npm install @mitre/hdf-diff` | `go get github.com/mitre/hdf-libs/hdf-diff/go/v3` |
| **Engine** — schema-typed read-side engines (detect, query, compliance) | `npm install @mitre/hdf-engine` | `go get github.com/mitre/hdf-libs/hdf-engine/go/v3` |
| **Extension Graph** — InSpec overlay/extension chain resolution | `npm install @mitre/hdf-extension-graph` | `go get github.com/mitre/hdf-libs/hdf-extension-graph/go/v3` |

The npm packages declare their dependencies, so `npm install @mitre/hdf-converters@stable` automatically pulls in schema, parsers, utilities, and mappings. Note the explicit `@stable`: the `@mitre/hdf-converters` npm name is shared with [heimdall2](https://github.com/mitre/heimdall2), whose v2 line owns the `latest` dist-tag — install this repo's v3 line via `@stable` or an exact version. The `@next` channel follows automatically published snapshots of main; see [main snapshots](site/docs/contributing/main-snapshots.md).

The **CLI** is distributed as pre-built binaries — see [hdf-cli](./hdf-cli/README.md) for installation.

## Development

This monorepo uses pnpm workspaces. Build order matters because some packages depend on generated types from others.

### Prerequisites

Install [mise](https://mise.jdx.dev/) 2026.10.9 or newer. It installs the pinned toolchain from `mise.toml` and `mise.lock`, the same releases CI and the pre-commit hook use:

| Tool | Pinned in |
|------|-----------|
| Node.js | `mise.toml` (the Active LTS line); exact release in `mise.lock` |
| pnpm | `packageManager` in `package.json` |
| Go | the `go` line of `go.work` |
| golangci-lint, gosec, govulncheck | `mise.toml` |
| actionlint, shellcheck | `mise.toml` |

Each download is checked against the checksum recorded in `mise.lock`. [gitleaks](https://github.com/gitleaks/gitleaks), used by `pnpm --filter hdf-cli security`, is installed separately.

**macOS and Linux:**

```bash
curl -fsSL https://mise.run | sh   # or: brew install mise
mise trust && mise install
```

**Windows (PowerShell):**

```powershell
irm https://mise.run/powershell | iex   # or: winget install jdx.mise
mise trust; mise install
```

Corepack is not needed: mise installs pnpm itself, and Node.js no longer ships Corepack from version 25. The pre-commit hook runs `mise exec -- pnpm check`, so it uses the pinned tools whether or not mise is activated in your shell; activate mise (`mise activate`, see its [shell setup](https://mise.jdx.dev/installing-mise.html)) to get the same versions in your own commands. The [developer guide](site/docs/contributing/developer-guide.md#toolchain) explains how the pins are verified and moved.

See [CONTRIBUTING.md](./CONTRIBUTING.md) for the PR process, coverage requirements, and how to add a converter.

### Setup

```bash
pnpm install
```

### Building

Build scripts are split by language so consumers can build only what they need:

```bash
# Build everything (TypeScript + Go)
pnpm build

# Build TypeScript packages only (no Go required)
pnpm build:ts

# Build Go CLI only (requires Go 1.27.3+)
pnpm build:go
```

`build:ts` handles dependency ordering automatically — hdf-schema is built first since other packages depend on its generated types.

**Submodule consumers** that only need the npm packages should use `pnpm build:ts`. Go is not required.

### Linting

Linting requires packages to be built first (especially for hdf-cli):

```bash
pnpm build
pnpm lint
```

### Testing

`pnpm test` automatically builds hdf-schema before running tests.

```bash
# All tests (TypeScript + Go)
pnpm test

# TypeScript tests only
pnpm test:ts

# Go tests only
pnpm test:go
```
