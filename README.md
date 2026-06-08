# HDF Libraries

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
| [`hdf-schema`](./hdf-schema/README.md) | JSON schemas and generated TypeScript/Go types for all 7 HDF document types |
| [`hdf-converters`](./hdf-converters/README.md) | 33 security tool format converters (Nessus, XCCDF, OSCAL, SARIF, Grype, etc.) |
| [`hdf-validators`](./hdf-validators/README.md) | Schema validation for all 7 HDF document types with embedded schemas |
| [`hdf-parsers`](./hdf-parsers/README.md) | Parse and flatten HDF documents |
| [`hdf-mappings`](./hdf-mappings/README.md) | CCI, NIST 800-53, CWE, OWASP, and tool-specific control mappings |
| [`hdf-utilities`](./hdf-utilities/README.md) | XML, CSV, JSON parsing, SHA-256/SHA-512 hashing, string helpers |
| [`hdf-generators`](./hdf-generators/README.md) | Generate InSpec profiles from HDF baselines or XCCDF benchmarks |
| [`hdf-diff`](./hdf-diff/README.md) | Structural diff engine for HDF results, baselines, and systems |
| [`hdf-extension-graph`](./hdf-extension-graph/README.md) | InSpec overlay/extension chain resolution (TypeScript only) |
| [`hdf-cli`](./hdf-cli/README.md) | Command-line tool wrapping all of the above — convert, validate, query, diff, amend |
| [`hdf-fixtures`](./hdf-fixtures/README.md) | Shared real-world HDF test data (internal; not published — used by cross-package tests in this monorepo) |

## Schema Types

HDF defines seven document types (all JSON Schema 2020-12):

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
Differential analysis between HDF documents (results, baselines, or systems). Produced by the hdf-diff library. All schemas are at v3.2.0.

## Installation

Install only the packages you need. Each package is published independently to npm and as a Go module.

| Package | npm | Go |
|---------|-----|----|
| **Schema** — HDF document types and JSON schemas | `npm install @mitre/hdf-schema` | `go get github.com/mitre/hdf-libs/hdf-schema/dist/go/v3` |
| **Converters** — 33 security tool format converters | `npm install @mitre/hdf-converters` | `go get github.com/mitre/hdf-libs/hdf-converters/v3` |
| **Validators** — schema validation with embedded schemas | `npm install @mitre/hdf-validators` | `go get github.com/mitre/hdf-libs/hdf-validators/go/v3` |
| **Parsers** — parse and flatten HDF documents | `npm install @mitre/hdf-parsers` | `go get github.com/mitre/hdf-libs/hdf-parsers/go/v3` |
| **Mappings** — CCI, NIST, CWE, OWASP control mappings | `npm install @mitre/hdf-mappings` | `go get github.com/mitre/hdf-libs/hdf-mappings/go/v3` |
| **Utilities** — XML, CSV, hash, string helpers | `npm install @mitre/hdf-utilities` | `go get github.com/mitre/hdf-libs/hdf-utilities/go/v3` |
| **Generators** — InSpec profile generation from baselines | `npm install @mitre/hdf-generators` | `go get github.com/mitre/hdf-libs/hdf-generators/go/v3` |
| **Diff** — structural diff engine for assessments | `npm install @mitre/hdf-diff` | `go get github.com/mitre/hdf-libs/hdf-diff/go/v3` |
| **Extension Graph** — InSpec overlay/extension chain resolution | `npm install @mitre/hdf-extension-graph` | — |

The npm packages declare their dependencies, so `npm install @mitre/hdf-converters` automatically pulls in schema, parsers, utilities, and mappings.

The **CLI** is distributed as pre-built binaries — see [hdf-cli](./hdf-cli/README.md) for installation.

## Development

This monorepo uses pnpm workspaces. Build order matters because some packages depend on generated types from others.

### Prerequisites

The following tools must be installed before running `pnpm lint` or `pnpm test`:

| Tool | Version | Purpose |
|------|---------|---------|
| [Node.js](https://nodejs.org/) | ≥22.0.0 | TypeScript build and test runner |
| [pnpm](https://pnpm.io/) | ≥9.0.0 | Package manager |
| [Go](https://go.dev/) | 1.26.x | Go packages and CLI tool |
| [golangci-lint](https://golangci-lint.run/) | latest | Go linter (required for `pnpm lint`) |
| [gosec](https://github.com/securego/gosec) | latest | Go SAST scanner (required for `pnpm check`) |
| [govulncheck](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck) | latest | Go vulnerability scanner (required for `pnpm check`) |
| [gitleaks](https://github.com/gitleaks/gitleaks) | latest | Secret detection (required for `pnpm check`) |

**macOS (Homebrew):**

```bash
brew install node go gitleaks
corepack enable && corepack prepare pnpm@9.14.2 --activate
go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
go install github.com/securego/gosec/v2/cmd/gosec@latest
go install golang.org/x/vuln/cmd/govulncheck@latest
```

**Ubuntu / WSL:**

```bash
# Node.js 22.x
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
sudo apt-get install -y nodejs
corepack enable && corepack prepare pnpm@9.14.2 --activate

# Go 1.26 — check https://go.dev/dl/ for the latest 1.26.x tarball
wget https://go.dev/dl/go1.26.0.linux-amd64.tar.gz
sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.26.0.linux-amd64.tar.gz
echo 'export PATH="$PATH:/usr/local/go/bin"' >> ~/.bashrc && source ~/.bashrc

# golangci-lint, gosec, govulncheck
go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
go install github.com/securego/gosec/v2/cmd/gosec@latest
go install golang.org/x/vuln/cmd/govulncheck@latest

# gitleaks
brew install gitleaks  # or download from GitHub releases
```

**Windows (native):**

```powershell
# Node.js and Go — use winget or download installers from nodejs.org / go.dev
winget install OpenJS.NodeJS.LTS
winget install GoLang.Go

# pnpm
corepack enable && corepack prepare pnpm@9.14.2 --activate

# Go tools (restart your terminal after installing Go)
go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
go install github.com/securego/gosec/v2/cmd/gosec@latest
go install golang.org/x/vuln/cmd/govulncheck@latest

# gitleaks
winget install Gitleaks.Gitleaks
```

Ensure `%USERPROFILE%\go\bin` is on your PATH (the Go installer usually adds this, but `go install` binaries land here).

After installing golangci-lint, ensure `$HOME/go/bin` is on your PATH. Add the following to your shell profile (`.zshrc`, `.bashrc`, etc.):

```bash
export PATH="$PATH:$HOME/go/bin"
```

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

# Build Go CLI only (requires Go 1.26+)
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
