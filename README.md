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

### npm libraries

| Package | Description |
|---------|-------------|
| [`@mitre/hdf-schema`](./hdf-schema/README.md) | JSON schemas and generated types for HDF documents |
| [`@mitre/hdf-mappings`](./hdf-mappings/README.md) | CCI, NIST 800-53, CIS, and CMMC framework mappings |
| [`@mitre/hdf-utilities`](./hdf-utilities/README.md) | Generic utilities for XML, CSV, and hash operations |
| [`@mitre/hdf-parsers`](./hdf-parsers/README.md) | Parse and flatten HDF documents |
| [`@mitre/hdf-converters`](./hdf-converters/README.md) | Convert security tool outputs to HDF |
| [`@mitre/hdf-validators`](./hdf-validators/README.md) | Validate HDF documents against schemas |

### CLI tool

| Tool | Description |
|------|-------------|
| [`hdf`](./hdf-cli/README.md) | Command-line tool for validating, querying, and converting HDF files |

## Schema Types

HDF defines two primary document types:

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

## Installation

```bash
npm install @mitre/hdf-schema
```

## Development

This monorepo uses pnpm workspaces. Build order matters because some packages depend on generated types from others.

### Prerequisites

The following tools must be installed before running `pnpm lint` or `pnpm test`:

| Tool | Version | Purpose |
|------|---------|---------|
| [Node.js](https://nodejs.org/) | ≥20.0.0 | TypeScript build and test runner |
| [pnpm](https://pnpm.io/) | ≥9.0.0 | Package manager |
| [Go](https://go.dev/) | 1.25.x | Go packages and CLI tool |
| [git-lfs](https://git-lfs.com/) | latest | Large test fixtures are stored in Git LFS |
| [golangci-lint](https://golangci-lint.run/) | latest | Go linter (required for `pnpm lint`) |
| [gosec](https://github.com/securego/gosec) | latest | Go SAST scanner (required for `pnpm check`) |
| [govulncheck](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck) | latest | Go vulnerability scanner (required for `pnpm check`) |
| [gitleaks](https://github.com/gitleaks/gitleaks) | latest | Secret detection (required for `pnpm check`) |

**macOS (Homebrew):**

```bash
brew install node go git-lfs gitleaks
corepack enable && corepack prepare pnpm@9.14.2 --activate
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
go install github.com/securego/gosec/v2/cmd/gosec@latest
go install golang.org/x/vuln/cmd/govulncheck@latest
```

After cloning, fetch LFS objects:

```bash
git lfs fetch --all && git lfs checkout
```

**Ubuntu / WSL:**

```bash
# Node.js 20.x
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs
corepack enable && corepack prepare pnpm@9.14.2 --activate

# Go 1.23 — check https://go.dev/dl/ for the latest 1.23.x tarball
wget https://go.dev/dl/go1.23.8.linux-amd64.tar.gz
sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.23.8.linux-amd64.tar.gz
echo 'export PATH="$PATH:/usr/local/go/bin"' >> ~/.bashrc && source ~/.bashrc

# golangci-lint, gosec, govulncheck
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
go install github.com/securego/gosec/v2/cmd/gosec@latest
go install golang.org/x/vuln/cmd/govulncheck@latest

# git-lfs and gitleaks
sudo apt-get install -y git-lfs
brew install gitleaks  # or download from GitHub releases
git lfs fetch --all && git lfs checkout
```

**Windows (native):**

```powershell
# Node.js and Go — use winget or download installers from nodejs.org / go.dev
winget install OpenJS.NodeJS.LTS
winget install GoLang.Go

# pnpm
corepack enable && corepack prepare pnpm@9.14.2 --activate

# Go tools (restart your terminal after installing Go)
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
go install github.com/securego/gosec/v2/cmd/gosec@latest
go install golang.org/x/vuln/cmd/govulncheck@latest

# gitleaks and git-lfs
winget install Gitleaks.Gitleaks
winget install GitHub.GitLFS
git lfs fetch --all && git lfs checkout
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

# Build Go CLI only (requires Go 1.23+)
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
