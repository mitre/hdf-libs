# hdf CLI

Command-line tool for validating, inspecting, querying, and converting Heimdall Data Format (HDF) files.

## Installation

Pre-built binaries for macOS, Linux, and Windows are planned. Until then, build from source.

**Requirements:** Go 1.23+, and the monorepo's npm dependencies for building schemas.

```bash
# From the hdf-libs monorepo root
pnpm install
pnpm build        # builds hdf-schema types first, then the hdf binary
```

The binary is written to `hdf-cli/hdf`. Add it to your PATH or invoke it directly.

## Commands

### validate

Validate an HDF results or baseline file against the JSON schema.

```bash
hdf validate results.json
hdf validate --json results.json     # machine-readable output
```

### info

Display summary information about an HDF results file (version, target count, profile count, control count).

```bash
hdf info results.json
```

### stats

Display pass/fail/error/not-reviewed statistics.

```bash
hdf stats results.json
hdf stats --json results.json
```

### list

List controls, profiles, or targets from an HDF results file.

```bash
hdf list controls results.json
hdf list profiles results.json
hdf list targets results.json
```

### query

Search and filter controls by status, severity, framework mapping, and more.

```bash
hdf query --status failed results.json
hdf query --severity high --status failed results.json
hdf query --nist "AC-2" results.json
hdf query --search "password policy" results.json
hdf query --count --status failed results.json
hdf query --limit 20 --status failed results.json
```

| Flag | Short | Description |
|------|-------|-------------|
| `--status` | `-s` | Filter by status: `passed`, `failed`, `error`, `not_applicable`, `not_reviewed` |
| `--severity` | | Filter by severity: `high`, `medium`, `low`, `none` |
| `--impact` | | Filter by impact value, e.g. `>0.5`, `>=0.7`, `0.5` |
| `--nist` | | Filter by NIST control, e.g. `AC-2`, `CM-6*` |
| `--cci` | | Filter by CCI identifier, e.g. `CCI-000366` |
| `--stig-id` | | Filter by STIG rule ID, e.g. `V-230221` |
| `--tag` | `-t` | Filter by tag, e.g. `severity:high` |
| `--search` | | Search in control title and description |
| `--profile` | `-p` | Filter by profile name |
| `--count` | `-c` | Show only the count of matching controls |
| `--limit` | `-l` | Limit number of results (0 = unlimited) |

### convert

Convert security assessment data between formats.

```bash
hdf convert <src-format> to <dest-format> <input> [output]
```

If output path is omitted, the result is written to stdout.

**Supported conversions:**

| Source | Destination | Description |
|--------|-------------|-------------|
| `nessus` | `hdf` | Nessus `.nessus` XML scan results |
| `sarif` | `hdf` | SARIF (Static Analysis Results Interchange Format) |
| `cyclonedx` | `hdf` | CycloneDX SBOM/VEX JSON |
| `grype` | `hdf` | Grype vulnerability scan JSON |
| `sonarqube` | `hdf` | SonarQube issues JSON export |
| `legacyhdf` | `hdf` | HDF v1.0 to current (v2.0) |
| `hdf` | `csv` | Export HDF controls to CSV |
| `hdf` | `xml` | Export HDF controls to XML |

**Examples:**

```bash
hdf convert nessus to hdf scan.nessus results.json
hdf convert sarif to hdf findings.sarif results.json
hdf convert cyclonedx to hdf bom.json results.json
hdf convert grype to hdf grype-output.json results.json
hdf convert sonarqube to hdf sonar-issues.json results.json
hdf convert legacyhdf to hdf old-scan.json new-scan.json
hdf convert hdf to csv results.json controls.csv
hdf convert hdf to xml results.json controls.xml
```

## Global flags

These flags apply to all commands.

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--json` | | false | Output in JSON format |
| `--no-color` | | false | Disable colored output |
| `--debug` | `-d` | false | Enable debug output |
| `--max-size` | | 50 | Maximum input file size in MB |
| `--no-follow-symlinks` | | false | Refuse to read symlinked files |
| `--schema-dir` | | | Load schemas from a directory instead of the embedded copies |

## Development

See the [monorepo root README](../README.md) for full setup. Quick reference from the monorepo root:

```bash
pnpm build           # build everything (schema types + hdf binary)
pnpm test            # run all tests
pnpm lint            # run golangci-lint
```

From within `hdf-cli/` directly:

```bash
pnpm fmt             # gofmt -s -w .
pnpm vet             # go vet ./...
pnpm test:coverage   # coverage report (generates coverage.out)
```

Command tests (validate, query, list, etc.) load HDF fixtures from `../hdf-schema/test/fixtures/`. Converter tests load format-specific fixtures from `../hdf-converters/converters/{tool}/fixtures/`. Both skip gracefully if the fixture directories are absent.
