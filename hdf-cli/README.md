# hdf CLI

Command-line tool for validating, inspecting, querying, and converting Heimdall Data Format (HDF) files. Part of the [hdf-libs](https://github.com/mitre/hdf-libs) monorepo.

HDF (Heimdall Data Format) is a standardized JSON format for security assessment results. It normalizes outputs from vulnerability scanners, compliance checkers, configuration auditors, and cloud security tools into a unified schema that can be viewed in [Heimdall](https://github.com/mitre/heimdall2).

## Table of Contents

- [Installation](#installation)
- [Terminology](#terminology)
- [Commands](#commands)
  - [validate](#validate) -- Validate an HDF file against the schema
  - [info](#info) -- Display summary information
  - [stats](#stats) -- Display assessment statistics
  - [list](#list) -- List controls, profiles, or targets
  - [query](#query) -- Search and filter controls
  - [convert](#convert) -- Convert between formats
  - [fetch](#fetch) -- Fetch from live APIs
    - [fetch aws-config](#fetch-aws-config) -- AWS Config compliance data
    - [fetch gitlab](#fetch-gitlab) -- GitLab CI/CD security artifacts
    - [fetch sonarqube](#fetch-sonarqube) -- SonarQube issues
    - [fetch splunk](#fetch-splunk) -- Splunk HDF events
  - [version](#version) -- Print version information
- [Global Flags](#global-flags)
- [Supported Conversions](#supported-conversions)
  - [To HDF](#to-hdf)
  - [From HDF](#from-hdf)
- [Credential Handling](#credential-handling)
- [Development](#development)
- [License](#license)

## Installation

Pre-built binaries for macOS, Linux, and Windows are planned. Until then, build from source.

**Requirements:** Go 1.23+

```bash
# From the hdf-libs monorepo root
pnpm install
pnpm build        # builds schema types first, then the hdf binary

# Or build only the CLI
cd hdf-cli
go build -o hdf ./cmd/hdf
```

The binary is written to `hdf-cli/hdf`. Add it to your PATH or invoke it directly.

## Terminology

| Term | Definition |
|------|-----------|
| **HDF** | Heimdall Data Format -- a JSON schema for security assessment data |
| **HDF Results** | An assessed HDF file containing pass/fail results for each requirement |
| **HDF Baseline** | An unassessed HDF file defining security requirements without results |
| **Requirement** | A single security check or control (called "control" in InSpec terminology) |
| **Baseline/Profile** | A named collection of requirements (e.g., "RHEL 8 STIG") |

## Commands

### validate

Validate an HDF results or baseline file against the JSON schema. Returns exit code 0 on success, 1 on failure.

```
USAGE
  hdf validate <file> [flags]

FLAGS
  -t, --type string    Schema type: results or baseline (default "results")
  -q, --quiet          Suppress output on success (exit code only)

EXAMPLES
  hdf validate results.json
  hdf validate baseline.json --type baseline
  hdf validate --json results.json          # machine-readable validation output
  cat results.json | hdf validate -         # read from stdin
  curl -s https://example.com/scan.json | hdf validate
```

### info

Display summary information about an HDF results file: generator tool/version, platform, profile names, target info, and assessment timestamp.

```
USAGE
  hdf info <file> [flags]

EXAMPLES
  hdf info results.json
  hdf info results.json --json
```

### stats

Display pass/fail/error/not-reviewed/not-applicable statistics from an HDF results file.

```
USAGE
  hdf stats <file> [flags]

EXAMPLES
  hdf stats results.json
  hdf stats results.json --json
```

### list

List controls, profiles, or targets from an HDF results file.

```
USAGE
  hdf list <what> <file> [flags]

LIST TYPES
  controls (aliases: control, c)
  profiles (aliases: profile, p)
  targets  (aliases: target, t)

FLAGS
  -s, --status string    Filter by status: passed, failed, error, not_applicable, not_reviewed
  -a, --all              Show all details

EXAMPLES
  hdf list controls results.json
  hdf list controls results.json --status failed
  hdf list profiles results.json
  hdf list targets results.json --json
```

### query

Search and filter controls by status, severity, framework mapping, tags, and free text. Multiple filters combine with AND logic.

```
USAGE
  hdf query <file> [flags]

FLAGS
  -s, --status string      Filter by status: passed, failed, error, not_applicable, not_reviewed
      --severity string    Filter by severity: high, medium, low, none
      --impact string      Filter by impact value (e.g., ">0.5", ">=0.7", "0.5")
      --cci string         Filter by CCI identifier (e.g., CCI-000366)
      --nist string        Filter by NIST control (e.g., AC-2, CM-6*)
      --stig-id string     Filter by STIG rule ID (e.g., V-230221)
  -t, --tag string         Filter by tag key:value (e.g., severity:high)
      --search string      Search in control title and description
  -p, --profile string     Filter by profile name
  -c, --count              Show only the count of matching controls
  -l, --limit int          Limit number of results (0 = unlimited)

EXAMPLES
  hdf query results.json --status failed
  hdf query results.json --status failed --severity high
  hdf query results.json --nist "AC-2"
  hdf query results.json --cci CCI-000366
  hdf query results.json --stig-id V-230221
  hdf query results.json --tag "severity:high"
  hdf query results.json --search "password policy"
  hdf query results.json --impact ">0.5" --status failed
  hdf query results.json --status failed --count
  hdf query results.json --limit 20 --status failed
```

### convert

Convert security assessment data between HDF and other formats. Uses natural language syntax: `convert <source> to <destination>`.

```
USAGE
  hdf convert <src-format> to <dest-format> <input> [output]

INPUT/OUTPUT
  <input>     File path or "-" for stdin
  [output]    File path; defaults to stdout if omitted

EXAMPLES
  hdf convert nessus to hdf scan.nessus results.json
  hdf convert sarif to hdf findings.sarif results.json
  hdf convert gosec to hdf gosec-output.json results.json
  hdf convert grype to hdf grype-output.json results.json
  hdf convert snyk to hdf snyk-output.json results.json
  hdf convert trufflehog to hdf secrets.json results.json
  hdf convert xccdf to hdf xccdf-results.xml results.json
  hdf convert gitlab to hdf gl-sast-report.json results.json
  hdf convert junit to hdf test-results.xml results.json
  hdf convert zap to hdf zap-report.json results.json
  hdf convert legacyhdf to hdf old-scan.json new-scan.json
  hdf convert hdf to csv results.json controls.csv
  hdf convert hdf to xml results.json controls.xml
  cat scan.json | hdf convert sarif to hdf - output.json
```

See [Supported Conversions](#supported-conversions) for the full list.

### fetch

Fetch security data from a live API and convert to HDF in a single step. No intermediate files needed.

All fetch subcommands support `--format raw` to skip HDF conversion and return the tool's native output, and `--output` / `-o` to write to a file instead of stdout.

Credentials are resolved from environment variables or tool-specific config files. See [Credential Handling](#credential-handling).

#### fetch aws-config

Fetch AWS Config compliance evaluation results and convert to HDF.

Credentials are resolved via the standard AWS credential chain: environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`), shared credentials file (`~/.aws/credentials`), or IAM instance role.

```
USAGE
  hdf fetch aws-config [output] [flags]

FLAGS
  -r, --region string     (required) AWS region (e.g., us-east-1)
  -p, --profile string    AWS CLI named profile
      --format string     Output format: hdf or raw (default "hdf")
  -o, --output string     Output file path (default: stdout)

EXAMPLES
  hdf fetch aws-config --region us-east-1 output.json
  hdf fetch aws-config --region us-east-1 --profile my-audit-account output.json
  hdf fetch aws-config --region us-east-1 --format raw | jq '.rules | length'
  hdf fetch aws-config --region us-east-1 | jq '.baselines[0].requirements | length'
```

#### fetch gitlab

Fetch a GitLab CI/CD security scan artifact (SAST, DAST, secret detection, etc.) and convert to HDF.

Token is resolved from: `GITLAB_TOKEN` env var, `GLAB_TOKEN` env var, or glab CLI config (`glab auth login`).

The `--scan-type` flag selects the default artifact filename:

| Scan Type | Default Artifact |
|-----------|-----------------|
| `sast` (default) | `gl-sast-report.json` |
| `dast` | `gl-dast-report.json` |
| `secret-detection` | `gl-secret-detection-report.json` |
| `dependency-scanning` | `gl-dependency-scanning-report.json` |
| `container-scanning` | `gl-container-scanning-report.json` |
| `api-fuzzing` | `gl-api-fuzzing-report.json` |

```
USAGE
  hdf fetch gitlab [output] [flags]

FLAGS
  -u, --url string              GitLab instance URL (default "https://gitlab.com")
      --project string          (required) Project ID or namespace/project path
      --ref string              Branch or tag name (default "main")
      --scan-type string        Scan type (default "sast")
      --artifact-path string    Override default artifact filename
      --job string              (required) CI job name that produced the artifact
      --format string           Output format: hdf or raw (default "hdf")
      --max-response-size int   Max response size in bytes (default 10MB, -1 for no limit)
  -o, --output string           Output file path (default: stdout)

EXAMPLES
  hdf fetch gitlab --project my-org/my-project --job semgrep-sast -o output.json
  hdf fetch gitlab --url http://gitlab.local:9090 --project 42 \
    --scan-type dast --ref develop --job dast -o output.json
  hdf fetch gitlab --project my-org/my-project --job secret_detection \
    --scan-type secret-detection --ref master -o secrets.json
  hdf fetch gitlab --project 42 --job semgrep-sast --format raw | jq '.vulnerabilities | length'
```

#### fetch sonarqube

Fetch SonarQube project issues and convert to HDF.

Token must be set via the `SONARQUBE_TOKEN` environment variable.

```
USAGE
  hdf fetch sonarqube [output] [flags]

FLAGS
  -u, --url string             (required) SonarQube server URL
  -k, --project-key string    (required) SonarQube project key
      --branch string          Branch name
      --pull-request string    Pull request ID
      --organization string    SonarCloud organization key
      --format string          Output format: hdf or raw (default "hdf")
  -o, --output string          Output file path (default: stdout)

NOTE
  --branch and --pull-request are mutually exclusive.

EXAMPLES
  export SONARQUBE_TOKEN=squ_abc123
  hdf fetch sonarqube --url https://sonarqube.example.com --project-key my-project -o output.json
  hdf fetch sonarqube --url https://sonarqube.example.com --project-key my-project \
    --branch develop -o output.json
  hdf fetch sonarqube --url https://sonarqube.example.com --project-key my-project \
    --pull-request 42 -o output.json
```

#### fetch splunk

Fetch HDF evaluation events from a Splunk index and reassemble into an HDF results file.

Token must be set via the `SPLUNK_TOKEN` environment variable.

```
USAGE
  hdf fetch splunk [output] [flags]

FLAGS
  -u, --url string       (required) Splunk server URL
  -i, --index string     (required) Splunk index name
  -g, --guid string      (required) Evaluation GUID to fetch
  -o, --output string    Output file path (default: stdout)

EXAMPLES
  export SPLUNK_TOKEN=your-splunk-token
  hdf fetch splunk --url https://splunk.example.com --index hdf --guid abc123 -o output.json
  hdf fetch splunk --url https://splunk.example.com --index hdf --guid abc123 | jq .
```

### version

Print version, commit hash, build date, and Go version.

```
USAGE
  hdf version [flags]

EXAMPLES
  hdf version
  hdf version --json
```

## Global Flags

These flags apply to all commands.

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--json` | | `false` | Output in JSON format |
| `--no-color` | | `false` | Disable colored output |
| `--debug` | `-d` | `false` | Enable debug output |
| `--max-size` | | `50` | Maximum input file size in MB |
| `--no-follow-symlinks` | | `false` | Refuse to read symlinked files |
| `--schema-dir` | | | Load schemas from a directory instead of the embedded copies |
| `--interactive` | `-i` | `false` | Launch interactive TUI mode |

## Supported Conversions

### To HDF

| Source Format | Aliases | Description |
|--------------|---------|-------------|
| `aws-config` | | AWS Config compliance evaluation results (JSON) |
| `cyclonedx` | | CycloneDX SBOM/VEX (JSON) |
| `gitlab` | `gitlab-sast`, `gitlab-dast` | GitLab CI/CD security scan reports (JSON) |
| `gosec` | | gosec Go security checker (JSON or SARIF) |
| `grype` | | Anchore Grype vulnerability scan (JSON) |
| `junit` | | JUnit XML test results |
| `legacyhdf` | `inspec` | HDF v1.0 (InSpec legacy format) to HDF v2.0 |
| `nessus` | | Tenable Nessus scan results (`.nessus` XML) |
| `nikto` | | Nikto web server scanner (JSON) |
| `sarif` | | SARIF 2.1.0 (Static Analysis Results Interchange Format) |
| `snyk` | | Snyk vulnerability scan (JSON) |
| `sonarqube` | | SonarQube issues export (JSON) |
| `splunk` | | Splunk HDF events (JSON) |
| `trufflehog` | | TruffleHog secret scanner (JSON, NDJSON, or single object) |
| `xccdf` | `arf` | XCCDF/ARF benchmark results (XML) |
| `zap` | | OWASP ZAP web scanner (JSON) |

Tools that support SARIF output (gosec, Snyk, etc.) are automatically detected and routed through the SARIF converter when SARIF input is provided. No special flag is needed.

### From HDF

| Source | Destination | Description |
|--------|-------------|-------------|
| `hdf` | `csv` | Export controls/requirements to CSV |
| `hdf` | `xml` | Export controls/requirements to XML |

## Credential Handling

The `fetch` commands connect to live APIs. Credentials are **never** accepted as CLI flags to prevent exposure in shell history, process listings, and CI logs.

| Service | Environment Variable | Config File Fallback |
|---------|---------------------|---------------------|
| AWS Config | `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY` | `~/.aws/credentials` (via AWS SDK credential chain) |
| GitLab | `GITLAB_TOKEN` or `GLAB_TOKEN` | glab CLI config (`glab auth login`) |
| SonarQube | `SONARQUBE_TOKEN` | None |
| Splunk | `SPLUNK_TOKEN` | None |

For GitLab, the glab CLI config is read from the platform's standard config directory:

| Platform | Config Path |
|----------|------------|
| Linux | `$XDG_CONFIG_HOME/glab-cli/config.yml` (default: `~/.config/glab-cli/`) |
| macOS | `~/Library/Application Support/glab-cli/config.yml` |
| Windows | `%LOCALAPPDATA%\glab-cli\config.yml` |

Override with the `GLAB_CONFIG_DIR` environment variable on any platform.

## Development

See the [monorepo root README](../README.md) and [CLAUDE.md](./CLAUDE.md) for full architecture and contribution guidelines.

### Quick Reference

From the monorepo root:

```bash
pnpm build           # build everything (schema types + hdf binary)
pnpm test            # run all tests (Go + TypeScript)
pnpm lint            # run golangci-lint
```

From within `hdf-cli/` directly:

```bash
go build -o hdf ./cmd/hdf       # build the binary
go test ./... -v                 # run all Go tests
pnpm fmt                        # gofmt -s -w .
pnpm vet                        # go vet ./...
pnpm test:coverage              # coverage report (generates coverage.out)
```

### Adding a New Converter

See the [`/build-converter` skill documentation](./CLAUDE.md) for the full process. In brief:

1. Implement Go converter in `hdf-converters/converters/<name>/go/converter.go`
2. Implement TypeScript converter in `hdf-converters/converters/<name>/typescript/converter.ts`
3. Register CLI integration in `hdf-cli/cmd/hdf/cmd/converter_<name>.go`
4. Add tests for all three layers
5. Source real fixtures from tool output -- never fabricate test data

### Test Fixtures

Command tests (validate, query, list, etc.) load HDF fixtures from `../hdf-schema/test/fixtures/`. Converter tests load format-specific fixtures from `../hdf-converters/converters/{tool}/fixtures/`. Both skip gracefully if the fixture directories are absent.

## License

Apache 2.0 -- Approved for Public Release; Distribution Unlimited. Case Number 18-3678.

Copyright 2024-2026 The MITRE Corporation.
