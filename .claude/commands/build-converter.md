---
description: Build a new HDF converter end-to-end following hdf-libs monorepo patterns. Use when asked to implement a new converter (e.g. "add a foo-to-hdf converter").
allowed-tools: Read, Glob, Grep, Bash, Edit, Write
---

Build the `$ARGUMENTS` converter end-to-end per the workflow and patterns below. Follow TDD: write tests and fixtures before implementation. Do not consider the converter done until CLI integration is complete and passing.

---

## Monorepo Layout

```
hdf-converters/converters/<name>/
  go/
    converter.go          # Implementation
    converter_test.go     # Unit tests
  fixtures/
    input/                # Source format samples (minimal.*, real.*, edge cases)
    output/               # Expected HDF JSON output (optional; prefer assertion-based tests)

hdf-cli/cmd/hdf/cmd/
  converter_<snake>.go    # CLI registration (wraps hdf-converters impl)
  converter_<snake>_test.go
```

Converter name conventions:
- Directory: `{source}-to-hdf` or `hdf-to-{dest}` (kebab-case)
- Go package: short, no hyphens (e.g. `package nessus`, `package hdftocsv`)
- CLI snake: hyphens → underscores (e.g. `nessus-to-hdf` → `converter_nessus.go`)

---

## Step 1 — Understand the Source Format

Before writing any code:
1. Read sample input files if the user provides them; otherwise ask.
2. Identify: What maps to `Requirement.ID`? What maps to `Impact`? What maps to `Status`? What maps to NIST tags?
3. Sketch the struct types needed to parse the source format.

---

## Step 2 — Source Real Fixtures

**Never fabricate fixture data.** Fixtures must come from one of:
1. Real tool output captured from an actual run
2. The heimdall2 repo at `~/repos/heimdall2/libs/hdf-converters/test/sample_input_report/`
3. The SAF CLI repo at `~/repos/saf/test/sample_data/`
4. Sanitized/anonymized copies of real customer data

Before writing any fixtures, check both repos:
```bash
ls ~/repos/heimdall2/libs/hdf-converters/test/sample_input_report/
ls ~/repos/saf/test/sample_data/
```

Also read the heimdall2 converter source to understand what input format it actually expects — the original converter may use live SDK calls rather than a static file, which changes the design significantly.

**If the source tool has no static export format** (the heimdall2 converter calls a live API directly), this converter requires two modes:
1. **File mode** — define a static JSON format that mirrors the API response, document how users produce it (e.g. `aws configservice describe-config-rules`), implement the converter against that format
2. **Live fetch mode** — implement a fetcher in `hdf-cli/internal/fetchers/<name>.go` that calls the API, marshals to the same static format, and hands bytes to the existing converter

See "Step 5b — Live Fetch Mode" below for details.

**For file-mode on API-pull converters:** the static format you define is the schema your fixtures must conform to. Before writing any fixtures, verify the format against the tool's real API response documentation or the heimdall2 source. Do not invent field names or nesting — if you don't have confirmed API response documentation, stop and ask. A fixture that doesn't match the real schema is worse than no fixture: it validates the wrong thing and will silently diverge from real data.

Copy or adapt real samples. Keep them small by truncating arrays, but preserve the real field names, types, and nesting. Name them descriptively (`minimal.<ext>`, `real.<ext>`, `edge-case.<ext>`).

---

## Step 3 — Write Unit Tests First (TDD)

File: `hdf-converters/converters/<name>/go/converter_test.go`

```go
package <pkg>

import (
    "os"
    "path/filepath"
    "testing"

    hdf "github.com/mitre/hdf-schema"
    shared "github.com/mitre/hdf-converters/shared/go"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

const converterVersion = "0.1.0"

func TestConvert_Minimal(t *testing.T) {
    inputPath := filepath.Join(shared.GetConvertersDir(), "<name>", "fixtures", "input", "minimal.<ext>")
    inputData, err := os.ReadFile(inputPath)
    require.NoError(t, err)

    result, err := Convert<Name>(inputData, converterVersion)
    require.NoError(t, err)
    require.NotNil(t, result)

    assert.Equal(t, "hdf-converters", result.Generator.Name)
    assert.Equal(t, converterVersion, result.Generator.Version)
    assert.Len(t, result.Baselines, 1)
    // ... assert specific field values from your fixture
}

func TestConvert_InvalidInput(t *testing.T) {
    _, err := Convert<Name>([]byte("not valid"), converterVersion)
    assert.Error(t, err)
}

func TestConvert_EmptyInput(t *testing.T) {
    _, err := Convert<Name>([]byte(""), converterVersion)
    assert.Error(t, err)
}
```

Also test individual helper functions directly — each private helper should have its own test cases covering boundary values, nil inputs, and error paths.

---

## Step 4 — Implement the Converter

File: `hdf-converters/converters/<name>/go/converter.go`

```go
package <pkg>

import (
    "crypto/sha256"
    "encoding/hex"
    "fmt"
    "time"

    hdf "github.com/mitre/hdf-schema"
)

// Convert<Name> converts <Source> to HDF format.
func Convert<Name>(input []byte, converterVersion string) (*hdf.HDFResults, error) {
    hash := sha256.Sum256(input)
    checksum := &hdf.Checksum{
        Algorithm: hdf.Sha256,
        Value:     hex.EncodeToString(hash[:]),
    }

    // ... parse input, build baselines, targets

    return &hdf.HDFResults{
        Generator: hdf.Generator{
            Name:    "hdf-converters",
            Version: converterVersion,
        },
        Baselines:  baselines,
        Targets:    targets,
        Statistics: hdf.Statistics{Duration: duration},
        Timestamp:  time.Now().UTC().Format(time.RFC3339),
    }, nil
}
```

### HDF Type Reference

```go
hdf.HDFResults           // Top-level: Generator, Baselines, Targets, Statistics, Timestamp
hdf.EvaluatedBaseline    // Name, Version, Title, Maintainer, Requirements, Checksum, Groups, Supports, Attributes
hdf.EvaluatedRequirement // ID, Title, Descriptions, Impact, Tags, SourceLocation, Results
hdf.RequirementResult    // Status (*hdf.ResultStatus), CodeDesc, StartTime, Message, RunTime
hdf.Target               // Name, Type, FQDN, IPAddresses, MACAddresses, CloudProvider

// Result status constants
hdf.Passed        hdf.ResultStatus = "passed"
hdf.Failed        hdf.ResultStatus = "failed"
hdf.Error         hdf.ResultStatus = "error"
hdf.NotApplicable hdf.ResultStatus = "notApplicable"
hdf.NotReviewed   hdf.ResultStatus = "notReviewed"

// Checksum algorithms
hdf.Sha256  hdf.ChecksumAlgorithm = "sha256"
hdf.Sha512  hdf.ChecksumAlgorithm = "sha512"
hdf.Md5     hdf.ChecksumAlgorithm = "md5"
```

### Standard Impact Mapping (use heimdall2 values)

```go
var impactMap = map[string]float64{
    "critical": 1.0,
    "high":     0.7,
    "medium":   0.5,
    "low":      0.3,
    "info":     0.0,
    "none":     0.0,
}
```

### NIST / CCI Tags

Use the mappings packages when the source format provides NIST or CCI references:
```go
import "github.com/mitre/hdf-mappings/go/cci"

// Tags field is map[string]interface{}
tags := map[string]interface{}{
    "nist": []string{"AC-2", "IA-5 (1)"},
    "cci":  []string{"CCI-000192"},
}
```

---

## Step 4b — Use Monorepo Libraries; Do Not Reinvent

Before implementing any utility logic, check whether a sibling package already provides it. The monorepo exists so this code is written once.

| Need | Use | Do NOT |
|------|-----|--------|
| Look up NIST controls from a tool's identifier | `hdf-mappings/go/<tool>` | Hardcode a map inside the converter |
| Look up CCI from NIST | `hdf-mappings/go/cci` | Reimplement CCI lookup |
| Parse CSV source input | `hdf-parsers` TypeScript package | Roll a CSV parser in Go in the converter |
| Parse XML source input | Use Go stdlib `encoding/xml` or `hdf-parsers` | Pull in a third-party XML library without first checking what parsers already uses |
| Validate that converter output is valid HDF | `hdf-validators/go` (`validators.ValidateResults()`) | Write ad-hoc JSON field checks in tests |
| HDF schema types | `hdf-schema` (already imported as `hdf "github.com/mitre/hdf-schema"`) | Redefine HDF structs inside the converter package |

Specifically:
- **`hdf-validators`** is already wired into `hdf-cli/cmd/hdf/cmd/input.go`. CLI integration tests should call `assertHDFOutput(t, output)`, which delegates to the validators package. Do not add a second validation path.
- **`hdf-mappings`** covers all tools with NIST/CCI mappings. If a mapping package for the source tool doesn't exist yet, create it in `hdf-mappings/go/<tool>/` rather than embedding the map in the converter.
- **`hdf-parsers`** owns CSV and XML handling for the TypeScript side. If implementing a Go converter for a CSV or XML source, use Go stdlib (`encoding/csv`, `encoding/xml`) but check whether there is already a shared Go helper in the monorepo before adding logic.

If you find yourself writing something that looks like general-purpose infrastructure (a lookup table, a format parser, a schema validator), stop and check whether it belongs in one of the sibling packages instead.

---

## Step 5 — CLI Integration

File: `hdf-cli/cmd/hdf/cmd/converter_<snake>.go`

```go
package cmd

import (
    "encoding/json"
    "fmt"

    <pkg> "github.com/mitre/hdf-converters/converters/<name>/go"
)

type <name>Converter struct{}

func (c *<name>Converter) Name() string { return "<Source> to HDF" }

func (c *<name>Converter) Convert(input []byte) ([]byte, error) {
    result, err := <pkg>.Convert<Name>(input, version)
    if err != nil {
        return nil, fmt.Errorf("<source> conversion failed: %w", err)
    }
    output, err := json.MarshalIndent(result, "", "  ")
    if err != nil {
        return nil, fmt.Errorf("failed to serialize HDF output: %w", err)
    }
    return output, nil
}

func init() {
    RegisterConverter("<source>", "hdf", &<name>Converter{})
}
```

For HDF-from converters (hdf → something), the `Convert` signature is the same — input is HDF JSON, output is the target format bytes.

---

## Step 5b — Live Fetch Mode (API-pull converters only)

Skip this step if the source tool exports a static file. Only needed for: aws-config, sonarqube, ionchannel, msft-secure-score, splunk.

### Fetcher location

```
hdf-cli/
  internal/
    fetchers/
      <name>.go        # Fetcher implementation
      <name>_test.go   # Tests using httptest.Server (no live credentials)
```

### Fetcher interface

```go
// Each fetcher implements this — takes its own params struct, returns
// the same bytes the file-based converter already accepts.
type Fetcher interface {
    Fetch(ctx context.Context) ([]byte, error)
}
```

### CLI integration

In `converter_<snake>.go`, add a `--live` flag and fetcher-specific flags. At runtime:
- If `--live` → instantiate fetcher, call `Fetch()`, get bytes
- Else → read input file, get bytes
- Either way → pass bytes to existing `Convert*()` function

```go
// Rough shape — adapt flags to the specific API
var liveCmd = &cobra.Command{
    Use:   "<source> to hdf [input] output",
    RunE: func(cmd *cobra.Command, args []string) error {
        var data []byte
        if live, _ := cmd.Flags().GetBool("live"); live {
            f := fetchers.NewXxxFetcher(/* flags */)
            var err error
            data, err = f.Fetch(cmd.Context())
            if err != nil { return err }
        } else {
            var err error
            data, err = os.ReadFile(args[0])
            if err != nil { return err }
        }
        // ... convert and write output
    },
}
```

### Mocking API calls in tests

**Never** require live credentials or a running service in tests. Use `httptest.NewServer`:

```go
func TestFetcher_Fetch(t *testing.T) {
    srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // assert r.URL.Path, r.Header, query params as needed
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusOK)
        _, _ = w.Write([]byte(`{ /* canned API response */ }`))
    }))
    defer srv.Close()

    f := NewXxxFetcher(XxxParams{URL: srv.URL, Token: "test-token", /* ... */})
    data, err := f.Fetch(context.Background())
    require.NoError(t, err)
    // assert data parses correctly
}
```

For AWS (which uses the SDK rather than raw HTTP), use the AWS SDK's built-in mock transport or implement a `ConfigServiceClient` interface and inject a stub.

### Dependencies

- SonarQube, IonChannel, Splunk: standard `net/http` only, no new deps
- AWS Config: `github.com/aws/aws-sdk-go-v2/service/configservice` (already approved — binary size increase accepted)
- MS Secure Score: `golang.org/x/oauth2` for token exchange + standard `net/http` for Graph API (avoid full Azure SDK)

### Security Review (mandatory for every fetcher)

After implementing a fetcher and its tests, **task a security agent** to review it before considering the work done. The review prompt should cover:

1. **Credential handling** — are secrets accepted as CLI flags (visible in `ps`, shell history, CI logs)? Prefer `--profile` (AWS), env vars, or token files over raw flag values. The AWS CLI itself does not accept `--secret-access-key` as a flag.
2. **Input validation** — are API endpoint URLs or region strings validated before being interpolated into HTTP requests? Unvalidated strings passed to SDK endpoint constructors are an SSRF vector (see GHSA-3jcv-796g-cpjg / CVE-2026-22611).
3. **Pagination safety** — are both pagination loops capped at a maximum page count? Uncapped loops can exhaust memory or loop forever on malformed continuation tokens.
4. **Context cancellation** — is `ctx.Err()` checked at the top of each pagination loop iteration, not just propagated via the next API call?
5. **Timeout** — does `Fetch()` apply a default deadline when the caller has not set one? A missing deadline blocks indefinitely on a hung endpoint.
6. **Error messages** — do errors inadvertently include credential values?
7. **TLS** — is TLS enforced? Document it in a comment if the SDK handles it automatically.

The AWS Config fetcher (`hdf-cli/internal/fetchers/awsconfig.go`) is the reference implementation for all of the above patterns.

---

## Step 6 — CLI Tests

File: `hdf-cli/cmd/hdf/cmd/converter_<snake>_test.go`

```go
package cmd

import (
    "os"
    "testing"

    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

func Test<Name>Converter_IsRegistered(t *testing.T) {
    converter, err := GetConverter("<source>", "hdf")
    require.NoError(t, err)
    assert.Equal(t, "<Source> to HDF", converter.Name())
}

func Test<Name>Converter_Convert_Minimal(t *testing.T) {
    inputData, err := os.ReadFile(converterFixturePath(t, "<name>", "input/minimal.<ext>"))
    require.NoError(t, err)

    converter, err := GetConverter("<source>", "hdf")
    require.NoError(t, err)

    output, err := converter.Convert(inputData)
    require.NoError(t, err)
    assertHDFOutput(t, output)
}

func Test<Name>Converter_Convert_InvalidInput(t *testing.T) {
    converter, _ := GetConverter("<source>", "hdf")
    output, err := converter.Convert([]byte("not valid"))
    assert.Error(t, err)
    assert.Nil(t, output)
    assert.Contains(t, err.Error(), "<source> conversion failed")
}
```

---

## Step 7 — Verify and Spot Check

```bash
# Run unit tests
cd hdf-converters && go test ./converters/<name>/go/...

# Run CLI tests
cd hdf-cli && go test ./cmd/hdf/cmd/...

# Spot check real output via CLI binary
cd hdf-cli && go build -o hdf ./cmd/hdf
./hdf convert <source> to hdf path/to/input.ext output.json
cat output.json | head -40

# Lint
pnpm lint

# Full test suite
pnpm test
```

---

## Coverage Requirements

- **>90% line/branch coverage** on `converter.go`
- Every public function must have at least: happy path, invalid input, and empty input tests
- Every non-trivial private helper should have direct unit tests
- CLI test must cover: registered, minimal conversion, invalid input

---

## Done Checklist

**All converters:**
- [ ] Fixtures created (`fixtures/input/minimal.*` at minimum, sourced from real tool output)
- [ ] Unit tests written and passing (`converter_test.go`)
- [ ] Implementation complete (`converter.go`)
- [ ] CLI registration file (`converter_<snake>.go`) — add `//nolint:dupl` if lint flags it as a duplicate of another thin converter wrapper
- [ ] CLI tests passing (`converter_<snake>_test.go`)
- [ ] `pnpm lint` clean
- [ ] `pnpm test` passes (both go and ts)
- [ ] Spot-checked output looks correct

**API-pull converters additionally (aws-config, sonarqube, ionchannel, msft-secure-score, splunk):**
- [ ] Static format definition verified against real API documentation or heimdall2 source — not invented
- [ ] Fetcher implemented (`hdf-cli/internal/fetchers/<name>.go`)
- [ ] Fetcher tests use `httptest.Server` (or SDK interface injection for AWS) — no live credentials required
- [ ] Security agent review completed covering: credential handling, input validation, pagination caps, context cancellation, default timeout, error message safety
- [ ] All security findings addressed before marking done
- [ ] `--live` flag wired into CLI converter command, file-based path still works
- [ ] Spot-checked live mode output (or documented why a live spot-check isn't possible)

**All converters — library usage check:**
- [ ] NIST/CCI lookups delegate to `hdf-mappings/go/<tool>` or `hdf-mappings/go/cci` — not reimplemented in the converter
- [ ] HDF output validation in CLI tests uses `assertHDFOutput()` / `hdf-validators` — no ad-hoc field checks
- [ ] CSV/XML parsing uses stdlib or existing monorepo helpers — no new third-party parser deps added without discussion
