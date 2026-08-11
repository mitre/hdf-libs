---
description: Build a new HDF converter end-to-end following hdf-libs monorepo patterns. Use when asked to implement a new converter (e.g. "add a foo-to-hdf converter").
allowed-tools: Read, Glob, Grep, Bash, Edit, Write, Task, EnterPlanMode, ExitPlanMode, AskUserQuestion
---

## Execution Strategy

Converters are multi-file, multi-language projects that span fixtures, tests, implementations, and CLI integration. **Do not attempt to build the entire converter in one shot.** Instead, follow this phased approach:

### Phase 1 — Research & Plan (enter plan mode)

1. **Enter plan mode** immediately. Use `EnterPlanMode` before writing any code.
2. In plan mode, research the source format:
   - Read sample input files if provided; otherwise ask the user.
   - **Decide the output document type up front**: HDF Results (most converters), HDF Baseline (benchmarks / catalogs), or HDF Amendments (waivers, attestations, POA&Ms, VEX-style consumer-attached context). See Step 4f when the answer is Amendments — the schema invariants and pattern differ substantially.
   - Identify what maps to HDF fields (Requirement.ID, Impact, Status, NIST tags).
   - Check whether the tool supports common output formats (SARIF, JUnit, CycloneDX, XCCDF) — if so, plan format detection and routing.
   - Check heimdall2 and SAF CLI repos for existing fixtures and converter logic.
   - Read the exports of `hdf-schema`, `hdf-utilities`, `hdf-mappings`, and `hdf-validators` to know what's available — converters that reinvent library functionality will be rejected. **This audit is mandatory and happens BEFORE implementation**, not reactively after review feedback.
   - **Maximize field coverage (Step 1a).** Plan a mapping for every source field that has a defensible HDF home — carry as much of the format into HDF as you can, not just the minimum. If you are unsure whether or how a field maps, STOP and ask the developer; never silently drop real data into freetext.
   - **Audit source-format fields against the HDF schema** (Step 1b). If you find a field with no HDF home, STOP and surface to the user — never silently add schema fields.
3. Write a detailed plan covering:
   - Source format structure and field mappings to HDF
   - Output document type and rationale
   - Field-gap audit results (categories a/b/c per Step 1b)
   - Fixture sourcing strategy (where real data comes from)
   - Test scenarios for both Go and TypeScript
   - Implementation approach (parsing, mapping, edge cases)
   - CLI integration (command name, aliases, flags)
   - Format detection routing if applicable
4. **Exit plan mode** and get user approval before proceeding.

### Phase 2 — Fixtures & Tests (TDD)

After plan approval, implement in order:
1. Source real fixtures (never fabricate)
2. Write Go tests (`converter_test.go`)
3. Write TypeScript tests (`converter.test.ts`)
4. Confirm all tests fail (red phase)

### Phase 3 — Implementation

1. Implement Go converter (`converter.go`) — run Go tests until green
2. Implement TypeScript converter (`converter.ts`) — run TS tests until green
3. Wire TypeScript barrel exports

### Phase 4 — CLI Integration

1. Write CLI registration (`converter_<snake>.go`)
2. Write CLI tests (`converter_<snake>_test.go`)
3. Spot-check output via CLI binary
4. Add the new format to the "Supported Conversions" table in `hdf-cli/README.md`
5. Add the new format to the converter table in `hdf-converters/README.md`

### Phase 5 — Verification

1. `pnpm lint` clean
2. `pnpm test` passes at root level (catches cross-package type errors)
3. Run the Done Checklist at the bottom of this file

**If context is running low between phases**, use `/prep-compact` to save state, compact, then resume with `/restore-context`. Each phase is designed to be independently resumable.

---

Build the `$ARGUMENTS` converter following the phases above and the reference patterns below. Follow TDD: write tests and fixtures before implementation. Do not consider the converter done until CLI integration is complete and passing.

---

## Monorepo Layout

```
hdf-converters/converters/<name>/
  go/
    converter.go          # Go implementation
    converter_test.go     # Go unit tests
  typescript/
    converter.ts          # TypeScript implementation
    converter.test.ts     # TypeScript unit tests
  fixtures/
    input/                # Source format samples (minimal.*, real.*, edge cases)
    output/               # Expected HDF JSON output (optional; prefer assertion-based tests)

hdf-cli/cmd/hdf/cmd/
  converter_<snake>.go    # CLI registration (wraps Go hdf-converters impl)
  converter_<snake>_test.go
```

**Both Go and TypeScript implementations are required.** A converter is not done until both are implemented, tested, and passing. The CLI integration wraps the Go implementation only — the TypeScript implementation is consumed by JS/TS tooling that imports from `@mitre/hdf-converters`.

Converter name conventions:
- Directory: `{source}-to-hdf` or `hdf-to-{dest}` (kebab-case)
- Go package: short, no hyphens (e.g. `package nessus`, `package hdftocsv`)
- TypeScript export: camelCase function (e.g. `convertGosecToHdf`, `convertNessusToHdf`)
- CLI snake: hyphens → underscores (e.g. `nessus-to-hdf` → `converter_nessus.go`)

---

## Step 1 — Understand the Source Format

Before writing any code:
1. Read sample input files if the user provides them; otherwise ask.
2. Identify: What maps to `Requirement.ID`? What maps to `Impact`? What maps to `Status`? What maps to NIST tags?
3. Sketch the struct types needed to parse the source format.
4. **Check whether the tool supports common output formats** (SARIF, JUnit XML, CycloneDX, XCCDF). If it does, the converter must detect and delegate to the shared format converter — see "Step 4c — Format Detection and Routing" below.

---

## Step 1a — Maximize Source-Field Coverage (translate everything defensible)

**The converter must carry as much of the source format into HDF as can be _defensibly_ mapped — not just the minimum to pass a smoke test.** A field-coverage sweep of the existing converters (epic `hdf-libs-j5hz`) found the same failure mode across dozens of them: real structured data flattened into freetext (`codeDesc`/`message`) or parsed into a struct and never emitted, even though HDF has a structured home for it.

**Enumerate against the source spec, not the sample.** Where the source format has a published spec or schema, work from the *spec's* field list — every field the spec defines gets a disposition below. Do NOT treat the fields that happen to appear in your sample fixture as the coverage checklist: a minimal fixture only exercises the fields it contains, so "the fixture converts cleanly" is never evidence of full coverage. Missed source fields are the single most common converter defect — this check exists to catch them before review does.

For **every** field the source carries, decide one of three and record the decision in the plan:

1. **Map it** — it has an HDF home (a structured field, or a defensible `tags` entry). Do the mapping. This is the default and should cover the large majority of fields.
2. **No HDF home** — genuinely inexpressible → go to Step 1b (surface to the developer; never silently invent a schema field).
3. **Unsure** — you cannot tell whether/how a field maps, or the source shape is ambiguous (deeply nested, polymorphic, version-dependent) → **STOP and ask the developer.** Do not guess, and do not silently drop the field into `codeDesc`/`message` freetext.

Never let real structured data land only in freetext when HDF has a home for it. Check explicitly for these recurring misses:
- **CVSS** → full `cvss[]` (baseScore AND vector AND version), not just score→impact with the vector discarded.
- **CWE** → first-class `requirement.cwe[]`, not only a `tags.cweid` string.
- **CVE / EPSS / KEV** → structured `epss`, `kev`, and CVE identity, not buried in a description blob.
- **Locations** → `sourceLocation{ref,line}` and `components[]` (host/image/OS/digest identity), not a file path concatenated into `codeDesc`.
- **References** → external links into `refs[]` (the `Reference` type), not parsed-then-dropped.
- **Remediation / fix / tips** → labeled `descriptions[]` entries.
- **Triage / waiver / suppression** → reconstruct `statusOverrides[]` (+ `disposition`, `effectiveStatus`) with owner/date/reason when the source carries them — not a lossy status flip plus a tag.
- **Raw source** → put the finding's raw source (or a serialized source object) in `requirement.code` so Heimdall's CODE tab renders (see `nessus`/`ionchannel`/`splunk` for the pattern).
- **Timestamps** → derive the top-level `timestamp` and per-result `startTime` from the source's real scan/finding time; never `time.Now()`/`new Date()` when the source supplies a time.
- **Categorization / metadata** → source taxonomy with no first-class field goes to `tags` passthrough, not dropped.
- **Tool identity** → set `tool.version` from the source when present.

A field "parsed into the struct but never emitted" is a bug, not a nicety: if you added a struct field, either map it or justify in the plan why it has no home. **When in doubt about any field, ask the developer rather than drop it.** Step 1b (below) governs the opposite risk — do not _over_-extend the schema; the two steps are complementary, and the answer to an "unsure" field is always to ask, never to silently add a field or silently discard data.

---

## Step 1b — Audit Field Gaps Before Extending the Schema

The HDF schema is stable enough that **additions are commitments** consumers will start depending on. Default posture when a converter author finds a source-format concept HDF can't express: **FLAG to the user**, never silently add schema fields.

For each source field that doesn't have an obvious HDF home, categorize:

(a) **Maps to an existing HDF field via mapping logic** — write the mapping in the converter. Done.
(b) **Format artifact safely synthesized on export** (export converters only) — generate from existing HDF state at write time. Done.
(c) **Genuinely represents a concept HDF cannot express** — STOP. Surface to the user with:
   - what the source concept is
   - why no existing HDF field works (audit, don't assume)
   - whether the concept generalizes beyond this one format
   - what the conversion behavior would be (lossy? refuse to emit?) without a schema change

Schema additions that DO go forward must be:
- **Generalized beyond the prompting format** — no `vexJustification`; use `justification` so OSCAL / FedRAMP DR can extend the same enum
- **Optional** — additive, doesn't break old documents
- **Approved by the user** with explicit awareness that schema additions are commitments

**Worked example from `openvex-to-hdf`**: the initial design proposed `vexJustification` and a `resolution` sub-object. Field audit produced:
- `justification` survived as ONE field, generalized from the VEX-specific name so OSCAL / FedRAMP DR can extend the same vocabulary later
- `resolution` was dropped entirely — amendment chain (`previousChecksum`) + `milestones[].status` already express POA&M closure losslessly

Net delta: two proposed fields → one shipped field after rigorous audit and pushback.

The bar is high. Three-line schema additions accumulate; every one is a schema-version bump and a forever maintenance commitment.

---

## Step 2 — Source Real Fixtures

**Never fabricate fixture data.** A converter tested against fabricated fixtures is untrusted — if the fixture is fake, the test proves nothing about real-world data. Every fixture must be **provably valid**: either sourced from real tool output or validated against the format's official schema.

### Fixture sources (in priority order)

1. **Real tool output** captured from an actual run or public CI pipeline (e.g., GitHub Actions artifacts, open-source project test resources)
2. The heimdall2 repo at `~/repos/heimdall2/libs/hdf-converters/test/sample_input_report/`
3. The SAF CLI repo at `~/repos/saf/test/sample_data/`
4. Sanitized/anonymized copies of real customer data

Before writing any fixtures, check both repos:
```bash
ls ~/repos/heimdall2/libs/hdf-converters/test/sample_input_report/
ls ~/repos/saf/test/sample_data/
```

### Fixture validation requirement

Every fixture MUST satisfy at least one of:
1. **Provenance documented** — commit message states exactly where the data came from (repo URL, file path, or how it was generated)
2. **Schema-validated** — validated against the format's official schema (JSON Schema, XSD, OpenAPI spec) with the validation command logged in the commit message or a comment in the test file

If the format has an official schema, validate against it even if the data is real. Common schemas:
- **SARIF**: `https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json`
- **JUnit XML**: Windyroad XSD or tool-specific DTD
- **Nessus**: Tenable's `.nessus` XML format (no public XSD, but structure is documented)
- **Grype**: `anchore/grype` JSON output schema
- **AWS Config**: AWS API response schemas in AWS SDK docs
- **SonarQube**: REST API response schema from SonarQube docs
- **HDF**: Our own `hdf-schema` package (use `hdf-validators` to validate)

If no real data source exists AND no schema exists to validate against, **stop and ask the user** — do not invent data.

### Sourcing from open-source projects

When real tool output isn't available locally, look for it in public repos:
- GitHub search: `filename:<format-extension> path:test` (e.g., `filename:.nessus path:test`)
- Tool's own test suite (e.g., apache/maven-surefire for JUnit XML, anchore/grype for Grype JSON)
- CI artifacts from open-source projects that use the tool

Also read the heimdall2 converter source to understand what input format it actually expects — the original converter may use live SDK calls rather than a static file, which changes the design significantly.

**If the source tool has no static export format** (the heimdall2 converter calls a live API directly), this converter requires two modes:
1. **File mode** — define a static JSON format that mirrors the API response, document how users produce it (e.g. `aws configservice describe-config-rules`), implement the converter against that format
2. **Live fetch mode** — implement a fetcher (via the `/build-fetcher` skill) in `hdf-converters/fetchers/<name>/` that calls the API, marshals to the same static format, and hands bytes to the existing converter

See "Step 5b — Live Fetch Mode" below for details.

**For file-mode on API-pull converters:** the static format you define is the schema your fixtures must conform to. Before writing any fixtures, verify the format against the tool's real API response documentation or the heimdall2 source. Do not invent field names or nesting — if you don't have confirmed API response documentation, stop and ask. A fixture that doesn't match the real schema is worse than no fixture: it validates the wrong thing and will silently diverge from real data.

Copy or adapt real samples. Keep them small by truncating arrays, but preserve the real field names, types, and nesting. Name them descriptively (`minimal.<ext>`, `real.<ext>`, `edge-case.<ext>`).

### Fixture location: local vs shared

**Default: keep fixtures in your converter's `fixtures/` dir.** That's the converter's *tested contract* and the natural home for the input/expected pair.

**Promote to `@mitre/hdf-fixtures` only when a second workspace package actively needs to load the same file** (parsers, validators, hdf-extension-graph, hdf-diff, etc.). When that happens:
1. Move the file to `../hdf-fixtures/<doc-type>/` (e.g. `results/`, `baseline/`, `inspec/`)
2. Wire it into both `hdf-fixtures/src/index.ts` (TS) and `hdf-fixtures/fixtures.go` (Go) with parallel access
3. Update both consumers to import from `@mitre/hdf-fixtures` (the converter test loads via `inspec.x.path` / `fixtures.Inspec.X` or similar)
4. **Delete the original** — no duplicates allowed
5. Document the move in `hdf-fixtures/README.md` with provenance and current consumers

**The inclusion bar is strict.** "Might be useful someday" or "good for cross-package parity-test breadth" doesn't qualify. Promote only when a second active consumer has materialized. See `../hdf-fixtures/README.md` for examples and the rationale (bead `hdf-libs-e95o`).

### Fixture size policy

**Committed fixtures should be small** (under ~1 MB per file). Full-size real-world scan outputs (e.g., complete DISA STIG scans, entire NIST 800-53 catalogs) should NOT be committed to the repo — they bloat the git history and caused LFS bandwidth issues.

**During development, test against full-size real data locally.** Download or generate realistic full-scale fixtures (hundreds of controls, real scan output) and use them to validate your converter handles real-world volume, field diversity, and edge cases. Keep these outside the repo (e.g., in a gitignored `fixtures/local/` directory or a shared team drive).

**Committed fixtures should be representative subsets**: trim real data to 3-10 rules/findings that exercise all code paths (different severity levels, various field combinations, edge cases like empty arrays or missing optional fields). The goal is coverage of parsing logic, not volume testing.

**Minimal fixtures catch drift, not coverage.** A small committed fixture's job is to lock in behavior and catch *regression/drift* over time — it is NOT a checklist of the fields the converter must handle, and passing on it is NOT evidence of exhaustive coverage during initial buildout. Establish field coverage against the source spec (Step 1a) first; then keep the committed fixture minimal for drift detection.

---

## Step 3 — Write Unit Tests First (TDD)

Write tests for **both Go and TypeScript** before implementing either. They share the same fixtures, so write them together.

### Step 3a — Go tests

File: `hdf-converters/converters/<name>/go/converter_test.go`

```go
package <pkg>

import (
    "os"
    "path/filepath"
    "testing"

    hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
    shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

const converterVersion = "0.1.0"

func fixtureDir() string {
    return filepath.Join(shared.GetConvertersDir(), "<name>", "fixtures", "input")
}

func loadFixture(t *testing.T, name string) []byte {
    t.Helper()
    data, err := os.ReadFile(filepath.Join(fixtureDir(), name))
    require.NoError(t, err)
    return data
}

func TestConvert_Minimal(t *testing.T) {
    result, err := Convert<Name>(loadFixture(t, "minimal.<ext>"), converterVersion)
    require.NoError(t, err)
    require.NotNil(t, result)

    require.NotNil(t, result.Generator)
    assert.Equal(t, "hdf-converters", result.Generator.Name)
    assert.Equal(t, converterVersion, result.Generator.Version)
    require.NotNil(t, result.Timestamp)
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

### Step 3b — TypeScript tests

File: `hdf-converters/converters/<name>/typescript/converter.test.ts`

```typescript
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { describe, it, expect } from 'vitest';
import { expectValidResults } from '../../../test/helpers/expectValidHdf.js';
import { convert<Name>ToHdf } from './converter.js';
import type { HDFResults } from '@mitre/hdf-schema';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(__dirname, '..', 'fixtures');

function loadFixture(name: string): string {
  return readFileSync(join(FIXTURES_DIR, 'input', name), 'utf-8');
}

describe('<name> to HDF converter', () => {
  it('should throw on invalid JSON', () => {
    expect(() => convert<Name>ToHdf('not json')).toThrow();
  });

  it('should throw on empty input', () => {
    expect(() => convert<Name>ToHdf('')).toThrow();
  });

  it('should produce valid HDF structure from minimal fixture', () => {
    const output = convert<Name>ToHdf(loadFixture('minimal.<ext>'));
    const hdf = JSON.parse(output) as HDFResults;

    expectValidResults(hdf); // schema gate — required on at least one success path

    expect(hdf.timestamp).toBeTruthy();
    expect(hdf.generator?.name).toBe('<source>-to-hdf'); // e.g. 'splunk-to-hdf'
    expect(hdf.baselines).toHaveLength(1);
  });

  // ... assert specific field values matching your Go tests
});
```

Mirror the same scenarios as the Go tests. Tests use vitest (not Jest) — syntax is nearly identical.

**Schema validation is required.** Every TS importer test file must call the
matching helper from `hdf-converters/test/helpers/expectValidHdf.ts` on at least
one success-path test. Choose the helper by output type: `expectValidResults`
for HDF Results, `expectValidBaseline` for HDF Baseline, `expectValidAmendments`
for HDF Amendments (VEX importers). This mirrors the Go pattern (`validators.
ValidateResults` after `json.Marshal`) and prevents schema-invalid output
from passing unit tests silently.

---

## Step 4 — Implement the Converter

### Step 4a — Go

File: `hdf-converters/converters/<name>/go/converter.go`

```go
package <pkg>

import (
    "fmt"
    "time"

    hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
    shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
)

// Convert<Name> converts <Source> to HDF format.
func Convert<Name>(input []byte, converterVersion string) (*hdf.HDFResults, error) {
    if len(input) == 0 {
        return nil, fmt.Errorf("empty input")
    }

    resultsChecksum := shared.InputChecksum(input)

    // ... parse input, build baselines, targets

    now := time.Now().UTC()
    return &hdf.HDFResults{
        Generator: &hdf.Generator{
            Name:    "hdf-converters",
            Version: converterVersion,
        },
        Tool: &hdf.Tool{
            Name:   shared.Ptr("<Source Tool Name>"),
            // Format names a FORMAT SPECIFICATION only (SARIF, XCCDF, FVDL,
            // exec-json) — never a serialization structure. Omit for the
            // tool's native output: "JSON"/"XML"/"CSV" are encodings, not
            // formats, and are banned here (swept fleet-wide 2026-08-01).
        },
        Baselines:  baselines,
        Components: components,
        Statistics: hdf.Statistics{Duration: duration},
        Timestamp:  &now,
    }, nil
}
```

### Input parsing — handle NDJSON when the tool can emit it

Some tools emit **NDJSON** (one JSON object per line) rather than a JSON array — typically behind a streaming `--json` flag (e.g. `trufflehog --json`). If the source tool can produce NDJSON, `Convert()` must accept all three input shapes, in this order:

1. Whole-input JSON array (`json.Unmarshal` into `[]Finding`)
2. Single JSON object (`json.Unmarshal` into one `Finding`)
3. Line-by-line NDJSON: split on `\n`, skip blank lines, `json.Unmarshal` each line

Reference implementation: `trufflehog-to-hdf/go/converter.go` (`parseFindings`) and its TS counterpart `typescript/converter.ts`. Mirror the same fallback in both languages.

**Why this is mandatory, not optional:** registry auto-detect (`registry/fingerprint.go`, `shared/typescript/fingerprint.ts`) fingerprints the **first line** when a whole-input parse fails, so NDJSON input now auto-detects correctly. If your `Convert()` only handles the array/single-object shapes, auto-detect will *succeed* and then conversion will *fail* — a worse failure mode than a clean "could not auto-detect." Handle NDJSON in `Convert()` whenever the tool can emit it, and add an `*.ndjson` fixture + test (including a CLI auto-detect test) to lock it in.

### HDF Type Reference

```go
hdf.HDFResults           // Top-level: Generator, Baselines, Targets, Statistics, Timestamp
hdf.EvaluatedBaseline    // Name, Version, Title, Maintainer, Requirements, Checksum, Groups, Supports, Attributes
hdf.EvaluatedRequirement // ID, Title, Descriptions, Impact, Tags, SourceLocation, Results
hdf.RequirementResult    // Status (*hdf.ResultStatus), CodeDesc, StartTime, Message, RunTime
hdf.Component               // Name, Type, FQDN, IPAddresses, MACAddresses, CloudProvider

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

### Baseline.Name Convention

`Baseline.Name` is a **fixed scan label**, not dynamic data. Examples: `"Snyk Scan"`, `"gosec Scan"`, `"OWASP ZAP Scan"`. Dynamic context (host, project, URL) belongs in `Baseline.Title` instead.

```go
// CORRECT — fixed label
baseline := hdf.EvaluatedBaseline{
    Name:  "Nessus Scan",
    Title: shared.Ptr("Nessus Scan of 192.168.1.0/24"),
}

// WRONG — dynamic data in Name
baseline := hdf.EvaluatedBaseline{
    Name:  "192.168.1.0/24",   // Do not put dynamic data here
}
```

TypeScript follows the same pattern:
```typescript
createMinimalBaseline('Nessus Scan', requirements, {
  title: `Nessus Scan of ${targetHost}`,
})
```

### Components Convention

Every converter that scans a specific target (host, URL, repo, cloud account) MUST populate `Components`. The `Type` field uses the `TargetType` enum (Go: `hdf.Application`, TS: `TargetType.Application`).

Choose the target type based on what the tool scans:

| Tool category | Component type | Example converters |
|---------------|-------------|-------------------|
| DAST (web scanners) | `Application` | ZAP, Burp, Nikto |
| SAST (code scanners) | `Repository` | gosec, Snyk, CodeQL, Semgrep |
| Container scanners | `ContainerImage` | Grype, Trivy |
| Host scanners | `Host` | Nessus, OpenSCAP |
| Cloud security | `CloudAccount` | AWS Config, ScoutSuite |
| Network scanners | `Network` | Nmap |

**Go:**
```go
targets := []hdf.Component{
    {Name: targetName, Type: hdf.Application, URL: &siteURL},
}
```

**TypeScript:**
```typescript
import { TargetType } from '@mitre/hdf-schema';
components: [{ name: targetName, type: TargetType.Application, url: siteURL }],
```

Set `URL` for DAST targets, `FQDN`/`IPAddress` for host targets, and `Digest`/`ImageID` for container targets, when the source data provides them. If the source provides no identifiable target (e.g., empty input or missing host), omit `Components` entirely rather than creating an "Unknown" target.

### Standard Impact Mapping (use heimdall2 values)

```go
var impactMap = map[string]float64{
    "critical": 0.9,
    "high":     0.7,
    "medium":   0.5,
    "low":      0.3,
    "info":     0.0,
    "none":     0.0,
}
```

**When impact is COMPUTED by division** (e.g. `cvssScore / 10`, `severity / 5`), wrap
the result in the canonical rounder so binary-float noise (`0.98000000000001`) collapses
to the 0.01 grid and stays byte-identical across Go/TS:

```go
import hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
impact := hdfutil.RoundImpact(score / 10.0)   // Go
```
```typescript
import { roundImpact } from '@mitre/hdf-utilities';
const impact = roundImpact(score / 10);        // TS
```

Never hand-roll `math.Round(x*100)/100` — use `RoundImpact`/`roundImpact`. (Table-lookup
impacts like the map above are already clean and need no rounding.)

### NIST / CCI Tags

Use the mappings packages when the source format provides NIST or CCI references:
```go
import "github.com/mitre/hdf-libs/hdf-mappings/go/v3/cci"

// Tags field is map[string]interface{}
tags := map[string]interface{}{
    "nist": []string{"AC-2", "IA-5 (1)"},
    "cci":  []string{"CCI-000192"},
}
```

---

## Step 4b — Use Monorepo Libraries; Do Not Reinvent

**This is a BLOCKING requirement.** Before writing ANY utility logic in a converter, you MUST check the four sibling libraries below and use their functions if they cover your need. Converters that reimplement library functionality will be rejected. The whole point of this monorepo is that common logic is written once.

**Before every converter implementation:** read the exports of each library to know what's available. If you skip this step you will inevitably duplicate something.

### `hdf-schema` — types and builder helpers

**Go** (`hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"`): All HDF struct types. Use these directly; never redefine HDF types in converter code.

**TypeScript** (`@mitre/hdf-schema`): Types AND builder helpers. Use these instead of constructing objects by hand:

| Function | Use for |
|----------|---------|
| `createMinimalBaseline(name, requirements, options)` | Building `EvaluatedBaseline` objects |
| `createRequirement(id, title, descriptions, impact, results, options)` | Building `EvaluatedRequirement` objects |
| `createResult(status, message, options)` | Building `RequirementResult` objects |
| `createDescription(label, data)` | Building `Description` objects |
| `createSourceLocation(ref, line)` | Building `SourceLocation` objects |
| `createEmptyChecksum()` | Default checksum placeholder |
| `severityToImpact(severity)` | Standard critical/high/medium/low/info → 0.0–1.0 mapping |
| `impactToSeverity(impact)` | Reverse of above |
| `ResultStatus.Passed / Failed / NotReviewed / NotApplicable / Error` | Status enum values |
| `HashAlgorithm.Sha256` | Checksum algorithm constant |

### `hdf-mappings` — NIST/CCI/CWE/OWASP lookups

**Go** (`github.com/mitre/hdf-libs/hdf-mappings/go/v3/cci`, `.../cwe`, `.../awsconfig`):

| Function | Use for |
|----------|---------|
| `cci.GetCCINistMappings(cciID)` | CCI → NIST controls |
| `cci.NISTToCCI(nistControls)` | NIST controls → CCI IDs (batch, deduplicated, sorted) |
| `cci.CCIToNIST(cciIDs)` | CCI IDs → NIST controls (batch, deduplicated, sorted) |
| `cwe.NISTControls(cweID)` | CWE → NIST control |
| `awsconfig.NISTControls(identifier)` | AWS Config rule → NIST controls |

**TypeScript** (`@mitre/hdf-mappings`):

| Function | Use for |
|----------|---------|
| `getCCINistMappings(cciId)` | CCI → NIST controls |
| `nistToCci(nistControls)` | NIST controls → CCI IDs (batch, deduplicated, sorted) |
| `getNistCCIMappings(nistControl)` | Single NIST control → CCI IDs |
| `getCweNistControl(numericCweId)` | CWE → NIST control |
| `getOwaspNistControl(owaspId)` | OWASP → NIST control |
| `getNessusNistControl(pluginFamily)` | Nessus plugin family → NIST control |
| `getNiktoNistControl(testId)` | Nikto test → NIST control |
| `getScoutsuiteNistControl(rule)` | ScoutSuite rule → NIST control |
| `getAwsConfigNistControlByIdentifier(id)` | AWS Config → NIST control |
| `DEFAULT_STATIC_ANALYSIS_NIST_TAGS` | Default NIST tags (`["SA-11", "RA-5"]`) when no CWE→NIST mapping applies |

If a mapping package for the source tool doesn't exist yet, create it in `hdf-mappings/go/<tool>/` and `hdf-mappings/src/<tool>/` rather than embedding a map in the converter.

### `hdf-utilities` — JSON/CSV/XML parsing and hashing

**TypeScript** (`@mitre/hdf-utilities`):

| Function | Use for |
|----------|---------|
| `parseJSON<T>(input)` | Parse JSON with error handling (use instead of raw `JSON.parse`) |
| `stringifyJSON(value, options)` | Serialize JSON with options |
| `isValidJSON(input)` | Check if string is valid JSON |
| `sha256(data)` | SHA-256 hash — async, returns `Promise<string>` (uses Web Crypto API, works in browser + Node) |
| `parseCsv<T>(input, options?)` | Parse CSV to typed records. Supports `{ maxSize: N }` |
| `buildCsv<T>(records)` | Build CSV from records |
| `parseXml(input, options?)` | Parse XML to JS object. Pass `{ maxSize: N }` to reject inputs over N chars |
| `parseXmlWithArrays(input, arrayTags, options?)` | Parse XML, forcing specified tags to always be arrays. Supports `{ maxSize: N }` |
| `buildXml(obj)` | Build XML from JS object |
| `findValuesByKey(obj, key)` | Recursively find all values for a key in nested object trees (parsed XML/JSON) |
| `findXmlValues(obj, key)` | Alias for `findValuesByKey` — use when working with parsed XML |
| `findJsonValues(obj, key)` | Alias for `findValuesByKey` — use when working with parsed JSON |
| `extractColumn(rows, column)` | Extract a named field from an array of objects, skipping undefined |
| `extractCsvColumn(rows, column)` | Alias for `extractColumn` — use when working with parsed CSV |
| `findRows(rows, column, value)` | Filter array of objects by strict equality on a column |
| `findCsvRows(rows, column, value)` | Alias for `findRows` — use when working with parsed CSV |

**Go**: Use stdlib (`encoding/json`, `encoding/csv`, `encoding/xml`, `crypto/sha256`).

Also available from `shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"`:

| Function | Use for |
|----------|---------|
| `shared.InputChecksum(input)` | SHA-256 checksum of raw input bytes → `*hdf.Checksum` |
| `shared.Ptr(s)` | Convert string to `*string` (avoids `&` on string literals) |
| `shared.ParseTimestamp(s)` | Parse ISO 8601 / RFC 3339 timestamps with multiple fallback formats |
| `shared.StripHTML(html)` | Strip HTML tags from a string, collapsing whitespace |
| `shared.BuildNISTCCITags(nist, cci)` | Build tags `map[string]interface{}` with NIST + CCI arrays |
| `shared.BuildNISTCCITagsWithExtras(nist, cci, extras)` | Same as above, plus extra key-value pairs merged in |
| `shared.BuildNoFindingsRequirement(id, codeDesc, startTime)` | Synthesize a passed placeholder when the scanner ran clean — see Step 4e |
| `shared.LimitSlice(items, max)` | Truncate large input arrays; returns `(limited, truncated bool)` |
| `shared.DetectFormat(input)` | Detect input format (SARIF, JUnit, XCCDF, etc.) — see Step 4c |
| `shared.FormatSARIF` / `shared.FormatUnknown` | Format detection result constants |
| `shared.DefaultStaticAnalysisNIST` | Default NIST tags (`["SA-11", "RA-5"]`) when no CWE mapping applies |
| `shared.GetConvertersDir()` | Absolute path to `hdf-converters/converters/` (for test fixture loading) |

Also available from `hdf-converters/shared/typescript/converterutil.ts`:

| Function | Use for |
|----------|---------|
| `inputChecksum(input)` | Async SHA-256 checksum → `Promise<Checksum>` |
| `buildNistCciTags(nist, cci, extras?)` | Build tags object with NIST + CCI arrays + optional extras |
| `buildNoFindingsRequirement(id, codeDesc, startTime)` | Synthesize a passed placeholder when the scanner ran clean — see Step 4e |
| `limitArray(items, maxItems?)` | Truncate large arrays; returns `{ items, truncated }` |
| `stripHTML(html)` | Strip HTML tags, collapse whitespace (mirrors Go `shared.StripHTML`) |
| `DEFAULT_MAX_ITEMS` | Maximum items constant (100,000) |
| `DEFAULT_STATIC_ANALYSIS_NIST_TAGS` | Re-export from `@mitre/hdf-mappings` |

Also available from `hdf-converters/shared/typescript/formatdetect.ts`:

| Function | Use for |
|----------|---------|
| `detectFormat(input)` | Detect input format → `'sarif' \| 'junit' \| 'xccdf' \| 'arf' \| 'unknown'` |

### `hdf-validators` — output validation

**Go** (`github.com/mitre/hdf-libs/hdf-validators/go/v3`):

| Function | Use for |
|----------|---------|
| `validators.ValidateResults(data)` | Validate HDF Results JSON against schema |
| `validators.ValidateBaseline(data)` | Validate HDF Baseline JSON against schema |

Already wired into `hdf-cli/cmd/hdf/cmd/input.go`. CLI integration tests MUST call `assertHDFOutput(t, output)`, which delegates to validators. Do not write ad-hoc JSON field checks as a substitute for schema validation.

### Rules

1. **Never hardcode a NIST/CCI/CWE lookup table in a converter.** Use `hdf-mappings`.
2. **Never iterate all CCI IDs to find which ones match a NIST control.** Use `cci.NISTToCCI()` (Go) or `nistToCci()` (TypeScript).
3. **Never redefine HDF types.** Import from `hdf-schema`.
4. **Never import `crypto` in TypeScript converters.** Use `sha256()` from `hdf-utilities` (async, uses Web Crypto API for browser compatibility).
5. **Never write raw `JSON.parse()` in TypeScript converters.** Use `parseJSON()` from `hdf-utilities`.
6. **Never write ad-hoc severity-to-impact maps in TypeScript.** Use `severityToImpact()` from `hdf-schema`. (Go converters may define their own if the source tool uses non-standard severity labels.)
7. **Never roll your own CSV/XML parser.** Use `hdf-utilities` (TypeScript) or Go stdlib.
8. **Never write recursive key-search loops in TypeScript converters.** Use `findValuesByKey()` / `findXmlValues()` / `findJsonValues()` from `hdf-utilities`.
9. **Never write manual column extraction or row filtering on arrays of objects in TypeScript.** Use `extractColumn()` / `findRows()` (or their CSV aliases) from `hdf-utilities`.
10. **If a new mapping package is created:** export it from `hdf-mappings/src/index.ts`, add it to the supported mappings table in `hdf-mappings/README.md`, and add usage examples for every exported function.
11. **If you find yourself writing general-purpose infrastructure** (a lookup table, a format parser, a hash function, a schema validator), stop and check whether it belongs in a sibling package instead.
12. **Never write a local `stripHTML()` function.** Use `shared.StripHTML()` (Go) or `stripHTML()` from `shared/typescript/converterutil.ts`.
13. **Never write a local `isSarif()` or format detection function.** Use `shared.DetectFormat()` (Go) or `detectFormat()` from `shared/typescript/formatdetect.ts`.
14. **Never build NIST/CCI tag objects by hand.** Use `shared.BuildNISTCCITags()` / `shared.BuildNISTCCITagsWithExtras()` (Go) or `buildNistCciTags()` from `shared/typescript/converterutil.ts`.

---

### Step 4b — TypeScript Implementation

File: `hdf-converters/converters/<name>/typescript/converter.ts`

```typescript
import { parseJSON, sha256 } from '@mitre/hdf-utilities'; // or parseXmlWithArrays for XML formats
import type {
  HDFResults, EvaluatedBaseline, EvaluatedRequirement,
  RequirementResult, Checksum, Description,
} from '@mitre/hdf-schema';
import {
  ResultStatus, HashAlgorithm,
  createMinimalBaseline, createRequirement, createResult, createDescription,
} from '@mitre/hdf-schema';

export async function convert<Name>ToHdf(input: string): Promise<string> {
  if (!input?.trim()) {
    throw new Error('Empty input');
  }

  const resultsChecksum: Checksum = {
    algorithm: HashAlgorithm.Sha256,
    value: await sha256(input),
  };

  const data = parseJSON<<SourceType>>(input);
  // ... validate structure, convert, build requirements ...

  const baseline = createMinimalBaseline(
    '<baseline name>',
    requirements,
    { resultsChecksum }
  ) as EvaluatedBaseline;

  const hdf: HDFResults = {
    baselines: [baseline],
    generator: { name: 'hdf-converters', version: '1.0.0' },
    tool: { name: '<Source Tool Name>', format: '<Format>' },
    timestamp: new Date(),
  };

  return JSON.stringify(hdf, null, 2);
}
```

#### TypeScript-specific notes

**`@mitre/hdf-schema` helpers available:**
- `createMinimalBaseline(name, requirements, options)` — builds an `EvaluatedBaseline`
- `createRequirement(id, title, descriptions, impact, results, options)` — builds a requirement; `options.tags` and `options.sourceLocation` are optional
- `createResult(status, message, options)` — builds a `RequirementResult`; `options.codeDesc` and `options.startTime` are optional
- `ResultStatus.Passed / Failed / NotReviewed / NotApplicable / Error` — status enum values
- `HashAlgorithm.Sha256` — checksum algorithm constant

**`createDescription` IS exported** from `@mitre/hdf-schema`. Use it to build description objects:
```typescript
import { createDescription } from '@mitre/hdf-schema';
const descriptions: Description[] = [
  createDescription('default', 'the primary description text'),
  createDescription('check', 'CWE-22: https://cwe.mitre.org/...'),
];
```

**`@mitre/hdf-mappings` helpers available:**
- `getCweNistControl(numericCweId: number): string | undefined` — returns a single NIST control or undefined
- `getAllCCIIds() / getCCINistMappings(cciId)` — for CCI lookups
- Tool-specific: `getNessusNistControl(pluginFamily)`, `getScoutsuitNistControl(service)`, etc.

**Build order matters for tests.** If TypeScript tests fail to resolve `@mitre/hdf-utilities`, `@mitre/hdf-mappings`, or `@mitre/hdf-schema`, those packages need to be built first:
```bash
cd hdf-utilities && pnpm build
cd hdf-mappings && pnpm build
cd hdf-schema && pnpm build
cd hdf-converters && pnpm test   # should now pass
```

#### TypeScript gotchas (lessons from SARIF development)

1. **ES2020 target**: `String.prototype.replaceAll` is not available. Use `str.split(search).join(replacement)` instead.
2. **`undefined` vs empty string**: JSON fields omitted from input arrive as `undefined`, not `""`. Always use optional chaining (`obj?.field`) and nullish coalescing (`obj?.field ?? ''`). Test assertions should use `toBeUndefined()` for truly absent fields, not `toBe('')`.
3. **Converter functions are `async`**: Because `sha256()` from `hdf-utilities` is async (Web Crypto API), all converter functions must be `async function convert<Name>ToHdf(input: string): Promise<string>`. Tests must `await` the result.
5. **`timestamp` is `Date`, not `string`**: The HDF schema `timestamp` field expects a `Date` object. Use `new Date()`, not `new Date().toISOString()`.
6. **Always run `pnpm lint && pnpm test` at root level** for final validation. Root `pnpm test` includes a `pretest` build step that catches TypeScript compilation errors that `vitest` alone does not — vitest transpiles on the fly and won't surface type errors.
7. **Optional fields in interfaces**: When defining TypeScript interfaces for parsed input, mark fields as optional (`field?: type`) when the source format doesn't guarantee their presence. This prevents runtime crashes from accessing undefined properties.

---

## Step 4c — Format Detection and Routing

Many security tools support multiple output formats. For example, gosec can emit native JSON or SARIF. Rather than requiring users to know which format they exported, converters **detect the input format and route accordingly**.

### When to add format routing

Add format routing when the source tool supports any of these common formats:
- **SARIF** — gosec, snyk, zap, jfrog-xray, semgrep, CodeQL, trivy, checkov, ESLint, fortify, veracode
- **JUnit XML** — test frameworks, CI/CD outputs
- **CycloneDX** — SBOM tools (trivy, syft, snyk, cdxgen)
- **XCCDF** — OpenSCAP, DISA STIGs

### Shared utilities

Format detection is implemented in:
- **Go:** `shared/go/formatdetect.go` — `shared.DetectFormat(input []byte) InputFormat`
- **TypeScript:** `shared/typescript/formatdetect.ts` — `detectFormat(input: string): InputFormat`

Returns `shared.FormatSARIF` / `'sarif'` (or other formats as they're added), or `shared.FormatUnknown` / `'unknown'`.

### Implementation pattern (Go)

At the top of your `Convert<Name>` function, before any tool-specific parsing:

```go
import (
    shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
    sarif "github.com/mitre/hdf-libs/hdf-converters/v3/converters/sarif-to-hdf/go"
)

func Convert<Name>(input []byte, converterVersion string) (*hdf.HDFResults, error) {
    // Format detection — delegate to shared converter if input is a common format
    if shared.DetectFormat(input) == shared.FormatSARIF {
        return sarif.ConvertSarifToHDF(input, converterVersion)
    }

    // ... native format parsing continues below
}
```

### Implementation pattern (TypeScript)

```typescript
import { detectFormat } from '../../../shared/typescript/formatdetect.js';
import { convertSarifToHdf } from '../../sarif-to-hdf/typescript/converter.js';

export function convert<Name>ToHdf(input: string): string {
  // Format detection — delegate to shared converter if input is a common format
  if (detectFormat(input) === 'sarif') {
    return convertSarifToHdf(input);
  }

  // ... native format parsing continues below
}
```

### Anti-patterns (do NOT do these)

1. **Do NOT return an error when SARIF is detected.** The converter must transparently delegate — the user should not need to know which format their file is in. Returning `fmt.Errorf("input appears to be SARIF; use the SARIF converter")` forces the user to guess.
2. **Do NOT use dynamic imports for SARIF delegation in TypeScript.** Use a static import (`import { convertSarifToHdf } from '../../sarif-to-hdf/typescript/converter.js'`), not `await import(...)`. Dynamic imports add unnecessary complexity and prevent tree-shaking.
3. **Do NOT write custom SARIF detection logic.** Use `shared.DetectFormat()` (Go) or `detectFormat()` (TypeScript) from the shared modules. Custom `isSarif()` functions duplicate logic and diverge over time.

### Required tests

Add two integration tests per language:
1. **SARIF routing** — load a SARIF fixture for the tool (e.g. `sarif-to-hdf/fixtures/input/gosec.sarif`), pass it through the tool converter, verify it produces valid HDF with enriched SARIF fields.
2. **Native not routed** — load a native fixture, verify it uses the tool-specific baseline name (not the SARIF converter's tool driver name).

---

## Step 4d — v3.2 Classification Fields (`controlType`, `verificationMethod`, `applicability`)

Schema v3.2.0 added three optional enum fields to `Requirement_Core`. Every
new converter MUST make a deliberate decision for each one — populate it only
when the **source format carries real per-finding signal** for that axis.
Blanket-stamping a constant with no signal is an anti-pattern (it's why
`DeriveControlTypeFromTags` gates out the static-fallback NIST bundles).
Omitting is always safe: consumers treat an omitted field as the conventional
default.

| Field | Enum | Set it when… |
|-------|------|-------------|
| `controlType` | `policy \| procedure \| technical \| management \| operational` | The finding has a real NIST 800-53 tag. Derive via the shared helper — never hand-roll. |
| `verificationMethod` | `automated \| manual-by-design \| manual-pending-automation \| hybrid` | The **source format guarantees** how verification happened. |
| `applicability` | `required \| optional \| advisory` | The source encodes a within-baseline applicability marker (e.g. FedRAMP OSCAL `CORE` prop, FedRAMP 20x `Optional:`). |

### `controlType` — derive from NIST tags

```go
// Go — after building the tags map with nist[] populated:
ControlType: shared.DeriveControlTypeFromTags(shared.NISTTagsFromMap(tags)),
```
```typescript
// TypeScript — pass the NIST tag array you already computed (there is no
// nistTagsFromMap helper in TS; build the array from your CCI->NIST lookup):
const nistTags = [...new Set(cciIds.flatMap((c) => getCCINistMappings(c) ?? []))].sort();
const controlType = deriveControlTypeFromTags(nistTags);
if (controlType !== undefined) req.controlType = controlType;
```

The helper returns nil/undefined when the tag set carries no signal (e.g. it
exactly matches a static-fallback bundle like `["RA-5","SA-11"]`), so a finding
with no real NIST mapping correctly gets no `controlType` rather than a
misleading one. Leave it that way — do not substitute a default.

### `verificationMethod` — only when provenance guarantees it

This is the field most easily misused. It describes the **requirement's
verification nature**, disambiguating the two cases that null `code` overloads:
inherently manual (`manual-by-design`) vs. automatable-but-not-yet
(`manual-pending-automation`). Set it ONLY when the source format *guarantees*
the answer:

- **Automated scanners** (Nessus, Burp, ZAP, Snyk, …) → `automated`, as a
  per-converter constant. Justified because the artifact is, by provenance,
  automated-scanner output: every finding *was* produced by automated
  execution. The format guarantees the claim.

- **A format merely associated with a manual workflow does NOT guarantee
  `manual-by-design`.** Worked example — the **CKL (DISA STIG Viewer
  checklist)** converter does **NOT** set `verificationMethod`, even though
  CKL is the hand-fill checklist format. Reasons, and the transferable test:
  1. A CKL rule could have been hand-assessed, *or* automated via SCAP/OVAL and
     exported to CKL by a tool, *or* mixed — the format has no field saying which.
  2. Most STIG rules are automatable, so `manual-by-design` (which asserts
     *inherently* manual) overclaims; we also can't assert
     `manual-pending-automation` per-rule.
  3. "The artifact is in the manual-workflow format" ≠ "this requirement is
     inherently manual." Provenance does not guarantee the claim, so omit.

  **The test:** does the source format *guarantee* the verification nature of
  each finding? Scanner output → yes (`automated`). A workflow-associated
  container format → usually no → omit.

### `applicability` — only on an explicit marker

Omit unless the source encodes a real within-baseline applicability signal.
A per-assessment *status* of `notApplicable` is NOT an `applicability` signal —
status is the assessment outcome, `applicability` is the baseline-level
designation. They are different axes; do not map one to the other.

### Done-checklist additions

- [ ] `controlType` derived from NIST tags via `DeriveControlTypeFromTags` (never hand-rolled); omitted when no NIST signal
- [ ] `verificationMethod` set only when the source format guarantees it (scanner provenance → `automated`); omitted otherwise
- [ ] `applicability` set only on an explicit source marker; `notApplicable` status NOT mapped to applicability

---

## Step 4e — Synthesize a passed placeholder for empty findings

The HDF schema enforces `requirements.minItems=1` on every baseline. A scanner that runs cleanly (no findings reported) still must emit one synthesized passed requirement so the document validates. A converter that emits `requirements: []` is broken.

### Pattern

When your converter's findings loop would otherwise produce zero requirements, synthesize one with the shared helper.

**Go:**
```go
if len(requirements) == 0 {
    target := /* host, project, repo, scanner, etc. — see "target derivation" below */
    requirements = []hdf.EvaluatedRequirement{
        shared.BuildNoFindingsRequirement(
            "<source>-no-findings",
            fmt.Sprintf("<Tool> scanned %s and reported zero findings.", target),
            time.Now().UTC(),
        ),
    }
}
```

**TypeScript:**
```typescript
if (requirements.length === 0) {
    const target = /* same derivation */;
    requirements.push(buildNoFindingsRequirement(
        '<source>-no-findings',
        `<Tool> scanned ${target} and reported zero findings.`,
        new Date(),
    ));
}
```

**Multi-baseline converters** (per-tool, per-host, per-scanner): apply the synthesizer **per empty baseline**, not just when the whole result has zero requirements. Iterate `baselines[]`, skip those with `requirements.length > 0`, synthesize for the rest. See `msft-defender-devops-to-hdf` for the model.

### Conventions

- **ID:** `<source>-no-findings` (kebab-case source name, matches the converter directory). For multi-baseline converters where each baseline represents a sub-tool or per-run identity, use `<sub-tool>-no-findings` derived from the baseline's natural name — e.g. MSDO produces `bandit-no-findings`/`eslint-no-findings` per scanner; `sarif-to-hdf` produces `<run.tool.driver.name>-no-findings` per SARIF run.
- **codeDesc:** `<Tool> <verb> <target> and reported zero <noun>.`
  - **verb:** `scanned` (default — Nessus, Burp Suite, Checkov, Snyk, Grype, ZAP, etc.); `analyzed` (Dependency-Track); `ran` (multi-tool wrappers — MSDO, generic SARIF).
  - **noun:** `findings` (default, including DAST/SAST/cloud-config/secrets scanners); `vulnerable components` (SCA / dependency / container-vuln scanners — Dependency-Track, Grype, JFrog Xray, NeuVector, Prisma Cloud, Snyk, Twistlock).
  - **target:** the most specific identifier the report provides — host, project name, repo, image, URL, scanner name. Fall back to a hardcoded generic phrase only when the report has no identifying field at all (examples in tree: gosec → `"Go codebase"`, JFrog Xray → `"the target artifact"`, MS Defender for Endpoint → `"the tenant"`, Prisma Cloud → `"the workload"`, TruffleHog → `"the target source"`, XCCDF results → `"the target"`, Veracode → `"Veracode Application"`).
  - **Pattern flexibility:** when the source's natural identifier doesn't fit the strict `<verb> <target>` template, prefer readability over template adherence. Example: GitLab security reports lack a project field; their codeDesc reads `GitLab <SAST|DAST|...> scan via <scanner> reported zero findings.` This still satisfies the convention (tool name, verb, scanner-as-target, "reported zero findings") but bends the literal word order. Do this sparingly and only when the natural target is genuinely awkward in the default template.
- **title, status, impact, tags, descriptions:** set by the shared helper — do not pass them. The helper produces `title="No findings reported"`, `status=passed`, `impact=0`, `tags={}`, one description with `label="default"` and `data=codeDesc`. All synthesized placeholders share this shape — do not inline a custom struct, refactor to the helper.

### `passed` vs. `notApplicable` — the distinction matters

Synthesize **`passed`** when the scanner *ran* against in-scope inputs and found nothing wrong. This is the default. Spec-backed: NIST 800-53A *Satisfied*, OSCAL `satisfied`, XCCDF `pass`, STIG *Not_a_Finding*, SARIF v2.1.0 §3.7.2 (empty `results[]` array means the scan ran clean). The shared `BuildNoFindingsRequirement` helper produces `passed` for this case.

Synthesize **`notApplicable`** when the rule's applicability check itself didn't run — e.g. an AWS Config rule with zero in-scope resources, where the rule never evaluated against anything. The codeDesc should explain *why* it didn't apply, and `tags` should preserve the scan metadata. Do NOT use `BuildNoFindingsRequirement` for this case; construct the requirement explicitly with `Status: hdf.NotApplicable`. See `aws-config-to-hdf` for the model.

The wrong choice silently misleads consumers: `passed` says "we checked and you're compliant"; `notApplicable` says "we didn't check this one."

### Test the empty case

Every converter MUST have an `empty.<ext>` fixture in `fixtures/input/` and a test asserting the synthesized placeholder shape. TDD-first: write the test before the synthesizer.

```go
func TestConvert_EmptyFindings(t *testing.T) {
    result, err := ConvertFoo(loadFixture(t, "empty.<ext>"), converterVersion)
    require.NoError(t, err)
    require.Len(t, result.Baselines, 1)
    require.Len(t, result.Baselines[0].Requirements, 1)
    req := result.Baselines[0].Requirements[0]
    assert.Equal(t, "foo-no-findings", req.ID)
    require.Len(t, req.Results, 1)
    assert.Equal(t, hdf.Passed, req.Results[0].Status)
    assert.Contains(t, req.Results[0].CodeDesc, "Foo")
}
```

Mirror the same assertions on the TypeScript side. The empty fixture should be a **valid input that the converter would accept** but with the findings array(s) empty — same outer structure as a real report, zero findings inside.

---

## Step 4f — Amendment-Output Converters

Some converters target HDF Amendments instead of HDF Results / Baseline. Use this pattern when the source format describes CONSUMER DECISIONS about findings — or third-party context the consumer is attaching to findings — not raw scanner findings themselves.

### When to use the amendment-output pattern

Use amendment-output when the source format:
- Records waivers, attestations, or POA&M items (OSCAL POA&M, eMASS waivers, FedRAMP deviation requests)
- Carries vulnerability-context statements meant to be attached to existing findings (VEX flavors: OpenVEX, CSAF VEX, CycloneDX VEX)
- Captures consumer risk-acceptance decisions (GRC system exports — Archer, ServiceNow GRC)

The act of attaching the source data to an HDF document IS the amendment act — even when the underlying claim originates upstream (vendor, distributor, governing body). The consumer's ingestion of that claim is the override.

### Real-system vs abstract-vuln distinction

Critical for any converter pulling supplier-statement data (VEX, CTI feeds, advisory streams):

- The source format describes an ABSTRACT VULNERABILITY OR PRODUCT VERSION in general (e.g. "log4j 2.x is vulnerable to CVE-2021-44228")
- HDF describes a SPECIFIC ASSESSED SYSTEM (e.g. "this Nessus scan ran on host A.B.C.D and reported CVE-2021-44228")

VEX `fixed` = "the vendor has released a fix in product version X." It is NOT evidence that the assessed system has that fix installed. A converter that maps `fixed` to `status='passed'` lies to the consumer about their real system state.

**Pattern:** Synthesize a POA&M with an `action_statement` reminding the consumer to apply and re-scan. Pin status to the pre-amendment effective value (typically `failed`) on the open POA&M. Status flips to `passed` only when the consumer re-scans and the new scan reflects the fix.

### Infrastructure

- **Go registry type**: `hdfAmendmentsConverter` in `hdf-cli/cmd/hdf/cmd/converter_registry.go` (parallel to `hdfResultsConverter` / `hdfBaselineConverter`).
- **One-liner CLI registration**: `registerHDFAmendmentsConverter(source, displayName, errPrefix, fn)` where `fn` is `func([]byte, string) (*hdf.HDFAmendments, error)`.
- **Auto-detect**: `detectHDFDocType` in `output_validation.go` recognizes top-level `overrides[]` → "amendments" and routes auto-validation through `validators.ValidateAmendments`.

### Shared ecosystem helper pattern

When the source format is one of a family (VEX has three flavors; OSCAL has 7 document types; etc.), factor the mapping logic into a shared helper at `hdf-converters/shared/{go,typescript}/<family>/`:

- Canonical status enum + normalization function (each ecosystem dialect → canonical)
- Justification / vocabulary mapping with unknown-value passthrough (don't drop values; warn or preserve raw in `reason`)
- Import-direction target selector (canonical status → HDF override type + status + flags)
- Export-direction status selector (HDF override state → canonical status)
- Supplier-identity-to-evidence builder (preserve provenance via `evidence[type=url]`)

The shared helper is the natural enforcement point for the real-system distinction — import targets that would otherwise flip status to `passed` on a supplier claim should be coded explicitly to NOT do so.

Reference: `hdf-converters/shared/{go,typescript}/vex/` (worked example from openvex-to-hdf).

### Schema invariants on `StandaloneOverride`

HDF Amendments has stricter shape requirements than HDF Results. Memorize these before writing the converter — schema validation will surface them late if you don't:

1. **`overrides.minItems = 1`** — a document with zero overrides fails schema validation. A converter that filters out every source statement (e.g. all VEX statements are `affected` or `under_investigation`) MUST NOT emit an empty document. Error out with a clear message ("no actionable statements") so the user knows the source produced no consumer-action payload.
2. **status / impact required on all non-`operationalRequirement` overrides** — schema enforces this via an `if`/`else` branch on `type`. POA&M, waiver, attestation, riskAdjustment, falsePositive, inherited all require at least one of `status` or `impact`. POA&M from supplier `fixed` should pin status to the pre-amendment value (typically `failed`) — the act of filing the POA&M doesn't itself change the system's state.
3. **`operationalRequirement` is the inverse** — neither `status` nor `impact` may be set. Documentation-only override.
4. **`expiresAt` is required and time-bounded** — no permanent amendments. Default to a reasonable horizon (one year is the common choice for VEX-style imports) and let re-imports refresh it.
5. **`appliedAt` and `appliedBy` are required** — derive from the source document's author + timestamp fields. Statement-level overrides supersede document-level when both present.

### Empty-input handling — error, do not synthesize

Step 4e's `passed`-placeholder pattern does NOT apply. The `requirements.minItems=1` invariant on Results / Baselines is what motivates the synthesizer — the scanner ran and found nothing, but the document still must validate. Amendment-output is different:

- An amendments document represents CONSUMER ACTION. "No actionable statements" means the consumer is not amending anything.
- The right response is to **error out and not write a document**, NOT to synthesize a placeholder attestation. A placeholder attestation that says "no amendment to apply" is itself a misleading amendment.

```go
if len(overrides) == 0 {
    return nil, fmt.Errorf("<source>-to-hdf: source document contains no actionable statements; no amendment to write")
}
```

### Sections that are N/A for amendment-output

When building an amendment-output converter, the following standard sections do NOT apply (the HDF Amendments shape has no equivalent):

- **Step 4c — Format Detection and Routing**: VEX / OSCAL POA&M / GRC exports don't share a wire format with SARIF / JUnit / CycloneDX results. (If your specific format DOES share a wire shape with one of those, route to the canonical converter as Step 4c describes.)
- **Step 4d — controlType / verificationMethod / applicability**: those fields are on `Requirement_Core`. Amendments target requirements but don't define them, so the classification axes don't appear on `StandaloneOverride`.
- **Step 4e — passed placeholder synthesizer**: replaced by the error-on-empty rule above.
- **Baseline.Name / Components conventions**: Amendments have no embedded baselines or components — they reference a baseline via `baselineRef` and a component via `componentRef`, both URI / id fields.
- **Tool driver name / NIST mapping**: amendments don't restate the underlying scanner. The original tool + NIST mapping live on the HDF Results document this amendments document is amending.

### CLI integration shape

```go
// hdf-cli/cmd/hdf/cmd/converter_<snake>.go
package cmd

import <pkg> "github.com/mitre/hdf-libs/hdf-converters/v3/converters/<name>/go"

func init() {
    registerHDFAmendmentsConverter("<source>", "<Source> to HDF Amendments", "<source>", <pkg>.Convert<Name>)
}
```

### CLI test shape

Standard `runStandardConverterTests` does NOT work — it asserts `validators.ValidateResults`. Write a focused test:

```go
func Test<Name>Converter_RegisteredAndProducesValidAmendments(t *testing.T) {
    converter, err := GetConverter("<source>", "hdf")
    require.NoError(t, err)
    assert.Equal(t, "<Source> to HDF Amendments", converter.Name())

    input, _ := os.ReadFile(converterFixturePath(t, "<name>-to-hdf", "input/minimal.<ext>"))
    output, err := converter.Convert(input)
    require.NoError(t, err)

    docType, ok := detectHDFDocType(output)
    require.True(t, ok)
    assert.Equal(t, "amendments", docType)

    result := validators.ValidateAmendments(output)
    assert.True(t, result.Valid, "amendments output must pass schema validation: %s", result.Error())
}
```

Also test the empty-input error path: a fixture with no actionable source statements must return an error containing your "no actionable" message, NOT silently produce an empty document.

### Done-checklist additions (amendment-output)

- [ ] Output validated against `validators.ValidateAmendments` in Go tests AND in CLI tests (auto-detect routes correctly)
- [ ] CLI test asserts `detectHDFDocType` returns `"amendments"`
- [ ] `overrides.minItems=1` invariant: a fixture with no actionable source statements produces an error, not an empty document
- [ ] Each emitted override sets one of `status` / `impact` (unless type is `operationalRequirement`)
- [ ] Supplier-claim sources (VEX, advisories) do NOT flip status to `passed` on `fixed` / `resolved` — they synthesize a POA&M and pin status to the pre-amendment value
- [ ] `expiresAt` set to a finite horizon; choice documented in code
- [ ] Shared ecosystem mapping helper lives in `hdf-converters/shared/{go,typescript}/<family>/`, not inlined in the converter
- [ ] Unknown justification / status values from the source are preserved (passed through into `reason` or evidence), not silently dropped

---

## Step 5 — CLI Integration

File: `hdf-cli/cmd/hdf/cmd/converter_<snake>.go`

```go
package cmd

import (
    "encoding/json"
    "fmt"

    <pkg> "github.com/mitre/hdf-libs/hdf-converters/v3/converters/<name>/go"
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

If the source is a live API rather than a static export file (aws-config, sonarqube, splunk, gitlab, aws-securityhub, and similar), the fetcher is built with the **`/build-fetcher`** skill — not here. Fetchers now live in `hdf-converters/fetchers/<tool>/{go,typescript}/` (next to their converter), are dual-language, and follow the two-constructor Go convention + auth-agnostic TS contract documented in `hdf-converters/fetchers/README.md`.

Build the converter first (this skill); then build the fetcher that feeds it (`/build-fetcher`).

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
# Quick iteration: run Go and TS tests for your converter
cd hdf-converters && go test ./converters/<name>/go/...
cd hdf-converters && pnpm vitest run converters/<name>

# Run CLI tests
cd hdf-cli && go test ./cmd/hdf/cmd/ -run <Name> -v

# MANDATORY: Run lint + full test suite at root level before committing.
# Root `pnpm test` includes a `pretest` build step that catches TypeScript
# compilation errors that vitest alone does not surface.
cd /path/to/hdf-libs && pnpm lint && pnpm test

# Spot check real output via CLI binary
cd hdf-cli && go build -o hdf ./cmd/hdf
./hdf convert --from <source> path/to/input.ext -o output.json
cat output.json | head -40
```

**Do not consider the converter done until `pnpm lint && pnpm test` passes at root level.** Individual package tests may pass while the TypeScript build is broken (wrong types, missing exports, etc.).

---

## Coverage Requirements

- **>90% line/branch coverage** on `converter.go`
- Every public function must have at least: happy path, invalid input, and empty input tests
- Every non-trivial private helper should have direct unit tests
- CLI test must cover: registered, minimal conversion, invalid input

---

## Done Checklist

**All converters:**
- [ ] Fixtures sourced from real tool output or validated against format schema — provenance documented in commit message
- [ ] No fabricated fixtures — every fixture is either from a real run, a public repo, heimdall2/SAF CLI samples, or schema-validated
- [ ] **Go:** Unit tests written and passing (`go/converter_test.go`)
- [ ] **Go:** Implementation complete (`go/converter.go`)
- [ ] **TypeScript:** Unit tests written and passing (`typescript/converter.test.ts`)
- [ ] **TypeScript:** Implementation complete (`typescript/converter.ts`)
- [ ] **TypeScript:** Barrel export (`typescript/index.ts`) and re-export from `hdf-converters/src/index.ts`
- [ ] **TypeScript:** Export existence test in `hdf-converters/test/index.test.ts`
- [ ] CLI registration file (`converter_<snake>.go`) — add `//nolint:dupl` if lint flags it as a duplicate of another thin converter wrapper
- [ ] CLI tests passing (`converter_<snake>_test.go`)
- [ ] `pnpm lint` clean
- [ ] `pnpm test` passes (Go and TypeScript)
- [ ] Spot-checked output looks correct

**API-pull converters additionally (aws-config, sonarqube, ionchannel, msft-secure-score, splunk):**
- [ ] Static format definition verified against real API documentation or heimdall2 source — not invented
- [ ] Fetcher implemented via `/build-fetcher` (`hdf-converters/fetchers/<name>/`)
- [ ] Fetcher tests use `httptest.Server` (or SDK interface injection for AWS) — no live credentials required
- [ ] Security agent review completed covering: credential handling, input validation, pagination caps, context cancellation, default timeout, error message safety
- [ ] All security findings addressed before marking done
- [ ] `--live` flag wired into CLI converter command, file-based path still works
- [ ] Spot-checked live mode output (or documented why a live spot-check isn't possible)

**Converters for tools that can emit NDJSON / line-delimited JSON (review Step 4 — Input parsing):**
- [ ] `Convert()` handles all shapes the tool emits: JSON array, single object, AND line-by-line NDJSON
- [ ] `*.ndjson` fixture from real `--json`/streaming output exists in `fixtures/input/`
- [ ] Go + TS tests convert the NDJSON fixture to valid HDF
- [ ] CLI auto-detect test: `convert <fixture>.ndjson` with no `--from` detects the tool (guards the registry first-line fingerprint path)

**Converters for tools with SARIF/JUnit/CycloneDX/XCCDF support (review Step 4c):**
- [ ] Format detection added at top of converter function (Go + TypeScript)
- [ ] SARIF routing test: tool's SARIF output produces valid HDF via shared converter
- [ ] Native format test: native input is NOT routed to shared converter
- [ ] SARIF fixture exists in `sarif-to-hdf/fixtures/input/` for the tool (or reuses existing one)

**All converters — Empty findings (review Step 4e):**
- [ ] `empty.<ext>` fixture exists in `fixtures/input/` — valid input shape with zero findings
- [ ] Empty-findings test in Go and TypeScript asserts the synthesized placeholder: id `<source>-no-findings`, status `passed`, codeDesc names the tool and target
- [ ] Synthesizer uses `shared.BuildNoFindingsRequirement` (Go) / `buildNoFindingsRequirement` (TS) — never an inlined struct
- [ ] Multi-baseline converters apply the synthesizer per empty baseline, not once at the end
- [ ] Decision logged: this converter emits `passed` (scanner ran clean) vs. `notApplicable` (rule didn't apply at all). Default is `passed`; `notApplicable` requires source-format justification.

**All converters — Baseline.Name and Components (review HDF Type Reference):**
- [ ] `Baseline.Name` is a fixed scan label (e.g., `"Nessus Scan"`), NOT dynamic data like a hostname or project name
- [ ] `Baseline.Title` contains dynamic context (e.g., `"Nessus Scan of 192.168.1.0/24"`)
- [ ] `Components` populated when the source tool scans an identifiable target (URL, host, repo, cloud account)
- [ ] Component `Type` matches tool category (`Application` for DAST, `Repository` for SAST, `Host` for host scanners, etc.)
- [ ] Component omitted (not set to "Unknown") when no identifiable target exists

**Amendment-output converters (review Step 4f):**
- [ ] Output type decision logged in plan: HDF Amendments vs Results/Baseline, with rationale
- [ ] Step 4f done-checklist completed (see Step 4f for the full list)
- [ ] Empty-input error path tested (fixture + Go test + TS test)
- [ ] Sections N/A for amendment-output explicitly skipped (4c routing if not applicable, 4d classification fields, 4e passed-placeholder, Baseline.Name/Components)

**All converters — field coverage (review Step 1a):**
- [ ] Coverage judged against the source **spec/schema** where one exists (every spec-defined field mapped or justified) — NOT just the fields present in the sample fixture
- [ ] Every source field has a logged disposition: mapped, no-HDF-home (Step 1b), or asked-the-developer — none silently dropped
- [ ] Structured data lands in its structured HDF field, not freetext: `cvss[]` (score+vector), `cwe[]`, `epss`/`kev`, `sourceLocation`, `components[]`, `refs[]`, `statusOverrides[]`, `requirement.code`
- [ ] Top-level `timestamp` / result `startTime` / `tool.version` come from the source when it supplies them (never `time.Now()`/`new Date()` as a substitute for a real source time)
- [ ] No "parsed into the struct but never emitted" fields — each is mapped or justified in the plan

**Schema-extension converters (review Step 1b):**
- [ ] Field-gap audit performed BEFORE implementation; categories (a)/(b)/(c) logged in plan
- [ ] No silent schema additions — any new field surfaced to the user with rationale
- [ ] Any schema addition is generalized (not tied to one source format) and optional

**All converters — library usage check (review Step 4b):**
- [ ] NIST/CCI lookups delegate to `hdf-mappings` — no hardcoded lookup tables in converter code
- [ ] CCI lookups use `cci.NISTToCCI()` / `nistToCci()` — not brute-force iteration over all CCI IDs
- [ ] TypeScript uses `parseJSON()` from `hdf-utilities` — not raw `JSON.parse()`
- [ ] TypeScript uses `severityToImpact()` from `hdf-schema` — not a custom impact map (unless non-standard severity labels)
- [ ] TypeScript uses `createMinimalBaseline()`, `createRequirement()`, `createResult()` from `hdf-schema` where applicable
- [ ] HDF types imported from `hdf-schema` — not redefined in converter
- [ ] HDF output validation in CLI tests uses `assertHDFOutput()` / `hdf-validators` — no ad-hoc field checks as substitute
- [ ] CSV/XML parsing uses `hdf-utilities` (TypeScript) or Go stdlib — no new third-party parser deps
- [ ] If a new mapping package was created: exported from `hdf-mappings/src/index.ts`, added to the table and usage examples in `hdf-mappings/README.md`
- [ ] New format added to "Supported Conversions" table in `hdf-cli/README.md`
- [ ] New format added to converter table in `hdf-converters/README.md`
