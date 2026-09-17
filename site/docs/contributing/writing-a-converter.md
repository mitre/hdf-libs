# Writing a Converter

A converter turns one security tool's output into HDF. There are 60-odd of them, each implemented twice — TypeScript for `@mitre/hdf-converters`, Go for the `hdf` CLI — against shared fixtures that keep the two honest.

This page is the human walkthrough. If you work in Claude Code, the `/build-converter` skill automates the same process in more depth; this page is what to read when you want to understand the shape rather than delegate it.

Related conventions live elsewhere and are not repeated here: the [developer guide](./developer-guide.md) covers the dual-implementation pattern, differential testing, timestamps and number formatting; [using mappings](./using-mappings-in-converters.md) covers enriching output with NIST controls.

## Why two implementations

The TypeScript build serves web and Node consumers through npm. The Go build produces a single CLI binary with no runtime dependency and a smaller attack surface — no Node runtime, no npm dependency tree at execution time. Neither is a port of the other in spirit: both are maintained, and shared fixtures prove they agree.

## What a converter looks like

```
converters/<tool>-to-hdf/
├── typescript/
│   ├── index.ts            # re-exports the entry point
│   ├── converter.ts        # the conversion
│   ├── converter.test.ts   # unit tests
│   ├── snapshot.test.ts    # golden comparison against fixtures/expected
│   └── fingerprint.ts      # auto-detect signature (if the format is detectable)
├── go/
│   ├── converter.go
│   ├── converter_test.go
│   ├── fingerprint.go
│   └── fidelity_test.go    # requirement-count fidelity
└── fixtures/
    ├── input/              # real tool output
    └── expected/           # expected HDF, schema-validated
```

## The entry points

The two languages differ in what they return, which surprises people. TypeScript serializes; Go returns the typed document and lets the caller serialize:

```typescript
export async function convertCheckovToHdf(
  input: string,
  converterVersion = '1.0.0',
): Promise<string> {
  validateInputSize(input, 'checkov');
  // ...
}
```

```go
func ConvertCheckovToHDF(input []byte, converterVersion string) (*hdf.HDFResults, error) {
```

The document type is `HDFResults` — or `HDFBaseline`, `HDFPlan` or `HDFAmendments` for converters that produce those. Decide which you are producing before you start; the registration helper differs per type.

**Validate size first.** `validateInputSize` / `ValidateJSONSize` (or `ValidateXMLInput` for XML) must be the first operation, before parsing. This is a security requirement, not a style preference — it is what stops a hostile input from exhausting memory during the parse.

## The steps

### 1. Source real fixtures

Never fabricate them. A fixture must be real tool output, adapted from heimdall2 or SAF CLI, or validated against the format's official schema with the proof recorded. A converter tested against invented data proves nothing about real data — the fixture is the thing that decides whether it works.

Fixtures stay in `converters/<tool>-to-hdf/fixtures/` as that converter's tested contract. They move to `@mitre/hdf-fixtures` only once a second workspace package actively loads the same file, and the original is deleted — no duplicates.

### 2. Write the tests first

Tests define the spec. Write them against the fixture you sourced, watch them fail, then implement.

```typescript
it('converts the minimal fixture', async () => {
  const hdf = JSON.parse(await convertCheckovToHdf(loadFixture('minimal.json')));
  expect(hdf.baselines[0].requirements).toHaveLength(4);
});
```

Prefer an input-derived count over a literal where one is available — `countXmlElements` / `CountXMLElements` with `assertRequirementCount` derive the expected number from the source document, so the converter cannot define its own correctness.

### 3. Implement both languages

Build against the shared helpers rather than reimplementing them. `buildHdfResults` / `BuildHDFResults` assemble the document; `SeverityToImpact`, `MapCWEToNIST`, `inputChecksum`, `LimitSliceWithWarning` and the rest live in `hdf-converters/shared`. A converter that reinvents library functionality will be sent back — check what exists before writing.

Parse timestamps with `parseTimestamp` / `ParseTimestamp`, never `new Date(value)` or `time.Parse` directly; zone-less input is otherwise read as host-local and the two languages diverge.

### 4. Register it

**A converter is not finished until the CLI can invoke it.** Three pieces:

Add the registry wrapper at `hdf-converters/registry/convert/converter_<tool>.go`:

```go
package convert

import checkov "github.com/mitre/hdf-libs/hdf-converters/v3/converters/checkov-to-hdf/go"

func init() {
	registerHDFConverter("checkov", "Checkov to HDF", "checkov", checkov.ConvertCheckovToHDF,
		WithExpectedRequirementCount(checkov.ExpectedRequirementCount))
}
```

Use the helper matching your output type: `registerHDFConverter` for Results, `registerHDFBaselineConverter` for Baseline, `registerHDFPlanConverter` for Plan, `registerHDFAmendmentsConverter` for Amendments. The `Multi` variants register one converter under several source names.

If the format is auto-detectable, add a blank import for its fingerprint in `hdf-converters/registry/all/all.go`.

Add the CLI integration test at `hdf-cli/cmd/hdf/cmd/converter_<tool>_test.go`, exercising the converter through the registry as the CLI reaches it.

### 5. Verify

Run both suites, then drive the real binary — the CLI path is what users touch, and it exercises registration, which the unit tests do not:

```bash
cd hdf-converters && go test ./converters/<tool>-to-hdf/... && pnpm exec vitest run converters/<tool>-to-hdf
hdf convert --from <tool> fixtures/input/sample.json -o out.json
hdf validate out.json
```

The converter catalog page is generated from the live registry and golden-tested, so a newly registered converter appears there once the manifest is regenerated.

## Common patterns

**Severity.** Map the tool's vocabulary onto HDF impact through the shared helpers rather than a private table. Where a tool reports no usable severity, mark it — a defaulted 0.5 is otherwise indistinguishable from a real medium, which is what `tags.severity_rating = "unrated"` exists to disambiguate.

**Identifiers.** A requirement id must be stable across runs and unique within the document. Prefer the tool's own rule or check identifier. Where one identifier can legitimately recur — the same control implemented by two components — qualify it so the two stay distinguishable, rather than emitting duplicates that no consumer can match.

**Delegation.** Several tools can emit SARIF, CycloneDX or JUnit as well as their native format. Detect and delegate to the existing converter rather than reimplementing that format; `checkov-to-hdf` routes SARIF input to `sarif-to-hdf` in both languages.

**Empty results.** A scan that found nothing is not the same as a scan that failed. Emit a no-findings placeholder requirement so an empty document stays distinguishable from a broken one.
