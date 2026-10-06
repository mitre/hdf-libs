# Writing a Converter

A converter turns a source security tool's output into HDF. These libraries implement dozens (around 60 at time of writing) of converters that allow HDF to make good on its promise of serving as the normalization point for security assessment data of all types.

The converters are what enable HDF to be used practically. They are how CLI tools and apps can ingest disparate sources (SARIF documents, InSpec scans, OWASP ZAP reports, and so on) representing many different parts of the software stack and create a common dataset from them.

This page provides a brief overview of how a new converter is built and added to the HDF libraries, in both Typescript and Go implementations. HDF is intended to be community driven, so if you want your favorite scanning tool's custom output to be convertable to HDF, feel free to put up a pull request following these conventions. Note that the HDF Libs repo includes a `build-converter` skill that automates much of this process if you're using coding agents (but as always, it is on the human to ensure that the outcome is correct).

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

Build against the shared helpers rather than reimplementing them. `buildHdfResults` / `BuildHDFResults` assemble the document; `MapCWEToNIST`, `inputChecksum` and `LimitSliceWithWarning` live in `hdf-converters/shared`, while lower-level primitives such as `SeverityToImpact` and `ParseTimestamp` come from `hdf-utilities`. A converter that reinvents library functionality will be sent back — check what exists before writing.

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

**Instance identity.** Every result must say *what* it describes, in the structured fields rather than only in `codeDesc` prose. `Requirement_Result.resource` names the **kind** of thing; `resourceId` names the **identity** of that thing. The requirement id answers "which requirement is this?"; the result's identity answers "which instance of it?". Set both or neither — a `resource` with no `resourceId` is a half-identified result, and an empty-string `resourceId` is worse than an absent one.

`resourceId` does **not** have to be unique within a requirement's `results[]`. It names a resource, not a finding: two flaws at the same file and line genuinely affect the same resource, so two results carrying the same `resourceId` is a true statement. Findings are distinguished by the whole result — `codeDesc`, `message`, and the source record — never by `resourceId`. Do not append a finding discriminator to force uniqueness; that makes the field name a finding and re-creates the overloading this convention exists to undo.

The mapping per converter, as ratified:

| Converter | `resource` | `resourceId` |
|---|---|---|
| grype | `package` | the artifact purl, else `name@version` |
| twistlock | `package` | `packageName@packageVersion` (the source has no purl) |
| cyclonedx | `component` | the component purl, else its `bom-ref`, else the unresolved `affects[].ref` for a VEX document with no `components[]` |
| veracode (static flaws) | `file` | `sourcefilepath + sourcefile + ":" + line` |
| veracode (SCA) | `component` | `component_id`, else `sha1` |
| neuvector | `file` when `file_name` is present, otherwise `package` | the file path, else `package_name@package_version` |
| zap | `url` | the instance `uri` |

Four things that caught us, worth knowing before mapping a new tool:

- **A file and line is a *location*, not an instance.** Veracode reports two distinct flaws at `UserController.java:898`; ZAP fires the same alert at one URL with a different `param`. Both are correct, and both are why uniqueness is not required.
- **A discriminator can be mostly absent.** NeuVector's `file_name` is the only thing separating its duplicate groups, but it is empty on 220 of 305 entries — so the primary identifier covers 28% of results and needs a fallback that keeps the `resource` kind truthful. Check population across every fixture before committing to a field.
- **Scan-level identity is not result-level identity.** An image digest, registry or repository describes the whole scan and belongs in `components[]`. Putting it in `resourceId` asserts that every finding affects the entire image.
- **A converter whose results aggregate several instances cannot carry an identity at all.** `scoutsuite-to-hdf` newline-joins its flagged items into one result, so no single `resourceId` is honest; it carries a guard test asserting both fields stay unset, which fails deliberately once the items are split into one result each. `prisma-to-hdf` has a recorded exception for a different reason — its discriminator exists only in free-text prose, and parsing it was rejected as too fragile.

A no-findings placeholder result carries no identity: there is no instance to name.

**Delegation.** Several tools can emit SARIF, CycloneDX or JUnit as well as their native format. Detect and delegate to the existing converter rather than reimplementing that format; `checkov-to-hdf` routes SARIF input to `sarif-to-hdf` in both languages.

**Empty results.** A scan that found nothing is not the same as a scan that failed. Emit a no-findings placeholder requirement so an empty document stays distinguishable from a broken one.
