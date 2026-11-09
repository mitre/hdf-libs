# @mitre/hdf-converters

Convert security tool outputs to and from Heimdall Data Format (HDF). Part of the [hdf-libs](https://github.com/mitre/hdf-libs) monorepo.

Every converter is implemented in both TypeScript and Go. The TypeScript library is published as an npm package; the Go implementations are used by the [`hdf` CLI](https://github.com/mitre/hdf-libs/tree/main/hdf-cli).

Security-tool importers produce [schema-validated HDF](https://mitre.github.io/hdf-libs/schemas/). Exporters produce their documented target formats.

## Supported Converters

### Security Tool to HDF

| Source Format | Function | Input |
|---|---|---|
| ASFF (AWS Security Finding Format) | `convertAsffToHdf` | JSON |
| AWS Config | `convertAwsConfigToHdf` | JSON |
| BurpSuite | `convertBurpsuiteToHdf` | XML |
| Checkov | `convertCheckovToHdf` | JSON |
| CKL (DISA STIG Viewer checklist) | `convertCklToHdf` | XML |
| CKLB (DISA STIG Viewer 3.x checklist) | `convertCklbToHdf` | JSON |
| Conveyor | `convertConveyorToHdf` | JSON |
| CSAF VEX (→ HDF Amendments) | `convertCsafVexToHdf` | JSON |
| CycloneDX (SBOM) | `convertCyclonedxToHdf` | JSON |
| CycloneDX VEX (→ HDF Amendments) | `convertCyclonedxVexToHdf` | JSON |
| DBProtect | `convertDbprotectToHdf` | XML |
| DefectDojo | `convertDefectDojoToHdf` | JSON |
| Dependency-Track | `convertDeptrackToHdf` | JSON |
| Fortify | `convertFortifyToHdf` | XML |
| GitLab Security Report | `convertGitlabToHdf` | JSON |
| GitLab Vulnerability Report (fetcher envelope, triage state preserved) | `convertGitlabVulnerabilitiesToHdf` | JSON |
| Gosec | `convertGosecToHdf` | JSON |
| Grype | `convertGrypeToHdf` | JSON |
| hadolint | `convertHadolintToHdf` | JSON |
| Hipcheck | `convertHipcheckToHdf` | JSON |
| Ion Channel | `convertIonchannelToHdf` | JSON |
| JFrog Xray | `convertJfrogXrayToHdf` | JSON |
| JUnit | `convertJunitToHdf` | XML |
| KICS | `convertKicsToHdf` | JSON |
| MSFT Defender for Cloud | `convertMsftDefenderCloudToHdf` | JSON |
| MSFT Defender for DevOps | `convertMsftDefenderDevopsToHdf` | JSON |
| MSFT Defender for Endpoint | `convertMsftDefenderEndpointToHdf` | JSON |
| MSFT Secure Score | `convertMsftSecureScoreToHdf` | JSON |
| Nessus | `convertNessusToHdf` | XML |
| Netsparker / Invicti | `convertNetsparkerToHdf` | XML |
| NeuVector | `convertNeuvectorToHdf` | JSON |
| Nikto | `convertNiktoToHdf` | JSON |
| OpenVEX (→ HDF Amendments) | `convertOpenVexToHdf` | JSON |
| OSCAL Catalog | `convertOscalCatalogToHdf` | JSON |
| OSCAL Component Definition | `convertOscalComponentToHdf` | JSON |
| OSCAL POA&M | `convertOscalPoamToHdf` | JSON |
| OSCAL Profile | `convertOscalProfileToHdf` | JSON |
| OSCAL SAP | `convertOscalSapToHdf` | JSON |
| OSCAL SAR | `convertOscalSarToHdf` | JSON |
| OSCAL SSP | `convertOscalSspToHdf` | JSON |
| OWASP ZAP | `convertZapToHdf` | JSON |
| Prisma Cloud | `convertPrismaToHdf` | JSON |
| SARIF | `convertSarifToHdf` | JSON |
| ScoutSuite | `convertScoutsuiteToHdf` | JSON |
| Semgrep | `convertSemgrepToHdf` | JSON (native; SARIF auto-routed) |
| Snyk | `convertSnykToHdf` | JSON |
| SonarQube | `convertSonarqubeToHdf` | JSON |
| SPDX VEX (SPDX 3.0 security profile → HDF Amendments) | `convertSpdxVexToHdf` | JSON |
| Splunk | `convertSplunkToHdf` | JSON |
| Trivy | `convertTrivyToHdf` | JSON (native; SARIF/CycloneDX/ASFF/GitLab auto-routed) |
| TruffleHog | `convertTrufflehogToHdf` | JSON |
| Twistlock | `convertTwistlockToHdf` | JSON |
| Veracode | `convertVeracodeToHdf` | XML |
| XCCDF Results | `convertXccdfResultsToHdf` | XML |

### Semgrep rule references

Native Semgrep conversion reads rule-author metadata `source-rule-url` and
`source_rule_url` independently as external references. Both contribute to HDF
requirement `refs`, alongside the existing reference fields; distinct URLs are
retained and identical URLs appear once. Neither key overrides the other, and
unrecognized spellings are not inferred. Empty, redacted or non-string values
follow the converter's existing per-field filtering. Semgrep JSON field names, including metadata and its containing objects, are
case-sensitive in both languages: differently capitalized keys are ignored and
cannot overwrite canonical values. Other Go decoding behavior, including
last-value handling of duplicate exact keys, is retained.

These keys are used by published rules to link to other rule implementations or
documentation; neither is a spelling error. `refs` carries the links, not their
original metadata keys. Retain the original scanner artifact when that provenance
is needed. Source-preserving SIEM export bundles preserve their HDF input; they
cannot reconstruct scanner metadata omitted during import.

### HDF to Other Formats

| Target Format | Function |
|---|---|
| CSV | `convertHdfToCsv` |
| HTML report (self-contained; executive, manager or administrator) | `convertHdfToHtml`; `convertHdfDocumentsToHtml` for several documents in one report |
| ECS (Elastic Common Schema 9.4.0 NDJSON) | `convertHdfToEcs` |
| Splunk (CIM Vulnerabilities / HEC NDJSON) | `convertHdfToSplunk` |
| OCSF (v1.8.0 Compliance / Vulnerability Finding NDJSON) | `convertHdfToOcsf` |
| ASFF (AWS Security Finding Format `{"Findings":[...]}` envelope) | `convertHdfToAsff` |
| XML | `convertHdfToXml` |
| XCCDF | `convertHdfToXccdf` |
| CKL (DISA STIG Viewer checklist) | `convertHdfToCkl` |
| CKLB (DISA STIG Viewer 3.x checklist) | `convertHdfToCklb` |
| OSCAL SAR | `convertHdfToOscalSar` |
| OSCAL POA&M | `convertHdfToOscalPoam` |
| SARIF 2.1.0 | `convertHdfToSarif` |
| CSAF VEX (HDF Amendments → advisory, partial-fidelity) | `convertHdfToCsafVex` |
| OpenVEX (HDF Amendments → statements, partial-fidelity) | `convertHdfToOpenVex` |
| CycloneDX VEX (HDF Amendments → BOM, partial-fidelity) | `convertHdfToCyclonedxVex` |

### Format Migration

| Conversion | Function |
|---|---|
| Legacy HDF (InSpec exec-json format) to current HDF | `convertV1ToV2` |
| Detect legacy HDF format | `isHDFV1` |

### Enrichment

Enrichment overlays external context onto an existing HDF document as inert `externalReferences[]` (matched to findings by CVE for a results document, else the document root; a system, plan or comparison document has no findings, so everything lands at the root). It is informational by default — it never changes a finding's status or impact unless the CLI's `--recompute-cvss` is passed — and is distinct from a converter (it takes a document *plus* a source, and returns the enriched document).

| Source | Function | Format |
|---|---|---|
| STIX 2.1 bundle → a document's `externalReferences[]` | `enrichStix` | JSON |
| Detect / parse a STIX 2.1 bundle | `detectStixBundle` / `parseStixBundle` | JSON |

CLI: `hdf enrich <document> <source>` (see the [hdf-cli README](../hdf-cli/README.md#enrich)).

## Installation

```bash
npm install @mitre/hdf-converters@stable   # newest v3 stable
npm install @mitre/hdf-converters@3.7.2  # pin an exact version
```

This package's npm name is shared with [heimdall2](https://github.com/mitre/heimdall2), which publishes the v2 line and owns the `latest` dist-tag — a plain `npm install @mitre/hdf-converters` installs v2, not this library. For stable releases, install the v3 line via `@stable` or an exact version (npm does not permit a `v3` dist-tag — tag names may not be valid semver ranges). Use `@next` to follow [development snapshots](../site/docs/contributing/main-snapshots.md) of main.

Requires Node.js >= 24.

## TypeScript Usage

All exports use ESM (`"type": "module"`).

### Convert a security tool report

```typescript
import { convertGrypeToHdf } from '@mitre/hdf-converters';

const grypeJson = fs.readFileSync('grype-report.json', 'utf-8');
const hdfResults = await convertGrypeToHdf(grypeJson); // second argument is the converter version stamped into generator.version, not a filename
```

### Auto-detect input format

The `@mitre/hdf-converters/detect` sub-path provides lightweight format detection without importing any converter code.

```typescript
import { registerAllFingerprints, detectConverter } from '@mitre/hdf-converters/detect';

registerAllFingerprints();
const result = detectConverter(rawInput);
// result.fingerprint.id  -> e.g. 'grype-to-hdf'
// result.confidence       -> 0.0 to 1.0
// result.version          -> detected format version (if available)
```

### Upgrade legacy HDF

```typescript
import { convertV1ToV2, isHDFV1 } from '@mitre/hdf-converters';

const data = JSON.parse(fileContent);
if (isHDFV1(data)) {
  const currentHdf = convertV1ToV2(data);
}
```

### Render an HTML report

```typescript
import { convertHdfToHtml, convertHdfDocumentsToHtml } from '@mitre/hdf-converters';

// One results document. reportType is 'executive', 'manager' or 'administrator' (the default).
const report = convertHdfToHtml(hdfResultsJson, { reportType: 'manager' });

// Several results documents in one report; each is listed under its name, in the order given.
const combined = convertHdfDocumentsToHtml([
  { name: 'web.hdf.json', content: webResultsJson },
  { name: 'db.hdf.json', content: dbResultsJson },
]);
```

Both return one self-contained HTML string. The same input always yields the same output, and the Go and TypeScript implementations yield identical bytes.

### Preserve SIEM source data

The explicit `convertHdfToEcsBundle`, `convertHdfToSplunkBundle` and
`convertHdfToOcsfBundle` APIs take original UTF-8 bytes and asynchronously return
`{ events: string, source: Uint8Array, manifest: string }`. Existing string-returning
exporters keep their signatures and native status/severity mappings.

```typescript
import { readFileSync, writeFileSync } from 'node:fs';
import { convertHdfToEcsBundle, resolveExportEvent } from '@mitre/hdf-converters';

const bundle = await convertHdfToEcsBundle(readFileSync('results.json'));
writeFileSync('events.ndjson', bundle.events);
writeFileSync('source.json', bundle.source);
writeFileSync('manifest.json', bundle.manifest);

const firstEvent = bundle.events.split('\n')[0];
if (firstEvent) {
  const verified = await resolveExportEvent(firstEvent, bundle.manifest, [
    { href: 'source.json', bytes: readFileSync('source.json') },
  ]);
  // JSON text preserves source number spelling; source remains the exact input bytes.
  console.log(verified.requirement, verified.baseline);
}
```

Each finding carries its complete requirement at `hdf.source` (ECS),
`event.hdf.source` (Splunk HEC), or `unmapped.hdf_source` (OCSF). The source artifact
retains document and baseline context once, including groups, integrity objects,
signatures and embedded scanner artifacts. An empty assessment still returns its
source and manifest. SHA512 identifies the exact bytes; an RFC 6901 occurrence
pointer distinguishes repeated requirement IDs.

`resolveExportEvent` verifies the manifest/profile, artifact identity and checksum,
pointer and complete carried record against caller-supplied bytes. It returns
`{ source, baseline, requirement }`; the latter two are JSON text with number tokens
preserved. It performs no filesystem or network reads. `resolveExportSource` is the
asynchronous lower-level equivalent for an already-extracted envelope **as JSON text**. Avoid
parsing and re-stringifying events with ordinary JavaScript numbers before
verification: that can round large integers or erase the distinction between
`1.0` and `1`.
Readback verifies the preserved requirement against the source artifact; it does
not recompute or authenticate native SIEM fields such as status or severity.

The manifest uses envelope version `1.0` and output profile `legacy-additive/1`.
Readers accept compatible higher minor versions, reject unknown major/output
profiles, and require event/manifest agreement. `exportBundleSchema` exports the
metadata schema; register the HDF common primitives embedded in the bundled HDF
results schema when compiling its external references. Schema validation does
not replace byte-integrity and record-consistency verification.

The new TypeScript APIs return promises because hashing reuses the existing Web
Crypto helper, avoiding a Node-only dependency in the shared package. They snapshot
caller-owned byte arrays before asynchronous work. Bundle inputs must be valid UTF-8 JSON with well-formed Unicode. The configured
input-size limit applies before decoding (256 MiB by default). Duplicate JSON
members retain the native last-member interpretation; the source artifact keeps
every original byte. Record comparison ignores object key order, but preserves
member presence, explicit null, array order, string values and numeric spelling.
Unicode token inspection uses Microsoft's `jsonc-parser` scanner, including for
large strings and overwritten members. Native JSON parsing still enforces strict
JSON: comments and trailing commas are not accepted.

Keep `source.json` and the manifest accessible for as long as the finding events
are retained. NDJSON alone does not deliver the complete source. Signatures are
carried, not cryptographically verified, and data is not automatically redacted.
The initial additive profile retains existing duplicated fields; a compact
profile/default migration remains a separate decision. For portable ZIP delivery
and verified local recovery, use the CLI's explicit
[`convert --bundle` and `evidence resolve` commands](../hdf-cli/README.md#convert-bundle). The CLI wraps the unchanged library artifacts in a standard HDF evidence package and verifies that package before recovering the original source.
Live Elasticsearch/Splunk ingestion qualification remains separate integration
work and is not implied by these library APIs or local archive verification.

## Go Usage

Go converters live under `converters/<name>/go/` and follow the same function signature:

```go
import grype "github.com/mitre/hdf-libs/hdf-converters/v3/converters/grype-to-hdf/go"

// converterVersion is the value stamped as generator.version in the output.
results, err := grype.ConvertGrypeToHDF(input, converterVersion)
```

The first argument is the raw tool output (`[]byte`); the second is the converter version string, not the source filename.

The SIEM bundle counterparts are `ConvertHDFToECSBundle`,
`ConvertHDFToSplunkBundle` and `ConvertHDFToOCSFBundle` in their existing converter
packages. They return `(*exportmap.ExportBundle, error)` with `Events`, `Source`
and `Manifest` byte slices. Go 1.27.3 or newer is required.

```go
import (
    ecs "github.com/mitre/hdf-libs/hdf-converters/v3/converters/hdf-to-ecs/go"
    "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go/exportmap"
)

bundle, err := ecs.ConvertHDFToECSBundle(input, converterVersion)
if err != nil { return err }
// eventLine is one complete NDJSON line from bundle.Events.
verified, err := exportmap.ResolveExportEvent(eventLine, bundle.Manifest,
    []exportmap.BundleArtifact{{Href: "source.json", Bytes: bundle.Source}})
if err != nil { return err }
// verified.Source is the original artifact; Baseline and Requirement are JSON bytes.
```

Exporters take an HDF document instead. The HTML report takes one results document, or several for a combined report:

```go
import hdftohtml "github.com/mitre/hdf-libs/hdf-converters/v3/converters/hdf-to-html/go"

report, err := hdftohtml.ConvertHDFToHTMLWithOptions(results, hdftohtml.Options{ReportType: hdftohtml.Manager})

combined, err := hdftohtml.ConvertHDFDocumentsToHTML([]hdftohtml.Document{
	{Name: "web.hdf.json", Data: webResults},
	{Name: "db.hdf.json", Data: dbResults},
}, hdftohtml.Options{})
```

For CLI usage, install the `hdf` binary from [hdf-cli](https://github.com/mitre/hdf-libs/tree/main/hdf-cli):

```bash
hdf convert grype-report.json -o results.json          # auto-detect format
hdf convert --from grype grype-report.json -o results.json  # explicit format
```

## Package Exports

| Import path | Contents |
|---|---|
| `@mitre/hdf-converters` | All converter functions and types |
| `@mitre/hdf-converters/detect` | Auto-detection (fingerprints, `detectConverter`) |
| `@mitre/hdf-converters/registry` | Fingerprint registry primitives |

## Project Structure

```
hdf-converters/
  converters/<name>/
    typescript/converter.ts       # TS implementation
    typescript/converter.test.ts  # TS tests
    go/converter.go               # Go implementation
    go/converter_test.go          # Go tests
    fixtures/input/               # Real tool output
    fixtures/expected/            # Schema-validated expected HDF
  shared/
    typescript/                   # Shared TS helpers
    go/                           # Shared Go helpers
  src/
    index.ts                      # Barrel export (all converters)
    detect.ts                     # Auto-detection sub-path entry
```

Each converter has shared test fixtures and differential tests that verify TypeScript and Go produce identical output.

## Adding a New Converter

See [Writing a Converter](../site/docs/contributing/writing-a-converter.md) for implementation instructions.

Summary:
1. Add real tool output fixtures in `converters/<name>/fixtures/input/`
2. Write tests first (TDD) in both TypeScript and Go
3. Implement the converter in `converters/<name>/typescript/` and `converters/<name>/go/`
4. Register a fingerprint for auto-detection and add its blank-import to `registry/all/all.go`
5. Register the converter in `registry/convert/converter_<name>.go` with an `init()` that calls `registerHDFConverter`, `registerHDFBaselineConverter`, `registerHDFPlanConverter`, or `registerHDFAmendmentsConverter` for its output type; the CLI and the MCP server share this registry, so only the integration test lives in `hdf-cli/cmd/hdf/cmd/converter_<name>_test.go`

## License

Apache-2.0 -- MITRE Corporation
