# @mitre/hdf-converters

Convert security tool outputs to and from Heimdall Data Format (HDF). Part of the [hdf-libs](https://github.com/mitre/hdf-libs) monorepo.

Every converter is implemented in both TypeScript and Go. The TypeScript library is published as an npm package; the Go implementations are used by the [`hdf` CLI](https://github.com/mitre/hdf-libs/tree/main/hdf-cli).

All converter output conforms to the [HDF JSON Schema](https://mitre.github.io/hdf-libs/schemas/).

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
| Gosec | `convertGosecToHdf` | JSON |
| Grype | `convertGrypeToHdf` | JSON |
| Hipcheck | `convertHipcheckToHdf` | JSON |
| Ion Channel | `convertIonchannelToHdf` | JSON |
| JFrog Xray | `convertJfrogXrayToHdf` | JSON |
| JUnit | `convertJunitToHdf` | XML |
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
| Snyk | `convertSnykToHdf` | JSON |
| SonarQube | `convertSonarqubeToHdf` | JSON |
| SPDX VEX (SPDX 3.0 security profile → HDF Amendments) | `convertSpdxVexToHdf` | JSON |
| Splunk | `convertSplunkToHdf` | JSON |
| TruffleHog | `convertTrufflehogToHdf` | JSON |
| Twistlock | `convertTwistlockToHdf` | JSON |
| Veracode | `convertVeracodeToHdf` | JSON |
| XCCDF Results | `convertXccdfResultsToHdf` | XML |

### HDF to Other Formats

| Target Format | Function |
|---|---|
| CSV | `convertHdfToCsv` |
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
| CSAF VEX (HDF Amendments → advisory, partial-fidelity) | `convertHdfToCsafVex` |
| OpenVEX (HDF Amendments → statements, partial-fidelity) | `convertHdfToOpenVex` |
| CycloneDX VEX (HDF Amendments → BOM, partial-fidelity) | `convertHdfToCyclonedxVex` |

### Format Migration

| Conversion | Function |
|---|---|
| Legacy HDF (InSpec exec-json format) to current HDF | `convertV1ToV2` |
| Detect legacy HDF format | `isHDFV1` |

### Enrichment

Enrichment overlays external context onto an existing HDF results document as inert `externalReferences[]` (matched to findings by CVE, else the results root). It is informational — it never changes a finding's status or impact — and is distinct from a converter (it takes a results doc *plus* a source, and returns the enriched results doc).

| Source | Function | Format |
|---|---|---|
| STIX 2.1 bundle → results `externalReferences[]` | `enrichStix` | JSON |
| Detect / parse a STIX 2.1 bundle | `detectStixBundle` / `parseStixBundle` | JSON |

CLI: `hdf enrich <results> <source>` (see the [hdf-cli README](../hdf-cli/README.md#enrich)).

## Installation

```bash
npm install @mitre/hdf-converters
```

Requires Node.js >= 22.

## TypeScript Usage

All exports use ESM (`"type": "module"`).

### Convert a security tool report

```typescript
import { convertGrypeToHdf } from '@mitre/hdf-converters';

const grypeJson = fs.readFileSync('grype-report.json', 'utf-8');
const hdfResults = convertGrypeToHdf(grypeJson, 'grype-report.json');
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

## Go Usage

Go converters live under `converters/<name>/go/` and follow the same function signature:

```go
import grype "github.com/mitre/hdf-libs/hdf-converters/v3/converters/grype-to-hdf/go"

results, err := grype.ConvertGrypeToHdf(input, "grype-report.json")
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

See [CONVERTER_GUIDE.md](https://github.com/mitre/hdf-libs/blob/main/hdf-converters/CONVERTER_GUIDE.md) for implementation instructions.

Summary:
1. Add real tool output fixtures in `converters/<name>/fixtures/input/`
2. Write tests first (TDD) in both TypeScript and Go
3. Implement the converter in `converters/<name>/typescript/` and `converters/<name>/go/`
4. Register a fingerprint for auto-detection
5. Add a CLI wrapper in `hdf-cli/cmd/hdf/cmd/`

## License

Apache-2.0 -- MITRE Corporation
