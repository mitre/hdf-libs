# @mitre/hdf-generators

Generate InSpec profile stubs from HDF Baseline definitions.

## What it does

Takes an HDF Baseline JSON document (requirement definitions with metadata, descriptions, and tags) and generates a complete InSpec profile directory structure:

- `inspec.yml` — profile metadata (name, maintainer, license, version, platform supports)
- `controls/*.rb` — one control file per requirement with `describe` blocks, tags, and impact

This bridges from HDF's tool-agnostic baseline format to InSpec's executable compliance-as-code format.

## Relationship to other packages

| Package | Relationship |
|---------|-------------|
| **hdf-schema** | Provides the `HDFBaseline` type that generators consume |
| **hdf-converters** | Converters produce baselines (e.g., XCCDF benchmark → HDF baseline) that generators can then turn into InSpec profiles |
| **hdf-cli** | `hdf generate inspec-profile` command wraps this library |
| **hdf-mappings** | Baselines may contain NIST/CCI tags from hdf-mappings |

## Installation

```bash
npm install @mitre/hdf-generators
```

## Usage (TypeScript)

```typescript
import { generateInSpecProfile } from '@mitre/hdf-generators';
import type { HDFBaseline } from '@mitre/hdf-schema';

const baseline: HDFBaseline = JSON.parse(fs.readFileSync('baseline.json', 'utf8'));

const profile = generateInSpecProfile(baseline, {
  metadata: {
    maintainer: 'MITRE SAF',
    copyright: 'MITRE Corporation',
    license: 'Apache-2.0',
  },
});

// profile.inspecYml — string content for inspec.yml
// profile.controls  — Map<string, string> of filename → Ruby control code
```

### Individual stubs

```typescript
import { generateControlStub, generateInSpecYml, escapeQuotes } from '@mitre/hdf-generators';

// Generate a single control file
const ruby = generateControlStub(requirement);

// Generate inspec.yml
const yml = generateInSpecYml(baseline, { metadata: { maintainer: 'Team', license: 'Apache-2.0' } });
```

## Usage (Go)

```go
import generators "github.com/mitre/hdf-libs/hdf-generators/go/v3"

profile := generators.GenerateInSpecProfile(baseline, &generators.GeneratorOptions{
    Metadata: &generators.ProfileMetadata{
        Maintainer: "MITRE SAF",
        License:    "Apache-2.0",
    },
})
// profile.InspecYml — string
// profile.Controls  — map[string]string
```

## CLI usage

```bash
hdf generate inspec-profile baseline.json output-dir/
hdf generate inspec-profile baseline.json output-dir/ --maintainer "MITRE SAF"
hdf generate inspec-profile baseline.json output-dir/ --single-file
```

## License

Apache-2.0 © MITRE Corporation
