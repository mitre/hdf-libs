# @mitre/hdf-converters

Converters for transforming security tool outputs and HDF format versions.

## Overview

This library provides converters for:
- **HDF v1.0 → v2.0**: Transform legacy HDF format to current version
- **Security Tools** (future): 30+ security tool output converters (Nessus, SCAP, etc.)

## Installation

```bash
npm install @mitre/hdf-converters
```

## Usage

### HDF v1.0 to v2.0 Conversion

```typescript
import { convertV1ToV2, isHDFV1 } from '@mitre/hdf-converters';

// Check if data is v1.0 format
const data = JSON.parse(fileContent);
if (isHDFV1(data)) {
  const v2Data = convertV1ToV2(data);
  console.log('Converted to v2.0:', v2Data);
}
```

### Key Changes in v2.0

- `version` field removed (implicit in schema)
- `profiles` → `baselines`
- `platform` (single object) → `targets` (array, supports multiple targets)
- Extension fields moved to `extensions` object

## Auto-Detection (Fingerprint Registry)

Automatically detect which converter to use for a given input:

```typescript
import { registerAllFingerprints, detectConverter } from '@mitre/hdf-converters/detect';

registerAllFingerprints();
const result = detectConverter(rawInput);
// result.fingerprint.id === 'gosec-to-hdf'
// result.confidence === 1.0
```

Each converter self-registers a lightweight structural fingerprint.
Detection is cheap (~2KB, no converter imports). Conversion is lazy-loaded.

Fingerprints can optionally detect the **format version** (e.g. SARIF 2.1.0,
CycloneDX 1.5) via the `detectVersion` field on `ConverterFingerprint`. The
detected version is returned in `DetectionResult.version`.

See **[Fingerprint Registry Guide](../docs/guides/converter-fingerprint-registry.md)**
for full documentation, usage examples, and how to add fingerprints for new converters.

## Version Specifiers

Converters support `format@version` syntax to specify input or output format versions:

```bash
# Explicit input version
hdf convert --from sarif@2.0 scan.sarif

# HDF schema version transforms
hdf convert --from hdf@1 --to hdf@2 legacy.json     # Upgrade v1 → v2
hdf convert --from hdf@1 --to hdf legacy.json        # Same (v2 is default)

# Post-process any converter output to v1
hdf convert --from grype --to hdf@1 scan.json         # Grype → HDF v2 → HDF v1
```

### Version Defaulting

- No `@version`: converter uses its latest supported version
- `--to hdf` (no version): produces latest HDF version (currently v2)
- `--to hdf@1`: downgrades output to HDF v1 (lossy — prints warning)
- `--from legacyhdf` is an alias for `--from hdf@1 --to hdf@2`

### Multi-Version Converters (VersionedConverter)

Converters that handle multiple input versions implement `VersionedConverter`:

```go
type VersionedConverter interface {
    Converter
    SetInputVersion(version string)
    SupportedVersions() []string
}
```

When `SetInputVersion("")` is called (or not called at all), the converter
defaults to its latest supported version. `SupportedVersions()` returns
versions in order, latest first.

### HDF Version Transforms

The `hdfversion` package provides a registry-based router for HDF schema
version transforms:

```go
import "github.com/mitre/hdf-converters/shared/go/hdfversion"

output, err := hdfversion.TransformHDF(input, "1", "2")  // upgrade
output, err := hdfversion.TransformHDF(input, "2", "1")  // downgrade (lossy)
ver, err := hdfversion.DetectHDFVersion(input)            // "1" or "2"
```

```typescript
import { transformHDF, detectHDFVersion } from '@mitre/hdf-converters/shared/typescript/hdf-version.js';

const v2 = transformHDF(v1Input, '1', '2');
const ver = detectHDFVersion(input); // '1' or '2'
```

## Adding New Converters

This package maintains **dual implementations** (TypeScript and Go) for all converters:
- TypeScript for npm package (web apps, Node.js tools)
- Go for `hdf-cli` (standalone binary, better security)

See **[CONVERTER_GUIDE.md](./CONVERTER_GUIDE.md)** for complete implementation instructions.

**Quick start**:
1. Implement TypeScript converter in `converters/{tool}/typescript/`
2. Add test fixtures in `converters/{tool}/fixtures/`
3. Port to Go in `converters/{tool}/go/`
4. Differential tests ensure both produce identical output

**Architecture decision**: [ADR-001](../docs/architecture/ADR-001-dual-converter-implementations.md)

## License

Apache-2.0 © MITRE Corporation
