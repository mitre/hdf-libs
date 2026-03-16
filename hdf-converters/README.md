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
