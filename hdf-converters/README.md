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

## License

Apache-2.0 © MITRE Corporation
