# @mitre/hdf-mappings

Security framework mappings for the Heimdall Data Format (HDF).

## Overview

This library provides mappings between various security compliance frameworks:
- **CCI (Control Correlation Identifier)** ↔ **NIST SP 800-53** controls
- NIST control descriptions and metadata
- Support for CIS, CMMC mappings (future)

## Installation

```bash
npm install @mitre/hdf-mappings
```

## Usage

### CCI Lookups

```typescript
import { getCCIDescription, getCCINistMappings } from '@mitre/hdf-mappings';

// Get CCI definition
const def = getCCIDescription('CCI-000001');
// Returns: "The organization develops an access control policy..."

// Get NIST controls for a CCI
const nistControls = getCCINistMappings('CCI-000001');
// Returns: ['AC-1 a', 'AC-1.1 (i and ii)', 'AC-1 a 1']
```

### NIST Lookups

```typescript
import { getNISTDescription } from '@mitre/hdf-mappings';

// Get NIST control description
const desc = getNISTDescription('AC-01');
// Returns: "ACCESS CONTROL POLICY AND PROCEDURES"
```

## Data Sources

Mapping data extracted from:
- NIST SP 800-53 Revision 5
- DISA CCI List

## License

Apache-2.0 © MITRE Corporation
