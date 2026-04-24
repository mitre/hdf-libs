# @mitre/hdf-mappings

Security framework mappings for the Heimdall Data Format (HDF).

## Overview

This library provides mappings between security tool identifiers and NIST SP 800-53 controls,
plus CCI↔NIST cross-reference data. Converters use these mappings to populate the `tags.nist`
and `tags.cci` fields in HDF output.

**Supported mappings:**

| Source | Maps to | Key type |
|--------|---------|----------|
| CCI (Control Correlation Identifier) | NIST SP 800-53 controls | CCI ID string (`CCI-000001`) |
| NIST SP 800-53 | Control descriptions | Control ID string (`AC-1`) |
| OWASP Top 10 | NIST SP 800-53 | OWASP ID string (`A1`) |
| CWE | NIST SP 800-53 | CWE ID number (`476`) |
| Nessus | NIST SP 800-53 | Plugin family string |
| Nikto | NIST SP 800-53 | Test ID string (`'1'`) |
| ScoutSuite | NIST SP 800-53 | Rule name string |
| AWS Config | NIST SP 800-53 | Rule identifier or rule name |

Go equivalents are available in `go/` subdirectories (see below).

## Installation

```bash
npm install @mitre/hdf-mappings
```

## Usage

### CCI Lookups

```typescript
import {
  getCCIDescription,
  getCCINistMappings,
  getAllCCIIds,
  cciExists,
  getNistCCIMappings,
  nistToCci,
} from '@mitre/hdf-mappings';

// Get the CCI definition text
const def = getCCIDescription('CCI-000001');
// Returns: "The organization develops an access control policy..."

// Get NIST controls for a CCI
const nistControls = getCCINistMappings('CCI-000001');
// Returns: ['AC-1 a', 'AC-1.1 (i and ii)', 'AC-1 a 1']

// Reverse lookup: get CCIs for a NIST control (curated mapping table)
const ccis = getNistCCIMappings('SI-10');
// Returns: ['CCI-001310']

// Batch reverse lookup: map multiple NIST controls to CCIs (deduplicated, sorted)
const allCcis = nistToCci(['SA-11', 'RA-5']);
// Returns: ['CCI-001643', 'CCI-003173']

// Check existence before lookup
if (cciExists('CCI-000001')) { /* ... */ }
```

### NIST Lookups

```typescript
import {
  getNISTDescription,
  getAllNISTIds,
  nistExists,
  getNISTFamily,
} from '@mitre/hdf-mappings';

// Get control description
const desc = getNISTDescription('AC-1');
// Returns: "ACCESS CONTROL POLICY AND PROCEDURES"

// Get control family
const family = getNISTFamily('AC-1');
// Returns: "AC"
```

### OWASP Top 10

```typescript
import {
  getOwaspNistControl,
  getOwaspName,
  getAllOwaspIds,
} from '@mitre/hdf-mappings';

const nistId = getOwaspNistControl('A1');
// Returns: 'SI-10'

const name = getOwaspName('A1');
// Returns: 'Injection'

const ids = getAllOwaspIds();
// Returns: ['A1', 'A2', ..., 'A10']
```

### CWE

```typescript
import {
  getCweNistControl,
  getCweName,
  cweExists,
} from '@mitre/hdf-mappings';

// CWE IDs are numbers
const nistId = getCweNistControl(476);
// Returns: 'SI-10'

const name = getCweName(476);
// Returns: ' NULL Pointer Dereference'

if (cweExists(79)) {
  const xss = getCweNistControl(79); // 'SI-10'
}
```

### Nessus

Nessus mappings are keyed by plugin family (the broad category reported in Nessus output).

```typescript
import {
  getNessusNistControl,
  getNessusPluginFamilyMappings,
  getAllNessusPluginFamilies,
} from '@mitre/hdf-mappings';

// Look up by plugin family (wildcards also supported per the data)
const nistId = getNessusNistControl('AIX Local Security Checks');
// Returns: 'SI-2|RA-5'

// Get all mappings for a family (may include per-plugin-ID overrides)
const familyMappings = getNessusPluginFamilyMappings('AIX Local Security Checks');

const families = getAllNessusPluginFamilies();
// Returns all known plugin family strings
```

### Nikto

Nikto test IDs are strings (zero-padded in Nikto output, but stored as plain numbers here).

```typescript
import {
  getNiktoNistControl,
  getAllNiktoIds,
  niktoExists,
} from '@mitre/hdf-mappings';

const nistId = getNiktoNistControl('1');
// Returns: 'AC-3'

// Also accepts numbers
const nistId2 = getNiktoNistControl(2);
// Returns: 'AC-3'

const ids = getAllNiktoIds();
// Returns all Nikto test ID strings
```

### ScoutSuite

```typescript
import {
  getScoutsuiteNistControl,
  getScoutsuiteNistMapping,
  getAllScoutsuiteRules,
} from '@mitre/hdf-mappings';

const nistId = getScoutsuiteNistControl('acm-certificate-with-close-expiration-date');
// Returns: 'SC-12'

const mapping = getScoutsuiteNistMapping('acm-certificate-with-close-expiration-date');
// Returns: { RULE: '...', 'NIST-ID': 'SC-12', ... }

const rules = getAllScoutsuiteRules();
// Returns all 139 ScoutSuite rule names
```

### AWS Config

AWS Config rules can be looked up by either their source identifier or their rule name.

```typescript
import {
  getAwsConfigNistControlByIdentifier,
  getAwsConfigNistControlByName,
  awsConfigIdentifierExists,
} from '@mitre/hdf-mappings';

// By source identifier (uppercase, underscores)
const nistId = getAwsConfigNistControlByIdentifier('SECRETSMANAGER_SCHEDULED_ROTATION_SUCCESS_CHECK');
// Returns: 'AC-2(1)|AC-2(j)'

// By rule name (lowercase, hyphens)
const nistId2 = getAwsConfigNistControlByName('secretsmanager-scheduled-rotation-success-check');
// Returns: 'AC-2(1)|AC-2(j)'

if (awsConfigIdentifierExists('SECRETSMANAGER_SCHEDULED_ROTATION_SUCCESS_CHECK')) { /* ... */ }
```

## Go API

Each mapping is also available as a Go package:

```
hdf-mappings/go/
  cci/        — CCI↔NIST lookups (GetCCINistMappings, NISTToCCI, CCIToNIST)
  cwe/        — CWE→NIST lookups (NISTControls)
  owasp/      — OWASP→NIST lookups (NISTControls)
  nessus/     — Nessus plugin→NIST lookups (NISTControls, with family+pluginID)
  nikto/      — Nikto test→NIST lookups (NISTControls)
  scoutsuite/ — ScoutSuite rule→NIST lookups (NISTControls)
  awsconfig/  — AWS Config→NIST lookups (NISTControls, GetByRuleName, GetByIdentifier)
```

```go
import "github.com/mitre/hdf-libs/hdf-mappings/go/v3/cci"

controls := cci.GetCCINistMappings("CCI-000001")
// Returns: []string{"AC-1 a", "AC-1.1 (i and ii)", "AC-1 a 1"}

ccis := cci.NISTToCCI([]string{"SA-11", "RA-5"})
// Returns: []string{"CCI-001643", "CCI-003173"}

nist := cci.CCIToNIST([]string{"CCI-000366", "CCI-000001"})
// Returns: []string{"AC-1 a", ..., "CM-6 b", ...}
```

```go
import "github.com/mitre/hdf-libs/hdf-mappings/go/v3/cwe"

controls := cwe.NISTControls("CWE-476")  // prefix form
controls  = cwe.NISTControls("476")      // numeric form — equivalent
```

```go
import "github.com/mitre/hdf-libs/hdf-mappings/go/v3/awsconfig"

controls := awsconfig.NISTControls("SECRETSMANAGER_SCHEDULED_ROTATION_SUCCESS_CHECK")
mapping  := awsconfig.GetByIdentifier("SECRETSMANAGER_SCHEDULED_ROTATION_SUCCESS_CHECK")
mapping   = awsconfig.GetByRuleName("secretsmanager-scheduled-rotation-success-check")
```

## Data Sources

| Data | Source |
|------|--------|
| CCI list | DISA CCI List |
| NIST SP 800-53 descriptions | NIST SP 800-53 Rev 5 |
| OWASP→NIST | heimdall2 mapping tables |
| CWE→NIST | heimdall2 mapping tables |
| Nessus→NIST | heimdall2 mapping tables |
| Nikto→NIST | heimdall2 mapping tables |
| ScoutSuite→NIST | heimdall2 mapping tables |
| AWS Config→NIST | heimdall2 mapping tables |

## License

Apache-2.0 © MITRE Corporation
