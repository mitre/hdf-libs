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
| Hipcheck | NIST SP 800-53 Rev 5 | Analysis name (`binary`, `mitre/binary`) |

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

// Get control description (IDs are zero-padded; defaults to the selected
// revision — Rev 5 unless overridden)
const desc = getNISTDescription('AC-01');
// Returns: "Policy and Procedures"

// Rev 4 text via the explicit revision argument
const descRev4 = getNISTDescription('AC-01', 4);
// Returns: "ACCESS CONTROL POLICY AND PROCEDURES"

// Get control family
const family = getNISTFamily('AC-01');
// Returns: "AC"
```

#### Rev 4 ↔ Rev 5 crosswalk

Translates control IDs between 800-53 Rev 4 and Rev 5 using NIST's own
comparison workbooks (the Rev 4→Rev 5 comparison workbook and the Appendix J
privacy-control comparison, both from the SP 800-53 Rev 5 final publication
page). Regenerated via `scripts/generate-nist-crosswalk.mjs`; both the Go and
TS copies are written byte-identically (`--check` gates drift). The full
revision contract — selection, guarantees, and data-consumer guidance — is
documented in the site guide
[NIST 800-53 revision handling](../site/docs/guides/nist-revisions.md).

```typescript
import { translateNistControl, translateNistControls } from '@mitre/hdf-mappings';

translateNistControl('IR-10', 4, 5);
// { control: 'IR-10', targets: ['IR-4(11)'], relation: 'moved', detail: 'Moved to IR-4(11)' }

translateNistControl('AC-1', 4, 5);
// { control: 'AC-1', targets: ['AC-1'], relation: 'identity' }  (present in both revisions)

const { translated, unmapped } = translateNistControls(['AC-1', 'IR-10', 'SC-19'], 4, 5);
// translated: ['AC-1', 'IR-4(11)']; unmapped: [{ control: 'SC-19', relation: 'none', ... }]
```

Relations: `identity` (same ID at both revisions), `moved` / `incorporated`
(NIST names a successor), `pointer` (Appendix J privacy controls — NIST calls
these pointers, not equivalences), `family` (incorporated into a whole family,
kept as a marker rather than expanded), `none` (NIST names no successor), and
`unknown` (not a control at the source revision). Controls NIST withdrew in
Rev 4 itself (e.g. `AC-13`) are valid at neither revision but still redirect to
their incorporation targets from either direction, so stale tags resolve.

> **Interpretation.** A crosswalk edge means NIST relocated or absorbed the
> requirement text — it does not make the target control's full scope
> equivalent to the source control. Treat translated tags as candidate control
> associations, exactly like the tool-specific mappings below.

#### Per-table revision handling

Every tool mapping table declares the NIST revision it was authored against,
and its default lookups translate to the current module-global revision
(`--nist-rev` / `setCurrentNistRevision`) through the crosswalk — so every
NIST-emitting converter honors the requested revision, not just aws-config:

| Table | Native revision | Notes |
|-------|-----------------|-------|
| awsconfig | 4 + 5 (dual) | native rows per revision + crosswalk backfill (see below) |
| cwe | 4 + 5 (dual) | control IDs are byte-identical across revisions |
| nessus | 4 | carries AU-8(1), which translates to SC-45(1) at Rev 5 |
| cci | 4 | DISA refs incl. Appendix J privacy controls; translated with statement suffixes |
| nikto, owasp, scoutsuite | 4 | content identical at both revisions today; a test guards that invariant |
| hipcheck | 5 | SR-family controls have no Rev 4 equivalent and drop at Rev 4 |

Translation semantics: statement-style suffixes ("AC-1 a") survive identity and
are dropped on redirects; controls with no equivalent at the requested revision
are dropped rather than mistranslated; tokens outside both NIST catalogs (tool
placeholders like Nessus's "UM-1") pass through unchanged.

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

// By source identifier (uppercase, underscores). Resolved at the selected
// NIST revision (Rev 5 default; the Rev 4 tags for this rule are 'AC-2(1)|AC-2(j)').
const nistId = getAwsConfigNistControlByIdentifier('SECRETSMANAGER_SCHEDULED_ROTATION_SUCCESS_CHECK');
// Returns: 'AC-2(1)|AC-3(15)'

// By rule name (lowercase, hyphens)
const nistId2 = getAwsConfigNistControlByName('secretsmanager-scheduled-rotation-success-check');
// Returns: 'AC-2(1)|AC-3(15)'

if (awsConfigIdentifierExists('SECRETSMANAGER_SCHEDULED_ROTATION_SUCCESS_CHECK')) { /* ... */ }
```

#### Coverage tiers and semantics

The AWS Config→NIST table is regenerated (via `scripts/generate-awsconfig-mappings.mjs`) from
four tiers, in precedence order; each row records its tier in the `Source` field:

1. **config-pack** — AWS Config's "Operational Best Practices for NIST 800-53" docs (Rev 4 + Rev 5).
2. **security-hub** — AWS Security Hub's NIST 800-53 r5 standard control pages (Rev 5).
3. **derived-theme** — for a managed rule the authoritative tiers miss but whose name matches a strong
   theme (encryption-at-rest, in-transit/TLS, logging/audit, public-access), the controls that
   ≥75% of AWS's *own* same-theme mapped rules carry. Nothing is invented — controls are reused
   from AWS's authoritative mappings. Rules matching no theme stay unmapped, and the
   `aws-config-to-hdf` converter floors them to **CM-6** (Configuration Settings) at conversion time.
4. **crosswalk** — per-revision completeness: a rule mapped at exactly one revision gets a row at
   the other revision by translating its controls through the NIST Rev 4↔Rev 5 crosswalk (above).
   Native rows are never modified. When the whole control set has no equivalent at the other
   revision, the row is an explicit **empty-`NIST-ID` marker** — "no mapping exists at this
   revision" is recorded as an answer, not left as a silent gap. Crosswalk rows inherit the
   confidence of the native row they were translated from.

With tier 4, every rule in the table has a defined outcome at both supported revisions: native,
crosswalk-derived, or explicitly unmapped. A single-revision view of the table is therefore
complete — filtering by `Rev` never silently drops a rule.

> **Interpretation.** These NIST tags are *candidate control associations for triage*, not evidence
> that a control is assessed or satisfied. A passed Config / Security Hub rule is evidence *toward*
> the tagged controls, not proof they are met — one rule rarely satisfies a control in full, and the
> derived and CM-6 tiers are coarse by design. Do not roll "rule passed" up to "tagged controls
> satisfied" in SSP / eMASS / ATO exports.

### Hipcheck

Maps MITRE Hipcheck analysis names to NIST 800-53 Rev 5 controls. Lookups accept
the bare analysis name (`binary`) or Hipcheck's published, publisher-prefixed
form (`mitre/binary`). `NIST-ID` is a `|`-delimited list.

```typescript
import {
  getHipcheckNistControls,
  hipcheckAnalysisExists,
  getAllHipcheckAnalyses,
} from '@mitre/hdf-mappings';

const controls = getHipcheckNistControls('mitre/binary');
// Returns: ['SI-7', 'SR-4']

if (hipcheckAnalysisExists('typo')) { /* ... */ }

const analyses = getAllHipcheckAnalyses();
// Returns the 9 mapped Hipcheck analysis names, sorted
```

> **Provenance.** Hipcheck publishes no analysis-to-controls crosswalk, so this
> table is a hand-curated, NIST-RMF-reviewed mapping — each row carries a
> `Rationale`. It is the single source of truth in
> `scripts/generate-hipcheck-mappings.mjs`, which writes both the Go and TS
> copies byte-identically (`--check` gates drift in CI). As with the other
> mappings, these are candidate control associations for triage, not evidence a
> control is assessed or satisfied.

## Go API

Each mapping is also available as a Go package:

```
hdf-mappings/go/
  cci/        — CCI↔NIST lookups (GetCCINistMappings, NISTToCCI, CCIToNIST)
  cwe/        — CWE→NIST lookups (NISTControls)
  owasp/      — OWASP→NIST lookups (NISTControl)
  nessus/     — Nessus plugin→NIST lookups (NISTControls, with family+pluginID)
  nikto/      — Nikto test→NIST lookups (NISTControl, NISTControlByInt)
  hipcheck/   — Hipcheck analysis→NIST lookups (NISTControls, Exists, AllAnalyses)
  scoutsuite/ — ScoutSuite rule→NIST lookups (NISTControls)
  awsconfig/  — AWS Config→NIST lookups (NISTControls, GetByRuleName, GetByIdentifier)
  nist/       — revision selection (Revision, SetRevision) + Rev 4↔5 crosswalk (Translate, TranslateControls)
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

```go
import "github.com/mitre/hdf-libs/hdf-mappings/go/v3/nist"

tr := nist.Translate("IR-10", 4, 5)
// Translation{Targets: []string{"IR-4(11)"}, Relation: "moved", ...}

translated, unmapped := nist.TranslateControls([]string{"AC-1", "IR-10", "SC-19"}, 4, 5)
// translated: ["AC-1", "IR-4(11)"]; unmapped: [{Control: "SC-19", Relation: "none", ...}]
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
| AWS Config→NIST | AWS Config OBP for NIST 800-53 docs + Security Hub NIST r5 standard + derived (see Coverage tiers) |
| NIST Rev 4↔5 crosswalk | NIST SP 800-53 Rev 4→Rev 5 comparison workbook + Appendix J comparison (csrc.nist.gov, Rev 5 final) |

## License

Apache-2.0 © MITRE Corporation
