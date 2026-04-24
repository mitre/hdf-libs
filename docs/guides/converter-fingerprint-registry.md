# Converter Fingerprint Registry

Auto-detect which security tool produced a given input file — without
asking the user to manually select a converter.

## How It Works

The fingerprint registry is a two-layer system:

```
┌─────────────────────────────────────────────────────┐
│  Consumer                                           │
│                                                     │
│  1. registerAllFingerprints()   ← call once at init │
│  2. detectConverter(rawInput)   ← returns match     │
│  3. lazy-load converter         ← only when needed  │
└─────────────────────────────────────────────────────┘
        │                              │
        ▼                              ▼
┌──────────────────┐    ┌─────────────────────────────┐
│  Registry        │    │  Dispatcher                 │
│                  │    │                             │
│  ConverterFP[]   │◄───│  detectFamily() → json/xml  │
│  - id            │    │  filter by inputFamily      │
│  - label         │    │  run each fingerprint()     │
│  - inputFamily   │    │  sort by confidence         │
│  - outputType    │    │  return best match          │
│  - fingerprint() │    └─────────────────────────────┘
└──────────────────┘
        ▲
        │  registerFingerprint()
        │
┌───────┴──────────────────────────────────────┐
│  Per-converter fingerprint.ts files          │
│                                              │
│  sarif:   version(string) + runs(array) →0.9 │
│  gosec:   GosecVersion + Issues[]       →1.0 │
│  nessus:  <NessusClientData_v2>         →1.0 │
│  ...32 more converters                       │
└──────────────────────────────────────────────┘
```

### Key Design Principles

**1. Detection is cheap, conversion is lazy.**
The `ConverterFingerprint` type contains ONLY lightweight metadata and a
pure structural check function. It does NOT import the converter function.
This means importing the detection system adds ~2KB to your bundle, not
the 200KB+ of all converter implementations.

**2. Self-describing converters (DRY).**
Each converter's fingerprint lives next to its converter code. The
fingerprint function checks the same structural keys the converter
already validates internally. There is ONE source of truth for "what
does GoSec JSON look like?" — it lives in
`converters/gosec-to-hdf/typescript/fingerprint.ts`.

**3. Confidence scoring resolves ambiguity.**
Multiple formats share similar structures (e.g., Snyk and GitLab both
have `vulnerabilities[]`). Each fingerprint returns a confidence score
0.0-1.0. The dispatcher returns the highest-confidence match, or all
matches sorted for UI display.

**4. Explicit registration, not side-effect magic.**
ESM bundlers (Vite, Rollup) tree-shake side-effect imports. We use
explicit `registerAllFingerprints()` instead, which is safe in any
bundler and any runtime.

## Usage

### Basic: Detect and convert

```typescript
import { registerAllFingerprints, detectConverter } from '@mitre/hdf-converters/detect';

// Call once at startup
registerAllFingerprints();

// Detect the input format
const result = detectConverter(rawFileContent);

if (result) {
  console.log(`Detected: ${result.fingerprint.label}`);    // "GoSec"
  console.log(`Confidence: ${result.confidence}`);          // 1.0
  console.log(`Output type: ${result.fingerprint.outputType}`); // "results"

  // Lazy-load and run the converter
  const { convertGosecToHdf } = await import('@mitre/hdf-converters');
  const hdf = await convertGosecToHdf(rawFileContent);
}
```

### Show all candidates (for UI dropdowns)

```typescript
import { detectConverterAll, registerAllFingerprints } from '@mitre/hdf-converters/detect';

registerAllFingerprints();

const matches = detectConverterAll(ambiguousInput);
// [
//   { fingerprint: { id: 'snyk-to-hdf', ... }, confidence: 0.5 },
//   { fingerprint: { id: 'gitlab-to-hdf', ... }, confidence: 0.4 },
// ]
```

### List all registered converters

```typescript
import { getFingerprints, registerAllFingerprints } from '@mitre/hdf-converters/detect';

registerAllFingerprints();

for (const fp of getFingerprints()) {
  console.log(`${fp.id}: ${fp.label} (${fp.inputFamily} → ${fp.outputType})`);
}
```

### Go

```go
import "github.com/mitre/hdf-libs/hdf-converters/v3/registry"

// Registration happens via init() in each converter package.
// Import the register_all package to trigger all registrations:
import _ "github.com/mitre/hdf-libs/hdf-converters/v3/registry/all"

result := registry.DetectConverter(inputBytes)
if result != nil {
    fmt.Printf("Detected: %s (%.1f confidence)\n", result.Fingerprint.Label, result.Confidence)
}
```

## Adding a New Converter Fingerprint

When you add a new converter (e.g., `trivy-to-hdf`), follow these steps:

### Step 1: Create the fingerprint file

```typescript
// converters/trivy-to-hdf/typescript/fingerprint.ts

import { registerFingerprint, getFingerprint, type ConverterFingerprint } from '../../../shared/typescript/registry.js';

export const trivyFingerprint: ConverterFingerprint = {
  id: 'trivy-to-hdf',
  label: 'Trivy',
  direction: 'ingest',
  inputFamily: 'json',
  outputType: 'results',
  fingerprint: (input: unknown): number => {
    if (typeof input !== 'object' || input === null) return 0;
    const obj = input as Record<string, unknown>;

    // Trivy JSON has SchemaVersion + Results[]
    if (typeof obj.SchemaVersion === 'number' && Array.isArray(obj.Results)) {
      return 1.0;
    }

    return 0;
  },
};

export function register(): void {
  if (getFingerprint('trivy-to-hdf')) return;
  registerFingerprint(trivyFingerprint);
}
```

### Step 2: Write the test

```typescript
// converters/trivy-to-hdf/typescript/fingerprint.test.ts

import { describe, it, expect, beforeEach } from 'vitest';
import { _resetRegistry, getFingerprint } from '../../../shared/typescript/registry.js';
import { detectConverter } from '../../../shared/typescript/fingerprint.js';
import { register, trivyFingerprint } from './fingerprint.js';

describe('trivy-to-hdf fingerprint', () => {
  beforeEach(() => {
    _resetRegistry();
    register();
  });

  it('is registered with correct metadata', () => {
    const fp = getFingerprint('trivy-to-hdf');
    expect(fp).toBeDefined();
    expect(fp!.label).toBe('Trivy');
    expect(fp!.inputFamily).toBe('json');
    expect(fp!.outputType).toBe('results');
  });

  it('detects Trivy JSON', () => {
    const input = JSON.stringify({ SchemaVersion: 2, Results: [] });
    const result = detectConverter(input);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('trivy-to-hdf');
    expect(result!.confidence).toBe(1.0);
  });

  it('does not match SARIF', () => {
    const sarif = JSON.stringify({ version: '2.1.0', runs: [] });
    expect(detectConverter(sarif)).toBeUndefined();
  });

  it('does not match empty object', () => {
    expect(detectConverter('{}')).toBeUndefined();
  });
});
```

### Step 3: Register in register-all.ts

```typescript
// shared/typescript/register-all.ts — add one line:

import { trivyFingerprint } from '../../converters/trivy-to-hdf/typescript/fingerprint.js';

const allFingerprints: ConverterFingerprint[] = [
  sarifFingerprint,
  gosecFingerprint,
  trivyFingerprint,  // ← add here
  // ...
];
```

### Step 4: Run tests

```bash
npx vitest run converters/trivy-to-hdf/typescript/fingerprint.test.ts
```

That's it. Three files touched, one test file, and the new converter is
auto-detectable everywhere.

## Confidence Guidelines

| Score | Meaning | Example |
|-------|---------|---------|
| 1.0 | Unique key present | `GosecVersion` in GoSec |
| 0.95 | Tool-specific variant of generic format | MSDO properties in SARIF |
| 0.9 | Strong generic match | `version`(string) + `runs`(array) for SARIF |
| 0.8 | High confidence from multiple keys | `bomFormat === 'CycloneDX'` |
| 0.5-0.7 | Partial/ambiguous | `vulnerabilities[]` (shared by Snyk, GitLab, etc.) |
| 0.0 | No match | |

**Rule:** Generic SARIF returns 0.9. Tool-specific SARIF wrappers (MSDO,
GoSec-as-SARIF) return 0.95+. This ensures the most specific match wins.

## Architecture Details

### Package exports

```
@mitre/hdf-converters           ← converter functions (heavy)
@mitre/hdf-converters/detect    ← detection + registration (lightweight)
@mitre/hdf-converters/registry  ← raw registry primitives
```

### File layout

```
hdf-converters/
  shared/typescript/
    registry.ts          ← ConverterFingerprint type + CRUD
    fingerprint.ts       ← detectConverter() dispatcher
    register-all.ts      ← explicit registration of all fingerprints
  src/
    index.ts             ← barrel export (converter functions)
    detect.ts            ← sub-path export (detection functions)
  registry/              ← Go package (mirrors TS)
    registry.go
    fingerprint.go
  converters/
    sarif-to-hdf/
      typescript/
        converter.ts     ← conversion logic (heavy)
        fingerprint.ts   ← fingerprint data (lightweight)
        fingerprint.test.ts
```

### Two detection domains

The fingerprint registry answers: **"What security tool produced this input?"**

A separate concern (tracked under a different card) is: **"What HDF schema
type is this document?"** (Results, Baseline, Plan, etc.) — that detection
is currently in `hdf-validators` and `hdf-parsers` and will be DRY'd into
a single canonical function separately.

## Go Parity

The Go implementation mirrors the TypeScript API exactly:

| TypeScript | Go |
|-----------|-----|
| `ConverterFingerprint` | `registry.ConverterFingerprint` |
| `registerFingerprint()` | `registry.Register()` |
| `detectConverter()` | `registry.DetectConverter()` |
| `detectConverterAll()` | `registry.DetectConverterAll()` |
| `detectFamily()` | `registry.DetectFamily()` |
| `getFingerprint()` | `registry.GetFingerprint()` |
| `_resetRegistry()` | `registry.ResetRegistry()` |

Go converters self-register via `init()` functions, which is Go's native
module initialization mechanism (equivalent to our explicit
`registerAllFingerprints()` in TypeScript).
