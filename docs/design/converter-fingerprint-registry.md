# Converter Fingerprint Registry — v2 (Post-Review)

**Status:** Revised after 3-agent review
**Date:** 2026-03-20
**Author:** Aaron Lippold
**Branch:** `feature/converter-fingerprint-registry` (off `dev`)
**Review agents:** TS completeness, Go integration, cross-cutting concerns

## Problem

hdf-libs has three separate auto-detection systems that violate DRY:

1. **Converter detection** — "What security tool made this?"
   Covers 4 of 32 formats. Each converter has internal validation but it's scattered.

2. **HDF type detection** — "What HDF schema variant is this?"
   Duplicated THREE times: `hdf-validators/typescript/index.ts` (validate()),
   `hdf-parsers/go/parsers.go` (Parse()), and `hdf-cli/cmd/hdf/cmd/detect.go`.
   All do the same root-key switch on baselines/requirements/components/etc.

3. **CLI converter routing** (`converter_registry.go`) — map[FormatPair]Converter.
   User must manually specify source format. No auto-detection.

Consumers lack a unified auto-detection API.

## Goals

1. Every ingest converter self-registers a lightweight structural fingerprint
2. Single `detectConverter(input)` call returns the matching converter
3. DRY: fingerprint logic co-located with each converter
4. TS and Go parity (registry + descriptor pattern)
5. Confidence scoring for ambiguous inputs
6. Works in browser, server, CLI, and MCP
7. Detection is CHEAP (no converter imports) — conversion is lazy-loaded
8. DRY the HDF type detection into one canonical function

## Non-Goals

- Binary file type detection (magic bytes)
- MIME type detection
- Replacing the CLI's FormatPair routing (it stays, optionally consumes fingerprints)

## Key Design Decisions (from review)

### D1: Separate fingerprint metadata from converter loading

**Problem:** If `ConverterDescriptor` includes a `convert` function, importing any
fingerprint transitively imports the full converter + its deps (fast-xml-parser,
ajv, d3-dsv, etc.). This bloats client bundles by 200-500KB.

**Decision:** Split into two layers:
- `ConverterFingerprint` — lightweight, pure key-checking, safe for any bundle
- Converter loading — lazy, on-demand via dynamic import or explicit import

### D2: Two detection domains, separate registries

**Converter fingerprints** ("what tool made this?") and **HDF type detection**
("what schema variant is this?") are separate concerns operating at different
stages (pre-conversion vs post-conversion). They share a pattern but not a registry.

- Converter fingerprint registry → lives in `hdf-converters`
- HDF type detection → should be canonicalized in `hdf-schema` or `hdf-validators`
  (single function, consumed by validators/parsers/CLI instead of 3 copies)

### D3: Explicit registration, not side-effect magic

ESM side-effect imports are fragile (tree-shaking strips them). Instead:
- TS: explicit `registerAllFingerprints()` function that imports all fingerprints
- Go: `init()` functions (Go's native mechanism, reliable)
- Consumers call `registerAllFingerprints()` once, or import barrel which does it

### D4: SARIF confidence tiers

Generic SARIF fingerprint returns 0.9 (not 1.0). Tool-specific SARIF wrappers
(MSDO, GoSec-as-SARIF) return 0.95+ with tool-specific key checks. This ensures
the most specific match wins.

### D5: Go registry in new sub-package

The existing `shared/go/` package is named `package shared`.
New registry goes in `hdf-converters/registry/` (clean package name, cleaner
import path).

## Architecture

```
hdf-converters/
  shared/
    typescript/
      registry.ts           <-- ConverterFingerprint type + register/get/detect
      register-all.ts        <-- imports all fingerprints, ensures registration
      xml-utils.ts           <-- shared XML utilities (extractXmlRootElement)
  registry/                  <-- Go registry package (clean import path)
    registry.go
    fingerprint.go
    register_all.go
  converters/
    sarif-to-hdf/
      typescript/
        fingerprint.ts       <-- exports register() + sarifFingerprint
      go/
        fingerprint.go       <-- init() calls registry.Register()
```

## Core Types (TypeScript)

```typescript
// shared/typescript/registry.ts

export type InputFamily = 'json' | 'xml' | 'csv' | 'text';
export type ConverterDirection = 'ingest' | 'export';
export type OutputType = 'results' | 'baseline' | 'plan' | 'amendments'
                       | 'system' | 'evidence-package' | 'raw';

/**
 * Lightweight fingerprint metadata — NO converter import.
 * Safe for client bundles. Pure structural key-checking.
 */
export interface ConverterFingerprint {
  id: string;                // 'gosec-to-hdf'
  label: string;             // 'GoSec'
  direction: ConverterDirection;
  inputFamily: InputFamily;
  outputType: OutputType;    // what the converter produces
  fingerprint: (input: unknown) => number;  // 0.0-1.0 confidence
}
```

### Confidence Guidelines

```
1.0  — unique key present (GosecVersion, bomFormat === 'CycloneDX')
0.95 — tool-specific SARIF (MSDO properties in SARIF runs)
0.9  — strong generic match (SARIF: version string + runs array)
0.7  — partial match (has vulnerabilities[] but no tool-specific key)
0.5  — ambiguous (could be multiple formats)
0.0  — no match
```

### Registration

```typescript
const registry: ConverterFingerprint[] = [];

export function registerFingerprint(fp: ConverterFingerprint): void {
  if (registry.some(d => d.id === fp.id)) {
    throw new Error(`Duplicate fingerprint: ${fp.id}`);
  }
  registry.push(fp);
}

export function getFingerprints(): readonly ConverterFingerprint[] {
  return registry;
}

export function getIngestFingerprints(): readonly ConverterFingerprint[] {
  return registry.filter(d => d.direction === 'ingest');
}

export function getFingerprint(id: string): ConverterFingerprint | undefined {
  return registry.find(d => d.id === id);
}

export function _resetRegistry(): void { registry.length = 0; }
```

### Dispatcher

```typescript
// shared/typescript/fingerprint.ts

export interface DetectionResult {
  fingerprint: ConverterFingerprint;
  confidence: number;
}

export function detectConverter(input: string): DetectionResult | undefined {
  return detectConverterAll(input)[0];
}

export function detectConverterAll(input: string): DetectionResult[] {
  const family = detectFamily(input);
  if (!family) return [];

  const parsed = family === 'json' ? tryParseJSON(input) : input;
  if (parsed === undefined) return [];

  const results: DetectionResult[] = [];
  for (const fp of getIngestFingerprints()) {
    if (fp.inputFamily !== family) continue;
    const confidence = fp.fingerprint(parsed);
    if (confidence > 0) results.push({ fingerprint: fp, confidence });
  }

  results.sort((a, b) => b.confidence - a.confidence);
  return results;
}

export function detectFamily(input: string): InputFamily | undefined {
  if (!input) return undefined;
  const trimmed = input.trim();
  if (!trimmed) return undefined;
  if (trimmed.startsWith('{') || trimmed.startsWith('[')) return 'json';
  if (trimmed.startsWith('<')) return 'xml';
  return 'text';
}
```

Note: CSV detection removed from `detectFamily()` (too many false positives).
CSV converters (Prisma) set `inputFamily: 'text'` and do their own header check.

### Converter Loading (separate from detection)

```typescript
// Consumer code:
import { detectConverter } from '@mitre/hdf-converters/detect';
import { registerAllFingerprints } from '@mitre/hdf-converters/detect';

// Call once at startup
registerAllFingerprints();

// Detect
const result = detectConverter(rawInput);
if (result) {
  // Lazy-load the converter only when needed
  const { convertGosecToHdf } = await import('@mitre/hdf-converters');
  const hdf = await convertGosecToHdf(rawInput);
}
```

### Explicit Registration (register-all.ts)

```typescript
// shared/typescript/register-all.ts
// Imports every converter's fingerprint to trigger registration.
// Called by registerAllFingerprints() or by barrel import.

import { sarifFingerprint } from '../../converters/sarif-to-hdf/typescript/fingerprint.js';
import { gosecFingerprint } from '../../converters/gosec-to-hdf/typescript/fingerprint.js';
// ... all 32+
import { registerFingerprint, getFingerprint } from './registry.js';

const allFingerprints = [sarifFingerprint, gosecFingerprint, /* ... */];

let registered = false;
export function registerAllFingerprints(): void {
  if (registered) return;
  registered = true;
  for (const fp of allFingerprints) {
    if (!getFingerprint(fp.id)) registerFingerprint(fp);
  }
}
```

Each converter's `fingerprint.ts` exports a `ConverterFingerprint` object (data)
and optionally a `register()` function. No side-effect imports at module scope.

### Package Exports

```json
// hdf-converters/package.json "exports"
{
  ".": "./dist/src/index.js",
  "./detect": "./dist/shared/typescript/fingerprint.js",
  "./registry": "./dist/shared/typescript/registry.js"
}
```

Add `"sideEffects": false` — our registration is explicit, not side-effect based.

## Fingerprint Table (corrected from review)

### JSON converters

| Converter | Confidence 1.0 Key | Fallback | OutputType |
|-----------|---------------------|----------|------------|
| gosec | `GosecVersion` + `Issues[]` | `Issues[]` + `Stats` (0.6) | results |
| snyk | `vulnerabilities[]` + `packageManager` | `vulnerabilities[]` (0.5) | results |
| grype | `matches[]` + `source.type` | `descriptor.name === 'grype'` (0.8) | results |
| sarif | `version` (string) + `runs[]` | — | results |
| cyclonedx | `bomFormat === 'CycloneDX'` | `components[]` + `specVersion` (0.8) | results |
| trufflehog | `SourceMetadata` + `DetectorName` | `Raw` + `Verified` (0.7) | results |
| gitlab | `vulnerabilities[]` + `scan.type` | `version` + `vulnerabilities[]` (0.5) | results |
| splunk | `results[]` + each has `control` | — | results |
| aws-config | `ConfigRules[]` OR `ConfigRuleName` | — | results |
| sonarqube | `issues[]` + `rule` + `component` | — | results |
| msft-defender-devops | SARIF + `tool.driver.name` contains 'Microsoft' | — (0.95) | results |
| msft-defender-cloud | `value[]` + `properties.alertDisplayName` | — | results |
| msft-defender-endpoint | `value[]` + `machineId` | — | results |
| msft-secure-score | `value[]` + `controlName` + `score` | — | results |
| deptrack | `findings[]` + `vulnerability.vulnId` | — | results |
| jfrog-xray | `violations[]` OR `vulnerabilities[]` + `watch_name` | — | results |
| neuvector | `vulnerabilities[]` + `name` + `package_name` | — | results |
| twistlock | `results[]` + `complianceDistribution` | — | results |
| scoutsuite | `services` + `last_run.ruleset` | — | results |
| conveyor | `findings[]` + `pipeline` | — | results |
| nikto | `vulnerabilities[]` + `host`/`port` | `vulnerabilities[]` (0.85) | results |
| zap | `site[]` + `@version`/`@generated` | `site[]` (0.85) | results |
| hdf-v2 (passthrough) | `baselines[]` + `components[]` | `baselines[]` (0.8) | results |
| hdf-v1 (legacy) | delegates to `isHDFV1()` | — | results |

**SARIF confidence: 0.9** (not 1.0). Tool-specific SARIF wrappers return 0.95.

**Corrections from review:**
- ~~Prisma listed as JSON~~ → Prisma is CSV/text input
- ~~Fortify listed as JSON~~ → Fortify is XML-only (FVDL root element)
- Added HDF v2 native detection (most common upload format)
- Added HDF v1 legacy detection (delegates to existing `isHDFV1()`)
- ~~Nikto listed as XML~~ → Nikto input is JSON (`vulnerabilities[]` + `host`/`port`)
- ~~ZAP listed as XML~~ → ZAP input is JSON (`site[]` + `@version`/`@generated`)

### XML converters

| Converter | Root Element | Namespace | OutputType |
|-----------|-------------|-----------|------------|
| xccdf + arf | `Benchmark` / `asset-report-collection` | `checklists.nist.gov/xccdf` | results |
| junit | `testsuites` / `testsuite` | — | results |
| nessus | `NessusClientData_v2` | — | results |
| netsparker | `netsparker-enterprise` / `invicti-enterprise` | — | results |
| burpsuite | `issues` | — | results |
| fortify | `FVDL` | `xmlns.fortify.com` | results |
| dbprotect | `dataset` | — | results |
| veracode | `detailedreport` | — | results |

### Text/CSV converters

| Converter | Detection | OutputType |
|-----------|-----------|------------|
| prisma | Header row contains `complianceMetadata` | results |

### OSCAL converters

| Converter | Top-level Key | OutputType |
|-----------|---------------|------------|
| oscal-catalog | `catalog` | baseline |
| oscal-component | `component-definition` | baseline |
| oscal-profile | `profile` | baseline |
| oscal-ssp | `system-security-plan` | raw |
| oscal-sap | `assessment-plan` | plan |
| oscal-sar | `assessment-results` | results |
| oscal-poam | `plan-of-action-and-milestones` | amendments |

## Go Architecture

```go
// hdf-converters/registry/registry.go
package registry

type InputFamily string
const (
    FamilyJSON InputFamily = "json"
    FamilyXML  InputFamily = "xml"
    FamilyText InputFamily = "text"
)

type OutputType string
const (
    OutputResults      OutputType = "results"
    OutputBaseline     OutputType = "baseline"
    OutputPlan         OutputType = "plan"
    OutputAmendments   OutputType = "amendments"
    OutputSystem       OutputType = "system"
    OutputRaw          OutputType = "raw"
)

type ConverterFingerprint struct {
    ID          string
    Label       string
    Direction   string      // "ingest" | "export"
    InputFamily InputFamily
    OutputType  OutputType
    Fingerprint func(input interface{}) float64
}

// Register, Detect, DetectAll, ResetRegistry (for tests)
```

Each Go converter calls `registry.Register()` in `init()`.
New Go registry package provides a clean import path separate from `package shared`.

CLI integration: `hdf convert input.json` (auto-detect) calls `registry.Detect()`.
Existing `FormatPair` registry is unchanged — `auto` is a new source format
that delegates to the fingerprint registry.

## Multi-Format Converters (resolved)

| Pattern | Converters | Approach |
|---------|-----------|----------|
| Native JSON + SARIF fallback | gosec, snyk, zap | Register ONE fingerprint for native format. SARIF delegation is internal to the converter. |
| SARIF wrapper with enrichment | msft-defender-devops | Register with SARIF sub-check at 0.95 confidence (outranks generic SARIF at 0.9). |
| Dual XML root elements | xccdf (Benchmark + ARF) | ONE fingerprint checking both root elements. |
| OSCAL multi-type | oscal-* (7 types) | 7 separate fingerprints, each checking one root key. Wraps existing `detectOscalDocumentType()`. |

## DRY: HDF Type Detection (separate work)

The HDF schema variant detection (`Results`/`Baseline`/`Plan`/etc.) is duplicated
in 3 places. This is a separate task tracked under a different card:

- Create `detectHdfType(data: unknown): HdfDocumentType` in `hdf-schema`
- `hdf-validators` validate() delegates to it
- `hdf-parsers` Parse() delegates to it
- CLI detect.go delegates to it
- All three switch statements collapse to one function call

## Testing Strategy

Each fingerprint exports a `ConverterFingerprint` object. Tests verify:
- Known-good fixture → confidence >= 0.9
- Similar-format fixture → confidence 0 (no false positive)
- Garbage/empty → confidence 0, no throw

Integration tests:
- Feed every converter's fixture through `detectConverter()` → correct match
- No false positives between similar formats (Snyk vs GitLab)
- OSCAL sub-type discrimination
- SARIF tier: generic < tool-specific
- Empty/malformed → undefined

## Open Questions (resolved)

1. ~~Confidence number vs enum~~ → **Number (0.0-1.0)**. More expressive.
2. ~~Multi-format converters~~ → **Resolved** (see table above).
3. ~~Registry mutable?~~ → **Yes**, consumers can register custom fingerprints.
4. ~~OSCAL profile needs extra input~~ → **Edge case**: profile converter registered
   in fingerprint registry for detection, but conversion requires catalog context.
   Consumers handle this at the application layer.
