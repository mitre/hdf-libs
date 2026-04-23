# v1 to v2 Migration Guide

This guide is for tool authors and pipeline maintainers who work with InSpec exec-json (HDF v1) output and need to understand the changes in HDF v2.

For full architecture details, see [hdf-v2-document-ecosystem.md](../architecture/hdf-v2-document-ecosystem.md).

## Audience

- Teams maintaining InSpec-based security scanning pipelines
- Developers integrating with Heimdall or the HDF CLI
- Tool authors consuming or producing HDF documents

## Key Renames

| v1 (InSpec exec-json) | v2 (HDF) | Notes |
|---|---|---|
| `profiles[]` | `baselines[]` | Terminology alignment -- "baseline" is tool-agnostic, "profile" is InSpec-specific |
| `controls[]` | `requirements[]` | Broader scope: security requirements, not just InSpec controls |
| `attributes[]` | `inputs[]` | InSpec v4/v5 rename; now typed with `Input` primitive |
| `platform` (object) | `components[]` (array) | Polymorphic, supports multiple components of different types |
| `code_desc` | `codeDesc` | camelCase normalization |
| `source_location` | `sourceLocation` | camelCase normalization |
| `start_time` | `startTime` | camelCase normalization; values normalized to ISO 8601 |
| `run_time` | `runTime` | camelCase normalization |
| status `"skipped"` | `"notReviewed"` | SARIF-compatible terminology: the requirement was not assessed |
| `sha256` (string) | `checksum` (object) | Structured: `{ "algorithm": "sha256", "value": "..." }` |
| `desc` (string) | `descriptions[]` (array) | Array of labeled descriptions with `{ "label": "default", "data": "..." }` |

## Structural Changes in Detail

### profiles to baselines

v1:
```json
{
  "profiles": [
    { "name": "rhel9-stig", "controls": [...] }
  ]
}
```

v2:
```json
{
  "baselines": [
    { "name": "rhel9-stig", "requirements": [...] }
  ]
}
```

The `baselines` array is the only required top-level field in hdf-results.

### platform to components

v1 has a single `platform` object:
```json
{
  "platform": { "name": "ubuntu", "release": "22.04", "target_id": "" }
}
```

v2 has an array of polymorphic `components`, each with a `type` discriminator:
```json
{
  "components": [
    {
      "type": "host",
      "name": "web-server-01",
      "osName": "Ubuntu",
      "osVersion": "22.04 LTS",
      "labels": { "component": "WebTier", "environment": "production" }
    }
  ]
}
```

Supported component types: `host`, `containerImage`, `containerInstance`, `containerPlatform`, `cloudAccount`, `cloudResource`, `repository`, `application`, `artifact`, `network`, `database`.

### attributes to inputs (typed)

v1 attributes are unstructured maps:
```json
{
  "attributes": [
    { "name": "max_sessions", "options": { "default": 3 } }
  ]
}
```

v2 inputs use the typed `Input` primitive:
```json
{
  "inputs": [
    {
      "name": "max_sessions",
      "type": "Numeric",
      "value": 3,
      "description": "Maximum concurrent sessions per user",
      "required": true,
      "operator": "le",
      "constraints": { "min": 1, "max": 100 }
    }
  ]
}
```

Supported input types: `String`, `Numeric`, `Boolean`, `Array`, `Hash`, `Regexp`.

### sha256 to checksum

v1:
```json
{ "sha256": "abc123def456..." }
```

v2:
```json
{
  "checksum": {
    "algorithm": "sha256",
    "value": "abc123def456..."
  }
}
```

The `Checksum` object supports multiple algorithms and is used across document types for integrity verification.

### Status normalization

v1 `"skipped"` maps to v2 `"notReviewed"`. The complete v2 `Result_Status` enum is:

- `passed` -- requirement met
- `failed` -- requirement not met
- `error` -- test execution error
- `notApplicable` -- requirement does not apply (impact = 0)
- `notReviewed` -- requirement was not assessed

v2 also adds `effectiveStatus` on each requirement, which reflects the status after applying overrides (waivers, attestations). If no overrides exist, `effectiveStatus` is computed from results using InSpec enhanced outcomes precedence: `error > failed > passed > notApplicable > notReviewed`. When `impact = 0`, `effectiveStatus` is always `notApplicable`.

### Severity

v2 adds an explicit `severity` field on requirements: `critical`, `high`, `medium`, `low`, `informational`. This is derived from `tags.severity` when present (preserving original STIG severity), falling back to impact-derived severity:

| Impact | Severity |
|---|---|
| >= 0.9 | critical |
| >= 0.7 | high |
| >= 0.5 | medium |
| > 0 | low |
| 0 | informational |

## New v2 Features Not in v1

These fields and concepts are new in v2 and have no v1 equivalent:

- **Labels** -- `Record<string, string>` on components and baselines for flexible grouping by system, component, environment, region, team, or custom dimensions.
- **Typed inputs** -- `Input` primitive with type, operator, and constraints. Bridges governance requirements to scanner automation.
- **systemRef / planRef** -- URI references linking results to hdf-system and hdf-plan documents, establishing provenance.
- **Multiple component types** -- 11 polymorphic component types (host, container, cloud account, cloud resource, repository, application, artifact, network, database).
- **hdf-system documents** -- Describe system architecture, authorization boundaries, components with label-based selectors, input overrides, and SBOM references.
- **hdf-plan documents** -- Assessment plans with resolved inputs, target selectors, runner configuration, and schedules.
- **hdf-amendments documents** -- Standalone signed waivers, attestations, and POA&Ms that merge into results.
- **hdf-evidence-package documents** -- Audit-ready bundles referencing all other document types with completeness checks and integrity verification.
- **hdf-comparison documents** -- Structured diffs between any two HDF documents of the same type.

## How to Convert

### CLI

```bash
hdf convert --from legacyhdf old-results.json -o new-results.json
```

The `inspec` alias also works:

```bash
hdf convert --from inspec old-results.json -o new-results.json
```

The converter reads from stdin if the input is `-`:

```bash
cat old-results.json | hdf convert --from legacyhdf - -o new-results.json
```

### Programmatic (Go)

```go
import (
    "encoding/json"
    legacyhdf "github.com/mitre/hdf-libs/hdf-converters/converters/legacyhdf-to-hdf/go"
)

var v1 legacyhdf.HDFV1Results
json.Unmarshal(input, &v1)
v2 := legacyhdf.ConvertV1ToV2(&v1)
```

The Go converter performs a comprehensive transformation:
- `profiles` to `baselines`, `controls` to `requirements`
- `attributes` to typed `inputs` (extracting name, value, description, sensitive, required, type from the v1 map)
- `sha256` to `checksum` object
- snake_case to camelCase on all fields
- `"skipped"` to `"notReviewed"`
- `platform` to a `components[]` array with a single `host` component
- Computes `effectiveStatus` and `severity` for every requirement
- Flattens overlay/wrapper baselines to eliminate duplicate controls

### Programmatic (TypeScript)

The `hdf-diff` normalizer handles v1 transparently for diffing purposes:

```typescript
import { isV1Format, normalizeToV2 } from '@mitre/hdf-diff/normalize';

if (isV1Format(doc)) {
  const v2 = normalizeToV2(doc);
  // v2 has baselines[], requirements[], camelCase fields
}
```

The normalizer detects v1 by checking for `profiles` at the top level (v2 uses `baselines`). It converts:
- `profiles[].controls[]` to `baselines[].requirements[]`
- `sha256` to `{ algorithm: "sha256", value: "..." }`
- `attributes` to `inputs`
- `source_location` to `sourceLocation`
- `code_desc` to `codeDesc`, `start_time` to `startTime`, `run_time` to `runTime`
- `"skipped"` to `"notReviewed"`
- Timestamps are normalized to ISO 8601

You can diff v1 and v2 documents directly -- the diff engine normalizes v1 on the fly:

```bash
hdf diff v1-results.json v2-results.json
```

## Common Pitfalls

### attributes and inputs are different structures

Do not write both `attributes` and `inputs` on the same baseline. v2 uses only `inputs`. If you are producing v2 output, use the `Input` type with `name` (required) and optional `type`, `value`, `description`, `required`, `sensitive`, `operator`, `constraints`.

v1 attributes used `options.default` for the value:
```json
{ "name": "x", "options": { "default": 3 } }
```

v2 inputs use a top-level `value` field:
```json
{ "name": "x", "type": "Numeric", "value": 3 }
```

### platform is an object, components is an array

v1 `platform` is a single object. v2 `components` is an array of objects, each with a required `type` discriminator. If you are constructing v2 output from v1 data, wrap the platform in an array and set `type: "host"`:

```json
{
  "components": [
    { "type": "host", "name": "ubuntu" }
  ]
}
```

### controls is not an array of strings

In v1 groups, `controls` is an array of control ID strings. In v2, the group field is renamed to `requirements` (also an array of requirement ID strings). But `requirements` at the baseline level is an array of `EvaluatedRequirement` objects. Do not confuse the two.

### Overlay flattening

v1 InSpec output often contains overlay/wrapper profiles where a parent profile includes controls from a child profile, resulting in duplicate controls across `profiles[]`. The v1-to-v2 converter automatically flattens these overlays so each requirement appears exactly once in the output. If you are writing your own converter, you may need to handle this deduplication.

### Timestamps

v1 uses formats like `"2017-09-22 14:12:15 -0400"` which are not valid ISO 8601. v2 requires ISO 8601 / RFC 3339 format (`"2017-09-22T18:12:15.000Z"`). The converter normalizes timestamps automatically. If you are producing v2 output directly, use ISO 8601.
