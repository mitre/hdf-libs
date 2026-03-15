# SBOM Library Research — TypeScript and Go

**Date:** 2026-03-15
**Purpose:** Identify existing libraries for CycloneDX/SPDX parsing, validation, and diffing
**Decision:** Adopt existing libraries, don't build our own

---

## Summary

| Need | TypeScript | Go |
|------|-----------|-----|
| CycloneDX parse/validate | `@cyclonedx/cyclonedx-library` (115K/wk) | `cyclonedx-go` (106 stars, 1.7K users) |
| SPDX parse/validate | **GAP** — `@spdx/tools` is v0.1.0, immature | `tools-golang` (161 stars, 1.9K users) |
| Unified CycloneDX + SPDX | **GAP** — nothing exists in JS/TS | **`protobom`** (320 stars, OpenSSF) |
| SBOM diff/compare | **GAP** — nothing exists in JS/TS | **`protobom`** has `Node.Diff()`, `Intersect()`, `Union()` |
| PURL handling | `packageurl-js` (254K/wk) | `packageurl-go` (72 stars) |
| SBOM generation | `@cyclonedx/cdxgen` (916 stars) | `anchore/syft` (8.5K stars) |

---

## Key Finding: Asymmetric Ecosystem

**Go has a clear winner: `protobom`** — unified CycloneDX + SPDX parsing into a common
graph model with built-in diff primitives. OpenSSF-backed, 320 stars, actively maintained.

**TypeScript has no equivalent.** The CycloneDX library is mature for creation/validation
but can't parse or diff. SPDX support is immature. No unified library exists. No diff
library exists.

---

## TypeScript Libraries

### CycloneDX

#### `@cyclonedx/cyclonedx-library` — Official, mature

- **Install:** `pnpm add @cyclonedx/cyclonedx-library`
- **GitHub:** https://github.com/CycloneDX/cyclonedx-javascript-library
- **Stars:** 22 | **Weekly downloads:** ~115,000
- **License:** Apache-2.0
- **Latest:** v10.0.0 (~March 2026)
- **Spec support:** CycloneDX 1.2–1.7
- **Capabilities:** Full data model, serialize to JSON/XML, Ajv validation
- **Limitations:** Does NOT parse existing SBOM files, does NOT diff
- **Note:** For parsing, use `JSON.parse()` + Ajv against bundled CycloneDX JSON schemas

#### `@cyclonedx/cdxgen` — SBOM generation tool

- **Install:** `pnpm add @cyclonedx/cdxgen`
- **Stars:** 916 | **License:** Apache-2.0
- **Capabilities:** Generate SBOMs from source code (30+ languages)
- **Not relevant** for parsing/diffing — it generates, not reads

### SPDX

#### `@spdx/tools` — Official but immature

- **Install:** `pnpm add @spdx/tools`
- **Stars:** 10 | **Latest:** v0.1.0 (Dec 2023)
- **Status:** EARLY DEVELOPMENT — cannot parse existing docs, no validation, no diff
- **Not usable** for our purposes

#### `spdx-tools-js` — ARCHIVED (Nov 2023), do not use

### Supporting

#### `packageurl-js` — PURL parsing

- **Install:** `pnpm add packageurl-js`
- **Stars:** (active) | **Weekly downloads:** ~254,000
- **License:** MIT | **Latest:** v2.0.1 (Sep 2024)
- **Essential** for component identification in SBOM comparison

#### `spdx-expression-parse` — License expression parsing

- Handles SPDX license expressions (e.g., "MIT OR Apache-2.0")
- Supplementary, not an SBOM parser

---

## Go Libraries

### CycloneDX

#### `github.com/CycloneDX/cyclonedx-go` — Official

- **Stars:** 106 | **Used by:** ~1,700 repos
- **License:** Apache-2.0
- **Latest:** v0.10.0 (Jan 2026)
- **Spec support:** CycloneDX 1.0–1.6
- **Capabilities:** Parse and produce CycloneDX JSON/XML, validation, marshal/unmarshal
- **No diff capability** — provides data structures only

### SPDX

#### `github.com/spdx/tools-golang` — Official

- **Stars:** 161 | **Used by:** ~1,900 repos
- **License:** Apache-2.0 OR GPL-2.0-or-later
- **Latest stable:** v0.5.7 (Jan 2026) | **RC:** v0.6.0-rc2 (SPDX 3.0 support)
- **Spec support:** SPDX 2.1, 2.2, 2.3 (stable); 3.0 (RC)
- **Capabilities:** Read/write tag-value, JSON, YAML, RDF. Validation. License reporting.
- **No diff capability**

### Unified + Diff

#### `github.com/protobom/protobom` — **STRONGEST CANDIDATE**

- **Stars:** 320 | **License:** Apache-2.0
- **Governance:** OpenSSF Sandbox project
- **Latest:** v0.5.4 (Aug 2025)
- **Format support:** CycloneDX 1.4–1.6 JSON, SPDX 2.3 JSON
- **Capabilities:**
  - Parse both formats into unified Protocol Buffer model
  - `Node.Diff(n2)` — field-level diff between two components
  - `Node.Equal(n2)` — equality comparison
  - `NodeList.Union(nl2)` — merge two SBOMs
  - `NodeList.Intersect(nl2)` — find common components
  - `NodeList.GetMatchingNode()` — cross-SBOM component matching
  - Graph operations: `NodeGraph()`, `NodeDescendants()`
- **This is the library to adopt for Go SBOM diffing**

#### `github.com/CycloneDX/sbom-utility` — Validation + experimental diff

- **Stars:** 128 | **License:** Apache-2.0
- **Spec support:** CycloneDX 1.2–1.6, SPDX 2.1–2.3.1
- **Capabilities:** Validate, SQL-like query, experimental diff (RFC 6902 patches)
- **Assessment:** Good for validation, but diff is patch-based not semantic. CLI tool, not library.

### Supporting

#### `github.com/package-url/packageurl-go` — PURL parsing

- **Stars:** 72 | **Latest:** v0.1.5 (Mar 2026) | **Used by:** 334+ projects
- **Essential** for component identity matching

### Other Tools (Not Libraries)

- **`anchore/syft`** (8.5K stars) — SBOM generation from containers/filesystems. Uses cyclonedx-go and tools-golang internally. Not a library API.
- **`bomctl`** (133 stars) — SBOM lifecycle management built on protobom. Diff is "FUTURE" feature.
- **`cyclonedx-cli`** (469 stars) — Best SBOM diff implementation but written in .NET/C#.
- **`sbomdiff`** (Python) — Handles both CycloneDX and SPDX diff. Reference for diff semantics.

---

## Recommended Adoption Strategy

### Go (strong ecosystem)

```
protobom          — unified parse + diff primitives (CycloneDX + SPDX)
packageurl-go     — PURL matching for component identity
```

Compose higher-level diff using protobom's `Intersect` (shared), set subtraction
(added/removed), and `Node.Diff()` (version changes). protobom handles format
differences transparently.

### TypeScript (custom diff needed)

```
@cyclonedx/cyclonedx-library  — CycloneDX data models + validation
packageurl-js                  — PURL matching
JSON.parse + Ajv               — Parse CycloneDX and SPDX JSON against their schemas
Custom diff logic              — Match by PURL, compare versions (algorithm is simple)
```

The TS diff algorithm is straightforward: parse two SBOMs (CycloneDX or SPDX JSON),
normalize into a common component model, index by PURL, compare version fields,
report added/removed/updated. Both formats supported from day one — SPDX JSON is just
JSON, parse and validate against SPDX JSON schemas (available at github.com/spdx/spdx-spec).

### Long-term consideration

If protobom ever gets JS/TS bindings (or WASM compilation), that would eliminate
the TS gap entirely. Worth watching.
