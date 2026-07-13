# HDF Developer Guide

Patterns and practices for contributing to the HDF libraries.

---

## Dual Implementation Pattern (TS + Go)

Every HDF library must be implemented in both TypeScript and Go simultaneously.
Do NOT build one language first and port later.

### Why

This was learned the hard way with hdf-diff: building TS first (380 tests) and then
porting to Go required multiple agent swarms, code review rounds, and bug fixes. The
Go nil-slice serialization issue (see below) would have been caught immediately if Go
was built alongside TS.

### Pattern

For each feature:
1. Design JSON Schema (primitives + top-level)
2. Write TDD tests in BOTH languages from shared fixture expectations
3. Implement in both languages
4. Run differential testing to verify identical output
5. Code review both implementations

### Shared Fixtures

Test fixtures live in the package's `test/fixtures/` directory and are shared between
TS and Go via relative paths. The Go tests load fixtures from `../../../<package>/test/fixtures/`.
Tests skip gracefully if fixtures are not found.

---

## Differential Testing

Differential testing verifies that TypeScript and Go implementations produce identical
output for the same inputs.

### How It Works

1. Both implementations run on the same shared fixtures
2. They assert the same expected values (same requirement states, same summary counts,
   same change reasons, same field changes)
3. Tests are NOT byte-identical comparison — they verify semantic equivalence because
   JSON key ordering may differ between languages

### Example

The hdf-diff differential tests (`hdf-diff/go/engine/differential_test.go`):
- Load fixtures from `../../../hdf-diff/test/fixtures/`
- Run Go's `engine.DiffHdf()` on each fixture pair
- Assert the same values that the TypeScript tests in `hdf-diff/test/diff.test.ts` assert

This found a real bug: Go was not threading document timestamps to
`ComputeEffectiveStatus()`, causing incorrect waiver expiration evaluation.

---

## Go Nil-Slice JSON Serialization

### The Problem

Go's `encoding/json` serializes nil slices as `null`. HDF JSON Schema 2020-12 with
`unevaluatedProperties: false` rejects `null` for optional array fields that aren't
explicitly nullable. TypeScript omits `undefined` fields entirely from serialized JSON.

### The Fix

`hdf-diff/go/validate/validate.go` exports `NormalizeForSchema()` which:
- Preserves `null` for explicitly nullable fields (`before`, `after`)
- Converts `null` to `[]` for required array fields (`fieldChanges`, `changeReasons`)
- Strips all other `null` values (matches JS undefined behavior)

`ValidateComparison()` calls `NormalizeForSchema()` automatically.

### Long-Term Fix

Update the quicktype Go code generator to emit `omitempty` on optional array fields,
or add custom `MarshalJSON` methods on `EvaluatedRequirement`. Tracked in beads
memory `go-nil-slice-null`.

### Rule

Any Go code producing HDF documents for schema validation must call
`validate.NormalizeForSchema()` before validation. This applies to all future
HDF document types (hdf-system, hdf-plan, hdf-amendments, hdf-evidence).

---

## Timestamp Handling

### Canonical form

Every timestamp in an HDF document (`timestamp`, result `startTime`, etc.) is
**RFC 3339 in UTC, with trailing fractional-second zeros trimmed and at most
millisecond precision** — e.g. `2024-11-15T10:30:00Z`, `2024-01-01T00:00:00.12Z`.
This is the single canonical form both the TypeScript and Go converters emit, so
their output is byte-identical and independent of the host machine's timezone.

UTC is canonical because `startTime`/`timestamp` are *instants* (when something
ran), not wall-clock-with-offset; UTC has exactly one rendering, which makes
cross-language parity trivial and eliminates the entire class of
host-timezone-dependent bugs.

### The Problem

Two traps produce drift:

1. **Zone-less parsing.** `new Date("2012-12-10T13:47:29")` (no `Z`/offset) is
   read as **host-local** time in JavaScript, but as **UTC** by Go's
   `time.Parse`. A converter using raw `new Date(value)` therefore produces
   different output depending on the machine it runs on.
2. **Offset / precision divergence.** A bare `time.Parse(time.RFC3339, ...)` in
   Go preserves the source offset (`-05:00`) and nanoseconds, while the TS side
   serializes a `Date` as UTC milliseconds — the two never match byte-for-byte.

### The Fix — always go through the shared helpers

| | TypeScript | Go |
|---|---|---|
| **Parse** a tool timestamp | `parseTimestamp(s)` from `@mitre/hdf-utilities` (zone-less → UTC, returns `Date \| null`) | `hdfutil.ParseTimestamp(s)` (zone-less → UTC, `.UTC().Truncate(ms)`, returns zero `time.Time` if unparseable) |
| **Format** for output | `formatTimestamp(d)` / let `buildHdfResults` / `serializeHdf` serialize the `Date` (they trim the fraction) | marshal the `time.Time` (RFC3339Nano of a UTC value is already trimmed) |

These helpers are the **single source of truth** — import them, never
re-implement timestamp parsing.

### Rules

- **Never** parse a tool-supplied timestamp with raw `new Date(value)` (TS) or
  `time.Parse(time.RFC3339, ...)` (Go). Use the shared helpers.
- A converter that builds HDF output by hand (a direct `JSON.stringify`) must use
  `serializeHdf()` from `converterutil`, not a bare `JSON.stringify`, so the
  fractional-second trim is applied.
- Result `startTime` is **schema-required**. When the source timestamp is absent
  or unparseable, fall back to a *valid* value (conversion time `new Date()` /
  the Go zero `time.Time`) — never `undefined` / omitted.
- A custom-layout `time.Parse("<layout>", ...)` is allowed **only** for formats
  `hdfutil.ParseTimestamp` does not cover (e.g. vendor-specific strings); pass
  the result through `hdfutil.NormalizeTimestamp(t)` (UTC + millisecond
  precision) to keep it canonical.

### Enforcement

These rules are enforced mechanically so the drift cannot recur:

- **TS:** a `no-restricted-syntax` ESLint rule in `hdf-converters/eslint.config.js`
  bans `new Date(<identifier|member>)` in `converters/*-to-hdf/**`.
- **Go:** `scripts/check-timestamp-usage.mjs` (run as `pnpm lint:timestamps`,
  part of `pnpm check`) bans `time.Parse(time.RFC3339...)` in converter Go.

Decision and rationale are recorded in beads memory `hdf-timestamp-canonical-utc`.

---

## Exit Code Conventions

The `hdf diff` CLI uses a researched exit code scheme. All future HDF CLI commands
that produce comparison or gate results should follow the same pattern.

### Basic Mode (`--exit-code`)

GNU diff compatible: 0=identical, 1=differences, 2=error.

### Detailed Mode (`--detailed-exitcode`)

| Code | Meaning | CI Action |
|------|---------|-----------|
| 0 | Identical | Pass |
| 1 | Error | Fail |
| 10 | Fixes only | Pass (improved) |
| 11 | Regressions only | Fail (degraded) |
| 12 | Mixed | Review |
| 13 | Baseline changed | Inform |
| 14 | Drift only | Inform |

Range 10-14 chosen to avoid sysexits.h (64-78), signal range (128+), and InSpec (100-101).
Full rationale documented in CHANGELOG.md.

---

## Schema Development Pattern

### Adding a New Document Type

1. Create `primitives/<name>.schema.json` with `$defs` for type-specific types
2. Create `hdf-<name>.schema.json` as the top-level document
3. Use `$ref` to existing primitives (Identity, Checksum, Signature, Target, etc.)
4. Set `unevaluatedProperties: false` on all object types
5. Add to `test/setup.ts` `createAjvWithPrimitives()` primitive list
6. Write `test/hdf-<name>.test.ts` with 20+ validation tests
7. Add to `src/generate-types.ts` for TS/Go type generation
8. Add subpath export to `package.json`
9. Add to `src/create-index.ts` for barrel exports

### Naming Conventions

- Schema `$defs`: `Snake_Case` (e.g., `Evaluated_Requirement`, `Authorization_Status`)
- JSON fields: `camelCase` (e.g., `authorizationStatus`, `baselineRefs`)
- Enum values: `camelCase` (e.g., `conditionallyAuthorized`, `notApplicable`)
- Go types: `PascalCase` (e.g., `AuthorizationStatus`, `BaselineRef`)
- Go constants: `PascalCase` with prefix (e.g., `StatusAuthorized`, `ModeBaseline`)

### $ref URI Pattern

```
https://mitre.github.io/hdf-libs/schemas/primitives/<name>/v3.4.0#/$defs/<Type>
https://mitre.github.io/hdf-libs/schemas/hdf-<name>/v3.4.0#/$defs/<Type>
```

---

## Cross-Platform Compatibility

### Scripts

- Use `rimraf` instead of `rm -rf` in package.json scripts (Windows compatibility)
- Use `cpy-cli` instead of `cp -r` (Windows compatibility)
- Use `readdirSync` instead of shell globs in Node scripts (`tsc dist/ts/*.ts` fails on Windows PowerShell)
- Use `working-directory` in GitHub Actions instead of `cd && command`

### Testing

- Use `fileParallelism: false` in vitest config for packages whose tests mutate
  shared state (e.g., hdf-schema's create-index tests clean and rebuild dist/)
- Use `server.deps.inline: [/@mitre\//]` in vitest config for packages that import
  workspace dependencies (fixes pnpm junction resolution on Windows)
- Go tests that load fixtures from sibling packages should skip gracefully if
  fixture files are not found

---

## Coverage Standards

- **95% minimum** for statements, branches, functions, and lines in all packages
- Coverage is enforced in CI — `continue-on-error` is never used
- Unreachable defensive branches can be annotated with `/* c8 ignore next */` (TS)
  or excluded via test-time assertions (Go), but MUST include a comment explaining
  why the branch is unreachable
- "Pre-existing" coverage gaps are not an excuse — if we find it, we fix it

---

## Progressive Enrichment Principle

When adding optional fields to HDF schemas (labels, sbomRef, systemRef, typed inputs,
signatures), follow the **progressive enrichment** pattern:

1. The field MUST be optional in the schema
2. Documents without the field MUST be fully valid and functional
3. Tests MUST cover both the "field present" and "field absent" cases
4. Converters SHOULD populate the field when source data is available, but MUST NOT
   fabricate data when it's not
5. Consumers (Heimdall, CLI) MAY prompt users to add enrichment, but MUST NOT fail
   when enrichment is absent

See CHANGELOG.md for the full rationale.

### SBOM References

`sbomRef` fields reference external SBOM documents (CycloneDX/SPDX) by URI. HDF does
not define its own SBOM format. Both CycloneDX and SPDX are supported from day one.

Rules:
- `sbomRef` is always optional
- When a system document's component has `sbomRef`, results for matching targets
  SHOULD reference the same SBOM (if the pipeline has access to it)
- When a vulnerability finding references a package not in any known SBOM, the
  `sbomRef` is absent — never fabricated
- Package-level data enters HDF through `tags.purl` on findings (populated by SCA
  converters like Grype/Trivy). Config scanners (InSpec, Nessus) never produce purls.

### SBOM Library Adoption

Full research: `docs/reviews/2026-03-15-sbom-library-research.md`

**Go:** Adopt `protobom` (OpenSSF) for unified CycloneDX + SPDX parsing with built-in
diff primitives. Also `packageurl-go` for PURL matching.

**TypeScript:** Adopt `@cyclonedx/cyclonedx-library` for CycloneDX validation +
`packageurl-js` for PURLs. Build custom format-agnostic parser (~100-200 lines)
normalizing CycloneDX `components[]` and SPDX `packages[]` into a common model.
The diff algorithm is format-agnostic once components are extracted.
