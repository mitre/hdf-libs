# ADR-0018: Enforce the declared schema dialect in HDF validators

**Date:** 2026-11-07
**Status:** Accepted
**Deciders:** HDF maintainers

## Scope

Enforce the declared JSON Schema dialect in Go and TypeScript without changing legacy-v2 validation or converter input policy. This decision is independent of SIEM export and packaging. [ADR-0019](adr-0019-siem-source-preservation.md) defines source preservation, [ADR-0020](adr-0020-siem-evidence-package-delivery.md) defines optional CLI delivery, and [ADR-0021](adr-0021-private-archives-and-unattended-sharing.md) defines archive access. The streaming boundary remains in [ADR-0005](adr-0005-hdf-conmon-requirement-change-events.md).

## Context

The modern HDF schemas declare JSON Schema 2020-12, but the original TypeScript validator instantiated draft-07 Ajv and the Go validator used gojsonschema. Both accepted undeclared properties at closed root and nested scopes. This made the CLI and library validation result weaker than the schema contract. The published-package reproduction is recorded in [issue #523](https://github.com/mitre/hdf-libs/issues/523).

The public validation result is consumed by converters, the CLI and MCP. Replacing an engine must preserve their contracts, including dotted Go field paths, the `invalid_type` keyword, format names and offending values. Legacy HDF v2 uses a separate schema and must keep its existing behavior.

## Decision

Use the existing Ajv dependency's `Ajv2020` class for modern TypeScript HDF validation and `github.com/santhosh-tekuri/jsonschema/v6` v6.0.3 for modern Go validation. Retain the existing Ajv instance and gojsonschema path for legacy v2. Preserve `RegisterRFCFormatCheckers`, which other Go packages call.

Do not change schema content, consumer input policy, package versions or dependency versions as part of selecting the correct dialect. Tekuri is a direct validator dependency and is also used by the converter module.

### Compatibility requirements

1. Compile all eight modern bundled schemas offline. Missing references must produce a useful error, never trigger an HTTP fetch.
2. Keep lazy schema compilation and `SetSchemaDir` behavior, including cache reset and error propagation.
3. Opt into Go format assertions and register the existing UUID/date-time semantics with the modern engine. Preserve the TypeScript date-time override. Run the shared format table in both languages.
4. Adapt structured Go errors into the existing `ValidationError`: dotted `Field`, `invalid_type` for type violations, `format` plus `Format` for format violations, and the offending `Value`. New closure failures must identify the actual property. Do not parse human-readable error strings to reconstruct the contract.
5. Keep the converters' existing narrow input checks. `rejectWronglyTypedFields` deliberately rejects non-null type violations and date-time format violations. Changing that policy is a separate decision; do not add new keyword filtering to hide stricter output validation failures.
6. Accept schema-declared open scopes such as `extensions.passthrough` without mutating input. Do not strip unknown properties, substitute defaults or weaken schema closure.

## Prior Art

Versions and license files were inspected on 2026-11-07. MIT and Apache-2.0 are not on `.github/workflows/dependency-review.yml`'s deny list. No source is vendored.

| Candidate | Version and license | Verdict | Reason |
|---|---|---|---|
| [Ajv](https://github.com/ajv-validator/ajv/tree/v8.18.0) | 8.18.0, MIT | ADOPT, retain existing version | Already installed; modern class enforces closure while retaining existing integration and format hooks. |
| [ajv-formats](https://github.com/ajv-validator/ajv-formats/tree/v3.0.1) | 3.0.1, MIT | ADOPT, retain existing version | Existing format behavior is a cross-language compatibility contract. |
| [santhosh-tekuri/jsonschema](https://github.com/santhosh-tekuri/jsonschema/tree/v6.0.3) | 6.0.3, Apache-2.0 | ADOPT | Compiles every HDF bundle offline; structured error tree, instance tokens, assertion controls and custom formats. |
| [google/jsonschema-go](https://github.com/google/jsonschema-go/tree/v0.4.3) | 0.4.3, MIT | REJECT for this adapter | Compiles the bundles and enforces closure, but its tested API does not assert date-time format and its returned errors do not provide the structured field/keyword/value contract this adapter needs. |
| [gojsonschema](https://github.com/xeipuuv/gojsonschema/tree/v1.2.0) | 1.2.0, Apache-2.0 | REJECT for v3; retain for legacy | Demonstrably ignores modern closure; existing legacy validation and exported format registration still depend on it. |

No npm dependency change is needed. The existing legacy dependency remains deliberate. Dependency maintenance is separate from selecting the correct schema dialect.

## Evidence

Research ran against upstream main commit `a9a5901d4cb3473dcdfc2a50efcdcecc098b7955`, whose bundled schema IDs identify v3.8.0. This is distinct from the published 3.7.2-package reproduction attached to #523. Inputs below are clones of the existing `hdf-fixtures/results/minimal.json`, with one named property added per negative case.

| Case | Original TypeScript | Ajv2020 | Original Go | Tekuri | Google |
|---|---|---|---|---|---|
| Unchanged minimal results | Accept | Accept | Accept | Accept | Accept |
| Undeclared root property | Accept (defect) | Reject | Accept (defect) | Reject | Reject |
| Undeclared baseline property | Accept (defect) | Reject | Accept (defect) | Reject | Reject |
| Undeclared requirement property | Accept (defect) | Reject | Accept (defect) | Reject | Reject |
| Arbitrary property inside extensions.passthrough | Accept | Accept | Accept | Accept | Accept |

Both Go candidates compile all eight committed bundles with external loading unavailable. Tekuri reports an instance location ending in the actual undeclared member. Google's error identifies the schema traversal instead. A separate format probe using Google's resolved draft-2020-12 schema accepts `not-a-timestamp` against `format: date-time`.

### Performance tradeoff

The Go comparison on 2026-11-10 uses identical, corrected and timestamp-normalized bytes derived from `hdf-fixtures/results/inspec-multilayered.json`: 7,101,796 bytes, SHA-256 `8eb7286407ec5c85f0d5b20c1ebf1b2ea6c0bc10a780455a29091f368365bd55`. Both engines accept that document. The modern measurement is pinned to commit `0aa5a63eb55d8f8a71214052a1d6ed8af64ca365`; subsequent diagnostic-summary changes affect invalid results, not this valid-document path.

| Measurement | Original gojsonschema validator | Modern Tekuri validator | Ratio |
|---|---:|---:|---:|
| First validation after schema-cache reset | 37.192 ms | 47.542 ms | 1.278× |
| Mean of ten subsequent validations | 31.6423 ms | 40.5553 ms | 1.282× |

Both measurements include JSON parsing. The first validation also includes schema compilation; the subsequent validations reuse compiled schemas. File reading and timestamp normalization occur outside the timed sections. This is a local comparative measurement, not a production latency guarantee or a concurrent-load benchmark.

The owner accepted this measured rollout tradeoff on 2026-11-10: approximately 9 ms additional warm validation time (31.6423 ms to 40.5553 ms, about 28%) for correct JSON Schema 2020-12 enforcement. This acceptance applies to the comparison above, not a general latency guarantee or permission for future regressions.

## Alternatives Considered

### Keep the engines and manually filter properties

- **Pros:** Small apparent change.
- **Cons:** Duplicates JSON Schema semantics and fails composition, conditional evaluation and future schema evolution.
- **Why rejected:** A filter cannot provide the declared dialect contract.

### Replace both language ecosystems or use Google's Go engine

- **Pros:** Could reduce dependence on older packages; Google's runtime has no third-party dependencies.
- **Cons:** Broadens the public compatibility problem. The tested Google API lacks the needed format enforcement and structured error adaptation.
- **Why rejected:** The existing Ajv modern class and Tekuri support the required mechanisms without implementing another validator layer.

### Do nothing

- **Pros:** Avoids exposing invalid historical producer output immediately.
- **Cons:** Both public validators continue accepting documents forbidden by the published schema.
- **Why rejected:** It leaves the reported defect in the contract boundary.

## Consequences

**What becomes easier:** Schema authors can rely on closed-object semantics and consumers can trust validation before storing or transforming documents.

**What becomes harder:** Invalid historical fixtures and producer output become visible. The Go adapter must normalize structured errors carefully and preserve intentionally narrow input checks.

**Risks and mitigation:** Cross-language format drift is controlled by the existing shared format table; closure drift by the new shared conformance table. Error adaptation is tested through the converter and CLI consumers. All bundled resources compile offline. Legacy-v2 stays separate.

## Implementation references

- [TypeScript validator](../hdf-validators/typescript/index.ts) and [Go validator](../hdf-validators/go/validators.go).
- Shared [schema conformance cases](../hdf-validators/testdata/shipped-schema-conformance-cases.json) and [format cases](../hdf-validators/testdata/shipped-format-cases.json) define the cross-language expectations.
- CLI and MCP preserve the public validation diagnostics; validation does not mutate or repair producer data.
