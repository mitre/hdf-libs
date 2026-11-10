# ADR-0018: Enforce the declared schema dialect in HDF validators

**Date:** 2026-11-07
**Status:** accepted for implementation on 2026-11-07; independent acceptance review required
**Deciders:** HDF maintainers

## Context

The modern HDF schemas declare JSON Schema 2020-12, while the shipped TypeScript validator instantiates draft-07 Ajv and the Go validator uses gojsonschema. Both accept undeclared properties at closed root and nested scopes. This makes the CLI and library validation result weaker than the schema contract. The work is tracked by [issue #523](https://github.com/mitre/hdf-libs/issues/523) and the existing validator epic, `hdf-libs-fdw4v`.

The public validation result is consumed by converters, the CLI and MCP. Replacing an engine must preserve their contracts, including dotted Go field paths, the `invalid_type` keyword, format names and offending values. Legacy HDF v2 uses a separate schema and must keep its existing behavior.

## Decision

Use the existing Ajv dependency's `Ajv2020` class for modern TypeScript HDF validation and `github.com/santhosh-tekuri/jsonschema/v6` v6.0.3 for modern Go validation. Retain the existing Ajv instance and gojsonschema path for legacy v2. Preserve `RegisterRFCFormatCheckers`, which other Go packages call.

Do not change schema content, consumer input policy, package versions or dependency versions as part of selecting the correct dialect. The Go dependency is already used by the converter module, but promoting it into the validator module still requires a direct dependency declaration and module checks.

### Compatibility requirements

1. Compile all eight modern bundled schemas offline. Missing references must produce a useful error, never trigger an HTTP fetch.
2. Keep lazy schema compilation and `SetSchemaDir` behavior, including cache reset and error propagation.
3. Opt into Go format assertions and register the existing UUID/date-time semantics with the modern engine. Preserve the TypeScript date-time override. Run the shared format table in both languages.
4. Adapt structured Go errors into the existing `ValidationError`: dotted `Field`, `invalid_type` for type violations, `format` plus `Format` for format violations, and the offending `Value`. New closure failures must identify the actual property. Do not parse human-readable error strings to reconstruct the contract.
5. Keep the converters' existing narrow input checks. `rejectWronglyTypedFields` deliberately rejects non-null type violations and date-time format violations. Changing that policy is a separate decision; do not add new keyword filtering to hide stricter output validation failures.
6. Accept schema-declared open scopes such as `extensions.passthrough` without mutating input. Do not strip unknown properties, substitute defaults or weaken schema closure.

### Recorded implementation decision

The owner instructed implementation using project-tdd crosscheck/standard after reviewing the proposed engine choice and complete PR scope. For this fix, retain the installed Ajv and ajv-formats versions, select Tekuri v6.0.3 for modern Go validation, and retain the older engines only for existing legacy behavior and exported format-registration compatibility. This is a bounded keep decision for the dependencies flagged stale by the activity rule, not an assertion that they are current or that age alone implies a vulnerability. Do not broaden this change into a dependency replacement or public input-policy change.

## Prior Art

Versions and license files were inspected on 2026-11-07. MIT and Apache-2.0 are not on `.github/workflows/dependency-review.yml`'s deny list. No source is vendored.

| Candidate | Version and license | Verdict | Reason |
|---|---|---|---|
| [Ajv](https://github.com/ajv-validator/ajv/tree/v8.18.0) | 8.18.0, MIT | ADOPT, retain existing version | Already installed; modern class enforces closure while retaining existing integration and format hooks. |
| [ajv-formats](https://github.com/ajv-validator/ajv-formats/tree/v3.0.1) | 3.0.1, MIT | ADOPT, retain existing version | Existing format behavior is a cross-language compatibility contract. |
| [santhosh-tekuri/jsonschema](https://github.com/santhosh-tekuri/jsonschema/tree/v6.0.3) | 6.0.3, Apache-2.0 | ADOPT | Compiles every HDF bundle offline; structured error tree, instance tokens, assertion controls and custom formats. |
| [google/jsonschema-go](https://github.com/google/jsonschema-go/tree/v0.4.3) | 0.4.3, MIT | REJECT for this adapter | Compiles the bundles and enforces closure, but its tested API does not assert date-time format and its returned errors do not provide the structured field/keyword/value contract this adapter needs. |
| [gojsonschema](https://github.com/xeipuuv/gojsonschema/tree/v1.2.0) | 1.2.0, Apache-2.0 | REJECT for v3; retain for legacy | Demonstrably ignores modern closure; existing legacy validation and exported format registration still depend on it. |

| Project | Latest release date | Latest merged PR found | Default-branch commit | Archived | Health |
|---|---|---|---|---|---|
| Ajv | 2026-04-24 | 2026-04-24 | 2026-04-24 | No | STALE |
| ajv-formats | 2021-08-14 (GitHub release API) | 2021-11-07 | 2024-04-05 | No | STALE |
| santhosh-tekuri/jsonschema | 2026-08-06 | 2026-11-06 | 2026-11-06 | No | Active |
| google/jsonschema-go | 2026-04-27 | 2026-05-22 | 2026-05-22 | No | Activity within six months |
| gojsonschema | 2019-10-15 | 2020-10-27 | 2020-10-27 | No | STALE |

Health uses repository metadata, latest-release and commit endpoints, and recently updated closed PRs with non-null merge dates. The PR lookup is bounded, not a full-history audit. GitHub release dates are not npm publication dates; ajv-formats 3.0.1 was separately confirmed at its source tag. License inspection covers the exact versions proposed here; no upgrade or relicensing transition is proposed.

Dependency footprint: no npm dependency changes. The Go validator would gain one direct requirement on Tekuri v6.0.3, already in the workspace graph. Its module lists `golang.org/x/text` and test-only `github.com/dlclark/regexp2`; production dependency delta must be verified with module tooling rather than inferred from the require list. Google's module lists test-only `go-cmp` and describes its runtime as standard-library-only. The existing legacy dependency remains deliberate.

## Executable findings

Research ran against upstream main commit `a9a5901d4cb3473dcdfc2a50efcdcecc098b7955`, whose bundled schema IDs identify v3.8.0. This is distinct from the published 3.7.2-package reproduction attached to #523. Inputs below are clones of the existing `hdf-fixtures/results/minimal.json`, with one named property added per negative case.

| Case | Current TypeScript | Ajv2020 | Current Go | Tekuri | Google |
|---|---|---|---|---|---|
| Unchanged minimal results | Accept | Accept | Accept | Accept | Accept |
| Undeclared root property | Accept (defect) | Reject | Accept (defect) | Reject | Reject |
| Undeclared baseline property | Accept (defect) | Reject | Accept (defect) | Reject | Reject |
| Undeclared requirement property | Accept (defect) | Reject | Accept (defect) | Reject | Reject |
| Arbitrary property inside extensions.passthrough | Accept | Accept | Accept | Accept | Accept |

Both Go candidates compile all eight committed bundles with external loading unavailable. Tekuri reports an instance location ending in the actual undeclared member. Google's error identifies the schema traversal instead. A separate format probe using Google's resolved draft-2020-12 schema accepts `not-a-timestamp` against `format: date-time`.

The Tekuri tagged README reports JSON-Schema-Test-Suite support for the relevant drafts and documents format assertion and custom format APIs. This research exercised HDF bundles and the cases above; it did not independently rerun the full upstream conformance suite. Full HDF shared-table coverage belongs to the implementation children.

The source inventory finds 78 `unevaluatedProperties` keyword occurrences. It finds no `dependentRequired`, `dependentSchemas`, `prefixItems`, `unevaluatedItems`, `$dynamicRef`, `$dynamicAnchor`, `minContains` or `maxContains` in active source schemas after excluding example/default data. The older epic's `dependentRequired` counts describe an earlier revision. The implementation table must cover keywords actually used and composition/conditional branches, without inventing current HDF fields to exercise absent keywords.

### Baseline and corpus findings

The unchanged validator passes all 142 TypeScript tests, the Go validator package tests and TypeScript type checking. Shared fixtures must be built before the TypeScript integration suite; a missing fixture-package build was corrected during setup.

Four of five shared results documents pass both current TypeScript and Ajv2020 unchanged: `minimal.json`, `duplicate-baselines.json`, `merge-grype.json` and `merge-zap.json`. The 7,103,929-byte `inspec-multilayered.json` fails both raw because of noncanonical timestamps. After the public timestamp normalization used by consumers, current TypeScript accepts it but Ajv2020 rejects its undeclared root `targets` member. This is a concrete rollout finding, not permission to delete data or relax the schema. The integration child must trace and correct the historical fixture with provenance intact.

### Timing limits

#### Preliminary probes (2026-11-07)

Five warm TypeScript validation iterations of the largest document, after public timestamp normalization and outside parsing, averaged approximately 0.96 ms for the current engine and 1.10 ms for Ajv2020 in this local probe. These are different validity outcomes because of `targets`; they are not a successful-valid-document performance comparison and do not establish a production budget. Go timings with parsing included for each engine, excluding schema compilation and timestamp normalization: current 31.78 ms (valid), Tekuri 35.24 ms (invalid), Google 39.43 ms (invalid). These also have different verdicts and establish no valid-document regression bound. No performance threshold has been accepted from this preliminary probe. Before rollout, measure the largest valid shared fixture and a corrected large real document with comparable verdicts, compilation accounted for separately.

#### Comparable-verdict measurement (2026-11-10)

The later Go comparison uses identical, corrected and timestamp-normalized bytes derived from `hdf-fixtures/results/inspec-multilayered.json`: 7,101,796 bytes, SHA-256 `8eb7286407ec5c85f0d5b20c1ebf1b2ea6c0bc10a780455a29091f368365bd55`. Both engines accept that document. The modern measurement is pinned to commit `0aa5a63eb55d8f8a71214052a1d6ed8af64ca365`; subsequent diagnostic-summary changes affect invalid results, not this valid-document path.

| Measurement | Original gojsonschema validator | Modern Tekuri validator | Ratio |
|---|---:|---:|---:|
| First validation after schema-cache reset | 37.192 ms | 47.542 ms | 1.278× |
| Mean of ten subsequent validations | 31.6423 ms | 40.5553 ms | 1.282× |

Both measurements include JSON parsing. The first validation also includes schema compilation; the subsequent validations reuse compiled schemas. File reading and timestamp normalization occur outside the timed sections. This is a local comparative measurement, not a production latency guarantee or a concurrent-load benchmark. It supersedes the preliminary, unequal-verdict Go comparison for assessing this rollout.

The owner accepted this measured rollout tradeoff on 2026-11-10: approximately 9 ms additional warm validation time (31.6423 ms to 40.5553 ms, about 28%) for correct JSON Schema 2020-12 enforcement. This acceptance applies to the comparison above, not a general latency guarantee or permission for future regressions. The Go implementation card's ten-times-baseline escalation threshold is not an agreed performance budget.

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

**Risks and mitigation:** Cross-language format drift is controlled by the existing shared format table; closure drift by the new shared conformance table. Error adaptation is tested through the converter and CLI consumers. All bundled resources compile offline. Legacy-v2 stays separate. The stricter validator may expose changes covered by [PR #518](https://github.com/mitre/hdf-libs/pull/518); test its immutable snapshot in a separate worktree and record actual conflicts without modifying that branch.

## Implementation Plan

### Quality standards and shared abstractions

Use TDD for behavior changes, stage failing tests before implementation, preserve >90% coverage for changed code and add no lint suppressions. Shared JSON documents and expected verdicts are consumed by both language suites; tests exercise public HDF validators, not copies of third-party internals. Test format behavior, legacy isolation, malformed input, offline loading, cache reset, type errors, composed closed scopes and permitted open scopes. Live checks use built TypeScript output, the Go CLI and MCP. Independent acceptance review precedes every card close.

### Phases

| Child | Deliverable | Dependency |
|---|---|---|
| `hdf-libs-fdw4v.1` | This decision, engine probes and compatibility contract | None; implementation authorized |
| `hdf-libs-fdw4v.2` | Shared conformance corpus and TypeScript modern-dialect enforcement | Accepted decision and independent review of .1 |
| `hdf-libs-fdw4v.3` | Go modern engine and compatible error adapter using the same corpus | .2 |
| `hdf-libs-fdw4v.4` | Consumer fixes, corpus corrections, documentation and PR evidence including #518 integration | .3 |

The Beads child cards contain exact file scopes, acceptance criteria and verification commands. Amend their file inventories before changing newly identified producer/fixture paths. Keep one PR branch for this concern. Git commits, pushes and publication remain with the user and maintainers.

### Verification strategy

Build utilities, schemas, fixtures and validators before the baseline package tests. Run each new regression red, then green after implementation; preserve the existing shared format and legacy suites. Run full workspace TS build/typecheck/tests/lint and Go module tests/vet/lint during integration. Inspect real CLI human/JSON errors and MCP output, and validate a locally packed TypeScript artifact outside workspace resolution. Compare all approved corpus verdicts across languages and verify errors retain the property and line location that callers use.
