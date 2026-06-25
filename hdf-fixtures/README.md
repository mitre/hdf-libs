# @mitre/hdf-fixtures

Shared real-world HDF reference fixtures for cross-package consumers
(parsers, validators, hdf-extension-graph, hdf-generators, legacyhdf-to-hdf
converter).

**Why this package exists.** Real-world test data was historically scattered
across converter packages, with no shared discovery mechanism. Packages that
needed it most (parsers, validators) couldn't see the wild-data samples that
already existed elsewhere. The class-of-bug fixed by `hdf-libs-2nm0` /
`hdf-libs-828d` (parsers rejecting real InSpec output with bare timestamps)
went undetected for exactly that reason — the bug-exhibiting file lived in
`hdf-extension-graph/test/fixtures/` and never reached the parser's tests.
See bead `hdf-libs-e95o` for the architecture rationale.

## Boundary rule

- **Converter fixtures stay where they are** unless multiple packages
  actively consume them. A converter's `fixtures/input/` and
  `fixtures/expected/` are the converter's *tested contract*.
- **Inclusion requires real multi-consumer usage** — at least two
  workspace packages actively load the file. "Might be useful someday" or
  "good for parity-test breadth" are not sufficient justification. When
  in doubt, leave the file where it is and migrate later once the second
  consumer materializes.
- **No duplicates.** If a fixture is going to be used by two packages,
  it lives here exactly once and both consumers import it. The original
  location's file gets deleted; consumer test code is updated.

## Layout

```
hdf-fixtures/
├── results/    — HDF Results docs
├── baseline/   — HDF Baseline docs
└── inspec/     — InSpec runner output (non-HDF)
```

The `inspec/` directory holds InSpec runner output (the input
format for `legacyhdf-to-hdf` — *not* HDF), kept here for cross-language
parser parity tests that verify both languages reject non-HDF inputs the
same way, AND for the legacyhdf-to-hdf converter's own tests (which load
them via the materialize-to-tmp-file helper in `converter_test.go`).

## Fixture provenance

All fixtures here are **real tool output**, never fabricated (per
CLAUDE.md's fixture-integrity rule).

### `results/` — HDF Results docs

| File | Source | Consumers |
|------|--------|-----------|
| `inspec-multilayered.json` | InSpec runner, multi-overlay scan | hdf-extension-graph TS + Go tests + hdf-parsers parser parity test. The bug-exhibiting fixture for `hdf-libs-2nm0` — bare timestamps that broke parsers before #83/#828d landed. Moved from `hdf-extension-graph/test/fixtures/multilayered-inspec.json`. |
| `minimal.json` | Hand-crafted minimal valid HDF Results doc | hdf-to-xml converter (TS + Go) + hdf-parsers integration test + hdf-validators integration test. The smallest schema-valid HDF Results document — single baseline, one passing requirement. Moved from `hdf-converters/converters/hdf-to-xml/fixtures/input/minimal.json`. |

### `baseline/` — HDF Baseline docs

| File | Source | Consumers |
|------|--------|-----------|
| `win2022-stig.json` | Windows Server 2022 STIG | hdf-generators TS + Go integration tests + hdf-parsers parser parity test. Was previously duplicated across `hdf-generators/go/testdata/` and `hdf-generators/test/fixtures/`. |

### `inspec/` — InSpec runner output (NOT HDF)

The input format for `legacyhdf-to-hdf` (which converts these to HDF). Kept
here because both that converter's tests AND the cross-language parser
parity test consume them. Each exercises a different timestamp format /
runner config.

| File | Notes | Consumers |
|------|-------|-----------|
| `ubi9-scan.json` | UBI9 container scan, `-05:00` offset | legacyhdf-to-hdf converter (TS + Go) + hdf-cli legacyhdf test + parser parity test |
| `container-scan.json` | Generic container scan, `-05:00` offset | same |
| `three-layer-overlay.json` | Three-layer overlay chain, `+00:00` offset | same |
| `wrapper.json` | InSpec wrapper-profile structure | legacyhdf-to-hdf converter (TS + Go) + hdf-parsers flatten integration test |
| `three-layer-rhel7.json` | Three-layer RHEL7 overlay (was `Three_Layer_RHEL7_Overlay_Example.json`) | hdf-parsers flatten integration test. Moved from `hdf-schema/test/fixtures/`. |

## Validation gate

`fixtures_gate_test.go` walks every HDF document in `results/` and
`baseline/` and validates against the appropriate schema (replaces the
per-converter snapshot coverage hdf-cli's
`converter_fixture_roundtrip_test.go` previously provided for these
specific files now that they live here). `inspec/*` is exempt — those
files are non-HDF by design.

## Usage

**TypeScript:**

```ts
import { results, baseline, inspec } from '@mitre/hdf-fixtures';

// On-disk path (for tools that need a file argument):
const path = results.inspecMultilayered.path;

// Or read the bytes directly:
const raw = results.inspecMultilayered.read();
```

**Go:**

```go
import fixtures "github.com/mitre/hdf-libs/hdf-fixtures"

data := fixtures.Results.InspecMultilayered // []byte, //go:embed'd at build
```

## When to add a new fixture

Add a fixture here when **two or more workspace packages already need it**
— not preemptively. If only one package needs it, keep it local to that
package; promote it here when a second consumer materializes.

Each new fixture must:
1. Come from a real tool run (no fabrication).
2. Be added to this README with provenance AND the list of consumers.
3. Be wired into both `src/index.ts` (TS) and `fixtures.go` (Go) so both
   sides have parallel access.
4. Have its original location deleted (no duplicates) and every consumer
   updated to import from here.
