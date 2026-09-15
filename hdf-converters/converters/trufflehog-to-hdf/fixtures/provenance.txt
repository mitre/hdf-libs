# TruffleHog fixtures — provenance

Fixtures for the `trufflehog-to-hdf` converter. TruffleHog's `--json` flag emits
**newline-delimited JSON (NDJSON)** — one finding object per line, with no array
wrapper — not a single JSON document. The converter accepts a JSON array, a
single JSON object, or NDJSON.

TruffleHog is **exit-code-first**: a clean scan (no secrets) writes *nothing* to
stdout and exits 0; the human-readable "finished scanning" summary goes to
stderr. There is no "empty report" — a clean run produces zero bytes. The
converter therefore treats empty, whitespace-only, and `[]` input alike as a
valid **zero-findings** signal, synthesizing a single passed
`trufflehog-no-findings` requirement rather than erroring.

## input/

### `minimal.json`
Single-object TruffleHog finding (one AWS credential). Exercises the
single-object parse path and one detector group → one requirement.

### `multi-detector.json`
JSON-array input with findings across multiple detectors. Exercises grouping by
`DetectorName + DecoderName` (findings sharing a detector collapse into one
requirement with many results).

### `ndjson-input.ndjson`
Native TruffleHog `--json` NDJSON output. Carries no git commit timestamp, so
the converter synthesizes `startTime` — hence this fixture's `startTime` is
masked in the snapshot goldens.

### `empty.json`
The literal empty JSON array `[]` (3 bytes). This is the shape a consumer gets
when they slurp NDJSON through `jq -s '.'` over an empty stream — the common
ecosystem bridge for "no findings." Asserts the zero-findings path in unit
tests.

### `empty-stdout.json`
A **genuinely empty (0-byte)** file — the exact shape a clean TruffleHog scan
produces on stdout. Captured from a real run: **TruffleHog v3.95.9**, `git`
source, `--json`, scanning a freshly-initialized repository containing only a
non-secret `README.md` (one commit). stdout was 0 bytes; exit code 0; the
`"finished scanning" … "verified_secrets":0,"unverified_secrets":0` summary was
emitted on stderr. This is the input the `jq -s` bridge is *not* applied to, and
the case the converter previously rejected. Its synthesized `startTime` is
masked in the snapshot goldens.

## Why both `empty.json` and `empty-stdout.json`?
They are the two real shapes of "a clean scan" a user can hand the converter:
`[]` (jq-slurped) and 0 bytes (raw stdout). Both must produce byte-identical
zero-findings HDF (modulo the volatile `resultsChecksum = sha256(input)` and the
masked timestamps). Keeping both guards against a future regression that handles
one shape but not the other.
