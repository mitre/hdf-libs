# hdf-to-ocsf fixtures — provenance

## `input/negzero.json`

**Adapted** from this repository's `hdf-to-ocsf/fixtures/input/scalartag.json`,
itself a Nessus-derived HDF Results document. Structure, tool identity, component
and CVE are carried over unchanged; only the two numeric fields under test were
altered — `impact` and `cvss[0].baseScore` are both set to the raw JSON token
`-0`, and the result status was changed to match a zero-impact finding.

**Schema-validated**, as the fixture policy requires for adapted input. Proof:

```
$ hdf validate converters/hdf-to-ocsf/fixtures/input/negzero.json
✓ ... is a valid HDF results file
```

`-0` satisfies the schema's `minimum: 0` on `impact` because JSON Schema
compares numbers mathematically and `-0 == 0`; no keyword can reject it while
accepting `0`.

**Why this is a file rather than test-constructed input.** The negative zero must
reach the converter as raw JSON *text*. Building the document with the testhdf
builders and serializing it destroys the distinction — `JSON.stringify({impact: -0})`
yields `{"impact":0}` — so a test-generated input would pass against the very
bug this fixture exists to catch. The file is also the channel that lets the Go
golden and the TypeScript byte-identity check run on identical input.

## Other fixtures in this directory

`compliance`, `cve`, `override`, `riskadjust` and any siblings predate the
per-directory provenance convention and are not yet documented here.
