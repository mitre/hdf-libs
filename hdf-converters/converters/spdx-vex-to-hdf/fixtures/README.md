# SPDX VEX fixture provenance

## Inputs

### `sample.spdx.json` — real tool output

`sample.spdx.json` is **real output** produced by the
[bootlin/sbom-cve-check](https://github.com/bootlin/sbom-cve-check) tool
(v1.3.3, using `spdx-python-model` 0.0.6 → SPDX spec version 3.0.1). It was
generated entirely inside a container, offline, against a small curated local
CVE database. No host directory was mounted; all inputs and outputs lived at a
generic container path. The only network access during image build was the
initial `pip install`.

Exact command (run with `docker run --network none`):

```
sbom-cve-check \
  --ignore-default-config --disable-auto-updates \
  -c config.toml \
  --sbom-path input.spdx.json \
  --export-type spdx3 \
  --export-path out.spdx.json \
  -v
```

Local databases (all wired by absolute container paths in `config.toml`):

- `cve-db-cvelist` — a CVEList-V5-shaped git repo (1 record, pinned to a
  lightweight tag so no clone/fetch occurs)
- `openvex-file` — VEX status + justification
- `simple-annotations` — VEX status YAML annotations

Curated CVE data (all synthetic / generic — no real advisories, no host data).
Components: `example-lib` 1.0.0, `sample-utils` 2.3.1, `demo-daemon` 0.9.0
(vendor `examplevendor`). The four CVEs exercise every VEX status:

| CVE            | Component     | Status               | Extra                                                   |
| -------------- | ------------- | -------------------- | ------------------------------------------------------- |
| CVE-2024-30001 | example-lib   | affected             | + CVSS v3.1 9.8 CRITICAL                                |
| CVE-2024-30002 | example-lib   | not_affected         | justification `vulnerableCodeNotInExecutePath` + impact |
| CVE-2024-30003 | sample-utils  | fixed                | status notes                                            |
| CVE-2024-30004 | demo-daemon   | under_investigation  | status notes                                            |

Host-data leak check (username, `$HOME`, hostname, home-directory paths): clean.

**The fixture converts to exactly 2 overrides.** `affected` (30001) and
`under_investigation` (30004) are informational — `vex.ImportTargetFor` returns
ok=false for them, so they produce no override (matching the sibling
cyclonedx-vex / openvex converters). The remaining two:

- `CVE-2024-30002` (not_affected) → `falsePositive` + `passed` + justification
- `CVE-2024-30003` (fixed) → `poam` + `failed` + a pending milestone

### `no-actionable.spdx.json` — derived, for the empty→error path

Derived by trimming `sample.spdx.json` down to only the `affected` (CVE-30001)
and `under_investigation` (CVE-30004) statements and their supporting elements.
Both statuses are informational, so the document yields zero overrides and the
converter returns the "no actionable VEX statements" error. Used only for the
error-path test; it has no expected/ golden.

## CVSS coverage caveat

The committed `sample.spdx.json` carries exactly one CVSS assessment
relationship, and it is attached to **CVE-2024-30001, which is `affected` and
therefore skipped**. As a result the golden output exercises no
`StandaloneOverride.cvss` field. The CVSS→override mapping is still implemented
and is covered by a focused unit test in both `go/converter_test.go` and
`typescript/converter.test.ts` that uses a hand-built minimal SPDX-3 snippet in
which a `not_affected` CVE also carries a `CvssV3` relationship.

## Expected output

`fixtures/expected/sample.spdx.json.hdf.json` is the byte-parity golden asserted
by both the Go (`TestSnapshots`) and TypeScript (`snapshot.test.ts`) snapshot
suites under the shared normalization. Regenerate after intentional changes with:

```
go test ./converters/spdx-vex-to-hdf/go/... -run TestSnapshots -update
```
