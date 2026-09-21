---
name: fixtures
description: Add, replace, trim, or relocate a converter test fixture in hdf-converters and write its provenance record. Use when adding a file under a converter's fixtures/input or fixtures/expected, vendoring a format's schema, writing provenance.txt or provenance.json, adding a no-golden.txt entry, regenerating goldens with -update, shrinking an oversized fixture, deciding between a testhdf builder and a file, or deciding whether a fixture stays local or moves to @mitre/hdf-fixtures.
---

# Converter fixtures

CLAUDE.md's Fixture Integrity section is the policy. This is the procedure that applies it at the moment a fixture is being added, which is the only moment the answers are cheap. Three tests make the policy mechanical, so read them when in doubt: `hdf-converters/shared/go/schemaload_test.go` (every `fixtures/` directory has a provenance record; every vendored schema is listed with a hash that still matches), and the snapshot harnesses `hdf-converters/shared/go/testing.go` / `hdf-converters/shared/typescript/snapshot.ts` (every input has a golden or a recorded reason).

Work the steps in order. Each ends with something written down.

## 1. File, or builder?

The `testhdf` builders (`@mitre/hdf-schema/testhdf`; Go `hdf-schema/testhdf/go`) construct schema-valid HDF documents in the test itself. Prefer them when the case is a shape of an HDF document and the test asserts fields, not a whole golden. They keep the case next to the assertion and add nothing to the tree.

A file is warranted when any of these holds:

- The input is a source tool's format, not HDF. Builders make HDF; they cannot make a Nessus export.
- Go and TypeScript must run on identical bytes to share a golden.
- **The value under test does not survive serialization.** `JSON.stringify({impact: -0})` yields `{"impact":0}`, so a builder-generated input silently drops the negative zero and the test passes against the very bug it exists to catch. `hdf-to-ecs/fixtures/input/negzero.json` is the standing example; its provenance record explains the exception. Anything else that lives only in the text of the document (whitespace, key order, duplicate keys, a raw number token) is the same case.

If a builder expresses it, stop here and write the test.

## 2. Where the file comes from

Two tiers, and the record has to say which one applies (step 4), not just the commit message.

**Real** — prefer this always:

1. **Real output** from an actual run or a public CI pipeline. Say which tool, which run, when.
2. **A copy from a published example or sample set** — heimdall2, SAF CLI, or the format's own spec/example repository. Record the upstream path and whether the copy is byte-identical or what changed.

**Schema-confirmed** — the fallback, only where no real source exists for a case that has to be covered:

3. A document adapted from a real base, or built for the case, then validated against the format's official schema with the result recorded. It is **not real**; say so in the record. It proves the shape is one the format admits, nothing more. The `empty.*` no-findings input lives here: it is synthetic, it validates, and the harness treats it specially.

**Blocked**: a document nothing confirms — no run behind it, no schema it was checked against. Hand-assembling one out of real strings counts, because the assembly can be wrong even when every string in it is genuine. If the format publishes no schema and no real source exists, stop and ask, and record the coverage gap rather than filling it with something nothing vouches for.

## 3. Does the format publish a schema?

Look before deciding: the tool's own repository, its standards body, its documentation. Record the search either way.

**If it does**, vendor it and validate the fixtures against it:

- Put it beside what it validates: an importer's fixtures under `fixtures/` (`sarif-to-hdf/fixtures/sarif-schema-2.1.0.json`), an exporter's target format under `schemas/` (`hdf-to-ocsf/schemas/`). If the repo already vendors that schema elsewhere, reference it in `provenance.txt` instead of copying it (`xccdf-results-to-hdf` points at `hdf-to-xccdf/schemas/xccdf_1.2.xsd`).
- Vendor the version the fixtures declare. Deviating needs a measured argument written down (`hdf-to-ocsf/schemas/provenance.txt` shows what one looks like).
- Record it in `provenance.json` in that directory: `file`, `source` (the canonical URL), `sha256` of the bytes as vendored, `retrieved` (date). A file edited locally so it resolves offline adds `modified` and `upstream_sha256`. `schemaload_test.go` fails on a missing entry, a wrong hash, or an unlisted schema.
- Vendored files are `-text` in `.gitattributes` so they check out byte-exact and the hash holds on every platform. Under `schemas/` that is automatic; under `fixtures/` the name must match `*.xsd`, `*schema*.json`, or `*-report-format-*.json`, or add a line. The `eol=lf` rule for fixtures would otherwise rewrite the bytes the hash was taken from.
- Both sweeps compile every vendored JSON Schema. If Go's `gojsonschema` cannot (regex syntax), pin it in `goCannotCompile` in `schemaload_test.go` with the reason; the TypeScript sweep handles draft-04 by itself.
- Validate every input against it and write the result in `provenance.txt` with the validator and the date. Where fixtures were authored or adapted here, add a test that keeps them valid (`gitlab-to-hdf/go/schema_validation_test.go` is the pattern). A fixture that fails the schema it declares is recorded as a defect, not silently kept.

**If it does not**, `provenance.txt` says what was searched and when (`nessus-to-hdf`: "no XSD was located in Tenable's documentation (2026-09-20)").

## 4. The provenance record

Every `fixtures/` directory carries `provenance.txt`; one that vendors a schema carries `provenance.json` as well. The guard test only checks that the file exists and is non-empty. Its content is trusted by construction, which is why it has to be true.

`provenance.txt` has these sections, in this order:

```
# <converter> fixtures — provenance
Recorded <date>. <Which upstreams were checked, at which commits.>

## `input/`
### `<file>`
<Origin: byte-identical to <upstream path> | derived from <upstream path>, trimmed <how> on <date> | real output of <tool> <run> | adapted from <base>, edits: ... | synthetic by construction (empty.*) | origin not established by those searches.>

## `expected/`
Generated by this repository's converters, not sourced. Regenerate with
`go test ./converters/<name>/... -run TestSnapshots -update`.

## Tool and version, read from the file itself (<date>)
- `<file>` — <format and version the file declares>; <producer field>: <tool> <version>.

## Schema
<Where it is vendored and recorded, or what was searched and not found. Validation result, validator, date.>
```

Rules for the "Tool and version" section, which is the part most often wrong:

- A version is what the fixture says about itself, read from the field the format defines for it (`runs[0].tool.driver.version`, `TestResult/@test-system`, `scan.scanner.version`). Name the field.
- If the format carries no producer version, write that it is not determinable from file content. Do not supply a plausible one. `nessus-to-hdf` records exactly this for all three files.
- The filename is not evidence. `gitleaks_7.5.0.sarif` declares v7.4.0 inside; the record says both and that the file is authoritative.
- An origin you could not establish is written as "not established by those searches", naming the searches. Not "most likely authored here".

`provenance.txt` is a statement of fact about the files beside it. Design rationale goes in the commit message; documentation goes under `site/docs/`.

## 5. Size

The guideline is about 1 MB per file (`.gitattributes` header). The audit found 14 files over it, and every one that stayed did so because a test asserts the whole document (`oscal-to-hdf`'s catalogs assert the full control count; `legacyhdf-to-hdf`'s goldens come from the shared corpus and cannot be trimmed from there). Before keeping a big file, check whether a test needs the volume. If none does, trim to a covering subset. The method the repo has used:

1. **Profile the output on the full file.** Convert it and list the distinct shapes it produces: (status, severity) pairs, tag keys, description labels, ecosystems, requirement-key forms, whatever the converter branches on.
2. **Keep N per shape**, first in document order (two has been enough), plus every item a test pins by id or timestamp. Keep only the groups, rules, hosts, or profile selects those items reference, so the document stays internally consistent. Remove; never edit text. What remains is still verbatim upstream.
3. **Regenerate the goldens** with `-update`.
4. **Read the diff.** Every kept requirement must be byte-identical to its previous golden entry; only the volume changes. If a kept entry changed, the trim broke a reference.
5. **Record the trim** in `provenance.txt`: the rule used, the count before and after, the date, and that the full file is in history before that date.

A test that scans every fixture in the tree for corpus size (an encoder collision sweep, a tag-key walk) makes every fixture's size load-bearing for a converter that does not own it. Give it one representative per shape in a shared table instead; `hdf-converters/shared/xccdf-group-id-cases.json` and `xml-element-name-cases.json` are the two that replaced fixture walks.

## 6. Goldens

An importer's golden is `fixtures/expected/<input filename>.hdf.json`, asserted by both languages through the shared harness (`converter_test.go` and `snapshot.test.ts`) with the same volatile-field masking. Any other name in `expected/` is asserted by nothing and fails the suite.

- Generate and regenerate with `go test ./converters/<name>/... -run TestSnapshots -update`. Read the diff before committing it; `-update` accepts whatever the converter produced, including a regression.
- `startTime` is masked only for inputs whose source carries no scan time (the harness's `maskStartTime` list). If the source has a time, the golden asserts it; masking a derivable `startTime` hides a wrong-time bug.
- An input that legitimately has no golden gets a line in `fixtures/no-golden.txt`: `<input> — <reason>`, the reason naming the test that consumes the file. The harness fails on a line with no reason, a line naming an input that is not there, and a line naming an input that has a golden, so the list cannot rot. `empty.*` needs no line.
- Exporters (`hdf-to-*`) keep goldens under their own names (`negzero.ndjson`, `minimal.oscal-sar.json`) and assert them in converter-specific tests; the `<input>.hdf.json` rule and `no-golden.txt` belong to the importer harness.

## 7. Local, or shared?

Default is local: the converter's `fixtures/` directory is its tested contract. Promote to `@mitre/hdf-fixtures` only when a second workspace *package* actively loads the same file. Then move it (`hdf-fixtures/<results|baseline|amendments|inspec>/`), wire it into `src/index.ts` and `fixtures.go`, add it to the `fixtures_gate_test.go` group map, list source and consumers in `hdf-fixtures/README.md`, and delete the original. A converter loads a shared input through the harness's input resolver (`legacyhdf-to-hdf` does).

Several converters inside one package sharing an input is not what the promotion rule addresses. The audit kept the SIEM exporters' copies in place and pinned them byte-identical in `hdf-converters/shared/go/siem_corpus_test.go`. A copy without a pin is silent drift waiting to happen: either add the file to that pin table or do not copy it.

## Do not

- Invent a document, or "sample" one from memory of the format.
- Hand-edit a real fixture to make a test pass. Trim by removal, or adapt from a real base and re-validate.
- Guess a tool version, or take it from the filename.
- Pad a corpus for breadth. One file per shape the converter branches on; a second file that produces the same output shapes proves nothing new.
- Duplicate a file without a pin, or promote one on "might be useful someday".
- Vendor a schema without `provenance.json`, or under a name the `-text` rule does not cover.
- Commit a golden you regenerated without reading its diff.
- Leave the origin, version, or validation result only in the commit message. The record beside the file is what the next reader finds.

## Done when

```bash
cd hdf-converters
go test ./shared/... -run 'TestSchemaLoad'            # provenance present, hashes hold, schemas compile
go test ./converters/<name>/...                        # goldens and coverage, Go
pnpm test:ts -- converters/<name>                      # goldens and coverage, TS
```

and `provenance.txt` answers, for the new file: where it came from, what tool and version it declares, whether it validates against the format's schema, and how it was trimmed if it was.
