# SARIF Round-Trip Fidelity

HDF converts [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/sarif-v2.1.0-errata01-os-complete.html)
in both directions — `sarif-to-hdf` imports it and `hdf-to-sarif` exports it — so a
document can make the trip SARIF → HDF → SARIF, or HDF → SARIF → HDF.

Neither trip returns the original bytes, and neither is meant to. Crossing a format
boundary means re-expressing a document in a model that draws its lines somewhere
else: SARIF scopes severity and position to each result, HDF scopes them to the
requirement a result belongs to. This guide states exactly what each direction
preserves, what it does not, and why — so the answer to "where did my field go" is
written down rather than discovered.

Each table below says what happens to a field and whether a test holds it to that.
The "asserted" column is the honest part: a field marked no is carried by the
mechanism but has no test of its own, usually because no committed fixture exercises
it.

## SARIF → HDF → SARIF

| What | Outcome | Asserted |
|---|---|---|
| Rule identity, for every rule a result references | preserved | both languages |
| Result count per rule | preserved | both |
| Each result's `kind` | preserved | both |
| Each result's message text, where one was present | preserved | both |
| Each result's resolved level (§3.27.10) | preserved | both |
| First location: artifact URI and `startLine` | preserved | both |
| Region integer members (`startColumn`, `endLine`, `endColumn`) | preserved | no |
| `region.snippet` | preserved | both |
| `fingerprints` and `partialFingerprints` | preserved | both |
| Each accepted suppression's justification and kind | preserved | both |
| Every property bag, on the object it came from | preserved | both |
| `invocations[].executionSuccessful`, where the run declared failure | becomes a requirement, not rebuilt as an invocation | both |
| Rules declared but referenced by no result | dropped | — |
| `taxonomies`, rule `relationships`, `relatedLocations`, driver `informationUri` | dropped | — |
| `codeFlows`, `threadFlows`, `graphs`, `stacks` | dropped | — |
| `fixes` (`artifactChanges`/`replacements`) | dropped | — |
| Localization, binary addressing, `webRequest`/`webResponse` | dropped | — |

A results document represents findings, not a scanner's rule catalog, which is why a
tool shipping 150 rule definitions and reporting against 13 round-trips as 13. The
dropped rows are structures HDF has no model for; they are not carried and are not
claimed to be recoverable.

`executionSuccessful` is the one row that is neither. A run that declares
`executionSuccessful: false` gains a synthesized requirement on import, with id
`<driver>-run-failed`, title `Run failed` and one result at status `error`. Its
`codeDesc` names the failure and appends the invocation's exit code, signal name and
exit description where the run supplied any — `failed-run.sarif` supplies none, so its
text is just `eslint reported that its run did not complete successfully.`

This is how HDF already expresses a partly-failed evaluation: a set of N results where
x < N carry `error`, the way InSpec does, where a control that fails to execute yields
`error` without scrubbing the run. So a failed run that *did* report findings keeps
every one of them exactly as reported — `spotbugs.sarif`'s 56 findings group into 9
requirements and none is restyled — and gains a tenth requirement for the run's own
failure. What such a run tells you is that its coverage was incomplete, not that what it
found is wrong. A run that reported nothing gets the `error` requirement in place of
whichever placeholder it would otherwise have received: the passing no-findings one when
`results` was `[]`, and the `notReviewed` not-analyzed one when `results` was absent or
null.

None of this is written to the baseline. A baseline is a policy document — what was
required — and it must not change in response to the results attached to it, or the same
policy scanned twice would produce two different baselines.

The requirement survives the trip back out, as a SARIF result carrying its
`<driver>-run-failed` rule id. That rule is the converter's own rather than the tool's,
so round-tripping a failed run yields one rule more than it started with. That is the
only rule either direction adds, and the round-trip tests name it per fixture, so an
addition nobody expected still fails them. The `invocations` array is not rebuilt:
the exporter has no invocation to put back, and synthesizing one would assert structure
the document never carried.

## HDF → SARIF → HDF

| What | Outcome | Asserted |
|---|---|---|
| Requirement identity and title | preserved | both |
| Descriptions by label, except `default` | preserved | both |
| Per-result status | preserved | both |
| `results[].resource`, `results[].resourceId`, `results[].startTime` | restored from the bag; a timestamp returns as the same instant in canonical spelling, so `.100Z` reads back `.1Z` in both languages | both |
| `cvss`, `epss`, `refs`, `affectedPackages`, `code`, `effectiveChecksum` | restored from the bag; a member the schema permits but this build does not declare is dropped by Go and kept by TypeScript | both |
| `verificationMethod` | restored from the bag | both |
| `statusOverrides`: `appliedBy`, `appliedAt`, `expiresAt` | restored from the bag | both |
| `tags.cwe`, and the NIST and CCI tags derived from it | preserved | both |
| `evidence`, `externalReferences` | restored from the bag | both |
| `kev`, `controlType`, `applicability`, `poams` | restored from the bag | no |
| `impact`, where the requirement carries CVSS | recomputed | both |
| `descriptions[default]` | derived from the SARIF | both |
| Per-result `codeDesc` | derived from the SARIF | both |
| `statusOverrides`: `type`, `status`, `reason` | derived from the suppression | no |
| `results[].message` | relocated, not lost | no |
| `severity` | added where the source had none | no |
| Baseline `name` | derived from the driver | both |
| Baseline `summary`, `description`, `maintainer`, `copyright`, `copyrightEmail`, `license`, `status`, `statusMessage`, `parentBaseline`, `labels`, `supports`, `depends`, `groups`, `inputs`, `externalReferences` | restored from the bag | both |
| Baseline `title` and `version` | restored from the bag; invented when it carries none | both |
| Baseline `resultsChecksum` | recomputed over the results present | no |
| Baseline `extensions` (its own passthrough) | restored from the bag | both |
| Baseline `integrity` and `originalChecksum` | dropped, deliberately | both |
| Document `generator` | re-stamped with the converter that produced the new file | both |
| A requirement's `error` status | degrades to `failed` | both |

Seven of those need the reason stated rather than the outcome alone.

- **`impact`** is published through SARIF's `security-severity` convention, which is a
  CVSS base score, and recomputed from it on the way back. A requirement whose impact
  came from a severity band rather than from CVSS returns with the impact the score
  implies. Where no CVSS is present nothing is published and impact survives.
- **Per-result `codeDesc`** is rebuilt from the result's location rather than
  restored. HDF's `Source_Location` is `{ref, line}` and closed, so every result of a
  requirement reports at the first one's location, and a `codeDesc` that is not
  positional at all — a package coordinate, say — is replaced rather than preserved.
- **`results[].message`** survives as data but moves. SARIF scopes a message to the
  result and expresses it as `result.message`, so the import side derives from that
  field rather than restoring from the bag: the first result's text reaches the
  requirement's `descriptions[default]`, and every result's text is addressable in
  `tags["sarif-results"][i].message`. What changes is placement.
- **Baseline `title` and `version`** are the only *baseline* fields restored over what
  the import derived, rather than only where it derived nothing. Three requirement-level
  fields behave the same way — `results[].startTime`, `verificationMethod`, and a status
  override's `appliedBy`/`appliedAt`/`expiresAt`. In each case what the import would
  otherwise write is the conversion time or a constant, not something read out of the
  SARIF, so a carried value outranks it. With no baseline to describe, the
  import writes the SARIF format's own name and spec version — `Static Analysis Results
  Interchange Format` and `2.1.0` — so where the bag carries the real ones, those are
  not a neutral default but a false claim about the policy.
- **A carried member this build does not declare** rides along without costing the value
  it is attached to. A few carried types are open in the schema — `Reference` is an
  `anyOf` with no `additionalProperties` — so a `refs` entry may legally carry more than
  `ref`, `url` and `uri`. The array and its declared members restore either way; whether
  the extra member itself survives differs by language, because Go decodes into a typed
  struct and drops it while TypeScript assigns the carried value verbatim and keeps it.
  Refusing the whole value over such a member would turn a partial restore into a total
  loss, and would do it again every time the schema gains a field.
- **Baseline `integrity` and `originalChecksum`** are refused even though the bag
  carries them and SARIF cannot express them. Both are tamper-evidence, and a round trip
  is a transformation of the thing they attest to: `Integrity` is defined over "the HDF
  file" and carries an optional `signature` and `signedBy`, so restoring it would
  re-attach a signature to a document nobody signed. `originalChecksum` attests to
  baseline requirements that the round trip has already changed.
- **`generator`** is refused for a different reason: it names the converter that
  produced *this* file, and `sarif-to-hdf` produced it. A document that began as
  `grype-to-hdf` output comes back stamped `sarif-to-hdf`, which is accurate rather than
  lossy — the original stays readable in the carried block.

## Why the passthrough block is not the general answer

`hdf-to-sarif` writes the HDF data SARIF cannot express into a reserved `hdf`
property bag, and `extensions.passthrough.sarif` carries the SARIF property bags an
HDF document retained. It is reasonable to ask why the import side does not simply
read all of it back and return the original document.

Because that block is only there when HDF Libs produced the document. It lives in
`extensions.passthrough`, which the schema leaves deliberately unconstrained — HDF
neither reads nor interprets what is in it, and no shape is imposed. It is therefore
untrusted input: a producer that wrote one could assert an `impact` the document's
own findings do not support. So the import side reads it for one purpose only — to
recover fields SARIF has no way to express — and never to override a value SARIF
does express. That is why `impact` does not round-trip even though the bag contains
it.

**This makes the two cases asymmetric, and it is worth stating plainly.** A SARIF
document this project exported round-trips more faithfully than one from a
third-party scanner, because only ours carries the bag. A third-party document is
mapped from its content alone: everything in "What survives SARIF → HDF → SARIF"
still holds, but the HDF-side fields in the list above have nothing to be recovered
from, because the producer never had them to write. If a field in the second list
matters to you and your input is third-party SARIF, the format cannot carry it and
no amount of conversion will invent it.

## Verifying it

The contract is executable rather than documentary:

- `hdf-converters/converters/hdf-to-sarif/go/roundtrip_test.go` and
  `typescript/roundtrip.test.ts` run both directions over committed fixtures and
  assert the survives lists and the expected-loss sets. The tables above mark which rows are
  asserted and which are carried without a test of their own.
- `hdf-converters/converters/sarif-to-hdf/fixtures/input/hdf-roundtrip.sarif` is the
  one committed SARIF input that carries an `hdf` bag — this project's own exporter
  output. It exists so the recovery path is held to account by the Go/TypeScript
  parity goldens; without it, a language missing that path would pass every other
  fixture.
