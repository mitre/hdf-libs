# Candidate corpus provenance

No candidate corpus is vendored here. This package carries the **contract** and
the **validator**; an operator supplies the corpus itself. This record covers
the artifacts the contract was checked against, so a later reader can tell what
the rules were written to admit — and what they were written to refuse.

## Artifacts retrieved

Retrieved 2026-10-28 from `risk-sentinel/kics-control-mapping` (public), at
branch `main`.

| Upstream path | Bytes as retrieved | sha256 as retrieved |
|---|---|---|
| `candidates/kics-control-candidates.v1.json` | 3022222 | `c7efb76e8b30b0480b52ec3df603c45028e9f98a20b40ac1c7aa9ba66e34c389` |
| `data/rev5-corpus.json` | 1630129 | `d13d848b619a427f77e07b9a2b49dad79a3b8987aba8e5860a657eddd0f9d018` |

Neither file is committed to this repo. The hashes pin what was measured below;
they are not a claim that these are the corpus a future ingest will read.

## What the candidate artifact contains

1,811 scanner checks, 9,055 candidate rows, 744 distinct control ids. Candidates
are capped at five per check. Scores are normalised per check, so every rank-1
candidate scores 1.0 and scores are not comparable across checks — upstream's
own README calls its quality metric circular.

Control ids arrive at three granularities, which is why the contract admits all
three: controls (`SA-15`), enhancements written with a dot (`SA-10.4`, 6,502
rows), and statement sub-parts (`SA-15 a`, `SA-4.3 (a)`, 1,764 rows). The CWE
table this epic replaces expresses none of the latter two.

## Findings that shaped the contract

Measured by running this repo's own `nist.NormalizeID` and
`nist.NistExistsForRevision` over every candidate id.

**Enhancement spelling.** Upstream writes `SA-10.4`; NIST writes `SA-10 (4)`.
As retrieved, only 28.2% of candidate rows (2,553 of 9,055) normalize at all.
After translating a dot before digits to NIST's parenthesised form, 100%
normalize. NIST uses no dots in control numbers, so the substitution is
unambiguous, and the contract performs it on ingest.

**Mixed catalog.** `catalog.source` reads `NIST SP 800-53 Rev 5`, but the
indexed catalog is not Rev 5 only: `data/rev5-corpus.json` holds 2,048 entries
of which 182 are controls only Rev 4 defines (`AC-13`, `AC-15`, `SC-19`,
`SC-9`). 35 of those surfaced as candidates across 401 rows. Of the 744 distinct
candidate ids, Rev 4 fails to define 204 and Rev 5 fails to define 35, so no
single revision explains the set.

None of these ids is fictitious — every one is a real control at some revision,
and this repo's existing Rev 4 to Rev 5 crosswalk carries a successor for each
one checked here: `SC-9` to `SC-8`, `AU-15` to `AU-5(5)`, `IR-10` to `IR-4(11)`,
`SA-12.6` to `SR-5(1)`. `SC-19` is the exception, which the crosswalk records as
technology-specific rather than superseded. No count is stated for the 35 as a
whole, because it cannot be reproduced from this repo: the crosswalk keys on
NIST's parenthesised spelling (`SA-12(6)`), not the normalized form this
contract produces (`SA-12 06`), and the corpus itself is not vendored here. The
defect is therefore a revision declaration, not bad data, which is why the
contract has a distinct refusal for it and why that refusal names the crosswalk
as the remedy.

**Scanner version.** `scanner.image` reads `checkmarx/kics:latest`, which names
no release, so the set of 1,811 checks scored cannot be reconstructed. KICS
stamps `kics_version` into every report it writes — the fixture at
`hdf-converters/converters/kics-to-hdf/fixtures/input/findings.json` records
`v2.1.20` — so a concrete version is both available upstream and checkable at
convert time. The contract requires one and refuses a floating tag.

## Field names this contract changes

The contract follows upstream's field names wherever upstream has the field, so
most of the artifact needs no translation. Three members differ, and the three
faults below are what the validator reports once they are reconciled:

| Upstream, as retrieved | This contract | Why |
|---|---|---|
| `schema: "control-mapping/v1"` | `schema: "control-mapping-candidates/v1"` | `control-mapping/v1` is the name the *adjudicated* artifact will carry. A scored review queue and a reviewed mapping must not share a schema literal, or a consumer cannot tell which one it holds. |
| `scanner.image` | `scanner.version` | An image reference answers "which container", not "which release". The contract still accepts an image reference and judges its tag, so upstream's value can be carried across unchanged once the tag is concrete. |
| *(absent)* | `catalog.revision` | Required. `catalog.source` is prose; nothing in the artifact states which revision the ids are to be read against. |

Taken **literally**, with no reconciliation, the artifact yields exactly one
fault — `schema_unknown` — because the schema literal is checked before
anything else is trusted. The case `schema-unknown` in the shared table uses
upstream's real literal, so that rename is pinned by a test.

One upstream member is admitted and then discarded: a check's `review` block
(`status`, `reviewer`, `decided_utc`, `accepted`, `rejected`, `notes`). It
passes validation, because a check object does not forbid extra members, but
neither language's ingested type carries it, so it does not survive ingestion.
That is deliberate — adjudication state belongs to the adjudicated artifact,
not to a scored queue — and it is recorded here so a later reader does not
assume the block arrives.

## Result against the artifact as retrieved

With the schema literal reconciled and nothing else altered, the candidate
artifact is **refused** on three counts: no declared catalog revision, no
concrete scanner version (`scanner.image` carries a floating tag and
`scanner.version` is absent), and a candidate set no single revision defines.
Each is a fixable upstream metadata or build problem rather than a reason to
loosen the contract.

Nothing else in the artifact is refused. Across all 9,055 candidate rows there
are zero unspellable ids and zero ids NIST defines at no revision, which is the
independent confirmation that the dot-to-parenthesis translation is complete.
