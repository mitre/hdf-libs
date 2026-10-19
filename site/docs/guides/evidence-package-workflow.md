# Evidence Packages End to End

A results document says what one tool found. A threshold says whether that was acceptable. An evidence package says: *here is everything we looked at for this release, here is what we decided about it, and here is proof none of it changed since.*

That last part is the point. A pipeline produces a scattering of artifacts — an SBOM, three scanner outputs, a waiver somebody approved — and they are only evidence while someone can still tell which release they belong to and that they are the same bytes that were reviewed. A directory of files cannot say that. An evidence package can: it names every document, records a checksum for each, and travels as one archive that re-verifies wherever it lands.

This guide builds one from a CI run, for a release built from source. Every transcript below is real output from `hdf`. The five pipeline artifacts are copies of this repository's converter fixtures, so you can follow along exactly:

| In this guide | Copied from |
|---|---|
| `sbom.cdx.json` | `hdf-converters/converters/cyclonedx-to-hdf/fixtures/input/juice-shop-sbom-minimal.json` |
| `grype-deps.json` | `hdf-converters/converters/grype-to-hdf/fixtures/input/directory_scan.json` |
| `semgrep-sast.json` | `hdf-converters/converters/semgrep-to-hdf/fixtures/input/minimal.json` |
| `trivy-fs.json` | `hdf-converters/converters/trivy-to-hdf/fixtures/input/fs-misconfig-secret.json` |
| `vendor-vex.json` | `hdf-converters/converters/csaf-vex-to-hdf/fixtures/input/sec-vex-2022-0001.json` |

For a broader tour of the CLI across all document types, see [CLI user stories](./cli-user-story-examples.md); this page goes deep on one document type instead of broad across all of them.

## What a package records, and what it only points at

Three arrays, and conflating them is the most common misunderstanding of this document type.

| Array | What it holds | Travels in the archive? |
|---|---|---|
| `contents[]` | HDF documents the package carries — results, baselines, plans, amendments, system, BOMs — by package-relative path | Yes |
| `externalEvidence[]` | Native-format artifacts the HDF came from, or that nothing converts: raw scanner output, logs, telemetry. By URI and hash | Yes, when the artifact lives inside the package directory |
| `externalReferences[]` | Inert context: an advisory, a CTI object, a vendor VEX. Never fetched, never carried, recorded so a reader knows what was consulted | No |

The distinction is about what the package is *attesting*. A document in `contents[]` is part of the assessment. An artifact in `externalEvidence[]` is the raw material behind it. A reference in `externalReferences[]` is something you read, which may live on someone else's server and may be gone next year — recording it is honest; pretending to carry it is not.

Two root fields, `systemRef` and `planRef`, each name a single document. `build` records those documents in `contents[]` as well, so they are both pointed at and carried; a reference in either that resolves outside the package directory is reported and does not travel.

**Everything in this guide stays local.** No reference points off this machine. That is a deliberate choice, and [The strict read](#the-strict-read) shows what it buys.

## Lay the directory out

Keep the package directory to things that belong *in* the package. Policy, specs and derived views live beside it, not in it — `build` classifies everything it finds, so a stray file becomes a line of output you have to explain, and a missing one silently shrinks the package.

```
release-4821/
├── policy.yaml          # the threshold, committed in the repo
├── fp-spec.json         # the adjudication spec
└── artifacts/           # the package directory
```

The criterion is not the file type, and it is not "only pipeline output" — it is whether the package will **carry or reference** the file. Everything it will goes inside, and that is wider than the HDF documents: the three converted results, the system document and the adjudications land in `contents[]`, but so does the SBOM, as a `bom` rather than an `hdf-*` type, and moving it out drops the package from six documents to five. The raw scanner outputs go inside too, because [the external evidence](#carry-the-native-evidence) travels only while it lives in the package directory, and so does the vendor VEX, so that [its reference](#point-at-context-you-did-not-produce) can be recorded relatively.

Two kinds of file stay out. Policy and specs — the threshold, the adjudication spec — are inputs to the process rather than evidence of it, so nothing in the package points at them. And a *derived* view stays out even when it would be carried: [the effective results](#adjudicate) are a recomputable projection of a document already in the package, so keeping them would record the same evidence twice.

The package document itself is the one thing the rule does not decide, because `bundle` makes the archive root *be* its directory. Keep it in the directory anyway: built a level up it still bundles, but every reference it records gains an `artifacts/` prefix and the archive reproduces that deeper shape instead of the flat one [below](#seal-it-and-hand-it-over). A second package built over the same directory is simply skipped, as the [rebuild below](#completeness-needs-a-plan) shows. Anything a command writes *about* the package rather than *into* it — a bundle archive, an updated copy — is cleaner outside.

A build of this release dropped five files into `artifacts/`, which is where the commands below run unless they say otherwise:

```console
$ cd artifacts
$ wc -c *
   36496 grype-deps.json
   12582 sbom.cdx.json
    4151 semgrep-sast.json
    8426 trivy-fs.json
    6462 vendor-vex.json
   68117 total
```

An SBOM generated from the dependency manifest, a dependency vulnerability scan, a static-analysis run, a filesystem scan for misconfiguration and secrets, and a vendor VEX the team pulled down while triaging. Five tools, five formats, nothing in common.

## Normalize

`hdf convert` auto-detects each scanner:

```console
$ hdf convert grype-deps.json -o deps.hdf.json
Detected: Grype (confidence: 100%)
grype-deps.json: 6 requirements, matching the input's grype matches and ignored matches

$ hdf convert semgrep-sast.json -o sast.hdf.json
Detected: Semgrep 1.174.0 (confidence: 100%)
semgrep-sast.json: 2 requirements, matching the input's distinct semgrep rules plus the scan-status requirements

$ hdf convert trivy-fs.json -o fs.hdf.json
Detected: Trivy 2 (confidence: 95%)
trivy-fs.json: 5 requirements, matching the input's trivy findings
```

Three formats in, one shape out. That shape is what makes a single policy, and a single package, possible.

## Gate

One policy, applied to all three:

```yaml
# policy.yaml
# No critical or high findings may ship.
failed:
    critical:
        max: 0
    high:
        max: 0
```

```console
$ hdf validate threshold deps.hdf.json -T ../policy.yaml
Agent-attributed overrides: 0
✗ deps.hdf.json — 1 threshold violation

  Violations:
    failed.high: 1 exceeds maximum 0
      Grype/GHSA-462w-v97r-4m45  Grype found a vulnerability to GHSA-462w-v97r-4m45 in .  [failed/high]

$ hdf validate threshold sast.hdf.json -T ../policy.yaml
Agent-attributed overrides: 0
✗ sast.hdf.json — 1 threshold violation

  Violations:
    failed.high: 1 exceeds maximum 0
      python.lang.security.audit.subprocess-shell-true.subprocess-shell-true  Subprocess Shell True  [failed/high]

$ hdf validate threshold fs.hdf.json -T ../policy.yaml
Agent-attributed overrides: 0
✗ fs.hdf.json — 2 threshold violations

  Violations:
    failed.critical: 2 exceeds maximum 0
      Trivy/secret/aws-access-key-id@app.env:2  AWS Access Key ID  [failed/critical]
      Trivy/secret/aws-secret-access-key@app.env:3  AWS Secret Access Key  [failed/critical]
    failed.high: 1 exceeds maximum 0
      Trivy/DS-0002  Image user should not be 'root'  [failed/high]
```

All three exit 1. See [Thresholds End to End](./thresholds-workflow.md) for the policy language.

## Adjudicate

Two of those critical findings are the same documented dummy key pair, committed in a test fixture. That is a judgement a scanner cannot make, so it goes in its own document rather than being edited into the results. Write it to `fp-spec.json`:

```json
[
  {
    "type": "falsePositive",
    "requirementId": "Trivy/secret/aws-access-key-id@app.env:2",
    "reason": "app.env is a committed test fixture; the key is a documented dummy from the AWS docs and grants nothing.",
    "appliedBy": { "identifier": "appsec@example.org", "type": "email" },
    "expiresAt": "1y"
  },
  {
    "type": "falsePositive",
    "requirementId": "Trivy/secret/aws-secret-access-key@app.env:3",
    "reason": "Same fixture, same documented dummy pair.",
    "appliedBy": { "identifier": "appsec@example.org", "type": "email" },
    "expiresAt": "1y"
  }
]
```

```console
$ hdf amend create --from ../fp-spec.json -o adjudications.json
Created adjudications.json with 2 amendments
```

The results stay exactly as the scanner produced them. The effective view is computed on demand, and written outside the package directory because it is derived, not evidence:

```console
$ hdf amend apply --results fs.hdf.json --amendments adjudications.json -o ../fs-effective.json
Applied 2 of 2 override(s)
Merged output written to ../fs-effective.json

$ hdf validate threshold ../fs-effective.json -T ../policy.yaml
Agent-attributed overrides: 0
✗ ../fs-effective.json — 1 threshold violation

  Violations:
    failed.high: 1 exceeds maximum 0
      Trivy/DS-0002  Image user should not be 'root'  [failed/high]
```

The two false positives are gone and one finding remains, because it is real. The container still runs as root and that has to be fixed — adjudicating evidence is not the same as passing, and the SAST and dependency findings are still outstanding too. See [Amendments End to End](./amendments-workflow.md) for authoring.

## Describe the software it covers

A package asserts something about a *system*, and for a release built from source the SBOM already describes it. Import it rather than retyping it:

```console
$ hdf system create sbom.cdx.json --from cyclonedx -o system.json
Imported cyclonedx SBOM as component "juice-shop" (type: application)
System document written to system.json (1 components)
```

`--from` here only *verifies* the auto-detected format — it never force-parses, so naming the wrong one fails rather than producing a wrong document.

## Assemble the package

Point `build` at the directory and it classifies every file by content, not by filename:

```console
$ hdf evidence build --from-dir . -o juice-shop.hdf-evidence-package.json
Skipped grype-deps.json: not an HDF document. To carry it as external evidence:
  hdf evidence add-evidence juice-shop.hdf-evidence-package.json --uri grype-deps.json --format <format>
Skipped semgrep-sast.json: not an HDF document. To carry it as external evidence:
  hdf evidence add-evidence juice-shop.hdf-evidence-package.json --uri semgrep-sast.json --format <format>
Skipped trivy-fs.json: not an HDF document. To carry it as external evidence:
  hdf evidence add-evidence juice-shop.hdf-evidence-package.json --uri trivy-fs.json --format <format>
Skipped vendor-vex.json: not an HDF document. To carry it as external evidence:
  hdf evidence add-evidence juice-shop.hdf-evidence-package.json --uri vendor-vex.json --format <format>
Evidence package written to juice-shop.hdf-evidence-package.json (6 documents)
```

Six documents: the system, three results, the SBOM, and the adjudications. Nothing was dropped in silence — four files are not HDF, so the scan names each one and hands you a command for it.

Take that offer for three of them and decline it for the fourth. That is the whole distinction: the scanner outputs are the evidence this release produced; the vendor VEX is something the team read.

## Carry the native evidence

The raw scanner output is the primary artifact. The HDF is a normalization of it, and an assessor may want to re-derive one from the other:

```console
$ hdf evidence add-evidence juice-shop.hdf-evidence-package.json \
    --uri grype-deps.json   --format x-grype \
    --uri semgrep-sast.json --format x-semgrep \
    --uri trivy-fs.json     --format x-trivy
Added 3 external evidence reference(s) to juice-shop.hdf-evidence-package.json
  grype-deps.json -> x-grype
  semgrep-sast.json -> x-semgrep
  trivy-fs.json -> x-trivy
```

Each is hashed as it is recorded. `format` is an open set — the reserved values are `ecs`, `ocsf`, `cyclonedx`, `spdx` and `raw-log`, and anything else must take an `x-` prefix, as above.

## Point at context you did not produce

The VEX is a vendor's statement about their own product — this repository's sample says Secvisogram is not affected by Log4Shell. It is not evidence this release produced, and the package should not claim to carry it:

```console
$ hdf evidence add-reference juice-shop.hdf-evidence-package.json --href vendor-vex.json \
    --source-name csaf --kind threat-intel --rel reference --external-id CVE-2021-44228
Added 1 external reference to juice-shop.hdf-evidence-package.json
  csaf CVE-2021-44228 -> vendor-vex.json (externalReferences — inert context)
```

Give the package a name while you are here:

```console
$ hdf evidence set juice-shop.hdf-evidence-package.json \
    --name "juice-shop 19.1.1 — build 4821" \
    --description "Source-code assessment evidence for release 19.1.1"
Updated juice-shop.hdf-evidence-package.json
```

## Verify

Every checksum above was computed when its entry was recorded — by the directory scan for the documents, by `add-evidence` and `add-reference` for the rest. Nothing is re-read or re-verified until you ask:

```console
$ hdf evidence info juice-shop.hdf-evidence-package.json --verify
Verifying evidence package: juice-shop 19.1.1 — build 4821

  ✓ system.json (sha512 match)
  ✓ deps.hdf.json (sha512 match)
  ✓ fs.hdf.json (sha512 match)
  ✓ sast.hdf.json (sha512 match)
  ✓ sbom.cdx.json (sha512 match)
  ✓ adjudications.json (sha512 match)
  ✓ grype-deps.json (sha512 match)
  ✓ semgrep-sast.json (sha512 match)
  ✓ trivy-fs.json (sha512 match)

Verified: 9/9 checksums valid
Agent-attributed overrides: 0
Note: no planRef in evidence package — skipping completeness check
```

Nine: the six documents and the three native artifacts. The VEX is absent from that list even though `add-reference` did hash it — `--verify` reads `contents[]` and `externalEvidence[]`, and `externalReferences[]` is outside its scope by design. An inert reference is recorded, not attested.

### Completeness needs a plan

That last note is worth reading rather than skipping. Completeness asks a different question from integrity — not "are these the bytes we reviewed" but "did we assess everything we said we would", which needs an assessment plan to compare against. Write it to `plan.json`:

```json
{
  "name": "release-4821-plan",
  "assessments": [
    { "baselineRef": "Grype Scan" },
    { "baselineRef": "Semgrep Scan" },
    { "baselineRef": "Trivy Scan" },
    { "baselineRef": "Nessus Scan" }
  ]
}
```

The package carries a plan in `contents[]` and names it in `planRef`, so a plan belongs in the package directory. Put it there and rebuild with `--plan`, which does both:

```console
$ hdf evidence build --from-dir . --plan plan.json -o planned.json
Skipped juice-shop.hdf-evidence-package.json (evidence-package): an evidence package's contents[] has no type for it.
# abridged — then the same four "not an HDF document" skips as before
Evidence package written to planned.json (7 documents)

$ hdf evidence info planned.json --verify
Verifying evidence package: juice-shop-system-evidence-package

  ✓ system.json (sha512 match)
  ✓ deps.hdf.json (sha512 match)
  ✓ fs.hdf.json (sha512 match)
  ✓ sast.hdf.json (sha512 match)
  ✓ plan.json (sha512 match)
  ✓ sbom.cdx.json (sha512 match)
  ✓ adjudications.json (sha512 match)

Verified: 7/7 checksums valid
Agent-attributed overrides: 0

Completeness check FAILED:
  Missing results for baseline: Grype Scan
  Missing results for baseline: Nessus Scan
```

Seven, not nine: this is a fresh build, so it carries the documents and not the three native artifacts the first package gained from `add-evidence`. The banner differs because `--name` overrode the name on the first package; `build` mints one from the system document, and this package still carries the minted form. The first skip is the first package itself — an evidence package is not a document another package can carry.

Exit 1, and the two misses teach different lessons. `Nessus Scan` is missing because this pipeline never ran one — a genuine gap. `Grype Scan` is missing because the Grype results carry a baseline named `.`, the directory it scanned, not the name the plan guessed. **Completeness matches on baseline names**, so a plan has to use the names the scanners actually emit; `Semgrep Scan` and `Trivy Scan` match because those are exactly what those converters produce.

## Seal it and hand it over

```console
$ hdf evidence bundle juice-shop.hdf-evidence-package.json -o ../juice-shop-build-4821.tar.gz
Archive written to ../juice-shop-build-4821.tar.gz (10 file(s))
Contains exactly the package, every document it references, in-tree external evidence — nothing else.
  not carried: vendor-vex.json (context, not evidence) — recorded in externalReferences
```

Ten files: the package and the nine things it carries. The VEX is named as not carried, which is the third array behaving exactly as designed.

The archive root *is* the package's own directory, so it reproduces that layout wherever it is extracted:

```console
$ tar -tzf ../juice-shop-build-4821.tar.gz
adjudications.json
deps.hdf.json
fs.hdf.json
grype-deps.json
juice-shop.hdf-evidence-package.json
sast.hdf.json
sbom.cdx.json
semgrep-sast.json
system.json
trivy-fs.json
```

That property holds because every reference here is recorded *relatively*. A reference recorded as an absolute path is the exception: its document travels under a relative name while the package still names the producing machine's path, so the extracted copy cannot resolve it. `bundle` reports that rather than rewriting the package, and the fix is to record the reference relatively when authoring it.

The recipient's check is the same command, run somewhere else entirely:

```console
$ mkdir -p /tmp/assessor
$ tar -xzf ../juice-shop-build-4821.tar.gz -C /tmp/assessor
$ cd /tmp/assessor
$ hdf evidence info juice-shop.hdf-evidence-package.json --verify
# abridged — the banner and the same nine checksum lines
Verified: 9/9 checksums valid
Agent-attributed overrides: 0
Note: no planRef in evidence package — skipping completeness check
```

Nine of nine, on a different machine, with no path rewriting. That is the property the package exists for. The remaining sections run back in the original `artifacts/` directory, so change back to it before continuing.

## The strict read

An assessor accepting this as the evidence of record can demand more than integrity. Two opt-in flags turn soft reports into failures:

- `--require-checksums` fails if a `contents[]` or `externalEvidence[]` entry records no checksum to verify. It does not reach `externalReferences[]`, which is never attested.
- `--require-reachable` fails if the package records a reference that does not resolve *into* the package — a URI on another system, or a path outside its directory.

```console
$ hdf evidence info juice-shop.hdf-evidence-package.json --verify \
    --require-checksums --require-reachable
# abridged — the banner and the same nine checksum lines
Verified: 9/9 checksums valid
Agent-attributed overrides: 0
Note: no planRef in evidence package — skipping completeness check
```

Exit 0 — and that is what the local-only decision bought. Add a single remote reference to the same package and the strict read stops passing:

```console
$ cp juice-shop.hdf-evidence-package.json remote-probe.json
$ hdf evidence add-evidence remote-probe.json --uri https://builds.example/run-4821.log \
    --format raw-log --checksum sha256:3b7a3b7a3b7a3b7a3b7a3b7a3b7a3b7a3b7a3b7a3b7a3b7a3b7a3b7a3b7a3b7a
Added 1 external evidence reference(s) to remote-probe.json
  https://builds.example/run-4821.log -> raw-log

$ hdf evidence info remote-probe.json --verify --require-reachable
# abridged — the banner and the same nine checksum lines, then
  ? https://builds.example/run-4821.log (not reachable here: remote)

Verified: 9/9 checksums valid, 1 not reachable here
Agent-attributed overrides: 0

  not reachable here: https://builds.example/run-4821.log (remote) — recorded in externalEvidence
These are recorded references the package does not carry; pass --require-reachable to treat that as a failure.
Error: 1 recorded reference(s) could not be resolved (--require-reachable)
```

Exit 1. A package that points at an artifact on a build server is a legitimate thing to produce — HDF supports it deliberately, and `--require-reachable` exists precisely so an assessor who cannot accept it can say so. But a self-contained package is the one that still verifies in five years, and it costs nothing to build if you decide it early.

## Keep it current

The next build produces new results for the same release line. `update` records them without disturbing the package:

```console
$ hdf evidence update juice-shop.hdf-evidence-package.json \
    --results deps.hdf.json -o ../build-4822.json
  replaced deps.hdf.json (same reference, refreshed in place)
Updated ../build-4822.json
```

A document at the same reference is replaced in place; a new one is added alongside. Pass `--dry-run` to see what would change and write nothing.

If you want a package to carry a stable identity across those updates, set one explicitly. `evidence build` does not mint a `packageId`, and `update` preserves whatever it finds:

```console
$ hdf evidence set juice-shop.hdf-evidence-package.json \
    --package-id 7c9e6679-7425-40de-944b-e07fc1f90ae7
Updated juice-shop.hdf-evidence-package.json
```

## Gating a pipeline with this

[Thresholds End to End](./thresholds-workflow.md) carries a section gating a GitHub pipeline. This guide has none yet, deliberately: this repository's own CI may only use a fully released version of the CLI, and the currently pinned release predates these subcommands. Rather than write a pipeline nobody can run, that section is tracked as `hdf-libs-wgvm.27` and will be written once a release carries them.

Until then the shape is the arc above: normalize in the job that produces each artifact, gate with `validate threshold`, assemble with `evidence build --from-dir` over the artifacts directory, and publish the `bundle` archive as a release asset. The property worth asserting in CI is the one [The strict read](#the-strict-read) demonstrates — download the archive, extract it somewhere that never built it, and require exit 0.

## Where to go next

- [Thresholds End to End](./thresholds-workflow.md) — the policy language the gate step used
- [Amendments End to End](./amendments-workflow.md) — authoring the adjudications, expiry, and the audit trail
- [CLI user stories](./cli-user-story-examples.md) — a broader tour across every document type
- [HDF Specification §7](../specification/hdf-specification.md) — the normative definition of the evidence package document
- `hdf evidence <subcommand> --help` — every flag, with the reasoning for the ones that refuse things
