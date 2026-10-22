# Evidence Packages End to End

An HDF evidence package is the sum total body of evidence that can be used to determine the risks to a system. In practical terms, it is the collection of all data pertaining to an HDF system at a given point in time -- its defining components, its security plan, its baselines, and the results that prove the status of those baselines, as well as any supporting external references.

Historically, the contents of an evidence package are what would be submitted to an auditor during an assessment, and more recently they would be what is submitted to a Governance, Risk and Compliance (GRC) tool to document a system's security status. Most organizations have some policy requirement to track their software systems' status in a GRC tool of some kind. In a modern DevSecOps paradigm, it's best to automate pushing updates to a GRC tool, since software systems are updated so often. Even in situations where manual data submissions are still required, it's best to have an organized and standardized body of evidence. That is the need the HDF evidence package schema was meant to fill.

This guide demonstrates how to build an HDF evidence package from a CI run for a software component, for a release built from source. Every transcript below is real output from `hdf`. The five pipeline artifacts are copies of this repository's converter fixtures, so you can follow along exactly:

| In this guide | Copied from |
|---|---|
| `sbom.cdx.json` | `hdf-converters/converters/cyclonedx-to-hdf/fixtures/input/juice-shop-sbom-minimal.json` |
| `grype-deps.json` | `hdf-converters/converters/grype-to-hdf/fixtures/input/directory_scan.json` |
| `semgrep-sast.json` | `hdf-converters/converters/semgrep-to-hdf/fixtures/input/minimal.json` |
| `trivy-fs.json` | `hdf-converters/converters/trivy-to-hdf/fixtures/input/fs-misconfig-secret.json` |
| `vendor-vex.json` | `hdf-converters/converters/csaf-vex-to-hdf/fixtures/input/sec-vex-2022-0001.json` |

For a broader tour of the CLI across all document types, see [CLI user stories](./cli-user-story-examples.md).

## What's in a package

| Array | What it holds | Travels in the archive? |
|---|---|---|
| `contents[]` | HDF documents the package carries — results, baselines, plans, amendments, system, BOMs — by package-relative path | Yes |
| `externalEvidence[]` | Native-format artifacts the HDF came from, or that nothing converts: raw scanner output, logs, telemetry. By URI and hash | Yes, when the artifact lives inside the package directory |
| `externalReferences[]` | Inert context: an advisory, a CTI object, a vendor VEX. Never fetched, never carried, recorded so a reader knows what was consulted | No |

Anything listed in the contents[] field is an HDF documents present inside the evidence package itself. Since the HDF schemas often allow for external references to be linked (such as, for example, an HDF System document referencing its full SBOM by URI instead of copying it inline), there are also lists of external references inside the package.

Furthermore, two root fields, `systemRef` and `planRef`, each name a single document. `build` records those documents in `contents[]` as well, so they are both pointed at and carried; a reference in either that resolves outside the package directory is reported and does not travel.

The reason for this is because the HDF CLI currently has no mechanism to download external references to place them locally, so any references that are not a local filepath just have to live as URIs for now. Many `hdf evidence` commands have flags to control whether an external reference that cannot be resolved is considered a problem or not.

Therefore, for the purposes of this guide, there are no external references present; all of our data comes from a single CI/CD pipeline. 

## The pipeline

Let's say we're the maintainers of a piece of software with attached CI/CD. A pipeline run for a new release of the application ("webapp"), built from source, left five files in its artifacts directory (such as GitHub or GitLab might produce). Every command below runs from there:

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

An SBOM generated from the dependency manifest, a dependency vulnerability scan, a static-analysis run, a filesystem scan for misconfiguration and secrets, and a vendor VEX the team pulled down while triaging.

(We picked these examples because they represent many types of security data and are a reasonable approximation of a real pipeline, but recall that HDF is all about normalizing any upstream format, so the specific scan types don't matter here.)

## Normalize what the scanners wrote

`hdf convert` autodetects each format and emits the HDF-normalized version:

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

## Describe the system the evidence covers

A package asserts something about a system, so we'll need an HDF system doc to identify what all of this HDF data is describing. We can use `hdf system create` to turn the SBOM document into an HDF system document.

```console
$ hdf system create sbom.cdx.json --from cyclonedx --component-name "webapp" -o system.json
Imported cyclonedx SBOM as component "webapp" (type: application)
System document written to system.json (1 components)
```

### Systems and components

Note that a full software system is likely made of multiple software components in a stack -- it would include the host that the webapp runs on, for example, and perhaps the cloud environment that host runs in. There may be a backing database component, a webserver proxy, and so on. For this example, since our data all describes the application's source code specifically, we designate "webapp" as a system with a single component.

## Build the package

Point `build` at the directory. It classifies every file by content:

```console
$ hdf evidence build --from-dir . -o evidence-package.json
Skipped grype-deps.json: not an HDF document. To carry it as external evidence:
  hdf evidence add-evidence evidence-package.json --uri grype-deps.json --format <format>
Skipped semgrep-sast.json: not an HDF document. To carry it as external evidence:
  hdf evidence add-evidence evidence-package.json --uri semgrep-sast.json --format <format>
Skipped trivy-fs.json: not an HDF document. To carry it as external evidence:
  hdf evidence add-evidence evidence-package.json --uri trivy-fs.json --format <format>
Skipped vendor-vex.json: not an HDF document. To carry it as external evidence:
  hdf evidence add-evidence evidence-package.json --uri vendor-vex.json --format <format>
Evidence package written to evidence-package.json (5 documents)
```

Five documents: the system, the three converted results, and the SBOM. For this example we left the original unconverted data that we passed to `hdf convert` earlier present in the directory to demonstrate that they're not included in the package, only HDF data is. The four files that are not HDF are each named, with the command that would carry them as external references.

Give the package a name while you are here:

```console
$ hdf evidence set evidence-package.json \
    --name "webapp X.Y.Z assessment evidence" \
    --description "Source-code assessment evidence for release X.Y.Z"
Updated evidence-package.json
```

## Add a scan result to an existing package

You can build an evidence package from scratch from a directory, but you can also add data to an existing one. When the next tool reports — here an IaC scan that was not in the first build — convert it and hand it to `update`:

```console
$ hdf convert checkov-iac.json -o iac.hdf.json
Detected: Checkov (confidence: 100%)
checkov-iac.json: 9 requirements, matching the input's distinct Checkov check ids

$ hdf evidence update evidence-package.json \
    --results iac.hdf.json -o evidence-package.json
  added iac.hdf.json
Updated evidence-package.json
```

`added`, not `replaced`: a document at a reference the package already records is refreshed in place, and a new one is added alongside. Pass `--dry-run` to see which of the two would happen before writing anything.

### Refreshing a scan you already have

Another common case is that a scan has re-run against the same component, and the evidence package should be updated to match. Let's say one of webapp's dependencies gets bumped and the scan is re-run to show a prior CVE finding is gone, and we want our package to show the updated version only.

`update` decides by the reference, so the same command does both jobs. `--dry-run` says which before anything is written:

```console
$ hdf evidence update evidence-package.json --results deps.hdf.json --dry-run
  replaced deps.hdf.json (same reference, refreshed in place)
Dry run: nothing written.
```

Drop `--dry-run` and the refresh lands, re-recording the checksum as it goes:

```console
$ hdf evidence update evidence-package.json --results deps.hdf.json -o evidence-package.json
  replaced deps.hdf.json (same reference, refreshed in place)
Updated evidence-package.json
```

```console
$ hdf evidence info evidence-package.json --verify
# abridged — the same six checksum lines
Verified: 6/6 checksums valid
Agent-attributed overrides: 0
Note: no planRef in evidence package — skipping completeness check
```

If we add data that represents a document the package has never seen, it is kept alongside rather than replacing anything. The CLI will note when another entry already covers the same baseline:

```console
$ hdf evidence update evidence-package.json --results extra.hdf.json --dry-run
  added extra.hdf.json
    also covered by an existing entry: Semgrep Scan
    both are kept — assessed 2026-10-22T15:06:38Z; no target components recorded
Dry run: nothing written.
```

So we can cover the case where multiple types of scanners cover the same baseline, if the developers want to do that for whatever reason.

One thing to know if you re-run `hdf convert` on an input that has not changed: the result is byte-identical, because conversion is deterministic and the HDF `timestamp` comes from the scan rather than from the moment of conversion. A refresh in that case is a no-op rather than an error.

## Inspect and verify the package

`hdf evidence info` reports what the package says about itself. It reads the package document and nothing else — none of the referenced documents are opened:

```console
$ hdf evidence info evidence-package.json
Evidence Package: webapp X.Y.Z assessment evidence
Prepared at: 2026-10-22T17:17:07Z
System: system.json

Contents (6):
  hdf-system       system.json  checksum recorded
  hdf-results      deps.hdf.json  checksum recorded
  hdf-results      fs.hdf.json  checksum recorded
  hdf-results      sast.hdf.json  checksum recorded
  bom              sbom.cdx.json  checksum recorded
  hdf-results      iac.hdf.json  checksum recorded

Completeness, as recorded by the package (not computed here — use --verify):
  All baselines assessed: yes
  All components covered: yes
  Compliance: 18%
```

Six documents: the five `build` recorded, plus the IaC results `update` added. `checksum recorded` means the package holds a hash for that entry — not that anything has been checked against it. Likewise the completeness block is a value the package carries, which is why the heading says so.

Adding `--verify` to that same command turns the report into a check. Each reference is read, hashed, and compared against the hash the package recorded as an integrity field:

```console
$ hdf evidence info evidence-package.json --verify
Verifying evidence package: webapp X.Y.Z assessment evidence

  ✓ system.json (sha512 match)
  ✓ deps.hdf.json (sha512 match)
  ✓ fs.hdf.json (sha512 match)
  ✓ sast.hdf.json (sha512 match)
  ✓ sbom.cdx.json (sha512 match)
  ✓ iac.hdf.json (sha512 match)

Verified: 6/6 checksums valid
Agent-attributed overrides: 0
Note: no planRef in evidence package — skipping completeness check
```

(Note that integrity and completeness are different questions: `--verify` answers "are these the bytes we recorded", and only an assessment plan can answer "did we assess everything we said we would". Give the package a `planRef` and the same command checks both.)

## Hand it over as one file

A directory verifies where it sits. `bundle` makes it travel:

```console
$ hdf evidence bundle evidence-package.json -o ../evidence-bundle.zip
Archive written to ../evidence-bundle.zip (7 file(s))
Contains exactly the package, every document it references — nothing else.
```

Seven: the package and the six documents it carries. The archive root is the package's own directory, so it reproduces that layout wherever it lands:

```console
$ unzip -Z1 ../evidence-bundle.zip
deps.hdf.json
evidence-package.json
fs.hdf.json
iac.hdf.json
sast.hdf.json
sbom.cdx.json
system.json
```

At the root sits `evidence-package.json` itself — the evidence package document, which validates against `hdf-evidence-package.schema.json` like any other HDF document:

```console
$ hdf validate evidence-package.json
✓ evidence-package.json is a valid HDF evidence-package file
```

It is the index the rest of the archive hangs from: every path in its `contents[]` is relative to the directory it sits in, which is why the archive needs no manifest of its own and why extracting it anywhere keeps the references intact. It carries no `$schema` or `formatVersion` field — the document type is recognized from its shape, which is also how `hdf` picks the right schema to validate it against.

The recipient runs the same command somewhere else entirely:

```console
$ mkdir -p /tmp/assessor && unzip -q ../evidence-bundle.zip -d /tmp/assessor
$ cd /tmp/assessor
$ hdf evidence info evidence-package.json --verify
# abridged — the same banner and six checksum lines
Verified: 6/6 checksums valid
Agent-attributed overrides: 0
Note: no planRef in evidence package — skipping completeness check
```

Six of six, on a different machine, with no path rewriting. That property holds because every reference the package records is relative to the package's own directory — which is what makes an evidence package a deliverable rather than a directory listing.

## Where to go next

- [Thresholds End to End](./thresholds-workflow.md) — gate a pipeline on what these results contain
- [Amendments End to End](./amendments-workflow.md) — waive, attest and adjudicate findings without editing the results
- [CLI user stories](./cli-user-story-examples.md) — a broader tour across every document type
- [HDF Specification §7](../specification/hdf-specification.md) — the normative definition of the evidence package document
- `hdf evidence <subcommand> --help` — every flag, with the reasoning for the ones that refuse things
