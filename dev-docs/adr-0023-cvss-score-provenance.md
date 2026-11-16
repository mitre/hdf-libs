# ADR-0023: Who supplied a CVSS score — provider and role on the Cvss primitive

- **Status:** Proposed
- **Date:** 2026-11-16
- **Deciders:** Will Dower
- **Relates to:**
  - GitHub issue #581 — CVSS gaps found on real Grype and OSV scans; this ADR is the root cause behind its Snyk finding.
  - [ADR-0006](adr-0006-stix-cti-integration.md) — introduced the CVSS scoring engine the converters share.
  - [ADR-0016](adr-0016-multi-scanner-results-merge.md) — merging results from several scanners, where scores from different providers meet.

## Context

A CVSS entry (`cvss.schema.json`) has one field about origin, `source`, documented as "the
identifier the CVSS data is associated with — most commonly a CVE ID … but may also be a vendor
advisory ID, GHSA, or similar". Nothing records **who supplied** the score, or whether it is that
provider's **primary** assessment or a **secondary** one.

Scanners routinely report several scores for one CVE, each from a different provider. With no
place for the provider, converters improvise, and they disagree (read from the code on
2026-11-16):

| Converter | What it writes into `source` |
|---|---|
| grype-to-hdf, snyk-to-hdf | the CVE id |
| trivy-to-hdf | the vendor key (`nvd`, `redhat`, `ghsa`) |
| cyclonedx-to-hdf | the rating's `source.name` (for example `NVD`) |

So `source` holds two kinds of value depending on the tool that produced the file, and no consumer
can rely on it. Where a scanner sends several scores, a converter must either drop all but one or
emit entries nobody can tell apart. The Snyk converter shows the cost: Snyk's top-level
`cvssScore` is its primary score, which for 39 of the 104 vulnerabilities in our fixtures is a
CVSS 4.0 score, but the converter pairs it with the top-level `CVSSv3` vector (a secondary 3.1
assessment) under version 3.1. Snyk itself sends every score with its own vector, version,
provider and role in `cvssSources[]`.

## How the standards and tools record it

Every format that carries more than one score per vulnerability records its provider per score:

| Format | Per-score provenance |
|---|---|
| CycloneDX 1.5/1.6 `vulnerabilities[].ratings[]` | `source { name, url }`, beside `score`, `severity`, `method`, `vector` |
| NVD API 2.0 `metrics.cvssMetricV31[]` (and V2, V30, V40) | `source` (the assigner) and `type` (`Primary` or `Secondary`) |
| CVE JSON 5 | scores sit in the CNA container or an ADP container, each with `providerMetadata` (`orgId`, `shortName`) |
| Grype `vulnerability.cvss[]` | `source` (for example `nvd@nist.gov` or a CNA's UUID) and `type` (`Primary` or `Secondary`) |
| Snyk `cvssSources[]` | `assigner` (Snyk, NVD, Red Hat, SUSE) and `type` (`primary` or `secondary`) |
| Trivy `CVSS` | an object keyed by vendor |

The external formats' field names are from their published schemas; the Grype, Snyk and Trivy
shapes were read from the fixtures in this repository.

## Decision (proposed)

1. **Add two optional fields to the Cvss primitive:**
   - `provider`: who supplied the score — `name` (required within the object) and an optional
     `identifier` (an e-mail, an organisation UUID or a URL, as the source gives it). This
     follows CycloneDX's `source { name, url }` and CVE 5's `providerMetadata`. Values are written
     as the source gives them; no alias table is imposed.
   - `role`: `primary` or `secondary`, as NVD, Grype and Snyk use the terms; absent when the
     source does not say.
2. **`source` keeps its documented meaning**, the identifier the score belongs to (a CVE,
   advisory or GHSA id). Converters stop writing provider names into it.
3. **One builder fills them.** The shared `BuildCvss` / `buildCvss` input gains `provider` and
   `role`, so every converter sets them the same way.
4. **Importers emit every score their source supplies,** each with its own vector, version,
   provider and role, rather than choosing one.
5. **Exporters carry them out** where the target format can hold them (CycloneDX `ratings[].source`,
   CSAF, OCSF), so a round trip loses nothing.
6. **One shared rule chooses the score that drives a requirement's impact** when several are
   present (primary before secondary, then version), instead of each converter choosing.

The change is additive: an existing document stays valid and a consumer that ignores the new
fields reads what it read before.

## Consequences

- A consumer can tell NVD's score from a vendor's and rank by the one it trusts.
- Files written before this change keep provider names in `source` where trivy-to-hdf or
  cyclonedx-to-hdf wrote them; readers cannot tell those apart from identifiers. The CHANGELOG
  states which converters did this and from which release they stop.
- More CVSS entries per finding where a scanner sends several scores; goldens grow accordingly.
- The score-selection rule touches impact, which overlaps the open decision on a rolled-up
  requirement's impact and severity (board card `hdf-libs-y2an7.48`).

## Alternatives considered

- **Keep `source` and write the provider there when it is known (as trivy-to-hdf does).** Rejected:
  it gives the field two meanings and contradicts its schema description.
- **Emit only the primary score per finding.** Rejected: drops the CVSS 3.x score for findings whose
  primary is 4.0 and drops every third-party score.
- **Emit only the scanner's own scores.** Workable without a schema change, but loses the NVD and
  vendor scores the same file already carries; kept as the fallback if this ADR is not accepted.
