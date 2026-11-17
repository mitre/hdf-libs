# ADR-0023: Who calculated a CVSS score, and where a VEX document's scores go

- **Status:** Proposed
- **Date:** 2026-11-16
- **Deciders:** Will Dower
- **Relates to:**
  - GitHub issue #581 — CVSS gaps found on real Grype and OSV scans; this ADR is the root cause behind its Snyk finding.
  - [ADR-0006](adr-0006-stix-cti-integration.md) — introduced the CVSS scoring engine the converters share.
  - [ADR-0016](adr-0016-multi-scanner-results-merge.md) — merging results from several scanners, where scores from different providers meet.

## Summary for the reviewer

Two questions, everything else follows from them.

**A. Record who calculated each score.** Add two optional fields to the CVSS entry: `provider` (who
calculated it — NVD, Red Hat, Tenable) and `role` (`primary` or `secondary`, as NVD, Grype and
Snyk mark it). `source` keeps its meaning, the CVE or advisory the score belongs to. Today
converters disagree on what goes in `source`, and a scanner that sends several scores per CVE
cannot be stored faithfully.

**B. Give amendments documents a place for published scores.** CycloneDX, CSAF and SPDX all give
a vulnerability two sibling things: a list of scores, each naming who scored it, and the VEX
statement per product. HDF results have both (`requirement.cvss[]` and overrides), but an
amendments document — what every VEX converter produces — has only overrides, and an override's
single `cvss` is the reviewer's own re-score behind a risk adjustment. So VEX scores are dropped
today, or one is put in the override's slot where it means something else. B adds a list of
published scores beside the overrides; applying the amendments adds them to the requirement's
score list.

**Shape, top to bottom:**

| Level | Change |
|---|---|
| Amendments document | **new** list of published scores beside `overrides` (B) |
| Results document | none — `requirement.cvss[]` is already a list |
| Override | none — its `cvss` stays the reviewer's re-score |
| CVSS entry | **new** optional `provider` and `role` (A) |
| Impact | one shared rule picks the score that drives it (primary first, then version) |

All of it is additive: existing documents stay valid.

**Order of work if agreed:** this ADR → one schema PR (both changes, generated types, spec docs)
→ one shared-code PR (the CVSS builder, merging the new list, the selection rule) → one PR per
converter → exporters. One question for you on the schema PR: 3.8.0 before it is final, or 3.9.0.

## Context

A CVSS entry (`cvss.schema.json`) has one field about origin, `source`, documented as "the
identifier the CVSS data is associated with — most commonly a CVE ID … but may also be a vendor
advisory ID, GHSA, or similar". Nothing records **who calculated** the score, or whether it is that
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
| CSAF 2.1 `vulnerabilities[].metrics[]` | `source`, "the URL of the source that originally determined the metric" |
| SPDX 3.0.1 CVSS assessment relationships | `suppliedBy` on each assessment |
| Dependency-Track finding | the vulnerability record's `source` (NVD, GITHUB, OSV …), which owns its CVSS fields |
| Nessus plugin | `cvss_score_source`, `cvss3_score_source`, `cvss4_score_source`: the CVE the score is derived from, or `manual` when Tenable assigned it |

The external formats' field names are from their published schemas and documentation; the Grype,
Snyk and Trivy shapes were read from the fixtures in this repository.

## Where the VEX formats put scores

The VEX formats keep a vulnerability's scores apart from its status statement:

| Format | Scores | Status statement |
|---|---|---|
| CycloneDX 1.6 | `vulnerabilities[].ratings[]` | `vulnerabilities[].analysis` |
| CSAF 2.0 / 2.1 | `vulnerabilities[].scores[]` / `metrics[]`, each for a set of products | `vulnerabilities[].product_status` |
| SPDX 3.0.1 | `security_Cvss*VulnAssessmentRelationship`, one per assessment | `security_Vex*VulnAssessmentRelationship` |
| OpenVEX | none | statements |

An HDF amendments document carries only `overrides[]`. `Standalone_Override.cvss` is one object,
defined in `amendments.schema.json` as the scoring "used to justify a riskAdjustment" — the
reviewer's own re-score. With nowhere else to go, the VEX converters read on 2026-11-16 either drop
the publisher's scores (cyclonedx-vex-to-hdf, csaf-vex-to-hdf) or put the first one into that
override field (spdx-vex-to-hdf), where it reads as a re-score nobody made.

## Decision (proposed)

1. **Add two optional fields to the Cvss primitive:**
   - `provider`: who calculated the score, as the input names it — `name` (required within the
     object) and an optional `identifier` (an e-mail, an organisation UUID or a URL, as the source
     gives it). This is the meaning CycloneDX gives `rating.source` ("the source that calculated
     the severity or risk rating") and CSAF 2.1 gives `metrics[].source` ("the source that
     originally determined the metric"), and follows CVE 5's `providerMetadata`. Values are
     written as the source gives them; no alias table is imposed. A tool that passes on another
     party's score without naming that party is not the provider, and the field stays absent:
     JFrog Xray's documentation says its CVSS scores come from NVD or an operating system's
     security advisory, and its reports carry an issue-level `provider` that does not say which.
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
7. **Amendments documents gain a list of published scores** beside `overrides`. Each item names
   the requirement it belongs to the way an override does (`requirementId`, optional
   `baselineRef` and `componentRef`) and carries a `cvss` list of CVSS entries, with `provider`
   and `role` as above. Merging the amendments into results appends those entries to the
   requirement's `cvss` list. `Standalone_Override.cvss` keeps its meaning. Field names here are
   a proposal for the schema PR.

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
- The VEX converters gain scores they drop today; spdx-vex-to-hdf stops filling
  `Standalone_Override.cvss` with a publisher's score.
- The amendments merge (`hdf-diff/go/amend`, used by `hdf amend` and the MCP tool) learns the new
  list.

## Alternatives considered

- **Keep `source` and write the provider there when it is known (as trivy-to-hdf does).** Rejected:
  it gives the field two meanings and contradicts its schema description.
- **Emit only the primary score per finding.** Rejected: drops the CVSS 3.x score for findings whose
  primary is 4.0 and drops every third-party score.
- **Emit only the scanner's own scores.** Workable without a schema change, but loses the NVD and
  vendor scores the same file already carries; kept as the fallback if this ADR is not accepted.
- **Make `Standalone_Override.cvss` a list and put VEX scores there.** Rejected: an override
  changes a finding's status or risk, and its `cvss` is the reviewer's justification for that;
  a publisher's scores are data about the vulnerability, which the VEX formats keep separate.
- **Leave VEX scores out of HDF.** Rejected: CycloneDX, CSAF and SPDX VEX documents carry them,
  and dropping them loses the vendor's own assessment of its product.
