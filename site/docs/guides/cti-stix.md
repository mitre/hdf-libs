# CTI / STIX Enrichment

Cyber Threat Intelligence (CTI) — expressed as [STIX 2.1](https://oasis-open.github.io/cti-documentation/)
bundles of `vulnerability`, `indicator`, `sighting`, `campaign`,
`threat-actor`, and `relationship` objects — describes *what is happening in
the wild*. An HDF results document describes *what a scan found on a system*.
`hdf enrich` correlates the two by CVE, attaching threat context to the
findings it explains — and, opt-in, recomputing a CVSS Threat score when the
intel shows active exploitation.

This is **enrichment**, not conversion: STIX rides into an *existing* results
document as inert context, never a standalone HDF file. This guide explains why
that model was chosen, what `hdf enrich` attaches and where, and the CVSS
Exploit Maturity bridge that lets exploitation intel adjust risk *without
fabricating a number*.

## Why enrichment, not a converter?

A `stix-to-hdf` converter would have nothing honest to convert. STIX carries no
control results and no CVSS **base vector**, so a converter could only either
invent findings from thin air or emit an empty shell. Both correlate "this CVE"
to "this finding" — which is a merge over a results document the converter does
not have.

So STIX integrates as a pass over a results doc you already have:

```bash
hdf enrich <results> <source>
```

Positional parity with `hdf convert` (`<results> <source>`), with `--from` as an
optional format assertion. The input is the raw STIX bundle; the output is the
same results document with references appended. **No new HDF document type is
introduced.**

## The command

```bash
# Attach STIX context (source format auto-detected)
hdf enrich results.json log4shell-bundle.json -o enriched.json

# Assert the source format explicitly
hdf enrich results.json feed.json --from stix -o enriched.json

# Also recompute CVSS Threat where the intel shows exploitation (see below)
hdf enrich results.json bundle.json --recompute-cvss -o enriched.json

# Write to stdout instead of a file
hdf enrich results.json bundle.json
```

| Flag | Meaning |
|---|---|
| `--from <fmt>` | Assert the source format (auto-detected if omitted). Supported: `stix`. `--from` is a *detect-then-match* assertion — an asserted source that doesn't look like a STIX 2.1 bundle is rejected, never force-parsed. |
| `--recompute-cvss` | Additionally author an auditable CVSS Threat `riskAdjustment` on exploited, base-vector-bearing findings. Off by default. |
| `-o, --output` | Output file (default: stdout). |

## What gets attached, and where

Every STIX object becomes one `External_Reference` — HDF's generalized,
purpose-agnostic reference primitive — appended to the document:

- A **CVE-bearing** object (its `external_references[]` carry `source_name: "cve"`)
  attaches to the finding whose requirement ID *is* that CVE, fanning out to
  every matching finding, with `rel: "investigate"` (a live pivot).
- **Everything else** — non-CVE objects (`threat-actor`, `campaign`, plain
  `identity`/`location`) and CVEs with no matching finding — attaches to the
  **results root** with `rel: "reference"`.

Each reference is an **enrichment envelope**: it both cites the source and
carries the raw STIX object losslessly.

| Field | Value on a STIX reference |
|---|---|
| `sourceName` | `stix` |
| `kind` | `threat-intel` (the open token that turns a bare reference into an enrichment envelope) |
| `rel` | `investigate` (CVE→finding) or `reference` (root) |
| `externalId` | the STIX object id (e.g. `vulnerability--…`) |
| `document` | the raw STIX object, **verbatim** — HDF never normalizes it into HDF fields |

Because the payload rides untouched in `document`, HDF stays payload-agnostic:
STIX is carried unchanged rather than duplicated into a parallel HDF ontology.
See the [`External_Reference`](/schemas/) primitive for the full field set
(`href`, `mediaType`, `checksum`, `addedBy`/`addedAt`).

## Two modes: context vs. score change

The design draws a hard line between *adding context* and *changing the
assessment*.

**Informational (default).** Plain `hdf enrich` attaches references and
**changes nothing evaluative** — no status flips, no impact change, no
overrides. A structural diff confirms it:

```bash
hdf diff results.json enriched.json
# → 0 fixed, 0 regressed, 0 new, 0 absent — unchanged
```

That "unchanged" is the point: enrichment is inert. (The attached
`externalReferences[]` are visible in the JSON / `--format json`, they simply
aren't a *posture* change.)

**Score-changing (opt-in).** `--recompute-cvss` is the *only* thing that
authors an override. When the intel shows active exploitation, it writes an
inline `riskAdjustment` `Status_Override` on the finding, which the diff and the
`effectiveImpact` resolver do surface.

::: tip Why the split matters
Threat intel is context. Whether a control passed or failed did not change just
because someone attached a threat report to it. Keeping enrichment inert by
default means an enriched document is still an honest record of the scan;
opting into `--recompute-cvss` is a deliberate, auditable risk decision.
:::

## The CVSS Exploit Maturity bridge

STIX has exactly one native numeric — `confidence` (0–100) — and it measures
*certainty of an assertion, not severity of a threat*. A direct "STIX → impact
number" would therefore be fabrication. But "actively exploited" is precisely
the semantic of one CVSS metric: **Exploit Maturity**. Applying it to a
finding's existing vendor **base vector** and re-running the published CVSS
formula produces a number that is **computed, not invented**.

`--recompute-cvss` does exactly that:

1. Detect exploitation for a CVE from the bundle — a `sighting`
   (`sighting_of_ref`), a `relationship` of type `targets`/`exploits`
   (`target_ref`), or an `indicator`/`report` (`object_refs`).
2. For each CVE-matched finding carrying a CVSS **3.1** base vector, apply
   Exploit Maturity **`E:H`** and recompute the Threat score via the
   [CVSS engine](/schemas/) in `hdf-utilities`.
3. Author an inline `riskAdjustment` with a `cvss` block (`version`,
   `baseVector`, `threatVector: "E:H"`, `threatScore`, `computedScore`),
   `impact.value = computedScore / 10` (rounded to impact's natural 0.01 grid),
   an `appliedBy` of `hdf-enrich`, a review-horizon `expiresAt`, and an
   `externalReferences[]` back to the STIX source (`rel: "evidence"`).

The existing resolver then surfaces the adjusted `effectiveImpact`.

::: warning Guardrails — no fabrication
- A finding with **no base vector** is left unchanged — there is nothing to
  recompute honestly, so nothing is authored.
- A finding with a **CVSS 4.0** base vector is currently **skipped** by the
  enrich recompute. The 4.0 MacroVector engine ships in `hdf-utilities`
  (`computeCvss40Score`, with `E:A` as the 4.0 Exploit-Maturity analog), but
  wiring it into the enrich pass is not yet done.
- Exploitation maps to CVSS Exploit Maturity **only** — never to `Kev` (the
  CISA catalog) or `Epss` (the FIRST model), which would be fabrication unless
  the STIX *source* is literally that feed.
:::

## Worked example

Enriching a results set that contains `CVE-2012-0158`
(base vector `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`, base score 9.8)
with a bundle in which a `campaign` `targets` that vulnerability:

```bash
hdf enrich results.json poison-ivy-bundle.json --recompute-cvss -o enriched.json
```

yields, on the `CVE-2012-0158` finding:

```json
{
  "type": "riskAdjustment",
  "reason": "CVE-2012-0158 actively exploited per STIX threat intelligence (…); CVSS Threat recomputed with Exploit Maturity E:H.",
  "impact": { "value": 0.98 },
  "appliedBy": { "type": "other", "identifier": "hdf-enrich" },
  "cvss": {
    "version": "3.1",
    "baseVector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "baseScore": 9.8,
    "threatVector": "E:H",
    "threatScore": 9.8,
    "computedScore": 9.8
  },
  "externalReferences": [{ "sourceName": "stix", "kind": "threat-intel", "rel": "evidence", "document": { "…": "raw STIX object" } }]
}
```

A same-bundle finding whose base vector is absent, or is a 4.0 vector, receives
no override — an honest skip.

## Not included

- **TAXII** live-fetch and **`hdf-to-stix`** export — enrichment is a local
  overlay over a bundle you already have.
- Fabricating findings from a bare STIX bundle.
- Asserting `Kev`/`Epss` from generic exploitation signals.
- CVSS **Environmental** tailoring beyond what the Threat recompute needs.

## See also

- [VEX Interoperability](/docs/guides/vex-interop) — the other consumer-attached
  enrichment path (supplier statements → HDF Amendments).
- [CVE Ecosystem](/docs/guides/cve-ecosystem) — how HDF models CVEs, CVSS, KEV,
  and EPSS.
