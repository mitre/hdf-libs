# Splunk_TA_hdf — HDF Add-on for Splunk

Normalizes HDF (Heimdall Data Format) assessment results into the Splunk
**Common Information Model (CIM)** so failed and CVE findings populate the
**Vulnerabilities** data model (and light up Enterprise Security / risk-based
alerting), while every result stays queryable for compliance posture.

This add-on is the search-time half of the export: the `hdf convert --to splunk`
exporter emits CIM-named HEC events under `sourcetype=hdf:results`, and this TA
tags them into the data model. CIM membership is applied by tags inside Splunk —
it cannot be set from the event payload alone — so the TA is required for
CIM/ES integration, not optional.

## What it does

- `props.conf` — configures `sourcetype=hdf:results` (JSON KV extraction; no
  field aliasing needed because the exporter already emits CIM field names).
- `eventtypes.conf` — `hdf_finding` matches failed/errored controls and any CVE
  finding, excluding `suppressed=true` (waived/false-positive/attested findings
  adjudicated out of the actionable set).
- `tags.conf` — applies `vulnerability` + `report` to `hdf_finding`, the tags
  the Vulnerabilities data model constrains on.

## Install

1. Copy `Splunk_TA_hdf/` into `$SPLUNK_HOME/etc/apps/` on your search head (and
   indexers, if you want index-time `fields`).
2. Restart Splunk (or reload: `| extract reload=T` is not sufficient — a restart
   or a debug/refresh of the endpoints is needed for new tags/eventtypes).
3. Send exporter output to HEC (`sourcetype` is already set in each event):
   ```
   hdf convert --from hdf --to splunk results.json -o out.ndjson
   curl -k https://<splunk>:8088/services/collector/event \
     -H "Authorization: Splunk <HEC_TOKEN>" --data-binary @out.ndjson
   ```

## Verify

```
| tstats count from datamodel=Vulnerabilities where source="hdf-exporter" by Vulnerabilities.signature
```

should return the failed/CVE findings. To confirm tagging on a raw event:

```
sourcetype=hdf:results | eval tagged=if(match(tag, "vulnerability"), "yes", "no") | table signature hdf_status tag
```

Passed / notApplicable / notReviewed non-CVE controls are intentionally **not**
tagged (they are posture, not findings); query them directly by `sourcetype`.

## CIM notes

- `cvss` is a single number (the max base score); the full `cvss[]` and all
  other HDF detail ride losslessly in the nested `hdf.*` object.
- `hdf_status` is the **raw** verdict — a waived control stays `hdf_status=failed`,
  never rewritten to `passed`. Acceptance rides the separate `suppressed` boolean:
  the `hdf_finding` eventtype excludes `suppressed=true`, so a waived/false-positive/
  attested control drops out of the Vulnerabilities model while a risk-adjusted
  still-failing control (`suppressed=false`) stays in. The canonical
  "still actionable" query is `hdf_status=failed suppressed=false`.
