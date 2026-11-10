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
  Calculated fields read each mirrored scalar directly from its original JSON
  value, so indexed and automatically extracted copies do not multiply grouped
  counts or turn multiline titles into conflicting values. The raw event is unchanged.
- `eventtypes.conf` — `hdf_finding` matches failed/errored controls and any CVE
  finding, excluding `suppressed=true` (waived/false-positive/attested findings
  adjudicated out of the actionable set).
- `tags.conf` — applies `vulnerability` + `report` to `hdf_finding`, the tags
  the Vulnerabilities data model constrains on.

## Install

1. Copy `Splunk_TA_hdf/` into `$SPLUNK_HOME/etc/apps/` on your search head and
   the parsing tier handling HEC events. The search settings supply extraction,
   scalar normalization and tags; parsing settings disable event truncation.
   HEC indexes the exporter's `fields` independently of the add-on.
2. Restart Splunk (or reload: `| extract reload=T` is not sufficient — a restart
   or a debug/refresh of the endpoints is needed for new tags/eventtypes).
3. Send exporter output to HEC (`sourcetype` is already set in each event):
   ```
   hdf convert --from hdf --to splunk results.json -o out.ndjson
   curl --cacert /path/to/splunk-ca.pem https://<splunk>:8088/services/collector/event \
     -H "Authorization: Splunk <HEC_TOKEN>" --data-binary @out.ndjson
   ```
   Replace the host, token and CA path with your deployment's values. With a
   publicly trusted certificate, omit `--cacert` and use the system trust store.

## Verify

```
| tstats count from datamodel=Vulnerabilities where source="hdf-exporter" by Vulnerabilities.signature
```

requires the Splunk Common Information Model add-on and should return the
failed/CVE findings. To confirm tagging on a raw event:

```
sourcetype=hdf:results | eval tagged=if(match(tag, "vulnerability"), "yes", "no") | table signature hdf_status tag
```

Passed / notApplicable / notReviewed non-CVE controls are intentionally **not**
tagged (they are posture, not findings); query them directly by `sourcetype`.

Check scalar counts without query-level deduplication:

```spl
sourcetype=hdf:results | stats count by hdf_status severity suppressed
```

The add-on uses Splunk's [calculated fields](https://help.splunk.com/en/data-management/splunk-enterprise-admin-manual/10.6/configuration-file-reference/10.6.0-configuration-file-reference/props.conf)
after JSON extraction to read the mirrored scalar fields with
[`spath(_raw, "field")`](https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/10.6/evaluation-functions/text-functions).
The original event supplies the value, including embedded newlines; no arbitrary
first value is selected. Exporter output, index-time fields and nested JSON
extraction retain their existing shape. Queries against indexed values alone
(such as `tstats`) do not apply these search-time calculations.

## CIM notes

- `cvss` is a single number (the max base score); the full `cvss[]` and all
  other HDF detail ride losslessly in the nested `hdf.*` object.
- `hdf_status` is the **raw** verdict — a waived control stays `hdf_status=failed`,
  never rewritten to `passed`. Acceptance rides the separate `suppressed` boolean:
  the `hdf_finding` eventtype excludes `suppressed=true`, so a waived/false-positive/
  attested control drops out of the Vulnerabilities model while a risk-adjusted
  still-failing control (`suppressed=false`) stays in. The canonical
  "still actionable" query is `hdf_status=failed suppressed=false`.
