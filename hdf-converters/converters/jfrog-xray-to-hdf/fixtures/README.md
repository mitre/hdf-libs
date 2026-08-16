# JFrog Xray fixtures — provenance

`jfrog_xray_sample.json` is **real JFrog Xray output** — it carries actual
published CVEs (e.g. CVE-2019-19919, CVE-2020-7598) with realistic severity,
summary, and component fields. `empty.json` is a trivial zero-findings document.

**Refreshing:** JFrog Xray is a commercial product; there is no free/open path to
regenerate current output. This fixture is a durable, real capture and does not
go stale in a way that breaks the converter (the Xray response shape is stable).
Refresh only if the Xray export schema materially changes, sourcing from a real
Xray instance or the heimdall2 upstream sample.
