# Prisma Cloud fixtures — provenance

`prismacloud_sample.csv` is **real Prisma Cloud (Twistlock) CSV export** — it
carries actual published CVEs (e.g. CVE-2015-1258, CVE-2016-1583), real CIS
benchmark IDs and descriptions (e.g. `CIS_Linux_2.0.0 - 5.2.2`), and real RHEL7
distro/package data. Host identifiers have been **anonymized** (`my-fake-host-1.somewhere.cloud`)
— the only sanitized field; the vulnerability/compliance content is genuine.
`minimal.csv` / `empty.csv` are trimmed/empty variants exercising parser edges.

**Refreshing:** Prisma Cloud is a commercial SaaS; there is no free/open path to
regenerate current output. The CSV column contract is stable, so this real,
host-anonymized capture remains valid. Refresh only on a column-format change,
re-anonymizing hostnames.
