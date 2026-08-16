# Nessus fixtures — provenance

Fixtures for the `nessus-to-hdf` converter. Nessus exports use the stable
`NessusClientData_v2` XML schema, which is emitted identically by standalone
Nessus, Tenable.sc, and DoD ACAS (ACAS is built on Tenable). The difference
between deployments is *which optional fields are populated* (e.g. ACAS /
Tenable.sc populate `cvss3_base_score`, `stig_severity`, and IAVM `xref`s), not
the document structure.

## input/

### `sample.nessus`
Real **Nessus Home** scan of a home network (3 hosts, 149 findings), captured
March 2022 (Log4Shell-era plugins). Sourced from the MITRE **heimdall2** sample
corpus — `libs/hdf-converters/sample_jsons/nessus_mapper/sample_input_report/sample.nessus`
(SAF carries a byte-identical copy). Our copy is byte-identical to upstream
except a single length-preserving hostname sanitization (`DESKTOP-LSFL6KC` →
`DESKTOP-TEST001`). Exercises the vulnerability path (CVSS v2/v3, CVE/CWE/xref,
severity → impact).

### `compliance.nessus`
Real Nessus **DISA STIG Compliance Audit** against RHEL-7, with authentic STIG
identifiers and cross-references (e.g. `RHEL-07-010010`, `CCI-000366`,
`SV-86473r2_rule`, `V-71849`). Exercises the compliance path (`cm:compliance-*`
items, `ComplianceReference` parsing, CAT → impact). The STIG identifiers are
genuine DISA content; the exact upstream file was not pinned down.

### `empty-host.nessus`
Synthesized minimal edge case (host `cleanhost.example.com`, the RFC-2606
reserved domain) added in PR #81 to exercise the empty-host / no-findings code
path. Not real scan output — a structural scaffold only.

## ACAS coverage note
DoD ACAS scans exercise two axes: vulnerability findings (CVSS v3, STIG/IAVM
xrefs) and DISA STIG compliance audits. Both are covered here — the former by
`sample.nessus`, the latter by `compliance.nessus`. ACAS is built on Tenable and
emits the same `NessusClientData_v2` schema as standalone Nessus, differing only
in *which optional fields are populated*, so no structural divergence exists.

`sample.nessus` is the standing **ACAS-shape regression guard**: though captured
from Nessus Home, it happens to carry the ACAS-distinctive fields —
`cvss3_base_score`/`cvss3_vector`, `stig_severity` (STIG CAT), and IAVM
`xref`s (IAVA/IAVB). `TestConvertNessusToHDF_ACASFieldsPreserved` (Go + TS) locks
in that these survive conversion: `cvss3_base_score` is promoted to a structured
tag and `cvss[]` entry, while the IAVM xref and `stig_severity` are preserved in
the raw `code` blob. Promoting those last two to first-class tags is tracked as
separate follow-up work.

No authoritative *dedicated* ACAS export is committed: real DoD ACAS exports are
DoD-internal and not shareable, Tenable's public docs specify only the
`NessusClientData_v2` structure (no populated sample), and no provenance-
documented public ACAS scan was locatable. Rather than pad the corpus with a
synthetic fixture duplicating fields `sample.nessus` already exercises, ACAS
coverage is asserted against that real scan.
