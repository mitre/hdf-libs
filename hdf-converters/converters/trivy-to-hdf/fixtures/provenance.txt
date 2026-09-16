# Trivy fixtures — provenance

Fixtures for the `trivy-to-hdf` converter. Native Trivy JSON (`trivy --format json`),
top-level `SchemaVersion: 2` — the self-describing format the converter fingerprints on.
Both files are real **Trivy 0.74.0** output (the current release as of 2026-08-14).

## input/

### `image-webgoat.json`
Real `trivy image` scan of the public **OWASP WebGoat** container image:

```
trivy image --format json --scanners vuln,secret,license webgoat/webgoat:latest
```

Covers three `Results[].Class` values: `os-pkgs` (Ubuntu 24.04 vulnerabilities),
`lang-pkgs` (Java `jar` vulnerabilities), and `license` (OS + Java package licenses).
The image carries no secrets or misconfigurations, so those Classes come from
`fs-misconfig-secret.json` instead.

**Subsetting** (the full scan is ~3 MB / 490 os-pkg + 128 lang-pkg vulns): reduced to
a small representative slice, preserving exact structure — 3 `os-pkgs` and 3 `lang-pkgs`
vulnerabilities, each from a distinct package and chosen for field richness (multi-source
CVSS across `nvd`/`ghsa`/`redhat`/`bitnami`, `CweIDs`, `FixedVersion`, `PkgIdentifier.PURL`),
plus 3 licenses per license Result. Each Result's `Packages` inventory is trimmed to the
packages the kept vulnerabilities reference (so the vuln→package join is intact), and each
vulnerability's `References` list is trimmed to 4 URLs.

All paths in this file are **in-image** (`/home/webgoat`, `/opt/java/openjdk`, package doc
paths) and all digests are the public image's content hashes — no host data.

### `fs-misconfig-secret.json`
Real `trivy fs` scan covering the `config` and `secret` Classes the image scan does not
produce. The scanned inputs were **crafted, sanitized test files** (NOT a real project):

```
# testdata/Dockerfile  — deliberate misconfigurations (latest tag, USER root, EXPOSE 22)
# testdata/app.env      — a PLANTED, FAKE AWS key pair (never a real credential)
trivy fs --format json --scanners misconfig,secret testdata/
```

Covers `config` (3 Dockerfile misconfigurations) and `secret` (2 findings).

**No secret material is committed.** Trivy redacts secret values to asterisks in its JSON
output (`"Match": "AWS_ACCESS_KEY_ID=********************"`); the fake key itself never
appears in this file, and the raw `testdata/` inputs are not committed. Targets are the
relative paths `Dockerfile` and `app.env`.

### `empty.json`
Real `trivy fs` scan of an empty directory (`trivy fs --scanners vuln,misconfig,secret emptydir`,
run from a relative path so `ArtifactName` is just `emptydir`). Trivy omits `Results`
entirely for a clean scan; exercises the synthesized `trivy-no-findings` passed requirement.

### Routing (delegation) tests
The router's SARIF/CycloneDX delegation is tested against the existing
`sarif-to-hdf` and `cyclonedx-to-hdf` fixtures rather than committing large Trivy
SARIF/CycloneDX exports — the routing logic keys on the format shape, not on Trivy
provenance, so no additional fixtures are needed.

## Sanitization

Applied to both files, and verified (`/Users/`, the host user/hostname, `/private/tmp`,
and any `AKIA…` key pattern all grep to zero):

- **`CreatedAt` normalized** to `2026-08-14T00:00:00Z`. The raw scans stamp the local wall
  clock *with this machine's timezone offset*; the fixed UTC value removes that and makes
  the converter's expected output deterministic.
- **Secrets redacted at the source** by Trivy (see above); no raw secret is committed.
- No host filesystem paths — the image scan carries only in-image paths, the fs scan only
  the relative `testdata/` names.
