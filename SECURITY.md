# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 3.x (current) | Yes |
| < 3.0 | No |

Note: the `@mitre/hdf-converters` npm package name is shared with [heimdall2](https://github.com/mitre/heimdall2), whose team maintains the 2.x line under the `latest` dist-tag. Report issues in 2.x versions of that package to heimdall2, not here.

## Reporting a Vulnerability

The MITRE SAF team takes security seriously. If you discover a vulnerability in hdf-libs, please report it privately — do not open a public issue.

- **Preferred**: [Report a vulnerability](https://github.com/mitre/hdf-libs/security/advisories/new) through this repository's Security tab (GitHub private vulnerability reporting).
- **Email**: [saf-security@mitre.org](mailto:saf-security@mitre.org)

### What to include

- A description of the issue and the affected package(s) or CLI command(s)
- Steps or input files that reproduce it (malformed scanner output is this project's largest attack surface — a reproducing input file is ideal)
- The version(s) you tested and any known impact

### What to expect

- We aim to acknowledge reports within 5 business days.
- We will keep you informed as we triage, and coordinate a disclosure timeline with you before publishing a fix or advisory.
- Fixes for supported versions are published as patch releases with a GitHub security advisory when warranted.

## Verifying Releases

Release artifacts ship with SBOMs, a Sigstore signature, and SLSA build provenance. See [Verifying Release Artifacts](https://mitre.github.io/hdf-libs/docs/guides/verifying-releases) for the verification commands.
