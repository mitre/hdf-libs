# Ion Channel fixtures — provenance

> **KNOWN-SYNTHETIC / UNVERIFIED.** These fixtures are **fabricated placeholder
> data**, not real Ion Channel output and **not validated against any official
> schema**. Every identifier is a template (`a1b2c3d4-e5f6-…`, `analysis-001-…`,
> `example-project`, `example-org`, `abc123def456`) and there are no real CVEs.

- `minimal.json` / `edge-cases.json` — hand-constructed to exercise the parser's
  code paths. They demonstrate that the converter *runs*, but because they are
  neither real tool output nor schema-validated, they prove nothing about
  behavior on genuine Ion Channel data (see the Fixture Integrity policy in the
  repo CLAUDE.md).

**Why it's stuck here:** Ion Channel is a SaaS product (now part of Anchore) with
no free/open path to capture a real analysis response, and no public response
schema was validated against when these were written.

**To fix (tracked separately):** either (a) capture a real Ion Channel analysis
response and sanitize it, or (b) validate a synthetic fixture against the official
Ion Channel API response schema and add an inline `_provenance` marker — the same
bar the `msft-defender-*` fixtures meet. Until then, treat this converter's tests
as mechanical-only.
