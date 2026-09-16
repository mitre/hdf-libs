# SonarQube fixtures — provenance

Input fixtures are SonarQube `/api/issues/search` responses (the shape the
`sonarqube` fetcher assembles and the converter consumes), with `rules[]`
enriched from `/api/rules/show` (`descriptionSections`, `sysTags`, `htmlDesc`).

## `sq26-owasp.json` — real scan, OWASP→NIST coverage

Real output from an OWASP Juice Shop scan, used to exercise the OWASP-2017 → NIST
fold (rules whose descriptions reference `OWASP Top 10 2017 - Category A#`).

- **Source app:** [OWASP Juice Shop](https://github.com/juice-shop/juice-shop)
  `v19.1.1` (commit `dd96757`), a public deliberately-vulnerable application.
- **Analyzer:** containerized `sonarsource/sonar-scanner-cli` against a locally-run
  SonarQube `26.1.0` Community instance (server version recorded in the fixture).
- **Capture:** fetched raw via `hdf fetch sonarqube --format raw`, then trimmed to
  11 representative requirements — VULNERABILITY, BUG, and CODE_SMELL types across
  BLOCKER/MAJOR/MINOR severities — covering every OWASP-2017 category the scan
  produced (A1, A2, A3, A10), each also carrying CWE refs so the fold demonstrably
  adds controls beyond CWE→NIST.
- **Sanitization:** per-finding `author`/`assignee` fields stripped. The
  `secrets:S6706` rule ships an **example** PEM private key in its documentation
  (`how_to_fix` section) — a rule-doc sample, not a live credential — replaced
  with `[EXAMPLE PRIVATE KEY REDACTED FROM FIXTURE]` so secret scanners don't trip
  on it (this section is not read for CWE/OWASP mapping, so the fold is
  unaffected). Component keys are the public Juice Shop source paths. No local
  host, port, token, or environment detail is present.

## Other fixtures (hand-curated, path-coverage)

`minimal.json`, `mqr.json`, `mqr-divergent.json`, `sq26-with-sections.json`, and
`empty.json` are small hand-curated documents exercising specific parser paths
(legacy vs MQR severity modes, SonarQube 26+ `descriptionSections`, and the
zero-findings placeholder). They carry no OWASP data.
