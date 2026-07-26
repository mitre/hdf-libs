# hipcheck-to-hdf fixtures

Source format: MITRE Hipcheck `hc check --format json` report (the `Report`
struct in `mitre/hipcheck` `hipcheck/src/report/mod.rs`), Hipcheck v3.15.0.

## input/

- **real.json** — Real scan of OWASP Juice Shop, produced with:
  `hc check -v quiet -f json --ref v20.1.1 https://github.com/juice-shop/juice-shop`.
  Public data only. Exercises passing (3), failing with and without `concerns`
  (3), errored (2), and an `Investigate` recommendation whose `reason` is the
  `{ "FailedAnalyses": [...] }` variant.

- **pass.json** — Real scan of this repository (`hc check -v quiet -f json .`),
  with the interactive progress preamble stripped. The six `mitre/affiliation`
  `concerns[]` strings have been anonymized (synthetic contributor names/emails)
  — the only change from the real output. Covers the `Pass` verdict, `reason:
  null`, and a passing `mitre/binary` analysis (paths `real.json` does not hit).
  Two analyses (`review`, `fuzz`) errored because a local target has no remote
  URL — real behavior, and useful error-path coverage.

- **empty.json** — A structurally valid report with empty `passing`/`failing`/
  `errored` arrays, to exercise the no-findings placeholder synthesizer. Derived
  from the real report shape (Hipcheck normally always runs analyses).
