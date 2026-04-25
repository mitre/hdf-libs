# Package-boundary drift fix — design plan

**Date:** 2026-04-25
**Status:** ready for execution (separate Claude Code session, branch off `main`, TDD)
**Tracking:** beads epic in this repo (run `bd ready` to see) + upstream issues mitre/hdf-libs #43, #44, #45

---

## Problem

A class of bug exists across multiple hdf-libs packages where utilities are present in source, re-exported from the package's `src/index.ts`, but **unreachable from any external consumer of the published package**. Three coordinated artifacts have drifted:

1. `src/<category>/index.ts` — present
2. `tsdown.config.ts` `entry` array — missing the entry
3. `package.json` `exports` map — missing the subpath

When any of (2) or (3) is missing, the source-level re-export resolves to a non-existent module in dist, the function is excluded from the main-entry bundle, and the subpath import is blocked at runtime. Source-level tests (which import from `src/`) continue to pass, hiding the drift.

## Confirmed cases

| # | Package | What's unreachable | Issue |
|---|---|---|---|
| 1 | `hdf-utilities` | `severityToImpact` and `impactToSeverity` (in `src/severity/`) | mitre/hdf-libs#43 |
| 2 | `hdf-diff` | `matching/` and `renderers/` subdirs | mitre/hdf-libs#44 |
| 3 | `hdf-mappings` | 8 mapping subpaths: `awsconfig`, `cci`, `cwe`, `nessus`, `nikto`, `nist`, `owasp`, `scoutsuite` | mitre/hdf-libs#44 |
| 4 | `hdf-mappings` | Main entry — runtime fails with `ERR_IMPORT_ATTRIBUTE_MISSING` (separate bug, JSON imports missing `with { type: "json" }`) | mitre/hdf-libs#45 |

Bug #4 is a different bug class than #1-3 (JSON import attribute, not package-boundary drift) but lives in the same package and should be fixed together.

## Goal

Three outcomes after this work:

1. **All published packages have reachable, runtime-importable subpath exports** matching the contents of their `src/` and `dist/` directories.
2. **An automated export-contract integration test exists** that catches this bug class for any future change in any hdf-libs package.
3. **The known bugs (#43, #44, #45) are closed** with the test as the regression guard.

## Strategy: TDD off main

Branch off `main`. Write the test first; the test should fail in a way that surfaces all four known bugs. Fix one bug at a time; the test goes greener with each fix. Final state: clean test pass, all four bugs closed.

### Branch name

`fix/package-boundary-drift` (or per maintainer preference)

### Step-by-step

#### Step 1 — Write the export-contract test (fails on all 4 known bugs)

**File:** `test/export-contract.test.ts` at the repo root, OR per-package versions at `<pkg>/test/export-contract.test.ts`. Choose based on repo convention (root-level integration test is simpler).

**What it checks, per package, post-build:**

For each `src/<subdir>/index.ts` (excluding internal dirs like `test/`, `types/`, `helpers/`):
- Assert `tsdown.config.ts` `entry` array includes `src/<subdir>/index.ts`
- Assert `package.json` `exports` has a `./<subdir>` key
- Assert `dist/<subdir>/index.js` exists after build
- Assert `dist/<subdir>/index.d.ts` exists after build

For each subpath in `package.json` `exports` (excluding `.` and `./package.json`):
- Assert the resolved file path under the `import` condition exists
- Assert dynamic runtime import succeeds: `await import('@mitre/<pkg>/<subpath>')` returns a non-empty module
- Assert the imported module has at least one named export

For each main entry (`.`):
- Assert `dist/index.js` exists
- Assert dynamic runtime import succeeds: `await import('@mitre/<pkg>')` returns a non-empty module
- For each `export { x } from './<subdir>/...'` in `src/index.ts`, assert `x` is reachable in the runtime-imported module

Run this test in CI (add to existing test script or new `test:exports` script). It must run **after `pnpm build`**.

#### Step 2 — Verify the test fails as predicted

Run `pnpm build && pnpm test:exports` (or whatever the script ends up named). Expected failures:
- `hdf-utilities`: severity subpath, severity main-entry visibility
- `hdf-diff`: matching subpath, renderers subpath, matching/renderers main-entry visibility
- `hdf-mappings`: 8 mapping subpaths, main-entry runtime import (separate failure mode for #45)

If the test passes spuriously on any of these, the test is wrong — fix the test before fixing the bugs.

#### Step 3 — Fix #43 (hdf-utilities severity)

In `hdf-utilities/tsdown.config.ts`:
```ts
entry: [
  'src/index.ts',
  'src/json/index.ts',
  'src/hash/index.ts',
  'src/xml/index.ts',
  'src/csv/index.ts',
  'src/object/index.ts',
  'src/string/index.ts',
  'src/severity/index.ts',  // ADD
],
```

In `hdf-utilities/package.json` `exports`:
```json
"./severity": {
  "types": "./dist/severity/index.d.ts",
  "import": "./dist/severity/index.js"
},
```

Run `pnpm --filter @mitre/hdf-utilities build && pnpm test:exports`. Verify hdf-utilities tests now pass.

#### Step 4 — Fix #44 part 1 (hdf-diff matching + renderers)

In `hdf-diff/tsdown.config.ts` (create if missing — `hdf-diff` does not currently have one based on the scan; investigate what builds it):
- Ensure `entry` includes `src/index.ts`, `src/matching/index.ts`, `src/renderers/index.ts`, plus any other top-level src files (`src/diff.ts`, `src/normalize.ts`, etc.)

In `hdf-diff/package.json` `exports`:
```json
"./matching": { "types": "./dist/matching/index.d.ts", "import": "./dist/matching/index.js" },
"./renderers": { "types": "./dist/renderers/index.d.ts", "import": "./dist/renderers/index.js" }
```

Build + test. Verify hdf-diff tests now pass.

#### Step 5 — Fix #44 part 2 (hdf-mappings 8 subpaths)

`hdf-mappings/dist/` already contains the subdirectories, so the build config is already producing them via some mechanism. Likely need only the `package.json` `exports` updates:

```json
"./awsconfig": { "types": "./dist/awsconfig/index.d.ts", "import": "./dist/awsconfig/index.js" },
"./cci":       { "types": "./dist/cci/index.d.ts",       "import": "./dist/cci/index.js" },
"./cwe":       { "types": "./dist/cwe/index.d.ts",       "import": "./dist/cwe/index.js" },
"./nessus":    { "types": "./dist/nessus/index.d.ts",    "import": "./dist/nessus/index.js" },
"./nikto":     { "types": "./dist/nikto/index.d.ts",     "import": "./dist/nikto/index.js" },
"./nist":      { "types": "./dist/nist/index.d.ts",      "import": "./dist/nist/index.js" },
"./owasp":     { "types": "./dist/owasp/index.d.ts",     "import": "./dist/owasp/index.js" },
"./scoutsuite":{ "types": "./dist/scoutsuite/index.d.ts","import": "./dist/scoutsuite/index.js" }
```

Build + test. Verify hdf-mappings subpath assertions pass. Main-entry will still fail (#45), expected.

#### Step 6 — Fix #45 (hdf-mappings main-entry import attribute)

This is a different bug class. Find every `.json` import in `hdf-mappings/src/**/*.ts`. Add the `with { type: "json" }` attribute:

```ts
// before
import data from './data/cci.json';

// after
import data from './data/cci.json' with { type: 'json' };
```

Verify `tsconfig.json` (and the build's TS settings) preserve the attribute through compilation. TypeScript 5.3+ + tsdown should handle it correctly when targeting Node 22+.

Build + test. Verify hdf-mappings main entry now imports successfully at runtime.

#### Step 7 — Audit other packages (preventive sweep)

For each remaining package — `hdf-cli`, `hdf-converters`, `hdf-extension-graph`, `hdf-generators`, `hdf-parsers`, `hdf-schema`, `hdf-validators` — run the export-contract test. Some packages don't have the `src/<subdir>/` pattern (single-entry) and the test should pass naturally. Others may surface new findings — handle each as discovered.

If any new bug surfaces, file an issue or extend the existing fix scope. Either way, the test ensures no silent drift remains.

#### Step 8 — Final verification

```bash
pnpm build               # all packages
pnpm test                # full test suite
pnpm test:exports        # the new contract test
pnpm lint                # no new warnings
```

Smoke test from a fresh consumer perspective:

```bash
# In a temp scratch dir outside the repo
mkdir /tmp/hdf-smoke && cd /tmp/hdf-smoke
npm init -y
npm install file:/Users/alippold/github/mitre/hdf-libs/hdf-utilities  # or however the workspace publishes
node -e "import('@mitre/hdf-utilities/severity').then(m => console.log(Object.keys(m)))"
# Expect: ['severityToImpact', 'impactToSeverity']
```

Repeat per fixed package.

#### Step 9 — Commit and PR

Conventional commits, one per logical fix:

```
test(exports): add export-contract test that catches package-boundary drift
fix(hdf-utilities): expose severity subpath (closes #43)
fix(hdf-diff): expose matching and renderers subpaths (#44)
fix(hdf-mappings): expose 8 mapping subpaths (#44)
fix(hdf-mappings): add 'with { type: json }' to JSON imports (closes #45)
```

PR title: `fix: close package-boundary drift across hdf-libs (#43, #44, #45) + add regression test`

Close all three issues from the PR.

## Acceptance criteria

- [ ] `pnpm build && pnpm test:exports` passes with zero failures
- [ ] All four bugs (#43, #44, #45 — issue 45 covers two distinct concerns in hdf-mappings) verifiably fixed at runtime via fresh-consumer smoke tests
- [ ] No new bugs introduced in other packages — preventive sweep clean
- [ ] CI runs the export-contract test on every PR
- [ ] Conventional commits, clean PR diff, no scope creep beyond the three issues + the test infrastructure

## Discipline (READ BEFORE STARTING)

This plan was written after a session where the same incomplete-loop pattern that produced these bugs in code form also blew up in chat. Three rules to enforce:

1. **Three-artifact rule (always).** Whenever you add or modify a `src/<subdir>/index.ts`, also touch `tsdown.config.ts` AND `package.json` exports. The export-contract test will catch you if you forget — but don't rely on the test as the only safeguard. Explicit is better than caught.

2. **Don't expand scope.** This plan covers issues #43, #44, #45 + the regression test. If a different bug surfaces during the sweep (Step 7), file it and stop — do NOT silently roll it into this PR. Decided scope > momentum.

3. **TDD discipline.** Test must fail first. If you find yourself writing fix code before the test fails, stop. The reason to write the test first is that it's the ONLY artifact that will catch this bug class going forward. Cutting corners on the test is the original sin recurring.

## Files this PR will touch

```
test/export-contract.test.ts                        # NEW — the regression test
hdf-utilities/tsdown.config.ts                      # add entry
hdf-utilities/package.json                          # add exports
hdf-diff/tsdown.config.ts                           # may need creation; ensure entries
hdf-diff/package.json                               # add exports
hdf-mappings/package.json                           # add 8 subpath exports
hdf-mappings/src/**/*.ts                            # JSON import attributes
package.json (root)                                 # add `test:exports` script if needed
.github/workflows/*.yml                             # ensure new test runs in CI
```

No other files should be touched. If you find yourself touching anything else, reconsider scope.

## References

- Companion local memory: `bd memories hdf-libs-package-three-artifact-rule`
- Companion bug list: `bd memories hdf-libs-known-bugs-2026-04-25`
- Companion build tooling: `bd memories hdf-libs-build-tooling`
- Issues: mitre/hdf-libs#43, #44, #45
- Source of bug class: same incomplete-loop pattern documented in Aesir-side feedback memories `feedback-package-boundary-three-artifacts`, `feedback-learn-form-before-output`, `feedback-deliverable-not-meta-plan`. Read them before starting if you have access to global beads memories (`bd memories --global`).
