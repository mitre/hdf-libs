# Publishing pipeline modernization — design plan

**Date:** 2026-04-25
**Status:** ready for execution **after** epic `hdf-libs-n1x2` (package-boundary drift) lands on main
**Tracking:** new beads epic on hdf-libs board (filed alongside this doc) — depends on `hdf-libs-n1x2`

---

## Problem

hdf-libs publishes manually from a maintainer's machine, with no CI publish gate, no version-coordination tooling, and no provenance attestation. Three concrete consequences:

1. **Downstream consumers can't safely consume hdf-libs `main` between releases.** When the package-boundary fix epic merges, Aesir Bifrost still has to wait for a manual `pnpm publish` before it can adopt the canonical `severityToImpact` / `impactToSeverity` utilities. Until then, downstream code maintains duplicates (acknowledged debt, not hidden hack).
2. **Cross-subpackage `workspace:^` deps don't survive any non-workspace install.** `hdf-schema` declares `"@mitre/hdf-utilities": "workspace:^"`. That literal string only resolves inside hdf-libs's own pnpm workspace. A git install of `hdf-schema` (or any consumer that doesn't have hdf-libs as a workspace) gets an unresolvable dep.
3. **No sigstore provenance attestation on published tarballs.** Modern npm consumers increasingly want to verify that a published artifact ties cryptographically to a specific GitHub Actions run. Without `--provenance` on publish, that chain is missing — and consumers downstream may have to add per-package trust exceptions when their toolchain expects attestation. (Real-world precedent: the chokidar 4.0.1 → 4.0.2 attestation gap caused months of npm/pnpm/yarn downstream pain — see `npm/cli#8018`, `paulmillr/chokidar#1440`.)

---

## Goal

After this work the publishing pipeline meets these criteria:

1. **Every published subpackage is self-contained.** Internal `@mitre/hdf-*` build-time deps are inlined; runtime-required deps (ajv, fast-xml-parser, etc.) stay external. The published tarball contains zero `workspace:` literals.
2. **Every merged PR triggers a publish-or-version-PR via changesets.** Maintainers add a changeset entry per PR; CI either publishes or opens a "Version Packages" PR.
3. **Every published artifact carries sigstore attestation.** Consumers can verify the tarball ties to a specific Actions run via `npm view <pkg> --json | jq .attestations`.
4. **Every publishable subpackage has a `prepare` script** so leaf packages (no internal cross-deps) are also git-installable as a side benefit. Smaller win, but cheap.
5. **The export-contract test from epic `hdf-libs-n1x2` runs as part of the publish gate**, alongside a new tarball-consume smoke test added by this epic.

---

## Scope boundaries

**IN scope:**
- `prepare` scripts on every publishable TS subpackage
- tsdown bundling configuration so internal `@mitre/hdf-*` deps inline into the tarball
- `changesets` adoption with a CI publish workflow
- sigstore provenance via `--provenance` + `id-token: write`
- a "consume from tarball" smoke test that simulates an external consumer

**OUT of scope (file separately if encountered):**
- Functional changes to any package's source
- Adding/removing exports (covered by `hdf-libs-n1x2`)
- Dual ESM/CJS publishing — currently ESM-only via `"type": "module"`; mention as future work
- `hdf-cli` Go publish flow — different channel (GoReleaser/binary releases), exclude via changesets `ignore`
- Renovate / Dependabot configuration
- README/CONTRIBUTING rewrites beyond the new changesets section

---

## The architectural decision: standardize on npm publish

Three options were considered. Capturing here so the question doesn't have to be re-litigated later.

| Option | What it means | Decision |
|---|---|---|
| **B1: Bundle internal `@mitre/hdf-*` deps via tsdown `noExternal`** | hdf-utilities' code is inlined into hdf-schema's `dist/` at build time. Each tarball self-contained. | **Accepted.** Modern norm in 2026 TS monorepos. Cost: minor code duplication in registry tarballs. |
| B2: Document npm publish as the only supported install path | Explicitly declare git installs unsupported for non-leaf subpackages. | Partial / complementary. Adopted alongside B1. |
| B3: Drop `workspace:^` for explicit version pins (`"^3.1.0"` directly) | Avoids the workspace-protocol issue at the source. | Rejected — loses workspace coordination, forces manual lockstep version bumps across subpackages. |

`prepare` scripts (Section 3 below) are added regardless of B1/B2/B3 — they're orthogonal and turn leaf subpackages git-installable for free.

---

## Strategy: TDD off main, after `hdf-libs-n1x2` merges

**Branch name:** `feat/publishing-pipeline`

Order matters — this branch must base off `main` *after* the package-boundary fix lands, otherwise the new publish-smoke test will conflict with the export-contract test from that epic.

---

## Step-by-step

### Step 1 — Write the publish-smoke test (fails on current state)

**File:** `test/publish-smoke.test.ts` at the repo root.

For each publishable subpackage (`hdf-utilities`, `hdf-schema`, `hdf-diff`, `hdf-mappings`, `hdf-converters`), post-build:

- `pnpm pack --pack-destination /tmp/hdf-pack/<pkg>` → produces a `.tgz`
- Create scratch project at `/tmp/hdf-smoke/<pkg>/`, init `package.json`, `npm install <abs path to tgz>`
- Read installed `node_modules/<pkg>/package.json` — assert no `workspace:` literals appear in `dependencies` or `peerDependencies`
- Dynamic `await import('<pkg>')` from a small `.mjs` script in the scratch project — assert it resolves and exports a non-empty module object
- For each subpath in the installed package's `exports` map (excluding `.` and `./package.json`), dynamic-import it — assert success and non-empty module

This test catches:
- `workspace:` literals leaking into published deps (today's blocker for hdf-schema)
- Missing `dist/` files referenced from `exports` map (overlap with `test:exports` from the prior epic — defense in depth)
- Broken bundling that makes a published package un-importable in a fresh-consumer context

Wired into npm scripts as `pnpm test:publish-smoke`. Runs in CI publish gate (Step 6).

### Step 2 — Run the test, verify it fails

`pnpm build && pnpm test:publish-smoke`. Expected: `hdf-schema` fails because the installed tarball's `dependencies` contain `"@mitre/hdf-utilities": "workspace:^"`. Other subpackages with no internal cross-deps may pass at this stage; that's fine — they'll get coverage from the smoke test even if they don't currently break.

If the test passes spuriously on hdf-schema, the test is wrong — fix the test before fixing the publishing pipeline.

### Step 3 — Add `prepare` scripts to every publishable subpackage

```json
"scripts": {
  "build": "tsdown",
  "prepare": "pnpm run build"
}
```

Touches: `hdf-utilities/package.json`, `hdf-schema/package.json`, `hdf-diff/package.json`, `hdf-mappings/package.json`, `hdf-converters/package.json`. (`hdf-cli` is Go — skip.)

`prepare` runs automatically on `npm install` from a git URL, on `pnpm pack`, and on `pnpm publish`. The dist/ is produced whenever the package is installed from source.

### Step 4 — Configure tsdown to bundle internal `@mitre/hdf-*` deps

In each subpackage's `tsdown.config.ts`:

```ts
import { defineConfig } from 'tsdown';

export default defineConfig({
  entry: ['src/index.ts', /* + subpath entries from epic hdf-libs-n1x2 */],
  format: ['esm'],
  dts: true,
  noExternal: [/^@mitre\/hdf-/],     // inline sibling workspace deps
  external: [/* runtime deps stay external — ajv, fast-xml-parser, etc. */],
});
```

Per-package, the `external` list reflects the actual runtime deps declared in `dependencies`. Don't blanket-exclude — pick deliberately. If a sibling `@mitre/hdf-*` is genuinely a runtime peer (rare; e.g. types-only re-exports), it can stay external by adding a more specific exclusion.

Verification per subpackage:
- `pnpm pack` → `tar -tf <tgz>` to inspect contents
- Unpack and grep `package.json` for `workspace:` — must not appear
- Grep installed `dist/index.js` for sibling-package import paths — they should be inlined, not requiring sibling at runtime
- Existing functional tests still pass (no behavioral change)

Re-run `pnpm test:publish-smoke`. hdf-schema now passes.

### Step 5 — Adopt `changesets`

```bash
pnpm add -Dw @changesets/cli
pnpm changeset init
```

Edit `.changeset/config.json`:

```json
{
  "$schema": "https://unpkg.com/@changesets/config@3.0.0/schema.json",
  "changelog": "@changesets/cli/changelog",
  "commit": false,
  "fixed": [],
  "linked": [],
  "access": "public",
  "baseBranch": "main",
  "updateInternalDependencies": "patch",
  "ignore": ["hdf-cli"]
}
```

Add to `CONTRIBUTING.md` (new file or new section):

```markdown
## Releasing

After making changes, run `pnpm changeset` and follow the prompts:
- Select affected packages (space to toggle, enter to confirm)
- Choose patch/minor/major per package
- Write a one-line summary of what changed

Commit the resulting `.changeset/*.md` file with your PR. CI will either
publish on merge to main, or open a "Version Packages" PR aggregating
unreleased changesets.
```

### Step 6 — Add the publish workflow

Create `.github/workflows/release.yml`:

```yaml
name: Release
on:
  push:
    branches: [main]
permissions:
  contents: write
  pull-requests: write
  id-token: write       # required for sigstore provenance
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: pnpm/action-setup@v3
      - uses: actions/setup-node@v4
        with:
          node-version: 22
          cache: pnpm
          registry-url: https://registry.npmjs.org
      - run: pnpm install --frozen-lockfile
      - run: pnpm build
      - run: pnpm test
      - run: pnpm test:exports        # from epic hdf-libs-n1x2
      - run: pnpm test:publish-smoke  # from this epic
      - uses: changesets/action@v1
        with:
          publish: pnpm changeset publish
          version: pnpm changeset version
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
          NPM_CONFIG_PROVENANCE: "true"
```

`NPM_CONFIG_PROVENANCE=true` is the env-var equivalent of `--provenance` and applies to every `pnpm publish` invoked by the changesets action. Combined with `id-token: write` on the job, sigstore attestation is generated automatically.

**Repository setup (Will or maintainer with admin access):**
- Add `NPM_TOKEN` secret to the repository (npm automation token, scope = `@mitre`)
- Verify GitHub branch protection on `main` allows the action to push (changesets opens "Version Packages" PRs back to main)

### Step 7 — Verify locally before merge

While the workflow file lives on the branch (won't fire until merged), verify the local end:

```bash
pnpm install
pnpm build
pnpm test:exports
pnpm test:publish-smoke
pnpm changeset                 # add a changeset for the publishing-pipeline change itself
pnpm changeset version --dry-run   # confirm version bumps look right
pnpm changeset publish --dry-run   # confirm publish would target the right packages
```

Manually pack one subpackage and inspect:
```bash
cd hdf-schema && pnpm pack && tar -tf mitre-hdf-schema-*.tgz | head -20
tar -xzf mitre-hdf-schema-*.tgz -C /tmp/extract
cat /tmp/extract/package/package.json | jq '.dependencies'
# Confirm: no "workspace:" literals
```

### Step 8 — PR

Conventional commits, one per logical step:

```
test(release): add publish-smoke test catching workspace: leak + missing dist
feat(release): add prepare scripts to publishable subpackages
feat(release): bundle @mitre/hdf-* internal deps via tsdown noExternal
feat(release): adopt changesets for version + publish coordination
ci(release): add publish workflow with sigstore provenance attestation
```

PR title: `feat(release): publishing pipeline modernization (changesets + provenance)`

Reference the prior epic in the PR body so the dependency chain is explicit.

### Step 9 — Post-merge verification

After Will configures `NPM_TOKEN`:

- Next merged PR carrying a changeset triggers the workflow
- Workflow either publishes (if `.changeset/*` files exist) or opens a "Version Packages" PR
- Once a real publish happens: verify attestation appears in `npm view @mitre/hdf-utilities --json | jq .attestations`
- Bifrost (and other downstream consumers) bump from interim workspace-link consumption to plain `^3.x` registry deps

---

## Acceptance criteria

- [ ] `pnpm test:publish-smoke` passes for every publishable subpackage
- [ ] No `workspace:` literals appear in any published tarball's `package.json`
- [ ] `prepare` script present in every publishable subpackage
- [ ] `.changeset/config.json` exists; `CONTRIBUTING.md` documents the changesets workflow
- [ ] `.github/workflows/release.yml` exists with `id-token: write` permission and `NPM_CONFIG_PROVENANCE=true` (or `--provenance` flag)
- [ ] First post-merge publish carries valid sigstore attestation (verify via `npm view`)
- [ ] `test:exports` from epic `hdf-libs-n1x2` continues to pass (no regression)
- [ ] No functional changes to any package source — diff is publishing infrastructure only

---

## Discipline (READ BEFORE STARTING)

This plan is publishing-pipeline only. Functional changes belong elsewhere.

1. **Don't expand scope.** If a packaging issue surfaces during this work that isn't in the IN-scope list above, file it as a separate issue and stop. (Same rule as the prior epic; same reasons.)
2. **Don't preempt the prior epic.** Start this branch only after `hdf-libs-n1x2` merges. Filing a publish-smoke test now would race with the export-contract test that epic adds, and the merges would conflict.
3. **Three-artifact rule still applies.** When tsdown config changes, `dist/` shape changes; if `dist/` shape changes, `package.json` `exports` may need adjustment. The exact bug class the prior epic fixed — don't recreate it here while working on bundling.
4. **TDD discipline.** Publish-smoke test fails first. If you find yourself adding `prepare` scripts or tsdown config changes before the test fails, stop — the test's job is to prove the regression won't recur. Cutting corners on the test is the original failure pattern recurring.
5. **Don't conflate "decided" with "executed" on the publish workflow.** The workflow file landing on `main` is decision-only; the first real publish is gated on Will adding `NPM_TOKEN`. Don't trigger a manual publish from a maintainer machine to "test" the flow before the secret is in place — that produces an attestation-less artifact and undermines the goal.

---

## Files this PR will touch

```
test/publish-smoke.test.ts                          # NEW — tarball-consume smoke test
hdf-utilities/package.json                          # add prepare script
hdf-utilities/tsdown.config.ts                      # add noExternal directive
hdf-schema/package.json                             # add prepare script
hdf-schema/tsdown.config.ts                         # add noExternal (key fix for workspace: leak)
hdf-diff/package.json                               # add prepare script
hdf-diff/tsdown.config.ts                           # add noExternal
hdf-mappings/package.json                           # add prepare script
hdf-mappings/tsdown.config.ts                       # add noExternal
hdf-converters/package.json                         # add prepare script
hdf-converters/tsdown.config.ts                     # add noExternal
package.json (root)                                 # add @changesets/cli devDep + test:publish-smoke script
.changeset/config.json                              # NEW — changesets configuration
.changeset/<auto-generated>.md                      # NEW — initial changeset for this PR itself
.github/workflows/release.yml                       # NEW — publish workflow
CONTRIBUTING.md                                     # add changesets contributor flow section
```

No other files. If you find yourself touching anything else, reconsider scope.

---

## Future work (out of scope; file separately if pursued)

- Dual ESM/CJS publishing (currently ESM-only via `"type": "module"`)
- Renovate or Dependabot config for automated dep updates
- npm package size budgets enforced in CI
- Per-package README.md regeneration at publish time
- Automated GitHub Releases creation from changesets (config option exists)
- `hdf-cli` Go binary release flow (separate channel — GoReleaser, GitHub Releases assets)

---

## References

- Prior epic: `hdf-libs-n1x2` — package-boundary drift fix (this epic depends on it)
- Prior plan: `docs/plans/2026-04-25-package-boundary-fix.md`
- changesets: <https://github.com/changesets/changesets>
- npm provenance: <https://docs.npmjs.com/generating-provenance-statements>
- chokidar provenance regression case study: `paulmillr/chokidar#1440`, `npm/cli#8018`, `npm/cli#8043`, `npm/cli#8144`
- pnpm publish + workspace protocol: <https://pnpm.io/cli/publish>
- pnpm package sources (git, link:, file:): <https://pnpm.io/package-sources>
- tsdown noExternal: <https://tsdown.dev/>
- Companion downstream consumer impact (Aesir Bifrost interim workaround): see master backlog on `aesirsystems/bifrost` board, card `bifrost-qvl`
