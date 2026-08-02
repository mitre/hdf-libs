---
description: Prepare the monorepo for a release. Runs a pre-release multi-agent swarm review (security / DRY / TS / Go / cross-PR), then for minor/major bumps sweeps every version-bearing file (package.json, go.mod, schema $id URLs, version-claiming docs) and propagates schema content into the spec, and finally reconciles the beads board and GitHub issues. Use for any version bump ("prep a 3.3.1 patch", "cut a 3.4.0 release", "cut 4.0.0").
allowed-tools: Read, Glob, Grep, Bash, Edit, Write, AskUserQuestion, Workflow, Agent
---

## When to use this skill

Run this skill whenever the workspace is moving to a new version. The monorepo uses **unified lockstep versioning**: every workspace package and every Go cross-module require moves to the same new version, and for minor/major bumps every schema `$id` URL moves with them. Drift between any of those is a release bug.

**Tier determines how much of the middle runs:**

- **Minor / major** (`3.2.0 → 3.3.0`, `3.x → 4.0`) — the full skill: schema `$id`s bump, the site archive gains a new version, version-claiming docs and the spec are swept, and (for minors that add fields) schema content is propagated into the spec.
- **Patch** (`3.2.0 → 3.2.1`) — the schema did not change, so its `$id` URLs **stay** at the old version (publishing an identical bumped schema would be dishonest) and the doc/archive/spec phases (Phases 2–4) **do not apply**. A patch bumps only the workspace `package.json` files + `go.mod` requires and finalizes the CHANGELOG.

**Phase 1 (swarm review), Phase 1.5 (pre-release bead reconciliation), and Phase 9 (release-time GitHub-issue reconciliation) run for *every* release, patch included.** Only the mechanical sweep and content phases are tier-gated.

**Bead vs. GitHub-issue closing policy (two different clocks):**
- **Beads close when their fix is *merged* (delivered), not when the release ships** — reconciled in Phase 1.5 as a pre-release step so the board shows only work that still genuinely needs addressing *before* cutting the release.
- **GitHub issues close when the release *ships*** — reconciled in Phase 9 after publish, so external watchers see "Resolved in vNEW." This is why we use `Refs #N` (never auto-closing `Closes #N`).

The current ("from") version is whatever the workspace `package.json` files agree on; mismatch between them means a prior release was incomplete and is itself a finding (treat as a separate cleanup before bumping).

## Version-bump policy (project rule)

The bump tier is determined by **what changed in the schema**, not by feature volume or perceived impact:

- **Schema changed in any way** (new field, new enum value, new `$defs` type, modified validation, modified `$id` URL) → **minor bump** (`3.x.0`). Schema changes are forwards-compatible by default but may break consumers that did exhaustive type matching, so they're always at least a minor.
- **No schema changes** (converter additions/fixes, CLI work, docs, fetcher additions, dep bumps, refactors) → **patch bump** (`3.x.y`). Even substantial feature work — and even a consumer-visible *behavior* change that does not touch the schema — is a patch by this project's convention (early-stage; breaking behavior changes have shipped as patches before, with a prominent CHANGELOG call-out). When a patch carries a behavior change, say so loudly in the CHANGELOG rather than escalating the tier.
- **Major bump** (`4.0.0` and up) → **only when the user explicitly says so**. Do not infer a major bump from breaking changes, removed features, or `!` markers in commit messages. If you see signs of a breaking change and the user hasn't said "major," surface it as a question (could this be a patch/minor with a breaking-change call-out instead?) — don't unilaterally jump to a major.

Practical signal at Phase 0:

```bash
# Did anything under hdf-schema/src/schemas/ change since the last release tag?
git diff --name-only "$(git describe --tags --abbrev=0)..HEAD" -- hdf-schema/src/schemas/
# If output is non-empty → minor.
# If output is empty → patch (or skip this skill entirely).
```

Even within "minor," walk the schema diff before settling on the tier — a single new optional field is a minor; a removed `$defs` type or tightened required-list might warrant the user-flagged major.

## Lessons learned from prior releases

These are the traps this skill exists to prevent. Real failure modes from the 3.2.0 release:

1. **Only the schema bumped.** `hdf-schema/package.json` and the seven schema `$id` URLs moved to 3.2.0, but the other nine workspace packages and every `go.mod` require line stayed at the old version. Result: schema released as 3.2.0, consumers shipped as 3.1.1.
2. **A README claimed the wrong version.** Root `README.md` said *"All schemas are at v3.1.0"* after schemas had moved to 3.2.0 — a flat-out wrong claim that survives unless you sweep for current-version assertions, not just literal old-version strings.
3. **The formal spec doc lagged the schema.** `site/docs/specification/hdf-specification.md` titled itself "v3.1.0 Specification", carried six stale `Schema ID:` URLs, AND was missing the new requirement fields entirely. A version-string substitution would have caught the URLs but left the canonical spec missing the content it's supposed to describe.
4. **`$ref` URI pattern examples in `site/docs/contributing/developer-guide.md` froze at the version they were written against.** These are shown as the canonical lookup pattern, not historical examples, so they need to track the current schema version.
5. **`go.work.sum` churn appears mid-release.** The Go toolchain speculatively adds checksum entries (`golang.org/x/sys`, AWS SDK, etc.) during builds. These are NOT part of the release — exclude them from the commit.
6. **Historical CHANGELOG entries are NOT version-string substitutions.** Lines like `## [3.1.0]` or `Schema version bumped from v3.0.0 to v3.1.0` are factual history. Touching them rewrites the past.
7. **Cross-library duplication slips in via agent-swarm work.** New code re-implements a function that already exists in a shared package instead of importing it (the architecture's single most common violation). Phase 1's DRY review exists to catch this before it ships.
8. **READMEs drift silently from the CLI/API they document.** `hdf-cli/README.md` documented removed `info`/`stats` commands and the old `hdf list <what> <file>` syntax long after the CLI folded those into `hdf list <file> --detail`; `hdf-diff/README.md` documented a non-existent `--mode baseline` flag. This drift is **not diff-scoped** — it predates the release window and survives any review that only looks at `BASE..HEAD`. Phase 1's docs-accuracy dimension checks each README against the *actual* current command/flag surface, not just what changed.

## Execution

### Phase 0 — Confirm scope

1. Determine `OLD_VERSION` by reading `hdf-schema/package.json` → `version`. Confirm with the user if it doesn't match the other workspace `package.json` files (drift = pre-existing bug, surface before continuing).
2. **Compute the recommended tier from the schema diff** before asking the user. Run:
   ```bash
   git diff --name-only "$(git describe --tags --abbrev=0)..HEAD" -- hdf-schema/src/schemas/
   ```
   - Non-empty → minor (next `3.x.0`). Recommend that to the user.
   - Empty → patch (next `3.x.y`). Recommend patch; the mechanical sweep / archive / doc / spec phases will be skipped.
   - **Never recommend a major bump.** Per project rule, major bumps happen only when the user explicitly says "this is a major." If the user picks major without saying so, ask them to confirm.
3. Ask the user for the target version, presenting the schema-diff-derived recommendation as the default. Capture it as `NEW_VERSION`. A consumer-visible behavior change with no schema change is still a patch by default — confirm the user wants to escalate before treating it as a minor.
4. Record `BASE=$(git describe --tags --abbrev=0)` (last release tag) — Phase 1 reviews everything from `BASE` to `HEAD`.

### Phase 1 — Pre-release swarm review (release gate)

Before touching any version, run a multi-agent review of everything merged since the last release. **This repo's most frequent defect is cross-library duplication** — agent swarms re-implementing logic that already exists in a shared package (`hdf-utilities`, `hdf-converters/shared`, `hdf-mappings`, `hdf-parsers`) instead of importing it, violating the import-don't-duplicate architecture. The review is a **gate**: critical/high findings block the release until fixed or explicitly waived by the user.

**Scope**
- Primary: `git diff BASE..HEAD` (file list: `git diff --name-only BASE..HEAD`).
- DRY/architecture additionally compares new code against the **whole shared surface**, not just the diff — a re-implementation is a finding even if the duplicated original is untouched.
- Cross-PR: enumerate everything merged since `BASE` (`git log BASE..HEAD --oneline`, PR refs in subjects).

**The six dimensions**
1. **Security** — every converter calls `ValidateJSONSize`/`ValidateXMLInput` as its first op; entity-expansion guards on XML; `safePath()` on JSON-derived file paths; `LimitSliceWithWarning`/`limitArrayWithWarning` on unbounded input arrays; no secrets; `gosec`/`govulncheck` deltas vs. `BASE`; injection/traversal.
2. **DRY / cross-library duplication (weighted heaviest).** For each new/changed function, ask: does an equivalent already exist in a shared package? Hotspots to check against: severity↔impact (`hdf-utilities/severity`), timestamp parse/normalize (`hdf-utilities`, `hdf-parsers.normalizeTimestamps`), CWE/CCI/NIST mapping (`hdf-mappings`), checksum/integrity + JSON-size/XML validation + HTML strip + CWE→NIST + control-type derivation (`hdf-converters/shared`), CVSS. Also flag a Go or TS converter that re-implements logic its language-peer or shared builder already owns (the legacyhdf/checklist class of divergence). Every hit = a finding citing the exact existing symbol to import.
3. **TypeScript best practices** — no unjustified `any`/`as`; exhaustive switches; no floating promises; ESM import correctness; closed-shape outputs (no schema-invalid passthroughs); matches the eslint config's intent.
4. **Go best practices** — error wrapping (`%w`), no swallowed errors, `omitempty` consistency, struct-tag correctness, context usage, no goroutine leaks; matches the 39-linter `golangci-lint` intent.
5. **Cross-PR consistency & regression** — for the PRs merged since `BASE`: did any two touch the same area inconsistently? Are shared-code changes reflected in *all* consumers? Is Go↔TS parity preserved where both exist? Did any PR reintroduce something another removed, or silently regress a third? **Do NOT flag the CHANGELOG as missing/out-of-date — the new-version section is authored later, in Phase 5, so its absence at review time is by design, not a finding.** The one CHANGELOG-adjacent thing worth surfacing is a *consumer-visible behavior change* that Phase 5 must call out loudly (report it as a low-severity note so Phase 5 remembers it — not as a blocking gap).
6. **Docs / README accuracy (full-surface, not diff-scoped).** For every package `README.md` (root, `hdf-cli`, `hdf-diff`, and each `@mitre/hdf-*` package), verify what it documents still matches reality: every documented command/subcommand and flag actually exists in the current CLI (`hdf <cmd> --help`) or public API; no *removed* command or renamed syntax is still shown; example invocations use real flags; and any embedded example output is faithful to a real run (statuses, counts, column headers, summary lines — not fabricated or stale). Because drift here predates the release window, this dimension inspects the **current** binary/API surface, not just `BASE..HEAD`. Every mismatch = a finding naming the README, the stale claim, and the correct current form.

**Orchestration** — use the `Workflow` tool (this instruction is the multi-agent opt-in). Fan out one finder per dimension (shard dimension×package when the diff is large), adversarially verify each finding with an independent skeptic prompted to *refute* (drop unless it survives — this kills best-practice nitpicks and hallucinated issues), then synthesize a deduped report grouped by dimension and severity. Pass `BASE`, the changed-file list, and the PR list in via `args`. Skeleton:

```js
export const meta = {
  name: 'pre-release-review',
  description: 'Pre-release swarm review: security, DRY, TS/Go best practices, cross-PR consistency',
  phases: [{ title: 'Review' }, { title: 'Verify' }],
}
const FINDINGS = { type: 'object', required: ['findings'], properties: { findings: { type: 'array',
  items: { type: 'object', required: ['severity', 'file', 'description'], properties: {
    severity: { enum: ['critical', 'high', 'medium', 'low'] },
    file: { type: 'string' }, line: { type: 'number' },
    description: { type: 'string' }, suggestedFix: { type: 'string' },
    existingSymbol: { type: 'string' } } } } } }   // DRY: the symbol that should have been imported
const VERDICT = { type: 'object', required: ['real'], properties: { real: { type: 'boolean' }, why: { type: 'string' } } }

const ctx = `Changes since ${args.base}. Changed files:\n${args.files.join('\n')}`
const DIMENSIONS = [
  { key: 'security', prompt: `${ctx}\n\nReport SECURITY issues (input-size/XML validation as first op, entity expansion, safePath, unbounded slices, secrets, injection, govulncheck/gosec deltas).` },
  { key: 'dry',      prompt: `${ctx}\n\nReport cross-library DUPLICATION: new code re-implementing functionality that already exists in hdf-utilities / hdf-converters/shared / hdf-mappings / hdf-parsers (or a Go/TS converter diverging from its shared builder or language-peer). For each, name the existing symbol that should be imported. Inspect the shared packages, not just the diff.` },
  { key: 'ts',       prompt: `${ctx}\n\nReport TypeScript best-practice violations in the changed .ts files (unjustified any/as, non-exhaustive switch, floating promises, bad ESM imports, schema-invalid passthroughs).` },
  { key: 'go',       prompt: `${ctx}\n\nReport Go best-practice violations in the changed .go files (unwrapped/swallowed errors, omitempty drift, struct-tag errors, context misuse, goroutine leaks).` },
  { key: 'crosspr',  prompt: `${ctx}\n\nPRs merged since ${args.base}:\n${args.prs}\n\nReport cross-PR inconsistencies/regressions: same area touched inconsistently, shared-code change not reflected in all consumers, broken Go/TS parity, one PR reverting/regressing another. Do NOT report a missing or out-of-date CHANGELOG — its new-version section is written later in Phase 5, so its absence now is expected. The only CHANGELOG-adjacent finding worth raising is a consumer-visible BEHAVIOR CHANGE Phase 5 must document loudly — report that as a low-severity note, not a blocking gap.` },
  { key: 'docs',     prompt: `Ignore the diff scope for this one — audit the CURRENT state. For every package README.md (root, hdf-cli, hdf-diff, each @mitre/hdf-* package), verify documented commands/subcommands/flags still exist in the real CLI (build ./hdf and run 'hdf <cmd> --help') or public API, that no removed/renamed command or syntax is still shown, and that any embedded example output is faithful to a real run (status labels, counts, headers, summary lines). Report each mismatch with the README path, the stale claim, and the correct current form.` },
]

phase('Review')
const reviewed = await pipeline(
  DIMENSIONS,
  d => agent(d.prompt, { label: `review:${d.key}`, phase: 'Review', schema: FINDINGS }),
  (r, d) => parallel((r?.findings ?? []).map(f => () =>
    agent(`Adversarially verify this ${d.key} finding — try to REFUTE it; set real=false if uncertain or if it is a stylistic nit:\n${JSON.stringify(f)}`,
          { label: `verify:${d.key}`, phase: 'Verify', schema: VERDICT })
      .then(v => ({ ...f, dimension: d.key, confirmed: v?.real === true })))),
)
return { confirmed: reviewed.flat().filter(Boolean).filter(f => f.confirmed) }
```

**Gate & output**
- Emit the confirmed findings (dimension × severity). Present to the user.
- **Block the version bump on unresolved critical/high findings.** Fix them (re-run the affected `pnpm check` slice), then continue. Medium/low: the user decides — fix now, file a bead, or waive with a one-line rationale recorded in the release notes.
- Deferred findings → `bd create` beads, linked in the response.
- This phase produces no version edits; it only gates and (optionally) drives fixes.

### Phase 1.5 — Pre-release bead reconciliation (close delivered beads)

Beads close when their fix is **merged**, not when the release ships — do this as a pre-release step so the board reflects only work that still genuinely needs addressing *before* the release. (GitHub issues are the opposite clock — Phase 9, at publish.)

1. `bd dolt pull`.
2. Build the delivered set: `git log BASE..HEAD` (merged since the last tag) plus any fix commits this release's own prep just produced (Phase 1). Note the `#N` / `hdf-libs-xxxx` refs.
3. Walk every **open / in_progress** bead and check it against the *actual delivered code on this branch* — not the card's status, and not its title. `in_progress` cards are the highest-suspicion for done-but-not-closed (a fix merged but the card was never moved). Verify the deliverable is really present (grep the code / read the diff) before closing — never close on a title match alone.
4. Close each genuinely-delivered bead citing the delivering PR/commit: `bd close <id> -r "Delivered by #N (<commit>); shipping in vNEW."`.
5. Leave genuinely-open work open. **Do not close** a bead just because it is adjacent to a shipped PR — a symptom fix does not close the deeper follow-up card (e.g. a converter bug fix does not close its test-strategy hardening card).
6. `bd dolt push`.

Then present a one-line-per-card summary of what remains open, grouped by whether it is a **release-blocking bug** vs. **patchable / enhancement / future** — this is the "what's left before we can cut the release" view. Only genuine correctness regressions in *this release's* surface should block; pre-existing narrow bugs and hardening/enhancement cards are candidates for a fast-follow patch series, at the user's call.

### Phase 1.6 — Suppression & deferral review (retire what's no longer needed)

The repo carries several **deliberate-suppression / "don't-bump" mechanisms**, each valid when added but each with a *condition under which it should be revisited* — and nothing else tracks those conditions, so they silently rot (a pinned "patched" version becomes the new vulnerable floor; a suppressed advisory that now has a fix stays suppressed; an ignore rule outlives the incompatibility that motivated it). The release is the periodic checkpoint. Walk each system and either confirm it's still needed or retire/refresh it — this phase runs for **every** release, patch included.

1. **`pnpm-workspace.yaml` `overrides`** (forced transitive versions for the security gate). Re-run `pnpm audit --prod --audit-level=moderate` and `pnpm audit --dev --audit-level=high`; for each pinned override confirm it's still the advisory's *current* patched floor (an escalated advisory turns the pin itself into the vulnerable floor). Bump stale pins, verifying the target version actually exists on the registry. Full procedure: `site/docs/contributing/developer-guide.md` → Dependency Audit Overrides.
2. **`pnpm-workspace.yaml` `auditConfig.ignoreGhsas`** (suppressed advisories). For each GHSA, check whether a patched version now exists; if so, drop the suppression and take the fix instead.
3. **`.github/dependabot.yml` `ignore` rules** (held bumps). For each rule, check whether its blocking condition still holds (e.g. a `typescript` major hold is gated on typescript-eslint adding support — `typescript-eslint#10940`). Lift the rule once the condition clears so the bump can flow.
4. **Spot-check code-level suppressions** *(lighter touch — these track the code, so only sweep when the diff touched them)*: `//nolint` (Go) and `/* c8 ignore */` (TS) directives added since `BASE` — confirm each still describes a genuinely-unreachable or justified case, not a masked new gap.

Retirements are their own small commits/PRs (they change behavior — a dropped override or lifted ignore can surface a real advisory or bump), not folded into the version-bump commit. Anything that can't be retired yet: leave it, and note the still-blocking condition so the next release re-checks it.

### Phase 1.7 — Vendored external-schema freshness *(minor/major only)*

Converters that emit a format with a published schema validate their output
against a **vendored copy** of that schema (see `converters/*/schemas/` and
sibling `*/fixtures/*schema*.json`, each with a `PROVENANCE.md`). Vendoring keeps
the tests hermetic and pins validation to the exact schema version the converter
claims — but the copy can drift from upstream. This phase is the checkpoint.
**Minor/major only** — the schemas don't change between patches, so this must not
hold up a patch release.

For each vendored external schema (JSON Schema or XSD) with a `PROVENANCE.md`:

1. Re-fetch the pinned source URL and compare its SHA-256 against the value
   recorded in the schema's `PROVENANCE.md`.
2. **Match** → still current; done.
3. **Mismatch** → upstream changed the artifact in place. Investigate: for a
   *versioned* spec (XCCDF 1.2, OSCAL 1.1.2, CSAF 2.0) an in-place change is rare
   and worth scrutiny; for a date-stamped one (e.g. FIRST.org CVSS) it may be a
   routine re-stamp. Refresh the vendored file, re-run that converter's
   output-validation test, re-apply any local edits the provenance documents
   (e.g. XCCDF `schemaLocation` rewrites), and update the recorded SHA-256.
4. **Fetch fails / URL moved** → note it; the pin still validates offline, but
   record the new canonical URL in `PROVENANCE.md`.

A drift or a new upstream schema version can surface real converter
conformance gaps — treat any resulting fix as its own commit, not folded into the
version bump. If nothing drifted, this phase is a no-op confirmation.

### Phase 2 — Mechanical version sweep *(minor/major only)*

> **Patch:** edit only the workspace `package.json` versions and `go.mod` requires (rows 1–2 and 4 below). Leave schema `$id` URLs at `OLD_VERSION` — the schema didn't change — and skip Phases 2.5–4 entirely.

These edits are uniform across the workspace and safe to script. Use a small Python script (per [global Memory guidance](#)) for the bulk substitutions — `sed` invocations can clobber unrelated `3.x.y` substrings in fixture files.

**Targets:**

| File pattern | What to change |
|---|---|
| Workspace `package.json` (9 files: `hdf-cli`, `hdf-converters`, `hdf-diff`, `hdf-extension-graph`, `hdf-generators`, `hdf-mappings`, `hdf-parsers`, `hdf-utilities`, `hdf-validators`) | `"version": "OLD"` → `"version": "NEW"` |
| `hdf-schema/package.json` | Same |
| `hdf-schema/src/schemas/*.schema.json` (7 root schemas) | `"$id"` URLs ending in `/vOLD` → `/vNEW`. Also any `$ref` URLs in primitives that quote a version path. |
| Cross-module `go.mod` requires (`hdf-converters/go.mod`, `hdf-cli/go.mod`, `hdf-diff/go/go.mod`, `hdf-parsers/go/go.mod`, `hdf-generators/go/go.mod`) | Lines matching `github.com/mitre/hdf-libs/<x>/v3 vOLD` → `vNEW`. Regex: `s/(hdf-libs/[^ ]+) vOLD/$1 vNEW/g` |

Use `git status` after the script run to spot-check no `node_modules`, `dist/`, or `.git/` paths got touched.

### Phase 2.5 — Site archive: stage the new version's raw schema files *(minor/major only)*

The docs site at mitre.github.io/hdf-libs/ archives every released schema version under `site/public/schemas/<name>/v<X.Y.Z>/index.json`. The archive backs both the canonical `$id` URL (consumers fetching `.../schemas/hdf-amendments/v3.2.0/` get the right file forever) and the per-version rendered docs at `/v3.2.0/schemas/`. New version files for THIS release must be added to the archive as part of this commit.

```bash
# Rebuild bundled schemas at the new version
cd hdf-schema && pnpm build:schemas && cd ..
# Generator writes the current version's archive entries as a side effect
cd site && pnpm generate && cd ..
# Confirm the new files appear (7 schemas × 1 new version dir each)
ls site/public/schemas/*/v$NEW/index.json
# Stage them with the rest of the release commit
git add 'site/public/schemas/*/v$NEW/'
```

If you forget this step, the archive 404s as soon as the next release ships and the rendered v$NEW snapshot is missing from the docs site. The site `pnpm exec vitepress build` smoke job in `ci.yml` won't catch this (it builds whatever's on disk locally) — only the post-deploy archive coverage suffers. Treat it as a release-time checklist item.

### Phase 3 — Current-version doc sweep *(minor/major only)*

These claims are not URL-pattern uniform — they're prose ("All schemas are at vX") or pedagogical examples. Each must be inspected. Verified targets:

| File | What to look for |
|---|---|
| `README.md` (root) | Any *"schemas are at vX"* / *"current schema vX"* / *"latest vX"* sentences. Update to NEW. |
| `site/docs/specification/hdf-specification.md` | (a) **Document title** (line 1) `# Heimdall Data Format (HDF) vX Specification`. (b) **Version metadata** (`**Version**: X`). (c) **Every `**Schema ID**: …/vX` line** — there's one per top-level document type (currently 6: results, baseline, system, plan, amendments, comparison). |
| `site/docs/contributing/developer-guide.md` | `$ref` URI pattern examples (currently around line 143). These show the canonical URL pattern, not historical examples, so they bump. |
| `hdf-cli/README.md` | Archive-naming example `hdf_<version>_<os>_<arch>.tar.gz (e.g., hdf_X_darwin_arm64.tar.gz)`. Bump the example. |
| `hdf-schema/README.md` | **Add a new `### What's new in vNEW` subsection** above the existing `### What's new in vOLD`. Keep the old "What's new" sections — they're historical. |
| `CLAUDE.md` (root) | Any field annotations marked `*(vX)*` are historical and stay. New 3.2-style annotations for fields added in this release should be added if applicable. |

**Search command to spot anything missed:**

```bash
grep -rnE "v?OLD_VERSION_REGEX\b" --include="*.md" --include="*.yml" --include="*.yaml" . \
  | grep -v node_modules | grep -v "/dist/" | grep -v ".vitepress/cache" \
  | grep -v "CHANGELOG.md"  # historical entries stay
```

For every hit: decide if it's a *current-version claim* (bump) or *historical record* (leave).

### Phase 4 — Schema content propagation to the spec doc *(minor/major only)*

This is the step that the 3.2.0 release missed. **The formal spec doc must list the same fields the schema does.** For minor releases that add new fields, the workflow is:

1. `grep` the schema source (`hdf-schema/src/schemas/primitives/*.json` and the root schemas) for fields added since OLD.
2. For each new field, identify which `$defs` type it lives on (commonly `Requirement_Core`, `Override_Type`, etc.).
3. In `site/docs/specification/hdf-specification.md`, find every spec-doc table that documents that `$defs` type. Some types appear in multiple tables (e.g. `Requirement_Core` fields surface in BOTH `Evaluated_Requirement` and `Baseline_Requirement`).
4. Add a new row per new field: `| name | TypeName | no | one-line description |`. Use the same type-name convention the table already uses (PascalCase without `_Enum` suffix — e.g. `Severity`, `ControlType`, not `Severity_Enum`).
5. Update field-set-overview prose anywhere it enumerates the fields explicitly.

For removed/deprecated fields, the same walk applies in reverse: remove the row, add a CHANGELOG migration note.

### Phase 5 — CHANGELOG

1. Open `CHANGELOG.md`. Insert a new `## [NEW_VERSION] - YYYY-MM-DD` block at the top (rename the existing `## [Unreleased]` block if the changes are already drafted there).
2. **Actively derive the breaking changes — do not leave them implied by the version bump.** A minor bump signals *"the schema changed"* but never explains *what broke*; that explanation is this section's job, and consumers cannot infer it from a version number. Walk the diff since `BASE` and enumerate every change that could break a downstream consumer, **excluding genuinely new/additive features** (a new optional field or new converter is a New Feature, not a breaking change). Concretely, treat as breaking and explain each in plain English (what changed, why, and the migration): schema field renames or removals; enum value removals; tightened/added validation (previously-valid docs now rejected); changed defaults; renamed/re-numbered CLI flags, arguments, or version identifiers; changed output shape or semantics of an existing command; and any consumer-visible behavior change (even one shipping in a patch). If the walk finds none, state "No breaking changes" explicitly rather than omitting the section. Sources for the walk: `git diff BASE..HEAD -- hdf-schema/src/schemas/`, the Phase 1 crosspr behavior-change note, and CLI help/output deltas.
3. Sections to fill in (skip empty ones, but never skip Breaking Changes silently — see step 2):
   - **New Features**
   - **Breaking Changes / Notable behavior changes** (each item explained, not just named: field renames, enum removals, schema-validation tightening, changed defaults, renamed/re-numbered CLI flags or version identifiers, changed command output/semantics — *and* any consumer-visible behavior change shipping in a patch, prominently).
   - **Architecture Changes** (for minor/major, note the schema `$id` bump explicitly: *"Schema version bumped from vOLD to vNEW across all `$id`/`$ref` URLs"*).
   - **Compatibility** (state backward-compat posture; "v(OLD-1).x documents validate cleanly under vNEW" is the typical line for additive minors).
   - **Internal consumer notes** if quicktype-generated Go names changed (constant-name collisions etc.)
4. **Do not touch any earlier `## [vX]` entry.** Those are factual history.

### Phase 6 — Build / lint / test gate

Run the full CI gate to confirm the bumped versions compile and don't introduce drift:

```bash
pnpm install            # regenerate pnpm-lock.yaml from bumped package.json files
pnpm build              # build TS + Go (proves go.mod requires resolve via replace directives)
pnpm test               # full TS + Go suite
pnpm lint               # eslint + golangci-lint
pnpm security           # pnpm audit + govulncheck + gosec
```

If any step fails, fix before proposing the commit. A common failure: forgetting one `go.mod` require line — `go build ./...` per-module will surface it.

### Phase 7 — Stage and propose the commit

1. **Exclude `go.work.sum`** from the staged set. It collects speculative checksums from the Go toolchain during builds; it's environmental churn, not the release.
2. Explicit `git add` of every file you intended to change (per global rule: no `git add .` / `git add -A`).
3. Run `git status --short` and verify only the intended files are staged.
4. Propose a single atomic commit:
   - **Subject:** `chore(release): bump workspace from OLD to NEW`
   - **Body:** Two or three sentences. State the unified-lockstep model. Call out anything special (new fields documented in spec, removed enum, behavior change). Do *not* enumerate files — `git diff` shows them.
5. Wait for explicit user approval before committing. The pre-commit hook will run `pnpm check`; if you ran Phase 6 first, this is a no-op.
6. **Never tag.** Tagging is handled by the release workflow (`goreleaser` + per-module tags in lockstep: `vX`, `hdf-cli/vX`, `hdf-converters/vX`, etc.). Do not run `git tag` manually.

### Phase 8 — Post-merge verification (after the user pushes and merges)

Once the release PR is merged to `main`, the user runs the release workflow. Confirm with the user that:
- All per-module Git tags appear at the same version
- Generated `site/` schema reference is at the new version (it's regenerated from the schemas, so it should auto-track) — minor/major only
- `pkg.go.dev` resolves the new versions for `github.com/mitre/hdf-libs/<module>/v3@vNEW`

If anything lags, surface it; don't paper over.

### Phase 9 — Reconcile GitHub issues (after the release is published)

Beads were already closed at merge time (Phase 1.5); this phase is the **public** half — GitHub issues close when the release *ships*, so external watchers see "Resolved in vNEW." After the release workflow publishes `vNEW`:

1. Build the delivered set: cross-reference this release's CHANGELOG entry (its `#N` and `hdf-libs-xxxx` references) plus `git log BASE..HEAD` for `Refs #N` / bead IDs.
2. **GitHub issues (public — do NOT close or comment as the user without explicit OK):** produce the list of issues fixed and now released, with a suggested resolution comment each (e.g. "Resolved in vNEW"). Present it for the user to action, or close only with explicit per-instance approval. We use `Refs #N` (never auto-closing `Closes #N`) precisely so closing happens here, at release time.
3. **Beads backstop:** `bd dolt pull`; catch any straggler bead that was delivered but missed in Phase 1.5 and close it citing `vNEW`; `bd dolt push`. In the normal flow Phase 1.5 already handled these — this is only a safety net.
4. Surface any mismatch (a bead with no issue, an issue with no shipped fix, a `Refs #N` whose issue is already closed) rather than papering over it.

## Quick checklist (paste into the response after Phase 0)

- [ ] Phase 1 swarm review run (incl. docs/README-accuracy dimension); critical/high findings resolved or waived; deferrals filed as beads
- [ ] Phase 1.5 pre-release bead reconciliation: every delivered open/in_progress bead verified against the code and closed citing its PR; remaining-open cards triaged as blocking-bug vs. patchable
- [ ] Phase 1.6 suppression review: pnpm overrides re-validated against current advisory floors; `ignoreGhsas` checked for now-available fixes; dependabot `ignore` rules checked against their still-blocking conditions; retirements filed as their own commits
- [ ] *(minor/major)* Phase 1.7 vendored external-schema freshness: each `converters/*/schemas/**` (and sibling fixture schema) re-fetched and SHA-256-compared against its `PROVENANCE.md`; drift refreshed + revalidated, or confirmed no-op
- [ ] 10 `package.json` files at NEW
- [ ] 5 `go.mod` files: every `hdf-libs/<x>/v3 vNEW` (no stragglers)
- [ ] *(minor/major)* 7 schema `$id` URLs at NEW
- [ ] *(minor/major)* 7 new archive files staged: `site/public/schemas/<name>/vNEW/index.json` (one per main schema). `cd site && pnpm generate` writes them; `git add 'site/public/schemas/*/vNEW/'` stages them. See Phase 2.5.
- [ ] *(minor/major)* Root `README.md` current-version claims updated
- [ ] *(minor/major)* `site/docs/specification/hdf-specification.md`: title + version metadata + 6 `Schema ID` URLs + new-field rows in every affected requirement/type table
- [ ] *(minor/major)* `site/docs/contributing/developer-guide.md` `$ref` URI pattern at NEW
- [ ] *(minor/major)* `hdf-cli/README.md` archive example at NEW
- [ ] *(minor/major)* `hdf-schema/README.md` new "What's new in vNEW" section added
- [ ] Breaking changes actively derived from the `BASE..HEAD` diff (excluding new/additive features) and each explained in the CHANGELOG's Breaking Changes section — or "No breaking changes" stated explicitly (never left implied by the version bump)
- [ ] `CHANGELOG.md` has a new `## [NEW] - YYYY-MM-DD` entry; historical entries untouched
- [ ] `pnpm check` (build + lint + test + security) all green
- [ ] `git status` shows no `go.work.sum`, `node_modules/`, `dist/`, or unrelated files staged
- [ ] No `git tag` run manually
- [ ] Phase 9: GitHub issue closures prepared for the user (not posted as the user without OK); beads backstop checked for stragglers
