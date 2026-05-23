---
description: Prepare the monorepo for a minor or major semver release. Sweeps every version-bearing file in the workspace (package.json, go.mod, schema $id URLs, docs that quote a current schema version) and ensures content docs include the new release's changes. Use when bumping the version line (e.g. "let's prep a 3.3.0 release", "cut a 4.0.0 release"). NOT for patch releases.
allowed-tools: Read, Glob, Grep, Bash, Edit, Write, AskUserQuestion
---

## When to use this skill

Run this skill whenever the workspace is moving to a new minor or major version (e.g. `3.2.0 → 3.3.0`, `3.x → 4.0`). The monorepo uses **unified lockstep versioning**: every workspace package, every Go cross-module require, and every schema `$id` URL moves to the same new version. Drift between any of those is a release bug.

**Skip this skill for patch bumps** (e.g. `3.2.0 → 3.2.1`). Patches by convention don't change the schema structure or the canonical docs — just the CHANGELOG entry and the workspace `package.json` version fields need editing. The full sweep below is overkill and the spec/content updates won't apply.

The current ("from") version is whatever the workspace `package.json` files agree on; mismatch between them means a prior release was incomplete and is itself a finding (treat as a separate cleanup before bumping).

## Lessons learned from prior releases

These are the traps this skill exists to prevent. Real failure modes from the 3.2.0 release:

1. **Only the schema bumped.** `hdf-schema/package.json` and the seven schema `$id` URLs moved to 3.2.0, but the other nine workspace packages and every `go.mod` require line stayed at the old version. Result: schema released as 3.2.0, consumers shipped as 3.1.1.
2. **A README claimed the wrong version.** Root `README.md` said *"All schemas are at v3.1.0"* after schemas had moved to 3.2.0 — a flat-out wrong claim that survives unless you sweep for current-version assertions, not just literal old-version strings.
3. **The formal spec doc lagged the schema.** `docs/specification/hdf-specification.md` titled itself "v3.1.0 Specification", carried six stale `Schema ID:` URLs, AND was missing the new requirement fields entirely. A version-string substitution would have caught the URLs but left the canonical spec missing the content it's supposed to describe.
4. **`$ref` URI pattern examples in `docs/design/developer-guide.md` froze at the version they were written against.** These are shown as the canonical lookup pattern, not historical examples, so they need to track the current schema version.
5. **`go.work.sum` churn appears mid-release.** The Go toolchain speculatively adds checksum entries (`golang.org/x/sys`, AWS SDK, etc.) during builds. These are NOT part of the release — exclude them from the commit.
6. **Historical CHANGELOG entries are NOT version-string substitutions.** Lines like `## [3.1.0]` or `Schema version bumped from v3.0.0 to v3.1.0` are factual history. Touching them rewrites the past.

## Execution

### Phase 0 — Confirm scope

1. Ask the user for the target version (e.g. `3.3.0`). Capture it as `NEW_VERSION`.
2. Determine `OLD_VERSION` by reading `hdf-schema/package.json` → `version`. Confirm with the user if it doesn't match the other workspace `package.json` files (drift = pre-existing bug, surface before continuing).
3. If `NEW_VERSION` is a patch bump of `OLD_VERSION` (only the third segment changed), warn the user that this skill is for minor/major bumps and ask if they want to continue anyway. For pure patches, just bump `package.json` files + add a CHANGELOG entry; the rest of this skill does not apply.

### Phase 1 — Mechanical version sweep

These edits are uniform across the workspace and safe to script. Use a small Python script (per [global Memory guidance](#)) for the bulk substitutions — `sed` invocations can clobber unrelated `3.x.y` substrings in fixture files.

**Targets:**

| File pattern | What to change |
|---|---|
| Workspace `package.json` (9 files: `hdf-cli`, `hdf-converters`, `hdf-diff`, `hdf-extension-graph`, `hdf-generators`, `hdf-mappings`, `hdf-parsers`, `hdf-utilities`, `hdf-validators`) | `"version": "OLD"` → `"version": "NEW"` |
| `hdf-schema/package.json` | Same |
| `hdf-schema/src/schemas/*.schema.json` (7 root schemas) | `"$id"` URLs ending in `/vOLD` → `/vNEW`. Also any `$ref` URLs in primitives that quote a version path. |
| Cross-module `go.mod` requires (`hdf-converters/go.mod`, `hdf-cli/go.mod`, `hdf-diff/go/go.mod`, `hdf-parsers/go/go.mod`, `hdf-generators/go/go.mod`) | Lines matching `github.com/mitre/hdf-libs/<x>/v3 vOLD` → `vNEW`. Regex: `s/(hdf-libs/[^ ]+) vOLD/$1 vNEW/g` |

Use `git status` after the script run to spot-check no `node_modules`, `dist/`, or `.git/` paths got touched.

### Phase 2 — Current-version doc sweep

These claims are not URL-pattern uniform — they're prose ("All schemas are at vX") or pedagogical examples. Each must be inspected. Verified targets:

| File | What to look for |
|---|---|
| `README.md` (root) | Any *"schemas are at vX"* / *"current schema vX"* / *"latest vX"* sentences. Update to NEW. |
| `docs/specification/hdf-specification.md` | (a) **Document title** (line 1) `# Heimdall Data Format (HDF) vX Specification`. (b) **Version metadata** (`**Version**: X`). (c) **Every `**Schema ID**: …/vX` line** — there's one per top-level document type (currently 6: results, baseline, system, plan, amendments, comparison). |
| `docs/design/developer-guide.md` | `$ref` URI pattern examples (currently around line 143). These show the canonical URL pattern, not historical examples, so they bump. |
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

### Phase 3 — Schema content propagation to the spec doc

This is the step that the 3.2.0 release missed. **The formal spec doc must list the same fields the schema does.** For minor releases that add new fields, the workflow is:

1. `grep` the schema source (`hdf-schema/src/schemas/primitives/*.json` and the root schemas) for fields added since OLD.
2. For each new field, identify which `$defs` type it lives on (commonly `Requirement_Core`, `Override_Type`, etc.).
3. In `docs/specification/hdf-specification.md`, find every spec-doc table that documents that `$defs` type. Some types appear in multiple tables (e.g. `Requirement_Core` fields surface in BOTH `Evaluated_Requirement` and `Baseline_Requirement`).
4. Add a new row per new field: `| name | TypeName | no | one-line description |`. Use the same type-name convention the table already uses (PascalCase without `_Enum` suffix — e.g. `Severity`, `ControlType`, not `Severity_Enum`).
5. Update field-set-overview prose anywhere it enumerates the fields explicitly.

For removed/deprecated fields, the same walk applies in reverse: remove the row, add a CHANGELOG migration note.

### Phase 4 — CHANGELOG

1. Open `CHANGELOG.md`. Insert a new `## [NEW_VERSION] - YYYY-MM-DD` block at the top.
2. Sections to fill in (skip empty ones):
   - **New Features**
   - **Breaking Changes** (call out any field renames, enum removals, schema-validation tightening)
   - **Architecture Changes** (note schema `$id` bump explicitly: *"Schema version bumped from vOLD to vNEW across all `$id`/`$ref` URLs"*)
   - **Compatibility** (state backward-compat posture; "v(OLD-1).x documents validate cleanly under vNEW" is the typical line for additive minors)
   - **Internal consumer notes** if quicktype-generated Go names changed (constant-name collisions etc.)
3. **Do not touch any earlier `## [vX]` entry.** Those are factual history.

### Phase 5 — Build / lint / test gate

Run the full CI gate to confirm the bumped versions compile and don't introduce drift:

```bash
pnpm install            # regenerate pnpm-lock.yaml from bumped package.json files
pnpm build              # build TS + Go (proves go.mod requires resolve via replace directives)
pnpm test               # full TS + Go suite
pnpm lint               # eslint + golangci-lint
pnpm security           # pnpm audit + govulncheck + gosec
```

If any step fails, fix before proposing the commit. A common failure: forgetting one `go.mod` require line — `go build ./...` per-module will surface it.

### Phase 6 — Stage and propose the commit

1. **Exclude `go.work.sum`** from the staged set. It collects speculative checksums from the Go toolchain during builds; it's environmental churn, not the release.
2. Explicit `git add` of every file you intended to change (per global rule: no `git add .` / `git add -A`).
3. Run `git status --short` and verify only the intended files are staged.
4. Propose a single atomic commit:
   - **Subject:** `chore(release): bump workspace from OLD to NEW`
   - **Body:** Two or three sentences. State the unified-lockstep model. Call out anything special (new fields documented in spec, removed enum, breaking change). Do *not* enumerate files — `git diff` shows them.
5. Wait for explicit user approval before committing. The pre-commit hook will run `pnpm check`; if you ran Phase 5 first, this is a no-op.
6. **Never tag.** Tagging is handled by the release workflow (`goreleaser` + per-module tags in lockstep: `vX`, `hdf-cli/vX`, `hdf-converters/vX`, etc.). Do not run `git tag` manually.

### Phase 7 — Post-merge verification (after the user pushes and merges)

Once the release PR is merged to `main`, the user runs the release workflow. Confirm with the user that:
- All per-module Git tags appear at the same version
- Generated `site/` schema reference is at the new version (it's regenerated from the schemas, so it should auto-track)
- `pkg.go.dev` resolves the new versions for `github.com/mitre/hdf-libs/<module>/v3@vNEW`

If anything lags, surface it; don't paper over.

## Quick checklist (paste into the response after Phase 0)

- [ ] 10 `package.json` files at NEW
- [ ] 7 schema `$id` URLs at NEW
- [ ] 5 `go.mod` files: every `hdf-libs/<x>/v3 vNEW` (no stragglers)
- [ ] Root `README.md` current-version claims updated
- [ ] `docs/specification/hdf-specification.md`: title + version metadata + 6 `Schema ID` URLs + new-field rows in every affected requirement/type table
- [ ] `docs/design/developer-guide.md` `$ref` URI pattern at NEW
- [ ] `hdf-cli/README.md` archive example at NEW
- [ ] `hdf-schema/README.md` new "What's new in vNEW" section added
- [ ] `CHANGELOG.md` has a new `## [NEW] - YYYY-MM-DD` entry; historical entries untouched
- [ ] `pnpm check` (build + lint + test + security) all green
- [ ] `git status` shows no `go.work.sum`, `node_modules/`, `dist/`, or unrelated files staged
- [ ] No `git tag` run manually
