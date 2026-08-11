# CLAUDE.md

Project context for Claude Code and human developers working in this repository.

## Quick Start

```bash
pnpm install          # Install all dependencies
pnpm build            # Build TS + Go
pnpm test             # Run all tests (TS + Go)
pnpm check            # Full CI gate: build + lint + test + security
pnpm lint             # ESLint (TS) + golangci-lint (Go)
pnpm security         # pnpm audit + govulncheck
```

## Monorepo Layout

pnpm workspace with 11 packages + a VitePress schema documentation site:

| Package | Purpose | Language |
|---------|---------|----------|
| `hdf-schema` | 7 JSON schemas + TS/Go/Python type generation | TS |
| `hdf-utilities` | XML, CSV, hash, string helpers | TS |
| `hdf-mappings` | CCI, NIST, CWE, OWASP control mappings | TS + Go |
| `hdf-validators` | Schema validation with embedded schemas | TS + Go |
| `hdf-parsers` | Parse and flatten HDF documents | TS + Go |
| `hdf-converters` | 40+ security tool converters (dual TS + Go) | TS + Go |
| `hdf-generators` | Generate InSpec profiles from baselines | TS + Go |
| `hdf-diff` | Structural diff engine for assessments | TS + Go |
| `hdf-engine` | Schema-typed read-side engines: document detection, query/filtering, compliance rollups | TS + Go |
| `hdf-extension-graph` | InSpec overlay/extension chain resolution | TS + Go |
| `hdf-fixtures` | Shared real-world HDF test data corpus (private; cross-package tests only) | TS + Go |
| `hdf-cli` | Go CLI wrapping all of the above | Go |
| `site/` | VitePress schema reference site for GitHub Pages | TS |

## Key Commands

### Per-package testing
```bash
cd hdf-converters && pnpm test:ts           # TS converter tests
cd hdf-converters && go test ./...           # Go converter tests
cd hdf-cli && go test ./cmd/hdf/cmd/ -run TestQuery -v  # Single CLI test
cd hdf-schema && pnpm test                  # Schema validation tests (rebuilds first)
```

### Go linting
```bash
cd hdf-cli && golangci-lint run             # 39 linters enabled
cd hdf-cli && golangci-lint run --fix       # Auto-fix
```

### Schema workflow
```bash
cd hdf-schema && pnpm build:schemas         # Bundle source → dist schemas (auto-syncs hdf-validators/go/schemas/)
cd hdf-schema && pnpm build                 # Bundle + generate TS/Go types
```

`build:schemas` copies the bundled `dist/schemas/*.schema.json` into `hdf-validators/go/schemas/` as its last step — the validator embed must always reflect the latest bundled output. Don't hand-edit `hdf-validators/go/schemas/`; rerun `build:schemas`.

### VitePress schema site
```bash
cd site && pnpm generate && pnpm exec vitepress dev  # Local preview
```

## Schema Architecture

7 document types, all JSON Schema 2020-12:

- **hdf-results** — Assessment findings (the primary converter output)
- **hdf-baseline** — Requirement definitions without results
- **hdf-system** — Authorization boundary, components, data flows, control designations
- **hdf-plan** — Assessment plan linking baselines to components
- **hdf-amendments** — Waivers, attestations, POA&Ms
- **hdf-evidence-package** — Bundle of references to all documents
- **hdf-comparison** — Differential analysis (v1.0.0; others are v2.0.0)

Source schemas: `hdf-schema/src/schemas/` (modular, with `primitives/` subdirectory)
Bundled schemas: `hdf-schema/dist/schemas/` (self-contained, all `$ref`s embedded)
Hosted at: `https://mitre.github.io/hdf-libs/schemas/`

### Key schema fields
- `components[]` — polymorphic array (11 types: host, containerImage, cloudAccount, etc.) with UUID `componentId`
- `tool` — source security tool metadata (name, version, format). Aligns with SARIF/OSCAL/CycloneDX.
- `generator` — converter that produced the HDF file (required: name + version)
- `integrity` — root-level hash + optional signature (Integrity type)
- `baselines[].resultsChecksum` / `originalChecksum` — per-baseline checksums (Checksum type)
- `disposition` — Override_Type of the governing non-expired override (waiver, falsePositive, riskAdjustment, etc.)
- `effectiveStatus` — Result_Status after overrides (passed, failed, notApplicable, notReviewed, error)
- `effectiveImpact` — impact score (0.0–1.0) after impact overrides
- `controlType` — *(v3.2.0)* optional enum on `Requirement_Core`: `policy | procedure | technical | management | operational`. Aligns with NIST SP 800-53A categorization.
- `verificationMethod` — *(v3.2.0)* optional enum on `Requirement_Core`: `automated | manual-by-design | manual-pending-automation | hybrid`. Disambiguates the two cases that null `code` overloads.
- `applicability` — *(v3.2.0)* optional enum on `Requirement_Core`: `required | optional | advisory`. Distinct from severity (risk weight) and status (lifecycle state). Maps cleanly onto FedRAMP OSCAL `CORE` prop, FedRAMP 20x inline `Optional:` markers, CMMC sublevels.

### Schema examples convention
When adding or modifying a `$defs` type in the schema source files, always add or update the `examples` array on the definition. Examples should:
- Use realistic data (real STIG IDs, plausible CVEs, genuine tool output patterns)
- Include a `$comment` field explaining what the example demonstrates
- Cover the key usage patterns and edge cases (e.g., both compliance-scan and CVE-scan false positives)
- Be valid against the schema — the bundler includes them in dist, and consumers see them in IDE tooltips

See `Evaluated_Requirement` in `hdf-results.schema.json` for the model to follow.

## Converter Pattern

Each converter exists in both TypeScript and Go with shared test fixtures:

```
hdf-converters/converters/<name>/
├── typescript/converter.ts      # TS implementation
├── typescript/converter.test.ts # TS tests
├── go/converter.go              # Go implementation
├── go/converter_test.go         # Go tests
├── fixtures/input/              # Source tool output (real data)
└── fixtures/expected/           # Expected HDF output (schema-validated)
```

### Shared helpers
- **Go**: `shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"` — `BuildHDFResults()`, `SeverityToImpact()`, `ValidateJSONSize()`, `LimitSliceWithWarning()`, `MapCWEToNIST()`
- **TS**: `converterutil.ts` — `buildHdfResults()`, `inputChecksum()`, `validateInputSize()`, `mapCWEToNIST()`, `limitArrayWithWarning()`

### Timestamps (canonical = trimmed-UTC RFC3339)
Always parse tool timestamps with `hdfutil.ParseTimestamp` (Go) / `parseTimestamp` from `@mitre/hdf-utilities` (TS) — **never** raw `new Date(value)` or `time.Parse(time.RFC3339, ...)` (zone-less input is read as host-local and diverges across languages). Serialize via `buildHdfResults`/`serializeHdf` (TS) so the fraction is trimmed. Result `startTime` is schema-required → on a missing/unparseable source time, fall back to a valid value (never omit). Enforced by an ESLint rule + `pnpm lint:timestamps`. Full convention: `site/docs/contributing/developer-guide.md` (Timestamp Handling); rationale in beads memory `hdf-timestamp-canonical-utc`.

### Converter registration
The convert registry lives in the cobra-free, importable package `hdf-converters/registry/convert` (package `convert`, imported as `convreg`), so the CLI and the MCP share one populated registry. Register a converter by adding `hdf-converters/registry/convert/converter_<name>.go` with an `init()` that calls the right helper for its output type — `registerHDFConverter` (results), `registerHDFBaselineConverter` (baseline), `registerHDFPlanConverter` (plan), or `registerHDFAmendmentsConverter` (amendments, e.g. the VEX family). Register the converter's fingerprint for auto-detect with a blank import in `hdf-converters/registry/all/all.go`. `hdf-cli/cmd/hdf/cmd/converter_registry.go` is now only a thin re-export layer (type aliases + bindings to `convreg`) — no registration logic lives there. The CLI integration *test* still lives at `hdf-cli/cmd/hdf/cmd/converter_<name>_test.go` (exercising the re-exported `GetConverter`).

## Go Module Structure

Multiple Go modules in the monorepo with `replace` directives for local development. Replace directives are ignored by consumers (`go get`) — this is the standard pattern (OpenTelemetry, gRPC-Go).

`go install` does not work with replace directives — CLI is distributed as pre-built binaries via goreleaser.

## Pre-commit Hook

`.husky/pre-commit` runs `pnpm check` (build + lint + test + security). This is the full CI gate. If it fails, fix the issue — do not bypass with `--no-verify` unless batching commits with no code changes between them.

## Security Requirements

- All converters must call `ValidateJSONSize` / `ValidateXMLInput` as first operation
- XML converters must check for entity expansion (`ValidateXMLInput` handles this)
- File paths from JSON must be validated with `safePath()` (evidence_verify, generators)
- No secrets in code; test tokens annotated with `//nolint:gosec`

## Adding a New Converter

Use the `/build-converter` skill (`.claude/commands/build-converter.md`) — it walks through the full process: research → fixtures → TDD tests → Go + TS implementation → CLI integration → verification. This is the most common development task in this repo.

Quick reference: `hdf convert <file> -o <output>` (auto-detects format) or `hdf convert --from nessus <file> -o <output>`

## Fixture Integrity

Never fabricate fixture data. Every converter fixture must be one of:

1. Real tool output from an actual run or public CI pipeline
2. Copied/adapted from heimdall2 (`~/repos/heimdall2/libs/hdf-converters/test/sample_input_report/`) or SAF CLI (`~/repos/saf/test/sample_data/`)
3. Validated against the format's official schema (JSON Schema, XSD, etc.) with proof logged in a comment or commit message

If no real data source exists and no schema exists to validate against, **stop and ask** — do not invent data. A converter tested against fabricated fixtures is untrusted: the fixture determines whether the converter works on real data; if the fixture is fake, the test proves nothing.

### Where fixtures live: local vs shared

- **Single-consumer → stays local.** If only the owning package's tests load the file (a converter's `fixtures/input/` or `fixtures/expected/`, a package's `test/fixtures/`, a Go package's `testdata/`), it stays there as that package's *tested contract*.
- **Multi-consumer → moves to `hdf-fixtures`.** When two or more workspace packages actively load the same fixture, it moves to `@mitre/hdf-fixtures` (the shared corpus) and every consumer imports it from there. The original location is deleted — **no duplicates**.
- **Inclusion bar is strict.** "Might be useful someday" or "good for parity-test breadth" are not sufficient justifications for landing a file in `hdf-fixtures`. Promote a fixture only once the second active consumer materializes.
- **`hdf-fixtures` provenance.** Every entry in `hdf-fixtures/README.md` lists the source AND the current consumers. Adding a fixture requires updating both `src/index.ts` (TS) and `fixtures.go` (Go) plus the README, and deleting the original location.

The architecture rationale lives in bead `hdf-libs-e95o`; `hdf-fixtures/README.md` documents the boundary rule with examples.

---

# Claude Code Policy

The sections below apply to Claude (and other AI coding agents) working in this repo. Human contributors should be aware of these too — they reflect this project's conventions.

## Communication Style

- Keep tone professional. No sycophancy — skip phrases like "great idea" or "excellent question."
- Push back on decisions when appropriate. Ask clarifying questions rather than assuming.

## Git Policy

- **Never commit without explicit permission** for each individual commit. Prepare detailed commit messages for approval first.
- **Never push.** User handles all pushes.
- **No authorship attribution.** Do not add "written by Claude Code", "Co-Authored-By: Claude", or similar to commits, comments, or documentation.
- **Brief commit messages.** Conventional-commit subject line, a blank line, then a short body (a few sentences) covering *what* changed and *why*. Don't list affected files — that's `git diff`'s job. Don't restate the subject in the body. Default to brevity; only substantial features warrant longer bodies.
- **Run lint before proposing a commit.** At minimum run `golangci-lint run` (for Go changes) and/or `pnpm lint` (for TS changes) and fix all issues before asking the user to approve. The pre-commit hook will catch failures anyway, but catching them early avoids wasted time.

## Development Practices

- **Test-driven development (TDD).** Write tests before implementation.
- **>90% code coverage required.** Code is not considered working without unit tests meeting this threshold.
- Tests define the spec; implementation fulfills the spec.
- **Zero lint warnings.** Fix all warnings in `pnpm lint` output, even pre-existing ones, unless explicitly told to ignore them.
- **No time-bomb timestamps in tests.** Any expiry/validity date a test needs to still be in the future (waiver `expiresAt`, cert/token validity, "not expired" fixtures) must be a far-future constant — use `2099-12-31T00:00:00Z`. Never use a real near-term date the wall clock will pass (this repo has been bitten repeatedly by fixtures like `2026-06-30` that silently start failing on that day), and **never** derive it from the current time (`time.Now()`, `new Date()`, "today"). A test whose pass/fail depends on when it runs is broken. Use a deliberately-past date (e.g. `2020-01-01`) only when the test specifically asserts expired behavior, and give every other date the far-future constant for consistency.
- **Comments only when the WHY is non-obvious.** A clear function name beats a multi-line preamble. No issue numbers, no "addresses bug X", no "see PR #Y" — that belongs in commit messages and PR descriptions, where it doesn't rot as the codebase evolves.
- **Multi-line comment blocks are almost never justified.** Default to a single line. Only spend more space when a non-obvious invariant, hidden constraint, or subtle cross-file interaction genuinely needs it. If the WHY fits in one line, write one line. Resist the urge to narrate design decisions — that's what the commit message is for.
- **No `docs/` folders inside individual library packages.** All documentation lives under the top-level `site/docs/` tree, which feeds the VitePress site. Put new docs in the appropriate `site/docs/` subtree (architecture, guides, contributing, specification) — not next to the code, where it fragments and never reaches the published site.
- **No emoji in the docs site.** The schema reference site (`site/`) is a technical reference; pictographic emoji read as sloppy. Do not use them in docs content, headings, nav, or VitePress config. Technical typography is fine and expected — flow/mapping arrows (`→ ← ↑ ↓`), ASCII box-drawing in diagrams, and monochrome text marks (`✓`/`✗`) in support matrices are not emoji and may stay.

## Converter Requirements

- **HDF CLI integration required.** Converters are not considered fully implemented until integrated into hdf-cli.
- Each converter must have both:
  1. Converter implementation and tests in `hdf-converters/converters/{name}/{typescript,go}/`
  2. Registry integration: an `init()` wrapper in `hdf-converters/registry/convert/converter_{name}.go` (+ a fingerprint blank-import in `hdf-converters/registry/all/all.go`), with the CLI integration test at `hdf-cli/cmd/hdf/cmd/converter_{name}_test.go`
- Spot check converter output via CLI before committing: `hdf convert {from} to {to} input.json output.{ext}`

<!-- BEGIN BEADS INTEGRATION v:1 profile:minimal hash:7510c1e2 -->
## Beads Issue Tracker

This project uses `bd` (gastownhall/beads, the Go mainline, NOT the Rust fork `br`) with an **embedded Dolt** backend (per-project DB; do not share with other repos). Run `bd prime` for the detailed command reference and session-close protocol.

### Quick Reference

```bash
bd ready                            # Find available work
bd show <id>                        # View issue details
bd update <id> --status in_progress # Claim work
bd close <id> -r "reason"           # Complete work
bd create --title "..." -d "..."    # Create new issue
bd dep add <issue> <depends-on>     # Add a dependency
```

### Rules

- Use `bd` for ALL task tracking — do NOT use TodoWrite, TaskCreate, or markdown TODO lists.
- **Never edit `.beads/issues.jsonl` directly** — it is the auto-export. Always go through `bd`.
- Use `bd remember` for persistent knowledge — do NOT use MEMORY.md files.

### Dolt sync on reserve/complete

Whenever you **reserve** (claim / move to `in_progress`) or **complete** (close) a card, bracket the write with a Dolt pull and push so the remote stays in sync with other clones working on this repo:

```bash
bd dolt pull                         # rebase any other-clone changes
bd update <id> --status in_progress  # or:  bd close <id> -r "..."
bd dolt push                         # publish the change
```

Same pattern for creating + immediately reserving a new card. This is the Dolt issue-tracker remote only; it has no relationship to `git push` (which the user handles separately for code changes).

If bd errors with "Database out of sync", run `bd dolt pull` first.

**Architecture in one line:** issues live in a local Dolt DB; sync uses `refs/dolt/data` on your git remote; `.beads/issues.jsonl` is a passive export. See https://github.com/gastownhall/beads/blob/main/docs/SYNC_CONCEPTS.md for details and anti-patterns.

**Git policy:** the user owns every commit and push in this repo. The bd-tool's default session-completion workflow (which prescribes a mandatory `git push`) does not apply here — the "Git Policy" section above is the authoritative rule. `bd dolt push` / `bd dolt pull` (issue-tracker sync) is a separate concept; follow the dolt-sync rule above for those.
<!-- END BEADS INTEGRATION -->

### Card hygiene: no machine-local details

Beads cards are shared across clones and exported to `.beads/issues.jsonl`. Keep them portable and free of any contributor's local environment:

- **No absolute/home filepaths.** Reference files by repo-relative path (`hdf-converters/converters/.../converter.go:277`), never `/Users/<name>/...` or `~/...`.
- **No local infrastructure names or stack descriptions.** Don't name a contributor's VMs, containers, container engine, cluster/namespace, ports, or hostnames. Describe the *capability* generically instead (e.g. "a SonarQube instance in MQR mode", not how or where it happens to run locally).
- **No secrets or tokens**, even read-scoped ones.

When a card needs a live service to reproduce or validate against, describe the service and its required mode/version generically and leave the "how I run it locally" out entirely.
