# CLAUDE.md

Project context for Claude Code and human developers working in this repository.

## Quick Start

```bash
pnpm install          # Install all dependencies
pnpm build            # Build TS + Go
pnpm test             # Run all tests (TS + Go)
pnpm check            # Pre-commit gate: TS build + lint + typecheck + TS tests + audit
                      # (Go: lints 3 of 13 modules, tests only hdf-cli — CI covers the rest)
pnpm lint             # ESLint (TS) + golangci-lint (Go)
pnpm security         # pnpm audit + govulncheck
```

## Monorepo Layout

pnpm workspace with 11 packages + a VitePress schema documentation site:

| Package | Purpose | Language |
|---------|---------|----------|
| `hdf-schema` | 7 JSON schemas + TS/Go type generation | TS |
| `hdf-utilities` | XML, CSV, hash, string helpers | TS |
| `hdf-mappings` | CCI, NIST, CWE, OWASP control mappings | TS + Go |
| `hdf-validators` | Schema validation with embedded schemas | TS + Go |
| `hdf-parsers` | Parse and flatten HDF documents | TS + Go |
| `hdf-converters` | 40+ security tool converters (dual TS + Go) | TS + Go |
| `hdf-generators` | Generate InSpec profiles from baselines | TS + Go |
| `hdf-diff` | Structural diff engine for assessments | TS + Go |
| `hdf-engine` | Schema-typed read-side engines: document detection, query/filtering, compliance rollups | TS + Go |
| `hdf-extension-graph` | InSpec overlay/extension chain resolution | TS + Go |
| `hdf-fixtures` | Shared real-world HDF test data corpus (published; cross-package tests here, and available to consumers) | TS + Go |
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
- Cover the key usage patterns and edge cases (e.g., both compliance-scan and CVE-scan false positives)
- Be valid against the schema — the bundler includes them in dist, and consumers see them in IDE tooltips
- Explain what the examples demonstrate in a `$comment` on the **definition**, as `"Examples, in order: 1) …; 2) …"`, never inside the example objects themselves. An example is data, not a schema, so a `$comment` key inside one is an undeclared property that fails validation on any definition with `unevaluatedProperties: false` — and it hands a consumer who copies the example a document their validator rejects. `scripts`-free guard: `hdf-schema/test/examples-valid.test.ts` validates every example against its own definition and fails the build otherwise.

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
- **Go**: `shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"` — `BuildHDFResults()`, `ValidateJSONSize()`, `LimitSliceWithWarning()`, `MapCWEToNIST()`. `SeverityToImpact()` is not here — it lives in `hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"` alongside `ParseTimestamp()`.
- **TS**: `converterutil.ts` — `buildHdfResults()`, `inputChecksum()`, `validateInputSize()`, `mapCWEToNIST()`, `limitArrayWithWarning()`

### Timestamps (canonical = trimmed-UTC RFC3339)
Always parse tool timestamps with `hdfutil.ParseTimestamp` (Go) / `parseTimestamp` from `@mitre/hdf-utilities` (TS) — **never** raw `new Date(value)` or `time.Parse(time.RFC3339, ...)` (zone-less input is read as host-local and diverges across languages). Serialize via `buildHdfResults`/`serializeHdf` (TS) so the fraction is trimmed. Result `startTime` is schema-required → on a missing/unparseable source time, fall back to a valid value (never omit). Enforced by an ESLint rule + `pnpm lint:timestamps`. Full convention: `site/docs/contributing/developer-guide.md` (Timestamp Handling); rationale in beads memory `hdf-timestamp-canonical-utc`.

### Converter registration
The convert registry lives in the cobra-free, importable package `hdf-converters/registry/convert` (package `convert`, imported as `convreg`), so the CLI and the MCP share one populated registry. Register a converter by adding `hdf-converters/registry/convert/converter_<name>.go` with an `init()` that calls the right helper for its output type — `registerHDFConverter` (results), `registerHDFBaselineConverter` (baseline), `registerHDFPlanConverter` (plan), or `registerHDFAmendmentsConverter` (amendments, e.g. the VEX family). Register the converter's fingerprint for auto-detect with a blank import in `hdf-converters/registry/all/all.go`. `hdf-cli/cmd/hdf/cmd/converter_registry.go` is now only a thin re-export layer (type aliases + bindings to `convreg`) — no registration logic lives there. The CLI integration *test* still lives at `hdf-cli/cmd/hdf/cmd/converter_<name>_test.go` (exercising the re-exported `GetConverter`).

## Go Module Structure

Multiple Go modules in the monorepo with `replace` directives for local development. Replace directives are ignored by consumers (`go get`) — this is the standard pattern (OpenTelemetry, gRPC-Go).

`go install` does not work with replace directives — CLI is distributed as pre-built binaries via goreleaser.

## Pre-commit Hook

`.husky/pre-commit` runs `pnpm check`: TypeScript build, ESLint and the repo's own lint scripts, typecheck, TypeScript tests with coverage, and the dependency audit. If it fails, fix the issue — do not bypass with `--no-verify` unless batching commits with no code changes between them.

**It is not the full CI gate, and the gap is on the Go side.** `check` builds no Go at all (it calls `build:ts`, not `build`), lints 3 of the 13 workspace modules, runs Go *tests* for `hdf-cli` alone, and runs govulncheck and gosec only there. CI is broader: it lints and runs govulncheck across all 13 modules, runs every Go test, and reaches all 13 with gosec — there is no standalone gosec step, but golangci-lint inherits the root `.golangci.yml` in any module that does not override it (only `hdf-cli` does), and `scripts/check-gosec-coverage.sh` fails the build if a module ever resolves a config without gosec. So a Go change that passes locally has had roughly one module's worth of scrutiny; wait for CI before treating it as verified, or run `pnpm test:go` and `golangci-lint run` in the module you touched.

## Security Requirements

- All converters must call `ValidateJSONSize` / `ValidateXMLInput` as first operation
- XML converters must check for entity expansion (`ValidateXMLInput` handles this)
- File paths from JSON must be validated with `safePath()` (evidence_verify, generators)
- No secrets in code; test tokens annotated with `//nolint:gosec`

## Adding a New Converter

Use the `/build-converter` skill (`.claude/commands/build-converter.md`) — it walks through the full process: research → fixtures → TDD tests → Go + TS implementation → CLI integration → verification. This is the most common development task in this repo.

Quick reference: `hdf convert <file> -o <output>` (auto-detects format) or `hdf convert --from nessus <file> -o <output>`

## Fixture Integrity

Never fabricate fixture data. A fixture counts as real in exactly two cases:

1. **We generated it by running another published tool** — an actual run, a public CI pipeline, or one of this repo's own converters fed an input that itself qualifies.
2. **We took it from someone else's published example or sample set** — [heimdall2](https://github.com/mitre/heimdall2/tree/master/libs/hdf-converters/sample_jsons), [SAF CLI](https://github.com/mitre/saf/tree/main/test/sample_data), or a format's upstream spec/example repository.

Anything else is fabrication, including hand-assembling a document out of real strings: the assembly itself can be wrong even when every string inside it is genuine. **Schema validation is not a third source.** Validating against the format's official schema (JSON Schema, XSD, etc.) is a check on a fixture that already qualifies under (1) or (2), and the proof belongs in the fixture's `provenance.txt` or the commit message — it never establishes that a document we built ourselves is real.

If no real data source exists, **stop and ask** — do not invent data. A converter tested against fabricated fixtures is untrusted: the fixture determines whether the converter works on real data; if the fixture is fake, the test proves nothing. Where no real source exists for some case, record the coverage gap instead of filling it.

**Trimming a real document is allowed** — by dropping whole elements only (a requirement, a POA&M item, a product branch). Never edit a string inside a kept element, and never add, remove or convert whitespace or line endings to make a test pass.

**No fixture carries a contributor's machine or identity** — a capture path (`/Users/<name>/…`, `~/…`), a hostname, a username, a token. Published tool output routinely contains them, so check before committing one.

**Redaction is therefore the one exception to "never edit a string".** Anything in the line above may be replaced. Redact the smallest thing that works — a path prefix, not the whole value — and record in the fixture's `provenance.txt` which field was redacted and what shape it had before. Redaction is never a licence to reshape prose: leave line endings, blank lines and edge whitespace exactly as captured.

### Realistic-prose fixtures

HDF prose is carried verbatim (`site/docs/specification/hdf-specification.md`, Conventions → Prose fields), so a fixture is only evidence of that if it actually carries something to preserve:

- **Content.** Multi-line prose, and edge whitespace (leading/trailing newlines or spaces, CRLF) *where the real source carries it*. Never synthesize edge whitespace onto a source that lacks it — that turns a real fixture into a fabricated one and the test then proves nothing about real data.
- **Assertion.** A schema pass is not preservation evidence, and neither is golden parity (`shared.NormalizeXMLForGolden` decodes entities and collapses inter-tag whitespace, so outputs differing in newline encoding compare equal). Assert a **byte-exact readback in both languages**: schema-validate the input, convert, parse each prose value back out of the output, and compare it to its source string. Also assert the fixture still contains its newlines and edge whitespace, so a future "cleanup" fails the test instead of silently weakening it.
- **Per-target expectation.** JSON targets (OSCAL POA&M/SAR, the VEX family) compare true bytes, CRLF included. XML targets (XCCDF and anything else routed through XML) compare LF-normalized, because XML 1.0 §2.11 requires the parser to fold line endings — cite that in the test. Putting a CRLF fixture through an XML exporter and asserting byte equality is a test that can only fail.
- **Provenance.** In the converter's `fixtures/provenance.txt` (or the `hdf-fixtures/README.md` row when shared), record: the source artifact with its canonical URL or upstream path and pinned version/commit; the **sha256 of the source as retrieved** (not of the trimmed fixture); the retrieval date; exactly what the trim dropped, stated as "whole elements dropped, no string edited"; and a field map naming which source string landed in which HDF field. The worked precedent for the fixture and its tests is `hdf-converters/converters/hdf-to-xccdf/fixtures/input/multiline-rhel9.json` (two requirements trimmed from a real RHEL 9 STIG scan) with the byte-exact assertions in that converter's `go/schema_validation_test.go` and `typescript/schema-validation.test.ts`.

**Recorded limit — the amendments family.** No published source puts edge whitespace or CRLF into an HDF amendments document, so that coverage does not exist and must not be faked. No published tool emits HDF amendments directly either (SAF CLI's `convert:ckl2poam` runs the other way, to an eMASS xlsx workbook that nothing reads back). A genuinely real amendments fixture *is* reachable through our own importer fed a published OSCAL POA&M — NIST's `usnistgov/oscal-content`, `examples/poam/json/ifa_plan-of-action-and-milestones.json`, via `hdf convert --from oscal-poam`, after the one permitted whole-element drop of the poam-item whose `related-risk` dangles in NIST's own example. Its multi-line prose does not reach HDF today, because the two multi-line fields (`risks[].statement`, `observations[].remarks`) are not carried by `oscal-to-hdf`; until they are, the family's multi-line coverage comes from the VEX inputs' `reason` field alone.

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
- **Never hand-edit beads state files.** Always go through `bd`. JSONL export is now opt-in (`export.auto` in `.beads/config.yaml`) rather than a standing artifact, so `.beads/issues.jsonl` is absent unless an integration asks for it.
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

**Architecture in one line:** issues live in a local Dolt DB and sync between clones over a Dolt remote; JSONL export is an optional interchange format, not the sync mechanism. See https://github.com/gastownhall/beads/blob/main/docs/SYNC_CONCEPTS.md for details and anti-patterns.

**Git policy:** the user owns every commit and push in this repo. The bd-tool's default session-completion workflow (which prescribes a mandatory `git push`) does not apply here — the "Git Policy" section above is the authoritative rule. `bd dolt push` / `bd dolt pull` (issue-tracker sync) is a separate concept; follow the dolt-sync rule above for those.
<!-- END BEADS INTEGRATION -->

### Card hygiene: no machine-local details

Beads cards are shared across clones through the Dolt remote. Keep them portable and free of any contributor's local environment:

- **No absolute/home filepaths.** Reference files by repo-relative path (`hdf-converters/converters/.../converter.go:277`), never `/Users/<name>/...` or `~/...`.
- **No local infrastructure names or stack descriptions.** Don't name a contributor's VMs, containers, container engine, cluster/namespace, ports, or hostnames. Describe the *capability* generically instead (e.g. "a SonarQube instance in MQR mode", not how or where it happens to run locally).
- **No secrets or tokens**, even read-scoped ones.

When a card needs a live service to reproduce or validate against, describe the service and its required mode/version generically and leave the "how I run it locally" out entirely.
