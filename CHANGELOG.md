# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

## [3.3.0] - 2026-06-14

### New Features

- **CVE ecosystem fields on `Evaluated_Requirement` and `Baseline_Requirement`** — five new optional, structured fields capture the data ecosystem around a vulnerability finding that previously lived in free-form `tags`:
  - **`cvss[]`** — typed CVSS scoring for all four major versions (v2, v3.0, v3.1, v4.0). Multi-entry to handle multi-CVE findings.
  - **`epss`** — EPSS exploit-probability data (percentile + score).
  - **`kev`** — CISA Known Exploited Vulnerabilities catalog status.
  - **`cwe[]`** — CWE classification IDs.
  - **`affectedPackages[]`** — affected-package identifiers (ecosystem + name + version) with a typed `ecosystem` enum: `npm | pypi | gem | maven | nuget | cargo | go | deb | rpm | generic`.
  - Four new primitive schemas back the additions: `affected-package`, `cvss`, `epss`, `kev`. See `site/docs/guides/cve-ecosystem.md` for the migration path away from `tags.cvss_base_score`/`tags.cve` and the multi-release deprecation timeline. (#75)
- **`justification` enum on `Standalone_Override` and `Status_Override`** — 5-value enum from the VEX ecosystem (`component_not_present`, `vulnerable_code_not_present`, `vulnerable_code_not_in_execute_path`, `vulnerable_code_cannot_be_controlled_by_adversary`, `inline_mitigations_already_exist`). Complements the existing free-text `reason` field: `reason` is the auditor-readable rationale, `justification` is the machine-readable category for filtering / aggregation / lossless round-trip with structured ecosystems (CSAF VEX, OpenVEX, CycloneDX VEX). Open for additive extension as OSCAL / FedRAMP DR vocabularies are integrated. (#88)
- **CVSS enrichment on `riskAdjustment` amendments** — `hdf amend draft` auto-scaffolds a `cvss` block on `riskAdjustment` stubs when the source requirement is a CVE-ecosystem finding. Headless validation: syntactic CVSS-vector check via `hdf-utilities.ValidateCvssVector`; soft stderr warning when `impact.value` and `cvss.computedScore / 10` disagree by more than 0.05 (never blocks). (#82)
- **`@mitre/hdf-extension-graph` Go port** — 1:1 mirror of the TypeScript implementation: same four-phase `BuildExtensionGraph`, same five derived methods on `ContextualizedRequirement` (`Root`, `IsRedundant`, `FullCode`, `ExtensionChain`, `Modifications`). 100% test coverage. Cross-language equivalence test runs both implementations against the same fixture and diffs their canonical JSON dumps, pinning Go↔TS parity going forward. (#84)
- **`@mitre/hdf-fixtures` workspace package** — shared real-world fixture corpus (private; cross-package tests only) with both TS and Go APIs. Owns wild-data references for cross-package consumers. Inclusion bar is strict: at least two workspace packages must actively consume a file before it lands here, and the original location's copy is deleted (no duplicates). Initial corpus: `multilayered-inspec.json` promoted from hdf-extension-graph (now also consumed by hdf-parsers). (#90)
- **`hdf convert` / `hdf fetch` validate Amendments output** — `detectHDFDocType` recognizes amendments (top-level `overrides[]`) alongside results/baseline; `validateHDFOutput` calls `ValidateAmendments` for the amendments doc type. Schema-invalid amendments output is blocked before writing to disk. (#88)

### Fixes

- **InSpec timestamp normalization in `hdf-parsers`** — the InSpec runner emits ISO 8601 timestamps without a timezone designator (e.g. `"2026-03-25T22:56:27.736808"`), which the HDF schema's `date-time` format check and Go's `time.Time` JSON unmarshal both reject. Real-world result: any Go HDF consumer reading actual InSpec output got zero-valued or partial `HDFResults`. The new `normalizeTimestamps` helper in `hdf-parsers` finds JSON-quoted bare ISO timestamps via regex and appends `Z` (treating them as UTC, matching what JS `Date.parse` and InSpec itself assume). Applied at the top of `ParseResults` and `ParseBaseline` before schema validation and `json.Decode`. Already-RFC3339 strings and timestamp-shaped substrings inside prose values are left alone. (Closes `hdf-libs-2nm0`; #83)
- **`hdf-cli` parse + normalize now delegate to `hdf-parsers`** — `parseHDFResults` / `parseHDFBaseline` in `input.go` previously re-implemented the parser pipeline, bypassing #83's bare-timestamp normalization. Every CLI command that loaded HDF (`list`, `query`, `diff`) crashed on real InSpec output; `validate.go` had the same problem on a separate code path. CLI now delegates to `hdfparsers.ParseResults` / `ParseBaseline`; `validate.go` runs `hdfparsers.NormalizeTimestamps` before `validators.Validate`. Verified end-to-end against `multilayered-inspec.json` (1603 reqs, all timestamps lack TZ). (Closes `hdf-libs-mccc`; #89)
- **AWS Config converter synthesizes `notApplicable` for zero-evaluation rules** — `hdf fetch aws-config` previously wrote requirements with `results: []` when a deployed Config rule evaluated zero in-scope resources, violating the schema's `minItems: 1` invariant. Both Go and TS converters now synthesize a single `notApplicable` result in that case, with a `codeDesc` explaining the rule's check ran but had no scope. Matches AWS Config's own console depiction (a dash, not "Compliant") — auditors see that no determination was made, not a vacuous "passed". (Fixes #80; #81)
- **`hdf-schema/helpers.d.ts` import path** — `helpers.d.ts` imported from `../dist/ts/hdf-results.js`, which was the per-document file removed by #77's combined-output refactor. Every attw entry that re-exports from `./helpers.js` failed type resolution post-merge, breaking the Pre-release checks workflow on main. Repointed to the consolidated `../dist/ts/hdf.js`. Also moved `publint` + `arethetypeswrong` from `pre-release.yml` into `ci.yml` so packaging defects surface on the PR that introduces them, not after merge to main. (#85, #87)

### Breaking Changes — Converters

- **`oscal-poam-to-hdf` now outputs an HDF Amendments document, not Results.** OSCAL POA&M is consumer-attached remediation context — the same conceptual shape as the `poam` override type — so it belongs alongside the VEX converters (`openvex`, `csaf-vex`, `cyclonedx-vex`) as an amendment-output converter. Each `poam-item` becomes one `Standalone_Override` (type `poam`) with milestones; `risks[]` populate the override's `requirementId` and `status`. The CLI auto-detects amendments via the top-level `overrides[]`, so downstream `hdf validate` / `hdf amend apply` work without flags. Consumers that previously parsed `hdf convert --from oscal-poam` output as Results must switch to Amendments (see `site/docs/guides/oscal-alignment.md` § POA&M to Amendments).

### Breaking Changes — TypeScript

- **Generated enum type renames** (no deprecation aliases provided). External code that imports any of the following from `@mitre/hdf-schema` must update the identifier:
  - `Copyright` → `TargetType` (component/target type discriminator)
  - `OwnerType` → `IdentityType` (identity kind: email/username/system/simple/other)
  - `Status` → `MilestoneStatus` (POA&M milestone status)
  - `SbomFormat` → `SBOMFormat`
  - `PoamType` → `POAMType`
- **Document root type renames** with deprecation aliases. Code importing the old names from `@mitre/hdf-schema` keeps compiling for now via `@deprecated` aliases; expect those aliases removed in a future bump. Migrate to the canonical names:
  - `HdfResults` → `HDFResults`
  - `HdfBaseline` → `HDFBaseline`
  - `HdfComparison` → `HDFComparison`
  - `HdfSystem` → `HDFSystem`
  - `HdfPlan` → `HDFPlan`
  - `HdfAmendments` → `HDFAmendments`
  - `HdfEvidencePackage` → `HDFEvidencePackage`
- **Subpath import compatibility narrowed.** The subpath exports (`@mitre/hdf-schema/hdf-results`, `/hdf-baseline`, etc.) now resolve to the combined `dist/ts/hdf.d.ts`, which carries only the canonical `HDF*` names. Subpath imports of the old `Hdf*` names will fail to resolve. Either move to the bare `@mitre/hdf-schema` import (where the deprecated aliases live) or switch to the canonical names at the subpath site.
- **`@mitre/hdf-diff`**: `HdfComparison` interface renamed to `HDFComparison`. A `@deprecated` alias `HdfComparison = HDFComparison` is re-exported from the barrel; existing `HdfDiff` alias is unchanged.

### Breaking Changes — Go

- **Generated enum type renames** (no Go aliases provided). Go consumers that reference `hdf.Copyright`, `hdf.OwnerType`, `hdf.Status` (as a *type*), `hdf.SbomFormat`, or `hdf.PoamType` no longer compile. Replace with `hdf.TargetType`, `hdf.IdentityType`, `hdf.MilestoneStatus`, `hdf.SBOMFormat`, `hdf.POAMType` respectively. All in-repo Go converters have been updated; out-of-tree Go consumers must mirror the rename.
- **`hdf.CopyrightApplication` constant removed.** It was a backward-compat alias for `hdf.Application`. Use the canonical name.

### Validation Changes (stricter — may reject previously-accepted documents)

- **`Component.type` is now a closed 11-value enum** (`host`, `containerImage`, `containerInstance`, `containerPlatform`, `cloudAccount`, `cloudResource`, `repository`, `application`, `artifact`, `network`, `database`). Previously declared as `"type": "string"` with the comment "Same values as Target types," but the enum was not enforced, so documents emitting out-of-list values (e.g. `lambda`, `iam-role`, `function`) validated cleanly. They will now fail validation. The closed set matches `Target.type` and the long-standing design intent — this brings validation in line with the documented contract. If you produce HDF documents with custom component types, either map them to one of the 11 canonical values or pick the closest match.
- **`Standalone_Override` with `type: "operationalRequirement"` may no longer carry `status` or `impact`.** The override is documentation-only — it records accepted risk without changing the finding. Documents that previously paired `operationalRequirement` with a status/impact value will now fail schema validation. The CLI (`hdf amend create --type operationalRequirement`) no longer emits a default `status: "failed"` on this type.

### Schema Output Format (Go marshaling)

- **`omitempty` removed from required `interface{}` fields** on `DataFlow.To`, `Impact_Override.Value`, and `Requirement_Diff.before`/`after`. The native quicktype option that replaces the previous regex post-processor correctly recognizes these fields as schema-required and does not emit `omitempty`. JSON output now serializes `null` for the rare case of a Go-nil interface on these fields, rather than omitting them. Required-field semantics were always documented this way; previously the regex post-processor silently violated them. `ComponentDiff.before`/`after` (which ARE optional) retain `omitempty` after a separate fix.

### Removals

- **`@mitre/hdf-converters`**: `hdf-version.ts` and its test removed. Use the `legacyhdf-to-hdf` converter for v1→current overlay flattening.
- **`@mitre/hdf-converters` `shared/typescript/converterutil.ts`**: re-exports of `Applicability`, `ControlType`, `VerificationMethodEnum`, `DEFAULT_MAX_ITEMS`, and `deriveControlType` removed. Import these directly from `@mitre/hdf-schema` (the first three) or use `deriveControlTypeFromTags` (the public API).

### Build Pipeline

- **`hdf-schema/package.json`'s `build:schemas` now auto-syncs** `dist/schemas/*.schema.json` to `hdf-validators/go/schemas/` so the embedded validator schemas never drift from the bundled output. The previous manual `cp` step is no longer required (and the manual rule has been removed from CLAUDE.md).
- **Type generation parallelized.** TS and Go quicktype runs in `generate-types.ts` now execute concurrently via `Promise.all`. Halves the type-generation wall-clock on every build.

### Internal

- Identity type deduplication achieved via combined TypeScript output (`dist/ts/hdf.ts`) — same approach as the existing Go output. Fixes the long-standing bug where `Identity` in a per-file output was nominally incompatible with `Identity` in another. (Fixes #76.)
- Schema source-of-truth for inline enum naming is now the `title` property on each enum. Quicktype derives stable, predictable names from titles instead of inventing them from context.
- `generate-types.ts` simplified: 287 → 153 lines (47% reduction). Dead `toOutputFilename`, dead outer `schemaInput` builder, error-recovery fallback paths, and the "other languages" loop all removed.
- `hdf-parsers` deduped `TrimSpace` and `[]byte → string` conversions. `ParseResults` / `ParseBaseline` previously did two conversions and two trim passes per call (once for the empty-check, once for the decoder); reordered so `NormalizeTimestamps` runs first and a single `TrimSpace` covers both purposes. (Closes `hdf-libs-komt`; #90)
- `computeCompleteness` in `hdf-cli`'s `evidence_build.go` uses raw `json.Unmarshal` walking instead of typed parsing — documented as intentional for a best-effort summary metric over arbitrary HDF where forward-compat with future schema additions matters more than type fidelity. (`c250ff1`)
- Build-pipeline CI hygiene: include `hdf-generators` and `hdf-extension-graph` `dist/` in the build artifact (verify-packages was failing on these two missing dirs); wire Node 22 through every workflow's setup-action call. (#85, #87)
- Dev-dependency CVE management: added pnpm override for `shell-quote@<1.8.4` (transitive critical: GHSA-w7jw-789q-3m8p via `concurrently`); added `pnpm.auditConfig.ignoreGhsas` for esbuild `GHSA-gv7w-rqvm-qjhr` (Deno-specific advisory; doesn't apply to our Node-only usage, and bumping past 0.28.1 breaks vitepress).
- Spec doc Override table corrected: shows the actual schema field names — `reason` (required free-text) and `justification` (optional VEX-aligned enum, new in v3.3.0). The previous table conflated the two by labeling the required string field as `justification`.

### Architecture Changes

- Schema version bumped from v3.2.0 to v3.3.0 across all `$id`/`$ref` URLs.

### Compatibility

- New schema fields (CVE ecosystem on requirements, `justification` on overrides) are all optional and additive — v3.2.x documents validate cleanly under v3.3.0.
- Breaking changes (enum type renames, document root type renames with deprecation aliases, narrowed subpath imports) require TypeScript and Go consumer updates. See Breaking Changes sections above.
- Stricter validation (closed `Component.type` enum, `operationalRequirement` without `status`/`impact`) may reject documents that previously passed. See Validation Changes above.

## [3.2.0] - 2026-05-11

### New Features

- **Control classification fields on `Requirement_Core`** — three optional, additive enum fields make catalogs self-describing about how a requirement should be categorized, verified, and applied. All three are optional; v3.1.x documents validate cleanly under v3.2.0 and consumers continue to work unchanged.
  - **`controlType`**: `policy | procedure | technical | management | operational`. Aligns with NIST SP 800-53 / SP 800-53A categories. Lets cross-framework translation (NIST → CIS → CMMC) preserve fidelity instead of forcing heuristic derivation from family conventions.
  - **`verificationMethod`**: `automated | manual-by-design | manual-pending-automation | hybrid`. Disambiguates the two distinct cases that null `code` overloads today — inherently manual (e.g. FedRAMP 20x KSIs) versus automation-could-exist-but-doesn't-yet (e.g. a STIG rule lacking a fix). Enables automation-coverage metrics across frameworks from HDF alone.
  - **`applicability`**: `required | optional | advisory`. Distinct from severity (risk weight) and status (lifecycle state). Provides a uniform expression for the within-baseline applicability that frameworks already carry in incompatible forms (FedRAMP rev5 OSCAL `CORE` prop, FedRAMP 20x inline `Optional:` markers, CIS Implementation Group memberships, CMMC sublevels).
- **`Requirement_Core` examples expanded** with four scenarios covering: v3.1.x-style (classification fields omitted), all-three-fields populated, manual-by-design KSI-style, and manual-pending-automation STIG-style.
- **`code` field description** updated to reference `verificationMethod` as the canonical way to disambiguate manual-by-design from manual-pending-automation.

### Architecture Changes

- Schema version bumped from v3.1.0 to v3.2.0 across all `$id`/`$ref` URLs.

### Compatibility

- Fully backward compatible. New fields are optional; existing v3.1.x documents validate without modification.
- Surfacing the new fields in consumers is opt-in. Heimdall, hdf-converters, and hdf-validators continue to work unchanged.
- Internal Go consumer note: the `hdf.Automated` constant on `PlanType` was renamed to `hdf.PlanTypeAutomated` by quicktype to disambiguate against the new `VerificationMethodEnum.Automated`. One internal caller (`hdf-converters/oscal-to-hdf/converter_sap.go`) was updated; external Go consumers using the un-prefixed name will see the same compile-time rename.

## [3.1.1] - 2026-04-23

### Go Module Changes

- **Go module paths now include `/v3` suffix** per Go major version convention. Consumers update imports from `github.com/mitre/hdf-libs/hdf-converters` to `github.com/mitre/hdf-libs/hdf-converters/v3` (and similarly for all other modules). This enables `go install` and `go get` to resolve versions correctly from the module proxy.
- **hdf-schema Go module path corrected** from `github.com/mitre/hdf-schema` to `github.com/mitre/hdf-libs/hdf-schema/dist/go/v3`.
- **goreleaser ldflags fixed** — version, commit, and date are now correctly injected into CLI binaries.
- **hdf-diff/go and hdf-utilities/go added to release workflow** — these modules now receive version tags alongside the other Go modules.

## [3.1.0] - 2026-04-23

### Breaking Changes

- **`exception` removed from Override_Type enum.** The `exception` override type was redundant with `waiver` + `status: "notApplicable"` and has no equivalent in FedRAMP or NIST RMF terminology. Existing HDF documents with `"type": "exception"` in statusOverrides or standalone overrides will fail schema validation against v3.1.0. **Migration:** Replace `"type": "exception"` with `"type": "waiver"` and set `"status": "notApplicable"`.
- **Python type generation removed.** The generated Python types were vestigial and never consumed. Only TypeScript and Go types are generated from v3.1.0 onward.

### New Features

- **Override_Type expanded** with 3 new values aligned with FedRAMP deviation request categories: `falsePositive` (scanner incorrectly identified a finding), `riskAdjustment` (impact score adjusted based on environmental context), `operationalRequirement` (deviation required by operational constraints)
- **Impact overrides** — `Status_Override` and `Standalone_Override` now support an optional `impact` field (`Impact_Override` object with a `value` from 0.0 to 1.0). At least one of `status` or `impact` must be set (enforced via `anyOf`).
- **`disposition` field** on `Evaluated_Requirement` — indicates the type of the governing override or POAM. Enables consumers to distinguish adjudication context (e.g., false positive vs genuinely not applicable).
- **`effectiveImpact` field** on `Evaluated_Requirement` — the computed impact score (0.0-1.0) after applying the most recent non-expired impact override.
- **`vendorDependency`** added to POAM type enum — tracks fixes that depend on a vendor releasing a patch or update.
- **Comprehensive examples** added to `Evaluated_Requirement` covering all disposition patterns.

### Architecture Changes

- **Go diff engine extracted** from `hdf-cli/pkg/diff/` to `hdf-diff/go/` — matches the monorepo pattern used by other packages.
- **`hdf-cli/pkg/hdf/` eliminated** — all Go code now imports canonical types from `hdf-schema/dist/go/`.
- **Amendment operations extracted** to `hdf-diff/go/amend/`.
- **Go module paths renamed** to `github.com/mitre/hdf-libs/*` with `go.work` workspace — enables `go get` for all Go library modules.
- **`dist/` build artifacts untracked** — TypeScript and schema dist outputs are now built at install/publish time. Go generated types remain committed (required for `go get`).

### Security Fixes

- Add `ValidateJSONSize` to legacyhdf converter
- Add top-level HTTP client timeout (5 min) to fetcher clients
- Add CSV formula injection sanitization to diff CSV renderer
- Add newline escaping to markdown table cell renderer
- Add schema validation to `amend apply` command
- Switch `evidence build` to size-limited `readInputFile`
- Add `sanitizeOutput` to `amend list` terminal output
- Fix thread-safe schema caching in `hdf-validators/go` (`sync.Once` with persistent error propagation)
- Bump `fast-xml-parser` 5.5.7 → 5.7.1 (GHSA-gh4j-gqv2-49f6, XML comment/CDATA injection)

### Quality Improvements

- Add `.golangci.yml` to 6 Go library modules
- Fix broken fixture paths in `hdf-diff/go` integration tests
- Fix `baselineReqsToEvaluated` dropping `Severity` field
- Add `type-check` script to `hdf-schema`
- Add `dispositionChanged` and `effectiveImpactChanged` to diff engine change detection
- Track `effectiveImpact` and `disposition` in `hdf-extension-graph` modification detection
- Schema version bumped from v3.0.0 to v3.1.0 across all `$id`/`$ref` URLs

### Bug Fixes

- Fix `workspace:*` → `workspace:^` in inter-package dependencies — resolves `npm install` failure for published packages (#28, #39)

### Compatibility

- TypeScript 6 compatibility for `create-index` and `type-check` scripts

## [3.0.0] - 2026-03-15

Initial public release of the HDF Libraries monorepo. Ground-up rewrite of the Heimdall Data Format ecosystem, previously spread across heimdall2, saf-cli, and inspec-objects. Followed by patch release v3.0.1 with deduplication fixes and barrel export corrections.

### Schema (`@mitre/hdf-schema`)

- **7 document types**: Results, Baseline, System, Plan, Amendments, Evidence Package, Comparison
- **JSON Schema 2020-12** with `unevaluatedProperties` enforcement
- **Polymorphic components**: 11 component types (host, container image/instance/platform, cloud account/resource, repository, application, artifact, network, database) with stable UUID identity, SBOM embedding, and external ID cross-references
- **Data flows**: typed interconnections between components with protocol, port, direction, and classification
- **Control inheritance**: controlDesignations for common/hybrid/system-specific controls with provider/inheritor tracking
- **Integrity fields**: algorithm + checksum + optional signature on all document types
- **Tool provenance**: `tool` field (name, version, format) identifies the source security scanner — aligns with SARIF, OSCAL, and CycloneDX terminology
- **Multi-language types**: TypeScript, Go, and Python generated from schemas via quicktype
- **Self-contained bundled schemas**: each dist schema embeds all referenced primitives — no external fetches needed
- **Hosted at**: `https://mitre.github.io/hdf-libs/schemas/`

### Converters (`@mitre/hdf-converters`)

- **33 security tool converters** in both TypeScript and Go:
  AWS Config, BurpSuite, Conveyor, CycloneDX, DBProtect, Dependency-Track, Fortify, GitLab SAST/DAST, gosec, Grype, Ion Channel, JFrog Xray, JUnit, Legacy HDF v1, Microsoft Defender (Cloud, DevOps, Endpoint), Microsoft Secure Score, Nessus, Netsparker/Invicti, NeuVector, Nikto, OSCAL (7 document types), Prisma Cloud, SARIF, ScoutSuite, Snyk, SonarQube, Splunk, TruffleHog, Twistlock, Veracode, XCCDF/ARF, ZAP
- **Output converters**: HDF-to-CSV, HDF-to-XML, HDF-to-XCCDF, HDF-to-OSCAL (SAR, POA&M)
- **Auto-detection**: fingerprint registry identifies input format from content structure
- **V1→V2 migration**: bidirectional HDF version transform (upgrade and lossy downgrade)
- **Shared utilities**: `BuildHDFResults` (Go) / `buildHdfResults` (TS) for consistent result construction, severity-to-impact mapping, CWE→NIST control mapping, input size validation, XML entity expansion prevention

### CLI (`hdf`)

- **Validate**: schema validation with line-number error reporting
- **Convert**: `hdf convert <file> -o <output>` with auto-detection, `--from`/`--to` flags, and 33+ source formats
- **Query**: filter requirements by status, severity, impact, NIST, CCI, STIG ID, tags, text search
- **Generate**: `hdf generate inspec-profile` from HDF Baseline JSON or XCCDF benchmark XML; `hdf generate threshold` for CI/CD compliance gates
- **Threshold**: `hdf validate threshold` with YAML templates or inline expressions, SAF CLI compatible
- **Diff**: structural comparison of HDF documents with exit codes for CI
- **System management**: create, set, add-component, update-component, data flows, SBOM embedding
- **Plan management**: create (from system or standalone), set, with auto-UUID
- **Amendments**: create waivers/attestations/POA&Ms with TUI flow, apply to results
- **Evidence packages**: build, verify (completeness + checksums), info
- **Fetch**: pull scan data from Splunk, GitLab, SonarQube, AWS Config with TLS options
- **List/Info/Stats**: human-readable and JSON output for all document types
- **Cross-platform binaries**: goreleaser builds for linux/darwin (amd64+arm64) and windows (amd64)

### Mappings (`@mitre/hdf-mappings`)

- CCI ↔ NIST 800-53 bidirectional mappings
- CWE → NIST 800-53 control mapping
- OWASP → NIST mapping
- Tool-specific mappings: Nessus, Nikto, ScoutSuite, AWS Config

### Other Packages

- **`@mitre/hdf-utilities`**: XML/CSV/JSON parsing, SHA-256/SHA-512 hashing, string manipulation
- **`@mitre/hdf-validators`**: schema validation with embedded bundled schemas
- **`@mitre/hdf-parsers`**: parse and flatten HDF documents
- **`@mitre/hdf-generators`**: generate InSpec profile stubs from HDF Baselines
- **`@mitre/hdf-diff`**: structural diff engine with fuzzy matching, multi-source comparison
- **`@mitre/hdf-extension-graph`**: InSpec profile overlay/extension chain resolution

### Security

- Path traversal prevention on all JSON-controlled file paths (evidence verify, InSpec generator)
- Input size validation (50MB default) on all converter entry points
- XML entity expansion (XXE) prevention on all XML converters
- Control ID sanitization for filesystem output
- No secrets in code; test-only tokens annotated

### Infrastructure

- pnpm workspace monorepo with 10 packages
- CI: ESLint, golangci-lint (39 linters), govulncheck, gosec, pnpm audit
- Pre-commit hook: `pnpm check` (build + lint + test + security)
- Release workflow: tag-triggered npm publish + goreleaser binaries + schema assets
- GitHub Pages: automatic schema deployment on push to main
- Go module tags: per-module version tags for Go module proxy discovery
