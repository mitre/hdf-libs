# Changelog

All notable changes to this project will be documented in this file.

## [3.1.0] - 2026-04-19

### Breaking Changes

- **`exception` removed from Override_Type enum.** The `exception` override type was redundant with `waiver` + `status: "notApplicable"` and has no equivalent in FedRAMP or NIST RMF terminology. Existing HDF documents with `"type": "exception"` in statusOverrides or standalone overrides will fail schema validation against v3.1.0. **Migration:** Replace `"type": "exception"` with `"type": "waiver"` and set `"status": "notApplicable"`.

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

### Security Fixes

- Add `ValidateJSONSize` to legacyhdf converter
- Add top-level HTTP client timeout (5 min) to fetcher clients
- Add CSV formula injection sanitization to diff CSV renderer
- Add newline escaping to markdown table cell renderer
- Add schema validation to `amend apply` command
- Switch `evidence build` to size-limited `readInputFile`
- Add `sanitizeOutput` to `amend list` terminal output
- Fix thread-safe schema caching in `hdf-validators/go` (`sync.Once` with persistent error propagation)

### Quality Improvements

- Add `.golangci.yml` to 6 Go library modules
- Fix broken fixture paths in `hdf-diff/go` integration tests
- Fix `baselineReqsToEvaluated` dropping `Severity` field
- Add `type-check` script to `hdf-schema`
- Add `dispositionChanged` and `effectiveImpactChanged` to diff engine change detection
- Track `effectiveImpact` and `disposition` in `hdf-extension-graph` modification detection
- Schema version bumped from v3.0.0 to v3.1.0 across all `$id`/`$ref` URLs

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
