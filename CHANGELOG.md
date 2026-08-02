# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added

- **STIX 2.1 CTI enrichment — `hdf enrich`.** A new enrichment pass overlays a STIX 2.1 bundle onto an existing HDF results document: a CVE-bearing STIX object attaches to the finding whose requirement ID is that CVE (`rel: investigate`), everything else (non-CVE objects, and CVEs with no matching finding) attaches to the results root (`rel: reference`) — each as an `External_Reference` enrichment envelope carrying the raw STIX object losslessly in `document`. Informational by default: it authors no overrides and changes no status or impact. Source format is auto-detected (`--from stix` to assert). Dual Go + TS. (ADR-0006)
- **`External_Reference` primitive + broad `externalReferences[]` wiring.** A generalized, purpose-agnostic reference (modeled on the STIX 2.1 `external_references` common property): required `sourceName` plus at least one of `externalId`/`href`/`description`, open `rel` and `kind` tokens, optional `mediaType`/`checksum`/`addedBy`/`addedAt`, and an optional lossless embedded `document` that turns a bare reference into an enrichment envelope. Wired across the HDF schemas, including on the inline `Status_Override`.
- **CVSS scoring engine in `hdf-utilities` (Go + TS).** Base + Threat score computation for CVSS **3.1** (`computeCvssScore`) and CVSS **4.0** (`computeCvss40Score` — the FIRST MacroVector algorithm with max-vector severity-distance interpolation, validated exact against FIRST reference vectors across 0.0–10.0). Extends the existing parse/validate; no third-party dependency; Go and TS produce byte-identical scores via a shared data table.
- **Opt-in CVSS Threat recompute — `hdf enrich --recompute-cvss`.** When a matched STIX object shows active exploitation (a sighting, a `targets`/`exploits` relationship, or an indicator/report reference) and the finding carries a CVSS 3.1 base vector, applies Exploit Maturity `E:H` and recomputes the Threat score, authoring an auditable inline `riskAdjustment` (with the `cvss` block, `impact.value = computedScore/10`, a review-horizon `expiresAt`, and an `externalReferences[]` back to the STIX source). Findings with no base vector — or a CVSS 4.0 base vector — are left unchanged. Exploitation maps to CVSS Exploit Maturity only, never to `Kev`/`Epss`.
- **`roundImpact` / `RoundImpact` in `hdf-utilities` (Go + TS).** Canonical rounding of a computed impact to its natural 0.01 grid, eliminating binary-float representation noise (e.g. `score/10` serializing as `0.9800000000000001`). Consumed by the enrich recompute.

### Notable behavior changes

- **`tool.format` now names formats, never serialization structures.** The field's schema description is sharpened: it carries a named format specification — an interchange format emitted by many tools (`SARIF`, `XCCDF`, `ARF`, `OSCAL`) or one of several named outputs a single tool produces (`FVDL`, `exec-json`) — and is omitted for a tool's native output. Twenty-three converters that stamped bare `JSON`/`XML`/`CSV` serialization labels no longer emit `tool.format` at all, `deptrack-to-hdf` now emits `FPF` (the Dependency-Track Finding Packaging Format) instead of `JSON`, and `checkov-to-hdf` no longer abuses `tool.format` for the scan scope — each requirement instead carries a `tags.check_type` array naming the framework report it came from (e.g. `["terraform"]`), which is new consumer-visible data. Consumers pinning exact converter output will see the `tool.format` key disappear (or change to `FPF`); the tool name and version are unchanged. Go and TypeScript in lockstep, goldens regenerated.

### Compatibility

- The schema additions are additive and optional (`External_Reference`, `externalReferences[]`, `kind`, `document`, and the inline `Status_Override.externalReferences[]`); existing v3.x HDF documents validate unchanged.

## [3.4.4] - 2026-07-30

### Fixes

- **`hdf convert --to hdf@2` (v3→v2 downgrade) now produces InSpec-exec-json documents Heimdall can load.** The downgrade previously emitted a structurally minimal legacy document that Heimdall's InSpec parser rejected — it omitted fields InSpec requires to be present even when empty (`platform.release`, profile `sha256`/`supports`/`attributes`/`groups`, control `refs`/`tags`/`source_location`, result `start_time`) and emitted result statuses outside InSpec's `error`/`failed`/`passed`/`skipped` enum — and it silently dropped amendments. It now emits every InSpec-required field, maps `notApplicable`/`notReviewed` result statuses to `skipped`, flattens status-changing amendments (waiver, falsePositive, attestation) into the control status with a `waiver_data` breadcrumb, carries `riskAdjustment` into the control impact, and warns on stderr for amendments with no v2 representation (POA&M, operationalRequirement). Verified against Heimdall's `exec-json.json` schema. Go transform with a TypeScript parity peer. (#181)
- **`grype-to-hdf`: requirements now carry a title and a real scan timestamp.** Each finding gets a title of the form `Grype found a vulnerability to <id> in <target>` (matching heimdall2's grype converter), and every result's `start_time` is anchored to the scan's `descriptor.timestamp` instead of the Go zero time — so a downgraded Grype scan sorts by its real date and shows a control title in Heimdall. Dual Go + TS. (#185)

### Notable behavior changes

- **The `hdf@3 → hdf@2` downgrade output changed shape.** Anyone consuming the previous v3→v2 output will see a different, now InSpec-conformant document: previously-absent InSpec-required fields are present, `notApplicable`/`notReviewed` result statuses serialize as `skipped`, and amendments are flattened into control status plus `waiver_data` (see Fixes). The prior output did not load in Heimdall at all, so this replaces broken behavior rather than changing working behavior. (#181)
- **`grype-to-hdf` requirements gained `title` and real `start_time`** (see Fixes). A consumer pinning exact grype→HDF output will see these two fields change; every other field is unchanged. (#185)

### Internal

- Pre-release review fixes: aligned the TypeScript v2-downgrade peer with the Go transform (profile dependencies emit only `name`/`url`/`path`/`git`; statistics projected to `duration`; typed `resultsChecksum`), stopped an expired override from naming itself in the `waiver_data` breadcrumb (Go + TS), made the grype top-level timestamp deterministic across Go/TS, and corrected stale API references in the `hdf-generators`, `hdf-utilities`, and `hdf-validators` READMEs. Added a vendored InSpec `exec-json` schema with an in-test validation of the downgrade output. The pre-commit hook now works from git worktrees. The `qs` audit override was advanced to `>=6.15.2` (GHSA-q8mj-m7cp-5q26). Dev-dependency bumps. (#181, #182, #183, #185)

### Compatibility

- Patch release: **no schema changes** — schema `$id` URLs remain at v3.4.0 and all v3.x HDF documents validate unchanged. The changes above affect converter output (`grype-to-hdf` title/start_time) and the `hdf@3 → hdf@2` downgrade behavior, not the schema.

## [3.4.3] - 2026-07-26

### Added

- **`hipcheck-to-hdf` converter.** Converts MITRE Hipcheck supply-chain analysis reports to HDF, backed by a new `hipcheck` NIST 800-53 Rev 5 mapping (analysis name → controls). Dual Go + TS. (#178)
- **`defectdojo-to-hdf` converter and live fetcher.** Converts DefectDojo findings to HDF and adds `hdf fetch defectdojo` to pull them from a DefectDojo instance (token auth, `--check` credential verification). Handles an empty result set gracefully (produces the no-findings HDF rather than erroring). Dual Go + TS. (#177)
- **AWS Config NIST-mapping coverage expansion.** A new checked-in generator (`hdf-mappings/scripts/generate-awsconfig-mappings.mjs`) rebuilds the AWS Config→NIST 800-53 table from authoritative AWS sources — AWS Config "Operational Best Practices" docs plus AWS Security Hub's NIST 800-53 r5 standard — and a derived strong-theme tier fills the residual, lifting Rev 5 catalog coverage from ~37% to ~47%. The three tiers (config-pack / security-hub / derived) are documented in the `hdf-mappings` README, with the caveat that these tags are candidate control associations for triage, not assessed-control evidence. (#175)

### Notable behavior changes

- **`aws-config-to-hdf`: unmapped Config rules now carry `nist: ["CM-6"]`.** A managed or custom Config rule with no entry in the mapping tables previously emitted no `nist` tag (`tags: {}`); it now floors to CM-6 (Configuration Settings) — an honest baseline, since every Config rule evaluates a configuration setting — and consequently derives an `operational` `controlType` where before it derived none. Mapped rules are unchanged. (#175)
- **`asff-to-hdf`: unmapped Security Hub Config-rule findings now floor to `nist: ["CM-6"]`.** They previously received the static-analysis default (`SA-11`, `RA-5`); they now match the `aws-config-to-hdf` floor, so the same Security Hub signal tags consistently across both converters. Generic ASFF scanner findings keep the `SA-11`/`RA-5` default. (#175)
- **HDF version-identifier taxonomy corrected.** `hdf convert --to hdf@N` and related version specifiers now number the legacy Heimdall/InSpec-ExecJSON shape as **hdf@2** and the modern hdf-libs schema as **hdf@3**. **hdf@1** is not a distinct schema (it is raw InSpec exec-json); it is accepted with a warning and mapped to hdf@2. Ingest raw InSpec with `--from inspec`. (#176)

### Internal

- Pre-release swarm review resolved cross-library duplication in the two new converters (shared severity→impact, CWE→NIST, and HDF-results builders reused instead of hand-rolled) and refreshed stale CLI/spec documentation. The `brace-expansion` audit override was advanced to `>=5.0.8` for GHSA-mh99-v99m-4gvg.

### Compatibility

- Patch release: **no schema changes** — schema `$id` URLs remain at v3.4.0 and v3.x HDF documents validate unchanged. The behavior changes above affect converter *output tags* and CLI version-specifier semantics, not the schema.

## [3.4.2] - 2026-07-24

### Notable behavior change

- **`hdf fetch aws-config` now excludes service-linked Config rules.** Rules owned by an AWS service (`CreatedBy` set — AWS Security Hub, conformance packs, Organizations) cannot be read via the Config API by a customer principal, and the previous fetcher **crashed** on any account that had them (a Security-Hub-enabled account, commonly). They are now skipped entirely — no compliance query, no output row — with a `WARNING: skipped N service-linked rule(s)` on stderr. Fetch their findings through the owning service instead (e.g. `hdf fetch aws-securityhub` for Security Hub controls). Consumers who previously saw these rows crash rather than convert; there is no loss of working behavior.

### Added

- **`aws-config-to-hdf`: remediation `fix` descriptions.** A customer-managed Config rule with an attached remediation configuration (SSM Automation document) now gains a `fix` description in its HDF requirement, and the `aws-config` fetcher pulls `DescribeRemediationConfigurations` to populate it. Dual Go + TS. (#167)
- **`trufflehog-to-hdf` accepts empty clean-scan output.** TruffleHog emits no report (empty stdout) on a clean scan; the converter now treats empty/whitespace-only input as zero findings. The CLI empty-input carve-out is generalized via an `EmptyInputAccepting` capability — empty stays an error for every other converter, honored only with an explicit `--from`. (#173, Refs hdf-libs-iow3)

### Fixes

- **`asff-to-hdf`: Trivy misconfiguration and secret findings are enriched.** `trivyMessage` now dispatches on finding shape so a Trivy misconfiguration surfaces its remediation message and file location and a secret surfaces its file, instead of only enriching CVE findings. Dual Go + TS at byte-identical parity. (#160)
- **`hdf-mappings` (AWS Config NIST): collapsed Rev-4 sub-parts are expanded.** Rev-4 rows carried collapsed NIST tokens (e.g. `IA-5(1)(a)(d)(e)`) that `split('|')` left as single unreachable tokens; they now resolve to sibling controls. Also benefits the Security Hub path, which resolves decorated rule names through this table. (#167)

### Internal

- Dependabot holds TypeScript major bumps until typescript-eslint supports them; a release **suppression-review** step (Phase 1.6) periodically retires stale audit overrides, dead `ignoreGhsas` suppressions, and outdated ignore rules. Audit override for `postcss` refreshed past an escalated advisory. (#169)

### Compatibility

- Patch release: **no schema changes** — schema `$id` URLs remain at v3.4.0. Aside from the `aws-config` service-linked-rule exclusion noted above, changes are additive converter/fetcher enrichment and fixes.

## [3.4.1] - 2026-07-16

### Added — Converters

- **`asff-to-hdf`: AWS Security Finding Format → HDF** (`hdf convert --from asff`). Converts ASFF findings — AWS Security Hub controls, plus Prowler (NDJSON) and Aqua Trivy product cases — into HDF, one baseline per product/standard, with auto-detect. Ships the **`aws-securityhub` fetcher** (`hdf fetch aws-securityhub`: paged `GetFindings`, `--check` credential verification, and a `--filter-json` `AwsSecurityFindingFilters` passthrough) and a substring-tolerant awsconfig NIST resolver for Security Hub's decorated `securityhub-<canonical>-<hash>` rule names. Dual Go + TS at byte-identical output parity. (#147, closes #143)
- **`hdf-to-asff`: HDF Results → AWS Security Finding Format** (`hdf convert --to asff`). Reverse exporter emitting the `{"Findings":[…]}` envelope that Security Hub `BatchImportFindings` accepts, one finding per requirement, deliberately lossy and standard-compliant — HDF structure ASFF cannot hold is dropped, not encoded into `Types[]` — and round-trips back through `asff-to-hdf`. `AwsAccountId` is recovered from a `cloudAccount` component. Dual Go + TS at byte-identical output parity; see the ASFF interoperability guide. (#154)

### Added — CLI

- **`hdf system add-component` accepts multiple BOM files in one invocation.** Pass N positional BOM files (shell globs expand for free) to add them all in a single system-document write — e.g. a build pipeline adding its SBOM + AI-BOM together. `--component-name-prefix` numbers unnamed subjects continuously across the whole batch; `--component-name` (which names a single component) is rejected in multi-file mode. The batch is **all-or-nothing** (validate-all-then-commit): every file is validated and built first, and if any fails, all failures are reported and nothing is written — deliberately stricter than `hdf validate`'s continue-and-report, because `add-component` mutates and appends. `--from`, when given, is a single uniform format assertion checked against every file (never a positional/CSV list). Single-file behavior is unchanged. (ADR-0005, hdf-libs-whlr)

### Fixes

- **`createResult` omits an empty `message`** — TS converters no longer emit a spurious `"message": ""` that Go's `omitempty` drops, restoring TS/Go parity; eight workaround converters collapse back to the shared helper. (#148)
- **`xccdf-results-to-hdf`: deterministic check selection** — a rule carrying multiple `<check>` elements now prefers the automated OVAL check over OCIL/SCE instead of letting document order decide, so `check_id` is stable. (#148, refs hdf-libs-i86q)
- **`checklist` (CKLB): `active` / `has_path` / `mode` are preserved across the HDF round-trip.** (#148)
- **`cyclonedx`: `boms[].document` key order is canonicalized** for Go/TS parity. (#148)
- **CLI: `evidence export` / `verify` read packages through the size-gated input boundary**, rejecting oversized inputs consistently. (#148)
- **Cross-language importer parity fixes** (surfaced by wiring oscal / legacyhdf / VEX into the shared snapshot harness): `legacyhdf` now flattens InSpec `options.value`/`type` (previously dropped every input value/type); `oscal` SSP `baselineRefs` ordering is deterministic; `oscal` POA&M extracts `risk.deadline` / task timing and fails loud when no deadline is derivable (previously fabricated dates from wall-clock `now()`); VEX importers emit the `1.0.0` `generator.version` default their Go twins already had. (#153)
- **Pre-release review fixes:** `asff-to-hdf` severity mapping delegates to the shared `hdf-utilities` table (removing a duplicated Go table), and `parseFindings` rejects valid-but-scalar JSON and treats `{"Findings":null}` as empty (Go/TS parity); a dead severity-remap branch was removed from `hdf-to-asff`; the `hdf-cli` README `go install` note and the workspace converter count were corrected.

### Internal

- **Test-strategy hardening:** input-derived ground-truth anchors were added to the structurally-rich importers (xccdf, ckl/cklb, nessus, oscal, sarif, legacyhdf, cyclonedx-vex) so a shared Go/TS misreading cannot stay green (#149, #153), and `startTime` golden-masking was made per-converter/fixture so importers that carry a real scan time assert it — which surfaced and fixed a nessus Go/TS serialization divergence (#152).

### Compatibility

- Patch release: **no schema changes** — the schema `$id` URLs remain at v3.4.0, and all v3.4.0 documents and consumers are unaffected. The changes are two new converters plus converter-output and importer-parity fixes.

## [3.4.0] - 2026-07-13

### Breaking Changes — Schema

- **Component artifact integrity is now a single generic `integrity[]` array of `Checksum` objects on `Base_Component`, replacing the per-type `Container_Image.digest` and `Artifact.checksum` fields.** One home for the integrity of any component's underlying bytes — model weights/shards, dataset archive, container image, or package — with an array to support multi-file/sharded artifacts. Distinct from BOM-document integrity (`Bom.hashes[]`) and the document tamper-evidence `Integrity` type. Migration: move a container image `digest` or artifact `checksum` into `integrity: [{ "algorithm": …, "value": … }]`. (ADR-0001)

- **Generalized BOM representation: the component `sbom` / `sbomRef` / `sbomFormat` trio is replaced by a single `boms[]` array of `Bom` objects** (discriminated by `bomType`), on both `Base_Component` and `hdf-system`. Each `Bom` carries either a passthrough shape (`ref` or `document`) or a normalized extension (`packages` for `sbom`, `model` for `ai-model`, `dataset` for `dataset`) — a `Bom` must carry at least one of these (a bare `{bomType, format}` is invalid). New `aiModel` and `dataset` component types model AI subjects, and the `ai-model` / `dataset` extensions carry cross-standard governance fields (`learningApproach`, `task`, `performanceMetrics`, `hyperparameters`, `inputOutput`; `modality`, `provenance`, `statisticalProperties`). `bomType` now also accepts `x-`-prefixed custom kinds alongside the reserved CycloneDX-aligned set.

  Migration — an external SBOM reference:

  ```jsonc
  // before
  { "name": "WebTier", "type": "application",
    "sbomRef": "https://artifacts.example.com/webtier.cdx.json", "sbomFormat": "cyclonedx" }

  // after
  { "name": "WebTier", "type": "application",
    "boms": [ { "bomType": "sbom", "format": "cyclonedx",
                "ref": "https://artifacts.example.com/webtier.cdx.json" } ] }
  ```

  An embedded SBOM moves from `"sbom": { … }` to `boms[].document`; the old `sbomFormat` value becomes `boms[].format`. (ADR-0001)

### Breaking Changes — CLI

- **`hdf system` reconciled with `hdf convert`: the input BOM/results file is now a positional argument, and `--from` selects the source format instead of naming the file.** All three subcommands change shape: `hdf system create <bom|url> [--from <format>]`, `hdf system add-component <bom|url> --system <doc> [--from <format>]`, and `hdf system update-component <bom|url> --system <doc> [--component-name <name>] [--from <format>]`. Previously `--from <file>` supplied the input path; that spelling is removed. Omitting `--from` keeps today's auto-detection unchanged; passing `--from` asserts a BOM format — the input is detected and the detected format must match (`cyclonedx`, `spdx`, `cyclonedx-mlbom`, or `spdx-ai`), and it is never force-parsed. On a mismatch or an unknown alias the command errors rather than guessing. Migration: move the file to the first positional and drop the `--from <file>` flag (e.g. `hdf system create results.json`); use `--from` only to assert a format (e.g. `hdf system create model.cdx.json --from cyclonedx-mlbom`). Relatedly, `cyclonedx-to-hdf` now emits an AI-BOM-specific message pointing at `hdf system create <file> --from cyclonedx-mlbom` when a no-vulnerability CycloneDX document carries a `machine-learning-model` component. (hdf-libs-cm7g)

- **`hdf system add-component` / `update-component` now ingest any BOM type, including multi-subject AI-BOMs** (superseding cm7g's interim AI-BOM reject). A single-subject BOM adds one correctly-typed component; a multi-subject SPDX-3 AI/Dataset document fans out into one `aiModel`/`dataset` component per subject, each stamped with its source subject id as `boms[].uniqueId`. `add-component` gains `--component-name-prefix` (namespace a multi-subject input; `--component-name` stays for single-component inputs and errors on multi-subject); a duplicate human-friendly name now warns instead of being rejected (names are labels, `componentId` is identity). `update-component` gains two modes: targeted (`--component-name`, replaces one component from a single-subject BOM) and reconcile (no `--component-name`, matches each subject to an existing component by `boms[].uniqueId` and refreshes it in place — so a system built from an AI-BOM can be refreshed from a later revision of the same source); unmatched subjects are skipped unless `--add-new`, and existing components absent from the BOM are left untouched. The subject→component builder is shared with `hdf system create` (no forked logic). (hdf-libs-opk1)

### Added — Schema

- **`agent` identity type for AI-agent provenance.** The `Identity.type` enum gains `agent` (additive — no existing document is invalidated), for an AI/LLM agent acting with autonomy. It is deliberately distinct from `system` (deterministic non-interactive automation like CI jobs, cron, and scanners) so auditors can apply AI-specific scrutiny and tooling can enforce AI-source policies (e.g. mandatory human review for `agent`-signed riskAdjustments; disclosure under the EU AI Act / NIST AI RMF). This supersedes the interim `type: "system"` + `identifier: "ai-agent:…"` convention previously documented for AI-suggested CVSS enrichment. (hdf-libs-psuv)
- **Host identity gains `hostname` and `domain` on `Host_Component`, and the `Hash_Algorithm` enum gains `blake3`.** `hostname` is the short OS-reported machine name and `domain` the directory (Active Directory / NetBIOS / LDAP) domain — both kept distinct from `fqdn` because an FQDN is not reliably decomposable into hostname + domain (ECS `host.hostname` / `host.domain` semantics; DISA STIG CKL `HOST_NAME`). The parallel `Runner` identity was reconciled to the same shape. All additive — no existing document is invalidated. (#133)
- **Carry external log/telemetry evidence by reference on `hdf-evidence-package`.** A new optional `externalEvidence[]` array of `External_Evidence_Reference` lets an evidence package point at native-format log/telemetry corpora (and other artifacts) by `uri` + integrity `checksum` + a `format` discriminator, without recreating the data inside HDF — logs are legitimate accreditation evidence and HDF acts as the structured index. `format` is an OPEN enum (reserved `ecs`, `ocsf`, `cyclonedx`, `spdx`, `raw-log` + `^x-` custom, mirroring `bomType`); serialization is captured separately via optional `mediaType` (MIME) and `formatVersion` (producer free-text), with optional `metadata` (`recordCount`, `timeRange`, `collector`). Reference-only — the artifact is never embedded (corpora can be huge) or transcoded (lossy). Query-time normalization models (Splunk CIM, Microsoft ASIM) are intentionally excluded — they have no portable stored artifact; reference their exported result set (JSON/CSV/NDJSON) via an `x-` format instead. `schema-one` is deferred until its authoritative spec is obtained. Additive — no existing document is invalidated. The `hdf evidence add-evidence` CLI command attaches these references (auto-computing a SHA-256 checksum when the URI is a local file, omitting it for a URL unless `--checksum` is supplied), and `hdf evidence info` surfaces them. (hdf-libs-8j9o)

### Added — Converters

- **`hdf-to-ecs` exporter: HDF Results → Elastic Common Schema NDJSON** (`hdf convert --from hdf --to ecs`). Emits one ECS 9.4.0 event per evaluated requirement as plain NDJSON, in a hybrid shape — a core-ECS-native projection (`event`/`rule`/`vulnerability`/`threat`/`observer`/`host`/`related.*`) for queryability alongside other security telemetry, plus a lossless `hdf.*` block preserving the full requirement (status, overrides, cvss, results, tags, poams) so nothing is dropped. Status is **raw-primary**: `event.outcome` carries the raw verdict (`passed→success`, `failed→failure`, else `unknown`) — a waived failure is still `failure`, never masked — with the lossless five-value status in `hdf.status`; the separate `hdf.suppressed` boolean marks raw-failing-but-accepted findings (waiver/falsePositive/attestation), while a risk-adjusted still-failing control stays actionable. Full override history preserved in `hdf.effective_status`/`hdf.disposition`/`hdf.status_overrides`. Canonical actionable-failures query: `event.outcome:"failure" AND hdf.suppressed:false`. CVE findings project `cvss[]`/`cwe` to `vulnerability.*`. Dual TS + Go at byte-identical output parity. Design: ADR-0002. (hdf-libs-wvc3)

- **`hdf-to-splunk` exporter: HDF Results → Splunk HEC (CIM) NDJSON** (`hdf convert --from hdf --to splunk`). Emits one HEC event per evaluated requirement (`sourcetype=hdf:results`, integer epoch `time`), in a hybrid shape — flat CIM-named scalars (`signature`/`signature_id`/`cve`/`cvss`/`severity`/`dest`/`vendor_product`/`category`) promoted to the top of the `event` payload and mirrored into the HEC indexed `fields` (so the hot fields beat Splunk's ~5000-char extraction cutoff), plus a lossless `hdf.*` block. `cvss` is the single max base score (per CIM typing; the full `cvss[]` rides in `hdf.*`); `severity` maps HDF impact to the CIM enum (`critical`/`high`/`medium`/`low`/`informational`); status is **raw-primary** — `hdf_status` carries the raw verdict (a waived failure is still `failed`) and a separate `suppressed` boolean (promoted to both `event` and the indexed `fields`) marks raw-failing-but-accepted findings. A companion technology add-on (`Splunk_TA_hdf`) tags failed/error/CVE findings into the CIM **Vulnerabilities** data model but excludes `suppressed=true` (tagging is impossible from the write side), so a waived control drops out while a risk-adjusted still-failing control stays in. Canonical actionable-failures query: `hdf_status=failed suppressed=false`. Shares its mapping core with `hdf-to-ecs`; dual TS + Go at byte-identical output parity. Design: ADR-0004. (hdf-libs-wvc3)

- **`hdf-to-ocsf` exporter: HDF Results → OCSF v1.8.0 Finding NDJSON** (`hdf convert --from hdf --to ocsf`). Emits one OCSF Finding per requirement — a CVE finding as a **Vulnerability Finding** (`class_uid 2002`), any other as a **Compliance Finding** (`class_uid 2003`), both under the Findings category. Unlike Splunk CIM, OCSF has native compliance *and* vulnerability finding classes, so the mapping is native rather than projected: control ids populate `compliance.checks[]` (`check.uid` = STIG/NIST/CCI id), CVSS maps 1:1 into `cve.cvss[]`, the host into `device`/`device.os`, and the full original requirement is preserved losslessly in OCSF's schema-sanctioned `unmapped.hdf_requirement`. **Status is raw-primary:** `compliance.status_id` always carries the raw verdict (a failed control stays `Fail` even when waived — never masked as a pass; the sibling `compliance.status` string is the OCSF caption `Pass`/`Warning`/`Fail`), while the acceptance axis rides the base finding `status_id` — `3 Suppressed` only when a waiver/falsePositive/attestation drove the raw failure non-failing, else `1 New`. A risk-adjusted still-failing control stays `New` (actionable), so a consumer filters open-actionable failures on normalized enums alone (`compliance.status_id=3 AND status_id=1`) — never on free text. `time` is epoch **milliseconds** (OCSF convention). Shares its mapping core with `hdf-to-ecs`; dual TS + Go at byte-identical output parity. Design: ADR-0002 addendum. (hdf-libs-wvc3)

### Fixes

- **`checklist` (CKL/CKLB): source-tool comments are kept separate from finding details** instead of being merged into the finding text on round-trip. (#145)
- **`xccdf-results-to-hdf`: traverses nested `<Group>` elements, keeps every rule, and maps rule severity**; the TypeScript importer was brought back to parity with its Go twin. Previously nested groups could drop rules and severity was not carried. (#137, #140)
- **`sonarqube-to-hdf`: corrected severity mapping.** (#135)
- **`hdf-to-csv`: output fixes** (alongside co-touched `csaf-vex`, `cyclonedx-vex`, `oscal-poam`, `oscal-sar` adjustments). (#134)
- **HDF ingest now accepts the zone-less timestamps real HDF documents carry**, parsing them via the canonical timestamp helper instead of failing or reading them as host-local. (#141)
- **`hdf-to-oscal-sar` reports the assessment time, not the conversion time.** (#144)
- **SIEM exporters use the canonical impact→severity banding.** `hdf-to-splunk` and `hdf-to-ocsf` now call the shared `ImpactToSeverity` helper instead of a hand-rolled copy, fixing a drift where an impact in `[0.0, 0.1)` was mislabeled `informational` instead of `low`. (pre-release review)
- **`hdf-to-ocsf` emits `finding_info.tags[].values` as an array even for a scalar `tags.nist`/`tags.cci`**, keeping the output schema-valid. (pre-release review)
- **`hdf-diff` system-drift now tracks a component's `integrity[]` change**, and the generated TypeScript `Component` type now exposes the `hostname`/`domain` identity fields (a quicktype rendering gap). The SPDX-3 AI/dataset subject list is now bounded like the SBOM package list. (pre-release review)

### Architecture

- **Schema version bumped from v3.3.0 to v3.4.0 across all `$id` / `$ref` URLs.** The generalized BOM parser lives in `hdf-converters/shared/{go,typescript}/bom`, and the three SIEM exporters share a common `exportmap` core that guarantees byte-identical TypeScript and Go output.

### Compatibility

- v3.3.x documents validate cleanly under v3.4.0 **except** for the two breaking schema removals: migrate `sbom`/`sbomRef`/`sbomFormat` to `boms[]` and per-type `digest`/`checksum` to the generic component `integrity[]`. All other schema changes are additive.

## [3.3.2] - 2026-06-29

Patch release: a legacy-HDF (InSpec v1) converter fidelity fix. No schema
changes — the schema `$id` URLs stay at v3.3.0.

### Fixes

- **`legacyhdf-to-hdf` now preserves four valid v1 fields it previously dropped**, mapping each to its v2 home in both TypeScript and Go (output kept identical across the two): control `refs` → `Requirement.refs` (empty/contentless refs dropped); result `skip_message` → result `message` when no explicit message is present (the skip reason was being lost on ~35% of real InSpec results); profile `supports` → `EvaluatedBaseline.supports` (InSpec hyphenated keys mapped to the schema's camelCase fields); and a platform `release` with no `target_id` now populates the component's `osName`/`osVersion` instead of being discarded. (#120; hdf-libs-9q8o)

### Compatibility

- Additive only: for the same legacy-HDF input the converter now emits more fields than before; no fields were renamed or removed, and output remains schema-valid. v3.3.x documents are unaffected (the change is in the v1→v2 upgrade path).

## [3.3.1] - 2026-06-28

Patch release: the NIST Rev 5 default flip, a workspace-wide UTC timestamp
normalization that makes converter output byte-identical across TypeScript and
Go, and several converter fixes. No schema changes — the schema `$id` URLs stay
at v3.3.0.

### New Features

- **Selectable NIST SP 800-53 revision.** NIST-emitting mappings are now revision-aware, carrying both Rev 4 and Rev 5 data. A process-global default revision drives every converter that emits NIST control tags; `hdf convert --nist-rev <4|5>` overrides it per invocation. For explicit, side-effect-free selection the libraries expose per-call `*ForRevision` lookups (Go) and an optional `rev` argument on each lookup (TS). (hdf-libs-9sh5)
- **AWS Config revision-alignment guard.** When an AWS Config export references managed rules that are mapped only at a NIST revision other than the one selected, `aws-config-to-hdf` logs one aggregated warning naming the rules and the revision that covers them — their NIST tags are omitted rather than silently dropped without explanation. `hdf convert --nist-strict` promotes that warning to a hard error. Rules unmapped at every revision are not flagged (a coverage gap, not a revision mismatch). (hdf-libs-9sh5)
- **Legacy InSpec (HDF v1) input converts to any export target.** `hdf convert` now upgrades legacy `hdf@1` / InSpec exec-json input in-flight (v1→v2) when the target is a non-HDF export format, instead of failing on the missing modern shape. (#112; closes #104 pt 1)
- **NDJSON input auto-detection.** The converter registry detects newline-delimited JSON (e.g. `trufflehog --json`) without a manual format hint. (#105)

### Fixes

- **All converter timestamps are normalized to UTC (trimmed RFC3339) and are now byte-identical across TypeScript and Go.** Previously the two implementations could emit different strings for the same instant — TypeScript read zone-less timestamps as host-local while Go read them as UTC, and they diverged on source offset and fractional-second formatting. Parsing/formatting now flows through shared helpers (`parseTimestamp` / `hdfutil.ParseTimestamp`, `NormalizeTimestamp`, `formatTimestamp` / `formatTimestampSeconds`, `serializeHdf`) that coerce every timestamp to UTC at millisecond precision — covering ISO, InSpec, C ctime (Nessus), and vendor formats (Netsparker, ZAP, DBProtect, Veracode). The schema-required result `startTime` always falls back to a valid value. An ESLint rule and a `pnpm lint:timestamps` check guard against regressions. (#115, #116, #117; hdf-libs-jmd0, hdf-libs-d2ql, hdf-libs-4dur, hdf-libs-2v64, hdf-libs-6gpa)
- **Every converter result now emits the schema-required `startTime`.** Several TypeScript importers previously omitted it (schema-invalid output); `oscal-sar` now skips zero-finding assessment results rather than emitting empty baselines, and CycloneDX / JUnit / Defender derive the document timestamp from source data instead of conversion time. (#114; hdf-libs-je13)
- **Leading UTF-8 BOM stripped from CLI input** before format detection; a BOM-only file now reports "no input provided" instead of a parse error. (#106)
- **CKL / CKLB with an empty inner rule set is rejected as malformed** at parse time, instead of silently producing an empty baseline. (hdf-libs-5u83)
- **`legacyhdf-to-hdf` TypeScript output aligned to Go for byte-parity** — drops non-schema legacy fields, maps `resource_class` → `resource`, emits trimmed-UTC `startTime`, and omits empty arrays. (hdf-libs-rf06)

### Breaking Changes — Converters

- **The default NIST SP 800-53 revision is now Rev 5 (was Rev 4).** Rev 4 was withdrawn in September 2023; Rev 5 is the current catalog. Converters that emit NIST control tags — most visibly `aws-config-to-hdf` — now emit Rev 5 control identifiers by default. For example, the `access-keys-rotated` rule maps to `AC-3(15)` instead of `AC-2(1) | AC-2(j)`. CWE→NIST mappings are unaffected: the control identifiers are identical across revisions (only control names were refreshed), so CWE-based converters produce the same tags as before. To retain Rev 4 output, pass `--nist-rev 4`. (hdf-libs-9sh5)
- **Converter timestamps that previously preserved a source UTC offset now emit UTC.** As part of the normalization above, a converter fed a non-UTC offset (e.g. `…-05:00`) now emits the equivalent `…Z` instant — the point in time is unchanged, only the rendering. Most visible in `legacyhdf`, `xccdf-results`, `splunk`, `sonarqube`, and `scoutsuite` output for offset-bearing source data.

## [3.3.0] - 2026-06-17

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
- **Uniform CLI schema validation gate across all 7 HDF doc types** — `hdf-cli`'s input/output gate previously covered Results, Baseline, and Amendments; System, Plan, Evidence Package, and Comparison now route through the same gate at every load and write site (`system.go`, `list.go`, `system_create.go`, `system_component.go`, `plan_create.go`, `doc_set.go` shared helper, `evidence_build.go`, `diff.go`). Schema-invalid HDF docs are rejected before mutation or disk write; load sites refuse undetected-type input. (Closes `hdf-libs-m58u`; #100)
- **`hdf-parsers` gains `ParseSystem` / `ParsePlan` / `ParseEvidencePackage` / `ParseComparison`** in both Go and TypeScript, mirroring the existing `ParseResults` / `ParseBaseline` shape (normalize-timestamps, schema-validate, decode, trailing-garbage check). The auto-detect `Parse` / `parse` extends to all 7 doc types. Library-API parity, not just CLI internal scaffolding — downstream consumers (heimdall2, saf-cli) get the symmetric surface. (#100)
- **TS-side schema validation harness for converter importer tests** — `hdf-converters/test/helpers/expectValidHdf.ts` adds `expectValidResults` / `expectValidBaseline` / `expectValidAmendments` helpers backed by `@mitre/hdf-validators`. 26 converter test suites now assert schema validity on at least one success path, matching the Go-side discipline. (Closes `hdf-libs-nrr4`; #101)

### Fixes

- **InSpec timestamp normalization in `hdf-parsers`** — the InSpec runner emits ISO 8601 timestamps without a timezone designator (e.g. `"2026-03-25T22:56:27.736808"`), which the HDF schema's `date-time` format check and Go's `time.Time` JSON unmarshal both reject. Real-world result: any Go HDF consumer reading actual InSpec output got zero-valued or partial `HDFResults`. The new `normalizeTimestamps` helper in `hdf-parsers` finds JSON-quoted bare ISO timestamps via regex and appends `Z` (treating them as UTC, matching what JS `Date.parse` and InSpec itself assume). Applied at the top of `ParseResults` and `ParseBaseline` before schema validation and `json.Decode`. Already-RFC3339 strings and timestamp-shaped substrings inside prose values are left alone. (Closes `hdf-libs-2nm0`; #83)
- **`hdf-cli` parse + normalize now delegate to `hdf-parsers`** — `parseHDFResults` / `parseHDFBaseline` in `input.go` previously re-implemented the parser pipeline, bypassing #83's bare-timestamp normalization. Every CLI command that loaded HDF (`list`, `query`, `diff`) crashed on real InSpec output; `validate.go` had the same problem on a separate code path. CLI now delegates to `hdfparsers.ParseResults` / `ParseBaseline`; `validate.go` runs `hdfparsers.NormalizeTimestamps` before `validators.Validate`. Verified end-to-end against `multilayered-inspec.json` (1603 reqs, all timestamps lack TZ). (Closes `hdf-libs-mccc`; #89)
- **AWS Config converter synthesizes `notApplicable` for zero-evaluation rules** — `hdf fetch aws-config` previously wrote requirements with `results: []` when a deployed Config rule evaluated zero in-scope resources, violating the schema's `minItems: 1` invariant. Both Go and TS converters now synthesize a single `notApplicable` result in that case, with a `codeDesc` explaining the rule's check ran but had no scope. Matches AWS Config's own console depiction (a dash, not "Compliant") — auditors see that no determination was made, not a vacuous "passed". (Fixes #80; #81)
- **`hdf-schema/helpers.d.ts` import path** — `helpers.d.ts` imported from `../dist/ts/hdf-results.js`, which was the per-document file removed by #77's combined-output refactor. Every attw entry that re-exports from `./helpers.js` failed type resolution post-merge, breaking the Pre-release checks workflow on main. Repointed to the consolidated `../dist/ts/hdf.js`. Also moved `publint` + `arethetypeswrong` from `pre-release.yml` into `ci.yml` so packaging defects surface on the PR that introduces them, not after merge to main. (#85, #87)
- **`sbomRef` / `systemRef` produced by `hdf system` and `hdf plan create` were schema-invalid on Windows.** The HDF System and Plan schemas require these fields to be `uri-reference`-formatted, but the CLI wrote the raw OS path. On Windows, backslashes in `C:\Users\…\foo.json` violate the format. Apply `filepath.ToSlash` at the four write sites (`system_create.go` FromSBOM, `system_component.go` add + update, `plan_create.go`). No behavior change on POSIX. Pre-existing cross-platform bug, surfaced by the new schema gate.
- **CLI test isolation: `TestSchemaDirFlag` no longer leaks `validators.schemaDir` to other tests in the package.** Adds `t.Cleanup` to reset the package-global after the test runs. Previously caused later tests to load schemas from disk instead of the embedded copy, which manifested as missing-schema failures on the CI Coverage job whenever the build artifact's `hdf-schema/dist/schemas/` was incomplete.
- **System-create / SBOM-import component-type mapping was producing schema-invalid `Component.type`** values (`compute`, `storage`, `other`). With the v3.3.0 closed 11-value enum (see Validation Changes below), the mapping is now identity for the 11 valid types; CycloneDX SBOM mappings updated accordingly. Surfaced by the new CLI schema gate.

### Breaking Changes — CLI

- **Converter `generator.name` now identifies each converter individually.** Previously ~9 converters (`nessus`, all 5 `oscal-*` sub-converters, `trufflehog`, `junit`, `xccdf-results`, plus `ckl` / `cklb` via a shared helper) emitted the generic literal `'hdf-converters'`. They now emit their own name (e.g. `'nessus-to-hdf'`, `'oscal-poam-to-hdf'`). Downstream tools that pivot on `generator.name == 'hdf-converters'` to detect "any HDF converter output" must broaden the check (e.g. match against the substring `-to-hdf`).
- **`hdf diff --json` renames `componentDiffs` → `extensions.componentSummaries`.** The CLI's per-component compliance aggregation reused the schema's `componentDiffs[]` JSON key for a structurally different shape (it carried compliance metrics, not Component_Diff state-change records, and lacked the schema-required `state` field). To satisfy `hdf-comparison`'s `unevaluatedProperties: false` constraint, the aggregation now ships under the schema's tool-data `extensions` slot at `extensions.componentSummaries`. Downstream consumers parsing `componentDiffs` from `hdf diff --json --system` output must update the JSON path. (#100)

### Breaking Changes — Converters

- **Clean scans now emit a synthesized `passed` placeholder requirement.** Across the ~24 converters that can produce zero-finding output, a tool that scanned cleanly previously yielded a baseline with `requirements: []`. The v3 schema enforces `requirements.minItems = 1`, so these converters now synthesize one `passed` requirement whose `codeDesc` reads `"<Tool> scanned <target> and reported zero findings."`. Downstream impact: consumers that count requirements/results per baseline will see **+1** for clean scans (previously 0), status aggregations gain one extra `passed` record per clean baseline, and that placeholder `codeDesc` becomes visible in display layers. See `site/docs/specification/hdf-specification.md` § "Clean-scan convention". (hdf-libs-qhl8)
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

### Documentation

- **Prose docs reorganized into the VitePress site.** `docs/` (specification, architecture, guides, contributing) moved to `site/docs/` and now ships as part of the documentation site at `https://mitre.github.io/hdf-libs/`. (#99)
- **Per-version schema archive on the docs site.** `site/public/schemas/<name>/v<X.Y.Z>/index.json` now snapshots the bundled schema at every release tag, keyed by `$id` (handles the historical v3.0.0 release-tag-vs-$id discrepancy). A version dropdown in the nav surfaces the prior versions. Release skill Phase 1.5 documents the archive-staging step so future bumps include the snapshot. (#99)
- **CI smoke-builds the docs site on every PR.** New `site-build` job in `ci.yml` runs `pnpm generate && vitepress build` after the main build job, catching site config breakage before merge. (#99)

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
