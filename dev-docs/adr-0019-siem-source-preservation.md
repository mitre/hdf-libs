# ADR-0019: Preserve HDF source data alongside stable SIEM projections

- **Status:** Accepted for explicit bundle-first implementation; compact default/deprecation policy remains undecided
- **Date:** 2026-11-07
- **Decision owner:** Repository maintainer
- **Scope:** Companion to [ADR-0002](adr-0002-hdf-to-ecs-export.md) and [ADR-0004](adr-0004-hdf-to-splunk-cim-export.md). Retains their hybrid architecture and status semantics; clarifies preservation and proposes a versioned output migration.
- **Related:** [ADR-0017](adr-0017-raw-source-artifact-carriage-and-requirement-rollup.md), [ADR-0018](adr-0018-validator-dialect.md); design task `hdf-libs-fdw4v.5`, integration task `hdf-libs-fdw4v.4`.

## Context

The SIEM exporters mix two responsibilities: mapping findings into native searchable fields and preserving their HDF source. The shared `buildHDFBlock` / `BuildHDFBlock` implements preservation through a handwritten field list and renamed members. Schema additions can therefore disappear unless both language implementations and each relevant exporter are updated. A concrete example is baseline integrity: ECS and Splunk read `baseline.checksum`, while schema-valid modern inputs carry `baseline.integrity`. The latter also supports `signature` and `signedBy`, so converting it into the old `Checksum` shape would lose information.

The required outcome is independently useful finding events with stable query fields, backed by complete, retrievable source data. Repeating a baseline's groups and other shared metadata in every event is not the intended end state. The source artifact and the event projection have different storage and retrieval requirements.

Existing documentation overstates round-trip support. The current Splunk importer consumes header/profile/control records with `meta.guid`, not the HEC envelopes produced by the current exporter. ADR-0002 explicitly excludes an ECS reverse importer, despite its later round-trip wording. Preservation does not imply that either inverse converter exists.

## Decision

Preserve source data independently of native SIEM projections. Carry the complete original HDF artifact once, identify each exported requirement within that artifact, and retain the requirement's complete JSON value alongside the stable native query projection. HDF property names and source values remain unchanged in the preserved record. New source properties do not need individual passthrough mappings.

Use existing HDF `External_Reference` and `Checksum` primitives, JSON Pointer (RFC 6901), and each target's supported extension location. This is an HDF export profile built on established standards, not a new industry-wide interchange standard. It does not change an HDF document schema or the converters' current input-validation policy.

### 1. Preservation boundary

| Data | Authoritative location | Guarantee |
|---|---|---|
| Original input document, including all baselines, groups, extensions and embedded source artifacts | Source artifact, retained once | Exact input bytes; verify its checksum before resolving records |
| Individual evaluated requirement | Event's source record | Complete JSON value, including nested arrays and newly accepted properties; no per-field preservation allowlist |
| Baseline and document context | Resolve from the retained source artifact | Complete original objects, including integrity and signatures; no sibling-requirement copying into each event |
| Native status, severity, identifiers and search fields | Target projection | Deliberate, documented mappings; independently tested against source semantics |

Presence, explicit null, empty collections, array order and string contents are significant. JSON formatting and key order are not part of the record-value guarantee. Preserve numeric source tokens without rounding; the consistency comparison retains their spelling (including `1.0` versus `1`). The original artifact remains byte authoritative even when a record is reserialized.

The accepted bundle APIs accept raw bytes (`Uint8Array` in TypeScript, `[]byte` in Go), hash and retain those bytes before decoding, and require valid UTF-8 JSON with well-formed Unicode strings and member names. Reject invalid UTF-8 and unpaired UTF-16 surrogate escapes explicitly; never replace them with U+FFFD. Valid surrogate pairs and a literal U+FFFD remain valid. This boundary applies to the new bundle operation; existing string-based converters retain their input policy. A caller that supplies an already-decoded string cannot claim preservation of bytes that were lost before the call.

Retaining a signature is not verifying that signature. A baseline's existing integrity object continues to describe its original subject. The artifact checksum covers the exact HDF input bytes, not a reconstructed baseline, normalized timestamps, or the exported event. Do not put the baseline checksum into ECS `event.hash`, whose subject is the event's raw data.

### 2. Proposed source envelope

The accepted bundle profile uses `hdf.source` for ECS, `event.hdf.source` inside Splunk's HEC envelope, and `unmapped.hdf_source` for OCSF. Library implementation and verification are in progress; release is gated on the delivery/integration work.

| Member | Meaning |
|---|---|
| `profileVersion` | `"1.0"` for the proposed preservation envelope; independent of exporter package, target schema, and HDF schema versions |
| `outputProfile` | Explicit query/output-shape contract. The experiment uses `"legacy-additive/1"`; the compact profile will have a distinct identifier accepted before production rollout |
| `artifact` | HDF `External_Reference`: `sourceName: "hdf-results"`, `externalId: "sha512:<digest>"`, `mediaType: "application/json"`, and `checksum: {algorithm: "sha512", value: "<digest>"}` in the implementation. The prototype used SHA256; its historical measurements below are unchanged |
| `pointer` | JSON Pointer locating this occurrence, such as `/baselines/0/requirements/0`, within the exact identified artifact |
| `requirement` | Complete source requirement object with its HDF names and values |

The artifact identity plus pointer identifies an occurrence, including duplicate requirement IDs. It does not replace existing event IDs, establish cross-scan identity, or infer component attribution. Document component inventory is preserved as inventory; it does not prove that a finding applies to every listed component.

Envelope versions use `major.minor`: a minor revision may add optional metadata without changing existing meanings or required fields; removals, changed meanings/types, or new mandatory behavior require a major revision. Readers reject unknown major versions and accept higher minor versions within a supported major while ignoring unknown optional metadata and enforcing all known invariants. `outputProfile` is a separate, explicitly supported identifier: a new compact shape or changed projection meaning cannot masquerade as an envelope minor bump. Readers report an unsupported output profile explicitly. The bundle manifest declares both identifiers and every event must agree. Legacy events without these discriminators remain legacy; they are never silently classified as source-preserving.

Current HDF results do not carry a mandatory source schema-version declaration. Never infer one from `generator.version` or the exporter's package version. If a future API supplies a schema identity, retain its provenance; a recorded `validatedAgainst` schema identifies an actual validation operation and must not be reported as the producer's declared schema. Keep this optional until its API contract is reviewed.

### 3. Deliver the artifact, not only a dangling reference

The recommended first delivery contract is an explicit export bundle containing:

- The target's ordinary finding-event NDJSON.
- The original input artifact stored once, unchanged.
- A small manifest linking the artifact identity to a relative artifact location and checksum, using `External_Reference`.

The accepted library manifest names `events.ndjson`, `source.json` and `manifest.json`. CLI archive delivery is a separate implementation phase; no CLI command is available merely because the library returns these artifacts. A bundle reader resolves the relative location within the bundle and verifies the bytes against the declared identity/checksum before using the pointer. A bundle `href` is a relative URI path with no scheme, authority, query or fragment. Decode percent escapes exactly once; reject invalid encodings, NUL, backslashes, absolute/drive paths and traversal, and enforce containment after resolving symlinks. Production readers must also reject missing artifacts, identity/checksum disagreement, invalid or ambiguous pointers and altered bytes. They must not fetch arbitrary network locations automatically.

After resolution, compare the carried requirement against the source value at the pointer. A disagreement is an explicit `record mismatch` error; do not silently accept the event value or silently repair it. The artifact is authoritative evidence, but a mismatched pair is unusable until the consumer handles the error. Compare decoded strings, member presence, array order and complete nested values, sorting object keys and preserving numeric tokens. The prototype implements this through canonical record serialization, not a claim of RFC 8785 conformance. The inline comparison candidate additionally checks its document and baseline context against the same artifact.

Deployment may instead retain the artifact at a caller-supplied durable HTTPS URI, recorded in `External_Reference.href`, with retrieval explicitly configured by the deployment. This must be a meaningful consumer-accessible location, not a producer filesystem path, `file:` URI, or a credential-bearing URL. No exporter-initiated fetch is implied. The consumer must have access to it for the lifetime of the corresponding finding events. A digest identifies bytes; it does not locate them or prove retention. An exporter cannot claim lossless delivery after writing NDJSON alone if the source artifact is neither included nor available through the documented retention mechanism.

Avoid embedding the entire input file per event in `event.original` or another string field. That preserves bytes but multiplies storage by the finding count. Avoid introducing baseline metadata events into the finding stream: that changes the one-event-per-requirement contract and complicates native target classes and queries.

### 4. Compatibility and migration

The standalone converter APIs currently return strings. Do not silently change their return types, require an unannounced sidecar, or remove fields from their existing output profile.

Introduce the preservation profile through an explicit new bundle API and CLI operation/options, as approved by the owner on 2026-11-07. Its initial implementation must retain established native projection semantics and make the artifact-delivery contract visible. The library signatures and readback contract are documented below. CLI syntax remains delivery work, not a command available merely from this library implementation.

A compact versioned profile can then remove duplicated baseline groups and obsolete preservation aliases, while keeping useful native query fields. Existing consumers receive migration documentation and a deliberately versioned transition. Retaining the old and new representations indefinitely is not the destination. An additive compatibility experiment will remain large until the obsolete representation is removed.

The existing `baseline_checksum` behavior for checksum-bearing inputs is not silently reinterpreted as an `Integrity` object. Modern source integrity remains intact in the preserved artifact. Any promoted integrity search fields are explicit query projections, not the authoritative copy.

**Owner decision (2026-11-07):** implement the explicit raw-byte bundle operation first, with its Unicode boundary and artifact delivery contract, while keeping existing API signatures and default outputs stable. A compact default and legacy deprecation timeline still require a separate decision. The owner also approved raising the Go minimum from 1.26.10 to 1.27.3 to use the standard `encoding/json/jsontext` decoder. An executable probe on 1.26.10 cannot import that package without the experimental build flag; 1.27.3 accepts valid Unicode and rejects unpaired surrogates without a flag. Use that standard decoder rather than promoting the prototype Unicode scanner. The measured metadata-loss repair remains blocking on the integration card until the agreed production contract works; this ADR does not park or waive it.

### Library API and verification contract

TypeScript exports `convertHdfToEcsBundle`, `convertHdfToSplunkBundle` and
`convertHdfToOcsfBundle` from `@mitre/hdf-converters`. Each takes a `Uint8Array`
and optional converter-version string and returns a promise of
`{events, source, manifest}`. New TypeScript bundle/readback APIs use the existing
Web Crypto SHA512 helper; caller byte arrays are copied before the first async
boundary. This keeps the shared package free of a new Node-only crypto import.
Go exposes `ConvertHDFToECSBundle`, `ConvertHDFToSplunkBundle` and
`ConvertHDFToOCSFBundle` in the existing target packages, returning
`(*exportmap.ExportBundle, error)` with byte-slice fields.

`resolveExportEvent` / `exportmap.ResolveExportEvent` accept one complete event,
its manifest and caller-supplied `{href, bytes}` artifacts. They preserve numeric
tokens while extracting the envelope. The lower-level `resolveExportSource` /
`ResolveExportSource` take envelope JSON directly. Both return the verified exact
source plus baseline and requirement JSON. Neither reads files nor fetches URLs;
URI containment belongs to a reader that actually accesses a filesystem.
Record consistency covers the preserved requirement and its source occurrence.
It does not recompute or authenticate the event's native query projection.

Production identity uses SHA512 under repository policy. The metadata schema
reuses the HDF `External_Reference` and `Checksum` definitions, rather than
maintaining parallel reference types. Its version/profile constraints accompany
runtime byte verification, reference uniqueness and complete record comparison.
A compatible minor version must agree across the event and manifest. Consumers
must not first round numbers by converting an event to an ordinary JavaScript
object and re-stringifying it; the full-event resolver avoids that failure mode.

Duplicate JSON members use the existing native last-member interpretation;
original source bytes retain their complete lexical representation. Every string,
including overwritten members, must still pass the Unicode boundary. The initial
TypeScript token-validation regex overflowed the stack on a valid 10 MiB string.
On 2026-11-07 the owner approved Microsoft's `jsonc-parser` 3.3.1 tokenizer to
replace it. Native JSON parsing still enforces strict JSON and preserves numeric
tokens; the scanner checks decoded token values for unpaired surrogates, including
overwritten object members. Comments and trailing commas remain invalid. Tests
cover export and verified readback of both plain and escaped large strings.

### 5. Indexing and operational behavior

Native SIEM fields retain explicit types and stable meanings. The preserved source record is retrieval data, not an invitation to dynamically index every HDF property. For Elasticsearch, supply and test an object mapping with `enabled: false` for the preservation payload while indexing only deliberately selected metadata/query fields outside it. Retain ordinary `_source`; do not claim preservation under synthetic-source reconstruction without testing its effects.

For Splunk, put the record inside `event`, never in HEC's flat indexed `fields`. Confirm that target ingestion limits, extraction settings and retention do not truncate or discard it. Preserve the existing sourcetype/CIM tagging behavior unless the versioned migration explicitly changes it. A shared source artifact needs an accessible storage location and a documented retrieval workflow; it need not be duplicated into Splunk finding events.

For OCSF, use its `unmapped` extension area and validate the complete modified event against the pinned OCSF schema. Avoid retaining two copies of the requirement indefinitely (`unmapped.hdf_requirement` and the proposed source envelope); consolidate only through the documented compatibility transition.

Preserved data inherits the sensitivity of the original assessment, including embedded raw scanner artifacts. Use the existing no-automatic-redaction policy; consumers must provision artifact access and retention consistently with event access. No new service, uploader, or automatic network fetch is introduced by this design experiment.

## Alternatives and prior art

| Approach | Benefits | Costs and disposition |
|---|---|---|
| Add `baseline_integrity` to each handwritten mapping | Small immediate repair | Leaves schema-drift mechanism and renamed parallel data model; not the long-term design |
| Inline complete document/baseline metadata per finding | Self-contained context | Large repeated groups/artifacts; measured below; retain as a comparison, not recommended default |
| Whole original document per event | Exact bytes locally available | Repeats the entire assessment for every finding; rejected |
| Source artifact once plus complete requirement records | Preserves schema evolution and original bytes without repeating shared context | Requires explicit artifact delivery, retention, resolution and a versioned migration; recommended |
| Only native fields plus a digest | Small events | Digest alone is not retrieval; loses local requirement detail; rejected |
| Shared metadata events inside the finding stream | No external sidecar | Changes event cardinality/classes and requires joins/assembly; not selected |
| Do nothing | No output migration | Existing integrity loss and false losslessness claims remain; rejected |

The prototype used Node and Go standard-library facilities. The production
TypeScript implementation adds the owner-approved, MIT-licensed `jsonc-parser`
3.3.1 dependency for Unicode token inspection; it has no runtime dependencies.
This replaces the failing regex without introducing a handwritten JSON decoder.
Go uses its standard strict JSON decoder. No transport or service is added.
Existing validator dependency-retention decisions remain in ADR-0018. A future
deployment/infrastructure choice requires its own dependency/license/health review.

Standards references inspected on 2026-11-07:

- [ECS custom fields](https://www.elastic.co/docs/reference/ecs/ecs-custom-fields-in-ecs): project namespaces may carry additional data.
- [ECS event fields](https://www.elastic.co/docs/reference/ecs/ecs-event): `event.original` and `event.hash` have event-specific meanings.
- [Elasticsearch object `enabled`](https://www.elastic.co/docs/reference/elasticsearch/mapping-reference/enabled): an object can remain retrievable without being parsed/indexed.
- [Splunk HEC event formatting](https://help.splunk.com/en/splunk-cloud-platform/get-started/get-data-in/10.6/get-data-with-http-event-collector/format-events-for-http-event-collector): structured `event` payload and separate indexed `fields`.
- [OCSF overview](https://github.com/ocsf/ocsf-docs/blob/main/overview/understanding-ocsf.md): native normalization with `unmapped`/raw-data carriage. Implementation must use the repository's pinned target schema.
- [JSON Pointer, RFC 6901](https://www.rfc-editor.org/rfc/rfc6901): locating a value within a JSON document.
- Existing `External_Reference` and `Checksum` definitions in `hdf-schema/src/schemas/primitives/common.schema.json`; ADR-0017 distinguishes artifact bytes from parsed record values.

## Executable experiment

The experiment reads the working tree based on `a9a5901d4cb3473dcdfc2a50efcdcecc098b7955`, including the already-corrected integration fixtures. It does not change production exporters. Scratch sources, commands, source fingerprints and output accompany the design card's evidence.

The original built ECS exporter fails the integrity-preservation assertion on the schema-valid override fixture. Two candidate source envelopes are then constructed in JavaScript and Go: inline context and artifact reference plus requirement. Ten accepted inputs produce 3,232 envelope evaluations across both modes; the serialized candidate envelopes match byte-for-byte across languages. Two additional boundary probes are rejected consistently for invalid UTF-8 and an unpaired surrogate.

Inputs are the existing Splunk exporter compliance, CVE, override, risk-adjustment and negative-zero fixtures; the large shared InSpec assessment; and four explicitly schema-confirmed experimental variants. The variants cover an Integrity schema signature example with nested nullable/empty extension data, an integer larger than JavaScript's safe integer range, absent integrity, and valid Unicode including a surrogate pair and literal escape text. They are not claimed to be captured scanner output. The large raw assessment still fails strict validation for 1,068 date-time format violations only; it is a preservation/size input under the existing exporter input policy, not evidence of a schema-valid large document.

Checks compare complete requirement values, reconstruct complete inline document/baseline context for comparison, preserve absence, and verify source checksums and signatures' carriage. The resolver rejects altered requirement data, deleted inline signatures and altered artifacts. A record-mismatch regression failed before the consistency check was implemented. The prototype's JavaScript source parser uses number source tokens and `JSON.rawJSON`; Go uses `UseNumber`, with explicit UTF-8/surrogate validation before decoding. This avoids rounding the large-integer probe and replacement of malformed strings. The initial runtime is Node 26.10.0 and Go 1.27.3; the final verification also exercises Node 24.22.2. This is runtime evidence for the prototype, not a full supported-runtime certification of the future production bundle API.

### Measured sizes

The large input is 7,103,932 bytes and contains 1,603 requirements. Sizes below are uncompressed UTF-8 bytes, not indexed-storage estimates.

| Candidate source-envelope stream | Total bytes | Largest envelope |
|---|---:|---:|
| Inline document and baseline context plus requirement | 91,893,650 | 82,175 |
| Artifact reference plus requirement | 6,291,589 | 14,151 |

The reference approach additionally retains the original 7,103,932-byte artifact once. These envelope-only numbers are not complete SIEM event sizes.

| Target | Existing NDJSON | Existing NDJSON plus reference envelope | Plus one source artifact |
|---|---:|---:|---:|
| ECS | 7,684,790 | 13,990,806 | 21,094,738 |
| Splunk | 91,847,909 | 98,153,925 | 105,257,857 |
| OCSF | 11,040,305 | 17,352,733 | 24,456,665 |

The manifest is additional small metadata not included in the final column. Existing Splunk output already repeats baseline groups. This additive experiment deliberately preserves every existing event field; it does not demonstrate the compact profile's final size. Adding a source envelope does not remove existing duplication. The migration must measure its compact profile separately before selecting deployment budgets.

For each target, the probe verifies that the proposed attachment location does not collide with an existing key, then attaches the envelope to measure output size. Exporter projections are unchanged because no exporter implementation changes in this experiment. Attaching then deleting a key is not independent behavioral proof of compatibility and is not reported as such. Production migration must compare actual old/new exporter behavior against the native projection contract.

### Limits and findings

- No live Elasticsearch or Splunk service was identified in the local container inventory. No live indexing, HEC ingestion, retrieval, truncation or retention pass is claimed. These remain required rollout checks.
- A metadata deletion and altered-artifact check are detected. A source artifact's checksum validates bytes, not the authenticity of its embedded signatures.
- The minimal prototype resolver handles the generated requirement pointers and checks manifest/event version, profile and artifact identity agreement. It is not a production bundle reader and does not claim hostile manifest/path handling, public API integration, CLI integration or reverse conversion.
- Existing component attribution work (`hdf-libs-y2an7.2`, `hdf-libs-uk999.7`) and severity-policy work (`hdf-libs-g1s4x`) retain ownership of those semantics. This design neither selects the first component as a new policy nor changes severity.
- The prototype initially repeated full-document parsing during verification and was stopped; the corrected harness parses/hashes once per source. A raw-number clone setup error was fixed before the successful run. Neither is evidence of a product failure or a product TDD pass.

### Independent review

Round 0 cross-family review (Claude Opus 5.5) returned FAIL. It found an absent record-to-artifact consistency rule, an unspecified byte/Unicode boundary and missing envelope/output-profile evolution rules. Those are corrected above and exercised in the revised prototype. Minor findings removed a tautological projection check, made bundle-readback evidence reproducible in `verify.mjs`, and tightened artifact-location rules.

Fresh Round 1 review returned PASS on all six design-task criteria and confirmed all six original findings addressed. Its remaining prototype notes were handled by adding manifest/event consistency rejection checks and making the additive-minor test explicitly assert successful resolution. The manifest mismatch check failed before its implementation. For production, prefer a supported decoder's native Unicode rejection where available; the experimental Go escape scan is not an automatically approved production parser. Original review output, coordinator checks and finding dispositions are retained with the card. This review accepted the design/prototype. The owner subsequently accepted explicit bundle-first implementation and Go 1.27.3; production verification and any compact-default/deprecation decision remain outstanding.

## Consequences

Schema evolution can preserve new source data without adding renamed passthrough fields. Native search mappings still require deliberate semantic work. The source artifact provides stronger forensic fidelity than reconstructed JSON, and baseline metadata is stored once.

The cost moves into artifact delivery and lifecycle management. Events alone do not provide complete assessment context. Compatibility prevents immediately deleting existing repeated fields. Minimum-runtime numeric preservation, target ingestion limits, and actual retrieval behavior require verification before deployment.

## Implementation plan

The owner subsequently approved local and GitHub Actions verification in the same PR. [The SIEM integration plan](../SIEM-INTEGRATION-PLAN.md#github-actions-verification) specifies separate native AMD64 target jobs, explicit Splunk consent, shared Testcontainers lifecycle, and JUnit/HDF evidence gates. Environment readiness is distinct from product ingestion/readback acceptance; both need independent review and actual execution evidence. This extends verification delivery without changing the accepted export profile or existing defaults. The service-smoke workflow now implements the readiness/cleanup portion using the shared environment runner, with explicit Splunk consent and sanitized per-target reports. [Native hosted qualification](https://github.com/mitre/hdf-libs/actions/runs/42820622016) passed for Elasticsearch and Splunk at source SHA `0a5fab45d0f00787be7627beb58e578e962f34ef`, including authentication, license readiness and cleanup. Full hosted product ingestion/readback and the JUnit/HDF gate subsequently passed for both targets; exact commit, merge-tree identity, run URLs and failure-probe results are recorded in the linked integration plan. The earlier experiment limitations above describe that experiment, not the later product qualification.

### Quality standards and shared abstractions

Keep raw-byte artifact identity, record extraction and target projections separate. One shared preservation implementation per language serves all three targets. Reuse HDF primitive schemas by reference; do not hand-copy Integrity or Checksum field lists. The export profile's own schema describes its envelope, not a second version of HDF. Keep permissive exporter input handling separate from any explicit strict-validation claim.

Production changes require behavioral RED before implementation, Go/TS parity, greater than 90% changed-code coverage, no lint suppressions, live checks at the changed layer and independent cross-family acceptance review. Do not accept blanket golden regeneration. Every changed golden must reflect a reviewed contract change with preservation assertions independent of that golden.

### Phase 1: Design and experiment

Create this ADR and the isolated prototype. Record schema provenance, input fingerprints, measured sizes, preservation checks and limitations. Obtain independent design review. Bring the bundle introduction/default/deprecation decision to the owner with the measured alternatives. The current task ends with a reviewable decision, not a silently selected production migration.

### Phase 2: Shared preservation and explicit bundle contract

For the accepted bundle-first implementation, enumerate exact files on implementation cards before editing. Expected implementation homes are `hdf-converters/shared/typescript/exportmap.ts`, `hdf-converters/shared/go/exportmap/exportmap.go`, their existing tests, a dedicated export-profile schema, and matching public bundle entry points. Source-artifact retention, manifest resolution, integrity checking and numeric preservation are shared responsibilities.

Acceptance must include raw source byte equality; correct artifact identity plus occurrence pointers; full requirement preservation; explicit rejection of event/source disagreement; baseline integrity/signature retrieval; duplicate IDs; empty/no-finding assessments whose artifact still survives; missing/null distinctions; valid Unicode and numeric fidelity on supported runtimes; consistent rejection of invalid UTF-8 and unpaired surrogate escapes under the accepted new bundle boundary; version/profile compatibility rules; and safe, explicit handling of unresolved artifacts. No changes to existing converters' input policy or guessed source schema version.

### Phase 3: Target adapters, migration and delivery

Wire ECS, Splunk and OCSF in both languages, their public APIs, registry/CLI delivery and fixtures atomically. Relevant existing targets are `hdf-converters/converters/hdf-to-{ecs,splunk,ocsf}/{go,typescript}` and the CLI convert command and target integration tests. Add exact new filenames only after the accepted API/CLI design. Provide the Elasticsearch mapping and Splunk artifact retrieval instructions; validate OCSF output with the pinned schema.

Document the two output profiles and their compatibility timeline in `site/docs/guides/siem-export.md`, converter/CLI package READMEs and `CHANGELOG.md`. Correct misleading touched round-trip comments. Preserve existing native query fields; remove repeated shared context only in the explicitly versioned compact profile. Measure complete event, artifact and manifest sizes together.

### Phase 4: Live verification and integration closure

Build and exercise the real CLI and locally packed TypeScript bundle API. In actual Elasticsearch and Splunk instances, ingest representative outputs, retrieve the complete source record, resolve baseline context from the retained artifact, verify its checksum, and exercise normal finding searches. Assert source data survives target limits and mappings without unexpected indexing. Repeat with absent/altered artifacts and verify explicit failure. Record server versions and configuration; no simulated ingestion counts as a pass.

Run full required workspace checks and cross-family review before closing the integration card. Keep the metadata-loss finding open until the chosen production path actually preserves and delivers that data. Any unavailable required infrastructure or unresolved migration decision remains a blocker, not a lower-priority follow-up.

### Local test environment implementation decision (2026-11-07)

The owner approved Testcontainers Node with `DockerComposeEnvironment` for the local SIEM integration harness. One vendor-derived Compose definition describes Elasticsearch and Splunk; a development-only Testcontainers dependency manages per-run startup, readiness, endpoint discovery and cleanup. The HDF runner supplies build/pack orchestration, product assertions and evidence. This reduces custom lifecycle code without changing the accepted export or artifact contract.

The prior-art matrix, inspected source revisions, licenses, health and adaptation constraints are maintained in [SIEM-INTEGRATION-PLAN.md](../SIEM-INTEGRATION-PLAN.md#reusable-implementations-inspected): Docker-Splunk and Elastic start-local configuration are adapted; OpenTelemetry's HEC/search/readback sequence is adapted; Testcontainers Node is adopted; the full docker-elk stack is not adopted. The environment card owns dependency qualification, runtime/socket and resource-reaper compatibility, bounded teardown and failure-path isolation. This decision authorizes the development dependency, not acceptance of vendor runtime terms. Live verification remains required.
### Local environment prior art matrix

This matrix mirrors the environment card's candidates. Inspected licenses and repository health were checked on 2026-11-07; full source paths and adaptation constraints are in the linked plan. Dates in the health column are latest release / latest observed merged PR / default-branch commit. All repositories were unarchived. MIT and Apache-2.0 tooling are not denied by the repository policy; Elasticsearch source-license restrictions and Splunk runtime terms remain separate from test-tool licenses.

| Candidate / inspected version or revision | License read | Decision | Health dates |
|---|---|---|---|
| [Docker Compose v5.7.0](https://github.com/docker/compose/tree/v5.7.0) | LICENSE: Apache-2.0 | ADOPT service definition and CLI underneath Testcontainers | 2026-11-02 / 2026-11-05 / 2026-11-05 |
| [Elasticsearch v9.5.6](https://github.com/elastic/elasticsearch/tree/v9.5.6) | LICENSE.txt: AGPL/SSPL/ELv2 source choices with ELv2-only code | ADOPT official external test runtime after distribution qualification; no source dependency | 2026-11-02 / 2026-11-07 / 2026-11-07 |
| [Docker-Splunk 10.6.1.1; source 138dd708](https://github.com/splunk/docker-splunk/tree/138dd708739b0956b6137f7f919f66583636fa13) | docs/LICENSE.md: Apache-2.0 tooling; separate runtime terms | ADAPT standalone HEC configuration and ADOPT qualified external runtime | 2026-10-27 / 2026-09-17 / 2026-09-17 |
| [Elastic start-local 0a56d370](https://github.com/elastic/start-local/tree/0a56d370042dc6d5032026b0173c93e94f2f1676) | LICENSE: Apache-2.0 | ADAPT single-node authenticated setup, selecting Basic | 2026-02-24 / 2026-06-23 / 2026-06-23 |
| [OpenTelemetry collector-contrib 817fe19a](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/817fe19a61cf04b27fc7d1e9128fc1b3bea7d047) | LICENSE: Apache-2.0 | ADAPT real HEC/search/readback sequence; replace sleeps and insecure TLS | 2026-11-07 / 2026-11-07 / 2026-11-07 |
| [Testcontainers Node c79a5a56; release v12.2.1 also inspected](https://github.com/testcontainers/testcontainers-node/tree/v12.2.1) | LICENSE: MIT | ADOPT root development-only Compose lifecycle dependency | 2026-10-13 / 2026-11-06 / 2026-11-06 |
| [docker-elk da954e82](https://github.com/deviantony/docker-elk/tree/da954e8262f48ceef54f2547b44f4662d354e341) | LICENSE: MIT | REFERENCE setup profile; REJECT full stack for direct exporter tests | 2025-11-06 / 2026-11-02 / 2026-11-02 |
