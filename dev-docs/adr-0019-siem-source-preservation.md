# ADR-0019: Preserve HDF source data alongside stable SIEM projections

- **Status:** Accepted; CLI delivery is governed by ADR-0020. Compact output is a separate future decision.
- **Date:** 2026-11-07
- **Decision owner:** Repository maintainer
- **Scope:** Companion to [ADR-0002](adr-0002-hdf-to-ecs-export.md) and [ADR-0004](adr-0004-hdf-to-splunk-cim-export.md). Retains their hybrid architecture and status and severity semantics; defines source preservation without changing existing default outputs.
- **Related:** [ADR-0017](adr-0017-raw-source-artifact-carriage-and-requirement-rollup.md), [ADR-0018](adr-0018-validator-dialect.md).

## Scope

The library's `ExportBundle` contains events, original source bytes and a manifest in memory. It creates neither a ZIP nor an HDF evidence package and performs no filesystem or network I/O. Applications own storage and transport. [ADR-0020](adr-0020-siem-evidence-package-delivery.md) supersedes the original standalone CLI delivery choice with an optional evidence-package adapter; [ADR-0021](adr-0021-private-archives-and-unattended-sharing.md) governs archive access.

This capability preserves assessment snapshots. It does not replace [ADR-0005's requirement-change events](adr-0005-hdf-conmon-requirement-change-events.md) or require a package per streamed event.

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

### 2. Source envelope

The accepted bundle profile uses `hdf.source` for ECS, `event.hdf.source` inside Splunk's HEC envelope, and `unmapped.hdf_source` for OCSF.

| Member | Meaning |
|---|---|
| `profileVersion` | `"1.0"` for the preservation envelope; independent of exporter package, target schema, and HDF schema versions |
| `outputProfile` | Explicit query/output-shape contract. The supported profile is `"legacy-additive/1"`; any future compact profile requires a distinct, explicitly accepted identifier |
| `artifact` | HDF `External_Reference`: `sourceName: "hdf-results"`, `externalId: "sha512:<digest>"`, `mediaType: "application/json"`, and `checksum: {algorithm: "sha512", value: "<digest>"}` |
| `pointer` | JSON Pointer locating this occurrence, such as `/baselines/0/requirements/0`, within the exact identified artifact |
| `requirement` | Complete source requirement object with its HDF names and values |

The artifact identity plus pointer identifies an occurrence, including duplicate requirement IDs. It does not replace existing event IDs, establish cross-scan identity, or infer component attribution. Document component inventory is preserved as inventory; it does not prove that a finding applies to every listed component.

Envelope versions use `major.minor`: a minor revision may add optional metadata without changing existing meanings or required fields; removals, changed meanings/types, or new mandatory behavior require a major revision. Readers reject unknown major versions and accept higher minor versions within a supported major while ignoring unknown optional metadata and enforcing all known invariants. `outputProfile` is a separate, explicitly supported identifier: a new compact shape or changed projection meaning cannot masquerade as an envelope minor bump. Readers report an unsupported output profile explicitly. The bundle manifest declares both identifiers and every event must agree. Legacy events without these discriminators remain legacy; they are never silently classified as source-preserving.

Current HDF results do not carry a mandatory source schema-version declaration. Never infer one from `generator.version` or the exporter's package version. If a future API supplies a schema identity, retain its provenance; a recorded `validatedAgainst` schema identifies an actual validation operation and must not be reported as the producer's declared schema. Keep this optional until its API contract is reviewed.

### 3. Deliver the artifact, not only a dangling reference

**Delivery decision superseded by [ADR-0020](adr-0020-siem-evidence-package-delivery.md).** The library still returns `events.ndjson`, exact `source.json` bytes and `manifest.json` as in-memory artifacts. The optional CLI places them in an evidence-package ZIP. A standalone three-file ZIP is not the CLI contract.

Readers that access files must enforce the explicit artifact-URI and package-containment rules in [ADR-0020](adr-0020-siem-evidence-package-delivery.md#verification-and-safe-readback), including rejection of ambiguous aliases and escaping symlinks. Missing artifacts, identity/checksum disagreement, invalid pointers and altered bytes are errors. Pure library resolvers instead use caller-supplied bytes and perform no filesystem or network access.

After resolution, compare the carried requirement against the source value at the pointer. A disagreement is an explicit `record mismatch` error; do not silently accept the event value or silently repair it. The artifact is authoritative evidence, but a mismatched pair is unusable until the consumer handles the error. Compare decoded strings, member presence, array order and complete nested values, sorting object keys and preserving numeric tokens. The resolver compares canonical record serialization; this is not a claim of RFC 8785 conformance.

Applications may implement other retention mechanisms outside the CLI package contract. If an application retains an artifact at a caller-supplied durable HTTPS URI, record it in `External_Reference.href` and configure retrieval explicitly in the deployment. The URI must identify a meaningful consumer-accessible location, not a producer filesystem path, `file:` URI, or a credential-bearing URL. No exporter-initiated fetch is implied. The consumer must have access to it for the lifetime of the corresponding finding events. A digest identifies bytes; it does not locate them or prove retention. An exporter cannot claim lossless delivery after writing NDJSON alone if the source artifact is neither included nor available through the documented retention mechanism.

Avoid embedding the entire input file per event in `event.original` or another string field. That preserves bytes but multiplies storage by the finding count. Avoid introducing baseline metadata events into the finding stream: that changes the one-event-per-requirement contract and complicates native target classes and queries.

### 4. Compatibility and migration

The standalone converter APIs currently return strings. Do not silently change their return types, require an unannounced sidecar, or remove fields from their existing output profile.

Expose preservation through explicit raw-byte bundle APIs, keeping standalone signatures and default outputs stable. The optional CLI operation is defined in ADR-0020.

A compact versioned profile can then remove duplicated baseline groups and obsolete preservation aliases, while keeping useful native query fields. Existing consumers receive migration documentation and a deliberately versioned transition. Retaining the old and new representations indefinitely is not the destination. The additive profile retains that duplication until a versioned migration removes it.

The existing `baseline_checksum` behavior for checksum-bearing inputs is not silently reinterpreted as an `Integrity` object. Modern source integrity remains intact in the preserved artifact. Any promoted integrity search fields are explicit query projections, not the authoritative copy.

A compact default and legacy deprecation timeline require a separate decision. Go uses the standard `encoding/json/jsontext` decoder for Unicode validation and number-token fidelity. Runtime requirements are documented in the [upgrade notes](../CHANGELOG.md), rather than fixed by this architecture decision.

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

Duplicate JSON members use the existing last-member interpretation; original source bytes retain their complete lexical representation. Every string, including overwritten members, must pass the Unicode boundary. TypeScript uses the MIT-licensed `jsonc-parser` 3.3.1 tokenizer for those string checks, with strict parsing and number-token preservation handled by the existing JSON helpers. A regex-based token check was rejected because it overflowed the stack on a valid 10 MiB string. Comments and trailing commas remain invalid.

### 5. Indexing and operational behavior

Native SIEM fields retain explicit types and stable meanings. The preserved source record is retrieval data, not an invitation to dynamically index every HDF property. For Elasticsearch, supply and test an object mapping with `enabled: false` for the preservation payload while indexing only deliberately selected metadata/query fields outside it. Retain ordinary `_source`; do not claim preservation under synthetic-source reconstruction without testing its effects.

For Splunk, put the record inside `event`, never in HEC's flat indexed `fields`. Confirm that target ingestion limits, extraction settings and retention do not truncate or discard it. Preserve the existing sourcetype/CIM tagging behavior unless the versioned migration explicitly changes it. A shared source artifact needs an accessible storage location and a documented retrieval workflow; it need not be duplicated into Splunk finding events.

For OCSF, use its `unmapped` extension area and validate the complete modified event against the pinned OCSF schema. Avoid retaining two copies of the requirement indefinitely (`unmapped.hdf_requirement` and the source envelope); consolidate only through the documented compatibility transition.

Preserved data inherits the sensitivity of the original assessment, including embedded raw scanner artifacts. Use the existing no-automatic-redaction policy; consumers must provision artifact access and retention consistently with event access. No new service, uploader, or automatic network fetch is introduced by this decision.

## Alternatives and prior art

| Approach | Benefits | Costs and disposition |
|---|---|---|
| Add `baseline_integrity` to each handwritten mapping | Small immediate repair | Leaves schema-drift mechanism and renamed parallel data model; not the long-term design |
| Inline complete document/baseline metadata per finding | Self-contained context | Large repeated groups/artifacts; rejected in favor of a shared artifact |
| Whole original document per event | Exact bytes locally available | Repeats the entire assessment for every finding; rejected |
| Source artifact once plus complete requirement records | Preserves schema evolution and original bytes without repeating shared context | Requires explicit artifact delivery, retention and resolution; selected |
| Only native fields plus a digest | Small events | Digest alone is not retrieval; loses local requirement detail; rejected |
| Shared metadata events inside the finding stream | No external sidecar | Changes event cardinality/classes and requires joins/assembly; not selected |
| Do nothing | No output migration | Existing integrity loss and false losslessness claims remain; rejected |

The tokenizer has no runtime dependencies. Go uses its standard strict JSON decoder. No transport or service is added; validator dependency decisions remain in ADR-0018.

Standards references inspected on 2026-11-07:

- [ECS custom fields](https://www.elastic.co/docs/reference/ecs/ecs-custom-fields-in-ecs): project namespaces may carry additional data.
- [ECS event fields](https://www.elastic.co/docs/reference/ecs/ecs-event): `event.original` and `event.hash` have event-specific meanings.
- [Elasticsearch object `enabled`](https://www.elastic.co/docs/reference/elasticsearch/mapping-reference/enabled): an object can remain retrievable without being parsed/indexed.
- [Splunk HEC event formatting](https://help.splunk.com/en/splunk-cloud-platform/get-started/get-data-in/10.6/get-data-with-http-event-collector/format-events-for-http-event-collector): structured `event` payload and separate indexed `fields`.
- [OCSF overview](https://github.com/ocsf/ocsf-docs/blob/main/overview/understanding-ocsf.md): native normalization with `unmapped`/raw-data carriage. Implementation must use the repository's pinned target schema.
- [JSON Pointer, RFC 6901](https://www.rfc-editor.org/rfc/rfc6901): locating a value within a JSON document.
- Existing `External_Reference` and `Checksum` definitions in `hdf-schema/src/schemas/primitives/common.schema.json`; ADR-0017 distinguishes artifact bytes from parsed record values.

## Evidence

The design experiment at base `a9a5901d4cb3473dcdfc2a50efcdcecc098b7955` reproduced loss of modern baseline integrity in the original ECS mapping. It compared inline document/baseline context with a shared artifact plus requirement record. On the 7,103,932-byte, 1,603-requirement assessment, the uncompressed candidate envelopes measured:

| Candidate | Envelope stream bytes | Additional source bytes |
|---|---:|---:|
| Inline document/baseline context plus requirement | 91,893,650 | 0 |
| Artifact reference plus requirement | 6,291,589 | 7,103,932 |

These prototype envelope sizes were measured with SHA-256 identifiers; the current profile uses SHA512. The figures are not complete production event sizes or indexed-storage estimates. The large input had noncanonical timestamps and served as a preservation/size input under the existing exporter policy, not evidence of schema validity. Original Splunk output already measured 91,847,909 bytes because it repeated baseline groups; adding preservation does not remove that duplication. Compact output needs its own migration and measurement.

Production [Go](../hdf-converters/shared/go/exportmap/bundle_test.go) and [TypeScript](../hdf-converters/shared/typescript/exportbundle.test.ts) tests exercise byte recovery, complete requirement values, numeric tokens, Unicode and rejection of inconsistent artifacts. Large-string regressions cover 10 MiB plain strings in both languages and escaped strings in TypeScript. The [SIEM integration plan](../SIEM-INTEGRATION-PLAN.md) owns live ingestion/readback qualification and the Testcontainers lifecycle; startup alone is not product verification.

## Consequences

Schema evolution can preserve new source data without adding renamed passthrough fields. Native search mappings still require deliberate semantic work. The source artifact provides stronger forensic fidelity than reconstructed JSON, and new preservation references share one copy of baseline context. Existing legacy event fields remain until a versioned migration.

The cost moves into artifact delivery and lifecycle management. Events alone do not provide complete assessment context. Compatibility prevents immediately deleting existing repeated fields. Minimum-runtime numeric preservation, target ingestion limits, and actual retrieval behavior require verification before deployment.
