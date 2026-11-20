# ADR-0020: Optional evidence-package delivery for SIEM exports

- **Status:** Accepted; archive access is governed by ADR-0021, which supersedes the original Windows inherited-permission default.
- **Date:** 2026-11-08
- **Decision owner:** Repository maintainer
- **Supersedes:** [ADR-0019](adr-0019-siem-source-preservation.md) section 3's standalone CLI delivery recommendation. Its preservation semantics, library APIs, profile evolution, compatibility and live-verification requirements remain in force.
- **Related:** [ADR-0017](adr-0017-raw-source-artifact-carriage-and-requirement-rollup.md), [ADR-0007](adr-0007-hdf-mcp-server.md), [SIEM integration plan](../SIEM-INTEGRATION-PLAN.md).

## Scope

This is an opt-in snapshot-delivery adapter, invoked by `hdf convert --bundle`. It packages the library's events, source and manifest using a minimal existing HDF evidence-package inventory. It does not assemble a complete authorization package or invent system context, plans, timestamps or completeness claims. Library preservation and resolution remain usable without this CLI adapter or a ZIP.

This decision does not require evidence packages in the streaming path. [ADR-0005](adr-0005-hdf-conmon-requirement-change-events.md) distinguishes change events and reconciled posture from full scans retained as evidence. Neither the change-event schema nor its pure kernel functions are changed here.

## Context

The reviewed SIEM library returns events, exact source bytes and a manifest. Archiving only those three files would introduce a delivery inventory alongside the existing HDF evidence-package system. The repository already supports typed HDF contents, opaque external evidence, checksums and deterministic archives. It also already separates pure library operations from filesystem and CLI adapters. Reusing those contracts makes this export composable with broader evidence workflows without changing the source-preservation profile.

The experimental CLI subcommand shadowed an existing input file named `bundle`. The implemented explicit conversion option preserves the existing positional-input contract.

## Decision and ownership

Deliver searchable SIEM findings with complete original HDF evidence, preserve future source properties without a passthrough allowlist, centralize generic inventory/verification/archive behavior, and retain existing exporter compatibility. Standard HDF evidence packages are the optional CLI delivery inventory. The existing SIEM profile is the converter-specific relationship between a finding and its source occurrence. A future compact profile removes old repeated baseline data; this delivery change does not silently make that migration.

Reuse the existing source schema and generated types. No new HDF document type, reserved external-evidence format, transport, storage service, or generic package-writing library. hdf-system remains system context, not an export container. ADR-0017 rawSourceArtifacts retains its pre-conversion scanner-source meaning; rawSourceRecord is not repurposed as a SIEM envelope.

## Library compatibility

Keep the Go/TS bundle entry points and their events/source/manifest outputs, and both full-event and source-envelope resolvers. Keep profileVersion 1.0 and outputProfile legacy-additive/1. Preserve unknown optional metadata and supported higher minor versions with agreement between manifest and event; reject unsupported major/output profiles. Library functions remain filesystem/network independent and TS browser compatible.

The exact input byte artifact is authoritative, including signatures and embedded scanner artifacts. Complete requirement JSON values retain member presence, nulls, ordering of arrays, strings and number token spelling; existing duplicate-member policy remains last-member interpretation with original source bytes intact. Do not strip a BOM, repair Unicode, normalize the source, infer a source schema version, or add full HDF schema validation to previously permissive conversion. New bundle Unicode/JSON restrictions remain as accepted. Existing pure resolver runtime checks remain required; generated manifest/envelope schema validation tests in both languages remain required. Package validation never substitutes for profile or record verification. No new general runtime schema loader is needed for this composition.

## Package layout

The convenience operation accepts one local HDF results file and one ECS, Splunk or OCSF target. Its ZIP has four root files:

    evidence-package.json
    source.json
    events.ndjson
    manifest.json

The evidence package uses existing generated types/schema:

- name: deterministic `HDF SIEM export (<target>)`.
- contents: one hdf-results reference to source.json with SHA512 of its exact bytes.
- externalEvidence: events.ndjson with format ecs, ocsf, or x-splunk-export; mediaType application/x-ndjson; SHA512 of exact bytes.
- externalEvidence: manifest.json with custom format x-hdf-siem-export-profile; mediaType application/json; SHA512 of exact bytes. This is generated supporting profile metadata, opaque to generic evidence tools. Existing CI's run.json/x-github-actions is the precedent.
- Omit optional packageId, preparedAt, systemRef, planRef, completeness, signatures and producer-version claims absent real supplied information. In particular do not call evidence build and inherit time.Now(). Identical bytes/target/converter version/options give identical artifacts and archive under the same implementation.

Retain the existing manifest unchanged: target, profileVersion/outputProfile, events.ndjson and source identity/href/checksum. The package hash describes file integrity; the manifest describes event/source association. Verify agreement, do not remove either or mislabel metadata as raw-log.

Generic evidence packages may contain other HDF types, context and multiple isolated export directories. Fixed manifest-relative names mean one export per directory, not one export per evidence package. Automatic multi-target export and cross-export dedup are outside this single-input convenience operation. Composition must preserve relative-directory structure and use the package root as the outer containment boundary. Sources cannot be renamed without a deliberate manifest rewrite/profile-aware operation.

Empty assessments retain source/manifest/package and a zero-byte events.ndjson with its checksum. Generic package verification works without a finding; a finding resolver requires an actual event and must not invent one.

## CLI contract

Use an explicit conversion option:

    hdf convert input.json --to ecs --bundle -o export.zip

Without --bundle, current dispatch/output remains unchanged, including a bare input named bundle. Bundle mode requires one regular local input, a supported explicit target and a file output. Reject directories, multiple inputs, stdin, transformation flags and incompatible options explicitly. Default refuse an existing output; --overwrite is bundle-only explicit consent and never permits overwriting source or aliases; --force remains incompatible with bundle mode. Write the archive with the machinery `hdf evidence bundle` uses: the same staged write and no-clobber publication, and the archive access policy [ADR-0021](adr-0021-private-archives-and-unattended-sharing.md) sets for `hdf evidence bundle` (`--output-access private|inherit`, verified private creation by default), applied unchanged to this archive.

Use a package-owned read operation:

    hdf evidence resolve evidence-package.json --event retained-event.json

This first iteration resolves the recognized SIEM profile only. Unknown profile types produce an explicit unsupported error. With exactly one x-hdf-siem-export-profile entry select it; with multiple require --manifest <package-relative-URI>, which must identify exactly one registered entry. Never accept a loose manifest as a substitute for the package. This does not repurpose evidence export (currently package-to-OSCAL), evidence bundle, or the removed evidence verify command.

--event accepts one event in the converter's documented export shape, not an arbitrary vendor search-response wrapper. Elasticsearch tests obtain raw _source JSON; Splunk tests obtain the exact decoded _raw string and wrap it as {"event":<raw JSON>} without parsing/re-serializing inner numbers. OCSF uses its complete event. The existing lower-level envelope resolver remains available to applications with other retrieval adapters. Document these concrete inputs and test the adapters; do not auto-detect ambiguous shapes or round numbers.

## Verification and safe readback

1. Read and validate the evidence-package document against the existing schema. Select exactly one registered profile manifest as above. The manifest selector, the package entries matched to the selected manifest, events and source, and manifest `href` values must be relative URI paths with no scheme, authority, query or fragment. Decode percent escapes exactly once; reject invalid encodings, NUL, backslashes, absolute/drive paths and traversal, and enforce containment after resolving symlinks. Establish package-relative identities before duplicate checks. The profile still requires the literal events value events.ndjson. The manifest-directory-relative decoded href (or events constant) must resolve to the same package-relative identity as the decoded package entry uri before checking uniqueness. Reject escaping paths and ambiguous aliases; never re-decode the composed path.
2. Require a local contained manifest with an explicit SHA512 checksum; verify its bytes, then enforce its target/version/profile and required fields using current profile semantics.
3. Resolve events.ndjson and every required source relative to the selected manifest directory. Require unique matching package entries: correct events format for target (format is the discriminator; mediaType is descriptive and is not used to select the profile), hdf-results source type, and source SHA512/identity agreement with the manifest. Reject missing, ambiguous, malformed, unsupported, escaping or mismatched required references. Do not accept a second alias as a second independent artifact.
4. Require explicit SHA512 checksums on all three selected artifacts and verify them using the existing engine. No skipped/unsupported/error result is success. Use the same bounded byte snapshots for hashing and resolution; do not verify one read and resolve a later read. Preserve os.OpenRoot containment and global size/symlink policy for every opened file; do not weaken containment to reuse a convenience reader. No network retrieval. Empty events is allowed, empty package/manifest/source/event is not.
5. Resolve the separately supplied retained event through the existing SIEM resolver. Require profile agreement, unique source identity, valid occurrence pointer and exact preserved-record value agreement. Return byte-exact original source on stdout only after success; diagnostics go to stderr; failure returns nonzero with no recovered source output.

Changes to the path-containment or parser security model require explicit scope assessment and focused deep review before acceptance.

This is verification of the selected SIEM export and its required files, not a claim that all unrelated contents/completeness in a larger evidence package were verified. Existing evidence info --verify remains the whole-package operation; its generic policy is unchanged. Checksums establish consistency relative to the supplied inventory, not authenticity of an unsigned package. The supplied recovered event is checked against the source occurrence; the whole vendor search response is not expected to hash like the archived NDJSON. Native severity/status and transport fields are not authenticated by the resolver; live semantic assertions test them independently.

## Alternatives and prior art

| Approach | Disposition and reason |
|---|---|
| Carry the existing SIEM artifacts inside a standard evidence package | Adopt: reuse the inventory, checksum and archive contracts while retaining reviewed library/profile behavior |
| Replace or thin the SIEM manifest into the package | Reject for this change: mixes generic inventory with finding/source semantics and requires an unnecessary profile/API migration |
| Ship a standalone three-file ZIP with an optional package adapter | Reject: makes parallel delivery surfaces the default and leaves package verification outside the recovery path |
| Keep metadata inside every finding and omit source delivery | Reject: repeats shared data and does not establish complete original-byte recovery |

No third-party dependency or infrastructure component is introduced by this decision. Reuse the internal `hdf-engine` checksum and parsing functions, `internal/evidenceref` decoding, generated HDF types, embedded package validator and `evidence_bundle.go` archive/atomic-write helpers. General package writing remains CLI-owned; no second Go/TS writer framework is needed. The existing CI `run.json` entry with `x-github-actions` supplies a precedent for custom-format generated supporting evidence. Vendor environment qualification remains governed by the integration plan; this decision changes no vendor or runtime selection.

## Consequences

Generic evidence tools can carry and verify the output without understanding the SIEM profile. Applications retain pure Go/TS preservation APIs and explicit filesystem ownership. Recovery gains verification of the manifest and events file, in addition to the original source and requirement checks.

The extra inventory records checksums also used in the SIEM source relationship; the reader must enforce their agreement. Complete source retention remains an operational responsibility. The initial additive profile still includes inherited repeated fields, so this is not the compact-output migration. A larger package may contain unrelated evidence that selected-export recovery does not verify.

## Implementation references

- [CLI conversion adapter](../hdf-cli/cmd/hdf/cmd/convert_bundle.go) composes the three library artifacts and the minimal inventory.
- [Package/profile helpers](../hdf-cli/cmd/hdf/cmd/evidence_siem.go) centralize format selection, URI handling and checksum checks.
- [SIEM guide](../site/docs/guides/siem-export.md) documents consumer use; the [integration plan](../SIEM-INTEGRATION-PLAN.md) defines live ingestion and readback verification.
