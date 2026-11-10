# ADR-0020: Deliver SIEM exports through HDF evidence packages

- **Status:** Accepted for implementation following independent design review and the owner instruction to proceed on 2026-11-08. Production acceptance remains open.
- **Date:** 2026-11-08
- **Decision owner:** Repository maintainer
- **Supersedes:** [ADR-0019](adr-0019-siem-source-preservation.md) section 3's standalone delivery recommendation and its delivery implementation steps. Its preservation semantics, library APIs, profile evolution, compatibility and live-verification requirements remain in force.
- **Related:** [ADR-0017](adr-0017-raw-source-artifact-carriage-and-requirement-rollup.md), [ADR-0007](adr-0007-hdf-mcp-server.md), [SIEM integration plan](../SIEM-INTEGRATION-PLAN.md).

## Context

The reviewed SIEM library returns events, exact source bytes and a manifest. Archiving only those three files would introduce a delivery inventory alongside the existing HDF evidence-package system. The repository already supports typed HDF contents, opaque external evidence, checksums and deterministic archives. It also already separates pure library operations from filesystem and CLI adapters. Reusing those contracts makes this export composable with broader evidence workflows without changing the source-preservation profile.

The experimental CLI subcommand also shadows an existing input file named `bundle`. An explicit conversion option preserves the existing positional-input contract. The CLI forms below are the implementation target; this decision does not claim they are already available.

## Goal and ownership

Deliver searchable SIEM findings with complete original HDF evidence, preserve future source properties without a passthrough allowlist, centralize generic inventory/verification/archive behavior, and retain existing exporter compatibility. Standard HDF evidence packages are the delivery inventory. The existing SIEM profile is the converter-specific relationship between a finding and its source occurrence. A future compact profile removes old repeated baseline data; this delivery change does not silently make that migration.

Reuse the existing source schema and generated types. No new HDF document type, reserved external-evidence format, transport, storage service, or generic package-writing library. hdf-system remains system context, not an export container. ADR-0017 rawSourceArtifacts retains its pre-conversion scanner-source meaning; rawSourceRecord is not repurposed as a SIEM envelope.

## Library compatibility

Keep reviewed Go/TS bundle entry points and their events/source/manifest outputs, and both full-event and source-envelope resolvers. Keep profileVersion 1.0 and outputProfile legacy-additive/1. Preserve unknown optional metadata and supported higher minor versions with agreement between manifest and event; reject unsupported major/output profiles. Library functions remain filesystem/network independent and TS browser compatible.

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

Replace the unshipped `convert bundle` subcommand with an explicit option:

    hdf convert input.json --to ecs --bundle -o export.zip

Without --bundle, current dispatch/output remains unchanged, including a bare input named bundle. Bundle mode requires one regular local input, a supported explicit target and a file output. Reject directories, multiple inputs, stdin, transformation flags and incompatible options explicitly. Default refuse an existing output; --overwrite is bundle-only explicit consent and never permits overwriting source or aliases; --force remains incompatible with bundle mode. Reuse current archive safety and atomic-write machinery. Archive access policy is superseded by [ADR-0021](adr-0021-private-archives-and-unattended-sharing.md): verified private creation by default, with explicit unattended inherited access.

Use a package-owned read operation:

    hdf evidence resolve evidence-package.json --event retained-event.json

This first iteration resolves the recognized SIEM profile only. Unknown profile types produce an explicit unsupported error. With exactly one x-hdf-siem-export-profile entry select it; with multiple require --manifest <package-relative-URI>, which must identify exactly one registered entry. Never accept a loose manifest as a substitute for the package. This does not repurpose evidence export (currently package-to-OSCAL), evidence bundle, or the removed evidence verify command.

--event accepts one event in the converter's documented export shape, not an arbitrary vendor search-response wrapper. Elasticsearch tests obtain raw _source JSON; Splunk tests obtain the exact decoded _raw string and wrap it as {"event":<raw JSON>} without parsing/re-serializing inner numbers. OCSF uses its complete event. The existing lower-level envelope resolver remains available to applications with other retrieval adapters. Document these concrete inputs and test the adapters; do not auto-detect ambiguous shapes or round numbers.

## Verification and safe readback

1. Read and validate the evidence-package document against the existing schema. Select exactly one registered profile manifest as above. Treat package uris and manifest hrefs as URI references, decode percent escapes exactly once, reject unsafe forms, and establish their package-relative identities before duplicate checks. The profile still requires the literal events value events.ndjson. The manifest-directory-relative decoded href (or events constant) must resolve to the same package-relative identity as the decoded package entry uri before checking uniqueness. Reject escaping paths and ambiguous aliases; never re-decode the composed path.
2. Require a local contained manifest with an explicit SHA512 checksum; verify its bytes, then enforce its target/version/profile and required fields using current profile semantics.
3. Resolve events.ndjson and every required source relative to the selected manifest directory. Require unique matching package entries: correct events format for target (format is the discriminator; mediaType is descriptive and is not used to select the profile), hdf-results source type, and source SHA512/identity agreement with the manifest. Reject missing, ambiguous, malformed, unsupported, escaping or mismatched required references. Do not accept a second alias as a second independent artifact.
4. Require explicit SHA512 checksums on all three selected artifacts and verify them using the existing engine. No skipped/unsupported/error result is success. Use the same bounded byte snapshots for hashing and resolution; do not verify one read and resolve a later read. Preserve os.OpenRoot containment and global size/symlink policy for every opened file; do not weaken containment to reuse a convenience reader. No network retrieval. Empty events is allowed, empty package/manifest/source/event is not.
5. Resolve the separately supplied retained event through the existing SIEM resolver. Require profile agreement, unique source identity, valid occurrence pointer and exact preserved-record value agreement. Return byte-exact original source on stdout only after success; diagnostics go to stderr; failure returns nonzero with no recovered source output.

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

## Implementation and quality gates

1. Update the existing CLI delivery card and target-test cards to this contract without removing requirements or reopening completed library work absent a demonstrated defect. Keep final integration dependent on CLI delivery and the complete SIEM integration epic.
2. Use `project-tdd crosscheck/standard` for behavior changes: intended failing test first, shared implementation, focused verification, final-tree required checks and independent cross-family AC review. Fix touched defects rather than hiding them in follow-up work. Setup failures are not behavioral RED; documentation and board changes require review, not invented tests.
3. Implement shared CLI composition and contained, bounded reads, then the bundle flag and package-first resolver. Reuse existing checksum/schema/ZIP behavior. Preserve same-byte-snapshot verification and source recovery; fix existing input-policy and lint findings before closure.
4. Verify all three targets, ordinary conversion including a literal `bundle` filename, archive determinism and relocation, nested/multiple export selection, conflicting references and aliases, each artifact's missing/tampered/checksum failures, unsafe URI/symlink/size cases, atomic failure, empty findings, numeric/Unicode/null/unknown-field preservation and stdout behavior. Require more than 90% changed-code coverage and existing suite compatibility.
5. Complete real Elasticsearch/Splunk ingestion with the current built CLI and locally packed TS APIs, pinned OCSF schema validation, native semantic queries and complete retained-source readback. Splunk adapters must preserve the inner `_raw` JSON tokens. Startup checks are not ingestion acceptance. Do not weaken comparisons if a target truncates or normalizes required data.
6. Complete the integration plan's separate native AMD64 CI jobs, explicit consent, smoke/full separation, bounded cleanup and JUnit/HDF evidence. Update the guide, runbook, READMEs, changelog and living PR summary as behavior is verified. Hosted execution, full required checks and independent acceptance remain mandatory.

Standard review is the default for the implementation cards. A change to the path-containment or parser security model, rather than composition using the established model, requires explicit scope assessment and focused deep review before acceptance. This does not waive the ordinary crosscheck/standard AC gate.

## Evidence and limits

Existing CLI probes composed all three target exports into schema-valid packages, verified their checksums, archived and relocated them, and recovered exact source bytes. A separate minimal-package probe omitted optional timestamps and IDs, verified all three artifact digests and produced identical repeated ZIPs for every target. Empty findings retained their source and a valid empty events artifact. These probes demonstrate composition using existing machinery, not implementation of the new CLI or live target ingestion.

Independent cross-family design review returned PASS after all nine original findings were resolved. The resulting contract explicitly states URI decoding and identity agreement, the format/media-type distinction and the existing 0600 output mode. Production code-review findings, required lint/test failures, upstream comparison-schema compatibility and real local/hosted verification remain acceptance work. No card closure or release is implied by this decision.
