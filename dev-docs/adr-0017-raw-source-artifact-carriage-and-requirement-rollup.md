# ADR-0017: Raw source-artifact carriage, the passthrough contract, and requirement roll-up

- **Status:** Proposed
- **Date:** 2026-09-27
- **Deciders:** Will Dower
- **Supersedes:** the draft `adr-0016-source-artifact-carriage.md` on branch `feat/schema-greenfield`, whose source-artifact strand is calved off into this ADR. That draft's remaining strands stay with it.
- **Relates to:**
  - [ADR-0001](adr-0001-generalized-bom-representation.md) — BOM carriage by reference (`ref`) or by embedding (`document`): the established "carry native data opaquely" precedent.
  - [ADR-0006](adr-0006-stix-cti-integration.md) — introduced the `External_Reference` primitive this ADR extends.
  - [ADR-0007](adr-0007-hdf-mcp-server.md) — the MCP's size constraints and token budgets.
  - [ADR-0014](adr-0014-oscal-namespace-and-prose-carriage.md) — Alternative F rejected document-level passthrough for OSCAL props, because *that* carriage must be object-local. Both mechanisms coexist; neither substitutes for the other.
  - [ADR-0015](adr-0015-saf-supplement-input-normalization.md) — rewrites a legacy top-level `passthrough` into `extensions.passthrough`. This ADR gives that destination a definition.
  - [ADR-0016](adr-0016-multi-scanner-results-merge.md) — union semantics across baselines; roll-up here is strictly *within* one baseline and never crosses one.

## Context

Three problems have the same root, and fixing them separately would touch every converter three times.

**1. There is no defined home for a converter's input.** HDF v2 converters could attach the original tool output to the document. In heimdall2 that lived inside a mapper-level `passthrough` block under two names: `raw` (the whole original input, attached only when the mapper was built with `withRaw` — 21 mappers do this) and `auxiliary_data` (fields the mapper deliberately carried but had no home for). `passthrough` appears **nowhere** in the InSpec exec-json schema: it was a convention, and the name described where the data could go rather than what it was.

HDF v3 inherited the gap. Root `extensions` invites "use this to preserve original tool output" but defines nothing, so `extensions.passthrough` is an undocumented convention key written by four code paths — the legacy converter in both languages (`legacyhdf-to-hdf/go/converter.go:681`, `typescript/converter.ts:1159`) and the SAF-supplement normalizer in both (`hdf-parsers/go/saf_supplement.go:148`, `typescript/saf-supplement.ts:116`) — that renders nowhere on the docs site because there is nothing defined to render.

**2. `code` has been absorbing raw payloads.** `Requirement_Core.code` means *the source code that ran to produce a result*. That is what it means in InSpec exec-json, where it holds the Ruby source of a control, and v3 inherited both the field and the meaning. But for a scanner finding nothing executed, so converters put the raw finding record there instead, because it was the only field with room.

Measured across every committed converter golden (2026-09-27): **19 converters write payload-shaped content into `code`, in ~1,855 requirements** — xccdf-results 862, neuvector 302, grype 137, twistlock 101, prisma 100, cyclonedx 91, asff 67, snyk 52, veracode 39, then nessus 23, msft-defender-devops 18, jfrog-xray 17, burpsuite 14, dbprotect 9, ionchannel 7, deptrack 5, gitlab 5, semgrep 5, netsparker 1. This is the inherited convention, not a handful of strays.

**3. Converters emit several requirements that share an id.** One scanner reporting one CVE against several packages emits one requirement per package. Measured: 5 converters, 6 goldens, **68 duplicate-id groups, 89 entries that would merge** (grype 45, twistlock 39, cyclonedx 2, prisma 2, veracode 1). heimdall2 avoided this in its framework: `base-converter.ts:111-160` `collapseDuplicates` keeps the first control and concatenates later same-id controls' `results`, and ~24 of its 28 mappers opt in with `key: 'id'`. Our ports carried each mapper's id expression and left that line behind: our grype golden has 89 entries over 47 ids with one result each, heimdall2's has 47 controls over 47 ids carrying the same 89 results.

Roll-up and payload relocation touch the same converters, so they are decided together and applied in one pass per converter.

### What the schema can hold today

`External_Reference` (`hdf-schema/src/schemas/primitives/common.schema.json:7-131`) already models reference-versus-embed: `href`, `checksum`, `mediaType`, open `rel` and `kind` tokens, a required `sourceName`, and `document` — "optional lossless embedded copy of the referenced artifact … preserved verbatim".

Two limits matter:

- **`document` is `type: object`.** Of 47 ingest converters (37 JSON, 9 XML, 1 CSV), it can hold the input of roughly 32. It cannot hold: all 9 XML converters, the CSV converter, the NDJSON inputs asff and trufflehog genuinely accept, scoutsuite's JS-wrapped input, or the 4 JSON converters whose accepted top level is an array (asff, checkov, splunk, trufflehog).
- **`mediaType` and `checksum` are documented as "meaningful only with `href`"** — scoped to the pointer, not to embedded bytes.

There is also no format-to-media-type mapping anywhere in the repo: two hardcoded strings exist (`hdf-to-oscal-poam/go/converter.go:693`, `hdf-to-oscal-sar/go/converter.go:471`) and no detector.

## Decision

### 1. `extensions` is a closed, defined object; `extensions.passthrough` is the catch-all inside it

`extensions` becomes a **defined object with a fixed member set**, not an open bag. Its members are `passthrough` and `rawSourceArtifacts`. An undeclared key on `extensions` is invalid.

`extensions.passthrough` is the deliberately permissive member: it accepts unenumerated properties by design, and it is where a producer puts data HDF does not model — heimdall2's `auxiliary_data` role. Anything that is not a defined HDF concept goes there.

It is **not** where the source artifact goes. The only reason v2 put the original there is that it was the only available slot.

**One definition, both levels.** Document-root `extensions` and `Evaluated_Baseline.extensions` point at the same `Extensions` definition. Two declarations of one field name is how the current drift happened.

**Applied to every document type with a producer envelope** — results, baseline, comparison, system, plan, amendments and evidence-package, all of which declare `generator` and/or `integrity`. Only `hdf-requirement-change-event` is excluded: it is an entry in an append-only stream rather than a produced document, and has no producer whose data would need a home. That line is drawn from the data model, so it does not move when a converter is added or reclassified — which matters, because the converter inventory turned out to be five output types, not the three first assumed.

**Closure is expressed with `additionalProperties: false`, not the house `unevaluatedProperties: false`.** `Extensions` composes nothing, so the simpler keyword suffices — and it is the only one that holds in both validators. The shipped Go validator is a draft-07 engine that does not implement `unevaluatedProperties`, so the house spelling would have closed `extensions` in ajv and been silently ignored by `hdf validate`: the same failure mode as a validation keyword beside a `$ref` (§3). The reasoning is recorded in the definition's own description so it is not "corrected" back later.

**This is a consumer-visible breaking change**, and it lands as a compile-time break for typed consumers rather than a silent one: `Extensions` becomes a struct in both languages, so `results.Extensions["key"]` stops compiling and becomes `results.Extensions.Passthrough["key"]`.

Every key this repository writes today migrates in the same change:

| Where | Keys | Written by |
|---|---|---|
| Document root | `checklistFormat`, `assetExtras`, `cklbVersion`, `cklbActive`, `cklbMode`, `cklbHasPath` | ckl, cklb |
| Document root | `hdf-merge` provenance; `v1_version` and the legacy converter's carried unknown v1 fields | merge engine; legacy converter |
| Baseline | `stigid`, `uuid`, `releaseInfo`, `classification`, `displayName`, `referenceIdentifier` | ckl, cklb |
| Baseline | `gosec`, `neuvector`, `ionchannel` scan metadata; `legacyAttributes`; `labels` | those converters; hdf-diff normalize; a stale CLI reader |
| Comparison document | `systemFieldChanges`, `dataFlowChanges`, `componentSummaries` | hdf-diff and `hdf diff` |

Several are read back, so writers and readers move together: the HDF→CKL round trip depends on `checklistFormat` and `assetExtras`, and closing `extensions` broke `hdf diff --system` outright until the comparison keys moved. Keys are placed flat under `passthrough` (`extensions.passthrough.checklistFormat`), which leaves every key-by-key round-trip path unchanged; producers outside this repository should namespace theirs under a tool name so two cannot collide.

Two of these migrations are mechanically correct but worth revisiting on their merits, and are carded rather than settled here: `labels` is read by `hdf diff --group-by` but written by nothing, while `Evaluated_Baseline.labels` is a first-class field real code populates; and `systemFieldChanges`, `dataFlowChanges` and `componentSummaries` are hdf-diff's own structured output rather than foreign producer data, so they may belong in real `hdf-comparison` fields instead of the catch-all.

### 2. `extensions.rawSourceArtifacts[]` carries the pre-converted input verbatim

An array of `External_Reference` entries, each one artifact exactly as the converter received it. The name is deliberate: **raw** (unprocessed, borrowing v2's own word), **source** (what is raw), **artifact** (the thing itself, not a description of it).

An array because conversion can consume more than one artifact — the OSCAL profile path takes a profile *and* a catalog (`oscal-to-hdf/go/converter_profile.go:28`, CLI `--catalog`). Every other converter takes one input; an array of one costs nothing and avoids a second mechanism later.

Each entry carries:

| Member | Value |
|---|---|
| `sourceName` | the producing tool (required by the primitive) |
| `content` + `encoding` | the artifact's bytes — see §3 |
| `mediaType` | the artifact's IANA media type, **required** on an entry that embeds |
| `checksum` | SHA-256 of the exact bytes the converter read — the value `inputChecksum` / `shared.InputChecksum` already computes |
| `rel` | `"raw-source"` |
| `href` | only when the caller supplies a meaningful location; never a local filesystem path |

### 3. `External_Reference` gains `content` and `encoding`; `document` keeps its meaning

`document` stays JSON-only and object-shaped. Non-JSON artifacts embed through a new sibling pair:

- **`content`** — a string holding the artifact's bytes.
- **`encoding`** — how to read that string: `utf-8` for text (XML, CSV, NDJSON, plain text, JS-wrapped) or `base64` for anything that is not valid UTF-8 text.

Chosen over widening `document` to accept a string. Widening would have crushed nine XML converters, a CSV converter and the NDJSON paths into an untyped string member whose interpretation depended on reading `mediaType` first, with no way to carry anything that is not text. A separate pair gives non-JSON inputs real support rather than a shared slot, states the encoding explicitly, and leaves a path for binary input if one ever appears.

`mediaType` and `checksum` descriptions widen: both are meaningful for embedded content, not only for a retrievable `href`. A `checksum` beside embedded bytes is what makes carriage verifiable rather than merely present.

**The primitive's `anyOf` also widens.** `External_Reference` required at least one of `externalId`, `href` or `description`, so an entry that *only* embeds — the normal `rawSourceArtifacts` case, since §2 sets `href` only when a meaningful location exists — would have been invalid. `content` or `document` now satisfies that rule too. Strictly additive: nothing that validated before stops validating. Without it, §2's own prohibition on local filesystem paths would have forced producers to invent a synthetic `href`.

**Conditions are expressed with `allOf`, never as keywords beside a `$ref`.** Draft-07 treats a `$ref` as replacing its schema object, so a sibling `if`/`then` is silently ignored — and the shipped Go validator is a draft-07 implementation. An early version of this change put the `mediaType` requirement beside a `$ref`: ajv enforced it and `hdf validate` accepted the invalid document. A repo-wide guard test now asserts that no source schema puts a validation keyword beside a `$ref` (annotations are fine, since they assert nothing).

### 4. Carriage is required of converters by policy, not by schema

Every ingest converter populates `rawSourceArtifacts` with its input, verbatim. This is enforced by the converter contract, the shared builders and the converter test harness — **not** by a schema `required`, because a tool that emits HDF natively has no source artifact, and a schema-level requirement would make valid native HDF invalid.

The policy belongs in the converter documentation and in the `build-converter` skill, so a new converter carries it from the first commit rather than acquiring it in review.

**It is satisfiable for every converter**, because §1 declares `extensions` on every document type a converter can emit. That needed establishing: ingest converters emit five output types, not three — results, amendments (five converters, including one declared in a table rather than a flat registration), baseline (three), plan (one), and one genuine ingest case declared as raw output, which is itself a misdeclaration worth fixing separately since it returns an HDF system document.

### 5. `code` means the code that ran; raw payloads move to `results[].rawSourceRecord`

`Requirement_Core.code` carries the source code, query or check that executed to produce a result, where one exists. It does **not** carry the record that running it produced. A converter writing a finding's raw payload into `code` is making a mapping error.

**The payload's home is `results[].rawSourceRecord`, not `rawSourceArtifacts`.** The two are different granularities and neither substitutes for the other: `extensions.rawSourceArtifacts[]` (§2) carries whole input artifacts, one per file the converter read; a misplaced `code` payload is a *fragment* — the one record inside that file which produced this finding. Nothing can reconstruct the fragment from the artifact without re-parsing the source format backwards, which is the converter run in reverse.

`Raw_Source_Record` is therefore defined on `Requirement_Result`, closed, with three required members and one optional locator:

| Member | Value |
|---|---|
| `content` | the record's bytes, as the tool wrote them |
| `encoding` | `utf-8` or `base64`, the same pair §3 gives artifacts |
| `mediaType` | the **record's** IANA media type, which may be narrower than its artifact's — an XCCDF `rule-result` is `application/xml` even when the document embedding it is JSON |
| `pointer` | optional: a JSON Pointer (RFC 6901) or XPath locating the record inside its artifact, e.g. `/matches/3` |

**The result, not the requirement, is the correct scope** — established from the data, not chosen for convenience. For a vulnerability scanner the native record is one (vulnerability, package) pair, which is exactly one result. In `grype-to-hdf`'s golden, 42 of 89 requirement ids are duplicated and *every* pair carries a different `code` payload, distinguished only by the package matched: `CVE-2022-48174` holds one record for `busybox` and another for `ssl_client`, `CVE-2024-5535` one for `libcrypto1.1` and one for `libssl1.1`. A requirement-scoped field cannot hold both.

**This is also what makes §6 lossless.** §6 merges entries sharing an id and rules `code` first-wins. Applied to payloads still sitting in `code`, that rule would discard 42 distinct match records from that one file — the same loss §6 rejects first-wins for on `affectedPackages`, one field over. Because `results[]` concatenate, a record carried on the result survives the merge untouched, and `code` first-wins becomes correct rather than lossy: once payloads move, a rolled-up requirement's `code` is genuinely shared or absent.

`pointer` is what makes carriage verifiable rather than merely present: with the artifact from §2 and the pointer from §5, a consumer can confirm the record really is the subtree it claims to be. That is the check `hdf verify` would run; nothing in this ADR requires it yet.

**Consequences this ADR previously missed.** The v2 downgrade populates `control.code` from `requirement.code` (`shared/go/hdfversion/hdf_version.go:311`), and Heimdall renders that field in its CODE tab — `hdf-libs-dggj` was closed specifically to fill it, after an empty tab was observed against heimdall2's native mapper. Emptying `code` without a replacement would regress that. With the record on the result the downgrade has a local mapping available again; the exact rule (which result's record populates a control's single `code`, or whether they concatenate) is decided by the card that migrates the downgrade. Separately, `.claude/commands/build-converter.md` still instructs the prohibited behaviour — *"put the finding's raw source … in `requirement.code` so Heimdall's CODE tab renders"* — and must be rewritten to name `rawSourceRecord`, or every new converter will keep reintroducing the error.

Note also that `Requirement_Core.code` is `{"type": "string"}` while its own description says *"Set to null for manual-only requirements"* — so `"code": null` fails validation today. That contradiction predates this ADR and is fixed separately; this section's rule is that an absent check leaves `code` **absent**, never null.

The 19 converters above need **per-converter judgment, not a blanket move**. Two examples from the measurement:

- **grype and neuvector** write the result record — `{"name": "CVE-2021-36159", "score": 6.4, "severity": "Critical", …}`. Plainly misplaced.
- **xccdf-results** writes the OVAL check-content reference — `{"system": "http://oval.mitre.org/XMLSchema/oval-definitions-5", "checkContentRef": {…}}`. That is arguably *what ran*, and it is the largest single population at 862 requirements. Whether it stays in `code`, moves to a check-reference field, or moves to the artifact is decided per converter as that converter is migrated.

A converter with no executable check leaves `code` absent rather than filling it.

### 6. Requirement roll-up: one requirement per id, within one baseline

Entries sharing an id merge into one requirement whose `results[]` is the concatenation of theirs, **within a single baseline only, never across baselines**. Crossing baselines would destroy real data: `prisma-to-hdf`'s golden has 16 baselines, 94 entries and 53 distinct ids but 92 distinct `(baseline, id)` pairs — a document-wide merge would collapse 39 findings from different hosts.

The instance that was a second requirement becomes a result, identified by `results[].resource` and `results[].resourceId` — fields that exist for exactly this and are populated by no forward converter today.

**Merge rules, every field:**

| Field | Rule |
|---|---|
| `id` | the merge key; identical by construction |
| `results` | concatenate, in source order — the whole point |
| `affectedPackages` | **union**, de-duplicated on `purl` where present, else name + version; source order preserved. Conflicts in 64 of 68 groups; first-wins would discard real package facts |
| `code` | first-wins. Conflicts in 66 of 68 groups today **only because payloads are misplaced** (§5); once they move, a rolled-up requirement's `code` is genuinely shared or absent |
| `cwe`, `refs`, `externalReferences`, `evidence`, `statusOverrides`, `poams` | **union**, de-duplicated on identity where the member has one |
| `tags` | per key: array-valued tags union; scalar-valued tags first-wins |
| `impact`, `severity`, `effectiveImpact` | worst-wins. Exercised by exactly one real group (veracode id `12`, impacts 0.5 and 0.3 — a CWE *category* id spanning two severities, which the converter-id policy may dissolve at source) |
| `title`, `descriptions` | first-wins. Zero conflicts in all 68 groups; stated as a rule so the helper has defined behaviour when a future converter conflicts |
| `sourceLocation` | first-wins, and meaningless on a rolled-up requirement — see Open Questions |
| `controlType`, `verificationMethod`, `applicability` | first-wins |
| `cvss`, `epss`, `kev` | first-wins; these describe the vulnerability, not the instance |
| `effectiveStatus`, `disposition`, `effectiveChecksum` | not merged — derived after merging, from the merged results and overrides |

**heimdall2 is first-wins for every requirement-level field.** We deliberately diverge on `affectedPackages` (union) and the array-valued tags, because execjson has no `affectedPackages` and ours conflicts in 64 of 68 groups. "We mirror heimdall2" is not a sufficient rule anywhere in this table.

**Opt-in is declared at the registry**, alongside the existing expected-count declaration, so roll-up and fidelity counting stay declared in one place. It is never a user-facing flag.

**A result-count anchor is mandatory.** Roll-up moves the raw-finding count from requirements to results; without a result-count check a rolled-up converter loses its under-extraction guard entirely.

### 7. Migration from v2

- `passthrough.raw` → a `rawSourceArtifacts` entry. A migrated entry carries at minimum `sourceName`, the bytes, and `mediaType` — the last is derivable, because v2's `passthrough.raw` held a parsed JSON payload, so `application/json` is known. The exemption from fresh-conversion completeness covers `checksum` and tool-version detail only: `mediaType` is required on any entry that embeds (§2), and a requirement that holds only in prose is not a contract.
- `passthrough.auxiliary_data` → stays in `extensions.passthrough`. It is genuinely homeless data, which is what that field is now for.
- Any other key under a legacy `passthrough` → stays in `extensions.passthrough`.

### 8. The media type is derived from the converter's declared input family, and a converter may override it

Every converter already declares an `InputFamily` in its fingerprint registration (`hdf-converters/registry/registry.go:8-13`): 41 declare `json`, 9 `xml`, 2 `text`. A shared helper maps that family to a default media type — `json` → `application/json`, `xml` → `application/xml`, `text` → `text/plain` — so 44 of 47 ingest converters need no change: the builder reads the family that is already registered.

A converter **may override** the derived value when it knows the bytes more precisely than its family does. Two cases exist today and one class will recur:

- **prisma** overrides to `text/csv`. Its input is CSV, which the `text` family cannot express.
- **scoutsuite** registers *two* fingerprints — `scoutsuite-to-hdf` in the `json` family for bare JSON, and `scoutsuite-to-hdf-js` in `text` for the JS-wrapped form. Only the second overrides, to `text/javascript`; the first takes the `application/json` default.
- **asff and trufflehog** accept JSON *or* NDJSON on one entry point, and the family is declared once at registration. They override to `application/x-ndjson` when that is what they parsed. The override is reported by the converter from the shape it actually parsed — not re-sniffed, because the converter has already made that determination in order to choose a parser.

**`FamilyCSV` is deliberately not added to the enum.** `InputFamily` is not a label: `registry/fingerprint.go:111` skips any converter whose declared family does not equal `DetectFamily`'s output, so the fingerprint never runs. `DetectFamily` (`:186-207`) switches on the first meaningful byte — `{`/`[` → json, `<` → xml, otherwise text — and therefore cannot produce CSV, because a CSV file starts with a letter exactly as scoutsuite's JavaScript does. Declaring `FamilyCSV` on prisma would make `DetectFamily` return `text`, the filter would skip prisma, and `hdf convert` would stop auto-detecting Prisma CSV altogether. Teaching the sniffer to recognise CSV means heuristics (delimiter counting across leading lines) that would also match plain text and JavaScript — a real detection risk bought for a string an override supplies for free.

That coupling — a declared family the sniffer cannot produce silently unregisters a converter — is a design weakness worth addressing on its own (a list of acceptable families, or a preference rather than a hard skip), but it is not in this ADR's scope and must not be smuggled into it. It is tracked as `hdf-libs-5sy1i`, which also records what makes the trap hard to see: the TypeScript family type already declares a `'csv'` member its own sniffer cannot produce (nothing declares it, so nothing is broken yet), and Go's fingerprint test helper calls a converter's `Fingerprint` directly with pre-parsed input, so it never exercises the family filter at all — the TypeScript helper routes through detection and would fail immediately. Nothing today is unreachable: auto-detect was verified against prisma's CSV and scoutsuite's JS fixtures.

## Alternatives Considered

### A: Mandatory inline embedding, enforced by the schema
- **Pros:** every document self-contained; one rule to state.
- **Cons:** makes natively-emitted HDF invalid, since a native emitter has no source artifact; invalidates every existing fixture and golden; measured median cost 2.32× raw and 1.99× gzipped, up to 12× for lossy converters, which halves the usable budget of every round-trip pipeline.
- **Rejected:** the guarantee is available from a policy the harness enforces, without breaking documents that were never converted.

### B: Keep the source artifact in `extensions.passthrough`
- **Pros:** matches v2's mental model and the name people expect.
- **Cons:** untyped — no checksum, media type or reference contract; object-only, so text sources still need wrapping; invisible to schema validation; retained in Go as an `interface{}` tree.
- **Rejected:** it keeps the bytes and loses the verifiability that makes carriage worth doing. `passthrough` keeps its catch-all job (§1).

### C: Widen `document` to `object | array | string`
- **Pros:** one member, smallest schema diff.
- **Cons:** one field holding parsed JSON or raw text, discriminated only by reading `mediaType`; no home for non-text; forces every consumer to type-switch.
- **Rejected:** see §3.

### D: A new top-level `source` field rather than one under `extensions`
- **Pros:** discoverable.
- **Cons:** duplicates `External_Reference`, which already carries href, checksum, media type and an embedded copy; adds a seventh meaning to "source" in a schema that already has `sourceLocation`, `sourceName`, `sourceIndex`, `sourceLabel`, `sourceDocument` and `sourceURI`.
- **Rejected:** the primitive exists; a new `rel` token and a named array compose with it.

### E: Standardize per-requirement raw carriage in `code` (formalize today's behaviour)
- **Pros:** data sits beside the finding that produced it; already practised by 19 converters.
- **Cons:** fragments the artifact so the original cannot be reconstructed; overloads a field with a different documented meaning; duplicates content once the document-level artifact exists.
- **Rejected:** it cannot deliver reconstruction, and §5 is the ruling against it.

### F: Do nothing
- **Cons:** `extensions.passthrough` stays an undocumented convention four code paths write; `code` keeps accumulating payloads; converters keep inventing carriage; duplicate ids keep breaking diff, events and thresholds.
- **Rejected:** the cost is already being paid, in defects rather than in work.

## Consequences

**Easier:** every converted document names its input and ties it to the exact bytes by checksum; reconstruction becomes possible where the artifact is embedded; `code` becomes meaningful again; requirement ids stop repeating within a baseline, which makes diff matching, change events and named-control thresholds correct without special cases.

**Harder or more expensive:** documents that embed grow — roughly double, and up to 12× for lossy converters — so a pipeline's headroom halves; every ingest converter is touched once for payload relocation plus roll-up; every affected golden regenerates; a media-type value is needed per converter where none exists today.

**Breaking:** consumers reading a raw payload out of `code` must read `rawSourceArtifacts` instead. Consumers counting requirements see fewer of them for the same findings — the count moves to results. Both need release-note prominence.

## Open Questions

1. **Embedding above the reading limit.** Size is a runtime policy, not a validity rule: the schema does not constrain it, and the CLI already owns the limit — `hdfutil.DefaultMaxInputSize` is **256 MB** (`hdf-utilities/go/size.go:11`), with `SetDefaultMaxInputSize` and `--max-size` to raise it. The largest committed converter input is the 10.4 MB OSCAL catalog, which embeds to roughly 21 MB, so this is an edge case in the fixture corpus — but note *why* the limit is 256 MB: a consumer reported hitting the previous cap with real scan data (issue #334), before inlining was proposed. Embedding doubles documents that were already pressing against a limit someone reached in practice, so the builder's behaviour here is a real question, not a theoretical one. The question is what a *builder* does when embedding would push output past the limit the next command will read it at: refuse to embed, embed and warn (`convert.go` already warns when output will need `--max-size` to re-read), or parse `content` lazily.
2. **`sourceLocation` on a rolled-up requirement.** It is genuinely per-instance for SAST findings and has no home on a result. Add it to `Requirement_Result`, encode it into `resourceId` as `file:line`, or keep first-wins and document the loss? Today it conflicts in one group, where the field is *already* corrupt: nine filenames newline-joined against one line number.
3. ~~**Media types.**~~ **Resolved 2026-09-27 — see §8.**
4. **`resultsChecksum` overlap.** Converters store the raw-input SHA-256 there, but the schema describes it as "raw results before any amendments". With the artifact's own checksum authoritative, does `resultsChecksum` get redefined?
5. **Sensitivity.** Raw tool output routinely carries hostnames, internal addresses and configuration fragments. Does embedding need a sensitivity marker, or redaction guidance?
6. **Reconstruction.** Is a `hdf restore`-style capability in scope, and is there a concrete workflow that needs it? No consumer reconstructs a source today.
7. **Multi-artifact order.** For the profile-plus-catalog case, does entry order carry meaning?
