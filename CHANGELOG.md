# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Notable behavior changes

- **`isValidXml` now rejects documents containing characters XML 1.0 forbids, and `hdf-to-xml` replaces them with U+FFFD instead of emitting them.** The validator checked structure but not the `Char` production, so it called a document well-formed that no conforming parser will read — which is how the TypeScript `hdf-to-xml` shipped documents a strict parser rejects whenever a result's `codeDesc` carried an ANSI colour escape, everyday InSpec output. The Go peer never had the defect: `encoding/xml` substitutes U+FFFD and that is not configurable, so matching it is what puts the two languages back in agreement. XML 1.0 defines no escape for these characters — a numeric reference to a C0 control is itself illegal — so losslessness was not available and a replacement character is the only representable answer. **Two consequences for consumers:** `isValidXml` returns `false` for input it previously accepted, including *received* XML from a scanner that emits raw control characters, and `extractTextFromXml` returns `''` for such input rather than its text; and `hdf-to-xml` output now carries U+FFFD where a control character used to pass through. Both are the correct XML 1.0 answer, but a caller relying on the old leniency will see the change on first run.
- **`hdf-to-openvex` now omits a statement's `products` array when nothing identifies a product, instead of emitting a synthetic `HDFPID-0001`.** OpenVEX types a component `@id` as an IRI, and a bare token is a relative reference, so any override carrying no `affectedPackages`, no `componentRef` and no legacy `Products:` line produced a document the OpenVEX schema rejects — from valid HDF, at exit 0. `products` is optional in OpenVEX, so omission is legal, and it is the honest answer: a minted identifier asserts a product the source never named. Round-tripping improves as a side effect, since the placeholder previously came back as a bogus `affectedPackages` entry.
- **BREAKING — `hdf amend verify` now exits non-zero on an expired, invalid or tampered amendment — it previously exited 0 no matter what it found.** Measured before the change: a file whose every waiver had lapsed printed `Valid: 0  Expired: 3  Warning: Some amendments are expired or invalid.` and exited 0, so a CI step written as `hdf amend verify waivers.json` was a green step that checked nothing. An expired amendment is now a failure, not a warning, and **there is deliberately no flag to make one pass** — a waiver that has outlived its review date is a suppression with no end date, and the remedy is to review the finding and issue a new amendment. The summary counts expired and structurally invalid amendments on separate lines, because they have different remedies (renew the review vs. fix the document), and structural validity is now checked against the hdf-amendments schema rather than an ad-hoc field check. **Anyone already scripting against this command will see a step that always passed start failing** — that is the point, but it will surface on first run.
- **`hdf amend verify` now actually verifies the amendment chain; it previously reported `All amendments are valid` on a tampered file.** The schema described `previousChecksum` as tamper-evident and the command's help claimed to check "chain integrity", but nothing recomputed it. Measured before the change: rewriting an override's `reason` while leaving the stale `previousChecksum` in place was reported clean at exit 0 — so an amendment's recorded justification, author or status could be altered after the fact with every integrity signal still green. Verify now recomputes each amendment's checksum and compares it against the next amendment's `previousChecksum`, naming the specific link that broke. The canonical hash is shared with `hdf amend create`, so the writer and the checker cannot drift into a check that always passes, and it is computed from the parsed document — a reformat that changes key order or whitespace does not false-positive. **What the chain proves is narrower than the old wording implied, and the schema descriptions and docs now say so:** it detects an amendment edited in place, not an editor who recomputes every later link or drops trailing amendments. `signature` remains what makes an amendment non-repudiable. Relatedly, the schema said `previousChecksum` was "Null for the first amendment" while typing it as an object, so a document following that prose failed validation; the descriptions now say "omitted", which is what `hdf amend create` has always written.
- **BREAKING — `hdf amend apply` and the `hdf_apply_amendment` MCP tool now refuse an amendments document that does not verify, instead of applying it.** Both previously merged whatever they were handed: an expired waiver, a document whose amendment chain was broken, or one that was not a structurally valid amendments document all applied cleanly at exit 0 — so the CLI could refuse to *verify* a file at the same moment it agreed to *apply* it, and an agent driving MCP had no gate at all. Apply now refuses everything a one-argument `hdf amend verify` refuses — structure, expiry and chain — through one shared implementation, and the refusal names what to fix. It deliberately does not adopt the results-pair checks the two-argument `verify <amendments> <results>` adds: an override naming a requirement absent from those particular results is normal, since one amendments document may cover a fleet and be applied per host. **There is no flag to apply an unverifiable document**; the remedy is to renew the amendment, repair the chain, or fix the document. Note that the structural half of the gate is the full hdf-amendments schema, so two shapes that previously applied are now refused: an override that spells an absent optional field as an explicit JSON `null` (some serializers emit `"signature": null` rather than omitting the key), and a document whose only defect is in envelope metadata (a non-UUID `amendmentId`, say). Both are genuinely schema-invalid and `hdf validate` has always said so; apply now agrees with it rather than the two commands disagreeing about the same file. The gate is document-scoped and deliberately stops there: an override naming a requirement that is absent from the particular results being amended is **not** refused, because one amendments document may legitimately cover a fleet and be applied per host, and automating that must not require a pre-check for which overrides match. A document still carrying the `_draft` marker keeps its own more specific refusal.
- **Every route that produces a finished amendments document now writes the `previousChecksum` chain; previously only `hdf amend create --from` did.** The interactive `hdf amend create`, `hdf amend create --from-vex`, both MCP `hdf_author` paths (from_vex and the agent-judgment path), and all five amendment-emitting converters (`openvex-to-hdf`, `csaf-vex-to-hdf`, `cyclonedx-vex-to-hdf`, `spdx-vex-to-hdf`, `oscal-poam-to-hdf`) emitted unchained documents, so `hdf amend verify` reported `Chain: not established` and the tamper-evidence was simply unavailable to the routes most people use. All of them chain now, and an in-place edit of a converter-produced amendments document is detected.

  Two routes deliberately do not chain, and both are tested as such. `hdf amend draft` emits incomplete stubs, so chaining them would guarantee a broken chain the moment anyone fills them in — **which means a completed draft carries no chain, and nothing re-chains it on completion**; use `hdf amend create --from` if you want the finished document chained. A document authored by other tooling that simply omits `previousChecksum` throughout is unaffected: it verifies clean as `Chain: not established` and applies normally, so declining the feature entirely remains a supported choice.

  **The canonical hash moved down into `@mitre/hdf-utilities` / `hdfutil` (`canonicalJson`/`canonicalChecksum`, `CanonicalJSON`/`ChecksumJSON`)** so the converters — which cannot depend on `hdf-diff` — hash identically to `hdf amend verify`. Existing chains are unaffected: the relocation is byte-identical, verified by the pinned checksums that already guarded it.

  The canonical form is Go's `encoding/json` encoding of the value's JSON shape, and reproducing it byte for byte in another language requires **all** of: object keys sorted by UTF-8 byte order (not UTF-16 code units, which differ for non-BMP keys); `<`, `>`, `&` escaped as `\u003c`/`\u003e`/`\u0026` and U+2028/U+2029 as `\u2028`/`\u2029`; null-valued object keys dropped; unpaired surrogates replaced with U+FFFD, in keys and values alike, because Go substitutes them at decode time while `JSON.parse` preserves them; negative zero emitted as `-0`, which `JSON.stringify` renders as `0`; and NaN/Infinity rejected. Every one of those is a point the two languages were found to diverge or would have — the surrogate case was reproduced end to end, where a TypeScript converter's own untampered output was reported as tampered and refused by `hdf amend apply`. Go and TypeScript are pinned against 26 shared vectors in `hdf-utilities/testdata/canonical-json-vectors.json`, which the Go implementation generates and both suites assert against.
- **BREAKING — consequence for the VEX import path: converting an old VEX document and applying it is now refused.** All four VEX importers (`openvex-to-hdf`, `csaf-vex-to-hdf`, `cyclonedx-vex-to-hdf`, `spdx-vex-to-hdf`) derive each override's `expiresAt` as the source document's own timestamp plus a one-year horizon, so a VEX document older than a year produces amendments that are *born expired* — measured on the shipped `spring-boot-log4j.openvex.json` fixture (statement time 2023-01-17, derived expiry 2024-01-17), `hdf amend apply` now exits 1 with `amendments document does not verify: 1 expired`. This is the intended semantics: a two-year-old VEX assessment with no current review is exactly the lapsed risk decision the gate exists to stop. **The remedy is `hdf amend create --from-vex <vex> --expires <date>`**, which derives the same overrides but makes the review horizon an explicit, current decision rather than an artifact of when the VEX document was written. Amendment documents shipped as converter *fixtures* are correspondingly expired, because their dates are derived from real source-document timestamps — the VEX horizon above, or, for `oscal-to-hdf`, the related risk's own `deadline`. They are left as-is rather than being given synthetic far-future dates, which would fabricate fixture data.
- **BREAKING — chain-hash epoch: amendment chains written before this release over an override carrying an explicit JSON null no longer verify.** The canonical form the chain hashes now drops null-valued keys, so that a document spelling an absent optional field as `null` hashes identically to one that omits it. Overrides with no nulls — everything `hdf amend create` has ever written — are unaffected and verify unchanged. An affected file reports a chain break on an untampered document; re-issue the amendments document to re-anchor it. The canonical form is now pinned by a test and documented in full (Go `encoding/json` map marshalling: sorted keys, `<`, `>` and `&` escaped as `\u003c`/`\u003e`/`\u0026`, null-valued keys dropped) so a future non-Go implementation can reproduce it byte for byte.
- **SARIF conversion now reads `properties.security-severity`, and it outranks `level` — impact and severity change for any scanner that carries CVSS there.** SARIF's `level` is only `error`/`warning`/`note`, and several scanners emit a single level for every finding while putting the real CVSS base score in the rule's `security-severity` property (CodeQL, semgrep and OSV-Scanner all do). The converter previously mapped `level` alone through a three-value table, so every finding from such a tool collapsed to one impact and carried no severity at all — measured on real osv-scanner output, a CVSS 8.2 finding arrived as `severity: null, impact: 0.5`, indistinguishable from a 5.5. Impact and severity are now derived from the CVSS score when the rule carries a usable one, with `level` as the fallback; both are rule-level, so nothing per-result is discarded. **This changes gate outcomes**: severity-tiered thresholds were previously unreachable for such tools — a `failed.high.max: 0` bound passed a CVSS 8.2 finding because it landed in the `medium` bucket — and now bite. Tools that vary `level` and carry no CVSS, such as eslint, are unaffected. (#292)
- **`hdf convert -o <dir>` now writes into the directory whatever the input count.** A directory output was only honored when more than one input file matched; a single file with `-o out/` wrote to a path named after the directory, and failed outright if that directory did not already exist. Whether a glob matches one file or twelve is an accident of how many scans a pipeline produced, so the flag now means the same thing at either arity: a trailing separator, or an existing directory, is a directory and is created if absent. A plain path is still a file. (#289)

- **`hdf validate threshold -T` now rejects unknown keys and templates that assert nothing — a misspelled key used to disable a gate silently.** The template file was parsed permissively, so any key the schema did not recognize was discarded: a template whose keys were misspelled parsed to an empty threshold set and reported `All thresholds passed` with exit 0. Measured on a document with 89 failing findings, `failed.total.max: 0` correctly failed, while `faild:`, `totl:` and `mx:` each passed vacuously — at every nesting level, so a single typo in a committed CI gate switched that gate off with no signal anywhere. Template decoding is now strict, and the rejection names the offending key and line in the template's own vocabulary rather than a Go type. **The `-I` inline path had a narrower version of the same flaw, also fixed here:** it rejected unknown categories and bounds, but a misspelled *severity* (`failed.totl.max`, `failed.hgh.max`) was silently bucketed into `none`, quietly asserting a bound nobody wrote and passing. Separately, a template that parses successfully but declares no bounds at all (an empty file, `{}`, comments only, or empty sections such as `failed: {}`) is now an error rather than a pass, since it asserts nothing about the document and its success means nothing. **A template carrying a stray or misspelled key now fails where it previously passed — that is the point, but it will surface on first run.** Templates produced by `hdf generate threshold` are unaffected and round-trip cleanly.
- **`hdf_compliance` applies that same threshold strictness, so the MCP tool and the CLI gate can no longer disagree about a spec.** The tool parsed threshold specs permissively, so an agent passing a spec with a misspelled key — or one asserting no bounds at all — got back a passing verdict from a check that never ran. Both are now rejected as `SCHEMA_INVALID` naming the offending key and line, for the `path` and `inline` spec shapes alike, and a rejected spec carries no `thresholdVerdict` at all so a caller can distinguish a malformed spec from a failed gate. The strictness lives in one place both surfaces call rather than in two implementations that happened to match.
- **Checksum epoch: previously derived requirement-change-event chains will report `chainGap` warnings.** Effective checksums hash the resolved status, so the semantics change above re-epochs them: chains derived by older binaries over documents containing affected requirements (impact-0 errored checks, stale stored statuses) verify against different expected values under this release. The chains are not corrupt — re-derive them from a fresh rescan to re-anchor; the `chainGap` warning text now explains both possible causes and the remedy (see `status-determination.md` § Checksum epochs). Epoch-aware acceptance of old checksums was deliberately not implemented, as it would weaken chain integrity for genuinely broken chains.
- **The ground-truth-only status contract now reaches every surface**: all exporters (asff/ecs/ocsf/splunk via the shared export core, plus ckl/cklb, xccdf, oscal-sar, csv) resolve status through the canonical ladder instead of trusting the stored field, so a gate and an export can no longer disagree about the same document; `legacyhdf-to-hdf` recomputes `effectiveStatus` on both conversion paths instead of baking the v1 control status verbatim, and synthesizes an errored result when a tool-level error is not reflected in the recorded results (a crashed tool's knowledge lands in ground truth, not a side-channel field); the public `@mitre/hdf-schema/helpers` `computeEffectiveStatus` now delegates to the canonical implementation (previously a documented divergent variant); and export `suppressed`/`overridden` flags now require actual override records — structural impact-0 Not Applicable is no longer mislabeled as acceptance-suppression, and the mere presence of a cached status field no longer counts as "overridden". Golden-visible effect: impact-0 findings align to Not Applicable in ECS (`event.outcome: unknown`), OCSF (`status_detail: notApplicable`), and ASFF (`Compliance.Status: NOT_AVAILABLE`).
- **Effective status is now computed from ground truth only — the stored `effectiveStatus` field is never read.** The canonical computation is a fixed four-step ladder: governing (non-expired) override → `error` roll-up → impact-0 `notApplicable` → worst-wins roll-up. Three visible changes: (1) an errored check escapes the impact-0 short-circuit and reports `error` (a crashed check never established applicability); (2) a stored `effectiveStatus` that contradicts the results is ignored in **both** directions — a stale `passed` over failing results no longer launders a failure through gates, and a stale `error` over passing results no longer sticks forever; (3) a governing override adjudicates uniformly at any impact, including impact 0, regardless of how the check terminated. Documents carrying stale baked values (converted before this change) will change gate outcomes — that is the point: the only sanctioned channel for status to diverge from results is a signed override. The field itself remains in the schema as a write-path-guaranteed cache for raw-JSON consumers. Full contract: `site/docs/architecture/status-determination.md`.
- **`hdf-to-oscal-sar` output is now schema-valid for real-world scans, which changes where prose lands in the SAR.** Multi-line `code`/`check`/`fix`/`rationale` text was previously emitted raw in finding `props[].value`, which OSCAL's `StringDatatype` forbids (no newlines, no edge whitespace) — a real RHEL 9 STIG scan produced 1,325 NIST v1.1.2 schema violations. Now: `check`/`rationale` (and plain-string `reference`) props carry a single-line preview as the value with the full text byte-exact in the prop's `remarks`; `fix` is no longer duplicated as a finding prop when a risk exists (its home remains `risk.remediations[].description`; impact-0 requirements keep a prose `fix` prop); `code` moves to a base64 back-matter resource linked from the finding with `rel: "code"`. Consumers reading `code`/`fix` finding props must switch to the new homes. Single-line values ≤120 chars are unchanged.

- **`hdf validate threshold` / `hdf generate threshold` now count by effective status — Not Applicable (impact 0) no longer inflates `skipped` or the compliance denominator.** Previously the threshold path counted raw result statuses: on InSpec-derived scans (where a skip serializes as a `notReviewed` result and Not Applicable is signalled by `impact == 0`), every impact-0 requirement was miscounted as `skipped`, the `no_impact.*` threshold section was effectively dead (always 0, never satisfiable), and compliance was understated by keeping Not Applicable in the denominator. Threshold counting now applies the canonical effective-status rule (`impact == 0 → notApplicable`, non-expired overrides honored) — the same rule the MCP read tools and HDF's compliance rollups use, so a CLI gate and `hdf_compliance` agree on the same document. **This changes CI-gate pass/fail outcomes on container-heavy corpora:** measured on real container InSpec scans, compliance rose ~30 points (e.g. 16.18% → 46.67%) as ~113 Not Applicable controls moved from `skipped` to `no_impact`. Threshold files that pinned `skipped.*` counts or relied on the understated compliance number must be regenerated (`hdf generate threshold`); `no_impact.*` bounds are now meaningful and enforceable.

### Added

- **`hdf validate threshold` accepts multiple files, applying one policy to many documents.** It was the only verb in the chain still limited to a single file, which forced CI gates into shell loops that rebuilt the output filenames `hdf convert` already generates. The template is parsed once and applied per file, so a broken template fails before any document is read, and `runBulk` semantics apply: every file is processed and the verdict reported at the end, with `-F` aborting early. `MinimumNArgs(1)` rather than arbitrary args, so an unmatched shell glob is an error rather than a vacuous pass. Single-file output, exit codes and violation text are unchanged. (#289)

### Fixes

- **BREAKING — `hdf amend verify <amendments> <results>` no longer reports a "Results link" verdict, and `--json` output drops three fields.** The check read a root `previousChecksum` off the *amendments* document and compared it to the hash of the results file. Nothing in the codebase has ever written that field, it is not in the hdf-amendments schema, and it could not be correct in general: one amendments document may be applied to many results files, so it cannot carry a single results hash. The check could therefore never fire on a document this toolchain produced. It is removed rather than repointed, because the capability it claimed — detecting that an amendments file was applied to results other than the ones it was authored against — requires a binding stored on the amendments side, which is the incoherent design being retired. The two-argument form keeps its real check, that every `requirementId` names a requirement present in those results. **Consumers parsing `--json` will see `chainEstablished`, `chainValid` and `chainMessage` gone** from the verify payload; the amendment-to-amendment chain reported under `expiration.chain` is a different mechanism and is unaffected.
- **`hdf amend apply` now returns the document untouched when no override matches, instead of rewriting it.** An amendments document whose overrides named no requirement present in the results still stamped the root checksum and re-stamped every requirement's `effectiveChecksum`, so applying a fleet-wide amendments file to a host it does not cover silently rewrote that host's results while amending nothing. Apply now reports whether each override matched and, when none did, returns the input unchanged. This is the shape reported in issue #248, where the only difference between a v2 input and its "merged" output was a root checksum; that input now round-trips byte-identically. The underlying gap in #248 — that legacy v2 (InSpec exec-json) documents match nothing at all because they carry no `baselines` — is unchanged and still open.
- **BREAKING — `hdf amend apply` now writes `preAmendmentChecksum` at the results root, renamed from `previousChecksum`, and `hdf-results` declares it.** Apply has always stamped a root-level hash of the results as they stood before the application, but the schema never declared the property while setting `unevaluatedProperties: false` — so every amended document was off-schema. That was invisible in practice only because the shipped validators are draft-07 and silently ignore that keyword; under a 2020-12 validator the same document was rejected with "must NOT have unevaluated properties". **The rename is deliberate and this was the last moment to make it for free:** `previousChecksum` already means "the previous amendment in the chain" on `Status_Override`, `POAM` and `Standalone_Override`, so an amended document carried one name with two unrelated meanings at two depths. Because the root field was never declared, no schema-conformant consumer could have depended on it, and the only writer is this toolchain. Anything reading the old root key by hand must move to the new one. What the field means: the prior state of **this results document**, most recent only — re-applying replaces the value rather than accumulating, so it is a single link back one step. The hash covers the results file's raw bytes as read, not a canonical form, so reproducing it needs the byte-identical original; the override-level chain, by contrast, hashes a canonical form.
- **`hdf validate` no longer prints document-controlled text to the terminal unfiltered.** Schema errors were written with a bare `fmt.Fprintf`, so a field path quoting a key from an open key space carried whatever that key contained — including ANSI escape sequences. The root `labels` object on hdf-amendments is `additionalProperties: {type: string}`, so a document with a label key containing a CSI sequence and a non-string value put a raw escape on the user's terminal. `hdf amend verify` already routed the identical strings through the sanitizer, so the two commands disagreed about the same file. All three branches of validate's error output are now sanitized, as is the message the `enrich` and `events` commands return. The offending text stays visible; only the escapes are defanged. `--json` output was never affected and is unchanged, since encoding escapes control characters already.
- **`netsparker-to-hdf` labels a vectorless CVSS 3.0 block as 3.0, not 3.1.** Invicti reports carry two classification blocks, `<cvss>` for 3.0 and `<cvss31>` for 3.1. The converter derived the version from the vector string alone and discarded which element the block came from, so a block carrying a Base score but no vector fell to the default and reported `3.1`. The element now supplies the version for a vectorless block, while a block that does carry a vector still takes the version from it. Consumer-visible in `cvss[].version`; the committed fixture carries vectors on both blocks, so no golden changed.
- **Interactive `hdf amend create` now schema-validates before writing, matching the headless routes.** The `--from` and `--from-vex` routes validated their output and refused to write on failure, while the interactive form marshalled and wrote with no validation at all, so a document that drifted from the schema was written silently and failed later at apply time or in a consumer. The gate now lives once on the shared write path and covers stdout as well as a file, since piping an invalid document to a consumer is the same defect as writing one.
- **`semgrep-to-hdf` now publishes `requirement.severity`; it was `null` on every finding.** The converter set `impact` from semgrep's severity (0.7 for ERROR, 0.5 for WARNING, 0.3 for INFO) and copied the raw label into `tags.severity`, but never filled the canonical top-level field — measured on a real 203-finding run, every requirement carried `severity: null`. Gates were unaffected, since the threshold engine falls back to impact, but any consumer reading the artifact had to know to look in `tags` or re-derive the band. The field is now the band the impact already implies (ERROR → `high`, WARNING → `medium`, INFO → `low`), so the two can never disagree. A finding whose severity semgrep withheld or omitted still has no `severity`, on purpose: its `tags.severity_rating: unrated` marker is what says the 0.5 was a default, and a published `medium` would hide that.

## [3.5.1] - 2026-08-11

Patch release: a new SPDX-VEX importer, NIST Rev 4 ↔ Rev 5 revision infrastructure, export-side field fidelity (the override channel now survives export), broad import-converter field backfills, and supply-chain hardening. No schema changes — schema `$id` URLs remain at v3.5.0.

### Added

- **`spdx-vex-to-hdf` converter (Go + TS + CLI).** Ingests SPDX 3.0 security-profile JSON-LD documents (VEX assessment relationships over CVE data) and emits an HDF Amendments document, joining the openvex/csaf-vex/cyclonedx-vex amendment-importer family. Registered in `hdf convert` auto-detection via a new SPDX-3-security fingerprint — such documents previously matched no detector and errored. A follow-up tracks the general "whole SPDX document in one go" case, which can span multiple HDF document types. (#210)
- **NIST SP 800-53 Rev 4 ↔ Rev 5 control crosswalk in `hdf-mappings`.** A generated `nist-revision-crosswalk.json` derived from NIST's own comparison workbooks (main + Appendix J): per-revision rosters plus explicit moved/incorporated/pointer/withdrawn edges, exposed via `Translate`/`TranslateControls` (Go) and `translateNistControl(s)` (TS). `awsconfig-mappings.json` is now per-revision complete (496 → 790 rows, each with a provenance `source` field). Documented in the new `site/docs/guides/nist-revisions.md`. (#190)
- **Rev 5 NIST control descriptions; rev-aware description lookups.** The description table was Rev 4-era (missing SR/PT families, carrying withdrawn controls, stale titles). A checked-in generator builds the Rev 5 set from NIST's OSCAL catalog; `getNISTDescription`/`nistExists`/`getNISTFamily`/`getAllNISTIds` take an optional revision parameter defaulting to the selected revision. (#203)
- **npm supply-chain cooldown.** `minimumReleaseAge: 7 days` in `pnpm-workspace.yaml` — dependency resolution refuses versions published within the last week, so a freshly-compromised release ages out of danger before it can be pulled. CI frozen-lockfile installs are unaffected. (#202)
- **`hdf validate` accepts requirement-change-event documents.** The 8th HDF document type (shipped in 3.5.0) is now auto-detected by its `eventId` root key and accepted via `--type requirement-change-event`; previously `hdf validate` rejected it as an unknown schema type even though the embedded validator already supported it.

### Fixes

- **Export converters carry the override channel.** All 14 `hdf-to-*` exports previously emitted the raw result status and dropped overrides, misrepresenting waived/false-positive findings in ASFF, ECS, OCSF, Splunk, CKL/CKLB, XCCDF, CSV, VEX, and OSCAL output. Exports now derive status from `effectiveStatus` and carry override provenance, closing ~100 audited field-loss gaps. (#209)
- **Import-converter field backfills.** Two additive sweeps restoring source fields that were parsed-then-dropped or never read (titles, timestamps, tags, identifiers, structured status overrides from source-native suppression/triage/dismissal data in sarif, cyclonedx, msft-defender-endpoint, and defectdojo). (#201, #211, #204)
- **Result `start_time` backfills:** zap (report generation time), burpsuite (exportTime), conveyor (`service_started`, was `service_completed`) — instead of the Go zero time. (#211)
- **Computed-impact float noise eliminated.** fortify, asff, cyclonedx, neuvector, and msft-secure-score route computed impacts through the shared `roundImpact`; `hdf-diff` rounds serialized `matchConfidence` to 4 decimals. (#212)
- **SARIF suppressions without a `status` property are honored.** SARIF 2.1.0 treats a status-less suppression as in force, and real producers (CodeQL, semgrep) emit exactly that shape; the suppression-to-override importer now treats absent status as accepted instead of silently dropping the suppression. Found in the pre-release review.
- **SARIF requirement roll-up follows the canonical worst-wins ordering.** The suppression-effectiveness check used a local ordering that ranked `failed` above `error` and `notReviewed` above `passed`; it now delegates to the shared `worstStatus` helper, matching every other component. Found in the pre-release review.
- **Nessus ACAS-shape regression guard.** A committed Go + TS test locks in that `cvss3_base_score` is promoted to a tag and CVSS entry and that IAVM xrefs and `stig_severity` survive, with fixture provenance documented. (#208)
- **STIX enrich fan-out is bounded.** `enrich stix` embedded the full raw STIX object into `externalReferences[]` of every finding matching a cited CVE (and of the results root) with no cap — an untrusted threat-intel bundle could amplify quadratically (N objects citing one CVE × M duplicate-id findings that cite it). STIX references are now capped per container via the shared truncation helper, preserving pre-existing references. Found in the pre-release review.

### Notable behavior changes

- **Export output changed for all 14 `hdf-to-*` converters** (#209): consumers pinning exact export bytes will see new fields, and — for findings under a governing override — a *different status value* than before (the effective status, not the raw one). The prior behavior misrepresented waived findings; this correctness fix ships in a patch per project convention.
- **NIST tags now resolve at the selected revision (default Rev 5)** (#190, #203): the nessus, nikto, scoutsuite, owasp, hipcheck, and CCI lookup tables (all natively Rev 4) pipe results through the crosswalk to the globally selected revision, so emitted NIST tags can differ from v3.5.0 (e.g. nessus `AU-8(1)` → `SC-45(1)`). Select Rev 4 explicitly to reproduce prior output.
- **`xccdf-results-to-hdf` zeroes impact for `notselected`/`notapplicable`/`informational` rule-results** (#211), changing computed compliance scores; `neuvector-to-hdf` moved scan-command metadata to `baseline.extensions`.
- **`sarif-to-hdf` emits structured `statusOverrides`** from accepted (or status-less) suppressions with `appliedAt` = conversion time and a one-year expiry, so repeated conversions of the same file differ in those timestamps. cyclonedx (VEX analysis), msft-defender-endpoint (triage), and defectdojo (false-positive dismissals) gained the same structured-override import. (#204)
- **`hdf-diff` normalizes zone-less timestamps as UTC** (#205) — diff output for zone-less InSpec timestamps no longer varies with the host timezone — and serialized `matchConfidence` is rounded to 4 decimals (#212).

### Internal

- Shared CVSS version detection gained a caller-supplied default; the nessus converters delegate to it (byte-identical output). Timestamp lint guards extended to hdf-diff, hdf-cli, and hdf-utilities. (#205)
- Suppression review: `postcss` audit-override floor raised to 8.5.23 (GHSA-fxqj-rqcc-2cmp); the aged-out `nanoid@3.3.17` cooldown exemption removed. The remaining vite advisories are dev-only and blocked on the vitepress 2.x migration (tracked).
- Source-hygiene: literal NUL bytes in two TypeScript converters replaced with `\u0000` escapes so git treats the files as text again.
- Dependency bumps: Go dependency groups (#200, #207), dev-dependency group (#199), pnpm/action-setup (#206).

### Compatibility

- **No schema changes**; schema `$id` URLs remain at v3.5.0 and v3.5.0 documents validate unchanged. No breaking schema or API removals. Consumers of converter *output* should review the Notable behavior changes above — the export-side effective-status fix (#209) and the Rev 5 default for NIST tags (#190) are the two most visible.

## [3.5.0] - 2026-08-02

Schema minor: `$id` URLs move from v3.4.0 to v3.5.0 across all seven assessment schemas, and a new eighth document type — the continuous-monitoring change-event stream — joins the family.

### Added

- **Requirement change-event stream — `hdf events derive|fold|apply` (ADR-0005).** A new `hdf-requirement-change-event` document type and a stateless, deterministic kernel in `hdf-diff` (`changeEventFromPrevious`, `foldChangeEventsIntoComparison`, `applyChangeEvents`, Go + TS) for continuous monitoring. `derive` emits an NDJSON stream of per-requirement events (`new`/`absent`/`updated`/`fixed`/`regressed`) between two same-target scans; `fold` materializes a batch into a `systemDrift` comparison; `apply` replays events onto a seed to reassemble a reconciled results document (parity law: `applyChangeEvents(A, derive(A→B)) ≡ B` at requirement level). Events are keyed by `(systemRef, componentId, requirementId)` with a per-key integer `sequence` as the sole ordering authority, `eventId` as a UUIDv5 dedup identity, and a `priorChecksum` chain. Batch subcommands accept multiple event files and stdin.
- **`effectiveChecksum` on `Evaluated_Requirement`.** A sha256 over the resolved effective posture (`{status, impact, disposition}`) — a change-detection fingerprint that flips only when the operative posture changes and is stable under all other document churn. Stamped by tooling; the anchor for change-event derivation.
- **STIX 2.1 CTI enrichment — `hdf enrich` (ADR-0006).** A new enrichment pass overlays a STIX 2.1 bundle onto an existing HDF results document: a CVE-bearing STIX object attaches to the finding whose requirement ID is that CVE (`rel: investigate`), everything else attaches to the results root (`rel: reference`) — each as an `External_Reference` enrichment envelope carrying the raw STIX object losslessly in `document`. Informational by default: it authors no overrides and changes no status or impact. Source format is auto-detected (`--from stix` to assert). Dual Go + TS.
- **`External_Reference` primitive + broad `externalReferences[]` wiring.** A generalized, purpose-agnostic reference (modeled on the STIX 2.1 `external_references` common property): required `sourceName` plus at least one of `externalId`/`href`/`description`, open `rel` and `kind` tokens, optional `mediaType`/`checksum`/`addedBy`/`addedAt`, and an optional lossless embedded `document`. Wired onto the results root, the inline `Status_Override`, and across the HDF schemas.
- **CVSS scoring engine in `hdf-utilities` (Go + TS).** Base + Threat score computation for CVSS **3.1** (`computeCvssScore`) and CVSS **4.0** (`computeCvss40Score` — the FIRST MacroVector algorithm with max-vector severity-distance interpolation, validated exact against FIRST reference vectors across 0.0–10.0). No third-party dependency; Go and TS produce byte-identical scores.
- **Opt-in CVSS Threat recompute — `hdf enrich --recompute-cvss`.** When a matched STIX object shows active exploitation and the finding carries a CVSS 3.1 base vector, applies Exploit Maturity `E:H`, recomputes the Threat score, and authors an auditable inline `riskAdjustment` (with the `cvss` block, `impact.value = computedScore/10`, a review-horizon `expiresAt`, and an `externalReferences[]` back to the STIX source). Findings with no base vector — or a CVSS 4.0 base vector — are left unchanged.
- **`roundImpact` / `RoundImpact` in `hdf-utilities` (Go + TS).** Canonical rounding of a computed impact to its natural 0.01 grid, eliminating binary-float representation noise. Consumed by the enrich recompute.
- **`Change_Reason` gains `dispositionChanged` and `effectiveImpactChanged`.** The diff engine's amendment-axis change reasons are now part of the comparison vocabulary (previously the engine emitted values the schema's enum rejected).
- **`hdf --version` flag** alongside the existing `hdf version` command. (#195)
- **Extended `create*` schema test helpers.** `createRequirement` title is now optional and the helpers model amendment and vulnerability fields (`code`, `effectiveStatus`/`effectiveImpact`/`disposition`/`statusOverrides`/`poams`, `cwe`/`cvss`/`refs`/`affectedPackages`/`epss`/`kev`), removing hand-spread boilerplate from tests. (#196)
- **Two new `convert --from` sources surfaced:** `oscal-profile` → HDF Baseline (requires `--catalog`) and `oscal-assessment-plan` → HDF Plan.

### Breaking Changes

- **POA&M `expiresAt` is now required.** A POA&M is a time-boxed acceptance of an open finding; with `expiresAt` optional a failing requirement could duck remediation indefinitely. The field is now required on the POA&M `$defs` (`Evaluated_Requirement.poams[]` and the amendments POA&M object). **HDF documents carrying a deadline-less POA&M now fail schema validation** — add a real remediation/vendor-fix deadline (never a wall-clock default). All other override types are unaffected. (#195)

### Notable behavior changes

- **`tool.format` now names formats, never serialization structures.** The field carries a named format specification — an interchange format emitted by many tools (`SARIF`, `XCCDF`, `ARF`, `OSCAL`) or one of several named outputs a single tool produces (`FVDL`, `exec-json`, `FPF`) — and is omitted for a tool's native output. Twenty-three converters that stamped bare `JSON`/`XML`/`CSV` serialization labels no longer emit `tool.format`, `deptrack-to-hdf` now emits `FPF` instead of `JSON`, and `checkov-to-hdf` moves scan scope out of `tool.format` into a per-requirement `tags.check_type` array (e.g. `["terraform"]`). Consumers pinning exact output will see the key disappear or change; tool name and version are unchanged. Go/TS in lockstep, goldens regenerated. (#192)
- **`ionchannel-to-hdf`: non-dependency scan summaries are now converted.** Previously only the dependency scan summary was emitted; each `scan_summaries[]` entry now yields its own baseline, and the analysis verdict (risk/passed/ruleset) is surfaced on the primary baseline. Consumers see additional baselines. (#197)
- **`zap-to-hdf`: every site is converted, not just the busiest.** A multi-site ZAP report now emits one baseline + Application component per site (linked via `labels.component`); findings on previously-dropped hosts now appear. (#197)
- **`checkov-to-hdf`: `requirement.code` is populated** from the source `code_block` (previously parsed then dropped), so Heimdall's CODE tab renders. (#197)
- **`legacyhdf-to-hdf`: converted documents now carry a top-level `timestamp`, a `generator`, and InSpec tool identity** (`{name: "InSpec", ...}` when the source is detected as exec-json, instead of an unconditional "Heimdall Data Format v1" label). The missing timestamp previously blocked deterministic change-event derivation on freshly-converted scans. (#189)
- **`hdf-to-oscal-sar` emits schema-valid OSCAL 1.1.2 Assessment Results.** A v3.4.0 regression produced documents that failed the NIST AR schema (missing `reviewed-controls`, finding `description`, risk-characterization `origin`; an empty-string prop value). Output now validates against the vendored NIST schema. (#194, #191)
- **`hdf convert --to hdf@2`: the downgraded InSpec profile `sha256` fingerprint is restored**, sourced from the baseline integrity hash so Heimdall matches the fingerprint (previously emitted empty → "No fingerprint match"). (#188)

### Architecture Changes

- **Schema version bumped from v3.4.0 to v3.5.0** across all `$id`/`$ref` URLs; the site archive gains a v3.5.0 snapshot per document type.
- **Unified worst-wins roll-up and effective-status computation** into one canonical implementation in `hdf-utilities` (Go + TS), with all previously-divergent copies (hdf-diff, hdfversion, exportmap, legacyhdf, the CLI status derivation, and the hdf-schema helper roll-up) delegating to it. Reconciles to the published precedence (`error > failed > passed > notApplicable > notReviewed`), governing-override selection (most-recent-by-`appliedAt`), and uniform `impact==0` handling — fixing hdfversion's downgrade path. No golden output changed. (#193)
- **Converter output is validated against its target schema in tests** where a published schema exists (OSCAL SAR/POA&M, CSAF-VEX, CycloneDX-VEX, OpenVEX), with vendored schemas + provenance — so schema-invalid output can no longer ship behind a golden that merely encodes it. (#191)

### Internal

- Pre-release swarm review remediation: routed the remaining `classifyChangeReasons` timestamp parsing (Go + TS) and `hdf-diff/amend` expiry parsing through the shared `parseTimestamp` helpers; hardened `hdf enrich` to use the security-gated input pipeline (size/symlink/BOM), schema-validate its results input, and honor `--max-size`; fixed a multi-CVE STIX vulnerability dropping all but the last CVE (Go + TS); made the events-kernel timestamp emission host-independent (TS parity with Go); hardened STIX bundle parsing against non-object elements; added `--start-sequence` boundary validation; guarded a zero-expiry override in the v2 `waiver_data` breadcrumb. Deferred findings filed as beads (enrich fan-out cap, `RoundImpact` migration, guard-scope extension, and others). ADR-0005 and ADR-0006 marked Accepted.

### Compatibility

- **v3.4.x documents validate cleanly under v3.5.0 with one exception:** a document carrying a deadline-less POA&M is now rejected (add `expiresAt`). All other additions are additive and optional (`External_Reference`, `externalReferences[]`, `effectiveChecksum`, the two new `Change_Reason` values, the change-event document type). Converter-output consumers that pin exact bytes should review the Notable behavior changes above.

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
