# ADR-0022: Pushing an HDF evidence package to a GRC system of record, starting with eMASS

- **Status:** Proposed
- **Date:** 2026-11-13

## Context

### Why this matters

eMASS is the GRC system of record for a large share of DoD and DoD-adjacent authorizations. An assessment that exists only as an HDF evidence package has not reached the system the authorizing official reads. Today the gap is closed by hand: an operator reads HDF, then retypes or re-uploads the same findings into eMASS. That is the step this ADR removes — and eMASS is the first such system, not the only one we expect to target.

### What the API actually is

eMASS does not publish its API as a product surface, but MITRE's [`mitre/emass_client`](https://github.com/mitre/emass_client) vendors the specification in full — a single `eMASSRestOpenApi.yaml`, OpenAPI 3.0.3, currently v3.22 — and generates three clients from it with OpenAPI Generator CLI: Ruby (which backs `mitre/emasser`), TypeScript (which backs SAF CLI), and Python. **There is no Go client.**

Facts that shape the design, from that spec and from `emasser`'s documentation:

- **Authentication is two-factor and partly out-of-band.** Every call carries an `api-key` header and a PKI client certificate (mTLS). Write operations additionally carry `user-uid`, the caller's identity-provider subject. `403` means an untrusted certificate, `401` a bad key or a key/certificate mismatch.
- **Reads are unprivileged; writes are not.** `GET` works with the API key alone. `PUT`/`POST`/`DELETE` require a registration and approval process per client application.
- **Write semantics differ per entity.** Test results are a batch `POST` whose response reports a per-object outcome. POA&M items have `POST` to create and `PUT` to update. Artifacts upsert, **matched by filename** — an unmatched filename creates a new artifact.
- **Entities interact.** A POA&M item whose status is `Not Applicable` is updated as a side effect of test-result creation, and a test result for a control with no POA&M or assessment procedure comes back non-compliant.
- **There is no modification timestamp.** Grepping the spec (10,103 lines) finds no `lastUpdate`, `lastModified`, `updatedDate` or `modifiedDate` on any schema. What exists is `createdDate` — `[Read-Only]`, int64 Unix — on POA&M items (*"when the POA&M Item was entered into the database"*) and on milestones. `PoamReadOnlyFields` carries no timestamp at all, and `sinceDate` is a query parameter on CMMC assessments only. So eMASS reports when a record was created, never when it last changed.
- **Batch support is uneven, and `emasser` is a reference rather than a ceiling.** Several eMASS endpoints accept multiple entries while `emasser` writes one at a time in some cases. We treat `emasser` as the best available guide to real-world behaviour, not as the performance bar: where eMASS accepts a batch, we send one.

### What HDF already models

No schema change is needed for identity. `hdf-system.identifier` is documented as *"System identifier from an authoritative source. Example: eMASS system ID"*, `hdf-system.identifierScheme` carries `https://emass.mil`, and `component.externalIds` lists `emass` as a well-known scheme. `hdf label set --external-id emass=<id>` already writes it.

The evidence package is the right unit: `contents[]` references the HDF documents and `externalEvidence[]` the native-format artifacts, with `integrity` and `completenessCheck` over the whole bundle.

ADR-0020 (accepted for implementation, in flight) defines a package layout and CLI contract for delivering SIEM exports *inside* evidence packages. That is the complementary direction — it shapes what goes into a package, this shapes how one reaches a remote system of record — so a push must read packages built to its layout, and the `hdf push` surface must stay consistent with the contract it establishes.

### What this repo does not have

- **No outbound write of any kind.** `hdf-converters/fetchers/` is inbound only; the two `POST` call sites in it are GraphQL and search reads. There is no pusher concept.
- **No client-certificate support.** `fetchers/shared/go`'s `TLSOptions` handles a CA certificate and an insecure override. eMASS needs mTLS, which it cannot currently express.

### Constraints

- Verification is **mock first**; a registered **test** instance, not production, carries the real verification.
- The fixture-integrity rule forbids fabricating API responses, so the published spec is the only thing that can vouch for a recorded request or response shape.

## Decision

### 1. The command is `hdf push <target>`, and the target is pluggable

`hdf push emass <evidence-package>` today; `hdf push <other-grc>` later. Subject–verb–object, and the verb generalizes.

Everything that is not eMASS-specific is built once in a target-agnostic layer: mTLS and HTTP transport, credential and address resolution from the environment, the reconcile-and-diff engine, the confirmation and partial-failure policy, the receipt format, and the exit-code vocabulary. Each target contributes only its own crosswalk, its natural keys, and its API calls, in files of its own.

**Non-goal: hdf-cli is not a general-purpose eMASS client.** Other eMASS interactions belong in their own commands where they already fit the CLI's shape — the way `hdf system create` is its own command — not under `push`. `push` sends an evidence package and nothing else.

### 2. Reconcile, do not blast: `GET`-diff-write

A push reads the target's current state, computes the difference against the evidence package, and then issues creates and updates per entity. It does not `POST` the package contents blindly.

This is possible **because reads are unprivileged** — the diff costs only an API key, so dry-run works for a caller with no write approval at all. It makes re-pushing safe without relying on duplicate-handling semantics that no source documents, and it makes the diff output real rather than a restatement of the input.

### 3. On conflict, the remote wins — detected in layers, none of them required

An evidence package is a snapshot. Between generating it and pushing it, another person or process may have updated the same records in eMASS. Those later changes win: a push must never silently overwrite a newer remote edit with an older local snapshot.

Detection is **layered, best-effort, and never a precondition for pushing.** Each layer is available independently, and the push degrades permissively rather than refusing:

1. **Content equality** — always available. If the remote record already carries what the package would write, nothing is written and it is reported as unchanged. This is what makes a clean re-push a no-op.
2. **`createdDate` against the package's `preparedAt`** — always available, no receipt needed. A POA&M item or milestone created *after* the package was prepared cannot be one the package knows about, so it was created by someone else. The remote wins: skip it and name it.
3. **The previous receipt**, when the caller kept one — the only layer that catches an *in-place edit* of a record that already existed when the package was prepared, since eMASS exposes no modification timestamp to detect that any other way.

**The receipt is therefore an enhancement, not a dependency.** A first push has none and works fine. A pipeline that discards it loses layer 3 only. Where no layer can tell whether a difference is our newer data or someone else's edit, the default is to **write** — the operator asked for the push, and refusing every ambiguous record would make the command useless on its first run against a populated system.

`--on-conflict` selects the policy for records a layer did flag: `skip` (default, remote wins), `overwrite`, or `fail`. A pipeline that would rather stop than overwrite sets `fail`; nothing forces that choice on everyone.

### 4. Idempotency by natural key, per entity

| HDF | eMASS | Natural key | Create / update |
|---|---|---|---|
| `hdf-system.identifier` (+ scheme `https://emass.mil`) | the system | `systemId` | neither — the system must already exist |
| hdf-results results | `/systems/{id}/test-results` | control acronym + assessment procedure | batch `POST`, per-object outcome |
| hdf-amendments POA&Ms | `/systems/{id}/poam` | correlation id (see Open Questions) | `POST` create, `PUT` update |
| POA&M milestones | `/poam/{poamId}/milestones` | parent POA&M + description | `POST` / `PUT` |
| `externalEvidence[]`, `contents[]` | `/systems/{id}/artifacts` | filename | upsert by filename |
| `completenessCheck`, `signature`, `integrity` | — | — | no equivalent; recorded in the receipt only |

A push never creates an eMASS system. If `identifier` resolves to no system, the push fails and names the identifier.

### 5. The Go client is a fourth language in `mitre/emass_client`, not a vendored copy here

The eMASS API client belongs with the specification it is generated from, alongside the Ruby, TypeScript and Python clients, published as a Go module and imported by hdf-cli like any other dependency.

This is better than vendoring the spec into hdf-libs on every count that matters: one client rather than a second divergent one, generated by the same pipeline from the same spec on the same trigger; no drift obligation and no vendored third-party spec in this repo; and it avoids changing `oapi-codegen`'s declared role here, which `mise.toml` pins as a measurement subject for `hdf-openapi`'s compatibility matrix rather than a build tool. The client is also then available to anyone else who needs eMASS from Go.

**Module path and versioning.** `github.com/mitre/emass_client/src/go_client/v3`, released as tags `src/go_client/v3.22.0`. The version tracks the spec, matching the three siblings — the Ruby config already pins `gemVersion: 3.22.0` — and Go's major-version path suffix is the price of that symmetry. The path is fixed from the first commit because it appears in every consumer's import line.

**Adding Go mimics the existing pipeline rather than reworking it.** `generate-clients.yml` runs one `openapitools-generator-action` step per language against `docs/eMASSRestOpenApi.yaml`, with a small `src/openapi/templates/<lang>/<lang>-generator-config.json`, then commits the generated tree to `src/<lang>_client`. Go needs the same three additions and no more. It needs no publish workflow at all, unlike the gem, npm and PyPI targets: a Go release is a tag.

**Development proceeds on a branch, released at epic close.** That workflow only triggers on a push to `main` with a changed spec, so the Go client is generated and committed on a branch. hdf-libs imports it from there by pseudo-version (`go get <module>@<branch>`), which is reproducible and belongs in `go.mod` — not a `replace` directive, which can only point at a local path and would break CI and other clones. When the epic's build-out is done the client is tagged, hdf-libs bumps the one `require` line from pseudo-version to tag, and the epic closes. The branch must not be force-pushed once hdf-libs pins a commit from it.

The cost is a cross-repo dependency and an ordering constraint: the Go client must exist before this repo's push command can be finished. That cost is acceptable because we can land and release changes in `emass_client` directly rather than waiting on an external reviewer.

### 6. Confirm by default, `-y` to proceed, `--no-partial` for all-or-nothing

Modelled on `dnf`/`apt`: `hdf push emass <pkg>` computes and prints the diff, then asks for confirmation. `-y` / `--yes` skips the prompt, so a pipeline is still one line. A non-TTY invocation without `-y` refuses rather than hanging or assuming consent.

- Exit codes follow the CLI's existing vocabulary: `0` success, `1` failure, `2` usage, `3` partial, `4` nothing to do. A partial push — some entities written, some failed — is `3`, because eMASS reports per-object outcomes and the caller must be able to tell that apart from total failure.
- **`--no-partial` refuses to write anything unless everything would succeed.** Every check the reconciler can make without writing runs first — identity resolution, required-field validation against the spec, conflict detection, artifact-name collisions — and any failure aborts with `1` before the first write.

  Stated precisely, because the honest limit matters: eMASS offers no transaction, so this cannot promise atomicity against a mid-push server rejection. It eliminates the failures we can predict, and on an unpredicted one it stops at the first failure rather than continuing. The receipt is the recovery record for that case.

### 7. Credentials *and the instance address* come from the environment, never from flags

The API key, `user-uid`, the client certificate and key paths, **and the target's base URL** are read from the environment, following the fetchers' convention and `emasser`'s own variables. Nothing sensitive is accepted as a CLI flag, where it would land in `ps`, shell history and CI logs — and the address is included because pointing a write at the wrong instance is its own incident. The library takes a configured transport and never reads the environment itself.

### 8. Every push emits a receipt

Per ADR-0013's rule that every mutation produces exactly one audit row, a push writes a receipt recording: the package `name` and `integrity` hash, the target and `systemId`, and per entity what was created, updated, skipped-as-unchanged, skipped-as-conflicted or failed — with the id assigned and the HDF source each came from, plus the resulting remote state used by Decision 3.

It is written on failure as well as success, because a partial push's receipt is the only recovery record. It serves three purposes: the audit trail, CI's machine-readable output, and — when the caller keeps it — layer 3 of conflict detection. Nothing about the push requires that it be kept.

### 9. Verification: spec-driven mock, then a campaign against a test instance

A mock served from the spec verifies request shape, headers, pagination, batch handling, reconciliation and idempotency. This proves **conformance to the published contract, not to a live instance**, and that limit is recorded rather than papered over.

Real verification runs against a registered eMASS **test** tier — never production — and is a campaign, not a single happy-path push. It must cover at least: a first push with no prior receipt; a clean re-push that writes nothing; a remote record edited between generation and push, asserting the remote wins; a partial failure and its receipt; `--no-partial` refusing a package with one bad entity; artifact upsert by filename; and a batch write large enough to exercise eMASS's multi-entry support.

## Reviewer challenge points

- **Is reconcile-then-write worth a read pass?** The alternative depends on duplicate-handling semantics nobody documents, in a system of record. I judge the read cheap and the dependency unacceptable, but this is the decision most worth arguing.
- **Permissive-by-default on ambiguity is a real choice.** Where no detection layer can distinguish our newer data from someone else's edit, the push writes. The alternative — refuse and make the operator resolve it — is safer and more annoying, and would make a first push against a populated system nearly unusable. `--on-conflict=fail` exists for callers who disagree.
- **Does a generic `push` layer earn its abstraction with one target?** Generalizing before the second target exists risks designing for an imagined eMASS-shaped sibling. The counter is that the alternative — writing eMASS specifics through the whole path and refactoring later — is how the fetchers accumulated near-duplicates.
- **Does the Go client belong in `emass_client`?** It splits this feature across two repos and two release cadences. The counter is that the client is not ours conceptually; it is the spec's.

## Alternatives Considered

### A: Vendor the spec and generate the client inside hdf-libs

Pin `eMASSRestOpenApi.yaml` here with its checksum and generate a Go client with `oapi-codegen`. **Rejected in favour of Decision 5:** it produces a second client diverging from MITRE's three, obliges this repo to track an upstream spec, and converts `oapi-codegen` from a measurement subject into a build tool, coupling `hdf-openapi`'s matrix pin to generated output. Remains the fallback if a Go module cannot be published from `emass_client`.

### B: Hand-write a minimal Go client

Six or so endpoints, following the fetcher conventions. **Rejected:** cheap to start and invisible to drift, which is the problem — the spec moves, and path renames have already happened between versions.

### C: Depend on MITRE's `emasser` (Ruby) or SAF CLI (TypeScript)

Shell out to a maintained client. **Rejected:** it puts a Ruby or Node runtime behind a statically distributed Go binary, with its own versioning, authentication and exit-code conventions.

### D: Extend SAF CLI's `emasser` instead of hdf-cli

**Rejected on unit-of-work grounds:** `emasser` is endpoint-shaped, one entity per invocation, and this feature's value is pushing a *package* coherently — one reconciliation, one receipt, one integrity binding. Building that there would mean reimplementing the evidence-package reader, the crosswalk and the reconciler in TypeScript, away from the schema they belong to.

### E: Take the community `pretorin-ai/emass-mock` as the contract source

**Rejected as the contract source** — conformance must be measured against MITRE's spec, not a third party's reading of it. Useful as a second opinion during implementation.

### F: Export an eMASS-shaped bundle for manual upload

**Rejected:** it does not close the gap, and eMASS's import surfaces are narrower than its API.

### G: Do nothing

Operators keep retyping findings. **Rejected**, but with a real argument behind it: this is the first outbound write in the repo, it targets a system of record, and getting it wrong writes bad data into an authorization package. That argues for the care above, not for declining.

## Consequences

**Easier:** an assessment reaches the system of record without transcription; re-running a scan and re-pushing becomes routine rather than risky; the receipt makes "what did we tell eMASS, from which package, and did someone else change it since" answerable. A second GRC target is an adapter, not a project.

**Harder:** the repo owns an outbound write path and mTLS credential handling it has never needed. CI cannot fully verify the feature, so a class of bug is only reachable on a test instance. And because eMASS exposes no modification timestamp, an in-place edit of a pre-existing record is undetectable unless the caller kept the previous receipt — a gap in the API, not in the design, and one no client can close.

**New obligations:** `fetchers/shared` is renamed to something direction-neutral and gains client-certificate support, touching every existing fetcher. A Go client must be landed in `emass_client` before Phase 5 can finish. A failed partial push leaves eMASS in a mixed state, so the receipt must be written even on failure.

**Reversible?** The command and the push layer are additive and removable. The `fetchers/shared` rename is not. The schema is untouched, so HDF itself is not committed to this direction.

## Implementation Plan

Quality standards inherited by every card: TDD; credentials and addresses never in flags or logs; URL validation on every request; limited response reads; `ctx.Err()` in every pagination loop; no fabricated fixtures; no linter disables; and no eMASS specifics in the target-agnostic layer.

**Phase 1 — shared transport foundations.**
Rename `fetchers/shared/go` to a direction-neutral package, add client-certificate support to `TLSOptions`, and migrate the existing fetchers in the same change.

**Phase 2 — the crosswalk, as a reviewable document.**
Decision 4's table expanded to field level, published under `site/docs/` as a reference page, recording every HDF field with no eMASS home. It gates the *adapter* in Phase 5, not the client in Phase 3 — a client generated from the whole spec is constrained only by the spec.

**Phase 3 — the Go client in `mitre/emass_client`** *(external repo; blocks Phase 5)*.
Add Go to that repo's generation pipeline and publish it as a Go module covering the whole spec, as its three siblings do. **Start here.** It is the only cross-repo item, so its lead time is the longest; it carries the most unknowns (module layout, generator configuration, that repo's CI); and it is the one card that can invalidate Decision 5 and force the fallback to Alternative A. Learning that before anything is built against an assumed import path is worth more than any other ordering.

**Phase 4 — the target-agnostic push layer.**
Reconcile-and-diff engine, receipt format, conflict detection, confirmation and partial-failure policy, environment-based credential and address resolution, exit codes. Pure and unit-testable against the spec-driven mock; no eMASS specifics.

**Phase 5 — the eMASS target and `hdf push emass`.**
The adapter: crosswalk implementation, natural keys, API calls. Then the command, with `-y` and `--no-partial`.

**Phase 6 — test-instance campaign** *(blocked on access)*.
The edge cases enumerated in Decision 9, against a registered test tier, with receipts pasted into the card. Gates the release.

### Out of scope, to be carded separately

- **`hdf system create` from an eMASS record.** Because a push requires the eMASS system to exist first, there is a natural companion: build an HDF system document *from* an eMASS system read over the API. Useful, and outside this epic.
- Any eMASS interaction other than pushing an evidence package.

## Open Questions

1. **How do HDF amendments correlate to existing eMASS POA&M items across pushes?** Artifacts key on filename and test results on control plus assessment procedure, but a POA&M has no obvious natural key. The receipt covers the second and later pushes; the *first* push against pre-existing POA&Ms still needs an answer. If it requires a durable id on the HDF side, that is a schema addition and must go through the field-gap audit rather than being invented here.
2. **Does any eMASS entity carry a modification timestamp outside the published spec?** The spec has none, and Decision 3 is designed around that. Worth one check against a live test instance in Phase 6, in case an instance returns more than the spec documents.
3. **Does a repeated `POST` to `/test-results` duplicate, reject or overwrite?** Undocumented. Reconciliation is designed so the answer does not matter, but establish it before the live campaign.
4. **The exact artifact upload encoding** (multipart versus zip) is not in any source consulted; read it from the spec in Phase 3.
5. **Is `user-uid` required on all writes, or only when acting on behalf of a user?** Sources conflict.
6. **Where should a receipt be kept between runs** to enable detection layer 3? CI artifact storage, a path in the repo, or written back to eMASS as an artifact itself. Optional, since the push works without it.
7. **Does the Go generator need template overrides?** Ruby, TypeScript and Python each pass a `template-dir`; Go may work from generator defaults with only a config file. Establish in Phase 3 — it decides whether `src/openapi/templates/go/` holds mustache overrides or just the config.

## References

- [`mitre/emass_client`](https://github.com/mitre/emass_client) — the spec and its generated clients
- [eMASS API reference (redoc)](https://mitre.github.io/emass_client/docs/redoc/) and [eMASS API documentation PDF](https://mitre.github.io/emass_client/docs/eMASS_API_Documentation.pdf)
- [`mitre/emasser` features](https://github.com/mitre/emasser/blob/main/docs/features.md) — endpoint set and per-entity write behaviour
- [SAF CLI eMASSer](https://saf-cli.mitre.org/docs/emasser/) — prior art and its batch limitations
- ADR-0013 — guarded outbound fetch, and the one-audit-row-per-mutation rule this inherits
- ADR-0020 — evidence packages as the delivery container for SIEM exports; defines the package layout and CLI contract a push consumes
- `/build-fetcher` skill — the constructor, credential and guard conventions the push layer mirrors
