# ADR-0012: The HDF Data Platform — How ADR-0008 to ADR-0011 and ADR-0013 Fit Together

**Status:** Proposed
**Date:** 2026-09-02 (revision 4 — round-7 review fold; revision 3 same day added ADR-0013, the round-6 spike outcomes, and the follow-on list; revision 2 same day followed one round of six-lens independent design review; revision 1 same day)
**Deciders:** Aaron Lippold (author); Will Dower (maintainer review — see "Reviewer challenge points")

> **How to review (~15 min, then the five ADRs):** this document is the map. It records the shape of the whole, the invariants every part obeys, who owns which decision, the language split, the cross-ADR dependency order, what was proven by running code, and what is deliberately left for later. It makes no decision the five ADRs do not make; where it seems to, the five win and this document is wrong. Read it first, then ADR-0008 → ADR-0009 → ADR-0010 → ADR-0011 → ADR-0013 in that order, replying to each per its challenge letters. Total review budget for the set: about 3 hours.

## Context

Until now HDF has been a **format**: eight JSON Schema 2020-12 document types, converters in and out of forty-odd tools, validators, an engine for querying and rolling up a document, a diff engine, a CLI, and a Go MCP server that lets an agent work on *one document at a time* from a directory. Everything is file-shaped. Five needs now exist that files cannot serve:

1. **Cross-document questions** — a new scan's findings were adjudicated last quarter; a similar system already answered this control; which package is this evidence part of. These are joins over stored data.
2. **A hosted surface** — pipelines, viewers, and partner tools want HTTP with a contract they can generate against, not a CLI they shell out to.
3. **Identity** — organizations, teams, users, OAuth clients and API keys for pipelines, and an authorization server that MCP clients can complete an OAuth flow against.
4. **Agents with history** — the MCP server should draft an amendment knowing what was adjudicated before, not just what is in front of it.
5. **Operational evidence** — a store of compliance evidence must evidence its own handling: who did what, jobs that outlive a request, organizations that can be exported and removed, events downstreams can subscribe to, and a tested way back from backup.

Five ADRs answer those needs. They were drafted together and reviewed as a set: three rounds of six-lens review on ADR-0008/0009, one round on the first five documents, a light pass on the fold, and a sixth round of **executable spikes** (four throwaway prototypes that ran the contract pipeline, the PGlite/pgvector/Drizzle stack, the better-auth-to-Go token path, and the Go testcontainers/RLS path), a community-and-standards grounding pass, and a gap analysis that produced ADR-0013. The ecosystem framing throughout is the open-source one: the HDF CLI and `hdf-serve`, the MCP server, and the Heimdall/SAF/partner tooling that consumes HDF.

## Decision

### 1. The shape

```
                         JSON Schema 2020-12 (hdf-schema) — the only hand-authored source
                                              │
                ┌─────────────────────────────┼───────────────────────────────┐
                ▼                             ▼                               ▼
   hdf-openapi (ADR-0008)          hdf-db-schema (ADR-0009)          hdf-validators / hdf-engine /
   components + API document       3NF rows + pgvector, migrations   hdf-diff / hdf-converters
   generated from the schemas      round-trip, deletion, tenancy     (existing dual-language libraries,
   and the MCP contract golden     seam, RLS, embeddings, audit +     plus four TS ports)
                │                  outbox + blobs tables (0013)                │
                │                             ▼                               │
                │                  hdf-data (ADR-0010)  ◄──────────────────────┘
                │                  Principal · DocumentStore · engine bridge
                │                  AdjudicationQuery rows · EmbeddingProvider
                │                  AuditSink · backends: file (Go) | db (TS + Go) | http (Go)
                │                    │                │                │
                ▼                    ▼                ▼                ▼
   generated Zod + client     hdf-serve (ADR-0011)   hdf mcp (Go)     hdf db (Go CLI)
   hdf-client (two            Hono · better-auth     stdio, or HTTP   import/export/delete/
   namespaces)                implements the         with the shared  reproject/precedent/
                              ADR-0008 document +    verifier; db or  embed/audit/jobs
                              hosts ADR-0013's       http backend
                              services (audit, jobs,
                              lifecycle, webhooks,
                              blobs, quotas, metrics)
                                    │                      │
                                    └────── one identity ──┘
                          (JWT, one issuer, one verifier description; per-resource audience;
                           tenant context set per transaction; RLS with an explicit flag)

   Engine: PostgreSQL 18 + pgvector — PGlite in-process for TS dev/test and embedded use,
           PostgreSQL (pgvector image) for deployments and Go tests. One store, one migration set,
           plus pg-boss's own schema on the same handle.
```

Data flows one way: schema → generated artefacts and tables → data layer → surfaces. Identity flows the other way: token → `Principal` → data layer → transaction-local tenant context → RLS. Nothing above the data layer touches a table; nothing below it knows what a token is. Every mutation, on every surface, leaves an audit row in its own transaction.

### 2. Invariants every ADR obeys

1. **One hand-authored source.** JSON Schema 2020-12 is the only authored contract. OpenAPI components, the API document, Zod, the client, Go row structs, the Go HTTP client, and the RLS migration are generated; hand-authored inputs are closed-grammar mappings (the binding table, the alias input, the legacy-key list, the role→scope table, the verifier description, the audit action vocabulary), each with a mechanical test that it is a mapping and not a shadow contract.
2. **Generation direction never reverses.** Schema + MCP golden → API document → Zod/client → service, whose emitted document must match the API document under the defined projection (ADR-0008 §7, ADR-0011 §2; measured to hold). Zod is never derived from the document schemas (it cannot be — measured) and never hand-written for them. Better-auth's own endpoints are described by better-auth's generator in a companion document, never merged.
3. **One store.** Relational rows, vectors, audit, outbox, blobs, and the job queue share one PostgreSQL-flavoured engine with `pgvector` as the only extension; the same migrations run on PGlite and PostgreSQL (ADR-0009 §1, §11; ADR-0013 §2). No second database of any kind.
4. **Documents are immutable after import; rows track the current schema; bytes are the verification truth; deletion is whole-document, cascades along owner FKs only, and respects holds** (ADR-0009 §5, §6, §12; ADR-0013 §3). Derived tables (attribution, links, tag values, embeddings) are rebuild-only; a schema bump re-projects from retained bytes.
5. **Identity is explicit.** A `Principal` is an argument to every data-layer call (ADR-0010 §2); tenancy is set per transaction from it with an explicit context flag (ADR-0009 §8); a `NULL` organization is unowned, never global, and is constructible only by local callers (ADR-0011 §3); there is no cross-tenant read for any scope; unknown or foreign ids are a uniform 404 (ADR-0008 §3); background jobs run under a principal snapshot (ADR-0013 §2).
6. **The MCP surface is a tracked golden.** Nine tools today; every addition (`hdf_precedent`, `hdf_similar`, `--transport http`) is an ADR-0007 amendment carded before the HTTP operations that derive from it exist (ADR-0010 §5, ADR-0011 §6–§7).
7. **Dual-language where Go consumes; TypeScript-only where only the service consumes.** Schema, validators, engine, diff, converters, db-schema, and data layer are TS + Go with shared-fixture parity; `hdf-serve` and `hdf-client` are TS; the MCP and CLI are Go, reaching a hosted store through the generated Go client. The line is drawn by consumers, not preference (§4).
8. **Real fixtures only**; the corpus is promoted under the fixture policy (ADR-0009 Phase 0) and every derived fixture ships with its script. No content in errors, logs, audit details, job payloads, or metrics labels — one canary test reused at every layer.
9. **Nothing in this design names a commercial downstream consumer.** The consumers are the CLI, the MCP server, `hdf-serve`, and the Heimdall/SAF/partner ecosystem.
10. **Every ADR carries reviewer challenge letters**, every implementation phase carries files, acceptance criteria, a verification command, and an agent-pace size, and **every load-bearing library claim was run before it was written** (§6) so cards are cut mechanically after review.

### 3. Decision ownership (who owns what — so no two ADRs decide the same thing)

| Concern | Owner | Others reference it |
|---|---|---|
| OpenAPI components and the API document; the synthetic operations (ingest, delete, two `documentOnly` token operations; the reserved jobs pair and ADR-0013's audit/evidence/hold entries); wire identity (opaque uuid + `ETag`); scope vocabulary and the two convention-owned problem types; HTTP conventions (`RateLimit`, 500, deprecation, pagination maximum); projection P | ADR-0008 | 0010 §6, 0011 §2–§3, 0013 §1/§2/§4 |
| Tables, migrations, round-trip, identity derivation, integrity, enums, **deletion semantics**, tenancy seam and RLS policy text (permissive tenant policy, restrictive pinned-role policy, `hdf_tenant_roles`), unique-import constraint, pgvector tables and the `SECURITY DEFINER` index function with the owner-run concurrent path, similarity exemplar, **schema-version policy and re-projection**, CI engines; hosts ADR-0013's tables in its ledger | ADR-0009 | 0010 §2–§5, 0011 §3, §5, 0013 §1/§4/§5 |
| `Principal`, store/query/provider interfaces, **precedent row types**, the `AuditSink` obligation, backends incl. **`http`**, Go pool ownership and the codec-free migration connection, the environment table, MCP and CLI wiring, the **error code table** (the single mapping), the `hdf-db-schema` import boundary | ADR-0010 | 0008 §3 (consumes the table), 0009 §8 (who sets tenant context), 0011 §2, 0013 §1 |
| The service, its runtime, structure, and packaging, the Node floor, the Zod/client pipeline execution, the **companion auth document**, authentication modes, token contract, **one issuer**, per-resource audiences, verifier description (TS + Go), the hardening set (MFA, lockout, revocation, FIPS algorithm), email, bootstrap, enforcement layering and entrypoint checks, Go MCP HTTP transport | ADR-0011 | 0008 §3/§7, 0009 §8, 0010 §2, 0013 §1/§6 |
| The organization-anchored tables' schema and migrations (hosted in ADR-0009's ledger), audit ledger with its hash chain and export, job runner and job kinds, organization lifecycle (delete guard, export, hold), outbox and Standard Webhooks, evidence blob store and quotas, deployment posture, metrics, backup/restore; the route-placement rule (companion strictly `/api/auth/*`) | ADR-0013 | 0008 §2/§3, 0009 §5/§8/§9/§12, 0010 §2/§4/§6, 0011 §1/§2/§3/§5 |
| The MCP tool surface and handle design; the golden | ADR-0007 (amended by 0010 §5 and 0011 §6 — two cards) | 0008 §2, 0010 §5 |
| Change-event key, kernel, and the producer (amendment named by 0013 §5) | ADR-0005 | 0009 §3, 0013 §5 |
| This map, the invariants, the ownership table, the sequencing, the follow-on list | ADR-0012 | — |

If a reviewer finds the same decision made in two places, that is a defect in this table, and the owner listed here wins.

### 4. Language map

| Component | Language | Why |
|---|---|---|
| `hdf-schema`, `hdf-validators`, `hdf-engine`, `hdf-diff`, `hdf-converters` | TS + Go (existing) | consumed by both the Go tools and TS libraries; ADR-0011 adds four TS ports in three cards (amendment merge, document builders, VEX→amendments, pair-keyed converter registry) to close real gaps |
| `hdf-openapi` (ADR-0008) | TS | build-time generator; its input includes a Go-produced golden |
| `hdf-db-schema` (ADR-0009, hosting ADR-0013's tables) | TS (Drizzle) + Go (generated structs, pgx applier) | Go MCP and CLI import and export rows |
| `hdf-data` (ADR-0010) | TS + Go (`file` and `http` backends Go-only) | the Go MCP and CLI are consumers; the TS service is a consumer |
| `hdf-serve`, `hdf-client` (ADR-0011, hosting ADR-0013's services) | TS | hosted service; better-auth, Zod, pg-boss are TS-native |
| `hdf` CLI, `hdf mcp` | Go (existing) | single binary; stdio MCP; HTTP transport with the shared verifier; hosted stores through the generated Go client |
| Token verifier | one JSON description; `jose` (TS) and `go-oidc` with a throttled JWKS transport (Go) | both surfaces must accept the same tokens, each for its own audience |

The one place a reviewer may reasonably disagree is the service language — ADR-0011 challenge (a) — and the map above is what changes if that decision flips: `hdf-serve` becomes a Go subcommand, better-auth becomes a separate TS process, Zod retreats to the client, the four TS ports are not needed, and pg-boss is replaced by a Go queue on the same store.

### 5. Cross-ADR sequencing

The "Depends on" line of each phase in each ADR is authoritative; this section only lists the **edges that cross ADR boundaries**, so cards carry them.

Prerequisite cards outside the five packages, runnable in parallel: ADR-0008 (a) enums on tool schemas, (b) exported shapes + one golden with the registration hook, (c) XML DOCTYPE hardening; ADR-0009 validators to 2020-12 engines, chain digest to a schema-defined location; ADR-0011 ports p1–p3; ADR-0007 amendment, transport card. The ADR-0007 precedent-tools card waits for ADR-0010 Phase 3; the ADR-0005 producer amendment waits for ADR-0009 Phase 7. The fast-uri override (PR #274) precedes every commit through the repo gauntlet.

| Depends | On | Why |
|---|---|---|
| ADR-0010 Phase 2 | ADR-0009 Phases 1a, 2c-ii; ADR-0013 Phase 0 (a no-op sink until then) | documents anchor, import/export/re-projection, deletion guard, audit sink |
| ADR-0010 Phase 3 | ADR-0009 Phases 3, 4, 5 | the exemplar joins and RLS-on assertions |
| ADR-0010 Phase 4 | ADR-0009 Phase 4b | embeddings tables and the registration function |
| ADR-0010 Phase 5 | ADR-0009 Phase 5 | the pinned-role policy the CLI test exercises |
| ADR-0010 Phase 7 | ADR-0011 Phases 3–4 (running service with ingest and auth); ADR-0011 Phase 7 for queries | the Go `http` backend needs a service to talk to |
| ADR-0011 Phase 0 | ADR-0010 Phase 2 | the service needs the `db` backend |
| ADR-0011 Phase 1 | ADR-0008 Phase 2 | the generated document is the pipeline's input |
| ADR-0011 Phase 3 | ports p1–p3 | write operations need the TS twins |
| ADR-0011 Phase 4 | ADR-0013 Phase 0 | auth events need the audit sink |
| ADR-0011 Phase 5 | ADR-0009 Phase 5 | RLS migration for the RLS-on negatives |
| ADR-0011 Phase 6 | ADR-0007 transport card | the amendment precedes the transport |
| ADR-0011 Phase 7 | ADR-0010 Phases 3–4; ADR-0007 precedent-tools card (which carries the ADR-0008 `bindings.yaml` entries and regeneration) | the operations derive from the tools |
| ADR-0013 Phase 0 | ADR-0009 Phase 1a | the ledger the audit table joins |
| ADR-0013 Phase 1 | ADR-0011 Phase 2 | the routes the jobs pair joins |
| ADR-0013 Phases 2–5 | ADR-0009 Phase 2c-ii / 4b, ADR-0010 Phases 2/4, ADR-0011 Phases 3–4 | as each phase's line states |
| ADR-0010 Phase 6, ADR-0011 Phase 8, ADR-0013 Phase 6 | ADR-0009 Phase 6 | the release-workflow policy (tag-stamp exclusion, `next`, the image job) is introduced once and extended |

Delivery units, as each ADR states: ADR-0008 two PRs; ADR-0009 one epic on one branch; ADR-0010 two PRs (Go file adapter and MCP refactor first, so the MCP behaves identically before the database exists); ADR-0011 one epic in phase-pair PRs; ADR-0013 one epic by phase. Agent-pace totals, **each ADR's figure already including its own prerequisites**: 0008 ≈ sp46 · 0009 ≈ sp193 · 0010 ≈ sp76 · 0011 ≈ sp107 · 0013 ≈ sp58 · ADR-0007 amendment ≈ sp8 → **≈ sp488, roughly 63–86 hours** at the repo's calibration (the ADRs' own ranges: 4–6 + 25–34 + 11–14 + 14–19 + 8–11, plus 1–2 for the amendment). Cards are cut only after the review of all five.

### 6. What was proven by running code (round 6)

The four spikes are throwaway scripts kept outside the repo as the seed of the Phase 1 tests they correspond to; their outputs sit beside the scripts, and the review triage holds the summaries (six claims whose probe output was not retained are marked as such in the owning ADR and re-run in its Phase 1 or 4). What they established, and what they corrected:

- **Contract pipeline**: Hey API accepts the 2020-12 document; the generated Zod drives `createRoute`; raw components register and the validator skips them; `getOpenAPI31Document` emits 3.1; **projection P held with zero residual** and the inventory assertion held; the generated client's form-encoded token call and async auth hook work. Corrections: query parameters need a pre-processing resolver (ADR-0008 §7); the client's Zod for HDF documents is lossy, so the client wraps document operations with `hdf-validators` (ADR-0011 §4); the auth hook is called per request, so the client caches the token.
- **PGlite, pgvector, Drizzle**: the partial expression HNSW index builds and is chosen on PGlite; roles and RLS enforce on PGlite under `SET ROLE`; the `SECURITY DEFINER` function works as a non-owner; both ledger claims hold and a hand-named folder fails exactly as predicted. Correction: Drizzle's `vector()` requires dimensions, so the column is a `customType` (ADR-0009 §11).
- **better-auth to Go**: `client_credentials` with `resource` yields a JWT that go-oidc and jose verify and audience-reject correctly; the org claim hook and the API-key exchange endpoint work as worded; the invitation hook works and `disableSignUp` does not. Corrections: without `resource` the token is opaque, so `resource` is mandatory; the public create-client endpoint drops the scope ceiling, so the service owns client creation; one server issues under two issuer strings, so the issuer is aligned at issuance (ADR-0011 §3).
- **Go, PostgreSQL 18, pgvector 0.8.6**: RLS as a non-owner under `FORCE`, the deletion guard, cascade through child triggers, and byte-identical ledger parity all passed. Corrections: the migration pool must not register pgvector types (ADR-0010 §1); a bound `model_id` loses the index after five executions, so index use is asserted by counting scans, not by reading a plan (ADR-0009 §11).

### 7. What each surface gets, once all five land

| Surface | Before | After |
|---|---|---|
| `hdf` CLI | files in, files out | `hdf db import/export/list/delete/reproject/precedent/similar/embed/audit/jobs` against a local database or a hosted store (`HDF_STORE=http`, no database credential) |
| `hdf mcp` (stdio) | one document per call from a directory | `HDF_STORE=db` or `http`: opens by id, drafts amendments with carry-forward and similar-system precedent (after the precedent-tools card) |
| `hdf mcp --transport http` | none | Streamable HTTP behind the shared verifier with its own audience; RFC 9728 metadata pointing at the issuer |
| HTTP API (`hdf-serve`) | none | every ADR-0008 operation, canonical full shapes, RFC 9457, cursor pagination, ETag/If-Match, `RateLimit` headers, tenant-scoped; plus audit, jobs, evidence, holds, usage, webhooks |
| Auth | none | better-auth issuer (organizations, teams, OAuth clients by default, API keys as the exception, MFA for privileged roles, lockout, revocation, OAuth 2.1 for MCP clients) or any external OIDC issuer; one token contract, one issuer |
| SDK | none | `hdf-client` (typed, Zod-validated, document operations validated with `hdf-validators`, generated token calls, two namespaces) plus types-only `openapi-typescript` |
| Operations | none | append-only audit with SIEM export, background jobs with `202`, organization export and safe deletion, signed webhooks, metrics, tested backup and restore |
| Dev/test | ad hoc | PGlite + pgvector in-process for everything TS incl. RLS and jobs; PostgreSQL + pgvector container for Go |

### 8. Follow-on ADRs, named now so nobody re-derives them

- **Viewer queries** (`findings` across systems, `complianceSeries` per system) on the ADR-0010 query surface — after ADR-0009 Phases 2–5 exist; sized ≈ sp13 by the gap analysis.
- **ADR-0005 producer amendment** — deriving requirement change events at ingest and persisting them (ADR-0009 Phase 7's table), emitted through ADR-0013's outbox.
- **Object storage for evidence bytes** behind ADR-0013's `BlobStore` seam, when a deployment needs it.
- **MCP served from TypeScript**, if a consumer appears that the Go MCP over HTTP does not serve.
- **OpenTelemetry tracing**, archival tiers, data residency, a Helm chart, a UI — each explicitly deferred in the owning ADR.

## Alternatives Considered and Implementation Plan

Not applicable: this document is an overview and makes no decision of its own; alternatives and plans live in the five ADRs it maps.

## Reviewer challenge points

Will's review should specifically challenge or verify: (a) the **ownership table** (§3) — is any decision made in two places, and is every owner the right one, now that ADR-0013's tables live in ADR-0009's ledger and its services in ADR-0011's process; (b) the **cross-ADR sequencing** (§5) — are the edges complete and is the critical path (ADR-0009 Phases 0 → 5) the one to shorten; (c) the **totals** (§5) as an honest agent-pace estimate for the set, and whether ADR-0013 should land before ADR-0011's write operations rather than beside them; (d) the **follow-on list** (§8) — anything there that must be v1, or anything in v1 that should be there.

## Consequences of reading the five as one

Easier: a reviewer can see that no layer re-implements another's decision; a contributor knows which package to change for which concern; cards can be cut with cross-ADR dependencies already named; the invariants are a checklist for every future ADR that touches the platform; the spike scripts give every Phase 1 a starting test.

Harder: the set is large (≈ 40k words of design), ships as one design PR, and lands over months; a decision reversed in one ADR must be traced through the ownership table; this document must be revised whenever one of the five changes an owned decision.

Risks and mitigations: the map drifts from the five → each ADR's "How to review" line names this document, and the ownership table is the first thing to update when an ADR revision changes an owner; the totals are read as commitments → they are agent-pace sizes with the calibration source named, re-measured at card cut; the diagram is read as a dependency graph → it is a data/identity flow only, and §5's table is the dependency source; the spike results are read as proof for the real document and stack → they are proof of the mechanisms on representative samples, and each Phase 1 repeats them on the real artefacts.

## References
- ADR-0007 (MCP server), ADR-0008 (OpenAPI components and API), ADR-0009 (relational + vector schema), ADR-0010 (data access layer), ADR-0011 (`hdf-serve`), ADR-0013 (operational services), ADR-0005 (change events), ADR-0002 (ECS export), ADR-0001 (BOMs) — `dev-docs/` (all accessed 2026-09-02)
- Repo conventions this set inherits: `CLAUDE.md` (fixture policy, converter/registry patterns, timestamp canon, beads), `site/docs/contributing/developer-guide.md`; estimation calibration in the repo's agent-pace notes (accessed 2026-09-02)
