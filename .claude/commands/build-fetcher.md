---
description: Build a new HDF live fetcher (Go + TS) end-to-end following hdf-libs monorepo patterns. Use when asked to add a fetcher for a security tool that pulls data from a live API (e.g. "add a Tenable.SC fetcher", "wire up a Crowdstrike fetcher").
allowed-tools: Read, Glob, Grep, Bash, Edit, Write, Task, EnterPlanMode, ExitPlanMode, AskUserQuestion
---

## What a fetcher is (and isn't)

A **fetcher** retrieves security data from a live API and hands the raw bytes
to a converter for HDF transformation. Fetchers exist when the source tool has
no static export format we can convert directly, or when the export is awkward
enough that pulling live is the user-friendly path.

A fetcher is NOT a converter. If the source format already exists as a file
type users can save (Nessus `.nessus`, Grype JSON, SARIF), build the converter
first via `/build-converter`. A fetcher is added when the data lives in a
remote API only.

**Two things ship together** when a tool needs both: the file-mode converter
(via `/build-converter`) AND the fetcher (via this skill). The fetcher's job
is to produce bytes that the existing converter already understands.

## What's shared with `/build-converter` (don't duplicate)

The following phases work identically — see `/build-converter` for the
authoritative procedure, don't re-derive it here:

- **Plan mode workflow** (enter immediately; write a detailed plan; exit
  with `ExitPlanMode` for user approval before any implementation)
- **TDD discipline** (write tests first, confirm red, implement to green)
- **Library reuse audit** (BLOCKING) — `hdf-schema`, `hdf-utilities`,
  `hdf-mappings`, `hdf-validators`, `hdf-converters/shared/{go,typescript}`,
  `hdf-converters/fetchers/shared/{go,typescript}`
- **`pnpm lint` clean and `pnpm test` passes at root** as the final gate
- **`bd` for task tracking** (not TodoWrite or markdown lists)
- **Commit only with explicit user approval**, signed (`-s`)

This skill covers only what's distinct from converter work.

## What's different about fetchers

| Concern | Converter (`/build-converter`) | Fetcher (this skill) |
|---|---|---|
| Input source | Static file (user provides bytes) | Live API |
| Auth | None (transform only) | Pre-authenticated transport (TS) / default-discovery + injection (Go) |
| Test fixtures | Real tool output (heimdall2 / SAF samples) | HTTP mocks that validate request params |
| Schema audit | HDF field-gap audit on source format | N/A (fetcher reuses the converter's audit) |
| Security gate | Input validation (size, XML entity expansion) | 7-point network safety review (pagination, timeouts, credential redaction, SSRF) |
| File layout | `hdf-converters/converters/<name>/{go,typescript}/` | `hdf-converters/fetchers/<tool>/{go,typescript}/` |
| Go constructors | One: `Convert<Name>(input, version) ([]byte, error)` | Two: `NewXFetcher` (default-discovery) + `NewXFetcherWithClient` (injection) |
| TS API | One sync/async function returning JSON | Multiple functions; each takes a pre-authenticated client |

## Auth-agnostic TS contract (project rule)

The single most important architectural rule, and the one that's easy to get
wrong:

**TS fetchers MUST NOT accept credentials, file paths, environment lookups,
or TLS configuration.** They MUST accept a *pre-authenticated transport*
chosen by the caller — an SDK client, a `splunkjs.Service`, an `authFetch`
callable, etc.

Why: library code that never receives credentials cannot log, persist, or
leak them. Auth concerns (rotation, vault integration, MFA, SSO, CSP-proxied
browser flows) belong in the application layer (heimdall2, saf-cli) where
they vary per deployment.

Concrete shapes by service type:

```typescript
// Service with an official SDK (AWS, Azure, GitHub):
async function fetchXToHdf(client: ConfiguredSDKClient, opts?: Filters): Promise<HDFResults>

// Service with an official non-SDK typed client (Splunk):
async function fetchYToHdf(service: splunkjs.Service, opts: { ... }): Promise<HDFResults>

// Bespoke REST API (Tenable, Snyk, ...):
type AuthFetch = (path: string, init?: RequestInit) => Promise<Response>;
async function fetchZToHdf(authFetch: AuthFetch, opts: { ... }): Promise<HDFResults>
```

If you're about to write `username: string, password: string` as parameters
on a TS fetcher signature, STOP. That's an auth-handling fetcher, which is
wrong. Push it back to the caller.

## Two-constructor Go pattern

Go fetchers offer two constructors so both consumers are served:

```go
// 1. Default-discovery convenience. Builds a stdlib *http.Client (or
//    SDK config) from TLSOptions + env vars. This is what hdf-cli uses.
func NewXFetcher(params XParams, tlsOpts shared.TLSOptions) (*XFetcher, error)

// 2. Client injection. Caller provides a pre-configured *http.Client
//    (or SDK-typed client where applicable). Used by downstream Go
//    consumers (saf-cli, custom orchestrators) that want full control
//    over transport and auth.
func NewXFetcherWithClient(params XParams, client *http.Client) (*XFetcher, error)
```

Both constructors share the same Params struct and `Fetch(ctx)` method —
only the transport setup differs.

## File layout

```
hdf-converters/fetchers/<tool>/
  go/
    fetcher.go            # XFetcher struct, NewXFetcher, NewXFetcherWithClient, Fetch(ctx)
    fetcher_test.go       # httptest.Server-based tests
  typescript/
    fetcher.ts            # fetchXToHdf / pushHdfToX / verifyXCredentials
    fetcher.test.ts
    index.ts              # barrel export

hdf-converters/fetchers/shared/
  go/                     # TLSOptions, NewHTTPClient, ValidateAndBuildAPIURL, ReadLimitedBody (already in tree)
  typescript/             # (empty today; populate only when a second TS fetcher needs the same helper)

hdf-cli/cmd/hdf/cmd/
  fetch_<tool>.go         # CLI wrapper; reads env vars / flags; calls NewXFetcher
  fetch_<tool>_test.go    # mocks the Fetcher interface; does NOT need real network
```

## Execution strategy

Mirror `/build-converter`'s phased approach. The phases below name only what's
distinct.

### Phase 1 — Research & Plan (enter plan mode)

1. **`EnterPlanMode` immediately.**
2. Research the API:
   - Read the official API docs. Identify the endpoints we need:
     `list` (enumerate jobs/scans/findings), `get` (fetch a specific one),
     and optionally `push` (upload HDF) and `verify` (test credentials).
   - **Decide the auth model the LIBRARY accepts**: SDK client, splunk-sdk
     `Service`, or `authFetch` callable. This is a contract decision, not
     an implementation detail. Different services may genuinely need
     different shapes — Tenable wants `authFetch`, AWS wants the SDK client.
   - Check whether an **official SDK** exists. If yes, prefer it (no SSRF
     surface to defend, no pagination loop to test, no auth-error
     translation to maintain). If no, the fetcher hand-rolls REST.
   - Identify whether the upstream tool also has a **file-mode export**.
     If yes, the file-mode converter probably already exists in
     `hdf-converters/converters/`; the fetcher's job is to produce bytes
     that converter already reads. If no file mode exists, you may need
     to **define a static format** the fetcher emits and the converter
     reads (see `/build-converter` Step 2 sourcing-from-API). When in
     doubt, ask the user.
3. Audit the existing fetchers (`hdf-converters/fetchers/{awsconfig,gitlab,sonarqube,splunk}/go/`)
   for a reference implementation. AWS Config is the canonical "uses
   official SDK" pattern; SonarQube is the canonical "hand-rolls REST,
   paginated GET" pattern; Splunk is the canonical "create job → poll →
   fetch results" pattern.
4. Write the plan covering:
   - **API surface**: endpoints, pagination shape, rate limits, max
     response size
   - **Auth model** for both Go (default-discovery + injection) and TS
     (which pre-authenticated transport)
   - **CLI shape** (`hdf fetch <tool>` flags, env vars for credentials)
   - **Mock strategy**: which fields tests will validate on the request
     side (headers, query params, body) — see "Mock discipline" below
   - **Security review checklist** (see Phase 5)
5. **`ExitPlanMode`** for user approval before any implementation.

### Phase 2 — Fixtures and Tests (TDD)

Fixtures here are **canned HTTP responses**, not real tool exports. They
live inline in test files (small) or in `fetcher_test.go`'s
`httptest.Server` handlers. Do NOT commit external response samples
unless they're large enough to warrant a `testdata/` directory.

#### Mock discipline (the single most important fetcher convention)

**Mocks MUST validate request parameters.** A mock that returns canned
JSON regardless of what the fetcher asked for proves nothing. The
canonical SonarQube bug (missing `additionalFields=rules`) was
invisible to mocks that returned rules regardless of query params.

Every fetcher test handler should assert:

- `r.URL.Path` matches the expected endpoint exactly (no fuzzy match)
- `r.Method` matches (GET / POST / etc.)
- For paginated requests: `r.URL.Query().Get("page")` (or equivalent
  continuation-token field) matches the expected value, and **the next
  page's request carries the previous page's returned token**
- For POST: read and assert on the request body
- For auth: assert on the header pattern but not the literal token —
  use a placeholder like `"Bearer <token>"`

Reference: `hdf-converters/fetchers/sonarqube/go/sonarqube_test.go`
shows the right shape. Note also `feedback_fetcher_mock_patterns.md` in
auto-memory.

#### Test scenarios every fetcher needs

- Single-page happy path
- Multi-page pagination (assert continuation-token plumbing)
- 401 unauthorized → error contains "unauthorized" / "auth" without
  leaking the token value
- 4xx other → error mentions the status code
- 5xx → error path
- Context cancellation (caller passes a cancelled `ctx` → error)
- Default timeout fires (long-hanging response → error after the default
  deadline)
- Response size cap (response > `maxResponseSize` → error)
- Pagination cap (continuation-token loop > `maxPages` → error)
- Token-leakage test: induce an error path, assert the secret token
  string is NOT in the error message

### Phase 3 — Implementation

**Go fetcher (`fetcher.go`):**
- Define `XParams` (the user-facing config: host, project ID, scan ID,
  etc. — never secrets)
- Define `XFetcher` struct (holds `*http.Client` and `XParams`)
- `NewXFetcher(params, tlsOpts)` — calls `shared.NewHTTPClient(tlsOpts)`
- `NewXFetcherWithClient(params, client)` — accepts caller-injected client
- `Fetch(ctx)` — context-cancellation-aware, default-deadline-applying,
  paginated, size-capped HTTP work; returns the same byte format the
  file-mode converter reads
- Use `shared.ValidateAndBuildAPIURL`, `shared.ReadLimitedBody` —
  don't re-roll
- All SDK calls / HTTP requests carry `ctx`; check `ctx.Err()` at the
  top of every pagination iteration

**TS fetcher (`fetcher.ts`):**
- Function signatures take the pre-authenticated transport, not credentials
- For SDK-based services, accept the SDK client directly
- For REST APIs, accept `authFetch: (path, init?) => Promise<Response>`
- Return `HDFResults` (call the converter inline) or raw bytes (let the
  caller convert) — match the heimdall2 / saf-cli call site shape
- NO `node:crypto` imports outside `crypto.getRandomValues` /
  `crypto.subtle` (browser-compat)

### Phase 4 — CLI integration (Go side only)

Add `hdf-cli/cmd/hdf/cmd/fetch_<tool>.go` following the existing pattern
(see `fetch_aws_config.go` or `fetch_sonarqube.go`):

- Read credentials from env vars (`<TOOL>_TOKEN`, `<TOOL>_USERNAME`,
  etc.), **never from CLI flags** (process listing leaks)
- Read non-secret config (URLs, project IDs, scan IDs) from CLI flags
- Call `fetchers.<tool>.NewXFetcher(params, fetchTLSOptions(cmd))`
- Wire into the parent `fetch` command's subcommand list (`fetch.go`)
- Update `fetch.go`'s `Long` description with the new source

The TS fetcher has NO CLI side — it's library code consumed by heimdall2
and saf-cli.

### Phase 5 — Security review (MANDATORY, blocking)

Before considering the fetcher done, run the 7-point review. EACH of
these MUST have a concrete defense in the code, not just a comment.
File a follow-up bead for any item that can't be resolved in this PR.

1. **Credential handling.** Secrets MUST come from env vars or config
   files, never CLI flags. Document the env var name in `hdf-cli/README.md`
   under "Credential Handling". TS side: ensure the auth-agnostic
   contract is upheld (no credential params).
2. **Input validation.** API URLs and identifier strings (project IDs,
   region codes, scan IDs) MUST be validated before being interpolated
   into request paths — unvalidated strings passed to SDK endpoint
   constructors are an SSRF vector (CVE-2026-22611 / GHSA-3jcv-796g-cpjg).
   Use `shared.ValidateAndBuildAPIURL` for ad-hoc REST. SDK calls are
   defended by the SDK.
3. **Pagination cap.** Every pagination loop MUST have a `maxPages`
   constant. Uncapped loops exhaust memory on malformed
   continuation-token responses. Default 10,000.
4. **Context cancellation.** Check `ctx.Err()` at the top of each
   pagination iteration, not just at request submission.
5. **Default timeout.** `Fetch()` MUST apply a default deadline when the
   caller has not set one (`5 * time.Minute` is the established default).
   Missing deadline → indefinite block on a hung endpoint.
6. **Error message safety.** Errors MUST NOT include credential values.
   The token-leakage test in Phase 2 confirms this.
7. **TLS enforcement.** TLS is enforced — either by SDK default or by
   our `shared.NewHTTPClient` (which sets `MinVersion: tls.VersionTLS12`).
   Document it in a comment if the SDK handles it automatically.

The reference implementation for all 7: `hdf-converters/fetchers/awsconfig/go/awsconfig.go`.

### Phase 6 — Documentation (CRITICAL, easy to forget)

A converter or fetcher that ships without documentation is invisible to
users. **The single biggest historical regression in this repo is
"shipped code, forgot docs."** Walk this list every time:

1. **`hdf-cli/README.md`**:
   - Add a row to the **"Live API Fetch (`hdf fetch ...`)"** table near
     the top of the Quick Reference
   - Add a detailed subsection under `hdf fetch <tool>` covering flags,
     env vars, example invocations
   - Add the env-var name(s) to the **"Credential Handling"** table
   - Update the parent `fetch` command's `Long` description (in
     `cmd/hdf/cmd/fetch.go`) to list the new source under "Available
     sources" with a one-line summary
2. **`hdf-converters/fetchers/README.md`** — add the tool to the
   "Currently in tree" list. Update the per-tool subsection if there
   are tool-specific notes (e.g., "uses splunk-sdk" / "TS takes an
   authFetch callable").
3. **CLI helptext** — every flag MUST have a non-trivial usage hint via
   `cmd.Flags().StringVarP(&x, "name", "n", "default", "Helpful description")`.
   `examples`/`usage` is not enough; users run `--help` first.
4. **`site/` documentation** — if a new "Live fetch" or "Credential
   Handling" section exists in the VitePress docs, mirror the
   `hdf-cli/README.md` updates there. (Check `site/docs/` for relevant
   pages; not every page applies, but the catalog of fetch sources
   usually does.)
5. **Bead progress note** — append a note to the parent bead via
   `bd update <id> --append-notes "..."` describing what landed,
   including the commit hash.

Verification: do a grep before commit. If the tool name appears only
in code files (`.go` / `.ts`), the docs gate failed.

```bash
git diff --name-only HEAD~1 | grep -vE "\.(go|ts|json|yml|yaml|jsonl|sum|lock)$" | head
# Should include at least: hdf-cli/README.md, hdf-converters/fetchers/README.md
```

### Phase 7 — Verification (`/build-converter` Phase 5 applies verbatim)

Same gates: `pnpm lint && pnpm test` at root, full `pnpm check`
(includes coverage threshold), CLI spot-check with `hdf fetch <tool>`
against a real instance if available, or a mocked-out path with debug
logging if not.

CLI spot-check expectations:

```bash
go build -o /tmp/hdf ./hdf-cli/cmd/hdf
export <TOOL>_TOKEN=...
/tmp/hdf fetch <tool> --required-arg value -o /tmp/out.json
/tmp/hdf validate /tmp/out.json
```

If a real instance isn't accessible, document why and bead the live
spot-check (see `hdf-libs-sokk` for the asff-validation precedent).

## Coverage requirements

Same threshold as converters: >90% line/branch coverage on `fetcher.go`.

Every public function gets at least: happy path, auth failure, 5xx,
context cancellation, pagination cap. Defensive arms that can't be
hit through realistic mocks (e.g., `json.Marshal` of a known-good
struct) may use `// nolint:gocover` / v8-ignore comments — same
discipline as converters.

## Done Checklist (this is the gate before saying "done")

### Architecture
- [ ] Go: two constructors (`NewXFetcher` + `NewXFetcherWithClient`)
- [ ] TS: auth-agnostic — accepts pre-authenticated transport, NO
      credential params
- [ ] `XParams` carries config only (URLs, IDs); secrets come from
      env vars in the CLI wrapper
- [ ] Lives in `hdf-converters/fetchers/<tool>/{go,typescript}/`

### Tests
- [ ] All tests use `httptest.Server` (or SDK interface injection) —
      no live credentials required
- [ ] **Mocks validate request parameters** (paths, methods, headers,
      query params, request bodies) — not just return canned responses
- [ ] Pagination cap test (loop > maxPages → error)
- [ ] Default timeout test (long-hanging response → error)
- [ ] Token-leakage test (induced error must NOT contain the secret)
- [ ] Context cancellation test
- [ ] Coverage ≥90% on `fetcher.go`

### Security (the 7-point review)
- [ ] Credentials from env vars / config files, NEVER CLI flags
- [ ] API URLs / identifier strings validated before path interpolation
- [ ] Pagination loops capped (default 10,000)
- [ ] `ctx.Err()` checked at top of each pagination iteration
- [ ] `Fetch()` applies default deadline when caller hasn't set one
- [ ] Error messages do NOT contain credential values
- [ ] TLS enforced (SDK or `shared.NewHTTPClient`)

### Documentation (the historical regression — DO NOT SKIP)
- [ ] `hdf-cli/README.md` — Live API Fetch table row + detailed
      subsection + Credential Handling table row
- [ ] `hdf-cli/cmd/hdf/cmd/fetch.go` — parent `Long` description
      lists the new source
- [ ] `hdf-converters/fetchers/README.md` — "Currently in tree" list
      updated
- [ ] CLI helptext — every flag has a useful description string
- [ ] `site/` VitePress docs — mirror the README updates where
      applicable
- [ ] Parent bead — `bd update <id> --append-notes` with commit hash

### Verification
- [ ] `pnpm check` clean (build + lint + test + security + coverage)
- [ ] CLI spot-check executed against a real instance OR live-validation
      bead filed (precedent: `hdf-libs-sokk`)

### Bead hygiene
- [ ] Parent fetcher bead transitioned to closed via `bd close`
      with a concise reason mentioning the commit
- [ ] `.beads/issues.jsonl` refreshed via `bd export` and staged in
      the same commit as the code

## When to bring `/build-converter` along

If the source tool has no file-mode converter in tree yet, **build the
converter first** via `/build-converter`. The fetcher cannot ship
without something for its bytes to flow into.

If both are needed in the same PR, do the converter under
`/build-converter`, commit it, then start `/build-fetcher` on top.
Keep the commits separate so the diff is reviewable per skill.

## When NOT to use this skill

- The source format is a file users save and convert (use `/build-converter`)
- The fetcher already exists and needs widening (just edit it; no skill
  ceremony)
- The "fetcher" is really CLI orchestration around an existing converter
  (just wire it in `hdf-cli/cmd/hdf/cmd/` directly)
