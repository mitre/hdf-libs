---
description: Build a new HDF live-API fetcher end-to-end following hdf-libs monorepo patterns. Use when asked to add a fetcher for an API-backed security tool (e.g. "add a defectdojo fetcher", "pull findings live from X"), or when a source is a live API rather than a static file.
allowed-tools: Read, Glob, Grep, Bash, Edit, Write, Task, EnterPlanMode, ExitPlanMode, AskUserQuestion
---

## What a fetcher is (and when to build one)

A **fetcher** is network-edge code that pulls security data from a remote API and hands the raw bytes to an existing HDF **converter**. It is NOT a format transform — the converter does that. The fetcher owns auth, pagination, rate limits, TLS, and URL validation; the converter owns the source-format → HDF mapping.

Build a fetcher when the source is a live API rather than a static export file (DefectDojo, SonarQube, Splunk, GitLab, AWS Config/Security Hub). Do **not** build one for a pure file-format transform — that is a converter (see the `/build-converter` skill).

**Hard prerequisite: a fetcher feeds a converter.** The HDF converter for the same source must already exist in `hdf-converters/converters/`, or land in the same PR. If it doesn't exist yet, build the converter first (`/build-converter`), then this fetcher. A fetcher with no converter to pipe into has nowhere to send its bytes.

> The old `build-converter` Step 5b ("Live Fetch Mode") is superseded by this skill. Fetchers no longer live in `hdf-cli/internal/fetchers/` and are no longer Go-only.

## Where fetchers live

```
hdf-converters/fetchers/
├── shared/
│   ├── go/          # TLSOptions, NewHTTPClient, ValidateAndBuildAPIURL, ReadLimitedBody
│   └── typescript/  # (populated as TS fetchers land)
├── <tool>/          # kebab-case, matches the converter name
│   ├── go/          # Go implementation — TWO constructors (below)
│   └── typescript/  # TS implementation — auth-agnostic (below)
└── README.md        # the authoritative convention — read it
```

CLI wiring lives in `hdf-cli/cmd/hdf/cmd/fetch_<tool>.go`, registered under the `fetch` subcommand. That is hdf-cli orchestration (flags, output paths, validation gating) — it stays in the CLI package, not in `fetchers/`.

**Read `hdf-converters/fetchers/README.md` and one existing fetcher before starting.** `gitlab` and `sonarqube` are the closest token-auth REST analogues; `aws-securityhub` is the reference for a dual-language (Go + TS) fetcher.

## Phase 1 — Research & Plan (enter plan mode)

**Enter plan mode immediately.** Fetchers touch credentials and untrusted network responses; the wrong design is a security bug, not just a rework. Do not write code before the plan is approved.

Research and decide:

1. **The converter it feeds.** Which existing converter consumes this source's bytes? What exact shape does that converter expect (JSON array? single object? NDJSON)? The fetcher must produce exactly that.
2. **Auth model.** Bearer token, API key header, session cookie, OAuth, SDK credential chain? Where does the credential come from — env var, config file, SDK discovery? **Credentials are never accepted as raw CLI flags** (visible in `ps`, shell history, CI logs) — prefer `--profile`, env vars, or a token file. The AWS CLI itself does not accept `--secret-access-key` as a flag; follow that precedent.
3. **Response schema — get a REAL sample.** Do not invent field names or nesting. Capture a real API response (a live instance you stand up and populate, or documented API reference). A fetcher/converter built against a guessed schema validates the wrong thing and diverges silently from real data. If you can't obtain a real sample, STOP and ask.
4. **Pagination & size.** Does the API paginate? Both loops must be capped at a maximum page count. Response bodies must be size-limited (`ReadLimitedBody`).
5. **`--check` / verify capability?** Many fetchers support a credentials-only probe (one cheap call, no findings download) so a user can validate auth before a full pull. Decide whether this tool needs it.
6. **Languages.** Go is required (hdf-cli drives it). Add TypeScript when a JS/TS consumer (heimdall2, saf-cli) needs it — `aws-securityhub` is the first dual-language fetcher; the TS side is in-tree but not yet exported to npm.

Write the plan: converter it feeds, auth/credential source, endpoints + pagination, response schema (with the real sample as evidence), `--check` decision, languages, and the CLI flag set. Exit plan mode for approval before implementing.

## Go convention — two constructors

Every Go fetcher exposes exactly two constructors. This is the security boundary: the library either configures transport from a `TLSOptions` struct (never touching raw credentials) or accepts a fully-configured client from the caller.

```go
// 1. Default-discovery — what hdf-cli uses. Builds an http.Client with
//    system-CA defaults from TLSOptions. The token is resolved at Fetch time
//    from env vars / CLI config, never handled in this constructor.
func NewFooFetcher(params FooParams, tlsOpts shared.TLSOptions) (*FooFetcher, error) {
    if err := validateFooURL(params.URL); err != nil { // validate BEFORE building anything
        return nil, err
    }
    client, err := shared.NewHTTPClient(tlsOpts)
    if err != nil { return nil, fmt.Errorf("failed to configure TLS: %w", err) }
    return &FooFetcher{client: client, params: params}, nil
}

// 2. Injection — caller hands in a pre-configured *http.Client (or SDK-typed
//    client). The library never touches transport, auth headers, or credential
//    discovery. Use for corporate proxies, custom MFA, credential vaults, mocks.
func NewFooFetcherWithClient(params FooParams, client *http.Client) (*FooFetcher, error) {
    if err := validateFooURL(params.URL); err != nil { return nil, err }
    return &FooFetcher{client: client, params: params}, nil
}
```

Required in every Go fetcher (see `gitlab/go/gitlab.go` for the reference):

- A `FooParams` struct with documented fields; `MaxResponseSize int64` (0 = default, -1 = unlimited).
- A default timeout constant applied when the caller sets no deadline (e.g. `5 * time.Minute`).
- A default max-response-size constant (e.g. `10 * 1024 * 1024`).
- URL validation up front — reject empty and non-`http(s)` schemes. Use `shared.ValidateAndBuildAPIURL(rawURL, path, toolName)` when building request URLs (it is the SSRF guard).
- `shared.ReadLimitedBody(resp.Body, max)` for every response read — never `io.ReadAll` an untrusted body.
- `Fetch(ctx context.Context) ([]byte, error)` returns the bytes the converter consumes. Check `ctx.Err()` at the top of every pagination iteration.

## TypeScript convention — auth-agnostic

TS fetchers do **not** accept credentials, file paths, env lookups, or TLS config. They accept a **pre-authenticated transport** and use it for every call. The caller (heimdall2, saf-cli) acquires credentials entirely.

- **SDK-based services** (AWS, Splunk): the caller passes a configured SDK client (`SecurityHubClient`, `splunkjs.Service`). The SDK carries credentials; the library never reads env vars or credential files. See `fetchAWSSecurityHubToHdf(client, options)` and `verifyAWSSecurityHubCredentials(client)`.
- **Bespoke REST APIs** (DefectDojo, Tenable.SC): the caller passes an `authFetch` callable of shape `(path, init?) => Promise<Response>` that injects the right headers/cookies/tokens.

> The security contract: **a library that never receives credentials cannot log, persist, or leak them.** Do not add a "convenience" constructor that reads a token from the environment — that belongs in the CLI/application layer, not the library.

## CLI wiring

Add `hdf-cli/cmd/hdf/cmd/fetch_<tool>.go`, following `fetch_gitlab.go` / `fetch_aws_securityhub.go`:

- `newFetch<Tool>Cmd() *cobra.Command`, `Use: "<tool> [output]"`, registered under `fetch` in `fetch.go`.
- Use the **default-discovery** constructor (`NewFooFetcher(params, TLSOptions{})`) — the CLI resolves credentials from flags/env and hands transport config through; it never passes raw secrets into the library.
- Standard flags: connection params, `--format hdf|raw` (convert vs native passthrough), `--output/-o`, `--max-response-size`, and `--check` if the tool supports a credentials-only probe.
- On `hdf` format, pipe the fetched bytes straight into the existing `Convert<Tool>` function; on `raw`, emit the native bytes.

## Tests — assert the request, not just the path

Mock the API with `httptest.NewServer` (Go) or a mock transport (TS). **Mocks must assert request headers, query params, and bodies — not just the path.** A test that only checks the URL path passes even when the auth header is wrong or a query param is dropped.

```go
srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    capturedAuth := r.Header.Get("Authorization")  // assert auth is sent correctly
    // assert query params, request body as applicable
    w.Header().Set("Content-Type", "application/json")
    _, _ = w.Write([]byte(`{ /* canned real-shaped response */ }`))
}))
defer srv.Close()
```

Cover: successful fetch, URL-validation rejections (empty, non-http scheme), auth-header propagation, pagination (multi-page + the cap), size-limit truncation, context cancellation, and the `--check` path if present. **Never require live credentials or a running service in a test.**

## Security review — MANDATORY, before "done"

After implementing the fetcher and its tests, **task a security agent** to review it. The prompt must cover:

1. **Credential handling** — no secrets accepted as CLI flags; env/profile/token-file only; not logged, not in error messages.
2. **SSRF** — endpoint URLs and region/host strings validated (`ValidateAndBuildAPIURL`) before use in requests. Unvalidated strings into endpoint constructors are an SSRF vector (cf. GHSA-3jcv-796g-cpjg).
3. **Pagination caps** — every pagination loop bounded by a max page count.
4. **Context cancellation** — `ctx.Err()` checked at the top of each pagination iteration, not just propagated.
5. **Timeout** — a default deadline applied when the caller sets none.
6. **Response size** — `ReadLimitedBody` on every body read.
7. **TLS** — enforced (documented in a comment if the SDK handles it).

Fix every finding before marking the work done. `aws-config` / `gitlab` are the reference implementations for these patterns.

## Done checklist

- [ ] The converter this fetcher feeds already exists (or lands in the same PR)
- [ ] Response schema confirmed against a REAL API sample — no invented fields
- [ ] `fetchers/<tool>/go/` — two constructors (default-discovery + injection), params struct, default timeout + max-size consts, URL validation, `ReadLimitedBody`, `ctx.Err()` in pagination
- [ ] `fetchers/<tool>/typescript/` (if in scope) — auth-agnostic: pre-authenticated transport / `authFetch`, never credentials
- [ ] Tests use `httptest.Server` / mock transport; assert headers + query params + body, not just path; no live credentials
- [ ] CLI `fetch_<tool>.go` uses the default-discovery constructor; `--format hdf|raw`, `--output`, `--max-response-size`, `--check` (if applicable); registered in `fetch.go`
- [ ] Fetched bytes pipe into the existing `Convert<Tool>` on `hdf` format
- [ ] Security agent review completed; all findings addressed
- [ ] `hdf-converters/fetchers/README.md` "Currently in tree" table updated
- [ ] `pnpm lint && pnpm test` clean at root; `golangci-lint run` clean in `hdf-cli`
- [ ] Spot-checked: `hdf fetch <tool> --check` and a real `hdf fetch <tool> -o out.json` against a live/populated instance (or documented why a live check isn't possible)
