# hdf-converters fetchers

Live API clients that retrieve security data from remote tools and pipe it
through the corresponding HDF converter. Each fetcher lives next to its
sibling converters so the network-edge code (auth, pagination, rate limits)
sits adjacent to the format transform it feeds.

## Layout

```
fetchers/
├── shared/
│   ├── go/             # TLSOptions, NewHTTPClient, ValidateAndBuildAPIURL, ReadLimitedBody
│   └── typescript/     # (populated as TS fetchers land)
├── <tool>/
│   ├── go/             # Go implementation, two constructors (see below)
│   └── typescript/     # TS implementation (auth-agnostic)
└── README.md
```

Currently in tree:

| Tool | Go | TS | Capabilities |
|---|---|---|---|
| `awsconfig` | ✓ | — | fetch |
| `aws-securityhub` | ✓ | ✓ | fetch, verify |
| `gitlab` | ✓ | — | fetch |
| `sonarqube` | ✓ | — | fetch |
| `splunk` | ✓ | — | fetch |

`aws-securityhub` is the first fetcher implemented in both Go and TS.
The Go side is what `hdf-cli` drives; the TS side is in-tree (used by its
own tests) but is **not yet exported to npm consumers** — the
`@mitre/hdf-converters` package `exports` do not include a `fetchers/*`
entrypoint, so publishing it requires an `exports`/build change first.
Its TS contract takes a caller-supplied `@aws-sdk/client-securityhub`
`SecurityHubClient` (auth-agnostic — the library never sees credentials).

## Go fetcher convention — two constructors

Each Go fetcher exposes **two** ways to construct a client:

```go
// 1. Default-discovery convenience. Reads TLS options from a TLSOptions struct
//    and builds a stdlib http.Client with system-CA defaults. This is what
//    hdf-cli uses — the CLI passes flags / env vars through to the SDK and
//    never handles raw credentials in process.
fetcher, err := splunk.NewSplunkFetcher(params, shared.TLSOptions{})

// 2. Client injection. Caller hands in a pre-configured *http.Client (or
//    SDK-typed client where the constructor name says so). The library
//    never touches transport, auth headers, or credential discovery —
//    everything is the caller's responsibility.
fetcher, err := splunk.NewSplunkFetcherWithClient(params, client)
```

Use the injection constructor whenever the application layer wants to control
auth/transport directly: corporate proxies, custom MFA flows, multi-tenant
credential vaults, mocked clients in tests.

## TypeScript fetcher convention — auth-agnostic

TS fetchers do NOT accept credentials, file paths, environment lookups, or
TLS configuration. They accept a **pre-authenticated transport** and use it
for every network call. The caller — heimdall2, saf-cli, or any future
downstream — handles credential acquisition entirely.

Shape varies per service:

- **AWS SDKs**: caller passes a configured `*Client` (e.g. `SecurityHubClient`,
  `ConfigServiceClient`). SDK auto-discovers credentials per its own chain;
  library never reads env vars or `~/.aws/credentials`.
- **splunk-sdk**: caller passes a configured `splunkjs.Service`.
- **Bespoke REST APIs (Tenable.SC, etc.)**: caller passes an `authFetch`
  callable of shape `(path, init?) => Promise<Response>` that injects the
  appropriate headers/cookies/tokens.

This boundary is the security contract: a library that never receives
credentials cannot log, persist, or leak them.

## Where fetchers belong

A fetcher belongs here when:
- It calls a remote API and returns bytes consumable by an HDF converter.
- The HDF converter for the same source format already exists in
  `hdf-converters/converters/`, or is being added in the same PR.

A fetcher does NOT belong here when:
- It is a pure file-format transform with no network calls (that is a
  converter — put it in `converters/`).
- It is hdf-cli-specific orchestration (command flags, output paths,
  validation gating) — that stays in `hdf-cli/cmd/hdf/cmd/`.

## Adding a new fetcher

1. Pick a tool name in `kebab-case`.
2. Add `fetchers/<tool>/{go,typescript}/`.
3. Implement both languages. Go gets two constructors; TS is
   auth-agnostic.
4. Add tests that validate request parameters (per the project's
   fetcher-mock convention) — mocks must check headers, query params,
   and request bodies, not just paths.
5. Wire the CLI command in `hdf-cli/cmd/hdf/cmd/fetch_<tool>.go` using
   the default-discovery constructor.
6. Update this README's "Currently in tree" list.
