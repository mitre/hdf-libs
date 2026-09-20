# Writing a Fetcher

A converter reads a file a tool already produced. A fetcher goes and gets it — a live API client that retrieves security data from a remote tool and hands the bytes to that tool's converter.

Fetchers live beside their converters, in `hdf-converters/fetchers/<tool>/`, so the network-edge concerns (auth, pagination, rate limits) sit next to the format transform they feed. The [fetcher inventory](https://github.com/mitre/hdf-libs/tree/main/hdf-converters/fetchers) lists what is in tree and which languages each supports.

This page is the human walkthrough. If you are using agents for coding, the repository ships a `build-fetcher` skill that automates the same process; this page is what to read when you want to understand the conventions rather than delegate them.

## When something is a fetcher

It belongs in `fetchers/` when it calls a remote API and returns bytes a converter can consume, and the converter for that source format already exists — or lands in the same change.

It does not belong there when it is a pure file transform with no network calls, which is a converter; or when it is CLI orchestration such as command flags, output paths and validation gating, which stays in `hdf-cli/cmd/hdf/cmd/`.

## The Go convention: two constructors

Every Go fetcher offers two ways to build a client, and the difference is who owns credentials. The parameters differ by service — the HTTP-based fetchers take TLS options and build a stdlib client, while the AWS ones take a context and build an SDK client — but the pairing is constant.

```go
// Default discovery. Reads TLS options and builds a stdlib http.Client with
// system-CA defaults. This is what hdf-cli uses: the CLI passes flags and
// environment through and never handles raw credentials in process.
fetcher, err := splunk.NewSplunkFetcher(params, shared.TLSOptions{})

// Client injection. The caller hands in a pre-configured client, and the
// library never touches transport, auth headers or credential discovery.
fetcher, err := splunk.NewSplunkFetcherWithClient(params, client)
```

The AWS fetchers take the same pair in SDK terms — `NewAWSConfigFetcher(ctx, params)`
for discovery, `NewAWSConfigFetcherWithClient(client)` where `client` satisfies the
SDK interface the fetcher declares.

Reach for the injection form whenever the application layer needs to own auth or transport — corporate proxies, custom MFA flows, multi-tenant credential vaults, or a mocked client in tests.

The shared helpers behind the default form live in `fetchers/shared/go`: `TLSOptions`, `NewHTTPClient`, `ValidateAndBuildAPIURL` and `ReadLimitedBody`.

## The TypeScript convention: auth-agnostic

TypeScript fetchers accept **no** credentials, file paths, environment lookups or TLS configuration. They take a pre-authenticated transport and use it for every call; the caller — heimdall2, saf-cli, or any downstream consumer — acquires credentials entirely on its own.

The shape varies by service, and both forms are in tree today:

- **An SDK client** — `aws-securityhub` takes a configured `SecurityHubClient`. The SDK discovers credentials through its own chain; the library never reads environment variables or `~/.aws/credentials`.
- **A bespoke REST API** — `defectdojo` takes an `authFetch` callable shaped `(path: string, init?: RequestInit) => Promise<Response>` that injects whatever headers, cookies or tokens the service wants.

A service with its own JavaScript SDK would follow the first shape, passing that SDK's configured client.

That boundary is the security contract, not a style preference: a library that never receives credentials cannot log, persist or leak them.


## The network edge is the security boundary

A converter's first obligation is a size guard on its input. A fetcher's equivalents are at the network edge, and they are requirements rather than suggestions — a fetcher reaches an attacker-influenced endpoint and reads an unbounded response.

- **Validate the endpoint before using it.** An unvalidated host or region string handed to an endpoint constructor is an SSRF vector. An HTTP fetcher builds its request URLs through the shared `ValidateAndBuildAPIURL` — see `sonarqube` or `defectdojo`. A fetcher that hands a string to an SDK validates it first in its own terms: `awsconfig` constrains the region with a DNS-label regex before the SDK ever sees it.
- **Bound every response read** with `ReadLimitedBody` — `defectdojo` and `splunk` are the examples. A fetcher that reads no raw bodies because its SDK owns the transport, like `awsconfig`, has nothing to bound.
- **Bound every pagination loop** by a maximum page count, and check `ctx.Err()` at the top of each iteration rather than only propagating the context. `sonarqube` is the fullest example.
- **Apply a default deadline** when the caller sets none.
- **Never accept a secret as a CLI flag** — environment, profile or token file only — and keep credentials out of logs and error messages.

These are checked in review, and the checks are listed in the repository's `build-fetcher` skill.

## Adding one

1. Pick a tool name in `kebab-case` and create `fetchers/<tool>/{go,typescript}/`.
2. Implement both languages — Go with the two constructors, TypeScript auth-agnostic.
3. Write tests that validate request *parameters*, not just paths: the mock must assert headers, query parameters and request bodies, or it passes against a client that sends the wrong request to the right URL.
4. Wire the CLI command in `hdf-cli/cmd/hdf/cmd/`, using the default-discovery constructor, **and register it** with an `AddCommand` line in `fetch.go` — creating the file alone compiles but leaves the subcommand invisible. The file name does not always follow the tool name: the `awsconfig` fetcher is driven by `fetch_aws_config.go`.
5. Add the tool to the "Currently in tree" table in [`fetchers/README.md`](https://github.com/mitre/hdf-libs/blob/main/hdf-converters/fetchers/README.md), which is where that inventory is maintained.
