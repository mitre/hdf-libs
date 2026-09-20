# hdf-converters fetchers

Live API clients that retrieve security data from remote tools and pipe it
through the corresponding HDF converter. Each fetcher lives next to its
sibling converters so the network-edge code (auth, pagination, rate limits)
sits adjacent to the format transform it feeds.

The authoring conventions — the Go two-constructor rule, the auth-agnostic
TypeScript contract, what belongs here, and how to add one — are documented at
[Writing a Fetcher](../../site/docs/contributing/writing-a-fetcher.md). This
file is the in-tree inventory.

## Layout

```
fetchers/
├── shared/
│   └── go/             # TLSOptions, NewHTTPClient, ValidateAndBuildAPIURL, ReadLimitedBody
├── <tool>/
│   ├── go/             # Go implementation, two constructors
│   └── typescript/     # TS implementation (auth-agnostic)
└── README.md
```

There is no `shared/typescript` yet; the TypeScript fetchers in tree have not
needed shared helpers.

## Currently in tree

| Tool | Go | TS | Capabilities |
|---|---|---|---|
| `awsconfig` | ✓ | — | fetch |
| `aws-securityhub` | ✓ | ✓ | fetch, verify |
| `defectdojo` | ✓ | ✓ | fetch, verify |
| `gitlab` | ✓ | — | fetch |
| `sonarqube` | ✓ | — | fetch |
| `splunk` | ✓ | — | fetch |

`aws-securityhub` was the first fetcher implemented in both Go and TypeScript.
The Go side is what `hdf-cli` drives; the TypeScript side is in tree and used by
its own tests, but is **not yet exported to npm consumers** — the
`@mitre/hdf-converters` package `exports` declare no `fetchers/*` entrypoint, so
publishing it requires an `exports` and build change first.
