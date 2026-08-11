# HDF MCP Server

`hdf mcp` runs the Heimdall Data Format server over the Model Context
Protocol (MCP), so an AI agent or MCP-aware client can read, analyze, and
author HDF documents through a small, typed tool surface instead of
shelling out to the CLI. It speaks JSON-RPC over **stdio**: the client
launches `hdf mcp` as a subprocess and every request and response is a
JSON-RPC frame on stdin/stdout (nothing else is written to stdout).

```bash
hdf mcp        # start the server (stdio transport)
```

A typical MCP client entry (for example a `config.toml` `mcp_servers`
block) launches the built binary with `mcp` as its argument and sets the
[environment variables](#deployment) below.

The design rationale lives in the architecture decision record
`dev-docs/adr-0007-hdf-mcp-server.md`; this guide documents the shipped
surface for consumers.

## The tool surface

The server exposes nine tools. Read tools never mutate anything; write
tools are governed by a deployer-controlled gate (see
[Reads vs. writes](#reads-vs-writes)). Every tool returns a compact
**summary** plus a reusable **handle** — never a multi-megabyte document
body.

### Read tools

| Tool | Purpose |
|------|---------|
| `hdf_open` | Entry point: open a document, return its detected type, schema version, validity, and a handle. Optional — every read tool also accepts a `{path}` directly. |
| `hdf_inspect` | Document **structure and metadata** for all eight HDF document types (counts, component/baseline/assessment breakdowns, top-level fields). It never returns requirements. |
| `hdf_query` | The **only** path to requirements (results and baseline documents only). Filters by status, severity, requirement ID, tag, and free text; concise by default, full on request; paginates when a response would exceed the token budget. |
| `hdf_compliance` | Status × severity rollups, the compliance percentage, optional threshold verdicts, and the agent-attributed override count. |
| `hdf_diff` | Compare two documents — temporal (results across time) or system-drift (system documents) — and emit an `hdf-comparison`. |
| `hdf_validate` | Validate a document in `schema`, `checksums`, or `completeness` mode. |

The `hdf_inspect` vs. `hdf_query` bright line is deliberate: **inspect is
structure, query is requirements.** If you want to know how many baselines
a results file has, or what components a system document declares, call
`hdf_inspect`. If you want the requirements themselves — their statuses,
severities, or IDs — call `hdf_query`. `hdf_inspect` will never return
requirements, and `hdf_query` only accepts results and baseline documents.

### Write tools

| Tool | Purpose |
|------|---------|
| `hdf_convert` | Convert source security-tool output (Nessus, SARIF, gosec, VEX, …) into an HDF document. Auto-detects the source format; returns a summary and a handle. |
| `hdf_author` | Author an HDF document from model-supplied structured content: `system` (components), `plan` (assessments), `evidence` (contents), or `amendments` (overrides). For amendments the server holds field authority (see below). |
| `hdf_apply_amendment` | Apply an `hdf-amendments` document to an `hdf-results` document, producing a **new** results file with `effectiveStatus`/`effectiveImpact`/`disposition` computed and the before/after compliance delta reported. It never overwrites its results input. |

> `hdf_author` is a single authoring tool. It subsumes what earlier designs
> split into separate document-builder and amendment-creator tools: the
> model supplies the content array, and the server assembles, validates,
> and stamps the schema-valid envelope.

## The source model

Every tool that reads a document takes a `source`:

```json
{ "source": { "path": "results/rhel9.json" } }
```

or

```json
{ "source": { "handle": "eyJwYXRoIjoi…" } }
```

- A `{path}` is resolved under `HDF_MCP_ROOT` (see
  [Deployment](#deployment)); a path that escapes the root is refused.
- A `{handle}` is the self-describing identity a prior call returned. It
  encodes the document's path, content hash, detected type, and schema
  version, so the server can re-read it and detect if the file changed
  underneath (a stale handle is reported, not silently trusted).

`hdf_open` is **optional, not a mandatory first hop** — you can pass a
`{path}` straight to `hdf_inspect`, `hdf_query`, or any read tool. Its
value is minting a handle you then reuse across a multi-step workflow.

Agents pass **handles** back to tools, never document bodies. Responses
are summaries plus handles precisely so a large results file never has to
travel through the model's context to be operated on again.

## Reads vs. writes

The server draws a firm line between reading and writing.

**Reads degrade gracefully.** A structurally-recognizable but
schema-invalid document still opens: the read returns `valid: false` and
the best structural summary it can, rather than failing. This lets an
agent inspect and reason about imperfect documents.

**Writes refuse invalid input.** Every write tool validates the document
it would produce against the real schema *before* writing, and refuses a
document that does not validate (`SCHEMA_INVALID`) — it is never written
or handed back.

**Write tools write by default; `dry_run` previews.** Within a deployment
that permits writes, a write tool writes its output file by default;
passing `dryRun: true` returns the same summary and validation verdict but
writes nothing.

**`HDF_MCP_ENABLE_WRITES` is the deployer ceiling.** Writes are disabled
by default. When they are disabled, a write call still succeeds — it
returns the computed summary plus a `WRITES_DISABLED` notice — but touches
no file. The agent cannot lift this ceiling; only the deployer can, by
setting the variable.

**Agent attribution travels in the data.** When `hdf_author` drafts
amendments from model judgment, the server stamps each override with
`appliedBy.type = "agent"` and an `appliedAt` timestamp — the model cannot
claim a non-agent identity. Those overrides survive `hdf_apply_amendment`
onto the applied results file, so `hdf_compliance` (and the
`hdf validate` / `hdf evidence verify` CLI readouts) can report how many
overrides an agent applied, without back-tracing to the amendments
document. This detective surface is what makes autonomous authoring
auditable.

## Deployment

The server is configured entirely through environment variables:

| Variable | Purpose | Default |
|----------|---------|---------|
| `HDF_MCP_ROOT` | Path-confinement root. Every `source.path` and write `output` is resolved under it; anything resolving outside is refused (`PATH_DENIED`). | the process working directory |
| `HDF_MCP_ENABLE_WRITES` | The write gate. Truthy (`1`, `true`, `yes`, `on`) permits writes; anything else disables them (write calls return previews). | disabled |
| `HDF_MCP_CACHE_BYTES` | Budget for the byte-bounded LRU parsed-document cache, so repeated reads of the same document skip re-parsing. | 256 MB |
| `HDF_MCP_LOG_LEVEL` | Structured-log level written to **stderr** (`error`, `warn`, `info`, `debug`). stdout carries only JSON-RPC frames. | `info` |

Set `HDF_MCP_ROOT` to the directory that holds the documents the agent
should work with, and leave `HDF_MCP_ENABLE_WRITES` unset for a read-only
trial — the write tools still work, returning previews, so you can see
exactly what they would produce before granting write access.

## Workflow guidance

The generative workflows an agent runs against this server — drafting
attestation amendments for `notReviewed` requirements, or applying a VEX
document as amendments — ship as a **usage Skill**, not as MCP prompts.
See `.claude/commands/hdf-mcp-workflows.md` for the tool sequencing each
workflow needs.
