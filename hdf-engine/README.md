# @mitre/hdf-engine

Shared, schema-typed read-side engines for Heimdall Data Format (HDF) documents — document-type **detection**, requirement **query/filtering**, and **compliance** rollups (with more read-side engines to follow).

It sits above `@mitre/hdf-schema` (types) and `@mitre/hdf-utilities` (schema-free primitives) and is consumed as a library by both the `hdf` CLI and the HDF MCP server — neither owns the engines. It is a sibling to `@mitre/hdf-diff` (which owns diff / change-events / amend); see `dev-docs/adr-0007-hdf-mcp-server.md`.

Dual-language: TypeScript (`@mitre/hdf-engine`) and Go (`github.com/mitre/hdf-libs/hdf-engine/go/v3`), kept at parity.
