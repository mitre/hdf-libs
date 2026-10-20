# The withdrawn MCP-to-API parity check

**Do not rebuild the MCP-to-API parity check.** It was designed, partly built, and withdrawn on 2026-10-13 along with the artifact it guarded. This page exists because the check was a good idea for a design that no longer holds, and the shape of it is attractive enough that someone will reach for it again.

## What it was

`hdf-openapi` once generated two documents. The first is the **components document**, built from the HDF JSON Schema bundles, and it still ships — that is the package's whole output today. The second was a **reference API document** describing an HTTP surface over HDF, and it was *derived* from the HDF MCP server's own contract: one tracked golden of the MCP's tools, resources and error taxonomy, plus a hand-authored binding table mapping each tool to a method and path.

Because the API document was derived from the MCP, the two surfaces could drift apart, and the parity check was the gate against that. It planted deliberate drifts — an unbound tool, a stale binding, a changed parameter, a changed enum, a resource, an error code, a response-shape field, a flipped hint — and failed if the comparison did not catch each one.

## Why it is gone

The derivation is gone, so there is nothing left for the check to compare.

Three decisions, agreed 2026-10-12 and recorded in ADR-0008 revision 22: the API document moves to the `hdf-data-platform` repository beside the server that implements it; it is **no longer derived from the MCP tool list**, the MCP becoming a *client* of the API rather than its source; and it is authored as TypeScript route declarations, with the OpenAPI document generated from those and reviewed as a diff.

A parity check between a source and its derivative cannot survive the removal of the derivation. Rebuilding one here would compare this repository's MCP surface against a document this repository does not have, does not author, and does not publish.

## What replaced the guarantee, and what is still open

The *guarantee* parity provided — that the MCP surface and the HTTP surface answer the same question the same way — was judged worth keeping. It is to be **replaced, not dropped**: a test that runs the same inputs through both surfaces and compares the answers.

That test does not exist yet, and three things about it are deliberately undecided. **Which repository hosts it**, since the MCP lives here and the service lives in the platform, so either host must reach the other's surface. **What "the same inputs" means**, now that nothing translates between the two shapes — the rewrite maps that used to define the correspondence went with the derivation. **What counts as the same answer**, given the MCP returns tool envelopes and the API returns HTTP responses carrying problem bodies; equality belongs at the level of the decision, not the serialization.

ADR-0012 §5 records those as open rather than resolving them, and ADR-0008 revision 22 commits to settling the home with the platform repository before the derivation link is cut.

## What this repository still guarantees on its own

Two things survive and are tested here, and neither needs the API document.

The **components document** is checked more strictly than any linter manages: every component is extracted back to a standalone 2020-12 schema and compiled, and every example — on the roots and on the definitions — is validated with a 2020-12 engine. This repository's own shipped validators are draft-07 and ignore `unevaluatedProperties`, so they would accept documents the schema text rejects.

The **MCP surface is still a tracked golden**, now for its own sake rather than as a generator input. Its contract and tool-list goldens live with the MCP and are its own drift gate — that gate is what caught a new error-taxonomy code arriving from an unrelated change.

## Where the history is

ADR-0008 §2 carries the withdrawal and the instruction not to rebuild. ADR-0008's Alternative I — route declarations as the source, originally rejected — records that it is now the decision, with each of the three original objections and why each stopped holding. ADR-0012 §2 invariant 6 records that no HTTP operation derives from an MCP tool, and §3 moves the API document's ownership to the platform's own ADR.
