---
description: Run generative workflows against the HDF MCP server (`hdf mcp`) — drafting attestation amendments for notReviewed requirements, or applying a VEX document as amendments — sequencing the author/apply tools. Use when asked to draft or apply HDF amendments through the MCP server.
allowed-tools: Read, Glob, Grep, Bash
---

# HDF MCP Workflows

Generative workflows an agent runs against the HDF MCP server (`hdf mcp`).
Per ADR-0007 §9, this guidance ships as a Skill rather than as MCP prompts:
the server is a non-interactive pipeline consumer, and these workflows are
procedure-shaped (a fixed tool sequence), which prompts fit poorly.

Use this Skill when asked to draft or apply HDF amendments through the MCP
server. It assumes the server is reachable as an MCP tool provider (the
consumer guide is `site/docs/guides/hdf-mcp.md`); the tools referenced here
are the shipped surface, not invented ones.

## Preconditions

- The documents you operate on live under `HDF_MCP_ROOT`; reference them by
  path relative to that root, or by a handle a prior call returned.
- Authoring and applying are **write** operations. If
  `HDF_MCP_ENABLE_WRITES` is unset, every write call returns a summary plus
  a `WRITES_DISABLED` notice and writes nothing — run the workflow in that
  mode first to preview, then ask the deployer to enable writes to commit.
- Never fabricate an expiry, a status, or an attribution. The server stamps
  `appliedBy.type = "agent"` and `appliedAt` itself; you supply the
  selection, the reason, and the required `expiresAt`.

## Workflow 1 — Draft attestation amendments for notReviewed requirements

An assessor has manually verified controls a scan left `notReviewed`, and
wants those recorded as attestation amendments.

1. **Find the notReviewed requirements.** Query the results document for the
   requirements that need attesting:

   ```json
   { "name": "hdf_query", "arguments": {
       "source": { "path": "results/rhel9.json" },
       "status": ["notReviewed"] } }
   ```

   The response lists each requirement's ID, title, and severity. Select the
   ones the assessor actually verified — do not blanket-attest.

2. **Author the amendments (judgment path).** Supply one override per
   selected requirement: its `requirementId`, `type: "attestation"`, the
   effective `status` the attestation asserts (usually `passed`), a
   `reason` capturing the assessor's justification, and a required
   `expiresAt` (RFC3339; use a real review-cycle date, never a fabricated
   default). The server stamps `appliedBy.type = "agent"` and `appliedAt`.

   ```json
   { "name": "hdf_author", "arguments": {
       "docType": "amendments",
       "name": "RHEL9 manual attestations",
       "content": [
         { "type": "attestation", "requirementId": "V-257777",
           "status": "passed",
           "reason": "Manually verified: FIPS mode enabled and confirmed on the host.",
           "expiresAt": "2027-01-01T00:00:00Z" } ],
       "output": "amendments/rhel9-attestations.json" } }
   ```

   The response reports `valid`, the override count, and a handle. If the
   content does not validate, the call is refused (`SCHEMA_INVALID`) — fix
   the override and retry; nothing is written.

3. **Apply the amendments to the results.** Produce a new results file with
   the effective statuses computed and the compliance delta reported:

   ```json
   { "name": "hdf_apply_amendment", "arguments": {
       "results": { "path": "results/rhel9.json" },
       "amendments": { "path": "amendments/rhel9-attestations.json" },
       "output": "results/rhel9-attested.json" } }
   ```

   The applied file is new — the input results file is never overwritten.
   The response's `projectedCompliance` (before/after) and
   `changedRequirementCount` show the effect. The applied file retains the
   `appliedBy.type = "agent"` overrides, so a downstream `hdf_compliance`
   call reports the agent-attributed override count.

## Workflow 2 — Apply a VEX document as amendments

A vulnerability scan reported findings, and a supplier VEX document says
some are not exploitable in this product. Record the VEX as amendments and
apply them.

1. **Author the amendments from the VEX (from_vex path).** Point
   `hdf_author` at the VEX document and supply the required `expiresAt`; the
   server runs the deterministic VEX→override mapping (no model prose on
   this path) and stamps `appliedBy.type = "system"` — a deterministic
   mapping is not agent judgment.

   ```json
   { "name": "hdf_author", "arguments": {
       "docType": "amendments",
       "name": "Supplier VEX",
       "source": { "path": "vex/product.openvex.json" },
       "expiresAt": "2027-01-01T00:00:00Z",
       "output": "amendments/product-vex.json" } }
   ```

   Supply either `content` (judgment) or `source` (from_vex) — not both. A
   VEX with no actionable statements is refused rather than producing an
   empty amendment set.

2. **Apply the amendments to the results** exactly as in Workflow 1 step 3,
   pointing at the vulnerability results and the VEX-derived amendments. The
   before/after compliance delta shows how many findings the VEX cleared.

## Sequencing notes

- **Preview before committing.** In a writes-disabled deployment (or with
  `dryRun: true` on `hdf_author`/`hdf_apply_amendment`), run the whole
  sequence to see the summaries and validation verdicts without writing,
  then re-run to commit once writes are enabled.
- **create-once / apply-many.** One amendments document can be applied to
  more than one results file; author it once, apply it where it belongs.
- **Reason strings are the audit trail.** The `reason` on each override is
  what an assessor reads later — make it specific about what was verified,
  not a restatement of the requirement.

## Anti-patterns

- Do NOT author amendments the assessor did not actually approve.
- Do NOT invent an `expiresAt` — a missing expiry is a refusal, not a
  server-chosen default.
- Do NOT try to set `appliedBy.type` yourself — the server owns it (agent
  for judgment, system for from_vex).
- Do NOT apply amendments in place — `hdf_apply_amendment` always writes a
  new file; the results input is never modified.
- Do NOT pass document bodies between tools — pass handles or paths.
