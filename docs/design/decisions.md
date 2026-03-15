# HDF v2 Design Decisions

This document records the major design decisions for HDF v2, including the research
that informed them, alternatives considered, and rationale for the chosen approach.

---

## Decision 1: Labels Over Hierarchies for System Grouping

**Date:** 2026-03-14
**Status:** Decided
**Context:** The user wanted to add system/sub-system concepts to the schema to enable
fleet comparison, ATO boundary scoping, and tiered compliance reporting.

### Research

Four independent research agents analyzed the problem:

1. **Standards researcher** — surveyed OSCAL SSP, DISA STIG, FedRAMP, RMF, AWS Organizations,
   Kubernetes, eMASS, ServiceNow GRC, Tenable.sc, DefectDojo hierarchy models
2. **Impact analyzer** — identified every file in the codebase that would need to change
   (~50 files for a fixed hierarchy, 2 fields for labels)
3. **Schema designer** — produced a complete System/Component schema with JSON Schema
   definitions, OSCAL-aligned field names, and example documents
4. **Critical reviewer** — challenged the hierarchy proposal and explored alternatives

### Alternatives Scored

| Approach | Flexibility | Simplicity | OSCAL | Backward Compat | Diff Impact | Converter Impact | Total |
|----------|-------------|------------|-------|-----------------|-------------|------------------|-------|
| Fixed hierarchy (System→Component→Target) | 2/10 | 3/10 | 6/10 | 2/10 | 4/10 | 2/10 | **19/60** |
| Extensions only (system metadata in extensions) | 8/10 | 9/10 | 3/10 | 10/10 | 5/10 | 10/10 | **45/60** |
| Labels (K8s-style key-value on targets) | 9/10 | 8/10 | 4/10 | 8/10 | 9/10 | 7/10 | **45/60** |
| Labels + separate hdf-system document type | 9/10 | 6/10 | 8/10 | 7/10 | 9/10 | 7/10 | **46/60** |
| Separate document type only (OSCAL pattern) | 8/10 | 7/10 | 9/10 | 9/10 | 6/10 | 9/10 | **48/60** |

### Decision

**Labels on targets/baselines + separate hdf-system document type.**

### Rationale

1. **Labels are strictly more powerful than a hierarchy.** A hierarchy forces one grouping
   dimension (system→component). Labels support unlimited dimensions simultaneously
   (system, component, environment, region, team). The diff engine can `--group-by` any label.

2. **Converters don't have system data.** When InSpec runs against a host, it doesn't know
   what "system" that host belongs to. Forcing converters to fabricate organizational structure
   violates the "never fabricate fixture data" principle.

3. **OSCAL separates SSP from AR.** OSCAL's System Security Plan (architecture) and
   Assessment Results (scan output) are separate document types linked by reference. HDF
   should follow the same pattern — not embed system architecture inside scan results.

4. **HDF is an assessment format, not a GRC platform.** Authorization status, FIPS
   categorization, and boundary descriptions are governance concepts. They belong in
   hdf-system (a separate document), not in hdf-results (scan output).

5. **Minimal schema change.** Labels require adding one optional field to two existing types.
   Zero breaking changes. Zero converter changes.

---

## Decision 2: Exit Code Scheme (0/1/2 basic, 10-14 detailed)

**Date:** 2026-03-14
**Status:** Decided and implemented

### Research

Surveyed exit code conventions across:
- **POSIX/GNU diff** — 0=identical, 1=different, 2=error (universal standard)
- **InSpec** — 0=pass, 1=error, 100=failures, 101=skipped (high-range codes)
- **Nagios** — 0=OK, 1=WARNING, 2=CRITICAL, 3=UNKNOWN (monitoring standard)
- **Terraform** — 0=no changes, 1=error, 2=changes (opt-in detailed)
- **Puppet** — bitmask system (2=changes, 4=failures, 6=both)
- **CI/CD systems** — GitHub Actions, GitLab CI, Jenkins all treat non-zero as failure;
  only GitLab supports `allow_failure:exit_codes` natively

### Decision

Hybrid scheme with opt-in detailed mode:

**`--exit-code` (GNU diff compatible):**
```
0 = identical (no differences)
1 = differences found (any kind)
2 = error
```

**`--detailed-exitcode` (nuanced security outcomes):**
```
0  = identical
1  = error
10 = fixes only (security improved)
11 = regressions only (security degraded)
12 = mixed fixes and regressions
13 = baseline changed (new/absent controls only)
14 = metadata drift only
```

### Rationale

- Range 10-14 avoids sysexits.h (64-78), signal range (128+), and InSpec codes (100-101)
- Default mode is universally understood (GNU diff)
- Detailed mode is opt-in (like Terraform's `--detailed-exitcode`)
- CI scripts can branch on specific codes:
  ```bash
  hdf diff --detailed-exitcode old.json new.json
  case $? in
    0)  echo "No changes" ;;
    10) echo "Improvements only — safe to deploy" ;;
    11) echo "Regressions — blocking" ; exit 1 ;;
    12) echo "Mixed — needs review" ;;
  esac
  ```
- GitLab CI supports `allow_failure: exit_codes: [10, 13, 14]` natively

---

## Decision 3: Full Before/After Snapshots (Terraform Pattern)

**Date:** 2026-03-13
**Status:** Decided and implemented

### Alternatives

| Approach | Self-contained | Storage | Consumer complexity |
|----------|---------------|---------|-------------------|
| Patches only (RFC 6902) | No — needs original docs | Small | Must reconstruct state |
| Summary only (counts) | Yes | Minimal | Can't drill down |
| Full snapshots (Terraform) | Yes — complete artifact | ~600KB | Simple — all data present |

### Decision

Full `EvaluatedRequirement` snapshots in `before`/`after` for all requirements,
including unchanged. No detail levels on the canonical document — detail levels
are a renderer concern.

### Rationale

Every well-designed diff format (Terraform, Debezium, Delta Lake, Review Board) uses
full snapshots. 600KB uncompressed → ~52KB gzipped. The comparison document is a
first-class audit artifact that must be self-contained. An auditor reading it should
understand the complete before and after state without needing the original source documents.

---

## Decision 4: SARIF-Compatible State Vocabulary

**Date:** 2026-03-13
**Status:** Decided and implemented

### Decision

Use SARIF's `baselineState` vocabulary as the foundation, extended for security domain:

| State | SARIF equivalent | Meaning |
|-------|-----------------|---------|
| `new` | `new` | Present only in new source |
| `absent` | `absent` | Present only in old source |
| `unchanged` | `unchanged` | Same effective status |
| `updated` | `updated` | Status changed (generic) |
| `fixed` | (extension) | Was failing, now passing |
| `regressed` | (extension) | Was passing, now failing |
| `moved` | (extension) | Reorganized, same content (v1.1) |
| `split` | (extension) | One became multiple (v1.1) |
| `merged` | (extension) | Multiple became one (v1.1) |

### Rationale

SARIF is the closest existing standard for tracking security findings across runs.
Using compatible vocabulary enables interoperability with GitHub Code Scanning,
Azure DevOps, and other SARIF consumers. The extensions (`fixed`, `regressed`) add
domain-specific semantics that SARIF lacks.

---

## Decision 5: Typed Inputs Bridging Governance and Automation

**Date:** 2026-03-14
**Status:** Decided, not yet implemented

### Problem

OSCAL and STIGs express requirements as prose: "The system must limit concurrent
sessions to 3 per user." Automated scanners need machine-readable expected values.
There is no standard way to connect governance prose to scanner parameters.

This was identified as a real-world gap by the user from experience on the OSCAL board,
where testable values and programming data types (lists, booleans, arrays) at the correct
level of detail were needed to bridge SSP/SAP expected values to automated testing scripts.

### Decision

Create a typed `Input` primitive that carries type information, enabling the full chain:

```
Baseline default (3) → System override (5) → Plan resolved (5) → Results observed (7) → Comparison drift (+2)
```

Also rename `Evaluated_Baseline.attributes` to `Evaluated_Baseline.inputs` to normalize
the legacy InSpec v3/v4 naming. InSpec renamed "attributes" to "inputs" in v4/v5 because
"attributes" was ambiguous.

### Rationale

Both schemas (hdf-baseline and hdf-results) already have `inputs[]`/`attributes[]` fields
carrying this data as unstructured `object` blobs. The data is already flowing through —
it just lacks type information. The typed Input primitive makes it structured and auditable.

---

## Decision 6: Seven Document Types (Not One Monolith)

**Date:** 2026-03-14
**Status:** Decided

### Research

Compared against OSCAL (7 document types), SCAP (6 component standards), and the
full security assessment lifecycle to identify the minimum coherent set.

### Decision

| # | Type | Status | Covers |
|---|------|--------|--------|
| 1 | hdf-baseline | Exists | Requirements definition |
| 2 | hdf-results | Exists | Assessment findings |
| 3 | hdf-comparison | Exists | Structured diff |
| 4 | hdf-system | New | System architecture |
| 5 | hdf-plan | New | Assessment planning |
| 6 | hdf-attestation | New | Risk governance |
| 7 | hdf-evidence-package | New | Audit evidence |

### What we explicitly decided NOT to build

- Policy documents (prose, GRC platforms)
- Remediation playbooks (Ansible/Terraform formats)
- SBOM (defer to CycloneDX/SPDX, reference by URI)
- VEX/Advisories (defer to CSAF/OpenVEX)
- Trending/time-series (query-time aggregation of comparisons)
- Alerts (integration concern — webhooks, PagerDuty)
- Incident response (STIX/TAXII, TheHive)

---

## Decision 7: AI/LLM Output Formats (TOON, JSON-LD, MCP)

**Date:** 2026-03-14
**Status:** Research complete, implementation deferred

### TOON (Token-Oriented Object Notation)

Researched for reducing token costs when passing HDF documents to AI agents.
- 30-60% token reduction for tabular/uniform arrays (our `requirementDiffs`)
- npm package `@toon-format/toon` exists (MIT, v3.0 spec working draft)
- Best for the `requirementDiffs` array; poor for nested before/after snapshots
- **Recommendation:** Add as optional output renderer when demand materializes

### JSON-LD

Considered for semantic web / AI agent discoverability.
- Would add `@context` mapping HDF fields to security ontology URIs
- Adds complexity without immediate need
- **Recommendation:** Defer to v2.1

### MCP Server

Wrapping `hdf-diff` as an MCP (Model Context Protocol) tool for AI agent invocation.
- HDF JSON Schema already serves as function calling spec
- Combined with TOON output, enables low-token-cost security analysis
- **Recommendation:** Create card when MCP ecosystem matures

---

## Decision 8: Dual TS+Go Implementation From Day One

**Date:** 2026-03-14
**Status:** Decided (learned from experience)

### Context

During hdf-diff development, TypeScript was built first (380 tests, 100% coverage),
then Go was ported afterward. This created a significant rework effort and parity gaps
that required multiple swarm sessions to close.

### Decision

All future HDF libraries (hdf-system, hdf-plan, hdf-attestation, hdf-evidence) must
implement TypeScript and Go side-by-side, not sequentially. Each implementation task
includes both languages. Differential testing verifies parity on shared fixtures.

### Rationale

Building both simultaneously:
- Catches design issues earlier (Go's type system reveals assumptions TS hides)
- Eliminates the "port everything again" rework
- Ensures the Go types inform the schema design (e.g., nil-slice serialization)
- Keeps test fixtures shared from the start
