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
| 6 | hdf-amendments | New | Risk governance |
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

All future HDF libraries (hdf-system, hdf-plan, hdf-amendments, hdf-evidence-package) must
implement TypeScript and Go side-by-side, not sequentially. Each implementation task
includes both languages. Differential testing verifies parity on shared fixtures.

### Rationale

Building both simultaneously:
- Catches design issues earlier (Go's type system reveals assumptions TS hides)
- Eliminates the "port everything again" rework
- Ensures the Go types inform the schema design (e.g., nil-slice serialization)
- Keeps test fixtures shared from the start

---

## Decision 9: Progressive Enrichment (Never Gating)

**Date:** 2026-03-15
**Status:** Decided

### Context

HDF documents carry optional metadata layers: labels, systemRef, planRef, typed inputs,
signatures, sbomRef. The question arose during SBOM integration design: should HDF
documents require any of these enrichment layers?

### Decision

**No enrichment layer is ever required.** Every optional field adds value when present
but the document is fully valid and functional without it.

### The Enrichment Stack

```
Level 0: Bare results (converter output)               → always works
Level 1: + Labels on targets                           → enables grouping
Level 2: + systemRef / planRef                         → enables provenance
Level 3: + Typed inputs                                → enables governance tracing
Level 4: + sbomRef on components/targets               → enables supply chain tracing
Level 5: + Signatures on overrides                     → enables non-repudiation
Level 6: + Evidence package with completeness check    → enables audit
```

### Rationale

Real-world conditions are imperfect:
- Most converters produce bare results with no labels or system context
- Many organizations don't have full SBOM coverage
- Configuration scanners (InSpec, OpenSCAP, Nessus) never produce SBOMs
- Signatures require infrastructure (HSMs, key management) that many teams lack

Making any enrichment layer required would exclude the majority of real-world usage.
Instead, consumers (Heimdall, CLI, CI/CD) can check for enrichment levels and prompt
users to add more context. The schema validates structure, not completeness.

### SBOM Specifically

SBOM references (`sbomRef`) follow the same pattern:
- `hdf-system.components[].sbomRef` — optional. "This component's SBOM lives here."
- `hdf-results.targets[].sbomRef` — optional. Should match system's sbomRef when it exists.
  When absent, the app layer interprets this as "no SBOM tracked for this target."
- `tags.purl` on findings — already how SCA converters (Grype, Trivy) identify packages.
  Config scanners will never produce purls. No schema change needed.
- If a vulnerability finding references a package not in any known SBOM, the sbomRef
  is simply absent. Business logic at the app layer would interpret that as "this package
  isn't tracked in any SBOM — consider re-running your SBOM scanner."

### SBOM Format Support

Both CycloneDX and SPDX are supported from day one. CycloneDX JSON is the more common
format in our ecosystem; SPDX JSON follows the same parse-and-diff pattern. The diff
algorithm is format-agnostic once components are extracted into a common model.

---

## Decision 10: Rename hdf-attestation to hdf-amendments

**Date:** 2026-03-15
**Status:** Decided

### Context

The planned document type `hdf-attestation` covered 4 subtypes: waiver, attestation,
exception, and POA&M. Calling the document "hdf-attestation" when one of its subtypes
is also "attestation" created a naming collision — like having a `Vehicle` document
where one vehicle type is "vehicle."

### Alternatives Considered

| Option | Name | Pros | Cons |
|--------|------|------|------|
| A | hdf-overrides | Matches existing `Status_Override` primitive | POA&Ms don't "override" anything |
| B | hdf-amendments | Matches amendment chain concept, governance term | Less immediately obvious to developers |
| C | Keep hdf-attestation | No rename needed | Name collision with subtype |

### Decision

**Rename to `hdf-amendments`.**

- Schema file: `hdf-amendments.schema.json`
- Primitives: `primitives/amendments.schema.json`
- CLI commands: `hdf amend create`, `hdf amend apply`, `hdf amend verify`, `hdf amend list`
- Subtype enum unchanged: `["waiver", "attestation", "exception", "poam"]`

### Rationale

1. **Amendment chain alignment.** The design uses `previousChecksum` to create a
   tamper-evident chain of modifications. Each document entry literally amends the
   previous state. The name matches the mechanism.

2. **Covers all 4 subtypes.** Every entry (waiver, attestation, exception, POA&M)
   amends the assessment record. "Override" was awkward for POA&Ms (they don't
   change status). "Amendment" works for all four.

3. **Correct governance term.** In legal and government contexts, an "amendment" is
   a formal change to an official document. This is exactly what these entries do —
   formally change an official assessment record with signed authorization.

4. **CLI reads naturally.** `hdf amend apply scan.json waivers.json` describes the
   action accurately.

### Downstream Impact

- All docs, plans, design docs, and beads cards updated
- Phase 5 (hdf-libs-qcj7): OSCAL converters reference `hdf-amendments`, not `hdf-attestation`
- hdf-cli: `hdf attest` → `hdf amend` command group
- Heimdall integration: "Waiver Management" section references amendments

---

## Decision 11: Generic Comparison (Any HDF Document Type)

**Date:** 2026-03-15
**Status:** Decided

### Context

The hdf-comparison schema was initially designed to compare only hdf-results documents
(assessment findings at two points in time). Discussion revealed that systems evolve —
components are added/swapped, SBOMs change, baselines are updated between STIG versions.
Auditors and security teams need to answer "what changed?" for any document type, not
just results.

Additionally, comparison is not limited to temporal diffs of the same system. It includes
cross-environment comparison (dev vs prod deployments of the same system) and cross-system
comparison (two different systems with similar baselines).

### Decision

**hdf-comparison is a generic structured diff for any two HDF documents of the same type.**

One comparison document contains one type of diff. The `comparisonMode` enum expands:

| Mode | Documents compared | Diff section | What it shows |
|------|-------------------|-------------|---------------|
| `temporal` | hdf-results vs hdf-results | `requirementDiffs[]` | Fixed, regressed, new, absent (already built) |
| `baseline` | hdf-results vs hdf-results | `requirementDiffs[]` | Asymmetric — reference vs target (already built) |
| `fleet` | hdf-results[] vs reference | `requirementDiffs[]` | N systems vs reference (already built) |
| `multiSource` | hdf-results vs hdf-results | `requirementDiffs[]` | Different tools, same target (already built) |
| `systemDrift` | hdf-system vs hdf-system | `componentDiffs[]` | Added/removed/modified components, SBOM changes, boundary changes |
| `baselineEvolution` | hdf-baseline vs hdf-baseline | `requirementChanges[]` | New/removed/modified requirements between versions |

Schema additions:
- Top-level `systemRef` field (confirmed Decision — auditor needs system boundary context)
- Optional `componentDiffs[]` section (for system comparison)
- Optional `packageDiffs[]` section (for SBOM comparison within system diff)
- Optional `requirementChanges[]` section (for baseline comparison)

### Rationale

1. **One format for "what changed."** Regardless of what kind of HDF document changed,
   the comparison document captures it in a structured, auditable way.

2. **SBOM diff is a sub-feature of system comparison.** When comparing two system
   documents, one aspect that may change is the SBOM. Package additions/removals/updates
   are captured in `componentDiffs[].packageDiffs[]`.

3. **Baseline evolution matters.** When DISA publishes STIG V1R2, organizations need
   to understand what requirements changed from V1R1. This is a comparison, same as any other.

4. **Cross-environment use cases.** Diffing dev vs prod deployments answers "is prod
   configured the same as what we tested in dev?" This is not temporal — it's
   cross-environment at a single point in time.

---

## Decision 12: SBOM Library Adoption (Both Formats, Day One)

**Date:** 2026-03-15
**Status:** Decided

### Research

Full report: `docs/reviews/2026-03-15-sbom-library-research.md`

Two agents surveyed the TypeScript and Go SBOM library ecosystems. Key finding:
the Go ecosystem has a clear winner (`protobom`), while the TypeScript ecosystem
has gaps that require custom code.

### Decision

Support both CycloneDX and SPDX from day one. Adopt existing libraries where
possible, build minimal custom code where gaps exist.

**Go adoption:**

| Need | Library |
|------|---------|
| Unified CycloneDX + SPDX parse + diff | `github.com/protobom/protobom` (OpenSSF, 320 stars) |
| PURL handling | `github.com/package-url/packageurl-go` |

protobom parses both CycloneDX (1.4–1.6) and SPDX (2.3) into a unified Protocol Buffer
model with built-in diff primitives: `Node.Diff()`, `NodeList.Intersect()`,
`NodeList.Union()`, `NodeList.GetMatchingNode()`.

**TypeScript adoption:**

| Need | Library |
|------|---------|
| CycloneDX data models + validation | `@cyclonedx/cyclonedx-library` (115K/wk) |
| PURL handling | `packageurl-js` (254K/wk) |
| CycloneDX JSON parsing | `JSON.parse()` + Ajv against bundled schemas |
| SPDX JSON parsing | `JSON.parse()` + Ajv against SPDX JSON schemas |
| SBOM diff | Custom (~100-200 lines): normalize both formats into common component model, index by PURL, compare versions |

### Rationale

1. **Both formats share the same diff algorithm.** Once components are extracted into
   a common model (PURL + version + name), the diff logic is format-agnostic. There's
   no reason to defer SPDX when the marginal effort is a thin JSON parser.

2. **protobom eliminates Go complexity.** One library handles both formats transparently.
   OpenSSF backing provides institutional stability.

3. **TS gap is small.** No unified JS/TS SBOM library exists, but CycloneDX JSON and
   SPDX JSON are both just JSON. Parse, validate with Ajv, normalize into common model.
   The custom code is ~100-200 lines, not a library.

### Downstream Impact

- hdf-system: components gain `sbomRef` and `sbomFormat` fields
- hdf-results: targets gain optional `sbomRef` field
- hdf-comparison: system-level diff includes `packageDiffs[]`
- hdf-evidence-package: contents[] supports `type: "sbom"` with `format` field
- All converters: SCA tools (Grype, Trivy) populate `tags.purl` (already do this)
- OSCAL converters: multiple document types affected (SSP ↔ hdf-system, SAR ↔ hdf-results, POA&M ↔ hdf-amendments)
