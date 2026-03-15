# HDF-Libs: Flatten Overlays — Architecture Design

**Date:** 2026-02-25
**Beads Card:** hdf-libs-sqb (Library 5: hdf-extension-graph) — first deliverable
**Consumer Bug:** P0 — 741 controls shown instead of 247 (wrong NA/NR counts in consuming application)
**Based on:** 6 research agents analyzing inspecjs, hdf-libs, InSpec spec, real fixtures, algorithm options, and downstream consumption

---

## Problem Statement

InSpec exec-json output with overlays or wrapper profiles contains multiple profiles (baselines) in a flat array. Consumers that naively iterate all baselines get duplicate controls. A 3-layer overlay with 247 unique controls produces 741 (3×247). A wrapper profile depending on k8s (81) + rhel9 (452) produces 1067 (534+81+0+452) instead of 534.

No existing library in the hdf-libs ecosystem handles flattening. The old inspecjs `contextualizeEvaluation()` did this via a graph structure, but it was overengineered for the actual data patterns and had confusing inverted naming.

---

## Two Kinds of Nesting in InSpec JSON

### Deep Nesting (Overlay Chain)

A profile customizes a base via `include_controls`. Each layer overrides specific control properties (code, impact, tags). The chain is linear: base → overlay1 → overlay2.

```
Three_Layer_RHEL7_Overlay_Example.json:
  profiles[0]: second-layer-overlay    (247 controls, 0 results)
   └→ profiles[1]: first-layer-overlay (247 controls, 0 results)
       └→ profiles[2]: rhel7-baseline  (247 controls, 247 results)

ALL profiles share the SAME 247 control IDs.
Results ONLY on the deepest base.
Metadata (impact, tags, desc) identical across all layers.
Only `code` differs: 2/247 controls overridden.
Correct output: 247 controls.
```

**Real-world examples:** CMS overlays on DISA STIGs, project-specific customizations.

### Wide Nesting (Wrapper/Meta-Profile)

A profile aggregates multiple independent bases. The wrapper's controls are the union of all children. Children have disjoint control IDs.

```
wrapper.json:
  profiles[0]: wrapper                 (534 controls, 1 result)
   ├→ profiles[1]: k8s-node-stig      (81 controls, 81 results)
   │    └→ profiles[2]: inspec-k8s-node (0 controls, resource pack)
   └→ profiles[3]: rhel9-stig-baseline (452 controls, 452 results)

Profile[0] = union of children (81 + 452 + 1 own = 534).
Children have DISJOINT control IDs.
Results on the children, not the wrapper.
Correct output: 534 controls (deduplicated).
```

**Real-world examples:** Compliance wrappers running multiple STIGs in one scan.

### Hybrid (Deep + Wide)

A wrapper aggregates multiple bases, where some bases are themselves overlay chains. The algorithm must handle both patterns simultaneously.

```
Hypothetical:
  wrapper (depends on cms-overlay + k8s-baseline)
   ├→ cms-overlay (overlays rhel7-baseline) ← DEEP
   │    └→ rhel7-baseline
   └→ k8s-baseline ← WIDE (disjoint IDs)
```

---

## Research Findings

### From Real Fixture Analysis (6 fixtures examined)

| Pattern | Fixture | Profiles | Controls/Profile | Code Diffs | Impact/Tag Diffs | Results Location |
|---------|---------|----------|-----------------|------------|-----------------|-----------------|
| Deep 3-layer | Three_Layer_RHEL7 | 3 | 247 each | 2 | 0 | Deepest only |
| Deep 2-layer | postgres_overlay | 2 | 80 each | 19 | 0 | Deepest only |
| Deep 2-layer | windows_2012r2 | 2 | 338 each | 49 | 0 | Deepest only |
| Deep 3-layer | triple_overlay_oracle | 3 | 5 each | varies | 0 | Deepest only |
| Wide | wrapper.json | 4 | 534/81/0/452 | N/A | N/A | Children |
| Wide | meta-profile.json | 3 | 71/71/0 | N/A | N/A | None (sample) |

**Universal patterns confirmed across ALL fixtures:**
1. Results live ONLY on the deepest base profile (overlay profiles have `results: []`)
2. Metadata (impact, tags, desc, title) is ALWAYS identical across all profiles for the same control ID
3. Only `code` actually differs between overlay and base controls
4. InSpec resolves overrides at execution time — base metadata already reflects overlay changes

### From InSpec Spec Research

- `parent_profile` (string) on child points UP to includer — set by InSpec runtime
- `depends` on parent points DOWN to dependencies — declared in inspec.yml
- They are inverse relationships
- `parent_profile` is single-valued (no diamond inheritance in InSpec's model)
- Overlays can: override properties, skip controls, add new controls
- Results only on base profile — confirmed as intended behavior (InSpec issue #5294)

### From Algorithm Research

**InSpec's model = single-parent inheritance (like JavaScript prototype chains).**

| Algorithm | Complexity | Lines | Handles Both Patterns? | Recommended? |
|-----------|-----------|-------|----------------------|-------------|
| Simple Map merge | O(N) | ~40-50 | Yes | **YES** |
| Graph (old inspecjs) | O(N) | ~120 | Yes (overengineered) | No |
| Toposort + reduce | O(V+E+N) | ~60 | Yes (overkill for trees) | No |
| Recursive DFS | O(N) | ~35 | Yes | Acceptable alternative |

**Recommendation: Simple Map merge.** Same correctness as all others, least code, easiest to test, trivially extensible. Graph approach is overengineered for single-parent trees. Toposort is the right tool for DAGs but InSpec doesn't produce DAGs.

---

## Architecture

### Package: `hdf-parsers`

**Why hdf-parsers:**
- README says "Parse and **flatten** HDF documents" — this was always the plan
- Already depends on `@mitre/hdf-schema` (types needed)
- Conceptually: parse → validate → flatten is a natural pipeline
- hdf-utilities is a generic utility belt (no HDF type awareness)

### New Files

```
hdf-parsers/
  typescript/
    src/
      flatten.ts          # flattenOverlays() + mergeRequirement() + buildBaselineTree()
    test/
      flatten.test.ts     # Unit + integration tests
    index.ts              # Add export
  go/
    flatten.go            # Go implementation (separate card, differential testing)
    flatten_test.go
```

---

## API Design

```typescript
import type { HdfResults, EvaluatedBaseline, EvaluatedRequirement } from '@mitre/hdf-schema';

// ── Public API ──────────────────────────────────────────────

/**
 * Flatten overlay/wrapper baselines in an HDF Results document.
 *
 * Handles two nesting patterns:
 * - Deep (overlay chain): multiple baselines share control IDs via parentBaseline.
 *   Produces one merged baseline per chain. Topmost overlay metadata + base results.
 * - Wide (wrapper): one baseline depends on multiple independent bases.
 *   Produces one baseline with all controls aggregated.
 *
 * Baselines with no parent-child relationships pass through unchanged.
 */
export function flattenOverlays(results: HdfResults): FlattenResult;

export interface FlattenResult {
  /** Flattened HdfResults with deduplicated baselines */
  results: HdfResults
  /** What was merged (debugging/UI) */
  metadata: FlattenMetadata
}

export interface FlattenMetadata {
  originalBaselineCount: number
  flattenedBaselineCount: number
  /** Per-root merge info */
  merges: BaselineMerge[]
  /** Warnings (orphans, cycles, etc.) */
  warnings: string[]
}

export interface BaselineMerge {
  /** Root baseline name (the one kept in output) */
  rootBaseline: string
  /** Overlay/child baselines absorbed, ordered base→topmost */
  absorbedBaselines: string[]
  /** Control counts before/after dedup */
  controlsBefore: number
  controlsAfter: number
  /** 'deep' (overlay chain, shared IDs) | 'wide' (wrapper, disjoint IDs) | 'hybrid' */
  pattern: 'deep' | 'wide' | 'hybrid'
}
```

---

## Algorithm

### Phase 1: Build Baseline Tree

```
Input: results.baselines[] (flat array, may be HDF v2 or converted v1)

1. Index baselines by name: Map<name, EvaluatedBaseline>

2. Build parent→children adjacency:
   For each baseline B:
     if B.parentBaseline is defined and exists in index:
       children[B.parentBaseline].push(B.name)

   Note: parentBaseline points UP (child → includer).
   In InSpec exec-json, the BASE profile has parentBaseline = overlay name.
   The TOP overlay has parentBaseline = undefined (it's the root).

3. Find roots: baselines where parentBaseline is undefined/null/missing-from-index.
   These are the top-level profiles the user actually executed.

4. Detect cycles: while building children map, track visited set. If a baseline
   appears twice in a chain, break the cycle and add warning.
```

### Phase 2: For Each Root, Collect Its Tree

```
For each root R:
  1. Collect all descendants via BFS/DFS on children map
  2. Order the chain: root first, then children in dependency order
     (for deep: root → overlay1 → overlay2 → base)
     (for wide: root, then each independent child subtree)
  3. Classify pattern:
     - If children share >50% control IDs with root → 'deep'
     - If children have mostly disjoint IDs → 'wide'
     - Mixed → 'hybrid'
```

### Phase 3: Merge Requirements

```
For each tree rooted at R:
  1. merged = new Map<controlId, EvaluatedRequirement>()

  2. Walk tree BOTTOM-UP (base/leaves first, root/overlay last):
     For each baseline in bottom-up order:
       For each requirement in baseline.requirements:
         if merged.has(requirement.id):
           merged.set(id, mergeRequirement(merged.get(id), requirement))
         else:
           merged.set(id, clone(requirement))

  3. Result: merged.values() = deduplicated requirements
     - For deep: overlay fields override base fields (overlay processed AFTER base)
     - For wide: disjoint IDs simply aggregate (no conflict)
```

### mergeRequirement(existing, incoming)

Based on real fixture analysis — InSpec already resolves metadata at execution time, so most fields are identical. The merge handles the cases where they differ:

```
function mergeRequirement(existing, incoming):
  result = { ...existing }  // shallow copy of what we have

  // Results: take whichever has non-empty results (base has them, overlay doesn't)
  if incoming.results?.length > 0:
    result.results = incoming.results

  // Code: take incoming if non-empty (overlay override)
  if incoming.code and incoming.code.trim() !== '':
    result.code = incoming.code

  // Scalars: take incoming if defined (overlay may change impact/severity)
  if incoming.impact !== undefined: result.impact = incoming.impact
  if incoming.title: result.title = incoming.title
  if incoming.desc: result.desc = incoming.desc

  // Tags: shallow merge (incoming keys override, existing keys preserved)
  if incoming.tags:
    result.tags = { ...existing.tags, ...incoming.tags }

  // Descriptions: merge by label
  if incoming.descriptions?.length:
    const descMap = new Map(existing.descriptions?.map(d => [d.label, d]))
    for (const d of incoming.descriptions):
      if d.data or !descMap.has(d.label):  // non-empty or new label
        descMap.set(d.label, d)
    result.descriptions = [...descMap.values()]

  return result
```

**Why bottom-up processing order:** The tree is walked from leaves (base profiles with results) toward the root (top overlay). Each layer's fields override the previous. Since the top overlay is processed LAST, it "wins" for metadata/code. Since the base is processed FIRST, its results are preserved (overlays have empty results, so the merge keeps the base's).

### Phase 4: Produce Output

```
For each root tree:
  Create one EvaluatedBaseline:
    name: root baseline's name (the profile the user executed)
    requirements: merged requirements from Phase 3
    parentBaseline: undefined (flattened — no more hierarchy)
    depends: undefined (resolved)
    All other metadata: from root baseline (title, version, checksum, etc.)

For standalone baselines (not part of any tree):
  Pass through unchanged

Return new HdfResults replacing baselines[] with flattened set
```

---

## Handling Both Patterns

### Deep (Overlay Chain) — Example

```
Input baselines:
  [0] "overlay2" (parentBaseline: undefined, 247 controls, 0 results)
  [1] "overlay1" (parentBaseline: "overlay2", 247 controls, 0 results)
  [2] "base"     (parentBaseline: "overlay1", 247 controls, 247 results)

Tree: overlay2 → overlay1 → base
Bottom-up order: base, overlay1, overlay2

Merge:
  1. Start with base's 247 controls (all have results)
  2. Apply overlay1's 247 controls (mostly no-ops; 2 code overrides)
  3. Apply overlay2's 247 controls (mostly no-ops; code already resolved)

Output: 1 baseline "overlay2" with 247 controls, all with results
```

### Wide (Wrapper) — Example

```
Input baselines:
  [0] "wrapper"  (parentBaseline: undefined, 534 controls, 1 result)
  [1] "k8s"      (parentBaseline: "wrapper", 81 controls, 81 results)
  [2] "k8s-node" (parentBaseline: "k8s", 0 controls, resource pack)
  [3] "rhel9"    (parentBaseline: "wrapper", 452 controls, 452 results)

Tree: wrapper → {k8s → k8s-node, rhel9}
Bottom-up order: k8s-node, k8s, rhel9, wrapper

Merge:
  1. Start with k8s-node (0 controls → empty map)
  2. Apply k8s (81 controls with results → map has 81)
  3. Apply rhel9 (452 controls with results → map has 533, disjoint)
  4. Apply wrapper (534 controls → overrides 533 existing + adds 1 own)

Output: 1 baseline "wrapper" with 534 controls, all with results
```

### Hybrid — Naturally Handled

The algorithm doesn't distinguish deep from wide during processing. Bottom-up merge handles both:
- Overlapping IDs → later layer overrides (deep behavior)
- Disjoint IDs → simply aggregates (wide behavior)

The `pattern` field in metadata is informational only, computed after the merge for debugging/display.

---

## Edge Cases

| Case | Handling |
|------|----------|
| No overlays (single baseline) | Pass through unchanged |
| Multiple independent baselines (no parentBaseline) | Each is its own root, pass through |
| Missing parentBaseline on all | All standalone, no merging |
| Orphan child (parentBaseline name not in baselines[]) | Treat as root, add warning |
| Circular parentBaseline | Detect during tree build, break cycle, add warning |
| Control only in base, not in overlay | Preserved from base |
| Control only in overlay, not in base | Added as new control |
| Empty requirements array | Valid — contributes nothing to merge |
| Profile with status='failed'/'skipped' | Skip — don't merge failed profiles. Add warning. |
| `inspec-k8s-node` resource pack (0 controls) | Valid — contributes nothing, pass through |
| v1 format (profiles/controls) vs v2 (baselines/requirements) | flattenOverlays works on v2 types; v1→v2 conversion happens first |

---

## What We're NOT Building

- **No graph structure** (ContextualizedControl/ContextualizedProfile) — flat merge sufficient
- **No `full_code` concatenation** — can be added later if UI needs it
- **No `root` traversal** — bottom-up merge eliminates the need
- **No Go implementation this card** — TypeScript first, Go follows
- **No C3 linearization / toposort** — InSpec is single-parent, not DAG

These can be added later. The `FlattenMetadata` provides enough provenance info for now.

---

## Test Plan (TDD — Tests First)

### Unit Tests

```
describe('flattenOverlays')

  describe('passthrough (no overlays)')
    it('returns unchanged results for single baseline')
    it('returns unchanged results for multiple independent baselines')
    it('metadata shows 0 merges, counts match')

  describe('deep nesting (overlay chain)')
    describe('two-layer')
      it('deduplicates to one baseline')
      it('preserves base results on merged controls')
      it('takes overlay code when non-empty')
      it('keeps base code when overlay code is empty')
      it('preserves controls only in base')
      it('adds controls only in overlay')
      it('metadata shows 1 merge, pattern=deep')

    describe('three-layer')
      it('deduplicates to one baseline')
      it('topmost code wins over intermediate and base')
      it('base results survive through all layers')
      it('metadata shows absorbed baselines in order')

  describe('wide nesting (wrapper/meta-profile)')
    it('aggregates disjoint children into wrapper')
    it('preserves child results in merged controls')
    it('wrapper own controls included')
    it('metadata shows pattern=wide')

  describe('hybrid (deep + wide)')
    it('handles wrapper with overlay chain children')
    it('overlay chain flattened, then merged into wrapper')

  describe('merge semantics')
    it('incoming results replace empty results')
    it('existing results preserved when incoming is empty')
    it('tags shallow-merged (incoming keys override)')
    it('descriptions merged by label')
    it('impact from incoming always wins')

  describe('edge cases')
    it('orphan child treated as root with warning')
    it('circular parentBaseline detected with warning')
    it('empty requirements array produces empty merge')
    it('skipped/failed profile excluded with warning')
    it('resource pack (0 controls) handled cleanly')

  describe('integration — real fixtures')
    it('Three_Layer_RHEL7: 3 profiles → 1 baseline, 247 controls')
    it('wrapper.json: 4 profiles → 1 baseline, 534 controls')
    it('meta-profile.json: handles wide nesting correctly')
```

---

## Implementation Order

1. **Create branch** `feature/flatten-overlays` off `hdf-libs-development`
2. **Create/update beads card** under `hdf-libs-sqb` epic
3. **Write failing tests** in `hdf-parsers/typescript/test/flatten.test.ts` — ALL must fail (RED)
4. **Implement** `hdf-parsers/typescript/src/flatten.ts` — make tests pass (GREEN)
5. **Export** from `hdf-parsers/typescript/index.ts`
6. **Run full hdf-parsers test suite** — no regressions
7. **Commit** to feature branch
8. **Wire into consuming application** (separate card)
9. **Go implementation** (separate card)

---

## Risk Assessment

| Risk | Mitigation |
|------|------------|
| InSpec format varies across versions | Test with multiple real fixtures (2-layer, 3-layer, wrapper) |
| v1 vs v2 field names | flattenOverlays works on v2 only; v1→v2 converter runs first |
| Some files use `depends` but not `parentBaseline` | Build tree from `parentBaseline` (set by InSpec runtime, reliable) |
| Future InSpec changes to overlay model | Algorithm is simple enough to adapt; metadata/warnings aid debugging |
| Performance at scale | O(N) merge with Map — sub-millisecond even at 10K controls |
