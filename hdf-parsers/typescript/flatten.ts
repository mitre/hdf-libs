import type { HdfResults, EvaluatedBaseline, EvaluatedRequirement } from '@mitre/hdf-schema';

// ── Public Types ────────────────────────────────────────────

export interface FlattenResult {
  results: HdfResults;
  metadata: FlattenMetadata;
}

export interface FlattenMetadata {
  originalBaselineCount: number;
  flattenedBaselineCount: number;
  merges: BaselineMerge[];
  warnings: string[];
}

export interface BaselineMerge {
  rootBaseline: string;
  absorbedBaselines: string[];
  controlsBefore: number;
  controlsAfter: number;
  pattern: 'deep' | 'wide' | 'hybrid';
}

// ── Internal Helpers ───────────────────────────────────────

/** BFS from root, returns names in top-down order. Cycle-safe. */
function collectTree(root: string, childrenMap: Map<string, string[]>): string[] {
  const order: string[] = [];
  const seen = new Set<string>();
  const queue = [root];
  while (queue.length > 0) {
    const name = queue.shift()!;
    if (seen.has(name)) continue;
    seen.add(name);
    order.push(name);
    for (const child of (childrenMap.get(name) || [])) {
      queue.push(child);
    }
  }
  return order;
}

/** Classify merge pattern based on tree shape */
function detectPattern(root: string, childrenMap: Map<string, string[]>): 'deep' | 'wide' | 'hybrid' {
  const rootChildren = childrenMap.get(root) || [];
  if (rootChildren.length <= 1) {
    return 'deep';
  }
  for (const child of rootChildren) {
    if ((childrenMap.get(child) || []).length > 0) {
      return 'hybrid';
    }
  }
  return 'wide';
}

/** Merge incoming requirement fields onto existing */
function mergeRequirement(
  existing: EvaluatedRequirement,
  incoming: EvaluatedRequirement
): EvaluatedRequirement {
  const result: EvaluatedRequirement = { ...existing };

  // Impact: incoming always wins (required field, always present)
  result.impact = incoming.impact;

  // Results: keep whichever is non-empty (base has them, overlay doesn't)
  if (incoming.results && incoming.results.length > 0) {
    result.results = incoming.results;
  }

  // Code: incoming wins if non-empty
  if (incoming.code && incoming.code.trim() !== '') {
    result.code = incoming.code;
  }

  // Tags: shallow merge (incoming keys override)
  if (incoming.tags) {
    result.tags = { ...existing.tags, ...incoming.tags };
  }

  // Severity: incoming wins if present, else keep existing
  if (incoming.severity !== undefined) {
    result.severity = incoming.severity;
  }

  // EffectiveStatus: incoming wins only if it has results (otherwise its
  // effectiveStatus is a computed artifact from empty results, not intentional).
  // Overlays typically have empty results — the base has the real test results.
  if (incoming.effectiveStatus !== undefined && incoming.results && incoming.results.length > 0) {
    result.effectiveStatus = incoming.effectiveStatus;
  }

  // Descriptions: merge by label (incoming overrides same label)
  if (incoming.descriptions && incoming.descriptions.length > 0) {
    const descMap = new Map(
      (existing.descriptions || []).map(d => [d.label, d])
    );
    for (const d of incoming.descriptions) {
      descMap.set(d.label, d);
    }
    result.descriptions = [...descMap.values()];
  }

  return result;
}

/**
 * Resolve parentBaseline for a baseline.
 * InSpec parent_profile can use depends-name aliases (e.g., 'k8s' instead of
 * 'k8s-node-stig-baseline'). When the value isn't a direct profile name,
 * find who depends on this baseline — that's the actual parent.
 */
function resolveParentBaseline(
  b: EvaluatedBaseline,
  byName: Map<string, EvaluatedBaseline>,
  allBaselines: EvaluatedBaseline[]
): string | undefined {
  if (!b.parentBaseline) return undefined;
  if (byName.has(b.parentBaseline)) return b.parentBaseline;

  // Alias resolution: find the profile whose depends array includes this baseline
  for (const candidate of allBaselines) {
    if (candidate.depends?.some((d) => d.name === b.name)) {
      return candidate.name;
    }
  }
  return undefined; // orphan
}

// ── Public API ──────────────────────────────────────────────

/**
 * Flatten overlay/wrapper baselines in an HDF Results document.
 *
 * Handles:
 * - Deep nesting (overlay chains with shared control IDs via parentBaseline)
 * - Wide nesting (wrapper profiles aggregating independent bases)
 * - Hybrid (both patterns in one document)
 *
 * @param results - Parsed HDF Results (from parseResults() or equivalent)
 * @returns FlattenResult with flattened data and merge metadata
 */
export function flattenOverlays(results: HdfResults): FlattenResult {
  const { baselines } = results;
  const warnings: string[] = [];
  const merges: BaselineMerge[] = [];

  if (!baselines || baselines.length === 0) {
    return {
      results: { ...results, baselines: [] },
      metadata: {
        originalBaselineCount: 0,
        flattenedBaselineCount: 0,
        merges: [],
        warnings: [],
      },
    };
  }

  // Index baselines by name
  const byName = new Map<string, EvaluatedBaseline>();
  for (const b of baselines) {
    if (byName.has(b.name)) {
      warnings.push(`Duplicate baseline name "${b.name}" — later entry overwrites earlier`);
    }
    byName.set(b.name, b);
  }

  // Resolve parentBaseline aliases and build parent map
  const resolvedParent = new Map<string, string | undefined>();
  for (const b of baselines) {
    const parent = resolveParentBaseline(b, byName, baselines);
    resolvedParent.set(b.name, parent);
    if (b.parentBaseline && !parent) {
      warnings.push(
        `Baseline "${b.name}" references nonexistent parent "${b.parentBaseline}"`
      );
    }
  }

  // Build parent → children adjacency using resolved parents
  const childrenMap = new Map<string, string[]>();
  for (const b of baselines) {
    const parent = resolvedParent.get(b.name);
    if (parent) {
      const list = childrenMap.get(parent) || [];
      list.push(b.name);
      childrenMap.set(parent, list);
    }
  }

  // Find roots: no resolved parent
  const roots: string[] = [];
  const visited = new Set<string>();

  for (const b of baselines) {
    if (!resolvedParent.get(b.name)) {
      roots.push(b.name);
    }
  }

  // Mark reachable from roots (iterative DFS to avoid stack overflow on deep trees)
  function markReachable(start: string): void {
    const stack = [start];
    while (stack.length > 0) {
      const name = stack.pop()!;
      if (visited.has(name)) continue;
      visited.add(name);
      const children = childrenMap.get(name);
      if (children) {
        for (const child of children) {
          stack.push(child);
        }
      }
    }
  }
  for (const r of roots) {
    markReachable(r);
  }

  // Detect cycles: unvisited baselines are in cycles
  for (const b of baselines) {
    if (!visited.has(b.name)) {
      warnings.push(`Circular parentBaseline detected involving "${b.name}"`);
      roots.push(b.name);
      markReachable(b.name);
    }
  }

  // Process each root tree
  const flatBaselines: EvaluatedBaseline[] = [];

  for (const rootName of roots) {
    const root = byName.get(rootName)!;
    const treeNames = collectTree(rootName, childrenMap);

    if (treeNames.length === 1) {
      // Standalone baseline — pass through unchanged (preserve depends)
      flatBaselines.push(root);
      continue;
    }

    // Bottom-up order: reverse top-down BFS
    const bottomUp = [...treeNames].reverse();

    // Merge requirements across the tree
    const merged = new Map<string, EvaluatedRequirement>();
    let controlsBefore = 0;
    const absorbed: string[] = [];

    for (const name of bottomUp) {
      const b = byName.get(name)!;
      controlsBefore += b.requirements.length;
      if (name !== rootName) {
        absorbed.push(name);
      }
      for (const req of b.requirements) {
        if (merged.has(req.id)) {
          merged.set(req.id, mergeRequirement(merged.get(req.id)!, req));
        } else {
          merged.set(req.id, { ...req });
        }
      }
    }

    const mergedReqs = [...merged.values()];
    const pattern = detectPattern(rootName, childrenMap);

    merges.push({
      rootBaseline: rootName,
      absorbedBaselines: absorbed,
      controlsBefore,
      controlsAfter: mergedReqs.length,
      pattern,
    });

    const out: EvaluatedBaseline = {
      ...root,
      requirements: mergedReqs,
    };
    delete out.parentBaseline;
    delete out.depends;
    flatBaselines.push(out);
  }

  return {
    results: { ...results, baselines: flatBaselines },
    metadata: {
      originalBaselineCount: baselines.length,
      flattenedBaselineCount: flatBaselines.length,
      merges,
      warnings,
    },
  };
}
