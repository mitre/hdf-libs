import type { HdfResults, EvaluatedBaseline, EvaluatedRequirement } from '@mitre/hdf-schema';

/**
 * Wraps an EvaluatedRequirement with bidirectional extension links.
 */
export class ContextualizedRequirement {
  /** The original requirement data. */
  readonly data: EvaluatedRequirement;

  /** The baseline this requirement belongs to. */
  readonly sourcedFrom: ContextualizedBaseline;

  /** Requirements in parent baselines that this requirement extends (overlays). */
  readonly extendsFrom: ContextualizedRequirement[] = [];

  /** Requirements in child baselines that extend this requirement. */
  readonly extendedBy: ContextualizedRequirement[] = [];

  constructor(data: EvaluatedRequirement, sourcedFrom: ContextualizedBaseline) {
    this.data = data;
    this.sourcedFrom = sourcedFrom;
  }
}

/**
 * Wraps an EvaluatedBaseline with bidirectional extension links
 * and contextualized requirements.
 */
export class ContextualizedBaseline {
  /** The original baseline data. */
  readonly data: EvaluatedBaseline;

  /** The HdfResults this baseline was sourced from. */
  readonly sourcedFrom: HdfResults;

  /** Parent baselines that this baseline extends. */
  readonly extendsFrom: ContextualizedBaseline[] = [];

  /** Child baselines that extend this baseline. */
  readonly extendedBy: ContextualizedBaseline[] = [];

  /** Contextualized wrappers for each requirement in this baseline. */
  readonly requirements: ContextualizedRequirement[];

  constructor(data: EvaluatedBaseline, sourcedFrom: HdfResults) {
    this.data = data;
    this.sourcedFrom = sourcedFrom;
    this.requirements = data.requirements.map(
      (req) => new ContextualizedRequirement(req, this)
    );
  }
}

/**
 * A bidirectional extension graph built from an HDF Results file.
 * Contains all baselines and requirements with their extension relationships.
 */
export class ExtensionGraph {
  /** All contextualized baselines in the graph. */
  readonly baselines: readonly ContextualizedBaseline[];

  /** All contextualized requirements across all baselines. */
  readonly requirements: readonly ContextualizedRequirement[];

  constructor(
    baselines: readonly ContextualizedBaseline[],
    requirements: readonly ContextualizedRequirement[]
  ) {
    this.baselines = baselines;
    this.requirements = requirements;
  }

  /** Find a baseline by name. Returns undefined if not found. */
  findBaseline(name: string): ContextualizedBaseline | undefined {
    return this.baselines.find((b) => b.data.name === name);
  }

  /** Find all requirements with the given id across all baselines. */
  findRequirements(id: string): ContextualizedRequirement[] {
    return this.requirements.filter((r) => r.data.id === id);
  }

  /** Baselines that have no parent (root of extension chains). */
  get rootBaselines(): ContextualizedBaseline[] {
    return this.baselines.filter((b) => !b.data.parentBaseline);
  }
}

/**
 * Build a bidirectional extension graph from an HDF Results file.
 *
 * Four phases:
 * 1. Wrap each EvaluatedBaseline in a ContextualizedBaseline
 * 2. Link baselines via parentBaseline name matching (bidirectional)
 * 3. Collect all requirements into a flat array
 * 4. Link requirements by id matching across linked baselines
 */
export function buildExtensionGraph(results: HdfResults): ExtensionGraph {
  // Phase 1: Wrap baselines
  const baselineMap = new Map<string, ContextualizedBaseline>();
  const baselines: ContextualizedBaseline[] = [];

  for (const baseline of results.baselines) {
    const ctx = new ContextualizedBaseline(baseline, results);
    baselines.push(ctx);
    baselineMap.set(baseline.name, ctx);
  }

  // Phase 2: Link baselines via parentBaseline
  for (const ctx of baselines) {
    const parentName = ctx.data.parentBaseline;
    if (parentName) {
      const parent = baselineMap.get(parentName);
      if (parent) {
        ctx.extendsFrom.push(parent);
        parent.extendedBy.push(ctx);
      }
    }
  }

  // Phase 3: Collect all requirements
  const allRequirements: ContextualizedRequirement[] = [];
  for (const ctx of baselines) {
    allRequirements.push(...ctx.requirements);
  }

  // Phase 4: Link requirements by id across linked baselines
  for (const ctx of baselines) {
    if (ctx.extendsFrom.length === 0) {
      continue;
    }
    for (const childReq of ctx.requirements) {
      for (const parentBaseline of ctx.extendsFrom) {
        const parentReq = parentBaseline.requirements.find(
          (r) => r.data.id === childReq.data.id
        );
        if (parentReq) {
          childReq.extendsFrom.push(parentReq);
          parentReq.extendedBy.push(childReq);
        }
      }
    }
  }

  return new ExtensionGraph(baselines, allRequirements);
}
