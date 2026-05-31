import type { HDFResults, EvaluatedBaseline, EvaluatedRequirement } from '@mitre/hdf-schema';

/** Fields compared for modification detection between overlay and parent. */
const TRACKED_FIELDS: readonly (string & keyof EvaluatedRequirement)[] = ['impact', 'title', 'severity', 'effectiveImpact', 'disposition'];

/** A detected change between an overlay requirement and its parent. */
export interface Modification {
  field: string;
  originalValue: unknown;
  newValue: unknown;
  inBaseline: string;
}

/**
 * Wraps an EvaluatedRequirement with bidirectional extension links
 * and derived properties for navigating extension chains.
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

  /** The root (base) requirement at the bottom of the extension chain. */
  get root(): ContextualizedRequirement {
    if (this.extendsFrom.length === 0) {
      return this;
    }
    // Walk to the first parent's root (first match, like Heimdall2)
    return this.extendsFrom[0]!.root;
  }

  /** True if this overlay adds no new code (empty/undefined or matches root). */
  get isRedundant(): boolean {
    if (this.extendsFrom.length === 0) {
      return false;
    }
    const code = this.data.code;
    if (!code) {
      return true;
    }
    return code === this.root.data.code;
  }

  /**
   * Full code concatenated from all layers, with baseline name headers.
   * Skips redundant overlay layers. Returns empty string if no code exists.
   */
  get fullCode(): string {
    if (this.isRedundant && this.extendsFrom.length > 0) {
      return this.extendsFrom[0]!.fullCode;
    }
    const code = this.data.code;
    if (!code) {
      return '';
    }
    const header = `# ${this.sourcedFrom.data.name}\n${code}`;
    if (this.extendsFrom.length === 0) {
      return header;
    }
    const parentCode = this.extendsFrom[0]!.fullCode;
    return parentCode ? `${header}\n\n${parentCode}` : header;
  }

  /** Ordered chain of baselines from root to this requirement's baseline. */
  get extensionChain(): ContextualizedBaseline[] {
    if (this.extendsFrom.length === 0) {
      return [this.sourcedFrom];
    }
    return [...this.extendsFrom[0]!.extensionChain, this.sourcedFrom];
  }

  /** Fields that differ between this requirement and its immediate parent. */
  get modifications(): Modification[] {
    if (this.extendsFrom.length === 0) {
      return [];
    }
    const parent = this.extendsFrom[0]!;
    const mods: Modification[] = [];
    for (const field of TRACKED_FIELDS) {
      const parentVal = (parent.data as Record<string, unknown>)[field];
      const thisVal = (this.data as Record<string, unknown>)[field];
      if (parentVal !== thisVal) {
        mods.push({
          field,
          originalValue: parentVal,
          newValue: thisVal,
          inBaseline: this.sourcedFrom.data.name,
        });
      }
    }
    return mods;
  }
}

/**
 * Wraps an EvaluatedBaseline with bidirectional extension links
 * and contextualized requirements.
 */
export class ContextualizedBaseline {
  /** The original baseline data. */
  readonly data: EvaluatedBaseline;

  /** The HDFResults this baseline was sourced from. */
  readonly sourcedFrom: HDFResults;

  /** Parent baselines that this baseline extends. */
  readonly extendsFrom: ContextualizedBaseline[] = [];

  /** Child baselines that extend this baseline. */
  readonly extendedBy: ContextualizedBaseline[] = [];

  /** Contextualized wrappers for each requirement in this baseline. */
  readonly requirements: ContextualizedRequirement[];

  constructor(data: EvaluatedBaseline, sourcedFrom: HDFResults) {
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
export function buildExtensionGraph(results: HDFResults): ExtensionGraph {
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
