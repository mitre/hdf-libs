import type { BaselineRequirement, Description, Reference } from '@mitre/hdf-schema';

export type PreferSide = 'current' | 'upstream' | undefined;

/**
 * Smart-merge a current and upstream requirement.
 *
 * Default (no prefer):
 *   - ID: always upstream
 *   - Scalars (title, impact, severity): upstream wins
 *   - Tags: union, upstream wins key conflicts
 *   - Descriptions: union by label, upstream wins on same label
 *   - Code: current (preserve tests)
 *   - Refs: union (deduplicated)
 *
 * prefer "current": scalars from current, current wins tag/desc conflicts
 * prefer "upstream": everything from upstream (full replacement)
 */
export function mergeRequirement(
  current: BaselineRequirement,
  upstream: BaselineRequirement,
  prefer?: PreferSide,
): BaselineRequirement {
  const merged: BaselineRequirement = {
    // ID always comes from upstream
    id: upstream.id,

    // Scalars
    title: prefer === 'current' ? current.title : upstream.title,
    impact: prefer === 'current' ? current.impact : upstream.impact,
    severity: prefer === 'current' ? current.severity : upstream.severity,

    // Collections
    tags: mergeTags(current.tags, upstream.tags, prefer),
    descriptions: mergeDescriptions(current.descriptions, upstream.descriptions, prefer),
    refs: mergeRefs(current.refs, upstream.refs, prefer),

    // Code: current by default, upstream only with --prefer upstream
    code: prefer === 'upstream'
      ? upstream.code
      : (current.code ?? upstream.code),

    // SourceLocation follows scalars
    sourceLocation: prefer === 'current' ? current.sourceLocation : upstream.sourceLocation,
  };

  // Clean up undefined optional fields
  if (merged.code === undefined) delete merged.code;
  if (merged.severity === undefined) delete merged.severity;
  if (merged.sourceLocation === undefined) delete merged.sourceLocation;
  if (merged.refs === undefined || merged.refs.length === 0) delete merged.refs;

  return merged;
}

/**
 * Merge two tag maps.
 *
 * Default: union of keys; upstream wins on key conflicts.
 * prefer "current": union; current wins on key conflicts.
 * prefer "upstream": upstream replaces all.
 */
export function mergeTags(
  current: Record<string, any>, // eslint-disable-line @typescript-eslint/no-explicit-any
  upstream: Record<string, any>, // eslint-disable-line @typescript-eslint/no-explicit-any
  prefer?: PreferSide,
): Record<string, any> { // eslint-disable-line @typescript-eslint/no-explicit-any
  if (prefer === 'upstream') {
    return { ...upstream };
  }

  const merged: Record<string, any> = { ...current }; // eslint-disable-line @typescript-eslint/no-explicit-any

  for (const [key, value] of Object.entries(upstream)) {
    if (prefer === 'current') {
      if (!(key in merged)) {
        merged[key] = value;
      }
    } else {
      // Default: upstream wins on conflict
      merged[key] = value;
    }
  }

  return merged;
}

/**
 * Merge two description arrays by label.
 *
 * Default: union by label; upstream wins on label conflicts.
 * prefer "current": union; current wins on label conflicts.
 * prefer "upstream": upstream replaces all.
 */
export function mergeDescriptions(
  current: Description[],
  upstream: Description[],
  prefer?: PreferSide,
): Description[] {
  if (prefer === 'upstream') {
    return [...upstream];
  }

  const byLabel = new Map<string, Description>();
  const order: string[] = [];

  // Start with current
  for (const d of current) {
    byLabel.set(d.label, d);
    order.push(d.label);
  }

  // Apply upstream
  for (const d of upstream) {
    if (byLabel.has(d.label)) {
      if (prefer !== 'current') {
        // Default: upstream wins
        byLabel.set(d.label, d);
      }
    } else {
      byLabel.set(d.label, d);
      order.push(d.label);
    }
  }

  return order.map(label => byLabel.get(label)!);
}

/**
 * Merge two reference arrays.
 *
 * Default: union, deduplicated by JSON key.
 * prefer "current": current only.
 * prefer "upstream": upstream only.
 */
export function mergeRefs(
  current?: Reference[],
  upstream?: Reference[],
  prefer?: PreferSide,
): Reference[] | undefined {
  if (prefer === 'current') {
    return current ? [...current] : undefined;
  }
  if (prefer === 'upstream') {
    return upstream ? [...upstream] : undefined;
  }

  // Default: union, deduplicated
  if (!current && !upstream) return undefined;

  const seen = new Set<string>();
  const result: Reference[] = [];

  const addRef = (r: Reference): void => {
    const key = JSON.stringify(r);
    if (!seen.has(key)) {
      seen.add(key);
      result.push(r);
    }
  };

  if (current) current.forEach(addRef);
  if (upstream) upstream.forEach(addRef);

  return result.length > 0 ? result : undefined;
}
