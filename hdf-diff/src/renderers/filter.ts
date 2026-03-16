import type { RequirementDiff } from '../types.js';
import type { RenderOptions } from './types.js';

/**
 * Filter requirement diffs based on render options.
 *
 * Supports filtering by:
 * - `filterStates`: Only include requirements matching the given states
 * - `filterSeverity`: Only include requirements matching the given severity tag
 */
export function filterRequirements(
  diffs: RequirementDiff[],
  options?: RenderOptions,
): RequirementDiff[] {
  let filtered = diffs;

  if (options?.filterStates && options.filterStates.length > 0) {
    const states = new Set(options.filterStates);
    filtered = filtered.filter((r) => states.has(r.state));
  }

  if (options?.filterSeverity) {
    const severity = options.filterSeverity.toLowerCase();
    filtered = filtered.filter((r) => {
      const before = r.before as Record<string, unknown> | null;
      const after = r.after as Record<string, unknown> | null;
      const tags =
        (after?.['tags'] as Record<string, unknown> | undefined) ??
        (before?.['tags'] as Record<string, unknown> | undefined);
      if (!tags) return false;
      return (
        typeof tags['severity'] === 'string' &&
        tags['severity'].toLowerCase() === severity
      );
    });
  }

  return filtered;
}
