import type { HDFComparison, RequirementDiff } from '../types.js';
import type { RenderOptions } from './types.js';
import { filterRequirements } from './filter.js';

/**
 * Strip `before` and `after` from a RequirementDiff, keeping only
 * the summary fields (id, state, title, statuses, changeReasons, fieldChanges).
 */
function stripSnapshots(
  req: RequirementDiff,
): Omit<RequirementDiff, 'before' | 'after'> {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const { before, after, ...rest } = req;
  return rest;
}

/**
 * Render an HDFComparison as a JSON string.
 *
 * - `detail: 'summary'` -- only `{ formatVersion, comparisonMode, summary }`
 * - `detail: 'control'` -- full document but `before`/`after` stripped from requirementDiffs
 * - `detail: 'full'`    -- `JSON.stringify(comparison, null, 2)` (the complete document)
 *
 * Default detail level: `'control'`.
 */
export function renderJson(
  comparison: HDFComparison,
  options?: RenderOptions,
): string {
  const detail = options?.detail ?? 'control';

  if (detail === 'summary') {
    return JSON.stringify(
      {
        formatVersion: comparison.formatVersion,
        comparisonMode: comparison.comparisonMode,
        summary: comparison.summary,
      },
      null,
      2,
    );
  }

  if (detail === 'full') {
    const filtered = filterRequirements(
      comparison.requirementDiffs,
      options,
    );
    if (filtered.length !== comparison.requirementDiffs.length) {
      return JSON.stringify(
        { ...comparison, requirementDiffs: filtered },
        null,
        2,
      );
    }
    return JSON.stringify(comparison, null, 2);
  }

  // detail === 'control' (default)
  const filtered = filterRequirements(
    comparison.requirementDiffs,
    options,
  );
  const strippedDiffs = filtered.map(stripSnapshots);

  return JSON.stringify(
    { ...comparison, requirementDiffs: strippedDiffs },
    null,
    2,
  );
}
