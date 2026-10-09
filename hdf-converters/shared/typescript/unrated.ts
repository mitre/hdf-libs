import { isUnratedSeverity } from '@mitre/hdf-utilities';

/**
 * The tag a roll-up leaves on a requirement whose severity the source never
 * rated, and the value it carries. A leaf module: converterutil.ts re-exports
 * these as part of its surface, and rollup.ts imports them here rather than
 * from the barrel that re-exports rollup itself — which is the cycle a second
 * declaration used to work around.
 */
export const UNRATED_SEVERITY_TAG = 'severity_rating';
export const UNRATED_SEVERITY_VALUE = 'unrated';

export function markUnratedSeverity(tags: Record<string, unknown>, severity?: string | null): void {
  if (isUnratedSeverity(severity)) tags[UNRATED_SEVERITY_TAG] = UNRATED_SEVERITY_VALUE;
}
