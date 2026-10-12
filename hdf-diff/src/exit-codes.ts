/**
 * GNU diff compatible and detailed exit codes for HDF comparison operations.
 * Basic codes are 0 for identical and 1 for differences; EXIT_ERROR is GNU
 * diff's trouble code, which this repo's own CLI does not use. Detailed codes
 * (10-14) communicate nuanced security outcomes such as fixes, regressions,
 * baseline changes, and metadata drift.
 */
import type { ComparisonSummary } from './types.js';

/** GNU diff compatible exit codes (--exit-code mode) */
export const EXIT_IDENTICAL = 0;
export const EXIT_DIFFERENCES = 1;
/**
 * GNU diff's trouble code. The hdf CLI does not return it: a diff that fails to
 * run exits 1 like any failed operation, and 2 there means a usage error. Kept
 * for a caller that wants GNU's convention instead.
 */
export const EXIT_ERROR = 2;

/** Detailed exit codes (--detailed-exitcode mode) */
export const EXIT_DETAILED_IDENTICAL = 0;
export const EXIT_DETAILED_ERROR = 1;
export const EXIT_DETAILED_FIXES_ONLY = 10;
export const EXIT_DETAILED_REGRESSIONS_ONLY = 11;
export const EXIT_DETAILED_MIXED = 12;
export const EXIT_DETAILED_BASELINE_CHANGED = 13;
export const EXIT_DETAILED_DRIFT_ONLY = 14;

/**
 * Compute the GNU diff compatible exit code from a comparison summary.
 *
 * Returns:
 *   0 = identical (no differences found)
 *   1 = differences found (any kind)
 *
 * Never EXIT_ERROR: a summary cannot describe a run that failed to produce one.
 * A caller that follows the hdf CLI returns 1 for such a failure, not EXIT_ERROR.
 */
export function computeExitCode(summary: ComparisonSummary): number {
  if (hasDifferences(summary)) {
    return EXIT_DIFFERENCES;
  }
  return EXIT_IDENTICAL;
}

/**
 * Compute the detailed exit code from a comparison summary.
 *
 * Returns:
 *   0  = identical (no differences found)
 *   10 = differences found, fixes only (security posture improved)
 *   11 = differences found, regressions only (security posture degraded)
 *   12 = differences found, mixed fixes and regressions
 *   13 = differences found, only new/absent controls (baseline changed)
 *   14 = differences found, only metadata drift (no status changes)
 *
 * Never EXIT_DETAILED_ERROR: callers return that themselves when a diff fails
 * to run, which matches the hdf CLI's 1 for a failed operation.
 *
 * Priority order: mixed(12) > regressions(11) > fixes(10) > baseline(13) > drift(14)
 */
export function computeDetailedExitCode(summary: ComparisonSummary): number {
  if (!hasDifferences(summary)) {
    return EXIT_DETAILED_IDENTICAL;
  }

  // Mixed: both fixes and regressions
  if (summary.regressed > 0 && summary.fixed > 0) {
    return EXIT_DETAILED_MIXED;
  }

  // Regressions only (no fixes)
  if (summary.regressed > 0) {
    return EXIT_DETAILED_REGRESSIONS_ONLY;
  }

  // Fixes only (no regressions)
  if (summary.fixed > 0) {
    return EXIT_DETAILED_FIXES_ONLY;
  }

  // Baseline changes: new or absent controls (but no status changes)
  if (summary.new > 0 || summary.absent > 0) {
    return EXIT_DETAILED_BASELINE_CHANGED;
  }

  // Everything else is metadata drift (updated tags, descriptions, etc.)
  return EXIT_DETAILED_DRIFT_ONLY;
}

/**
 * Returns true if the summary indicates any differences at all.
 */
function hasDifferences(summary: ComparisonSummary): boolean {
  return summary.total !== summary.unchanged;
}
