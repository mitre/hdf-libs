import type { ComparisonSummary } from './types.js';

/** GNU diff compatible exit codes (--exit-code mode) */
export const EXIT_IDENTICAL = 0;
export const EXIT_DIFFERENCES = 1;
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
 * Note: error (exit code 2) is not computed from the summary — callers
 * should return EXIT_ERROR directly when I/O or parse errors occur.
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
 * Note: error (exit code 1) is not computed from the summary — callers
 * should return EXIT_DETAILED_ERROR directly when I/O or parse errors occur.
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
