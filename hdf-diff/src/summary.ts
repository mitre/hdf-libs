import type { ComparisonSummary, RequirementDiff } from './types.js';

/**
 * Compute summary counts from an array of RequirementDiff entries.
 */
export function computeSummary(requirements: RequirementDiff[]): ComparisonSummary {
  const summary: ComparisonSummary = {
    fixed: 0,
    regressed: 0,
    new: 0,
    absent: 0,
    unchanged: 0,
    updated: 0,
    total: requirements.length,
    matchedCount: 0,
    unmatchedOldCount: 0,
    unmatchedNewCount: 0,
  };

  for (const req of requirements) {
    switch (req.state) {
      case 'fixed':
        summary.fixed++;
        summary.matchedCount++;
        break;
      case 'regressed':
        summary.regressed++;
        summary.matchedCount++;
        break;
      case 'new':
        summary.new++;
        summary.unmatchedNewCount++;
        break;
      case 'absent':
        summary.absent++;
        summary.unmatchedOldCount++;
        break;
      case 'unchanged':
        summary.unchanged++;
        summary.matchedCount++;
        break;
      case 'updated':
        summary.updated++;
        summary.matchedCount++;
        break;
    }
  }

  return summary;
}
