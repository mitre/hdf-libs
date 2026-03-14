import type { HdfComparison, RequirementDiff } from '../types.js';
import type { RenderOptions } from './types.js';
import { filterRequirements } from './filter.js';

/**
 * Render the summary table in markdown format.
 */
function renderSummaryTable(comparison: HdfComparison): string {
  const { summary } = comparison;
  const lines: string[] = [
    '## HDF Comparison Summary',
    '',
    '| Metric | Count |',
    '|--------|-------|',
    `| Fixed | ${summary.fixed} |`,
    `| Regressed | ${summary.regressed} |`,
    `| New | ${summary.new} |`,
    `| Absent | ${summary.absent} |`,
    `| Unchanged | ${summary.unchanged} |`,
    `| Updated | ${summary.updated} |`,
    `| **Total** | **${summary.total}** |`,
  ];
  return lines.join('\n');
}

/**
 * Group requirement diffs by state.
 */
function groupByState(
  diffs: RequirementDiff[],
): Map<string, RequirementDiff[]> {
  const groups = new Map<string, RequirementDiff[]>();
  for (const diff of diffs) {
    const existing = groups.get(diff.state);
    if (existing) {
      existing.push(diff);
    } else {
      groups.set(diff.state, [diff]);
    }
  }
  return groups;
}

/**
 * Escape a value for use in a markdown table cell.
 * Replaces pipe characters with their HTML entity.
 */
function escapeCell(value: string): string {
  return value.replace(/\|/g, '&#124;');
}

/**
 * Format field changes for a markdown cell.
 */
function formatFieldChanges(req: RequirementDiff): string {
  if (req.fieldChanges.length === 0) return '';
  return req.fieldChanges
    .map((fc) => {
      if (fc.op === 'add') return `+${fc.path}: ${JSON.stringify(fc.newValue)}`;
      if (fc.op === 'remove')
        return `-${fc.path}: ${JSON.stringify(fc.oldValue)}`;
      return `${fc.path}: ${JSON.stringify(fc.oldValue)} -> ${JSON.stringify(fc.newValue)}`;
    })
    .join('; ');
}

/**
 * Render a section for a single state group.
 */
function renderStateSection(
  state: string,
  diffs: RequirementDiff[],
  detail: string,
): string {
  const label = state.charAt(0).toUpperCase() + state.slice(1);
  const lines: string[] = [`### ${label} (${diffs.length})`];

  if (diffs.length === 0) {
    lines.push('', '(none)');
    return lines.join('\n');
  }

  lines.push('');

  if (detail === 'full') {
    lines.push(
      '| ID | Title | Old Status | New Status | Change Reasons | Field Changes |',
      '|----|-------|------------|------------|----------------|---------------|',
    );
    for (const req of diffs) {
      const id = escapeCell(req.id);
      const title = escapeCell(req.title ?? '');
      const oldStatus = escapeCell(req.oldEffectiveStatus ?? '');
      const newStatus = escapeCell(req.newEffectiveStatus ?? '');
      const reasons = escapeCell(req.changeReasons.join(', '));
      const fieldChanges = escapeCell(formatFieldChanges(req));
      lines.push(
        `| ${id} | ${title} | ${oldStatus} | ${newStatus} | ${reasons} | ${fieldChanges} |`,
      );
    }
  } else {
    lines.push(
      '| ID | Title | Old Status | New Status |',
      '|----|-------|------------|------------|',
    );
    for (const req of diffs) {
      const id = escapeCell(req.id);
      const title = escapeCell(req.title ?? '');
      const oldStatus = escapeCell(req.oldEffectiveStatus ?? '');
      const newStatus = escapeCell(req.newEffectiveStatus ?? '');
      lines.push(`| ${id} | ${title} | ${oldStatus} | ${newStatus} |`);
    }
  }

  return lines.join('\n');
}

/**
 * Render an HdfComparison as a Markdown string.
 *
 * - `detail: 'summary'` -- summary table only
 * - `detail: 'control'` -- summary + per-requirement tables by state
 * - `detail: 'full'`    -- summary + per-requirement tables with changeReasons and fieldChanges
 *
 * Default detail level: `'control'`.
 */
export function renderMarkdown(
  comparison: HdfComparison,
  options?: RenderOptions,
): string {
  const detail = options?.detail ?? 'control';
  const parts: string[] = [renderSummaryTable(comparison)];

  if (detail === 'summary') {
    return parts.join('\n');
  }

  // Determine which states to display
  const stateOrder: string[] = [
    'fixed',
    'regressed',
    'new',
    'absent',
    'updated',
    'unchanged',
  ];

  const filtered = filterRequirements(
    comparison.requirementDiffs,
    options,
  );
  const grouped = groupByState(filtered);

  // If filtering by states, only show those specific states
  const statesToShow =
    options?.filterStates && options.filterStates.length > 0
      ? stateOrder.filter((s) => options.filterStates!.includes(s))
      : stateOrder;

  for (const state of statesToShow) {
    parts.push('');
    const diffs = grouped.get(state) ?? [];
    parts.push(renderStateSection(state, diffs, detail));
  }

  return parts.join('\n');
}
