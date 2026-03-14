import type { HdfComparison, RequirementDiff } from '../types.js';
import type { RenderOptions } from './types.js';
import { filterRequirements } from './filter.js';

/**
 * Escape a value for CSV output.
 *
 * Per RFC 4180:
 * - Fields containing commas, double quotes, or newlines are enclosed in double quotes.
 * - Double quotes within a field are escaped by doubling them.
 */
function escapeCsvField(value: string): string {
  if (value.includes(',') || value.includes('"') || value.includes('\n') || value.includes('\r')) {
    return `"${value.replace(/"/g, '""')}"`;
  }
  return value;
}

/**
 * Format field changes as a human-readable string.
 */
function formatFieldChanges(req: RequirementDiff): string {
  if (req.fieldChanges.length === 0) return '';
  return req.fieldChanges
    .map((fc) => {
      if (fc.op === 'add') return `+${fc.path}: ${JSON.stringify(fc.newValue)}`;
      if (fc.op === 'remove') return `-${fc.path}: ${JSON.stringify(fc.oldValue)}`;
      return `${fc.path}: ${JSON.stringify(fc.oldValue)} -> ${JSON.stringify(fc.newValue)}`;
    })
    .join('; ');
}

/**
 * Render an HdfComparison as a CSV string.
 *
 * One row per requirement. Columns:
 * - ID, Title, State, Old Status, New Status, Impact (Old), Impact (New), Change Reasons
 *
 * When `detail: 'full'`, an additional Field Changes column is included.
 *
 * Header row is always included. Standard CSV escaping (RFC 4180).
 * Default detail level: `'control'`.
 */
export function renderCsv(
  comparison: HdfComparison,
  options?: RenderOptions,
): string {
  const detail = options?.detail ?? 'control';
  const filtered = filterRequirements(comparison.requirementDiffs, options);

  const headers = [
    'ID',
    'Title',
    'State',
    'Old Status',
    'New Status',
    'Impact (Old)',
    'Impact (New)',
    'Change Reasons',
  ];

  if (detail === 'full') {
    headers.push('Field Changes');
  }

  const lines: string[] = [headers.join(',')];

  for (const req of filtered) {
    const row = [
      escapeCsvField(req.id),
      escapeCsvField(req.title ?? ''),
      escapeCsvField(req.state),
      escapeCsvField(req.oldEffectiveStatus ?? ''),
      escapeCsvField(req.newEffectiveStatus ?? ''),
      escapeCsvField(req.oldImpact !== undefined ? String(req.oldImpact) : ''),
      escapeCsvField(req.newImpact !== undefined ? String(req.newImpact) : ''),
      escapeCsvField(req.changeReasons.join(', ')),
    ];

    if (detail === 'full') {
      row.push(escapeCsvField(formatFieldChanges(req)));
    }

    lines.push(row.join(','));
  }

  return lines.join('\n');
}
