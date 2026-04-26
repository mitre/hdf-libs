import type { HdfComparison, RequirementDiff } from '../types.js';
import type { RenderOptions } from './types.js';
import { filterRequirements } from './filter.js';

// Spreadsheet apps (Excel, Sheets, LibreOffice) treat cells starting with
// these characters as formulas and execute them on file open. Scan-tool
// output (vuln titles, descriptions) is attacker-influenced, so neutralize
// any cell whose first character is dangerous. OWASP "CSV Injection";
// CWE-1236.
const FORMULA_TRIGGERS = new Set(['=', '+', '-', '@', '\t', '\r']);

function neutralizeFormulaInjection(value: string): string {
  if (value.length === 0) return value;
  return FORMULA_TRIGGERS.has(value[0]!) ? `'${value}` : value;
}

/**
 * Escape a value for CSV output.
 *
 * Two-step:
 * 1. Neutralize formula-injection triggers (CSV-injection / CWE-1236).
 * 2. RFC-4180: enclose in double quotes if the field contains commas,
 *    double quotes, or newlines; double internal quotes.
 */
function escapeCsvField(value: string): string {
  const safe = neutralizeFormulaInjection(value);
  if (safe.includes(',') || safe.includes('"') || safe.includes('\n') || safe.includes('\r')) {
    return `"${safe.replace(/"/g, '""')}"`;
  }
  return safe;
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
