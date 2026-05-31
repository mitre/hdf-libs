import type { HDFComparison, RequirementDiff } from '../types.js';
import type { RenderOptions } from './types.js';
import { filterRequirements } from './filter.js';

// ANSI color codes
const RESET = '\x1b[0m';
const GREEN = '\x1b[32m';
const RED = '\x1b[31m';
const YELLOW = '\x1b[33m';
const BOLD = '\x1b[1m';
const DIM = '\x1b[2m';

/**
 * Get the symbol and color for a requirement state.
 */
function getSymbolAndColor(
  state: string,
  useColor: boolean,
): { symbol: string; colorFn: (s: string) => string } {
  const identity = (s: string): string => s;

  switch (state) {
    case 'fixed':
    case 'new':
      return {
        symbol: '+',
        colorFn: useColor ? (s) => `${GREEN}${s}${RESET}` : identity,
      };
    case 'regressed':
    case 'absent':
      return {
        symbol: '-',
        colorFn: useColor ? (s) => `${RED}${s}${RESET}` : identity,
      };
    case 'updated':
      return {
        symbol: '~',
        colorFn: useColor ? (s) => `${YELLOW}${s}${RESET}` : identity,
      };
    case 'unchanged':
    default:
      return {
        symbol: ' ',
        colorFn: useColor ? (s) => `${DIM}${s}${RESET}` : identity,
      };
  }
}

/**
 * Format the status transition for a requirement.
 */
function formatStatusTransition(req: RequirementDiff): string {
  if (req.state === 'new') {
    return '(new)';
  }
  if (req.state === 'absent') {
    return '(absent)';
  }

  const parts: string[] = [];

  // Show status change if both exist
  if (req.oldEffectiveStatus && req.newEffectiveStatus) {
    parts.push(`${req.oldEffectiveStatus} → ${req.newEffectiveStatus}`);
  }

  // Add state label for non-obvious transitions
  if (req.state !== 'unchanged') {
    parts.push(`(${req.state})`);
  }

  return parts.join('   ');
}

/**
 * Format field changes for full detail.
 */
function formatFieldChangesForTerminal(req: RequirementDiff): string {
  if (req.fieldChanges.length === 0) return '';

  const parts = req.fieldChanges.map((fc) => {
    if (fc.op === 'add') return `+${fc.path}: ${JSON.stringify(fc.newValue)}`;
    if (fc.op === 'remove') return `-${fc.path}: ${JSON.stringify(fc.oldValue)}`;
    return `${fc.path}: ${JSON.stringify(fc.oldValue)} → ${JSON.stringify(fc.newValue)}`;
  });

  return parts.join('; ');
}

/**
 * Render a single requirement line.
 */
function renderRequirementLine(
  req: RequirementDiff,
  detail: string,
  useColor: boolean,
): string {
  const { symbol, colorFn } = getSymbolAndColor(req.state, useColor);
  const title = req.title ?? '';
  const transition = formatStatusTransition(req);

  let line = `  ${symbol} ${req.id}  ${title}    ${transition}`;

  if (detail === 'full') {
    // Add change reasons
    if (req.changeReasons.length > 0) {
      line += `  [${req.changeReasons.join(', ')}]`;
    }
    // Add field changes
    const fieldChanges = formatFieldChangesForTerminal(req);
    if (fieldChanges) {
      line += `  ${fieldChanges}`;
    }
  }

  return colorFn(line);
}

/**
 * Build the summary line.
 */
function buildSummaryLine(comparison: HDFComparison, useColor: boolean): string {
  const { summary } = comparison;

  const parts = [
    `${summary.fixed} fixed`,
    `${summary.regressed} regressed`,
    `${summary.new} new`,
    `${summary.absent} absent`,
    `${summary.unchanged} unchanged`,
    `${summary.updated} updated`,
    `(${summary.total} total)`,
  ];

  const line = `Summary: ${parts.join(', ')}`;

  if (useColor) {
    return `${BOLD}${line}${RESET}`;
  }
  return line;
}

/**
 * Build the header line.
 */
function buildHeaderLine(comparison: HDFComparison, useColor: boolean): string {
  const mode = comparison.comparisonMode;
  const oldSource = comparison.sources.find((s) => s.role === 'old' || s.role === 'golden' || s.role === 'reference');
  const newSource = comparison.sources.find((s) => s.role === 'new' || s.role === 'system');

  let header = `HDF Comparison: ${mode}`;

  const oldTimestamp = oldSource?.assessmentTimestamp;
  const newTimestamp = newSource?.assessmentTimestamp;

  if (oldTimestamp && newTimestamp) {
    // Format as date-only if possible, otherwise use full timestamp
    // split() always returns at least one element, so [0] is safe
    const oldDate = oldTimestamp.split('T')[0]!;
    const newDate = newTimestamp.split('T')[0]!;
    header += ` (${oldDate} → ${newDate})`;
  }

  if (useColor) {
    return `${BOLD}${header}${RESET}`;
  }
  return header;
}

/**
 * Render an HDFComparison for terminal display with optional ANSI colors.
 *
 * - `detail: 'summary'` -- just the summary line
 * - `detail: 'control'` -- requirement list + summary (excludes unchanged)
 * - `detail: 'full'`    -- all requirements including unchanged, with changeReasons and fieldChanges
 *
 * When `color: false`, no ANSI escape codes are emitted.
 * Default detail level: `'control'`. Default color: `true`.
 */
export function renderTerminal(
  comparison: HDFComparison,
  options?: RenderOptions,
): string {
  const detail = options?.detail ?? 'control';
  const useColor = options?.color ?? true;

  const lines: string[] = [];

  // Header
  lines.push(buildHeaderLine(comparison, useColor));
  lines.push('');

  if (detail === 'summary') {
    lines.push(buildSummaryLine(comparison, useColor));
    return lines.join('\n');
  }

  // Requirement lines
  const filtered = filterRequirements(comparison.requirementDiffs, options);

  for (const req of filtered) {
    // In 'control' mode, skip unchanged requirements
    if (detail === 'control' && req.state === 'unchanged') {
      continue;
    }
    lines.push(renderRequirementLine(req, detail, useColor));
  }

  lines.push('');
  lines.push(buildSummaryLine(comparison, useColor));

  return lines.join('\n');
}
