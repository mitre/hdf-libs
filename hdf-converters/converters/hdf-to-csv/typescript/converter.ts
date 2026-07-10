import { parseJSON } from '@mitre/hdf-utilities';
import { buildCsv } from '@mitre/hdf-utilities';
import type { HDFResults, EvaluatedBaseline, EvaluatedRequirement, Component, Description } from '@mitre/hdf-schema';
import { validateInputSize } from '../../../shared/typescript/converterutil.js';

/**
 * Row structure for CSV export
 */
interface CsvRow {
  'Baseline ID': string;
  'Baseline Version': string;
  'Baseline Title': string;
  'Target ID': string;
  'Target Type': string;
  'Requirement ID': string;
  'Requirement Title': string;
  'Description': string;
  'Check': string;
  'Fix': string;
  'Rationale': string;
  'Code': string;
  'References': string;
  'Severity': string;
  'Impact': number;
  'Status': string;
  'NIST Controls': string;
  'CCI Controls': string;
  'Control Type': string;
  'Verification Method': string;
  'Applicability': string;
  'Result Message': string;
}

/**
 * Convert HDF JSON to CSV format
 * @param input HDF JSON string
 * @returns CSV string with sanitized output
 */
export function convertHdfToCsv(input: string): string {
  validateInputSize(input, 'hdf-to-csv');
  const hdf = parseJSON<HDFResults>(input);

  if (!hdf || typeof hdf !== 'object' || !('baselines' in hdf)) {
    throw new Error('Invalid HDF structure: missing baselines field');
  }

  if (!Array.isArray(hdf.baselines)) {
    throw new Error('Invalid HDF structure: baselines must be an array');
  }

  const rows: CsvRow[] = [];

  // Get components array (may be empty or undefined)
  const components = hdf.components || [];

  // If no components, create a single default target entry
  const targetList: Array<{ name: string; type: string }> = components.length > 0
    ? components.map((t: Component) => ({ name: t.name, type: t.type }))
    : [{ name: '', type: '' }];

  // Iterate through each baseline
  for (const baseline of hdf.baselines) {
    // Iterate through each requirement in the baseline
    for (const requirement of baseline.requirements) {
      // Create a row for each target
      for (const target of targetList) {
        rows.push(createRow(baseline, requirement, target));
      }
    }
  }

  // Convert to CSV with sanitization enabled
  return buildCsv(rows, { sanitize: true });
}

/**
 * Create a CSV row from baseline, requirement, and target data
 */
function createRow(
  baseline: EvaluatedBaseline,
  requirement: EvaluatedRequirement,
  target: { name: string; type: string }
): CsvRow {
  // Get default description (required to be present per schema)
  const defaultDesc = requirement.descriptions.find((d: Description) => d.label === 'default');
  const description = defaultDesc?.data || '';

  // Other conventional description labels (check/fix/rationale) — empty when absent
  const check = descriptionByLabel(requirement, 'check');
  const fix = descriptionByLabel(requirement, 'fix');
  const rationale = descriptionByLabel(requirement, 'rationale');
  const code = requirement.code ?? '';
  const references = flattenRefs(requirement.refs);

  // Get severity from tags or derive from impact
  const severity = getSeverity(requirement);

  // Get status from first result (results is required, minItems: 1 per schema)
  const firstResult = requirement.results[0];
  const status = firstResult?.status || '';
  const message = firstResult?.message || '';

  // Extract NIST and CCI controls from tags
  const nistControls = extractArrayFromTags(requirement.tags, 'nist');
  const cciControls = extractArrayFromTags(requirement.tags, 'cci');

  return {
    'Baseline ID': baseline.name,
    'Baseline Version': baseline.version || '',
    'Baseline Title': baseline.title || '',
    'Target ID': target.name,
    'Target Type': target.type,
    'Requirement ID': requirement.id,
    'Requirement Title': requirement.title || '',
    'Description': description,
    'Check': check,
    'Fix': fix,
    'Rationale': rationale,
    'Code': code,
    'References': references,
    'Severity': severity,
    'Impact': requirement.impact,
    'Status': String(status),
    'NIST Controls': nistControls,
    'CCI Controls': cciControls,
    'Control Type': requirement.controlType ?? '',
    'Verification Method': requirement.verificationMethod ?? '',
    'Applicability': requirement.applicability ?? '',
    'Result Message': message
  };
}

/**
 * Get severity from requirement tags or derive from impact
 */
function getSeverity(requirement: EvaluatedRequirement): string {
  // Check if severity is explicitly provided in tags
  if (requirement.tags && typeof requirement.tags === 'object') {
    if ('severity' in requirement.tags) {
      const sev = requirement.tags.severity;
      if (typeof sev === 'string') {
        return sev;
      }
      if (Array.isArray(sev) && sev.length > 0) {
        return String(sev[0]);
      }
    }
  }

  // Derive from impact if not provided
  const impact = requirement.impact;
  if (impact >= 0.7) return 'high';
  if (impact >= 0.4) return 'medium';
  return 'low';
}

/**
 * Extract array values from tags object and join with semicolons
 */
function extractArrayFromTags(
  tags: Record<string, unknown>,
  key: string
): string {
  if (!tags || typeof tags !== 'object') {
    return '';
  }

  const value = tags[key];
  if (Array.isArray(value)) {
    return value.map(v => String(v)).join('; ');
  }

  return '';
}

/**
 * Get the data of the first description matching a label. Empty when absent.
 */
function descriptionByLabel(
  requirement: EvaluatedRequirement,
  label: string
): string {
  const match = requirement.descriptions.find((d: Description) => d.label === label);
  return match?.data || '';
}

/**
 * Flatten a requirement's refs to one string: each Reference rendered as its
 * url/uri (or a string `ref`); array-form refs are skipped. Joined with '; ' to
 * match the NIST/CCI column convention.
 */
function flattenRefs(refs: EvaluatedRequirement['refs']): string {
  if (!Array.isArray(refs)) {
    return '';
  }
  const out: string[] = [];
  for (const r of refs) {
    if (!r || typeof r !== 'object') {
      continue;
    }
    const o = r as Record<string, unknown>;
    if (typeof o.url === 'string') {
      out.push(o.url);
    } else if (typeof o.uri === 'string') {
      out.push(o.uri);
    } else if (typeof o.ref === 'string') {
      out.push(o.ref);
    }
  }
  return out.join('; ');
}
