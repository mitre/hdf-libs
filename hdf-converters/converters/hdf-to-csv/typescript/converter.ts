import { buildCsv, parseTimestamp, formatTimestamp } from '@mitre/hdf-utilities';
import type { HDFResults, EvaluatedBaseline, EvaluatedRequirement, Component, Description, StatusOverride, Cvss } from '@mitre/hdf-schema';
import { requireHdfResults } from '../../../shared/typescript/converterutil.js';

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
  'Impact': string;
  'Status': string;
  'NIST Controls': string;
  'CCI Controls': string;
  'Control Type': string;
  'Verification Method': string;
  'Applicability': string;
  'Result Message': string;
  'Effective Status': string;
  'Effective Impact': string;
  'Disposition': string;
  'Override Reason': string;
  'Applied By': string;
  'Expires At': string;
  'CVSS': string;
  'CWE': string;
  'EPSS': string;
  'KEV': string;
  'Target FQDN': string;
  'Target IP': string;
}

interface TargetIdentity {
  name: string;
  type: string;
  fqdn: string;
  ipAddress: string;
}

/**
 * Convert HDF JSON to CSV format
 * @param input HDF JSON string
 * @returns CSV string with sanitized output
 */
export function convertHdfToCsv(input: string): string {
  const hdf = requireHdfResults<HDFResults>(input, 'hdf-to-csv');

  const rows: CsvRow[] = [];

  // Get components array (may be empty or undefined)
  const components = hdf.components || [];

  // If no components, create a single default target entry
  const targetList: TargetIdentity[] = components.length > 0
    ? components.map((t: Component) => ({
        name: t.name,
        type: t.type,
        fqdn: t.fqdn ?? '',
        ipAddress: t.ipAddress ?? ''
      }))
    : [{ name: '', type: '', fqdn: '', ipAddress: '' }];

  // Iterate through each baseline
  for (const baseline of hdf.baselines) {
    // requirements carries minItems 1 on top of being required, so an absent or
    // empty one is malformed input, not a baseline that evaluated nothing.
    // Top-level baselines is the opposite case — no minItems — so an empty
    // assessment stays valid and simply produces an empty report.
    if (!Array.isArray(baseline.requirements) || baseline.requirements.length === 0) {
      throw new Error(`hdf-to-csv: baseline "${text(baseline.name)}" has no requirements`);
    }
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
 * The CWE cell. Unlike tags — an untyped map where Go filters non-string entries,
 * so this side filters too — cwe is typed string[] in HDF, and a non-string entry
 * fails Go's typed decode and rejects the whole document. Rejecting here keeps
 * the two languages agreeing on WHETHER a document converts; the message text
 * differs by construction, since Go's comes from encoding/json.
 */
function cweCell(requirement: EvaluatedRequirement): string {
  const cwe = requirement.cwe;
  if (cwe === undefined || cwe === null) return '';
  if (!Array.isArray(cwe)) {
    throw new Error(
      `hdf-to-csv: requirement "${requirementIdText(requirement.id)}" has a non-array cwe`,
    );
  }
  if (!cwe.every((v) => typeof v === 'string')) {
    throw new Error(
      `hdf-to-csv: requirement "${requirementIdText(requirement.id)}" has a non-string cwe entry`,
    );
  }
  return cwe.join('; ');
}

/**
 * A schema-required number as a number. Go decodes an absent one to the zero
 * value and cannot tell it apart from a real zero — impact 0 legitimately means
 * Not Applicable — so distinguishing them would need a schema validation pass
 * the converters deliberately do not do. Rendering 0 here matches what Go emits,
 * where reading .toFixed off an absent value threw a raw TypeError instead.
 */
function numeric(value: number | undefined | null): number {
  return typeof value === 'number' ? value : 0;
}

/**
 * A schema-required string as text. Nested-invalid input reaches the converter
 * with these absent, and an absent value reached sanitizeCsvValue's String() as
 * the literal "undefined" — where Go, formatting a zero-value string, wrote
 * nothing. Every schema-required STRING cell goes through here; the numeric
 * ones go through numeric(), which serves the same purpose for a different type.
 */
function text(value: string | undefined | null): string {
  return typeof value === 'string' ? value : '';
}

/** The requirement id as text; also names the requirement in the no-results error. */
function requirementIdText(id: string | undefined): string {
  return text(id);
}

/**
 * Create a CSV row from baseline, requirement, and target data
 */
function createRow(
  baseline: EvaluatedBaseline,
  requirement: EvaluatedRequirement,
  target: TargetIdentity
): CsvRow {
  // results and descriptions both carry minItems 1 on top of being required, so
  // an absent or empty one is malformed input, not a row with unknown values.
  // Checked before ANY field access: descriptions was read at the top of this
  // function, so a guard further down reported a TypeError instead of the cause.
  // Array.isArray also covers null, which reaches here as a non-array.
  const results = Array.isArray(requirement.results) ? requirement.results : [];
  const [firstResult] = results;
  if (!firstResult) {
    throw new Error(`hdf-to-csv: requirement "${requirementIdText(requirement.id)}" has no results`);
  }
  if (!Array.isArray(requirement.descriptions) || requirement.descriptions.length === 0) {
    throw new Error(
      `hdf-to-csv: requirement "${requirementIdText(requirement.id)}" has no descriptions`,
    );
  }

  // Get default description (required to be present per schema)
  const description = descriptionByLabel(requirement, 'default');

  // Other conventional description labels (check/fix/rationale) — empty when absent
  const check = descriptionByLabel(requirement, 'check');
  const fix = descriptionByLabel(requirement, 'fix');
  const rationale = descriptionByLabel(requirement, 'rationale');
  const code = requirement.code ?? '';
  const references = flattenRefs(requirement.refs);

  // Get severity from tags or derive from impact
  const severity = getSeverity(requirement);

  const status = firstResult.status;
  const message = firstResult.message ?? '';

  // Extract NIST and CCI controls from tags
  const nistControls = extractArrayFromTags(requirement.tags, 'nist');
  const cciControls = extractArrayFromTags(requirement.tags, 'cci');

  // Post-override posture: effective columns fall back to the raw value when no
  // override governs, so the column is always populated and sortable.
  // Presence, not truthiness: Go's EffectiveStatus is a pointer, so an explicit
  // empty string is present and renders empty, where a truthy test fell through
  // to the raw status and reported a different posture than the document states.
  const effectiveStatus =
    requirement.effectiveStatus !== undefined && requirement.effectiveStatus !== null
      ? String(requirement.effectiveStatus)
      : text(status);
  const effectiveImpact = numeric(requirement.effectiveImpact ?? requirement.impact).toFixed(2);
  const disposition = requirement.disposition ? String(requirement.disposition) : '';

  return {
    'Baseline ID': text(baseline.name),
    'Baseline Version': baseline.version || '',
    'Baseline Title': baseline.title || '',
    'Target ID': text(target.name),
    'Target Type': text(target.type),
    'Requirement ID': requirementIdText(requirement.id),
    'Requirement Title': requirement.title || '',
    'Description': description,
    'Check': check,
    'Fix': fix,
    'Rationale': rationale,
    'Code': code,
    'References': references,
    'Severity': severity,
    'Impact': numeric(requirement.impact).toFixed(2),
    'Status': text(status),
    'NIST Controls': nistControls,
    'CCI Controls': cciControls,
    'Control Type': requirement.controlType ?? '',
    'Verification Method': requirement.verificationMethod ?? '',
    'Applicability': requirement.applicability ?? '',
    'Result Message': message,
    'Effective Status': effectiveStatus,
    'Effective Impact': effectiveImpact,
    'Disposition': disposition,
    'Override Reason': joinOverrides(requirement.statusOverrides, o => o.reason ?? ''),
    'Applied By': joinOverrides(requirement.statusOverrides, o => o.appliedBy?.identifier ?? ''),
    'Expires At': joinOverrides(requirement.statusOverrides, o => formatExpires(o.expiresAt)),
    'CVSS': cvssScores(requirement.cvss),
    'CWE': cweCell(requirement),
    'EPSS': requirement.epss ? numeric(requirement.epss.score).toFixed(5) : '',
    'KEV': requirement.kev ? (requirement.kev.inKev ? 'true' : 'false') : '',
    'Target FQDN': target.fqdn,
    'Target IP': target.ipAddress
  };
}

/**
 * Apply pick to every status override and join non-empty results with '; ',
 * matching the NIST/CCI multi-value column convention.
 */
function joinOverrides(
  overrides: StatusOverride[] | undefined,
  pick: (o: StatusOverride) => string
): string {
  if (!Array.isArray(overrides)) {
    return '';
  }
  const out: string[] = [];
  for (const o of overrides) {
    // A null element is a zero-value struct in Go, so every picked field is
    // empty and the entry drops out; reading through it threw here instead.
    if (o === null || o === undefined) {
      continue;
    }
    const v = pick(o);
    if (v) {
      out.push(v);
    }
  }
  return out.join('; ');
}

/**
 * Render an override's expiry as a canonical trimmed-UTC RFC3339 timestamp,
 * byte-identical to the Go converter's RFC3339Nano output.
 */
function formatExpires(value: StatusOverride['expiresAt']): string {
  const parsed = parseTimestamp(String(value));
  return parsed ? formatTimestamp(parsed) : '';
}

/**
 * Render each CVSS entry's score (computed when present, else base) to one
 * decimal — the precision the CVSS spec defines and the source carries — joined
 * with '; ' to preserve multi-CVE findings. The Go peer rounds through a shared
 * helper matching toFixed, so a .x5 score renders the same digits in both.
 */
function cvssScores(entries: Cvss[] | undefined): string {
  if (!Array.isArray(entries)) {
    return '';
  }
  const out: string[] = [];
  for (const c of entries) {
    // A null entry is a zero-value struct in Go, whose scores are absent. And an
    // explicit null score passed a !== undefined check while still throwing on
    // .toFixed, so the test is for a number rather than against undefined.
    if (c === null || c === undefined) {
      continue;
    }
    const score = c.computedScore ?? c.baseScore;
    if (typeof score === 'number') {
      out.push(score.toFixed(1));
    }
  }
  return out.join('; ');
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
      // Only a string first item: a numeric severity is not one of the bands,
      // and stringifying it produced a Severity cell of "1". Matches the Go peer.
      if (Array.isArray(sev) && typeof sev[0] === 'string') {
        return sev[0];
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
    // Only string items: a number or null in a nist array is not a control id,
    // and stringifying it invented one. Matches the Go peer's type assertion.
    return value.filter((v): v is string => typeof v === 'string').join('; ');
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
  // A null element decodes to a zero-value struct in Go, which is simply not the
  // label being looked for; reading .label off it threw here instead. Both the
  // default lookup and the check/fix/rationale lookups come through here, so the
  // guard cannot be applied to one and missed on the other.
  const match = requirement.descriptions.find(
    (d: Description | null | undefined) => d !== null && d !== undefined && d.label === label,
  );
  return match?.data || '';
}

/**
 * Flatten a requirement's refs to one string: each Reference rendered as its
 * url/uri (or a string `ref`); array-form refs are skipped here, though a document
 * containing one never reaches this function in Go, whose typed decode rejects
 * it outright — a reject-versus-degrade split tracked on its own card. Joined with '; ' to
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
