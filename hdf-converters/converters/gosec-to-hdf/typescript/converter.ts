import { parseJSON } from '@mitre/hdf-utilities';
import { detectConverter } from '../../../shared/typescript/fingerprint.js';
import { registerAllFingerprints } from '../../../shared/typescript/register-all.js';
import { convertSarifToHdf } from '../../sarif-to-hdf/typescript/converter.js';
import { inputChecksum, limitArray, validateInputSize, mapCWEToNIST, DEFAULT_REMEDIATION_NIST_TAGS, buildHdfResults } from '../../../shared/typescript/converterutil.js';
import type {
  EvaluatedBaseline,
  EvaluatedRequirement,
  RequirementResult,
  Checksum,
} from '@mitre/hdf-schema';
import {
  ResultStatus,
  createMinimalBaseline,
  createRequirement,
  createResult,
  type Description,
} from '@mitre/hdf-schema';

/**
 * gosec JSON output structures
 * See https://github.com/securego/gosec for the full schema.
 */
interface GosecReport {
  'Golang errors': unknown;
  Issues: GosecIssue[];
  Stats: GosecStats;
  GosecVersion: string;
}

interface GosecStats {
  files: number;
  lines: number;
  nosec: number;
  found: number;
}

interface GosecCWE {
  id: string;
  url: string;
}

interface GosecSuppression {
  kind: string;
  justification: string;
}

interface GosecIssue {
  severity: string;
  confidence: string;
  cwe: GosecCWE;
  rule_id: string;
  details: string;
  file: string;
  code: string;
  line: string;
  column: string;
  nosec: boolean;
  suppressions: GosecSuppression[] | null;
}

/**
 * Severity to HDF impact mapping for gosec.
 */
const IMPACT_MAPPING: Record<string, number> = {
  HIGH: 0.7,
  MEDIUM: 0.5,
  LOW: 0.3,
};


/**
 * Returns true if the issue is suppressed (via nosec flag or suppressions list).
 */
function isSuppressed(issue: GosecIssue): boolean {
  return issue.nosec || issue.suppressions !== null;
}

/**
 * Builds a skip message from a suppressions list.
 * Returns undefined when suppressions is null (issue not suppressed via list).
 */
function formatSkipMessage(suppressions: GosecSuppression[] | null): string | undefined {
  if (suppressions === null) {
    return undefined;
  }
  if (suppressions.length === 0) {
    return 'No justification provided';
  }
  return suppressions
    .map(s => `${s.justification || 'No justification provided'} (${s.kind})`)
    .join('\n');
}

/**
 * Converts a single GosecIssue to an HDF RequirementResult.
 */
function issueToResult(issue: GosecIssue): RequirementResult {
  const suppressed = isSuppressed(issue);
  const status = suppressed ? ResultStatus.NotReviewed : ResultStatus.Failed;

  let message: string;
  if (suppressed) {
    const skipMsg = formatSkipMessage(issue.suppressions);
    message = skipMsg ?? 'No justification provided';
  } else {
    message = `${issue.confidence} confidence of rule violation at:\n${issue.code}`;
  }

  const codeDesc = `Rule ${issue.rule_id} violation detected at:\nFile: ${issue.file}\nLine: ${issue.line}\nColumn: ${issue.column}`;

  return createResult(status, message, { codeDesc });
}

/**
 * Converts a group of issues sharing a rule_id into one EvaluatedRequirement.
 */
function buildRequirement(ruleId: string, issues: GosecIssue[]): EvaluatedRequirement {
  const rep = issues[0]!;
  const impact = IMPACT_MAPPING[rep.severity.toUpperCase()] ?? 0.5;
  const nist = mapCWEToNIST([rep.cwe.id], DEFAULT_REMEDIATION_NIST_TAGS);

  const tags: Record<string, unknown> = {
    nist,
    cwe: { id: rep.cwe.id, url: rep.cwe.url },
  };

  const results = issues.map(issueToResult);

  const descriptions: Description[] = [
    { label: 'default', data: rep.details },
    { label: 'check', data: `CWE-${rep.cwe.id}: ${rep.cwe.url}` },
  ];

  return createRequirement(ruleId, rep.details, descriptions, impact, results, { tags });
}

/**
 * Converts gosec output to HDF format.
 * Accepts both native gosec JSON and SARIF format — SARIF input is detected
 * automatically and delegated to the shared SARIF converter.
 *
 * @param input - gosec JSON or SARIF string
 * @returns HDF JSON string
 */
export async function convertGosecToHdf(input: string): Promise<string> {
  validateInputSize(input, 'gosec');
  // Detect format: if SARIF, delegate to the shared SARIF converter
  registerAllFingerprints();
  const detected = detectConverter(input);
  if (detected && detected.fingerprint.id === 'sarif-to-hdf') {
    return convertSarifToHdf(input);
  }

  const resultsChecksum: Checksum = await inputChecksum(input);

  const report = parseJSON<GosecReport>(input);

  if (!report || typeof report !== 'object') {
    throw new Error('Invalid gosec structure: not a valid JSON object');
  }

  if (!Array.isArray(report.Issues)) {
    throw new Error('Invalid gosec structure: missing or invalid Issues field');
  }

  // Group issues by rule_id, preserving insertion order.
  const { items: limitedIssues, truncated: truncatedIssues } = limitArray(report.Issues);
  /* v8 ignore next -- truncation only triggers with >100K items */
  if (truncatedIssues) {
    // eslint-disable-next-line no-console
    console.warn(`WARNING: Input truncated at ${limitedIssues.length} issue items (original: ${report.Issues.length})`);
  }
  const groups = new Map<string, GosecIssue[]>();
  for (const issue of limitedIssues) {
    const existing = groups.get(issue.rule_id);
    if (existing) {
      existing.push(issue);
    } else {
      groups.set(issue.rule_id, [issue]);
    }
  }

  const requirements: EvaluatedRequirement[] = [];
  for (const [ruleId, issues] of groups) {
    requirements.push(buildRequirement(ruleId, issues));
  }

  const baseline: EvaluatedBaseline = createMinimalBaseline(
    'gosec Scan',
    requirements,
    { resultsChecksum }
  ) as EvaluatedBaseline;

  return buildHdfResults({
    generatorName: 'gosec-to-hdf',
    converterVersion: '1.0.0',
    toolName: 'gosec',
    toolVersion: report.GosecVersion || undefined,
    baselines: [baseline],
    timestamp: new Date(),
  });
}
