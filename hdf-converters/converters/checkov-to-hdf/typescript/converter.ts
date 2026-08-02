import { parseJSON } from '@mitre/hdf-utilities';
import { DEFAULT_STATIC_ANALYSIS_NIST_TAGS } from '@mitre/hdf-mappings';
import { detectConverter } from '../../../shared/typescript/fingerprint.js';
import { registerAllFingerprints } from '../../../shared/typescript/register-all.js';
import { convertSarifToHdf } from '../../sarif-to-hdf/typescript/converter.js';
import { buildNoFindingsRequirement, deriveControlTypeFromTags, inputChecksum, limitArray, validateInputSize, buildHdfResults } from '../../../shared/typescript/converterutil.js';
import type {
  EvaluatedBaseline,
  EvaluatedRequirement,
  RequirementResult,
  Checksum,
} from '@mitre/hdf-schema';
import {
  ResultStatus,
  VerificationMethodEnum,
  severityToImpact,
  createMinimalBaseline,
  createRequirement,
  createResult,
  type Description,
} from '@mitre/hdf-schema';

/**
 * Checkov JSON output structures.
 */
interface CheckovReport {
  check_type: string;
  results: CheckovResults;
  summary: CheckovSummary;
}

interface CheckovResults {
  passed_checks: CheckovCheck[];
  failed_checks: CheckovCheck[];
  skipped_checks: CheckovCheck[];
}

interface CheckovSummary {
  passed: number;
  failed: number;
  skipped: number;
  parsing_errors: number;
  resource_count: number;
  checkov_version: string;
}

interface CheckovCheck {
  check_id: string;
  check_name: string;
  check_result: CheckovCheckResult;
  severity: string | null;
  file_path: string;
  file_line_range: number[];
  resource: string;
  guideline: string | null;
  code_block: unknown;
  check_class: string;
}

interface CheckovCheckResult {
  result: string;
  suppress_comment?: string;
}

/**
 * Maps checkov result string to HDF ResultStatus.
 */
function mapStatus(result: string): ResultStatus {
  switch (result.toUpperCase()) {
    case 'PASSED':
      return ResultStatus.Passed;
    case 'FAILED':
      return ResultStatus.Failed;
    case 'SKIPPED':
      return ResultStatus.NotReviewed;
    default:
      return ResultStatus.NotReviewed;
  }
}

/**
 * Maps severity to impact, defaulting to 0.5 for null/unknown.
 */
function getImpact(severity: string | null): number {
  if (!severity) return 0.5;
  return severityToImpact(severity);
}

/**
 * Converts a single CheckovCheck to an HDF RequirementResult.
 */
function checkToResult(check: CheckovCheck, scanTime: Date): RequirementResult {
  const status = mapStatus(check.check_result.result);
  const codeDesc = `Resource: ${check.resource}\nFile: ${check.file_path} (lines ${JSON.stringify(check.file_line_range)})`;

  let message: string | undefined;
  if (status === ResultStatus.NotReviewed && check.check_result.suppress_comment) {
    message = check.check_result.suppress_comment;
  }

  // message carries the suppression comment, so results without one carry no message key.
  return createResult(status, message, { codeDesc, startTime: scanTime });
}

/** A check paired with the check_type of the report it came from. */
interface CheckWithType {
  check: CheckovCheck;
  checkType: string;
}

/**
 * Renders checkov's code_block ([[lineno, "source"], ...]) into a readable,
 * line-numbered source snippet for the Heimdall CODE tab. Returns undefined when
 * the code_block is absent or not an array so requirement.code is omitted.
 */
function renderCodeBlock(codeBlock: unknown): string | undefined {
  if (!Array.isArray(codeBlock)) return undefined;
  const lines: string[] = [];
  for (const entry of codeBlock) {
    if (!Array.isArray(entry) || entry.length < 2) continue;
    const lineno = entry[0];
    const src = typeof entry[1] === 'string' ? entry[1] : '';
    const trimmed = src.endsWith('\n') ? src.slice(0, -1) : src;
    lines.push(`${lineno} ${trimmed}`);
  }
  return lines.length ? lines.join('\n') : undefined;
}

/**
 * Converts a group of checks sharing a check_id into one EvaluatedRequirement.
 */
function buildRequirement(checkId: string, group: CheckWithType[], scanTime: Date): EvaluatedRequirement {
  const checks = group.map((c) => c.check);
  const rep = checks[0]!;
  const impact = getImpact(rep.severity);

  const tags: Record<string, unknown> = {
    nist: [...DEFAULT_STATIC_ANALYSIS_NIST_TAGS],
  };
  // The scan scope (which framework's report produced this finding) is
  // requirement-level data, not tool metadata. Mirrors the Go converter.
  const checkTypes = [...new Set(group.map((c) => c.checkType).filter((t) => t !== ''))].sort();
  if (checkTypes.length > 0) {
    tags['check_type'] = checkTypes;
  }

  const descriptions: Description[] = [
    { label: 'default', data: rep.check_name },
  ];
  if (rep.guideline) {
    descriptions.push({ label: 'check', data: rep.guideline });
  }

  const results = checks.map((check) => checkToResult(check, scanTime));

  const req = createRequirement(checkId, rep.check_name, descriptions, impact, results, { tags }) as EvaluatedRequirement;
  req.verificationMethod = VerificationMethodEnum.Automated;

  const code = renderCodeBlock(rep.code_block);
  if (code !== undefined) {
    req.code = code;
  }

  const controlType = deriveControlTypeFromTags([...DEFAULT_STATIC_ANALYSIS_NIST_TAGS]);
  if (controlType !== undefined) {
    req.controlType = controlType;
  }

  return req;
}

/**
 * Parses checkov input which can be a single object or array.
 */
function parseInput(input: string): CheckovReport[] {
  const parsed = parseJSON<CheckovReport | CheckovReport[]>(input);
  if (Array.isArray(parsed)) {
    return parsed;
  }
  if (!parsed || typeof parsed !== 'object') {
    throw new Error('Invalid checkov structure: not a valid JSON object');
  }
  if (!parsed.results || typeof parsed.results !== 'object') {
    throw new Error('Invalid checkov structure: missing or invalid results field');
  }
  return [parsed];
}

/**
 * Converts checkov output to HDF format.
 * Accepts native checkov JSON (single object or array) and SARIF format.
 * SARIF input is detected automatically and delegated to the shared SARIF converter.
 *
 * @param input - checkov JSON or SARIF string
 * @returns HDF JSON string
 */
export async function convertCheckovToHdf(input: string, converterVersion = '1.0.0'): Promise<string> {
  validateInputSize(input, 'checkov');

  // Detect SARIF format and delegate
  registerAllFingerprints();
  const detected = detectConverter(input);
  if (detected && detected.fingerprint.id === 'sarif-to-hdf') {
    return convertSarifToHdf(input, converterVersion);
  }

  const resultsChecksum: Checksum = await inputChecksum(input);

  // Checkov native JSON carries no per-finding or scan timestamp; use conversion time
  // for every result's startTime, the no-findings placeholder, and the document timestamp.
  const scanTime = new Date();

  const reports = parseInput(input);

  // Merge all checks from all frameworks
  const allChecks: CheckWithType[] = [];
  const checkTypes: string[] = [];
  let version: string | undefined;

  for (const report of reports) {
    checkTypes.push(report.check_type);
    if (!version && report.summary.checkov_version) {
      version = report.summary.checkov_version;
    }
    for (const check of [...report.results.passed_checks, ...report.results.failed_checks, ...report.results.skipped_checks]) {
      allChecks.push({ check, checkType: report.check_type });
    }
  }

  const { items: limitedChecks, truncated } = limitArray(allChecks);
  /* v8 ignore next -- truncation only triggers with >100K items */
  if (truncated) {
    // eslint-disable-next-line no-console
    console.warn(`WARNING: Input truncated at ${limitedChecks.length} check items (original: ${allChecks.length})`);
  }

  // Group by check_id preserving insertion order
  const groups = new Map<string, CheckWithType[]>();
  for (const entry of limitedChecks) {
    const existing = groups.get(entry.check.check_id);
    if (existing) {
      existing.push(entry);
    } else {
      groups.set(entry.check.check_id, [entry]);
    }
  }

  const requirements: EvaluatedRequirement[] = [];
  for (const [checkId, checks] of groups) {
    requirements.push(buildRequirement(checkId, checks, scanTime));
  }

  // The joined check_types survive only in the no-findings message; the
  // per-finding scan scope lives in requirement tags (never tool.format).
  const format = checkTypes.join(', ');

  if (requirements.length === 0) {
    const target = format || 'input';
    requirements.push(buildNoFindingsRequirement(
      'checkov-no-findings',
      `Checkov scanned ${target} and reported zero findings.`,
      scanTime,
    ));
  }

  const baseline: EvaluatedBaseline = createMinimalBaseline(
    'Checkov Scan',
    requirements,
    { resultsChecksum }
  ) as EvaluatedBaseline;

  return buildHdfResults({
    generatorName: 'checkov-to-hdf',
    converterVersion,
    toolName: 'Checkov',
    toolVersion: version,
    baselines: [baseline],
    timestamp: scanTime,
  });
}
