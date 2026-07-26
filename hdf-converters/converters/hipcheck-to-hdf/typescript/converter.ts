import { parseJSON, parseTimestamp } from '@mitre/hdf-utilities';
import { getHipcheckNistControls, nistToCci } from '@mitre/hdf-mappings';
import {
  buildNistCciTags,
  buildNoFindingsRequirement,
  deriveControlTypeFromTags,
  inputChecksum,
  serializeHdf,
  validateInputSize,
} from '../../../shared/typescript/converterutil.js';
import type {
  HDFResults,
  EvaluatedBaseline,
  EvaluatedRequirement,
  RequirementResult,
  Description,
  Tool,
} from '@mitre/hdf-schema';
import {
  ResultStatus,
  TargetType,
  VerificationMethodEnum,
  createMinimalBaseline,
  createRequirement,
} from '@mitre/hdf-schema';

/** One passing/failing analysis in a Hipcheck report. */
interface Analysis {
  name: string;
  passed: boolean;
  policy_expr?: string;
  final_value?: string | null;
  message?: string;
  concerns?: string[];
}

/** One analysis that failed to run. `analysis` holds the name (not a tag). */
interface ErroredAnalysis {
  name: string;
  error?: ErrorReport;
}

interface ErrorReport {
  msg?: string;
  source?: ErrorReport;
}

interface Recommendation {
  kind?: string;
  reason?: unknown;
  risk_score?: number;
  risk_policy?: string;
}

/** Top-level Hipcheck `hc check --format json` report. */
interface Report {
  repo_name?: string;
  repo_owner?: string | null;
  repo_head?: string;
  hipcheck_version?: string;
  analyzed_at?: string;
  passing?: Analysis[];
  failing?: Analysis[];
  errored?: ErroredAnalysis[];
  recommendation?: Recommendation;
}

/** "owner/name" when both are present, else whichever is non-empty (never a
 * bare "owner/" or "/name"). */
function repoIdent(r: Report): string {
  const owner = r.repo_owner ?? '';
  const name = r.repo_name ?? '';
  if (owner && name) {
    return `${owner}/${name}`;
  }
  return name || owner;
}

/** Build NIST/CCI tags for an analysis name via the hipcheck mapping. */
function analysisTags(name: string): { tags: Record<string, unknown>; nist: string[] } {
  const nist = getHipcheckNistControls(name);
  if (nist.length === 0) {
    return { tags: buildNistCciTags([], []), nist: [] };
  }
  return { tags: buildNistCciTags(nist, nistToCci(nist)), nist };
}

function applyClassification(req: EvaluatedRequirement, nist: string[]): void {
  const controlType = deriveControlTypeFromTags(nist);
  if (controlType !== undefined) {
    req.controlType = controlType;
  }
  req.verificationMethod = VerificationMethodEnum.Automated;
}

function buildAnalysisRequirement(
  a: Analysis,
  status: ResultStatus,
  startTime: Date,
): EvaluatedRequirement {
  const { tags, nist } = analysisTags(a.name);
  const message = a.message ?? '';

  const descriptions: Description[] = [{ label: 'default', data: message }];
  if (a.policy_expr) {
    descriptions.push({ label: 'check', data: a.policy_expr });
  }

  let resultMessage = message;
  if (a.concerns && a.concerns.length > 0) {
    resultMessage = `${message}\nConcerns:\n- ${a.concerns.join('\n- ')}`;
  }

  const result: RequirementResult = {
    status,
    codeDesc: a.policy_expr ?? '',
    message: resultMessage,
    startTime,
  };

  const req = createRequirement(a.name, a.name, descriptions, 0.5, [result], {
    tags,
  }) as EvaluatedRequirement;
  applyClassification(req, nist);
  return req;
}

function buildErroredRequirement(e: ErroredAnalysis, startTime: Date): EvaluatedRequirement {
  const { tags, nist } = analysisTags(e.name);
  const msg = flattenError(e.error);

  const result: RequirementResult = {
    status: ResultStatus.Error,
    codeDesc: '',
    message: msg,
    startTime,
  };

  const req = createRequirement(
    e.name,
    e.name,
    [{ label: 'default', data: msg }],
    0.5,
    [result],
    { tags },
  ) as EvaluatedRequirement;
  applyClassification(req, nist);
  return req;
}

/** Render Hipcheck's recursive error chain as "msg: source: ...". */
function flattenError(e: ErrorReport | undefined): string {
  const parts: string[] = [];
  for (let cur = e; cur; cur = cur.source) {
    if (cur.msg) parts.push(cur.msg);
  }
  return parts.length > 0 ? parts.join(': ') : 'unknown error';
}

/** Render a risk score without trailing zeros (0.42, 0.33, 0), matching Go. */
function formatScore(f: number): string {
  return String(f);
}

/** Render the overall recommendation as baseline summary prose. */
function buildSummary(rec: Recommendation): string {
  const base = `Hipcheck recommendation: ${rec.kind ?? ''} (risk score ${formatScore(rec.risk_score ?? 0)}, policy '${rec.risk_policy ?? ''}').`;
  if ((rec.kind ?? '').toLowerCase() !== 'investigate') {
    return base;
  }
  const suffix = investigateReason(rec.reason);
  return suffix ? `${base} ${suffix}` : base;
}

/** Decode the polymorphic `reason` into a sentence, or "". */
function investigateReason(reason: unknown): string {
  if (reason === null || reason === undefined) {
    return '';
  }
  if (typeof reason === 'string') {
    if (reason === 'Policy') {
      return 'Investigation triggered because the risk score exceeded the policy threshold.';
    }
    return `Investigation reason: ${reason}.`;
  }
  if (typeof reason === 'object') {
    const failed = (reason as { FailedAnalyses?: unknown }).FailedAnalyses;
    if (Array.isArray(failed) && failed.length > 0) {
      return `Investigation forced by failed analyses: ${failed.join(', ')}.`;
    }
  }
  return '';
}

/**
 * Converts a MITRE Hipcheck `hc check --format json` report to HDF Results.
 *
 * @param input - Hipcheck JSON report string
 * @returns HDF JSON string
 */
export async function convertHipcheckToHdf(input: string, converterVersion = '1.0.0'): Promise<string> {
  validateInputSize(input, 'hipcheck');
  if (!input || input.trim().length === 0) {
    throw new Error('hipcheck: empty input');
  }

  const report = parseJSON<Report>(input);
  if (!report.hipcheck_version && !report.repo_name) {
    throw new Error('hipcheck: input does not look like a Hipcheck report');
  }

  const parsed = report.analyzed_at ? parseTimestamp(report.analyzed_at) : undefined;
  const startTime = parsed ?? new Date();

  const requirements: EvaluatedRequirement[] = [];
  for (const a of report.passing ?? []) {
    requirements.push(buildAnalysisRequirement(a, ResultStatus.Passed, startTime));
  }
  for (const a of report.failing ?? []) {
    requirements.push(buildAnalysisRequirement(a, ResultStatus.Failed, startTime));
  }
  for (const e of report.errored ?? []) {
    requirements.push(buildErroredRequirement(e, startTime));
  }

  if (requirements.length === 0) {
    requirements.push(
      buildNoFindingsRequirement(
        'hipcheck-no-findings',
        `Hipcheck analyzed ${repoIdent(report)} and reported zero analyses.`,
        startTime,
      ),
    );
  }

  const summary = buildSummary(report.recommendation ?? {});
  const title = `Hipcheck analysis of ${repoIdent(report)} @ ${report.repo_head ?? ''}`;
  const resultsChecksum = await inputChecksum(input);

  const baseline: EvaluatedBaseline = createMinimalBaseline('Hipcheck Scan', requirements, {
    title,
    summary,
    resultsChecksum,
  }) as EvaluatedBaseline;

  const tool: Tool = { name: 'Hipcheck', format: 'JSON', version: report.hipcheck_version };

  const hdf: HDFResults = {
    baselines: [baseline],
    generator: { name: 'hipcheck-to-hdf', version: converterVersion },
    tool,
    timestamp: new Date(),
  };

  const ident = repoIdent(report);
  if (ident) {
    hdf.components = [{ name: ident, type: TargetType.Repository }];
  }

  return serializeHdf(hdf);
}
