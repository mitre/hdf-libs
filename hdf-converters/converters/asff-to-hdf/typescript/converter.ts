/**
 * AWS Security Finding Format (ASFF) to HDF converter.
 *
 * A single ASFF envelope can carry findings from many products, and Security Hub
 * findings span multiple compliance standards (CIS, AFSBP, PCI, ...). Because
 * hdf-results supports multiple baselines in one document, each product — and
 * each Security Hub standard — becomes its own baseline entry, mirroring the
 * per-file split the predecessor SAF CLI produced.
 */

import { parseJSON, parseTimestamp } from '@mitre/hdf-utilities';
import {
  nistToCci,
  getAwsConfigNistControlsBySubstring,
  DEFAULT_STATIC_ANALYSIS_NIST_TAGS,
} from '@mitre/hdf-mappings';
import {
  buildNoFindingsRequirement,
  deriveControlTypeFromTags,
  inputChecksum,
  buildNistCciTags,
  serializeHdf,
  validateInputSize,
} from '../../../shared/typescript/converterutil.js';
import type {
  HDFResults,
  EvaluatedBaseline,
  EvaluatedRequirement,
  RequirementResult,
  Description,
  Component,
} from '@mitre/hdf-schema';
import {
  ResultStatus,
  TargetType,
  createMinimalBaseline,
  createRequirement,
  createResult,
} from '@mitre/hdf-schema';

interface AsffSeverity {
  Label?: string;
  Normalized?: number;
}

interface AsffFinding {
  Id?: string;
  GeneratorId?: string;
  ProductArn?: string;
  AwsAccountId?: string;
  Title?: string;
  Description?: string;
  Types?: string[];
  SourceUrl?: string;
  LastObservedAt?: string;
  UpdatedAt?: string;
  Severity?: AsffSeverity;
  Remediation?: { Recommendation?: { Text?: string; Url?: string } };
  ProductFields?: Record<string, string>;
  Resources?: { Type?: string; Id?: string; Partition?: string; Region?: string }[];
  Compliance?: { Status?: string; StatusReasons?: { ReasonCode?: string; Description?: string }[] };
  Workflow?: { Status?: string };
}

/** Accepts the `{ "Findings": [...] }` envelope, a bare array, or a single finding. */
function parseFindings(input: string): AsffFinding[] {
  const parsed = parseJSON<unknown>(input);
  if (parsed !== null && typeof parsed === 'object' && 'Findings' in parsed) {
    const findings = (parsed as { Findings: unknown }).Findings;
    return Array.isArray(findings) ? (findings as AsffFinding[]) : [];
  }
  if (Array.isArray(parsed)) {
    return parsed as AsffFinding[];
  }
  if (parsed !== null && typeof parsed === 'object') {
    return [parsed as AsffFinding];
  }
  throw new Error('invalid ASFF JSON');
}

/**
 * mapComplianceStatus maps ASFF Compliance.Status to an HDF result status.
 * hdf-results has no "skipped": WARNING and NOT_AVAILABLE (no clean pass/fail
 * verdict) map to notReviewed; an absent status defaults to failed.
 */
export function mapComplianceStatus(status: string | undefined): ResultStatus {
  switch (status) {
    case 'PASSED':
      return ResultStatus.Passed;
    case 'FAILED':
      return ResultStatus.Failed;
    case 'WARNING':
    case 'NOT_AVAILABLE':
      return ResultStatus.NotReviewed;
    case undefined:
    case '':
      return ResultStatus.Failed;
    default:
      return ResultStatus.Error;
  }
}

export function severityLabelToImpact(label: string | undefined): number {
  switch ((label ?? '').toUpperCase()) {
    case 'CRITICAL':
      return 0.9;
    case 'HIGH':
      return 0.7;
    case 'MEDIUM':
      return 0.5;
    case 'LOW':
      return 0.3;
    default:
      return 0.0;
  }
}

/**
 * findingImpact derives a 0.0–1.0 impact. Suppressed findings are forced to 0.
 * Security Hub's INFORMATIONAL is up-graded to MEDIUM (Security Hub over-marks
 * findings INFORMATIONAL without context).
 */
export function findingImpact(f: AsffFinding): number {
  if (f.Workflow?.Status === 'SUPPRESSED') {
    return 0.0;
  }
  let label = f.Severity?.Label;
  if (isSecurityHub(f) && (label ?? '').toUpperCase() === 'INFORMATIONAL') {
    label = 'MEDIUM';
  }
  if (label) {
    return severityLabelToImpact(label);
  }
  if (typeof f.Severity?.Normalized === 'number') {
    return f.Severity.Normalized / 100.0;
  }
  return 0.0;
}

function productArnParts(arn: string | undefined): [string, string] {
  if (!arn) return ['', ''];
  const tail = arn.split(':').pop() ?? '';
  const segs = tail.split('/');
  if (segs.length >= 3) return [segs[1]!, segs[2]!];
  return ['', ''];
}

function isSecurityHub(f: AsffFinding): boolean {
  return productArnParts(f.ProductArn)[1] === 'securityhub';
}

const normalizeStd = (s: string): string => s.toLowerCase().replace(/-/g, ' ');

function titleCaseWords(s: string): string {
  return s
    .split(/\s+/)
    .filter(Boolean)
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(' ');
}

/**
 * securityHubStandardName derives "CIS AWS Foundations Benchmark v1.2.0" from a
 * finding's StandardsControlArn, preferring the nicer Types[0] casing when it
 * matches the ARN's standard slug (mirrors the SAF CLI grouping key).
 */
function securityHubStandardName(f: AsffFinding): string {
  const arn = f.ProductFields?.StandardsControlArn ?? '';
  if (!arn) return '';
  const segs = arn.split('/');
  if (segs.length < 4) return '';
  const slug = segs[segs.length - 4]!;
  const version = segs[segs.length - 2]!;

  let typesLast = '';
  if (f.Types && f.Types.length > 0) {
    const ts = f.Types[0]!.split('/');
    typesLast = ts[ts.length - 1]!;
  }

  const standard =
    typesLast && normalizeStd(typesLast) === normalizeStd(slug)
      ? typesLast.replace(/-/g, ' ')
      : titleCaseWords(slug.replace(/-/g, ' '));
  return `${standard} v${version}`;
}

/** Level-1 grouping key: Security Hub standard name, else ProductArn identity. */
function baselineName(f: AsffFinding): string {
  if (isSecurityHub(f)) {
    const name = securityHubStandardName(f);
    if (name) return name;
  }
  const [company, product] = productArnParts(f.ProductArn);
  if (!company && !product) return 'AWS Security Finding Format';
  return `${company} - ${product}`;
}

/** Level-2 grouping key within a baseline. */
function controlId(f: AsffFinding): string {
  if (isSecurityHub(f)) {
    if (f.ProductFields?.ControlId) return f.ProductFields.ControlId;
    if (f.ProductFields?.RuleId) return f.ProductFields.RuleId;
  }
  if (f.GeneratorId) {
    const segs = f.GeneratorId.split('/');
    return segs[segs.length - 1]!;
  }
  return f.Id ?? '';
}

/**
 * nistTags derives NIST controls for a finding group: AWS Config rule → NIST via
 * the shared awsconfig mapping, falling back to the static analysis default
 * bundle (matching the SAF CLI) when no config rule applies.
 */
function nistTags(group: AsffFinding[]): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const f of group) {
    for (const tag of configRuleNist(f)) {
      if (!seen.has(tag)) {
        seen.add(tag);
        out.push(tag);
      }
    }
  }
  return out.length > 0 ? out : DEFAULT_STATIC_ANALYSIS_NIST_TAGS;
}

function configRuleNist(f: AsffFinding): string[] {
  if (f.ProductFields?.['RelatedAWSResources:0/type'] !== 'AWS::Config::ConfigRule') {
    return [];
  }
  const name = f.ProductFields?.['RelatedAWSResources:0/name'];
  if (!name) return [];
  return getAwsConfigNistControlsBySubstring(name);
}

function remediationText(f: AsffFinding): string {
  const parts: string[] = [];
  const rec = f.Remediation?.Recommendation;
  if (rec?.Text) parts.push(rec.Text);
  if (rec?.Url) parts.push(rec.Url);
  return parts.join('\n');
}

function resourceCodeDesc(f: AsffFinding): string {
  const parts = (f.Resources ?? []).map((r) => {
    let seg = `Type: ${r.Type ?? ''}, Id: ${r.Id ?? ''}`;
    if (r.Partition) seg += `, Partition: ${r.Partition}`;
    if (r.Region) seg += `, Region: ${r.Region}`;
    return seg;
  });
  return `Resources: [${parts.join('; ')}]`;
}

function statusReason(f: AsffFinding): string {
  const lines: string[] = [];
  for (const r of f.Compliance?.StatusReasons ?? []) {
    if (r.ReasonCode) lines.push(`ReasonCode: ${r.ReasonCode}`);
    if (r.Description) lines.push(`Description: ${r.Description}`);
  }
  return lines.join('\n');
}

function buildResult(f: AsffFinding): RequirementResult {
  const start = parseTimestamp(f.LastObservedAt ?? f.UpdatedAt ?? '') ?? new Date();
  const message = statusReason(f);
  return createResult(mapComplianceStatus(f.Compliance?.Status), message || undefined, {
    codeDesc: resourceCodeDesc(f),
    startTime: start,
  });
}

function buildRequirement(id: string, group: AsffFinding[]): EvaluatedRequirement {
  const primary = group[0]!;
  const impact = Math.max(...group.map(findingImpact));

  const descriptions: Description[] = [
    { label: 'default', data: primary.Description ?? primary.Title ?? '' },
  ];
  const fix = remediationText(primary);
  if (fix) descriptions.push({ label: 'fix', data: fix });

  const nist = nistTags(group);
  const tags = nist.length > 0 ? buildNistCciTags(nist, nistToCci(nist)) : {};

  const results = group.map(buildResult);

  const req = createRequirement(id, primary.Title ?? '', descriptions, impact, results, {
    tags,
  }) as EvaluatedRequirement;

  const controlType = deriveControlTypeFromTags(nist);
  if (controlType !== undefined) {
    req.controlType = controlType;
  }
  if (primary.SourceUrl) {
    req.refs = [{ url: primary.SourceUrl }];
  }
  return req;
}

function buildBaseline(
  name: string,
  findings: AsffFinding[],
  resultsChecksum: HDFResults['baselines'][number]['resultsChecksum']
): EvaluatedBaseline {
  const order: string[] = [];
  const groups = new Map<string, AsffFinding[]>();
  for (const f of findings) {
    const id = controlId(f);
    const existing = groups.get(id);
    if (existing) {
      existing.push(f);
    } else {
      order.push(id);
      groups.set(id, [f]);
    }
  }

  const requirements = order.map((id) => buildRequirement(id, groups.get(id)!));
  return createMinimalBaseline(name, requirements, { resultsChecksum }) as EvaluatedBaseline;
}

/** Converts an ASFF document to HDF Results JSON. */
export async function convertAsffToHdf(input: string, converterVersion = '1.0.0'): Promise<string> {
  if (!input || input.trim().length === 0) {
    throw new Error('asff: empty input');
  }
  validateInputSize(input, 'asff');

  const findings = parseFindings(input);
  const resultsChecksum = await inputChecksum(input);

  const order: string[] = [];
  const byBaseline = new Map<string, AsffFinding[]>();
  const accounts: string[] = [];
  const seenAccount = new Set<string>();
  for (const f of findings) {
    const name = baselineName(f);
    const existing = byBaseline.get(name);
    if (existing) {
      existing.push(f);
    } else {
      order.push(name);
      byBaseline.set(name, [f]);
    }
    if (f.AwsAccountId && !seenAccount.has(f.AwsAccountId)) {
      seenAccount.add(f.AwsAccountId);
      accounts.push(f.AwsAccountId);
    }
  }

  let baselines = order.map((name) => buildBaseline(name, byBaseline.get(name)!, resultsChecksum));

  if (baselines.length === 0) {
    baselines = [
      createMinimalBaseline(
        'AWS Security Finding Format',
        [
          buildNoFindingsRequirement(
            'asff-no-findings',
            'AWS Security Finding Format input contained zero findings.',
            new Date()
          ),
        ],
        { resultsChecksum }
      ) as EvaluatedBaseline,
    ];
  }

  const hdf: HDFResults = {
    baselines,
    generator: { name: 'asff-to-hdf', version: converterVersion },
    tool: { name: 'AWS Security Finding Format', format: 'JSON' },
    timestamp: new Date(),
  };

  if (accounts.length > 0) {
    const refs = baselines.map((b) => b.name);
    hdf.components = accounts.map(
      (acct): Component => ({ name: acct, type: TargetType.CloudAccount, baselineRefs: refs })
    );
  }

  return serializeHdf(hdf);
}
