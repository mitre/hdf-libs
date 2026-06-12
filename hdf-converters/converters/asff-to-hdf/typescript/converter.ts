import { parseJSON } from '@mitre/hdf-utilities';
import { nistToCci } from '@mitre/hdf-mappings';
import {
  TargetType,
  ResultStatus,
  VerificationMethodEnum,
  type EvaluatedBaseline,
  type EvaluatedRequirement,
  type RequirementResult,
  type Description,
  type Reference,
  type Component,
} from '@mitre/hdf-schema';
import {
  buildHdfResults,
  buildNoFindingsRequirement,
  deriveControlTypeFromTags,
  inputChecksum,
  validateInputSize,
} from '../../../shared/typescript/converterutil.js';
import {
  dispatch,
  dispatchAll,
  type AsffFinding,
  type CaseHandler,
} from './cases.js';

const GENERATOR_NAME = 'asff-to-hdf';
const TOOL_NAME = 'AWS Security Finding Format';
const TOOL_FORMAT = 'JSON';

/**
 * Convert ASFF (AWS Security Finding Format) JSON to HDF Results.
 *
 * Accepts the standard `{"Findings": [...]}` envelope, a bare top-level
 * array, or a single finding object — heimdall2 parity.
 */
export async function convertAsffToHdf(input: string, converterVersion = '1.0.0'): Promise<string> {
  validateInputSize(input, GENERATOR_NAME);
  if (!input?.trim()) {
    throw new Error(`${GENERATOR_NAME}: empty input`);
  }

  const findings = parseFindings(input);
  const now = new Date();

  let requirements = await buildRequirements(findings, now);
  if (requirements.length === 0) {
    requirements = [
      buildNoFindingsRequirement(
        'asff-no-findings',
        'ASFF scanned the AWS account and reported zero findings.',
        now,
      ),
    ];
  }

  const baseline = await buildBaseline(findings, requirements, input);
  const components = buildComponents(findings);

  return buildHdfResults({
    generatorName: GENERATOR_NAME,
    converterVersion,
    toolName: TOOL_NAME,
    toolFormat: TOOL_FORMAT,
    baselines: [baseline],
    components,
    timestamp: now,
  });
}

function parseFindings(input: string): AsffFinding[] {
  const trimmed = input.trim();
  if (!trimmed) throw new Error(`${GENERATOR_NAME}: empty input`);
  if (trimmed[0] === '[') {
    const arr = parseJSON<unknown>(trimmed);
    if (!Array.isArray(arr)) {
      throw new Error(`${GENERATOR_NAME}: top-level array did not parse as array`);
    }
    return arr.map((v, i) => {
      if (typeof v !== 'object' || v === null || Array.isArray(v)) {
        throw new Error(`${GENERATOR_NAME}: Findings[${i}] is not an object`);
      }
      return v as AsffFinding;
    });
  }
  if (trimmed[0] === '{') {
    const obj = parseJSON<Record<string, unknown>>(trimmed);
    if ('Findings' in obj) {
      const raw = obj.Findings;
      if (!Array.isArray(raw)) {
        throw new Error(`${GENERATOR_NAME}: Findings must be an array`);
      }
      return raw.map((v, i) => {
        if (typeof v !== 'object' || v === null || Array.isArray(v)) {
          throw new Error(`${GENERATOR_NAME}: Findings[${i}] is not an object`);
        }
        return v as AsffFinding;
      });
    }
    return [obj as AsffFinding];
  }
  throw new Error(`${GENERATOR_NAME}: input must be a JSON object or array`);
}

async function buildRequirements(
  findings: AsffFinding[],
  now: Date,
): Promise<EvaluatedRequirement[]> {
  if (findings.length === 0) return [];

  interface Bucket {
    req: EvaluatedRequirement;
    sources: AsffFinding[];
  }
  const order: string[] = [];
  const groups = new Map<string, Bucket>();

  for (const f of findings) {
    const h = dispatch(f);
    const req = buildRequirement(f, h, now);
    const existing = groups.get(req.id);
    if (existing) {
      existing.req.results.push(...req.results);
      existing.req.impact = Math.max(existing.req.impact, req.impact);
      existing.req.descriptions = mergeDescriptions(existing.req.descriptions, req.descriptions);
      existing.req.refs = mergeRefs(existing.req.refs, req.refs);
      existing.req.tags = mergeTags(existing.req.tags, req.tags);
      existing.sources.push(f);
    } else {
      groups.set(req.id, { req, sources: [f] });
      order.push(req.id);
    }
  }

  return order.map((id) => {
    const b = groups.get(id)!;
    b.req.code = JSON.stringify({ Findings: b.sources }, null, 2);
    return b.req;
  });
}

function buildRequirement(
  finding: AsffFinding,
  h: CaseHandler,
  now: Date,
): EvaluatedRequirement {
  const id = h.findingId(finding) || 'asff-finding';
  const title = h.findingTitle(finding);
  const descText = (finding.Description as string) ?? '';
  const descriptions: Description[] = [
    { label: 'default', data: descText.trim() ? descText : title || 'ASFF finding' },
  ];
  const rem = remediationText(finding);
  if (rem) descriptions.push({ label: 'fix', data: rem });

  const impact = h.findingImpact(finding);
  const tags = buildTags(h.findingNistTags(finding));
  const refs = buildRefs(finding);
  const status = h.findingStatus(finding);

  const startTime = parseDate((finding.UpdatedAt as string) ?? '', now);
  const message = statusMessage(finding, status);
  const codeDesc = buildCodeDesc(finding);

  const result: RequirementResult = {
    status,
    codeDesc,
    startTime,
  };
  if (message) result.message = message;

  const req: EvaluatedRequirement = {
    id,
    title,
    descriptions,
    impact,
    tags,
    refs,
    results: [result],
    verificationMethod: VerificationMethodEnum.Automated,
  };
  const controlType = deriveControlTypeFromTags(extractNistTags(tags));
  if (controlType !== undefined) req.controlType = controlType;
  return req;
}

async function buildBaseline(
  findings: AsffFinding[],
  requirements: EvaluatedRequirement[],
  input: string,
): Promise<EvaluatedBaseline> {
  const handler = dispatchAll(findings);
  const productName = findings.length > 0 ? handler.productName(findings) : 'ASFF Findings';
  const checksum = await inputChecksum(input);
  return {
    name: 'ASFF',
    title: productName,
    requirements,
    resultsChecksum: checksum,
  };
}

function buildComponents(findings: AsffFinding[]): Component[] {
  const first = findings[0];
  if (!first) return [];
  const accountId = (first.AwsAccountId as string) ?? '';
  if (!accountId) return [];
  return [
    {
      name: `AWS Account ${accountId}`,
      type: TargetType.CloudAccount,
      labels: { account: accountId, provider: 'aws' },
    },
  ];
}

// ---- helpers ----

function buildTags(nist: string[]): Record<string, unknown> {
  if (nist.length === 0) return {};
  const tags: Record<string, unknown> = { nist };
  const cci = nistToCci(nist);
  if (cci.length > 0) tags.cci = cci;
  return tags;
}

function extractNistTags(tags: Record<string, unknown>): string[] {
  const nist = tags.nist;
  if (!Array.isArray(nist)) return [];
  return nist.filter((v): v is string => typeof v === 'string');
}

function buildRefs(finding: AsffFinding): Reference[] {
  const url = finding.SourceUrl;
  if (typeof url !== 'string' || !url) return [];
  return [{ url }];
}

function remediationText(finding: AsffFinding): string {
  const rem = finding.Remediation as Record<string, unknown> | undefined;
  if (!rem) return '';
  const rec = rem.Recommendation as Record<string, unknown> | undefined;
  if (!rec) return '';
  const parts: string[] = [];
  if (typeof rec.Text === 'string' && rec.Text) parts.push(rec.Text);
  if (typeof rec.Url === 'string' && rec.Url) parts.push(rec.Url);
  return parts.join('\n');
}

function buildCodeDesc(finding: AsffFinding): string {
  const resources = finding.Resources;
  if (!Array.isArray(resources) || resources.length === 0) return 'Resources: []';
  const parts: string[] = [];
  for (const r of resources) {
    if (typeof r !== 'object' || r === null) continue;
    const rm = r as Record<string, unknown>;
    const type = (rm.Type as string) ?? '';
    const id = (rm.Id as string) ?? '';
    let part = `Type: ${type}, Id: ${id}`;
    if (typeof rm.Partition === 'string' && rm.Partition) part += `, Partition: ${rm.Partition}`;
    if (typeof rm.Region === 'string' && rm.Region) part += `, Region: ${rm.Region}`;
    parts.push(part);
  }
  return `Resources: [${parts.join(', ')}]`;
}

function statusMessage(finding: AsffFinding, status: ResultStatus): string {
  const reason = statusReason(finding);
  if (!reason) return '';
  if (status === ResultStatus.Passed || status === ResultStatus.Failed || status === ResultStatus.NotReviewed) {
    return reason;
  }
  return '';
}

function statusReason(finding: AsffFinding): string {
  const c = finding.Compliance as Record<string, unknown> | undefined;
  if (!c) return '';
  const reasons = c.StatusReasons;
  if (!Array.isArray(reasons) || reasons.length === 0) return '';
  const parts: string[] = [];
  for (const r of reasons) {
    if (typeof r !== 'object' || r === null) continue;
    const rm = r as Record<string, unknown>;
    const desc = typeof rm.Description === 'string' ? rm.Description : '';
    const code = typeof rm.ReasonCode === 'string' ? rm.ReasonCode : '';
    if (desc && code) parts.push(`${code}: ${desc}`);
    else if (desc) parts.push(desc);
    else if (code) parts.push(code);
  }
  return parts.join('; ');
}

function parseDate(s: string, fallback: Date): Date {
  if (!s) return fallback;
  const d = new Date(s);
  if (Number.isNaN(d.getTime())) return fallback;
  return d;
}

function mergeDescriptions(a: Description[], b: Description[]): Description[] {
  const seen = new Set<string>();
  const out: Description[] = [];
  for (const d of [...a, ...b]) {
    if (!d.data) continue;
    const key = `${d.label}\0${d.data}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(d);
  }
  return out;
}

function mergeRefs(a: Reference[] | undefined, b: Reference[] | undefined): Reference[] {
  const seen = new Set<string>();
  const out: Reference[] = [];
  for (const r of [...(a ?? []), ...(b ?? [])]) {
    /* v8 ignore next */
    if (!r.url) continue; // buildRefs filters undefined urls; defensive
    if (seen.has(r.url)) continue;
    seen.add(r.url);
    out.push(r);
  }
  return out;
}

function mergeTags(
  a: Record<string, unknown>,
  b: Record<string, unknown>,
): Record<string, unknown> {
  const out: Record<string, unknown> = { ...a };
  for (const [k, v] of Object.entries(b)) {
    if (k in out) {
      out[k] = unionStringArrays(out[k], v);
    } /* v8 ignore next 3 */ else {
      // ASFF findings only ever emit nist+cci tag keys; same-shape per-finding tags
      // make this branch unreachable through normal flow. Defensive only.
      out[k] = v;
    }
  }
  return out;
}

function unionStringArrays(x: unknown, y: unknown): unknown {
  if (Array.isArray(x) && Array.isArray(y)) {
    const all = [...x, ...y];
    const seen = new Set<string>();
    const out: string[] = [];
    for (const v of all) {
      /* v8 ignore next */
      if (typeof v === 'string' && !seen.has(v)) {
        seen.add(v);
        out.push(v);
      }
    }
    return out;
  }
  /* v8 ignore next 2 */
  // Tag values are always string[] in our converter; defensive fallback.
  return x;
}
