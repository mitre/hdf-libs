import { getAwsConfigNistControlByName } from '@mitre/hdf-mappings';
import { ResultStatus } from '@mitre/hdf-schema';

export type AsffFinding = Record<string, unknown>;

export type SpecialCase = 'Default' | 'SecurityHub';

export interface CaseHandler {
  productName(findings: AsffFinding[]): string;
  findingId(finding: AsffFinding): string;
  findingTitle(finding: AsffFinding): string;
  findingImpact(finding: AsffFinding): number;
  findingNistTags(finding: AsffFinding): string[];
  findingStatus(finding: AsffFinding): ResultStatus;
}

// Heimdall2 parity: same impact band as the Go side.
const SEVERITY_IMPACT_MAP: Record<string, number> = {
  CRITICAL: 0.9,
  HIGH: 0.7,
  MEDIUM: 0.5,
  LOW: 0.3,
  INFORMATIONAL: 0.0,
};

export function asffLabelToImpact(label: string): number | undefined {
  return SEVERITY_IMPACT_MAP[label];
}

// Public name preserved for tests that imported the previous constant shape.
export const ASFF_SEVERITY_TO_IMPACT = SEVERITY_IMPACT_MAP;

const PRODUCT_SECURITY_HUB = /^arn:[^:]+:securityhub:[^:]+:[^:]*:product\/aws\/securityhub$/;

export function whichSpecialCase(finding: AsffFinding): SpecialCase {
  const productArn = (finding.ProductArn as string) ?? '';
  if (PRODUCT_SECURITY_HUB.test(productArn)) return 'SecurityHub';
  return 'Default';
}

export function dispatch(finding: AsffFinding): CaseHandler {
  switch (whichSpecialCase(finding)) {
    case 'SecurityHub':
      return securityHubHandler;
    default:
      return defaultHandler;
  }
}

export function dispatchAll(findings: AsffFinding[]): CaseHandler {
  const first = findings[0];
  if (!first) return defaultHandler;
  return dispatch(first);
}

// ---- helpers ----

function getNested(m: unknown, path: string): string | undefined {
  if (typeof m !== 'object' || m === null) return undefined;
  const direct = (m as Record<string, unknown>)[path];
  if (typeof direct === 'string') return direct;
  const dotIdx = path.indexOf('.');
  if (dotIdx >= 0) {
    const head = path.slice(0, dotIdx);
    const rest = path.slice(dotIdx + 1);
    const nested = (m as Record<string, unknown>)[head];
    return getNested(nested, rest);
  }
  return undefined;
}

function getSeverityLabel(finding: AsffFinding): string | undefined {
  const sev = finding.Severity as Record<string, unknown> | undefined;
  return typeof sev?.Label === 'string' ? sev.Label : undefined;
}

function getNormalizedSeverity(finding: AsffFinding): number | undefined {
  const sev = finding.Severity as Record<string, unknown> | undefined;
  return typeof sev?.Normalized === 'number' ? sev.Normalized : undefined;
}

function isSuppressed(finding: AsffFinding): boolean {
  const w = finding.Workflow as Record<string, unknown> | undefined;
  return w?.Status === 'SUPPRESSED';
}

function titleCase(s: string): string {
  return s
    .split(/\s+/)
    .filter((p) => p.length > 0)
    .map((p) => (p[0] ?? '').toUpperCase() + p.slice(1))
    .join(' ');
}

// ---- default case ----

export const defaultHandler: CaseHandler = {
  productName(findings) {
    const first = findings[0];
    if (!first) return 'ASFF Findings';
    const productArn = (first.ProductArn as string) ?? '';
    const tail = productArn.split(':').pop() ?? '';
    const segs = tail.split('/');
    if (segs.length >= 3) return `${segs[1]} - ${segs[2]}`;
    return 'ASFF Findings';
  },
  findingId(finding) {
    return (finding.GeneratorId as string) ?? '';
  },
  findingTitle(finding) {
    return (finding.Title as string) ?? '';
  },
  findingImpact(finding) {
    if (isSuppressed(finding)) return 0.0;
    const label = getSeverityLabel(finding);
    if (label) {
      const v = asffLabelToImpact(label);
      if (v !== undefined) return v;
    }
    const norm = getNormalizedSeverity(finding);
    if (typeof norm === 'number') return norm / 100;
    return 0.0;
  },
  findingNistTags(_finding) {
    return [];
  },
  findingStatus(finding) {
    const c = finding.Compliance as Record<string, unknown> | undefined;
    if (!c) return ResultStatus.Failed;
    switch (c.Status) {
      case 'PASSED':
        return ResultStatus.Passed;
      case 'FAILED':
        return ResultStatus.Failed;
      case 'WARNING':
      case 'NOT_AVAILABLE':
        return ResultStatus.NotReviewed;
      default:
        return ResultStatus.Error;
    }
  },
};

// ---- SecurityHub case ----

export const securityHubHandler: CaseHandler = {
  ...defaultHandler,
  productName(findings) {
    const first = findings[0];
    if (!first) return 'AWS Security Hub';
    const arn = getNested(first, 'ProductFields.StandardsControlArn');
    if (!arn) return defaultHandler.productName(findings);
    const segs = arn.split('/');
    if (segs.length < 4) return defaultHandler.productName(findings);
    const standardSlug = segs[segs.length - 4] ?? '';
    const version = segs[segs.length - 2] ?? '';
    return `${titleCase(standardSlug.replace(/-/g, ' '))} v${version}`;
  },
  findingId(finding) {
    const controlId = getNested(finding, 'ProductFields.ControlId');
    if (controlId) return controlId;
    const ruleId = getNested(finding, 'ProductFields.RuleId');
    if (ruleId) return ruleId;
    const gen = (finding.GeneratorId as string) ?? '';
    const slashIdx = gen.lastIndexOf('/');
    return slashIdx >= 0 ? gen.slice(slashIdx + 1) : gen;
  },
  findingImpact(finding) {
    if (isSuppressed(finding)) return 0.0;
    const label = getSeverityLabel(finding);
    if (label === 'INFORMATIONAL') {
      // Heimdall2 parity — Security Hub mislabels real findings as informational.
      return 0.5;
    }
    if (label) {
      const v = asffLabelToImpact(label);
      if (v !== undefined) return v;
    }
    const norm = getNormalizedSeverity(finding);
    if (typeof norm === 'number') return norm / 100;
    return 0.0;
  },
  findingNistTags(finding) {
    const related = getNested(finding, 'ProductFields.RelatedAWSResources:0/type');
    if (related !== 'AWS::Config::ConfigRule') return [];
    const name = getNested(finding, 'ProductFields.RelatedAWSResources:0/name');
    if (!name) return [];
    const raw = getAwsConfigNistControlByName(name);
    if (!raw) return [];
    return raw
      .split('|')
      .map((s) => s.trim())
      .filter((s) => s.length > 0);
  },
};
