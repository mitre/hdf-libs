// Compliance & threshold engine — the TypeScript peer of
// hdf-engine/go/compliance.go. Pure functions, kept at behavioural parity with
// the Go implementation (see test/compliance.test.ts, which runs both over the
// same fixture). Violation message formats match the Go fmt.Sprintf output.

import type { HDFResults, EvaluatedRequirement, RequirementResult, Severity } from '@mitre/hdf-schema';
import { worstStatus, impactToSeverity } from '@mitre/hdf-utilities';
import { effectiveImpactOf } from './effective.js';
import type { ThresholdRule } from './rules.js';

/** Threshold status-key constants (SAF CLI-compatible keys). */
export const THRESHOLD_PASSED = 'passed';
export const THRESHOLD_FAILED = 'failed';
export const THRESHOLD_SKIPPED = 'skipped';
export const THRESHOLD_ERROR = 'error';
export const THRESHOLD_NO_IMPACT = 'no_impact';

/**
 * The name the informational severity bucket had before 3.7.0 renamed it.
 * Accepted on input and echoed back in violations written with it, never
 * emitted by generate.
 */
const LEGACY_INFORMATIONAL_KEY = 'none';

export interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  /** The schema's fifth severity; also absorbs a severity that cannot be derived or is not in the enum. */
  informational: number;
  total: number;
}

export interface StatusCounts {
  passed: SeverityCounts;
  failed: SeverityCounts;
  skipped: SeverityCounts;
  error: SeverityCounts;
  noImpact: SeverityCounts;
}

export interface ControlIDMapping {
  id: string;
  status: string;
  /**
   * The counting BUCKET, not the requirement's raw severity string: always one
   * of `critical`, `high`, `medium`, `low`, `informational`, having gone through
   * severityBucket. Anything else would name a bucket the counts do not have,
   * and a bound listing the control would report a mismatch against the bucket
   * that control was counted in.
   */
  severity: string;
}

export interface ThresholdBound {
  min?: number;
  max?: number;
  controls?: string[];
}

export interface ThresholdSeverity {
  critical?: ThresholdBound;
  high?: ThresholdBound;
  medium?: ThresholdBound;
  low?: ThresholdBound;
  informational?: ThresholdBound;
  /** The name `informational` replaced in 3.7.0; resolved on read, never written. */
  none?: ThresholdBound;
  total?: ThresholdBound;
}

export interface ComplianceBound {
  min?: number;
  max?: number;
}

export interface ThresholdConfig {
  compliance?: ComplianceBound;
  passed?: ThresholdSeverity;
  failed?: ThresholdSeverity;
  skipped?: ThresholdSeverity;
  error?: ThresholdSeverity;
  noImpact?: ThresholdSeverity;
  /**
   * The additive half: a filter predicate plus a bound, for the policies the
   * fixed grid above cannot express. See rules.ts.
   */
  rules?: ThresholdRule[];
}

function newSeverityCounts(): SeverityCounts {
  return { critical: 0, high: 0, medium: 0, low: 0, informational: 0, total: 0 };
}

function newStatusCounts(): StatusCounts {
  return {
    passed: newSeverityCounts(),
    failed: newSeverityCounts(),
    skipped: newSeverityCounts(),
    error: newSeverityCounts(),
    noImpact: newSeverityCounts(),
  };
}

/**
 * overallStatus is the canonical worst-wins roll-up of a requirement's result
 * statuses, delegated to @mitre/hdf-utilities worstStatus (error > failed >
 * passed > notApplicable > notReviewed; empty → notReviewed). No local rank
 * switch — the TS peer of the Go overallStatus dedup (supersedes hdf-libs-ixhx).
 */
export function overallStatus(results: RequirementResult[]): string {
  return worstStatus(results.map((r) => String(r.status)));
}

/**
 * deriveSeverity determines the severity string from impact and optional explicit
 * severity, using impactToSeverity. Both paths yield a value from the schema's
 * severity enum: an explicit informational and an impact-derived one are the same
 * thing and must not land in different buckets.
 */
export function deriveSeverity(impact: number, severity?: Severity | null): string {
  // Presence-based, matching Go DeriveSeverity's `if severity != nil`: an explicit
  // severity — including an empty string — is returned verbatim; only a
  // null/undefined severity derives from impact. Testing truthiness here would
  // send "" through the impact path and diverge from Go (bead 4908.20).
  if (severity != null) {
    return String(severity);
  }
  return impactToSeverity(impact);
}

/**
 * severityBucket folds a severity string into the bucket the threshold grid
 * counts it in. The schema's four named levels pass through; informational and
 * anything outside the enum land in informational, so a malformed severity is
 * counted rather than dropped and a document still gates.
 *
 * Exported because ControlIDMapping.severity is the bucket, not the raw string:
 * a caller assembling its own control map has to apply the same rule or its
 * listing and its counts will disagree. Parity: SeverityBucket in
 * go/compliance.go.
 */
export function severityBucket(severity: string): string {
  switch (severity) {
    case 'critical':
    case 'high':
    case 'medium':
    case 'low':
      return severity;
    default:
      return 'informational';
  }
}

function statusBucket(counts: StatusCounts, status: string): SeverityCounts {
  switch (status) {
    case 'passed':
      return counts.passed;
    case 'failed':
      return counts.failed;
    case 'error':
      return counts.error;
    case 'notApplicable':
      return counts.noImpact;
    case 'notReviewed':
      return counts.skipped;
    default:
      return counts.skipped;
  }
}

function addCount(counts: StatusCounts, status: string, severity: string): void {
  const sc = statusBucket(counts, status);
  sc.total++;
  switch (severityBucket(severity)) {
    case 'critical':
      sc.critical++;
      break;
    case 'high':
      sc.high++;
      break;
    case 'medium':
      sc.medium++;
      break;
    case 'low':
      sc.low++;
      break;
    default:
      sc.informational++;
  }
}

function statusToThresholdKey(status: string): string {
  switch (status) {
    case 'passed':
      return THRESHOLD_PASSED;
    case 'failed':
      return THRESHOLD_FAILED;
    case 'notReviewed':
      return THRESHOLD_SKIPPED;
    case 'error':
      return THRESHOLD_ERROR;
    case 'notApplicable':
      return THRESHOLD_NO_IMPACT;
    default:
      return THRESHOLD_SKIPPED;
  }
}

/**
 * countControlsByStatusSeverity counts requirements by overall status and severity.
 * Reads each requirement's OWN impact and raw result statuses by design: this is the
 * no-override-awareness twin of countControlsByStatus, which is its purpose.
 */
export function countControlsByStatusSeverity(results: HDFResults): StatusCounts {
  const counts = newStatusCounts();
  for (const baseline of results.baselines ?? []) {
    for (const req of baseline.requirements ?? []) {
      addCount(counts, overallStatus(req.results ?? []), deriveSeverity(req.impact, reqSeverity(req)));
    }
  }
  return counts;
}

/**
 * countControlsByStatus counts requirements by a caller-resolved status — the
 * injected-resolver twin of countControlsByStatusSeverity (which counts raw
 * result statuses with no override awareness). statusOf returns each
 * requirement's status in the schema vocabulary (passed/failed/notApplicable/
 * notReviewed/error); an empty or unrecognized value counts as skipped, and an
 * absent resolver yields all-skipped. Callers build effective-status rollups
 * (e.g. compliance with and without agent-attributed overrides) without the
 * engine binding to any one status convention. Parity: go/compliance.go.
 */
export function countControlsByStatus(
  results: HDFResults,
  statusOf?: (req: EvaluatedRequirement) => string,
): StatusCounts {
  const counts = newStatusCounts();
  for (const baseline of results.baselines ?? []) {
    for (const req of baseline.requirements ?? []) {
      const status = statusOf ? statusOf(req) : '';
      // Effective impact, so a governing riskAdjustment moves the requirement
      // into the band it was re-scored into. This function already resolves
      // STATUS through the injected resolver; deriving severity from the raw
      // impact counted one post-adjudication and the other pre-adjudication.
      addCount(counts, status, deriveSeverity(effectiveImpactOf(req), reqSeverity(req)));
    }
  }
  return counts;
}

/**
 * agentOverrideCount counts the status overrides across a result set whose
 * applied-by identity type is "agent" — the detective count. Deterministic
 * from_vex/system overrides are excluded so the count is a meaningful AI-scrutiny
 * signal. Parity: go/compliance.go AgentOverrideCount.
 */
export function agentOverrideCount(results: HDFResults): number {
  let count = 0;
  for (const baseline of results.baselines ?? []) {
    for (const req of baseline.requirements ?? []) {
      for (const o of req.statusOverrides ?? []) {
        if (o.appliedBy?.type === 'agent') {
          count++;
        }
      }
    }
  }
  return count;
}

/** MapControlIDs builds control ID → status/severity mappings from a result set. */
export function mapControlIDs(results: HDFResults): ControlIDMapping[] {
  const mappings: ControlIDMapping[] = [];
  for (const baseline of results.baselines ?? []) {
    for (const req of baseline.requirements ?? []) {
      const status = overallStatus(req.results ?? []);
      mappings.push({
        id: req.id,
        status: statusToThresholdKey(status),
        severity: severityBucket(deriveSeverity(req.impact, reqSeverity(req))),
      });
    }
  }
  return mappings;
}

/**
 * mapControlIDsByStatus builds control ID → status/severity mappings using a
 * caller-resolved status — the injected-resolver twin of mapControlIDs (which
 * maps raw result statuses). statusOf returns each requirement's status in the
 * schema vocabulary; an empty or unrecognized value maps to skipped, and an
 * absent resolver yields all-skipped. Callers build effective-status control
 * listings (the same injection pattern as countControlsByStatus). Parity:
 * go/compliance.go MapControlIDsByStatus.
 */
export function mapControlIDsByStatus(
  results: HDFResults,
  statusOf?: (req: EvaluatedRequirement) => string,
): ControlIDMapping[] {
  const mappings: ControlIDMapping[] = [];
  for (const baseline of results.baselines ?? []) {
    for (const req of baseline.requirements ?? []) {
      const status = statusOf ? statusOf(req) : '';
      mappings.push({
        id: req.id,
        status: statusToThresholdKey(status),
        // Effective impact, matching countControlsByStatus, so a control
        // listing and the counts it is listed alongside cannot disagree.
        severity: severityBucket(deriveSeverity(effectiveImpactOf(req), reqSeverity(req))),
      });
    }
  }
  return mappings;
}

function reqSeverity(req: EvaluatedRequirement): Severity | null {
  return (req.severity ?? null) as Severity | null;
}

/**
 * calculateCompliance returns the compliance percentage rounded to two decimals:
 * passed / (passed + failed + skipped + error) * 100; notApplicable excluded.
 */
export function calculateCompliance(counts: StatusCounts): number {
  const relevant = counts.passed.total + counts.failed.total + counts.skipped.total + counts.error.total;
  if (relevant === 0) {
    return 0;
  }
  const pct = (counts.passed.total / relevant) * 100;
  return Math.round(pct * 100) / 100;
}

/**
/** One status category of a spec after the former severity name has been resolved. */
interface ResolvedSection {
  name: string;
  threshold: ThresholdSeverity | undefined;
  counts: SeverityCounts;
  wroteNone: boolean;
}

/**
 * resolveLegacySeverity folds a section's pre-3.7 `none` key into
 * `informational`, reporting whether the bound was written that way so a
 * violation can name the key the author will find in their own file. A spec
 * setting both is refused rather than resolved: 3.7.0 renamed the bucket, so the
 * two name one thing and silently honouring one would drop a bound the author
 * wrote.
 *
 * The caller's section is COPIED, never rewritten. Folding in place made the
 * name a one-shot property of the config object: the same spec reported the
 * author's key on its first validate pass and the canonical one on every pass
 * after, which is the confusion naming the author's key exists to remove.
 * Parity: resolveLegacySeverity in go/compliance.go.
 */
function resolveLegacySeverity(
  name: string,
  ts: ThresholdSeverity | undefined,
): { threshold: ThresholdSeverity | undefined; wroteNone: boolean; refusal: string } {
  if (!ts?.none) {
    return { threshold: ts, wroteNone: false, refusal: '' };
  }
  if (ts.informational) {
    return {
      threshold: ts,
      wroteNone: false,
      refusal: `${name}: both 'none' and 'informational' are set; 'informational' replaced 'none' in 3.7.0 and both name the same bucket`,
    };
  }
  const resolved: ThresholdSeverity = { ...ts, informational: ts.none };
  delete resolved.none;
  return { threshold: resolved, wroteNone: true, refusal: '' };
}

/**
 * validateThresholds checks all threshold bounds against observed counts and
 * compliance, returning human-readable violation messages (empty when all pass).
 */
export function validateThresholds(
  config: ThresholdConfig,
  counts: StatusCounts,
  compliance: number,
  controlMap: ControlIDMapping[],
): string[] {
  const violations = validateGrid(config, counts, compliance, controlMap);
  // A config carrying rules cannot be judged by the grid alone. Returning the
  // grid's verdict as though the rules were satisfied would report a passing
  // gate over policy nobody applied, so the caller is told rather than quietly
  // getting half an answer. Appended, not prepended, so the two languages order
  // violations alike. Parity: ValidateThresholds in go/compliance.go.
  if (config.rules && config.rules.length > 0) {
    violations.push(ruleRefusal(config.rules.length));
  }
  return violations;
}

/**
 * ruleRefusal is what a caller is told when a policy carries rules the path it
 * used cannot evaluate. It reaches end users, so it names the spec and what to do
 * about it rather than an internal function. Parity: ruleRefusal in go/rules.go.
 */
export function ruleRefusal(count: number): string {
  const noun = count === 1 ? 'rule' : 'rules';
  return (
    `this spec declares ${count} ${noun}, which this evaluation path cannot apply; ` +
    `the tool must evaluate rules against the document, not against counts alone`
  );
}

/**
 * validateGrid is the status x severity half of a policy, shared by
 * validateThresholds and evaluate. Parity: validateGrid in go/compliance.go.
 */
export function validateGrid(
  config: ThresholdConfig,
  counts: StatusCounts,
  compliance: number,
  controlMap: ControlIDMapping[],
): string[] {
  const violations: string[] = [];

  // Every construction path lands here, so the former name is resolved once
  // rather than in each caller. Resolved before the compliance bounds so a
  // refusal is reported ahead of them.
  const sections: ResolvedSection[] = [
    { name: THRESHOLD_PASSED, threshold: config.passed, counts: counts.passed, wroteNone: false },
    { name: THRESHOLD_FAILED, threshold: config.failed, counts: counts.failed, wroteNone: false },
    { name: THRESHOLD_SKIPPED, threshold: config.skipped, counts: counts.skipped, wroteNone: false },
    { name: THRESHOLD_ERROR, threshold: config.error, counts: counts.error, wroteNone: false },
    { name: THRESHOLD_NO_IMPACT, threshold: config.noImpact, counts: counts.noImpact, wroteNone: false },
  ];
  for (const section of sections) {
    const { threshold, wroteNone, refusal } = resolveLegacySeverity(section.name, section.threshold);
    if (refusal) {
      violations.push(refusal);
    }
    section.threshold = threshold;
    section.wroteNone = wroteNone;
  }

  const actualControls = new Map<string, ControlIDMapping>();
  for (const m of controlMap) {
    actualControls.set(m.id, m);
  }

  if (config.compliance) {
    if (config.compliance.min !== undefined && compliance < config.compliance.min) {
      violations.push(`compliance ${compliance.toFixed(2)}% is below minimum ${config.compliance.min.toFixed(2)}%`);
    }
    if (config.compliance.max !== undefined && compliance > config.compliance.max) {
      violations.push(`compliance ${compliance.toFixed(2)}% exceeds maximum ${config.compliance.max.toFixed(2)}%`);
    }
  }

  for (const section of sections) {
    violations.push(
      ...checkSeverityThreshold(section.name, section.threshold, section.counts, actualControls, section.wroteNone),
    );
  }

  return violations;
}

function checkSeverityThreshold(
  status: string,
  threshold: ThresholdSeverity | undefined,
  actual: SeverityCounts,
  actualControls: Map<string, ControlIDMapping>,
  wroteNone: boolean,
): string[] {
  if (!threshold) {
    return [];
  }
  // The path names the key the author wrote; the comparison below keeps the
  // canonical bucket name, because informational is where the control was
  // actually counted. Reporting `expected no_impact/none` would name a bucket
  // that does not exist.
  const pathLabel = (label: string): string =>
    wroteNone && label === 'informational' ? LEGACY_INFORMATIONAL_KEY : label;
  const violations: string[] = [];
  const check = (label: string, bound: ThresholdBound | undefined, actualCount: number): void => {
    if (!bound) {
      return;
    }
    const path = `${status}.${pathLabel(label)}`;
    if (bound.min !== undefined && actualCount < bound.min) {
      violations.push(`${path}: ${actualCount} is below minimum ${bound.min}`);
    }
    if (bound.max !== undefined && actualCount > bound.max) {
      violations.push(`${path}: ${actualCount} exceeds maximum ${bound.max}`);
    }
    for (const expectedID of bound.controls ?? []) {
      const ac = actualControls.get(expectedID);
      if (!ac) {
        violations.push(`${path}: expected control ${expectedID} not found in results`);
      } else if (ac.status !== status || ac.severity !== label) {
        violations.push(
          `${path}: control ${expectedID} expected ${status}/${label} but found ${ac.status}/${ac.severity}`,
        );
      }
    }
  };

  check('critical', threshold.critical, actual.critical);
  check('high', threshold.high, actual.high);
  check('medium', threshold.medium, actual.medium);
  check('low', threshold.low, actual.low);
  check('informational', threshold.informational, actual.informational);
  check('total', threshold.total, actual.total);

  return violations;
}
