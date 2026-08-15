// Compliance & threshold engine — the TypeScript peer of
// hdf-engine/go/compliance.go. Pure functions, kept at behavioural parity with
// the Go implementation (see test/compliance.test.ts, which runs both over the
// same fixture). Violation message formats match the Go fmt.Sprintf output.

import type { HDFResults, EvaluatedRequirement, RequirementResult, Severity } from '@mitre/hdf-schema';
import { worstStatus, impactToSeverity } from '@mitre/hdf-utilities';

/** Threshold status-key constants (SAF CLI-compatible keys). */
export const THRESHOLD_PASSED = 'passed';
export const THRESHOLD_FAILED = 'failed';
export const THRESHOLD_SKIPPED = 'skipped';
export const THRESHOLD_ERROR = 'error';
export const THRESHOLD_NO_IMPACT = 'no_impact';

export interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  none: number;
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
}

function newSeverityCounts(): SeverityCounts {
  return { critical: 0, high: 0, medium: 0, low: 0, none: 0, total: 0 };
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
 * severity, using impactToSeverity. Maps "informational" to "none".
 */
export function deriveSeverity(impact: number, severity?: Severity | null): string {
  // Presence-based, matching Go DeriveSeverity's `if severity != nil`: an explicit
  // severity — including an empty string — is returned verbatim; only a
  // null/undefined severity derives from impact. Testing truthiness here would
  // send "" through the impact path and diverge from Go (bead 4908.20).
  if (severity != null) {
    return String(severity);
  }
  const sev = impactToSeverity(impact);
  return sev === 'informational' ? 'none' : sev;
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
  switch (severity) {
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
      sc.none++;
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

/** CountControlsByStatusSeverity counts requirements by overall status and severity. */
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
      addCount(counts, status, deriveSeverity(req.impact, reqSeverity(req)));
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
        severity: deriveSeverity(req.impact, reqSeverity(req)),
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
        severity: deriveSeverity(req.impact, reqSeverity(req)),
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
 * validateThresholds checks all threshold bounds against observed counts and
 * compliance, returning human-readable violation messages (empty when all pass).
 */
export function validateThresholds(
  config: ThresholdConfig,
  counts: StatusCounts,
  compliance: number,
  controlMap: ControlIDMapping[],
): string[] {
  const violations: string[] = [];

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

  violations.push(...checkSeverityThreshold(THRESHOLD_PASSED, config.passed, counts.passed, actualControls));
  violations.push(...checkSeverityThreshold(THRESHOLD_FAILED, config.failed, counts.failed, actualControls));
  violations.push(...checkSeverityThreshold(THRESHOLD_SKIPPED, config.skipped, counts.skipped, actualControls));
  violations.push(...checkSeverityThreshold(THRESHOLD_ERROR, config.error, counts.error, actualControls));
  violations.push(...checkSeverityThreshold(THRESHOLD_NO_IMPACT, config.noImpact, counts.noImpact, actualControls));

  return violations;
}

function checkSeverityThreshold(
  status: string,
  threshold: ThresholdSeverity | undefined,
  actual: SeverityCounts,
  actualControls: Map<string, ControlIDMapping>,
): string[] {
  if (!threshold) {
    return [];
  }
  const violations: string[] = [];
  const check = (label: string, bound: ThresholdBound | undefined, actualCount: number): void => {
    if (!bound) {
      return;
    }
    const path = `${status}.${label}`;
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
  check('none', threshold.none, actual.none);
  check('total', threshold.total, actual.total);

  return violations;
}
