import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import {
  worstStatus,
  computeEffectiveStatus,
  type EffectiveStatusInput,
  type StatusOverrideInput,
} from '@mitre/hdf-utilities';
import type { HDFResults, RequirementResult, EvaluatedRequirement } from '@mitre/hdf-schema';
import {
  countControlsByStatusSeverity,
  countControlsByStatus,
  agentOverrideCount,
  mapControlIDs,
  mapControlIDsByStatus,
  calculateCompliance,
  validateThresholds,
  overallStatus,
  deriveSeverity,
  type ThresholdConfig,
} from '../src/compliance.js';
import type { Severity } from '@mitre/hdf-schema';

// Shared cross-language fixture (also read by go/compliance_test.go), so both
// compliance implementations run the same input.
const fixturePath = join(dirname(fileURLToPath(import.meta.url)), '..', 'testdata', 'query-fixture.json');
const results = JSON.parse(readFileSync(fixturePath, 'utf-8')) as HDFResults;

// Shared agent-override fixture (also read by go/compliance_test.go) for the §3
// detective-surface parity tests.
const agentFixturePath = join(dirname(fileURLToPath(import.meta.url)), '..', 'testdata', 'agent-overrides-fixture.json');
const agentResults = JSON.parse(readFileSync(agentFixturePath, 'utf-8')) as HDFResults;

// statusInput builds the effective-status input from a requirement — the test's
// injected mapping, mirroring shared.RequirementStatusInput that the production
// MCP tool injects into countControlsByStatus. Parity: statusInput in
// go/compliance_test.go.
function statusInput(req: EvaluatedRequirement): EffectiveStatusInput {
  const overrides: StatusOverrideInput[] = (req.statusOverrides ?? []).map((o) => ({
    appliedAt: o.appliedAt,
    expiresAt: o.expiresAt,
    status: o.status as string | undefined,
  }));
  return {
    impact: req.impact,
    effectiveStatus: (req.effectiveStatus ?? undefined) as string | undefined,
    overrides,
    resultStatuses: (req.results ?? []).map((r) => String(r.status)),
  };
}

// effectiveStatusOf resolves a requirement's effective status; excludeAgent drops
// appliedBy.type==='agent' overrides first. Parity: effectiveStatusOf in Go.
function effectiveStatusOf(excludeAgent: boolean): (req: EvaluatedRequirement) => string {
  return (req: EvaluatedRequirement): string => {
    const kept = excludeAgent
      ? { ...req, statusOverrides: (req.statusOverrides ?? []).filter((o) => o.appliedBy?.type !== 'agent') }
      : req;
    return computeEffectiveStatus(statusInput(kept));
  };
}

function rs(...statuses: string[]): RequirementResult[] {
  return statuses.map((s) => ({ status: s }) as unknown as RequirementResult);
}

describe('overallStatus — delegates to worstStatus (parity with go/compliance.go)', () => {
  const cases: { name: string; in: RequirementResult[]; want: string }[] = [
    { name: 'empty', in: [], want: 'notReviewed' },
    { name: 'passed', in: rs('passed'), want: 'passed' },
    { name: 'failed', in: rs('failed'), want: 'failed' },
    { name: 'error', in: rs('error'), want: 'error' },
    { name: 'notApplicable', in: rs('notApplicable'), want: 'notApplicable' },
    { name: 'notReviewed', in: rs('notReviewed'), want: 'notReviewed' },
    { name: 'error beats failed', in: rs('failed', 'error'), want: 'error' },
    { name: 'failed beats passed', in: rs('passed', 'failed'), want: 'failed' },
    { name: 'passed beats notApplicable', in: rs('notApplicable', 'passed'), want: 'passed' },
  ];
  for (const c of cases) {
    it(c.name, () => {
      expect(overallStatus(c.in)).toBe(c.want);
      // Equivalence to the shared roll-up (no local rank switch).
      expect(overallStatus(c.in)).toBe(worstStatus(c.in.map((r) => String(r.status))));
    });
  }
});

describe('compliance counts + percentage — parity with go/compliance_test.go', () => {
  it('counts by status/severity and computes 25.0% over the shared fixture', () => {
    const counts = countControlsByStatusSeverity(results);
    expect(counts.passed.total).toBe(1);
    expect(counts.passed.high).toBe(1);
    expect(counts.failed.total).toBe(1);
    expect(counts.failed.critical).toBe(1);
    expect(counts.skipped.total).toBe(1);
    expect(counts.skipped.low).toBe(1);
    expect(counts.error.total).toBe(1);
    expect(counts.error.none).toBe(1);
    expect(counts.noImpact.total).toBe(1);
    expect(counts.noImpact.medium).toBe(1);
    expect(calculateCompliance(counts)).toBe(25.0);
  });

  it('empty / absent baselines → 0%', () => {
    expect(calculateCompliance(countControlsByStatusSeverity({} as unknown as HDFResults))).toBe(0);
    expect(mapControlIDs({} as unknown as HDFResults)).toEqual([]);
  });
});

describe('threshold verdict — parity with go/compliance_test.go TestValidateThresholds', () => {
  const counts = countControlsByStatusSeverity(results);
  const compliance = calculateCompliance(counts); // 25.0
  const controlMap = mapControlIDs(results);

  it('compliance below min → violation (identical message to Go)', () => {
    const cfg: ThresholdConfig = { compliance: { min: 90 } };
    const v = validateThresholds(cfg, counts, compliance, controlMap);
    expect(v).toEqual(['compliance 25.00% is below minimum 90.00%']);
  });
  it('compliance meets min → no violation', () => {
    expect(validateThresholds({ compliance: { min: 20 } }, counts, compliance, controlMap)).toEqual([]);
  });
  it('failed.critical.max exceeded → violation', () => {
    const cfg: ThresholdConfig = { failed: { critical: { max: 0 } } };
    expect(validateThresholds(cfg, counts, compliance, controlMap)).toEqual(['failed.critical: 1 exceeds maximum 0']);
  });
  it('passed.total.min met → no violation', () => {
    expect(validateThresholds({ passed: { total: { min: 1 } } }, counts, compliance, controlMap)).toEqual([]);
  });
  it('expected control present with right status/severity → no violation', () => {
    const cfg: ThresholdConfig = { failed: { critical: { controls: ['SV-230221'] } } };
    expect(validateThresholds(cfg, counts, compliance, controlMap)).toEqual([]);
  });
  it('expected control missing → violation', () => {
    const cfg: ThresholdConfig = { failed: { critical: { controls: ['SV-999999'] } } };
    expect(validateThresholds(cfg, counts, compliance, controlMap)).toEqual([
      'failed.critical: expected control SV-999999 not found in results',
    ]);
  });
  it('compliance above max → violation', () => {
    expect(validateThresholds({ compliance: { max: 10 } }, counts, compliance, controlMap)).toEqual([
      'compliance 25.00% exceeds maximum 10.00%',
    ]);
  });
  it('severity-total below min → violation', () => {
    expect(validateThresholds({ passed: { total: { min: 5 } } }, counts, compliance, controlMap)).toEqual([
      'passed.total: 1 is below minimum 5',
    ]);
  });
  it('per-severity bound (passed.high.max) exceeded → violation', () => {
    expect(validateThresholds({ passed: { high: { max: 0 } } }, counts, compliance, controlMap)).toEqual([
      'passed.high: 1 exceeds maximum 0',
    ]);
  });
  it('covers other status categories and severities (skipped.low, error.none min, no_impact.medium)', () => {
    expect(validateThresholds({ skipped: { low: { max: 0 } } }, counts, compliance, controlMap)).toEqual([
      'skipped.low: 1 exceeds maximum 0',
    ]);
    expect(validateThresholds({ error: { none: { min: 5 } } }, counts, compliance, controlMap)).toEqual([
      'error.none: 1 is below minimum 5',
    ]);
    expect(validateThresholds({ noImpact: { medium: { max: 0 } } }, counts, compliance, controlMap)).toEqual([
      'no_impact.medium: 1 exceeds maximum 0',
    ]);
  });
  it('expected control present but wrong status/severity → mismatch violation', () => {
    // SV-230222 is passed/high; asserting it under failed.critical.
    const cfg: ThresholdConfig = { failed: { critical: { controls: ['SV-230222'] } } };
    expect(validateThresholds(cfg, counts, compliance, controlMap)).toEqual([
      'failed.critical: control SV-230222 expected failed/critical but found passed/high',
    ]);
  });
});

describe('deriveSeverity', () => {
  it('explicit severity wins over impact', () => {
    expect(deriveSeverity(0.5, 'high' as unknown as Severity)).toBe('high');
  });
  it('impact-derived, informational maps to none', () => {
    expect(deriveSeverity(0.0)).toBe('none');
  });
  it('impact-derived high', () => {
    expect(deriveSeverity(0.7)).toBe('high');
  });
  // Parity with Go DeriveSeverity, which is presence-based (`if severity != nil`):
  // an explicit empty-string severity is returned verbatim, NOT re-derived from
  // impact. TS must test presence (severity != null), not truthiness — otherwise
  // "" (falsy) would fall through to impact and the same requirement could land
  // in a different compliance bucket than Go (bead 4908.20). Go ground truth:
  // DeriveSeverity(0.7, &"") => "", DeriveSeverity(0.7, nil) => "high".
  it('empty-string severity is returned verbatim (Go presence-parity)', () => {
    expect(deriveSeverity(0.7, '' as unknown as Severity)).toBe('');
  });
  it('null/undefined severity still derives from impact', () => {
    expect(deriveSeverity(0.7, null)).toBe('high');
    expect(deriveSeverity(0.7, undefined)).toBe('high');
  });
});

describe('agent-override detective surface — parity with go/compliance_test.go', () => {
  it('agentOverrideCount counts agent-attributed overrides only', () => {
    // One agent override (V-AGENT-A); the system/from_vex override (V-SYSTEM-B) is excluded.
    expect(agentOverrideCount(agentResults)).toBe(1);
  });

  it('countControlsByStatus yields the effective compliance delta agent overrides cause', () => {
    const withAgent = calculateCompliance(countControlsByStatus(agentResults, effectiveStatusOf(false)));
    const withoutAgent = calculateCompliance(countControlsByStatus(agentResults, effectiveStatusOf(true)));
    // With all overrides: A,B,C passed, D failed → 3/4 = 75%.
    expect(withAgent).toBe(75.0);
    // Stripping the agent override: A reverts to failed, B stays passed (system) → 2/4 = 50%.
    expect(withoutAgent).toBe(50.0);
    expect(withAgent - withoutAgent).toBe(25.0);
    // An absent resolver counts everything as skipped → 0% compliance.
    expect(calculateCompliance(countControlsByStatus(agentResults))).toBe(0.0);
  });

  it('mapControlIDsByStatus uses the injected resolver, diverging from raw mapControlIDs', () => {
    // Impact-0 notReviewed: skipped under raw counting, no_impact under the
    // effective-status resolver. Parity: go/compliance_test.go.
    const na: EvaluatedRequirement = {
      id: 'SV-NA',
      impact: 0.0,
      results: [{ status: 'notReviewed' } as RequirementResult],
    } as EvaluatedRequirement;
    const results = { baselines: [{ requirements: [na] }] } as HDFResults;

    const raw = mapControlIDs(results);
    expect(raw).toHaveLength(1);
    expect(raw[0]!.status).toBe('skipped');

    const eff = mapControlIDsByStatus(results, (req) => computeEffectiveStatus(statusInput(req)));
    expect(eff).toHaveLength(1);
    expect(eff[0]!.id).toBe('SV-NA');
    expect(eff[0]!.status).toBe('no_impact');

    // An absent resolver maps everything to skipped.
    expect(mapControlIDsByStatus(results)[0]!.status).toBe('skipped');
  });
});
