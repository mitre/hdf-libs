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
import { results as fixtureResults } from '@mitre/hdf-fixtures';
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
    // Was counts.error.none before the two spellings were unified.
    expect(counts.error.informational).toBe(1);
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
  it('covers other status categories and severities (skipped.low, error.informational min, no_impact.medium)', () => {
    expect(validateThresholds({ skipped: { low: { max: 0 } } }, counts, compliance, controlMap)).toEqual([
      'skipped.low: 1 exceeds maximum 0',
    ]);
    // The legacy `none` spelling still resolves, and reports under the name it
    // normalizes to.
    expect(validateThresholds({ error: { none: { min: 5 } } }, counts, compliance, controlMap)).toEqual([
      'error.informational: 1 is below minimum 5',
    ]);
    expect(validateThresholds({ error: { informational: { min: 5 } } }, counts, compliance, controlMap)).toEqual([
      'error.informational: 1 is below minimum 5',
    ]);
    expect(
      validateThresholds(
        { error: { none: { min: 5 }, informational: { min: 5 } } },
        counts,
        compliance,
        controlMap,
      )[0],
    ).toContain('pre-3.7 spelling');
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
  it('impact-derived informational is the schema value, not a separate bucket', () => {
    expect(deriveSeverity(0.0)).toBe('informational');
    expect(deriveSeverity(0.0, 'informational' as unknown as Severity)).toBe('informational');
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

  it('impact-0 errored control resolves to the error bucket, not no_impact', () => {
    // A crashed check at impact 0 must surface as error so hdf threshold's
    // error.total gate sees it. Parity: go/compliance_test.go.
    const errored: EvaluatedRequirement = {
      id: 'SV-ERR',
      impact: 0.0,
      results: [{ status: 'error' } as RequirementResult],
    } as EvaluatedRequirement;
    const results = { baselines: [{ requirements: [errored] }] } as HDFResults;

    const eff = mapControlIDsByStatus(results, (req) => computeEffectiveStatus(statusInput(req)));
    expect(eff).toHaveLength(1);
    expect(eff[0]!.id).toBe('SV-ERR');
    expect(eff[0]!.status).toBe('error');

    const counts = countControlsByStatus(results, (req) =>
      computeEffectiveStatus(statusInput(req))
    );
    expect(counts.error.total).toBe(1);
    expect(counts.noImpact.total).toBe(0);
  });
});

// Shared real InSpec multi-overlay run from @mitre/hdf-fixtures (also read by
// go/compliance_test.go). A requirement id names the requirement, not one
// finding, so an overlay chain re-reports the same id in every layer it touches
// — 534 of this run's ids appear more than once, 406 with differing statuses.
const multilayered = JSON.parse(fixtureResults.inspecMultilayered.read()) as HDFResults;

describe('named-control assertions over duplicate ids — parity with go/compliance_test.go TestValidateThresholds_NamedControlMustHoldForEveryEntry', () => {
  const counts = countControlsByStatusSeverity(multilayered);
  const compliance = calculateCompliance(counts);
  const controlMap = mapControlIDs(multilayered);

  const validate = (cfg: ThresholdConfig): string[] => validateThresholds(cfg, counts, compliance, controlMap);

  // namedControl builds a spec asserting one control id under one
  // status/severity bucket — test code, not fixture data.
  const namedControl = (status: string, severity: string, id: string): ThresholdConfig => ({
    [status === 'no_impact' ? 'noImpact' : status]: { [severity]: { controls: [id] } },
  });

  it('duplicate ids are counted per entry (counting semantics unchanged)', () => {
    // 1603 requirement entries over 534 distinct ids: every entry is counted.
    expect(counts.skipped.total).toBe(1196);
    expect(counts.skipped.medium).toBe(885);
    expect(counts.failed.total).toBe(273);
    expect(counts.failed.medium).toBe(246);
    expect(counts.passed.total).toBe(134);
    expect(
      counts.passed.total + counts.failed.total + counts.skipped.total + counts.error.total + counts.noImpact.total,
    ).toBe(1603);
  });

  // V-242399 is notReviewed in the two wrapper layers and passed in the
  // k8s-node layer, so the last entry alone satisfies passed/medium.
  it('a passing last entry no longer greens a gate its earlier entries fail', () => {
    expect(validate(namedControl('passed', 'medium', 'V-242399'))).toEqual([
      'passed.medium: control V-242399 expected passed/medium but found skipped/medium (entry 1 of 3)',
      'passed.medium: control V-242399 expected passed/medium but found skipped/medium (entry 2 of 3)',
    ]);
  });

  // The mirror: the FIRST entries satisfy skipped/medium and the last does not.
  // A first-wins resolution would pass this; fail-closed must not.
  it('a satisfying first entry does not rescue an unsatisfying last', () => {
    expect(validate(namedControl('skipped', 'medium', 'V-242399'))).toEqual([
      'skipped.medium: control V-242399 expected skipped/medium but found passed/medium (entry 3 of 3)',
    ]);
  });

  // V-242387: notReviewed, notReviewed, failed across three baselines.
  it('a failing last entry no longer greens a failed-control gate', () => {
    expect(validate(namedControl('failed', 'high', 'V-242387'))).toEqual([
      'failed.high: control V-242387 expected failed/high but found skipped/high (entry 1 of 3)',
      'failed.high: control V-242387 expected failed/high but found skipped/high (entry 2 of 3)',
    ]);
  });

  it('every baseline carrying the id contributes an entry', () => {
    expect(controlMap.filter((m) => m.id === 'V-242387')).toHaveLength(3);
    const baselinesWithIt = (multilayered.baselines ?? []).filter((b) =>
      (b.requirements ?? []).some((r) => r.id === 'V-242387'),
    );
    expect(baselinesWithIt).toHaveLength(3);
  });

  // SV-257777 is reported twice within ONE baseline (and again in two others):
  // duplication inside a single baseline resolves the same way.
  it('duplicate entries within one baseline are resolved too', () => {
    expect(validate(namedControl('skipped', 'informational', 'SV-257777'))).toEqual([
      'skipped.informational: control SV-257777 expected skipped/informational but found failed/informational (entry 3 of 5)',
      'skipped.informational: control SV-257777 expected skipped/informational but found failed/informational (entry 4 of 5)',
    ]);
  });

  // Severity is checked per entry alongside status: V-242387 is impact 0.7
  // (high) in every layer, so a critical assertion mismatches all three.
  it('severity is checked on every entry', () => {
    const v = validate(namedControl('failed', 'critical', 'V-242387'));
    expect(v).toHaveLength(3);
    expect(v[0]).toBe('failed.critical: control V-242387 expected failed/critical but found skipped/high (entry 1 of 3)');
    expect(v[2]).toBe('failed.critical: control V-242387 expected failed/critical but found failed/high (entry 3 of 3)');
  });

  // V-242376 is notReviewed at impact 0 in all three layers.
  it('duplicate entries that all satisfy the assertion pass', () => {
    expect(validate(namedControl('skipped', 'informational', 'V-242376'))).toEqual([]);
  });

  it('an id in no entry is still reported missing', () => {
    expect(validate(namedControl('failed', 'high', 'V-999999'))).toEqual([
      'failed.high: expected control V-999999 not found in results',
    ]);
  });

  // The single-entry contract — identical verdict AND identical message text,
  // with no entry-index suffix — is pinned by the 'threshold verdict' suite
  // above, whose fixture carries each id exactly once. Every id in this
  // document is duplicated, so it cannot be asserted here.
});
