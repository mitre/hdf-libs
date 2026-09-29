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
  type StatusCounts,
  type SeverityCounts,
  validateThresholds,
  violationMessages,
  overallStatus,
  deriveSeverity,
  severityBucket,
  type ThresholdConfig,
} from '../src/compliance.js';
import { evaluateRules, evaluate, PREDICATE_FIELDS, type ThresholdRule } from '../src/rules.js';
import { filter } from '../src/query.js';
import { ruleRefusal } from '../src/compliance.js';
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
    // Was counts.error.none before 3.7.0 renamed the bucket.
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
    // The former name `none` still resolves, and reports under the key the
    // author wrote — parity with Go
    // TestValidateThresholds_LegacyNoneNormalizesToInformational.
    expect(validateThresholds({ error: { none: { min: 5 } } }, counts, compliance, controlMap)).toEqual([
      'error.none: 1 is below minimum 5',
    ]);
    expect(validateThresholds({ error: { informational: { min: 5 } } }, counts, compliance, controlMap)).toEqual([
      'error.informational: 1 is below minimum 5',
    ]);
    // The refusal does not skip the section: the informational bound the author
    // wrote is still checked, so the refusal and its verdict are both reported.
    expect(
      validateThresholds({ error: { none: { min: 5 }, informational: { min: 5 } } }, counts, compliance, controlMap),
    ).toEqual([`error: ${BOTH_NAMES_SET}`, 'error.informational: 1 is below minimum 5']);
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

// The shared cross-language contract for threshold rules. go/rules_test.go reads
// the SAME file and runs the SAME cases, so the two evaluators cannot drift. The
// reference clock lives in the file, which keeps expiry a property of the fixture
// rather than of the day the suite runs.
interface RuleCases {
  now: string;
  predicateFields: string[];
  refusalByCount: Record<string, string>;
  fixture: HDFResults;
  cases: { name: string; rules: ThresholdRule[]; expect: string[] }[];
}

const rulePath = join(dirname(fileURLToPath(import.meta.url)), '..', 'testdata', 'threshold-rule-cases.json');
const ruleTable = JSON.parse(readFileSync(rulePath, 'utf-8')) as RuleCases;

// A StatusCounts carrying a single failed requirement, for the grid half of the
// refusal test. Built here rather than counted from a document so the test is
// about ordering, not about counting.
function oneFailedCount(): StatusCounts {
  const zero = { critical: 0, high: 0, medium: 0, low: 0, informational: 0, total: 0 };
  return {
    passed: { ...zero },
    failed: { ...zero, total: 1 },
    skipped: { ...zero },
    error: { ...zero },
    noImpact: { ...zero },
  };
}

describe('threshold rules (parity with go/rules.go)', () => {
  it('has cases to run', () => {
    expect(ruleTable.cases.length).toBeGreaterThan(0);
  });

  for (const c of ruleTable.cases) {
    it(c.name, () => {
      const got = violationMessages(
        evaluateRules({ rules: c.rules }, ruleTable.fixture, {
          now: ruleTable.now,
          statusOf: effectiveStatusOf(false),
        }),
      );
      expect(got).toEqual(c.expect);
    });
  }

  // Go maps predicate fields onto the filter explicitly while TypeScript spreads
  // the object, so a field added to one language reaches the filter there and
  // silently does nothing in the other. Both definitions are pinned to one list.
  it('the predicate surface matches the shared table', () => {
    expect(ruleTable.predicateFields.length).toBeGreaterThan(0);
    expect([...PREDICATE_FIELDS].sort()).toEqual(ruleTable.predicateFields.slice().sort());
  });

  // The refusal is user-facing text emitted by both languages, so its wording
  // lives in the shared table rather than in two hand-written copies — which is
  // how the two had already drifted apart in text and position.
  it('the refusal wording matches the shared table', () => {
    expect(Object.keys(ruleTable.refusalByCount).length).toBeGreaterThan(0);
    for (const [count, want] of Object.entries(ruleTable.refusalByCount)) {
      expect(ruleRefusal(Number(count))).toBe(want);
    }
  });

  // Silently skipping rules would report a passing gate over policy nobody
  // applied — the false green reached through a caller not yet taught about them.
  it('validateThresholds refuses a rules-bearing config, appending after the grid', () => {
    const violations = validateThresholds(
      {
        failed: { total: { max: 0 } },
        rules: [{ name: 'x', where: { status: ['failed'] }, max: 0 }],
      },
      oneFailedCount(),
      100,
      []
    );
    expect(violations).toHaveLength(2);
    expect(violations[0]).toBe('failed.total: 1 exceeds maximum 0');
    expect(violations[1]).toBe(ruleRefusal(1));
  });

  // evaluate is the entry point a surface should call: grid and rules together,
  // so a consumer cannot half-apply a policy. Its absence in TypeScript was the
  // blocking finding of this card's first review.
  it('evaluate applies the grid and the rules together', () => {
    const statusOf = effectiveStatusOf(false);
    const counts = countControlsByStatus(ruleTable.fixture, statusOf);
    const violations = evaluate(
      {
        failed: { total: { max: 0 } },
        rules: [
          { name: 'nothing fails without a plan', where: { status: ['failed'], poams: 'none-valid' }, max: 0 },
        ],
      },
      {
        results: ruleTable.fixture,
        counts,
        compliance: calculateCompliance(counts),
        controlMap: mapControlIDsByStatus(ruleTable.fixture, statusOf),
        now: ruleTable.now,
        statusOf,
      }
    );
    const messages = violationMessages(violations);
    expect(messages).toContain('nothing fails without a plan: 1 matched, maximum 0');
    expect(messages).toContain('failed.total: 2 exceeds maximum 0');
  });
});

// The override-aware counting path resolved STATUS through an injected resolver
// while deriving SEVERITY from raw impact, so a risk-adjusted requirement was
// counted post-adjudication for one and pre-adjudication for the other. A
// formally re-scored finding belongs in the bucket it was re-scored into.
//
// The raw twins (countControlsByStatusSeverity, mapControlIDs) are documented as
// having no override awareness and keep deriving from the requirement's own
// impact — that is their purpose, not an oversight.
// Parity: TestOverrideAwareCountingUsesEffectiveImpactForSeverity in go/compliance_test.go.
describe('override-aware counting derives severity from effective impact', () => {
  // Impact 0.9 derives to critical (the band starts at 0.9); re-scored to 0.3 it
  // derives to low. No explicit severity, because an explicit one wins over both
  // and would mask the whole question.
  const adjusted = {
    baselines: [
      {
        name: 'adjustments',
        requirements: [
          {
            id: 'ADJUSTED',
            impact: 0.9,
            results: [{ status: 'failed' }],
            statusOverrides: [
              {
                type: 'riskAdjustment',
                reason: 'environmental context',
                appliedAt: '2024-06-01T00:00:00Z',
                expiresAt: '2099-12-31T00:00:00Z',
                impact: { value: 0.3 },
              },
            ],
          },
        ],
      },
    ],
  } as unknown as HDFResults;
  const statusOf = () => 'failed';

  it('counts the re-scored requirement in the band it was moved to', () => {
    const counts = countControlsByStatus(adjusted, statusOf);
    expect(counts.failed.low).toBe(1);
    expect(counts.failed.critical).toBe(0);
  });

  it('lists the control at the severity it was counted at', () => {
    const mapped = mapControlIDsByStatus(adjusted, statusOf);
    expect(mapped).toHaveLength(1);
    expect(mapped[0]?.severity).toBe('low');
  });

  it('leaves the no-override-awareness twin reading the requirement own impact', () => {
    expect(countControlsByStatusSeverity(adjusted).failed.critical).toBe(1);
  });
});

// The exact refusal text both languages emit, so the assertions below pin bytes
// rather than a substring. Mirrors the Go format string in go/compliance.go.
const BOTH_NAMES_SET =
  "both 'none' and 'informational' are set; 'informational' replaced 'none' in 3.7.0 and both name the same bucket";

const zeroSeverityCounts = (): SeverityCounts => ({
  critical: 0,
  high: 0,
  medium: 0,
  low: 0,
  informational: 0,
  total: 0,
});

const zeroStatusCounts = (): StatusCounts => ({
  passed: zeroSeverityCounts(),
  failed: zeroSeverityCounts(),
  skipped: zeroSeverityCounts(),
  error: zeroSeverityCounts(),
  noImpact: zeroSeverityCounts(),
});

// The same hand-built counts Go's legacy-`none` tests use, so the two languages
// assert the identical violation strings rather than merely the same shape.
const threeInformationalNoImpact = (): StatusCounts => ({
  passed: zeroSeverityCounts(),
  failed: zeroSeverityCounts(),
  skipped: zeroSeverityCounts(),
  error: zeroSeverityCounts(),
  noImpact: { ...zeroSeverityCounts(), informational: 3, total: 3 },
});

describe('the former `none` name and severity bucketing — parity with go/compliance_test.go', () => {
  const counts = countControlsByStatusSeverity(results);
  const compliance = calculateCompliance(counts);
  const controlMap = mapControlIDs(results);

  // Byte-identical to the strings Go's
  // TestValidateThresholds_LegacyNoneNormalizesToInformational asserts, over the
  // same hand-built counts, so the two languages cannot drift on the wording.
  it('reports the same bytes as Go for a none-written bound', () => {
    const counts = threeInformationalNoImpact();

    expect(validateThresholds({ noImpact: { none: { max: 0 } } }, counts, 100, [])).toEqual([
      'no_impact.none: 3 exceeds maximum 0',
    ]);
    expect(validateThresholds({ noImpact: { informational: { max: 0 } } }, counts, 100, [])).toEqual([
      'no_impact.informational: 3 exceeds maximum 0',
    ]);
    expect(validateThresholds({ noImpact: { none: { min: 5 } } }, counts, 100, [])).toEqual([
      'no_impact.none: 3 is below minimum 5',
    ]);
  });

  // Byte-identical to the string Go's
  // TestValidateThresholds_BothNoneAndInformationalIsRefused pins.
  it('refuses a spec naming both names with the same bytes as Go', () => {
    expect(
      validateThresholds(
        { noImpact: { none: { max: 2 }, informational: { max: 2 } } },
        zeroStatusCounts(),
        100,
        [],
      ),
    ).toEqual([`no_impact: ${BOTH_NAMES_SET}`]);
  });

  // Parity: Go TestValidateThresholds_LegacyNoneSurvivesConfigReuse.
  it('reports identically on a second pass over the same config object', () => {
    const counts = threeInformationalNoImpact();
    const config: ThresholdConfig = { noImpact: { none: { max: 0 } } };

    const first = validateThresholds(config, counts, 100, []);
    const second = validateThresholds(config, counts, 100, []);
    expect(second).toEqual(first);
    expect(second).toEqual(['no_impact.none: 3 exceeds maximum 0']);

    // The caller's spec must come back as it went in.
    expect(config.noImpact?.none).toBeDefined();
    expect(config.noImpact?.informational).toBeUndefined();
  });

  it('a bound written as none reports under none; informational reports under informational', () => {
    expect(validateThresholds({ error: { none: { max: 0 } } }, counts, compliance, controlMap)).toEqual([
      'error.none: 1 exceeds maximum 0',
    ]);
    expect(validateThresholds({ error: { informational: { max: 0 } } }, counts, compliance, controlMap)).toEqual([
      'error.informational: 1 exceeds maximum 0',
    ]);
  });

  it('a control listed under a none bound compares against the canonical bucket', () => {
    expect(
      validateThresholds({ noImpact: { none: { controls: ['C-1'] } } }, counts, compliance, [
        { id: 'C-1', status: 'no_impact', severity: 'low' },
      ]),
    ).toEqual(['no_impact.none: control C-1 expected no_impact/informational but found no_impact/low']);
  });

  it('severityBucket folds anything outside the enum into informational', () => {
    for (const s of ['critical', 'high', 'medium', 'low']) {
      expect(severityBucket(s)).toBe(s);
    }
    for (const s of ['informational', 'none', 'sev-9', '']) {
      expect(severityBucket(s)).toBe('informational');
    }
  });

  it('a control listing buckets an out-of-enum severity the way the counts do', () => {
    const malformed = {
      baselines: [
        {
          requirements: [
            {
              id: 'C-1',
              impact: 0.5,
              severity: 'sev-9',
              results: [{ status: 'failed' }],
            },
          ],
        },
      ],
    } as unknown as HDFResults;

    const mappings = mapControlIDs(malformed);
    expect(mappings[0].severity).toBe('informational');

    const malformedCounts = countControlsByStatusSeverity(malformed);
    expect(malformedCounts.failed.informational).toBe(1);
    expect(
      validateThresholds({ failed: { informational: { controls: ['C-1'] } } }, malformedCounts, 0, mappings),
    ).toEqual([]);

    expect(mapControlIDsByStatus(malformed, () => 'failed')[0].severity).toBe('informational');
  });
});

// A violation that names only a count sends the reader to an artifact and a
// script. The matches are already computed, so carrying them costs nothing but
// keeping what was thrown away. Parity: go/rules_test.go
// TestRuleViolationCarriesTheMatchingFindings and its two siblings.
describe('a violation carries the requirements that breached it', () => {
  const statusOf = effectiveStatusOf(false);

  it('a rule names every match, not a sample', () => {
    const violations = evaluateRules(
      { rules: [{ name: 'no failures', where: { status: ['failed'] }, max: 0 }] },
      ruleTable.fixture,
      { now: ruleTable.now, statusOf },
    );
    expect(violations).toHaveLength(1);
    expect(violations[0].message).toContain('no failures');

    const matched = filter(ruleTable.fixture, { status: ['failed'], statusOf });
    expect(violations[0].findings).toHaveLength(matched.length);
    expect(violations[0].findings.length).toBeGreaterThan(0);
    for (const f of violations[0].findings) {
      expect(f.id).toBeTruthy();
      expect(f.status).toBe('failed');
    }
  });

  it('a count bound names the requirements in the bucket it bounded', () => {
    const counts = countControlsByStatus(ruleTable.fixture, statusOf);
    const violations = evaluate(
      { failed: { total: { max: 0 } } },
      {
        results: ruleTable.fixture,
        counts,
        compliance: calculateCompliance(counts),
        controlMap: mapControlIDsByStatus(ruleTable.fixture, statusOf),
        now: ruleTable.now,
        statusOf,
      },
    );
    expect(violations).toHaveLength(1);
    expect(violations[0].message).toContain('failed.total');
    expect(violations[0].findings.length).toBeGreaterThan(0);
    for (const f of violations[0].findings) {
      expect(f.status, 'only the bucket that was bounded').toBe('failed');
      expect(f.id).toBeTruthy();
    }

    // The title is the middle of the three things a finding line promises, and
    // it was the one nothing asserted: mapControlIDsByStatus could stop carrying
    // it and every test still passed. Pinned against the fixture's own text so a
    // dropped field cannot pass as an untitled requirement.
    // Parity: TestValidateThreshold_FindingLineCarriesTheTitle in hdf-cli.
    const noPlan = violations[0].findings.find((f) => f.id === 'NO-PLAN');
    expect(noPlan, 'precondition: the bounded bucket contains the titled requirement').toBeDefined();
    expect(noPlan?.title).toBe('Failing with no remediation plan');
  });

  it('a compliance bound names none — it is a property of the whole document', () => {
    const counts = countControlsByStatus(ruleTable.fixture, statusOf);
    const violations = evaluate(
      { compliance: { min: 99 } },
      {
        results: ruleTable.fixture,
        counts,
        compliance: calculateCompliance(counts),
        controlMap: mapControlIDsByStatus(ruleTable.fixture, statusOf),
        now: ruleTable.now,
        statusOf,
      },
    );
    expect(violations.length).toBeGreaterThan(0);
    expect(violations[0].message).toContain('compliance');
    expect(violations[0].findings).toEqual([]);
  });

  it('a count bound names exactly as many findings as its message counts', () => {
    const counts = countControlsByStatus(ruleTable.fixture, statusOf);
    const violations = evaluate(
      { failed: { total: { max: 0 } } },
      {
        results: ruleTable.fixture,
        counts,
        compliance: calculateCompliance(counts),
        controlMap: mapControlIDsByStatus(ruleTable.fixture, statusOf),
        now: ruleTable.now,
        statusOf,
      },
    );
    // The invariant that makes the list trustworthy: a reader counting the lines
    // must get the number the message reported.
    const reported = Number(/: (\d+) exceeds/.exec(violations[0].message)![1]);
    expect(violations[0].findings).toHaveLength(reported);
  });

  // The control map holds the THRESHOLD key (no_impact) while the filter holds
  // the SCHEMA status (notApplicable). A finding names the requirement, so both
  // report the schema status — the only vocabulary `hdf query --status` accepts.
  // Parity: CLI TestValidateThreshold_CountAndRuleFindingsReadAlike.
  it('a count bound reports the schema status, not the threshold key', () => {
    // Its own fixture: the shared rule fixture carries only passed and failed
    // requirements, and those are two of the three buckets where the two
    // vocabularies coincide — so it cannot show this difference at all.
    const notApplicable = {
      baselines: [
        {
          requirements: [
            { id: 'SV-NA-1', title: 'Not applicable one', impact: 0, results: [{ status: 'notApplicable' }] },
          ],
        },
      ],
    } as unknown as HDFResults;
    const naStatusOf = () => 'notApplicable';

    const counts = countControlsByStatus(notApplicable, naStatusOf);
    const violations = evaluate(
      { noImpact: { total: { max: 0 } } },
      {
        results: notApplicable,
        counts,
        compliance: calculateCompliance(counts),
        controlMap: mapControlIDsByStatus(notApplicable, naStatusOf),
        statusOf: naStatusOf,
      },
    );
    const findings = violations.flatMap((v) => v.findings);
    expect(findings.length, 'precondition: the bound must actually be breached').toBeGreaterThan(0);
    for (const f of findings) {
      expect(f.status, 'a threshold key is refused by hdf query --status').toBe('notApplicable');
    }
  });

  it('a controls list names none — the message already names the requirement', () => {
    const counts = countControlsByStatus(ruleTable.fixture, statusOf);
    const violations = evaluate(
      // failed/critical, not passed/high: the fixture HAS failed/critical
      // requirements, so inBucket would return a non-empty list if a controls
      // violation wrongly carried one. Asserting on an empty bucket proved
      // nothing.
      { failed: { critical: { controls: ['NO-SUCH-ID'] } } },
      {
        results: ruleTable.fixture,
        counts,
        compliance: calculateCompliance(counts),
        controlMap: mapControlIDsByStatus(ruleTable.fixture, statusOf),
        now: ruleTable.now,
        statusOf,
      },
    );
    expect(violations).toHaveLength(1);
    expect(violations[0].message).toContain('NO-SUCH-ID');
    expect(violations[0].findings).toEqual([]);
  });
});

// The Go engine has a severity-narrowing test and TypeScript had none, so the TS
// inBucket's narrowing was unprotected. Its own fixture with two failed
// severities: the shared rule fixture's failed requirements are all critical, so
// bounding failed.critical there lists the whole status either way.
// Parity: go/rules_test.go TestCountBoundFindingsAreNarrowedBySeverity.
describe('a severity label narrows the bucket it lists', () => {
  it('lists only the bounded severity, not the whole status', () => {
    const results = {
      baselines: [
        {
          requirements: [
            { id: 'CRIT-1', title: 'Critical one', impact: 0.9, severity: 'critical', results: [{ status: 'failed' }] },
            { id: 'HIGH-1', title: 'High one', impact: 0.7, severity: 'high', results: [{ status: 'failed' }] },
          ],
        },
      ],
    } as unknown as HDFResults;
    const statusOf = () => 'failed';

    const counts = countControlsByStatus(results, statusOf);
    expect(counts.failed.critical, 'precondition: a STRICT subset, or narrowing is unobservable').toBeLessThan(
      counts.failed.total,
    );

    const violations = evaluate(
      { failed: { critical: { max: 0 } } },
      {
        results,
        counts,
        compliance: calculateCompliance(counts),
        controlMap: mapControlIDsByStatus(results, statusOf),
        statusOf,
      },
    );
    expect(violations).toHaveLength(1);
    expect(violations[0].findings).toHaveLength(counts.failed.critical);
    expect(violations[0].findings[0].id).toBe('CRIT-1');
  });
});
