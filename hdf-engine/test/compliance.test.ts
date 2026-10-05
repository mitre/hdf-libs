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
import { VALUE_FIELDS } from '../src/query.js';
import { effectiveImpactOf, overrideInputs } from '../src/effective.js';
import { filter, type Match } from '../src/query.js';
import { ruleRefusal } from '../src/compliance.js';
import type { Severity } from '@mitre/hdf-schema';
import { results as fixtureResults } from '@mitre/hdf-fixtures';

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
// The shared shape a violation's findings are pinned to. Title is carried
// deliberately rather than ids alone: it is the field that ended up unasserted
// in BOTH languages at once, which is what this section prevents.
interface ExpectFinding {
  id: string;
  title: string;
  status: string;
  severity: string;
}

interface RuleCases {
  now: string;
  predicateFields: string[];
  refusalByCount: Record<string, string>;
  fixture: HDFResults;
  cases: { name: string; rules: ThresholdRule[]; expect: string[]; expectFindings: ExpectFinding[][] }[];
  gridCases: {
    name: string;
    config: ThresholdConfig;
    expect: string[];
    expectFindings: ExpectFinding[][];
  }[];
}

// Compares one violation's findings against the shared table. Parity:
// assertFindings in go/rules_test.go.
function assertFindings(want: ExpectFinding[], got: Match[]): void {
  expect(got, 'a violation must name exactly the requirements the table lists').toHaveLength(want.length);
  want.forEach((w, i) => {
    expect(got[i]?.id).toBe(w.id);
    expect(got[i]?.title, 'the title is promised by the docs and was once unasserted').toBe(w.title);
    expect(got[i]?.status).toBe(w.status);
    expect(got[i]?.severity).toBe(w.severity);
  });
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
      const violations = evaluateRules({ rules: c.rules }, ruleTable.fixture, {
        now: ruleTable.now,
        statusOf: effectiveStatusOf(false),
      });
      expect(violationMessages(violations)).toEqual(c.expect);

      // The findings half, pinned by the same table so it cannot diverge
      // between languages the way it already did once.
      expect(c.expectFindings, 'the table must state findings for every expected violation').toHaveLength(
        c.expect.length,
      );
      c.expectFindings.forEach((want, i) => assertFindings(want, violations[i]!.findings));
    });
  }

  // The grid's bounds resolve their offenders from the control map rather than
  // from a filter, so they are pinned by their own section of the same table. The
  // two that deliberately name NOTHING sit beside a count bound that names two,
  // on the same fixture — so an empty expectation here is a real assertion.
  // Parity: TestEvaluateGridFindings in go/rules_test.go.
  describe('grid bounds name their offenders, pinned by the shared table', () => {
    it('has cases to run', () => {
      expect(ruleTable.gridCases.length).toBeGreaterThan(0);
    });

    // The table states config in the POLICY vocabulary an author writes
    // (no_impact, skipped), which is what Go's YAML decoding accepts. TypeScript
    // does no YAML decoding, so its ThresholdConfig uses the camelCase type key
    // (noImpact). Translating here rather than duplicating the table is the
    // point — but an UNRECOGNIZED key must be loud: passing one through silently
    // creates no bound, and a case whose expectation is empty then passes for
    // the wrong reason. That is exactly how the no_impact case was vacuous.
    const CONFIG_KEYS: Record<string, keyof ThresholdConfig> = {
      compliance: 'compliance',
      passed: 'passed',
      failed: 'failed',
      skipped: 'skipped',
      error: 'error',
      no_impact: 'noImpact',
      rules: 'rules',
    };
    const toTsConfig = (raw: Record<string, unknown>): ThresholdConfig => {
      const out: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(raw)) {
        const mapped = CONFIG_KEYS[k];
        if (mapped === undefined) {
          throw new Error(`threshold key "${k}" is not translatable to the TypeScript config; it would create no bound`);
        }
        out[mapped] = v;
      }
      return out as ThresholdConfig;
    };

    for (const c of ruleTable.gridCases) {
      it(c.name, () => {
        const statusOf = effectiveStatusOf(false);
        const counts = countControlsByStatus(ruleTable.fixture, statusOf);
        const violations = evaluate(toTsConfig(c.config as unknown as Record<string, unknown>), {
          results: ruleTable.fixture,
          counts,
          compliance: calculateCompliance(counts),
          controlMap: mapControlIDsByStatus(ruleTable.fixture, statusOf),
          now: ruleTable.now,
          statusOf,
        });
        expect(violationMessages(violations)).toEqual(c.expect);
        expect(c.expectFindings).toHaveLength(c.expect.length);
        c.expectFindings.forEach((want, i) => assertFindings(want, violations[i]!.findings));
      });
    }
  });

  // Go maps predicate fields onto the filter explicitly while TypeScript spreads
  // the object, so a field added to one language reaches the filter there and
  // silently does nothing in the other. Both definitions are pinned to one list.
  // TypeScript reaches the one decoder through a hand-maintained field list
  // where Go reaches it by type, so that list can silently fall behind the
  // predicate surface and a new field would lose scalar sugar and negation in
  // one language only. Pinned to the same table PREDICATE_FIELDS is pinned to.
  it('every multi-value predicate field reaches the decoder', () => {
    const scalarFields = ['impact', 'rawImpact', 'cvss', 'epss', 'kev', 'id', 'search', 'baseline', 'poams'];
    const expected = ruleTable.predicateFields.filter((f) => !scalarFields.includes(f)).sort();
    expect(expected.length).toBeGreaterThan(0);
    expect([...VALUE_FIELDS].sort()).toEqual(expected);
  });

  it('the predicate surface matches the shared table', () => {
    expect(ruleTable.predicateFields.length).toBeGreaterThan(0);
    expect([...PREDICATE_FIELDS].sort()).toEqual(ruleTable.predicateFields.slice().sort());
  });

  // The motivating policy — "no failures in anything labelled
  // environment=production" — is a RULE, not a query, so the predicate has to
  // carry the key or the capability does not exist where it was asked for.
  // Parity: go/rules_test.go TestRulePredicateSelectsByBaselineLabel.
  describe('a rule selects by the labels of the baseline a requirement sits in', () => {
    const statusOf = effectiveStatusOf(false);

    it('a labelled baseline with a failure breaches the bound', () => {
      const violations = evaluateRules(
        { rules: [{ name: 'nothing fails in production', where: { status: ['failed'], baselineLabel: ['environment:production'] }, max: 0 }] },
        results,
        { statusOf },
      );
      expect(violations).toHaveLength(1);
      expect(violations[0].findings.length).toBeGreaterThan(0);
      expect(violations[0].findings[0].id).toBe('SV-230221');
    });

    // The case above survives a predicate that is ignored entirely, since the
    // fixture's only failure happens to sit in the labelled baseline. Bounding
    // the label alone is what shows the selection NARROWS.
    it('the label narrows — the unlabelled baseline is absent', () => {
      const violations = evaluateRules(
        { rules: [{ name: 'nothing in production', where: { baselineLabel: ['environment:production'] }, max: 0 }] },
        results,
        { statusOf },
      );
      expect(violations).toHaveLength(1);
      const matched = violations[0].findings.map((f) => f.id);
      expect(matched, 'the unlabelled baseline must not be selected').not.toContain('SV-100001');
      expect(matched.length, 'a label that selects the whole document narrows nothing').toBeLessThan(
        filter(results, { statusOf }).length,
      );
    });

    it('a label nothing carries selects nothing and passes', () => {
      expect(
        evaluateRules(
          { rules: [{ name: 'nothing fails in staging', where: { status: ['failed'], baselineLabel: ['environment:staging'] }, max: 0 }] },
          results,
          { statusOf },
        ),
      ).toEqual([]);
    });
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
  // NOTE: five tests that used to sit in this block were deleted when the shared
  // case table gained expectFindings/gridCases. They asserted COUNTS or mere
  // non-emptiness; the table pins exact membership by id, title, status and
  // severity and is read by both languages, which is strictly stronger. The two
  // that remain are kept because each brings its OWN fixture for a discrimination
  // the shared fixture cannot make — each declares its own status resolver, so
  // the block-level one the deleted tests shared is gone with them.


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

// Go's typed decode yields the zero instant for an absent appliedAt/expiresAt
// and its ladder reads zero as "never expires", so an unvalidated document with
// an override missing either one counts in Go. TypeScript must count it too
// rather than throwing, or the two languages disagree about the same bytes.
describe('an override missing its timestamps', () => {
  const requirement = (): EvaluatedRequirement =>
    ({
      id: 'NO-DATES',
      impact: 0.5,
      results: [{ status: 'failed' } as RequirementResult],
      statusOverrides: [{ status: 'falsePositive', impact: { value: 0 } }],
    }) as unknown as EvaluatedRequirement;

  const document = (): HDFResults =>
    ({ baselines: [{ requirements: [requirement()] }] }) as unknown as HDFResults;

  it('resolves effective impact instead of throwing', () => {
    expect(effectiveImpactOf(requirement())).toBe(0);
  });

  // Asserts the BUCKET, not merely that no throw happened: the document has to
  // reach the loop for this to mean anything, and an impact re-scored to 0 is
  // informational, not the medium its raw 0.5 would be.
  // A null member is what an unvalidated document yields where Go's typed decode
  // produced a zero struct, so it must not throw either.
  it('tolerates a null override member', () => {
    const withNull = {
      id: 'NULL-MEMBER',
      impact: 0.5,
      results: [{ status: 'failed' } as RequirementResult],
      statusOverrides: [null],
    } as unknown as EvaluatedRequirement;
    expect(effectiveImpactOf(withNull)).toBe(0.5);
    expect(overrideInputs(withNull)).toHaveLength(1);
  });

  // governingPoamType indexes control.poams by (index - statusOverrides.length),
  // so dropping an unusable member instead of keeping its slot would silently
  // name the wrong POA&M.
  it('keeps one entry per override so the poam index stays aligned', () => {
    const control = {
      id: 'ALIGN',
      impact: 0.5,
      statusOverrides: [null, { status: 'waiver', appliedAt: '2020-01-01T00:00:00Z' }],
    } as unknown as EvaluatedRequirement;
    expect(overrideInputs(control)).toHaveLength(2);
  });

  it('counts the re-scored requirement as informational, the path hdf-to-html takes', () => {
    const counts = countControlsByStatus(document(), () => 'failed');
    expect(counts.failed.informational).toBe(1);
    expect(counts.failed.medium).toBe(0);
  });
});
