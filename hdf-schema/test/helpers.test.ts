import { describe, it, expect, beforeAll } from 'vitest';
import type Ajv2020 from 'ajv/dist/2020.js';
import {
  computeEffectiveStatus,
  severityToImpact,
  impactToSeverity,
  createResult,
  createRequirement,
  createMinimalBaseline,
  createDescription,
  createStatusOverride,
  createPoam,
  createCvss,
} from '../src/helpers.js';
import { createAjvWithPrimitives, loadSchema, createMinimalResultsDoc } from './setup';

/**
 * Minimal requirement stub with only the fields computeEffectiveStatus inspects.
 */
function req(
  impact: number,
  results: Array<{ status: string }>,
  effectiveStatus?: string
) {
  return { impact, results, effectiveStatus } as Parameters<
    typeof computeEffectiveStatus
  >[0];
}

describe('severityToImpact', () => {
  // CVSS bands normalized to 0-1:
  // critical=0.9, high=0.7, medium=0.5, low=0.3, informational=0.0

  it('should map critical to 0.9 (floor of critical band 0.9-1.0)', () => {
    expect(severityToImpact('critical')).toBe(0.9);
  });

  it('should map high to 0.7 (floor of high band 0.7-0.8)', () => {
    expect(severityToImpact('high')).toBe(0.7);
  });

  it('should map medium to 0.5 (floor of medium band 0.4-0.6)', () => {
    expect(severityToImpact('medium')).toBe(0.5);
  });

  it('should map low to 0.3 (floor of low band 0.1-0.3)', () => {
    expect(severityToImpact('low')).toBe(0.3);
  });

  it('should map informational to 0.0 (not applicable)', () => {
    expect(severityToImpact('informational')).toBe(0.0);
  });

  it('should map info shorthand to 0.0', () => {
    expect(severityToImpact('info')).toBe(0.0);
  });

  it('should be case-insensitive', () => {
    expect(severityToImpact('CRITICAL')).toBe(0.9);
    expect(severityToImpact('High')).toBe(0.7);
    expect(severityToImpact('MEDIUM')).toBe(0.5);
    expect(severityToImpact('LOW')).toBe(0.3);
  });

  it('should default to 0.5 (medium) for unknown severity', () => {
    expect(severityToImpact('unknown')).toBe(0.5);
    expect(severityToImpact('')).toBe(0.5);
  });

  it('should return null for null input', () => {
    expect(severityToImpact(null)).toBeNull();
  });
});

describe('impactToSeverity', () => {
  // Band boundaries: 0.0=informational, 0.1-0.3=low, 0.4-0.6=medium, 0.7-0.8=high, 0.9-1.0=critical

  it('should map 1.0 to critical', () => {
    expect(impactToSeverity(1.0)).toBe('critical');
  });

  it('should map 0.9 to critical (lower bound)', () => {
    expect(impactToSeverity(0.9)).toBe('critical');
  });

  it('should map 0.8 to high (upper bound)', () => {
    expect(impactToSeverity(0.8)).toBe('high');
  });

  it('should map 0.7 to high (lower bound)', () => {
    expect(impactToSeverity(0.7)).toBe('high');
  });

  it('should map 0.6 to medium (upper bound)', () => {
    expect(impactToSeverity(0.6)).toBe('medium');
  });

  it('should map 0.5 to medium (midpoint)', () => {
    expect(impactToSeverity(0.5)).toBe('medium');
  });

  it('should map 0.4 to medium (lower bound)', () => {
    expect(impactToSeverity(0.4)).toBe('medium');
  });

  it('should map 0.3 to low (upper bound)', () => {
    expect(impactToSeverity(0.3)).toBe('low');
  });

  it('should map 0.1 to low (lower bound)', () => {
    expect(impactToSeverity(0.1)).toBe('low');
  });

  it('should map 0.0 to informational', () => {
    expect(impactToSeverity(0.0)).toBe('informational');
  });

  it('should return null for null input', () => {
    expect(impactToSeverity(null)).toBeNull();
  });

  // Sub-band precision: values within a band should all map to the same severity
  it('should map all values in critical band (0.9-1.0) to critical', () => {
    expect(impactToSeverity(0.91)).toBe('critical');
    expect(impactToSeverity(0.95)).toBe('critical');
    expect(impactToSeverity(0.99)).toBe('critical');
  });

  it('should map all values in high band (0.7-0.89) to high', () => {
    expect(impactToSeverity(0.71)).toBe('high');
    expect(impactToSeverity(0.75)).toBe('high');
    expect(impactToSeverity(0.89)).toBe('high');
  });

  // Round-trip: severity → impact → severity should be stable
  it('should round-trip through severityToImpact', () => {
    expect(impactToSeverity(severityToImpact('critical'))).toBe('critical');
    expect(impactToSeverity(severityToImpact('high'))).toBe('high');
    expect(impactToSeverity(severityToImpact('medium'))).toBe('medium');
    expect(impactToSeverity(severityToImpact('low'))).toBe('low');
    expect(impactToSeverity(severityToImpact('informational'))).toBe('informational');
  });
});

describe('computeEffectiveStatus', () => {
  // --- effectiveStatus already set ---

  it('should return effectiveStatus when already set', () => {
    expect(
      computeEffectiveStatus(req(0.5, [{ status: 'failed' }], 'passed'))
    ).toBe('passed');
  });

  it('should return effectiveStatus even if impact is 0', () => {
    expect(
      computeEffectiveStatus(req(0, [{ status: 'passed' }], 'failed'))
    ).toBe('failed');
  });

  // --- impact === 0 ---

  it('should return notApplicable when impact is 0 and no effectiveStatus', () => {
    expect(computeEffectiveStatus(req(0, [{ status: 'passed' }]))).toBe(
      'notApplicable'
    );
  });

  it('should return notApplicable when impact is 0 with no results', () => {
    expect(computeEffectiveStatus(req(0, []))).toBe('notApplicable');
  });

  // --- no results ---

  it('should return notReviewed when no results and impact > 0', () => {
    expect(computeEffectiveStatus(req(0.5, []))).toBe('notReviewed');
  });

  it('should return notReviewed when results is undefined', () => {
    expect(
      computeEffectiveStatus({ impact: 0.5 } as Parameters<
        typeof computeEffectiveStatus
      >[0])
    ).toBe('notReviewed');
  });

  // --- single result statuses ---

  it('should return passed when all results passed', () => {
    expect(
      computeEffectiveStatus(
        req(0.5, [{ status: 'passed' }, { status: 'passed' }])
      )
    ).toBe('passed');
  });

  it('should return failed when any result failed', () => {
    expect(
      computeEffectiveStatus(
        req(0.5, [{ status: 'passed' }, { status: 'failed' }])
      )
    ).toBe('failed');
  });

  it('should return error when any result is error', () => {
    expect(
      computeEffectiveStatus(
        req(0.5, [{ status: 'passed' }, { status: 'error' }])
      )
    ).toBe('error');
  });

  // --- precedence ---

  it('should return error over failed', () => {
    expect(
      computeEffectiveStatus(
        req(0.5, [{ status: 'failed' }, { status: 'error' }])
      )
    ).toBe('error');
  });

  it('should return failed over passed', () => {
    expect(
      computeEffectiveStatus(
        req(0.5, [
          { status: 'passed' },
          { status: 'passed' },
          { status: 'failed' },
        ])
      )
    ).toBe('failed');
  });

  it('should return error over failed and passed', () => {
    expect(
      computeEffectiveStatus(
        req(0.5, [
          { status: 'passed' },
          { status: 'failed' },
          { status: 'error' },
        ])
      )
    ).toBe('error');
  });

  // --- notReviewed/skipped results ---

  it('should return notReviewed when all results are notReviewed', () => {
    expect(
      computeEffectiveStatus(
        req(0.5, [{ status: 'notReviewed' }, { status: 'notReviewed' }])
      )
    ).toBe('notReviewed');
  });

  it('should return passed when mixed passed and notReviewed', () => {
    expect(
      computeEffectiveStatus(
        req(0.5, [{ status: 'passed' }, { status: 'notReviewed' }])
      )
    ).toBe('passed');
  });

  // --- edge cases ---

  it('should return notReviewed for single result with unknown status', () => {
    expect(
      computeEffectiveStatus(req(0.5, [{ status: 'something_else' }]))
    ).toBe('notReviewed');
  });

  it('should handle impact exactly at boundary (0.0)', () => {
    expect(computeEffectiveStatus(req(0.0, [{ status: 'failed' }]))).toBe(
      'notApplicable'
    );
  });

  it('should handle very small positive impact', () => {
    expect(computeEffectiveStatus(req(0.1, [{ status: 'passed' }]))).toBe(
      'passed'
    );
  });
});

describe('createResult', () => {
  it('omits message when not provided (no spurious empty message)', () => {
    const r = createResult('passed');
    expect('message' in r).toBe(false);
    expect(r.status).toBe('passed');
    expect(r.codeDesc).toBe('');
  });

  it('omits message when explicitly empty', () => {
    expect('message' in createResult('failed', '')).toBe(false);
  });

  it('includes message when non-empty, in position after status', () => {
    const r = createResult('failed', 'boom', { codeDesc: 'cd' });
    expect(r.message).toBe('boom');
    // key order must stay status, message, codeDesc, … to preserve Go-parity byte order
    expect(Object.keys(r).slice(0, 3)).toEqual(['status', 'message', 'codeDesc']);
  });

  it('passes options through', () => {
    const r = createResult('passed', undefined, { codeDesc: 'x', runTime: 5 });
    expect(r.codeDesc).toBe('x');
    expect(r.runTime).toBe(5);
    expect('message' in r).toBe(false);
  });

  it('includes resource and resourceId when provided', () => {
    const r = createResult('failed', 'boom', { resource: 'File', resourceId: '/etc/passwd' });
    expect(r.resource).toBe('File');
    expect(r.resourceId).toBe('/etc/passwd');
  });

  it('omits resource/resourceId when not provided', () => {
    const r = createResult('passed');
    expect('resource' in r).toBe(false);
    expect('resourceId' in r).toBe(false);
  });
});

describe('createRequirement extensions', () => {
  it('omits title when not provided', () => {
    const req = createRequirement('V-1', undefined, [createDescription('default', 'd')], 0.5, []);
    expect('title' in req).toBe(false);
    expect(req.id).toBe('V-1');
  });

  it('includes title when provided (unchanged behavior)', () => {
    const req = createRequirement('V-1', 'A title', [createDescription('default', 'd')], 0.5, []);
    expect(req.title).toBe('A title');
  });

  it('models control code', () => {
    const req = createRequirement('V-1', 'T', [], 0.5, [], { code: 'describe(...) do; end' });
    expect(req.code).toBe('describe(...) do; end');
  });

  it('models amendment fields', () => {
    const req = createRequirement('V-1', 'T', [], 0.5, [], {
      effectiveStatus: 'failed',
      effectiveImpact: 0.5,
      disposition: 'poam',
      statusOverrides: [createStatusOverride('waiver', { status: 'notApplicable' })],
      poams: [createPoam('remediation')],
    });
    expect(req.effectiveStatus).toBe('failed');
    expect(req.effectiveImpact).toBe(0.5);
    expect(req.disposition).toBe('poam');
    expect(req.statusOverrides).toHaveLength(1);
    expect(req.poams).toHaveLength(1);
  });

  it('models vulnerability fields', () => {
    const req = createRequirement('CVE-2024-1', 'T', [], 0.7, [], {
      cwe: ['CWE-79'],
      cvss: [createCvss('3.1', { baseScore: 9.8, baseSeverity: 'critical' })],
      refs: [{ url: 'https://nvd.nist.gov/vuln/detail/CVE-2024-1' }],
    });
    expect(req.cwe).toEqual(['CWE-79']);
    expect(req.cvss?.[0].baseScore).toBe(9.8);
    expect(req.refs).toHaveLength(1);
  });
});

describe('piece-builders produce schema-valid pieces', () => {
  it('createStatusOverride defaults to a valid, non-expired override', () => {
    const o = createStatusOverride('waiver');
    expect(o.type).toBe('waiver');
    expect(o.expiresAt).toBe('2099-12-31T00:00:00Z');
    // anyOf(status|impact): the minimal builder must set one to stay schema-valid.
    expect(o.status ?? o.impact).toBeDefined();
  });

  it('createPoam carries the now-required expiresAt', () => {
    const p = createPoam('remediation');
    expect(p.type).toBe('remediation');
    expect(p.expiresAt).toBe('2099-12-31T00:00:00Z');
    expect(p.explanation).toBeTruthy();
  });

  it('createCvss requires only version and passes options through', () => {
    expect(createCvss('3.1')).toEqual({ version: '3.1' });
    expect(createCvss('4.0', { baseScore: 7.5 }).baseScore).toBe(7.5);
  });
});

describe('helper-built docs validate against hdf-results.schema.json', () => {
  let validate: ReturnType<Ajv2020['compile']>;
  beforeAll(() => {
    validate = createAjvWithPrimitives().compile(loadSchema('hdf-results.schema.json'));
  });

  it('a requirement with amendment + vulnerability fields is schema-valid', () => {
    const req = createRequirement(
      'CVE-2024-1',
      undefined,
      [createDescription('default', 'Vulnerable dependency')],
      0.7,
      [createResult('failed', 'found', { startTime: '2026-01-01T00:00:00Z', resource: 'Package', resourceId: 'openssl' })],
      {
        code: 'check openssl version',
        effectiveStatus: 'failed',
        disposition: 'poam',
        statusOverrides: [createStatusOverride('riskAdjustment', { impact: { value: 0.4 } })],
        poams: [createPoam('remediation', { milestones: [{ description: 'patch', estimatedCompletion: '2099-01-01T00:00:00Z', status: 'pending' }] })],
        cwe: ['CWE-327'],
        cvss: [createCvss('3.1', { baseScore: 7.5, baseSeverity: 'high' })],
        refs: [{ url: 'https://example.gov/advisory' }],
      },
    );
    const doc = createMinimalResultsDoc({
      baselines: [createMinimalBaseline('b', [req])],
      components: [],
    });

    const ok = validate(doc);
    expect(ok, JSON.stringify(validate.errors)).toBe(true);
  });
});
