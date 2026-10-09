import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import {
  normalizeThresholdConfig,
  validateThresholds,
  type ThresholdConfig,
  type ThresholdBound,
} from '../src/compliance.js';

const testdata = join(dirname(fileURLToPath(import.meta.url)), '..', 'testdata');

// The same table go/threshold_saf_test.go reads, so the two languages cannot
// disagree about what a SAF-shaped bound means.
interface BoundCases {
  cases: { name: string; bound: number | ThresholdBound; want: ThresholdBound }[];
}
const boundCases = JSON.parse(
  readFileSync(join(testdata, 'saf-bound-shorthand-cases.json'), 'utf-8'),
) as BoundCases;

describe('SAF threshold-file compatibility — parity with go/threshold_saf_test.go', () => {
  it('normalizes every SAF-shaped bound the shared table lists', () => {
    expect(boundCases.cases.length).toBeGreaterThan(0);
    for (const c of boundCases.cases) {
      const normalized = normalizeThresholdConfig({
        passed: { total: c.bound as ThresholdBound },
      } as ThresholdConfig);
      expect(normalized.passed?.total, c.name).toEqual(c.want);
    }
  });

  it('a scalar bound is EXACT when evaluated, not a minimum', () => {
    const config = normalizeThresholdConfig({ passed: { total: 2 as unknown as ThresholdBound } });
    const counts = (total: number) => ({
      passed: { critical: 0, high: 0, medium: 0, low: 0, informational: 0, total },
      failed: { critical: 0, high: 0, medium: 0, low: 0, informational: 0, total: 0 },
      skipped: { critical: 0, high: 0, medium: 0, low: 0, informational: 0, total: 0 },
      error: { critical: 0, high: 0, medium: 0, low: 0, informational: 0, total: 0 },
      noImpact: { critical: 0, high: 0, medium: 0, low: 0, informational: 0, total: 0 },
    });
    expect(validateThresholds(config, counts(2), 100, [])).toEqual([]);
    expect(validateThresholds(config, counts(3), 100, [])).not.toEqual([]);
    expect(validateThresholds(config, counts(1), 100, [])).not.toEqual([]);
  });

  it('refuses a bare bound that is not a whole count', () => {
    expect(() =>
      normalizeThresholdConfig({ passed: { total: 1.5 as unknown as ThresholdBound } }),
    ).toThrow(/whole number of controls/);
  });

  it('does not mutate the caller\'s config', () => {
    const original: ThresholdConfig = { passed: { total: 19 as unknown as ThresholdBound } };
    normalizeThresholdConfig(original);
    expect(original.passed?.total).toBe(19);
  });

});

describe('the real SAF threshold files', () => {
  // Read as YAML-free JSON is not possible, so the fixtures are asserted on by the
  // Go peer, which owns the decoding. What TypeScript pins here is the rule those
  // files exercise — the scalar shorthand — through the shared table above.
  it('the vendored fixture set is present and carries its provenance', () => {
    const provenance = readFileSync(join(testdata, 'saf-thresholds', 'provenance.txt'), 'utf-8');
    expect(provenance).toContain('mitre/saf');
    expect(provenance).toContain('sha256');
  });
});

// The default path, not a pre-normalized one. A TypeScript consumer that parsed a
// SAF file itself and called validateThresholds directly used to get a bound of
// `19` whose .min/.max read undefined — so the bound applied to nothing and the
// gate went green, the silent-ignore this card exists to refuse. The Go peer
// cannot reach this state because its YAML decoding normalizes on the way in.
describe('a scalar bound reaching validateThresholds unnormalized', () => {
  const counts = (total: number) => ({
    passed: { critical: 0, high: 0, medium: 0, low: 0, informational: 0, total },
    failed: { critical: 0, high: 0, medium: 0, low: 0, informational: 0, total: 0 },
    skipped: { critical: 0, high: 0, medium: 0, low: 0, informational: 0, total: 0 },
    error: { critical: 0, high: 0, medium: 0, low: 0, informational: 0, total: 0 },
    noImpact: { critical: 0, high: 0, medium: 0, low: 0, informational: 0, total: 0 },
  });

  it('is applied, not silently skipped', () => {
    // Exactly as a consumer would hand it over after JSON.parse / YAML.parse.
    const raw = { passed: { total: 2 } } as unknown as ThresholdConfig;

    expect(validateThresholds(raw, counts(2), 100, [])).toEqual([]);
    expect(validateThresholds(raw, counts(3), 100, []), 'a count above an exact bound must fail').not.toEqual(
      [],
    );
    expect(validateThresholds(raw, counts(1), 100, []), 'and one below it').not.toEqual([]);
  });

  it('a non-numeric bare bound is refused rather than passed through', () => {
    // A string bound would otherwise become an object whose min/max read
    // undefined — the silent no-op, reached by a different route. Go refuses every
    // non-!!int scalar, so this keeps the two languages symmetric.
    // null is NOT in this list: an absent bound is absent, matching Go's nil
    // pointer. Only a present non-numeric value is a mistake.
    for (const bad of ['19', true, []]) {
      expect(() =>
        validateThresholds({ passed: { total: bad } } as unknown as ThresholdConfig, counts(2), 100, []),
      ).toThrow(/whole number of controls|min\/max mapping/);
    }
  });

  it('a non-integer bare bound is refused rather than ignored', () => {
    const raw = { passed: { total: 1.5 } } as unknown as ThresholdConfig;
    expect(() => validateThresholds(raw, counts(2), 100, [])).toThrow(/whole number of controls/);
  });
  // Parity: TestThresholdBoundRefusesTheSharedRefusals in go. A mapping that
  // is not a bound must be refused up front: typed through as one, {min: "abc"}
  // compares a count against a string and never fires — the silent no-op this
  // whole function exists to close.
  it('refuses every bound the shared refusals table lists', () => {
    expect(boundCases.refusals.length).toBeGreaterThan(0);
    for (const c of boundCases.refusals) {
      expect(
        () => normalizeThresholdConfig({ passed: { total: c.bound as unknown as ThresholdBound } } as ThresholdConfig),
        c.name,
      ).toThrow();
    }
  });
});
