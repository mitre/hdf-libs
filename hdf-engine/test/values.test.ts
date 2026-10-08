import { describe, it, expect } from 'vitest';
import { normalizeValues, valuesAll, valuesMatch, valuesActive } from '../src/values.js';

// The decoder's REFUSAL surface had no test at all, which an AC review caught by
// deleting the vocabulary check inside not and watching the whole hdf-cli suite
// stay green. Parity: go/values_test.go.
describe('normalizeValues — accepted forms', () => {
  it.each([
    ['a scalar is the one-element list', 'failed', { in: ['failed'], not: [] }],
    ['a list', ['failed', 'error'], { in: ['failed', 'error'], not: [] }],
    ['not over a list', { not: ['passed'] }, { in: [], not: ['passed'] }],
    ['not over a scalar', { not: 'passed' }, { in: [], not: ['passed'] }],
  ])('%s', (_name, raw, want) => {
    expect(normalizeValues(raw)).toEqual(want);
  });

  it('undefined constrains nothing', () => {
    expect(normalizeValues(undefined)).toEqual({ in: [], not: [] });
    expect(valuesActive(normalizeValues(undefined))).toBe(false);
  });
});

// Go refuses exactly these, and a form one language accepts while the other
// refuses is a surface divergence a policy author hits without warning. The
// `in` key is the one that matters: it is the decoder's OUTPUT shape, never a
// policy spelling, and accepting it here once diverged from Go.
describe('normalizeValues — refused forms match Go', () => {
  it.each([
    ['an empty not asserts nothing', { not: [] }, 'asserts nothing'],
    ['not cannot nest', { not: { not: ['passed'] } }, 'nested'],
    ['an unknown key is not a form', { nope: ['passed'] }, 'not a known form'],
    ['the in key is not a policy form', { in: ['failed'] }, 'not a known form'],
    ['a number is not a value', 5, 'a predicate value is'],
    ['a list of non-strings', [1, 2], 'a predicate value is'],
  ])('%s', (_name, raw, msg) => {
    expect(() => normalizeValues(raw)).toThrow(new RegExp(msg));
  });
});

describe('valuesAll covers both modes', () => {
  it('so a typo inside not is refused exactly as one outside it is', () => {
    expect(valuesAll({ in: ['a'], not: ['b'] }).sort()).toEqual(['a', 'b']);
    expect(valuesAll(undefined)).toEqual([]);
  });
});

describe('valuesMatch combines the modes', () => {
  const is = (actual: string) => (want: string) => actual === want;

  it('values within a field OR', () => {
    expect(valuesMatch({ in: ['a', 'b'], not: [] }, is('b'))).toBe(true);
    expect(valuesMatch({ in: ['a'], not: [] }, is('b'))).toBe(false);
  });

  it('not excludes', () => {
    expect(valuesMatch({ in: [], not: ['a'] }, is('a'))).toBe(false);
    expect(valuesMatch({ in: [], not: ['a'] }, is('b'))).toBe(true);
  });

  // ABSENCE: a field matching no value at all satisfies a negation. This is what
  // lets a gate catch the failure nobody adjudicated.
  it('an absent field satisfies a negation and fails an inclusion', () => {
    const never = () => false;
    expect(valuesMatch({ in: [], not: ['waiver'] }, never)).toBe(true);
    expect(valuesMatch({ in: ['waiver'], not: [] }, never)).toBe(false);
  });

  it('an inactive field constrains nothing', () => {
    expect(valuesMatch({ in: [], not: [] }, is('anything'))).toBe(true);
  });
});
