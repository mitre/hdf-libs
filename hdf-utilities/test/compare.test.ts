import { describe, it, expect } from 'vitest';
import { compareCodePoint } from '../src/index.js';

describe('compareCodePoint', () => {
  it("orders mixed-case and '-' vs '_' ids exactly as Go's sort.Strings does", () => {
    const ids = ['b-2', 'B-1', 'a-10', 'A-2', 'V-1_x', 'V-1-x', 'sv-1', 'SV-1'];
    expect([...ids].sort(compareCodePoint)).toEqual(['A-2', 'B-1', 'SV-1', 'V-1-x', 'V-1_x', 'a-10', 'b-2', 'sv-1']);
  });

  it('compares code points, not UTF-16 units: U+E000 sorts before U+10000', () => {
    expect(['\u{10000}', ''].sort(compareCodePoint)).toEqual(['', '\u{10000}']);
  });

  it('sorts a prefix first and reports equal strings as equal', () => {
    expect(['ab', 'a', ''].sort(compareCodePoint)).toEqual(['', 'a', 'ab']);
    expect(compareCodePoint('same', 'same')).toBe(0);
    expect(compareCodePoint('a', 'b')).toBeLessThan(0);
    expect(compareCodePoint('b', 'a')).toBeGreaterThan(0);
  });
});
