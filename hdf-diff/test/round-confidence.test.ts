import { describe, it, expect } from 'vitest';
import { roundConfidence } from '../src/diff.js';

describe('roundConfidence', () => {
  it('strips IEEE-754 noise to 4 decimal places', () => {
    expect(roundConfidence(1 / 3)).toBe(0.3333);
    expect(roundConfidence(1 - 1.0 / 3.0)).toBe(0.6667);
    expect(roundConfidence(2 / 3)).toBe(0.6667);
  });

  it('leaves clean values unchanged', () => {
    expect(roundConfidence(1)).toBe(1);
    expect(roundConfidence(0)).toBe(0);
    expect(roundConfidence(0.5)).toBe(0.5);
  });
});
