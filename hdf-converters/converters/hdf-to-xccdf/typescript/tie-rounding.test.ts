import { describe, it, expect } from 'vitest';
import { convertHdfToXccdf } from './converter.js';

// The Go peer asserts this same score on the same shape. See its comment for why
// 512 is the smallest scorable count that can tie at six decimals: the score has
// to land on an odd multiple of 1/128 for its decimal expansion to end at the
// seventh digit with a 5. 1 passed of 512 gives exactly 0.1953125.
const SCORABLE = 512;
const PASSED = 1;

function tieDocument(): string {
  const requirements = Array.from({ length: SCORABLE }, (_, i) => ({
    id: `V-${String(i).padStart(4, '0')}`,
    title: `requirement ${i}`,
    impact: 0.5,
    tags: { nist: ['AC-3'] },
    results: [
      {
        status: i < PASSED ? 'passed' : 'failed',
        startTime: '2026-01-01T00:00:00Z',
      },
    ],
  }));
  return JSON.stringify({
    generator: { name: 'test', version: '1.0.0' },
    timestamp: '2026-01-01T00:00:00Z',
    baselines: [{ name: 'tie', version: '1.0.0', requirements }],
  });
}

describe('hdf-to-xccdf renders exact ties the way Go now does', () => {
  it('rounds a 1-of-512 score to 0.195313 at six decimals', () => {
    const out = convertHdfToXccdf(tieDocument());
    expect(out).toContain('0.195313');
    expect(out).not.toContain('0.195312');
  });
});
