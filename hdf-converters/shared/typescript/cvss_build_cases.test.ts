import { readFileSync } from 'fs';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';
import { describe, expect, it } from 'vitest';
import { Version as CvssVersion } from '@mitre/hdf-schema';
import { buildCvss, cvssVersionFromVector } from './cvss.js';

interface CvssBuildCases {
  buildCases: Array<{
    name: string;
    input: { version: CvssVersion; baseScore?: number; baseVector?: string };
    want: { baseScore: number | null; baseSeverity: string | null };
  }>;
  versionCases: Array<{ vector: string; fallback?: CvssVersion; want: CvssVersion }>;
}

// Shared with go/cvss_test.go so both languages assert one table.
const CASES = JSON.parse(
  readFileSync(join(dirname(fileURLToPath(import.meta.url)), '..', 'cvss-build-cases.json'), 'utf-8'),
) as CvssBuildCases;

describe('buildCvss shared cases', () => {
  it('has populated shared tables', () => {
    expect(CASES.buildCases.length).toBeGreaterThan(0);
    expect(CASES.versionCases.length).toBeGreaterThan(0);
  });

  it.each(CASES.buildCases)('$name', ({ input, want }) => {
    const got = buildCvss(input);
    expect(got.baseScore ?? null).toBe(want.baseScore);
    expect(got.baseSeverity ?? null).toBe(want.baseSeverity);
  });
});

describe('cvssVersionFromVector shared cases', () => {
  it.each(CASES.versionCases)('$vector (fallback $fallback) is $want', ({ vector, fallback, want }) => {
    const got = fallback === undefined ? cvssVersionFromVector(vector) : cvssVersionFromVector(vector, fallback);
    expect(got).toBe(want);
  });
});

// JSON cannot carry a non-finite number, so these cannot live in the shared
// table. Peer of TestBuildCvss_NonFiniteScoreReadsAsAbsent in go/cvss_test.go.
describe('buildCvss with a non-finite base score', () => {
  it.each([
    ['NaN', Number.NaN],
    ['positive infinity', Number.POSITIVE_INFINITY],
    ['negative infinity', Number.NEGATIVE_INFINITY],
  ])('%s with a vector takes the score from the vector', (_name, baseScore) => {
    const got = buildCvss({
      version: CvssVersion.The20,
      baseScore,
      baseVector: 'AV:N/AC:L/Au:N/C:C/I:C/A:C',
    });
    expect(got.baseScore).toBe(10);
    expect(got.baseSeverity).toBe('high');
  });

  it.each([
    ['NaN', Number.NaN],
    ['positive infinity', Number.POSITIVE_INFINITY],
    ['negative infinity', Number.NEGATIVE_INFINITY],
  ])('%s without a vector leaves the entry without a score', (_name, baseScore) => {
    const got = buildCvss({version: CvssVersion.The20, baseScore});
    expect(got.baseScore).toBeUndefined();
    expect(got.baseSeverity).toBeUndefined();
  });
});
