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
