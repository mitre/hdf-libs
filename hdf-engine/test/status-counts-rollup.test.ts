import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { addCounts, severityTotals } from '../src/index.js';
import type { SeverityCounts, StatusCounts } from '../src/index.js';

const testdata = join(dirname(fileURLToPath(import.meta.url)), '..', 'testdata');

// The same table go/rollup_counts_test.go reads, so the two languages cannot
// disagree about what rolling count sets up means. Entries omit their zero
// fields, so a case shows only the buckets it exercises; the two fill helpers
// below are where those omissions become numbers.
interface RollupCases {
  cases: {
    name: string;
    note?: string;
    inputs: Partial<Record<keyof StatusCounts, Partial<SeverityCounts>>>[];
    want: Partial<Record<keyof StatusCounts, Partial<SeverityCounts>>>;
    wantSeverityTotals: Partial<SeverityCounts>;
  }[];
}
const table = JSON.parse(readFileSync(join(testdata, 'status-counts-rollup-cases.json'), 'utf-8')) as RollupCases;

function severity(partial: Partial<SeverityCounts> = {}): SeverityCounts {
  return {
    critical: partial.critical ?? 0,
    high: partial.high ?? 0,
    medium: partial.medium ?? 0,
    low: partial.low ?? 0,
    informational: partial.informational ?? 0,
    total: partial.total ?? 0,
  };
}

function counts(partial: Partial<Record<keyof StatusCounts, Partial<SeverityCounts>>>): StatusCounts {
  return {
    passed: severity(partial.passed),
    failed: severity(partial.failed),
    skipped: severity(partial.skipped),
    error: severity(partial.error),
    noImpact: severity(partial.noImpact),
  };
}

describe('StatusCounts roll-up — parity with go/rollup_counts_test.go', () => {
  it('reads a non-empty shared table', () => {
    expect(table.cases.length).toBeGreaterThan(0);
  });

  for (const c of table.cases) {
    it(`addCounts: ${c.name}`, () => {
      expect(addCounts(...c.inputs.map(counts)), c.note).toEqual(counts(c.want));
    });

    it(`severityTotals: ${c.name}`, () => {
      expect(severityTotals(counts(c.want)), c.note).toEqual(severity(c.wantSeverityTotals));
    });

    // A sum that rewrote its arguments would corrupt the per-source and
    // per-baseline rows the HTML report prints alongside the whole, which are
    // the same objects it sums.
    it(`addCounts leaves its arguments alone: ${c.name}`, () => {
      const inputs = c.inputs.map(counts);
      addCounts(...inputs);
      expect(inputs).toEqual(c.inputs.map(counts));
    });
  }

  it('severityTotals leaves its argument alone', () => {
    const input = counts({ passed: { critical: 1, total: 1 } });
    severityTotals(input);
    expect(input).toEqual(counts({ passed: { critical: 1, total: 1 } }));
  });

  it('sums no count sets to an empty one', () => {
    expect(addCounts()).toEqual(counts({}));
  });
});
