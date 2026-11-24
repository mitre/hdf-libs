import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, it, expect } from 'vitest';
import { createExactIdStrategy } from '../../src/matching/exact-id.js';
import { createMappedIdStrategy } from '../../src/matching/mapped-id.js';
import type { MatchStrategy } from '../../src/matching/types.js';

/**
 * The table read here is also read by go/matching/shared_cases_test.go, so both engines
 * are asserted against ONE definition of how a repeated id's occurrences pair up,
 * ordering included, rather than two suites that can drift.
 */

interface SharedMatchCase {
  name: string;
  strategy: string;
  mapping?: Record<string, string>;
  old: Record<string, unknown>[];
  new: Record<string, unknown>[];
  matched: [string, string][];
  unmatchedOld: string[];
  unmatchedNew: string[];
  why: string;
}

const table = JSON.parse(
  readFileSync(resolve(import.meta.dirname, '..', '..', 'testdata', 'duplicate-id-matching-cases.json'), 'utf-8'),
) as { cases: SharedMatchCase[] };

const titleOf = (req: Record<string, unknown>): string => (req['title'] as string | undefined) ?? '';

describe('shared duplicate-id matching cases', () => {
  it('carries cases for every strategy both engines implement', () => {
    const strategies = new Set(table.cases.map((c) => c.strategy));
    expect(strategies).toEqual(new Set(['exactId', 'mappedId']));
  });

  for (const tc of table.cases) {
    it(tc.name, () => {
      let strategy: MatchStrategy;
      switch (tc.strategy) {
        case 'exactId':
          strategy = createExactIdStrategy();
          break;
        case 'mappedId':
          strategy = createMappedIdStrategy(tc.mapping ?? {});
          break;
        default:
          throw new Error(`unknown strategy ${tc.strategy}`);
      }

      const result = strategy.match(tc.old, tc.new);

      expect(result.matched, tc.why).toHaveLength(tc.matched.length);
      for (const [i, want] of tc.matched.entries()) {
        expect(titleOf(result.matched[i]!.oldReq), `pair ${i} old side: ${tc.why}`).toBe(want[0]);
        expect(titleOf(result.matched[i]!.newReq), `pair ${i} new side: ${tc.why}`).toBe(want[1]);
      }
      expect(result.unmatchedOld.map(titleOf), tc.why).toEqual(tc.unmatchedOld);
      expect(result.unmatchedNew.map(titleOf), tc.why).toEqual(tc.unmatchedNew);
    });
  }
});
