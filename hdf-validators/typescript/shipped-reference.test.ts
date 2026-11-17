/**
 * Pins the shipped TypeScript validator to its Go peer on the closure of the
 * Reference primitive, the shape of every requirement's `refs[]` entry. Both
 * languages read ../testdata/shipped-reference-cases.json.
 */
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from 'vitest';
import { validateResults } from './index.js';

interface ShippedReferenceCase {
  name: string;
  reference: unknown;
  valid: boolean;
  why: string;
}

const cases = (
  JSON.parse(
    readFileSync(
      join(dirname(fileURLToPath(import.meta.url)), '..', 'testdata', 'shipped-reference-cases.json'),
      'utf-8',
    ),
  ) as { cases: ShippedReferenceCase[] }
).cases;

function documentFor(reference: unknown): Record<string, unknown> {
  return {
    baselines: [
      {
        name: 'Test Baseline',
        checksum: { algorithm: 'sha256', value: 'abc123' },
        requirements: [
          {
            id: 'REQ-001',
            descriptions: [{ label: 'default', data: 'd' }],
            impact: 0.5,
            tags: {},
            refs: [reference],
            results: [{ status: 'passed', codeDesc: 'ok', startTime: '2025-01-01T00:00:00Z' }],
          },
        ],
      },
    ],
    components: [],
    statistics: {},
  };
}

describe('shipped validator: the Reference primitive is closed', () => {
  it('reads a non-empty shared case table', () => {
    expect(cases.length).toBeGreaterThan(0);
  });

  it.each(cases)('$name', (tc) => {
    const result = validateResults(documentFor(tc.reference));
    expect(result.valid, `${tc.why}\ngot: ${JSON.stringify(result.errors)}`).toBe(tc.valid);
  });
});
