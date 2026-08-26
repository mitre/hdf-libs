/**
 * Pins the shipped TypeScript validator to its Go peer on JSON Schema `format`.
 *
 * The two are a public API pair: a document one accepts, the other must accept.
 * gojsonschema's format checkers broke that in four ways at once — rejecting an
 * uppercase UUID and a lowercase RFC 3339 `t`, rejecting a legal leap second,
 * and accepting a bare date as a date-time — so `hdf validate` disagreed with
 * validateResults on documents that are valid HDF. Both languages read
 * ../testdata/shipped-format-cases.json, which names the RFC clause settling
 * each case.
 */
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from 'vitest';
import { validateResults } from './index.js';

interface ShippedFormatCase {
  name: string;
  field: 'componentId' | 'startTime';
  value: string;
  valid: boolean;
  why: string;
}

const cases = (
  JSON.parse(
    readFileSync(
      join(dirname(fileURLToPath(import.meta.url)), '..', 'testdata', 'shipped-format-cases.json'),
      'utf-8',
    ),
  ) as { cases: ShippedFormatCase[] }
).cases;

/** Places the case's value at a real format-bearing site in hdf-results. */
function documentFor(tc: ShippedFormatCase): Record<string, unknown> {
  const doc: Record<string, unknown> = {
    baselines: [
      {
        name: 'Format Test Baseline',
        checksum: { algorithm: 'sha256', value: 'abc123' },
        requirements: [
          {
            id: 'SV-1',
            impact: 0.5,
            tags: {},
            descriptions: [{ label: 'default', data: 'Test' }],
            results: [
              {
                status: 'passed',
                codeDesc: 'Test',
                startTime: tc.field === 'startTime' ? tc.value : '2025-01-01T00:00:00Z',
              },
            ],
          },
        ],
      },
    ],
    components:
      tc.field === 'componentId' ? [{ componentId: tc.value, type: 'host', name: 'h' }] : [],
    statistics: {},
  };
  return doc;
}

describe('shipped validators agree on format', () => {
  it('covers both format-bearing fields', () => {
    expect(new Set(cases.map((c) => c.field))).toEqual(new Set(['componentId', 'startTime']));
  });

  it.each(cases.map((c) => [c.name, c] as const))('%s', (_name, tc) => {
    const result = validateResults(documentFor(tc));
    expect(result.valid, `${tc.why}\ngot: ${JSON.stringify(result.errors ?? [])}`).toBe(tc.valid);
  });
});
