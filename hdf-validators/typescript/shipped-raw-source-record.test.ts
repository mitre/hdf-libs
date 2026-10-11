/**
 * Pins the shipped TypeScript validator to its Go peer on the closure of
 * `results[].rawSourceRecord`.
 *
 * The record is a closed, defined object — `content`, `encoding`, `mediaType`
 * and an optional `pointer` — and is deliberately NOT a passthrough bag. The Go
 * validator is a draft-07 engine that silently ignores
 * `unevaluatedProperties`, so a closure written that way would hold here and
 * nowhere else. Both languages read
 * ../testdata/shipped-raw-source-record-cases.json.
 */
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from 'vitest';
import { validateResults } from './index.js';

interface ShippedRawSourceRecordCase {
  name: string;
  record: unknown;
  valid: boolean;
  why: string;
}

const cases = (
  JSON.parse(
    readFileSync(
      join(
        dirname(fileURLToPath(import.meta.url)),
        '..',
        'testdata',
        'shipped-raw-source-record-cases.json',
      ),
      'utf-8',
    ),
  ) as { cases: ShippedRawSourceRecordCase[] }
).cases;

function documentFor(record: unknown): Record<string, unknown> {
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
            results: [
              {
                status: 'passed',
                codeDesc: 'ok',
                startTime: '2025-01-01T00:00:00Z',
                rawSourceRecord: record,
              },
            ],
          },
        ],
      },
    ],
    components: [],
    statistics: {},
  };
}

describe('shipped validator: results[].rawSourceRecord is closed', () => {
  it('reads a non-empty shared case table', () => {
    expect(cases.length).toBeGreaterThan(0);
  });

  it.each(cases)('$name', (tc) => {
    const result = validateResults(documentFor(tc.record));
    expect(result.valid, `${tc.why}\ngot: ${JSON.stringify(result.errors)}`).toBe(tc.valid);
  });

  // The field is optional: a tool that emits HDF natively has no source record.
  it('accepts a result carrying no record at all', () => {
    const doc = documentFor(undefined);
    const results = (doc.baselines as Record<string, unknown>[])[0]!.requirements as Record<
      string,
      unknown
    >[];
    delete (results[0]!.results as Record<string, unknown>[])[0]!.rawSourceRecord;
    expect(validateResults(doc).valid).toBe(true);
  });
});
