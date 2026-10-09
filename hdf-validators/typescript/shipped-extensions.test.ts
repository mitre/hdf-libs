/**
 * Pins the shipped TypeScript validator to its Go peer on the closure of
 * `extensions`.
 *
 * `extensions` is a closed, defined object — `passthrough` and
 * `rawSourceArtifacts` — and everything else a producer carries goes inside
 * `passthrough`. The Go validator is a draft-07 engine that silently ignores
 * `unevaluatedProperties`, so a closure written that way would hold here and
 * nowhere else. Both languages read ../testdata/shipped-extensions-cases.json.
 */
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from 'vitest';
import { validateResults } from './index.js';

interface ShippedExtensionsCase {
  name: string;
  extensions: Record<string, unknown>;
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
        'shipped-extensions-cases.json',
      ),
      'utf-8',
    ),
  ) as { cases: ShippedExtensionsCase[] }
).cases;

function documentFor(tc: ShippedExtensionsCase, atBaseline: boolean): Record<string, unknown> {
  const baseline: Record<string, unknown> = {
    name: 'CVE-Ecosystem Test Baseline',
    checksum: { algorithm: 'sha256', value: 'abc123' },
    requirements: [
      {
        id: 'CVE-2024-12345',
        descriptions: [{ label: 'default', data: 'Test CVE finding' }],
        impact: 0.7,
        tags: {},
        results: [
          { status: 'failed', codeDesc: 'Vulnerable', startTime: '2026-05-26T00:00:00Z' },
        ],
      },
    ],
  };
  if (atBaseline) baseline.extensions = tc.extensions;
  return {
    baselines: [baseline],
    components: [],
    statistics: {},
    ...(atBaseline ? {} : { extensions: tc.extensions }),
  };
}

describe('shipped validators agree that extensions is closed', () => {
  for (const site of ['root', 'baseline'] as const) {
    describe(site, () => {
      it.each(cases.map((c) => [c.name, c] as const))('%s', (_name, tc) => {
        const result = validateResults(documentFor(tc, site === 'baseline'));
        expect(result.valid, `${tc.why}\ngot: ${JSON.stringify(result.errors ?? [])}`).toBe(
          tc.valid,
        );
      });
    });
  }
});
