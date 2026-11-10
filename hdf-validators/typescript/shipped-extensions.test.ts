// Both languages consume the same closure and migration cases.
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
  undeclaredKeys?: string[];
}

const table = (
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
  ) as { migrationMessage: string; cases: ShippedExtensionsCase[] }
);
const cases = table.cases;

function documentFor(tc: ShippedExtensionsCase, atBaseline: boolean): Record<string, unknown> {
  const baseline: Record<string, unknown> = {
    name: 'CVE-Ecosystem Test Baseline',
    integrity: { algorithm: 'sha256', checksum: 'abc123' },
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

describe('extensions migration hint', () => {
  const migrations = cases.filter(tc => tc.undeclaredKeys !== undefined);
  if (migrations.length === 0) throw new Error('Missing migration cases');
  for (const atBaseline of [false, true]) {
    it.each(migrations)('$name at baseline: '+atBaseline, tc => {
      const result = validateResults(documentFor(tc, atBaseline));
      expect(result.valid).toBe(false);
      expect(result.errors).not.toHaveLength(0);
      expect(result.errors[0].message).toBe(table.migrationMessage);
      const prefix = atBaseline ? 'baselines.0.extensions.' : 'extensions.';
      const keys = tc.undeclaredKeys;
      if (!keys) throw new Error('Migration case must name its undeclared keys');
      expect(result.errors).toHaveLength(keys.length);
      expect(result.errors).toEqual(expect.arrayContaining(keys.map(key => ({
        field: prefix + key, message: table.migrationMessage,
        keyword: 'additionalProperties', value: tc.extensions,
      }))));
    });
  }
});

describe('extensions hint scope', () => {
  it.each([false, true])('does not hint on wrong-type extensions at baseline: %s', atBaseline => {
    const doc = documentFor({name: '', why: '', valid: true, extensions: {}}, atBaseline);
    const target = atBaseline ? (doc.baselines as Record<string, unknown>[])[0] : doc;
    target.extensions = 'wrong type';
    const result = validateResults(doc);
    expect(result.valid).toBe(false);
    expect(result.errors).not.toHaveLength(0);
    for (const error of result.errors) expect(error.message).not.toContain('Move producer-specific data');
  });
  it('does not hint on additionalProperties in a raw source record', () => {
    const doc = documentFor({name: '', why: '', valid: true, extensions: {}}, false);
    const baseline = (doc.baselines as Record<string, unknown>[])[0];
    const requirement = (baseline.requirements as Record<string, unknown>[])[0];
    const resultDoc = (requirement.results as Record<string, unknown>[])[0];
    resultDoc.rawSourceRecord = {content: '{}', encoding: 'utf-8', mediaType: 'application/json', system_context: {}};
    const result = validateResults(doc);
    expect(result.valid).toBe(false);
    expect(result.errors).toEqual([expect.objectContaining({
      keyword: 'additionalProperties', message: 'is not allowed',
      field: 'baselines.0.requirements.0.results.0.rawSourceRecord.system_context',
    })]);
  });
});
