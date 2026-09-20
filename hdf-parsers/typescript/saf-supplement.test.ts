import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { describe, it, expect } from 'vitest';
import { normalizeSafSupplement, parseResults } from './index.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturesDir = join(__dirname, '..', 'testdata', 'saf-supplement');

// Minimal schema-valid v3 results base; extra top-level keys are spliced in per test.
function validV3WithExtra(extra: Record<string, unknown>): string {
  return JSON.stringify({
    timestamp: '2026-01-01T00:00:00Z',
    generator: { name: 't', version: '0.0.1' },
    statistics: { duration: 0.1 },
    baselines: [{
      name: 'B',
      resultsChecksum: { algorithm: 'sha256', value: '0'.repeat(64) },
      requirements: [{
        id: 'x', title: 't', impact: 0, tags: {},
        descriptions: [{ label: 'default', data: 'd' }],
        results: [{ status: 'passed', codeDesc: 'd', startTime: '2026-01-01T00:00:00Z' }],
      }],
    }],
    ...extra,
  });
}

describe('normalizeSafSupplement', () => {
  it('rewrites a legacy target into a components[] cloudAccount entry', () => {
    const { output, warnings } = normalizeSafSupplement(
      validV3WithExtra({ target: { id: 'prod-account', type: 'cloudAccount', boundary: 'sparc' } }),
    );
    const doc = JSON.parse(output);
    expect('target' in doc).toBe(false);
    expect(doc.components).toHaveLength(1);
    expect(doc.components[0]).toMatchObject({
      type: 'cloudAccount', name: 'prod-account', accountId: 'prod-account', labels: { boundary: 'sparc' },
    });
    expect(warnings.length).toBeGreaterThan(0);
  });

  it('rewrites a legacy passthrough under extensions.passthrough', () => {
    const { output, warnings } = normalizeSafSupplement(
      validV3WithExtra({ passthrough: { audit: { runId: 'r-123' } } }),
    );
    const doc = JSON.parse(output);
    expect('passthrough' in doc).toBe(false);
    expect(doc.extensions.passthrough.audit.runId).toBe('r-123');
    expect(warnings.length).toBeGreaterThan(0);
  });

  it('adds passthrough alongside an existing extensions key without clobbering it', () => {
    const { output } = normalizeSafSupplement(
      validV3WithExtra({ extensions: { foo: 'bar' }, passthrough: { audit: { runId: 'r-1' } } }),
    );
    const doc = JSON.parse(output);
    expect(doc.extensions.foo).toBe('bar');
    expect(doc.extensions.passthrough.audit.runId).toBe('r-1');
  });

  it('passes a doc with no legacy keys through byte-identical with no warnings', () => {
    const input = validV3WithExtra({});
    const { output, warnings } = normalizeSafSupplement(input);
    expect(output).toBe(input);
    expect(warnings).toHaveLength(0);
  });

  it('merges a target into a matching existing component rather than duplicating', () => {
    const { output } = normalizeSafSupplement(
      validV3WithExtra({
        components: [{ name: 'prod-account', type: 'cloudAccount' }],
        target: { id: 'prod-account', type: 'cloudAccount', boundary: 'sparc' },
      }),
    );
    const doc = JSON.parse(output);
    expect(doc.components).toHaveLength(1);
    expect(doc.components[0].labels.boundary).toBe('sparc');
  });

  it('leaves an unmapped target type in place for the schema to reject', () => {
    const { output, warnings } = normalizeSafSupplement(
      validV3WithExtra({ target: { id: 'x', type: 'not-a-real-type' } }),
    );
    const doc = JSON.parse(output);
    expect('target' in doc).toBe(true);
    expect(warnings.length).toBeGreaterThan(0);
  });

  // camfd wiring: parseResults runs the normalizer before ajv validation, so a
  // SAF-supplemented doc (which ajv would otherwise reject on unevaluatedProperties)
  // parses, with target as a component and the deprecation warning surfaced.
  it('parseResults accepts a SAF-supplemented doc and surfaces the warning', () => {
    const input = readFileSync(join(fixturesDir, 'legacy-in.json'), 'utf-8');
    const r = parseResults(input);
    expect(r.success).toBe(true);
    const comps = (r.data?.components ?? []) as Array<{ name?: string; type?: string }>;
    expect(comps.some((c) => c.name === 'prod-account' && c.type === 'cloudAccount')).toBe(true);
    expect(r.warnings && r.warnings.length).toBeGreaterThan(0);
  });

  // Cross-language parity: TS normalizes the shared legacy-in fixture to the same
  // v3 document the Go suite asserts (deep-equal; key order differs across langs).
  it('matches the shared legacy-in / v3-out fixture pair (Go parity)', () => {
    const input = readFileSync(join(fixturesDir, 'legacy-in.json'), 'utf-8');
    const expected = JSON.parse(readFileSync(join(fixturesDir, 'v3-out.json'), 'utf-8'));
    const { output } = normalizeSafSupplement(input);
    expect(JSON.parse(output)).toEqual(expected);
  });
});
