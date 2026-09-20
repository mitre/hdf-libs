import { afterAll, describe, expect, it } from 'vitest';
import { normalizeVolatileFields } from './snapshot.js';

// Mirrors shared/go/snapshotmask_test.go: the harness masks only the keys in the
// per-fixture mask set — timestamp always, startTime only for synthesized fixtures.
describe('snapshot harness per-fixture masking', () => {
  const doc = () => ({
    timestamp: '2026-07-12T00:00:00Z',
    baselines: [{ requirements: [{ results: [{ startTime: '2022-02-18T23:31:42Z', status: 'failed' }] }] }],
  });

  const startTimeOf = (v: unknown): { ts: unknown; st: unknown } => {
    const d = v as Record<string, any>;
    return { ts: d.timestamp, st: d.baselines[0].requirements[0].results[0].startTime };
  };

  it('asserts startTime for an input-derived fixture (only timestamp masked)', () => {
    const { ts, st } = startTimeOf(normalizeVolatileFields(doc(), new Set(['timestamp'])));
    expect(ts).toBe('(normalized)');
    expect(st).toBe('2022-02-18T23:31:42Z');
  });

  it('masks startTime for a synthesized fixture', () => {
    const { ts, st } = startTimeOf(normalizeVolatileFields(doc(), new Set(['timestamp', 'startTime'])));
    expect(ts).toBe('(normalized)');
    expect(st).toBe('(normalized)');
  });
});

import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { checkGoldenCoverage } from './snapshot.js';

// Deleting a golden whose input still exists used to remove its test silently:
// the harness only ever discovered goldens. Mirrors shared/go/snapshotcoverage_test.go.
describe('snapshot harness golden coverage', () => {
  const roots: string[] = [];
  afterAll(() => {
    for (const r of roots) rmSync(r, { recursive: true, force: true });
  });
  const fixtures = (files: Record<string, string>, manifest?: string): { input: string; expected: string; manifest: string } => {
    const root = mkdtempSync(join(tmpdir(), 'golden-coverage-'));
    roots.push(root);
    const input = join(root, 'input');
    const expected = join(root, 'expected');
    mkdirSync(input);
    mkdirSync(expected);
    for (const [name, where] of Object.entries(files)) writeFileSync(join(root, where, name), '{}');
    const manifestPath = join(root, 'no-golden.txt');
    if (manifest !== undefined) writeFileSync(manifestPath, manifest);
    return { input, expected, manifest: manifestPath };
  };

  it('reports an input whose golden is missing', () => {
    const f = fixtures({ 'a.json': 'input', 'a.json.hdf.json': 'expected', 'b.json': 'input' });
    expect(checkGoldenCoverage(f.input, f.expected, f.manifest)).toEqual([
      'input b.json has no golden expected/b.json.hdf.json and no entry in no-golden.txt',
    ]);
  });

  it('accepts the empty.* convention without a manifest', () => {
    const f = fixtures({ 'empty.json': 'input', 'empty.xml': 'input', 'a.json': 'input', 'a.json.hdf.json': 'expected' });
    expect(checkGoldenCoverage(f.input, f.expected, f.manifest)).toEqual([]);
  });

  it('accepts an input the manifest records, with a reason', () => {
    const f = fixtures({ 'b.json': 'input' }, 'b.json — used by TestX, which asserts an error\n');
    expect(checkGoldenCoverage(f.input, f.expected, f.manifest)).toEqual([]);
  });

  it('rejects a manifest entry that names no input, so the list cannot rot', () => {
    const f = fixtures({}, 'gone.json — once here\n');
    expect(checkGoldenCoverage(f.input, f.expected, f.manifest)).toEqual([
      'no-golden.txt names gone.json, which is not in input/ — remove the entry',
    ]);
  });

  it('rejects a manifest entry for an input that has a golden after all', () => {
    const f = fixtures({ 'a.json': 'input', 'a.json.hdf.json': 'expected' }, 'a.json — no golden\n');
    expect(checkGoldenCoverage(f.input, f.expected, f.manifest)).toEqual([
      'no-golden.txt names a.json, but expected/a.json.hdf.json exists — remove the entry',
    ]);
  });

  it('rejects a manifest entry without a reason', () => {
    const f = fixtures({ 'b.json': 'input' }, 'b.json\n');
    expect(checkGoldenCoverage(f.input, f.expected, f.manifest)).toEqual([
      'no-golden.txt entry for b.json gives no reason — write one after " — "',
    ]);
  });
});
