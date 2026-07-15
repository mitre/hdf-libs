import { describe, expect, it } from 'vitest';
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
