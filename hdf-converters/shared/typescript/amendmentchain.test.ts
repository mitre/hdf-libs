import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { HashAlgorithm } from '@mitre/hdf-schema';
import type { StandaloneOverride } from '@mitre/hdf-schema';
import { chainOverrides } from './amendmentchain.js';

function waiver(id: string, reason: string): StandaloneOverride {
  return {
    type: 'waiver',
    requirementId: id,
    status: 'passed',
    reason,
    appliedBy: { type: 'email', identifier: 'admin@example.com' },
    appliedAt: new Date('2026-03-01T12:00:00Z'),
    expiresAt: new Date('2099-12-31T00:00:00Z'),
  } as unknown as StandaloneOverride;
}

describe('chainOverrides', () => {
  it('leaves the first override unlinked and chains the rest', async () => {
    const overrides = [waiver('AC-1', 'first'), waiver('AC-2', 'second'), waiver('AC-3', 'third')];
    await chainOverrides(overrides);

    expect(overrides[0].previousChecksum).toBeUndefined();
    expect(overrides[1].previousChecksum?.algorithm).toBe(HashAlgorithm.Sha256);
    expect(overrides[1].previousChecksum?.value).toMatch(/^[0-9a-f]{64}$/);
    expect(overrides[2].previousChecksum?.value).not.toBe(overrides[1].previousChecksum?.value);
  });

  it('is deterministic for identical input', async () => {
    const a = [waiver('AC-1', 'x'), waiver('AC-2', 'y')];
    const b = [waiver('AC-1', 'x'), waiver('AC-2', 'y')];
    await chainOverrides(a);
    await chainOverrides(b);
    expect(a[1].previousChecksum?.value).toBe(b[1].previousChecksum?.value);
  });

  it('changes the recorded link when the preceding override changes', async () => {
    const before = [waiver('AC-1', 'original'), waiver('AC-2', 'second')];
    const after = [waiver('AC-1', 'edited'), waiver('AC-2', 'second')];
    await chainOverrides(before);
    await chainOverrides(after);
    expect(after[1].previousChecksum?.value).not.toBe(before[1].previousChecksum?.value);
  });

  it('re-chaining an already-chained set is stable', async () => {
    const overrides = [waiver('AC-1', 'first'), waiver('AC-2', 'second')];
    await chainOverrides(overrides);
    const first = overrides[1].previousChecksum?.value;
    await chainOverrides(overrides);
    expect(overrides[1].previousChecksum?.value).toBe(first);
  });

  // The chain a TS converter writes must verify under Go's `hdf amend verify`.
  // The Go-generated expected fixtures are the contract; this asserts the link
  // this code produces is the one those fixtures record.
  it('reproduces the checksums in the Go-generated expected fixture', async () => {
    const expected = JSON.parse(
      readFileSync(
        'converters/openvex-to-hdf/fixtures/expected/multi-status.openvex.json.hdf.json',
        'utf8',
      ),
    ) as { overrides: StandaloneOverride[] };

    const recorded = expected.overrides.map((o) => o.previousChecksum?.value);
    const rechained = expected.overrides.map((o) => ({ ...o }));
    await chainOverrides(rechained as StandaloneOverride[]);

    expect(rechained.map((o) => o.previousChecksum?.value)).toEqual(recorded);
    expect(recorded.filter(Boolean).length).toBeGreaterThan(0);
  });
});
