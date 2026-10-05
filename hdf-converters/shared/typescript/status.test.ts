import { readFileSync } from 'fs';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';

import { describe, it, expect } from 'vitest';
import type { EvaluatedRequirement } from '@mitre/hdf-schema';

import { requirementEffectiveStatus, requirementStatusInput } from './status.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

interface StatusExpiryCase {
  name: string;
  note: string;
  want: string;
  requirement: EvaluatedRequirement;
}

const expiryCases = (
  JSON.parse(readFileSync(join(__dirname, '..', 'status-expiry-cases.json'), 'utf-8')) as {
    cases: StatusExpiryCase[];
  }
).cases;

describe('requirementEffectiveStatus: shared Go/TypeScript expiry case table', () => {
  it.each(expiryCases.map((c) => [c.name, c] as const))('%s', (_name, c) => {
    expect(requirementEffectiveStatus(c.requirement), c.note).toBe(c.want);
  });
});

// quicktype types expiresAt as Date, so a consumer that hands the bridge a
// decoded document gives it a Date instance rather than the raw string.
describe('requirementStatusInput: Go zero time as a Date instance', () => {
  const zeroTimeOverride = (expiresAt: Date): EvaluatedRequirement =>
    ({
      id: 'SV-230221',
      impact: 0.7,
      results: [{ status: 'failed', startTime: '2025-03-14T09:12:44Z' }],
      statusOverrides: [
        {
          type: 'waiver',
          status: 'passed',
          reason: 'Vendor support contract renewed; waiver recorded in the SSP.',
          appliedBy: { type: 'simple', identifier: 'isso@example.test' },
          appliedAt: new Date('2025-03-20T00:00:00Z'),
          expiresAt,
        },
      ],
    }) as unknown as EvaluatedRequirement;

  it('drops expiresAt when the Date carries the Go zero instant', () => {
    const req = zeroTimeOverride(new Date('0001-01-01T00:00:00Z'));
    expect(requirementStatusInput(req).overrides).toEqual([
      { status: 'passed', appliedAt: '2025-03-20T00:00:00.000Z', expiresAt: undefined },
    ]);
    expect(requirementEffectiveStatus(req)).toBe('passed');
  });

  it('keeps expiresAt when the Date carries a real far-future instant', () => {
    const req = zeroTimeOverride(new Date('2099-12-31T00:00:00Z'));
    expect(requirementStatusInput(req).overrides).toEqual([
      {
        status: 'passed',
        appliedAt: '2025-03-20T00:00:00.000Z',
        expiresAt: '2099-12-31T00:00:00.000Z',
      },
    ]);
    expect(requirementEffectiveStatus(req)).toBe('passed');
  });
});
