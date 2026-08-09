import { describe, it, expect } from 'vitest';
import { validateRequirementChangeEvent } from '@mitre/hdf-validators';
import { changeEventFromPrevious, type KeyState, type EventInputs } from '../src/change-event.js';

// Pinned vectors shared with the Go suite (effective_checksum_test.go).
const VECTOR_FAILED_HALF = '704f62b2d0803438ad6b7b9bab45e2c4f350b7344135a2a7f8ef986d98669021';
const VECTOR_PASSED_HALF = '73908440a3b44d76de559753babfea36987a618b80ee9d26adcf29cb5c7a5217';

function inputs(): EventInputs {
  return {
    eventId: '0190f6f2-1c4e-7c3a-9f2a-3b1d5e7a9c01',
    source: 'inspec://web01/rhel9-stig',
    sequence: 412,
    systemRef: 'apptier.hdf-system.json',
    componentId: '6e0f2a3b-9c01-4d5e-8f7a-1b2c3d4e5f60',
    requirementId: 'SV-100001',
    timestamp: '2026-07-22T14:03:11Z',
    referenceTimestamp: '2026-07-22T14:03:11Z',
  };
}

function prevFailing(): KeyState {
  return {
    effectiveStatus: 'failed',
    effectiveImpact: 0.5,
    checksum: { algorithm: 'sha256', value: VECTOR_FAILED_HALF },
  };
}

function makeReq(status: string, extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: 'SV-100001',
    impact: 0.5,
    tags: {},
    descriptions: [{ label: 'default', data: 'test description' }],
    results: [{ status, codeDesc: 'test', startTime: '2025-01-01T00:00:00Z' }],
    ...extra,
  };
}

function makeOverride(extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    type: 'waiver',
    status: 'passed',
    reason: 'approved by team lead',
    appliedBy: { type: 'simple', identifier: 'admin' },
    appliedAt: '2026-07-01T00:00:00Z',
    expiresAt: '2099-12-31T00:00:00Z',
    ...extra,
  };
}

function assertValidEvent(ev: Record<string, unknown>): void {
  const result = validateRequirementChangeEvent(ev);
  expect(result.valid, JSON.stringify(result.errors)).toBe(true);
}

describe('changeEventFromPrevious', () => {
  it('returns null when the checksum matches (no change)', async () => {
    const ev = await changeEventFromPrevious(prevFailing(), makeReq('failed'), null, inputs());
    expect(ev).toBeNull();
  });

  it('returns null when both prev and new are absent', async () => {
    expect(await changeEventFromPrevious(null, null, null, inputs())).toBeNull();
  });

  it('emits new for an unseen key (chain start)', async () => {
    const ev = await changeEventFromPrevious(null, makeReq('passed'), null, inputs());
    expect(ev).not.toBeNull();
    expect(ev!.state).toBe('new');
    expect(ev!.before).toBeNull();
    expect(ev!.priorChecksum).toBeNull();
    expect(ev!.after).not.toBeNull();
    assertValidEvent(ev!);
  });

  it('emits absent when the requirement leaves scope', async () => {
    const ev = await changeEventFromPrevious(prevFailing(), null, null, inputs());
    expect(ev).not.toBeNull();
    expect(ev!.state).toBe('absent');
    expect(ev!.after).toBeNull();
    expect(ev!.before).toEqual({ effectiveStatus: 'failed', effectiveImpact: 0.5 });
    expect((ev!.priorChecksum as Record<string, unknown>).value).toBe(VECTOR_FAILED_HALF);
    assertValidEvent(ev!);
  });

  it('classifies failed→passed as fixed with the chain link', async () => {
    const ev = await changeEventFromPrevious(prevFailing(), makeReq('passed'), null, inputs());
    expect(ev).not.toBeNull();
    expect(ev!.state).toBe('fixed');
    expect((ev!.priorChecksum as Record<string, unknown>).value).toBe(VECTOR_FAILED_HALF);
    assertValidEvent(ev!);
  });

  it('classifies passed→failed as regressed', async () => {
    const prev: KeyState = {
      effectiveStatus: 'passed',
      effectiveImpact: 0.5,
      checksum: { algorithm: 'sha256', value: VECTOR_PASSED_HALF },
    };
    const ev = await changeEventFromPrevious(prev, makeReq('failed'), null, inputs());
    expect(ev!.state).toBe('regressed');
    assertValidEvent(ev!);
  });

  it('classifies an impact-only change as updated with impactChanged', async () => {
    const req = makeReq('failed', {
      statusOverrides: [
        makeOverride({ type: 'riskAdjustment', status: undefined, impact: { value: 0.2 } }),
      ],
    });
    delete (req.statusOverrides as Record<string, unknown>[])[0].status;
    const ev = await changeEventFromPrevious(prevFailing(), req, null, inputs());
    expect(ev!.state).toBe('updated');
    expect(ev!.changeReasons).toContain('impactChanged');
    assertValidEvent(ev!);
  });

  it('echoes all envelope inputs', async () => {
    const i = { ...inputs(), schemaRef: 'https://mitre.github.io/hdf-libs/schemas/hdf-requirement-change-event/v3.4.0' };
    const ev = await changeEventFromPrevious(prevFailing(), makeReq('passed'), null, i);
    expect(ev!.eventId).toBe(i.eventId);
    expect(ev!.source).toBe(i.source);
    expect(ev!.sequence).toBe(i.sequence);
    expect(ev!.systemRef).toBe(i.systemRef);
    expect(ev!.componentId).toBe(i.componentId);
    expect(ev!.requirementId).toBe(i.requirementId);
    expect(ev!.timestamp).toBe(i.timestamp);
    expect(ev!.schemaRef).toBe(i.schemaRef);
    assertValidEvent(ev!);
  });

  it('attributes an override-driven flip when the full prior requirement is given', async () => {
    const prevReq = makeReq('failed');
    const newReq = makeReq('failed', { statusOverrides: [makeOverride()] });
    const ev = await changeEventFromPrevious(prevFailing(), newReq, prevReq, inputs());
    expect(ev!.state).toBe('fixed');
    expect(ev!.changeReasons).toContain('overrideAdded');
    expect(ev!.changeReasons).not.toContain('resultChanged');
    assertValidEvent(ev!);
  });

  it('filters batch-only reasons out of the wire vocabulary', async () => {
    const prevReq = makeReq('failed');
    const newReq = makeReq('passed', { title: 'Renamed control title' });
    const ev = await changeEventFromPrevious(prevFailing(), newReq, prevReq, inputs());
    expect(ev!.changeReasons).toContain('resultChanged');
    expect(ev!.changeReasons).not.toContain('metadataChanged');
    assertValidEvent(ev!);
  });

  it('matches the Go kernel field-for-field on the shared fixed-transition case', async () => {
    const ev = await changeEventFromPrevious(prevFailing(), makeReq('passed'), null, inputs());
    // Mirror of TestChangeEventFromPrevious_FailedToPassedIsFixed — the Go
    // suite asserts the same state/priorChecksum/envelope values.
    expect({
      state: ev!.state,
      priorChecksum: ev!.priorChecksum,
      before: ev!.before,
      sequence: ev!.sequence,
    }).toEqual({
      state: 'fixed',
      priorChecksum: { algorithm: 'sha256', value: VECTOR_FAILED_HALF },
      before: { effectiveStatus: 'failed', effectiveImpact: 0.5 },
      sequence: 412,
    });
  });
});

describe('mapped and window-dependent change reasons', () => {
  const WAIVED_CHECKSUM = 'd11c074ab9131807816013a71d986f1ceb2e5871a8a01dee4043391b7a6bf37b';

  it('maps effectiveImpactChanged to a single impactChanged', async () => {
    const prevReq = makeReq('failed');
    const newReq = makeReq('failed', {
      statusOverrides: [
        makeOverride({ type: 'riskAdjustment', impact: { value: 0.2 } }),
      ],
      effectiveImpact: 0.2,
    });
    delete (newReq.statusOverrides as Record<string, unknown>[])[0].status;

    const ev = await changeEventFromPrevious(prevFailing(), newReq, prevReq, inputs());
    expect(ev).not.toBeNull();
    expect(ev!.changeReasons).toContain('overrideAdded');
    const impactCount = (ev!.changeReasons as string[]).filter((r) => r === 'impactChanged').length;
    expect(impactCount, 'effectiveImpactChanged must map to a single impactChanged').toBe(1);
    assertValidEvent(ev!);
  });

  it('maps a base impact change to impactChanged', async () => {
    const prevReq = makeReq('failed');
    const newReq = makeReq('failed', { impact: 0.3 });
    const ev = await changeEventFromPrevious(prevFailing(), newReq, prevReq, inputs());
    expect(ev!.changeReasons).toContain('impactChanged');
    assertValidEvent(ev!);
  });

  it('detects overrideExpired across the observation window', async () => {
    // Identical scans; the waiver lapsed between observations (deliberately-past
    // expiresAt asserts expiry behavior).
    const waived = () =>
      makeReq('failed', {
        statusOverrides: [makeOverride({ expiresAt: '2026-07-21T00:00:00Z' })],
      });
    const prev: KeyState = {
      effectiveStatus: 'passed',
      effectiveImpact: 0.5,
      checksum: { algorithm: 'sha256', value: WAIVED_CHECKSUM },
    };
    const ev = await changeEventFromPrevious(prev, waived(), waived(), {
      ...inputs(),
      prevReferenceTimestamp: '2026-07-20T00:00:00Z',
      referenceTimestamp: '2026-07-22T14:03:11Z',
    });
    expect(ev).not.toBeNull();
    expect(ev!.state).toBe('regressed');
    expect(ev!.changeReasons).toContain('overrideExpired');
    expect(ev!.changeReasons).not.toContain('resultChanged');
    assertValidEvent(ev!);
  });

  it('detects overrideRemoved', async () => {
    const prevReq = makeReq('failed', { statusOverrides: [makeOverride()] });
    const newReq = makeReq('failed');
    const prev: KeyState = {
      effectiveStatus: 'passed',
      effectiveImpact: 0.5,
      checksum: { algorithm: 'sha256', value: WAIVED_CHECKSUM },
    };
    const ev = await changeEventFromPrevious(prev, newReq, prevReq, inputs());
    expect(ev!.state).toBe('regressed');
    expect(ev!.changeReasons).toContain('overrideRemoved');
    assertValidEvent(ev!);
  });
});
