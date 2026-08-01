import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { validateComparison } from '@mitre/hdf-validators';
import { diffHdf } from '../src/diff.js';
import type { RequirementDiff, ChangeReason } from '../src/types.js';
import { changeEventFromPrevious, type KeyState } from '../src/change-event.js';
import { computeEffectiveChecksum, computeEffectiveImpact } from '../src/effective-checksum.js';
import { computeEffectiveStatus } from '../src/status.js';
import { foldChangeEventsIntoComparison } from '../src/fold-events.js';

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), 'fixtures');
const load = (name: string): string => readFileSync(join(FIXTURES, name), 'utf-8');

type Req = Record<string, unknown>;

function requirementsOf(doc: Req): Req[] {
  const baselines = (doc['baselines'] as Req[] | undefined) ?? [];
  return baselines.flatMap((b) => (b['requirements'] as Req[] | undefined) ?? []);
}

async function deriveStream(seedJson: string, nextJson: string): Promise<Req[]> {
  const seedDoc = JSON.parse(seedJson) as Req;
  const nextDoc = JSON.parse(nextJson) as Req;
  const refTs = (nextDoc['timestamp'] as string | undefined) ?? '2026-07-22T14:03:11Z';
  const prevRefTs = (seedDoc['timestamp'] as string | undefined) ?? refTs;

  const prevByKey = new Map<string, { state: KeyState; req: Req }>();
  for (const r of requirementsOf(seedDoc)) {
    prevByKey.set(r['id'] as string, {
      state: {
        effectiveStatus: computeEffectiveStatus(r, refTs),
        effectiveImpact: computeEffectiveImpact(r, refTs),
        checksum: await computeEffectiveChecksum(r, refTs),
      },
      req: r,
    });
  }

  let seq = 0;
  const mkInputs = (id: string) => ({
    eventId: `0190f6f2-0000-7000-8000-${String(++seq).padStart(12, '0')}`,
    source: 'inspec://fixture/scan',
    sequence: seq,
    systemRef: 'fixture.hdf-system.json',
    componentId: '6e0f2a3b-9c01-4d5e-8f7a-1b2c3d4e5f60',
    requirementId: id,
    timestamp: refTs,
    referenceTimestamp: refTs,
    prevReferenceTimestamp: prevRefTs,
  });

  const events: Req[] = [];
  for (const r of requirementsOf(nextDoc)) {
    const id = r['id'] as string;
    const prev = prevByKey.get(id) ?? null;
    prevByKey.delete(id);
    const ev = await changeEventFromPrevious(prev?.state ?? null, r, prev?.req ?? null, mkInputs(id));
    if (ev) events.push(ev);
  }
  for (const id of [...prevByKey.keys()].sort()) {
    const prev = prevByKey.get(id)!;
    const ev = await changeEventFromPrevious(prev.state, null, prev.req, mkInputs(id));
    if (ev) events.push(ev);
  }
  return events;
}

/** The kernel's batch→event reason mapping, for law comparison. */
const EVENT_REASON: Partial<Record<ChangeReason, string>> = {
  resultChanged: 'resultChanged',
  overrideAdded: 'overrideAdded',
  overrideExpired: 'overrideExpired',
  overrideRemoved: 'overrideRemoved',
  impactChanged: 'impactChanged',
  effectiveImpactChanged: 'impactChanged',
};

function mapBatchReasons(reasons: ChangeReason[]): Set<string> {
  const out = new Set<string>();
  for (const r of reasons) {
    const mapped = EVENT_REASON[r];
    if (mapped) out.add(mapped);
  }
  return out;
}

async function foldLawCheck(seedName: string, nextName: string): Promise<void> {
  const seedJson = load(seedName);
  const nextJson = load(nextName);
  const events = await deriveStream(seedJson, nextJson);

  const { comparison, warnings } = await foldChangeEventsIntoComparison(seedJson, events);
  expect(warnings, 'a complete derived stream must fold cleanly').toEqual([]);

  // TS diffHdf routes systemDrift to diffSystems (system documents), unlike
  // Go's DiffHdf — a pre-existing cross-language batch routing difference.
  // Temporal mode uses the identical comparePair construction the law needs.
  const batch = diffHdf(JSON.parse(seedJson) as Req, JSON.parse(nextJson) as Req, {
    comparisonMode: 'temporal',
  });
  const want = new Map<string, RequirementDiff>();
  for (const d of batch.requirementDiffs) {
    if (['unchanged', 'moved', 'split', 'merged'].includes(d.state)) continue;
    want.set(d.id, d);
  }

  const got = new Map((comparison['requirementDiffs'] as RequirementDiff[]).map((d) => [d.id, d]));
  expect(got.size, 'fold and batch must agree on the changed-key set').toBe(want.size);
  for (const [id, w] of want) {
    const g = got.get(id);
    expect(g, `key ${id} missing from fold output`).toBeDefined();
    expect(g!.state, `${id} state`).toBe(w.state);
    expect(g!.oldEffectiveStatus, `${id} oldEffectiveStatus`).toBe(w.oldEffectiveStatus);
    expect(g!.newEffectiveStatus, `${id} newEffectiveStatus`).toBe(w.newEffectiveStatus);
    expect(g!.oldImpact, `${id} oldImpact`).toBe(w.oldImpact);
    expect(g!.newImpact, `${id} newImpact`).toBe(w.newImpact);
    expect(g!.title, `${id} title`).toBe(w.title);
    expect(g!.fieldChanges, `${id} fieldChanges`).toEqual(w.fieldChanges);
    expect(g!.before, `${id} before`).toEqual(w.before);
    expect(g!.after, `${id} after`).toEqual(w.after);
    expect(new Set(g!.changeReasons as string[]), `${id} changeReasons (through the event mapping)`).toEqual(
      mapBatchReasons(w.changeReasons),
    );
    // matchStrategy/matchConfidence are batch matching metadata a per-key
    // stream never has; excluded from the law by design.
  }
}

describe('foldChangeEventsIntoComparison', () => {
  it('satisfies the fold-batch law on the scan pair', async () => {
    await foldLawCheck('scan-before.json', 'scan-after.json');
  });

  it('satisfies the fold-batch law on the override pair', async () => {
    await foldLawCheck('scan-before.json', 'scan-with-override.json');
  });

  it('produces a deterministic, schema-valid systemDrift comparison', async () => {
    const seedJson = load('scan-before.json');
    const events = await deriveStream(seedJson, load('scan-after.json'));
    const { comparison } = await foldChangeEventsIntoComparison(seedJson, events);

    expect(comparison['comparisonMode']).toBe('systemDrift');
    expect(comparison['systemRef']).toBe('fixture.hdf-system.json');
    expect(comparison['formatVersion']).toBe('1.0.0');
    expect(comparison['timestamp']).toBe('2024-02-01T00:00:00Z');
    expect((comparison['requirementDiffs'] as RequirementDiff[]).length).toBe(5);

    const validation = validateComparison(comparison);
    expect(validation.valid, JSON.stringify(validation.errors)).toBe(true);
  });

  it('is idempotent and order-invariant', async () => {
    const seedJson = load('scan-before.json');
    const events = await deriveStream(seedJson, load('scan-after.json'));
    const base = await foldChangeEventsIntoComparison(seedJson, events);
    const doubled = await foldChangeEventsIntoComparison(seedJson, [...events, ...events]);
    const reversed = await foldChangeEventsIntoComparison(seedJson, [...events].reverse());
    expect(doubled.comparison).toEqual(base.comparison);
    expect(reversed.comparison).toEqual(base.comparison);
  });

  it('warns on a chain gap but still lifts the winner', async () => {
    const seedJson = load('scan-before.json');
    const events = await deriveStream(seedJson, load('scan-after.json'));
    const withoutSv1 = events.filter((e) => e['requirementId'] !== 'SV-001');
    const sv1 = events.find((e) => e['requirementId'] === 'SV-001')!;
    const after = sv1['after'] as Req;
    const followOn = await changeEventFromPrevious(
      {
        effectiveStatus: 'passed',
        effectiveImpact: 0.7,
        checksum: await computeEffectiveChecksum(after, '2024-02-01T00:00:00Z'),
      },
      { ...after, results: [{ status: 'failed', codeDesc: 'regressed again', startTime: '2024-03-01T00:00:00Z' }] },
      after,
      {
        eventId: '0190f6f2-0000-7000-8000-000000000099',
        source: 'inspec://fixture/scan',
        sequence: 99,
        systemRef: 'fixture.hdf-system.json',
        componentId: '6e0f2a3b-9c01-4d5e-8f7a-1b2c3d4e5f60',
        requirementId: 'SV-001',
        timestamp: '2024-03-01T00:00:00Z',
        referenceTimestamp: '2024-03-01T00:00:00Z',
      },
    );
    const { comparison, warnings } = await foldChangeEventsIntoComparison(seedJson, [
      ...withoutSv1,
      followOn!,
    ]);
    const gaps = warnings.filter((w) => w.kind === 'chainGap');
    expect(gaps).toHaveLength(1);
    expect(gaps[0].requirementId).toBe('SV-001');
    const sv1Diff = (comparison['requirementDiffs'] as RequirementDiff[]).find((d) => d.id === 'SV-001');
    expect(sv1Diff?.state).toBe('regressed');
  });

  it('folds an empty batch to an empty valid comparison', async () => {
    const seedJson = load('scan-before.json');
    const { comparison, warnings } = await foldChangeEventsIntoComparison(seedJson, []);
    expect(warnings).toEqual([]);
    expect(comparison['requirementDiffs']).toEqual([]);
    const validation = validateComparison(comparison);
    expect(validation.valid, JSON.stringify(validation.errors)).toBe(true);
  });
});

describe('foldChangeEventsIntoComparison defensive edges', () => {
  const MINI_SEED = JSON.stringify({
    timestamp: '2026-07-01T00:00:00Z',
    baselines: [
      { name: 'a', requirements: [{ id: 'R1', impact: 0.5, tags: {}, descriptions: [{ label: 'default', data: 'd' }], results: [{ status: 'failed', codeDesc: 't', startTime: '2025-01-01T00:00:00Z' }] }] },
    ],
  });

  function rawEvent(overrides: Req): Req {
    return {
      eventId: '0190f6f2-0000-7000-8000-000000000601',
      source: 'inspec://edge/scan',
      sequence: 601,
      systemRef: 'edge.hdf-system.json',
      componentId: '6e0f2a3b-9c01-4d5e-8f7a-1b2c3d4e5f60',
      requirementId: 'R-EDGE',
      timestamp: '2026-07-02T00:00:00Z',
      priorChecksum: null,
      state: 'new',
      before: null,
      after: {
        id: 'R-EDGE', impact: 0.5, tags: {},
        descriptions: [{ label: 'default', data: 'd' }],
        results: [{ status: 'passed', codeDesc: 't', startTime: '2026-07-02T00:00:00Z' }],
      },
      ...overrides,
    };
  }

  it('warns absentUnknown and emits no entry for an unknown tombstone', async () => {
    const { comparison, warnings } = await foldChangeEventsIntoComparison(MINI_SEED, [
      rawEvent({ state: 'absent', after: null, before: { effectiveStatus: 'failed', effectiveImpact: 0.5 } }),
    ]);
    expect(warnings).toHaveLength(1);
    expect(warnings[0].kind).toBe('absentUnknown');
    expect(comparison['requirementDiffs']).toEqual([]);
  });

  it('coerces an unknown-key content chain to new with a chainGap warning', async () => {
    const { comparison, warnings } = await foldChangeEventsIntoComparison(MINI_SEED, [
      rawEvent({ state: 'regressed', before: { effectiveStatus: 'passed', effectiveImpact: 0.5 }, priorChecksum: { algorithm: 'sha256', value: 'deadbeef' } }),
    ]);
    expect(warnings).toHaveLength(1);
    expect(warnings[0].kind).toBe('chainGap');
    const diffs = comparison['requirementDiffs'] as RequirementDiff[];
    expect(diffs).toHaveLength(1);
    expect(diffs[0].state).toBe('new');
    expect(diffs[0].before).toBeNull();
  });

  it('warns chainGap when the winning event carries no after payload', async () => {
    const { warnings } = await foldChangeEventsIntoComparison(MINI_SEED, [
      rawEvent({ requirementId: 'R1', state: 'updated', after: null, before: { effectiveStatus: 'failed', effectiveImpact: 0.5 } }),
    ]);
    expect(warnings.some((w) => w.kind === 'chainGap')).toBe(true);
  });

  it('emits an absent diff for a known tombstone', async () => {
    const { comparison, warnings } = await foldChangeEventsIntoComparison(MINI_SEED, [
      rawEvent({ requirementId: 'R1', state: 'absent', after: null, before: { effectiveStatus: 'failed', effectiveImpact: 0.5 }, priorChecksum: { algorithm: 'sha256', value: '704f62b2d0803438ad6b7b9bab45e2c4f350b7344135a2a7f8ef986d98669021' } }),
    ]);
    const diffs = comparison['requirementDiffs'] as RequirementDiff[];
    expect(diffs).toHaveLength(1);
    expect(diffs[0].state).toBe('absent');
    expect(diffs[0].after).toBeNull();
    expect(warnings.filter((w) => w.kind !== 'chainGap')).toEqual([]);
  });

  it('throws when the comparison timestamp is underivable', async () => {
    await expect(foldChangeEventsIntoComparison(JSON.stringify({ baselines: [] }), [])).rejects.toThrow(
      /cannot derive/,
    );
  });
});

describe('foldChangeEventsIntoComparison — timestamp-less seed', () => {
  // Deliberately-past waiver: active at the 2024 event occurrence, expired
  // by any later wall clock — so a wall-clock expiry anchor is observable
  // as a wrong seed-side status. Go parity:
  // TestFoldChangeEvents_TimestampLessSeedAnchorsToEventOccurrence.
  const refTs = '2024-02-01T00:00:00Z';

  function timestampLessSeed(): { seedJson: string; seedReq: Req } {
    const doc = JSON.parse(load('scan-before.json')) as Req;
    delete doc['timestamp'];
    const seedReq = requirementsOf(doc).find((r) => r['id'] === 'SV-001');
    if (!seedReq) throw new Error('fixture missing SV-001');
    seedReq['statusOverrides'] = [
      {
        type: 'waiver',
        status: 'passed',
        reason: 'accepted pending redesign',
        appliedBy: { type: 'simple', identifier: 'admin' },
        appliedAt: '2024-01-01T00:00:00Z',
        expiresAt: '2025-06-01T00:00:00Z',
      },
    ];
    return { seedJson: JSON.stringify(doc), seedReq };
  }

  const inputs = {
    eventId: '0190f6f2-0000-7000-8000-000000000099',
    source: 'inspec://fixture/scan',
    sequence: 1,
    systemRef: 'fixture.hdf-system.json',
    componentId: '6e0f2a3b-9c01-4d5e-8f7a-1b2c3d4e5f60',
    requirementId: 'SV-001',
    timestamp: refTs,
    referenceTimestamp: refTs,
    prevReferenceTimestamp: refTs,
  };

  async function seedState(seedReq: Req): Promise<KeyState> {
    const state = {
      effectiveStatus: computeEffectiveStatus(seedReq, refTs),
      effectiveImpact: computeEffectiveImpact(seedReq, refTs),
      checksum: await computeEffectiveChecksum(seedReq, refTs),
    };
    expect(state.effectiveStatus, 'waiver must be active at the event occurrence').toBe('passed');
    return state;
  }

  it('absent branch anchors the seed-side status to the event occurrence', async () => {
    const { seedJson, seedReq } = timestampLessSeed();
    const ev = await changeEventFromPrevious(await seedState(seedReq), null, seedReq, inputs);
    expect(ev).not.toBeNull();

    const result = await foldChangeEventsIntoComparison(seedJson, [ev as Req]);
    expect(result.warnings).toEqual([]);
    const diffs = result.comparison['requirementDiffs'] as Req[];
    expect(diffs).toHaveLength(1);
    expect(diffs[0]?.['oldEffectiveStatus'], 'expiry must anchor to the event occurrence, never the wall clock').toBe('passed');
  });

  it('content branch anchors the seed-side status to the event occurrence', async () => {
    const { seedJson, seedReq } = timestampLessSeed();
    const next = { ...seedReq, impact: 0.6 };
    const ev = await changeEventFromPrevious(await seedState(seedReq), next, seedReq, inputs);
    expect(ev).not.toBeNull();
    expect((ev as Req)['state']).toBe('updated');

    const result = await foldChangeEventsIntoComparison(seedJson, [ev as Req]);
    const diffs = result.comparison['requirementDiffs'] as Req[];
    expect(diffs).toHaveLength(1);
    expect(diffs[0]?.['oldEffectiveStatus'], 'expiry must anchor to the event occurrence, never the wall clock').toBe('passed');
  });
});
