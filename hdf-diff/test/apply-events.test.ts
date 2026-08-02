import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { validateResults } from '@mitre/hdf-validators';
import { changeEventFromPrevious, type KeyState } from '../src/change-event.js';
import { computeEffectiveChecksum, computeEffectiveImpact } from '../src/effective-checksum.js';
import { computeEffectiveStatus } from '../src/status.js';
import { applyChangeEvents, type ApplyInputs } from '../src/apply-events.js';

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), 'fixtures');

function loadFixture(name: string): string {
  return readFileSync(join(FIXTURES, name), 'utf-8');
}

function applyInputs(): ApplyInputs {
  return {
    generator: { name: 'conmon-reconciler-test', version: '0.0.1' },
    seedUri: 'seed.hdf.json',
    source: 'inspec://fixture/scan',
  };
}

type Req = Record<string, unknown>;

function requirementsOf(doc: Record<string, unknown>): Req[] {
  const baselines = (doc['baselines'] as Record<string, unknown>[] | undefined) ?? [];
  return baselines.flatMap((b) => (b['requirements'] as Req[] | undefined) ?? []);
}

/** Derive the event stream between two same-target docs via the real kernel. */
async function deriveStream(seedJson: string, nextJson: string): Promise<Req[]> {
  const seedDoc = JSON.parse(seedJson) as Record<string, unknown>;
  const nextDoc = JSON.parse(nextJson) as Record<string, unknown>;
  const refTs = (nextDoc['timestamp'] as string | undefined) ?? '2026-07-22T14:03:11Z';

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
    timestamp: '2026-07-22T14:03:11Z',
    referenceTimestamp: refTs,
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

function maskVolatile(req: Req): void {
  for (const r of (req['results'] as Req[] | undefined) ?? []) {
    delete r['startTime'];
    delete r['runTime'];
  }
}

async function parityCheck(seedName: string, nextName: string): Promise<void> {
  const seedJson = loadFixture(seedName);
  const nextJson = loadFixture(nextName);
  const events = await deriveStream(seedJson, nextJson);
  const changed = new Set(events.map((e) => e['requirementId'] as string));

  const { results, warnings } = await applyChangeEvents(seedJson, events, applyInputs());
  expect(warnings, 'a complete derived stream must verify cleanly').toEqual([]);

  const got = new Map(requirementsOf(results).map((r) => [r['id'] as string, r]));
  const want = new Map(
    requirementsOf(JSON.parse(nextJson) as Record<string, unknown>).map((r) => [r['id'] as string, r]),
  );
  expect(got.size).toBe(want.size);
  for (const [id, wantReq] of want) {
    const gotReq = got.get(id);
    expect(gotReq, `requirement ${id} missing from reassembled doc`).toBeDefined();
    const w = structuredClone(wantReq);
    const g = structuredClone(gotReq!);
    if (!changed.has(id)) {
      maskVolatile(w);
      maskVolatile(g);
    }
    expect(g, `requirement ${id} must match the rescan content`).toEqual(w);
  }

  const validation = validateResults(results);
  expect(validation.valid, JSON.stringify(validation.errors)).toBe(true);
}

describe('applyChangeEvents', () => {
  it('satisfies the reassembly-parity law on the scan pair', async () => {
    await parityCheck('scan-before.json', 'scan-after.json');
  });

  it('satisfies the reassembly-parity law on the override pair', async () => {
    await parityCheck('scan-before.json', 'scan-with-override.json');
  });

  it('is idempotent under duplicate delivery', async () => {
    const seedJson = loadFixture('scan-before.json');
    const events = await deriveStream(seedJson, loadFixture('scan-after.json'));
    const once = await applyChangeEvents(seedJson, events, applyInputs());
    const twice = await applyChangeEvents(seedJson, [...events, ...events], applyInputs());
    expect(twice.results).toEqual(once.results);
  });

  it('is invariant under delivery order', async () => {
    const seedJson = loadFixture('scan-before.json');
    const events = await deriveStream(seedJson, loadFixture('scan-after.json'));
    const inOrder = await applyChangeEvents(seedJson, events, applyInputs());
    const reversed = await applyChangeEvents(seedJson, [...events].reverse(), applyInputs());
    expect(reversed.results).toEqual(inOrder.results);
  });

  it('detects a chain gap but still applies last-value-wins', async () => {
    const seedJson = loadFixture('scan-before.json');
    const events = await deriveStream(seedJson, loadFixture('scan-after.json'));
    // Drop the fixed-transition event for SV-001, then send a later crafted
    // event for the same key whose prior links to the dropped posture.
    const sv1 = events.find((e) => e['requirementId'] === 'SV-001')!;
    const rest = events.filter((e) => e['requirementId'] !== 'SV-001');
    const after = sv1['after'] as Req;
    const followOn = await changeEventFromPrevious(
      {
        effectiveStatus: 'passed',
        effectiveImpact: 0.7,
        checksum: await computeEffectiveChecksum(after, '2026-07-22T14:03:11Z'),
      },
      { ...after, results: [{ status: 'failed', codeDesc: 'regressed again', startTime: '2026-07-23T00:00:00Z' }] },
      after,
      {
        eventId: '0190f6f2-0000-7000-8000-000000000099',
        source: 'inspec://fixture/scan',
        sequence: 99,
        systemRef: 'fixture.hdf-system.json',
        componentId: '6e0f2a3b-9c01-4d5e-8f7a-1b2c3d4e5f60',
        requirementId: 'SV-001',
        timestamp: '2026-07-23T00:00:00Z',
        referenceTimestamp: '2026-07-23T00:00:00Z',
      },
    );
    const { warnings } = await applyChangeEvents(seedJson, [...rest, followOn!], applyInputs());
    const gap = warnings.filter((w) => w.kind === 'chainGap');
    expect(gap).toHaveLength(1);
    expect(gap[0].requirementId).toBe('SV-001');
  });

  it('warns absentUnknown for a tombstone on an unknown key', async () => {
    const seedJson = loadFixture('scan-before.json');
    const ghost = await changeEventFromPrevious(
      {
        effectiveStatus: 'failed',
        effectiveImpact: 0.5,
        checksum: {
          algorithm: 'sha256',
          value: '704f62b2d0803438ad6b7b9bab45e2c4f350b7344135a2a7f8ef986d98669021',
        },
      },
      null,
      null,
      {
        eventId: '0190f6f2-0000-7000-8000-000000000777',
        source: 'inspec://fixture/scan',
        sequence: 7,
        systemRef: 'fixture.hdf-system.json',
        componentId: '6e0f2a3b-9c01-4d5e-8f7a-1b2c3d4e5f60',
        requirementId: 'SV-999999',
        timestamp: '2026-07-22T14:03:11Z',
        referenceTimestamp: '2026-07-22T14:03:11Z',
      },
    );
    const { warnings } = await applyChangeEvents(seedJson, [ghost!], applyInputs());
    expect(warnings).toHaveLength(1);
    expect(warnings[0].kind).toBe('absentUnknown');
  });

  it('passes the seed through with lineage on an empty batch', async () => {
    const seedJson = loadFixture('scan-before.json');
    const { results, warnings } = await applyChangeEvents(seedJson, [], applyInputs());
    expect(warnings).toEqual([]);
    const derivation = results['derivation'] as Req;
    expect(derivation['eventsApplied']).toBe(0);
    expect(derivation['throughSequence']).toBe(0);
    expect(typeof derivation['asOf']).toBe('string');
    const seedRef = derivation['seed'] as Req;
    expect(seedRef['uri']).toBe('seed.hdf.json');
    expect((seedRef['checksum'] as Req)['algorithm']).toBe('sha256');
    expect((results['generator'] as Req)['name']).toBe('conmon-reconciler-test');
  });
});

describe('applyChangeEvents defensive edges', () => {
  const MINI_SEED = JSON.stringify({
    timestamp: '2026-07-01T00:00:00Z',
    baselines: [
      { name: 'a', requirements: [{ id: 'R1', impact: 0.5, tags: {}, descriptions: [{ label: 'default', data: 'd' }], results: [{ status: 'failed', codeDesc: 't', startTime: '2025-01-01T00:00:00Z' }] }] },
      { name: 'b', requirements: [] },
    ],
  });

  function rawEvent(overrides: Record<string, unknown>): Record<string, unknown> {
    return {
      eventId: '0190f6f2-0000-7000-8000-000000000501',
      source: 'inspec://edge/scan',
      sequence: 501,
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

  it('warns multiBaseline when inserting a new key into a multi-baseline seed', async () => {
    const { warnings, results } = await applyChangeEvents(MINI_SEED, [rawEvent({})], applyInputs());
    expect(warnings.some((w) => w.kind === 'multiBaseline')).toBe(true);
    const first = (results['baselines'] as Req[])[0];
    expect((first['requirements'] as Req[]).some((r) => r['id'] === 'R-EDGE')).toBe(true);
  });

  it('throws when a new key arrives and the seed has no baselines', async () => {
    const seed = JSON.stringify({ timestamp: '2026-07-01T00:00:00Z', baselines: [] });
    await expect(applyChangeEvents(seed, [rawEvent({})], applyInputs())).rejects.toThrow(
      /no baselines/,
    );
  });

  it('throws when asOf is underivable (no events, no seed timestamp)', async () => {
    const seed = JSON.stringify({ baselines: [] });
    await expect(applyChangeEvents(seed, [], applyInputs())).rejects.toThrow(/cannot derive asOf/);
  });

  it('falls back to the seed timestamp for asOf when an event timestamp is unparseable', async () => {
    // A malformed event timestamp → parseTimestamp returns null → asOf is not
    // taken from the event; it falls back to the seed document's timestamp.
    const { results } = await applyChangeEvents(
      MINI_SEED,
      [rawEvent({ timestamp: 'not-a-date' })],
      applyInputs(),
    );
    const derivation = results['derivation'] as Record<string, unknown>;
    expect(derivation['asOf']).toBe('2026-07-01T00:00:00Z');
  });

  it('re-renders an offset-bearing event timestamp as trimmed UTC in asOf (Go parity)', async () => {
    // Go emits maxOccurred.UTC().Format(RFC3339Nano); a verbatim offset
    // string would diverge byte-wise between the two implementations.
    const { results } = await applyChangeEvents(
      MINI_SEED,
      [rawEvent({ timestamp: '2026-07-02T05:00:00+02:00' })],
      applyInputs(),
    );
    const derivation = results['derivation'] as Record<string, unknown>;
    expect(derivation['asOf']).toBe('2026-07-02T03:00:00Z');
    expect(results['timestamp']).toBe('2026-07-02T03:00:00Z');
  });

  it('warns chainGap on a content-bearing chain for a key the seed does not carry', async () => {
    const { warnings } = await applyChangeEvents(
      MINI_SEED,
      [rawEvent({ state: 'updated', before: { effectiveStatus: 'failed', effectiveImpact: 0.5 }, priorChecksum: { algorithm: 'sha256', value: 'deadbeef' } })],
      applyInputs(),
    );
    const gaps = warnings.filter((w) => w.kind === 'chainGap');
    expect(gaps).toHaveLength(1);
    expect(gaps[0].requirementId).toBe('R-EDGE');
    // The two-baseline seed also legitimately warns multiBaseline on insertion.
    expect(warnings.some((w) => w.kind === 'multiBaseline')).toBe(true);
  });

  it('warns chainGap when the winning event carries no after payload', async () => {
    const { warnings } = await applyChangeEvents(
      MINI_SEED,
      [rawEvent({ requirementId: 'R1', state: 'updated', after: null, before: { effectiveStatus: 'failed', effectiveImpact: 0.5 } })],
      applyInputs(),
    );
    expect(warnings.some((w) => w.kind === 'chainGap')).toBe(true);
  });
});
