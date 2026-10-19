import { describe, it, expect, afterEach, vi } from 'vitest';
import crosswalkAsset from '../src/data/nist-revision-crosswalk.json';
import {
  translateNistControl,
  translateNistControls,
  nistRosterSize,
} from '../src/nist/index.js';

describe('crosswalk asset validation', () => {
  afterEach(() => {
    vi.doUnmock('../src/data/nist-revision-crosswalk.json');
    vi.resetModules();
  });

  const withoutRosters = structuredClone(crosswalkAsset);
  Reflect.deleteProperty(withoutRosters, 'rosters');
  const withoutEdges = structuredClone(crosswalkAsset);
  Reflect.deleteProperty(withoutEdges, 'edges');
  const edge = crosswalkAsset.edges[0];
  const cases: { name: string; asset: unknown }[] = [
    { name: 'root is null', asset: null },
    { name: 'root is an array', asset: [] },
    { name: 'rosters is an array', asset: { ...crosswalkAsset, rosters: [] } },
    { name: 'rosters is null', asset: { ...crosswalkAsset, rosters: null } },
    { name: 'rosters is missing', asset: withoutRosters },
    { name: 'roster is a string', asset: { ...crosswalkAsset, rosters: { '4': 'AC-1' } } },
    { name: 'roster is null', asset: { ...crosswalkAsset, rosters: { '4': null } } },
    { name: 'roster is an object', asset: { ...crosswalkAsset, rosters: { '4': {} } } },
    { name: 'roster contains a number', asset: { ...crosswalkAsset, rosters: { '4': [1] } } },
    { name: 'roster contains null', asset: { ...crosswalkAsset, rosters: { '4': [null] } } },
    { name: 'edges is an object', asset: { ...crosswalkAsset, edges: {} } },
    { name: 'edges is a string', asset: { ...crosswalkAsset, edges: '' } },
    { name: 'edges is null', asset: { ...crosswalkAsset, edges: null } },
    { name: 'edges is missing', asset: withoutEdges },
    { name: 'edge is a number', asset: { ...crosswalkAsset, edges: [1] } },
    { name: 'edge is null', asset: { ...crosswalkAsset, edges: [null] } },
    { name: 'edge is an array', asset: { ...crosswalkAsset, edges: [[]] } },
    { name: 'from is a string', asset: { ...crosswalkAsset, edges: [{ ...edge, from: '4' }] } },
    { name: 'from is fractional', asset: { ...crosswalkAsset, edges: [{ ...edge, from: 4.5 }] } },
    { name: 'from is not a safe integer', asset: { ...crosswalkAsset, edges: [{ ...edge, from: 1e20 }] } },
    { name: 'control is a number', asset: { ...crosswalkAsset, edges: [{ ...edge, control: 1 }] } },
    { name: 'targets is a string', asset: { ...crosswalkAsset, edges: [{ ...edge, targets: 'AC-1' }] } },
    { name: 'targets is null', asset: { ...crosswalkAsset, edges: [{ ...edge, targets: null }] } },
    { name: 'targets contains a number', asset: { ...crosswalkAsset, edges: [{ ...edge, targets: [1] }] } },
    { name: 'targets contains null', asset: { ...crosswalkAsset, edges: [{ ...edge, targets: [null] }] } },
    { name: 'relation is a number', asset: { ...crosswalkAsset, edges: [{ ...edge, relation: 1 }] } },
    { name: 'detail is a number', asset: { ...crosswalkAsset, edges: [{ ...edge, detail: 1 }] } },
    { name: 'family is a number', asset: { ...crosswalkAsset, edges: [{ ...edge, family: 1 }] } },
    { name: 'family is null', asset: { ...crosswalkAsset, edges: [{ ...edge, family: null }] } },
  ];

  for (const field of ['from', 'control', 'targets', 'relation', 'detail']) {
    const incompleteEdge = structuredClone(edge);
    Reflect.deleteProperty(incompleteEdge, field);
    cases.push({
      name: `${field} is missing`,
      asset: { ...crosswalkAsset, edges: [incompleteEdge] },
    });
  }

  it.each(cases)('refuses $name with an asset-naming error', async ({ asset }) => {
    vi.resetModules();
    vi.doMock('../src/data/nist-revision-crosswalk.json', () => ({ default: asset }));
    await expect(import('../src/nist/crosswalk.js')).rejects.toThrow('nist-revision-crosswalk.json');
  });
});

describe('translateNistControl', () => {
  it('returns identity for controls present in both revisions', () => {
    for (const id of ['AC-1', 'AC-2', 'IA-2(1)', 'SC-7(5)']) {
      const tr = translateNistControl(id, 4, 5);
      expect(tr.relation).toBe('identity');
      expect(tr.targets).toEqual([id]);
    }
    const back = translateNistControl('AC-1', 5, 4);
    expect(back.relation).toBe('identity');
    expect(back.targets).toEqual(['AC-1']);
  });

  it('follows moved controls to their Rev 5 location', () => {
    const tr = translateNistControl('IR-10', 4, 5);
    expect(tr.relation).toBe('moved');
    expect(tr.targets).toEqual(['IR-4(11)']);
  });

  it('follows incorporated controls', () => {
    const tr = translateNistControl('IA-2(11)', 4, 5);
    expect(tr.relation).toBe('incorporated');
    expect(tr.targets).toEqual(['IA-2(6)']);
  });

  it('handles multi-target redirects', () => {
    expect(translateNistControl('SA-12(14)', 4, 5).targets).toEqual(['SR-4(1)', 'SR-4(2)']);
    expect(translateNistControl('IA-5(11)', 4, 5).targets).toEqual(['IA-2(1)', 'IA-2(2)']);
  });

  it('normalizes statement-part targets to the base control, keeping raw text in detail', () => {
    const tr = translateNistControl('AC-2(10)', 4, 5);
    expect(tr.targets).toEqual(['AC-2']);
    expect(tr.detail).toBeTruthy();
  });

  it('reports withdrawn-without-successor as none', () => {
    const tr = translateNistControl('SC-19', 4, 5);
    expect(tr.relation).toBe('none');
    expect(tr.targets).toEqual([]);
  });

  it('keeps family-level incorporation as a marker, never expanded', () => {
    const tr = translateNistControl('SA-12', 4, 5);
    expect(tr.relation).toBe('family');
    expect(tr.targets).toEqual([]);
    expect(tr.family).toBe('SR');
  });

  it('maps Appendix J privacy controls as pointers', () => {
    const tr = translateNistControl('AP-1', 4, 5);
    expect(tr.relation).toBe('pointer');
    expect(tr.targets).toEqual(['PT-2']);

    const ar7 = translateNistControl('AR-7', 4, 5);
    expect(ar7.relation).toBe('none');
    expect(ar7.targets).toEqual([]);
  });

  it('reports new-in-Rev5 controls as none when translating to Rev 4', () => {
    const tr = translateNistControl('AC-3(15)', 5, 4);
    expect(tr.relation).toBe('none');
    expect(tr.targets).toEqual([]);
  });

  it('derives Rev5-to-Rev4 origins from inverted moved edges', () => {
    const tr = translateNistControl('SR-5', 5, 4);
    expect(tr.relation).toBe('moved');
    expect(tr.targets).toEqual(['SA-12(1)']);
  });

  it('redirects controls already withdrawn in Rev 4 from either direction', () => {
    for (const [from, to] of [
      [4, 5],
      [5, 4],
    ] as const) {
      const tr = translateNistControl('AC-13', from, to);
      expect(tr.relation).toBe('incorporated');
      expect(tr.targets).toEqual(['AC-2', 'AU-6']);
    }
  });

  it('reports unknown controls and unsupported revisions as unknown', () => {
    expect(translateNistControl('ZZ-99', 4, 5).relation).toBe('unknown');
    expect(translateNistControl('', 4, 5).relation).toBe('unknown');
    expect(translateNistControl('AC-1', 4, 6).relation).toBe('unknown');
    expect(translateNistControl('AC-1', 3, 5).relation).toBe('unknown');
    expect(translateNistControl('AC-1', 4, 4).relation).toBe('identity');
  });

  it('passes statement-letter tags through on identity, drops them on redirect', () => {
    const same = translateNistControl('AC-2(j)', 4, 5);
    expect(same.relation).toBe('identity');
    expect(same.targets).toEqual(['AC-2(j)']);

    const moved = translateNistControl('IR-10(a)', 4, 5);
    expect(moved.targets).toEqual(['IR-4(11)']);
  });
});

describe('translateNistControls', () => {
  it('splits results into translated tags and unmapped entries', () => {
    const { translated, unmapped } = translateNistControls(
      ['AC-1', 'IR-10', 'SC-19', 'AC-3(15)'],
      4,
      5
    );
    expect(translated).toEqual(['AC-1', 'IR-4(11)']);
    expect(unmapped).toHaveLength(2);
    expect(unmapped[0]).toMatchObject({ control: 'SC-19', relation: 'none' });
    expect(unmapped[1]).toMatchObject({ control: 'AC-3(15)', relation: 'unknown' });
  });

  it('dedups convergent targets', () => {
    const { translated, unmapped } = translateNistControls(['IA-2(7)', 'IA-2(11)'], 4, 5);
    expect(translated).toEqual(['IA-2(6)']);
    expect(unmapped).toEqual([]);
  });
});

describe('nistRosterSize', () => {
  it('covers the full control universe at each revision', () => {
    expect(nistRosterSize(5)).toBeGreaterThanOrEqual(1000);
    expect(nistRosterSize(4)).toBeGreaterThanOrEqual(850);
    expect(nistRosterSize(6)).toBe(0);
  });
});
