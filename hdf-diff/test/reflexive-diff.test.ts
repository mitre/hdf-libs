import { describe, it, expect } from 'vitest';
import { results } from '@mitre/hdf-fixtures';
import { diffHdf } from '../src/diff.js';

/** A comparison is reflexive: a document compared with an identical copy reports no
 * change. It was not, wherever an id sat in more than one baseline, because the baselines
 * were pooled before matching. Go peer: go/reflexive_diff_test.go. */

const cases: { name: string; read: () => string; why: string }[] = [
  {
    name: 'inspec-multilayered',
    read: () => results.inspecMultilayered.read(),
    why: '5 baselines, 533 ids carried by three of them: 1603 new and 1603 absent',
  },
  {
    name: 'duplicate-baselines',
    read: () => results.duplicateBaselines.read(),
    why: '16 baselines, all sharing one name: 53 and 53',
  },
  {
    name: 'merge-grype',
    read: () => results.mergeGrype.read(),
    why: 'one baseline with genuinely repeated ids: 6 and 6',
  },
  {
    name: 'merge-zap',
    read: () => results.mergeZap.read(),
    why: 'no repeated id within any baseline, but 4 baselines share ids across them: 3 and 3',
  },
  {
    name: 'minimal',
    read: () => results.minimal.read(),
    why: 'a single requirement, already reflexive — kept as a regression guard',
  },
];

describe('diffHdf is reflexive on every shared results fixture', () => {
  for (const tc of cases) {
    it(tc.name, () => {
      const doc = JSON.parse(tc.read()) as Record<string, unknown>;

      const comparison = diffHdf(doc, doc);

      expect(comparison.summary.new, tc.why).toBe(0);
      expect(comparison.summary.absent, tc.why).toBe(0);
      expect(comparison.summary.fixed, tc.why).toBe(0);
      expect(comparison.summary.regressed, tc.why).toBe(0);
      expect(comparison.summary.updated, tc.why).toBe(0);
      for (const d of comparison.requirementDiffs) {
        expect(d.state, `${d.id} in ${d.baseline ?? '(none)'}: ${tc.why}`).toBe('unchanged');
      }
    });
  }
});

describe('a change is reported against its own baseline', () => {
  const requirement = (id: string, status: string) => ({
    id,
    impact: 0.7,
    results: [{ status, codeDesc: 'test', startTime: '2024-01-01T00:00:00Z' }],
  });
  const doc = (overlayStatus: string, baseStatus: string) => ({
    baselines: [
      { name: 'overlay', version: '1.0.0', requirements: [requirement('SV-001', overlayStatus)] },
      { name: 'base', version: '1.0.0', requirements: [requirement('SV-001', baseStatus)] },
    ],
  });

  it('names the layer that changed and leaves the other unchanged', () => {
    const comparison = diffHdf(doc('failed', 'failed'), doc('passed', 'failed'));

    const byBaseline = new Map(comparison.requirementDiffs.map((d) => [d.baseline, d.state]));
    expect(byBaseline.get('overlay')).toBe('fixed');
    expect(byBaseline.get('base')).toBe('unchanged');
  });

  it('reports one diff per baseline for an id both carry, and neither as the sentinel', () => {
    const same = doc('failed', 'failed');

    const comparison = diffHdf(same, same);

    expect(comparison.requirementDiffs).toHaveLength(2);
    expect(new Set(comparison.requirementDiffs.map((d) => d.baseline))).toEqual(
      new Set(['overlay', 'base']),
    );
  });
});

describe('ties on id keep the pairing order', () => {
  it('emits one diff per baseline carrying the id, in pairing order', () => {
    const doc = JSON.parse(results.inspecMultilayered.read()) as Record<string, unknown>;

    const comparison = diffHdf(doc, doc);

    // Ties on id are routine now, so both languages sort stably and emit this same order.
    // The Go peer asserts the identical sequence.
    expect(
      comparison.requirementDiffs.filter((d) => d.id === 'SV-257777').map((d) => d.baseline),
    ).toEqual([
      'metawrapper',
      'metawrapper',
      'wrapper',
      'wrapper',
      'redhat-enterprise-linux-9-stig-baseline',
    ]);
  });
});

describe('baseline pairing edge cases', () => {
  const requirement = (id: string) => ({
    id,
    impact: 0.7,
    results: [{ status: 'failed', codeDesc: 'test', startTime: '2024-01-01T00:00:00Z' }],
  });
  const baseline = (name: string, ids: string[]) => ({
    name,
    version: '1.0.0',
    requirements: ids.map(requirement),
  });

  it('gathers two baselines sharing a name as one', () => {
    const split = { baselines: [baseline('same', ['SV-001']), baseline('same', ['SV-002'])] };
    const merged = { baselines: [baseline('same', ['SV-001', 'SV-002'])] };

    const comparison = diffHdf(split, merged);

    expect(comparison.requirementDiffs).toHaveLength(2);
    for (const d of comparison.requirementDiffs) {
      expect(d.state, d.id).toBe('unchanged');
    }
  });

  it('reports a requirement that moved between baselines as absent and new', () => {
    // It is compared within its baseline and has no counterpart there. The reserved
    // `moved` state is never emitted, so the output cannot say more than this.
    const before = {
      baselines: [baseline('alpha', ['SV-STAY', 'SV-MOVER']), baseline('beta', ['SV-OTHER'])],
    };
    const after = {
      baselines: [baseline('alpha', ['SV-STAY']), baseline('beta', ['SV-OTHER', 'SV-MOVER'])],
    };

    const comparison = diffHdf(before, after);

    const mover = comparison.requirementDiffs.filter((d) => d.id === 'SV-MOVER');
    expect(mover.map((d) => d.state).sort()).toEqual(['absent', 'new']);
    expect(mover.map((d) => d.baseline).sort()).toEqual(['alpha', 'beta']);
    expect(comparison.requirementDiffs.filter((d) => d.state === 'unchanged')).toHaveLength(2);
  });
});
