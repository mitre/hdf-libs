import { describe, it, expect } from 'vitest';
import { flattenOverlays } from './flatten.js';
import { inspec } from '@mitre/hdf-fixtures';
import type { HDFResults, EvaluatedBaseline, EvaluatedRequirement } from '@mitre/hdf-schema';
import { readFileSync } from 'node:fs';

// ── Helpers ──────────────────────────────────────────────────

function makeReq(
  id: string,
  overrides: Partial<EvaluatedRequirement> = {}
): EvaluatedRequirement {
  return {
    id,
    impact: 0.5,
    tags: {},
    results: [],
    descriptions: [{ label: 'default', data: `Requirement ${id}` }],
    ...overrides,
  };
}

function makeBaseline(
  name: string,
  requirements: EvaluatedRequirement[],
  overrides: Partial<EvaluatedBaseline> = {}
): EvaluatedBaseline {
  return { name, requirements, ...overrides };
}

function makeResults(baselines: EvaluatedBaseline[]): HDFResults {
  return { baselines };
}

// ── Passthrough ─────────────────────────────────────────────

describe('flattenOverlays', () => {
  describe('passthrough (no overlays)', () => {
    it('returns unchanged results for single baseline', () => {
      const results = makeResults([
        makeBaseline('single', [makeReq('V-1'), makeReq('V-2')]),
      ]);
      const { results: flat, metadata } = flattenOverlays(results);
      expect(flat.baselines).toHaveLength(1);
      expect(flat.baselines[0].name).toBe('single');
      expect(flat.baselines[0].requirements).toHaveLength(2);
      expect(metadata.merges).toHaveLength(0);
      expect(metadata.originalBaselineCount).toBe(1);
      expect(metadata.flattenedBaselineCount).toBe(1);
    });

    it('returns unchanged results for multiple independent baselines', () => {
      const results = makeResults([
        makeBaseline('alpha', [makeReq('A-1')]),
        makeBaseline('beta', [makeReq('B-1')]),
      ]);
      const { results: flat, metadata } = flattenOverlays(results);
      expect(flat.baselines).toHaveLength(2);
      expect(metadata.merges).toHaveLength(0);
    });

    it('metadata shows 0 merges, no warnings', () => {
      const results = makeResults([makeBaseline('only', [makeReq('V-1')])]);
      const { metadata } = flattenOverlays(results);
      expect(metadata.originalBaselineCount).toBe(1);
      expect(metadata.flattenedBaselineCount).toBe(1);
      expect(metadata.merges).toEqual([]);
      expect(metadata.warnings).toEqual([]);
    });
  });

  // ── Deep nesting (overlay chain) ──────────────────────────

  describe('deep nesting — two-layer overlay', () => {
    function makeTwoLayer() {
      return makeResults([
        makeBaseline('my-overlay', [
          makeReq('V-1', { code: 'overlay code V1', results: [], tags: { cci: ['CCI-001'] } }),
          makeReq('V-2', { code: '', results: [], tags: { cci: ['CCI-002'] } }),
        ]),
        makeBaseline('my-base', [
          makeReq('V-1', { code: 'base code V1', results: [{ status: 'passed', codeDesc: 'test' }], tags: { cci: ['CCI-001'] } }),
          makeReq('V-2', { code: 'base code V2', results: [{ status: 'failed', codeDesc: 'test' }], tags: { cci: ['CCI-002'] } }),
          makeReq('V-3', { code: 'base only', results: [{ status: 'passed', codeDesc: 'test' }] }),
        ], { parentBaseline: 'my-overlay' }),
      ]);
    }

    it('deduplicates to one baseline named after the root', () => {
      const { results: flat } = flattenOverlays(makeTwoLayer());
      expect(flat.baselines).toHaveLength(1);
      expect(flat.baselines[0].name).toBe('my-overlay');
    });

    it('preserves base results on merged controls', () => {
      const { results: flat } = flattenOverlays(makeTwoLayer());
      const reqs = flat.baselines[0].requirements;
      expect(reqs.find(r => r.id === 'V-1')!.results[0].status).toBe('passed');
      expect(reqs.find(r => r.id === 'V-2')!.results[0].status).toBe('failed');
    });

    it('takes overlay code when non-empty', () => {
      const { results: flat } = flattenOverlays(makeTwoLayer());
      expect(flat.baselines[0].requirements.find(r => r.id === 'V-1')!.code).toBe('overlay code V1');
    });

    it('keeps base code when overlay code is empty', () => {
      const { results: flat } = flattenOverlays(makeTwoLayer());
      expect(flat.baselines[0].requirements.find(r => r.id === 'V-2')!.code).toBe('base code V2');
    });

    it('preserves controls only in base (inherited)', () => {
      const { results: flat } = flattenOverlays(makeTwoLayer());
      const v3 = flat.baselines[0].requirements.find(r => r.id === 'V-3');
      expect(v3).toBeDefined();
      expect(v3!.code).toBe('base only');
      expect(v3!.results).toHaveLength(1);
    });

    it('adds controls only in overlay (new controls)', () => {
      const results = makeResults([
        makeBaseline('overlay', [makeReq('V-1'), makeReq('NEW-1', { code: 'new' })]),
        makeBaseline('base', [
          makeReq('V-1', { results: [{ status: 'passed', codeDesc: 'test' }] }),
        ], { parentBaseline: 'overlay' }),
      ]);
      const { results: flat } = flattenOverlays(results);
      expect(flat.baselines[0].requirements.map(r => r.id).sort()).toEqual(['NEW-1', 'V-1']);
    });

    it('metadata shows 1 merge with pattern=deep', () => {
      const { metadata } = flattenOverlays(makeTwoLayer());
      expect(metadata.originalBaselineCount).toBe(2);
      expect(metadata.flattenedBaselineCount).toBe(1);
      expect(metadata.merges).toHaveLength(1);
      expect(metadata.merges[0].rootBaseline).toBe('my-overlay');
      expect(metadata.merges[0].absorbedBaselines).toContain('my-base');
      expect(metadata.merges[0].controlsBefore).toBe(5);
      expect(metadata.merges[0].controlsAfter).toBe(3);
      expect(metadata.merges[0].pattern).toBe('deep');
    });

    it('clears parentBaseline and depends on flattened baseline', () => {
      const { results: flat } = flattenOverlays(makeTwoLayer());
      expect(flat.baselines[0].parentBaseline).toBeUndefined();
      expect(flat.baselines[0].depends).toBeUndefined();
    });
  });

  describe('deep nesting — three-layer overlay', () => {
    function makeThreeLayer() {
      return makeResults([
        makeBaseline('top', [
          makeReq('V-1', { code: 'top override', results: [] }),
          makeReq('V-2', { code: '', results: [] }),
        ]),
        makeBaseline('mid', [
          makeReq('V-1', { code: '', results: [] }),
          makeReq('V-2', { code: 'mid override', results: [] }),
        ], { parentBaseline: 'top' }),
        makeBaseline('base', [
          makeReq('V-1', { code: 'base code', results: [{ status: 'passed', codeDesc: 'test' }] }),
          makeReq('V-2', { code: 'base code', results: [{ status: 'failed', codeDesc: 'test' }] }),
        ], { parentBaseline: 'mid' }),
      ]);
    }

    it('deduplicates to one baseline', () => {
      const { results: flat } = flattenOverlays(makeThreeLayer());
      expect(flat.baselines).toHaveLength(1);
      expect(flat.baselines[0].requirements).toHaveLength(2);
    });

    it('topmost non-empty code wins over intermediate and base', () => {
      const { results: flat } = flattenOverlays(makeThreeLayer());
      const reqs = flat.baselines[0].requirements;
      expect(reqs.find(r => r.id === 'V-1')!.code).toBe('top override');
      expect(reqs.find(r => r.id === 'V-2')!.code).toBe('mid override');
    });

    it('base results survive through all layers', () => {
      const { results: flat } = flattenOverlays(makeThreeLayer());
      const reqs = flat.baselines[0].requirements;
      expect(reqs.find(r => r.id === 'V-1')!.results).toHaveLength(1);
      expect(reqs.find(r => r.id === 'V-2')!.results).toHaveLength(1);
    });

    it('metadata lists absorbed baselines in bottom-up order', () => {
      const { metadata } = flattenOverlays(makeThreeLayer());
      expect(metadata.merges[0].absorbedBaselines).toEqual(['base', 'mid']);
    });
  });

  // ── Wide nesting (wrapper) ────────────────────────────────

  describe('wide nesting (wrapper/meta-profile)', () => {
    function makeWide() {
      return makeResults([
        makeBaseline('wrapper', [
          makeReq('K-1', { code: 'wrapper k1' }),
          makeReq('R-1', { code: 'wrapper r1' }),
          makeReq('W-1', { code: 'own', results: [{ status: 'passed', codeDesc: 'own' }] }),
        ]),
        makeBaseline('k8s', [
          makeReq('K-1', { code: 'k8s code', results: [{ status: 'passed', codeDesc: 'k8s' }] }),
        ], { parentBaseline: 'wrapper' }),
        makeBaseline('rhel', [
          makeReq('R-1', { code: 'rhel code', results: [{ status: 'failed', codeDesc: 'rhel' }] }),
        ], { parentBaseline: 'wrapper' }),
      ]);
    }

    it('produces single baseline with all control IDs', () => {
      const { results: flat } = flattenOverlays(makeWide());
      expect(flat.baselines).toHaveLength(1);
      expect(flat.baselines[0].requirements.map(r => r.id).sort()).toEqual(['K-1', 'R-1', 'W-1']);
    });

    it('child results merged into wrapper controls', () => {
      const { results: flat } = flattenOverlays(makeWide());
      const reqs = flat.baselines[0].requirements;
      expect(reqs.find(r => r.id === 'K-1')!.results[0].status).toBe('passed');
      expect(reqs.find(r => r.id === 'R-1')!.results[0].status).toBe('failed');
    });

    it('wrapper own controls preserved', () => {
      const { results: flat } = flattenOverlays(makeWide());
      const w1 = flat.baselines[0].requirements.find(r => r.id === 'W-1');
      expect(w1!.results).toHaveLength(1);
    });

    it('metadata shows pattern=wide', () => {
      const { metadata } = flattenOverlays(makeWide());
      expect(metadata.merges).toHaveLength(1);
      expect(metadata.merges[0].pattern).toBe('wide');
    });
  });

  // ── Hybrid (deep + wide) ─────────────────────────────────

  describe('hybrid (deep + wide)', () => {
    it('handles wrapper with overlay chain child', () => {
      const results = makeResults([
        makeBaseline('wrapper', [makeReq('V-1'), makeReq('K-1')]),
        makeBaseline('overlay', [
          makeReq('V-1', { code: 'overlay code', results: [] }),
        ], { parentBaseline: 'wrapper' }),
        makeBaseline('base', [
          makeReq('V-1', { code: 'base code', results: [{ status: 'passed', codeDesc: 'test' }] }),
        ], { parentBaseline: 'overlay' }),
        makeBaseline('k8s', [
          makeReq('K-1', { results: [{ status: 'failed', codeDesc: 'k8s' }] }),
        ], { parentBaseline: 'wrapper' }),
      ]);

      const { results: flat } = flattenOverlays(results);
      expect(flat.baselines).toHaveLength(1);

      const reqs = flat.baselines[0].requirements;
      expect(reqs.find(r => r.id === 'V-1')!.results).toHaveLength(1);
      expect(reqs.find(r => r.id === 'V-1')!.code).toBe('overlay code');
      expect(reqs.find(r => r.id === 'K-1')!.results[0].status).toBe('failed');
    });
  });

  // ── Merge semantics ───────────────────────────────────────

  describe('merge semantics', () => {
    it('base results preserved when overlay has empty results', () => {
      const results = makeResults([
        makeBaseline('overlay', [makeReq('V-1', { results: [] })]),
        makeBaseline('base', [
          makeReq('V-1', { results: [{ status: 'passed', codeDesc: 'test' }] }),
        ], { parentBaseline: 'overlay' }),
      ]);
      const { results: flat } = flattenOverlays(results);
      expect(flat.baselines[0].requirements[0].results).toHaveLength(1);
    });

    it('tags shallow-merged (incoming keys override)', () => {
      const results = makeResults([
        makeBaseline('overlay', [makeReq('V-1', { tags: { severity: 'high', custom: 'new' } })]),
        makeBaseline('base', [
          makeReq('V-1', { tags: { severity: 'low', nist: ['AC-2'] } }),
        ], { parentBaseline: 'overlay' }),
      ]);
      const { results: flat } = flattenOverlays(results);
      const tags = flat.baselines[0].requirements[0].tags;
      expect(tags.severity).toBe('high');   // overlay wins
      expect(tags.nist).toEqual(['AC-2']);   // base preserved
      expect(tags.custom).toBe('new');       // overlay added
    });

    it('descriptions merged by label', () => {
      const results = makeResults([
        makeBaseline('overlay', [makeReq('V-1', {
          descriptions: [
            { label: 'default', data: 'overlay default' },
            { label: 'rationale', data: 'overlay rationale' },
          ],
        })]),
        makeBaseline('base', [makeReq('V-1', {
          descriptions: [
            { label: 'default', data: 'base default' },
            { label: 'check', data: 'base check' },
          ],
        })], { parentBaseline: 'overlay' }),
      ]);
      const { results: flat } = flattenOverlays(results);
      const descs = flat.baselines[0].requirements[0].descriptions;
      const descMap = new Map(descs.map(d => [d.label, d.data]));
      expect(descMap.get('default')).toBe('overlay default');     // overlay wins
      expect(descMap.get('check')).toBe('base check');            // base preserved
      expect(descMap.get('rationale')).toBe('overlay rationale'); // overlay added
    });

    it('impact from overlay wins', () => {
      const results = makeResults([
        makeBaseline('overlay', [makeReq('V-1', { impact: 0.0 })]),  // risk accepted
        makeBaseline('base', [
          makeReq('V-1', { impact: 0.7 }),
        ], { parentBaseline: 'overlay' }),
      ]);
      const { results: flat } = flattenOverlays(results);
      expect(flat.baselines[0].requirements[0].impact).toBe(0.0);
    });

    it('severity from overlay wins over base', () => {
      const results = makeResults([
        makeBaseline('overlay', [makeReq('V-1', { impact: 0.0, severity: 'medium' })]),
        makeBaseline('base', [
          makeReq('V-1', { impact: 0.7, severity: 'high', results: [{ status: 'passed', codeDesc: 'test' }] }),
        ], { parentBaseline: 'overlay' }),
      ]);
      const { results: flat } = flattenOverlays(results);
      // Overlay sets impact=0 (NA) but severity=medium (original STIG severity).
      // Severity must survive the merge — not be lost.
      expect(flat.baselines[0].requirements[0].severity).toBe('medium');
    });

    it('base severity preserved when overlay has no severity', () => {
      const results = makeResults([
        makeBaseline('overlay', [makeReq('V-1', { impact: 0.0 })]),
        makeBaseline('base', [
          makeReq('V-1', { impact: 0.7, severity: 'high', results: [{ status: 'passed', codeDesc: 'test' }] }),
        ], { parentBaseline: 'overlay' }),
      ]);
      const { results: flat } = flattenOverlays(results);
      // Base had severity=high, overlay didn't set one. Base value must survive.
      expect(flat.baselines[0].requirements[0].severity).toBe('high');
    });

    it('severity survives three-layer merge', () => {
      const results = makeResults([
        makeBaseline('top', [makeReq('V-1', { impact: 0.0, severity: 'medium' })]),
        makeBaseline('mid', [makeReq('V-1', { impact: 0.0 })], { parentBaseline: 'top' }),
        makeBaseline('base', [
          makeReq('V-1', { impact: 0.7, severity: 'high', results: [{ status: 'passed', codeDesc: 'test' }] }),
        ], { parentBaseline: 'mid' }),
      ]);
      const { results: flat } = flattenOverlays(results);
      // Top overlay explicitly sets severity=medium. Must propagate through all layers.
      expect(flat.baselines[0].requirements[0].severity).toBe('medium');
    });

    it('effectiveStatus from overlay wins when overlay has results', () => {
      // Overlay with its own results — effectiveStatus is meaningful
      const results = makeResults([
        makeBaseline('overlay', [makeReq('V-1', {
          impact: 0.0,
          effectiveStatus: 'notApplicable',
          results: [{ status: 'notApplicable', codeDesc: 'NA check' }],
        })]),
        makeBaseline('base', [
          makeReq('V-1', { impact: 0.7, effectiveStatus: 'passed', results: [{ status: 'passed', codeDesc: 'test' }] }),
        ], { parentBaseline: 'overlay' }),
      ]);
      const { results: flat } = flattenOverlays(results);
      expect(flat.baselines[0].requirements[0].effectiveStatus).toBe('notApplicable');
    });

    it('base effectiveStatus preserved when overlay has no results', () => {
      // Overlay with empty results — its effectiveStatus is a computed artifact, not intentional
      const results = makeResults([
        makeBaseline('overlay', [makeReq('V-1', { impact: 0.0, effectiveStatus: 'notReviewed' })]),
        makeBaseline('base', [
          makeReq('V-1', { impact: 0.7, effectiveStatus: 'passed', results: [{ status: 'passed', codeDesc: 'test' }] }),
        ], { parentBaseline: 'overlay' }),
      ]);
      const { results: flat } = flattenOverlays(results);
      // Base had real results → its effectiveStatus is authoritative
      expect(flat.baselines[0].requirements[0].effectiveStatus).toBe('passed');
    });
  });

  // ── Edge cases ────────────────────────────────────────────

  describe('edge cases', () => {
    it('orphan child (parentBaseline not found) treated as root with warning', () => {
      const results = makeResults([
        makeBaseline('orphan', [makeReq('V-1')], { parentBaseline: 'nonexistent' }),
      ]);
      const { results: flat, metadata } = flattenOverlays(results);
      expect(flat.baselines).toHaveLength(1);
      expect(metadata.warnings.length).toBeGreaterThan(0);
      expect(metadata.warnings[0]).toContain('nonexistent');
    });

    it('circular parentBaseline detected with warning', () => {
      const results = makeResults([
        makeBaseline('A', [makeReq('V-1')], { parentBaseline: 'B' }),
        makeBaseline('B', [makeReq('V-1')], { parentBaseline: 'A' }),
      ]);
      const { results: flat, metadata } = flattenOverlays(results);
      // Should not infinite loop — should produce some output with a warning
      expect(flat.baselines.length).toBeGreaterThanOrEqual(1);
      expect(metadata.warnings.length).toBeGreaterThan(0);
    });

    it('empty requirements array produces empty merge', () => {
      const results = makeResults([
        makeBaseline('overlay', []),
        makeBaseline('base', [], { parentBaseline: 'overlay' }),
      ]);
      const { results: flat } = flattenOverlays(results);
      expect(flat.baselines).toHaveLength(1);
      expect(flat.baselines[0].requirements).toHaveLength(0);
    });

    it('resource pack (0 controls) handled cleanly', () => {
      const results = makeResults([
        makeBaseline('wrapper', [makeReq('K-1')]),
        makeBaseline('k8s', [
          makeReq('K-1', { results: [{ status: 'passed', codeDesc: 'test' }] }),
        ], { parentBaseline: 'wrapper' }),
        makeBaseline('k8s-resources', [], { parentBaseline: 'k8s' }),  // resource pack
      ]);
      const { results: flat } = flattenOverlays(results);
      expect(flat.baselines).toHaveLength(1);
      expect(flat.baselines[0].requirements).toHaveLength(1);
    });

    it('preserves non-baseline fields on HDFResults', () => {
      const results = makeResults([makeBaseline('single', [makeReq('V-1')])]);
      results.statistics = { duration: 42 } as any;
      results.generator = { name: 'InSpec', version: '5.0' } as any;
      const { results: flat } = flattenOverlays(results);
      expect(flat.statistics).toEqual({ duration: 42 });
      expect(flat.generator).toEqual({ name: 'InSpec', version: '5.0' });
    });
  });

  // ── Integration: real fixtures ────────────────────────────

  /**
   * Load an InSpec v1 exec-json fixture and convert to HDF v2 baselines
   * for testing flattenOverlays with real data.
   */
  function loadV1FixtureAsHdfResults(fixturePath: string): HDFResults {

    const raw = JSON.parse(readFileSync(fixturePath, 'utf-8')) as any;

    const baselines: EvaluatedBaseline[] = raw.profiles.map((p: any) => ({
      name: p.name,
      parentBaseline: p.parent_profile || undefined,
  
      requirements: (p.controls || []).map((c: any) => ({
        id: c.id,
        impact: c.impact ?? 0.5,
        tags: c.tags || {},
    
        results: (c.results || []).map((r: any) => ({
          status: r.status,
          codeDesc: r.code_desc || '',
          message: r.message || undefined,
          runTime: r.run_time || undefined,
        })),
    
        descriptions: (c.descriptions || []).map((d: any) => ({
          label: d.label,
          data: d.data,
        })),
        code: c.code || '',
        title: c.title || '',
      })),
  
      depends: (p.depends || []).map((d: any) => ({ name: d.name })),
    }));
    return { baselines };
  }

  describe('integration — real fixtures', () => {
    // Migrated from hdf-schema/test/fixtures to @mitre/hdf-fixtures/inspec/
    // (see bead hdf-libs-e95o).
    it('Three_Layer_RHEL7: 3 profiles → 1 baseline, 247 controls', () => {
      const { results: flat, metadata } = flattenOverlays(
        loadV1FixtureAsHdfResults(inspec.threeLayerRhel7.path)
      );

      expect(flat.baselines).toHaveLength(1);
      expect(flat.baselines[0].requirements).toHaveLength(247);
      expect(metadata.originalBaselineCount).toBe(3);
      expect(metadata.flattenedBaselineCount).toBe(1);

      const withResults = flat.baselines[0].requirements.filter(r => r.results.length > 0);
      expect(withResults.length).toBe(247);
    });

    it('wrapper.json: 4 profiles → 1 baseline, 534 controls', () => {
      const { results: flat, metadata } = flattenOverlays(
        loadV1FixtureAsHdfResults(inspec.wrapper.path)
      );

      expect(flat.baselines).toHaveLength(1);
      expect(flat.baselines[0].requirements).toHaveLength(534);
      expect(metadata.originalBaselineCount).toBe(4);
      expect(metadata.flattenedBaselineCount).toBe(1);
    });
  });
});
