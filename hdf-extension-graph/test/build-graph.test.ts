import { describe, it, expect } from 'vitest';
import {
  buildExtensionGraph,
  ContextualizedBaseline,
} from '../src/index.js';
import { makeRequirement, makeBaseline, makeResults } from './helpers.js';

describe('buildExtensionGraph', () => {
  describe('Phase 1: baseline wrapping', () => {
    it('wraps all baselines from the results', () => {
      const results = makeResults([
        makeBaseline({ name: 'alpha', requirements: [] }),
        makeBaseline({ name: 'beta', requirements: [] }),
      ]);

      const graph = buildExtensionGraph(results);

      expect(graph.baselines).toHaveLength(2);
      expect(graph.baselines[0]).toBeInstanceOf(ContextualizedBaseline);
      expect(graph.baselines[0]!.data.name).toBe('alpha');
      expect(graph.baselines[1]!.data.name).toBe('beta');
    });

    it('sets sourcedFrom to the original results on each baseline', () => {
      const results = makeResults([
        makeBaseline({ name: 'base', requirements: [] }),
      ]);

      const graph = buildExtensionGraph(results);

      expect(graph.baselines[0]!.sourcedFrom).toBe(results);
    });

    it('returns empty graph for empty baselines array', () => {
      const results = makeResults([]);

      const graph = buildExtensionGraph(results);

      expect(graph.baselines).toHaveLength(0);
      expect(graph.requirements).toHaveLength(0);
    });
  });

  describe('Phase 2: baseline linking via parentBaseline', () => {
    it('links child to parent baseline bidirectionally', () => {
      const parent = makeBaseline({ name: 'parent-stig', requirements: [] });
      const child = makeBaseline({ name: 'child-overlay', requirements: [], parentBaseline: 'parent-stig' });
      const results = makeResults([parent, child]);

      const graph = buildExtensionGraph(results);

      const ctxParent = graph.findBaseline('parent-stig')!;
      const ctxChild = graph.findBaseline('child-overlay')!;

      // Child extends from parent
      expect(ctxChild.extendsFrom).toHaveLength(1);
      expect(ctxChild.extendsFrom[0]).toBe(ctxParent);

      // Parent is extended by child
      expect(ctxParent.extendedBy).toHaveLength(1);
      expect(ctxParent.extendedBy[0]).toBe(ctxChild);
    });

    it('handles three-layer extension chain', () => {
      const base = makeBaseline({ name: 'base', requirements: [] });
      const mid = makeBaseline({ name: 'mid', requirements: [], parentBaseline: 'base' });
      const top = makeBaseline({ name: 'top', requirements: [], parentBaseline: 'mid' });
      const results = makeResults([base, mid, top]);

      const graph = buildExtensionGraph(results);

      const ctxBase = graph.findBaseline('base')!;
      const ctxMid = graph.findBaseline('mid')!;
      const ctxTop = graph.findBaseline('top')!;

      expect(ctxBase.extendedBy).toContain(ctxMid);
      expect(ctxMid.extendsFrom).toContain(ctxBase);
      expect(ctxMid.extendedBy).toContain(ctxTop);
      expect(ctxTop.extendsFrom).toContain(ctxMid);

      // Base has no parent, top has no children
      expect(ctxBase.extendsFrom).toHaveLength(0);
      expect(ctxTop.extendedBy).toHaveLength(0);
    });

    it('leaves extendsFrom empty when parentBaseline names a missing baseline', () => {
      const orphan = makeBaseline({ name: 'orphan', requirements: [], parentBaseline: 'nonexistent' });
      const results = makeResults([orphan]);

      const graph = buildExtensionGraph(results);

      const ctxOrphan = graph.findBaseline('orphan')!;
      expect(ctxOrphan.extendsFrom).toHaveLength(0);
    });

    it('does not link baselines without parentBaseline', () => {
      const a = makeBaseline({ name: 'a', requirements: [] });
      const b = makeBaseline({ name: 'b', requirements: [] });
      const results = makeResults([a, b]);

      const graph = buildExtensionGraph(results);

      expect(graph.findBaseline('a')!.extendsFrom).toHaveLength(0);
      expect(graph.findBaseline('a')!.extendedBy).toHaveLength(0);
      expect(graph.findBaseline('b')!.extendsFrom).toHaveLength(0);
      expect(graph.findBaseline('b')!.extendedBy).toHaveLength(0);
    });
  });

  describe('Phase 3: requirement wrapping', () => {
    it('collects all requirements from all baselines', () => {
      const results = makeResults([
        makeBaseline({ name: 'a', requirements: [makeRequirement({ id: 'R1' }), makeRequirement({ id: 'R2' })] }),
        makeBaseline({ name: 'b', requirements: [makeRequirement({ id: 'R3' })] }),
      ]);

      const graph = buildExtensionGraph(results);

      expect(graph.requirements).toHaveLength(3);
      expect(graph.requirements.map((r) => r.data.id)).toEqual(['R1', 'R2', 'R3']);
    });

    it('each requirement references its owning baseline', () => {
      const results = makeResults([
        makeBaseline({ name: 'base', requirements: [makeRequirement({ id: 'R1' })] }),
      ]);

      const graph = buildExtensionGraph(results);

      expect(graph.requirements[0]!.sourcedFrom.data.name).toBe('base');
    });
  });

  describe('Phase 4: requirement linking across baselines', () => {
    it('links requirements with matching ids across linked baselines', () => {
      const parent = makeBaseline({
        name: 'parent',
        requirements: [makeRequirement({ id: 'SV-001', code: 'original code' })],
      });
      const child = makeBaseline({
        name: 'child',
        requirements: [makeRequirement({ id: 'SV-001', code: 'overlay code' })],
        parentBaseline: 'parent',
      });
      const results = makeResults([parent, child]);

      const graph = buildExtensionGraph(results);

      const parentReqs = graph.baselines[0]!.requirements;
      const childReqs = graph.baselines[1]!.requirements;

      // Child requirement extends from parent requirement
      expect(childReqs[0]!.extendsFrom).toHaveLength(1);
      expect(childReqs[0]!.extendsFrom[0]).toBe(parentReqs[0]);

      // Parent requirement is extended by child requirement
      expect(parentReqs[0]!.extendedBy).toHaveLength(1);
      expect(parentReqs[0]!.extendedBy[0]).toBe(childReqs[0]);
    });

    it('does not link requirements that share id but have no baseline relationship', () => {
      const a = makeBaseline({
        name: 'standalone-a',
        requirements: [makeRequirement({ id: 'SV-001' })],
      });
      const b = makeBaseline({
        name: 'standalone-b',
        requirements: [makeRequirement({ id: 'SV-001' })],
      });
      const results = makeResults([a, b]);

      const graph = buildExtensionGraph(results);

      const aReqs = graph.baselines[0]!.requirements;
      const bReqs = graph.baselines[1]!.requirements;

      expect(aReqs[0]!.extendsFrom).toHaveLength(0);
      expect(aReqs[0]!.extendedBy).toHaveLength(0);
      expect(bReqs[0]!.extendsFrom).toHaveLength(0);
      expect(bReqs[0]!.extendedBy).toHaveLength(0);
    });

    it('links requirements through a three-layer chain', () => {
      const base = makeBaseline({
        name: 'base',
        requirements: [makeRequirement({ id: 'R1', code: 'base code' })],
      });
      const mid = makeBaseline({
        name: 'mid',
        requirements: [makeRequirement({ id: 'R1', code: 'mid code' })],
        parentBaseline: 'base',
      });
      const top = makeBaseline({
        name: 'top',
        requirements: [makeRequirement({ id: 'R1', code: 'top code' })],
        parentBaseline: 'mid',
      });
      const results = makeResults([base, mid, top]);

      const graph = buildExtensionGraph(results);

      const baseR1 = graph.baselines[0]!.requirements[0]!;
      const midR1 = graph.baselines[1]!.requirements[0]!;
      const topR1 = graph.baselines[2]!.requirements[0]!;

      // mid extends base
      expect(midR1.extendsFrom[0]).toBe(baseR1);
      expect(baseR1.extendedBy[0]).toBe(midR1);

      // top extends mid
      expect(topR1.extendsFrom[0]).toBe(midR1);
      expect(midR1.extendedBy[0]).toBe(topR1);

      // base has no parent, top has no children
      expect(baseR1.extendsFrom).toHaveLength(0);
      expect(topR1.extendedBy).toHaveLength(0);
    });

    it('only links requirements that exist in both parent and child', () => {
      const parent = makeBaseline({
        name: 'parent',
        requirements: [
          makeRequirement({ id: 'R1' }),
          makeRequirement({ id: 'R2' }),
        ],
      });
      const child = makeBaseline({
        name: 'child',
        requirements: [
          makeRequirement({ id: 'R1' }),
          makeRequirement({ id: 'R3' }),
        ],
        parentBaseline: 'parent',
      });
      const results = makeResults([parent, child]);

      const graph = buildExtensionGraph(results);

      const parentR1 = graph.baselines[0]!.requirements[0]!;
      const parentR2 = graph.baselines[0]!.requirements[1]!;
      const childR1 = graph.baselines[1]!.requirements[0]!;
      const childR3 = graph.baselines[1]!.requirements[1]!;

      // R1 is linked
      expect(childR1.extendsFrom[0]).toBe(parentR1);

      // R2 and R3 are unlinked (no matching id in the other baseline)
      expect(parentR2.extendedBy).toHaveLength(0);
      expect(childR3.extendsFrom).toHaveLength(0);
    });
  });
});
