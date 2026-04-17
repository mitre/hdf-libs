import { describe, it, expect } from 'vitest';
import { buildExtensionGraph } from '../src/index.js';
import { makeRequirement, makeBaseline } from './helpers.js';

describe('ContextualizedRequirement derived properties', () => {
  describe('root', () => {
    it('returns itself when there is no parent', () => {
      const graph = buildExtensionGraph({
        baselines: [makeBaseline({ name: 'base', requirements: [makeRequirement({ id: 'R1', code: 'base code' })] })],
      } as any);

      const req = graph.requirements[0]!;
      expect(req.root).toBe(req);
    });

    it('returns the base requirement in a two-layer chain', () => {
      const graph = buildExtensionGraph({
        baselines: [
          makeBaseline({ name: 'base', requirements: [makeRequirement({ id: 'R1', code: 'base code' })] }),
          makeBaseline({ name: 'overlay', requirements: [makeRequirement({ id: 'R1', code: 'overlay code' })], parentBaseline: 'base' }),
        ],
      } as any);

      const baseR1 = graph.baselines[0]!.requirements[0]!;
      const overlayR1 = graph.baselines[1]!.requirements[0]!;

      expect(overlayR1.root).toBe(baseR1);
      expect(baseR1.root).toBe(baseR1);
    });

    it('returns the root in a three-layer chain', () => {
      const graph = buildExtensionGraph({
        baselines: [
          makeBaseline({ name: 'base', requirements: [makeRequirement({ id: 'R1', code: 'base' })] }),
          makeBaseline({ name: 'mid', requirements: [makeRequirement({ id: 'R1', code: 'mid' })], parentBaseline: 'base' }),
          makeBaseline({ name: 'top', requirements: [makeRequirement({ id: 'R1', code: 'top' })], parentBaseline: 'mid' }),
        ],
      } as any);

      const baseR1 = graph.baselines[0]!.requirements[0]!;
      const topR1 = graph.baselines[2]!.requirements[0]!;

      expect(topR1.root).toBe(baseR1);
    });
  });

  describe('isRedundant', () => {
    it('returns false for a root requirement', () => {
      const graph = buildExtensionGraph({
        baselines: [makeBaseline({ name: 'base', requirements: [makeRequirement({ id: 'R1', code: 'some code' })] })],
      } as any);

      expect(graph.requirements[0]!.isRedundant).toBe(false);
    });

    it('returns true when overlay code is empty', () => {
      const graph = buildExtensionGraph({
        baselines: [
          makeBaseline({ name: 'base', requirements: [makeRequirement({ id: 'R1', code: 'base code' })] }),
          makeBaseline({ name: 'overlay', requirements: [makeRequirement({ id: 'R1', code: '' })], parentBaseline: 'base' }),
        ],
      } as any);

      const overlayR1 = graph.baselines[1]!.requirements[0]!;
      expect(overlayR1.isRedundant).toBe(true);
    });

    it('returns true when overlay code is undefined', () => {
      const graph = buildExtensionGraph({
        baselines: [
          makeBaseline({ name: 'base', requirements: [makeRequirement({ id: 'R1', code: 'base code' })] }),
          makeBaseline({ name: 'overlay', requirements: [makeRequirement({ id: 'R1' })], parentBaseline: 'base' }),
        ],
      } as any);

      const overlayR1 = graph.baselines[1]!.requirements[0]!;
      expect(overlayR1.isRedundant).toBe(true);
    });

    it('returns true when overlay code matches root code', () => {
      const graph = buildExtensionGraph({
        baselines: [
          makeBaseline({ name: 'base', requirements: [makeRequirement({ id: 'R1', code: 'same code' })] }),
          makeBaseline({ name: 'overlay', requirements: [makeRequirement({ id: 'R1', code: 'same code' })], parentBaseline: 'base' }),
        ],
      } as any);

      const overlayR1 = graph.baselines[1]!.requirements[0]!;
      expect(overlayR1.isRedundant).toBe(true);
    });

    it('returns false when overlay code differs from root', () => {
      const graph = buildExtensionGraph({
        baselines: [
          makeBaseline({ name: 'base', requirements: [makeRequirement({ id: 'R1', code: 'base code' })] }),
          makeBaseline({ name: 'overlay', requirements: [makeRequirement({ id: 'R1', code: 'modified code' })], parentBaseline: 'base' }),
        ],
      } as any);

      const overlayR1 = graph.baselines[1]!.requirements[0]!;
      expect(overlayR1.isRedundant).toBe(false);
    });
  });

  describe('fullCode', () => {
    it('returns own code for a root requirement', () => {
      const graph = buildExtensionGraph({
        baselines: [makeBaseline({ name: 'base', requirements: [makeRequirement({ id: 'R1', code: 'describe "test" do\n  it { should pass }\nend' })] })],
      } as any);

      const req = graph.requirements[0]!;
      expect(req.fullCode).toContain('describe "test" do');
      expect(req.fullCode).toContain('base');
    });

    it('concatenates code from overlay and base with headers', () => {
      const graph = buildExtensionGraph({
        baselines: [
          makeBaseline({ name: 'rhel9-stig', requirements: [makeRequirement({ id: 'R1', code: 'base code' })] }),
          makeBaseline({ name: 'my-overlay', requirements: [makeRequirement({ id: 'R1', code: 'overlay code' })], parentBaseline: 'rhel9-stig' }),
        ],
      } as any);

      const overlayR1 = graph.baselines[1]!.requirements[0]!;
      const full = overlayR1.fullCode;

      // Should contain both codes with baseline name headers
      expect(full).toContain('my-overlay');
      expect(full).toContain('overlay code');
      expect(full).toContain('rhel9-stig');
      expect(full).toContain('base code');
    });

    it('skips redundant overlay code in concatenation', () => {
      const graph = buildExtensionGraph({
        baselines: [
          makeBaseline({ name: 'base', requirements: [makeRequirement({ id: 'R1', code: 'base code' })] }),
          makeBaseline({ name: 'overlay', requirements: [makeRequirement({ id: 'R1', code: '' })], parentBaseline: 'base' }),
        ],
      } as any);

      const overlayR1 = graph.baselines[1]!.requirements[0]!;
      const full = overlayR1.fullCode;

      // Should still include base code
      expect(full).toContain('base code');
      // Should not have an empty overlay section
      expect(full).not.toContain('overlay');
    });

    it('concatenates three layers', () => {
      const graph = buildExtensionGraph({
        baselines: [
          makeBaseline({ name: 'base', requirements: [makeRequirement({ id: 'R1', code: 'base code' })] }),
          makeBaseline({ name: 'mid', requirements: [makeRequirement({ id: 'R1', code: 'mid code' })], parentBaseline: 'base' }),
          makeBaseline({ name: 'top', requirements: [makeRequirement({ id: 'R1', code: 'top code' })], parentBaseline: 'mid' }),
        ],
      } as any);

      const topR1 = graph.baselines[2]!.requirements[0]!;
      const full = topR1.fullCode;

      expect(full).toContain('top');
      expect(full).toContain('top code');
      expect(full).toContain('mid');
      expect(full).toContain('mid code');
      expect(full).toContain('base');
      expect(full).toContain('base code');

      // top should appear before mid, mid before base
      const topIdx = full.indexOf('top code');
      const midIdx = full.indexOf('mid code');
      const baseIdx = full.indexOf('base code');
      expect(topIdx).toBeLessThan(midIdx);
      expect(midIdx).toBeLessThan(baseIdx);
    });

    it('returns empty string when code is undefined and no parent', () => {
      const graph = buildExtensionGraph({
        baselines: [makeBaseline({ name: 'base', requirements: [makeRequirement({ id: 'R1' })] })],
      } as any);

      const req = graph.requirements[0]!;
      expect(req.fullCode).toBe('');
    });
  });

  describe('extensionChain', () => {
    it('returns single-element array for root requirement', () => {
      const graph = buildExtensionGraph({
        baselines: [makeBaseline({ name: 'base', requirements: [makeRequirement({ id: 'R1' })] })],
      } as any);

      const req = graph.requirements[0]!;
      expect(req.extensionChain).toHaveLength(1);
      expect(req.extensionChain[0]!.data.name).toBe('base');
    });

    it('returns ordered chain from root to leaf for two layers', () => {
      const graph = buildExtensionGraph({
        baselines: [
          makeBaseline({ name: 'base', requirements: [makeRequirement({ id: 'R1' })] }),
          makeBaseline({ name: 'overlay', requirements: [makeRequirement({ id: 'R1' })], parentBaseline: 'base' }),
        ],
      } as any);

      const overlayR1 = graph.baselines[1]!.requirements[0]!;
      const chain = overlayR1.extensionChain;

      expect(chain).toHaveLength(2);
      expect(chain[0]!.data.name).toBe('base');
      expect(chain[1]!.data.name).toBe('overlay');
    });

    it('returns ordered chain for three layers', () => {
      const graph = buildExtensionGraph({
        baselines: [
          makeBaseline({ name: 'base', requirements: [makeRequirement({ id: 'R1' })] }),
          makeBaseline({ name: 'mid', requirements: [makeRequirement({ id: 'R1' })], parentBaseline: 'base' }),
          makeBaseline({ name: 'top', requirements: [makeRequirement({ id: 'R1' })], parentBaseline: 'mid' }),
        ],
      } as any);

      const topR1 = graph.baselines[2]!.requirements[0]!;
      const chain = topR1.extensionChain;

      expect(chain.map((b) => b.data.name)).toEqual(['base', 'mid', 'top']);
    });
  });

  describe('modifications', () => {
    it('returns empty array for root requirement', () => {
      const graph = buildExtensionGraph({
        baselines: [makeBaseline({ name: 'base', requirements: [makeRequirement({ id: 'R1', impact: 0.7 })] })],
      } as any);

      expect(graph.requirements[0]!.modifications).toEqual([]);
    });

    it('detects impact change', () => {
      const graph = buildExtensionGraph({
        baselines: [
          makeBaseline({ name: 'base', requirements: [makeRequirement({ id: 'R1', impact: 1.0 })] }),
          makeBaseline({ name: 'overlay', requirements: [makeRequirement({ id: 'R1', impact: 0.5 })], parentBaseline: 'base' }),
        ],
      } as any);

      const overlayR1 = graph.baselines[1]!.requirements[0]!;
      const mods = overlayR1.modifications;

      expect(mods).toHaveLength(1);
      expect(mods[0]).toEqual({
        field: 'impact',
        originalValue: 1.0,
        newValue: 0.5,
        inBaseline: 'overlay',
      });
    });

    it('detects title change', () => {
      const graph = buildExtensionGraph({
        baselines: [
          makeBaseline({ name: 'base', requirements: [makeRequirement({ id: 'R1', title: 'Original Title' })] }),
          makeBaseline({ name: 'overlay', requirements: [makeRequirement({ id: 'R1', title: 'Modified Title' })], parentBaseline: 'base' }),
        ],
      } as any);

      const overlayR1 = graph.baselines[1]!.requirements[0]!;
      const mods = overlayR1.modifications;

      expect(mods.some((m) => m.field === 'title')).toBe(true);
      const titleMod = mods.find((m) => m.field === 'title')!;
      expect(titleMod.originalValue).toBe('Original Title');
      expect(titleMod.newValue).toBe('Modified Title');
    });

    it('does not report unchanged fields', () => {
      const graph = buildExtensionGraph({
        baselines: [
          makeBaseline({ name: 'base', requirements: [makeRequirement({ id: 'R1', impact: 0.5, title: 'Same' })] }),
          makeBaseline({ name: 'overlay', requirements: [makeRequirement({ id: 'R1', impact: 0.5, title: 'Same' })], parentBaseline: 'base' }),
        ],
      } as any);

      const overlayR1 = graph.baselines[1]!.requirements[0]!;
      expect(overlayR1.modifications).toEqual([]);
    });

    it('detects effectiveImpact change', () => {
      const graph = buildExtensionGraph({
        baselines: [
          makeBaseline({ name: 'base', requirements: [makeRequirement({ id: 'R1', effectiveImpact: 0.7 } as any)] }),
          makeBaseline({ name: 'overlay', requirements: [makeRequirement({ id: 'R1', effectiveImpact: 0.3 } as any)], parentBaseline: 'base' }),
        ],
      } as any);

      const overlayR1 = graph.baselines[1]!.requirements[0]!;
      const mods = overlayR1.modifications;

      expect(mods).toHaveLength(1);
      expect(mods[0]).toEqual({
        field: 'effectiveImpact',
        originalValue: 0.7,
        newValue: 0.3,
        inBaseline: 'overlay',
      });
    });

    it('detects disposition change', () => {
      const graph = buildExtensionGraph({
        baselines: [
          makeBaseline({ name: 'base', requirements: [makeRequirement({ id: 'R1', disposition: 'waiver' } as any)] }),
          makeBaseline({ name: 'overlay', requirements: [makeRequirement({ id: 'R1', disposition: 'riskAdjustment' } as any)], parentBaseline: 'base' }),
        ],
      } as any);

      const overlayR1 = graph.baselines[1]!.requirements[0]!;
      const mods = overlayR1.modifications;

      expect(mods.some((m) => m.field === 'disposition')).toBe(true);
      const dispMod = mods.find((m) => m.field === 'disposition')!;
      expect(dispMod.originalValue).toBe('waiver');
      expect(dispMod.newValue).toBe('riskAdjustment');
    });

    it('does not report unchanged effectiveImpact and disposition', () => {
      const graph = buildExtensionGraph({
        baselines: [
          makeBaseline({ name: 'base', requirements: [makeRequirement({ id: 'R1', effectiveImpact: 0.3, disposition: 'waiver' } as any)] }),
          makeBaseline({ name: 'overlay', requirements: [makeRequirement({ id: 'R1', effectiveImpact: 0.3, disposition: 'waiver' } as any)], parentBaseline: 'base' }),
        ],
      } as any);

      const overlayR1 = graph.baselines[1]!.requirements[0]!;
      expect(overlayR1.modifications.filter((m) => m.field === 'effectiveImpact' || m.field === 'disposition')).toEqual([]);
    });

    it('detects multiple changes at once', () => {
      const graph = buildExtensionGraph({
        baselines: [
          makeBaseline({ name: 'base', requirements: [makeRequirement({ id: 'R1', impact: 1.0, title: 'Old' })] }),
          makeBaseline({ name: 'overlay', requirements: [makeRequirement({ id: 'R1', impact: 0.0, title: 'New' })], parentBaseline: 'base' }),
        ],
      } as any);

      const overlayR1 = graph.baselines[1]!.requirements[0]!;
      const mods = overlayR1.modifications;

      expect(mods.length).toBeGreaterThanOrEqual(2);
      expect(mods.some((m) => m.field === 'impact')).toBe(true);
      expect(mods.some((m) => m.field === 'title')).toBe(true);
    });
  });
});
