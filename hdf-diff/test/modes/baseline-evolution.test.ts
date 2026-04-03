import { describe, it, expect } from 'vitest';
import { diffBaselines, diffHdf } from '../../src/diff.js';
import type { HdfComparison, RequirementDiff } from '../../src/types.js';

// ── Inline fixtures ──────────────────────────────────────────────────

const baselineV1 = {
  name: 'test-stig',
  version: '1.0',
  requirements: [
    {
      id: 'SV-001',
      title: 'Old Title',
      impact: 0.7,
      descriptions: [{ label: 'default', data: 'Check X' }],
      tags: { nist: ['AC-1'] },
    },
    {
      id: 'SV-002',
      title: 'Unchanged',
      impact: 0.5,
      descriptions: [{ label: 'default', data: 'Check Y' }],
      tags: { nist: ['AC-2'] },
    },
    {
      id: 'SV-003',
      title: 'Removed',
      impact: 0.3,
      descriptions: [],
      tags: {},
    },
  ],
};

const baselineV2 = {
  name: 'test-stig',
  version: '2.0',
  requirements: [
    {
      id: 'SV-001',
      title: 'New Title',
      impact: 0.9,
      descriptions: [{ label: 'default', data: 'Check X revised' }],
      tags: { nist: ['AC-1', 'AC-1 (1)'] },
    },
    {
      id: 'SV-002',
      title: 'Unchanged',
      impact: 0.5,
      descriptions: [{ label: 'default', data: 'Check Y' }],
      tags: { nist: ['AC-2'] },
    },
    {
      id: 'SV-004',
      title: 'Added',
      impact: 0.7,
      descriptions: [],
      tags: {},
    },
  ],
};

function findReq(diff: HdfComparison, id: string): RequirementDiff | undefined {
  return diff.requirementDiffs.find((r) => r.id === id);
}

// ── Tests ────────────────────────────────────────────────────────────

describe('baseline evolution comparison mode', () => {
  describe('top-level metadata', () => {
    it('should set comparisonMode to baselineEvolution', () => {
      const diff = diffBaselines(baselineV1, baselineV2);
      expect(diff.comparisonMode).toBe('baselineEvolution');
    });

    it('should have formatVersion 1.0.0', () => {
      const diff = diffBaselines(baselineV1, baselineV2);
      expect(diff.formatVersion).toBe('1.0.0');
    });

    it('should include a timestamp', () => {
      const diff = diffBaselines(baselineV1, baselineV2);
      expect(diff.timestamp).toBeDefined();
      expect(typeof diff.timestamp).toBe('string');
    });
  });

  describe('sources', () => {
    it('should have 2 sources', () => {
      const diff = diffBaselines(baselineV1, baselineV2);
      expect(diff.sources).toHaveLength(2);
    });

    it('should label sources with baseline name and version', () => {
      const diff = diffBaselines(baselineV1, baselineV2);
      expect(diff.sources[0]!.label).toBe('test-stig 1.0');
      expect(diff.sources[1]!.label).toBe('test-stig 2.0');
    });

    it('should use old/new roles', () => {
      const diff = diffBaselines(baselineV1, baselineV2);
      expect(diff.sources[0]!.role).toBe('old');
      expect(diff.sources[1]!.role).toBe('new');
    });
  });

  describe('baselineDiffs', () => {
    it('should show baseline version change', () => {
      const diff = diffBaselines(baselineV1, baselineV2);
      expect(diff.baselineDiffs).toHaveLength(1);
      expect(diff.baselineDiffs[0]!.name).toBe('test-stig');
      expect(diff.baselineDiffs[0]!.oldVersion).toBe('1.0');
      expect(diff.baselineDiffs[0]!.newVersion).toBe('2.0');
      expect(diff.baselineDiffs[0]!.state).toBe('updated');
    });

    it('should mark baseline as unchanged when versions match', () => {
      const diff = diffBaselines(baselineV1, baselineV1);
      expect(diff.baselineDiffs[0]!.state).toBe('unchanged');
    });
  });

  describe('requirement states', () => {
    it('should mark SV-001 as updated (title, impact, descriptions, tags changed)', () => {
      const diff = diffBaselines(baselineV1, baselineV2);
      const req = findReq(diff, 'SV-001');
      expect(req).toBeDefined();
      expect(req!.state).toBe('updated');
    });

    it('should mark SV-002 as unchanged', () => {
      const diff = diffBaselines(baselineV1, baselineV2);
      const req = findReq(diff, 'SV-002');
      expect(req).toBeDefined();
      expect(req!.state).toBe('unchanged');
    });

    it('should mark SV-003 as absent (removed in v2)', () => {
      const diff = diffBaselines(baselineV1, baselineV2);
      const req = findReq(diff, 'SV-003');
      expect(req).toBeDefined();
      expect(req!.state).toBe('absent');
      expect(req!.before).not.toBeNull();
      expect(req!.after).toBeNull();
    });

    it('should mark SV-004 as new (added in v2)', () => {
      const diff = diffBaselines(baselineV1, baselineV2);
      const req = findReq(diff, 'SV-004');
      expect(req).toBeDefined();
      expect(req!.state).toBe('new');
      expect(req!.before).toBeNull();
      expect(req!.after).not.toBeNull();
    });
  });

  describe('field changes for SV-001', () => {
    it('should have fieldChanges for title, impact, descriptions, and tags', () => {
      const diff = diffBaselines(baselineV1, baselineV2);
      const req = findReq(diff, 'SV-001');
      expect(req).toBeDefined();
      expect(req!.fieldChanges.length).toBeGreaterThanOrEqual(4);

      const changedPaths = req!.fieldChanges.map((fc) => fc.path);
      expect(changedPaths).toContain('title');
      expect(changedPaths).toContain('impact');
      expect(changedPaths).toContain('descriptions');
      expect(changedPaths).toContain('tags');
    });

    it('should record title change as replace', () => {
      const diff = diffBaselines(baselineV1, baselineV2);
      const req = findReq(diff, 'SV-001');
      const titleChange = req!.fieldChanges.find((fc) => fc.path === 'title');
      expect(titleChange).toBeDefined();
      expect(titleChange!.op).toBe('replace');
      expect(titleChange!.oldValue).toBe('Old Title');
      expect(titleChange!.newValue).toBe('New Title');
    });

    it('should record impact change as replace', () => {
      const diff = diffBaselines(baselineV1, baselineV2);
      const req = findReq(diff, 'SV-001');
      const impactChange = req!.fieldChanges.find((fc) => fc.path === 'impact');
      expect(impactChange).toBeDefined();
      expect(impactChange!.op).toBe('replace');
      expect(impactChange!.oldValue).toBe(0.7);
      expect(impactChange!.newValue).toBe(0.9);
    });
  });

  describe('change reasons', () => {
    it('should include impactChanged and metadataChanged for SV-001', () => {
      const diff = diffBaselines(baselineV1, baselineV2);
      const req = findReq(diff, 'SV-001');
      expect(req!.changeReasons).toContain('impactChanged');
      expect(req!.changeReasons).toContain('metadataChanged');
    });

    it('should have empty changeReasons for unchanged SV-002', () => {
      const diff = diffBaselines(baselineV1, baselineV2);
      const req = findReq(diff, 'SV-002');
      expect(req!.changeReasons).toEqual([]);
    });

    it('should have empty changeReasons for absent SV-003', () => {
      const diff = diffBaselines(baselineV1, baselineV2);
      const req = findReq(diff, 'SV-003');
      expect(req!.changeReasons).toEqual([]);
    });

    it('should have empty changeReasons for new SV-004', () => {
      const diff = diffBaselines(baselineV1, baselineV2);
      const req = findReq(diff, 'SV-004');
      expect(req!.changeReasons).toEqual([]);
    });
  });

  describe('summary counts', () => {
    it('should have correct totals', () => {
      const diff = diffBaselines(baselineV1, baselineV2);
      expect(diff.summary.total).toBe(4);
      expect(diff.summary.matchedCount).toBe(2);
      expect(diff.summary.unmatchedOldCount).toBe(1);
      expect(diff.summary.unmatchedNewCount).toBe(1);
      expect(diff.summary.updated).toBe(1);
      expect(diff.summary.unchanged).toBe(1);
      expect(diff.summary.absent).toBe(1);
      expect(diff.summary.new).toBe(1);
    });

    it('should not have fixed or regressed counts', () => {
      const diff = diffBaselines(baselineV1, baselineV2);
      expect(diff.summary.fixed).toBe(0);
      expect(diff.summary.regressed).toBe(0);
    });
  });

  describe('matching config', () => {
    it('should default to exactId strategy', () => {
      const diff = diffBaselines(baselineV1, baselineV2);
      expect(diff.matching?.primaryStrategy).toBe('exactId');
    });

    it('should include match metadata on matched requirements', () => {
      const diff = diffBaselines(baselineV1, baselineV2);
      const req = findReq(diff, 'SV-001');
      expect(req!.matchStrategy).toBe('exactId');
      expect(req!.matchConfidence).toBe(1.0);
    });
  });

  describe('auto-detection via diffHdf', () => {
    it('should auto-select baselineEvolution mode when both inputs are baselines', () => {
      const diff = diffHdf(baselineV1, baselineV2);
      expect(diff.comparisonMode).toBe('baselineEvolution');
    });

    it('should not auto-select when comparisonMode is explicitly set', () => {
      const diff = diffHdf(baselineV1, baselineV2, { comparisonMode: 'temporal' });
      expect(diff.comparisonMode).toBe('temporal');
    });
  });

  describe('identical baselines', () => {
    it('should classify all requirements as unchanged', () => {
      const diff = diffBaselines(baselineV1, baselineV1);
      for (const req of diff.requirementDiffs) {
        expect(req.state).toBe('unchanged');
      }
    });
  });

  describe('before/after snapshots', () => {
    it('should include full requirement snapshots in before/after', () => {
      const diff = diffBaselines(baselineV1, baselineV2);
      const req = findReq(diff, 'SV-001');
      expect(req!.before).toBeDefined();
      expect(req!.after).toBeDefined();
      expect((req!.before as Record<string, unknown>)['title']).toBe('Old Title');
      expect((req!.after as Record<string, unknown>)['title']).toBe('New Title');
    });
  });
});
