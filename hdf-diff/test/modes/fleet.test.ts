import { describe, it, expect } from 'vitest';
import { diffHdf } from '../../src/diff.js';
import type { HdfComparison, RequirementDiff } from '../../src/types.js';

function findReqsBySource(diff: HdfComparison, sourceIndex: number): RequirementDiff[] {
  return diff.requirementDiffs.filter((r) => r.sourceIndex === sourceIndex);
}

// ── Inline fixtures ────────────────────────────────────────────────

const reference: Record<string, unknown> = {
  baselines: [{
    name: 'test-baseline', version: '1.0.0',
    requirements: [
      {
        id: 'SV-001', title: 'Check A', impact: 0.7, tags: {},
        descriptions: [{ label: 'default', data: 'test' }],
        results: [{ status: 'passed', codeDesc: 'test', startTime: '2024-01-01T00:00:00Z' }],
      },
      {
        id: 'SV-002', title: 'Check B', impact: 0.5, tags: {},
        descriptions: [{ label: 'default', data: 'test' }],
        results: [{ status: 'passed', codeDesc: 'test', startTime: '2024-01-01T00:00:00Z' }],
      },
    ],
    groups: [], supports: [],
  }],
  timestamp: '2024-01-01T00:00:00Z',
};

const systemA: Record<string, unknown> = {
  baselines: [{
    name: 'test-baseline', version: '1.0.0',
    requirements: [
      {
        id: 'SV-001', title: 'Check A', impact: 0.7, tags: {},
        descriptions: [{ label: 'default', data: 'test' }],
        results: [{ status: 'failed', codeDesc: 'test', startTime: '2024-02-01T00:00:00Z', message: 'failed' }],
      },
      {
        id: 'SV-002', title: 'Check B', impact: 0.5, tags: {},
        descriptions: [{ label: 'default', data: 'test' }],
        results: [{ status: 'passed', codeDesc: 'test', startTime: '2024-02-01T00:00:00Z' }],
      },
    ],
    groups: [], supports: [],
  }],
  timestamp: '2024-02-01T00:00:00Z',
};

const systemB: Record<string, unknown> = {
  baselines: [{
    name: 'test-baseline', version: '1.0.0',
    requirements: [
      {
        id: 'SV-001', title: 'Check A', impact: 0.7, tags: {},
        descriptions: [{ label: 'default', data: 'test' }],
        results: [{ status: 'passed', codeDesc: 'test', startTime: '2024-03-01T00:00:00Z' }],
      },
      {
        id: 'SV-002', title: 'Check B', impact: 0.5, tags: {},
        descriptions: [{ label: 'default', data: 'test' }],
        results: [{ status: 'passed', codeDesc: 'test', startTime: '2024-03-01T00:00:00Z' }],
      },
    ],
    groups: [], supports: [],
  }],
  timestamp: '2024-03-01T00:00:00Z',
};

describe('fleet comparison mode', () => {
  // ── 1. Top-level metadata ──────────────────────────────────────────
  describe('top-level metadata', () => {
    it('should set comparisonMode to fleet', () => {
      const diff = diffHdf(reference, [systemA, systemB], { comparisonMode: 'fleet' });
      expect(diff.comparisonMode).toBe('fleet');
    });

    it('should have formatVersion 1.0.0', () => {
      const diff = diffHdf(reference, [systemA, systemB], { comparisonMode: 'fleet' });
      expect(diff.formatVersion).toBe('1.0.0');
    });
  });

  // ── 2. Sources array ──────────────────────────────────────────────
  describe('sources', () => {
    it('should have 3 sources for reference + 2 systems', () => {
      const diff = diffHdf(reference, [systemA, systemB], { comparisonMode: 'fleet' });
      expect(diff.sources).toHaveLength(3);
    });

    it('should use role "reference" for the first source', () => {
      const diff = diffHdf(reference, [systemA, systemB], { comparisonMode: 'fleet' });
      expect(diff.sources[0]!.role).toBe('reference');
    });

    it('should label the first source "Reference"', () => {
      const diff = diffHdf(reference, [systemA, systemB], { comparisonMode: 'fleet' });
      expect(diff.sources[0]!.label).toBe('Reference');
    });

    it('should use role "system" for each system source', () => {
      const diff = diffHdf(reference, [systemA, systemB], { comparisonMode: 'fleet' });
      expect(diff.sources[1]!.role).toBe('system');
      expect(diff.sources[2]!.role).toBe('system');
    });

    it('should label systems with sequential numbering', () => {
      const diff = diffHdf(reference, [systemA, systemB], { comparisonMode: 'fleet' });
      expect(diff.sources[1]!.label).toBe('System 1');
      expect(diff.sources[2]!.label).toBe('System 2');
    });

    it('should include assessment timestamps for reference and systems', () => {
      const diff = diffHdf(reference, [systemA, systemB], { comparisonMode: 'fleet' });
      expect(diff.sources[0]!.assessmentTimestamp).toBe('2024-01-01T00:00:00Z');
      expect(diff.sources[1]!.assessmentTimestamp).toBe('2024-02-01T00:00:00Z');
      expect(diff.sources[2]!.assessmentTimestamp).toBe('2024-03-01T00:00:00Z');
    });
  });

  // ── 3. RequirementDiffs with sourceIndex ───────────────────────────
  describe('requirementDiffs with sourceIndex', () => {
    it('should include diffs for all systems', () => {
      const diff = diffHdf(reference, [systemA, systemB], { comparisonMode: 'fleet' });
      // 2 requirements x 2 systems = 4 diffs
      expect(diff.requirementDiffs).toHaveLength(4);
    });

    it('should set sourceIndex=1 for system-A diffs', () => {
      const diff = diffHdf(reference, [systemA, systemB], { comparisonMode: 'fleet' });
      const sysADiffs = findReqsBySource(diff, 1);
      expect(sysADiffs).toHaveLength(2);
    });

    it('should set sourceIndex=2 for system-B diffs', () => {
      const diff = diffHdf(reference, [systemA, systemB], { comparisonMode: 'fleet' });
      const sysBDiffs = findReqsBySource(diff, 2);
      expect(sysBDiffs).toHaveLength(2);
    });

    it('should detect SV-001 regression in system-A', () => {
      const diff = diffHdf(reference, [systemA, systemB], { comparisonMode: 'fleet' });
      const sysADiffs = findReqsBySource(diff, 1);
      const sv001 = sysADiffs.find((r) => r.id === 'SV-001');
      expect(sv001).toBeDefined();
      expect(sv001!.state).toBe('regressed');
      expect(sv001!.oldEffectiveStatus).toBe('passed');
      expect(sv001!.newEffectiveStatus).toBe('failed');
    });

    it('should detect SV-002 unchanged in system-A', () => {
      const diff = diffHdf(reference, [systemA, systemB], { comparisonMode: 'fleet' });
      const sysADiffs = findReqsBySource(diff, 1);
      const sv002 = sysADiffs.find((r) => r.id === 'SV-002');
      expect(sv002).toBeDefined();
      expect(sv002!.state).toBe('unchanged');
    });

    it('should detect all unchanged in system-B', () => {
      const diff = diffHdf(reference, [systemA, systemB], { comparisonMode: 'fleet' });
      const sysBDiffs = findReqsBySource(diff, 2);
      for (const req of sysBDiffs) {
        expect(req.state).toBe('unchanged');
      }
    });
  });

  // ── 4. Summary counts ─────────────────────────────────────────────
  describe('summary counts', () => {
    it('should count total requirements across all systems', () => {
      const diff = diffHdf(reference, [systemA, systemB], { comparisonMode: 'fleet' });
      // 2 requirements x 2 systems = 4 total
      expect(diff.summary.total).toBe(4);
    });

    it('should count 1 regressed, 3 unchanged', () => {
      const diff = diffHdf(reference, [systemA, systemB], { comparisonMode: 'fleet' });
      expect(diff.summary.regressed).toBe(1);
      expect(diff.summary.unchanged).toBe(3);
      expect(diff.summary.fixed).toBe(0);
      expect(diff.summary.new).toBe(0);
      expect(diff.summary.absent).toBe(0);
    });

    it('should count all 4 as matched (no unmatched)', () => {
      const diff = diffHdf(reference, [systemA, systemB], { comparisonMode: 'fleet' });
      expect(diff.summary.matchedCount).toBe(4);
      expect(diff.summary.unmatchedOldCount).toBe(0);
      expect(diff.summary.unmatchedNewCount).toBe(0);
    });
  });

  // ── 5. Single system fleet mode ───────────────────────────────────
  describe('single system fleet mode', () => {
    it('should work with a single-element array', () => {
      const diff = diffHdf(reference, [systemA], { comparisonMode: 'fleet' });
      expect(diff.sources).toHaveLength(2);
      expect(diff.sources[0]!.role).toBe('reference');
      expect(diff.sources[1]!.role).toBe('system');
      expect(diff.sources[1]!.label).toBe('System 1');
    });

    it('should set sourceIndex=1 for the single system', () => {
      const diff = diffHdf(reference, [systemA], { comparisonMode: 'fleet' });
      expect(diff.requirementDiffs).toHaveLength(2);
      for (const req of diff.requirementDiffs) {
        expect(req.sourceIndex).toBe(1);
      }
    });
  });

  // ── 6. Single doc (non-array) still works in fleet mode ───────────
  describe('single document (non-array) fallback', () => {
    it('should treat single doc like a one-system fleet', () => {
      const diff = diffHdf(reference, systemA, { comparisonMode: 'fleet' });
      expect(diff.comparisonMode).toBe('fleet');
      expect(diff.sources).toHaveLength(2);
      expect(diff.sources[0]!.role).toBe('reference');
      expect(diff.sources[1]!.role).toBe('system');
      expect(diff.requirementDiffs).toHaveLength(2);
      for (const req of diff.requirementDiffs) {
        expect(req.sourceIndex).toBe(1);
      }
    });
  });

  // ── 7. Requirement ordering ───────────────────────────────────────
  describe('requirement ordering', () => {
    it('should sort requirementDiffs by id then sourceIndex', () => {
      const diff = diffHdf(reference, [systemA, systemB], { comparisonMode: 'fleet' });
      const ids = diff.requirementDiffs.map((r) => `${r.id}:${r.sourceIndex}`);
      const sorted = [...ids].sort();
      expect(ids).toEqual(sorted);
    });
  });

  // ── 8. Fleet with system that has extra/missing requirements ──────
  describe('systems with different requirements than reference', () => {
    const systemWithExtra: Record<string, unknown> = {
      baselines: [{
        name: 'test-baseline', version: '1.0.0',
        requirements: [
          {
            id: 'SV-001', title: 'Check A', impact: 0.7, tags: {},
            descriptions: [{ label: 'default', data: 'test' }],
            results: [{ status: 'passed', codeDesc: 'test', startTime: '2024-04-01T00:00:00Z' }],
          },
          {
            id: 'SV-002', title: 'Check B', impact: 0.5, tags: {},
            descriptions: [{ label: 'default', data: 'test' }],
            results: [{ status: 'passed', codeDesc: 'test', startTime: '2024-04-01T00:00:00Z' }],
          },
          {
            id: 'SV-003', title: 'Check C', impact: 0.9, tags: {},
            descriptions: [{ label: 'default', data: 'test' }],
            results: [{ status: 'failed', codeDesc: 'test', startTime: '2024-04-01T00:00:00Z', message: 'fail' }],
          },
        ],
        groups: [], supports: [],
      }],
      timestamp: '2024-04-01T00:00:00Z',
    };

    it('should mark extra requirement in system as new', () => {
      const diff = diffHdf(reference, [systemWithExtra], { comparisonMode: 'fleet' });
      const sysReqs = findReqsBySource(diff, 1);
      const sv003 = sysReqs.find((r) => r.id === 'SV-003');
      expect(sv003).toBeDefined();
      expect(sv003!.state).toBe('new');
    });

    it('should include new requirements in summary counts', () => {
      const diff = diffHdf(reference, [systemWithExtra], { comparisonMode: 'fleet' });
      expect(diff.summary.new).toBe(1);
      expect(diff.summary.unchanged).toBe(2);
      expect(diff.summary.total).toBe(3);
    });
  });

  // ── 9. System missing a requirement the reference has ───────────────
  describe('system missing a reference requirement', () => {
    const systemMissing: Record<string, unknown> = {
      baselines: [{
        name: 'test-baseline', version: '1.0.0',
        requirements: [
          {
            id: 'SV-001', title: 'Check A', impact: 0.7, tags: {},
            descriptions: [{ label: 'default', data: 'test' }],
            results: [{ status: 'passed', codeDesc: 'test', startTime: '2024-05-01T00:00:00Z' }],
          },
          // SV-002 is intentionally absent — the reference has it but this system does not
        ],
        groups: [], supports: [],
      }],
      timestamp: '2024-05-01T00:00:00Z',
    };

    it('should produce an absent diff for the missing requirement', () => {
      const diff = diffHdf(reference, [systemMissing], { comparisonMode: 'fleet' });
      const sysReqs = findReqsBySource(diff, 1);
      const sv002 = sysReqs.find((r) => r.id === 'SV-002');
      expect(sv002).toBeDefined();
      expect(sv002!.state).toBe('absent');
    });

    it('should set sourceIndex on the absent diff', () => {
      const diff = diffHdf(reference, [systemMissing], { comparisonMode: 'fleet' });
      const sysReqs = findReqsBySource(diff, 1);
      const sv002 = sysReqs.find((r) => r.id === 'SV-002');
      expect(sv002).toBeDefined();
      expect(sv002!.sourceIndex).toBe(1);
    });

    it('should count the absent requirement in summary', () => {
      const diff = diffHdf(reference, [systemMissing], { comparisonMode: 'fleet' });
      expect(diff.summary.absent).toBe(1);
      expect(diff.summary.unchanged).toBe(1);
      expect(diff.summary.total).toBe(2);
    });
  });
});
