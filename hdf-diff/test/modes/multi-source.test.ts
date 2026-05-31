import { describe, it, expect } from 'vitest';
import { diffHdf } from '../../src/diff.js';
import type { HDFComparison, RequirementDiff } from '../../src/types.js';

function findReq(diff: HDFComparison, id: string): RequirementDiff | undefined {
  return diff.requirementDiffs.find((r) => r.id === id);
}

// ── Inline fixtures ────────────────────────────────────────────────

const scanA: Record<string, unknown> = {
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
        results: [{ status: 'failed', codeDesc: 'test', startTime: '2024-01-01T00:00:00Z', message: 'fail' }],
      },
    ],
    groups: [], supports: [],
  }],
  timestamp: '2024-01-01T00:00:00Z',
  dataSource: { name: 'InSpec Scanner' },
};

const scanB: Record<string, unknown> = {
  baselines: [{
    name: 'test-baseline', version: '1.0.0',
    requirements: [
      {
        id: 'SV-001', title: 'Check A', impact: 0.7, tags: {},
        descriptions: [{ label: 'default', data: 'test' }],
        results: [{ status: 'passed', codeDesc: 'test', startTime: '2024-01-15T00:00:00Z' }],
      },
      {
        id: 'SV-002', title: 'Check B', impact: 0.5, tags: {},
        descriptions: [{ label: 'default', data: 'test' }],
        results: [{ status: 'passed', codeDesc: 'test', startTime: '2024-01-15T00:00:00Z' }],
      },
    ],
    groups: [], supports: [],
  }],
  timestamp: '2024-01-15T00:00:00Z',
  dataSource: { name: 'Nessus Scanner' },
};

const scanNoDataSource: Record<string, unknown> = {
  baselines: [{
    name: 'test-baseline', version: '1.0.0',
    requirements: [
      {
        id: 'SV-001', title: 'Check A', impact: 0.7, tags: {},
        descriptions: [{ label: 'default', data: 'test' }],
        results: [{ status: 'passed', codeDesc: 'test', startTime: '2024-02-01T00:00:00Z' }],
      },
    ],
    groups: [], supports: [],
  }],
  timestamp: '2024-02-01T00:00:00Z',
};

describe('multiSource comparison mode', () => {
  // ── 1. Top-level metadata ──────────────────────────────────────────
  describe('top-level metadata', () => {
    it('should set comparisonMode to multiSource', () => {
      const diff = diffHdf(scanA, scanB, { comparisonMode: 'multiSource' });
      expect(diff.comparisonMode).toBe('multiSource');
    });

    it('should have formatVersion 1.0.0', () => {
      const diff = diffHdf(scanA, scanB, { comparisonMode: 'multiSource' });
      expect(diff.formatVersion).toBe('1.0.0');
    });
  });

  // ── 2. Sources with dataSource labels ─────────────────────────────
  describe('sources with dataSource labels', () => {
    it('should have 2 sources', () => {
      const diff = diffHdf(scanA, scanB, { comparisonMode: 'multiSource' });
      expect(diff.sources).toHaveLength(2);
    });

    it('should use role "old" for the first source', () => {
      const diff = diffHdf(scanA, scanB, { comparisonMode: 'multiSource' });
      expect(diff.sources[0]!.role).toBe('old');
    });

    it('should use role "new" for the second source', () => {
      const diff = diffHdf(scanA, scanB, { comparisonMode: 'multiSource' });
      expect(diff.sources[1]!.role).toBe('new');
    });

    it('should include dataSource name in label when available', () => {
      const diff = diffHdf(scanA, scanB, { comparisonMode: 'multiSource' });
      expect(diff.sources[0]!.label).toBe('InSpec Scanner');
      expect(diff.sources[1]!.label).toBe('Nessus Scanner');
    });

    it('should fall back to default labels when dataSource is unavailable', () => {
      const diff = diffHdf(scanNoDataSource, scanNoDataSource, { comparisonMode: 'multiSource' });
      expect(diff.sources[0]!.label).toBe('Old evaluation');
      expect(diff.sources[1]!.label).toBe('New evaluation');
    });

    it('should include assessment timestamps', () => {
      const diff = diffHdf(scanA, scanB, { comparisonMode: 'multiSource' });
      expect(diff.sources[0]!.assessmentTimestamp).toBe('2024-01-01T00:00:00Z');
      expect(diff.sources[1]!.assessmentTimestamp).toBe('2024-01-15T00:00:00Z');
    });
  });

  // ── 3. Diff logic is identical to temporal ─────────────────────────
  describe('diff logic matches temporal mode', () => {
    it('should produce the same requirement states as temporal mode', () => {
      const multiDiff = diffHdf(scanA, scanB, { comparisonMode: 'multiSource' });
      const temporalDiff = diffHdf(scanA, scanB, { comparisonMode: 'temporal' });

      expect(multiDiff.requirementDiffs).toHaveLength(
        temporalDiff.requirementDiffs.length,
      );

      for (const temporalReq of temporalDiff.requirementDiffs) {
        const multiReq = findReq(multiDiff, temporalReq.id);
        expect(multiReq).toBeDefined();
        expect(multiReq!.state).toBe(temporalReq.state);
      }
    });

    it('should produce the same summary counts as temporal mode', () => {
      const multiDiff = diffHdf(scanA, scanB, { comparisonMode: 'multiSource' });
      const temporalDiff = diffHdf(scanA, scanB, { comparisonMode: 'temporal' });

      expect(multiDiff.summary).toEqual(temporalDiff.summary);
    });

    it('should detect SV-002 fixed from failed to passed', () => {
      const diff = diffHdf(scanA, scanB, { comparisonMode: 'multiSource' });
      const req = findReq(diff, 'SV-002');
      expect(req).toBeDefined();
      expect(req!.state).toBe('fixed');
      expect(req!.oldEffectiveStatus).toBe('failed');
      expect(req!.newEffectiveStatus).toBe('passed');
    });
  });

  // ── 4. Mixed dataSource availability ──────────────────────────────
  describe('mixed dataSource availability', () => {
    it('should use dataSource name for one and default for the other', () => {
      const diff = diffHdf(scanA, scanNoDataSource, { comparisonMode: 'multiSource' });
      expect(diff.sources[0]!.label).toBe('InSpec Scanner');
      expect(diff.sources[1]!.label).toBe('New evaluation');
    });
  });
});
