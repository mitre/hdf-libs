import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { diffHdf } from '../../src/diff.js';
import type { HDFComparison, RequirementDiff } from '../../src/types.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

function loadFixture(name: string): Record<string, unknown> {
  const filePath = resolve(__dirname, '..', 'fixtures', name);
  return JSON.parse(readFileSync(filePath, 'utf-8')) as Record<string, unknown>;
}

function findReq(diff: HDFComparison, id: string): RequirementDiff | undefined {
  return diff.requirementDiffs.find((r) => r.id === id);
}

describe('baseline comparison mode', () => {
  let goldenDoc: Record<string, unknown>;
  let currentDoc: Record<string, unknown>;

  beforeAll(() => {
    goldenDoc = loadFixture('scan-before.json');
    currentDoc = loadFixture('scan-after.json');
  });

  // ── 1. Top-level metadata ──────────────────────────────────────────
  describe('top-level metadata', () => {
    it('should set comparisonMode to baseline', () => {
      const diff = diffHdf(goldenDoc, currentDoc, { comparisonMode: 'baseline' });
      expect(diff.comparisonMode).toBe('baseline');
    });

    it('should have formatVersion 1.0.0', () => {
      const diff = diffHdf(goldenDoc, currentDoc, { comparisonMode: 'baseline' });
      expect(diff.formatVersion).toBe('1.0.0');
    });

    it('should include a timestamp', () => {
      const diff = diffHdf(goldenDoc, currentDoc, { comparisonMode: 'baseline' });
      expect(diff.timestamp).toBeDefined();
      expect(typeof diff.timestamp).toBe('string');
    });
  });

  // ── 2. Sources with correct roles and labels ──────────────────────
  describe('sources', () => {
    it('should have 2 sources', () => {
      const diff = diffHdf(goldenDoc, currentDoc, { comparisonMode: 'baseline' });
      expect(diff.sources).toHaveLength(2);
    });

    it('should use role "golden" for the first source', () => {
      const diff = diffHdf(goldenDoc, currentDoc, { comparisonMode: 'baseline' });
      expect(diff.sources[0]!.role).toBe('golden');
    });

    it('should use role "new" for the second source', () => {
      const diff = diffHdf(goldenDoc, currentDoc, { comparisonMode: 'baseline' });
      expect(diff.sources[1]!.role).toBe('new');
    });

    it('should label the first source "Golden baseline"', () => {
      const diff = diffHdf(goldenDoc, currentDoc, { comparisonMode: 'baseline' });
      expect(diff.sources[0]!.label).toBe('Golden baseline');
    });

    it('should label the second source "Current scan"', () => {
      const diff = diffHdf(goldenDoc, currentDoc, { comparisonMode: 'baseline' });
      expect(diff.sources[1]!.label).toBe('Current scan');
    });

    it('should include assessment timestamps in sources', () => {
      const diff = diffHdf(goldenDoc, currentDoc, { comparisonMode: 'baseline' });
      expect(diff.sources[0]!.assessmentTimestamp).toBe('2024-01-01T00:00:00Z');
      expect(diff.sources[1]!.assessmentTimestamp).toBe('2024-02-01T00:00:00Z');
    });
  });

  // ── 3. Diff logic is identical to temporal ─────────────────────────
  describe('diff logic matches temporal mode', () => {
    it('should produce the same requirementDiffs as temporal mode', () => {
      const baselineDiff = diffHdf(goldenDoc, currentDoc, { comparisonMode: 'baseline' });
      const temporalDiff = diffHdf(goldenDoc, currentDoc, { comparisonMode: 'temporal' });

      // Same number of requirement diffs
      expect(baselineDiff.requirementDiffs).toHaveLength(
        temporalDiff.requirementDiffs.length,
      );

      // Same states for each requirement
      for (const temporalReq of temporalDiff.requirementDiffs) {
        const baselineReq = findReq(baselineDiff, temporalReq.id);
        expect(baselineReq).toBeDefined();
        expect(baselineReq!.state).toBe(temporalReq.state);
        expect(baselineReq!.oldEffectiveStatus).toBe(temporalReq.oldEffectiveStatus);
        expect(baselineReq!.newEffectiveStatus).toBe(temporalReq.newEffectiveStatus);
        expect(baselineReq!.changeReasons).toEqual(temporalReq.changeReasons);
      }
    });

    it('should produce the same summary counts as temporal mode', () => {
      const baselineDiff = diffHdf(goldenDoc, currentDoc, { comparisonMode: 'baseline' });
      const temporalDiff = diffHdf(goldenDoc, currentDoc, { comparisonMode: 'temporal' });

      expect(baselineDiff.summary).toEqual(temporalDiff.summary);
    });

    it('should produce the same baselineDiffs as temporal mode', () => {
      const baselineDiff = diffHdf(goldenDoc, currentDoc, { comparisonMode: 'baseline' });
      const temporalDiff = diffHdf(goldenDoc, currentDoc, { comparisonMode: 'temporal' });

      expect(baselineDiff.baselineDiffs).toEqual(temporalDiff.baselineDiffs);
    });

    it('should mark SV-001 as fixed just like temporal mode', () => {
      const diff = diffHdf(goldenDoc, currentDoc, { comparisonMode: 'baseline' });
      const req = findReq(diff, 'SV-001');
      expect(req).toBeDefined();
      expect(req!.state).toBe('fixed');
    });

    it('should mark SV-003 as regressed just like temporal mode', () => {
      const diff = diffHdf(goldenDoc, currentDoc, { comparisonMode: 'baseline' });
      const req = findReq(diff, 'SV-003');
      expect(req).toBeDefined();
      expect(req!.state).toBe('regressed');
    });
  });

  // ── 4. Identical documents in baseline mode ───────────────────────
  describe('identical documents in baseline mode', () => {
    it('should classify all requirements as unchanged', () => {
      const diff = diffHdf(goldenDoc, goldenDoc, { comparisonMode: 'baseline' });
      for (const req of diff.requirementDiffs) {
        expect(req.state).toBe('unchanged');
      }
    });
  });
});
