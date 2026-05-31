import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { diffHdf } from '../src/diff.js';
import type { HDFComparison, RequirementDiff } from '../src/types.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

function loadFixture(name: string): Record<string, unknown> {
  const filePath = resolve(__dirname, 'fixtures', name);
  return JSON.parse(readFileSync(filePath, 'utf-8')) as Record<string, unknown>;
}

describe('diffHdf', () => {
  let scanBefore: Record<string, unknown>;
  let scanAfter: Record<string, unknown>;
  let scanWithOverride: Record<string, unknown>;

  beforeAll(() => {
    scanBefore = loadFixture('scan-before.json');
    scanAfter = loadFixture('scan-after.json');
    scanWithOverride = loadFixture('scan-with-override.json');
  });

  // ── Helpers ──────────────────────────────────────────────────────────
  function findReq(diff: HDFComparison, id: string): RequirementDiff | undefined {
    return diff.requirementDiffs.find((r) => r.id === id);
  }

  // ── 0. Top-level HDFComparison structure ──────────────────────────────
  describe('HDFComparison top-level structure', () => {
    it('should have formatVersion 1.0.0', () => {
      const diff = diffHdf(scanBefore, scanAfter);
      expect(diff.formatVersion).toBe('1.0.0');
    });

    it('should default to temporal comparisonMode', () => {
      const diff = diffHdf(scanBefore, scanAfter);
      expect(diff.comparisonMode).toBe('temporal');
    });

    it('should include sources array with old and new roles', () => {
      const diff = diffHdf(scanBefore, scanAfter);
      expect(diff.sources).toHaveLength(2);
      expect(diff.sources[0]!.role).toBe('old');
      expect(diff.sources[1]!.role).toBe('new');
    });

    it('should include assessment timestamps in sources', () => {
      const diff = diffHdf(scanBefore, scanAfter);
      expect(diff.sources[0]!.assessmentTimestamp).toBe('2024-01-01T00:00:00Z');
      expect(diff.sources[1]!.assessmentTimestamp).toBe('2024-02-01T00:00:00Z');
    });

    it('should include matching config', () => {
      const diff = diffHdf(scanBefore, scanAfter);
      expect(diff.matching).toBeDefined();
      expect(diff.matching!.primaryStrategy).toBe('exactId');
    });

    it('should have a timestamp string', () => {
      const diff = diffHdf(scanBefore, scanAfter);
      expect(diff.timestamp).toBeDefined();
      expect(typeof diff.timestamp).toBe('string');
    });
  });

  // ── 1. Identical documents → all unchanged ──────────────────────────
  describe('when comparing identical documents', () => {
    it('should classify every requirement as unchanged', () => {
      const diff = diffHdf(scanBefore, scanBefore);

      for (const req of diff.requirementDiffs) {
        expect(req.state).toBe('unchanged');
      }
    });

    it('should have summary zeros except unchanged and total', () => {
      const diff = diffHdf(scanBefore, scanBefore);

      expect(diff.summary.fixed).toBe(0);
      expect(diff.summary.regressed).toBe(0);
      expect(diff.summary.new).toBe(0);
      expect(diff.summary.absent).toBe(0);
      expect(diff.summary.updated).toBe(0);
      expect(diff.summary.unchanged).toBe(5);
      expect(diff.summary.total).toBe(5);
      expect(diff.summary.matchedCount).toBe(5);
      expect(diff.summary.unmatchedOldCount).toBe(0);
      expect(diff.summary.unmatchedNewCount).toBe(0);
    });
  });

  // ── 2. scan-before vs scan-after: per-requirement diffs ─────────────
  describe('when comparing scan-before to scan-after', () => {
    let diff: HDFComparison;

    beforeAll(() => {
      diff = diffHdf(scanBefore, scanAfter);
    });

    it('should mark SV-001 as fixed (failed → passed)', () => {
      const req = findReq(diff, 'SV-001');
      expect(req).toBeDefined();
      expect(req!.state).toBe('fixed');
      expect(req!.oldEffectiveStatus).toBe('failed');
      expect(req!.newEffectiveStatus).toBe('passed');
    });

    it('should include before/after snapshots for SV-001', () => {
      const req = findReq(diff, 'SV-001');
      expect(req).toBeDefined();
      expect(req!.before).not.toBeNull();
      expect(req!.after).not.toBeNull();
      expect((req!.before as Record<string, unknown>)['id']).toBe('SV-001');
      expect((req!.after as Record<string, unknown>)['id']).toBe('SV-001');
    });

    it('should mark SV-002 as unchanged (passed → passed)', () => {
      const req = findReq(diff, 'SV-002');
      expect(req).toBeDefined();
      expect(req!.state).toBe('unchanged');
      expect(req!.oldEffectiveStatus).toBe('passed');
      expect(req!.newEffectiveStatus).toBe('passed');
    });

    it('should mark SV-003 as regressed (passed → failed)', () => {
      const req = findReq(diff, 'SV-003');
      expect(req).toBeDefined();
      expect(req!.state).toBe('regressed');
      expect(req!.oldEffectiveStatus).toBe('passed');
      expect(req!.newEffectiveStatus).toBe('failed');
    });

    it('should mark SV-004 as absent (only in old scan)', () => {
      const req = findReq(diff, 'SV-004');
      expect(req).toBeDefined();
      expect(req!.state).toBe('absent');
      expect(req!.oldEffectiveStatus).toBe('failed');
      expect(req!.newEffectiveStatus).toBeUndefined();
      expect(req!.before).not.toBeNull();
      expect(req!.after).toBeNull();
    });

    it('should mark SV-005 as updated with impactChanged reason', () => {
      const req = findReq(diff, 'SV-005');
      expect(req).toBeDefined();
      expect(req!.state).toBe('updated');
      expect(req!.changeReasons).toContain('impactChanged');
      expect(req!.oldImpact).toBe(0.3);
      expect(req!.newImpact).toBe(0.0);
    });

    it('should mark SV-006 as new (only in new scan)', () => {
      const req = findReq(diff, 'SV-006');
      expect(req).toBeDefined();
      expect(req!.state).toBe('new');
      expect(req!.oldEffectiveStatus).toBeUndefined();
      expect(req!.newEffectiveStatus).toBe('passed');
      expect(req!.before).toBeNull();
      expect(req!.after).not.toBeNull();
    });

    it('should set matchStrategy and matchConfidence for matched requirements', () => {
      const req = findReq(diff, 'SV-001');
      expect(req).toBeDefined();
      expect(req!.matchStrategy).toBe('exactId');
      expect(req!.matchConfidence).toBe(1.0);
    });
  });

  // ── 3. Summary counts ──────────────────────────────────────────────
  describe('summary counts for scan-before vs scan-after', () => {
    it('should have correct counts for each state category', () => {
      const diff = diffHdf(scanBefore, scanAfter);

      expect(diff.summary.fixed).toBe(1);
      expect(diff.summary.regressed).toBe(1);
      expect(diff.summary.new).toBe(1);
      expect(diff.summary.absent).toBe(1);
      expect(diff.summary.unchanged).toBe(1);
      expect(diff.summary.updated).toBe(1);
      expect(diff.summary.total).toBe(6);
      expect(diff.summary.matchedCount).toBe(4);
      expect(diff.summary.unmatchedOldCount).toBe(1);
      expect(diff.summary.unmatchedNewCount).toBe(1);
    });
  });

  // ── 4. Baseline diff ───────────────────────────────────────────────
  describe('baseline diff', () => {
    it('should detect baseline version change', () => {
      const diff = diffHdf(scanBefore, scanAfter);

      expect(diff.baselineDiffs).toHaveLength(1);
      expect(diff.baselineDiffs[0]).toEqual({
        name: 'rhel9-stig-baseline',
        oldVersion: '1.0.0',
        newVersion: '1.1.0',
        state: 'updated',
      });
    });
  });

  // ── 5. Sources contain timestamps ──────────────────────────────────
  describe('sources timestamps', () => {
    it('should capture timestamps from both evaluations in sources', () => {
      const diff = diffHdf(scanBefore, scanAfter);

      expect(diff.sources[0]!.assessmentTimestamp).toBe('2024-01-01T00:00:00Z');
      expect(diff.sources[1]!.assessmentTimestamp).toBe('2024-02-01T00:00:00Z');
    });
  });

  // ── 6. Requirements sorted by id ──────────────────────────────────
  describe('requirement ordering', () => {
    it('should return requirementDiffs sorted by id', () => {
      const diff = diffHdf(scanBefore, scanAfter);
      const ids = diff.requirementDiffs.map((r) => r.id);

      const sorted = [...ids].sort();
      expect(ids).toEqual(sorted);
    });
  });

  // ── 7. Override detection ─────────────────────────────────────────
  describe('when comparing scan-before to scan-with-override', () => {
    it('should detect overrideAdded when requirement gains a waiver', () => {
      const diff = diffHdf(scanBefore, scanWithOverride);
      const req = findReq(diff, 'SV-001');

      expect(req).toBeDefined();
      expect(req!.changeReasons).toContain('overrideAdded');
      // SV-001 in scan-before has no override → effectiveStatus 'failed'
      // SV-001 in scan-with-override has a waiver → effectiveStatus 'passed'
      expect(req!.oldEffectiveStatus).toBe('failed');
      expect(req!.newEffectiveStatus).toBe('passed');
    });
  });

  // ── 8. Empty baselines ────────────────────────────────────────────
  describe('when both documents have empty baselines', () => {
    it('should return empty requirementDiffs and baselineDiffs arrays', () => {
      const emptyOld: Record<string, unknown> = {
        baselines: [],
        statistics: { duration: 0 },
        timestamp: '2024-01-01T00:00:00Z',
        targets: [],
      };
      const emptyNew: Record<string, unknown> = {
        baselines: [],
        statistics: { duration: 0 },
        timestamp: '2024-02-01T00:00:00Z',
        targets: [],
      };

      const diff = diffHdf(emptyOld, emptyNew);

      expect(diff.requirementDiffs).toEqual([]);
      expect(diff.baselineDiffs).toEqual([]);
      expect(diff.summary.total).toBe(0);
    });
  });

  // ── 9. Multiple baselines: one new, one absent ─────────────────
  describe('when baselines are added and removed', () => {
    it('should detect new and absent baselines', () => {
      const oldDoc: Record<string, unknown> = {
        baselines: [
          {
            name: 'baseline-alpha',
            version: '1.0.0',
            requirements: [],
            groups: [],
            supports: [],
          },
        ],
        statistics: { duration: 0 },
        timestamp: '2024-01-01T00:00:00Z',
        targets: [],
      };
      const newDoc: Record<string, unknown> = {
        baselines: [
          {
            name: 'baseline-beta',
            version: '2.0.0',
            requirements: [],
            groups: [],
            supports: [],
          },
        ],
        statistics: { duration: 0 },
        timestamp: '2024-02-01T00:00:00Z',
        targets: [],
      };

      const diff = diffHdf(oldDoc, newDoc);

      expect(diff.baselineDiffs).toHaveLength(2);

      const alpha = diff.baselineDiffs.find((b) => b.name === 'baseline-alpha');
      expect(alpha).toBeDefined();
      expect(alpha!.state).toBe('absent');
      expect(alpha!.oldVersion).toBe('1.0.0');
      expect(alpha!.newVersion).toBeUndefined();

      const beta = diff.baselineDiffs.find((b) => b.name === 'baseline-beta');
      expect(beta).toBeDefined();
      expect(beta!.state).toBe('new');
      expect(beta!.oldVersion).toBeUndefined();
      expect(beta!.newVersion).toBe('2.0.0');
    });
  });

  // ── 10. Field changes tracked ─────────────────────────────────────
  describe('field-level change tracking', () => {
    it('should include impact in fieldChanges when impact changes (using op/path format)', () => {
      const diff = diffHdf(scanBefore, scanAfter);
      const req = findReq(diff, 'SV-005');

      expect(req).toBeDefined();
      expect(req!.fieldChanges).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            op: 'replace',
            path: 'impact',
            oldValue: 0.3,
            newValue: 0.0,
          }),
        ]),
      );
    });

    it('should not include fieldChanges for requirements with no field differences', () => {
      const diff = diffHdf(scanBefore, scanAfter);
      const req = findReq(diff, 'SV-002');

      expect(req).toBeDefined();
      expect(req!.fieldChanges).toEqual([]);
    });

    it('should use op "add" when a tracked field is added in the new requirement', () => {
      const oldDoc: Record<string, unknown> = {
        baselines: [{
          name: 'test', version: '1.0.0',
          requirements: [{
            id: 'SV-001', impact: 0.7, tags: {},
            results: [{ status: 'passed', codeDesc: 'test', startTime: '2024-01-01T00:00:00Z' }],
          }],
          groups: [], supports: [],
        }],
        timestamp: '2024-01-01T00:00:00Z',
      };
      const newDoc: Record<string, unknown> = {
        baselines: [{
          name: 'test', version: '1.0.0',
          requirements: [{
            id: 'SV-001', impact: 0.7, tags: {}, severity: 'high',
            results: [{ status: 'passed', codeDesc: 'test', startTime: '2024-02-01T00:00:00Z' }],
          }],
          groups: [], supports: [],
        }],
        timestamp: '2024-02-01T00:00:00Z',
      };

      const diff = diffHdf(oldDoc, newDoc, { trackedFields: ['severity'] });
      const req = findReq(diff, 'SV-001');

      expect(req).toBeDefined();
      expect(req!.fieldChanges).toEqual([
        { op: 'add', path: 'severity', newValue: 'high' },
      ]);
    });

    it('should use op "remove" when a tracked field is removed in the new requirement', () => {
      const oldDoc: Record<string, unknown> = {
        baselines: [{
          name: 'test', version: '1.0.0',
          requirements: [{
            id: 'SV-001', impact: 0.7, tags: {}, severity: 'high',
            results: [{ status: 'passed', codeDesc: 'test', startTime: '2024-01-01T00:00:00Z' }],
          }],
          groups: [], supports: [],
        }],
        timestamp: '2024-01-01T00:00:00Z',
      };
      const newDoc: Record<string, unknown> = {
        baselines: [{
          name: 'test', version: '1.0.0',
          requirements: [{
            id: 'SV-001', impact: 0.7, tags: {},
            results: [{ status: 'passed', codeDesc: 'test', startTime: '2024-02-01T00:00:00Z' }],
          }],
          groups: [], supports: [],
        }],
        timestamp: '2024-02-01T00:00:00Z',
      };

      const diff = diffHdf(oldDoc, newDoc, { trackedFields: ['severity'] });
      const req = findReq(diff, 'SV-001');

      expect(req).toBeDefined();
      expect(req!.fieldChanges).toEqual([
        { op: 'remove', path: 'severity', oldValue: 'high' },
      ]);
    });
  });

  // ── Edge cases ────────────────────────────────────────────────────
  describe('edge cases', () => {
    it('should include title from whichever evaluation has the requirement', () => {
      const diff = diffHdf(scanBefore, scanAfter);

      const added = findReq(diff, 'SV-006');
      expect(added).toBeDefined();
      expect(added!.title).toBe('Ensure SELinux is enforcing');

      const removed = findReq(diff, 'SV-004');
      expect(removed).toBeDefined();
      expect(removed!.title).toBe('Ensure FIPS mode is enabled');
    });

    it('should have empty changeReasons for unchanged requirements', () => {
      const diff = diffHdf(scanBefore, scanAfter);
      const req = findReq(diff, 'SV-002');

      expect(req).toBeDefined();
      expect(req!.changeReasons).toEqual([]);
    });

    it('should include resultChanged in changeReasons for fixed and regressed', () => {
      const diff = diffHdf(scanBefore, scanAfter);

      const fixed = findReq(diff, 'SV-001');
      expect(fixed).toBeDefined();
      expect(fixed!.changeReasons).toContain('resultChanged');

      const regressed = findReq(diff, 'SV-003');
      expect(regressed).toBeDefined();
      expect(regressed!.changeReasons).toContain('resultChanged');
    });
  });

  // ── Custom options ────────────────────────────────────────────────
  describe('custom trackedFields option', () => {
    it('should only track specified fields in fieldChanges', () => {
      const diff = diffHdf(scanBefore, scanAfter, { trackedFields: ['impact'] });
      const req = findReq(diff, 'SV-005');

      expect(req).toBeDefined();
      expect(req!.fieldChanges).toHaveLength(1);
      expect(req!.fieldChanges[0]!.path).toBe('impact');
      expect(req!.fieldChanges[0]!.op).toBe('replace');
    });
  });

  // ── Title fallback ───────────────────────────────────────────────
  describe('title fallback', () => {
    it('should use oldReq title when newReq has no title', () => {
      const oldDoc: Record<string, unknown> = {
        baselines: [{
          name: 'test-baseline',
          version: '1.0.0',
          requirements: [{
            id: 'SV-001',
            title: 'Old Title',
            descriptions: [{ label: 'default', data: 'test' }],
            impact: 0.7,
            tags: {},
            results: [{ status: 'passed', codeDesc: 'test', startTime: '2024-01-01T00:00:00Z' }],
          }],
          groups: [],
          supports: [],
        }],
        timestamp: '2024-01-01T00:00:00Z',
      };
      const newDoc: Record<string, unknown> = {
        baselines: [{
          name: 'test-baseline',
          version: '1.0.0',
          requirements: [{
            id: 'SV-001',
            descriptions: [{ label: 'default', data: 'test' }],
            impact: 0.7,
            tags: {},
            results: [{ status: 'passed', codeDesc: 'test', startTime: '2024-02-01T00:00:00Z' }],
          }],
          groups: [],
          supports: [],
        }],
        timestamp: '2024-02-01T00:00:00Z',
      };

      const diff = diffHdf(oldDoc, newDoc);
      const req = findReq(diff, 'SV-001');
      expect(req!.title).toBe('Old Title');
    });
  });

  // ── Documents without timestamps ─────────────────────────────────
  describe('documents without timestamps', () => {
    it('should handle missing timestamps gracefully', () => {
      const oldDoc: Record<string, unknown> = {
        baselines: [{
          name: 'b1', version: '1.0.0', requirements: [], groups: [], supports: [],
        }],
      };
      const newDoc: Record<string, unknown> = {
        baselines: [{
          name: 'b1', version: '1.0.0', requirements: [], groups: [], supports: [],
        }],
      };
      const diff = diffHdf(oldDoc, newDoc);
      // Sources should still exist but assessmentTimestamp may be undefined
      expect(diff.sources).toHaveLength(2);
      expect(diff.sources[0]!.assessmentTimestamp).toBeUndefined();
      expect(diff.sources[1]!.assessmentTimestamp).toBeUndefined();
    });
  });

  // ── Documents without baselines field ─────────────────────────────
  describe('documents without baselines field', () => {
    it('should handle missing baselines field gracefully', () => {
      const diff = diffHdf({}, {});
      expect(diff.requirementDiffs).toEqual([]);
      expect(diff.baselineDiffs).toEqual([]);
      expect(diff.summary.total).toBe(0);
    });
  });

  // ── Before/after snapshot validation ──────────────────────────────
  describe('before/after snapshots', () => {
    it('should set before=null for new requirements', () => {
      const diff = diffHdf(scanBefore, scanAfter);
      const req = findReq(diff, 'SV-006');
      expect(req).toBeDefined();
      expect(req!.before).toBeNull();
      expect(req!.after).not.toBeNull();
    });

    it('should set after=null for absent requirements', () => {
      const diff = diffHdf(scanBefore, scanAfter);
      const req = findReq(diff, 'SV-004');
      expect(req).toBeDefined();
      expect(req!.before).not.toBeNull();
      expect(req!.after).toBeNull();
    });

    it('should include both before and after for matched requirements', () => {
      const diff = diffHdf(scanBefore, scanAfter);
      const req = findReq(diff, 'SV-002');
      expect(req).toBeDefined();
      expect(req!.before).not.toBeNull();
      expect(req!.after).not.toBeNull();
    });
  });

  // ── comparisonMode option ──────────────────────────────────────────
  describe('comparisonMode option', () => {
    it('should allow overriding comparisonMode', () => {
      const diff = diffHdf(scanBefore, scanAfter, { comparisonMode: 'baseline' });
      expect(diff.comparisonMode).toBe('baseline');
    });
  });

  // ── Array validation ───────────────────────────────────────────────
  describe('array validation for newResults', () => {
    it('should throw when newResults is an empty array', () => {
      expect(() => diffHdf(scanBefore, [])).toThrow('newResults array must not be empty');
    });

    it('should throw when non-fleet mode receives multiple documents', () => {
      expect(() => diffHdf(scanBefore, [scanAfter, scanAfter], { comparisonMode: 'temporal' }))
        .toThrow("Mode 'temporal' expects a single document, got 2. Use 'fleet' mode for multiple documents.");
    });

    it('should throw for baseline mode with multiple documents', () => {
      expect(() => diffHdf(scanBefore, [scanAfter, scanAfter], { comparisonMode: 'baseline' }))
        .toThrow("Mode 'baseline' expects a single document, got 2. Use 'fleet' mode for multiple documents.");
    });

    it('should accept a single-element array in non-fleet modes', () => {
      const diff = diffHdf(scanBefore, [scanAfter], { comparisonMode: 'temporal' });
      expect(diff.comparisonMode).toBe('temporal');
      expect(diff.requirementDiffs.length).toBeGreaterThan(0);
    });

    it('should throw for empty array even in fleet mode', () => {
      expect(() => diffHdf(scanBefore, [], { comparisonMode: 'fleet' }))
        .toThrow('newResults array must not be empty');
    });
  });
});
