import { describe, it, expect } from 'vitest';
import { diffHdf } from '../src/diff.js';
import type { HdfComparison, RequirementDiff } from '../src/types.js';

/**
 * Drift vs Changes separation tests.
 *
 * Terraform separates resource_changes (intended) from resource_drift (external).
 * We adopt this pattern:
 *
 * - requirementDiffs: ALL requirements, including unchanged ones
 * - drift: subset of 'unchanged' requirements that have metadata changes
 *   (tags, descriptions, impact-that-doesn't-change-status, etc.)
 *
 * drift is additive — requirements in drift also appear in requirementDiffs as 'unchanged'.
 */

// ── Helpers ──────────────────────────────────────────────────────────

function findReq(diff: HdfComparison, id: string): RequirementDiff | undefined {
  return diff.requirementDiffs.find((r) => r.id === id);
}

function findDrift(diff: HdfComparison, id: string): RequirementDiff | undefined {
  return diff.drift?.find((r) => r.id === id);
}

/** Build a minimal HDF document with the given requirements */
function makeDoc(
  requirements: Record<string, unknown>[],
  timestamp: string,
): Record<string, unknown> {
  return {
    baselines: [{
      name: 'test-baseline',
      version: '1.0.0',
      requirements,
      groups: [],
      supports: [],
    }],
    timestamp,
  };
}

/** A passing requirement with customizable metadata */
function passingReq(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: 'SV-001',
    title: 'SSH Check',
    impact: 0.7,
    tags: { cci: ['CCI-000366'], nist: ['AC-6'] },
    descriptions: [{ label: 'default', data: 'Default description' }],
    results: [{ status: 'passed', codeDesc: 'test', startTime: '2024-01-01T00:00:00Z' }],
    ...overrides,
  };
}

/** A failing requirement with customizable metadata */
function failingReq(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: 'SV-001',
    title: 'SSH Check',
    impact: 0.7,
    tags: { cci: ['CCI-000366'], nist: ['AC-6'] },
    descriptions: [{ label: 'default', data: 'Default description' }],
    results: [{ status: 'failed', codeDesc: 'test', startTime: '2024-01-01T00:00:00Z' }],
    ...overrides,
  };
}

// ── Tests ────────────────────────────────────────────────────────────

describe('drift separation', () => {
  describe('drift array presence', () => {
    it('should always include a drift array in the result', () => {
      const doc = makeDoc([passingReq()], '2024-01-01T00:00:00Z');
      const diff = diffHdf(doc, doc);
      expect(diff.drift).toBeDefined();
      expect(Array.isArray(diff.drift)).toBe(true);
    });
  });

  describe('no drift when nothing changed', () => {
    it('should return empty drift when comparing identical documents', () => {
      const doc = makeDoc([passingReq()], '2024-01-01T00:00:00Z');
      const diff = diffHdf(doc, doc);

      expect(diff.drift).toEqual([]);
      expect(diff.requirementDiffs).toHaveLength(1);
      expect(diff.requirementDiffs[0]!.state).toBe('unchanged');
      expect(diff.requirementDiffs[0]!.changeReasons).toEqual([]);
    });
  });

  describe('no drift when status changed', () => {
    it('should not produce drift when a requirement goes from failed to passed', () => {
      const oldDoc = makeDoc([failingReq()], '2024-01-01T00:00:00Z');
      const newDoc = makeDoc([passingReq()], '2024-02-01T00:00:00Z');
      const diff = diffHdf(oldDoc, newDoc);

      // Requirement is in requirementDiffs as 'fixed', not in drift
      const req = findReq(diff, 'SV-001');
      expect(req).toBeDefined();
      expect(req!.state).toBe('fixed');

      expect(diff.drift).toEqual([]);
    });

    it('should not produce drift for new requirements', () => {
      const oldDoc = makeDoc([], '2024-01-01T00:00:00Z');
      const newDoc = makeDoc([passingReq()], '2024-02-01T00:00:00Z');
      const diff = diffHdf(oldDoc, newDoc);

      expect(diff.drift).toEqual([]);
    });

    it('should not produce drift for absent requirements', () => {
      const oldDoc = makeDoc([passingReq()], '2024-01-01T00:00:00Z');
      const newDoc = makeDoc([], '2024-02-01T00:00:00Z');
      const diff = diffHdf(oldDoc, newDoc);

      expect(diff.drift).toEqual([]);
    });
  });

  describe('drift when tags change but status stays the same', () => {
    it('should produce drift when CCI tags are added but status remains passed', () => {
      const oldDoc = makeDoc(
        [passingReq({ tags: { cci: ['CCI-000366'], nist: ['AC-6'] } })],
        '2024-01-01T00:00:00Z',
      );
      const newDoc = makeDoc(
        [passingReq({ tags: { cci: ['CCI-000366', 'CCI-000370'], nist: ['AC-6'] } })],
        '2024-02-01T00:00:00Z',
      );
      const diff = diffHdf(oldDoc, newDoc);

      // In requirementDiffs as 'unchanged' (status didn't change)
      const req = findReq(diff, 'SV-001');
      expect(req).toBeDefined();
      expect(req!.state).toBe('unchanged');
      expect(req!.changeReasons).toContain('metadataChanged');

      // Also in drift
      expect(diff.drift).toHaveLength(1);
      const driftReq = findDrift(diff, 'SV-001');
      expect(driftReq).toBeDefined();
      expect(driftReq!.state).toBe('unchanged');
      expect(driftReq!.changeReasons).toContain('metadataChanged');
    });
  });

  describe('drift when impact changes but status stays the same', () => {
    it('should produce drift when impact changes from 0.7 to 0.5 (both non-zero, still passes)', () => {
      const oldDoc = makeDoc(
        [passingReq({ impact: 0.7 })],
        '2024-01-01T00:00:00Z',
      );
      const newDoc = makeDoc(
        [passingReq({ impact: 0.5 })],
        '2024-02-01T00:00:00Z',
      );
      const diff = diffHdf(oldDoc, newDoc);

      // In requirementDiffs as 'unchanged' (still passed → passed)
      const req = findReq(diff, 'SV-001');
      expect(req).toBeDefined();
      expect(req!.state).toBe('unchanged');
      expect(req!.changeReasons).toContain('impactChanged');

      // Also in drift
      expect(diff.drift).toHaveLength(1);
      const driftReq = findDrift(diff, 'SV-001');
      expect(driftReq).toBeDefined();
      expect(driftReq!.changeReasons).toContain('impactChanged');
    });
  });

  describe('drift when description changes', () => {
    it('should produce drift when description text changes but status remains the same', () => {
      const oldDoc = makeDoc(
        [passingReq({ descriptions: [{ label: 'default', data: 'Old description text' }] })],
        '2024-01-01T00:00:00Z',
      );
      const newDoc = makeDoc(
        [passingReq({ descriptions: [{ label: 'default', data: 'Updated description text' }] })],
        '2024-02-01T00:00:00Z',
      );
      const diff = diffHdf(oldDoc, newDoc);

      const req = findReq(diff, 'SV-001');
      expect(req).toBeDefined();
      expect(req!.state).toBe('unchanged');
      expect(req!.changeReasons).toContain('metadataChanged');

      expect(diff.drift).toHaveLength(1);
      const driftReq = findDrift(diff, 'SV-001');
      expect(driftReq).toBeDefined();
      expect(driftReq!.changeReasons).toContain('metadataChanged');
    });
  });

  describe('multiple drift items', () => {
    it('should collect drift for multiple requirements with metadata changes', () => {
      const oldDoc = makeDoc(
        [
          passingReq({ id: 'SV-001', tags: { cci: ['CCI-000366'] } }),
          passingReq({ id: 'SV-002', title: 'Firewall Check' }),
          passingReq({ id: 'SV-003', title: 'Audit Logging', impact: 0.5 }),
        ],
        '2024-01-01T00:00:00Z',
      );
      const newDoc = makeDoc(
        [
          passingReq({ id: 'SV-001', tags: { cci: ['CCI-000366', 'CCI-000370'] } }),  // tags changed
          passingReq({ id: 'SV-002', title: 'Firewall Check' }),  // truly unchanged
          passingReq({ id: 'SV-003', title: 'Audit Logging', impact: 0.3 }),  // impact changed
        ],
        '2024-02-01T00:00:00Z',
      );
      const diff = diffHdf(oldDoc, newDoc);

      // All three in requirementDiffs
      expect(diff.requirementDiffs).toHaveLength(3);

      // SV-002 is truly unchanged — not in drift
      expect(findDrift(diff, 'SV-002')).toBeUndefined();

      // SV-001 and SV-003 have metadata changes — both in drift
      expect(diff.drift).toHaveLength(2);
      expect(findDrift(diff, 'SV-001')).toBeDefined();
      expect(findDrift(diff, 'SV-003')).toBeDefined();
    });
  });

  describe('drift has field changes', () => {
    it('should populate fieldChanges on drift entries showing what metadata changed', () => {
      const oldDoc = makeDoc(
        [passingReq({ impact: 0.7 })],
        '2024-01-01T00:00:00Z',
      );
      const newDoc = makeDoc(
        [passingReq({ impact: 0.5 })],
        '2024-02-01T00:00:00Z',
      );
      const diff = diffHdf(oldDoc, newDoc);

      expect(diff.drift).toHaveLength(1);
      const driftReq = findDrift(diff, 'SV-001');
      expect(driftReq).toBeDefined();
      expect(driftReq!.fieldChanges).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            op: 'replace',
            path: 'impact',
            oldValue: 0.7,
            newValue: 0.5,
          }),
        ]),
      );
    });

    it('should populate fieldChanges for tags when tracked', () => {
      const oldDoc = makeDoc(
        [passingReq({ tags: { cci: ['CCI-000366'] } })],
        '2024-01-01T00:00:00Z',
      );
      const newDoc = makeDoc(
        [passingReq({ tags: { cci: ['CCI-000366', 'CCI-000370'] } })],
        '2024-02-01T00:00:00Z',
      );
      const diff = diffHdf(oldDoc, newDoc);

      expect(diff.drift).toHaveLength(1);
      const driftReq = findDrift(diff, 'SV-001');
      expect(driftReq).toBeDefined();
      expect(driftReq!.fieldChanges).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            op: 'replace',
            path: 'tags',
          }),
        ]),
      );
    });
  });

  describe('drift has before/after snapshots', () => {
    it('should include full before and after snapshots in drift entries', () => {
      const oldDoc = makeDoc(
        [passingReq({ tags: { cci: ['CCI-000366'] } })],
        '2024-01-01T00:00:00Z',
      );
      const newDoc = makeDoc(
        [passingReq({ tags: { cci: ['CCI-000366', 'CCI-000370'] } })],
        '2024-02-01T00:00:00Z',
      );
      const diff = diffHdf(oldDoc, newDoc);

      expect(diff.drift).toHaveLength(1);
      const driftReq = findDrift(diff, 'SV-001');
      expect(driftReq).toBeDefined();
      expect(driftReq!.before).not.toBeNull();
      expect(driftReq!.after).not.toBeNull();
      expect((driftReq!.before as Record<string, unknown>)['id']).toBe('SV-001');
      expect((driftReq!.after as Record<string, unknown>)['id']).toBe('SV-001');
    });
  });

  describe('summary is not affected by drift', () => {
    it('should count drift items as unchanged in summary, not as a separate category', () => {
      const oldDoc = makeDoc(
        [
          passingReq({ id: 'SV-001', tags: { cci: ['CCI-000366'] } }),
          passingReq({ id: 'SV-002', title: 'Firewall Check' }),
        ],
        '2024-01-01T00:00:00Z',
      );
      const newDoc = makeDoc(
        [
          passingReq({ id: 'SV-001', tags: { cci: ['CCI-000366', 'CCI-000370'] } }),  // drift
          passingReq({ id: 'SV-002', title: 'Firewall Check' }),  // truly unchanged
        ],
        '2024-02-01T00:00:00Z',
      );
      const diff = diffHdf(oldDoc, newDoc);

      // Summary counts should reflect requirementDiffs, not drift
      expect(diff.summary.unchanged).toBe(2);  // both are 'unchanged' in requirementDiffs
      expect(diff.summary.total).toBe(2);
      expect(diff.summary.fixed).toBe(0);
      expect(diff.summary.regressed).toBe(0);
      expect(diff.summary.new).toBe(0);
      expect(diff.summary.absent).toBe(0);
      expect(diff.summary.updated).toBe(0);

      // But drift shows only the one with metadata changes
      expect(diff.drift).toHaveLength(1);
    });
  });

  describe('drift independence from requirementDiffs', () => {
    it('should produce independent copies — modifying drift should not affect requirementDiffs', () => {
      const oldDoc = makeDoc(
        [passingReq({ tags: { cci: ['CCI-000366'] } })],
        '2024-01-01T00:00:00Z',
      );
      const newDoc = makeDoc(
        [passingReq({ tags: { cci: ['CCI-000366', 'CCI-000370'] } })],
        '2024-02-01T00:00:00Z',
      );
      const diff = diffHdf(oldDoc, newDoc);

      // Mutate drift entry
      const driftReq = diff.drift![0]!;
      driftReq.id = 'MUTATED';

      // requirementDiffs entry should be unaffected
      const req = findReq(diff, 'SV-001');
      expect(req).toBeDefined();
      expect(req!.id).toBe('SV-001');
    });
  });

  describe('drift with fleet mode', () => {
    it('should populate drift in fleet mode comparisons', () => {
      const refDoc = makeDoc(
        [passingReq({ tags: { cci: ['CCI-000366'] } })],
        '2024-01-01T00:00:00Z',
      );
      const sysDoc = makeDoc(
        [passingReq({ tags: { cci: ['CCI-000366', 'CCI-000370'] } })],
        '2024-02-01T00:00:00Z',
      );
      const diff = diffHdf(refDoc, [sysDoc], { comparisonMode: 'fleet' });

      expect(diff.drift).toBeDefined();
      expect(diff.drift).toHaveLength(1);
      expect(diff.drift![0]!.id).toBe('SV-001');
      expect(diff.drift![0]!.changeReasons).toContain('metadataChanged');
    });
  });

  describe('drift with title change', () => {
    it('should produce drift when title changes but status stays the same', () => {
      const oldDoc = makeDoc(
        [passingReq({ title: 'Old Title' })],
        '2024-01-01T00:00:00Z',
      );
      const newDoc = makeDoc(
        [passingReq({ title: 'New Title' })],
        '2024-02-01T00:00:00Z',
      );
      const diff = diffHdf(oldDoc, newDoc);

      const req = findReq(diff, 'SV-001');
      expect(req).toBeDefined();
      expect(req!.state).toBe('unchanged');
      expect(req!.changeReasons).toContain('metadataChanged');

      expect(diff.drift).toHaveLength(1);
      const driftReq = findDrift(diff, 'SV-001');
      expect(driftReq).toBeDefined();
      expect(driftReq!.changeReasons).toContain('metadataChanged');
    });
  });
});
