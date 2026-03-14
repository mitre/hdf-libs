import { describe, it, expect } from 'vitest';
import { filterRequirements } from '../../src/renderers/filter.js';
import type { RequirementDiff } from '../../src/types.js';

function makeReq(overrides: Partial<RequirementDiff> = {}): RequirementDiff {
  return {
    id: 'SV-001',
    state: 'fixed',
    changeReasons: [],
    before: { id: 'SV-001', tags: { severity: 'high' } },
    after: { id: 'SV-001', tags: { severity: 'high' } },
    title: 'Test requirement',
    oldEffectiveStatus: 'failed',
    newEffectiveStatus: 'passed',
    fieldChanges: [],
    ...overrides,
  };
}

describe('filterRequirements', () => {
  it('should return all diffs when no options are provided', () => {
    const diffs = [makeReq()];
    expect(filterRequirements(diffs)).toEqual(diffs);
  });

  it('should return all diffs when options is empty', () => {
    const diffs = [makeReq()];
    expect(filterRequirements(diffs, {})).toEqual(diffs);
  });

  it('should filter by state', () => {
    const diffs = [
      makeReq({ id: 'SV-001', state: 'fixed' }),
      makeReq({ id: 'SV-002', state: 'regressed' }),
    ];
    const result = filterRequirements(diffs, { filterStates: ['fixed'] });
    expect(result).toHaveLength(1);
    expect(result[0]!.id).toBe('SV-001');
  });

  it('should filter by severity using after tags', () => {
    const diffs = [
      makeReq({
        id: 'SV-001',
        after: { tags: { severity: 'high' } },
        before: null,
      }),
      makeReq({
        id: 'SV-002',
        after: { tags: { severity: 'low' } },
        before: null,
      }),
    ];
    const result = filterRequirements(diffs, { filterSeverity: 'high' });
    expect(result).toHaveLength(1);
    expect(result[0]!.id).toBe('SV-001');
  });

  it('should fall back to before tags when after has no tags', () => {
    const diffs = [
      makeReq({
        id: 'SV-001',
        after: null,
        before: { tags: { severity: 'medium' } },
      }),
    ];
    const result = filterRequirements(diffs, { filterSeverity: 'medium' });
    expect(result).toHaveLength(1);
    expect(result[0]!.id).toBe('SV-001');
  });

  it('should exclude requirements with no tags at all', () => {
    const diffs = [
      makeReq({
        id: 'SV-001',
        after: {},
        before: {},
      }),
    ];
    const result = filterRequirements(diffs, { filterSeverity: 'high' });
    expect(result).toHaveLength(0);
  });

  it('should exclude requirements where both before and after are null', () => {
    const diffs = [
      makeReq({
        id: 'SV-001',
        after: null,
        before: null,
      }),
    ];
    const result = filterRequirements(diffs, { filterSeverity: 'high' });
    expect(result).toHaveLength(0);
  });

  it('should handle case-insensitive severity matching', () => {
    const diffs = [
      makeReq({
        id: 'SV-001',
        after: { tags: { severity: 'HIGH' } },
      }),
    ];
    const result = filterRequirements(diffs, { filterSeverity: 'high' });
    expect(result).toHaveLength(1);
  });

  it('should handle non-string severity values', () => {
    const diffs = [
      makeReq({
        id: 'SV-001',
        after: { tags: { severity: 5 } },
      }),
    ];
    const result = filterRequirements(diffs, { filterSeverity: 'high' });
    expect(result).toHaveLength(0);
  });

  it('should apply both filterStates and filterSeverity together', () => {
    const diffs = [
      makeReq({ id: 'SV-001', state: 'fixed', after: { tags: { severity: 'high' } } }),
      makeReq({ id: 'SV-002', state: 'fixed', after: { tags: { severity: 'low' } } }),
      makeReq({ id: 'SV-003', state: 'regressed', after: { tags: { severity: 'high' } } }),
    ];
    const result = filterRequirements(diffs, {
      filterStates: ['fixed'],
      filterSeverity: 'high',
    });
    expect(result).toHaveLength(1);
    expect(result[0]!.id).toBe('SV-001');
  });

  it('should not filter with empty filterStates array', () => {
    const diffs = [makeReq(), makeReq({ id: 'SV-002', state: 'regressed' })];
    const result = filterRequirements(diffs, { filterStates: [] });
    expect(result).toHaveLength(2);
  });
});
