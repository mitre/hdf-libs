import { describe, it, expect } from 'vitest';
import {
  getHipcheckNistControls,
  hipcheckAnalysisExists,
  getAllHipcheckAnalyses,
  getAllHipcheckMappings,
} from '../src/hipcheck/index.js';

describe('Hipcheck to NIST mappings', () => {
  it('returns multiple controls for multi-control analyses', () => {
    expect(getHipcheckNistControls('binary')).toEqual(['SI-7', 'SR-4']);
    expect(getHipcheckNistControls('activity')).toEqual(['SR-3', 'SR-4']);
    expect(getHipcheckNistControls('typo')).toEqual(['SR-11', 'SR-4']);
  });

  it('returns a single control for single-control analyses', () => {
    expect(getHipcheckNistControls('fuzz')).toEqual(['SA-11']);
    expect(getHipcheckNistControls('identity')).toEqual(['AC-5']);
    expect(getHipcheckNistControls('review')).toEqual(['SA-15']);
    expect(getHipcheckNistControls('affiliation')).toEqual(['SR-6']);
  });

  it('strips the mitre/ publisher prefix', () => {
    expect(getHipcheckNistControls('mitre/binary')).toEqual(['SI-7', 'SR-4']);
    expect(getHipcheckNistControls('mitre/fuzz')).toEqual(['SA-11']);
  });

  it('returns [] for unknown analyses', () => {
    expect(getHipcheckNistControls('mitre/does-not-exist')).toEqual([]);
    expect(getHipcheckNistControls('')).toEqual([]);
  });

  it('reports existence, prefix-aware', () => {
    expect(hipcheckAnalysisExists('entropy')).toBe(true);
    expect(hipcheckAnalysisExists('mitre/entropy')).toBe(true);
    expect(hipcheckAnalysisExists('nonsense')).toBe(false);
  });

  it('lists all mapped analyses sorted', () => {
    expect(getAllHipcheckAnalyses()).toEqual([
      'activity', 'affiliation', 'binary', 'churn', 'entropy',
      'fuzz', 'identity', 'review', 'typo',
    ]);
  });

  it('every mapping row carries a rationale (judgment table is documented)', () => {
    const all = getAllHipcheckMappings();
    expect(all).toHaveLength(9);
    for (const m of all) {
      expect(m.Rationale.length).toBeGreaterThan(0);
      expect(m.Rev).toBe(5);
    }
  });
});
