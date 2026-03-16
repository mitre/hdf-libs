import type { HdfResults, EvaluatedBaseline, EvaluatedRequirement } from '@mitre/hdf-schema';

export function makeRequirement(overrides: Partial<EvaluatedRequirement> & { id: string }): EvaluatedRequirement {
  return {
    impact: 0.5,
    tags: {},
    descriptions: [{ label: 'default', data: 'Test requirement' }],
    results: [{ codeDesc: 'test', startTime: new Date(), status: 'passed' as any }],
    ...overrides,
  };
}

export function makeBaseline(overrides: Partial<EvaluatedBaseline> & { name: string; requirements: EvaluatedRequirement[] }): EvaluatedBaseline {
  return {
    groups: [],
    supports: [],
    sha256: 'abc123',
    ...overrides,
  };
}

export function makeResults(baselines: EvaluatedBaseline[]): HdfResults {
  return { baselines } as HdfResults;
}
