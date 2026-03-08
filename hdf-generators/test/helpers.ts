import type { BaselineRequirement, HdfBaseline, Description } from '@mitre/hdf-schema';

/** Create a BaselineRequirement with sensible defaults. */
export function makeRequirement(
  overrides: Partial<BaselineRequirement> & { id: string },
): BaselineRequirement {
  return {
    impact: 0.5,
    tags: {},
    descriptions: [{ label: 'default', data: 'Test requirement' }],
    ...overrides,
  };
}

/** Create an HdfBaseline with sensible defaults. */
export function makeBaseline(
  overrides: Partial<HdfBaseline> & { name: string; requirements: BaselineRequirement[] },
): HdfBaseline {
  return {
    groups: [],
    supports: [],
    ...overrides,
  };
}

/** Shorthand for creating a Description. */
export function desc(label: string, data: string): Description {
  return { label, data };
}
