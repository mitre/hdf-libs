import type { BaselineRequirement, HDFBaseline, Description } from '@mitre/hdf-schema';

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

/** Create an HDFBaseline with sensible defaults. */
export function makeBaseline(
  overrides: Partial<HDFBaseline> & { name: string; requirements: BaselineRequirement[] },
): HDFBaseline {
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
