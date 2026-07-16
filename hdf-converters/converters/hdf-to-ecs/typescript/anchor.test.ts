import { describe, it, expect } from 'vitest';
import { results } from '@mitre/hdf-fixtures';
import { countHdfResultRequirements, countNdjsonRecords } from '../../../shared/typescript/anchor.js';
import { convertHdfToEcs } from './converter.js';

// Export-side ground-truth anchor: one ECS NDJSON event per HDF requirement. Mirrors Go.
describe('hdf-to-ecs output-count anchor', () => {
  it('emits one ECS event per HDF requirement', () => {
    const input = results.inspecMultilayered.read();
    const want = countHdfResultRequirements(input);
    expect(want).toBeGreaterThan(1);
    const got = countNdjsonRecords(convertHdfToEcs(input, '1.0.0'));
    expect(got, 'one ECS event per HDF requirement').toBe(want);
  });
});
