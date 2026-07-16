import { describe, it, expect } from 'vitest';
import { results } from '@mitre/hdf-fixtures';
import { countHdfResultRequirements, countNdjsonRecords } from '../../../shared/typescript/anchor.js';
import { convertHdfToOcsf } from './converter.js';

// Export-side ground-truth anchor: one OCSF NDJSON finding per HDF requirement. Mirrors Go.
describe('hdf-to-ocsf output-count anchor', () => {
  it('emits one NDJSON finding per HDF requirement', () => {
    const input = results.inspecMultilayered.read();
    const want = countHdfResultRequirements(input);
    expect(want).toBeGreaterThan(1);
    const got = countNdjsonRecords(convertHdfToOcsf(input, '1.0.0'));
    expect(got, 'one OCSF finding per HDF requirement').toBe(want);
  });
});
