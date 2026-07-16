import { describe, it, expect } from 'vitest';
import { results } from '@mitre/hdf-fixtures';
import { countHdfResultRequirements, countNdjsonRecords } from '../../../shared/typescript/anchor.js';
import { convertHdfToSplunk } from './converter.js';

// Export-side ground-truth anchor: one Splunk HEC NDJSON event per HDF requirement. Mirrors Go.
describe('hdf-to-splunk output-count anchor', () => {
  it('emits one HEC event per HDF requirement', () => {
    const input = results.inspecMultilayered.read();
    const want = countHdfResultRequirements(input);
    expect(want).toBeGreaterThan(1);
    const got = countNdjsonRecords(convertHdfToSplunk(input, '1.0.0'));
    expect(got, 'one Splunk HEC event per HDF requirement').toBe(want);
  });
});
