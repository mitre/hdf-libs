import { describe, it, expect } from 'vitest';
import { results } from '@mitre/hdf-fixtures';
import { countHdfResultRequirements, countJsonItemsUnderKey } from '../../../shared/typescript/anchor.js';
import { convertHdfToOscalSar } from './converter.js';

// Export-side ground-truth anchor: one OSCAL finding per HDF requirement (summed
// across every results[].findings[]). Mirrors Go.
describe('hdf-to-oscal-sar output-count anchor', () => {
  it('emits one OSCAL finding per HDF requirement', async () => {
    const input = results.inspecMultilayered.read();
    const want = countHdfResultRequirements(input);
    expect(want).toBeGreaterThan(1);
    const got = countJsonItemsUnderKey(await convertHdfToOscalSar(input), 'findings');
    expect(got, 'one OSCAL finding per HDF requirement').toBe(want);
  });
});
