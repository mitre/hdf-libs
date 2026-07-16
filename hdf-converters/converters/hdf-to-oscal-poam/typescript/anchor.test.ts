import { describe, it, expect } from 'vitest';
import { amendments } from '@mitre/hdf-fixtures';
import { countHdfOverrides, countJsonItemsUnderKey } from '../../../shared/typescript/anchor.js';
import { convertHdfToOscalPoam } from './converter.js';

// Export-side ground-truth anchor: one OSCAL poam-item per HDF override. Mirrors Go.
describe('hdf-to-oscal-poam output-count anchor', () => {
  it('emits one poam-item per HDF override', async () => {
    const input = amendments.multiCve.read();
    const want = countHdfOverrides(input);
    expect(want).toBeGreaterThan(1);
    const got = countJsonItemsUnderKey(await convertHdfToOscalPoam(input), 'poam-items');
    expect(got, 'one OSCAL poam-item per HDF override').toBe(want);
  });
});
