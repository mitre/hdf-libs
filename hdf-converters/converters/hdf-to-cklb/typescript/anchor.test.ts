import { describe, it, expect } from 'vitest';
import { results } from '@mitre/hdf-fixtures';
import { countHdfResultRequirements, countJsonItemsUnderKey } from '../../../shared/typescript/anchor.js';
import { convertHdfToCklb } from './converter.js';

// Export-side ground-truth anchor: one cklb rule per HDF requirement. Mirrors Go.
describe('hdf-to-cklb output-count anchor', () => {
  it('emits one rule per HDF requirement', () => {
    const input = results.inspecMultilayered.read();
    const want = countHdfResultRequirements(input);
    expect(want).toBeGreaterThan(1);
    const got = countJsonItemsUnderKey(convertHdfToCklb(input), 'rules');
    expect(got, 'one cklb rule per HDF requirement').toBe(want);
  });
});
