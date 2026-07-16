import { describe, it, expect } from 'vitest';
import { results } from '@mitre/hdf-fixtures';
import { countHdfResultRequirements, countXmlElements } from '../../../shared/typescript/anchor.js';
import { convertHdfToCkl } from './converter.js';

// Export-side ground-truth anchor: hdf-to-ckl emits one <VULN> per HDF
// requirement, so the emitted VULN count must equal the requirement count derived
// independently from the HDF input (sum of baselines[].requirements — not the
// converter's parser). Mirrors the Go anchor.
describe('hdf-to-ckl output-count anchor', () => {
  it('emits one <VULN> per HDF requirement', () => {
    const input = results.inspecMultilayered.read();
    const want = countHdfResultRequirements(input);
    expect(want).toBeGreaterThan(1);
    const got = countXmlElements(convertHdfToCkl(input), 'VULN');
    expect(got, 'one <VULN> per HDF requirement').toBe(want);
  });
});
