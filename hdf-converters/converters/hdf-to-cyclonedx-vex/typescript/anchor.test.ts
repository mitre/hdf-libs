import { describe, it, expect } from 'vitest';
import { amendments } from '@mitre/hdf-fixtures';
import { countDistinctCveOverrides, countJsonItemsUnderKey } from '../../../shared/typescript/anchor.js';
import { convertHdfToCyclonedxVex } from './converter.js';

// Export-side ground-truth anchor: hdf-to-cyclonedx-vex drops non-CVE overrides
// and emits one vulnerability per distinct CVE-shaped requirementId. Mirrors Go.
describe('hdf-to-cyclonedx-vex output-count anchor', () => {
  it('emits one vulnerability per distinct CVE-shaped override', async () => {
    const input = amendments.multiCve.read();
    const want = countDistinctCveOverrides(input);
    expect(want).toBeGreaterThan(1);
    const got = countJsonItemsUnderKey(await convertHdfToCyclonedxVex(input, '1.0.0'), 'vulnerabilities');
    expect(got, 'one CycloneDX vulnerability per distinct CVE-shaped override').toBe(want);
  });
});
