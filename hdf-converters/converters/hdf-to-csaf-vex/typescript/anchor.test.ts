import { describe, it, expect } from 'vitest';
import { amendments } from '@mitre/hdf-fixtures';
import { countDistinctCveOverrides, countJsonItemsUnderKey } from '../../../shared/typescript/anchor.js';
import { convertHdfToCsafVex } from './converter.js';

// Export-side ground-truth anchor: hdf-to-csaf-vex drops non-CVE overrides and
// groups by CVE, emitting one vulnerability per distinct CVE-shaped
// requirementId. Mirrors Go.
describe('hdf-to-csaf-vex output-count anchor', () => {
  it('emits one vulnerability per distinct CVE-shaped override', () => {
    const input = amendments.multiCve.read();
    const want = countDistinctCveOverrides(input);
    expect(want).toBeGreaterThan(1);
    const got = countJsonItemsUnderKey(convertHdfToCsafVex(input, '1.0.0'), 'vulnerabilities');
    expect(got, 'one CSAF vulnerability per distinct CVE-shaped override').toBe(want);
  });
});
