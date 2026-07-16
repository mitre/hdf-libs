import { describe, it, expect } from 'vitest';
import { amendments } from '@mitre/hdf-fixtures';
import { countDistinctCveOverrides, countJsonItemsUnderKey } from '../../../shared/typescript/anchor.js';
import { convertHdfToOpenVex } from './converter.js';

// Export-side ground-truth anchor: hdf-to-openvex drops non-CVE overrides and
// emits one statement per CVE-shaped requirementId per status bucket. When each
// CVE resolves to a single bucket (the MultiCVE fixture is all falsePositive),
// the statement count equals the distinct-CVE count. Mirrors Go.
describe('hdf-to-openvex output-count anchor', () => {
  it('emits one statement per distinct CVE-shaped override (single bucket each)', async () => {
    const input = amendments.multiCve.read();
    const want = countDistinctCveOverrides(input);
    expect(want).toBeGreaterThan(1);
    const got = countJsonItemsUnderKey(await convertHdfToOpenVex(input, '1.0.0'), 'statements');
    expect(got, 'one OpenVEX statement per distinct CVE-shaped override').toBe(want);
  });
});
