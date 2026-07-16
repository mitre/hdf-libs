import { describe, it, expect } from 'vitest';
import { results } from '@mitre/hdf-fixtures';
import { countHdfResultRequirements, countXmlElements } from '../../../shared/typescript/anchor.js';
import { convertHdfToXml } from './converter.js';

// Export-side ground-truth anchor: hdf-to-xml faithfully serializes the tree,
// one <requirement> element per HDF requirement (the plural <requirements>
// wrappers are a distinct local name and are not matched). Mirrors Go.
describe('hdf-to-xml output-count anchor', () => {
  it('emits one <requirement> element per HDF requirement', () => {
    const input = results.inspecMultilayered.read();
    const want = countHdfResultRequirements(input);
    expect(want).toBeGreaterThan(1);
    const got = countXmlElements(convertHdfToXml(input), 'requirement');
    expect(got, 'one <requirement> element per HDF requirement').toBe(want);
  });
});
