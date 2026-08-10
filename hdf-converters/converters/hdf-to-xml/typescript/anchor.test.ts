import { describe, it, expect } from 'vitest';
import { results } from '@mitre/hdf-fixtures';
import { countXmlElements } from '../../../shared/typescript/anchor.js';
import { convertHdfToXml } from './converter.js';

// Counts every OBJECT item of every "requirements" array anywhere in the HDF
// tree (not via the converter's parser). The generic serializer emits a
// <requirement> element only for the object-array form; scalar id-ref items
// (e.g. groups[].requirements: ["simple"]) render as unwrapped repeated
// <requirements> keys and are excluded. This is the independent ground-truth
// for the emitted <requirement> element count.
function countRequirementObjects(value: unknown): number {
  if (Array.isArray(value)) {
    return value.reduce((n: number, item) => n + countRequirementObjects(item), 0);
  }
  if (value && typeof value === 'object') {
    let n = 0;
    for (const [key, val] of Object.entries(value as Record<string, unknown>)) {
      if (key === 'requirements' && Array.isArray(val)) {
        n += val.filter(item => item !== null && typeof item === 'object').length;
      }
      n += countRequirementObjects(val);
    }
    return n;
  }
  return 0;
}

// Export-side ground-truth anchor: the generic serializer emits exactly one
// <requirement> element per object item of a "requirements" array in the HDF
// input (at any nesting depth). Mirrors Go.
describe('hdf-to-xml output-count anchor', () => {
  it('emits one <requirement> element per object requirements-array item', () => {
    const raw = results.inspecMultilayered.read();
    const want = countRequirementObjects(JSON.parse(raw));
    expect(want).toBeGreaterThan(1);
    const got = countXmlElements(convertHdfToXml(raw), 'requirement');
    expect(got, 'one <requirement> element per object requirements-array item').toBe(want);
  });
});
